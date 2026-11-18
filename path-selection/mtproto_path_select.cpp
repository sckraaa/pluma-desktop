/*
This file is part of Pluma, built on Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_path_select.h"

#include "mtproto/connection_tcp.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_dc_options.h"
#include "base/invoke_queued.h"
#include "settings.h"

#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QSaveFile>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QNetworkInterface>

#include <atomic>
#include <mutex>

namespace MTP::details {
namespace {

// The fingerprint of the network is taken again at most this often.
constexpr auto kFingerprintEvery = crl::time(2000);

// A new network ranks the paths at once, at most this often.
constexpr auto kNetworkRankEvery = path::Time(120) * 1000;

// A request without a byte back ranks the paths at most this often.
constexpr auto kSuspectEvery = path::Time(60) * 1000;

// The rank of a start, after the session connected.
constexpr auto kStartRankDelay = path::Time(5) * 1000;

// Files moved within this time are a transfer going on; a switch that is
// not urgent waits for it at most kTransferWaitMax.
constexpr auto kTransferQuiet = path::Time(3) * 1000;
constexpr auto kTransferWaitMax = path::Time(120) * 1000;

// While another account's session probes, and while nothing is due.
constexpr auto kBusyRetry = crl::time(1000);
constexpr auto kIdleRetry = crl::time(60) * 1000;

// A race all of whose paths dropped out is the network: again after this,
// doubled each time up to the maximum.
constexpr auto kRaceBackoffMin = path::Time(2) * 1000;
constexpr auto kRaceBackoffMax = path::Time(60) * 1000;

constexpr auto kMaxFileSize = 64 * 1024;

struct State {
	std::mutex mutex;
	bool loaded = false;
	QJsonObject probe; // pluma_probe as it came, kept in the file
	path::Params params;
	// Until when the probes rest: every probe of a round was closed right
	// after resPQ. The gateway does so when it knows no probe and when its
	// limits refuse one (the server's task 113 brief, «Контракт пробы»), so
	// the rest lasts until the next app config or failed_ttl_s, not for good.
	path::Time unsupportedUntil = 0;
	path::Table table;
	path::Paths paths;
	std::vector<std::string> fingerprint;
	crl::time fingerprintAt = 0;
	bool fingerprinted = false;
	std::string key;
	std::string current;

	uint64 roundId = 0;
	bool running = false;
	std::string roundKey;
	path::Kind roundKind = path::Kind::Gate;
	bool gateDue = true;
	path::Time gateAt = 0;
	path::Time gateBackoff = 0;
	bool startRank = true;
	path::Time rankAt = 0;
	path::Time lastSuspect = 0;
	path::Time lastNetworkRank = 0;
	path::Time lastRound = 0;
	std::vector<path::Result> carried;

	std::string deferredTo;
	path::Time deferredSince = 0;

	uint64 version = 0;
};

std::atomic<path::Time> FileActivityAt = 0;
std::atomic<path::Time> UserActiveAt = 0;

[[nodiscard]] State &Global() {
	static State result;
	return result;
}

// Main thread alone.
[[nodiscard]] rpl::event_stream<> &Switches() {
	static auto result = rpl::event_stream<>();
	return result;
}

[[nodiscard]] rpl::event_stream<> &NetworkChanges() {
	static auto result = rpl::event_stream<>();
	return result;
}

[[nodiscard]] path::Time Now() {
	return path::Time(QDateTime::currentMSecsSinceEpoch());
}

[[nodiscard]] QString FilePath() {
	return cWorkingDir() + u"tdata/pluma_edge_paths"_q;
}

[[nodiscard]] bool Transferring(path::Time now) {
	return now - FileActivityAt.load() < kTransferQuiet;
}

// --- The fingerprint of the network ------------------------------------------

[[nodiscard]] QString Prefix(const QHostAddress &ip, int length) {
	if (ip.protocol() == QAbstractSocket::IPv4Protocol) {
		const auto bits = std::clamp(length, 0, 32);
		const auto mask = bits ? (~quint32(0) << (32 - bits)) : quint32(0);
		return QHostAddress(ip.toIPv4Address() & mask).toString()
			+ '/'
			+ QString::number(bits);
	}
	auto address = ip.toIPv6Address();
	const auto bits = std::clamp(length, 0, 128);
	for (auto i = 0; i != 16; ++i) {
		const auto keep = std::clamp(bits - 8 * i, 0, 8);
		address[i] &= quint8((0xFF00 >> keep) & 0xFF);
	}
	return QHostAddress(address).toString() + '/' + QString::number(bits);
}

// The kinds of the interfaces that are up and the prefixes of their
// addresses: no SSID, no location, no permission. The key hashes it; no
// address is kept or logged.
[[nodiscard]] std::vector<std::string> Fingerprint() {
	auto result = std::vector<std::string>();
	for (const auto &face : QNetworkInterface::allInterfaces()) {
		const auto flags = face.flags();
		if (!(flags & QNetworkInterface::IsUp)
			|| !(flags & QNetworkInterface::IsRunning)
			|| (flags & QNetworkInterface::IsLoopBack)) {
			continue;
		}
		for (const auto &entry : face.addressEntries()) {
			const auto ip = entry.ip();
			const auto length = entry.prefixLength();
			if (ip.isNull()
				|| ip.isLoopback()
				|| ip.isLinkLocal()
				|| length < 0) {
				continue;
			}
			result.push_back((QString::number(int(face.type()))
				+ ':'
				+ Prefix(ip, length)).toStdString());
		}
	}
	return result;
}

// Under the mutex: the key of the network from the country and the
// fingerprint; another one than before is a new network.
void Rekey(State &state, path::Time now, bool askConfig) {
	if (!state.fingerprinted) {
		return;
	}
	const auto key = path::NetworkKey(
		state.params.country,
		state.fingerprint);
	if (key == state.key) {
		return;
	}
	const auto first = state.key.empty();
	state.key = key;
	if (first) {
		return;
	}
	LOG(("MTP Info: the network changed, the paths to %1 race again."
		).arg(kEdgeDcId));
	state.gateDue = true;
	state.gateAt = state.gateBackoff = 0;
	state.carried.clear();
	state.deferredTo.clear();
	if (now - state.lastNetworkRank >= kNetworkRankEvery) {
		state.lastNetworkRank = now;
		state.rankAt = now;
	}
	if (askConfig) {
		crl::on_main([] {
			NetworkChanges().fire({});
		});
	}
}

void RefreshFingerprint(State &state) {
	{
		const auto lock = std::lock_guard(state.mutex);
		const auto now = crl::now();
		if (state.fingerprinted && now - state.fingerprintAt < kFingerprintEvery) {
			return;
		}
		state.fingerprintAt = now;
	}
	auto parts = Fingerprint();
	const auto lock = std::lock_guard(state.mutex);
	state.fingerprinted = true;
	state.fingerprint = std::move(parts);
	Rekey(state, Now(), true);
}

// --- tdata/pluma_edge_paths --------------------------------------------------

[[nodiscard]] const char *OutcomeName(path::Outcome outcome) {
	switch (outcome) {
	case path::Outcome::Ok: return "ok";
	case path::Outcome::Slow: return "slow";
	case path::Outcome::Frozen: return "frozen";
	case path::Outcome::Failed: return "failed";
	case path::Outcome::Unsupported: return "unsupported";
	}
	Unexpected("Outcome in OutcomeName.");
}

[[nodiscard]] std::optional<path::Outcome> OutcomeFromName(
		const QString &name) {
	for (const auto outcome : {
			path::Outcome::Ok,
			path::Outcome::Slow,
			path::Outcome::Frozen,
			path::Outcome::Failed }) {
		if (name == QLatin1String(OutcomeName(outcome))) {
			return outcome;
		}
	}
	return std::nullopt;
}

[[nodiscard]] std::map<std::string, path::Field> Fields(
		const QJsonObject &object) {
	auto result = std::map<std::string, path::Field>();
	for (auto i = object.begin(); i != object.end(); ++i) {
		auto &field = result[i.key().toStdString()];
		if (i.value().isDouble()) {
			field.number = i.value().toDouble();
		} else if (i.value().isString()) {
			field.text = i.value().toString().toStdString();
		}
	}
	return result;
}

[[nodiscard]] QJsonObject Serialize(const State &state) {
	auto networks = QJsonArray();
	for (const auto &network : state.table.networks) {
		auto paths = QJsonArray();
		for (const auto &path : network.paths) {
			paths.push_back(QJsonObject{
				{ u"id"_q, QString::fromStdString(path.id) },
				{ u"score"_q, double(path.score) },
				{ u"outcome"_q, QLatin1String(OutcomeName(path.outcome)) },
				{ u"at"_q, double(path.at) },
				{ u"misses"_q, int(path.misses) },
				{ u"count"_q, int(path.count) },
				{ u"bad_until"_q, double(path.badUntil) },
				{ u"failed_until"_q, double(path.failedUntil) },
			});
		}
		networks.push_back(QJsonObject{
			{ u"key"_q, QString::fromStdString(network.key) },
			{ u"at"_q, double(network.at) },
			{ u"best"_q, QString::fromStdString(network.best) },
			{ u"switched"_q, double(network.switchedAt) },
			{ u"ranked"_q, double(network.rankedAt) },
			{ u"pending"_q, QString::fromStdString(network.pending) },
			{ u"pending_at"_q, double(network.pendingAt) },
			{ u"paths"_q, paths },
		});
	}
	auto result = QJsonObject{
		{ u"v"_q, 1 },
		{ u"networks"_q, networks },
	};
	if (!state.probe.isEmpty()) {
		result.insert(u"probe"_q, state.probe);
	}
	return result;
}

[[nodiscard]] path::Time TimeOf(const QJsonValue &value) {
	const auto number = value.toDouble();
	return (std::isfinite(number) && number >= 0.) ? path::Time(number) : 0;
}

// What is not as Serialize writes it is skipped.
void Deserialize(State &state, const QJsonObject &object) {
	if (object.value(u"v"_q).toDouble() != 1.) {
		return;
	}
	const auto probe = object.value(u"probe"_q).toObject();
	if (const auto params = path::ParseParams(Fields(probe))) {
		state.probe = probe;
		state.params = *params;
	}
	for (const auto &entry : object.value(u"networks"_q).toArray()) {
		const auto data = entry.toObject();
		auto network = path::Network{
			.key = data.value(u"key"_q).toString().toStdString(),
			.at = TimeOf(data.value(u"at"_q)),
			.best = data.value(u"best"_q).toString().toStdString(),
			.switchedAt = TimeOf(data.value(u"switched"_q)),
			.rankedAt = TimeOf(data.value(u"ranked"_q)),
			.pending = data.value(u"pending"_q).toString().toStdString(),
			.pendingAt = TimeOf(data.value(u"pending_at"_q)),
		};
		if (network.key.size() != 16
			|| int(state.table.networks.size()) >= path::kMaxNetworks) {
			continue;
		}
		for (const auto &item : data.value(u"paths"_q).toArray()) {
			const auto fields = item.toObject();
			const auto outcome = OutcomeFromName(
				fields.value(u"outcome"_q).toString());
			const auto id = fields.value(u"id"_q).toString().toStdString();
			if (!outcome || id.empty()) {
				continue;
			}
			network.paths.push_back({
				.id = id,
				.score = TimeOf(fields.value(u"score"_q)),
				.outcome = *outcome,
				.at = TimeOf(fields.value(u"at"_q)),
				.misses = uint8_t(fields.value(u"misses"_q).toInt() & 0x0F),
				.count = uint8_t(std::clamp(
					fields.value(u"count"_q).toInt(),
					0,
					path::kHistory)),
				.badUntil = TimeOf(fields.value(u"bad_until"_q)),
				.failedUntil = TimeOf(fields.value(u"failed_until"_q)),
			});
		}
		state.table.networks.push_back(std::move(network));
	}
}

// Under the mutex: the memory of the last run, read once.
void LoadOnce(State &state) {
	if (state.loaded) {
		return;
	}
	state.loaded = true;
	auto file = QFile(FilePath());
	if (!file.open(QIODevice::ReadOnly)) {
		return;
	}
	const auto document = QJsonDocument::fromJson(file.read(kMaxFileSize));
	if (document.isObject()) {
		Deserialize(state, document.object());
	}
}

struct Snapshot {
	QByteArray data;
	uint64 version = 0;
};

// Under the mutex: what to write after it.
[[nodiscard]] Snapshot Changed(State &state) {
	return {
		.data = QJsonDocument(Serialize(state)).toJson(
			QJsonDocument::Compact),
		.version = ++state.version,
	};
}

// Without the mutex: the newest snapshot wins.
void Write(const Snapshot &snapshot) {
	static auto mutex = std::mutex();
	static auto written = uint64(0);
	const auto lock = std::lock_guard(mutex);
	if (snapshot.version <= written) {
		return;
	}
	written = snapshot.version;
	auto file = QSaveFile(FilePath());
	if (!file.open(QIODevice::WriteOnly)
		|| file.write(snapshot.data) != snapshot.data.size()
		|| !file.commit()) {
		LOG(("MTP Error: could not keep the paths of the networks."));
	}
}

// --- The choice --------------------------------------------------------------

[[nodiscard]] QString Name(const std::string &id) {
	return QString::fromStdString(id);
}

void FireSwitch() {
	crl::on_main([] {
		Switches().fire({});
	});
}

// Under the mutex: the path chosen for this network; the sessions move
// unless they use it already. Not urgent, it waits for a transfer.
void Switch(
		State &state,
		path::Network &network,
		const std::string &to,
		bool urgent,
		path::Time now) {
	network.best = to;
	network.switchedAt = now;
	network.pending.clear();
	if (to == state.current) {
		state.deferredTo.clear();
		return;
	} else if (!urgent && Transferring(now)) {
		if (state.deferredTo.empty()) {
			state.deferredSince = now;
		}
		state.deferredTo = to;
		LOG(("MTP Info: datacenter %1 will go through %2 after the transfer."
			).arg(kEdgeDcId
			).arg(Name(to)));
		return;
	}
	state.deferredTo.clear();
	LOG(("MTP Info: datacenter %1 goes through %2%3."
		).arg(kEdgeDcId
		).arg(Name(to)
		).arg(urgent ? u" at once"_q : QString()));
	FireSwitch();
}

} // namespace

struct PathRound {
	uint64 id = 0;
	path::Kind kind = path::Kind::Gate;
	std::vector<QString> first = {};
	std::vector<QString> later = {};
	QString current = {};
	path::Params params = {};
	std::vector<path::Result> results = {};
	bool laterStarted = false;
};

struct PathProber::Probe {
	explicit Probe(not_null<QThread*> thread) : timer(thread) {
	}

	QString id;
	bool edge = false;
	ConnectionPointer connection;
	crl::time started = 0;
	crl::time ready = 0;
	crl::time sent = 0;
	crl::time rtt = 0;
	path::Watch watch;
	path::Speed speed;
	std::optional<path::AnswerReader> reader;
	std::optional<path::Outcome> outcome;
	base::Timer timer;
};

namespace {

// Under the mutex: the round to run now, or how long until one may be due.
[[nodiscard]] std::optional<PathRound> Due(
		State &state,
		path::Time now,
		crl::time &wait) {
	wait = kIdleRetry;
	if (state.unsupportedUntil) {
		if (now < state.unsupportedUntil) {
			return std::nullopt;
		}
		state.unsupportedUntil = 0;
		state.gateDue = true;
		state.gateAt = 0;
	}
	if (state.key.empty() || state.current.empty()) {
		return std::nullopt;
	}
	if (!state.deferredTo.empty()) {
		if (!Transferring(now)
			|| now - state.deferredSince >= kTransferWaitMax) {
			LOG(("MTP Info: datacenter %1 goes through %2."
				).arg(kEdgeDcId
				).arg(Name(state.deferredTo)));
			state.deferredTo.clear();
			FireSwitch();
		} else {
			wait = kBusyRetry;
		}
	}
	if (state.running) {
		wait = kBusyRetry;
		return std::nullopt;
	}
	const auto network = path::Fresh(state.table, state.key, now);
	const auto make = [&](
			path::Kind kind,
			const std::vector<std::string> &first,
			const std::vector<std::string> &later) {
		const auto convert = [](const std::vector<std::string> &ids) {
			return ranges::views::all(ids)
				| ranges::views::transform(Name)
				| ranges::to_vector;
		};
		state.running = true;
		state.roundKey = state.key;
		state.roundKind = kind;
		return PathRound{
			.id = ++state.roundId,
			.kind = kind,
			.first = convert(first),
			.later = convert(later),
			.current = Name(state.current),
			.params = state.params,
		};
	};
	if (state.gateDue) {
		if (now < state.gateAt) {
			wait = std::min(wait, crl::time(state.gateAt - now));
			return std::nullopt;
		}
		state.gateDue = false;
		auto race = path::GateRace(state.paths, network, now);
		if (!state.carried.empty()) {
			// The paths that failed the rank before this race stay out
			// of it, unless no other one is left.
			const auto failed = [&](const std::string &id) {
				return ranges::contains(
					state.carried,
					id,
					&path::Result::id);
			};
			auto first = race.first | ranges::views::remove_if(failed)
				| ranges::to_vector;
			auto later = race.later | ranges::views::remove_if(failed)
				| ranges::to_vector;
			if (first.empty()) {
				std::swap(first, later);
			}
			if (!first.empty()) {
				race = { std::move(first), std::move(later) };
			}
		}
		return make(path::Kind::Gate, race.first, race.later);
	}
	if (base::take(state.startRank)
		&& (!network
			|| now - network->rankedAt >= state.params.rankMinInterval)) {
		const auto at = now + kStartRankDelay;
		state.rankAt = state.rankAt ? std::min(state.rankAt, at) : at;
	}
	auto due = state.rankAt;
	if (network
		&& network->rankedAt
		&& UserActiveAt.load() > state.lastRound) {
		const auto periodic = network->rankedAt + state.params.reprobe;
		due = due ? std::min(due, periodic) : periodic;
	}
	if (!due) {
		return std::nullopt;
	} else if (now < due) {
		wait = std::min(wait, crl::time(due - now));
		return std::nullopt;
	}
	state.rankAt = 0;
	return make(
		path::Kind::Rank,
		path::RankPaths(state.paths, network, state.current, state.params),
		{});
}

// The round ended: into the memory, and the choice.
void Finished(
		uint64 id,
		std::vector<path::Result> results) {
	auto &state = Global();
	auto snapshot = Snapshot();
	{
		const auto lock = std::lock_guard(state.mutex);
		if (!state.running || id != state.roundId) {
			return;
		}
		const auto now = Now();
		const auto kind = state.roundKind;
		state.running = false;
		state.lastRound = now;
		const auto unsupported = !results.empty() && ranges::all_of(
			results,
			[](const path::Result &result) {
				return result.outcome == path::Outcome::Unsupported;
			});
		if (unsupported) {
			LOG(("MTP Info: the gateway answers no path probes, "
				"the edges choose until the next app config "
				"or failed_ttl_s."));
			state.unsupportedUntil = now + state.params.failedTtl;
			return;
		} else if (state.roundKey != state.key) {
			// Probes of another network.
			return;
		}
		auto &network = path::Use(state.table, state.key, now);
		if (kind == path::Kind::Gate) {
			results.insert(
				begin(results),
				begin(state.carried),
				end(state.carried));
			state.carried.clear();
		}
		path::Record(network, results, kind, state.params, now);
		if (kind == path::Kind::Gate) {
			const auto winner = path::GateWinner(results, state.current);
			if (winner.empty()) {
				// Every path dropped out: the network, not the paths.
				state.gateBackoff = std::clamp(
					state.gateBackoff * 2,
					kRaceBackoffMin,
					kRaceBackoffMax);
				state.gateDue = true;
				state.gateAt = now + state.gateBackoff;
			} else {
				state.gateBackoff = 0;
				if (winner != state.current) {
					Switch(state, network, winner, true, now);
				} else if (network.best.empty()) {
					network.best = winner;
				}
			}
		} else {
			const auto choice = path::Choose(
				network,
				results,
				state.paths,
				state.current,
				state.params,
				now);
			if (!choice.to.empty()) {
				Switch(state, network, choice.to, choice.now, now);
			} else if (choice.now) {
				// The current path failed and no other one was ranked:
				// the rest race.
				state.carried = results;
				state.gateDue = true;
				state.gateAt = 0;
			}
			if (choice.again) {
				state.rankAt = state.rankAt
					? std::min(state.rankAt, choice.again)
					: choice.again;
			}
		}
		snapshot = Changed(state);
	}
	Write(snapshot);
}

void Aborted(uint64 id) {
	auto &state = Global();
	const auto lock = std::lock_guard(state.mutex);
	if (state.running && id == state.roundId) {
		state.running = false;
		if (state.roundKind == path::Kind::Gate) {
			state.gateDue = true;
		} else if (!state.rankAt) {
			state.rankAt = Now();
		}
	}
}

[[nodiscard]] bool DirectEndpoint(
		not_null<Instance*> instance,
		QString &address,
		int &port,
		bytes::vector &secret) {
	using Variants = DcOptions::Variants;
	const auto variants = instance->dcOptions().lookup(
		kEdgeDcId,
		DcType::Regular,
		false);
	for (const auto type : { Variants::IPv4, Variants::IPv6 }) {
		const auto &list = variants.data[type][Variants::Tcp];
		if (!list.empty()) {
			address = QString::fromStdString(list.front().ip);
			port = list.front().port;
			secret = list.front().secret;
			return true;
		}
	}
	return false;
}

} // namespace

QString PathDirect() {
	return Name(path::kDirect);
}

std::vector<QString> PathOrder(
		const std::vector<QString> &edges,
		bool edgesFirst) {
	auto &state = Global();
	{
		const auto lock = std::lock_guard(state.mutex);
		LoadOnce(state);
	}
	RefreshFingerprint(state);
	const auto lock = std::lock_guard(state.mutex);
	state.paths = path::Paths{
		.edges = edges
			| ranges::views::transform([](const QString &url) {
				return url.toStdString();
			})
			| ranges::to_vector,
		.edgesFirst = edgesFirst,
	};
	const auto now = Now();
	if (now < state.unsupportedUntil || state.key.empty()) {
		return {};
	}
	const auto order = path::ConnectOrder(
		state.paths,
		path::Fresh(state.table, state.key, now),
		now);
	return order | ranges::views::transform(Name) | ranges::to_vector;
}

bool PathFroze() {
	auto &state = Global();
	auto snapshot = Snapshot();
	{
		const auto lock = std::lock_guard(state.mutex);
		LoadOnce(state);
		const auto now = Now();
		if (now < state.unsupportedUntil || state.key.empty()) {
			return false;
		}
		auto &network = path::Use(state.table, state.key, now);
		path::MarkFrozen(network, path::kDirect, state.params, now);
		const auto to = path::BestKnown(
			network,
			state.paths,
			path::kDirect,
			now);
		if (!to.empty()) {
			Switch(state, network, to, true, now);
		} else {
			state.gateDue = true;
			state.gateAt = 0;
		}
		snapshot = Changed(state);
	}
	Write(snapshot);
	return true;
}

void PathFileActivity() {
	FileActivityAt = Now();
}

void PathUserActive() {
	UserActiveAt = Now();
}

void PathApplyAppConfig(const MTPJSONValue *value) {
	auto object = QJsonObject();
	auto params = path::Params();
	if (value) {
		const auto json = EdgeJson(*value);
		const auto parsed = json.isObject()
			? path::ParseParams(Fields(json.toObject()))
			: std::nullopt;
		if (parsed) {
			object = json.toObject();
			params = *parsed;
		} else {
			LOG(("API Error: pluma_probe of the app config is not valid."));
		}
	}
	auto &state = Global();
	auto snapshot = Snapshot();
	{
		const auto lock = std::lock_guard(state.mutex);
		LoadOnce(state);
		if (base::take(state.unsupportedUntil)) {
			state.gateDue = true;
			state.gateAt = 0;
		}
		if (state.probe == object) {
			return;
		}
		state.probe = object;
		state.params = params;
		Rekey(state, Now(), false);
		snapshot = Changed(state);
	}
	Write(snapshot);
}

rpl::producer<> PathSwitches() {
	return Switches().events();
}

rpl::producer<> PathNetworkChanges() {
	return NetworkChanges().events();
}

PathProber::PathProber(
	not_null<Instance*> instance,
	not_null<QThread*> thread)
: _instance(instance)
, _thread(thread)
, _tick(thread, [=] { tick(); })
, _suspect(thread, [=] {
	auto &state = Global();
	{
		const auto lock = std::lock_guard(state.mutex);
		const auto now = Now();
		if (now < state.unsupportedUntil
			|| now - state.lastSuspect < kSuspectEvery) {
			return;
		}
		state.lastSuspect = now;
		state.rankAt = now;
	}
	DEBUG_LOG(("MTP Info: no answer for %1 ms, the paths rank."
		).arg(_suspectTimeout));
	tick();
})
, _stagger(thread, [=] { startLater(); })
, _late(thread, [=] { complete(); })
, _settle(thread, [=] { settle(); }) {
}

PathProber::~PathProber() {
	if (_round) {
		Aborted(_round->id);
	}
}

void PathProber::connected(const QString &path) {
	auto &state = Global();
	{
		const auto lock = std::lock_guard(state.mutex);
		state.current = path.toStdString();
		if (state.deferredTo == state.current) {
			state.deferredTo.clear();
		}
	}
	tick();
}

void PathProber::sent() {
	if (_suspectTimeout && !_suspect.isActive()) {
		_suspect.callOnce(_suspectTimeout);
	}
}

void PathProber::received() {
	_suspect.cancel();
}

void PathProber::tick() {
	if (_round) {
		return;
	}
	auto &state = Global();
	RefreshFingerprint(state);
	auto wait = crl::time();
	auto round = std::optional<PathRound>();
	{
		const auto lock = std::lock_guard(state.mutex);
		const auto now = Now();
		_suspectTimeout = (now < state.unsupportedUntil)
			? 0
			: state.params.suspect;
		round = Due(state, now, wait);
	}
	if (round) {
		start(std::move(*round));
	} else {
		_tick.callOnce(std::max(wait, crl::time(1)));
	}
}

void PathProber::start(PathRound round) {
	_tick.cancel();
	_round = std::make_unique<PathRound>(std::move(round));
	DEBUG_LOG(("MTP Info: the paths to %1 %2, %3 first."
		).arg(kEdgeDcId
		).arg((_round->kind == path::Kind::Gate) ? u"race"_q : u"rank"_q
		).arg(int(_round->first.size())));
	for (const auto &id : _round->first) {
		startProbe(id);
	}
	if (_round->kind == path::Kind::Gate && !_round->later.empty()) {
		_stagger.callOnce(std::max(_round->params.raceStagger, path::Time(1)));
	}
	_settle.callOnce(0);
}

void PathProber::startProbe(const QString &id) {
	const auto &params = _round->params;
	auto owned = std::make_unique<Probe>(_thread);
	const auto probe = owned.get();
	_probes.push_back(std::move(owned));
	probe->id = id;
	probe->edge = (id != PathDirect());
	probe->started = crl::now();
	probe->watch = path::Watch{
		.stall = params.stall,
		.deadline = probe->started + params.deadline,
	};
	auto address = QString();
	auto port = 0;
	auto secret = bytes::vector();
	if (probe->edge) {
		address = id;
		port = 443;
	} else if (!DirectEndpoint(_instance, address, port, secret)) {
		finish(probe, path::Outcome::Failed);
		return;
	}
	probe->connection = ConnectionPointer::New<TcpConnection>(
		_instance,
		_thread.get(),
		ProxyData());
	const auto tcp = static_cast<TcpConnection*>(probe->connection.get());
	tcp->setPathProbe({
		.ready = [=] { probeReady(probe); },
		.read = [=](int count) {
			const auto now = crl::now();
			probe->watch.lastByte = now;
			probe->watch.anyByte = true;
			if (probe->sent) {
				probe->speed.read(count, now);
				probe->watch.answered = true;
			}
		},
		.packet = [=](bytes::const_span packet) {
			probePacket(probe, packet);
		},
	});
	QObject::connect(tcp, &AbstractConnection::connected, [=] {
		probeAnswered(probe);
	});
	QObject::connect(tcp, &AbstractConnection::error, [=](qint32) {
		probeClosed(probe);
	});
	QObject::connect(tcp, &AbstractConnection::disconnected, [=] {
		probeClosed(probe);
	});
	probe->timer.setCallback([=] { probeCheck(probe); });
	probe->timer.callOnce(params.deadline);
	const auto protocolDcId = int16(_instance->isTestMode()
		? (kTestModeDcIdShift + kEdgeDcId)
		: kEdgeDcId);
	InvokeQueued(tcp, [=] {
		tcp->connectToServer(address, port, secret, protocolDcId, false);
	});
}

// The socket connected and req_pq_multi went: the connection took this
// long, which stands for the round trip until resPQ. An edge's socket has
// carried TLS and the WebSocket answer by now.
void PathProber::probeReady(not_null<Probe*> probe) {
	const auto now = crl::now();
	probe->ready = now;
	probe->watch.from = now + (now - probe->started);
	if (probe->edge) {
		probe->watch.anyByte = true;
		probe->watch.lastByte = now;
	}
	probeCheck(probe);
}

// resPQ to our req_pq_multi: pluma.probe on the same connection.
void PathProber::probeAnswered(not_null<Probe*> probe) {
	if (probe->outcome) {
		return;
	}
	const auto &params = _round->params;
	const auto now = crl::now();
	probe->rtt = now - probe->ready;
	probe->sent = now;
	uint8_t nonce[path::kNonceSize];
	bytes::set_random(bytes::make_span(nonce));
	auto pad = std::vector<uint8_t>(size_t(params.up));
	if (!pad.empty()) {
		bytes::set_random(bytes::make_span(pad));
	}
	const auto down = (_round->kind == path::Kind::Gate)
		? params.gateDown
		: params.rankDown;
	const auto message = path::ProbeRequest(nonce, down, pad);
	probe->reader.emplace(nonce, down);
	probe->watch.from = now + probe->rtt;
	probe->watch.answered = false;
	probe->watch.deadline = now + params.deadline;
	static_cast<TcpConnection*>(probe->connection.get())->sendPathProbe(
		bytes::make_span(message));
	probeCheck(probe);
}

void PathProber::probePacket(
		not_null<Probe*> probe,
		bytes::const_span packet) {
	if (probe->outcome) {
		return;
	} else if (!probe->reader) {
		finish(probe, path::Outcome::Failed);
		return;
	}
	using Step = path::AnswerReader::Step;
	const auto step = probe->reader->feed(
		reinterpret_cast<const uint8_t*>(packet.data()),
		size_t(packet.size()));
	if (step == Step::Bad) {
		finish(probe, path::Outcome::Failed);
	} else if (step == Step::Done) {
		finish(probe, path::Outcome::Ok);
	}
}

// Closed: before a byte of the answer to pluma.probe that follows resPQ,
// the gateway does not probe (or refused this one), which says nothing of
// the path.
void PathProber::probeClosed(not_null<Probe*> probe) {
	if (probe->outcome) {
		return;
	}
	finish(probe, (probe->sent && !probe->speed.bytes)
		? path::Outcome::Unsupported
		: path::Outcome::Failed);
}

void PathProber::probeCheck(not_null<Probe*> probe) {
	if (probe->outcome) {
		return;
	}
	const auto now = crl::now();
	if (const auto outcome = path::Overdue(probe->watch, now)) {
		finish(probe, *outcome);
		return;
	}
	probe->timer.callOnce(
		std::max(path::NextCheck(probe->watch) - now, crl::time(1)));
}

void PathProber::finish(not_null<Probe*> probe, path::Outcome outcome) {
	probe->outcome = outcome;
	probe->timer.cancel();
	_round->results.push_back({
		.id = probe->id.toStdString(),
		.outcome = outcome,
		.rtt = probe->rtt,
		.speed = probe->speed.bytesPerSecond(),
	});
	DEBUG_LOG(("MTP Info: the path %1: %2, rtt %3 ms, %4 bytes a second."
		).arg(probe->id
		).arg(QString::fromLatin1(OutcomeName(outcome))
		).arg(probe->rtt
		).arg(int64(probe->speed.bytesPerSecond())));
	// The connection calls back from inside its own reads.
	_settle.callOnce(0);
}

bool PathProber::gateDone() const {
	const auto passed = [&](const QString &id) {
		return ranges::any_of(_round->results, [&](const path::Result &r) {
			return (r.outcome == path::Outcome::Ok)
				&& (QString::fromStdString(r.id) == id);
		});
	};
	if (passed(_round->current)) {
		return true;
	}
	const auto other = ranges::any_of(
		_round->results,
		[](const path::Result &r) { return r.outcome == path::Outcome::Ok; });
	const auto currentRunning = ranges::any_of(_probes, [&](
			const std::unique_ptr<Probe> &probe) {
		return (probe->id == _round->current) && !probe->outcome;
	});
	return other && !currentRunning;
}

void PathProber::settle() {
	if (!_round) {
		return;
	}
	_probes.erase(ranges::remove_if(_probes, [](
			const std::unique_ptr<Probe> &probe) {
		return probe->outcome.has_value();
	}), end(_probes));
	if (_round->kind == path::Kind::Gate) {
		if (gateDone()) {
			complete();
			return;
		}
		const auto passed = ranges::any_of(
			_round->results,
			[](const path::Result &r) { return r.outcome == path::Outcome::Ok; });
		if (passed && !_late.isActive()) {
			// Another path passed while the current one still runs: it
			// has race_stagger more.
			_late.callOnce(std::max(_round->params.raceStagger, path::Time(1)));
		}
		if (_probes.empty() && !_round->laterStarted && !passed) {
			// All the first dropped out: the rest at once.
			startLater();
			return;
		}
	}
	if (_probes.empty()) {
		complete();
	}
}

void PathProber::startLater() {
	if (!_round || _round->laterStarted) {
		return;
	}
	_round->laterStarted = true;
	_stagger.cancel();
	const auto passed = ranges::any_of(
		_round->results,
		[](const path::Result &r) { return r.outcome == path::Outcome::Ok; });
	if (!passed) {
		for (const auto &id : _round->later) {
			startProbe(id);
		}
	}
	_settle.callOnce(0);
}

void PathProber::complete() {
	if (!_round) {
		return;
	}
	_stagger.cancel();
	_late.cancel();
	_settle.cancel();
	_probes.clear();
	const auto round = base::take(_round);
	Finished(round->id, std::move(round->results));
	tick();
}

} // namespace MTP::details
