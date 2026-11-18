/*
This file is part of Pluma, built on Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

// The rules of choosing the path to datacenter 1 by probes (task 113 of
// the server repository, ADR 0073): the parameters of pluma_probe, the
// bytes of pluma.probe and pluma.probeData, what a probe found, the score
// of a path, the memory by network and the choice between the paths. Plain
// C++ without Qt: path-selection/rules_test.cpp checks it.
namespace MTP::details::path {

// Milliseconds of the wall clock: the memory outlives the process.
using Time = int64_t;

// The path ids: the direct path, or an edge's wss:// URL.
inline const std::string kDirect = "direct";

// --- pluma_probe of help.getAppConfig ----------------------------------------

struct Params {
	std::string country; // ISO 3166-1 alpha-2 of the client's address
	int gateDown = 65536;
	int rankDown = 196608;
	int up = 20480;
	Time stall = 1500;
	Time deadline = 6000;
	Time suspect = 4000;
	Time reprobe = Time(21600) * 1000;
	Time rankMinInterval = Time(1800) * 1000;
	Time minDwell = Time(600) * 1000;
	double switchRatio = 0.7;
	double switchRatioNow = 0.25;
	Time edgeProbeIfDirect = 1500;
	Time badTtl = Time(86400) * 1000;
	Time failedTtl = Time(300) * 1000;
	Time raceStagger = 800;
	Time confirm = Time(60) * 1000;
};

// A value of the pluma_probe object: a number, a string, or neither.
struct Field {
	std::optional<double> number;
	std::optional<std::string> text;
};

namespace details {

struct NumberRule {
	const char *key;
	double min;
	double max;
	bool whole;
	void (*set)(Params &params, double value);
};

inline constexpr Time kSecond = 1000;

inline const NumberRule kNumberRules[] = {
	{ "gate_down", 16384, 524288, true,
		[](Params &p, double v) { p.gateDown = int(v); } },
	{ "rank_down", 16384, 524288, true,
		[](Params &p, double v) { p.rankDown = int(v); } },
	{ "up", 0, 65536, true,
		[](Params &p, double v) { p.up = int(v); } },
	{ "stall_ms", 300, 10000, true,
		[](Params &p, double v) { p.stall = Time(v); } },
	{ "deadline_ms", 1000, 30000, true,
		[](Params &p, double v) { p.deadline = Time(v); } },
	{ "suspect_ms", 1000, 60000, true,
		[](Params &p, double v) { p.suspect = Time(v); } },
	{ "reprobe_s", 600, 604800, true,
		[](Params &p, double v) { p.reprobe = Time(v) * kSecond; } },
	{ "rank_min_interval_s", 60, 86400, true,
		[](Params &p, double v) { p.rankMinInterval = Time(v) * kSecond; } },
	{ "min_dwell_s", 0, 86400, true,
		[](Params &p, double v) { p.minDwell = Time(v) * kSecond; } },
	{ "switch_ratio", 0.05, 0.95, false,
		[](Params &p, double v) { p.switchRatio = v; } },
	{ "switch_ratio_now", 0.01, 0.95, false,
		[](Params &p, double v) { p.switchRatioNow = v; } },
	{ "edge_probe_if_direct_ms", 100, 60000, true,
		[](Params &p, double v) { p.edgeProbeIfDirect = Time(v); } },
	{ "bad_ttl_s", 60, 604800, true,
		[](Params &p, double v) { p.badTtl = Time(v) * kSecond; } },
	{ "failed_ttl_s", 10, 86400, true,
		[](Params &p, double v) { p.failedTtl = Time(v) * kSecond; } },
	{ "race_stagger_ms", 0, 10000, true,
		[](Params &p, double v) { p.raceStagger = Time(v); } },
	{ "confirm_s", 10, 3600, true,
		[](Params &p, double v) { p.confirm = Time(v) * kSecond; } },
};

} // namespace details

// {"v":1,"country":"RU","gate_down":65536,...}: v is 1; country is empty
// or two capital letters; every number known here is a number in its range
// (whole where it counts bytes or time), the stall shorter than the
// deadline, switch_ratio_now not above switch_ratio. A key missing takes
// its default, a key unknown here is skipped (a later server may add
// some). Anything else: nullopt, the whole value is not taken.
[[nodiscard]] inline std::optional<Params> ParseParams(
		const std::map<std::string, Field> &fields) {
	const auto version = fields.find("v");
	if (version == end(fields)
		|| !version->second.number
		|| *version->second.number != 1.) {
		return std::nullopt;
	}
	auto result = Params();
	if (const auto country = fields.find("country");
			country != end(fields)) {
		if (!country->second.text) {
			return std::nullopt;
		}
		const auto &text = *country->second.text;
		const auto capital = [](char c) { return c >= 'A' && c <= 'Z'; };
		if (!text.empty()
			&& (text.size() != 2 || !capital(text[0]) || !capital(text[1]))) {
			return std::nullopt;
		}
		result.country = text;
	}
	for (const auto &rule : details::kNumberRules) {
		const auto i = fields.find(rule.key);
		if (i == end(fields)) {
			continue;
		} else if (!i->second.number) {
			return std::nullopt;
		}
		const auto value = *i->second.number;
		if (!std::isfinite(value)
			|| value < rule.min
			|| value > rule.max
			|| (rule.whole && value != std::floor(value))) {
			return std::nullopt;
		}
		rule.set(result, value);
	}
	if (result.stall >= result.deadline
		|| result.switchRatioNow > result.switchRatio) {
		return std::nullopt;
	}
	return result;
}

// --- pluma.probe and pluma.probeData -----------------------------------------
// pluma.probe#5c316d30 nonce:int128 down:int pad:bytes = pluma.Probe;
// pluma.probeData#6ab3780b nonce:int128 seq:int total:int server_ms:long
//   pad:bytes = pluma.ProbeData;
// Unencrypted messages (auth_key_id 0), little-endian; the gateway sends
// down, clamped to 16 to 512 KiB, in pads of 16 KiB, the last one the rest
// (docs/tasks/113-smart-path-selection.md of the server, «Контракт пробы»).

inline constexpr uint32_t kProbeId = 0x5C316D30U;
inline constexpr uint32_t kProbeDataId = 0x6AB3780BU;
inline constexpr int kNonceSize = 16;
inline constexpr int kChunk = 16384;
inline constexpr int kDownMin = 16384;
inline constexpr int kDownMax = 524288;
inline constexpr int kUpMax = 65536;

[[nodiscard]] inline int ClampDown(int down) {
	return std::clamp(down, kDownMin, kDownMax);
}

[[nodiscard]] inline int ChunkCount(int down) {
	return (ClampDown(down) + kChunk - 1) / kChunk;
}

namespace details {

inline void AppendUint32(std::vector<uint8_t> &to, uint32_t value) {
	for (auto i = 0; i != 4; ++i) {
		to.push_back(uint8_t(value >> (8 * i)));
	}
}

[[nodiscard]] inline uint32_t ReadUint32(const uint8_t *from) {
	return uint32_t(from[0])
		| (uint32_t(from[1]) << 8)
		| (uint32_t(from[2]) << 16)
		| (uint32_t(from[3]) << 24);
}

// The size of TL bytes of this length: the length, the data, the zeros up
// to a multiple of 4.
[[nodiscard]] inline size_t BytesSize(size_t length) {
	const auto prefix = (length < 254) ? 1 : 4;
	return (prefix + length + 3) / 4 * 4;
}

} // namespace details

// The message_data of pluma.probe; pad is at most kUpMax bytes.
[[nodiscard]] inline std::vector<uint8_t> ProbeRequest(
		const uint8_t (&nonce)[kNonceSize],
		int down,
		const std::vector<uint8_t> &pad) {
	auto result = std::vector<uint8_t>();
	result.reserve(4 + kNonceSize + 4 + details::BytesSize(pad.size()));
	details::AppendUint32(result, kProbeId);
	result.insert(end(result), nonce, nonce + kNonceSize);
	details::AppendUint32(result, uint32_t(down));
	const auto start = result.size();
	if (pad.size() < 254) {
		result.push_back(uint8_t(pad.size()));
	} else {
		result.push_back(254);
		result.push_back(uint8_t(pad.size()));
		result.push_back(uint8_t(pad.size() >> 8));
		result.push_back(uint8_t(pad.size() >> 16));
	}
	result.insert(end(result), begin(pad), end(pad));
	while ((result.size() - start) % 4) {
		result.push_back(0);
	}
	return result;
}

// Reads the answer of one probe, message by message.
class AnswerReader final {
public:
	enum class Step {
		More,
		Done,
		Bad,
	};

	AnswerReader(const uint8_t (&nonce)[kNonceSize], int down)
	: _down(ClampDown(down))
	, _total(ChunkCount(down)) {
		std::memcpy(_nonce, nonce, kNonceSize);
	}

	// An unencrypted message as the transport gives it: auth_key_id,
	// msg_id, message_data_length, message_data, maybe the padding of the
	// transport after it. Done after the last pluma.probeData; Bad for
	// anything but the next one, and for everything after Bad or Done.
	[[nodiscard]] Step feed(const uint8_t *data, size_t size) {
		if (_bad || _next == _total) {
			_bad = true;
			return Step::Bad;
		}
		const auto step = read(data, size);
		if (step == Step::Bad) {
			_bad = true;
		}
		return step;
	}

	// The pad bytes of the messages read whole.
	[[nodiscard]] int received() const {
		return _received;
	}

private:
	// 4 constructor, 16 nonce, 4 seq, 4 total, 8 server_ms.
	static constexpr auto kHeader = 36;

	[[nodiscard]] Step read(const uint8_t *data, size_t size) {
		if (size < 20) {
			return Step::Bad;
		}
		for (auto i = 0; i != 8; ++i) {
			if (data[i]) {
				return Step::Bad;
			}
		}
		const auto length = size_t(details::ReadUint32(data + 16));
		if (length > size - 20 || length < kHeader + 4) {
			return Step::Bad;
		}
		const auto object = data + 20;
		if (details::ReadUint32(object) != kProbeDataId
			|| std::memcmp(object + 4, _nonce, kNonceSize)
			|| int32_t(details::ReadUint32(object + 20)) != _next
			|| int32_t(details::ReadUint32(object + 24)) != _total) {
			return Step::Bad;
		}
		const auto pad = object + kHeader;
		const auto padSize = (pad[0] < 254)
			? size_t(pad[0])
			: (pad[0] == 254)
			? (size_t(pad[1]) | (size_t(pad[2]) << 8) | (size_t(pad[3]) << 16))
			: size_t(-1);
		const auto expected = (_next + 1 < _total)
			? size_t(kChunk)
			: size_t(_down - kChunk * (_total - 1));
		if (padSize != expected
			|| kHeader + details::BytesSize(padSize) != length) {
			return Step::Bad;
		}
		_received += int(padSize);
		return (++_next == _total) ? Step::Done : Step::More;
	}

	uint8_t _nonce[kNonceSize] = { 0 };
	int _down = 0;
	int _total = 0;
	int _next = 0;
	int _received = 0;
	bool _bad = false;

};

// --- What a probe found ------------------------------------------------------

enum class Outcome : uint8_t {
	Ok,          // every byte asked arrived
	Slow,        // not all by the deadline, but they kept coming
	Frozen,      // the path carried a byte, then none for the stall time
	Failed,      // no connection, closed, or no byte by the deadline
	Unsupported, // closed right after resPQ: no probes there, no verdict
};

[[nodiscard]] inline bool Answered(Outcome outcome) {
	return (outcome == Outcome::Ok) || (outcome == Outcome::Slow);
}

// The clock of a probe waiting for bytes. Silence counts from the later of
// the last byte and the write of the request plus the round trip (a path
// that freezes on the request's own bytes answers with none).
struct Watch {
	Time from = 0;
	Time lastByte = 0;
	bool anyByte = false;  // TLS, the WebSocket answer, resPQ or the answer
	bool answered = false; // a byte of the answer to the request
	Time stall = 0;
	Time deadline = 0;
};

// What the probe is at now; nullopt to wait for more.
[[nodiscard]] inline std::optional<Outcome> Overdue(
		const Watch &watch,
		Time now) {
	const auto silentFrom = std::max(watch.from, watch.lastByte);
	if (watch.anyByte && now - silentFrom >= watch.stall) {
		return Outcome::Frozen;
	} else if (now >= watch.deadline) {
		return watch.answered ? Outcome::Slow : Outcome::Failed;
	}
	return std::nullopt;
}

// When Overdue can say something next, unless a byte comes first.
[[nodiscard]] inline Time NextCheck(const Watch &watch) {
	const auto silentFrom = std::max(watch.from, watch.lastByte);
	return watch.anyByte
		? std::min(silentFrom + watch.stall, watch.deadline)
		: watch.deadline;
}

// The bytes of the answer timed off the socket: the speed is the bytes
// after the first read over the time from the first read to the last.
struct Speed {
	Time first = 0;
	Time last = 0;
	int64_t firstBytes = 0;
	int64_t bytes = 0;

	void read(int64_t count, Time now) {
		if (!bytes) {
			first = now;
			firstBytes = count;
		}
		bytes += count;
		last = now;
	}
	[[nodiscard]] double bytesPerSecond() const {
		const auto span = last - first;
		return (bytes > firstBytes && span > 0)
			? double(bytes - firstBytes) * 1000. / double(span)
			: 0.;
	}
};

// --- The score of a path -----------------------------------------------------

// The size of the notional answer whose time is the score.
inline constexpr auto kScoreBytes = 256 * 1024;

// rtt plus the time of 256 KiB at the speed, in milliseconds; nullopt
// without a speed.
[[nodiscard]] inline std::optional<Time> Score(Time rtt, double speed) {
	if (!(speed > 0.) || rtt < 0) {
		return std::nullopt;
	}
	return rtt + Time(std::ceil(double(kScoreBytes) * 1000. / speed));
}

// --- The memory by network ---------------------------------------------------

inline constexpr auto kMaxNetworks = 16;
inline constexpr auto kHistory = 4;
inline constexpr Time kFresh = Time(7) * 86400 * 1000;

struct PathRecord {
	std::string id;
	Time score = 0; // 0: unknown
	Outcome outcome = Outcome::Failed;
	Time at = 0;
	uint8_t misses = 0; // bit i: the probe i probes ago was not ok
	uint8_t count = 0;  // probes in misses, up to kHistory
	Time badUntil = 0;
	Time failedUntil = 0;

	friend inline bool operator==(
		const PathRecord &,
		const PathRecord &) = default;
};

struct Network {
	std::string key;
	Time at = 0; // last used
	std::string best;
	Time switchedAt = 0;
	Time rankedAt = 0;
	std::string pending; // a path that won one rank, waiting for another
	Time pendingAt = 0;
	std::vector<PathRecord> paths;

	friend inline bool operator==(const Network &, const Network &) = default;
};

struct Table {
	std::vector<Network> networks;

	friend inline bool operator==(const Table &, const Table &) = default;
};

// The network's record of this key when it was used within kFresh.
[[nodiscard]] inline const Network *Fresh(
		const Table &table,
		const std::string &key,
		Time now) {
	for (const auto &network : table.networks) {
		if (network.key == key) {
			return (now - network.at <= kFresh) ? &network : nullptr;
		}
	}
	return nullptr;
}

// The network's record, made (or emptied, when not fresh) as needed; the
// least recently used goes beyond kMaxNetworks.
[[nodiscard]] inline Network &Use(
		Table &table,
		const std::string &key,
		Time now) {
	auto &networks = table.networks;
	auto i = std::find_if(begin(networks), end(networks), [&](
			const Network &network) {
		return network.key == key;
	});
	if (i != end(networks) && now - i->at > kFresh) {
		*i = Network{ .key = key };
	} else if (i == end(networks)) {
		if (int(networks.size()) >= kMaxNetworks) {
			networks.erase(std::min_element(
				begin(networks),
				end(networks),
				[](const Network &a, const Network &b) { return a.at < b.at; }));
		}
		networks.push_back(Network{ .key = key });
		i = end(networks) - 1;
	}
	i->at = std::max(i->at, now);
	return *i;
}

[[nodiscard]] inline const PathRecord *Find(
		const Network *network,
		const std::string &id) {
	if (!network) {
		return nullptr;
	}
	for (const auto &path : network->paths) {
		if (path.id == id) {
			return &path;
		}
	}
	return nullptr;
}

[[nodiscard]] inline PathRecord &FindOrAdd(
		Network &network,
		const std::string &id) {
	for (auto &path : network.paths) {
		if (path.id == id) {
			return path;
		}
	}
	network.paths.push_back(PathRecord{ .id = id });
	return network.paths.back();
}

// Two of the last four probes not ok.
[[nodiscard]] inline bool Lossy(const PathRecord &path) {
	auto missed = 0;
	for (auto i = 0; i != std::min<int>(path.count, kHistory); ++i) {
		missed += (path.misses >> i) & 1;
	}
	return missed >= 2;
}

// The score the choice compares: doubled for a lossy path; nullopt unknown.
[[nodiscard]] inline std::optional<Time> Effective(const PathRecord &path) {
	if (!path.score) {
		return std::nullopt;
	}
	return Lossy(path) ? (path.score * 2) : path.score;
}

// Frozen in this network within bad_ttl (until a rank probe passes), or
// failed within failed_ttl.
[[nodiscard]] inline bool Excluded(const PathRecord *path, Time now) {
	return path && (path->badUntil > now || path->failedUntil > now);
}

// --- The paths and their order -----------------------------------------------

// The paths of datacenter 1: the direct one and the edges, in the order of
// pluma_edge (edgesFirst: "order":["edge","direct"]).
struct Paths {
	std::vector<std::string> edges;
	bool edgesFirst = false;
};

[[nodiscard]] inline std::vector<std::string> DefaultOrder(
		const Paths &paths) {
	auto result = std::vector<std::string>();
	if (!paths.edgesFirst) {
		result.push_back(kDirect);
	}
	result.insert(end(result), begin(paths.edges), end(paths.edges));
	if (paths.edgesFirst) {
		result.push_back(kDirect);
	}
	return result;
}

namespace details {

// The paths in the default order without the excluded ones; all of them
// when every one is excluded (then it is the network, not the paths).
[[nodiscard]] inline std::vector<std::string> Usable(
		const Paths &paths,
		const Network *network,
		Time now) {
	const auto all = DefaultOrder(paths);
	auto result = std::vector<std::string>();
	for (const auto &id : all) {
		if (!Excluded(Find(network, id), now)) {
			result.push_back(id);
		}
	}
	return result.empty() ? all : result;
}

[[nodiscard]] inline bool Contains(
		const std::vector<std::string> &list,
		const std::string &id) {
	return std::find(begin(list), end(list), id) != end(list);
}

} // namespace details

// The order to connect in: the best of this network first, then the
// default order; the excluded paths are left out.
[[nodiscard]] inline std::vector<std::string> ConnectOrder(
		const Paths &paths,
		const Network *network,
		Time now) {
	auto result = details::Usable(paths, network, now);
	if (network && details::Contains(result, network->best)) {
		result.erase(std::find(begin(result), end(result), network->best));
		result.insert(begin(result), network->best);
	}
	return result;
}

// The gate race: the paths started at once, and those started after
// race_stagger unless one of the first has passed by then, or at once when
// all the first have dropped out. With a fresh memory the best path goes
// alone first; without, the first group of the default order (the edges
// or the direct path).
struct Race {
	std::vector<std::string> first;
	std::vector<std::string> later;
};

[[nodiscard]] inline Race GateRace(
		const Paths &paths,
		const Network *network,
		Time now) {
	const auto usable = details::Usable(paths, network, now);
	auto result = Race();
	if (network && details::Contains(usable, network->best)) {
		result.first.push_back(network->best);
	} else {
		const auto edgeGroup = paths.edgesFirst;
		for (const auto &id : usable) {
			if ((id != kDirect) == edgeGroup) {
				result.first.push_back(id);
			}
		}
		if (result.first.empty()) {
			result.first = usable;
		}
	}
	for (const auto &id : usable) {
		if (!details::Contains(result.first, id)) {
			result.later.push_back(id);
		}
	}
	return result;
}

// The paths of a rank probe: the direct path and the current one always;
// the other edges only when the order puts the edges first or the direct
// path is not good (its last probe was not ok, or it scored worse than
// edge_probe_if_direct). Who has a good direct path shows the edges no
// probes (ADR 0072 §5).
[[nodiscard]] inline std::vector<std::string> RankPaths(
		const Paths &paths,
		const Network *network,
		const std::string &current,
		const Params &params) {
	const auto direct = Find(network, kDirect);
	const auto directScore = direct ? Effective(*direct) : std::nullopt;
	const auto directBad = direct
		&& (direct->outcome != Outcome::Ok
			|| !directScore
			|| *directScore > params.edgeProbeIfDirect);
	const auto edges = paths.edgesFirst || directBad;
	auto result = std::vector<std::string>();
	for (const auto &id : DefaultOrder(paths)) {
		if (id == kDirect || id == current || edges) {
			result.push_back(id);
		}
	}
	return result;
}

// --- Probes into the memory --------------------------------------------------

struct Result {
	std::string id;
	Outcome outcome = Outcome::Failed;
	Time rtt = 0;
	double speed = 0.; // bytes a second
};

enum class Kind {
	Gate,
	Rank,
};

// Takes a round into the memory; false when it says nothing of the paths:
// every probe unsupported, or every path dropped out (no network, a hotel
// portal not passed yet, a white list), which is the network and not the
// paths.
inline bool Record(
		Network &network,
		const std::vector<Result> &results,
		Kind kind,
		const Params &params,
		Time now) {
	const auto judged = std::count_if(
		begin(results),
		end(results),
		[](const Result &r) { return r.outcome != Outcome::Unsupported; });
	const auto answered = std::count_if(
		begin(results),
		end(results),
		[](const Result &r) { return Answered(r.outcome); });
	if (!judged || !answered) {
		return false;
	}
	for (const auto &result : results) {
		if (result.outcome == Outcome::Unsupported) {
			continue;
		}
		auto &path = FindOrAdd(network, result.id);
		const auto ok = (result.outcome == Outcome::Ok);
		path.misses = uint8_t(((path.misses << 1) | (ok ? 0 : 1))
			& ((1 << kHistory) - 1));
		path.count = uint8_t(std::min(path.count + 1, kHistory));
		path.outcome = result.outcome;
		path.at = now;
		const auto score = Answered(result.outcome)
			? Score(result.rtt, result.speed)
			: std::nullopt;
		path.score = score.value_or(0);
		if (result.outcome == Outcome::Frozen) {
			path.badUntil = now + params.badTtl;
		} else if (result.outcome == Outcome::Failed) {
			path.failedUntil = now + params.failedTtl;
		} else if (ok) {
			path.failedUntil = 0;
			if (kind == Kind::Rank) {
				path.badUntil = 0;
			}
		}
	}
	if (kind == Kind::Rank) {
		network.rankedAt = now;
	}
	return true;
}

// The best of the paths answered in a round: the lowest effective score;
// scores within 30% of it are a tie, which the default order breaks.
[[nodiscard]] inline std::string Best(
		const Network &network,
		const std::vector<Result> &results,
		const Paths &paths) {
	auto scores = std::vector<std::pair<std::string, Time>>();
	for (const auto &result : results) {
		if (!Answered(result.outcome)) {
			continue;
		} else if (const auto path = Find(&network, result.id)) {
			if (const auto score = Effective(*path)) {
				scores.emplace_back(result.id, *score);
			}
		}
	}
	if (scores.empty()) {
		return {};
	}
	auto lowest = scores.front().second;
	for (const auto &[id, score] : scores) {
		lowest = std::min(lowest, score);
	}
	for (const auto &id : DefaultOrder(paths)) {
		for (const auto &[scored, score] : scores) {
			if (scored == id && double(score) <= double(lowest) * 1.3) {
				return id;
			}
		}
	}
	return {};
}

// The winner of a gate race: the current path when it passed, otherwise
// the first that passed; empty when none did.
[[nodiscard]] inline std::string GateWinner(
		const std::vector<Result> &results,
		const std::string &current) {
	auto first = std::string();
	for (const auto &result : results) {
		if (result.outcome != Outcome::Ok) {
			continue;
		} else if (result.id == current) {
			return current;
		} else if (first.empty()) {
			first = result.id;
		}
	}
	return first;
}

// The guard of task 109 saw the path freeze on the connection in use: it
// is kept out of the race in this network for bad_ttl.
inline void MarkFrozen(
		Network &network,
		const std::string &id,
		const Params &params,
		Time now) {
	auto &path = FindOrAdd(network, id);
	path.misses = uint8_t(((path.misses << 1) | 1) & ((1 << kHistory) - 1));
	path.count = uint8_t(std::min(path.count + 1, kHistory));
	path.outcome = Outcome::Frozen;
	path.at = now;
	path.score = 0;
	path.badUntil = now + params.badTtl;
}

// The best path of this network that passed its last probe within
// kFresh, but this one, and is not kept out: the lowest effective score,
// the default order for ties; empty when there is none.
[[nodiscard]] inline std::string BestKnown(
		const Network &network,
		const Paths &paths,
		const std::string &but,
		Time now) {
	auto results = std::vector<Result>();
	for (const auto &id : DefaultOrder(paths)) {
		const auto path = Find(&network, id);
		if (id != but
			&& path
			&& path->outcome == Outcome::Ok
			&& now - path->at <= kFresh
			&& !Excluded(path, now)) {
			results.push_back({ .id = id, .outcome = Outcome::Ok });
		}
	}
	return Best(network, results, paths);
}

// What to do after a rank round recorded in the network.
struct Choice {
	std::string to;   // the path to go to, empty to stay
	bool now = false; // the current path failed: at once, no waiting
	Time again = 0;   // a win not taken yet: rank again at this time
};

// The current path failed the round: the best path that answered, at once
// (none: a gate race of the rest). Otherwise a better path is taken when
// its score is at most switch_ratio of the current one's in two rounds in
// a row (the second within twice confirm of the first) or at most
// switch_ratio_now in one, and min_dwell has passed since the last switch;
// a win not taken asks for another rank after confirm, or when min_dwell
// ends.
[[nodiscard]] inline Choice Choose(
		Network &network,
		const std::vector<Result> &results,
		const Paths &paths,
		const std::string &current,
		const Params &params,
		Time now) {
	const auto mine = std::find_if(begin(results), end(results), [&](
			const Result &r) {
		return r.id == current;
	});
	const auto best = Best(network, results, paths);
	if (mine == end(results) || !Answered(mine->outcome)) {
		network.pending.clear();
		return best.empty()
			? Choice{ .now = true }
			: Choice{ .to = best, .now = true };
	}
	const auto currentPath = Find(&network, current);
	const auto currentScore = currentPath
		? Effective(*currentPath)
		: std::nullopt;
	const auto bestPath = Find(&network, best);
	const auto bestScore = bestPath ? Effective(*bestPath) : std::nullopt;
	if (best.empty() || best == current || !currentScore || !bestScore) {
		network.pending.clear();
		return {};
	}
	const auto ratio = double(*bestScore) / double(*currentScore);
	if (ratio > params.switchRatio) {
		network.pending.clear();
		return {};
	}
	const auto confirmed = (network.pending == best)
		&& (now - network.pendingAt <= 2 * params.confirm);
	const auto dwelt = !network.switchedAt
		|| (now - network.switchedAt >= params.minDwell);
	if ((ratio <= params.switchRatioNow || confirmed) && dwelt) {
		network.pending.clear();
		return { .to = best };
	}
	network.pending = best;
	network.pendingAt = now;
	return {
		.again = dwelt
			? (now + params.confirm)
			: std::max(
				now + params.confirm,
				network.switchedAt + params.minDwell),
	};
}

// --- The key of a network ----------------------------------------------------

// The country and the local fingerprint of the platform (the kinds and
// prefixes of its interfaces), hashed: no address is kept.
[[nodiscard]] inline std::string NetworkKey(
		const std::string &country,
		std::vector<std::string> parts) {
	std::sort(begin(parts), end(parts));
	auto hash = uint64_t(14695981039346656037ULL);
	const auto add = [&](const std::string &text) {
		for (const auto c : text) {
			hash ^= uint8_t(c);
			hash *= 1099511628211ULL;
		}
		hash ^= 0xFF;
		hash *= 1099511628211ULL;
	};
	add(country);
	for (const auto &part : parts) {
		add(part);
	}
	static constexpr char kHex[] = "0123456789abcdef";
	auto result = std::string(16, '0');
	for (auto i = 0; i != 16; ++i) {
		result[15 - i] = kHex[(hash >> (4 * i)) & 0x0F];
	}
	return result;
}

} // namespace MTP::details::path
