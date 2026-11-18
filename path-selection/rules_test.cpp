// The rules of the path selection (mtproto_path_rules.h), checked without
// Qt: ci/path_rules_test.py builds and runs this file.
#include "mtproto_path_rules.h"

#include <cstdio>
#include <cstdlib>
#include <initializer_list>

namespace {

using namespace MTP::details::path;

int Failures = 0;

#define CHECK(condition) \
	do { \
		if (!(condition)) { \
			std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #condition); \
			++Failures; \
		} \
	} while (false)

std::map<std::string, Field> Fields(
		std::initializer_list<std::pair<const char*, double>> numbers,
		std::optional<std::string> country = std::nullopt) {
	auto result = std::map<std::string, Field>();
	for (const auto &[key, value] : numbers) {
		result[key].number = value;
	}
	if (country) {
		result["country"].text = *country;
	}
	return result;
}

void TestParams() {
	// Only v: the defaults of the brief.
	const auto defaults = ParseParams(Fields({ { "v", 1 } }));
	CHECK(defaults.has_value());
	CHECK(defaults->gateDown == 65536);
	CHECK(defaults->rankDown == 196608);
	CHECK(defaults->up == 20480);
	CHECK(defaults->stall == 1500);
	CHECK(defaults->deadline == 6000);
	CHECK(defaults->suspect == 4000);
	CHECK(defaults->reprobe == 21600 * 1000LL);
	CHECK(defaults->rankMinInterval == 1800 * 1000LL);
	CHECK(defaults->minDwell == 600 * 1000LL);
	CHECK(defaults->switchRatio == 0.7);
	CHECK(defaults->switchRatioNow == 0.25);
	CHECK(defaults->edgeProbeIfDirect == 1500);
	CHECK(defaults->badTtl == 86400 * 1000LL);
	CHECK(defaults->failedTtl == 300 * 1000LL);
	CHECK(defaults->raceStagger == 800);
	CHECK(defaults->confirm == 60 * 1000LL);
	CHECK(defaults->country.empty());

	// The example of the brief, every key with a value of its own.
	const auto full = ParseParams(Fields({
		{ "v", 1 }, { "gate_down", 32768 }, { "rank_down", 262144 },
		{ "up", 8192 }, { "stall_ms", 2000 }, { "deadline_ms", 8000 },
		{ "suspect_ms", 5000 }, { "reprobe_s", 3600 },
		{ "rank_min_interval_s", 900 }, { "min_dwell_s", 300 },
		{ "switch_ratio", 0.6 }, { "switch_ratio_now", 0.2 },
		{ "edge_probe_if_direct_ms", 1200 }, { "bad_ttl_s", 43200 },
		{ "failed_ttl_s", 120 }, { "race_stagger_ms", 500 },
		{ "confirm_s", 30 }, { "a_later_key", 7 },
	}, "RU"));
	CHECK(full.has_value());
	CHECK(full->country == "RU");
	CHECK(full->gateDown == 32768);
	CHECK(full->rankDown == 262144);
	CHECK(full->up == 8192);
	CHECK(full->stall == 2000);
	CHECK(full->deadline == 8000);
	CHECK(full->suspect == 5000);
	CHECK(full->reprobe == 3600 * 1000LL);
	CHECK(full->rankMinInterval == 900 * 1000LL);
	CHECK(full->minDwell == 300 * 1000LL);
	CHECK(full->switchRatio == 0.6);
	CHECK(full->switchRatioNow == 0.2);
	CHECK(full->edgeProbeIfDirect == 1200);
	CHECK(full->badTtl == 43200 * 1000LL);
	CHECK(full->failedTtl == 120 * 1000LL);
	CHECK(full->raceStagger == 500);
	CHECK(full->confirm == 30 * 1000LL);
	CHECK(ParseParams(Fields({ { "v", 1 } }, "")).has_value());

	// Not taken at all.
	CHECK(!ParseParams({}).has_value());
	CHECK(!ParseParams(Fields({ { "v", 2 } })).has_value());
	for (const auto country : { "ru", "RUS", "R", "R1" }) {
		CHECK(!ParseParams(Fields({ { "v", 1 } }, country)).has_value());
	}
	auto textNumber = Fields({ { "v", 1 } });
	textNumber["stall_ms"].text = "1500";
	CHECK(!ParseParams(textNumber).has_value());
	auto numberCountry = Fields({ { "v", 1 } });
	numberCountry["country"].number = 7;
	CHECK(!ParseParams(numberCountry).has_value());
	for (const auto &[key, value] : std::initializer_list<std::pair<const char*, double>>{
			{ "gate_down", 16383 }, { "gate_down", 524289 }, { "gate_down", 65536.5 },
			{ "rank_down", 1000 }, { "up", -1 }, { "up", 65537 },
			{ "stall_ms", 299 }, { "deadline_ms", 30001 }, { "suspect_ms", 999 },
			{ "reprobe_s", 599 }, { "rank_min_interval_s", 59 }, { "min_dwell_s", -1 },
			{ "switch_ratio", 1 }, { "switch_ratio_now", 0 }, { "edge_probe_if_direct_ms", 99 },
			{ "bad_ttl_s", 59 }, { "failed_ttl_s", 9 }, { "race_stagger_ms", 10001 },
			{ "confirm_s", 3601 }, { "confirm_s", NAN }, { "confirm_s", INFINITY } }) {
		CHECK(!ParseParams(Fields({ { "v", 1 }, { key, value } })).has_value());
	}
	// The stall is shorter than the deadline; the immediate ratio is not
	// above the other one.
	CHECK(!ParseParams(Fields({ { "v", 1 }, { "stall_ms", 6000 } })).has_value());
	CHECK(!ParseParams(Fields({ { "v", 1 }, { "switch_ratio", 0.3 }, { "switch_ratio_now", 0.4 } })).has_value());
}

void Nonce(uint8_t (&nonce)[kNonceSize]) {
	for (auto i = 0; i != kNonceSize; ++i) {
		nonce[i] = uint8_t(i);
	}
}

void TestRequest() {
	uint8_t nonce[kNonceSize];
	Nonce(nonce);
	// The vector of the contract.
	const auto empty = ProbeRequest(nonce, 65536, {});
	const auto expected = std::vector<uint8_t>{
		0x30, 0x6d, 0x31, 0x5c,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	CHECK(empty == expected);
	const auto pad = std::vector<uint8_t>(20480, 0xAB);
	const auto full = ProbeRequest(nonce, 65536, pad);
	CHECK(full.size() == 20508); // 24 + 4 + 20480
	CHECK(full[24] == 0xfe && full[25] == 0x00 && full[26] == 0x50 && full[27] == 0x00);
	CHECK(full[28] == 0xAB && full.back() == 0xAB);
	const auto odd = ProbeRequest(nonce, 1, std::vector<uint8_t>(5, 1));
	CHECK(odd.size() == 24 + 8); // 1 + 5 + 2 zeros
	CHECK(odd[30] == 0 && odd[31] == 0);
}

void Put(std::vector<uint8_t> &to, uint64_t value, int size) {
	for (auto i = 0; i != size; ++i) {
		to.push_back(uint8_t(value >> (8 * i)));
	}
}

// An unencrypted pluma.probeData as the gateway writes it.
std::vector<uint8_t> Data(
		const uint8_t (&nonce)[kNonceSize],
		int seq,
		int total,
		int pad,
		int extraInside = 0,
		int transportPadding = 0) {
	auto object = std::vector<uint8_t>();
	Put(object, kProbeDataId, 4);
	object.insert(end(object), nonce, nonce + kNonceSize);
	Put(object, uint32_t(seq), 4);
	Put(object, uint32_t(total), 4);
	Put(object, 1700000000000ULL, 8);
	if (pad < 254) {
		object.push_back(uint8_t(pad));
	} else {
		object.push_back(254);
		Put(object, uint32_t(pad), 3);
	}
	object.insert(end(object), size_t(pad), 0x5A);
	while (object.size() % 4) {
		object.push_back(0);
	}
	object.insert(end(object), size_t(extraInside), 0);
	auto result = std::vector<uint8_t>();
	Put(result, 0, 8);
	Put(result, (1ULL << 32) | 1, 8);
	Put(result, uint32_t(object.size()), 4);
	result.insert(end(result), begin(object), end(object));
	result.insert(end(result), size_t(transportPadding), 0x77);
	return result;
}

AnswerReader::Step Feed(AnswerReader &reader, const std::vector<uint8_t> &message) {
	return reader.feed(message.data(), message.size());
}

void TestAnswer() {
	using Step = AnswerReader::Step;
	uint8_t nonce[kNonceSize];
	Nonce(nonce);
	CHECK(ClampDown(1) == 16384 && ClampDown(600000) == 524288);
	CHECK(ChunkCount(65536) == 4 && ChunkCount(20000) == 2 && ChunkCount(1) == 1 && ChunkCount(600000) == 32);

	{
		auto reader = AnswerReader(nonce, 65536);
		CHECK(Data(nonce, 0, 4, 16384).size() == 16444);
		CHECK(Feed(reader, Data(nonce, 0, 4, 16384)) == Step::More);
		CHECK(Feed(reader, Data(nonce, 1, 4, 16384, 0, 12)) == Step::More);
		CHECK(Feed(reader, Data(nonce, 2, 4, 16384)) == Step::More);
		CHECK(Feed(reader, Data(nonce, 3, 4, 16384)) == Step::Done);
		CHECK(reader.received() == 65536);
		// Nothing more is an answer.
		CHECK(Feed(reader, Data(nonce, 4, 4, 16384)) == Step::Bad);
	}
	{
		// The last pad holds the rest; down below the minimum is clamped.
		auto reader = AnswerReader(nonce, 20000);
		CHECK(Feed(reader, Data(nonce, 0, 2, 16384)) == Step::More);
		CHECK(Feed(reader, Data(nonce, 1, 2, 20000 - 16384)) == Step::Done);
		// A last pad of 5 bytes: one of length, 2 zeros after it.
		auto odd = AnswerReader(nonce, kChunk + 5);
		CHECK(Feed(odd, Data(nonce, 0, 2, kChunk)) == Step::More);
		CHECK(Feed(odd, Data(nonce, 1, 2, 5)) == Step::Done);
		CHECK(odd.received() == kChunk + 5);
		auto small = AnswerReader(nonce, 100);
		CHECK(Feed(small, Data(nonce, 0, 1, 16384)) == Step::Done);
		CHECK(small.received() == 16384);
	}
	uint8_t other[kNonceSize] = {};
	std::memcpy(other, nonce, kNonceSize);
	other[15] ^= 1;
	const auto bad = [&](std::vector<uint8_t> message) {
		auto reader = AnswerReader(nonce, 65536);
		const auto first = Feed(reader, message);
		// And it stays bad.
		const auto next = Feed(reader, Data(nonce, 0, 4, 16384));
		return (first == Step::Bad) && (next == Step::Bad);
	};
	CHECK(bad(Data(other, 0, 4, 16384)));      // another probe's
	CHECK(bad(Data(nonce, 1, 4, 16384)));      // seq skipped
	CHECK(bad(Data(nonce, 0, 5, 16384)));      // another total
	CHECK(bad(Data(nonce, 0, 4, 16380)));      // a short pad
	CHECK(bad(Data(nonce, 0, 4, 16384, 4)));   // bytes inside after the pad
	auto encrypted = Data(nonce, 0, 4, 16384);
	encrypted[3] = 1;
	CHECK(bad(encrypted));
	auto longer = Data(nonce, 0, 4, 16384);
	longer[16] += 4; // message_data_length past the packet
	CHECK(bad(longer));
	auto otherType = Data(nonce, 0, 4, 16384);
	otherType[20] ^= 1;
	CHECK(bad(otherType));
	CHECK(bad(std::vector<uint8_t>(19, 0)));
	auto badLength = Data(nonce, 0, 4, 16384);
	badLength[56] = 255; // a TL length byte that does not exist
	CHECK(bad(badLength));
}

void TestWatch() {
	auto watch = Watch{
		.from = 1000,
		.stall = 1500,
		.deadline = 7000,
	};
	// No byte from the path: failed at the deadline, never frozen.
	CHECK(!Overdue(watch, 6999));
	CHECK(Overdue(watch, 7000) == Outcome::Failed);
	CHECK(NextCheck(watch) == 7000);
	// A byte before (the TLS of an edge): silence counts from the later of
	// the request plus rtt and the last byte.
	watch.anyByte = true;
	watch.lastByte = 500;
	CHECK(!Overdue(watch, 2499));
	CHECK(Overdue(watch, 2500) == Outcome::Frozen);
	CHECK(NextCheck(watch) == 2500);
	watch.lastByte = 3000;
	watch.answered = true;
	CHECK(!Overdue(watch, 4499));
	CHECK(Overdue(watch, 4500) == Outcome::Frozen);
	// Bytes all the time, not all of them by the deadline: slow.
	watch.lastByte = 6900;
	CHECK(Overdue(watch, 7000) == Outcome::Slow);
	CHECK(NextCheck(watch) == 7000);

	auto speed = Speed();
	CHECK(speed.bytesPerSecond() == 0.);
	speed.read(1000, 100);
	CHECK(speed.bytesPerSecond() == 0.);
	speed.read(100000, 600);
	speed.read(100000, 1100);
	CHECK(speed.bytesPerSecond() == 200000.);
}

void TestScore() {
	CHECK(Score(50, 262144.) == 1050);
	CHECK(Score(0, 1024. * 1024.) == 250);
	CHECK(!Score(50, 0.));
	CHECK(!Score(-1, 1000.));
}

const auto Ru = std::string("wss://ru.example.com/apiws");
const auto Cdn = std::string("wss://cdn.example.com/apiws");

Paths Edges(bool first) {
	return { .edges = { Ru, Cdn }, .edgesFirst = first };
}

std::vector<std::string> List(std::initializer_list<std::string> ids) {
	return ids;
}

void TestMemory() {
	const auto params = Params();
	auto table = Table();
	auto &network = Use(table, "k1", 1000);
	CHECK(Fresh(table, "k1", 1000) != nullptr);
	CHECK(Fresh(table, "k1", 1000 + kFresh + 1) == nullptr);
	CHECK(Fresh(table, "k2", 1000) == nullptr);

	// Every path dropped out: nothing is written.
	CHECK(!Record(network, { { kDirect, Outcome::Frozen }, { Ru, Outcome::Failed } }, Kind::Gate, params, 2000));
	CHECK(network.paths.empty());
	// Nothing but unsupported: nothing either.
	CHECK(!Record(network, { { kDirect, Outcome::Unsupported } }, Kind::Gate, params, 2000));
	CHECK(network.paths.empty());

	CHECK(Record(network, {
		{ kDirect, Outcome::Frozen },
		{ Ru, Outcome::Ok, 40, 262144. },
		{ Cdn, Outcome::Failed },
		{ "wss://x.example.com/apiws", Outcome::Unsupported },
	}, Kind::Gate, params, 2000));
	const auto direct = Find(&network, kDirect);
	CHECK(direct && direct->badUntil == 2000 + params.badTtl && direct->score == 0);
	CHECK(Find(&network, Ru)->score == 1040);
	CHECK(Find(&network, Cdn)->failedUntil == 2000 + params.failedTtl);
	CHECK(!Find(&network, "wss://x.example.com/apiws"));
	CHECK(Excluded(direct, 3000) && !Excluded(direct, 2000 + params.badTtl));
	CHECK(network.rankedAt == 0);

	// A gate pass keeps the exclusion of a frozen path, a rank pass ends it.
	CHECK(Record(network, { { kDirect, Outcome::Ok, 20, 1e6 } }, Kind::Gate, params, 3000));
	CHECK(Find(&network, kDirect)->badUntil == 2000 + params.badTtl);
	CHECK(Record(network, { { kDirect, Outcome::Ok, 20, 1e6 } }, Kind::Rank, params, 4000));
	CHECK(Find(&network, kDirect)->badUntil == 0);
	CHECK(network.rankedAt == 4000);

	// Two of the last four not ok double the score.
	auto lossy = PathRecord{ .id = Ru, .score = 100 };
	lossy.misses = 0b0001;
	lossy.count = 4;
	CHECK(!Lossy(lossy) && Effective(lossy) == 100);
	lossy.misses = 0b1001;
	CHECK(Lossy(lossy) && Effective(lossy) == 200);
	lossy.misses = 0b10001; // the fifth probe ago does not count
	CHECK(!Lossy(lossy));

	// Sixteen networks at most, the least recently used goes.
	auto many = Table();
	for (auto i = 0; i != kMaxNetworks; ++i) {
		(void)Use(many, "n" + std::to_string(i), 100 + i);
	}
	(void)Use(many, "n0", 500);
	(void)Use(many, "new", 600);
	CHECK(int(many.networks.size()) == kMaxNetworks);
	CHECK(Fresh(many, "n0", 600) && !Fresh(many, "n1", 600) && Fresh(many, "new", 600));
	// A record not used for a week starts empty.
	auto &old = Use(many, "n2", 102 + kFresh + 1);
	CHECK(old.paths.empty() && old.best.empty());
}

void TestOrder() {
	auto table = Table();
	auto &network = Use(table, "k", 1000);
	CHECK(ConnectOrder(Edges(false), nullptr, 1000) == List({ kDirect, Ru, Cdn }));
	CHECK(ConnectOrder(Edges(true), nullptr, 1000) == List({ Ru, Cdn, kDirect }));
	network.best = Cdn;
	CHECK(ConnectOrder(Edges(false), &network, 1000) == List({ Cdn, kDirect, Ru }));
	FindOrAdd(network, kDirect).badUntil = 5000;
	CHECK(ConnectOrder(Edges(false), &network, 1000) == List({ Cdn, Ru }));
	FindOrAdd(network, Ru).failedUntil = 5000;
	FindOrAdd(network, Cdn).badUntil = 5000;
	// Every path excluded: it is the network; all of them again.
	CHECK(ConnectOrder(Edges(false), &network, 1000) == List({ Cdn, kDirect, Ru }));
	CHECK(ConnectOrder(Edges(false), &network, 5000) == List({ Cdn, kDirect, Ru }));

	// The gate race.
	auto fresh = Table();
	auto &mine = Use(fresh, "k", 1000);
	auto race = GateRace(Edges(true), nullptr, 1000);
	CHECK(race.first == List({ Ru, Cdn }) && race.later == List({ kDirect }));
	race = GateRace(Edges(false), nullptr, 1000);
	CHECK(race.first == List({ kDirect }) && race.later == List({ Ru, Cdn }));
	mine.best = Ru;
	race = GateRace(Edges(false), &mine, 1000);
	CHECK(race.first == List({ Ru }) && race.later == List({ kDirect, Cdn }));
	FindOrAdd(mine, kDirect).badUntil = 9000;
	mine.best.clear();
	race = GateRace(Edges(false), &mine, 1000);
	CHECK(race.first == List({ Ru, Cdn }) && race.later.empty());
}

void TestRankPaths() {
	const auto params = Params();
	auto table = Table();
	auto &network = Use(table, "k", 1000);
	// Nothing known of the direct path: the direct and the current one.
	CHECK(RankPaths(Edges(false), &network, kDirect, params) == List({ kDirect }));
	CHECK(RankPaths(Edges(false), &network, Ru, params) == List({ kDirect, Ru }));
	auto &direct = FindOrAdd(network, kDirect);
	direct.outcome = Outcome::Ok;
	direct.score = 900;
	CHECK(RankPaths(Edges(false), &network, kDirect, params) == List({ kDirect }));
	// The edges first by the server's order, or the direct path bad.
	CHECK(RankPaths(Edges(true), &network, kDirect, params) == List({ Ru, Cdn, kDirect }));
	direct.score = 1501;
	CHECK(RankPaths(Edges(false), &network, kDirect, params) == List({ kDirect, Ru, Cdn }));
	direct.score = 900;
	direct.outcome = Outcome::Frozen;
	CHECK(RankPaths(Edges(false), &network, kDirect, params) == List({ kDirect, Ru, Cdn }));
}

void TestChoose() {
	const auto params = Params();
	const auto paths = Edges(false);
	const auto rank = [&](Network &network, Time now, Time direct, Time ru) {
		auto results = std::vector<Result>{
			{ kDirect, direct ? Outcome::Ok : Outcome::Frozen, 0, direct ? double(kScoreBytes) * 1000. / double(direct) : 0. },
			{ Ru, Outcome::Ok, 0, double(kScoreBytes) * 1000. / double(ru) },
		};
		Record(network, results, Kind::Rank, params, now);
		return results;
	};
	{
		// The current path failed: the best other one at once.
		auto table = Table();
		auto &network = Use(table, "k", 1000);
		const auto results = rank(network, 1000, 0, 400);
		const auto choice = Choose(network, results, paths, kDirect, params, 1000);
		CHECK(choice.to == Ru && choice.now);
		// Nothing else answered: a race of the rest.
		const auto none = Choose(network, { { kDirect, Outcome::Frozen } }, paths, kDirect, params, 1000);
		CHECK(none.to.empty() && none.now);
	}
	{
		// Four times better: at once.
		auto table = Table();
		auto &network = Use(table, "k", 1000);
		const auto results = rank(network, 1000, 400, 4000);
		const auto choice = Choose(network, results, paths, Ru, params, 1000);
		CHECK(choice.to == kDirect && !choice.now);
	}
	{
		// Twice better: twice in a row, the second within twice confirm.
		auto table = Table();
		auto &network = Use(table, "k", 1000);
		auto results = rank(network, 1000, 1000, 2000);
		auto choice = Choose(network, results, paths, Ru, params, 1000);
		CHECK(choice.to.empty() && choice.again == 1000 + params.confirm);
		results = rank(network, 61000, 1000, 2000);
		choice = Choose(network, results, paths, Ru, params, 61000);
		CHECK(choice.to == kDirect);
		// Too late for a second win: a first win again.
		auto late = Table();
		auto &slow = Use(late, "k", 1000);
		(void)Choose(slow, rank(slow, 1000, 1000, 2000), paths, Ru, params, 1000);
		choice = Choose(slow, rank(slow, 1000 + 2 * params.confirm + 1, 1000, 2000), paths, Ru, params, 1000 + 2 * params.confirm + 1);
		CHECK(choice.to.empty() && choice.again);
		// A round without the win in between ends the row.
		auto broken = Table();
		auto &row = Use(broken, "k", 1000);
		(void)Choose(row, rank(row, 1000, 1000, 2000), paths, Ru, params, 1000);
		choice = Choose(row, rank(row, 2000, 1900, 2000), paths, Ru, params, 2000);
		CHECK(choice.to.empty() && !choice.again && row.pending.empty());
	}
	{
		// Not ten minutes since the last switch: not yet, again when they pass.
		auto table = Table();
		auto &network = Use(table, "k", 1000);
		network.switchedAt = 1000;
		const auto results = rank(network, 2000, 400, 4000);
		const auto choice = Choose(network, results, paths, Ru, params, 2000);
		CHECK(choice.to.empty() && choice.again == 1000 + params.minDwell);
	}
	{
		// Within 30%: the order of pluma_edge, and no switch for it.
		auto table = Table();
		auto &network = Use(table, "k", 1000);
		const auto results = rank(network, 1000, 1200, 1000);
		CHECK(Best(network, results, paths) == kDirect);
		const auto choice = Choose(network, results, paths, kDirect, params, 1000);
		CHECK(choice.to.empty() && !choice.now && !choice.again);
		CHECK(Best(network, results, Edges(true)) == Ru);
	}
}

void TestGuard() {
	const auto params = Params();
	// The winner of a gate race.
	CHECK(GateWinner({ { Ru, Outcome::Ok }, { kDirect, Outcome::Ok } }, kDirect) == kDirect);
	CHECK(GateWinner({ { kDirect, Outcome::Frozen }, { Cdn, Outcome::Ok }, { Ru, Outcome::Ok } }, kDirect) == Cdn);
	CHECK(GateWinner({ { kDirect, Outcome::Slow } }, kDirect).empty());

	// The guard of task 109: the frozen path out, the best known one in.
	auto table = Table();
	auto &network = Use(table, "k", 1000);
	CHECK(BestKnown(network, Edges(false), kDirect, 1000).empty());
	Record(network, {
		{ kDirect, Outcome::Ok, 10, 1e6 },
		{ Ru, Outcome::Ok, 10, 262144. },
		{ Cdn, Outcome::Ok, 10, 524288. },
	}, Kind::Rank, params, 1000);
	MarkFrozen(network, kDirect, params, 2000);
	const auto direct = Find(&network, kDirect);
	CHECK(direct->outcome == Outcome::Frozen && direct->badUntil == 2000 + params.badTtl);
	CHECK(direct->score == 0 && direct->count == 2 && direct->misses == 1);
	CHECK(BestKnown(network, Edges(false), kDirect, 2000) == Cdn);
	FindOrAdd(network, Cdn).failedUntil = 9000;
	CHECK(BestKnown(network, Edges(false), kDirect, 2000) == Ru);
	CHECK(BestKnown(network, Edges(false), kDirect, 1000 + kFresh + 1).empty());
}

void TestKey() {
	const auto a = NetworkKey("DE", { "1:192.168.1.0/24", "1:2001:db8::/64" });
	CHECK(a.size() == 16);
	CHECK(a.find_first_not_of("0123456789abcdef") == std::string::npos);
	CHECK(a == NetworkKey("DE", { "1:2001:db8::/64", "1:192.168.1.0/24" }));
	CHECK(a != NetworkKey("RU", { "1:192.168.1.0/24", "1:2001:db8::/64" }));
	CHECK(a != NetworkKey("DE", { "1:192.168.2.0/24", "1:2001:db8::/64" }));
	// Parts do not run into each other.
	CHECK(NetworkKey("", { "ab", "c" }) != NetworkKey("", { "a", "bc" }));
}

} // namespace

int main() {
	TestParams();
	TestRequest();
	TestAnswer();
	TestWatch();
	TestScore();
	TestMemory();
	TestOrder();
	TestRankPaths();
	TestChoose();
	TestGuard();
	TestKey();
	if (Failures) {
		std::fprintf(stderr, "%d checks failed\n", Failures);
		return EXIT_FAILURE;
	}
	std::printf("path rules: ok\n");
	return EXIT_SUCCESS;
}
