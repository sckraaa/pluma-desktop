/*
This file is part of Pluma, built on Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_edge_route.h"
#include "mtproto/details/mtproto_path_rules.h"
#include "mtproto/connection_abstract.h"
#include "base/timer.h"

namespace MTP {
class Instance;
} // namespace MTP

namespace MTP::details {

// The choice of the path to datacenter 1 by probes (task 113 of the server
// repository, ADR 0073): the direct path or an edge of task 109. A probe
// is a connection of its own to the path that, after resPQ, asks the
// gateway for pluma.probeData, well past the ~16 KB after which a blocked
// path goes silent (task 092). The sessions connect at once in the order
// of the memory of this network; the main session of datacenter 1 probes
// the paths beside it (one round at a time in the process, whichever
// account runs it) and the choice moves the sessions to another path when
// the current one fails or another one is clearly better. Off with a
// proxy of the user's (no edges then), and until the next app config when
// the gateway answers no probes.

// The id of the direct path among the paths of an order.
[[nodiscard]] QString PathDirect();

// Any thread: the paths to connect through, best first, without the ones
// kept out of the race in this network; empty while the probes are off,
// and then the order of task 109 decides. The edges are the plan's, in
// the order of their list.
[[nodiscard]] std::vector<QString> PathOrder(
	const std::vector<QString> &edges,
	bool edgesFirst);

// Any thread: the guard of task 109 saw the direct path freeze on the
// connection in use. The best path that passed a probe in this network
// takes its place, or the paths race; false while the probes are off.
bool PathFroze();

// Any thread: a session of files to datacenter 1 sent or received; a
// switch that is not urgent waits for the transfer, up to two minutes.
void PathFileActivity();

// Main thread: the user did something in the app; the periodic probes
// run only for a user who did since the last probes.
void PathUserActive();

// Main thread: the pluma_probe value of help.getAppConfig, nullptr when
// the key is not there (the built-in parameters then). Kept in
// tdata/pluma_edge_paths with the memory.
void PathApplyAppConfig(const MTPJSONValue *value);

// Main thread: the path chosen changed; the sessions of datacenter 1
// reconnect.
[[nodiscard]] rpl::producer<> PathSwitches();

// Main thread: the network changed; the app config is asked again, its
// pluma_edge and country may differ there.
[[nodiscard]] rpl::producer<> PathNetworkChanges();

struct PathRound;

// The probes of the main session of datacenter 1 of an account, on the
// session's thread.
class PathProber final {
public:
	PathProber(not_null<Instance*> instance, not_null<QThread*> thread);
	~PathProber();

	// The session's connection works, through this path.
	void connected(const QString &path);

	// A request went out on the session's connection; a byte came back.
	// A request without a byte back for suspect_ms makes the paths rank.
	void sent();
	void received();

private:
	struct Probe;

	void tick();
	void start(PathRound round);
	void startProbe(const QString &path);
	void probeReady(not_null<Probe*> probe);
	void probeAnswered(not_null<Probe*> probe);
	void probePacket(not_null<Probe*> probe, bytes::const_span packet);
	void probeClosed(not_null<Probe*> probe);
	void probeCheck(not_null<Probe*> probe);
	void finish(not_null<Probe*> probe, path::Outcome outcome);
	void settle();
	void startLater();
	void complete();
	[[nodiscard]] bool gateDone() const;

	const not_null<Instance*> _instance;
	const not_null<QThread*> _thread;
	std::unique_ptr<PathRound> _round;
	std::vector<std::unique_ptr<Probe>> _probes;
	base::Timer _tick;
	base::Timer _suspect;
	base::Timer _stagger;
	base::Timer _late;
	base::Timer _settle;
	path::Time _suspectTimeout = 0;

};

} // namespace MTP::details
