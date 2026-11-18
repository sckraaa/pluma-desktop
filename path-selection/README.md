# The path to the server by probes

Task 113 and ADR 0073 of the server repository; the README's "The path to
the server by probes" says what the app does. `ci/patch.py` copies these
files into `Telegram/SourceFiles/mtproto/details` of a build with edges
(`PATH_FILES`), and checks that the build has them unchanged:

- `mtproto_path_rules.h`: the rules in plain C++, without Qt: the
  parameters of `pluma_probe`, the bytes of `pluma.probe` and
  `pluma.probeData`, what a probe found, the score of a path, the memory by
  network and the choice between the paths;
- `mtproto_path_select.h`, `mtproto_path_select.cpp`: the memory in
  `tdata/pluma_edge_paths`, the key of the network, the rounds of probes on
  connections of their own and the switches of the sessions.

`rules_test.cpp` is the test of the rules; `ci/path_rules_test.py` builds it
with the system's compiler (C++20, sanitizers on) and runs it. It is not
part of the app.
