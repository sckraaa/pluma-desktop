#!/usr/bin/env bash
# Prints the statistics of a build's compilations through ccache and the
# sources that missed the cache, from the stats log the workflow gives the
# build ($CCACHE_STATSLOG), and hands the number of misses to the workflow
# (misses=N in $GITHUB_OUTPUT): a build that missed nothing saves no new
# entry. The stats were zeroed before the build.
set -euo pipefail

ccache --show-stats --verbose || true
misses=$(ccache --print-stats 2>/dev/null | tr -d '\r' | awk -F '\t' '$1 == "cache_miss" {print $2; exit}' || true)
misses=${misses:-0}

log=${CCACHE_STATSLOG:-}
if [ -n "$log" ] && command -v cygpath >/dev/null; then
	log=$(cygpath -u "$log")
fi
if [ -n "$log" ] && [ -f "$log" ]; then
	# A compilation is a line "# <source>" followed by the IDs of its
	# counters. A source compiled for two architectures is listed once.
	missed=$(tr -d '\r' <"$log" | awk '/^# / {source = substr($0, 3); next} $0 == "cache_miss" {print source}' | sort -u)
	if [ -z "$missed" ]; then
		echo "ccache-stats: no source missed the cache"
	else
		n=$(printf '%s\n' "$missed" | wc -l | tr -d ' ')
		echo "ccache-stats: $n sources missed the cache:"
		printf '%s\n' "$missed" | sed -n '1,100p'
		if [ "$n" -gt 100 ]; then
			echo "ccache-stats: and $((n - 100)) more"
		fi
	fi
elif [ -n "$log" ] && [ "$misses" != 0 ]; then
	# ccache writes the log into an existing folder only, and says nothing
	# when it cannot.
	echo "ccache-stats: $misses misses, but no stats log at $log" >&2
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	echo "misses=$misses" >>"$GITHUB_OUTPUT"
fi
