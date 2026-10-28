#!/usr/bin/env bash
# The budget of the repository's GitHub Actions cache (README, Caches). Above
# 10 GB GitHub evicts the least recently used entries, whichever system's they
# are, so each kind of entry has a cap, and the caps add up to 9000 MB. Only
# runs on main save entries, and a job deletes the entries of its kind that a
# new one supersedes before it saves that one: a kind never has two entries,
# not even while one is being saved.
#   cache-budget.sh cap <kind>            the cap of a kind, in MB;
#   cache-budget.sh room <kind> <path>... before an entry of the kind is saved:
#                                         measures <path>... as actions/cache
#                                         stores them (tar, zstd). Within the
#                                         cap, deletes the kind's entries of
#                                         this branch and writes save=true to
#                                         $GITHUB_OUTPUT; above it, reports an
#                                         error and writes save=false.
# A kind is the prefix of its keys without the dash.
#
# Environment for room: GH_TOKEN with actions: write, GITHUB_REPOSITORY,
# GITHUB_REF.
set -euo pipefail
usage="usage: cache-budget.sh cap <kind> | room <kind> <path>..."
mode=${1:?$usage}
kind=${2:?$usage}
shift 2

case $kind in
linux-ccache) cap=1500 ;;
windows-ccache) cap=1500 ;;
macos-ccache) cap=2250 ;;
windows-libs) cap=1750 ;;
macos-libs) cap=2000 ;;
*)
	echo "cache-budget: no cap for $kind" >&2
	exit 2
	;;
esac

case $mode in
cap)
	echo "$cap"
	;;
room)
	if [ $# = 0 ]; then
		echo "$usage" >&2
		exit 2
	fi
	: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}" "${GITHUB_REF:?GITHUB_REF is not set}"
	# About as actions/cache packs an entry: a tar archive through zstd.
	size=$(tar -cPf - "$@" | zstd -T0 -3 -q -c | wc -c)
	mb=$((size / 1000000))
	echo "cache-budget: $kind takes $mb MB of its $cap MB"
	if [ "$mb" -gt "$cap" ]; then
		echo "::error::The new $kind cache entry takes $mb MB, over its cap of $cap MB, and is not saved. Raise its cap in ci/cache-budget.sh and lower another's (README, Caches)."
		echo "save=false" >>"${GITHUB_OUTPUT:-/dev/null}"
		exit 0
	fi
	ids=$(gh cache list --repo "$GITHUB_REPOSITORY" --ref "$GITHUB_REF" --key "$kind-" \
		--limit 100 --json id --jq '.[].id')
	n=0
	for id in $ids; do
		gh cache delete --repo "$GITHUB_REPOSITORY" "$id"
		n=$((n + 1))
	done
	echo "cache-budget: $kind: $n superseded entries deleted"
	echo "save=true" >>"${GITHUB_OUTPUT:-/dev/null}"
	;;
*)
	echo "$usage" >&2
	exit 2
	;;
esac
