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
#                                         stores them (tar, zstd), then as
#                                         admit;
#   cache-budget.sh admit <kind> <MB>     whether an entry of <MB> may be
#                                         saved: if so, deletes the kind's
#                                         entries of this branch and writes
#                                         save=true to $GITHUB_OUTPUT,
#                                         otherwise save=false.
# An entry within its cap is saved. One over it is an error of the run, and is
# saved only where the cache cannot pass 10 GB by it: in place of entries that
# take as much or more, or when its overrun and those of the other entries fit
# in the reserve the caps leave. Entries of other branches count whole, being
# outside the caps.
# A kind is the prefix of its keys without the dash.
#
# Environment for room and admit: GH_TOKEN with actions: write,
# GITHUB_REPOSITORY, GITHUB_REF.
set -euo pipefail
usage="usage: cache-budget.sh cap <kind> | room <kind> <path>... | admit <kind> <MB>"
mode=${1:?$usage}
kind=${2:?$usage}
shift 2

# 10 GB less the caps, in MB.
reserve=1000

# The cap of kind $1, in MB.
cap_of() {
	case $1 in
	linux-ccache) echo 2000 ;;
	windows-ccache) echo 2500 ;;
	macos-ccache) echo 2250 ;;
	windows-libs) echo 1500 ;;
	macos-libs) echo 750 ;;
	*) return 1 ;;
	esac
}

if ! cap=$(cap_of "$kind"); then
	echo "cache-budget: no cap for $kind" >&2
	exit 2
fi

case $mode in
cap)
	echo "$cap"
	exit 0
	;;
room)
	if [ $# = 0 ]; then
		echo "$usage" >&2
		exit 2
	fi
	# About as actions/cache packs an entry: a tar archive through zstd.
	size=$(tar -cPf - "$@" | zstd -T0 -3 -q -c | wc -c)
	mb=$((size / 1000000))
	;;
admit)
	mb=${1:-}
	if [[ ! $mb =~ ^[0-9]+$ ]]; then
		echo "$usage" >&2
		exit 2
	fi
	;;
*)
	echo "$usage" >&2
	exit 2
	;;
esac

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}" "${GITHUB_REF:?GITHUB_REF is not set}"
echo "cache-budget: $kind takes $mb MB of its $cap MB"
# The kind's entries of this branch, which the new one supersedes, and what
# the others take above their caps.
entries=$(gh cache list --repo "$GITHUB_REPOSITORY" --limit 100 --json id,key,ref,sizeInBytes \
	--jq '.[] | [.id, .key, .ref, .sizeInBytes] | @tsv')
ids="" replaced=0 over=0
while IFS=$'\t' read -r id key ref bytes; do
	if [ -z "$id" ]; then
		continue
	fi
	entry=$((bytes / 1000000))
	rest=${key#*-}
	other=${key%%-*}-${rest%%-*}
	if [ "$other" = "$kind" ] && [ "$ref" = "$GITHUB_REF" ]; then
		ids="$ids $id"
		replaced=$((replaced + entry))
	elif [ "$ref" = refs/heads/main ] && c=$(cap_of "$other"); then
		if [ "$entry" -gt "$c" ]; then
			over=$((over + entry - c))
		fi
	else
		over=$((over + entry))
	fi
done <<<"$entries"

if [ "$mb" -gt "$cap" ]; then
	fix="Raise its cap in ci/cache-budget.sh and lower another's (README, Caches)."
	if [ "$mb" -le "$replaced" ]; then
		echo "::error::The new $kind cache entry takes $mb MB, over its cap of $cap MB. It is saved in place of the $replaced MB it supersedes. $fix"
	elif [ $((mb - cap + over)) -le "$reserve" ]; then
		echo "::error::The new $kind cache entry takes $mb MB, over its cap of $cap MB. It is saved: with the $over MB the other entries take above their caps, the cache keeps within 10 GB. $fix"
	else
		echo "::error::The new $kind cache entry takes $mb MB, over its cap of $cap MB, and is not saved: with the $over MB the other entries take above their caps, the cache could pass 10 GB. $fix"
		echo "save=false" >>"${GITHUB_OUTPUT:-/dev/null}"
		exit 0
	fi
fi
n=0
for id in $ids; do
	gh cache delete --repo "$GITHUB_REPOSITORY" "$id"
	n=$((n + 1))
done
echo "cache-budget: $kind: $n superseded entries deleted"
echo "save=true" >>"${GITHUB_OUTPUT:-/dev/null}"
