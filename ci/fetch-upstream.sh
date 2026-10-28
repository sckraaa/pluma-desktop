#!/usr/bin/env bash
# Fetches the upstream commit upstream.env pins: one commit, no history.
#   fetch-upstream.sh sparse  into ./upstream, only the files ci/patch.py
#                             reads and checks (ci/patch.py --paths and
#                             --submodule-paths): seconds, for the check job
#                             and the tests;
#   fetch-upstream.sh full    into $UPSTREAM_DIR (default ./upstream) with
#                             every submodule, for a build.
# Text files are checked out with LF line endings on every system (Windows
# included, where Git would write CRLF): ci/patch.py matches the upstream
# byte for byte. Batch files stay CRLF, as the upstream's .gitattributes asks.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
mode=${1:?usage: fetch-upstream.sh sparse|full}

# GNU timeout where there is one (Linux, Git for Windows; macOS only with
# coreutils).
with_timeout() {
	local limit=$1
	shift
	if command -v timeout >/dev/null; then
		timeout "$limit" "$@"
	elif command -v gtimeout >/dev/null; then
		gtimeout "$limit" "$@"
	else
		"$@"
	fi
}

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "fetch-upstream: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

# Settings for every git command below, submodules included.
export GIT_CONFIG_COUNT=4
export GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false
export GIT_CONFIG_KEY_1=core.eol GIT_CONFIG_VALUE_1=lf
export GIT_CONFIG_KEY_2=core.longpaths GIT_CONFIG_VALUE_2=true
export GIT_CONFIG_KEY_3=advice.detachedHead GIT_CONFIG_VALUE_3=false

python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi

case $mode in
sparse)
	dir=upstream
	;;
full)
	dir=${UPSTREAM_DIR:-upstream}
	;;
*)
	echo "usage: fetch-upstream.sh sparse|full" >&2
	exit 2
	;;
esac

# Fetches commit $3 of $2 into the new repository $1; in sparse mode only
# the paths on standard input are checked out.
fetch_commit() {
	local into=$1 url=$2 ref=$3
	rm -rf "$into"
	git init -q "$into"
	git -C "$into" remote add origin "$url"
	local fetch=(fetch -q --depth 1)
	if [ "$mode" = sparse ]; then
		# Only the blobs of these paths are downloaded, at checkout.
		git -C "$into" config core.sparseCheckout true
		sed 's|^|/|' >"$into/.git/info/sparse-checkout"
		fetch+=(--filter=blob:none)
	fi
	retry with_timeout 10m git -C "$into" "${fetch[@]}" origin "$ref"
	retry with_timeout 10m git -C "$into" checkout -q FETCH_HEAD
	test "$(git -C "$into" rev-parse HEAD)" = "$ref"
}

case $mode in
sparse)
	$python -I ci/patch.py --paths | fetch_commit "$dir" "$UPSTREAM_REPO" "$UPSTREAM_REF"
	# The files of submodules the patch reads, from the commits the pinned
	# upstream records for them.
	subs=$($python -I ci/patch.py --submodule-paths | awk '{print $1}' | sort -u)
	for sub in $subs; do
		commit=$(git -C "$dir" ls-tree HEAD "$sub" | awk '$2 == "commit" {print $3}')
		url=$(git -C "$dir" config -f .gitmodules --get "submodule.$sub.url")
		if [ -z "$commit" ] || [ -z "$url" ]; then
			echo "fetch-upstream: $sub is not a submodule of the pinned upstream" >&2
			exit 1
		fi
		$python -I ci/patch.py --submodule-paths | awk -v s="$sub" '$1 == s {print $2}' |
			fetch_commit "$dir/$sub" "$url" "$commit"
	done
	;;
full)
	fetch_commit "$dir" "$UPSTREAM_REPO" "$UPSTREAM_REF" </dev/null
	# Git clones every submodule first and checks them out after; a clone
	# that fails stops it before the checkouts. A plain retry then skips a
	# submodule whose fresh clone already has the recorded commit as HEAD,
	# and leaves its work tree empty: --force checks out each one anyway.
	retry with_timeout 30m git -C "$dir" submodule update -q --init --recursive --force --depth 1 --jobs 4
	# Every submodule is checked out: its index is its commit. The command
	# runs in each submodule, where git sets $displaypath.
	# shellcheck disable=SC2016
	git -C "$dir" submodule foreach --recursive --quiet \
		'git diff --cached --quiet --ignore-submodules=all || { echo "fetch-upstream: $displaypath is not checked out" >&2; exit 1; }'
	;;
esac
echo "fetch-upstream: $UPSTREAM_TAG ($UPSTREAM_REF), $mode, in $dir"
