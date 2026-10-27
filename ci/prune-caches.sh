#!/usr/bin/env bash
# Deletes the caches of main that a newer one of the same kind replaced:
# prune-caches.sh <key prefix>... Cache entries cannot be updated, so a build
# saves a new one whenever its content changed; keeping only the newest of
# each kind keeps the Linux, Windows and macOS caches side by side within the
# 10 GB of a repository instead of evicting each other. Prints the
# repository's cache usage and warns above 9 GB.
#
# Environment: GH_TOKEN with actions: write, GITHUB_REPOSITORY.
set -euo pipefail
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
if [ $# = 0 ]; then
	echo "usage: prune-caches.sh <key prefix>..." >&2
	exit 2
fi
for prefix in "$@"; do
	ids=$(gh cache list --repo "$GITHUB_REPOSITORY" --ref refs/heads/main --key "$prefix" \
		--sort created_at --order desc --limit 100 --json id --jq '.[1:][].id')
	n=0
	for id in $ids; do
		gh cache delete --repo "$GITHUB_REPOSITORY" "$id"
		n=$((n + 1))
	done
	echo "prune-caches: $prefix: $n older entries deleted"
done
gh cache list --repo "$GITHUB_REPOSITORY" --limit 100 --json key,sizeInBytes \
	--jq '.[] | "prune-caches: \(.sizeInBytes / 1e9 * 100 | floor / 100) GB \(.key)"'
used=$(gh api "repos/$GITHUB_REPOSITORY/actions/cache/usage" --jq .active_caches_size_in_bytes)
echo "prune-caches: $((used / 1000000)) MB of 10000 MB used"
if [ "$used" -gt 9000000000 ]; then
	echo "::warning::The caches take $((used / 1000000)) MB of the repository's 10 GB; the oldest get evicted (README, Caches)."
fi
