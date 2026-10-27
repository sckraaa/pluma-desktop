#!/usr/bin/env bash
# The Docker image the Linux client is built in: the upstream's own build
# environment, Telegram/build/docker/centos_env (Rocky Linux 8, gcc-toolset-15
# and every library, Qt included, built from source). Building it takes two
# to four hours, so it is built once for each version of that directory and
# kept in the GitHub container registry.
#   linux-env.sh ref     prints the image of the pinned upstream:
#                        <image>:<tree hash of centos_env>-<recipe>;
#   linux-env.sh ensure  builds and pushes it unless the registry has it.
#
# Needs a checkout of the upstream in $UPSTREAM_DIR (default ./upstream; the
# sparse one is enough). Environment: PLUMA_LINUX_IMAGE (default
# ghcr.io/<owner>/pluma-desktop-linux-env), GH_TOKEN and GITHUB_ACTOR to log
# in to ghcr.io (packages: write for ensure).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
mode=${1:?usage: linux-env.sh ref|ensure}
dir=${UPSTREAM_DIR:-upstream}
env_dir=Telegram/build/docker/centos_env

# Changes when this script builds the image differently: a new tag.
RECIPE=r1

image=${PLUMA_LINUX_IMAGE:-}
if [ -z "$image" ]; then
	owner=${GITHUB_REPOSITORY_OWNER:?set PLUMA_LINUX_IMAGE, or GITHUB_REPOSITORY_OWNER as in CI}
	image="ghcr.io/$(printf '%s' "$owner" | tr '[:upper:]' '[:lower:]')/pluma-desktop-linux-env"
fi
tree=$(git -C "$dir" rev-parse "HEAD:$env_dir")
ref="$image:${tree:0:16}-$RECIPE"

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "linux-env: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

case $mode in
ref)
	echo "$ref"
	exit 0
	;;
ensure) ;;
*)
	echo "usage: linux-env.sh ref|ensure" >&2
	exit 2
	;;
esac

if [ -n "${GH_TOKEN:-}" ]; then
	printf '%s' "$GH_TOKEN" | retry docker login ghcr.io -u "${GITHUB_ACTOR:?}" --password-stdin >/dev/null
fi
if docker buildx imagetools inspect "$ref" >/dev/null 2>&1; then
	echo "linux-env: $ref is in the registry"
	echo "image=$ref" >>"${GITHUB_OUTPUT:-/dev/null}"
	exit 0
fi
echo "linux-env: building $ref"

if [ -n "${CI:-}" ]; then
	# The image takes tens of GB while it builds.
	df -h /
	sudo rm -rf /usr/local/lib/android /usr/share/dotnet /usr/share/swift /opt/ghc /usr/local/.ghcup \
		/opt/hostedtoolcache /usr/local/share/boost /usr/local/julia* || true
	docker image prune --all --force >/dev/null || true
	df -h /
	if ! python3 -c 'import jinja2' 2>/dev/null; then
		retry sudo apt-get update -q
		retry sudo apt-get install -y -q --no-install-recommends python3-jinja2
	fi
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; docker buildx rm pluma-linux-env >/dev/null 2>&1 || true' EXIT

# The upstream CI's variant: no debug information, no LTO in the libraries.
env DEBUG= LTO= python3 "$dir/$env_dir/gen_dockerfile.py" >"$tmp/Dockerfile"
grep -q '^FROM rockylinux:8 AS builder$' "$tmp/Dockerfile"

docker buildx create --name pluma-linux-env --driver docker-container \
	--driver-opt "image=$BUILDKIT_IMAGE" --use >/dev/null
# Every stage's layers go to a cache image next to it, so that an image for
# a changed centos_env rebuilds only the changed stages. A second attempt
# (a download that failed) rebuilds only the stages the first one did not
# finish: the builder keeps them.
build=(docker buildx build
	--file "$tmp/Dockerfile"
	--tag "$ref"
	--label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY:-sckraaa/pluma-desktop}"
	--label "org.opencontainers.image.description=Build environment of Pluma for Linux: $env_dir of tdesktop $UPSTREAM_TAG"
	--label "org.opencontainers.image.revision=$UPSTREAM_REF"
	--cache-from "type=registry,ref=$image:buildcache"
	--cache-to "type=registry,ref=$image:buildcache,mode=max,ignore-error=true"
	--provenance=false --sbom=false
	--progress=plain
	--push
	"$dir/$env_dir")
if ! "${build[@]}"; then
	echo "linux-env: the build failed; trying once more" >&2
	"${build[@]}"
fi
echo "linux-env: pushed $ref"
echo "image=$ref" >>"${GITHUB_OUTPUT:-/dev/null}"
