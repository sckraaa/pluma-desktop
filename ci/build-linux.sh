#!/usr/bin/env bash
# Builds the patched $UPSTREAM_DIR (default ./upstream) for Linux in the
# upstream's build environment (ci/linux-env.sh), the way the upstream CI
# does, but in the Release configuration: build-linux.sh <image>. The result
# is $UPSTREAM_DIR/out/Release/Telegram; ci/package.sh linux packs it.
#
# The compiler runs through ccache in $CCACHE_DIR (default ./.ccache), which
# the workflow keeps in the GitHub Actions cache: the static ccache of
# upstream.env from the PATH (ci/setup.sh ccache) in place of the image's
# ccache 3.7.7. That one keeps each sixteenth of the cache within a sixteenth
# of CCACHE_MAXSIZE, so it evicts a precompiled header larger than that as
# soon as it stores it, and every file built with the header misses.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./config/app.env
. ./upstream.env
image=${1:?usage: build-linux.sh <image>}
dir=$(cd "${UPSTREAM_DIR:-upstream}" && pwd)
ccache_dir=${CCACHE_DIR:-$PWD/.ccache}
mkdir -p "$ccache_dir"

if [ ! -f "$dir/pluma-patch.txt" ]; then
	echo "build-linux: $dir is not patched (ci/configure.sh)" >&2
	exit 1
fi
if ! ccache=$(command -v ccache) || ! "$ccache" --version | head -n 1 | grep -qxF "ccache version $CCACHE_VERSION"; then
	echo "build-linux: no ccache $CCACHE_VERSION on the PATH (ci/setup.sh ccache)" >&2
	exit 1
fi

for attempt in 1 2 3; do
	if docker pull -q "$image"; then
		break
	fi
	if [ "$attempt" = 3 ]; then
		echo "build-linux: cannot pull $image" >&2
		exit 1
	fi
	sleep $((attempt * 15))
done

# The flags of the Release configuration, with the one ccache needs to reuse
# precompiled headers (as the upstream CI does for Debug).
release_flags="-O3 -DNDEBUG -fpch-preprocess"
docker run --rm \
	-u "$(id -u)" \
	-v "$dir:/usr/src/tdesktop" \
	-v "$ccache_dir:/var/cache/ccache" \
	-v "$ccache:/usr/bin/ccache:ro" \
	-e CONFIG=Release \
	-e CCACHE_SLOPPINESS=pch_defines,time_macros \
	-e CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-3G}" \
	"$image" \
	env -u CCACHE_DISABLE /usr/src/tdesktop/Telegram/build/docker/centos_env/build.sh \
	-D CMAKE_CONFIGURATION_TYPES=Release \
	-D "CMAKE_C_FLAGS_RELEASE=$release_flags" \
	-D "CMAKE_CXX_FLAGS_RELEASE=$release_flags" \
	-D "TDESKTOP_API_ID=$PLUMA_API_ID" \
	-D "TDESKTOP_API_HASH=$PLUMA_API_HASH" \
	-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON \
	-D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON

binary="$dir/out/Release/Telegram"
if [ ! -x "$binary" ]; then
	echo "build-linux: no $binary" >&2
	exit 1
fi
echo "build-linux: $binary ($(du -h "$binary" | awk '{print $1}'))"
