#!/usr/bin/env bash
# Installs a pinned tool, checked against its SHA-256, into
# ${RUNNER_TEMP:-$HOME/.local}/pluma-bin and adds it to the PATH of the next
# workflow steps:
#   setup.sh age     age, to encrypt builds for a real server (Linux x86-64,
#                    macOS arm64, Windows x86-64);
#   setup.sh ccache  the ccache of upstream.env: on Linux x86-64 for the
#                    statistics and the trimming of the cache (the compiler
#                    runs through the image's own ccache, as upstream), on
#                    macOS arm64 and Windows x86-64 for the client's build.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
tool=${1:?usage: setup.sh age|ccache}

AGE_VERSION=1.3.2

bin=${RUNNER_TEMP:-$HOME/.local}/pluma-bin
mkdir -p "$bin"
python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi
platform="$(uname -s)_$(uname -m)"

case $tool/$platform in
age/Linux_x86_64)
	url=https://github.com/FiloSottile/age/releases/download/v$AGE_VERSION/age-v$AGE_VERSION-linux-amd64.tar.gz
	sha256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
	member=age/age
	;;
age/Darwin_arm64)
	url=https://github.com/FiloSottile/age/releases/download/v$AGE_VERSION/age-v$AGE_VERSION-darwin-arm64.tar.gz
	sha256=e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5
	member=age/age
	;;
age/MINGW64_NT*_x86_64 | age/MSYS_NT*_x86_64)
	url=https://github.com/FiloSottile/age/releases/download/v$AGE_VERSION/age-v$AGE_VERSION-windows-amd64.zip
	sha256=f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7
	member=age/age.exe
	;;
ccache/Linux_x86_64)
	url=https://github.com/ccache/ccache/releases/download/v$CCACHE_VERSION/ccache-$CCACHE_VERSION-linux-x86_64-glibc.tar.xz
	sha256=$CCACHE_SHA256
	member=ccache-$CCACHE_VERSION-linux-x86_64-glibc/ccache
	;;
# The archives of ccache 4.13.6, the CCACHE_VERSION of upstream.env; an update
# of it changes these too.
ccache/Darwin_arm64)
	url=https://github.com/ccache/ccache/releases/download/v$CCACHE_VERSION/ccache-$CCACHE_VERSION-darwin.tar.gz
	sha256=0274210ec9c9936ed5711d59b0de3167a51216a588ddde35f6bc828f366fe6d9
	member=ccache-$CCACHE_VERSION-darwin/ccache
	;;
ccache/MINGW64_NT*_x86_64 | ccache/MSYS_NT*_x86_64)
	url=https://github.com/ccache/ccache/releases/download/v$CCACHE_VERSION/ccache-$CCACHE_VERSION-windows-x86_64.zip
	sha256=3d7cebb05850ad704e197b3f1d3f0f924ab6c9fdfc561578e146184fe9d89380
	member=ccache-$CCACHE_VERSION-windows-x86_64/ccache.exe
	;;
*)
	echo "setup: no pinned $tool for $platform" >&2
	exit 1
	;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/${url##*/}"
curl -fsSL --retry 3 -o "$archive" "$url"
if command -v sha256sum >/dev/null; then
	got=$(sha256sum "$archive" | awk '{print $1}')
else
	got=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
if [ "$got" != "$sha256" ]; then
	echo "setup: ${url##*/} has SHA-256 $got, expected $sha256" >&2
	exit 1
fi
# Python unpacks every format on every system alike.
$python -I - "$archive" "$member" "$bin" <<'EOF'
import os, shutil, sys, tarfile, zipfile
archive, member, bin_dir = sys.argv[1:]
target = os.path.join(bin_dir, os.path.basename(member))
if archive.endswith(".zip"):
    with zipfile.ZipFile(archive) as z, z.open(member) as src, open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
else:
    with tarfile.open(archive) as t, t.extractfile(member) as src, open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
os.chmod(target, 0o755)
EOF
if [ -n "${GITHUB_PATH:-}" ]; then
	if command -v cygpath >/dev/null; then
		cygpath -w "$bin" >>"$GITHUB_PATH"
	else
		echo "$bin" >>"$GITHUB_PATH"
	fi
fi
echo "setup: $tool $("$bin/${member##*/}" --version | head -n 1) in $bin"
