#!/usr/bin/env bash
# Packs the client built in $UPSTREAM_DIR (default ./upstream) into ./out:
#   package.sh linux dev|server    pluma-desktop-<version>-linux[-dev].tar.xz:
#                                  Pluma/Pluma and Pluma/chat.pluma.desktop.desktop;
#   package.sh windows dev|server  pluma-desktop-<version>-windows[-dev].zip:
#                                  Pluma/Pluma.exe;
#   package.sh macos dev|server    pluma-desktop-<version>-macos[-dev].zip:
#                                  Pluma.app, signed ad hoc.
# The executables keep the upstream's names inside the build and get Pluma's
# here. Each file comes with its SHA-256.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
os=${1:?usage: package.sh linux|windows|macos dev|server}
target=${2:?usage: package.sh linux|windows|macos dev|server}
dir=$(cd "${UPSTREAM_DIR:-upstream}" && pwd)
out=$dir/out/Release
case $target in
dev) suffix=-dev ;;
server) suffix= ;;
*)
	echo "usage: package.sh linux|windows|macos dev|server" >&2
	exit 2
	;;
esac
name="pluma-desktop-$UPSTREAM_VERSION-$os$suffix"
app=$PLUMA_APP_NAME

python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rm -rf out
mkdir -p out

case $os in
linux)
	mkdir "$work/$app"
	cp "$out/Telegram" "$work/$app/$app"
	cp "$dir/lib/xdg/org.telegram.desktop.desktop" "$work/$app/$PLUMA_APP_ID.desktop"
	file=$name.tar.xz
	tar -C "$work" -cJf "out/$file" "$app"
	;;
windows)
	mkdir "$work/$app"
	cp "$out/Telegram.exe" "$work/$app/$app.exe"
	file=$name.zip
	$python -I -c 'import shutil, sys; shutil.make_archive(sys.argv[1], "zip", sys.argv[2], sys.argv[3])' \
		"out/$name" "$work" "$app"
	;;
macos)
	bundle="$work/$app.app"
	ditto "$out/Telegram.app" "$bundle"
	plist() {
		/usr/libexec/PlistBuddy -c "Print :$1" "$bundle/Contents/Info.plist"
	}
	if [ "$(plist CFBundleIdentifier)" != "$PLUMA_APP_ID" ]; then
		echo "package: the app is $(plist CFBundleIdentifier), not $PLUMA_APP_ID" >&2
		exit 1
	fi
	if [ "$(plist CFBundleShortVersionString)" != "$UPSTREAM_VERSION" ]; then
		echo "package: the app is version $(plist CFBundleShortVersionString), upstream.env says $UPSTREAM_VERSION" >&2
		exit 1
	fi
	# No Developer ID: an ad hoc signature, which Apple Silicon requires to
	# run the app at all. Gatekeeper asks the user once (README).
	codesign --force --deep --sign - "$bundle"
	codesign --verify --deep --strict "$bundle"
	file=$name.zip
	ditto -c -k --keepParent "$bundle" "out/$file"
	;;
*)
	echo "usage: package.sh linux|windows|macos dev|server" >&2
	exit 2
	;;
esac

if command -v sha256sum >/dev/null; then
	(cd out && sha256sum "$file" >"$file.sha256")
else
	(cd out && shasum -a 256 "$file" >"$file.sha256")
fi
echo "package: out/$file ($(du -h "out/$file" | awk '{print $1}'))"
echo "file=$file" >>"${GITHUB_OUTPUT:-/dev/null}"
