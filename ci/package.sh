#!/usr/bin/env bash
# Packs the client built in $UPSTREAM_DIR (default ./upstream) into ./out:
#   package.sh linux dev|server    pluma-desktop-<version>-linux[-dev].tar.xz:
#                                  Pluma/Pluma, Pluma/Updater and
#                                  Pluma/chat.pluma.desktop.desktop;
#   package.sh windows dev|server  pluma-desktop-<version>-windows[-dev].zip:
#                                  Pluma/Pluma.exe and Pluma/Updater.exe;
#   package.sh macos dev|server    pluma-desktop-<version>-macos[-dev].zip:
#                                  Pluma.app with the Icon Composer icon of
#                                  brand/Icon.icon, signed ad hoc, with the
#                                  Updater in Contents/Frameworks.
# The Updater, next to the app, installs the update packages the app
# downloads (task 054 of the server repository).
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
rm -rf out symbols
mkdir -p out

case $os in
linux)
	mkdir "$work/$app"
	cp "$out/Telegram" "$work/$app/$app"
	cp "$out/Updater" "$work/$app/Updater"
	cp "$dir/lib/xdg/org.telegram.desktop.desktop" "$work/$app/$PLUMA_APP_ID.desktop"
	file=$name.tar.xz
	tar -C "$work" -cJf "out/$file" "$app"
	;;
windows)
	mkdir "$work/$app"
	cp "$out/Telegram.exe" "$work/$app/$app.exe"
	cp "$out/Updater.exe" "$work/$app/Updater.exe"
	file=$name.zip
	$python -I -c 'import shutil, sys; shutil.make_archive(sys.argv[1], "zip", sys.argv[2], sys.argv[3])' \
		"out/$name" "$work" "$app"
	;;
macos)
	bundle="$work/$app.app"
	ditto "$out/Telegram.app" "$bundle"
	if [ ! -x "$bundle/Contents/Frameworks/Updater" ]; then
		echo "package: the app has no Updater in Contents/Frameworks" >&2
		exit 1
	fi
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
	# macOS 26 draws an icon of the old format on a grey plate, so the app
	# takes the Icon Composer icon: actool compiles it into an asset catalog
	# (with renderings for older systems) and an .icns, which replace the
	# upstream's. Its catalog holds the icon alone; anything else in it would
	# be lost, so it stops the build.
	resources="$bundle/Contents/Resources"
	if [ "$(plist CFBundleIconName)" != Icon ] || [ "$(plist CFBundleIconFile)" != Icon ]; then
		echo "package: the app's icon is not named Icon (Info.plist)" >&2
		exit 1
	fi
	xcrun assetutil --info "$resources/Assets.car" | $python -I -c '
import json, sys
names = {a["Name"] for a in json.load(sys.stdin) if "Name" in a}
other = sorted(n for n in names if n != "Icon" and not n.startswith("ZZZZPackedAsset-"))
if other:
    sys.exit("package: the upstream asset catalog holds more than the icon: " + ", ".join(other))
'
	mkdir "$work/icon"
	xcrun actool --compile "$work/icon" --platform macosx \
		--minimum-deployment-target "$(plist LSMinimumSystemVersion)" \
		--app-icon Icon --output-partial-info-plist "$work/icon/Info.plist" \
		brand/Icon.icon >/dev/null
	cp "$work/icon/Assets.car" "$work/icon/Icon.icns" "$resources/"
	# The executables are stripped before the signature, as upstream's
	# release script does (Telegram/build/build.sh:320-325 at a1e89e1f): the
	# Release build keeps their symbols (COPY_PHASE_STRIP NO in
	# Telegram/CMakeLists.txt). Unstripped the app was 1.5 GB, more than an
	# update package may hold (1 GiB uncompressed: packer.cpp:312, :380;
	# ci/pack_update.py). Crash reports are off: nothing needs the symbols.
	exe="$bundle/Contents/MacOS/$(plist CFBundleExecutable)"
	# The symbols go first into a dSYM, as upstream keeps its own
	# (dump_syms before strip, Telegram/build/build.sh:290-317): with it a
	# crash report of this build is read on a Mac (atos -o
	# <dSYM>/Contents/Resources/DWARF/<exe> -l <load address> <addresses>;
	# the report's UUID matches dwarfdump --uuid). symbols/ is not out/: the
	# release takes every zip of out/ for an app.
	mkdir -p symbols
	xcrun dsymutil "$exe" -o "$work/$(basename "$exe").dSYM"
	tar --options xz:threads=0 -C "$work" -cJf "symbols/$name.dSYM.tar.xz" "$(basename "$exe").dSYM"
	strip "$exe" "$bundle/Contents/Frameworks/Updater"
	echo "package: the largest files of the app:"
	find "$bundle" -type f -size +10M -exec du -h {} + | sort -h | tail -n 8 | sed "s|$work/||"
	bytes=$($python -I -c '
import os, sys
total = 0
for root, dirs, files in os.walk(sys.argv[1]):
    for f in files:
        p = os.path.join(root, f)
        if not os.path.islink(p):
            total += os.path.getsize(p)
print(total)
' "$bundle")
	echo "package: the app holds $bytes bytes"
	if [ "$bytes" -gt $((1 << 30)) ]; then
		echo "package: the app holds more than the 1 GiB an update package may (ci/pack_update.py)" >&2
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
