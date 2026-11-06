#!/usr/bin/env bash
# Makes the disk image of the macOS app: make-dmg.sh APP DMG.
# Its window shows the app, a link to /Applications and the background of
# brand/dmg (an arrow and the hint to drag the app there), the icons where
# the background expects them (ci/dmg-settings.py). dmgbuild writes the
# window's .DS_Store itself, without Finder, so it works on a runner with no
# one at the screen; it and the packages it needs are pinned in
# ci/dmg-requirements.txt and installed with their hashes into a throwaway
# venv. The image is then mounted and checked: the app's signature as it
# went in, and the link. PLUMA_DMGBUILD names a dmgbuild to run instead
# (the tests' fake).
set -euo pipefail
cd "$(dirname "$0")/.."
usage="usage: make-dmg.sh APP DMG"
app=${1:?$usage}
dmg=${2:?$usage}
. ./config/app.env
if [ "$(basename "$app")" != "$PLUMA_APP_NAME.app" ] || [ ! -d "$app" ]; then
	echo "make-dmg: $app is not a $PLUMA_APP_NAME.app" >&2
	exit 1
fi

work=$(mktemp -d)
mnt=$work/mnt
mounted=
cleanup() {
	if [ -n "$mounted" ]; then
		hdiutil detach "$mnt" -force >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

dmgbuild=${PLUMA_DMGBUILD:-}
if [ -z "$dmgbuild" ]; then
	python3 -I -m venv "$work/venv"
	"$work/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
		--only-binary=:all: --no-deps -r ci/dmg-requirements.txt
	dmgbuild=$work/venv/bin/dmgbuild
fi
# The volume name is the app's, never the version: it names the window.
"$dmgbuild" -s ci/dmg-settings.py -D app="$app" -D background="$PWD/brand/dmg/background.png" \
	"$PLUMA_APP_NAME" "$dmg"

mkdir "$mnt"
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
mounted=1
codesign --verify --deep --strict "$mnt/$PLUMA_APP_NAME.app"
if [ "$(readlink "$mnt/Applications")" != /Applications ]; then
	echo "make-dmg: $dmg has no link to /Applications" >&2
	exit 1
fi
hdiutil detach "$mnt" >/dev/null
mounted=
echo "make-dmg: $dmg ($(du -h "$dmg" | awk '{print $1}'))"
