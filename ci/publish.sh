#!/usr/bin/env bash
# Hands a build of the desktop app to the releases service of the server,
# which serves it on the site and to the updater of installed apps (task 054
# and ADR 0035 of the server repository):
#
#   publish.sh macos|windows|linux <installer>
#
# The installer is what ci/package.sh made (for macOS, the DMG sign-macos.sh
# made, signed and notarized): the site offers it for a first install. From it
# the update package is packed (ci/pack_update.py) and signed with Pluma's key:
# Pluma.app of the DMG on macOS, universal; Telegram.exe and Updater.exe on Windows,
# x64; Telegram and Updater on Linux, x64. The binary goes under upstream's
# name, which the Updater renames to the installed one.
#
# The format of the package is in release/update-format: v1 (the RSA key of
# the apps up to 7.0.9) for the one release that carries installed apps to the
# updater of 7.4.1, then v2 (the Ed25519 release key and config/update).
#
# The release is <UPSTREAM_VERSION>.<build>, the build zero-padded to five
# digits; the package carries the build number, which the updater compares
# (PlumaBuild, ci/patch.py, updates), and is named by it. The notes are
# release/notes.en.txt and release/notes.ru.txt.
#
# Environment:
#   BUILD_NUMBER            the number the build was patched with (the run
#                           number of the desktop workflow);
#   PLUMA_UPDATE_KEY_FILE   format v1: the RSA key of the packages (the
#                           secret PLUMA_UPDATE_KEY; ci/update-key.sh);
#   PLUMA_UPDATE_KEY_V2_FILE format v2: the Ed25519 release key (the secret
#                           PLUMA_UPDATE_KEY_V2; ci/update-key.sh);
#   PLUMA_RELEASES_URL      the site, https://pluma.chat;
#   RELEASES_UPLOAD_TOKEN   the releases service's upload token
#                           (teamgramd/deploy/releases/put-token.sh of the
#                           server repository sets it);
#   PLUMA_UPDATE_PUBLIC_KEY the public key a v1 package is checked against,
#                           config/update_public.pem when unset (the tests
#                           give their own);
#   PLUMA_UPDATE_KEYS       the folder of a v2 package's root key and
#                           manifest, config/update when unset (the tests
#                           give their own);
#   PLUMA_UPDATE_FORMAT     the format, release/update-format when unset (the
#                           tests give their own).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
os=${1:?usage: publish.sh macos|windows|linux <installer>}
installer=${2:?usage: publish.sh macos|windows|linux <installer>}
build=${BUILD_NUMBER:?BUILD_NUMBER is not set}
: "${RELEASES_UPLOAD_TOKEN:?RELEASES_UPLOAD_TOKEN is not set}"
format=${PLUMA_UPDATE_FORMAT:-$(tr -d '[:space:]' <release/update-format)}
case $format in
v1) : "${PLUMA_UPDATE_KEY_FILE:?PLUMA_UPDATE_KEY_FILE is not set}" ;;
v2) : "${PLUMA_UPDATE_KEY_V2_FILE:?PLUMA_UPDATE_KEY_V2_FILE is not set}" ;;
*)
	echo "publish: release/update-format is $format, not v1 or v2" >&2
	exit 1
	;;
esac
if [[ ! "${PLUMA_RELEASES_URL:-}" =~ ^https://[a-z0-9.-]+$ ]]; then
	echo "publish: PLUMA_RELEASES_URL is not the site's https:// address" >&2
	exit 1
fi
if [[ ! "$build" =~ ^[0-9]{1,5}$ ]]; then
	echo "publish: BUILD_NUMBER $build is not a number" >&2
	exit 1
fi
public_key=${PLUMA_UPDATE_PUBLIC_KEY:-config/update_public.pem}
update_keys=${PLUMA_UPDATE_KEYS:-config/update}
if [ "$format" = v1 ]; then
	key_material=$public_key
else
	key_material=$update_keys/manifest.min.json
fi
for f in "$installer" release/notes.en.txt release/notes.ru.txt "$key_material"; do
	[ -s "$f" ] || { echo "publish: $f is missing or empty" >&2; exit 1; }
done
build=$((10#$build))
version="$UPSTREAM_VERSION.$(printf %05d "$build")"
app=$PLUMA_APP_NAME

python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pluma-publish.XXXXXX")
mounted=
cleanup() {
	if [ -n "$mounted" ]; then
		hdiutil detach "$work/mnt" -force >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/unpacked" "$work/package"
case $os in
linux)
	arch=x64
	tar -C "$work/unpacked" -xJf "$installer"
	cp -p "$work/unpacked/$app/$app" "$work/package/Telegram"
	cp -p "$work/unpacked/$app/Updater" "$work/package/Updater"
	update=tlinuxupd$build
	paths=("$work/package/Telegram" "$work/package/Updater")
	;;
windows)
	arch=x64
	$python -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$installer" "$work/unpacked"
	cp "$work/unpacked/$app/$app.exe" "$work/package/Telegram.exe"
	cp "$work/unpacked/$app/Updater.exe" "$work/package/Updater.exe"
	update=tx64upd$build
	paths=("$work/package/Telegram.exe" "$work/package/Updater.exe")
	;;
macos)
	# One universal app serves Intel and Apple processors (tmacupd serves
	# the updater's keys mac and armac).
	arch=universal
	if [[ "$installer" != *.dmg ]]; then
		echo "publish: the macOS installer is the DMG of sign-macos.sh, not $installer" >&2
		exit 2
	fi
	# Notarized and stapled, or the site would offer what Gatekeeper refuses.
	codesign --verify --strict "$installer"
	xcrun stapler validate "$installer"
	mkdir "$work/mnt"
	hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$work/mnt" "$installer" >/dev/null
	mounted=1
	ditto "$work/mnt/$app.app" "$work/package/$app.app"
	hdiutil detach "$work/mnt" >/dev/null
	mounted=
	codesign --verify --deep --strict "$work/package/$app.app"
	update=tmacupd$build
	paths=("$work/package/$app.app")
	;;
*)
	echo "usage: publish.sh macos|windows|linux <installer>" >&2
	exit 2
	;;
esac
if [ "$format" = v1 ]; then
	$python -I ci/pack_update.py --format v1 --os "$os" --version "$build" --key "$PLUMA_UPDATE_KEY_FILE" \
		--public-key "$public_key" --out "$work/$update" "${paths[@]}"
else
	$python -I ci/pack_update.py --format v2 --os "$os" --version "$build" --key "$PLUMA_UPDATE_KEY_V2_FILE" \
		--update-keys "$update_keys" --out "$work/$update" "${paths[@]}"
fi

# The token goes in a header file, not on the command line.
umask 077
printf 'Authorization: Bearer %s\n' "$RELEASES_UPLOAD_TOKEN" >"$work/auth"
ext=${installer##*/}
case $ext in
*.tar.xz) ext=tar.xz ;;
*) ext=${ext##*.} ;;
esac
status=$(curl -sS --retry 3 --retry-all-errors --max-time 1800 -o "$work/answer" -w '%{http_code}' \
	-H @"$work/auth" \
	-F "platform=$os" -F "version=$version" -F "build=$build" \
	-F "notes_en=<release/notes.en.txt" -F "notes_ru=<release/notes.ru.txt" \
	-F "installer.$arch=@$installer;filename=$app-$version-$os-$arch.$ext" \
	-F "update.$arch=@$work/$update;filename=$update" \
	"$PLUMA_RELEASES_URL/dl/upload")
case $status in
200) echo "publish: $app $version (build $build) for $os is on the site" ;;
409) echo "publish: build $build for $os is published already" ;;
*)
	echo "publish: HTTP $status: $(head -c 500 "$work/answer")" >&2
	exit 1
	;;
esac
