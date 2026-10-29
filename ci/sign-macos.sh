#!/usr/bin/env bash
# Signs the macOS app of a build for a server with Pluma's Developer ID, has
# Apple notarize it and staples the ticket to it, so Gatekeeper opens it
# without a warning, offline too:
#   sign-macos.sh ZIP OUT   ZIP is package.sh's pluma-desktop-<version>-macos.zip
#                           (signed ad hoc); OUT gets the signed app under the
#                           same name, with its SHA-256.
# The signature is upstream's (Telegram/build/build.sh): the hardened runtime,
# a secure timestamp and the entitlements of Telegram.entitlements, which
# ci/macos.entitlements copies (ci/patch.py checks it): the microphone, the
# camera, the location. From the environment:
#   PLUMA_DEVELOPER_ID_P12       the Developer ID Application certificate and
#                                its key, a PKCS#12 file
#   PLUMA_DEVELOPER_ID_PASSWORD  its password
#   PLUMA_NOTARY_KEY             an App Store Connect API key, a .p8 file
#   PLUMA_NOTARY_KEY_ID          its key id
#   PLUMA_NOTARY_ISSUER_ID       its issuer id
# It runs on a GitHub runner only: codesign finds an identity only in a
# keychain on the user's search list, and the script puts its own there,
# which on a Mac of a person would change their keychains.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${GITHUB_ACTIONS:-}" != true ]; then
	echo "sign-macos: runs on a GitHub runner only (it changes the keychain search list)" >&2
	exit 2
fi
zip=${1:?usage: sign-macos.sh ZIP OUT}
out=${2:?usage: sign-macos.sh ZIP OUT}
for v in PLUMA_DEVELOPER_ID_P12 PLUMA_DEVELOPER_ID_PASSWORD PLUMA_NOTARY_KEY PLUMA_NOTARY_KEY_ID PLUMA_NOTARY_ISSUER_ID; do
	if [ -z "${!v:-}" ]; then
		echo "sign-macos: $v is not set (README, Signing)" >&2
		exit 1
	fi
done
. ./config/app.env

work=$(mktemp -d)
keychain=$work/signing.keychain-db
cleanup() {
	security delete-keychain "$keychain" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

# A keychain of its own holds the identity, on the search list, and codesign
# may use its key without asking.
password=$(openssl rand -hex 16)
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$PLUMA_DEVELOPER_ID_P12" -k "$keychain" -P "$PLUMA_DEVELOPER_ID_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" login.keychain-db
identity=$(security find-identity -v -p codesigning "$keychain" | awk '/"Developer ID Application: / {print $2; exit}')
if [ -z "$identity" ]; then
	echo "sign-macos: PLUMA_DEVELOPER_ID_P12 holds no valid Developer ID Application identity" >&2
	exit 1
fi

ditto -x -k "$zip" "$work/app"
app=$work/app/$PLUMA_APP_NAME.app
if [ ! -d "$app" ]; then
	echo "sign-macos: no $PLUMA_APP_NAME.app in $zip" >&2
	exit 1
fi
codesign --force --deep --timestamp --options runtime --entitlements ci/macos.entitlements \
	--keychain "$keychain" --sign "$identity" "$app"
codesign --verify --deep --strict "$app"

# Apple checks the app and issues a ticket; stapled into the app, it lets
# Gatekeeper accept the app without asking Apple.
ditto -c -k --keepParent "$app" "$work/notarize.zip"
notary=(--key "$PLUMA_NOTARY_KEY" --key-id "$PLUMA_NOTARY_KEY_ID" --issuer "$PLUMA_NOTARY_ISSUER_ID")
xcrun notarytool submit "$work/notarize.zip" "${notary[@]}" --wait --timeout 1h --output-format json >"$work/notary.json"
field() {
	python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$work/notary.json" "$1"
}
status=$(field status)
if [ "$status" != Accepted ]; then
	echo "sign-macos: notarization: ${status:-no answer}; Apple's log:" >&2
	id=$(field id)
	if [ -n "$id" ]; then
		xcrun notarytool log "$id" "${notary[@]}" >&2 || true
	fi
	exit 1
fi
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"

mkdir -p "$out"
name=$(basename "$zip")
ditto -c -k --keepParent "$app" "$out/$name"
(cd "$out" && shasum -a 256 "$name" >"$name.sha256")
echo "sign-macos: $out/$name, notarized"
