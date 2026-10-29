#!/usr/bin/env bash
# Signs the macOS app of a build for a server with Pluma's Developer ID, has
# Apple notarize it and staples the ticket to it, so Gatekeeper opens it
# without a warning, offline too. Apple usually answers within minutes but
# may take hours, and keeps checking after notarytool stops waiting, so the
# work has two steps:
#   sign-macos.sh sign ZIP OUT
#       ZIP is package.sh's pluma-desktop-<version>-macos.zip (signed ad
#       hoc). Signs the app, submits it and waits half an hour. Accepted: OUT
#       gets the notarized app under ZIP's name, with its SHA-256. Still
#       checking: OUT gets the signed app under that name, its SHA-256 and
#       <name>.notary-id, the submission, for the step staple.
#   sign-macos.sh staple ZIP ID OUT
#       ZIP is the signed app of sign, ID its submission. Waits ten minutes
#       for Apple and staples the ticket; OUT gets the notarized app as
#       above. Exits 75 while Apple is still checking: run it again later.
# The signature is upstream's (Telegram/build/build.sh): the hardened runtime,
# a secure timestamp and the entitlements of Telegram.entitlements, which
# ci/macos.entitlements copies (ci/patch.py checks it): the microphone, the
# camera, the location. From the environment:
#   PLUMA_DEVELOPER_ID_P12       the Developer ID Application certificate and
#                                its key, a PKCS#12 file (sign only)
#   PLUMA_DEVELOPER_ID_PASSWORD  its password (sign only)
#   PLUMA_NOTARY_KEY             an App Store Connect API key, a .p8 file
#   PLUMA_NOTARY_KEY_ID          its key id
#   PLUMA_NOTARY_ISSUER_ID       its issuer id
# The step sign runs on a GitHub runner only: codesign finds an identity only
# in a keychain on the user's search list, and the script puts its own there,
# which on a Mac of a person would change their keychains.
set -euo pipefail
cd "$(dirname "$0")/.."
usage="usage: sign-macos.sh sign ZIP OUT | staple ZIP ID OUT"
step=${1:?$usage}
vars=(PLUMA_NOTARY_KEY PLUMA_NOTARY_KEY_ID PLUMA_NOTARY_ISSUER_ID)
case $step in
sign)
	[ $# = 3 ] || { echo "$usage" >&2; exit 2; }
	zip=$2 out=$3 id=
	vars+=(PLUMA_DEVELOPER_ID_P12 PLUMA_DEVELOPER_ID_PASSWORD)
	if [ "${GITHUB_ACTIONS:-}" != true ]; then
		echo "sign-macos: sign runs on a GitHub runner only (it changes the keychain search list)" >&2
		exit 2
	fi
	;;
staple)
	[ $# = 4 ] || { echo "$usage" >&2; exit 2; }
	zip=$2 id=$3 out=$4
	if [[ ! "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
		echo "sign-macos: $id is not a submission id" >&2
		exit 2
	fi
	;;
*)
	echo "$usage" >&2
	exit 2
	;;
esac
for v in "${vars[@]}"; do
	if [ -z "${!v:-}" ]; then
		echo "sign-macos: $v is not set (README, Signing)" >&2
		exit 1
	fi
done
. ./config/app.env

work=$(mktemp -d)
keychain=$work/signing.keychain-db
cleanup() {
	if [ -e "$keychain" ]; then
		security delete-keychain "$keychain" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

ditto -x -k "$zip" "$work/app"
app=$work/app/$PLUMA_APP_NAME.app
if [ ! -d "$app" ]; then
	echo "sign-macos: no $PLUMA_APP_NAME.app in $zip" >&2
	exit 1
fi
name=$(basename "$zip")
notary=(--key "$PLUMA_NOTARY_KEY" --key-id "$PLUMA_NOTARY_KEY_ID" --issuer "$PLUMA_NOTARY_ISSUER_ID")

# The app zipped into OUT under ZIP's name, with its SHA-256.
deliver() {
	mkdir -p "$out"
	ditto -c -k --keepParent "$app" "$out/$name"
	(cd "$out" && shasum -a 256 "$name" >"$name.sha256")
}

# Apple's answer in $work/notary.json: notarytool's exit code is 124 when it
# stops waiting first, and the answer then has the id but no status.
field() {
	python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$work/notary.json" "$1"
}

if [ "$step" = sign ]; then
	# A keychain of its own holds the identity, on the search list, and
	# codesign may use its key without asking.
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
	codesign --force --deep --timestamp --options runtime --entitlements ci/macos.entitlements \
		--keychain "$keychain" --sign "$identity" "$app"
	codesign --verify --deep --strict "$app"

	# Apple checks the app and issues a ticket; stapled into the app, it
	# lets Gatekeeper accept the app without asking Apple.
	ditto -c -k --keepParent "$app" "$work/notarize.zip"
	rc=0
	xcrun notarytool submit "$work/notarize.zip" "${notary[@]}" --wait --timeout 30m --output-format json >"$work/notary.json" || rc=$?
	id=$(field id)
	if [ "$rc" = 124 ] && [ -n "$id" ]; then
		deliver
		echo "$id" >"$out/$name.notary-id"
		echo "sign-macos: $out/$name, signed; Apple is still checking submission $id (sign-macos.sh staple)"
		exit 0
	fi
else
	# info answers in the fields of submit; wait's own answer is not
	# documented.
	rc=0
	xcrun notarytool wait "$id" "${notary[@]}" --timeout 10m >&2 || rc=$?
	xcrun notarytool info "$id" "${notary[@]}" --output-format json >"$work/notary.json"
	if [ "$(field status)" = "In Progress" ]; then
		echo "sign-macos: Apple is still checking submission $id; run it again later" >&2
		exit 75
	fi
fi

status=$(field status)
if [ "$status" != Accepted ]; then
	echo "sign-macos: notarization: ${status:-no answer} (exit code $rc); Apple's log:" >&2
	if [ -n "$id" ]; then
		xcrun notarytool log "$id" "${notary[@]}" >&2 || true
	fi
	exit 1
fi
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
deliver
echo "sign-macos: $out/$name, notarized"
