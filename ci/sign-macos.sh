#!/usr/bin/env bash
# Signs the macOS app of a build for a server with Pluma's Developer ID, puts
# it into Pluma's DMG (ci/make-dmg.sh), signs the DMG, has Apple notarize it
# and staples the ticket to it, so Gatekeeper opens it without a warning.
# Upstream notarizes its DMG the same way, once, with the app inside
# (Telegram/build/build.sh:361-423 at a1e89e1f): Apple issues tickets for the
# image and for what it holds. Apple usually answers within minutes but may
# take hours, and keeps checking after notarytool stops waiting, so the work
# has two steps:
#   sign-macos.sh sign ZIP OUT
#       ZIP is package.sh's pluma-desktop-<version>-macos.zip (signed ad
#       hoc). Signs the app, makes the DMG, signs and submits it and waits
#       half an hour. Accepted: OUT gets the notarized
#       pluma-desktop-<version>-macos.dmg, with its SHA-256. Still checking:
#       OUT gets the signed DMG under that name, its SHA-256 and
#       <name>.notary-id, the submission, for the step staple.
#   sign-macos.sh staple DMG ID OUT
#       DMG is the signed DMG of sign, ID its submission. Waits ten minutes
#       for Apple and staples the ticket; OUT gets the notarized DMG as
#       above. Exits 75 while Apple is still checking: run it again later.
# The app's signature is upstream's (Telegram/build/build.sh): the hardened runtime,
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
usage="usage: sign-macos.sh sign ZIP OUT | staple DMG ID OUT"
step=${1:?$usage}
vars=(PLUMA_NOTARY_KEY PLUMA_NOTARY_KEY_ID PLUMA_NOTARY_ISSUER_ID)
case $step in
sign)
	[ $# = 3 ] || { echo "$usage" >&2; exit 2; }
	input=$2 out=$3 id=
	vars+=(PLUMA_DEVELOPER_ID_P12 PLUMA_DEVELOPER_ID_PASSWORD)
	if [ "${GITHUB_ACTIONS:-}" != true ]; then
		echo "sign-macos: sign runs on a GitHub runner only (it changes the keychain search list)" >&2
		exit 2
	fi
	;;
staple)
	[ $# = 4 ] || { echo "$usage" >&2; exit 2; }
	input=$2 id=$3 out=$4
	if [[ "$input" != *.dmg ]]; then
		echo "sign-macos: staple takes the DMG of sign, not $input" >&2
		exit 2
	fi
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

name=$(basename "$input")
name=${name%.zip}
name=${name%.dmg}.dmg
dmg=$work/$name
keys=(--key "$PLUMA_NOTARY_KEY" --key-id "$PLUMA_NOTARY_KEY_ID" --issuer "$PLUMA_NOTARY_ISSUER_ID")

# The DMG into OUT, with its SHA-256.
deliver() {
	mkdir -p "$out"
	cp "$dmg" "$out/$name"
	(cd "$out" && shasum -a 256 "$name" >"$name.sha256")
}

# notary CMD...: runs notarytool CMD; its answer goes to $work/notary.json,
# its exit code to rc. The answer is JSON on stdout, except that wait prints
# it on stderr when it stops waiting first (exit code 124), so both streams
# are kept.
notary() {
	rc=0
	xcrun notarytool "$@" "${keys[@]}" --output-format json >"$work/notary.json" 2>&1 || rc=$?
}

# field KEY: KEY of the last JSON object in the answer that has it.
field() {
	python3 -I -c '
import json, sys
for line in reversed(open(sys.argv[1]).read().splitlines()):
    try:
        answer = json.loads(line)
    except ValueError:
        continue
    if isinstance(answer, dict) and sys.argv[2] in answer:
        print(answer[sys.argv[2]])
        break
' "$work/notary.json" "$1"
}

# wait_for DURATION: waits for Apple's answer on submission $id and sets
# status ("In Progress", "Accepted", "Invalid", "Rejected"; empty when Apple
# could not be asked).
wait_for() {
	notary wait "$id" --timeout "$1"
	notary info "$id"
	status=$(field status)
}

rejected() {
	echo "sign-macos: notarization of submission $id: $status; Apple's log:" >&2
	xcrun notarytool log "$id" "${keys[@]}" >&2 || true
	exit 1
}

if [ "$step" = sign ]; then
	ditto -x -k "$input" "$work/app"
	app=$work/app/$PLUMA_APP_NAME.app
	if [ ! -d "$app" ]; then
		echo "sign-macos: no $PLUMA_APP_NAME.app in $input" >&2
		exit 1
	fi
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

	# The DMG holds the signed app, and is signed itself, with an identifier
	# of its own.
	ci/make-dmg.sh "$app" "$dmg"
	codesign --force --timestamp --keychain "$keychain" --sign "$identity" -i "$PLUMA_APP_ID.dmg" "$dmg"
	codesign --verify --strict "$dmg"

	# Apple checks the DMG and what it holds and issues a ticket; stapled
	# into the DMG, it lets Gatekeeper accept it without asking Apple. The
	# id of the submission comes right after the upload: whatever happens
	# while waiting, the signed DMG is kept with it.
	notary submit "$dmg"
	id=$(field id)
	if [ -z "$id" ]; then
		echo "sign-macos: the upload to Apple failed (exit code $rc):" >&2
		cat "$work/notary.json" >&2
		exit 1
	fi
	wait_for 30m
	case $status in
	Accepted) ;;
	Invalid | Rejected) rejected ;;
	*)
		deliver
		echo "$id" >"$out/$name.notary-id"
		echo "sign-macos: $out/$name, signed; Apple's answer on submission $id: ${status:-none yet} (sign-macos.sh staple)"
		exit 0
		;;
	esac
else
	cp "$input" "$dmg"
	wait_for 10m
	case $status in
	Accepted) ;;
	Invalid | Rejected) rejected ;;
	*)
		echo "sign-macos: Apple's answer on submission $id: ${status:-none}; run it again later" >&2
		exit 75
		;;
	esac
fi

xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
codesign --verify --strict "$dmg"
deliver
echo "sign-macos: $out/$name, notarized"
