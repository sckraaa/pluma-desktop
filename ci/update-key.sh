#!/usr/bin/env bash
# Makes the key of Pluma's update packages, once (task 054 of the server
# repository; the format of tdesktop's updater: RSA, 1024 bits, SHA-1):
#   - the private key goes to $PLUMA_UPDATE_KEY_DIR (default
#     ~/pluma-secrets/desktop), mode 0600, and to the secret PLUMA_UPDATE_KEY
#     of the environment "release", which signs the packages (ci/publish.sh);
#   - the public key, PKCS#1, goes to config/update_public.pem, which the
#     patch builds into the app (commit it).
# Nothing secret is printed or passed on a command line. With a key in place
# already, it only sets the secret and the public key again from it: a new
# key would lock every installed app out of updates.
#
#   update-key.sh [<owner/repo>]
set -euo pipefail
cd "$(dirname "$0")/.."
repo=${1:-sckraaa/pluma-desktop}
dir=${PLUMA_UPDATE_KEY_DIR:-$HOME/pluma-secrets/desktop}
key=$dir/update-key.pem
umask 077
mkdir -p "$dir"
if [ ! -s "$key" ]; then
	openssl genrsa -out "$key.tmp" 1024 2>/dev/null
	mv "$key.tmp" "$key"
	echo "update-key: a new key in $key; back it up off-line"
else
	echo "update-key: the key in $key is kept"
fi
bits=$(openssl rsa -in "$key" -noout -text 2>/dev/null | sed -n 's/^Private-Key: (\([0-9]*\) bit.*/\1/p')
if [ "$bits" != 1024 ]; then
	echo "update-key: $key is not a 1024-bit RSA key" >&2
	exit 1
fi
openssl rsa -in "$key" -RSAPublicKey_out -out config/update_public.pem 2>/dev/null
gh secret set PLUMA_UPDATE_KEY --env release -R "$repo" <"$key"
echo "update-key: PLUMA_UPDATE_KEY set in $repo (release); the public key is config/update_public.pem"
