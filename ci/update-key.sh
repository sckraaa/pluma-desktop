#!/usr/bin/env bash
# Makes the keys of Pluma's update packages, once (tasks 054 and 074 of the
# server repository):
#   - the RSA key of format v1 (1024 bits, SHA-1), for the one release that
#     carries installed apps from 7.0.9 to the new updater: it stays in
#     $PLUMA_UPDATE_KEY_DIR (default ~/pluma-secrets/desktop) and in the
#     secret PLUMA_UPDATE_KEY of the environment "release"; its public key,
#     PKCS#1, is config/update_public.pem;
#   - the Ed25519 keys of format v2: the root key in $PLUMA_UPDATE_KEY_DIR,
#     never in CI (it signs the manifest, and a new manifest can change the
#     release key), and the release key there and in the secret
#     PLUMA_UPDATE_KEY_V2, which signs the packages (ci/publish.sh); the public
#     root key, the manifest and its signature go to config/update (commit it).
# Nothing secret is printed or passed on a command line. With a key in place
# already, it only sets the secret and the files again from it: a new root
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

# Format v2: the root key signs a manifest that names the release key.
python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi
PLUMA_UPDATE_KEY_DIR=$dir $python -I ci/update-keys-v2.py
gh secret set PLUMA_UPDATE_KEY_V2 --env release -R "$repo" <"$dir/update-release.pem"
echo "update-key: PLUMA_UPDATE_KEY_V2 set in $repo (release); the public files are in config/update"
