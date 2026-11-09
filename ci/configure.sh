#!/usr/bin/env bash
# Patches $UPSTREAM_DIR (default ./upstream) with ci/patch.py:
#   configure.sh dev     for the development server of config/dev;
#   configure.sh server  for the server the repository variables name.
#
# Environment for server: SERVER_IPV4, SERVER_PORT, SERVER_IPV6 (optional),
# RSA_PUBLIC_KEY (PKCS#1 PEM).
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?usage: configure.sh dev|server}
dir=${UPSTREAM_DIR:-upstream}

python=python3
if ! python3 -c '' 2>/dev/null; then
	python=python # Windows
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case $target in
dev)
	. config/dev/server.env
	SERVER_IPV4=$PLUMA_SERVER_IPV4
	SERVER_PORT=$PLUMA_SERVER_PORT
	SERVER_IPV6=
	cp config/dev/server_public.pem "$tmp/key.pem"
	# A development build never updates itself from the real server: a
	# prefix of nowhere, and a root key whose private half nobody keeps.
	update_prefix=https://127.0.0.1/dl/desktop
	update_keys=config/dev/update
	data_name=$PLUMA_DATA_NAME
	;;
server)
	# Half a configuration would build a client that cannot sign in.
	for v in SERVER_IPV4 SERVER_PORT RSA_PUBLIC_KEY; do
		if [ -z "${!v:-}" ]; then
			echo "configure: PLUMA_$v is not set (README, Configuration)" >&2
			exit 1
		fi
	done
	printf '%s\n' "$RSA_PUBLIC_KEY" >"$tmp/key.pem"
	update_keys=config/update
	if [ ! -s "$update_keys/manifest.min.json" ]; then
		echo "configure: $update_keys is missing; ci/update-key.sh makes it (README, Releases)" >&2
		exit 1
	fi
	;;
*)
	echo "usage: configure.sh dev|server" >&2
	exit 2
	;;
esac

$python -I ci/patch.py --source "$dir" --upstream upstream.env --app config/app.env \
	--server-ipv4 "$SERVER_IPV4" --server-port "$SERVER_PORT" --server-ipv6 "${SERVER_IPV6:-}" \
	--rsa-public-key "$tmp/key.pem" --update-keys "$update_keys" \
	--build "${PLUMA_BUILD:-0}" ${update_prefix:+--update-prefix "$update_prefix"} \
	${data_name:+--data-name "$data_name"}
echo "configure: $target build"
