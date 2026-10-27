#!/usr/bin/env bash
# Keys of the GitHub Actions cache of the libraries that
# Telegram/build/prepare/prepare.py builds (Windows, macOS):
#   cache-key.sh prepare      a hash of prepare.py of $UPSTREAM_DIR: the
#                             libraries of the same script are restored first;
#   cache-key.sh state <dir>  a hash of the stage keys prepare.py wrote under
#                             each <dir>/cache_keys: the state of what is
#                             built, so an unchanged state is not saved again.
set -euo pipefail
mode=${1:?usage: cache-key.sh prepare|state <dir>...}
shift

sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum | awk '{print $1}'
	else
		shasum -a 256 | awk '{print $1}'
	fi
}

case $mode in
prepare)
	key=$(sha256 <"${UPSTREAM_DIR:?UPSTREAM_DIR is not set}/Telegram/build/prepare/prepare.py")
	;;
state)
	if [ $# = 0 ]; then
		echo "usage: cache-key.sh state <dir>..." >&2
		exit 2
	fi
	key=$(for d in "$@"; do
		if [ -d "$d/cache_keys" ]; then
			(cd "$d" && find cache_keys -type f | LC_ALL=C sort | while read -r f; do
				printf '%s %s\n' "$(basename "$d")/$f" "$(tr -d '\r\n' <"$f")"
			done)
		fi
	done | sha256)
	;;
*)
	echo "usage: cache-key.sh prepare|state <dir>..." >&2
	exit 2
	;;
esac
echo "${key:0:16}"
