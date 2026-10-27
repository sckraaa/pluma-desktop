#!/usr/bin/env bash
# Encrypts the builds in a directory for the owner: encrypt.sh <dir>. Each
# file but the .sha256 ones becomes <name>.age (with its .sha256 kept next
# to it) and the plain one is removed: workflow artifacts of a public
# repository are readable by anyone (ADR 0010 of the server repository).
#
# Environment: PLUMA_AGE_RECIPIENT, an age public key (age1...).
set -euo pipefail
dir=${1:?usage: encrypt.sh dir}
if [[ ! "${PLUMA_AGE_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]; then
	echo "encrypt: PLUMA_AGE_RECIPIENT is not an age public key (README, Builds for a server)" >&2
	exit 1
fi
shopt -s nullglob
n=0
for f in "$dir"/*; do
	case $f in
	*.sha256 | *.age) continue ;;
	esac
	age --encrypt --recipient "$PLUMA_AGE_RECIPIENT" --output "$f.age" "$f"
	rm -f "$f"
	echo "encrypt: $f.age"
	n=$((n + 1))
done
if [ "$n" = 0 ]; then
	echo "encrypt: nothing to encrypt in $dir" >&2
	exit 1
fi
