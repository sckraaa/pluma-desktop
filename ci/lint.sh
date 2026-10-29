#!/usr/bin/env bash
# Lints the shell scripts (shellcheck) and the workflow (actionlint, which
# also runs shellcheck on its run: steps). actionlint is fetched at the
# version pinned here and checked against its SHA-256 when it is missing.
set -euo pipefail
cd "$(dirname "$0")/.."

ACTIONLINT_VERSION=1.7.12

shellcheck -x ci/*.sh brand/*.sh

actionlint=$(command -v actionlint || true)
if [ -z "$actionlint" ]; then
	case "$(uname -s)_$(uname -m)" in
	Linux_x86_64)
		platform=linux_amd64
		sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
		;;
	Darwin_arm64)
		platform=darwin_arm64
		sha256=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
		;;
	*)
		echo "lint: no pinned actionlint for $(uname -s) $(uname -m)" >&2
		exit 1
		;;
	esac
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	tarball="actionlint_${ACTIONLINT_VERSION}_$platform.tar.gz"
	curl -fsSL --retry 3 -o "$tmp/$tarball" \
		"https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION/$tarball"
	if command -v sha256sum >/dev/null; then
		check=(sha256sum -c -)
	else
		check=(shasum -a 256 -c -)
	fi
	echo "$sha256  $tmp/$tarball" | "${check[@]}" >/dev/null
	tar -xzf "$tmp/$tarball" -C "$tmp" actionlint
	actionlint=$tmp/actionlint
fi
"$actionlint"
echo "lint: shell scripts and workflows are clean"
