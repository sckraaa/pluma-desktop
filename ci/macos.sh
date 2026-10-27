#!/usr/bin/env bash
# Builds on macOS, as the upstream CI does:
#   macos.sh setup      selects the Xcode of upstream.env and installs the
#                       tools Telegram/build/prepare/prepare.py uses;
#   macos.sh libraries  the libraries (universal, release and debug builds)
#                       into ../Libraries and ../ThirdParty next to the
#                       checkout; a stage built already is skipped;
#   macos.sh trim       removes what the client build does not need from the
#                       libraries, before they are cached (as upstream);
#   macos.sh client     the client in the Release configuration, unsigned:
#                       $UPSTREAM_DIR/out/Release/Telegram.app (ci/package.sh
#                       signs it ad hoc).
# $UPSTREAM_DIR is the patched checkout (ci/configure.sh). The paths of the
# libraries end up in their cache keys, so CI keeps them the same from run to
# run.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
mode=${1:?usage: macos.sh setup|libraries|trim|client}

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "macos: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

case $mode in
setup)
	xcode="/Applications/Xcode_$XCODE_VERSION.app"
	if [ ! -d "$xcode" ]; then
		echo "macos: no $xcode on this runner image (README, Updating the upstream)" >&2
		ls -d /Applications/Xcode*.app >&2 || true
		exit 1
	fi
	sudo xcode-select -s "$xcode/Contents/Developer"
	version=$(xcodebuild -version | awk '/^Xcode / {print $2}')
	if [ "$version" != "$XCODE_VERSION" ]; then
		echo "macos: $xcode is Xcode $version, upstream.env says $XCODE_VERSION" >&2
		exit 1
	fi
	echo "macos: Xcode $version, macOS SDK $(xcrun --sdk macosx --show-sdk-version)"

	# The libraries and a universal Release build fill tens of GB. The other
	# Xcode versions of the image go first, then the simulator runtimes;
	# neither is used.
	free_gb() {
		df -g "$HOME" | awk 'NR == 2 {print $4}'
	}
	need=${PLUMA_MIN_FREE_GB:-60}
	echo "macos: $(free_gb) GB free, $need needed"
	if [ "$(free_gb)" -lt "$need" ]; then
		keep=$(cd "$xcode" && pwd -P)
		for x in /Applications/Xcode*.app; do
			if [ ! -L "$x" ] && [ "$(cd "$x" && pwd -P)" != "$keep" ]; then
				sudo rm -rf "$x" &
			fi
		done
		wait
		echo "macos: $(free_gb) GB free without the other Xcode versions"
	fi
	if [ "$(free_gb)" -lt "$need" ]; then
		xcrun simctl runtime delete all >/dev/null 2>&1 || true
		echo "macos: $(free_gb) GB free without the simulator runtimes"
	fi
	if [ "$(free_gb)" -lt "$need" ]; then
		echo "macos: only $(free_gb) GB free, $need needed" >&2
		df -h "$HOME" >&2
		exit 1
	fi

	HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 \
		retry brew install --quiet automake libtool meson nasm ninja pkg-config
	# Spotlight indexing slows the build down.
	sudo mdutil -a -i off >/dev/null || true
	# Some stages commit their own patches.
	git config --global user.email "ci@pluma.invalid"
	git config --global user.name "Pluma CI"
	exit 0
	;;
libraries | trim | client) ;;
*)
	echo "usage: macos.sh setup|libraries|trim|client" >&2
	exit 2
	;;
esac

dir=$(cd "${UPSTREAM_DIR:?UPSTREAM_DIR is not set}" && pwd)
root=$(dirname "$dir")
if [ ! -f "$dir/pluma-patch.txt" ]; then
	echo "macos: $dir is not patched (ci/configure.sh)" >&2
	exit 1
fi

case $mode in
libraries)
	mkdir -p "$root/Libraries" "$root/ThirdParty"
	"$dir/Telegram/build/prepare/mac.sh" silent
	;;
trim)
	# The upstream CI's "Free up some disk space" step.
	find "$root/Libraries" '(' '(' ! '(' -name '*.a' -o -name '*.h' -o -name '*.hpp' -o -name '*.inc' \
		-o -name '*.cmake' -o -path '*/include/*' -o -path '*/objects-*' -o -path '*/cache_keys/*' \
		-o -path '*/patches/*' -o -perm +111 ')' -type f ')' -o -empty ')' -delete
	du -sh "$root/Libraries" "$root/ThirdParty"
	;;
client)
	(
		cd "$dir/Telegram"
		./configure.sh \
			-D CMAKE_CONFIGURATION_TYPES=Release \
			-D CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO \
			-D "TDESKTOP_API_ID=$PLUMA_API_ID" \
			-D "TDESKTOP_API_HASH=$PLUMA_API_HASH" \
			-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON \
			-D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON
		cmake --build ../out --config Release --parallel
	)
	app="$dir/out/Release/Telegram.app"
	if [ ! -d "$app" ]; then
		echo "macos: no $app" >&2
		exit 1
	fi
	echo "macos: $app ($(du -sh "$app" | awk '{print $1}'))"
	;;
esac
