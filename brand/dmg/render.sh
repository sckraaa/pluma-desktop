#!/usr/bin/env bash
# Renders background.html into background.png (640x400) and background@2x.png
# (1280x800), the background of the window of Pluma's DMG (ci/make-dmg.sh;
# dmgbuild combines the two for Retina screens). The PNGs are committed: run
# this after changing the page and commit the result. Needs Google Chrome and
# python3 (the page loads its font and mark over HTTP, as a file:// page may
# not fetch).
set -euo pipefail
cd "$(dirname "$0")"
chrome=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
if [ ! -x "$chrome" ]; then
	echo "render: no Google Chrome at $chrome (set CHROME)" >&2
	exit 1
fi
port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -I -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 50); do
	curl -sf -o /dev/null "http://127.0.0.1:$port/background.html" && break
	sleep 0.1
done
for scale in 1 2; do
	out=background.png
	[ "$scale" = 2 ] && out=background@2x.png
	"$chrome" --headless=new --disable-gpu --hide-scrollbars --window-size=640,400 \
		--force-device-scale-factor="$scale" --virtual-time-budget=3000 \
		--screenshot="$PWD/$out" "http://127.0.0.1:$port/background.html" >/dev/null 2>&1
	echo "render: $out"
done
