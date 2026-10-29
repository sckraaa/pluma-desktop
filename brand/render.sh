#!/usr/bin/env bash
# Renders the icons of the Pluma desktop client from the SVGs of brand/svg
# into brand/tree, at the paths of the upstream files they replace
# (ASSETS in ci/patch.py), and the layer of the macOS 26 icon into
# brand/Icon.icon. The rendered files are committed, so a build takes
# them as they are and needs neither tool: run this after changing an SVG and
# commit the result. Needs rsvg-convert (librsvg) and ImageMagick 7 (magick).
set -euo pipefail
cd "$(dirname "$0")"

for tool in rsvg-convert magick; do
	if ! command -v "$tool" >/dev/null; then
		echo "render: $tool is missing (librsvg, ImageMagick 7)" >&2
		exit 1
	fi
done

art=tree/Telegram/Resources/art
icons=tree/Telegram/Resources/icons
assets=tree/Telegram/Telegram/Images.xcassets
rm -rf tree
mkdir -p "$art" "$icons" "$assets/Icon.appiconset" "$assets/Icon.iconset"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# render <svg> <width> <height> <png> [background]: a transparent PNG, or an
# opaque one on the background (the alpha masks: white is drawn).
render() {
	if [ -z "${5:-}" ]; then
		rsvg-convert -w "$2" -h "$3" -o "$4" "svg/$1"
	else
		# RGBA, opaque, as upstream's masks; no time stamps, so the same SVG
		# gives the same file.
		rsvg-convert -w "$2" -h "$3" -b "$5" "svg/$1" |
			magick - -alpha set -strip -define png:exclude-chunks=date,time "PNG32:$4"
	fi
}

# Windows and Linux: the window, taskbar and tray icon (logo_256, its body
# 228 of 256 as upstream's), the sizes Linux installs, and the executable's
# icon: BMP entries up to 48, a PNG entry at 256, as upstream's. The round
# full-bleed logo, as upstream's, serves small tray icons, notifications and
# the avatar of the service notifications account, which is clipped to a
# circle.
render app-icon-margin.svg 256 256 "$art/logo_256.png"
render logo-round.svg 256 256 "$art/logo_256_no_margin.png"
for size in 16 32 48 64 128 256 512; do
	render app-icon-margin.svg "$size" "$size" "$art/icon$size.png"
	render app-icon-margin.svg $((size * 2)) $((size * 2)) "$art/icon$size@2x.png"
done
for size in 16 24 32 48 256; do
	render app-icon-margin.svg "$size" "$size" "$tmp/ico$size.png"
done
magick "$tmp/ico16.png" "$tmp/ico24.png" "$tmp/ico32.png" "$tmp/ico48.png" "$tmp/ico256.png" "$tmp/bmp.ico"
# ImageMagick writes every entry as BMP: the 256 one becomes the PNG.
python3 -I - "$tmp/bmp.ico" "$tmp/ico256.png" "$art/icon256.ico" <<'PY'
import struct, sys
ico, png = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
count = struct.unpack_from("<H", ico, 4)[0]
last = 6 + 16 * (count - 1)
size, offset = struct.unpack_from("<II", ico, last + 8)
if count != 5 or ico[last:last + 2] != b"\0\0" or offset + size != len(ico):
    sys.exit("render: unexpected ICO from magick")
head = bytearray(ico[:offset])
struct.pack_into("<I", head, last + 8, len(png))
open(sys.argv[3], "wb").write(bytes(head) + png)
PY

# macOS: the app icon (the Xcode asset catalog and the iconset for builds
# without Xcode) and the round variant of Settings > Advanced.
for size in 16 32 128 256 512; do
	render macos-icon.svg "$size" "$size" "$assets/Icon.appiconset/icon$size.png"
	render macos-icon.svg $((size * 2)) $((size * 2)) "$assets/Icon.appiconset/icon$size@2x.png"
	cp "$assets/Icon.appiconset/icon$size.png" "$assets/Icon.iconset/icon_${size}x$size.png"
	cp "$assets/Icon.appiconset/icon$size@2x.png" "$assets/Icon.iconset/icon_${size}x$size@2x.png"
done
render round-icon.svg 1024 1024 "$art/icon_round512@2x.png"
# macOS 26 draws an icon of the old format on a grey plate: its icon is an
# Icon Composer file, the mark on white, which ci/package.sh compiles into the
# bundle (the icons above stay for the patch and older systems get actool's
# rendering).
mkdir -p Icon.icon/Assets
rsvg-convert -w 1024 -h 1024 svg/macos-mark.svg |
	magick - -strip -define png:exclude-chunks=date,time PNG32:Icon.icon/Assets/mark.png

# The one-colour tray icons and the mark cut out of QR codes stay SVG.
cp svg/tray.svg "$icons/tray_monochrome.svg"
cp svg/tray-attention.svg "$icons/tray_monochrome_attention.svg"
cp svg/tray-mute.svg "$icons/tray_monochrome_mute.svg"
cp svg/plane-white.svg "$icons/plane_white.svg"

# Alpha masks at 1x, 2x and 3x, which the interface tints with palette
# colours: the macOS menu bar icon, the mark in the login QR code, and the
# four parts of the mark on the intro cover (ring, three feathers).
mask() {
	local svg=$1 width=$2 height=$3 name=$4 scale suffix
	for scale in 1 2 3; do
		suffix=$([ "$scale" = 1 ] || echo "@${scale}x")
		render "$svg" $((width * scale)) $((height * scale)) "$icons/$name$suffix.png" '#000000'
	done
}
mask mask-mac-tray.svg 22 22 mac_tray_icon
mask mask-qr.svg 35 35 intro_qr_plane
mask mask-intro-ring.svg 202 143 intro_plane_trace
mask mask-intro-feather1.svg 202 143 intro_plane_inner
mask mask-intro-feather2.svg 202 143 intro_plane_outer
mask mask-intro-feather3.svg 202 143 intro_plane_top

echo "render: $(find tree -type f | wc -l | tr -d ' ') files in brand/tree"
