#!/usr/bin/env python3
"""Turns a checkout of telegramdesktop/tdesktop into the Pluma desktop client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. After the edits the result is checked
again: no Telegram datacenter address or server key is left in the client's
sources, the fallbacks that reach Telegram are never started, and the
identity is Pluma's.

The brand is Pluma's too: the name in the interface, plm:// links in place
of tg://, the icons rendered in brand/, and the palette "graphite and sage"
of the default light and dark themes (brand/palette-*.txt).

The api_id and api_hash are not edits: the build passes them to CMake
(-D TDESKTOP_API_ID / TDESKTOP_API_HASH), together with the options that
compile out the updater and the crash reports (the patch makes CMake refuse
a configuration without them).

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import hashlib
import io
import ipaddress
import pathlib
import re
import struct
import sys
import uuid
import zipfile
import zlib

# Telegram's own server keys (production, test) with the fingerprints the
# server announces for them, and the key Telegram signs its "special config"
# (backup addresses) with. None of them may survive the patch.
TELEGRAM_FINGERPRINTS = (0xD09D1D85DE64FD85, 0xB25898DF208D2603)
TELEGRAM_KEY_LINES = (
    "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g",
    "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR",
    "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF",
)

# Telegram's 1024-bit keys of its update packages. The updater is compiled
# out (TDESKTOP_DISABLE_AUTOUPDATE), so they verify nothing; they may stay
# where upstream keeps them, and nowhere else.
UPDATE_KEY_LINES = (
    "MIGJAoGBAMA4ViQrjkPZ9xj0lrer3r23JvxOnrtE8nI69XLGSr+sRERz9YnUptnU",
    "MIGJAoGBALWu9GGs0HED7KG7BM73CFZ6o0xufKBRQsdnq3lwA8nFQEvmdu+g/I1j",
)

# Telegram's address ranges (core.telegram.org/resources/cidr.txt) and the
# one built-in address outside them.
TELEGRAM_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
    "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32",
    "95.161.76.100/32",
))
# Every address of those ranges, written out, starts with one of these.
TELEGRAM_PREFIXES = ("149.154.", "91.108.", "91.105.", "185.76.151.", "95.161.76.100", "2001:", "2a0a:", "2A0A:")

# Telegram Desktop's GUIDs, which Pluma's identity must not reuse.
TELEGRAM_GUIDS = ("53F49750-6209-4FBF-9CA8-7A333C87D1ED", "87A94AB0-E370-4CDE-98D3-ACC110C5967D",
                  "F11932D3-6110-4BBC-9B02-B2EC07A1BD19")

SOURCES = "Telegram/SourceFiles"
API_TL = SOURCES + "/mtproto/scheme/api.tl"
VERSION_H = SOURCES + "/core/version.h"
CONFIG_H = SOURCES + "/config.h"
DC_OPTIONS = SOURCES + "/mtproto/mtproto_dc_options.cpp"
INSTANCE_H = SOURCES + "/mtproto/mtp_instance.h"
INSTANCE = SOURCES + "/mtproto/mtp_instance.cpp"
CONFIG_LOADER = SOURCES + "/mtproto/config_loader.cpp"
SPECIAL_CONFIG = SOURCES + "/mtproto/special_config_request.cpp"
PROXY_DATA = SOURCES + "/mtproto/mtproto_proxy_data.cpp"
APPLICATION = SOURCES + "/core/application.cpp"
LAUNCHER = SOURCES + "/core/launcher.cpp"
LINUX = SOURCES + "/platform/linux/specific_linux.cpp"
WIN_APP_ID = SOURCES + "/platform/win/windows_app_user_model_id.cpp"
WIN_TOAST = SOURCES + "/platform/win/windows_toast_activator.h"
WIN_SPECIFIC = SOURCES + "/platform/win/specific_win.cpp"
WIN_RC = "Telegram/Resources/winrc/Telegram.rc"
CMAKE_APP = "Telegram/CMakeLists.txt"
CMAKE_OPTIONS = "Telegram/cmake/telegram_options.cmake"
PLIST = "Telegram/Telegram.plist"
ENTITLEMENTS = "Telegram/Telegram/Telegram.entitlements"
DESKTOP_FILE = "lib/xdg/org.telegram.desktop.desktop"
QT_VERSION_PY = "Telegram/build/qt_version.py"
PREPARE = "Telegram/build/prepare/prepare.py"
DOCKER_ENV = "Telegram/build/docker/centos_env"
BUILDING_WIN = "docs/building-win.md"
LINUX_WORKFLOW = ".github/workflows/linux.yml"
# The banner of contacts' birthdays at the top of the chat list.
BIRTHDAY_CONTACTS = SOURCES + "/dialogs/suggestions/suggestion_birthday_contacts.cpp"
# The gift button of a chat and the birthday row of a profile.
HISTORY_WIDGET = SOURCES + "/history/history_widget.cpp"
PROFILE_ACTIONS = SOURCES + "/info/profile/info_profile_actions.cpp"
# In the cmake_helpers submodule at cmake/.
CMAKE_VARIABLES = "cmake/variables.cmake"

# The brand (task 017 of the server repository): the files of brand/, the
# texts, the link scheme and the default themes.
BRAND = pathlib.Path(__file__).resolve().parent.parent / "brand"
LANG = "Telegram/Resources/langs/lang.strings"
NIGHT_THEME = "Telegram/Resources/night.tdesktop-theme"
SHELL_PAGE = "Telegram/Resources/bot_webview_shell_html/page.js"
CUSTOM_SHORTCUTS = "Telegram/Resources/default_shortcuts-custom.json"
EMBEDDED_THEMES = SOURCES + "/window/themes/window_themes_embedded.cpp"
EXPORT_HTML = SOURCES + "/export/output/export_output_html.cpp"
INTRO_QR = SOURCES + "/intro/intro_qr.cpp"
CONNECTION_BOX = SOURCES + "/boxes/connection_box.cpp"
ABOUT_BOX = SOURCES + "/boxes/about_box.cpp"
BANNED_BOX = SOURCES + "/boxes/phone_banned_box.cpp"
MAIN_MENU = SOURCES + "/window/window_main_menu.cpp"
SETTINGS_MAIN = SOURCES + "/settings/sections/settings_main.cpp"
DATA_PEER = SOURCES + "/data/data_peer.cpp"
SETTINGS_INTRO = SOURCES + "/settings/settings_intro.cpp"
# In the lib_ui and lib_base submodules.
PALETTE = "Telegram/lib_ui/ui/colors.palette"
TEXT_ENTITY = "Telegram/lib_ui/ui/text/text_entity.cpp"
QTHELP_URL = "Telegram/lib_base/base/qthelp_url.cpp"

# Upstream files that brand/tree replaces, rendered from brand/svg by
# brand/render.sh, with the SHA-256 of the pinned upstream's file: the patch
# replaces a file only when it is still upstream's (icons of a release that
# changes them are looked at again).
ASSETS = (
    ("Telegram/Resources/art/icon128.png", "731431e47a5bc91c697d25c3a54fe7ba004752f5b66e0f282c47588ff7a314e6"),
    ("Telegram/Resources/art/icon128@2x.png", "a6e26ac151cea4bf7642ce5ffcfed1dfec938a0c2db2ce26626adb4b14880b9c"),
    ("Telegram/Resources/art/icon16.png", "ea1f36152b143cc2664daef5026656d55be2230ed42d43628e17ef7d2fff718c"),
    ("Telegram/Resources/art/icon16@2x.png", "beecd061f6df3a63a8165bcac0b4acc322f5d096f1439c06e812225cfa3e23ae"),
    ("Telegram/Resources/art/icon256.ico", "6d27da5cf7669e32dc2cf09e331befe8e39045f75f95e0cbfe02c16e675d81bb"),
    ("Telegram/Resources/art/icon256.png", "3fb1400c7dc9bbc3b5cb3ffedcbf4a9b09c53e28b57a7ff33a8a6b9048864090"),
    ("Telegram/Resources/art/icon256@2x.png", "c395c36446e752513c3bba8a31da3a0bfd130440be2b71e6c3fa5ea05ffbd7ce"),
    ("Telegram/Resources/art/icon32.png", "9e4180c78c895783b4559c5e1a7868a2c9aa30a29969fe5dbe9a4ce4cf5cde6c"),
    ("Telegram/Resources/art/icon32@2x.png", "a67e2b8375e8ef28655f8772a85013ce637124971c0307d9d04497233cac400a"),
    ("Telegram/Resources/art/icon48.png", "041b78681a35f07c3c929662fc66b6592c88588dc7297a5394ef7f923f2118e2"),
    ("Telegram/Resources/art/icon48@2x.png", "2f7c026037ddfe12ecd3567f296aa6cbfb98a3c7f278798a9eca5f434f2893f7"),
    ("Telegram/Resources/art/icon512.png", "e297771c75bd2f81d637a3234f83568be62092f67d16946be23895fa92fa7119"),
    ("Telegram/Resources/art/icon512@2x.png", "286fbd6f210511daf5e7d26b62784d5d6abe575d72863b45c409f4e57b93db5d"),
    ("Telegram/Resources/art/icon64.png", "554dff9f55697d4e8ec69e9aa53678aa5dae3e91aa13adc3b115526d8d51dfc9"),
    ("Telegram/Resources/art/icon64@2x.png", "3072dec3872444fc3c1b8d7900205d3867e2fa312bb7084ac4f820a1ca518b78"),
    ("Telegram/Resources/art/icon_round512@2x.png", "fe5ef7cc2d6de70c63db265c849af6f912b1c0792eae9e12bec627b4f8366234"),
    ("Telegram/Resources/art/logo_256.png", "3fb1400c7dc9bbc3b5cb3ffedcbf4a9b09c53e28b57a7ff33a8a6b9048864090"),
    ("Telegram/Resources/art/logo_256_no_margin.png", "44af9a76a532559ef8cb450b48096713be819103ab79a19d7e4abb9b32ff4cb7"),
    ("Telegram/Resources/icons/intro_plane_inner.png", "4a7592dd9a7436cc0f5cb9f1f5676e69d3d1f97831f521204ba2f1675b7c33ea"),
    ("Telegram/Resources/icons/intro_plane_inner@2x.png", "25b9ad6b0176fbb787aa63947229e4d7bfb2b3de54be402cc50936a8a953da3f"),
    ("Telegram/Resources/icons/intro_plane_inner@3x.png", "6b4af679260bdf4585b825342f7cbc62ea61794c21ee5caa3b55cf59283ba5e4"),
    ("Telegram/Resources/icons/intro_plane_outer.png", "0119d5f36727e4634126dd15548398d37dbc11a03c12abb2798d8796fc5f49bd"),
    ("Telegram/Resources/icons/intro_plane_outer@2x.png", "9fd5188991564ae806b3ff4daa1412e0dab1e538c1d4b6127a9b88dfac0b5cc7"),
    ("Telegram/Resources/icons/intro_plane_outer@3x.png", "c596bbdda0e38786863d13579f3e995d2b541ddebb8c732caeeb4997616ac3e7"),
    ("Telegram/Resources/icons/intro_plane_top.png", "b2debf476ba94567633411b3786c30e3e4a2ea234f913756bd2ea04537fe2ab7"),
    ("Telegram/Resources/icons/intro_plane_top@2x.png", "ffe198e9f246c686782e4edfa242c0c7522f6b451ccddd76752bd3f5bce4e4f3"),
    ("Telegram/Resources/icons/intro_plane_top@3x.png", "a51803e3a345802577e0ad9e1d50560abfe347fcadc798415c109298151d2285"),
    ("Telegram/Resources/icons/intro_plane_trace.png", "e27a03292893b813ba89175f4667020280dc9bf980007a8a3216b071b23318f3"),
    ("Telegram/Resources/icons/intro_plane_trace@2x.png", "bfd4f363c9142f91b9bcc2186420a5d539581ab8557c88dc6adca4b52da9c15c"),
    ("Telegram/Resources/icons/intro_plane_trace@3x.png", "dcb075d5ac7a8b84113307cca7351b3aa21f517ea32b70db67dea73ee3bcdfb8"),
    ("Telegram/Resources/icons/intro_qr_plane.png", "7a3f2aadcb125f33757729cf707afc987a4ca1b8f288b2b49dec86a34402238d"),
    ("Telegram/Resources/icons/intro_qr_plane@2x.png", "482b4caa7daa25fa31bd3dd56b853df4506e4cfd241cb24a518344c7a5474ab5"),
    ("Telegram/Resources/icons/intro_qr_plane@3x.png", "1f4a91ceda3f74a9b544c810c54383c7d2ee7fc6056b04f19a71e5f24c21b267"),
    ("Telegram/Resources/icons/mac_tray_icon.png", "fdd45401382301b3495398a7e40919e5717c2b7239240a843d01ef15ebc54a1c"),
    ("Telegram/Resources/icons/mac_tray_icon@2x.png", "ccadde7f1b72e1aec15dc1054be5f36191357df847f883bc0f7d54b439f3b369"),
    ("Telegram/Resources/icons/mac_tray_icon@3x.png", "334731eed269374c2c3cb5836aa70a932fbf2697715bd2574ba4b2c5b4291eb5"),
    ("Telegram/Resources/icons/plane_white.svg", "03c4d53763861ff93e08314a3f5bf710059cb89aadfffc44c6be24dba29e57cb"),
    ("Telegram/Resources/icons/tray_monochrome.svg", "a93380f2c7e6aae4d5fde8940020bd966e97ad8c4880f45c016edfef3f5193e1"),
    ("Telegram/Resources/icons/tray_monochrome_attention.svg", "2b67ee19839dbbb9f57f2d7433fd6dc1059634d6d081c5e4c422c14f53fcfcc7"),
    ("Telegram/Resources/icons/tray_monochrome_mute.svg", "efa1439bd60b58db7b755f5d21be854ea686a0e1e2f1aa6e43bf35c083ee72fc"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon128.png", "440c9bda08c610968689793f91e8c9ddb6f68cbe036ec1c565652e4a490c31ee"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon128@2x.png", "2224aff4b266bbe8537a3665976755532fbed0f0a1b9c3c5b69ce685a14d81e9"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon16.png", "0c0865970588581338734e89ae3a34a93926f4f75117d72e903748528e3dc0cc"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon16@2x.png", "507d7c6066057ffce3539d6cf36eef4ec187187b4306d66586b4451e144ab6a4"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon256.png", "b82ae7291bd5fe75257ba7b10f04eb720aa1bd07a233a3e9f4998db6e4b2d3b0"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon256@2x.png", "560712f2fd027401853644906d4bd403ff702446a77c48650cca47cbd22fb1e4"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon32.png", "2f09885d2a44487631b73aad913060aa9c19da2f2cce289060f9c2b0fea01ca5"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon32@2x.png", "b66147a5f0b64ce49df92b26f7e833bd732f6cb42f2d65259ed55e18b6b37327"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon512.png", "d5f261f0e500cb9c553e515a59e7c802c6ad1c13d8a29dd306f65cbd7892a546"),
    ("Telegram/Telegram/Images.xcassets/Icon.appiconset/icon512@2x.png", "23cd0fb47b2a26eef1abf69e760dfb5deb02b1a60ce60f05c5f9d8c65f2f7b36"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_128x128.png", "440c9bda08c610968689793f91e8c9ddb6f68cbe036ec1c565652e4a490c31ee"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_128x128@2x.png", "2224aff4b266bbe8537a3665976755532fbed0f0a1b9c3c5b69ce685a14d81e9"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_16x16.png", "0c0865970588581338734e89ae3a34a93926f4f75117d72e903748528e3dc0cc"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_16x16@2x.png", "507d7c6066057ffce3539d6cf36eef4ec187187b4306d66586b4451e144ab6a4"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_256x256.png", "b82ae7291bd5fe75257ba7b10f04eb720aa1bd07a233a3e9f4998db6e4b2d3b0"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_256x256@2x.png", "560712f2fd027401853644906d4bd403ff702446a77c48650cca47cbd22fb1e4"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_32x32.png", "2f09885d2a44487631b73aad913060aa9c19da2f2cce289060f9c2b0fea01ca5"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_32x32@2x.png", "b66147a5f0b64ce49df92b26f7e833bd732f6cb42f2d65259ed55e18b6b37327"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_512x512.png", "d5f261f0e500cb9c553e515a59e7c802c6ad1c13d8a29dd306f65cbd7892a546"),
    ("Telegram/Telegram/Images.xcassets/Icon.iconset/icon_512x512@2x.png", "23cd0fb47b2a26eef1abf69e760dfb5deb02b1a60ce60f05c5f9d8c65f2f7b36"),
)

# The classes whose network requests go to Google, Mozilla and Firebase for
# Telegram's backup addresses and time: they may be constructed nowhere.
FALLBACK_CLASSES = {
    "SpecialConfigRequest": SOURCES + "/mtproto/special_config_request.",
    "DomainResolver": SOURCES + "/mtproto/details/mtproto_domain_resolver.",
}

# Written by the patch: what it did, for the build scripts and a reader.
MARKER = "pluma-patch.txt"

# Everything the patch reads, edits or checks: the check job fetches only
# these (ci/fetch-upstream.sh sparse). verify() scans all the sources.
UPSTREAM_PATHS = (".gitmodules", SOURCES, CMAKE_APP, CMAKE_OPTIONS, PLIST, ENTITLEMENTS, WIN_RC, DESKTOP_FILE,
                  QT_VERSION_PY, PREPARE, DOCKER_ENV, BUILDING_WIN, LINUX_WORKFLOW,
                  LANG, NIGHT_THEME, SHELL_PAGE, CUSTOM_SHORTCUTS) + tuple(path for path, _ in ASSETS)
# The same for files of submodules: (submodule, path inside it).
SUBMODULE_PATHS = (("cmake", "variables.cmake"), ("Telegram/lib_ui", "ui/colors.palette"),
                   ("Telegram/lib_ui", "ui/text/text_entity.cpp"), ("Telegram/lib_base", "base/qthelp_url.cpp"))

SOURCE_SUFFIXES = (".cpp", ".h", ".mm", ".m", ".c", ".cc", ".hpp")


class PatchError(Exception):
    pass


# --- RSA key -----------------------------------------------------------------


def _der_read(data, pos, tag):
    if pos >= len(data) or data[pos] != tag:
        raise PatchError(f"RSA key: unexpected DER at {pos}, expected tag {tag:#x}")
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return data[pos:pos + length], pos + length


def parse_pkcs1_der(der):
    """Returns (n, e) as big-endian bytes without leading zeros."""
    seq, end = _der_read(der, 0, 0x30)
    if end != len(der):
        raise PatchError("RSA key: trailing data after the key")
    n, pos = _der_read(seq, 0, 0x02)
    e, pos = _der_read(seq, pos, 0x02)
    if pos != len(seq):
        raise PatchError("RSA key: unexpected fields in the key")
    return n.lstrip(b"\0"), e.lstrip(b"\0")


def parse_pkcs1_public_key(pem):
    lines = [l.strip() for l in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN RSA PUBLIC KEY-----" or lines[-1] != "-----END RSA PUBLIC KEY-----":
        raise PatchError("RSA key: expected a PKCS#1 PEM (BEGIN RSA PUBLIC KEY)")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise PatchError("RSA key: the PEM body is not base64")
    return parse_pkcs1_der(der)


def _tl_bytes(b):
    if len(b) < 254:
        out = bytes([len(b)]) + b
    else:
        out = b"\xfe" + len(b).to_bytes(3, "little") + b
    return out + b"\0" * (-len(out) % 4)


def key_fingerprint(n, e):
    """MTProto fingerprint, as MTP::details::RSAPublicKey computes it: the
    low 64 bits of SHA1 over the TL-serialized modulus and exponent."""
    digest = hashlib.sha1(_tl_bytes(n) + _tl_bytes(e)).digest()
    return int.from_bytes(digest[-8:], "little")


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def canonical_pem(n, e):
    def der_int(b):
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + _der_len(len(b)) + b

    body = der_int(n) + der_int(e)
    der = b"\x30" + _der_len(len(body)) + body
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ["-----BEGIN RSA PUBLIC KEY-----", *lines, "-----END RSA PUBLIC KEY-----"]


def cpp_key(pem):
    """The PEM lines in tdesktop's layout of a key in a string literal: every
    line but the last ends with \\n and a line continuation."""
    return "".join(f"{l}\\n\\\n" for l in pem[:-1]) + pem[-1]


# --- edits -------------------------------------------------------------------


class Tree:
    """Files of the checkout, read and written as bytes: an edit must match
    the upstream exactly, line endings included."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        if not (self.root / VERSION_H).is_file() or not (self.root / CMAKE_APP).is_file():
            raise PatchError(f"{root}: not a telegramdesktop/tdesktop checkout")

    def read(self, rel):
        return self.read_bytes(rel).decode("utf-8")

    def read_bytes(self, rel):
        try:
            return (self.root / rel).read_bytes()
        except FileNotFoundError:
            raise PatchError(f"{rel}: missing; upstream moved it, or the checkout lacks it")

    def scan(self, rel):
        """A file to search, whatever its encoding."""
        return (self.root / rel).read_bytes().decode("utf-8", errors="replace")

    def write(self, rel, text):
        self.write_bytes(rel, text.encode("utf-8"))

    def write_bytes(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def lf_only(self, rel):
        if "\r\n" in self.read(rel):
            raise PatchError(f"{rel}: CRLF line endings; check out with core.autocrlf=false, core.eol=lf "
                             "(ci/fetch-upstream.sh)")

    def expect(self, rel, s, count=1):
        found = self.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; upstream changed it")

    def expect_some(self, rel, s):
        if s not in self.read(rel):
            raise PatchError(f"{rel}: no {s!r}; upstream changed it")

    def replace(self, rel, old, new, count=1):
        text = self.read(rel)
        found = text.count(old)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {old!r}, expected {count}")
        self.write(rel, text.replace(old, new))

    def sub(self, rel, pattern, repl, count=1):
        text = self.read(rel)
        out, found = re.subn(pattern, lambda _: repl, text)
        if found != count:
            raise PatchError(f"{rel}: {found} matches of /{pattern}/, expected {count}")
        self.write(rel, out)

    def _span(self, rel, head, tail, must_contain):
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head)
        end = text.find(tail, start + len(head))
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end + len(tail)]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        return text, start, end

    def replace_body(self, rel, head, tail, body, must_contain=()):
        """Replaces what lies between head and the first tail after it."""
        text, start, end = self._span(rel, head, tail, must_contain)
        self.write(rel, text[:start + len(head)] + body + text[end:])

    def replace_block(self, rel, head, tail, block, must_contain=()):
        """Replaces head, the first tail after it and what lies between."""
        text, start, end = self._span(rel, head, tail, must_contain)
        self.write(rel, text[:start] + block + text[end + len(tail):])

    def sources(self):
        base = self.root / SOURCES
        if not base.is_dir():
            raise PatchError(f"{SOURCES}: missing; not a full checkout of the sources")
        for p in sorted(base.rglob("*")):
            if p.suffix in SOURCE_SUFFIXES and p.is_file():
                yield p.relative_to(self.root).as_posix()


# --- configuration -----------------------------------------------------------


def load_env(path):
    out = {}
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise PatchError(f"{path}:{n}: expected KEY=VALUE")
        out[key.strip()] = value.strip()
    return out


class Config:
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem):
        def need(env, key):
            if not env.get(key):
                raise PatchError(f"{key} is not set")
            return env[key]

        def guid(key):
            try:
                value = str(uuid.UUID(need(app, key))).upper()
            except ValueError:
                raise PatchError(f"{key} is not a GUID")
            if value in TELEGRAM_GUIDS:
                raise PatchError(f"{key} is Telegram Desktop's GUID")
            return value

        self.layer = int(need(upstream, "UPSTREAM_LAYER"))
        self.version = need(upstream, "UPSTREAM_VERSION")
        self.qt = need(upstream, "QT_VERSION")
        self.windows_sdk = need(upstream, "WINDOWS_SDK")
        self.msvc_toolset = need(upstream, "MSVC_TOOLSET")
        self.ccache = need(upstream, "CCACHE_VERSION")

        self.app_name = need(app, "PLUMA_APP_NAME")
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]{1,31}", self.app_name) or "telegram" in self.app_name.lower():
            raise PatchError(f"PLUMA_APP_NAME {self.app_name!r}: a name of Pluma's own, a capital letter "
                             "first, then letters and digits (it names the data folder and the shortcuts)")
        self.app_id = need(app, "PLUMA_APP_ID")
        if (not re.fullmatch(r"[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+", self.app_id)
                or self.app_id.startswith(("org.telegram.", "com.tdesktop."))):
            raise PatchError(f"PLUMA_APP_ID {self.app_id!r} is not a reverse-DNS ID of Pluma's own")
        self.aumid = need(app, "PLUMA_WINDOWS_APP_USER_MODEL_ID")
        if (not re.fullmatch(r"[A-Za-z0-9]+(\.[A-Za-z0-9]+){1,3}", self.aumid) or len(self.aumid) > 128
                or self.aumid.lower().startswith("telegram.")):
            raise PatchError(f"PLUMA_WINDOWS_APP_USER_MODEL_ID {self.aumid!r}: Company.Product of Pluma's own")
        self.app_guid = guid("PLUMA_WINDOWS_APP_GUID")
        self.instance_guid = guid("PLUMA_INSTANCE_GUID")
        self.toast_clsid = guid("PLUMA_TOAST_ACTIVATOR_CLSID")
        if len({self.app_guid, self.instance_guid, self.toast_clsid}) != 3:
            raise PatchError("the Windows GUIDs of config/app.env must differ from each other")
        self.api_id = int(need(app, "PLUMA_API_ID"))
        if self.api_id <= 0:
            raise PatchError("PLUMA_API_ID must be positive")
        self.api_hash = need(app, "PLUMA_API_HASH")
        if not re.fullmatch(r"[0-9a-f]{32}", self.api_hash):
            raise PatchError("PLUMA_API_HASH must be 32 lowercase hex digits")

        try:
            self.ipv4 = str(ipaddress.IPv4Address(server_ipv4))
        except ValueError:
            raise PatchError(f"server IPv4 {server_ipv4!r} is not an IPv4 address (the built-in "
                             "datacenter takes an address, not a name)")
        self.ipv6 = None
        if server_ipv6:
            try:
                # tdesktop writes its built-in IPv6 addresses out in full.
                self.ipv6 = ipaddress.IPv6Address(server_ipv6).exploded
            except ValueError:
                raise PatchError(f"server IPv6 {server_ipv6!r} is not an IPv6 address")
        for a in filter(None, (self.ipv4, self.ipv6)):
            if any(ipaddress.ip_address(a) in net for net in TELEGRAM_NETWORKS):
                raise PatchError(f"server address {a} is Telegram's")
        try:
            self.port = int(server_port)
        except ValueError:
            self.port = 0
        if not 0 < self.port < 65536:
            raise PatchError(f"server port {server_port!r} is not a port")

        self.n, self.e = parse_pkcs1_public_key(rsa_pem)
        if len(self.n) * 8 != 2048 or int.from_bytes(self.e, "big") != 65537:
            raise PatchError(f"RSA key: {len(self.n) * 8} bits, exponent {int.from_bytes(self.e, 'big')}; "
                             "the clients expect 2048 bits and 65537")
        self.rsa_pem = canonical_pem(self.n, self.e)
        self.fingerprint = key_fingerprint(self.n, self.e)
        if self.fingerprint in TELEGRAM_FINGERPRINTS:
            raise PatchError("RSA key: this is Telegram's key")


# --- the patch ---------------------------------------------------------------

DC_ADDRESSES = ("149.154.175.50", "149.154.167.51", "95.161.76.100", "149.154.175.100", "149.154.167.91",
                "149.154.171.5", "2001:0b28:f23d:f001:0000:0000:0000:000a", "149.154.175.10", "149.154.167.40",
                "149.154.175.117", "2001:0b28:f23d:f003:0000:0000:0000:000e")

CMAKE_OPTIONS_OLD = """\
if (DESKTOP_APP_DISABLE_AUTOUPDATE)
    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE)
endif()

if (DESKTOP_APP_DISABLE_CRASH_REPORTS)
    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_CRASH_REPORTS)
endif()
"""

CMAKE_OPTIONS_NEW = """\
# pluma: no updates from Telegram and no crash reports to Telegram, whatever
# the options say. The build passes both (ci/); without them it stops here.
if (NOT DESKTOP_APP_DISABLE_AUTOUPDATE OR NOT DESKTOP_APP_DISABLE_CRASH_REPORTS)
    message(FATAL_ERROR "Pluma: configure with -D DESKTOP_APP_DISABLE_AUTOUPDATE=ON -D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON")
endif()
target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE TDESKTOP_DISABLE_CRASH_REPORTS)
"""
CMAKE_DEFINITIONS = "target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE TDESKTOP_DISABLE_CRASH_REPORTS)\n"

# The files the patch edits; it refuses CRLF in any of them.
EDITED = (DC_OPTIONS, INSTANCE_H, INSTANCE, CONFIG_LOADER, SPECIAL_CONFIG, PROXY_DATA, APPLICATION, LAUNCHER,
          LINUX, WIN_APP_ID, WIN_TOAST, WIN_SPECIFIC, WIN_RC, VERSION_H, CONFIG_H, CMAKE_APP, CMAKE_OPTIONS,
          PLIST, DESKTOP_FILE, PREPARE, BIRTHDAY_CONTACTS, HISTORY_WIDGET, PROFILE_ACTIONS)


# Backports of upstream fixes to the build scripts, each as (file, the
# pinned upstream's text, the fixed text), byte for byte as upstream wrote
# them. Once upstream.env pins a release that has a fix, its edit no longer
# matches and the patch stops: the backport goes then.
BACKPORTS = (
    # tdesktop b244f1b3 (2026-09-30, "Update msys2 and use ucrt versions of
    # packages"): MSYS2 removed the msvcrt-based mingw-w64-x86_64-* packages,
    # so prepare.py of 7.0.9 fails on Windows at its second stage.
    (PREPARE, "    'ThirdParty\\\\msys64\\\\mingw64\\\\bin',\n", "    'ThirdParty\\\\msys64\\\\ucrt64\\\\bin',\n"),
    (PREPARE, "releases/download/2025-08-30/msys2-base-x86_64-20250830.sfx.exe\"\n",
     "releases/download/2026-09-27/msys2-base-x86_64-20260927.sfx.exe\"\n"),
    (PREPARE, "        mingw-w64-x86_64-diffutils ^\n"
              "        mingw-w64-x86_64-gperf ^\n"
              "        mingw-w64-x86_64-nasm ^\n"
              "        mingw-w64-x86_64-perl ^\n"
              "        mingw-w64-x86_64-pkgconf\n",
     "        mingw-w64-ucrt-x86_64-diffutils ^\n"
     "        mingw-w64-ucrt-x86_64-gperf ^\n"
     "        mingw-w64-ucrt-x86_64-nasm ^\n"
     "        mingw-w64-ucrt-x86_64-perl ^\n"
     "        mingw-w64-ucrt-x86_64-pkgconf\n"),
)


# Pluma's own edits of the build scripts, as (file, the pinned upstream's
# text, the edited text).
BUILD_EDITS = (
    # prepare.py builds breakpad's dump_syms in the release variant on
    # Windows: symbol files for Telegram's crash reports, which Pluma compiles
    # out. It needs ATL, which the image's MSVC 14.44 toolset does not have
    # ("Cannot open include file: 'atlbase.h'"); the upstream CI, building
    # Debug only, never reaches it.
    (PREPARE, "    ninja -C out/Release%FolderPostfix% common crash_generation_client exception_handler\n"
              "    cd tools\\\\windows\\\\dump_syms\n"
              "    gyp dump_syms.gyp --format=msvs\n"
              "    msbuild -m dump_syms.vcxproj /property:Configuration=Release /property:Platform=\"x64\" %ToolsetProp%\n"
              "win:\n",
     "    ninja -C out/Release%FolderPostfix% common crash_generation_client exception_handler\n"
     "win:\n"),
    # macOS: the Release client links the release variants of the libraries
    # alone (cmake_helpers picks them by $<CONFIG>). The libraries took 20 GB
    # after trimming, 4.8 GB in the cache, above all the debug builds of Qt
    # and tg_owt and Qt's debug information, which serves symbol files of
    # crash reports that Pluma compiles out. So Qt is built in its release
    # variant alone, without -force-debug-info, into an emptied prefix (the
    # files of a previous build would stay), and tg_owt without its Debug
    # builds. The Windows libraries stay as they are.
    (PREPARE, "    CONFIGURATIONS=-debug\n"
              "release:\n"
              "    CONFIGURATIONS=-debug-and-release\n"
              "mac:\n"
              "    ./configure -prefix \"$USED_PREFIX/Qt-$QT\" \\\n"
              "        $CONFIGURATIONS \\\n"
              "        -force-debug-info \\\n",
     "    CONFIGURATIONS=-debug\n"
     "release:\n"
     "    CONFIGURATIONS=-release\n"
     "mac:\n"
     "    rm -rf \"$USED_PREFIX/Qt-$QT\"\n"
     "    ./configure -prefix \"$USED_PREFIX/Qt-$QT\" \\\n"
     "        $CONFIGURATIONS \\\n"),
    (PREPARE, "".join(f"    mkdir Debug.{arch}\n"
                      f"    cd Debug.{arch}\n"
                      "    cmake \\\n"
                      "        -DCMAKE_BUILD_TYPE=Debug \\\n"
                      f"        -DCMAKE_OSX_ARCHITECTURES={arch} \\\n"
                      "        -DTG_OWT_BUILD_AUDIO_BACKENDS=OFF \\\n"
                      "        -DTG_OWT_SPECIAL_TARGET=$SPECIAL_TARGET \\\n"
                      "        -DTG_OWT_LIBJPEG_INCLUDE_PATH=$MOZJPEG_PATH \\\n"
                      "        -DTG_OWT_OPENSSL_INCLUDE_PATH=$LIBS_DIR/openssl3/include \\\n"
                      "        -DTG_OWT_OPUS_INCLUDE_PATH=$OPUS_PATH \\\n"
                      "        -DTG_OWT_LIBVPX_INCLUDE_PATH=$LIBVPX_PATH \\\n"
                      "        -DTG_OWT_OPENH264_INCLUDE_PATH=$OPENH264_PATH \\\n"
                      "        -DTG_OWT_FFMPEG_INCLUDE_PATH=$FFMPEG_PATH ../..\n"
                      "    cmake --build .\n"
                      "    cd ..\n" for arch in ("x86_64", "arm64"))
              + "    mkdir Debug\n"
                "    lipo -create Debug.arm64/libtg_owt.a Debug.x86_64/libtg_owt.a -output Debug/libtg_owt.a\n",
     ""),
)

# The banner "It's ...'s birthday today!" at the top of the chat list, as
# (the pinned upstream's text, Pluma's) of BIRTHDAY_CONTACTS. Upstream shows
# it only to those who can buy Premium (Session::premiumCanBuy(), false when
# help.getAppConfig sets premium_purchase_blocked, as the Pluma server does),
# and a click opens the gift box. Pluma has no Premium and no gifts: the
# banner shows to everyone, and a click opens the chat with the contact or,
# for several, a box "Birthdays" with them, where a click opens the chat
# (ContactsBoxController::rowClicked). It says "Send message" in place of
# "Send them a Gift.", and closing it, which still dismisses it as upstream
# does, shows no toast that a gift can be sent later. When it shows and how
# it looks stay upstream's. The chat it opens and the contact's profile offer
# no gift either (BIRTHDAY_GIFTS).
BIRTHDAY_BANNER = (
    ('#include "boxes/star_gift_box.h"\n', '#include "boxes/peer_list_controllers.h"\n'),
    ("bool Available(const Context &context) {\n"
     "\tconst auto session = context.session.get();\n"
     "\treturn session->premiumCanBuy()\n"
     "\t\t&& session->promoSuggestions().current(kSugBirthdayContacts.utf8());\n"
     "}\n",
     "// pluma: the contacts with a birthday today in a box of the contacts,\n"
     "// where a click opens the chat (ContactsBoxController::rowClicked).\n"
     "// Without a search controller its search filters them by name and sends\n"
     "// no contacts.search.\n"
     "class BirthdayContactsController final : public ContactsBoxController {\n"
     "public:\n"
     "\tBirthdayContactsController(\n"
     "\t\tnot_null<Main::Session*> session,\n"
     "\t\tstd::vector<UserId> users)\n"
     "\t: ContactsBoxController(session, nullptr)\n"
     "\t, _users(std::move(users)) {\n"
     "\t}\n"
     "\n"
     "protected:\n"
     "\tstd::unique_ptr<PeerListRow> createRow(\n"
     "\t\t\tnot_null<UserData*> user) override {\n"
     "\t\treturn ranges::contains(_users, peerToUser(user->id))\n"
     "\t\t\t? ContactsBoxController::createRow(user)\n"
     "\t\t\t: nullptr;\n"
     "\t}\n"
     "\n"
     "private:\n"
     "\tconst std::vector<UserId> _users;\n"
     "\n"
     "};\n"
     "\n"
     "bool Available(const Context &context) {\n"
     "\t// pluma: not only for those who can buy Premium: the banner opens a\n"
     "\t// chat, not the gift box.\n"
     "\tconst auto session = context.session.get();\n"
     "\treturn session->promoSuggestions().current(kSugBirthdayContacts.utf8());\n"
     "}\n"),
    ("\t\tcontent->setClickedCallback([=] {\n"
     "\t\t\tif (isSingle) {\n"
     "\t\t\t\tUi::ShowStarGiftBox(controller, first);\n"
     "\t\t\t} else {\n"
     "\t\t\t\tUi::ChooseStarGiftRecipient(controller);\n"
     "\t\t\t}\n"
     "\t\t});\n"
     "\t\tcontent->setHideCallback([=] {\n"
     "\t\t\tpromo->dismiss(kSugBirthdayContacts.utf8());\n"
     "\t\t\tcontroller->showToast(\n"
     "\t\t\t\ttr::lng_dialogs_suggestions_birthday_contact_dismiss(\n"
     "\t\t\t\t\ttr::now));\n"
     "\t\t\trecompute();\n"
     "\t\t});\n",
     "\t\t// pluma: no gift box. The chat with the contact, or a box with those\n"
     "\t\t// whose birthday is today, to open the chat with one.\n"
     "\t\tcontent->setClickedCallback([=] {\n"
     "\t\t\tif (isSingle) {\n"
     "\t\t\t\tcontroller->showPeerHistory(first);\n"
     "\t\t\t} else {\n"
     "\t\t\t\tcontroller->show(Box<PeerListBox>(\n"
     "\t\t\t\t\tstd::make_unique<BirthdayContactsController>(\n"
     "\t\t\t\t\t\tsession,\n"
     "\t\t\t\t\t\tusers),\n"
     "\t\t\t\t\t[](not_null<PeerListBox*> box) {\n"
     "\t\t\t\t\t\tbox->setTitle(tr::lng_gift_subtitle_birthdays());\n"
     "\t\t\t\t\t\tbox->addButton(tr::lng_close(), [=] {\n"
     "\t\t\t\t\t\t\tbox->closeBox();\n"
     "\t\t\t\t\t\t});\n"
     "\t\t\t\t\t}));\n"
     "\t\t\t}\n"
     "\t\t});\n"
     "\t\t// pluma: no toast that a gift can be sent later in Settings.\n"
     "\t\tcontent->setHideCallback([=] {\n"
     "\t\t\tpromo->dismiss(kSugBirthdayContacts.utf8());\n"
     "\t\t\trecompute();\n"
     "\t\t});\n"),
    ("\t\tauto text = isSingle\n"
     "\t\t\t? tr::lng_dialogs_suggestions_birthday_contact_about(\n"
     "\t\t\t\ttr::now,\n"
     "\t\t\t\tTextWithEntities::Simple)\n"
     "\t\t\t: tr::lng_dialogs_suggestions_birthday_contacts_about(\n"
     "\t\t\t\ttr::now,\n"
     "\t\t\t\tTextWithEntities::Simple);\n",
     "\t\t// pluma: what a click does, in place of the offer of a gift.\n"
     "\t\tauto text = tr::lng_context_send_message(\n"
     "\t\t\ttr::now,\n"
     "\t\t\tTextWithEntities::Simple);\n"),
)

# Where upstream offers a gift on a contact's birthday although Premium cannot
# be bought, as (file, the pinned upstream's text, Pluma's). Upstream shows
# the gift button of a chat (HistoryWidget::refreshSendGiftToggle) on the
# contact's birthday whatever Premium, and the birthday row of a profile opens
# the gift box on any day while Premium cannot be bought, for gifts paid in
# Stars. Pluma has no Premium, no Stars and no gifts: both offer a gift only
# while Premium can be bought, as the gift button of a profile's top bar
# (info_profile_top_bar.cpp) and the Android and web apps do.
BIRTHDAY_GIFTS = (
    (HISTORY_WIDGET,
     "\t\t&& !user->isBot()\n"
     "\t\t&& ((disallowed & Type::SendHide)\n",
     "\t\t&& !user->isBot()\n"
     "\t\t// pluma: no gift while Premium cannot be bought.\n"
     "\t\t&& session().premiumCanBuy()\n"
     "\t\t&& ((disallowed & Type::SendHide)\n"),
    (PROFILE_ACTIONS,
     "\t\tconst auto disable = !today && user->session().premiumCanBuy();\n",
     "\t\t// pluma: the gift on the birthday only, and only while Premium can be\n"
     "\t\t// bought.\n"
     "\t\tconst auto disable = !today || !user->session().premiumCanBuy();\n"),
)

# --- the brand ---------------------------------------------------------------

# The name in the code: (file, upstream text, Pluma's with {name}, how many).
# Log lines, identifiers, file formats nobody sees, the alpha-only and
# crash-report-only texts (both compiled out) stay; verify() counts what is
# left (CODE_TELEGRAM).
CODE_NAMES = (
    (SOURCES + "/intro/intro_start.cpp", 'setTitleText(rpl::single(u"Telegram Desktop"_q));',
     'setTitleText(rpl::single(u"{name}"_q));', 1),
    (ABOUT_BOX, 'box->setTitle(u"Telegram Desktop"_q);', 'box->setTitle(u"{name}"_q);', 1),
    (SOURCES + "/window/main_window.cpp", '(user.isEmpty() ? u"Telegram"_q : user)',
     '(user.isEmpty() ? u"{name}"_q : user)', 1),
    (SOURCES + "/window/notifications_manager_default.cpp", 'TextWithEntities{ u"Telegram Desktop"_q }',
     'TextWithEntities{ u"{name}"_q }', 1),
    (SOURCES + "/settings/sections/settings_notifications.cpp", 'elided(u"Telegram Desktop"_q, rectForName.width())',
     'elided(u"{name}"_q, rectForName.width())', 1),
    (SOURCES + "/platform/mac/window_title_mac.mm", 'p.drawText(titleRect, u"Telegram"_q, style::al_center);',
     'p.drawText(titleRect, u"{name}"_q, style::al_center);', 1),
    (SOURCES + "/platform/mac/global_menu_mac.mm", '\t\t\tu"About Telegram"_q,\n', '\t\t\tu"About {name}"_q,\n', 1),
    (SOURCES + "/platform/mac/global_menu_mac.mm", '\t\tu"Show Telegram"_q,\n', '\t\tu"Show {name}"_q,\n', 1),
    (SOURCES + "/platform/mac/global_menu_mac.mm", '_menuBar->addMenu(u"Telegram"_q)', '_menuBar->addMenu(u"{name}"_q)', 1),
    # The {telegram} of "Quit {telegram}" and "About {telegram}".
    (SOURCES + "/platform/linux/main_window_linux.cpp", 'u"Telegram"_q)', 'u"{name}"_q)', 2),
    (WIN_SPECIFIC, 'L"Telegram autorun link.\\n"\n\t\t"You can disable autorun in Telegram settings.");',
     'L"{name} autorun link.\\n"\n\t\t"You can disable autorun in {name} settings.");', 1),
    (WIN_SPECIFIC, 'L"Telegram send to link.\\n"\n\t\t"You can disable send to menu item in Telegram settings.");',
     'L"{name} send to link.\\n"\n\t\t"You can disable send to menu item in {name} settings.");', 1),
    # The ring of text around a round video being recorded.
    (SOURCES + "/ui/controls/round_video_recorder.cpp", 'u"Telegram"_q.toUpper(),', 'u"{name}"_q.toUpper(),', 1),
    # The title of a bot web app's window on Linux, until the app sets one.
    (SOURCES + "/ui/chat/attach/attach_bot_webview_linux_shell.cpp", '"document.title = \'Telegram\';"',
     '"document.title = \'{name}\';"', 1),
    (SHELL_PAGE, "document.title = (data && data.title) || 'Telegram';",
     "document.title = (data && data.title) || '{name}';", 2),
    # The name of the service notifications account (777000) until the
    # server's arrives.
    (SOURCES + "/data/data_session.cpp", 'MTP_string("Telegram"),', 'MTP_string("{name}"),', 1),
    (SOURCES + "/data/data_message_reactions.cpp", '.title = u"Telegram Star"_q,', '.title = u"{name} Star"_q,', 1),
    (SOURCES + "/lang/lang_hardcoded.h", "Telegram Passport", "{name} Passport", 5),
    # The HTML of an export.
    (EXPORT_HTML, '"of Telegram Desktop. Please update the application."',
     '"of {name}. Please update the application."', 1),
    (EXPORT_HTML, '" joined Telegram";', '" joined {name}";', 1),
    (EXPORT_HTML, "Telegram Premium", "{name} Premium", 7),
    (EXPORT_HTML, '" Telegram Stars."', '" {name} Stars."', 5),
    (EXPORT_HTML, '"Telegram and received', '"{name} and received', 2),
    (EXPORT_HTML, '"selected by Telegram and received', '"selected by {name} and received', 2),
    (EXPORT_HTML, '" was randomly selected by Telegram."', '" was randomly selected by {name}."', 1),
    # The window shown when the app cannot start (no writable data folder).
    (SOURCES + "/core/crash_report_window.cpp", 'setWindowTitle(title.isEmpty() ? u"Telegram"_q : title);',
     'setWindowTitle(title.isEmpty() ? u"{name}"_q : title);', 1),
    (SOURCES + "/core/crash_report_window.cpp", 'u"Could not start Telegram Desktop!\\nYou can see complete log below:"_q',
     'u"Could not start {name}!\\nYou can see complete log below:"_q', 1),
    # Local automation: the question, and the error the other program gets.
    (SOURCES + "/core/external_control.cpp", 'u"Telegram Desktop over the local socket', 'u"{name} over the local socket', 1),
    (SOURCES + "/core/external_control.cpp", 'u"Telegram window to enable"_q', 'u"{name} window to enable"_q', 1),
    (SOURCES + "/core/mime_type.cpp", 'u"Telegram sticker (*.tgs)"_q', 'u"{name} sticker (*.tgs)"_q', 1),
    # The headers of the shortcut files in the data folder.
    (SOURCES + "/core/shortcuts.cpp", "// This is a list of default shortcuts for Telegram Desktop\n",
     "// This is a list of default shortcuts for {name}\n", 1),
    (SOURCES + "/core/shortcuts.cpp", "// This is a list of changed shortcuts for Telegram Desktop\n",
     "// This is a list of changed shortcuts for {name}\n", 1),
    (CUSTOM_SHORTCUTS, "// This is a list of your own shortcuts for Telegram Desktop\n",
     "// This is a list of your own shortcuts for {name}\n", 1),
)

# What stays of "Telegram" as a word in the string literals of the sources
# (links and copyright headers aside), per file: the edits above leave these
# on purpose, and a new one in an upstream update stops the patch here.
CODE_TELEGRAM = {
    # The updater and its startup task, which Pluma does not build.
    "_other/startup_task_win.cpp": 1,
    "_other/updater_linux.cpp": 4,
    "_other/updater_osx.m": 2,
    "_other/updater_win.cpp": 9,
    "core/update_checker.cpp": 1,
    # Log lines.
    "api/api_updates.cpp": 1,
    "core/crash_reports.cpp": 1,
    "core/launcher.cpp": 2,
    "core/sandbox.cpp": 1,
    # The windows of a crash report, compiled out (TDESKTOP_DISABLE_CRASH_REPORTS).
    "core/crash_report_window.cpp": 7,
    # Builds Pluma does not make: alpha versions, the Mac App Store, Windows Store.
    "boxes/about_box.cpp": 1,
    "core/file_utilities.cpp": 1,
    "platform/win/specific_win.cpp": 1,
    "platform/win/windows_app_user_model_id.cpp": 1,
    # Telegram Desktop's own api_id in the list of sessions.
    "api/api_authorizations.cpp": 1,
    # Names in files and protocols nobody reads: the calendar file's PRODID,
    # the generator of a rich message export, the test example of an export,
    # the company name sent to Stripe, the resource file of the macOS bundle.
    "core/click_handler_types.cpp": 1,
    "iv/iv_rich_page.h": 1,
    "export/output/export_output_abstract.cpp": 1,
    "payments/payments_form.cpp": 1,
    "platform/mac/launcher_mac.mm": 1,
}

# The built-in English (lang.strings): every "Telegram" outside a link names
# Pluma, "Telegram Desktop" included; the keys and their counts are pinned in
# brand/strings.txt (patch.py --strings prints them for a lang.strings). The
# links keep opening Telegram's pages. Kept: the credit of the protocol in
# the about box.
LANG_ENTRY = re.compile(r'^"(?P<key>[A-Za-z0-9_#]+)" = +"(?P<value>(?:[^"\\\n]|\\.)*)";$', re.M)
LANG_LINK = re.compile(r"(?:https?://)?(?:[\w-]+\.)*(?:telegram\.org|telegram\.me|t\.me|fragment\.com)"
                       r"(?:/[^\s\"<>)\]]*)?", re.I)
LANG_KEEP = {"lng_about_text1_api": "Telegram API"}

# plm:// links in place of tg://, with how many "tg://" each file of the
# sources holds: the app opens, recognises in texts and creates plm:// links
# (the QR code of a sign-in among them), and registers plm:// with the
# system. tg:// and tonsite:// stay with Telegram Desktop on the same computer.
SCHEME_FILES = {
    "api/api_single_message_search.cpp": 3,
    "boxes/connection_box.cpp": 3,
    "core/application.cpp": 3,
    "core/click_handler_types.cpp": 2,
    "core/deep_links/deep_links_settings.cpp": 2,
    "core/local_url_handlers.cpp": 30,
    "core/ui_integration.cpp": 1,
    "data/data_cloud_themes.cpp": 1,
    "data/data_story.cpp": 1,
    "history/history_drag_area.cpp": 2,
    "history/view/media/history_view_theme_document.cpp": 1,
    "history/view/media/history_view_userpic_suggestion.cpp": 1,
    "inline_bots/bot_attach_web_view.cpp": 2,
    "intro/intro_qr.cpp": 1,
    "iv/editor/iv_editor_clipboard_import.cpp": 1,
    "iv/iv_rich_message_html_export.cpp": 4,
    "media/stories/media_stories_controller.cpp": 1,
    "menu/menu_ttl_validator.cpp": 1,
    "settings/sections/settings_main.cpp": 1,
    "settings/sections/settings_privacy_security.cpp": 1,
    "settings/settings_experimental.cpp": 1,
    "ui/boxes/about_cocoon_box.cpp": 1,
    "window/window_filters_favorite.cpp": 3,
}

REGISTER_URL_SCHEME = """\
	const auto arguments = Launcher::Instance().customWorkingDir()
		? u"-workdir \\"%1\\""_q.arg(cWorkingDir())
		: QString();

	// pluma: plm:// links. The tg and tonsite schemes stay with Telegram
	// Desktop on the same computer.
	base::Platform::RegisterUrlScheme(base::Platform::UrlSchemeDescriptor{
		.executable = Platform::ExecutablePathForShortcuts(),
		.arguments = arguments,
		.protocol = u"plm"_q,
		.protocolName = u"{name} Link"_q,
		.shortAppName = u"pluma"_q,
		.longAppName = QCoreApplication::applicationName(),
		.displayAppName = AppName.utf16(),
		.displayAppDescription = AppName.utf16(),
	});"""

# The default themes, palette "graphite and sage" (brand/palette-*.txt): the
# night theme is a zip of its colours and a 1x1 background, which the patch
# writes again; the background is the chat's, a shade below the window's.
NIGHT_THEME_SHA256 = "364fcd7288453377e16db9c733fd98699b161248bc62cc62f78d58d909951d3a"
NIGHT_COLORS, NIGHT_BACKGROUND = "colors.tdesktop-theme", "background.png"
NIGHT_WALLPAPER = (0x0F, 0x11, 0x0F)

# The theme tiles of Settings > Chat Settings and the base colour of the
# accent picker, which recolours what is near it: the Pluma accent.
EMBEDDED_CLASSIC = ("""\
			EmbeddedType::Default,
			qColor("9bd494"),
			qColor("eaffdc"),
			qColor("ffffff"),
			qColor("eaffdc"),
			qColor("ffffff"),
			name(tr::lng_settings_theme_classic),
			QString(),
			qColor("40a7e3")
""", """\
			EmbeddedType::Default,
			qColor("9bd494"),
			qColor("e3eae2"),
			qColor("ffffff"),
			qColor("e3eae2"),
			qColor("ffffff"),
			name(tr::lng_settings_theme_classic),
			QString(),
			qColor("5b7a5e") // pluma: the accent of brand/palette-day.txt
""")
EMBEDDED_NIGHT = ("""\
			EmbeddedType::Night,
			qColor("485761"),
			qColor("5ca7d4"),
			qColor("6b808d"),
			qColor("6b808d"),
			qColor("5ca7d4"),
			name(tr::lng_settings_theme_tinted),
			":/gui/night.tdesktop-theme",
			qColor("5288c1")
""", """\
			EmbeddedType::Night,
			qColor("3a423a"),
			qColor("7fa082"),
			qColor("5f685f"),
			qColor("5f685f"),
			qColor("7fa082"),
			name(tr::lng_settings_theme_tinted),
			":/gui/night.tdesktop-theme",
			qColor("9dbb9f") // pluma: the accent of brand/palette-night.txt
""")
# When the user picks an accent for the night theme, the text on what the
# accent fills keeps its contrast: Pluma's text there is dark, so a dark
# accent turns it white.
NIGHT_CONTRAST = ("""\
		result.keepContrast = base::flat_map<QLatin1String, Pair>{ {
			//{ qstr("windowFgActive"), Pair{ cColor("5288c1"), cColor("17212b") } }, // windowBgActive
			{ qstr("activeButtonFg"), Pair{ cColor("2f6ea5"), cColor("17212b") } }, // activeButtonBg
			{ qstr("profileVerifiedCheckFg"), Pair{ cColor("5288c1"), cColor("17212b") } }, // profileVerifiedCheckBg
			{ qstr("overviewCheckFgActive"), Pair{ cColor("5288c1"), cColor("17212b") } }, // overviewCheckBgActive
			{ qstr("historyFileInIconFg"), Pair{ cColor("3f96d0"), cColor("182533") } }, // msgFileInBg, msgInBg
			{ qstr("historyFileInIconFgSelected"), Pair{ cColor("6ab4f4"), cColor("2e70a5") } }, // msgFileInBgSelected, msgInBgSelected
			{ qstr("historyFileInRadialFg"), Pair{ cColor("3f96d0"), cColor("182533") } }, // msgFileInBg, msgInBg
			{ qstr("historyFileInRadialFgSelected"), Pair{ cColor("6ab4f4"), cColor("2e70a5") } }, // msgFileInBgSelected, msgInBgSelected
			{ qstr("historyFileOutIconFg"), Pair{ cColor("4c9ce2"), cColor("2b5278") } }, // msgFileOutBg, msgOutBg
			{ qstr("historyFileOutIconFgSelected"), Pair{ cColor("58abf3"), cColor("2e70a5") } }, // msgFileOutBgSelected, msgOutBgSelected
			{ qstr("historyFileOutRadialFg"), Pair{ cColor("4c9ce2"), cColor("2b5278") } }, // msgFileOutBg, msgOutBg
			{ qstr("historyFileOutRadialFgSelected"), Pair{ cColor("58abf3"), cColor("2e70a5") } }, // msgFileOutBgSelected, msgOutBgSelected
		} };
""", """\
		// pluma: the night colours of brand/palette-night.txt.
		result.keepContrast = base::flat_map<QLatin1String, Pair>{ {
			{ qstr("activeButtonFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // activeButtonBg
			{ qstr("profileVerifiedCheckFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // profileVerifiedCheckBg
			{ qstr("overviewCheckFgActive"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // overviewCheckBgActive
			{ qstr("historyFileInIconFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // msgFileInBg
			{ qstr("historyFileInIconFgSelected"), Pair{ cColor("b2ceb4"), cColor("ffffff") } }, // msgFileInBgSelected
			{ qstr("historyFileInRadialFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // msgFileInBg
			{ qstr("historyFileInRadialFgSelected"), Pair{ cColor("b2ceb4"), cColor("ffffff") } }, // msgFileInBgSelected
			{ qstr("historyFileOutIconFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // msgFileOutBg
			{ qstr("historyFileOutIconFgSelected"), Pair{ cColor("b2ceb4"), cColor("ffffff") } }, // msgFileOutBgSelected
			{ qstr("historyFileOutRadialFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }, // msgFileOutBg
			{ qstr("historyFileOutRadialFgSelected"), Pair{ cColor("b2ceb4"), cColor("ffffff") } }, // msgFileOutBgSelected
		} };
""")
# The circle under the mark in the centre of QR codes (sign-in, proxy).
QR_COLORS = ((INTRO_QR, "\treturn QColor(0x40, 0xA7, 0xE3); // Default windowBgActive.\n",
              "\treturn QColor(0x5B, 0x7A, 0x5E); // pluma: the default windowBgActive.\n"),
             (CONNECTION_BOX, "\treturn QColor(0x40, 0xA7, 0xE3);\n",
              "\treturn QColor(0x5B, 0x7A, 0x5E); // pluma: the default windowBgActive.\n"))

# Telegram's accent blues, in no default colour of Pluma's (verify()).
TELEGRAM_BLUES = ("40a7e3", "419fd9", "39a5db", "2095d0", "37a1de", "54c3f3", "5288c1", "6ab3f3", "2f6ea5",
                  "4082bc", "2b5278", "6ab2f2", "72bcfd", "64b9fa", "5eb5f7")
# Keys of the default themes that may stay blue: user colours, file type
# colours, the Premium, statistics and call palettes (verify()).
KEPT_BLUE = re.compile(r"historyPeer[47]\w*|msgFile1\w*|mediaviewFileBlueCornerFg|settingsIconBg[45]"
                       r"|stickerPanPremium[12]|premiumButtonBg1|statisticsChart\w+|groupCall\w+")


def load_table(path):
    """The lines "key: upstream value -> Pluma value" of a brand table."""
    rows = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, rest = line.partition(": ")
        old, arrow, new = rest.partition(" -> ")
        if not sep or not arrow or not re.fullmatch(r"[A-Za-z0-9_]+", key) or not old or not new:
            raise PatchError(f"{path.name}:{n}: expected 'key: upstream value -> Pluma value'")
        rows.append((key, old, new))
    if len({key for key, _, _ in rows}) != len(rows):
        raise PatchError(f"{path.name}: a key is there twice")
    return rows


def recolor(text, rows, where):
    """The colours of a palette or theme with every "key: old;" of rows made
    "key: new;", and the keys with old "-" added."""
    text = "\n" + text
    for key, old, new in rows:
        if old == "-":
            if re.search(rf"^{key}:", text, re.M):
                raise PatchError(f"{where}: {key} is there already; upstream added it")
            text += f"{key}: {new}; // pluma\n"
            continue
        line = f"\n{key}: {old};"
        if text.count(line) != 1:
            raise PatchError(f"{where}: {text.count(line)} occurrences of {line.strip()!r}, expected 1; "
                             "upstream changed the colour")
        text = text.replace(line, f"\n{key}: {new};")
    return text[1:]


def palette_values(text):
    """{key: value} of a palette or theme, the value as written."""
    return dict(re.findall(r"^([A-Za-z0-9_]+):\s*([^;]*?)\s*;", text, re.M))


def night_colors(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.namelist() != [NIGHT_COLORS, NIGHT_BACKGROUND]:
                raise PatchError(f"{NIGHT_THEME}: holds {z.namelist()}")
            return z.read(NIGHT_COLORS).decode("utf-8")
    except zipfile.BadZipFile:
        raise PatchError(f"{NIGHT_THEME}: not a zip")


def png_1x1(rgb):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0" + bytes(rgb), 9)) + chunk(b"IEND", b""))


def night_theme(colors):
    """The night theme's zip, the same for the same colours."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in ((NIGHT_COLORS, colors.encode("utf-8")), (NIGHT_BACKGROUND, png_1x1(NIGHT_WALLPAPER))):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)
    return out.getvalue()


def lang_entries(text):
    entries = list(LANG_ENTRY.finditer(text))
    lines = sum(1 for line in text.split("\n") if line.startswith('"'))
    if len(entries) != lines:
        raise PatchError(f"{LANG}: {lines - len(entries)} entries in a form the patch does not read")
    return entries


def name_telegram(value, name):
    """value with every "Telegram" outside its links naming name, and how
    many there were."""
    out, count, pos = [], 0, 0
    for m in [*LANG_LINK.finditer(value), None]:
        plain = value[pos:m.start() if m else len(value)]
        count += plain.count("Telegram")
        out.append(plain.replace("Telegram Desktop", name).replace("Telegram", name))
        if m:
            out.append(m.group(0))
            pos = m.end()
    return "".join(out), count


def lang_counts(text):
    """{key: how many "Telegram" outside links} of a lang.strings, in its
    order, LANG_KEEP aside."""
    result = {}
    for m in lang_entries(text):
        if m["key"] not in LANG_KEEP:
            count = name_telegram(m["value"], "")[1]
            if count:
                result[m["key"]] = count
    return result


def load_strings():
    result = {}
    path = BRAND / "strings.txt"
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([A-Za-z0-9_#]+) ([1-9][0-9]*)", line)
        if not m or m.group(1) in result:
            raise PatchError(f"{path.name}:{n}: expected 'key count', each key once")
        result[m.group(1)] = int(m.group(2))
    return result


def rebrand(tree, c):
    """The brand of Pluma (task 017 of the server repository)."""
    name = c.app_name

    # The texts: the built-in English and the places in the code.
    text = tree.read(LANG)
    found, expected = lang_counts(text), load_strings()
    if found != expected:
        def keys(ks):
            return ", ".join(sorted(ks)[:5]) or "none"
        changed = {k for k in set(found) & set(expected) if found[k] != expected[k]}
        raise PatchError(f"{LANG}: the strings that name Telegram are not those of brand/strings.txt "
                         f"(new: {keys(set(found) - set(expected))}; gone: {keys(set(expected) - set(found))}; "
                         f"changed: {keys(changed)}); look at them and write the table again "
                         "(patch.py --strings)")
    for key, value in LANG_KEEP.items():
        tree.expect(LANG, f'"{key}" = "{value}";\n')

    def entry(m):
        if m["key"] in LANG_KEEP:
            return m.group(0)
        head = m.group(0)[:m.start("value") - m.start()]
        return head + name_telegram(m["value"], name)[0] + '";'
    tree.write(LANG, LANG_ENTRY.sub(entry, text))
    for rel, old, new, count in CODE_NAMES:
        tree.replace(rel, old, new.replace("{name}", name), count=count)

    # plm:// in place of tg://.
    for rel, count in SCHEME_FILES.items():
        tree.replace(f"{SOURCES}/{rel}", "tg://", "plm://", count=count)
    tree.replace_body(APPLICATION, "void Application::RegisterUrlScheme() {\n", "\n}\n",
                      REGISTER_URL_SCHEME.replace("{name}", name),
                      must_contain=('.protocol = u"tg"_q', '.protocol = u"tonsite"_q', 'u"Telegram Link"_q'))
    tree.replace(TEXT_ENTITY, '\taddOne(QString::fromLatin1("tg")); // local urls\n',
                 '\taddOne(QString::fromLatin1("plm")); // local urls (pluma)\n')
    tree.replace(QTHELP_URL, '\t\t|| equals(qstr("tg"))\n', '\t\t|| equals(qstr("plm")) // pluma\n')

    # The icons.
    for rel, sha256 in ASSETS:
        if hashlib.sha256(tree.read_bytes(rel)).hexdigest() != sha256:
            raise PatchError(f"{rel}: not the pinned upstream's file; upstream changed it (brand/render.sh)")
        tree.write_bytes(rel, (BRAND / "tree" / rel).read_bytes())

    # The colours: the light palette compiled in, the night theme, the theme
    # tiles and the accent picker, the QR codes.
    tree.write(PALETTE, recolor(tree.read(PALETTE), load_table(BRAND / "palette-day.txt"), PALETTE))
    data = tree.read_bytes(NIGHT_THEME)
    if hashlib.sha256(data).hexdigest() != NIGHT_THEME_SHA256:
        raise PatchError(f"{NIGHT_THEME}: not the pinned upstream's theme; upstream changed it")
    colors = recolor(night_colors(data), load_table(BRAND / "palette-night.txt"), f"{NIGHT_THEME}: {NIGHT_COLORS}")
    tree.write_bytes(NIGHT_THEME, night_theme(colors))
    for old, new in (EMBEDDED_CLASSIC, EMBEDDED_NIGHT, NIGHT_CONTRAST):
        tree.replace(EMBEDDED_THEMES, old, new)
    for rel, old, new in QR_COLORS:
        tree.replace(rel, old, new)

    # The service notifications account is drawn as any other: by its photo,
    # which the server gives it (pluma-admin service-photo), and by its
    # letter until the photo loads. Upstream draws the app logo meanwhile,
    # and the list of chats keeps that logo cached over the photo once it
    # loads (its cache is redrawn only after a letter).
    tree.replace(DATA_PEER, "\t} else if (isNotificationsUser()) {\n"
                            "\t\tstatic auto result = Window::LogoNoMargin().scaledToWidth(\n"
                            "\t\t\tkUserpicSize,\n\t\t\tQt::SmoothTransformation);\n\t\treturn &result;\n\t}\n",
                 "\t}\n\t// pluma: no logo in place of the service account's photo, which\n"
                 "\t// the server gives it; the list kept the logo over the photo.\n")

    # Ways into Telegram's own services, which Pluma users do not have: the
    # FAQ, Telegram Features and Ask a Question in Settings (the support
    # account is Telegram's: help.getSupport), the FAQ in the login screen's
    # settings and in the about box, the link of the main menu's footer to
    # desktop.telegram.org, and the "Help" of a banned phone number, which
    # wrote to Telegram's login@stel.com.
    tree.replace_body(SETTINGS_MAIN, "void BuildHelpSection(SectionBuilder &builder) {\n", "\n}\n",
                      "\t// pluma: no FAQ, Telegram Features or Ask a Question: they lead to\n"
                      "\t// Telegram's pages and support.\n"
                      "\tQ_UNUSED(builder);",
                      must_contain=("OpenFaq(controller);", "lng_telegram_features_url",
                                    "OpenAskQuestionConfirm(controller);"))
    tree.replace(SETTINGS_INTRO, "\tUi::AddDivider(result);\n\tUi::AddSkip(result);\n\n"
                                 "\tAddButtonWithIcon(\n\t\tresult,\n\t\ttr::lng_settings_faq(),\n"
                                 "\t\tst::settingsButtonNoIcon\n\t)->addClickHandler([] {\n"
                                 "\t\tOpenFaq(nullptr);\n\t});\n",
                 "\t// pluma: no FAQ, which is Telegram's.\n")
    tree.replace_block(ABOUT_BOX, "rpl::producer<TextWithEntities> Text3() {\n", "}\n\n", "",
                       must_contain=("telegramFaqLink()",))
    tree.replace(ABOUT_BOX, "\taddText(Text2());\n\taddText(Text3());\n",
                 "\taddText(Text2());\n\t// pluma: no FAQ, which is Telegram's.\n")
    tree.replace(MAIN_MENU, '\t_telegram->setMarkedText(tr::link(\n\t\tu"Telegram Desktop"_q,\n'
                            '\t\tu"https://desktop.telegram.org"_q));\n',
                 f'\t_telegram->setMarkedText(TextWithEntities{{ u"{name}"_q }}); // pluma: no link to Telegram\'s site\n')
    tree.replace_block(BANNED_BOX, "namespace {\n\nvoid SendToBannedHelp(", "} // namespace\n\n", "",
                       must_contain=('"login@stel.com"',))
    tree.replace_body(BANNED_BOX, "\t\tconst QString &phone) {\n", "\n}\n",
                      "\t// pluma: no \"Help\", which wrote to Telegram's support.\n"
                      "\tQ_UNUSED(phone);\n"
                      "\tcontroller->show(\n"
                      "\t\tUi::MakeInformBox(tr::lng_signin_banned_text()),\n"
                      "\t\tUi::LayerOption::CloseOther);",
                      must_contain=("SendToBannedHelp(phone);",))


def is_blue(value):
    """A colour of Telegram's blues: hue 185-240, not grey."""
    m = re.fullmatch(r"#([0-9a-fA-F]{6})([0-9a-fA-F]{2})?", value)
    if not m:
        return False
    r, g, b = (int(m.group(1)[i:i + 2], 16) for i in (0, 2, 4))
    high, low = max(r, g, b), min(r, g, b)
    if high - low < 0.12 * 255 or b != high:
        return False
    hue = 60 * (4 + (r - g) / (high - low)) % 360
    return 185 <= hue <= 240


def resolve(values, key, seen=()):
    """The colour a palette key has: its literal, or its reference's."""
    value = values[key].split("|")[0].strip()
    if value.startswith("#") or value in seen or value not in values:
        return value
    return resolve(values, value, seen + (key,))


def verify_brand(tree):
    """Checks the brand independently of how the edits were made."""
    # No Telegram in the built-in English but links and LANG_KEEP, nor in the
    # string literals of the code but what CODE_TELEGRAM keeps.
    for m in lang_entries(tree.read(LANG)):
        if "Teamgram" in m["value"] or (m["key"] not in LANG_KEEP and name_telegram(m["value"], "")[1]):
            raise PatchError(f"{LANG}: {m['key']} still names Telegram")
    left = {}
    for rel in tree.sources():
        count = code_telegram(tree.scan(rel))
        if count:
            left[rel[len(SOURCES) + 1:]] = count
    if left != CODE_TELEGRAM:
        diff = sorted(k for k in set(left) | set(CODE_TELEGRAM) if left.get(k) != CODE_TELEGRAM.get(k))
        raise PatchError(f"{SOURCES}: Telegram in the texts of {', '.join(diff[:5])} "
                         "is not what CODE_TELEGRAM keeps")

    # plm:// alone.
    for rel in tree.sources():
        if "tg://" in tree.scan(rel):
            raise PatchError(f"{rel}: still has tg:// links")
    application = tree.read(APPLICATION)
    if (application.count("base::Platform::RegisterUrlScheme(") != 1 or '.protocol = u"plm"_q' not in application
            or "if (!OptionSkipUrlSchemeRegister.value()) {\n\t\tInvokeQueued(this, [] { RegisterUrlScheme(); });"
            not in application):
        raise PatchError(f"{APPLICATION}: does not register plm:// alone at the first start")
    if ("\t\t\t\t<string>plm</string>\n\t\t\t</array>" not in tree.read(PLIST)
            or "MimeType=x-scheme-handler/plm;\n" not in tree.read(DESKTOP_FILE)):
        raise PatchError(f"{PLIST}, {DESKTOP_FILE}: the app does not declare plm:// alone")
    if ('fromLatin1("plm")); // local urls' not in tree.read(TEXT_ENTITY)
            or 'fromLatin1("tg")); // local urls' in tree.read(TEXT_ENTITY)
            or 'qstr("tg")' in tree.read(QTHELP_URL)):
        raise PatchError(f"{TEXT_ENTITY}, {QTHELP_URL}: texts still link tg:// and not plm://")

    # Pluma's icons, and no Telegram blue in the default themes but what
    # KEPT_BLUE keeps.
    for rel, _ in ASSETS:
        if tree.read_bytes(rel) != (BRAND / "tree" / rel).read_bytes():
            raise PatchError(f"{rel}: not Pluma's (brand/tree)")
    day = palette_values(tree.read(PALETTE))
    night = {**day, **palette_values(night_colors(tree.read_bytes(NIGHT_THEME)))}
    for where, values in ((PALETTE, day), (NIGHT_THEME, night)):
        for key in values:
            color = resolve(values, key)
            if (is_blue(color) or color[1:7].lower() in TELEGRAM_BLUES) and not KEPT_BLUE.fullmatch(key):
                raise PatchError(f"{where}: {key} is Telegram's blue {color}")


CODE_STRING = re.compile(r'//[^\n]*|/\*.*?\*/|R"([^(\s]*)\((.*?)\)\1"|"(?:[^"\\\n]|\\.)*"'
                         r"|'(?:[^'\\\n]|\\.)*'", re.S)
CODE_LINK = re.compile(r"(?:https?://)?(?:[\w-]+\.)*(?:telegram\.org|telegram\.me|t\.me|telegram\.dog)\S*", re.I)


def code_telegram(text):
    """How many times the string literals of a source name Telegram as a
    word (links aside)."""
    count = 0
    for m in CODE_STRING.finditer(text):
        s = m.group(0)
        if not s.startswith("/"):
            count += len(re.findall(r"\bTelegram\b", CODE_LINK.sub("", s)))
    return count


def brand_edited():
    """The text files rebrand() edits."""
    return tuple(dict.fromkeys((LANG, PALETTE, TEXT_ENTITY, QTHELP_URL, EMBEDDED_THEMES, SETTINGS_MAIN,
                                SETTINGS_INTRO, ABOUT_BOX, MAIN_MENU, BANNED_BOX, DATA_PEER)
                               + tuple(rel for rel, _, _, _ in CODE_NAMES)
                               + tuple(f"{SOURCES}/{rel}" for rel in SCHEME_FILES)
                               + tuple(rel for rel, _, _ in QR_COLORS)))


def check_upstream(tree, c):
    """The checkout is the one upstream.env describes: the schema layer the
    server speaks (ADR 0008 of the server repository), the version, the
    toolchain the CI installs, and what the build scripts rely on."""
    layers = re.findall(r"^// LAYER (\d+)$", tree.read(API_TL), re.M)
    if layers != [str(c.layer)]:
        raise PatchError(f"{API_TL}: layer {', '.join(layers) or 'none'}, upstream.env says {c.layer}")
    tree.expect(VERSION_H, f'constexpr auto AppVersionStr = "{c.version}";\n')
    # macOS, and Windows with qt6.
    tree.expect(QT_VERSION_PY, f"os.environ['QT'] = '{c.qt}'\n", count=2)
    tree.expect(BUILDING_WIN, f"**{c.windows_sdk}** SDK version")
    tree.expect_some(BUILDING_WIN, f"-vcvars_ver={c.msvc_toolset}")
    tree.expect_some(LINUX_WORKFLOW, f"/ccache/releases/download/v{c.ccache}/ccache-{c.ccache}-linux-x86_64-glibc.tar.xz")
    # ci/build-linux.sh: the image's build script and how its Dockerfile is made.
    tree.expect(DOCKER_ENV + "/build.sh", 'cd Telegram\n./configure.sh "$@"\ncmake --build ../out --config "${CONFIG:-Release}"\n')
    tree.expect(DOCKER_ENV + "/gen_dockerfile.py", 'DEBUG=checkEnv("DEBUG", True),\n')
    tree.expect(DOCKER_ENV + "/gen_dockerfile.py", 'LTO=checkEnv("LTO", True),\n')
    # ci/windows.sh and ci/macos.sh: prepare.py builds the release libraries
    # without questions with "silent", Qt 6 on Windows with "qt6".
    tree.expect(PREPARE, "optionsList = [\n    'qt6',\n")
    tree.expect(PREPARE, "        elif arg == 'silent':\n            rebuildStale = True\n")
    # The options the build passes are still the upstream's.
    tree.expect(CMAKE_VARIABLES, 'option(DESKTOP_APP_DISABLE_AUTOUPDATE "Disable autoupdate."')
    tree.expect(CMAKE_VARIABLES, 'option(DESKTOP_APP_DISABLE_CRASH_REPORTS "Disable crash report generation."')
    # ci/sign-macos.sh signs with upstream's entitlements, which it copies.
    if tree.read(ENTITLEMENTS) != (BRAND.parent / "ci" / "macos.entitlements").read_text():
        raise PatchError(f"{ENTITLEMENTS}: not ci/macos.entitlements; upstream changed what the app may use")
    for rel in EDITED + brand_edited():
        tree.lf_only(rel)


def patch(tree, c):
    check_upstream(tree, c)

    for rel, old, new in BACKPORTS + BUILD_EDITS:
        tree.replace(rel, old, new)

    # Datacenters: the Pluma server is the only built-in one, datacenter 1,
    # for the production and the test backend alike; a fresh install starts
    # on it. Its key replaces Telegram's production and test keys.
    key = cpp_key(c.rsa_pem)
    tree.expect(DC_OPTIONS, "\t\t? gsl::make_span(kTestPublicRSAKeys)\n\t\t: gsl::make_span(kPublicRSAKeys);\n")
    tree.replace_block(DC_OPTIONS, "struct BuiltInDc {\n", '-----END RSA PUBLIC KEY-----" };\n\n} // namespace\n',
                       "// pluma: no built-in datacenter of Telegram's. The Pluma server is the only\n"
                       "// one, on the production and the test backend alike (constructFromBuiltIn).\n"
                       "\n"
                       "// pluma: the key of the Pluma server, for both backends.\n"
                       f'const char *kTestPublicRSAKeys[] = {{ "\\\n{key}" }};\n'
                       "\n"
                       f'const char *kPublicRSAKeys[] = {{ "\\\n{key}" }};\n'
                       "\n"
                       "} // namespace\n",
                       must_contain=DC_ADDRESSES + TELEGRAM_KEY_LINES[:2])
    builtin = ["\tWriteLocker lock(this);",
               "\t_data.clear();",
               "",
               "\treadBuiltInPublicKeys();",
               "",
               "\t// pluma: the Pluma server, datacenter 1, on both backends.",
               f'\tapplyOneGuarded(1, Flag::f_static | 0, "{c.ipv4}", {c.port}, {{}});']
    if c.ipv6:
        builtin.append(f'\tapplyOneGuarded(1, Flag::f_static | Flag::f_ipv6, "{c.ipv6}", {c.port}, {{}});')
    tree.replace_body(DC_OPTIONS, "void DcOptions::constructFromBuiltIn() {\n", "\n}\n", "\n".join(builtin),
                      must_contain=("readBuiltInPublicKeys();", "kBuiltInDcsTest", "kBuiltInDcsIPv6Test"))
    tree.replace(INSTANCE_H, "\t\tstatic constexpr auto kDefaultMainDc = 2;\n",
                 "\t\tstatic constexpr auto kDefaultMainDc = 1; // pluma: the server is datacenter 1.\n")

    # No backup addresses: Telegram publishes them in DNS records, fetched
    # over DNS-over-HTTPS at Google and Mozilla, and in Firebase, and they
    # point at Telegram. Nor the time from those servers' HTTP headers.
    tree.replace_body(CONFIG_LOADER, "void ConfigLoader::createSpecialLoader() {\n", "\n}\n",
                      "\t// pluma: no backup addresses. Telegram publishes them in DNS records,\n"
                      "\t// read over DNS-over-HTTPS at Google and Mozilla, and in Firebase,\n"
                      "\t// and they point at Telegram.\n"
                      "\t_triedSpecialEndpoints.clear();\n"
                      "\t_specialLoader = nullptr;",
                      must_contain=("std::make_unique<SpecialConfigRequest>(",))
    tree.replace_body(INSTANCE, "void Instance::Private::syncHttpUnixtime() {\n", "\n}\n",
                      "\t// pluma: no time from the HTTP headers of Google, Mozilla and Firebase;\n"
                      "\t// the server's messages correct the clock as before.",
                      must_contain=("std::make_unique<SpecialConfigRequest>(",))
    # The special config's key: the requests are off, and none of Telegram's
    # keys stays in the client.
    tree.replace_block(SPECIAL_CONFIG, 'constexpr auto kPublicKey = "\\\n', '-----END RSA PUBLIC KEY-----\\\n"_cs;\n',
                       "// pluma: the key of the Pluma server; no special config is requested.\n"
                       f'constexpr auto kPublicKey = "\\\n{key}\\\n"_cs;\n',
                       must_contain=(TELEGRAM_KEY_LINES[2],))

    # Proxy host names resolve through the system resolver, not over
    # DNS-over-HTTPS at Google and Mozilla.
    tree.replace_body(PROXY_DATA, "bool ProxyData::tryCustomResolve() const {\n", "\n}\n",
                      "\t// pluma: proxy host names resolve through the system resolver, not over\n"
                      "\t// DNS-over-HTTPS at Google and Mozilla (MTP::details::DomainResolver).\n"
                      "\treturn false;",
                      must_contain=("Type::Socks5", "is_ipv6(host)"))
    tree.replace_body(INSTANCE, "void Instance::Private::resolveProxyDomain(const QString &host) {\n", "\n}\n",
                      "\t// pluma: never called; proxy host names resolve through the system\n"
                      "\t// resolver (ProxyData::tryCustomResolve).\n"
                      "\tQ_UNUSED(host);",
                      must_contain=("std::make_unique<DomainResolver>(",))

    # No updates from Telegram and no crash reports to it: compiled out.
    tree.replace(CMAKE_OPTIONS, CMAKE_OPTIONS_OLD, CMAKE_OPTIONS_NEW)

    # plm:// links in place of tg:// and tonsite://, which stay with Telegram
    # Desktop on the same computer: the app registers plm:// at its first
    # start (rebrand(), RegisterUrlScheme), and its macOS bundle and Linux
    # .desktop file declare plm:// alone.
    tree.replace(PLIST, "\t\t\t\t<string>tg</string>\n\t\t\t\t<string>tonsite</string>\n",
                 "\t\t\t\t<string>plm</string>\n")

    # Identity: the name, and with it the data folder (%APPDATA%\Pluma, a
    # portable folder next to Pluma.exe, ~/Library/Application Support/Pluma,
    # ~/.local/share/Pluma), and Pluma's own GUIDs.
    name = c.app_name
    tree.sub(VERSION_H, r'constexpr auto AppId = "\{[0-9A-F-]{36}\}"_cs;',
             f'constexpr auto AppId = "{{{c.app_guid}}}"_cs; // pluma: Pluma\'s own')
    tree.replace(VERSION_H, 'constexpr auto AppNameOld = "Telegram Win (Unofficial)"_cs;\n',
                 f'constexpr auto AppNameOld = "{name}"_cs; // pluma: no older folder to move data from\n')
    tree.replace(VERSION_H, 'constexpr auto AppName = "Telegram Desktop"_cs;\n', f'constexpr auto AppName = "{name}"_cs;\n')
    tree.replace(VERSION_H, 'constexpr auto AppFile = "Telegram"_cs;\n', f'constexpr auto AppFile = "{name}"_cs;\n')
    tree.replace(CONFIG_H, '\tstatic const char *gGuidStr = "{87A94AB0-E370-4cde-98D3-ACC110C5967D}";\n',
                 f'\tstatic const char *gGuidStr = "{{{c.instance_guid}}}"; // pluma: Pluma\'s own\n')
    tree.replace(LAUNCHER, '\tQApplication::setApplicationName(u"TelegramDesktop"_q);\n',
                 f'\tQApplication::setApplicationName(u"{name}"_q); // pluma: the Linux data folder\n')

    # Linux: the application ID (Wayland app_id, the D-Bus name, the
    # .desktop file), and no look into ~/.TelegramDesktop for old data.
    tree.replace(LINUX, '\t\treturn u"org.telegram.desktop"_q;\n', f'\t\treturn u"{c.app_id}"_q;\n')
    tree.replace(LINUX, '\t\t\treturn u"org.telegram.desktop._%1"_q.arg(\n', f'\t\t\treturn u"{c.app_id}._%1"_q.arg(\n')
    tree.replace_body(LINUX, "QString psAppDataPath() {\n", "\n}\n",
                      "\t// pluma: no look into ~/.TelegramDesktop, where an old Telegram Desktop\n"
                      "\t// kept its data.\n"
                      "\treturn QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + '/';",
                      must_contain=('u"/.TelegramDesktop/"_q', "AppLocalDataLocation"))
    desktop = (("Name=Telegram\n", f"Name={name}\n"),
               ("TryExec=Telegram\n", f"TryExec={name}\n"),
               ("Exec=Telegram -- %U\n", f"Exec={name} -- %U\n"),
               ("Icon=org.telegram.desktop\n", f"Icon={c.app_id}\n"),
               ("StartupWMClass=TelegramDesktop\n", f"StartupWMClass={name}\n"),
               # plm:// links; tg:// and tonsite:// stay with Telegram Desktop.
               ("MimeType=x-scheme-handler/tg;x-scheme-handler/tonsite;\n", "MimeType=x-scheme-handler/plm;\n"),
               ("Keywords=tg;chat;im;messaging;messenger;sms;tdesktop;\n", "Keywords=chat;im;messaging;messenger;\n"),
               # No D-Bus service file comes with the app.
               ("DBusActivatable=true\n", ""),
               ("Exec=Telegram -quit\n", f"Exec={name} -quit\n"),
               ("Name=Quit Telegram\n", f"Name=Quit {name}\n"))
    for old, new in desktop:
        tree.replace(DESKTOP_FILE, old, new)

    # Windows: the AppUserModelID, the class notifications activate, the
    # shortcuts (Start menu, autostart, Send To, desktop), the file version.
    tree.replace(WIN_APP_ID, 'const WCHAR AppUserModelIdBase[] = L"Telegram.TelegramDesktop";\n',
                 f'const WCHAR AppUserModelIdBase[] = L"{c.aumid}"; // pluma\n')
    tree.replace(WIN_APP_ID, 'u"Telegram.lnk"_q', f'u"{name}.lnk"_q', count=2)
    tree.replace(WIN_APP_ID, '\tconst auto installed = u"Telegram Desktop/Telegram.lnk"_q;\n',
                 f'\tconst auto installed = u"{name}/{name}.lnk"_q;\n')
    tree.replace(WIN_APP_ID, '\tconst auto old = u"Telegram Win (Unofficial)/Telegram.lnk"_q;\n',
                 f'\tconst auto old = u"{name}/{name}.lnk"_q;\n')
    tree.replace(WIN_TOAST, '// {F11932D3-6110-4BBC-9B02-B2EC07A1BD19}\nclass DECLSPEC_UUID("F11932D3-6110-4BBC-9B02-B2EC07A1BD19")',
                 f'// {{{c.toast_clsid}}} (pluma: Pluma\'s own)\nclass DECLSPEC_UUID("{c.toast_clsid}")')
    tree.replace(WIN_SPECIFIC, '"\\\\Telegram.lnk";\n', f'"\\\\{name}.lnk";\n', count=2)
    for field in ("FileDescription", "ProductName"):
        tree.replace(WIN_RC, f'VALUE "{field}", "Telegram Desktop"\n', f'VALUE "{field}", "{name}"\n')
    tree.replace(WIN_RC, 'VALUE "CompanyName", "Telegram FZ-LLC"\n', f'VALUE "CompanyName", "{name}"\n')

    # macOS: the bundle ID and the name.
    tree.replace(CMAKE_APP, '        set(bundle_identifier "com.tdesktop.Telegram$<$<CONFIG:Debug>:Debug>")\n',
                 f'        set(bundle_identifier "{c.app_id}$<$<CONFIG:Debug>:.debug>")\n')
    tree.replace(CMAKE_APP, '        set(bundle_identifier "com.tdesktop.Telegram")\n', f'        set(bundle_identifier "{c.app_id}")\n')
    tree.replace(PLIST, "\t<key>CFBundleName</key>\n\t<string>@output_name@</string>\n",
                 f"\t<key>CFBundleName</key>\n\t<string>{name}</string>\n")
    tree.replace(PLIST, "\t<key>CFBundleGetInfoString</key>\n\t<string>Telegram Desktop messaging app</string>\n",
                 f"\t<key>CFBundleGetInfoString</key>\n\t<string>{name}</string>\n")

    # The banner of contacts' birthdays: without Premium, a click opens the
    # chat, no gift is offered (BIRTHDAY_BANNER).
    for old, new in BIRTHDAY_BANNER:
        tree.replace(BIRTHDAY_CONTACTS, old, new)
    for rel, old, new in BIRTHDAY_GIFTS:
        tree.replace(rel, old, new)

    rebrand(tree, c)

    address = c.ipv4 + (f", {c.ipv6}" if c.ipv6 else "")
    tree.write(MARKER, f"Patched by pluma-desktop ci/patch.py: {c.app_id} \"{name}\", layer {c.layer}, "
                       f"server {address} port {c.port}, server key {c.fingerprint:#018x}.\n")


IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
PEM_BLOCK = re.compile(r"-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.S)


def telegram_addresses(text):
    if not any(p in text for p in TELEGRAM_PREFIXES):
        return []
    found = []
    for pattern, kind in ((IPV4, ipaddress.IPv4Address), (IPV6, ipaddress.IPv6Address)):
        for m in pattern.finditer(text):
            try:
                a = kind(m.group(0))
            except ValueError:
                continue
            if any(a in net for net in TELEGRAM_NETWORKS):
                found.append(str(a))
    return found


def embedded_keys(text):
    """The RSA keys in a source file, as (n, e, first line): every PEM block
    whose body is base64 once the string literal syntax (quotes, \\n, line
    continuations, line breaks) is gone."""
    keys = []
    for m in PEM_BLOCK.finditer(text):
        body = re.sub(r'\\n|\\|["\s]', "", m.group(1))
        if len(body) < 100 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", body):
            continue  # code around the markers, not a key (mtproto_rsa_public_key.cpp)
        try:
            n, e = parse_pkcs1_der(base64.b64decode(body, validate=True))
        except (ValueError, IndexError, PatchError):
            raise PatchError(f"an RSA key that does not parse: {body[:40]}...")
        keys.append((n, e, body[:64]))
    return keys


CONSTRUCTION = re.compile(r"\b(?:make_unique|make_shared)\s*<\s*(?:[\w:]+::)?(SpecialConfigRequest|DomainResolver)\s*>"
                          r"|\bnew\s+(?:[\w:]+::)?(SpecialConfigRequest|DomainResolver)\b"
                          r"|\b(SpecialConfigRequest|DomainResolver)\s*[({]"
                          r"|\b(SpecialConfigRequest|DomainResolver)\s+\w+\s*[({]")


def verify(tree, c):
    """Checks the result independently of how the edits were made."""
    server_keys = 0
    for rel in tree.sources():
        text = tree.scan(rel)
        addresses = telegram_addresses(text)
        if addresses:
            raise PatchError(f"{rel}: Telegram's address {addresses[0]} is still there")
        for line in TELEGRAM_KEY_LINES:
            if line in text:
                raise PatchError(f"{rel}: Telegram's key {line[:24]}... is still there")
        if "RSA PUBLIC KEY" in text:
            try:
                found = embedded_keys(text)
            except PatchError as e:
                raise PatchError(f"{rel}: {e}")
            for n, e, first in found:
                if (n, e) == (c.n, c.e):
                    server_keys += 1
                elif first not in UPDATE_KEY_LINES or rel not in (CONFIG_H, SOURCES + "/_other/packer.cpp"):
                    raise PatchError(f"{rel}: an RSA key other than the server's ({key_fingerprint(n, e):#018x})")
        if "SpecialConfigRequest" in text or "DomainResolver" in text:
            if not any(rel.startswith(own) for own in FALLBACK_CLASSES.values()):
                m = CONSTRUCTION.search(text)
                if m:
                    raise PatchError(f"{rel}: constructs {next(filter(None, m.groups()))}, "
                                     "which asks Google, Mozilla or Firebase for Telegram's addresses")
    if server_keys != 3:
        raise PatchError(f"the sources hold {server_keys} copies of the server key, expected 3 "
                         "(production, test, special config)")

    dc = tree.read(DC_OPTIONS)
    if ("kBuiltInDcs" in dc or dc.count("applyOneGuarded(1, Flag::f_static") != 1 + (1 if c.ipv6 else 0)
            or f'"{c.ipv4}", {c.port}, {{}});' not in dc
            or (c.ipv6 and f'"{c.ipv6}", {c.port}, {{}});' not in dc)):
        raise PatchError(f"{DC_OPTIONS}: the built-in datacenters are not the server alone")
    if "static constexpr auto kDefaultMainDc = 1;" not in tree.read(INSTANCE_H):
        raise PatchError(f"{INSTANCE_H}: a fresh install does not start on datacenter 1")
    if not re.search(r"bool ProxyData::tryCustomResolve\(\) const \{\n(?:\t//[^\n]*\n)*\treturn false;\n\}\n",
                     tree.read(PROXY_DATA)):
        raise PatchError(f"{PROXY_DATA}: proxy host names still resolve over DNS-over-HTTPS")
    options = tree.read(CMAKE_OPTIONS)
    if CMAKE_DEFINITIONS not in options or "if (DESKTOP_APP_DISABLE_AUTOUPDATE)" in options:
        raise PatchError(f"{CMAKE_OPTIONS}: the updater or the crash reports are not compiled out")

    for rel, traces in ((VERSION_H, ('"Telegram Desktop"', '"Telegram"_cs', "Unofficial")),
                        (CONFIG_H, ("87A94AB0-E370-4cde-98D3-ACC110C5967D",)),
                        (LAUNCHER, ('u"TelegramDesktop"_q',)),
                        (LINUX, ('return u"org.telegram.desktop', "/.TelegramDesktop/")),
                        (DESKTOP_FILE, ("Telegram", "x-scheme-handler/tg", "tonsite")),
                        (WIN_APP_ID, ('L"Telegram.TelegramDesktop";', "Telegram.lnk")),
                        (WIN_TOAST, ("F11932D3-6110-4BBC-9B02-B2EC07A1BD19",)),
                        (WIN_SPECIFIC, ("Telegram.lnk",)),
                        (WIN_RC, ("Telegram FZ-LLC", "Telegram Desktop")),
                        (CMAKE_APP, ("com.tdesktop.Telegram",)),
                        (PLIST, ("<string>tg</string>", "<string>tonsite</string>", "Telegram Desktop"))):
        text = tree.read(rel)
        for s in traces:
            if s in text:
                raise PatchError(f"{rel}: Telegram Desktop's {s!r} is still there")
    prepare = tree.read(PREPARE)
    if "mingw-w64-x86_64-" in prepare or "msys64\\\\mingw64" in prepare:
        raise PatchError(f"{PREPARE}: still asks MSYS2 for the msvcrt-based packages it removed")
    if "dump_syms.vcxproj" in prepare:
        raise PatchError(f"{PREPARE}: still builds breakpad's dump_syms on Windows")
    # The macOS configure of Qt, up to the blank line after it.
    start = prepare.find('    rm -rf "$USED_PREFIX/Qt-$QT"\n    ./configure -prefix "$USED_PREFIX/Qt-$QT"')
    mac_qt = prepare[start:prepare.find("\n\n", start)] if start >= 0 else ""
    if (not mac_qt or "-force-debug-info" in mac_qt
            or "    CONFIGURATIONS=-debug-and-release\n" in prepare
            or "Debug.arm64/libtg_owt.a" in prepare):
        raise PatchError(f"{PREPARE}: still builds the debug variants of Qt or tg_owt on macOS")
    if f'constexpr auto AppName = "{c.app_name}"_cs;' not in tree.read(VERSION_H):
        raise PatchError(f"{VERSION_H}: the app is not {c.app_name}")
    if f'return u"{c.app_id}"_q;' not in tree.read(LINUX):
        raise PatchError(f"{LINUX}: the application ID is not {c.app_id}")
    verify_brand(tree)


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if args == ["--paths"]:
        print("\n".join(UPSTREAM_PATHS))
        return 0
    if args == ["--submodule-paths"]:
        print("\n".join(f"{sub} {path}" for sub, path in SUBMODULE_PATHS))
        return 0
    if len(args) == 2 and args[0] == "--strings":
        try:
            counts = lang_counts(pathlib.Path(args[1]).read_bytes().decode("utf-8"))
        except PatchError as e:
            print(f"patch: {e}", file=sys.stderr)
            return 1
        print("\n".join(f"{key} {count}" for key, count in counts.items()))
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 epilog="patch.py --paths and --submodule-paths print the upstream paths the patch reads; "
                                        "patch.py --strings <lang.strings> the table of brand/strings.txt.")
    ap.add_argument("--source", required=True, help="the tdesktop checkout")
    ap.add_argument("--upstream", required=True, help="upstream.env")
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--server-ipv4", required=True)
    ap.add_argument("--server-port", required=True)
    ap.add_argument("--server-ipv6", default="")
    ap.add_argument("--rsa-public-key", required=True, help="PKCS#1 PEM of the server key")
    a = ap.parse_args(args)
    try:
        c = Config(load_env(a.upstream), load_env(a.app), a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text())
        tree = Tree(a.source)
        if (tree.root / MARKER).exists():
            raise PatchError(f"{a.source} is patched already; fetch it again (ci/fetch-upstream.sh)")
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    address = c.ipv4 + (f", {c.ipv6}" if c.ipv6 else "")
    print(f"patch: {c.app_id} \"{c.app_name}\", api_id {c.api_id}, layer {c.layer}, "
          f"server {address} port {c.port}, server key {c.fingerprint:#018x} ({c.fingerprint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
