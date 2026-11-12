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
of tg:// and pluma.chat links beside t.me's, the icons rendered in brand/,
the palette "graphite and sage" of the default light and dark themes
(brand/palette-*.txt), and people's blue and cyan identity colours in every
theme (IDENTITY_COLORS).

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
import json
import pathlib
import re
import struct
import sys
import uuid
import zipfile
import zlib

# ed25519.py lies next to this script; the build scripts run it with -I,
# which leaves the script's folder out of the path.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ed25519  # noqa: E402

# Telegram's own server keys (production, test) with the fingerprints the
# server announces for them, and the key Telegram signs its "special config"
# (backup addresses) with. None of them may survive the patch.
TELEGRAM_FINGERPRINTS = (0xD09D1D85DE64FD85, 0xB25898DF208D2603)
TELEGRAM_KEY_LINES = (
    "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g",
    "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR",
    "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF",
)

# Telegram's former 1024-bit update keys, which may stay only in Packer, which
# Pluma does not build.
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
MAC_SPECIFIC_P = SOURCES + "/platform/mac/specific_mac_p.mm"
WIN_RC = "Telegram/Resources/winrc/Telegram.rc"
CMAKE_APP = "Telegram/CMakeLists.txt"
CMAKE_OPTIONS = "Telegram/cmake/telegram_options.cmake"
PLIST = "Telegram/Telegram.plist"
ENTITLEMENTS = "Telegram/Telegram/Telegram.entitlements"
DESKTOP_FILE = "lib/xdg/org.telegram.desktop.desktop"
# Telegram's root key and manifest of its update packages (update system v2),
# which Pluma's take the place of.
UPDATE_RESOURCES = "Telegram/Resources/update"
UPDATE_ROOT = UPDATE_RESOURCES + "/root-public.pem"
UPDATE_MANIFEST = UPDATE_RESOURCES + "/manifest.min.json"
UPDATE_MANIFEST_SIG = UPDATE_RESOURCES + "/manifest.sig"
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
# The tags of Saved Messages: the session, and where they check Premium.
MAIN_SESSION_H = SOURCES + "/main/main_session.h"
MAIN_SESSION = SOURCES + "/main/main_session.cpp"
SECTION_WIDGET = SOURCES + "/window/section_widget.cpp"
STICKERS_LIST_WIDGET = SOURCES + "/chat_helpers/stickers_list_widget.cpp"
FIELD_AUTOCOMPLETE = SOURCES + "/chat_helpers/field_autocomplete.cpp"
STICKER_SET_BOX = SOURCES + "/boxes/sticker_set_box.cpp"
STICKER_SET_BOX_H = SOURCES + "/boxes/sticker_set_box.h"
STICKERS_BOX = SOURCES + "/boxes/stickers_box.cpp"
DATA_STICKERS = SOURCES + "/data/stickers/data_stickers.cpp"
HISTORY_ITEM = SOURCES + "/history/history_item.cpp"
DATA_MEDIA_TYPES = SOURCES + "/data/data_media_types.cpp"
VIEW_ELEMENT = SOURCES + "/history/view/history_view_element.cpp"
REACTIONS_SELECTOR = SOURCES + "/history/view/reactions/history_view_reactions_selector.cpp"
SEARCH_TAGS = SOURCES + "/dialogs/dialogs_search_tags.cpp"
DATA_REACTIONS = SOURCES + "/data/data_message_reactions.cpp"
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
DEEP_LINKS_SETTINGS = SOURCES + "/core/deep_links/deep_links_settings.cpp"
LOCAL_URL_HANDLERS = SOURCES + "/core/local_url_handlers.cpp"
DATA_PEER = SOURCES + "/data/data_peer.cpp"
SETTINGS_INTRO = SOURCES + "/settings/settings_intro.cpp"
# The other themes of Settings > Chat Settings (Day, Night), the bases of
# chat themes, and the stylesheet of the HTML export: people's colours.
DAY_BLUE_THEME = "Telegram/Resources/day-blue.tdesktop-theme"
NIGHT_GREEN_THEME = "Telegram/Resources/night-green.tdesktop-theme"
DAY_BASE_THEME = "Telegram/Resources/day-custom-base.tdesktop-theme"
NIGHT_BASE_THEME = "Telegram/Resources/night-custom-base.tdesktop-theme"
EXPORT_CSS = "Telegram/Resources/export_html/css/style.css"
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
    ("Telegram/Resources/icons/chat/unsupported_plane.svg", "5042921c0547a54ba11f3d6c9fd46a55938f548982afab9920d9746cc5babcbc"),
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

# The start of the outline of Telegram's paper plane, in any icon of the
# release: a new file that draws it stops the patch, and goes to ASSETS.
ICONS = "Telegram/Resources/icons"
TELEGRAM_PLANE = "M226.328419,494.722069"

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
                  UPDATE_RESOURCES, QT_VERSION_PY, PREPARE, DOCKER_ENV, BUILDING_WIN, LINUX_WORKFLOW,
                  LANG, NIGHT_THEME, DAY_BLUE_THEME, NIGHT_GREEN_THEME, DAY_BASE_THEME, NIGHT_BASE_THEME, EXPORT_CSS,
                  SHELL_PAGE, CUSTOM_SHORTCUTS) + tuple(path for path, _ in ASSETS)
# The same for files of submodules: (submodule, path inside it).
SUBMODULE_PATHS = (("cmake", "variables.cmake"), ("Telegram/lib_ui", "ui/colors.palette"),
                   ("Telegram/lib_ui", "ui/text/text_entity.cpp"), ("Telegram/lib_base", "base/qthelp_url.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/v2/InstanceV2Impl.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/v2/CustomParameters.h"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/VideoCaptureInterfaceImpl.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/VideoCaptureInterfaceImpl.h"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/desktop_capturer/DesktopCaptureSource.h"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/desktop_capturer/DesktopCaptureSourceHelper.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/desktop_capturer/DesktopCaptureSourceHelper.h"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/platform/tdesktop/VideoCapturerInterfaceImpl.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/platform/darwin/DesktopSharingCapturer.mm"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/group/GroupInstanceCustomImpl.cpp"),
                   ("Telegram/ThirdParty/tgcalls", "tgcalls/group/GroupInstanceCustomImpl.h"))

SOURCE_SUFFIXES = (".cpp", ".h", ".mm", ".m", ".c", ".cc", ".hpp")
# What the scans of verify() leave out: upstream's own test harness and unit
# tests, compiled out of a Release build (TDESKTOP_RELEASE_TEST_HARNESS is
# off, test/test_agent.cpp), with sample links and names of their own.
TEST_SOURCES = (SOURCES + "/test/", SOURCES + "/gram/tests/", SOURCES + "/tests/")


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
                rel = p.relative_to(self.root).as_posix()
                if not rel.startswith(TEST_SOURCES):
                    yield rel


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
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem, update_keys, build=0):
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
        # The data folder: the app's name, or a name of its own for a
        # development build (config/dev/server.env), so that a build for the
        # development server never reads the data, the server's address
        # among them, of a build for the real one, or the other way round.
        self.data_name = app.get("PLUMA_DATA_NAME") or self.app_name
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]{1,31}", self.data_name) or "telegram" in self.data_name.lower():
            raise PatchError(f"PLUMA_DATA_NAME {self.data_name!r}: a capital letter first, then letters and digits")
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

        # Updates (task 054): the prefix the updater asks before the first
        # config, the site behind it, Pluma's root key and manifest, the
        # build number.
        self.update_prefix = need(app, "PLUMA_UPDATE_PREFIX")
        m = re.fullmatch(r"(https://[a-z0-9.-]+)(/[A-Za-z0-9/_-]*[A-Za-z0-9_-])", self.update_prefix)
        if not m or "telegram" in self.update_prefix:
            raise PatchError(f"PLUMA_UPDATE_PREFIX {self.update_prefix!r}: an https:// address of Pluma's, without / at the end")
        self.site = m.group(1)
        self.update_root, self.update_manifest, self.update_manifest_sig = update_keys
        check_update_keys(self.update_root, self.update_manifest, self.update_manifest_sig)
        if not isinstance(build, int) or not 0 <= build < 100000:
            raise PatchError(f"build number {build!r}: 0 to 99999")
        self.build = build
        major, minor, patch_ = (int(x) for x in self.version.split("."))
        self.upstream_app_version = major * 1000000 + minor * 1000 + patch_
        # The release as Pluma shows it (ci/publish.sh).
        self.release_version = f"{self.version}.{build:05d}"

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


# --- updates -----------------------------------------------------------------
# Task 054, ADR 0035 of the server repository and task 074 (the update system
# v2 of tdesktop 7.2 and later). The updater of tdesktop is on, with Pluma's own
# packages: the app asks <prefix>/current4 of the Pluma server (the prefix comes
# from help.getConfig, and before the first config from the default here),
# downloads the package of its system and checks it as upstream does:
# VerifyUpdate of core/update_verify.cpp reads the "TDUP" envelope and accepts
# it only under Pluma's root key and the manifest that key signed (Ed25519).
# - Pluma's root public key, manifest and its signature (config/update,
#   ci/update-key.sh) take the place of Telegram's in Telegram/Resources/update:
#   Telegram's keys verify nothing any more.
# - The default prefix (localstorage.cpp 558) is the Pluma server's, not
#   td.telegram.org.
# - No check over MTProto (update_checker.cpp 1768-1772): it reads Telegram's
#   channel tdhbcfeed, which the Pluma server does not have. The empty checker
#   fails at once; LookupCanaryPrivateSession, used only there, stays for it.
# - The packages keep the names of the Pluma server's feed (tx64upd<N>,
#   tmacupd<N>, tlinuxupd<N>): the releases service and every installed app know
#   them, and only FindUpdateFile (update_checker.cpp 351-357) knows upstream's
#   td-update-<os>-<arch>-<N>.
# - The macOS package is one universal app, as before: it is built for mac, and
#   armac takes it too (update_verify.cpp, TargetFromPlatformKey).
# - The Windows package is raw LZMA from liblzma (ci/pack_update.py), which ends
#   with an end marker the SDK's LzmaUncompress leaves unread: the payload is
#   authenticated before this, and the check of the bytes read goes
#   (update_unpack.cpp 155-163).
# - The macOS package and the Updater name the bundle Pluma.app
#   (update_checker.cpp 2129, updater_osx.m 11), the name ci/package.sh
#   gives it; the binary inside keeps upstream's name.
# - The Windows Updater writes the uninstall entry of an installed app under
#   Telegram's GUID with Telegram's names (updater_win.cpp 431-440): next to
#   an installed Telegram Desktop it would rewrite that entry. It gets
#   Pluma's GUID, name and site; Pluma has no installer, so the entry is not
#   there. Its fallback folder (646) is Pluma's data folder.
# - The updater compares Pluma's build number, PlumaBuild of version.h (the
#   run number of CI), where upstream compares AppVersion: the version of a
#   package in /current4 (update_checker.cpp 883), the running version of
#   VerifyUpdate (RunningUpdateVersion, update_channel.h) and the downloaded
#   update (update_checker.cpp 2116). AppVersion stays upstream's: tdesktop
#   keys its local data (streamAppVersion gates of the serializers) and its
#   settings migrations by it, and a Pluma version above a later upstream's
#   would make the next upstream misread them. The release is 7.4.1.NNNNN, the
#   package's version is <N> << 32, its inner version <N>.
UPDATE_CHECKER = SOURCES + "/core/update_checker.cpp"
UPDATE_CHANNEL = SOURCES + "/core/update_channel.h"
UPDATE_VERIFY = SOURCES + "/core/update_verify.cpp"
UPDATE_UNPACK = SOURCES + "/core/update_unpack.cpp"
LOCAL_STORAGE = SOURCES + "/storage/localstorage.cpp"
UPDATER_OSX = SOURCES + "/_other/updater_osx.m"
UPDATER_WIN = SOURCES + "/_other/updater_win.cpp"
TELEGRAM_APP_GUID = "53F49750-6209-4FBF-9CA8-7A333C87D1ED"
# Telegram's files of Telegram/Resources/update, with the SHA-256 of the
# pinned upstream's: the patch replaces them only while they are upstream's.
UPDATE_RESOURCE_FILES = (
    (UPDATE_ROOT, "root-public.pem", "fc60e0100b44343a13220467544abfff3659b93176fd65d9b9c26557898fe600"),
    (UPDATE_MANIFEST, "manifest.min.json", "5153035ed1e4f9a5cb288c241cd52a1c700510a41e39ade614cf815bbf784cf2"),
    (UPDATE_MANIFEST_SIG, "manifest.sig", "e158bf81e5cadd52e098753a41274ede5d661378a4b2519b8d39b0dfcd82bb0f"),
)
# Telegram's root and manifest keys of the pinned upstream, as the manifest
# writes them (base64url): none may sign for Pluma.
TELEGRAM_UPDATE_KEYS = (
    "RgB8IFZWA08OzifsbPQ3SRdGbON2ecPVsMm1Qo7QNR0",
    "C8sDZ7G_3-v5DPKBjqcU6hCNFJjC1z8ggFcCyoVLtC0",
    "STnSOvgTXqkfM-TelsKMG6UVPHIuoB23vf5ckVKu-JU",
    "Nn5D71VdtoaXuCAdLBixdeMbLpy8ApzZMfp8iMtqE9Q",
    "gsX8hFpkokAvvHqFhZ65D2cv0zLfDVpS60961hho6PM",
)
UPDATES_MTP_OLD = """\
		startImplementation(
			&_mtpImplementation,
			std::make_unique<MtpChecker>(
				LookupCanaryPrivateSession(_session),
				_testing));
"""
UPDATES_MTP_NEW = """\
		// pluma: no check over MTProto, which reads Telegram's channel
		// tdhbcfeed: an empty checker fails at once, and the HTTP check's
		// failure and timeout handling stays upstream's.
		startImplementation(&_mtpImplementation, nullptr);
"""
UPDATES_LOOKUP_OLD = "[[nodiscard]] base::weak_ptr<Main::Session> LookupCanaryPrivateSession(\n"
UPDATES_LOOKUP_NEW = "[[maybe_unused]] [[nodiscard]] base::weak_ptr<Main::Session> LookupCanaryPrivateSession(\n"
UPDATE_FILE_OLD = '\t\t\t"^td-update-(win|mac|linux)-(x86|x64|arm)-\\\\d+"\n'
UPDATE_FILE_NEW = ('\t\t\t// pluma: the packages keep the names of the Pluma server\'s feed.\n'
                   '\t\t\t"^(tx64upd|tmacupd|tlinuxupd)\\\\d+$|"\n'
                   '\t\t\t"^td-update-(win|mac|linux)-(x86|x64|arm)-\\\\d+"\n')
UPDATE_TARGET_OLD = '\t} else if (key == "armac") {\n\t\treturn Target{ Os::Mac, Arch::Arm };\n'
UPDATE_TARGET_NEW = ('\t} else if (key == "armac") {\n'
                     '\t\t// pluma: one universal package serves Intel and Apple processors.\n'
                     '\t\treturn Target{ Os::Mac, Arch::X64 };\n')
UPDATE_LZMA_OLD = ("\tif (status != SZ_OK\n"
                   "\t\t|| sourceSize != compressedSize\n"
                   "\t\t|| resultSize != size_t(originalSize)) {\n")
UPDATE_LZMA_NEW = ("\t// pluma: the package was verified before this; the end marker of\n"
                   "\t// ci/pack_update.py's LZMA stays unread.\n"
                   "\tif (status != SZ_OK || resultSize != size_t(originalSize)) {\n")
UPDATE_RUNNING_OLD = "\t\tquint32(AppVersion),\n\t\tCanaryBuildCounter);\n"
UPDATE_RUNNING_NEW = "\t\tquint32(PlumaBuild), // pluma: Pluma's build number\n\t\tCanaryBuildCounter);\n"
# Where the updater compares versions: upstream's text, Pluma's.
UPDATE_VERSION_EDITS = (
    ("\t\t: uint64(AppVersion);\n",
     "\t\t: uint64(PlumaBuild); // pluma: Pluma's build number\n"),
    ("\t\t} else if (versionNum <= AppVersion) {\n",
     "\t\t} else if (versionNum <= PlumaBuild) { // pluma: Pluma's build number\n"),
)


def read_update_keys(folder):
    """The root public key, the manifest and its signature of a folder
    (config/update, config/dev/update), as bytes."""
    keys = []
    for _, name, _ in UPDATE_RESOURCE_FILES:
        try:
            keys.append((pathlib.Path(folder) / name).read_bytes())
        except OSError as e:
            raise PatchError(f"{folder}/{name}: {e.strerror}; ci/update-key.sh makes it")
    return tuple(keys)


def check_update_keys(root, manifest, signature):
    """The key material is Pluma's and of the form the updater takes
    (ParseVerifiedManifest): the root key signs the manifest, the manifest
    is valid and authorizes the stable channel, the only one Pluma has."""
    try:
        root_key = ed25519.parse_public_pem(root.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as e:
        raise PatchError(f"update root key: {e}")
    if base64.urlsafe_b64encode(root_key).rstrip(b"=").decode() in TELEGRAM_UPDATE_KEYS:
        raise PatchError("update root key: this is Telegram's key")
    if not ed25519.verify(root_key, manifest, signature):
        raise PatchError("update manifest: the root signature does not verify")
    try:
        data = json.loads(manifest)
    except ValueError:
        raise PatchError("update manifest: not JSON")
    if (not isinstance(data, dict) or data.get("format") != 1
            or not isinstance(data.get("manifest_version"), int) or data["manifest_version"] < 1
            or not isinstance(data.get("keys"), list) or not isinstance(data.get("channels"), dict)
            or not isinstance(data.get("revoked"), list)):
        raise PatchError("update manifest: not of the format the updater reads")
    keys = {}
    for key in data["keys"]:
        if not isinstance(key, dict) or key.get("alg") != "Ed25519" or not isinstance(key.get("id"), str) or not key["id"]:
            raise PatchError("update manifest: a key that is not Ed25519, or without an id")
        if key.get("x") in TELEGRAM_UPDATE_KEYS:
            raise PatchError("update manifest: Telegram's key is in it")
        keys[key["id"]] = key
    stable = data["channels"].get("stable")
    if (not isinstance(stable, list) or not stable
            or any(not isinstance(g, list) or not g or any(i not in keys or i in data["revoked"] for i in g) for g in stable)
            or set(data["channels"]) != {"stable"}):
        raise PatchError("update manifest: the channel stable, alone, must name keys of the manifest")


def patch_updates(tree, c):
    tree.replace(LOCAL_STORAGE, '\treturn AutoupdatePrefix("https://td.telegram.org");\n',
                 f'\treturn AutoupdatePrefix("{c.update_prefix}"); // pluma: the Pluma server\n')
    # Pluma's root key and manifest in place of Telegram's.
    for (rel, _, sha256), data in zip(UPDATE_RESOURCE_FILES, (c.update_root, c.update_manifest, c.update_manifest_sig)):
        if hashlib.sha256(tree.read_bytes(rel)).hexdigest() != sha256:
            raise PatchError(f"{rel}: not the pinned upstream's file; upstream changed it")
        tree.write_bytes(rel, data)
    tree.replace(UPDATE_CHECKER, UPDATES_MTP_OLD, UPDATES_MTP_NEW)
    tree.replace(UPDATE_CHECKER, UPDATES_LOOKUP_OLD, UPDATES_LOOKUP_NEW)
    tree.replace(UPDATE_CHECKER, UPDATE_FILE_OLD, UPDATE_FILE_NEW)
    tree.replace(UPDATE_VERIFY, UPDATE_TARGET_OLD, UPDATE_TARGET_NEW)
    tree.replace(UPDATE_UNPACK, UPDATE_LZMA_OLD, UPDATE_LZMA_NEW)
    tree.replace(UPDATE_CHECKER, 'u"tupdates/temp/Telegram.app/Contents/Frameworks/Updater"_q',
                 f'u"tupdates/temp/{c.app_name}.app/Contents/Frameworks/Updater"_q')
    tree.replace(UPDATER_OSX, 'NSString *appName = @"Telegram.app";\n',
                 f'NSString *appName = @"{c.app_name}.app"; // pluma: the bundle of ci/package.sh\n')
    tree.replace(UPDATER_WIN, f"Uninstall\\\\{{{TELEGRAM_APP_GUID}}}_is1",
                 f"Uninstall\\\\{{{c.app_guid}}}_is1")
    tree.replace(UPDATER_WIN, 'wsprintf(nameStr, L"Telegram Desktop");', f'wsprintf(nameStr, L"{c.app_name}");')
    tree.replace(UPDATER_WIN, 'wsprintf(publisherStr, L"Telegram FZ-LLC");', f'wsprintf(publisherStr, L"{c.app_name}");')
    tree.replace(UPDATER_WIN, 'wsprintf(icongroupStr, L"Telegram Desktop");', f'wsprintf(icongroupStr, L"{c.app_name}");')
    tree.replace(UPDATER_WIN, 'const WCHAR *appURL = L"https://desktop.telegram.org";',
                 f'const WCHAR *appURL = L"{c.site}";')
    tree.replace(UPDATER_WIN, 'static const WCHAR *_programName = L"Telegram Desktop"; // folder in APPDATA, if current path is unavailable for writing\n',
                 f'static const WCHAR *_programName = L"{c.data_name}"; // pluma: the data folder in APPDATA, if current path is unavailable for writing\n')
    tree.replace(VERSION_H, f"constexpr auto AppVersion = {c.upstream_app_version};\n",
                 f"constexpr auto AppVersion = {c.upstream_app_version};\n"
                 f"constexpr auto PlumaBuild = {c.build}; // pluma: the build number, which the updater compares\n")
    tree.replace(UPDATE_CHANNEL, UPDATE_RUNNING_OLD, UPDATE_RUNNING_NEW)
    for old, new in UPDATE_VERSION_EDITS:
        tree.replace(UPDATE_CHECKER, old, new)


def verify_updates(tree, c):
    if f'AutoupdatePrefix("{c.update_prefix}")' not in tree.read(LOCAL_STORAGE) or "td.telegram.org" in tree.read(LOCAL_STORAGE):
        raise PatchError(f"{LOCAL_STORAGE}: the default update prefix is not the Pluma server")
    files = [tree.read_bytes(rel) for rel, _, _ in UPDATE_RESOURCE_FILES]
    if files != [c.update_root, c.update_manifest, c.update_manifest_sig]:
        raise PatchError(f"{UPDATE_RESOURCES}: the update keys are not Pluma's")
    check_update_keys(*files)
    checker = tree.read(UPDATE_CHECKER)
    if "std::make_unique<MtpChecker>" in checker or "Telegram.app" in checker:
        raise PatchError(f"{UPDATE_CHECKER}: the check over MTProto or the name Telegram.app is still there")
    if UPDATE_FILE_NEW not in checker:
        raise PatchError(f"{UPDATE_CHECKER}: the names of the Pluma server's packages are not taken")
    if UPDATE_TARGET_NEW not in tree.read(UPDATE_VERIFY):
        raise PatchError(f"{UPDATE_VERIFY}: armac does not take the universal package")
    if UPDATE_LZMA_NEW not in tree.read(UPDATE_UNPACK):
        raise PatchError(f"{UPDATE_UNPACK}: the LZMA of ci/pack_update.py is not taken")
    if '@"Telegram.app"' in tree.read(UPDATER_OSX):
        raise PatchError(f"{UPDATER_OSX}: the Updater still looks for Telegram.app")
    win = tree.read(UPDATER_WIN)
    for trace in (TELEGRAM_APP_GUID, '"Telegram Desktop"', "Telegram FZ-LLC", "desktop.telegram.org"):
        if trace in win:
            raise PatchError(f"{UPDATER_WIN}: Telegram's {trace} is still there")
    version = tree.read(VERSION_H)
    if (f"constexpr auto AppVersion = {c.upstream_app_version};\n" not in version
            or f"constexpr auto PlumaBuild = {c.build};" not in version):
        raise PatchError(f"{VERSION_H}: AppVersion is not upstream's or PlumaBuild is not {c.build}")
    channel = tree.read(UPDATE_CHANNEL)
    if channel.count(UPDATE_RUNNING_NEW) != 1 or "quint32(AppVersion)" in channel:
        raise PatchError(f"{UPDATE_CHANNEL}: the running version is not PlumaBuild")
    for _, new in UPDATE_VERSION_EDITS:
        if checker.count(new) != 1:
            raise PatchError(f"{UPDATE_CHECKER}: the updater does not compare PlumaBuild ({new.strip()})")
    if "startImplementation(&_mtpImplementation, nullptr);" not in checker:
        raise PatchError(f"{UPDATE_CHECKER}: the empty MTProto checker is not there")


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
# pluma: no crash reports to Telegram, whatever the options say. The updater
# is on: it takes Pluma's own packages from the Pluma server, signed with
# Pluma's key (task 054). The build passes the crash reports option (ci/);
# without it, or with the updater turned off, it stops here.
if (NOT DESKTOP_APP_DISABLE_CRASH_REPORTS OR DESKTOP_APP_DISABLE_AUTOUPDATE)
    message(FATAL_ERROR "Pluma: configure with -D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON and without DESKTOP_APP_DISABLE_AUTOUPDATE")
endif()
target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_CRASH_REPORTS)
"""
CMAKE_DEFINITIONS = "target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_CRASH_REPORTS)\n"

# The files the patch edits; it refuses CRLF in any of them.
EDITED = (DC_OPTIONS, INSTANCE_H, INSTANCE, CONFIG_LOADER, SPECIAL_CONFIG, PROXY_DATA, APPLICATION, LAUNCHER,
          LINUX, WIN_APP_ID, WIN_TOAST, WIN_SPECIFIC, WIN_RC, VERSION_H, CONFIG_H, CMAKE_APP, CMAKE_OPTIONS,
          PLIST, DESKTOP_FILE, PREPARE, BIRTHDAY_CONTACTS, HISTORY_WIDGET, PROFILE_ACTIONS,
          MAIN_SESSION_H, MAIN_SESSION, SECTION_WIDGET, VIEW_ELEMENT, REACTIONS_SELECTOR,
          SEARCH_TAGS, UPDATE_CHECKER, UPDATE_CHANNEL, UPDATE_VERIFY, UPDATE_UNPACK, LOCAL_STORAGE, UPDATER_OSX, UPDATER_WIN,
          MAC_SPECIFIC_P)


# Backports of upstream fixes to the build scripts, each as (file, the
# pinned upstream's text, the fixed text), byte for byte as upstream wrote
# them. Once upstream.env pins a release that has a fix, its edit no longer
# matches and the patch stops: the backport goes then. None at the pinned
# release: the MSYS2 packages of b244f1b3 are upstream's since 7.4.1.
BACKPORTS = ()


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
              "    ASSERTS=\n"
              "release:\n"
              "    CONFIGURATIONS=-debug-and-release\n"
              "mac_asserts:\n"
              "    ASSERTS=-force-asserts\n"
              "mac:\n"
              "    ./configure -prefix \"$USED_PREFIX/Qt-$QT\" \\\n"
              "        $CONFIGURATIONS \\\n"
              "        $ASSERTS \\\n"
              "        -force-debug-info \\\n",
     "    CONFIGURATIONS=-debug\n"
     "    ASSERTS=\n"
     "release:\n"
     "    CONFIGURATIONS=-release\n"
     "mac_asserts:\n"
     "    ASSERTS=-force-asserts\n"
     "mac:\n"
     "    rm -rf \"$USED_PREFIX/Qt-$QT\"\n"
     "    ./configure -prefix \"$USED_PREFIX/Qt-$QT\" \\\n"
     "        $CONFIGURATIONS \\\n"
     "        $ASSERTS \\\n"),
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
    # The links into the gift box and its recipient chooser.
    (DEEP_LINKS_SETTINGS,
     "\t\t\tUi::ChooseStarGiftRecipient(ctx.controller);\n",
     "\t\t\t// pluma: no gift while Premium cannot be bought.\n"
     "\t\t\tif (!ctx.controller->session().premiumCanBuy()) {\n"
     "\t\t\t\treturn Result::Unsupported;\n"
     "\t\t\t}\n"
     "\t\t\tUi::ChooseStarGiftRecipient(ctx.controller);\n"),
    (DEEP_LINKS_SETTINGS,
     "\t\t\tUi::ShowStarGiftBox(ctx.controller, ctx.controller->session().user());\n",
     "\t\t\t// pluma: no gift while Premium cannot be bought.\n"
     "\t\t\tif (!ctx.controller->session().premiumCanBuy()) {\n"
     "\t\t\t\treturn Result::Unsupported;\n"
     "\t\t\t}\n"
     "\t\t\tUi::ShowStarGiftBox(ctx.controller, ctx.controller->session().user());\n"),
    (LOCAL_URL_HANDLERS,
     "\tif (!controller) {\n\t\treturn false;\n\t}\n\tUi::ChooseStarGiftRecipient(controller);\n",
     "\t// pluma: no gift while Premium cannot be bought.\n"
     "\tif (!controller || !controller->session().premiumCanBuy()) {\n\t\treturn false;\n\t}\n"
     "\tUi::ChooseStarGiftRecipient(controller);\n"),
)

# The links to what BuildHelpSection no longer shows (plm://settings/faq,
# /ask-question, /features): without a route they get upstream's answer to
# a link it does not know.
HELP_ROUTES = (
    ("Result ShowFaq(const Context &ctx) {\n"
     "\t::Settings::OpenFaq(\n"
     "\t\tctx.controller ? base::make_weak(ctx.controller) : nullptr);\n"
     "\treturn Result::Handled;\n"
     "}\n\n",
     ""),
    ('\trouter.add(u"settings"_q, {\n'
     '\t\t.path = u"faq"_q,\n'
     '\t\t.action = CodeBlock{ ShowFaq },\n'
     '\t\t.requiresAuth = false,\n'
     '\t});\n'
     '\n'
     '\trouter.add(u"settings"_q, {\n'
     '\t\t.path = u"ask-question"_q,\n'
     '\t\t.action = CodeBlock{ [](const Context &ctx) {\n'
     '\t\t\tif (!ctx.controller) {\n'
     '\t\t\t\treturn Result::NeedsAuth;\n'
     '\t\t\t}\n'
     '\t\t\t::Settings::OpenAskQuestionConfirm(ctx.controller);\n'
     '\t\t\treturn Result::Handled;\n'
     '\t\t}},\n'
     '\t});\n'
     '\n'
     '\trouter.add(u"settings"_q, {\n'
     '\t\t.path = u"features"_q,\n'
     '\t\t.action = CodeBlock{ [](const Context &ctx) {\n'
     '\t\t\t::Settings::OpenFeatures(\n'
     '\t\t\t\tctx.controller ? base::make_weak(ctx.controller) : nullptr);\n'
     '\t\t\treturn Result::Handled;\n'
     '\t\t}},\n'
     '\t\t.requiresAuth = false,\n'
     '\t});\n'
     '\n',
     "\t// pluma: no FAQ, Ask a Question or Features: they lead to Telegram's\n"
     "\t// pages and support.\n\n"),
)

# Who may open Telegram's help (its definitions and the declarations, and
# OpenFaq inside OpenAskQuestionConfirm, which nothing calls), and the links
# into the gift box.
HELP_OPENERS = re.compile(r"\b(?:OpenFaq|OpenFeatures|OpenAskQuestionConfirm)\(")
HELP_OPENERS_KEPT = {"settings/sections/settings_main.cpp": 4, "settings/sections/settings_main.h": 3}
GIFT_OPENERS = re.compile(r"\bUi::(?:ChooseStarGiftRecipient|ShowStarGiftBox)\(")

# The tags of Saved Messages, which Telegram gives to Premium alone, for
# every user: Pluma has no Premium (the server sets premium_purchase_blocked).
# Main::Session::savedTagsAvailable() stands for premium() at the places that
# let a user tag a message, search by a tag, rename it, and at the hint of
# the reactions selector, so they behave as upstream does for Premium; the
# Premium promos there are no longer reached. The rest of Premium stays shut:
# the selector of tags offers no custom emoji (LookupPossibleReactions keeps
# premiumPossible()), and how many tags a message takes is the server's
# reactions_user_max_default (SentReactionsLimit), as for reactions. As (file,
# the pinned upstream's text, Pluma's).
SAVED_TAGS = (
    (MAIN_SESSION_H,
     "\t[[nodiscard]] bool premiumCanBuy() const;\n",
     "\t[[nodiscard]] bool premiumCanBuy() const;\n"
     "\t// pluma: the tags of Saved Messages, which need Premium upstream.\n"
     "\t[[nodiscard]] bool savedTagsAvailable() const;\n"),
    (MAIN_SESSION,
     "bool Session::premiumCanBuy() const {\n"
     "\treturn _premiumPossible.current();\n"
     "}\n",
     "bool Session::premiumCanBuy() const {\n"
     "\treturn _premiumPossible.current();\n"
     "}\n"
     "\n"
     "bool Session::savedTagsAvailable() const {\n"
     "\t// pluma: for every user, Premium or not; the server has no Premium.\n"
     "\treturn true;\n"
     "}\n"),
    # Adding and removing a tag: the selector, the quick reaction, a click.
    (SECTION_WIDGET,
     "\tif (item->reactionsAreTags()) {\n"
     "\t\tif (controller->session().premium()) {\n",
     "\tif (item->reactionsAreTags()) {\n"
     "\t\t// pluma: the tags without Premium.\n"
     "\t\tif (controller->session().savedTagsAvailable()) {\n"),
    # A click on a tag of a message searches by it.
    (VIEW_ELEMENT,
     "\t\t\t\tif (item->reactionsAreTags()) {\n"
     "\t\t\t\t\tif (item->history()->session().premium()) {\n",
     "\t\t\t\tif (item->reactionsAreTags()) {\n"
     "\t\t\t\t\t// pluma: the search by a tag without Premium.\n"
     "\t\t\t\t\tif (item->history()->session().savedTagsAvailable()) {\n"),
    # The hint above the tags of the selector, in place of the offer of
    # Premium.
    (REACTIONS_SELECTOR,
     "\t\t: item->history()->session().premium()\n"
     "\t\t? TextWithEntities{ tr::lng_add_tag_about(tr::now) }\n",
     "\t\t// pluma: the hint of a user who can tag, without Premium.\n"
     "\t\t: item->history()->session().savedTagsAvailable()\n"
     "\t\t? TextWithEntities{ tr::lng_add_tag_about(tr::now) }\n"),
    # The tags above a search of Saved Messages, in the chat list and in the
    # chat: a filter and the menu of a tag (rename), not the promo chip.
    (SEARCH_TAGS,
     "\trpl::combine(\n"
     "\t\tstd::move(tags),\n"
     "\t\tData::AmPremiumValue(&owner->session())\n"
     "\t) | rpl::on_next([=](\n",
     "\trpl::combine(\n"
     "\t\tstd::move(tags),\n"
     "\t\t// pluma: not Data::AmPremiumValue.\n"
     "\t\trpl::single(owner->session().savedTagsAvailable())\n"
     "\t) | rpl::on_next([=](\n"),
)
# Premium stickers (a document whose video thumbnail has type "f",
# data_session.cpp 4003), which Telegram gives to Premium alone, for every
# user (task 058): Pluma has no Premium to sell, and the owner reported the
# gate as a defect. Main::Session::premiumStickersAvailable() stands in at the
# places that keep them from a user: sending (ShowSendPremiumError,
# section_widget.cpp 597, the one gate every send goes through: history,
# scheduled, chat section, polls, stories), the lists that leave them out
# while Premium cannot be bought (skipPremium, stickers_list_widget.cpp; the
# count of a set in the sets box, stickers_box.cpp 2455; the set's window,
# sticker_set_box.cpp 1112), how search mixes them in
# (data_stickers.cpp 1503) and the lock on them (StickerPremiumMark, which
# draws Premium's star instead; only the sticker uses of it, emoji keep the
# lock). The own copy of a sent or forwarded premium sticker plays its effect
# (history_item.cpp 788, data_media_types.cpp 1092), as for Premium. Custom
# emoji stay behind Premium. As (file, the pinned upstream's text, Pluma's,
# how many times upstream has it).
PREMIUM_STICKERS = (
    (MAIN_SESSION_H,
     "\t[[nodiscard]] bool premiumPossible() const;\n",
     "\t[[nodiscard]] bool premiumPossible() const;\n"
     "\t// pluma: premium stickers, which need Premium upstream.\n"
     "\t[[nodiscard]] bool premiumStickersAvailable() const;\n", 1),
    (MAIN_SESSION,
     "bool Session::premiumPossible() const {\n",
     "bool Session::premiumStickersAvailable() const {\n"
     "\t// pluma: for every user, Premium or not; the server has no Premium.\n"
     "\treturn true;\n"
     "}\n"
     "\n"
     "bool Session::premiumPossible() const {\n", 1),
    (SECTION_WIDGET,
     "\tif (!document->isPremiumSticker()\n"
     "\t\t|| document->session().premium()) {\n",
     "\t// pluma: premium stickers without Premium.\n"
     "\tif (!document->isPremiumSticker()\n"
     "\t\t|| document->session().premium()\n"
     "\t\t|| document->session().premiumStickersAvailable()) {\n", 1),
    (STICKERS_LIST_WIDGET,
     "const auto skipPremium = !session().premiumPossible();\n",
     "const auto skipPremium = !session().premiumPossible()\n"
     "\t\t&& !session().premiumStickersAvailable();\n", 6),
    (STICKERS_LIST_WIDGET,
     "\t&session(),\n"
     "\tst::stickersPremiumLock))\n",
     "\t&session(),\n"
     "\tst::stickersPremiumLock,\n"
     "\tRectPart::Bottom,\n"
     "\tsession().premiumStickersAvailable()))\n", 1),
    (FIELD_AUTOCOMPLETE,
     ", _premiumMark(_session, st::stickersPremiumLock)\n",
     ", _premiumMark(\n"
     "\t_session,\n"
     "\tst::stickersPremiumLock,\n"
     "\tRectPart::Bottom,\n"
     "\t_session->premiumStickersAvailable())\n", 1),
    (STICKER_SET_BOX_H,
     "\t\tRectPart part = RectPart::Bottom);\n",
     "\t\tRectPart part = RectPart::Bottom,\n"
     "\t\tbool unlocked = false);\n", 1),
    (STICKER_SET_BOX,
     "\tRectPart part)\n"
     ": _lockIcon(lockIcon)\n",
     "\tRectPart part,\n"
     "\tbool unlocked)\n"
     ": _lockIcon(lockIcon)\n", 1),
    (STICKER_SET_BOX,
     "\t\t_premium = premium;\n",
     "\t\t_premium = premium || unlocked;\n", 1),
    (STICKER_SET_BOX,
     ", _premiumMark(_session, st::stickersPremiumLock)\n",
     ", _premiumMark(\n"
     "\t_session,\n"
     "\tst::stickersPremiumLock,\n"
     "\tRectPart::Bottom,\n"
     "\t_session->premiumStickersAvailable())\n", 1),
    (STICKER_SET_BOX,
     "\tconst auto premiumPossible = _session->premiumPossible();\n",
     "\tconst auto premiumPossible = _session->premiumPossible()\n"
     "\t\t|| _session->premiumStickersAvailable();\n", 1),
    (STICKERS_BOX,
     "bool StickersBox::Inner::skipPremium() const {\n"
     "\treturn !_session->premiumPossible();\n",
     "bool StickersBox::Inner::skipPremium() const {\n"
     "\treturn !_session->premiumPossible()\n"
     "\t\t&& !_session->premiumStickersAvailable();\n", 1),
    (DATA_STICKERS,
     "\tif (session().premium()) {\n"
     "\t\tconst auto normalsPerPremium = appConfig->get<int>(\n",
     "\tif (session().premium() || session().premiumStickersAvailable()) {\n"
     "\t\tconst auto normalsPerPremium = appConfig->get<int>(\n", 1),
    (HISTORY_ITEM,
     "\t\t.skipPremiumEffect = !history->session().premium(),\n",
     "\t\t.skipPremiumEffect = !history->session().premium()\n"
     "\t\t\t&& !history->session().premiumStickersAvailable(),\n", 1),
    (DATA_MEDIA_TYPES,
     "\t\t.skipPremiumEffect = !_document->session().premium(),\n",
     "\t\t.skipPremiumEffect = !_document->session().premium()\n"
     "\t\t\t&& !_document->session().premiumStickersAvailable(),\n", 1),
)

# What SAVED_TAGS leaves to upstream, in DATA_REACTIONS: a user without
# Premium puts as many reactions, and tags, on a message as the server's
# reactions_user_max_default says, and the tags of the selector take no
# custom emoji while Premium cannot be bought.
SAVED_TAGS_KEPT = (
    "\treturn session->premium()\n"
    "\t\t? config->get<int>(\"reactions_user_max_premium\", 3)\n"
    "\t\t: config->get<int>(\"reactions_user_max_default\", 1);\n",
    "\t\tresult.customAllowed = premiumPossible;\n\t\tresult.tags = true;\n",
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
    # The title of a window restored without a name, and of a saved window.
    (SOURCES + "/window/window_restore_shell.cpp", 'title.isEmpty() ? u"Telegram"_q : title',
     'title.isEmpty() ? u"{name}"_q : title', 1),
    (SOURCES + "/window/window_saved_windows.cpp", '(user.isEmpty() ? u"Telegram"_q : user)',
     '(user.isEmpty() ? u"{name}"_q : user)', 1),
    (SOURCES + "/window/notifications_manager_default.cpp", 'TextWithEntities{ u"Telegram Desktop"_q }',
     'TextWithEntities{ u"{name}"_q }', 1),
    (SOURCES + "/settings/sections/settings_notifications.cpp", 'elided(u"Telegram Desktop"_q, rectForName.width())',
     'elided(u"{name}"_q, rectForName.width())', 1),
    (SOURCES + "/platform/mac/window_title_mac.mm", 'p.drawText(titleRect, u"Telegram"_q, style::al_center);',
     'p.drawText(titleRect, u"{name}"_q, style::al_center);', 1),
    (SOURCES + "/platform/mac/window_title_mac.mm", 'u"Telegram"_q,\n\t\t\tstyle::al_left);',
     'u"{name}"_q,\n\t\t\tstyle::al_left);', 1),
    # The bundle's name if Info.plist lost it, and the alert of a copy of the
    # app that macOS moved to a read-only place.
    (SOURCES + "/platform/mac/global_menu_mac.mm", '\t\t: u"Telegram"_q;\n', '\t\t: u"{name}"_q;\n', 1),
    (SOURCES + "/platform/mac/specific_mac.mm", '@"Telegram Desktop can\'t start from here"', '@"{name} can\'t start from here"', 1),
    (SOURCES + "/platform/mac/specific_mac.mm", '@"macOS started this copy of Telegram Desktop "', '@"macOS started this copy of {name} "', 1),
    # What the updater and the relaunch show when they fail.
    (UPDATER_WIN, 'L"Failed to update Telegram :(', 'L"Failed to update {name} :(', 1),
    (SOURCES + "/platform/linux/launcher_linux.cpp", 'u"Could not relaunch Telegram: %1"_q', 'u"Could not relaunch {name}: %1"_q', 1),
    # The page of a WEB proxy, which opens in the browser.
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "Telegram Web Proxy", "{name} Web Proxy", 2),
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "Connecting to Telegram Desktop", "Connecting to {name}", 1),
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "'Telegram Desktop disconnected.", "'{name} disconnected.", 1),
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "'Could not connect to Telegram Desktop.'", "'Could not connect to {name}.'", 1),
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "'Telegram Desktop is not consuming", "'{name} is not consuming", 1),
    (SOURCES + "/mtproto/web_proxy/web_proxy_transport.cpp", "while using Telegram.", "while using {name}.", 1),
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
    (SHELL_PAGE, "document.title = (data && data.windowTitle) || 'Telegram';",
     "document.title = (data && data.windowTitle) || '{name}';", 2),
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
    # The startup task of the Windows Store build, which Pluma does not build.
    "_other/startup_task_win.cpp": 1,
    # The Updater: upstream's names of the binary in a package (Telegram.exe,
    # Telegram, Contents/MacOS/Telegram), which it renames to the installed
    # one, and log lines; the names of Pluma's own are patched (updates).
    "_other/updater_linux.cpp": 4,
    "_other/updater_osx.m": 1,
    "_other/updater_win.cpp": 5,
    # The protected update of an installation in a root-owned folder: the
    # binary's name in the package and an error for the log.
    "platform/linux/update_install_linux.cpp": 6,
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
    # the generator of a rich message export, the company name sent to Stripe,
    # the resource file of the macOS bundle.
    "core/click_handler_types.cpp": 1,
    "iv/iv_rich_page.h": 1,
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
# system. tg://, tonsite:// and ton:// stay with Telegram Desktop on the same
# computer.
SCHEME_FILES = {
    "api/api_single_message_search.cpp": 3,
    "boxes/connection_box.cpp": 3,
    "core/application.cpp": 4,
    "core/click_handler_types.cpp": 2,
    "core/deep_links/deep_links_settings.cpp": 2,
    "core/local_url_handlers.cpp": 35,
    "core/ui_integration.cpp": 1,
    "data/data_cloud_themes.cpp": 1,
    "data/data_story.cpp": 1,
    "history/history_drag_area.cpp": 3,
    "history/view/media/history_view_theme_document.cpp": 1,
    "history/view/media/history_view_userpic_suggestion.cpp": 1,
    "inline_bots/bot_attach_web_view.cpp": 3,
    "intro/intro_qr.cpp": 1,
    "iv/editor/iv_editor_clipboard_import.cpp": 1,
    "iv/iv_rich_message_html_export.cpp": 4,
    "media/stories/media_stories_controller.cpp": 1,
    "menu/menu_ttl_validator.cpp": 1,
    "settings/sections/settings_main.cpp": 1,
    "settings/sections/settings_privacy_security.cpp": 1,
    "settings/settings_experimental.cpp": 1,
    "ui/boxes/about_cocoon_box.cpp": 1,
    "wallet/wallet_content.cpp": 1,
    "window/window_filters_favorite.cpp": 3,
}

# The lists of URL schemes a link may have (tdesktop 7.x), which name tg and so
# would refuse plm:// in a Markdown article and in the HTML export, and take a
# plm:// link in a text for one that needs a confirmation
# (SchemeRequiresConfirmation, core/ui_integration.cpp).
SCHEME_LISTS = (
    (SOURCES + "/core/file_utilities.cpp", '\t\tu"tel"_q,\n\t\tu"tg"_q,\n\t\tu"ton"_q,\n\t\tu"tonsite"_q,\n\t};\n',
     '\t\tu"tel"_q,\n\t\tu"plm"_q, // pluma\n\t\tu"tg"_q,\n\t\tu"ton"_q,\n\t\tu"tonsite"_q,\n\t};\n'),
    (SOURCES + "/iv/markdown/iv_markdown_prepare_links.cpp", '\t\tu"tg"_q,\n\t\tu"ton"_q,\n\t\tu"tel"_q,\n\t};\n',
     '\t\tu"plm"_q, // pluma\n\t\tu"tg"_q,\n\t\tu"ton"_q,\n\t\tu"tel"_q,\n\t};\n'),
    (SOURCES + "/export/output/export_output_html.cpp", '\t\tu"tel"_q,\n\t\tu"tg"_q,\n\t};\n',
     '\t\tu"tel"_q,\n\t\tu"plm"_q, // pluma\n\t\tu"tg"_q,\n\t};\n'),
)

REGISTER_URL_SCHEME = """\
	const auto arguments = Launcher::Instance().customWorkingDir()
		? u"-workdir \\"%1\\""_q.arg(cWorkingDir())
		: QString();

	// pluma: plm:// links. The tg, tonsite and ton schemes stay with Telegram
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

# pluma.chat links (task 026 of the server repository). pluma.chat is an
# internal link host as t.me is: the app opens its links inside, as it opens
# t.me's, and the links it builds for the user to copy, share or read are
# pluma.chat's. Most of them come from the server's me_url_prefix already
# (Main::Session::createInternalLink). The host is matched exactly: the names
# under it (web.pluma.chat) are sites, not usernames as x.t.me are. t.me,
# telegram.me and telegram.dog stay internal, as upstream has them, so the
# links handed out before keep opening inside.
LINK_HOST = "pluma.chat"
# The paths of the site pluma.chat itself: the first segments of its pages
# and its files. A pluma.chat link to one of them, or to the root, is the
# site's page, not a username, and opens in the browser as any site's link
# (no username is one of them: the server refuses them, ReservedUsername of
# its user service, or they are too short). The same list in every client.
SITE_PATHS = ("iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl", "ios",
              "collect", "assets", "_l", ".well-known",
              "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json")
# TryConvertUrlToLocal leaves those links as they are (the converter's
# answer for any site link): the root with or without "/" and a query or a
# fragment, and a site path followed by nothing, "/", a query or a fragment.
SITE_LINK = (r"^(https?://)?pluma\.chat(/(" + "|".join(s.replace(".", r"\.") for s in SITE_PATHS)
             + r")([/?#].*)?|/?([?#].*)?)$")
CLICK_HANDLER_TYPES = SOURCES + "/core/click_handler_types.cpp"
# Where the app recognises t.me as its own: (file, the pinned upstream's
# text, Pluma's).
LINK_HOSTS = (
    # The one converter of https links into plm:// ones (TryConvertUrlToLocal):
    # every link clicked, pasted, dropped or started with goes through it. The
    # capture of the path stays the fifth. Before it, the site's own pages
    # (SITE_LINK) are left as they are: the callers open a link that is not
    # plm://, tonsite:// or internal: in the browser (UiIntegration::
    # handleUrlClick, File::OpenUrl), as they do t.me/iv?url=.
    (LOCAL_URL_HANDLERS,
     "\tauto telegramMeMatch = regex_match("
     r'u"^(https?://)?(www\\.)?(telegram\\.(me|dog)|t\\.me)/(.+)$"_q, url, matchOptions);' "\n",
     "\t// pluma: the pages of the site pluma.chat open in the browser, as any\n"
     "\t// site's: its root and its paths (SITE_PATHS of ci/patch.py).\n"
     "\tif (regex_match(u\"" + SITE_LINK.replace("\\", "\\\\") + "\"_q, url, matchOptions)) {\n"
     "\t\treturn url;\n"
     "\t}\n"
     "\t// pluma: pluma.chat links are internal, as t.me's; its exact host only.\n"
     "\tauto telegramMeMatch = regex_match("
     r'u"^(https?://)?(?:(www\\.)?(telegram\\.(me|dog)|t\\.me)|pluma\\.chat)/(.+)$"_q, url, matchOptions);' "\n"),
    # A hidden link (a text with a link under it) to the app's own host asks
    # before it opens.
    (CLICK_HANDLER_TYPES,
     "\t\t" r'"(^|\\.)(telegram\\.(me|dog)|t\\.me)$",' "\n",
     "\t\t" r'"(^|\\.)(telegram\\.(me|dog)|t\\.me)$|^pluma\\.chat$", // pluma' "\n"),
    # The hosts whose links open without asking: the client's list
    # (DefaultWhitelistedDomains) with pluma.chat in it, and the server's on
    # top of it, not instead of it: the Pluma server names pluma.chat alone,
    # and Telegram's hosts would start to ask and to be cut from bios.
    (CLICK_HANDLER_TYPES,
     '\t\tu"fragment.com"_q,\n\t};\n',
     '\t\tu"fragment.com"_q,\n\t\tu"pluma.chat"_q, // pluma\n\t};\n'),
    (CLICK_HANDLER_TYPES,
     '\treturn config.get<std::vector<QString>>(\n'
     '\t\tu"whitelisted_domains"_q,\n'
     '\t\tDefaultWhitelistedDomains());\n',
     '\t// pluma: the server\'s list adds to the client\'s and does not replace it.\n'
     '\tauto result = DefaultWhitelistedDomains();\n'
     '\tconst auto server = config.get<std::vector<QString>>(\n'
     '\t\tu"whitelisted_domains"_q,\n'
     '\t\tstd::vector<QString>());\n'
     '\tresult.insert(result.end(), server.begin(), server.end());\n'
     '\treturn result;\n'),
    # Of pluma.chat, the exact host opens without asking: the names under it
    # are the site's. HostInAnyWhitelist stays wide: it strips the tokens of
    # a foreign login, which web.pluma.chat would take.
    (CLICK_HANDLER_TYPES,
     '[[nodiscard]] bool HostInAnyWhitelist(const QString &host) {\n',
     '// pluma: the names under pluma.chat are the site\'s and ask before opening.\n'
     '[[nodiscard]] bool HostOpensWithoutAsking(\n'
     '\t\tconst QString &host,\n'
     '\t\tconst std::vector<QString> &domains) {\n'
     '\treturn !host.endsWith(u".pluma.chat"_q, Qt::CaseInsensitive)\n'
     '\t\t&& HostInDomains(host, domains);\n'
     '}\n'
     '\n'
     '[[nodiscard]] bool HostInAnyWhitelist(const QString &host) {\n'),
    (CLICK_HANDLER_TYPES,
     '\t\t|| !HostInDomains(url.host(), WhitelistedDomains(my))\n',
     '\t\t|| !HostOpensWithoutAsking(url.host(), WhitelistedDomains(my)) // pluma\n'),
    (CLICK_HANDLER_TYPES,
     '\treturn !HostInDomains(\n\t\turl.host(),\n\t\tWhitelistedDomains(session->appConfig()));\n',
     '\treturn !HostOpensWithoutAsking( // pluma\n\t\turl.host(),\n\t\tWhitelistedDomains(session->appConfig()));\n'),
    # Proxy links pasted into the proxy settings.
    (SOURCES + "/boxes/connection_box.cpp",
     "\t\t" r'R"((?:https?:\/\/[^\s]+|tg:\/\/[^\s]+|(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)\/[^\s]+))",' "\n",
     "\t\t" r'R"((?:https?:\/\/[^\s]+|tg:\/\/[^\s]+|(?:(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)|pluma\.chat)\/[^\s]+))", // pluma' "\n"),
    # The link of a sticker set pasted as the set of a group.
    (SOURCES + "/boxes/stickers_box.cpp",
     '\t\tu"telegram.dog/"_q,\n\t\tu"addstickers/"_q,\n',
     '\t\tu"telegram.dog/"_q,\n\t\tu"pluma.chat/"_q, // pluma\n\t\tu"addstickers/"_q,\n'),
    # A link to a chat dropped on a folder (a username of a profile dragged).
    (SOURCES + "/boxes/choose_filter_box.cpp",
     '\t\t} else if (text.startsWith(u"https://t.me/"_q)) {\n\t\t\ttext = text.mid(13);\n',
     '\t\t} else if (text.startsWith(u"https://t.me/"_q)) {\n\t\t\ttext = text.mid(13);\n'
     '\t\t} else if (text.startsWith(u"https://pluma.chat/"_q)) { // pluma\n\t\t\ttext = text.mid(19);\n'),
    # The links a fact check may hold.
    (SOURCES + "/chat_helpers/message_field.cpp",
     '\treturn url.startsWith(u"t.me/"_q) || url.startsWith(u"https://t.me/"_q);\n',
     '\treturn url.startsWith(u"t.me/"_q) || url.startsWith(u"https://t.me/"_q)\n'
     '\t\t|| url.startsWith(u"pluma.chat/"_q) // pluma\n'
     '\t\t|| url.startsWith(u"https://pluma.chat/"_q);\n'),
    # The search of Settings finds the username by "pluma.chat" too.
    (SOURCES + "/settings/sections/settings_information.cpp",
     '\t\t\t.keywords = { u"username"_q, u"link"_q, u"t.me"_q },\n',
     '\t\t\t.keywords = { u"username"_q, u"link"_q, u"t.me"_q, u"pluma.chat"_q }, // pluma\n'),
    # Links without a scheme ("pluma.chat/name", as the app shows a username)
    # are links in the texts the app parses itself, as "t.me/name" are.
    (TEXT_ENTITY,
     '\taddOne(QString::fromLatin1("cat"));\n',
     '\taddOne(QString::fromLatin1("cat"));\n\taddOne(QString::fromLatin1("chat")); // pluma: pluma.chat\n'),
    # The name of an invite link in its list, where upstream shows the hash
    # alone for t.me's (the server gives https://pluma.chat/+hash).
    (SOURCES + "/boxes/peers/edit_peer_invite_links.cpp",
     '\t).replace(\n\t\tu"t.me/joinchat/"_q,\n\t\tQString()\n\t);\n',
     '\t).replace(\n\t\tu"t.me/joinchat/"_q,\n\t\tQString()\n\t).replace(\n\t\tu"pluma.chat/+"_q, // pluma\n\t\tQString()\n\t);\n'),
    # The same for the invite links of a shared folder.
    (SOURCES + "/boxes/filters/edit_filter_links.cpp",
     '\t).replace(\n\t\tu"t.me/joinchat/"_q,\n\t\tQString()\n\t);\n',
     '\t).replace(\n\t\tu"t.me/joinchat/"_q,\n\t\tQString()\n\t).replace(\n\t\tu"pluma.chat/+"_q, // pluma\n\t\tQString()\n\t);\n'),
)
# The links the app builds with t.me where the server's me_url_prefix does
# not reach: (file, the text, how many). "t.me" becomes "pluma.chat" in each.
LINK_BUILDERS = (
    # The prefix of links until the server's config arrives, and when the
    # server's is not a link (ValidatedInternalLinksDomain).
    (SOURCES + "/mtproto/mtproto_config.h", 'u"https://t.me/"_q', 1),
    # The link of a language that "Share" copies.
    (SOURCES + "/boxes/language_box.cpp", 'u"https://t.me/setlanguage/"_q', 1),
    # The links of mentions and channels in the HTML of a rich message.
    (SOURCES + "/iv/iv_rich_message_html_export.cpp", 'u"https://t.me/"_q', 2),
    # The links of forum topics in service messages and the admin log: they
    # open inside, and "Copy link" copies them.
    (SOURCES + "/history/history_item.cpp", 'u"https://t.me/c/%1/%2"_q', 1),
    (VIEW_ELEMENT, 'u"https://t.me/c/%1/%2"_q', 1),
    (SOURCES + "/history/admin_log/history_admin_log_item.cpp", 'u"https://t.me/c/%1/%2"_q', 1),
    # The placeholder of the username in Settings, and the link of a new
    # managed bot's username.
    (SOURCES + "/settings/sections/settings_information.cpp", '"t.me/username"', 1),
    (SOURCES + "/boxes/peers/create_managed_bot_box.cpp", 'u"t.me/"_q + full', 1),
)
# What stays of t.me in the string literals of the sources after the edits,
# per file; a new one in an upstream update stops the patch here (look at it:
# a link the app builds, a host it recognises, or Telegram's own).
LINKS_KEPT = {
    # The hosts recognised as the app's own, beside pluma.chat (LINK_HOSTS),
    # and the user.t.me links, which become t.me/user ones inside.
    "core/local_url_handlers.cpp": 4,
    "core/click_handler_types.cpp": 2,
    "boxes/connection_box.cpp": 1,
    "boxes/stickers_box.cpp": 2,
    "boxes/choose_filter_box.cpp": 1,
    "chat_helpers/message_field.cpp": 2,
    "settings/sections/settings_information.cpp": 1,
    # The names of invite links that upstream strips: links handed out
    # before still show their hash. The admin log shows "t.me/+hash" for
    # those as it shows "pluma.chat/+hash" for Pluma's.
    "boxes/peers/edit_peer_invite_links.cpp": 2,
    "boxes/filters/edit_filter_links.cpp": 2,
    "history/admin_log/history_admin_log_item.cpp": 1,
    # A mini app's web_app_open_tg_link: its path made a t.me link that opens
    # inside and is never shown.
    "ui/chat/attach/attach_bot_webview.cpp": 1,
    # The experimental option of a favorite folder button: the links it takes.
    "window/window_filters_favorite.cpp": 1,
    # The result a bot's HTML widget gets: a word, not a link.
    "tgw/tgw_bridge.cpp": 1,
    # Telegram's own: the invoice of Premium, @premiumbot, @BotFather,
    # @stickers, none of which Pluma has.
    "settings/sections/settings_premium.cpp": 1,
    "dialogs/suggestions/suggestion_premium_grace.cpp": 1,
    "dialogs/ui/dialogs_suggestions.cpp": 1,
    "boxes/peers/create_managed_bot_box.cpp": 1,
    "boxes/sticker_set_box.cpp": 1,
}
# The hosts of Telegram and of the TON services in the string literals of the
# sources, per file, t.me aside (LINKS_KEPT): a new one in an upstream update
# stops the patch here. Reached through what the server does not serve (the
# wallet, its gifts and collectibles, ads and bot widgets), or only texts that
# never make a connection (the origin of the bot web view's shell, loaded
# locally).
EXTERNAL_HOSTS = re.compile(r"(?<![\w-])(?:[\w-]+\.)*(?:telegram\.org|telegram\.me|telegram\.dog|telegra\.ph"
                            r"|fragment\.com|toncenter\.com|tonviewer\.com)(?![\w-])")
HOSTS_KEPT = {
    # The credit of the protocol; the FAQ link is gone (rebrand()).
    "boxes/about_box.cpp": 2,
    "boxes/about_sponsored_box.cpp": 1,
    "boxes/peers/edit_peer_reactions.cpp": 1,
    # The links a user can paste as a sticker set's, recognised as t.me's are.
    "boxes/stickers_box.cpp": 4,
    # The wallet (AppConfig::walletAvailable, off) and the gifts behind it.
    "boxes/transfer_gift_box.cpp": 1,
    "core/ton_explorer_url.cpp": 1,
    "gram/api/gram_api_nft.cpp": 2,
    "wallet/wallet_collectibles.cpp": 3,
    "wallet/wallet_session.cpp": 2,
    "wallet/wallet_ton_connect.cpp": 1,
    # The domains the app treats as Telegram's own.
    "core/click_handler_types.cpp": 7,
    "core/crash_report_window.cpp": 1,
    # The fallback link of UpdateApplication, for a build without the updater.
    "core/update_checker.cpp": 1,
    "data/data_passkey_deserialize.cpp": 1,
    "export/output/export_output_html.cpp": 1,
    "history/history_item_helpers.cpp": 1,
    "iv/iv_instance.cpp": 2,
    "menu/menu_sponsored.cpp": 2,
    "ui/chat/attach/attach_bot_webview.cpp": 2,
    "ui/chat/attach/attach_bot_webview_linux_shell.cpp": 1,
}
LINK_TME = re.compile(r"(?<![\w-])t(?:\\*\.)me(?![\w-])")
LINK_PLUMA = re.compile(r"(?<![\w-])pluma(?:\\*\.)chat(?![\w-])")

# The default themes, palette "graphite and sage" (brand/palette-*.txt): the
# night theme is a zip of its colours and a 1x1 background, which the patch
# writes again; the background is the chat's, a shade below the window's.
NIGHT_THEME_SHA256 = "364fcd7288453377e16db9c733fd98699b161248bc62cc62f78d58d909951d3a"
# The file of a zipped theme that holds its colours.
THEME_COLORS = "colors.tdesktop-theme"
NIGHT_COLORS, NIGHT_BACKGROUND = THEME_COLORS, "background.png"
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

# People's identity colours. Telegram gives every user and chat one of seven
# colours by its id (Ui::DecideColorIndex, id % 7: 0 red, 1 orange, 2 violet,
# 3 green, 4 cyan, 5 blue, 6 pink) for its letter avatar, a gradient from the
# first colour at the top to the second (Ui::EmptyUserpic), its name in groups
# and the bars of its replies and link previews
# (Ui::ChatStyle::computeColorIndexValues). Each colour has the palette keys
# of a slot N, historyPeerN* (Ui::ColorIndexToPaletteIndex: blue is slot 4,
# cyan slot 7), which every theme defines and the accent picker leaves as they
# are (kColorizeIgnoredKeys in window_themes_embedded.cpp). Blue becomes the
# palette's sage and cyan a teal without Telegram's blue, in every theme of
# the app; cyan names in the dark themes take the teal Telegram's Android app
# shows at night (Telegram's own here, #62d4e3 and #57c9e0, lean to blue).
# The other five stay
# Telegram's, and so do the colours from 7 up, whose names and bars the server
# colours (help.getPeerColors). What draws the blue or cyan slot as a plain
# colour takes these keys and follows them; so do folder tags, in the second
# colour of their slot (dialogs_inner_widget.cpp, edit_filter_box.cpp). Blue:
# the session icons of Settings > Devices for Windows, macOS and the rest
# (settings_active_sessions.cpp), the placeholder of a photo to choose
# (userpic_button.cpp), the picture of a shared folder link
# (filter_link_header.cpp), the icons of Contacts and Not archived among the
# chats of a folder (edit_filter_chats_list.cpp), the giveaway icon and badge
# in the list of boosts (statistics.style,
# info_statistics_list_controllers.cpp), and, in Day, Night and the bases,
# whose historyPeerSavedMessagesBg2 (and the day base's
# historyPeerSavedMessagesBg) refer to the blue slot, the avatars of Saved
# Messages, Replies, My Notes and the currency of a gift transfer
# (empty_userpic.cpp) and of a search of posts in the history of Stars
# (credits_graphics.cpp). Cyan: the session icons of iPhone and iPad, the App
# Store in the history of Stars (credits_graphics.cpp), the icons of
# Non-contacts and Read among the chats of a folder, and what
# st::colorIndexBlue draws, which is 4, Telegram's cyan, despite its name
# (color_indices.style): the tag "+N" of more folders
# (dialogs_inner_widget.cpp), the rows of the list of boosts
# (info_statistics_list_controllers.cpp), the giveaway to chosen users
# (giveaway_type_row.cpp), the bar of a sponsored message without a colour
# (sponsored_message_bar.cpp).
# As (key, Telegram's value in every theme or None for each theme's own
# (IDENTITY_THEMES), Pluma's in the light themes, in the dark themes or None
# to keep Telegram's).
IDENTITY_COLORS = (
    ("historyPeer4NameFg", None, "#4f6e52", "#9dbb9f"),
    ("historyPeer4UserpicBg", "#5caffa", "#7fa082", "#7fa082"),
    ("historyPeer4UserpicBg2", "#408acf", "#5b7a5e", "#5b7a5e"),
    ("historyPeer7NameFg", None, "#1f8a80", "#53ccc6"),
    ("historyPeer7UserpicBg", "#5bcbe3", "#5bcbc4", "#5bcbc4"),
    ("historyPeer7UserpicBg2", "#359ad4", "#2c9c98", "#2c9c98"),
)
# The themes that define them, as {theme: (dark, Telegram's names of blue and
# cyan there)}: the palette compiled in (Classic, and the colours a theme
# leaves out), the default dark theme (Tinted), Day and Night, and the bases
# of chat themes (Window::Theme::PreparePaletteCallback).
IDENTITY_THEMES = {
    PALETTE: (False, {"historyPeer4NameFg": "windowActiveTextFg", "historyPeer7NameFg": "#2996ad"}),
    NIGHT_THEME: (True, {"historyPeer4NameFg": "#65bdf3", "historyPeer7NameFg": "#62d4e3"}),
    DAY_BLUE_THEME: (False, {"historyPeer4NameFg": "windowActiveTextFg", "historyPeer7NameFg": "#2996ad"}),
    NIGHT_GREEN_THEME: (True, {"historyPeer4NameFg": "#68c7f3", "historyPeer7NameFg": "#57c9e0"}),
    DAY_BASE_THEME: (False, {"historyPeer4NameFg": "windowActiveTextFg", "historyPeer7NameFg": "#2996ad"}),
    NIGHT_BASE_THEME: (True, {"historyPeer4NameFg": "#65bdf3", "historyPeer7NameFg": "#62d4e3"}),
}
# The zipped themes that keep Telegram's colours but these, with the SHA-256
# of the pinned upstream's file: the patch writes their colours again and
# keeps the rest of the zip as it is.
TELEGRAM_THEMES = {
    DAY_BLUE_THEME: "4ae75620a0aac54b79604e17ed4406556f90b4f15143bf1a099b74fac12e3bb3",
    NIGHT_GREEN_THEME: "059752f44c98a2be714799a7d3aa89b17dc3a7587f5619ed502a73b988641d0d",
    DAY_BASE_THEME: "3e32484edd81fbebfa1725847737709d7b4b288561aa466566d8069bc288829b",
    NIGHT_BASE_THEME: "ca675f580b40f8ecfb1d581f29ebd777c03eab4c27821251a369ed16f6f5cb5d",
}
# The HTML export draws a letter avatar in one colour, the class userpic1 to
# userpic8 by slot (export_output_html.cpp), from the export's style.css:
# Telegram's colours there lie near the middle of the app's gradient
# (#4f9cd9 for #5caffa to #408acf). Blue and cyan take the middle of Pluma's
# gradients (#6d8d70, #44b4ae); the media icons that shared their rules keep
# Telegram's colours. As (the pinned upstream's rule, the slot).
EXPORT_USERPICS = (
    (".color_blue,\n.userpic4,\n.media_audio_file .fill,\n.media_voice_message .fill {\n"
     "    background-color: #4f9cd9;\n}\n", 4),
    (".color_sea,\n.userpic7,\n.media_location .fill,\n.media_video .fill {\n"
     "    background-color: #47bcd1;\n}\n", 7),
)

# Telegram's accent blues, in no default colour of Pluma's (verify()).
TELEGRAM_BLUES = ("40a7e3", "419fd9", "39a5db", "2095d0", "37a1de", "54c3f3", "5288c1", "6ab3f3", "2f6ea5",
                  "4082bc", "2b5278", "6ab2f2", "72bcfd", "64b9fa", "5eb5f7")
# Keys of the default themes that may stay blue (verify()): file type
# colours and the Premium and statistics palettes; calls are Pluma's
# (CALL_COLORS).
KEPT_BLUE = re.compile(r"msgFile1\w*|mediaviewFileBlueCornerFg|settingsIconBg[45]"
                       r"|stickerPanPremium[12]|premiumButtonBg1|statisticsChart\w+")
# The verified badge, Telegram's rosette with a check, in the default themes
# (verify()): the rosette in the accent and the check in the colour of text on
# it, as Telegram draws it in the accent of its theme (colors.palette refers
# the keys to windowBgActive and windowFgActive); in the chosen row of the
# chat list the rosette is white with the check in the row's colour. Every
# place that draws it takes these keys: the chat list, the chat's top bar,
# lists of people and search (dialogs.style, peer_list_box.cpp), the profile
# and Settings (info.style, settings.style), the box of a bot's web app
# (attach_bot_webview.cpp). Day, Night and the bases keep Telegram's accent,
# and their badge follows it. As {key: (Classic, Tinted)}.
VERIFIED_BADGE = {
    "dialogsVerifiedIconBg": ("#5b7a5e", "#9dbb9f"),
    "dialogsVerifiedIconFg": ("#ffffff", "#131513"),
    "dialogsVerifiedIconBgOver": ("#5b7a5e", "#9dbb9f"),
    "dialogsVerifiedIconFgOver": ("#ffffff", "#131513"),
    "dialogsVerifiedIconBgActive": ("#ffffff", "#ffffff"),
    "dialogsVerifiedIconFgActive": ("#5b7a5e", "#2c3a2d"),
    "profileVerifiedCheckBg": ("#5b7a5e", "#9dbb9f"),
    "profileVerifiedCheckFg": ("#ffffff", "#131513"),
}
# The icons of the badge in the styles of the sources, with their colour. A
# profile with a colour of its own (a collectible, a profile colour) draws it
# on that colour, white with the check in the profile's colour
# (infoColoredPeerBadge, info_profile_top_bar.cpp), as Telegram does.
VERIFIED_ICON = re.compile(r'"[\w/]*_verified_(?:star|check)"\s*,\s*([^\s,}]+)')
VERIFIED_ON_COVER = ("groupCallMembersFg", SOURCES + "/info/profile/info_profile_top_bar.style")


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


def theme_zip(files):
    """A zipped theme of (name, data), the same for the same files."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)
    return out.getvalue()


def night_theme(colors):
    """The night theme's zip, the same for the same colours."""
    return theme_zip(((NIGHT_COLORS, colors.encode("utf-8")), (NIGHT_BACKGROUND, png_1x1(NIGHT_WALLPAPER))))


def zipped_colors(data, where):
    """The colours of a zipped theme."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.namelist().count(THEME_COLORS) != 1:
                raise PatchError(f"{where}: holds {z.namelist()}")
            return z.read(THEME_COLORS).decode("utf-8")
    except zipfile.BadZipFile:
        raise PatchError(f"{where}: not a zip")


def with_colors(data, colors):
    """A zipped theme with other colours, its other files as they were."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return theme_zip([(name, colors.encode("utf-8") if name == THEME_COLORS else z.read(name))
                          for name in z.namelist()])


def identity(text, theme):
    """The colours of a theme of IDENTITY_THEMES with people's blue and cyan
    of IDENTITY_COLORS. Each key must hold Telegram's value; a fallback after
    "|" stays."""
    dark, names = IDENTITY_THEMES[theme]
    for key, telegram, on_light, on_dark in IDENTITY_COLORS:
        old, new = telegram or names[key], on_dark if dark else on_light
        line = re.compile(rf"^{key}: {re.escape(old)}((?: \| [A-Za-z0-9_]+)?;)", re.M)
        found = len(line.findall(text))
        if found != 1:
            raise PatchError(f"{theme}: {found} occurrences of '{key}: {old};', expected 1; "
                             "upstream changed the colour")
        if new:
            text = line.sub(lambda m: f"{key}: {new}{m.group(1)}", text)
    return text


def middle(a, b):
    """The colour halfway between two #rrggbb."""
    return "#" + "".join(f"{(int(a[i:i + 2], 16) + int(b[i:i + 2], 16) + 1) // 2:02x}" for i in (1, 3, 5))


def export_userpic(slot):
    """The colour of the export's letter avatars of a slot: the middle of
    Pluma's gradient."""
    light = {key: value for key, _, value, _ in IDENTITY_COLORS}
    return middle(light[f"historyPeer{slot}UserpicBg"], light[f"historyPeer{slot}UserpicBg2"])


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
                      must_contain=('.protocol = u"tg"_q', '.protocol = u"tonsite"_q', '.protocol = u"ton"_q',
                                    'u"Telegram Link"_q'))
    tree.replace(TEXT_ENTITY, '\taddOne(QString::fromLatin1("tg")); // local urls\n',
                 '\taddOne(QString::fromLatin1("plm")); // local urls (pluma)\n')
    tree.replace(QTHELP_URL, '\t\t|| equals(qstr("tg"))\n', '\t\t|| equals(qstr("plm")) // pluma\n')
    for rel, old, new in SCHEME_LISTS:
        tree.replace(rel, old, new)

    # The icons.
    for rel, sha256 in ASSETS:
        if hashlib.sha256(tree.read_bytes(rel)).hexdigest() != sha256:
            raise PatchError(f"{rel}: not the pinned upstream's file; upstream changed it (brand/render.sh)")
        tree.write_bytes(rel, (BRAND / "tree" / rel).read_bytes())

    # The colours: the light palette compiled in, the night theme, the theme
    # tiles and the accent picker, the QR codes; people's blue and cyan in
    # every theme and in the export.
    palette = recolor(tree.read(PALETTE), load_table(BRAND / "palette-day.txt"), PALETTE)
    tree.write(PALETTE, identity(palette, PALETTE))
    data = tree.read_bytes(NIGHT_THEME)
    if hashlib.sha256(data).hexdigest() != NIGHT_THEME_SHA256:
        raise PatchError(f"{NIGHT_THEME}: not the pinned upstream's theme; upstream changed it")
    colors = recolor(night_colors(data), load_table(BRAND / "palette-night.txt"), f"{NIGHT_THEME}: {NIGHT_COLORS}")
    tree.write_bytes(NIGHT_THEME, night_theme(identity(colors, NIGHT_THEME)))
    for rel, sha256 in TELEGRAM_THEMES.items():
        data = tree.read_bytes(rel)
        if hashlib.sha256(data).hexdigest() != sha256:
            raise PatchError(f"{rel}: not the pinned upstream's theme; upstream changed it")
        tree.write_bytes(rel, with_colors(data, identity(zipped_colors(data, rel), rel)))
    for old, slot in EXPORT_USERPICS:
        tree.replace(EXPORT_CSS, old, old.replace(f"\n.userpic{slot},", "")
                     + f".userpic{slot} {{\n    background-color: {export_userpic(slot)}; /* pluma */\n}}\n")
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
                      must_contain=("OpenFaq(controller);", "OpenFeatures(controller);",
                                    "OpenAskQuestionConfirm(controller);"))
    for old, new in HELP_ROUTES:
        tree.replace(DEEP_LINKS_SETTINGS, old, new)
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


def verify_help_and_gifts(tree):
    """Telegram's FAQ, Features and support are reached by nothing but the
    code of Settings that nothing opens, and the gift box by no link while
    Premium cannot be bought: each caller in the sources is one of these."""
    found = {}
    for rel in tree.sources():
        count = len(HELP_OPENERS.findall(tree.scan(rel)))
        if count:
            found[rel[len(SOURCES) + 1:]] = count
    if found != HELP_OPENERS_KEPT:
        diff = sorted(k for k in set(found) | set(HELP_OPENERS_KEPT) if found.get(k) != HELP_OPENERS_KEPT.get(k))
        raise PatchError(f"{SOURCES}: Telegram's FAQ or support is opened from {', '.join(diff[:5])}")
    for rel, gifts, guards in ((DEEP_LINKS_SETTINGS, 2, 2), (LOCAL_URL_HANDLERS, 1, 1)):
        text = tree.read(rel)
        if len(GIFT_OPENERS.findall(text)) != gifts or text.count("session().premiumCanBuy()) {\n") != guards:
            raise PatchError(f"{rel}: a link opens the gift box without asking whether Premium can be bought")


def verify_verified_badge(tree, day, night):
    """The verified badge in Pluma's accent in Classic and Tinted
    (VERIFIED_BADGE), and every icon of it in the styles drawn in those keys
    but on a profile's own colour (VERIFIED_ON_COVER)."""
    for i, (where, values) in enumerate(((PALETTE, day), (NIGHT_THEME, night))):
        for key, colors in VERIFIED_BADGE.items():
            color = resolve(values, key) if key in values else "missing"
            if color.lower() != colors[i]:
                raise PatchError(f"{where}: the verified badge's {key} is {color}, not {colors[i]}")
    found = 0
    for p in sorted((tree.root / SOURCES).rglob("*.style")):
        rel = p.relative_to(tree.root).as_posix()
        for color in VERIFIED_ICON.findall(tree.scan(rel)):
            found += 1
            if color not in VERIFIED_BADGE and (color, rel) != VERIFIED_ON_COVER:
                raise PatchError(f"{rel}: the verified badge is drawn in {color}, not in a key of VERIFIED_BADGE")
    if not found:
        raise PatchError(f"{SOURCES}: no icon of the verified badge in the styles; upstream renamed them")


def verify_brand(tree):
    """Checks the brand independently of how the edits were made."""
    # No Telegram in the built-in English but links, LANG_KEEP and the texts
    # of the login code screens, which name the real one (LOGIN_CODE_STRINGS),
    # nor in the string literals of the code but what CODE_TELEGRAM keeps.
    for m in lang_entries(tree.read(LANG)):
        kept = m["key"] in LANG_KEEP or LOGIN_CODE_STRINGS.get(m["key"]) == m["value"]
        if "Teamgram" in m["value"] or (not kept and name_telegram(m["value"], "")[1]):
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

    # plm:// alone, but the link of the login code screens to Telegram's own
    # settings (TELEGRAM_SETTINGS_LINK).
    for rel in tree.sources():
        text = tree.scan(rel)
        if rel == INTRO_CODE:
            if text.count(TELEGRAM_SETTINGS_LINK) != 1:
                raise PatchError(f"{rel}: no link to Telegram's settings of the phone number")
            text = text.replace(TELEGRAM_SETTINGS_LINK, "")
        if "tg://" in text:
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
    for rel, _, new in SCHEME_LISTS:
        if tree.read(rel).count(new) != 1:
            raise PatchError(f"{rel}: the list of URL schemes does not take plm://")

    # Pluma's icons, and no Telegram blue in the default themes but what
    # KEPT_BLUE keeps.
    for rel, _ in ASSETS:
        if tree.read_bytes(rel) != (BRAND / "tree" / rel).read_bytes():
            raise PatchError(f"{rel}: not Pluma's (brand/tree)")
    for p in sorted((tree.root / ICONS).rglob("*.svg")):
        if TELEGRAM_PLANE in p.read_text(encoding="utf-8", errors="replace"):
            raise PatchError(f"{p.relative_to(tree.root).as_posix()}: Telegram's paper plane; add the icon to ASSETS")
    day = palette_values(tree.read(PALETTE))
    night = {**day, **palette_values(night_colors(tree.read_bytes(NIGHT_THEME)))}
    for where, values in ((PALETTE, day), (NIGHT_THEME, night)):
        for key in values:
            color = resolve(values, key)
            if (is_blue(color) or color[1:7].lower() in TELEGRAM_BLUES) and not KEPT_BLUE.fullmatch(key):
                raise PatchError(f"{where}: {key} is Telegram's blue {color}")
    verify_verified_badge(tree, day, night)

    # People's blue and cyan in every theme, the colours a theme leaves out
    # taken from the palette, and in the export: Pluma's colour as drawn, or
    # Telegram's value as written where it stays (a reference among them).
    for theme, (dark, names) in IDENTITY_THEMES.items():
        values = {**day, **palette_values(tree.read(theme) if theme == PALETTE
                                          else zipped_colors(tree.read_bytes(theme), theme))}
        for key, telegram, on_light, on_dark in IDENTITY_COLORS:
            pluma = on_dark if dark else on_light
            color = resolve(values, key) if pluma else values[key].split("|")[0].strip()
            expected = pluma or telegram or names[key]
            if color.lower() != expected.lower():
                raise PatchError(f"{theme}: people's {key} is {color}, not {expected}")
    css = re.sub(r"/\*.*?\*/", "", tree.read(EXPORT_CSS), flags=re.S)
    rules = [([s.strip() for s in m.group(1).split(",")], m.group(2))
             for m in re.finditer(r"([^{}]*)\{([^{}]*)\}", css)]
    for _, slot in EXPORT_USERPICS:
        found = [body for selectors, body in rules if f".userpic{slot}" in selectors]
        if [re.findall(r"background-color:\s*([^;\s]+)", body) for body in found] != [[export_userpic(slot)]]:
            raise PatchError(f"{EXPORT_CSS}: the letter avatars .userpic{slot} are not {export_userpic(slot)} alone")


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


def link_literals(text, host):
    """How many times the string literals of a source name a host (comments
    aside)."""
    count = 0
    for m in CODE_STRING.finditer(text):
        s = m.group(0)
        if not s.startswith("/"):
            count += len(host.findall(s))
    return count


def links(tree):
    """pluma.chat links (task 026 of the server repository)."""
    for rel, old, new in LINK_HOSTS:
        tree.replace(rel, old, new)
    for rel, old, count in LINK_BUILDERS:
        tree.replace(rel, old, old.replace("t.me", LINK_HOST), count=count)


def links_edited():
    """The files links() edits."""
    return tuple(dict.fromkeys(rel for rel, _, _ in LINK_HOSTS + LINK_BUILDERS))


def verify_hosts(tree):
    """Checks that no new literal names Telegram's or TON's hosts: what is
    there is what HOSTS_KEPT keeps."""
    found = {}
    for rel in tree.sources():
        text = tree.scan(rel)
        if EXTERNAL_HOSTS.search(text):
            count = link_literals(text, EXTERNAL_HOSTS)
            if count:
                found[rel[len(SOURCES) + 1:]] = count
    if found != HOSTS_KEPT:
        diff = sorted(k for k in set(found) | set(HOSTS_KEPT) if found.get(k) != HOSTS_KEPT.get(k))
        raise PatchError(f"{SOURCES}: the hosts in {', '.join(diff[:5])} are not what HOSTS_KEPT keeps")


def verify_links(tree):
    """Checks the links independently of how the edits were made: the t.me
    left in the string literals of the sources is what LINKS_KEPT keeps, and
    pluma.chat is in each file the edits name, as often as they put it."""
    expected = {}
    for rel, _, new in LINK_HOSTS:
        if rel.startswith(SOURCES + "/"):
            key = rel[len(SOURCES) + 1:]
            expected[key] = expected.get(key, 0) + link_literals(new, LINK_PLUMA)
    for rel, _, count in LINK_BUILDERS:
        key = rel[len(SOURCES) + 1:]
        expected[key] = expected.get(key, 0) + count
    kept, pluma = {}, {}
    for rel in tree.sources():
        text = tree.scan(rel)
        key = rel[len(SOURCES) + 1:]
        if LINK_TME.search(text):
            count = link_literals(text, LINK_TME)
            if count:
                kept[key] = count
        # The update prefix names pluma.chat too (patch_updates).
        if key in expected:
            pluma[key] = link_literals(text, LINK_PLUMA)
    for found, table, what in ((kept, LINKS_KEPT, "t.me links that LINKS_KEPT keeps"),
                               (pluma, expected, f"{LINK_HOST} links of LINK_HOSTS and LINK_BUILDERS")):
        if found != table:
            diff = sorted(k for k in set(found) | set(table) if found.get(k) != table.get(k))
            raise PatchError(f"{SOURCES}: the links of {', '.join(diff[:5])} are not the {what}")
    if tree.read(TEXT_ENTITY).count('addOne(QString::fromLatin1("chat"));') != 1:
        raise PatchError(f"{TEXT_ENTITY}: the domain .chat is not there once; {LINK_HOST} without a scheme "
                         "is not a link, or upstream takes it already (drop the edit)")
    # Every check of a whitelist is known: a new one decides about the names
    # under pluma.chat and the server's list.
    types = tree.read(CLICK_HANDLER_TYPES)
    if (types.count("HostOpensWithoutAsking(") != 3 or types.count("HostInDomains(") != 4
            or types.count("WhitelistedDomains(") != 10 or "return config.get<std::vector<QString>>(" in types
            or "result.insert(result.end(), server.begin(), server.end());" not in types):
        raise PatchError(f"{CLICK_HANDLER_TYPES}: the hosts that open without asking are not the client's "
                         f"list with the server's on top and {LINK_HOST} exact")
    verify_site_links(tree)


def verify_site_links(tree):
    """The site's own pages stay out of the app: TryConvertUrlToLocal leaves
    the root and SITE_PATHS of pluma.chat as they are before anything matches
    pluma.chat as a username. The expression is read back from the patched
    source and tried on links of each path."""
    text = tree.read(LOCAL_URL_HANDLERS)
    start = text.find("QString TryConvertUrlToLocal(QString url) {\n")
    site = text.find("\tif (regex_match(u\"^(https?://)?pluma", start)
    me = text.find("\tauto telegramMeMatch = regex_match(", start)
    if (text.count("pluma\\\\.chat(/(") != 1 or not 0 <= start < site < me
            or not text.startswith("\"_q, url, matchOptions)) {\n\t\treturn url;\n\t}\n", text.index('"_q', site))):
        raise PatchError(f"{LOCAL_URL_HANDLERS}: the pages of {LINK_HOST} are not left to the browser "
                         "once, before its links are taken as the app's")
    literal = text[site:text.index('"_q', site)].split('u"', 1)[1]
    site_link = re.compile(literal.replace("\\\\", "\\"), re.I)
    pages = ["pluma.chat", "https://pluma.chat/", "http://PLUMA.CHAT/?a=1", "https://pluma.chat#x"]
    for path in SITE_PATHS:
        pages += [f"https://pluma.chat/{path}", f"pluma.chat/{path.upper()}/x?y=1", f"https://pluma.chat/{path}#z"]
    links = ["https://pluma.chat/durov", "https://pluma.chat/+AbC", "https://pluma.chat/c/1/2",
             "https://pluma.chat/iphones", "https://pluma.chat/xapp", "https://pluma.chat/en_us",
             "https://pluma.chat/favicon.svgx", "https://pluma.chat/faviconxsvg", "https://web.pluma.chat/",
             "https://www.pluma.chat/iphone", "https://t.me/iphone", "https://pluma.chat.example.com/"]
    wrong = [u for u in pages if not site_link.match(u)] + [u for u in links if site_link.match(u)]
    if wrong:
        raise PatchError(f"{LOCAL_URL_HANDLERS}: the expression of the pages of {LINK_HOST} takes these "
                         f"wrongly: {', '.join(wrong[:5])}")


def brand_edited():
    """The text files rebrand() edits."""
    return tuple(dict.fromkeys((LANG, PALETTE, TEXT_ENTITY, QTHELP_URL, EMBEDDED_THEMES, SETTINGS_MAIN, DEEP_LINKS_SETTINGS,
                                SETTINGS_INTRO, ABOUT_BOX, MAIN_MENU, BANNED_BOX, DATA_PEER, EXPORT_CSS)
                               + tuple(rel for rel, _, _, _ in CODE_NAMES)
                               + tuple(f"{SOURCES}/{rel}" for rel in SCHEME_FILES)
                               + tuple(rel for rel, _, _ in SCHEME_LISTS)
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
    tree.expect(DOCKER_ENV + "/build.sh", 'cd Telegram\n./configure.sh "$@"\n')
    tree.expect(DOCKER_ENV + "/build.sh", 'cmake --build ../out --config "${CONFIG:-Release}" ${KEEP_GOING:+-- -k 0}\n')
    tree.expect(DOCKER_ENV + "/gen_dockerfile.py", 'DEBUG=checkEnv("DEBUG", True),\n')
    tree.expect(DOCKER_ENV + "/gen_dockerfile.py", 'LTO=checkEnv("LTO", True),\n')
    # ci/windows.sh and ci/macos.sh: prepare.py builds the release libraries
    # without questions with "silent", Qt 6 on Windows with "qt6".
    tree.expect(PREPARE, "optionsList = [\n    'qt5',\n    'qt6',\n")
    tree.expect(PREPARE, "        elif arg == 'silent':\n            rebuildStale = True\n")
    # The options the build passes are still the upstream's.
    tree.expect(CMAKE_VARIABLES, 'option(DESKTOP_APP_DISABLE_AUTOUPDATE "Disable autoupdate."')
    tree.expect(CMAKE_VARIABLES, 'option(DESKTOP_APP_DISABLE_CRASH_REPORTS "Disable crash report generation."')
    # ci/sign-macos.sh signs with upstream's entitlements, which it copies.
    if tree.read(ENTITLEMENTS) != (BRAND.parent / "ci" / "macos.entitlements").read_text():
        raise PatchError(f"{ENTITLEMENTS}: not ci/macos.entitlements; upstream changed what the app may use")
    for rel in (EDITED + brand_edited() + links_edited() + login_code_edited() + no_ai_editor_edited()
                + call_parameters_edited() + service_account_edited() + group_calls_e2e_edited()
                + call_colors_edited()):
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

    # No crash reports to Telegram: compiled out. Updates from the Pluma server.
    tree.replace(CMAKE_OPTIONS, CMAKE_OPTIONS_OLD, CMAKE_OPTIONS_NEW)
    patch_updates(tree, c)

    # plm:// links in place of tg://, tonsite:// and ton://, which stay with Telegram
    # Desktop on the same computer: the app registers plm:// at its first
    # start (rebrand(), RegisterUrlScheme), and its macOS bundle and Linux
    # .desktop file declare plm:// alone.
    tree.replace(PLIST, "\t\t\t\t<string>tg</string>\n\t\t\t\t<string>tonsite</string>\n\t\t\t\t<string>ton</string>\n",
                 "\t\t\t\t<string>plm</string>\n")

    # Identity: the name, and with it the data folder (%APPDATA%\Pluma, a
    # portable folder next to Pluma.exe, ~/Library/Application Support/Pluma,
    # ~/.local/share/Pluma), and Pluma's own GUIDs.
    name = c.app_name
    tree.sub(VERSION_H, r'constexpr auto AppId = "\{[0-9A-F-]{36}\}"_cs;',
             f'constexpr auto AppId = "{{{c.app_guid}}}"_cs; // pluma: Pluma\'s own')
    tree.replace(VERSION_H, 'constexpr auto AppNameOld = "Telegram Win (Unofficial)"_cs;\n',
                 f'constexpr auto AppNameOld = "{c.data_name}"_cs; // pluma: no older folder to move data from\n')
    tree.replace(VERSION_H, 'constexpr auto AppName = "Telegram Desktop"_cs;\n', f'constexpr auto AppName = "{name}"_cs;\n')
    tree.replace(VERSION_H, 'constexpr auto AppFile = "Telegram"_cs;\n', f'constexpr auto AppFile = "{name}"_cs;\n')
    tree.replace(CONFIG_H, '\tstatic const char *gGuidStr = "{87A94AB0-E370-4cde-98D3-ACC110C5967D}";\n',
                 f'\tstatic const char *gGuidStr = "{{{c.instance_guid}}}"; // pluma: Pluma\'s own\n')
    tree.replace(LAUNCHER, '\tQApplication::setApplicationName(u"TelegramDesktop"_q);\n',
                 f'\tQApplication::setApplicationName(u"{c.data_name}"_q); // pluma: the Linux data folder\n')
    # The data folder of Windows and macOS, by the same name.
    tree.replace(WIN_SPECIFIC, "\t\treturn appData.absolutePath() + '/' + AppName.utf16() + '/';\n",
                 f"\t\treturn appData.absolutePath() + u\"/{c.data_name}/\"_q; // pluma: the data folder\n")
    tree.replace(MAC_SPECIFIC_P, "\t\treturn QString::fromUtf8([[url path] fileSystemRepresentation]) + '/' + AppName.utf16() + '/';\n",
                 f"\t\treturn QString::fromUtf8([[url path] fileSystemRepresentation]) + u\"/{c.data_name}/\"_q; // pluma: the data folder\n")

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
               # plm:// links; tg://, tonsite:// and ton:// stay with Telegram Desktop.
               ("MimeType=x-scheme-handler/tg;x-scheme-handler/tonsite;x-scheme-handler/ton;\n", "MimeType=x-scheme-handler/plm;\n"),
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
    # The tags of Saved Messages without Premium (SAVED_TAGS).
    for s in SAVED_TAGS_KEPT:
        tree.expect(DATA_REACTIONS, s)
    for rel, old, new in SAVED_TAGS:
        tree.replace(rel, old, new)
    # Premium stickers without Premium (PREMIUM_STICKERS).
    for rel, old, new, count in PREMIUM_STICKERS:
        tree.replace(rel, old, new, count)

    # pluma.chat links beside t.me's (LINK_HOSTS, LINK_BUILDERS).
    links(tree)

    rebrand(tree, c)
    premium_for_everyone(tree)
    transcription(tree)
    no_ai_editor(tree)
    # After rebrand(): the texts name the real Telegram.
    login_code_screens(tree)
    call_parameters(tree)
    service_account(tree)
    group_calls_e2e(tree)
    # After rebrand(): it writes the themes first.
    call_colors(tree)

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
                elif first not in UPDATE_KEY_LINES or rel != SOURCES + "/_other/packer.cpp":
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
    if (CMAKE_DEFINITIONS not in options or "if (DESKTOP_APP_DISABLE_AUTOUPDATE)" in options
            or "TDESKTOP_DISABLE_AUTOUPDATE" in options):
        raise PatchError(f"{CMAKE_OPTIONS}: the crash reports are not compiled out, or the updater is")
    verify_updates(tree, c)

    for rel, traces in ((VERSION_H, ('"Telegram Desktop"', '"Telegram"_cs', "Unofficial")),
                        (CONFIG_H, ("87A94AB0-E370-4cde-98D3-ACC110C5967D",)),
                        (LAUNCHER, ('u"TelegramDesktop"_q',)),
                        (LINUX, ('return u"org.telegram.desktop', "/.TelegramDesktop/")),
                        (DESKTOP_FILE, ("Telegram", "x-scheme-handler/tg", "tonsite", "x-scheme-handler/ton")),
                        (WIN_APP_ID, ('L"Telegram.TelegramDesktop";', "Telegram.lnk")),
                        (WIN_TOAST, ("F11932D3-6110-4BBC-9B02-B2EC07A1BD19",)),
                        (WIN_SPECIFIC, ("Telegram.lnk",)),
                        (WIN_RC, ("Telegram FZ-LLC", "Telegram Desktop")),
                        (CMAKE_APP, ("com.tdesktop.Telegram",)),
                        (PLIST, ("<string>tg</string>", "<string>tonsite</string>", "<string>ton</string>", "Telegram Desktop"))):
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
    # Every system keeps its data in the folder of data_name, and Windows
    # moves no files from another one (logs.cpp MoveOldDataFiles).
    for rel, text in ((WIN_SPECIFIC, f'u"/{c.data_name}/"_q; // pluma: the data folder'),
                      (MAC_SPECIFIC_P, f'u"/{c.data_name}/"_q; // pluma: the data folder'),
                      (LAUNCHER, f'setApplicationName(u"{c.data_name}"_q);'),
                      (VERSION_H, f'constexpr auto AppNameOld = "{c.data_name}"_cs;'),
                      (UPDATER_WIN, f'_programName = L"{c.data_name}";')):
        if tree.read(rel).count(text) != 1:
            raise PatchError(f"{rel}: the data folder is not {c.data_name}")
    if f'return u"{c.app_id}"_q;' not in tree.read(LINUX):
        raise PatchError(f"{LINUX}: the application ID is not {c.app_id}")
    verify_links(tree)
    verify_hosts(tree)
    verify_brand(tree)
    verify_help_and_gifts(tree)
    verify_premium_for_everyone(tree)
    verify_transcription(tree)
    verify_no_ai_editor(tree)
    verify_login_code_screens(tree)
    verify_call_parameters(tree)
    verify_service_account(tree)
    verify_group_calls_e2e(tree)
    verify_call_colors(tree)



# --- Premium for everyone -----------------------------------------------------
# Task 071 (ADR 0041): every user has Premium and every boost-gated feature is
# open, so the server sends the Premium flag for everybody. Only what the flag
# would make wrong is edited: the star by every name, the purchase rows that
# show for anyone with Premium, and what the server does not serve.
PREMIUM_FOR_EVERYONE_EDITS = (
    # The wallet (Money, tdesktop 7.3) talks to toncenter.com and fragment.com
    # and to the server's wallet service, which does not exist. Upstream's
    # default is on; only a server that says wallet_available would turn it on.
    ("Telegram/SourceFiles/main/main_app_config.cpp",
     "\treturn get<bool>(u\"wallet_available\"_q, true);\n",
     "\t// pluma: the server has no wallet service (TON, Money).\n\treturn get<bool>(u\"wallet_available\"_q, false);\n"),
    ("Telegram/SourceFiles/main/main_session.cpp",
     "bool Session::premiumBadgesShown() const {\n\treturn supportMode() || premiumPossible();\n}\n",
     "bool Session::premiumBadgesShown() const {\n\t// pluma: no star by a name: everybody has Premium (ADR 0041).\n\treturn supportMode();\n}\n"),
    ("Telegram/SourceFiles/settings/sections/settings_main.cpp",
     "void BuildPremiumSection(SectionBuilder &builder) {\n\tconst auto session = builder.session();\n\tconst auto controller = builder.controller();\n\tconst auto showOther = builder.showOther();\n\n\tif (!session->premiumPossible()) {\n",
     "void BuildPremiumSection(SectionBuilder &builder) {\n\tconst auto session = builder.session();\n\tconst auto controller = builder.controller();\n\tconst auto showOther = builder.showOther();\n\n\t// pluma: the section is the purchase; everybody has Premium.\n\tif (!session->premiumCanBuy()) {\n"),
    ("Telegram/SourceFiles/window/window_main_menu.cpp",
     "void MainMenu::setupSetEmojiStatus() {\n\t_setEmojiStatus->overrideLinkClickHandler([=] {\n\t\tchooseEmojiStatus();\n\t});\n}\n",
     "void MainMenu::setupSetEmojiStatus() {\n\t// pluma: the server does not serve account.updateEmojiStatus.\n\t_setEmojiStatus->hide();\n\t_setEmojiStatus->overrideLinkClickHandler([=] {\n\t\tchooseEmojiStatus();\n\t});\n}\n"),
    # The star after a sender's name in a group: the slot for it stays only
    # for an emoji status.
    ("Telegram/SourceFiles/history/view/history_view_message.cpp",
     "\tif (from->isPremium()\n\t\t|| (from->isChannel()\n\t\t\t&& from->emojiStatusId()\n\t\t\t&& from != history()->peer)) {\n",
     "\tif ((from->isPremium() // pluma: no star by a name (ADR 0041)\n\t\t\t&& (from->session().premiumBadgesShown()\n\t\t\t\t|| fromNameStatusId(from)))\n\t\t|| (from->isChannel()\n\t\t\t&& from->emojiStatusId()\n\t\t\t&& from != history()->peer)) {\n"),
    # The star on a privacy row of Premium users.
    ("Telegram/SourceFiles/settings/sections/settings_privacy_security.cpp",
     "\tbadge->showOn(Data::AmPremiumValue(session));\n",
     "\t// pluma: no star: everybody has Premium (ADR 0041).\n\tbadge->showOn(rpl::single(session->premiumBadgesShown()));\n"),
    # "Set as status" in the menu of a custom emoji (tdesktop 7.x).
    ("Telegram/SourceFiles/menu/menu_emoji_status.cpp",
     "\tif (!session->premium()\n\t\t|| !sticker\n\t\t|| sticker->setType != Data::StickersType::Emoji) {\n",
     "\tif (true // pluma: the server does not serve account.updateEmojiStatus\n\t\t|| !session->premium()\n\t\t|| !sticker\n\t\t|| sticker->setType != Data::StickersType::Emoji) {\n"),
    # What leads to the gift store, as D-049 and D-050 close the older ones:
    # the button at the message field of a chat section, and the tile of the
    # QR code's gifts on one's own profile (tdesktop 7.3).
    ("Telegram/SourceFiles/history/view/controls/history_view_compose_controls.cpp",
     "\t\t&& !user->isBot()\n\t\t&& ((disallowed & Type::SendHide)\n",
     "\t\t&& !user->isBot()\n\t\t// pluma: no gift while Premium cannot be bought.\n\t\t&& session().premiumCanBuy()\n\t\t&& ((disallowed & Type::SendHide)\n"),
    ("Telegram/SourceFiles/info/profile/info_profile_qr_gifts.cpp",
     "\t} else if (peer->isSelf()) {\n\t\treturn rpl::single(true);\n\t} else if (const auto channel = peer->asBroadcast()) {\n",
     "\t} else if (peer->isSelf()) {\n\t\t// pluma: no gift store while Premium cannot be bought.\n\t\treturn rpl::single(controller->session().premiumCanBuy());\n\t} else if (const auto channel = peer->asBroadcast()) {\n"),
    # Boosts do not exist here: nothing waits for a level of a channel, no
    # screen, prompt or link offers one.
    ("Telegram/SourceFiles/boxes/peers/edit_peer_info_box.cpp",
     "\t\t\t\t.allowedCustomReactions = counters.level,\n",
     "\t\t\t\t// pluma: custom reactions need no boost level, only the limit.\n\t\t\t\t.allowedCustomReactions = Data::PremiumLimits(\n\t\t\t\t\t&_peer->session()).maxBoostLevel(),\n"),
    ("Telegram/SourceFiles/window/window_peer_menu.cpp",
     "void Filler::addBoostChat() {\n\tif (const auto channel = _peer->asChannel()) {\n\t\tif (channel->isMonoforum()) {\n",
     "void Filler::addBoostChat() {\n\tif (const auto channel = _peer->asChannel()) {\n\t\tif (true || channel->isMonoforum()) { // pluma: boosts do not exist here (ADR 0041)\n"),
    ("Telegram/SourceFiles/window/window_peer_menu.cpp",
     "\t\tif (canGetStats\n\t\t\t|| channel->amCreator()\n\t\t\t|| channel->canPostStories()) {\n\t\t\t_addAction(tr::lng_boosts_title(tr::now), [=] {\n",
     "\t\tif (false // pluma: boosts do not exist here (ADR 0041)\n\t\t\t&& (canGetStats\n\t\t\t|| channel->amCreator()\n\t\t\t|| channel->canPostStories())) {\n\t\t\t_addAction(tr::lng_boosts_title(tr::now), [=] {\n"),
    ("Telegram/SourceFiles/window/window_session_controller.cpp",
     "\t} else if (resolveType == ResolveType::Boost && peer->isChannel()) {\n\t\tresolveBoostState(peer->asChannel());\n",
     "\t} else if (false // pluma: a boost link opens the channel\n\t\t&& resolveType == ResolveType::Boost && peer->isChannel()) {\n\t\tresolveBoostState(peer->asChannel());\n"),
    ("Telegram/SourceFiles/api/api_peer_colors.cpp",
     "\tif (Data::DecideColorIndex(channel) == index) {\n\t\treturn 0;\n\t}\n\tif (profile) {\n",
     "\tif (true || Data::DecideColorIndex(channel) == index) { // pluma: no colour needs a boost level\n\t\treturn 0;\n\t}\n\tif (profile) {\n"),
    ("Telegram/SourceFiles/boxes/peers/edit_peer_permissions_box.cpp",
     "\tstate->boostsUnrestrict = AddBoostsUnrestrictWrapped(\n\t\tinner,\n\t\tpeer,\n\t\tstate->hasSendRestrictions.value());\n",
     "\tstate->boostsUnrestrict = AddBoostsUnrestrictWrapped(\n\t\tinner,\n\t\tpeer,\n\t\trpl::single(false)); // pluma: boosts do not exist here (ADR 0041)\n"),
    ("Telegram/SourceFiles/boxes/peers/edit_peer_color_box.cpp",
     "\t\tif (group) {\n\t\t\tauto colorProducer = state->profileIndex.value(\n",
     "\t\tif (false && group) { // pluma: boosts do not exist here (ADR 0041)\n\t\t\tauto colorProducer = state->profileIndex.value(\n"),
)


def premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        tree.replace(rel, old, new)


def verify_premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of task 071 is not there")


# --- Transcription of voice and round messages ---------------------------------
# The server transcribes for everybody with Premium (task 080, ADR 0041), so
# the button on a voice message and on a round video is upstream's again.
# It never shows on a message that plays once or self-destructs: upstream
# hides it for any media with a ttl (Data::Media::ttlSeconds(), which a
# view-once message has as kTimeToLiveSingleView, data_media_types.h:211),
# in Document::countOptimalSize and Gif::ensureTranscribeButton, the only
# two places that make the button of a voice or round message; the server
# refuses such a message too. No source is edited: upstream changing either
# condition, or making the button anywhere else, stops the patch until that
# place is read.
TRANSCRIBE_TTL_CHECKS = (
    (SOURCES + "/history/view/media/history_view_document.cpp",
     "\t\tconst auto media = _parent->data()->media();\n"
     "\t\tif ((media && media->ttlSeconds())\n\t\t\t|| IsHostedInstantViewMedia(_parent)\n"
     "\t\t\t|| _realParent->isScheduled()\n\t\t\t|| _realParent->isAdminLogEntry()\n"
     "\t\t\t|| (!session->premium()\n\t\t\t\t&& !transcribes->freeFor(_realParent)\n"
     "\t\t\t\t&& !transcribes->trialsSupport())\n\t\t\t|| (!session->premium()\n"
     "\t\t\t\t&& _data->duration() > transcribes->trialsMaxLengthMs())) {\n"
     "\t\t\tvoice->transcribe = nullptr;\n\t\t\tvoice->transcribeText = {};\n\t\t} else {\n"),
    (SOURCES + "/history/view/media/history_view_gif.cpp",
     "void Gif::ensureTranscribeButton() const {\n\tconst auto media = _parent->data()->media();\n"
     "\tif (_data->isVideoMessage()\n\t\t&& (!media || !media->ttlSeconds())\n\t\t&& !_parent->data()->isScheduled()\n"),
)
# Every place upstream makes a transcribe button: the two above, and the
# summary of a long text (Message::ensureSummarizeButton), which is not
# audio. Another one is a surface the ttl conditions above do not cover.
TRANSCRIBE_BUTTON = "std::make_unique<TranscribeButton>("
TRANSCRIBE_BUTTONS = {
    SOURCES + "/history/view/media/history_view_document.cpp":
        "\t\t\t\tvoice->transcribe = std::make_unique<TranscribeButton>(\n\t\t\t\t\t_realParent,\n\t\t\t\t\tfalse);\n",
    SOURCES + "/history/view/media/history_view_gif.cpp":
        "\t\t\t_transcribe = std::make_unique<TranscribeButton>(\n\t\t\t\t_realParent,\n\t\t\t\ttrue);\n",
    SOURCES + "/history/view/history_view_message.cpp":
        "\t\t\t\t= std::make_unique<TranscribeButton>(data(), false, true);\n",
}


def transcription(tree):
    for rel, s in TRANSCRIBE_TTL_CHECKS:
        tree.expect(rel, s)
    for rel, s in TRANSCRIBE_BUTTONS.items():
        tree.expect(rel, s)


def verify_transcription(tree):
    for rel, s in TRANSCRIBE_TTL_CHECKS:
        if tree.read(rel).count(s) != 1:
            raise PatchError(f"{rel}: not upstream's transcribe button, which a view-once message "
                             "does not show (task 080)")
    for rel in tree.sources():
        text = tree.scan(rel)
        if TRANSCRIBE_BUTTON not in text:
            continue
        known = TRANSCRIBE_BUTTONS.get(rel)
        if known is None or text.count(known) != 1 or TRANSCRIBE_BUTTON in text.replace(known, ""):
            raise PatchError(f"{rel}: another transcribe button, which the conditions on a view-once "
                             "message (task 080) do not cover")


# --- No AI message editor (task 079) ------------------------------------------
# The AI editor rewrites, proofreads, restyles and translates a typed message
# (ComposeAiBox, CreateAiBox: messages.composeMessageWithAI,
# messages.composeRichMessageWithAI and the aicompose.* tones); Pluma runs no
# language model to answer them (the owner's decision, 2026-11-11). Every AI
# button of a compose field (the chat, the compose controls of other
# sections, the captions of files, GIFs and edits) shows only while
# Ui::HasEnoughLinesForAi says so, which upstream already makes false with
# its "hide-ai-button" option or an empty tone list; it is false always now.
# The rich editor's AI pill, upstream gated only by that option, is never
# made, as with the option on. The Shortcuts settings no longer list the
# shortcut that applies a tone bound in the editor.
AI_BUTTON_FACTORY = SOURCES + "/ui/controls/compose_ai_button_factory.cpp"
AI_IV_EDITOR = SOURCES + "/iv/editor/iv_editor_box.cpp"
AI_SHORTCUTS = SOURCES + "/settings/sections/settings_shortcuts.cpp"
NO_AI_EDITOR_EDITS = (
    (AI_BUTTON_FACTORY,
     "\tif (HideAiButtonOption.value()\n\t\t|| session->data().aiComposeTones().list().empty()) {\n\t\treturn false;\n\t}\n",
     "\tif (true // pluma: no AI editor, Pluma runs no language model (task 079)\n"
     "\t\t|| HideAiButtonOption.value()\n\t\t|| session->data().aiComposeTones().list().empty()) {\n\t\treturn false;\n\t}\n"),
    (AI_IV_EDITOR,
     "\tif (!base::options::value<bool>(Ui::kOptionHideAiButton)) {\n\t\tconst auto session = descriptor.session;\n\t\t_aiPill = ",
     "\tif (false // pluma: no AI editor, Pluma runs no language model (task 079)\n"
     "\t\t&& !base::options::value<bool>(Ui::kOptionHideAiButton)) {\n\t\tconst auto session = descriptor.session;\n\t\t_aiPill = "),
    (AI_SHORTCUTS,
     "\t\t{ C::ComposeAiApplyInPlace, tr::lng_shortcuts_ai_compose_apply() },\n",
     "\t\t// pluma: no AI editor to bind a tone in (task 079).\n"),
)
# The other ways to the editor, each of which the edits above close: the
# buttons that ask HasEnoughLinesForAi and the pill. Upstream adding one stops
# the patch until it is read.
NO_AI_EDITOR_GUARDS = (
    (SOURCES + "/history/history_widget.cpp", "Ui::HasEnoughLinesForAi(", 1),
    (SOURCES + "/history/view/controls/history_view_compose_controls.cpp", "Ui::HasEnoughLinesForAi(", 1),
    (SOURCES + "/boxes/send_files_box.cpp", "Ui::HasEnoughLinesForAi(", 1),
    (AI_BUTTON_FACTORY, "HasEnoughLinesForAi(session, field)", 1),
    (AI_IV_EDITOR, "_aiPill = object_ptr<ToolbarPill>(", 1),
    (AI_IV_EDITOR, "ShowComposeAiBox(", 2),
    (AI_IV_EDITOR, "ShowCreateAiBox(", 1),
)


def no_ai_editor(tree):
    for rel, old, new in NO_AI_EDITOR_EDITS:
        tree.replace(rel, old, new)


def verify_no_ai_editor(tree):
    for rel, old, new in NO_AI_EDITOR_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the AI editor is offered again")
    for rel, s, count in NO_AI_EDITOR_GUARDS:
        found = tree.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; another way into the AI editor")


def no_ai_editor_edited():
    """The files no_ai_editor() edits."""
    return tuple(sorted({rel for rel, _, _ in NO_AI_EDITOR_EDITS}))



# --- The screens of the login code -------------------------------------------
# Task 076 of the server repository. The server tells by the type of
# auth.sentCode where the code went, so that the screen says the truth:
# - sentCodeTypeApp: to the person's other Pluma session; the native screen,
#   with "Didn't get the code?" in place of "Send code via SMS";
# - sentCodeTypeFragmentSms: to the person's own Telegram, in a message from
#   the server's account; url is tg://resolve of that account, or empty. The
#   layout of upstream's Fragment screen (intro_code.cpp:52-57, :94-100,
#   :365-371, :422-436) with Pluma's texts and no Fragment logo: Pluma has no
#   Fragment numbers;
# - sentCodeTypeSms: the code did not reach Telegram (Pluma sends no SMS).
#   The same layout: the path in Telegram's privacy settings, a button to
#   them, and "Send again" after the countdown of next_type and timeout.
# "Didn't get the code?" calls auth.resendCode, on the same screen, which
# then follows the new answer; upstream took every resent code for an SMS
# (intro_code.cpp:469). With no next_type nothing more can be sent: a box
# sends the person to the administrator; nothing leads to Telegram's support.
# The buttons open the real Telegram with tg://, which Pluma does not handle
# (SCHEME_FILES); Telegram Desktop routes tg://settings/phone_privacy to
# Privacy > Phone Number (core/deep_links/deep_links_settings.cpp:2125-2128).
# Whether an app handles tg:// is not known reliably on the desktop systems
# (sandboxes of Flatpak and Snap, xdg-open succeeding without a handler), so
# the buttons show always, as the task's design says for Desktop.
# The texts name the real Telegram: they are added after rebrand(), and
# verify_brand() keeps them by key and exact value. Other languages come from
# the server's language pack of tdesktop.
INTRO_CODE = SOURCES + "/intro/intro_code.cpp"
INTRO_CODE_H = SOURCES + "/intro/intro_code.h"
INTRO_STEP = SOURCES + "/intro/intro_step.cpp"
INTRO_STEP_H = SOURCES + "/intro/intro_step.h"
INTRO_WIDGET = SOURCES + "/intro/intro_widget.cpp"
INTRO_WIDGET_H = SOURCES + "/intro/intro_widget.h"
MAIN_WINDOW = SOURCES + "/window/main_window.cpp"
MAIN_WINDOW_H = SOURCES + "/window/main_window.h"
MAINWINDOW = SOURCES + "/mainwindow.cpp"
MAINWINDOW_H = SOURCES + "/mainwindow.h"

# The built-in English, as lang.strings writes it, after this entry.
LOGIN_CODE_STRINGS_AFTER = '"lng_intro_fragment_button" = "Open Fragment";\n'
LOGIN_CODE_STRINGS = {
    "lng_pluma_code_telegram_title": "Check Telegram",
    "lng_pluma_code_telegram_about": "We've sent the code for **{phone_number}** to your Telegram, "
                                     "in a message from the Pluma account.",
    "lng_pluma_code_telegram_button": "Open Telegram",
    "lng_pluma_code_no_code": "Didn't get the code?",
    "lng_pluma_code_failed_title": "Code didn't reach Telegram",
    "lng_pluma_code_failed_about": "The code for **{phone_number}** didn't reach your Telegram. "
                                   "Let Telegram find you by your number: **Settings → Privacy and Security "
                                   "→ Phone Number → Who can find me by my number? → Everybody**."
                                   "\\n\\nNo Telegram? Ask the administrator for the code and enter it here.",
    "lng_pluma_code_failed_button": "Open Telegram settings",
    "lng_pluma_code_resend_in": "Send again in {time}",
    "lng_pluma_code_resend": "Send again",
    "lng_pluma_code_sending": "Sending…",
    "lng_pluma_code_admin_title": "Ask the administrator",
    "lng_pluma_code_admin_text": "Ask the Pluma administrator for your code and enter it here.",
}

# The one tg:// link of the sources, which opens Telegram's own settings.
TELEGRAM_SETTINGS_LINK = 'u"tg://settings/phone_privacy"_q'

LOGIN_CODE_TITLE_OLD = """\
\tsetTitleText(_isFragment.value(
\t) | rpl::map([=](bool isFragment) {
\t\treturn !isFragment
\t\t\t? rpl::single(Ui::FormatPhone(getData()->phone))
\t\t\t: tr::lng_intro_fragment_title();
\t}) | rpl::flatten_latest());
"""
LOGIN_CODE_TITLE_NEW = """\
\t// pluma: the code in the person's own Telegram, or not delivered there
\t// (task 076); Pluma has no Fragment numbers.
\tsetTitleText(_mode.value(
\t) | rpl::map([=](Mode mode) {
\t\treturn (mode == Mode::Telegram)
\t\t\t? tr::lng_pluma_code_telegram_title()
\t\t\t: (mode == Mode::Undelivered)
\t\t\t? tr::lng_pluma_code_failed_title()
\t\t\t: rpl::single(Ui::FormatPhone(getData()->phone));
\t}) | rpl::flatten_latest());

\t// pluma: on the screens of task 076 a description longer than the three
\t// lines upstream lays out above the field moves the field, the row under
\t// it and the button down by what it has more; the native screens keep
\t// upstream's layout.
\trpl::combine(
\t\tdescriptionHeightValue(),
\t\t_mode.value()
\t) | rpl::on_next([=](int height, Mode mode) {
\t\tconst auto room = st::introDescription.style.lineHeight * 3;
\t\tsetContentShift((mode == Mode::Telegram || mode == Mode::Undelivered)
\t\t\t? std::max(height - room, 0)
\t\t\t: 0);
\t}, lifetime());
\tcontentShiftValue(
\t) | rpl::on_next([=](int) {
\t\tupdateControlsGeometry();
\t}, lifetime());
"""

LOGIN_CODE_CALL_TEXT_OLD = "void CodeWidget::updateCallText() {\n\tauto text = ([this]() -> QString {\n"
LOGIN_CODE_CALL_TEXT_NEW = """\
void CodeWidget::updateCallText() {
\t// pluma: the screens of task 076 have no call. The row under the field
\t// holds the countdown to "Send again" (the server's timeout, or its
\t// FLOOD_WAIT), the request being sent, or the link.
\tconst auto mode = _mode.current();
\tif (mode != Mode::Default) {
\t\tconst auto resendAt = std::max(
\t\t\t(mode == Mode::Undelivered)
\t\t\t\t? getData()->codeResendAt
\t\t\t\t: crl::time(0),
\t\t\t_resendFloodUntil);
\t\tconst auto left = int(std::max(
\t\t\t(resendAt - crl::now() + 999) / 1000,
\t\t\tcrl::time(0)));
\t\tif (!left) {
\t\t\t_resendTimer.cancel();
\t\t} else if (!_resendTimer.isActive()) {
\t\t\t_resendTimer.callEach(1000);
\t\t}
\t\tconst auto text = _noTelegramCodeRequestId
\t\t\t? tr::lng_pluma_code_sending(tr::now)
\t\t\t: left
\t\t\t? tr::lng_pluma_code_resend_in(
\t\t\t\ttr::now,
\t\t\t\tlt_time,
\t\t\t\tu"%1:%2"_q.arg(left / 60).arg(left % 60, 2, 10, QChar('0')))
\t\t\t: QString();
\t\t_noTelegramCode->setText(
\t\t\t(mode == Mode::Undelivered && getData()->codeResendable)
\t\t\t\t? tr::lng_pluma_code_resend(tr::now)
\t\t\t\t: tr::lng_pluma_code_no_code(tr::now));
\t\t_noTelegramCode->setVisible(text.isEmpty() && !animating());
\t\t_callLabel->setText(text);
\t\t_callLabel->setVisible(!text.isEmpty() && !animating());
\t\treturn;
\t}
\tauto text = ([this]() -> QString {
"""

LOGIN_CODE_DESC_TEXT = """\
\tconst auto byTelegram = getData()->codeByTelegram;
\t// pluma: the code went to the person's own Telegram (FragmentSms), or
\t// did not reach it (Sms: Pluma sends no SMS); task 076.
\tconst auto mode = getData()->codeInTelegram
\t\t? Mode::Telegram
\t\t: getData()->codeUndelivered
\t\t? Mode::Undelivered
\t\t: byTelegram
\t\t? Mode::App
\t\t: Mode::Default;
\t_mode.force_assign(mode);
\tconst auto phone = [&] {
\t\treturn rpl::single(
\t\t\tTextWithEntities::Simple(Ui::FormatPhone(getData()->phone)));
\t};
\tconst auto emailPattern = !getData()->emailPatternSetup.isEmpty()
\t\t? getData()->emailPatternSetup
\t\t: getData()->emailPatternLogin;
\tsetDescriptionText(!emailPattern.isEmpty()
\t\t? tr::lng_intro_email_confirm_subtitle(
\t\t\tlt_email,
\t\t\trpl::single(Ui::Text::WrapEmailPattern(emailPattern)),
\t\t\ttr::marked)
\t\t: (mode == Mode::Telegram)
\t\t? tr::lng_pluma_code_telegram_about(
\t\t\tlt_phone_number,
\t\t\tphone(),
\t\t\ttr::rich)
\t\t: (mode == Mode::Undelivered)
\t\t? tr::lng_pluma_code_failed_about(
\t\t\tlt_phone_number,
\t\t\tphone(),
\t\t\ttr::rich)
\t\t: (byTelegram ? tr::lng_code_from_telegram : tr::lng_code_desc)(
\t\t\ttr::rich));
\tif (mode != Mode::Default) {
\t\t_callTimer.cancel();
\t} else {
\t\t_noTelegramCode->hide();
\t\t_callStatus = getData()->callStatus;
\t\t_callTimeout = getData()->callTimeout;
\t\tif (_callStatus == CallStatus::Waiting && !_callTimer.isActive()) {
\t\t\t_callTimer.callEach(1000);
\t\t}
\t}
\tupdateCallText();"""

LOGIN_CODE_SUBMIT = """\
\t// pluma: the buttons of task 076 open the real Telegram: the chat with
\t// the code, or its privacy settings of the phone number.
\tconst auto mode = _mode.current();
\tif (mode == Mode::Undelivered) {
\t\tFile::OpenUrl(""" + TELEGRAM_SETTINGS_LINK + """);
\t} else if (mode == Mode::Telegram
\t\t&& !getData()->codeByFragmentUrl.isEmpty()) {
\t\tFile::OpenUrl(getData()->codeByFragmentUrl);
\t} else {
\t\t_code->requestCode();
\t}"""

LOGIN_CODE_NEXT_TEXT = """\
\treturn _mode.value(
\t) | rpl::map([=](Mode mode) {
\t\t// pluma: no chat to open, no button (task 076).
\t\treturn (mode == Mode::Telegram)
\t\t\t? (getData()->codeByFragmentUrl.isEmpty()
\t\t\t\t? rpl::single(QString())
\t\t\t\t: tr::lng_pluma_code_telegram_button())
\t\t\t: (mode == Mode::Undelivered)
\t\t\t? tr::lng_pluma_code_failed_button()
\t\t\t: Step::nextButtonText();
\t}) | rpl::flatten_latest();"""

LOGIN_CODE_NEXT_STYLE = """\
\t// pluma: the step's own button, with no Fragment logo (task 076).
\treturn rpl::single(static_cast<const style::RoundButton*>(nullptr));"""

LOGIN_CODE_NO_CODE = """\
\tif (_noTelegramCodeRequestId) {
\t\treturn;
\t}
\t// pluma: with nothing more to send the code by, the administrator gives
\t// it; no SMS and no Telegram support (task 076).
\tif (!getData()->codeResendable) {
\t\tshowAdministratorBox();
\t\treturn;
\t}
\t_noTelegramCodeRequestId = api().request(MTPauth_ResendCode(
\t\tMTP_flags(0),
\t\tMTP_string(getData()->phone),
\t\tMTP_bytes(getData()->phoneHash),
\t\tMTPstring() // reason
\t)).done([=](const MTPauth_SentCode &result) {
\t\tnoTelegramCodeDone(result);
\t}).fail([=](const MTP::Error &error) {
\t\tnoTelegramCodeFail(error);
\t}).handleFloodErrors().send();
\tupdateCallText(); // pluma: "Sending..." in the row"""

LOGIN_CODE_NO_CODE_FAIL = """\
\t_noTelegramCodeRequestId = 0;
\tconst auto &type = error.type();
\tconst auto flood = MTP::IsFloodError(error);
\tconst auto unavailable = (type == u"SEND_CODE_UNAVAILABLE"_q);
\tif (flood) {
\t\t// pluma: no "Send again" before the wait of FLOOD_WAIT_X is over.
\t\tconst auto seconds = type.mid(type.lastIndexOf('_') + 1).toInt();
\t\t_resendFloodUntil = crl::now() + seconds * crl::time(1000);
\t} else if (unavailable) {
\t\t// pluma: nothing more to send the code by (task 076).
\t\tgetData()->codeResendable = false;
\t}
\tupdateCallText(); // pluma: the link or the countdown back in the row
\tif (flood) {
\t\tshowCodeError(tr::lng_flood_error());
\t} else if (unavailable) {
\t\tshowAdministratorBox(); // pluma
\t} else if (type == u"PHONE_CODE_EXPIRED"_q) {
\t\tgoBack(); // pluma: as codeSubmitFail, not the error's name
\t} else if (!MTP::IgnoreError(error)) {
\t\tshowCodeError(rpl::single(type));
\t}"""

LOGIN_CODE_ADMINISTRATOR_BOX = """\
void CodeWidget::showAdministratorBox() {
\t// pluma: with nothing more to send the code by, the administrator gives
\t// it (task 076).
\tUi::show(Ui::MakeInformBox({
\t\t.text = tr::lng_pluma_code_admin_text(),
\t\t.title = tr::lng_pluma_code_admin_title(),
\t}));
}
"""

# Whole functions of intro_code.cpp: (head, body, what the replaced one had).
LOGIN_CODE_BODIES = (
    ("void CodeWidget::updateDescText() {\n", LOGIN_CODE_DESC_TEXT,
     ("_isFragment = isFragment;", "tr::lng_intro_fragment_about(", "_callTimer.callEach(1000);")),
    ("void CodeWidget::submit() {\n", LOGIN_CODE_SUBMIT, ("File::OpenUrl(getData()->codeByFragmentUrl);",)),
    ("rpl::producer<QString> CodeWidget::nextButtonText() const {\n", LOGIN_CODE_NEXT_TEXT,
     ("tr::lng_intro_fragment_button()",)),
    ("rpl::producer<const style::RoundButton*> CodeWidget::nextButtonStyle() const {\n", LOGIN_CODE_NEXT_STYLE,
     ("&st::introFragmentButton",)),
    ("void CodeWidget::noTelegramCode() {\n", LOGIN_CODE_NO_CODE, ("MTPauth_ResendCode(", "noTelegramCodeFail(error);")),
    ("void CodeWidget::noTelegramCodeFail(const MTP::Error &error) {\n", LOGIN_CODE_NO_CODE_FAIL,
     ('u"SEND_CODE_UNAVAILABLE"_q',)),
)

LOGIN_CODE_EDITS = (
    # The data of the step: what the server answered (intro_step.cpp:359-372).
    (INTRO_WIDGET_H, "\tQString codeByFragmentUrl;\n",
     "\tQString codeByFragmentUrl;\n"
     "\t// pluma: the code went to the person's own Telegram (FragmentSms) or\n"
     "\t// did not reach it (Sms: Pluma sends no SMS), whether auth.resendCode\n"
     "\t// has another way (next_type) and from when (timeout); task 076.\n"
     "\tbool codeInTelegram = false;\n"
     "\tbool codeUndelivered = false;\n"
     "\tbool codeResendable = false;\n"
     "\tcrl::time codeResendAt = 0;\n"),
    (INTRO_STEP, "\tgetData()->codeByTelegram = false;\n\tgetData()->codeByFragmentUrl = QString();\n",
     "\tgetData()->codeByTelegram = false;\n\tgetData()->codeByFragmentUrl = QString();\n"
     "\t// pluma: task 076 (Data::codeInTelegram).\n"
     "\tgetData()->codeInTelegram = false;\n"
     "\tgetData()->codeUndelivered = false;\n"
     "\tgetData()->codeResendable = data.vnext_type().has_value();\n"
     "\tconst auto timeout = data.vtimeout().value_or(0);\n"
     "\tgetData()->codeResendAt = (timeout > 0)\n"
     "\t\t? (crl::now() + timeout * crl::time(1000))\n"
     "\t\t: 0;\n"),
    (INTRO_STEP, "\t}, [&](const MTPDauth_sentCodeTypeSms &data) {\n\t\tgetData()->codeLength = data.vlength().v;\n",
     "\t}, [&](const MTPDauth_sentCodeTypeSms &data) {\n"
     "\t\tgetData()->codeUndelivered = true; // pluma\n"
     "\t\tgetData()->codeLength = data.vlength().v;\n"),
    (INTRO_STEP, "\t\tgetData()->codeByFragmentUrl = qs(data.vurl());\n",
     "\t\tgetData()->codeInTelegram = true; // pluma\n"
     "\t\tgetData()->codeByFragmentUrl = qs(data.vurl());\n"),
    # A step's description may move what is under it (the code step's texts):
    # by contentShift, animated on the step on view. The content rises as
    # far as the window needs to keep the next button and the language link
    # under it in view, and the window keeps the height the step needs, as
    # it does for its bars (Window::MainWindow::computeMinHeight()).
    (INTRO_STEP_H, "\t[[nodiscard]] int contentTop() const;\n",
     "\t[[nodiscard]] int contentTop() const;\n"
     "\t// pluma: how far a longer description moves the content under it,\n"
     "\t// the next button included, and the height the step then needs, or\n"
     "\t// 0 when the window's own minimum is enough (task 076).\n"
     "\t[[nodiscard]] int contentShift() const {\n"
     "\t\treturn _contentShift.current();\n"
     "\t}\n"
     "\t[[nodiscard]] rpl::producer<int> contentShiftValue() const {\n"
     "\t\treturn _contentShift.value();\n"
     "\t}\n"
     "\t[[nodiscard]] rpl::producer<int> requiredHeightValue() const {\n"
     "\t\treturn _requiredHeight.value();\n"
     "\t}\n"),
    (INTRO_STEP_H, "\tvoid setDescriptionText(v::text::data &&descriptionText);\n",
     "\tvoid setDescriptionText(v::text::data &&descriptionText);\n"
     "\t[[nodiscard]] rpl::producer<int> descriptionHeightValue() const; // pluma\n"
     "\tvoid setContentShift(int shift); // pluma\n"),
    (INTRO_STEP_H, "\t[[nodiscard]] QPixmap prepareSlideAnimation();\n",
     "\t[[nodiscard]] QPixmap prepareSlideAnimation( // pluma\n"
     "\t\tint top,\n"
     "\t\tint slideHeight);\n"
     "\t[[nodiscard]] static int ContentBelowNextTop(); // pluma\n"),
    (INTRO_STEP_H, "\tobject_ptr<Ui::FadeWrap<Ui::FlatLabel>> _description;\n",
     "\tobject_ptr<Ui::FadeWrap<Ui::FlatLabel>> _description;\n"
     "\t// pluma: task 076.\n"
     "\trpl::variable<int> _contentShift = 0;\n"
     "\tint _contentShiftTo = 0;\n"
     "\tUi::Animations::Simple _contentShiftAnimation;\n"
     "\trpl::variable<int> _requiredHeight = 0;\n"),
    (INTRO_STEP_H, "\tstd::unique_ptr<Ui::SlideAnimation> _slideAnimation;\n",
     "\tstd::unique_ptr<Ui::SlideAnimation> _slideAnimation;\n"
     "\tint _slideTop = 0; // pluma: of both steps' snapshots\n"
     "\tint _slideHeight = 0;\n"),
    (INTRO_STEP, "\t_descriptionText = v::text::take_marked(std::move(descriptionText));\n}\n",
     "\t_descriptionText = v::text::take_marked(std::move(descriptionText));\n}\n"
     "\n"
     "rpl::producer<int> Step::descriptionHeightValue() const { // pluma\n"
     "\treturn _description->entity()->heightValue();\n"
     "}\n"
     "\n"
     "int Step::ContentBelowNextTop() { // pluma\n"
     "\t// The next button, the language link under it at its own height\n"
     "\t// (Widget::updateControlsGeometry) and the margin of the bottom ones.\n"
     "\treturn st::introNextButton.height\n"
     "\t\t+ 2 * st::defaultLinkButton.font->height\n"
     "\t\t+ st::introResetBottom;\n"
     "}\n"
     "\n"
     "void Step::setContentShift(int shift) { // pluma\n"
     "\tif (_contentShiftTo == shift) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t_contentShiftTo = shift;\n"
     "\t_requiredHeight = shift\n"
     "\t\t? (st::introStepTopMin\n"
     "\t\t\t+ st::introNextTop\n"
     "\t\t\t+ shift\n"
     "\t\t\t+ ContentBelowNextTop())\n"
     "\t\t: 0;\n"
     "\tconst auto apply = [=] {\n"
     "\t\t_contentShift = int(base::SafeRound(\n"
     "\t\t\t_contentShiftAnimation.value(_contentShiftTo)));\n"
     "\t\tupdateLabelsPosition();\n"
     "\t};\n"
     "\t// The step on view moves with its next button; one yet to slide in,\n"
     "\t// or sliding, is laid out at once.\n"
     "\tif (isHidden() || animating()) {\n"
     "\t\t_contentShiftAnimation.stop();\n"
     "\t\tapply();\n"
     "\t} else {\n"
     "\t\t_contentShiftAnimation.start(\n"
     "\t\t\tapply,\n"
     "\t\t\t_contentShift.current(),\n"
     "\t\t\tshift,\n"
     "\t\t\tst::introSlideDuration);\n"
     "\t}\n"
     "}\n"),
    (INTRO_STEP, "\tauto result = (height() - st::introHeight) / 2;\n\taccumulate_max(result, st::introStepTopMin);\n",
     "\tauto result = (height() - st::introHeight) / 2;\n"
     "\t// pluma: content moved down by a longer description rises as far as\n"
     "\t// the next button and the language link need to stay in view.\n"
     "\tif (const auto shift = contentShift()) {\n"
     "\t\taccumulate_min(\n"
     "\t\t\tresult,\n"
     "\t\t\theight() - st::introNextTop - shift - ContentBelowNextTop());\n"
     "\t}\n"
     "\taccumulate_max(result, st::introStepTopMin);\n"),
    (INTRO_STEP, "\t\tauto leftSnapshot = after->prepareSlideAnimation();\n"
                 "\t\tauto rightSnapshot = prepareSlideAnimation();\n",
     "\t\t// pluma: one rect for both steps, which a longer description may\n"
     "\t\t// make taller or move (task 076).\n"
     "\t\t_slideTop = std::min(contentTop(), after->contentTop());\n"
     "\t\t_slideHeight = std::max(\n"
     "\t\t\tcontentTop() + contentShift(),\n"
     "\t\t\tafter->contentTop() + after->contentShift())\n"
     "\t\t\t+ st::introStepHeight\n"
     "\t\t\t- _slideTop;\n"
     "\t\tauto leftSnapshot = after->prepareSlideAnimation(\n"
     "\t\t\t_slideTop,\n"
     "\t\t\t_slideHeight);\n"
     "\t\tauto rightSnapshot = prepareSlideAnimation(_slideTop, _slideHeight);\n"),
    (INTRO_STEP, "QPixmap Step::prepareSlideAnimation() {\n\tauto grabLeft = (width() - st::introStepWidth) / 2;\n"
                 "\tauto grabTop = contentTop();\n\treturn Ui::GrabWidget(\n\t\tthis,\n"
                 "\t\tQRect(grabLeft, grabTop, st::introStepWidth, st::introStepHeight));\n",
     "QPixmap Step::prepareSlideAnimation(int top, int slideHeight) { // pluma\n"
     "\tauto grabLeft = (width() - st::introStepWidth) / 2;\n"
     "\treturn Ui::GrabWidget(\n"
     "\t\tthis,\n"
     "\t\tQRect(grabLeft, top, st::introStepWidth, slideHeight));\n"),
    (INTRO_STEP, "\t\t_slideAnimation->paintFrame(p, (width() - st::introStepWidth) / 2, contentTop(), width());\n",
     "\t\t_slideAnimation->paintFrame(\n"
     "\t\t\tp,\n"
     "\t\t\t(width() - st::introStepWidth) / 2,\n"
     "\t\t\t_slideTop, // pluma\n"
     "\t\t\twidth());\n"),
    (INTRO_STEP, "\t\t\t[=] { update(0, contentTop(), width(), st::introStepHeight); },\n",
     "\t\t\t[=] { update(0, _slideTop, width(), _slideHeight); }, // pluma\n"),
    (INTRO_STEP, "\t\tif (!QRect(0, contentTop(), width(), st::introStepHeight).intersects(clip)) {\n",
     "\t\tif (!QRect(\n"
     "\t\t\t\t0,\n"
     "\t\t\t\tcontentTop(),\n"
     "\t\t\t\twidth(),\n"
     "\t\t\t\tst::introStepHeight + contentShift() // pluma\n"
     "\t\t\t).intersects(clip)) {\n"),
    # The next button and the window follow the step on view.
    (INTRO_WIDGET, "\tauto nextTopTo = getStep()->contentTop() + st::introNextTop;\n"
                   "\tauto nextTop = anim::interpolate(_nextTopFrom, nextTopTo, shown);\n",
     "\tauto nextTopTo = getStep()->contentTop()\n"
     "\t\t+ st::introNextTop\n"
     "\t\t+ getStep()->contentShift(); // pluma: under a longer description\n"
     "\tauto nextTop = anim::interpolate(\n"
     "\t\t_nextTopFrom,\n"
     "\t\tnextTopTo,\n"
     "\t\tshown * _nextMoveAnimation.value(1.)); // pluma\n"),
    (INTRO_WIDGET, "\t\t\twasStep->hasCover() ? anim::linear : anim::easeOutCirc);\n\t}\n",
     "\t\t\twasStep->hasCover() ? anim::linear : anim::easeOutCirc);\n"
     "\t} else if (wasStep->contentTop() + wasStep->contentShift()\n"
     "\t\t!= getStep()->contentTop() + getStep()->contentShift()) {\n"
     "\t\t// pluma: under a longer description the button moves to its\n"
     "\t\t// place with the slide (task 076).\n"
     "\t\t_nextTopFrom = wasStep->contentTop()\n"
     "\t\t\t+ st::introNextTop\n"
     "\t\t\t+ wasStep->contentShift();\n"
     "\t\t_nextMoveAnimation.start(\n"
     "\t\t\t[this] { updateControlsGeometry(); },\n"
     "\t\t\t0.,\n"
     "\t\t\t1.,\n"
     "\t\t\tst::introSlideDuration);\n"
     "\t}\n"),
    (INTRO_WIDGET, "\t}, getStep()->lifetime());\n\n\tgetStep()->nextButtonFocusRequests() | rpl::on_next([=] {\n",
     "\t}, getStep()->lifetime());\n"
     "\n"
     "\t// pluma: the button follows the step's description, and the window\n"
     "\t// keeps the height the step needs (task 076). A step left in the\n"
     "\t// history is not on view.\n"
     "\tconst auto step = getStep();\n"
     "\tstep->contentShiftValue(\n"
     "\t) | rpl::on_next([=](int) {\n"
     "\t\tif (getStep() == step) {\n"
     "\t\t\tupdateControlsGeometry();\n"
     "\t\t}\n"
     "\t}, step->lifetime());\n"
     "\tstep->requiredHeightValue(\n"
     "\t) | rpl::on_next([=](int height) {\n"
     "\t\tif (getStep() == step) {\n"
     "\t\t\t_requiredHeight = height;\n"
     "\t\t}\n"
     "\t}, step->lifetime());\n"
     "\n"
     "\tgetStep()->nextButtonFocusRequests() | rpl::on_next([=] {\n"),
    (INTRO_WIDGET_H, "\t[[nodiscard]] rpl::producer<> showSettingsRequested() const;\n",
     "\t[[nodiscard]] rpl::producer<> showSettingsRequested() const;\n"
     "\n"
     "\t// pluma: the height the step on view needs, or 0 when the window's\n"
     "\t// own minimum is enough (task 076).\n"
     "\t[[nodiscard]] int requiredHeight() const {\n"
     "\t\treturn _requiredHeight.current();\n"
     "\t}\n"
     "\t[[nodiscard]] rpl::producer<int> requiredHeightValue() const {\n"
     "\t\treturn _requiredHeight.value();\n"
     "\t}\n"),
    (INTRO_WIDGET_H, "\tint _controlsTopFrom = 0;\n",
     "\tint _controlsTopFrom = 0;\n"
     "\tUi::Animations::Simple _nextMoveAnimation; // pluma\n"
     "\trpl::variable<int> _requiredHeight = 0; // pluma\n"),
    (MAIN_WINDOW_H, "\tvirtual QRect computeDesktopRect() const;\n",
     "\tvirtual QRect computeDesktopRect() const;\n"
     "\n"
     "\t// pluma: what the body's content needs above windowMinHeight\n"
     "\t// (task 076).\n"
     "\t[[nodiscard]] virtual int bodyMinHeightAdd() const {\n"
     "\t\treturn 0;\n"
     "\t}\n"),
    (MAIN_WINDOW, "\treturn outdated + screenReader + st::windowMinHeight;\n",
     "\treturn outdated\n"
     "\t\t+ screenReader\n"
     "\t\t+ st::windowMinHeight\n"
     "\t\t+ bodyMinHeightAdd(); // pluma\n"),
    (MAINWINDOW_H, "\tvoid clearWidgetsHook() override;\n",
     "\tvoid clearWidgetsHook() override;\n"
     "\t[[nodiscard]] int bodyMinHeightAdd() const override; // pluma\n"),
    (MAINWINDOW, "\tclearWidgets();\n\t_intro = std::move(created);\n",
     "\tclearWidgets();\n"
     "\t_intro = std::move(created);\n"
     "\t// pluma: the window keeps the height the login code screens need\n"
     "\t// (task 076).\n"
     "\t_intro->requiredHeightValue(\n"
     "\t) | rpl::skip(1) | rpl::on_next([=](int) {\n"
     "\t\trecountGeometryConstraints();\n"
     "\t}, _intro->lifetime());\n"),
    (MAINWINDOW, "\t_main.destroy();\n\t_intro.destroy();\n",
     "\t_main.destroy();\n"
     "\t// pluma: without the intro the window's own minimum height.\n"
     "\tconst auto introHeight = _intro ? _intro->requiredHeight() : 0;\n"
     "\t_intro.destroy();\n"
     "\tif (introHeight) {\n"
     "\t\tsetMinimumSize(QSize(computeMinWidth(), computeMinHeight()));\n"
     "\t}\n"),
    (MAINWINDOW, "QPixmap MainWindow::grabForSlideAnimation() {\n",
     "int MainWindow::bodyMinHeightAdd() const { // pluma\n"
     "\treturn _intro\n"
     "\t\t? std::max(_intro->requiredHeight() - st::windowMinHeight, 0)\n"
     "\t\t: 0;\n"
     "}\n"
     "\n"
     "QPixmap MainWindow::grabForSlideAnimation() {\n"),
    # The code step.
    (INTRO_CODE_H, "\trpl::variable<bool> _isFragment = false;\n",
     "\t// pluma: what the screen says of the code's delivery (task 076).\n"
     "\tenum class Mode {\n"
     "\t\tDefault,\n"
     "\t\tApp,\n"
     "\t\tTelegram,\n"
     "\t\tUndelivered,\n"
     "\t};\n"
     "\trpl::variable<Mode> _mode = Mode::Default;\n"),
    (INTRO_CODE_H, "\tbase::Timer _callTimer;\n",
     "\tbase::Timer _callTimer;\n"
     "\tbase::Timer _resendTimer; // pluma: the countdown to \"Send again\"\n"
     "\tcrl::time _resendFloodUntil = 0; // pluma: and the server's FLOOD_WAIT\n"),
    (INTRO_CODE_H, "\tvoid noTelegramCodeFail(const MTP::Error &result);\n",
     "\tvoid noTelegramCodeFail(const MTP::Error &result);\n"
     "\tvoid showAdministratorBox(); // pluma\n"),
    (INTRO_CODE, "\n} // namespace details\n} // namespace Intro\n",
     "\n" + LOGIN_CODE_ADMINISTRATOR_BOX + "\n} // namespace details\n} // namespace Intro\n"),
    (INTRO_CODE, ", _callTimer([=] { sendCall(); })\n",
     ", _callTimer([=] { sendCall(); })\n"
     ", _resendTimer([=] { updateCallText(); }) // pluma\n"),
    (INTRO_CODE, LOGIN_CODE_TITLE_OLD, LOGIN_CODE_TITLE_NEW),
    (INTRO_CODE, "\treturn contentTop() + st::introErrorBelowLinkTop;\n",
     "\treturn contentTop()\n"
     "\t\t+ st::introErrorBelowLinkTop\n"
     "\t\t+ contentShift(); // pluma: under a longer description\n"),
    (INTRO_CODE, LOGIN_CODE_CALL_TEXT_OLD, LOGIN_CODE_CALL_TEXT_NEW),
    (INTRO_CODE, "\t\tcontentTop() + st::introStepFieldTop + st::introPhoneTop * 3);\n",
     "\t\tcontentTop()\n"
     "\t\t\t+ st::introStepFieldTop\n"
     "\t\t\t+ st::introPhoneTop * 3\n"
     "\t\t\t+ contentShift()); // pluma: under a longer description\n"),
    (INTRO_CODE, "\tif (getData()->codeByTelegram) {\n\t\t_noTelegramCode->show();\n\t} else {\n"
                 "\t\t_callLabel->show();\n\t}\n\tsetInnerFocus();\n",
     "\t// pluma: the row under the field of task 076's screens.\n"
     "\tif (_mode.current() != Mode::Default) {\n"
     "\t\tupdateCallText();\n"
     "\t} else {\n"
     "\t\t_callLabel->show();\n"
     "\t}\n"
     "\tsetInnerFocus();\n"),
    (INTRO_CODE, "\t_callTimer.cancel();\n\tapiClear();\n",
     "\t_callTimer.cancel();\n"
     "\t_resendTimer.cancel(); // pluma\n"
     "\tapiClear();\n"),
    (INTRO_CODE, "\t\tgetData()->codeByTelegram = false;\n\t\tupdateDescText();\n",
     "\t\t// pluma: the answer decides the screen (task 076); upstream took\n"
     "\t\t// every resent code for an SMS.\n"
     "\t\tupdateDescText();\n"),
)


def login_code_edited():
    """The files login_code_screens() edits."""
    return (LANG, INTRO_CODE, INTRO_CODE_H, INTRO_STEP, INTRO_STEP_H, INTRO_WIDGET, INTRO_WIDGET_H, MAIN_WINDOW,
            MAIN_WINDOW_H, MAINWINDOW, MAINWINDOW_H)


def login_code_strings():
    return "".join(f'"{key}" = "{value}";\n' for key, value in LOGIN_CODE_STRINGS.items())


def login_code_screens(tree):
    """Runs after rebrand(): its texts name the real Telegram."""
    tree.replace(LANG, LOGIN_CODE_STRINGS_AFTER, LOGIN_CODE_STRINGS_AFTER + login_code_strings())
    for rel, old, new in LOGIN_CODE_EDITS:
        tree.replace(rel, old, new)
    for head, body, had in LOGIN_CODE_BODIES:
        tree.replace_body(INTRO_CODE, head, "\n}\n", body, must_contain=had)


def verify_login_code_screens(tree):
    entries = [(m["key"], m["value"]) for m in lang_entries(tree.read(LANG))]
    for key, value in LOGIN_CODE_STRINGS.items():
        if entries.count((key, value)) != 1 or [k for k, _ in entries].count(key) != 1:
            raise PatchError(f"{LANG}: {key} is not the text of the login code screens (task 076)")
    for rel, old, new in LOGIN_CODE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of the login code screens (task 076) is not there")
    code = tree.read(INTRO_CODE)
    for head, body, _ in LOGIN_CODE_BODIES:
        if code.count(head + body + "\n}\n") != 1:
            raise PatchError(f"{INTRO_CODE}: {head.strip()} is not the one of the login code screens (task 076)")
    for rel in (INTRO_CODE, INTRO_CODE_H):
        if "_isFragment" in tree.read(rel) or "introFragmentButton" in tree.read(rel):
            raise PatchError(f"{rel}: the code step still shows Fragment's screen")


# --- Call parameters from the server (task 077) ------------------------------
# The quality of a 1:1 call is set in tgcalls by literals that no setting
# reaches (docs/tasks/077-research of the server repository, audio.md and
# video.md, read at the tgcalls commit 1c236c09 this release pins). The server
# sends values in phoneCall.custom_parameters, a JSON object; tgcalls already
# parses it into a map for its network_* keys (v2/InstanceV2Impl.cpp, the
# constructor), but tdesktop, unlike Android and iOS, never passed it
# (calls_call.cpp, createAndStartController). Each key replaces one literal
# where tgcalls sets it today. A key that is absent, not a number or outside
# the range the server accepts (pkg/phonecalls/parameters.go) keeps
# upstream's value, so a server that sends nothing gets Telegram's behaviour,
# for an A/B comparison. The server's kbit/s count 1000 bit/s, while upstream
# writes its own rates as kbit * 1024 (32 * 1024), so the members hold bit/s:
#   audio_ptime_ms          Opus packet time of the sender, 60 ms upstream
#                           (10, 20, 40, 60 or 120);
#   audio_max_bitrate_kbps  the Opus cap, 32 * 1024 bit/s upstream (6-128);
#   audio_min_bitrate_kbps  with the cap, the range the bandwidth estimate
#                           moves Opus in (WebRTC-Audio-Allocation); upstream
#                           holds Opus at the cap (min = max,
#                           WebRtcAudioSendStream::UpdateAllowedBitrateRange)
#                           (6-128);
#   audio_jitter_min_ms     the receiver's jitter buffer floor, 50 ms
#                           upstream (1-500);
#   audio_rnnoise           RNNoise after the classic noise suppressor, as in
#                           group calls; off upstream (true/false);
#   video_max_bitrate_kbps  the camera cap, 1000 * 1024 bit/s upstream
#                           (100-20000);
#   screen_max_bitrate_kbps the screen cap; upstream sets none, WebRTC's
#                           default by frame size applies (100-20000);
#   start_bitrate_kbps      the start of the bandwidth estimate (CallConfig
#                           bitrate_config); upstream sets none, WebRTC starts
#                           at 300 kbit/s (30-20000);
#   video_fps               the rate the camera is adapted to, 25 upstream
#                           (VideoCaptureInterfaceImpl.cpp 129, 131), set on
#                           the capture when the call takes the camera, as on
#                           iOS (1-60). It acts on macOS only: there
#                           adaptVideoSource drops frames of the 30 the camera
#                           captures (DarwinInterface.mm 120-121,
#                           VideoCapturerInterfaceImpl.mm 236); on Windows and
#                           Linux adaptVideoSource does nothing
#                           (DesktopInterface.cpp 45-46) and the camera runs at
#                           the 30 it asks the device for (VideoCameraCapturer
#                           .cpp 21-23), which the key does not change.
#                           The rate stays on the capture object: a call
#                           moved to a conference hands it over
#                           (calls_call.cpp 448), so on macOS the
#                           conference keeps the call's rate;
#   screen_fps              the rate of a shared screen, upstream 24 on Windows
#                           and Linux (VideoCapturerInterfaceImpl.cpp 48-51)
#                           and 25 on macOS (DesktopSharingCapturer.mm 72-76)
#                           (1-60);
#   screen_max_size_px      the long side of a shared screen; upstream halves a
#                           frame at least twice 1280x720 (1920x1080 on macOS)
#                           and sends a smaller one whole
#                           (DesktopCaptureSourceHelper.cpp,
#                           SourceFrameCallbackImpl::OnCaptureResult); with the
#                           key a larger frame is scaled down to it whole and a
#                           smaller one is sent as it is (320-3840).
# The screen capture is not the call's: tdesktop makes it outside the call and
# shares it in the process (calls_instance.cpp 1028-1049,
# Instance::getVideoCapture; the source previews of
# desktop_capture_choose_source.cpp make their own). So the engine sets the two
# screen keys process-wide (SetCallScreenCaptureLimits) when it starts and
# clears them when it goes, and only the screen capturers of a call
# (DesktopCaptureSourceData::followsCallLimits) read them, on every frame, so
# a share started before the call connected follows them too. One private
# call runs at a time, and none beside a group call (calls_instance.cpp 705,
# 346): a group call's screen, made by the same capturer
# (calls_group_call.cpp 2903-2906), keeps upstream's values, and a call moved
# to a conference hands its capture over with upstream's from its end.
# The library version the server negotiates between native clients, 9.0.0,
# runs InstanceV2Impl, the engine edited here.
TGCALLS = "Telegram/ThirdParty/tgcalls"
TGCALLS_V2 = TGCALLS + "/tgcalls/v2/InstanceV2Impl.cpp"
TGCALLS_CUSTOM_PARAMETERS = TGCALLS + "/tgcalls/v2/CustomParameters.h"
TGCALLS_CAPTURE = TGCALLS + "/tgcalls/VideoCaptureInterfaceImpl.cpp"
TGCALLS_CAPTURE_HEADER = TGCALLS + "/tgcalls/VideoCaptureInterfaceImpl.h"
TGCALLS_SCREEN_SOURCE = TGCALLS + "/tgcalls/desktop_capturer/DesktopCaptureSource.h"
TGCALLS_SCREEN_HELPER = TGCALLS + "/tgcalls/desktop_capturer/DesktopCaptureSourceHelper.cpp"
TGCALLS_SCREEN_HELPER_HEADER = TGCALLS + "/tgcalls/desktop_capturer/DesktopCaptureSourceHelper.h"
TGCALLS_SCREEN_WINDOWS_LINUX = TGCALLS + "/tgcalls/platform/tdesktop/VideoCapturerInterfaceImpl.cpp"
TGCALLS_SCREEN_MACOS = TGCALLS + "/tgcalls/platform/darwin/DesktopSharingCapturer.mm"
CALLS_CALL = SOURCES + "/calls/calls_call.cpp"
CALL_PARAMETERS_EDITS = (
    (CALLS_CALL,
     "\t\t\t.maxApiLayer = protocol.vmax_layer().v,\n\t\t},\n",
     "\t\t\t.maxApiLayer = protocol.vmax_layer().v,\n"
     "\t\t\t// pluma: the call's parameters from the server, which tgcalls\n"
     "\t\t\t// reads (task 077); upstream does not pass them.\n"
     "\t\t\t.customParameters = (call.vcustom_parameters()\n"
     "\t\t\t\t? call.vcustom_parameters()->c_dataJSON().vdata().v.toStdString()\n"
     "\t\t\t\t: std::string()),\n"
     "\t\t},\n"),
    (TGCALLS_CUSTOM_PARAMETERS,
     "} // namespace tgcalls\n\n#endif\n",
     "// pluma: an integer key read against upstream's own value. An absent key, a\n"
     "// value that is not a number or one outside [minValue, maxValue] reads as\n"
     "// defaultValue, so a server value of 0 differs from an absent key and a value\n"
     "// out of range keeps upstream's behaviour. A fraction is truncated.\n"
     "inline int getCustomParameterIntOr(std::map<std::string, json11::Json> const &parameters, std::string const &name, "
     "int defaultValue, int minValue, int maxValue) {\n"
     "    const auto value = parameters.find(name);\n"
     "    if (value != parameters.end() && value->second.is_number()) {\n"
     "        const double number = value->second.number_value();\n"
     "        if (number >= minValue && number <= maxValue) {\n"
     "            return static_cast<int>(number);\n"
     "        }\n"
     "    }\n"
     "    return defaultValue;\n"
     "}\n"
     "\n"
     "// pluma: a rate key in kbit/s of the server, which counts 1000 bit/s, as\n"
     "// bit/s; defaultBps (upstream's own value, which counts a kbit as 1024 bit)\n"
     "// when the key is absent, not a number or outside [minKbps, maxKbps].\n"
     "// minKbps is above 0.\n"
     "inline int getCustomParameterKbpsAsBps(std::map<std::string, json11::Json> const &parameters, std::string const &name, "
     "int defaultBps, int minKbps, int maxKbps) {\n"
     "    const int kbps = getCustomParameterIntOr(parameters, name, 0, minKbps, maxKbps);\n"
     "    return kbps > 0 ? kbps * 1000 : defaultBps;\n"
     "}\n"
     "\n"
     "} // namespace tgcalls\n\n#endif\n"),
    (TGCALLS_V2,
     "#include <random>\n#include <sstream>\n",
     "#include <random>\n#include <sstream>\n"
     "// pluma: the field trials, the noise suppression and the screen limits of a\n"
     "// call (task 077).\n"
     "#include <cmath>\n"
     "#include <cstring>\n"
     "#include <mutex>\n"
     "#include <set>\n"
     "#include \"modules/audio_processing/include/audio_processing.h\"\n"
     "#include \"desktop_capturer/DesktopCaptureSourceHelper.h\"\n"
     "\n"
     "#ifndef USE_RNNOISE\n"
     "#define USE_RNNOISE 1\n"
     "#endif\n"
     "\n"
     "#if USE_RNNOISE\n"
     "#include \"rnnoise.h\"\n"
     "#endif\n"),
    (TGCALLS_V2,
     "class OutgoingAudioChannel : public sigslot::has_slots<> {\n",
     "// pluma: WebRTC keeps the pointer to the field trial string it is given\n"
     "// (field_trial::InitFieldTrialsFromString) and reads it until the next\n"
     "// call replaces it, which may come from another engine. Each distinct\n"
     "// string a call builds therefore stays allocated for the life of the\n"
     "// process; the server sends a few distinct values at most.\n"
     "static const char *PersistentFieldTrials(std::string const &fieldTrials) {\n"
     "    static std::mutex mutex;\n"
     "    static std::set<std::string> *strings = new std::set<std::string>();\n"
     "    std::lock_guard<std::mutex> lock(mutex);\n"
     "    return strings->insert(fieldTrials).first->c_str();\n"
     "}\n"
     "\n"
     "#if USE_RNNOISE\n"
     "// pluma: RNNoise on the captured voice, as group calls run it\n"
     "// (group/GroupInstanceCustomImpl.cpp, AudioCapturePostProcessor), when\n"
     "// the server asks for it with audio_rnnoise (task 077); the classic\n"
     "// noise suppressor stays on before it, as there. RNNoise takes 10 ms at\n"
     "// 48 kHz, the rate the capture is processed at for Opus; a buffer of\n"
     "// another size or with more channels passes unchanged.\n"
     "class RnnoiseCapturePostProcessor : public webrtc::CustomProcessing {\n"
     "public:\n"
     "    RnnoiseCapturePostProcessor() :\n"
     "    _denoiseState(rnnoise_create(nullptr)),\n"
     "    _frameSamples(rnnoise_get_frame_size()) {\n"
     "    }\n"
     "\n"
     "    ~RnnoiseCapturePostProcessor() override {\n"
     "        if (_denoiseState) {\n"
     "            rnnoise_destroy(_denoiseState);\n"
     "        }\n"
     "    }\n"
     "\n"
     "private:\n"
     "    void Initialize(int sample_rate_hz, int num_channels) override {\n"
     "    }\n"
     "\n"
     "    void Process(webrtc::AudioBuffer *buffer) override {\n"
     "        if (!buffer || !_denoiseState || buffer->num_channels() != 1 || buffer->num_frames() != _frameSamples.size()) {\n"
     "            return;\n"
     "        }\n"
     "        float *samples = buffer->channels()[0];\n"
     "        float peak = 0.0f;\n"
     "        for (size_t i = 0; i < _frameSamples.size(); i++) {\n"
     "            peak = std::max(std::fabs(samples[i]), peak);\n"
     "        }\n"
     "        // Silence is left alone, as in group calls.\n"
     "        if (peak < 0.01f) {\n"
     "            return;\n"
     "        }\n"
     "        rnnoise_process_frame(_denoiseState, _frameSamples.data(), samples);\n"
     "        std::memcpy(samples, _frameSamples.data(), _frameSamples.size() * sizeof(float));\n"
     "    }\n"
     "\n"
     "    std::string ToString() const override {\n"
     "        return \"RnnoiseCapturePostProcessor\";\n"
     "    }\n"
     "\n"
     "    void SetRuntimeSetting(webrtc::AudioProcessing::RuntimeSetting setting) override {\n"
     "    }\n"
     "\n"
     "    DenoiseState *_denoiseState = nullptr;\n"
     "    std::vector<float> _frameSamples;\n"
     "};\n"
     "#endif\n"
     "\n"
     "class OutgoingAudioChannel : public sigslot::has_slots<> {\n"),
    (TGCALLS_V2,
     "        std::shared_ptr<Threads> threads\n    ) :\n    _threads(threads),\n    _ssrc(mediaContent.ssrc),\n    _call(call),\n",
     "        std::shared_ptr<Threads> threads,\n"
     "        int packetTimeMs // pluma: the Opus packet time, upstream 60 ms\n"
     "    ) :\n    _threads(threads),\n    _ssrc(mediaContent.ssrc),\n    _call(call),\n"),
    (TGCALLS_V2,
     "                codec.SetParam(cricket::kCodecParamPTime, 60);\n",
     "                codec.SetParam(cricket::kCodecParamPTime, packetTimeMs); // pluma: upstream 60\n"),
    (TGCALLS_V2,
     "        std::function<void(float)> onAudioLevelUpdated,\n        std::shared_ptr<Threads> threads) :\n",
     "        std::function<void(float)> onAudioLevelUpdated,\n"
     "        std::shared_ptr<Threads> threads,\n"
     "        int jitterBufferMinDelayMs) : // pluma: the jitter buffer floor, upstream 50 ms\n"),
    (TGCALLS_V2,
     "        audioOptions.audio_jitter_buffer_min_delay_ms = 50;\n",
     "        audioOptions.audio_jitter_buffer_min_delay_ms = jitterBufferMinDelayMs; // pluma: upstream 50\n"),
    (TGCALLS_V2,
     "        webrtc::field_trial::InitFieldTrialsFromString(\n"
     "            \"WebRTC-DataChannel-Dcsctp/Enabled/\"\n"
     "            \"WebRTC-Audio-MinimizeResamplingOnMobile/Enabled/\"\n"
     "            \"WebRTC-Audio-iOS-Holding/Enabled/\"\n"
     "            \"WebRTC-IceFieldTrials/skip_relay_to_non_relay_connections:true/\"\n"
     "        );\n"
     "        \n"
     "        if (!descriptor.config.customParameters.empty()) {\n"
     "            std::string parsingError;\n"
     "            auto customParametersJson = json11::Json::parse(descriptor.config.customParameters, parsingError);\n"
     "            if (customParametersJson.is_object()) {\n"
     "                _customParameters = customParametersJson.object_items();\n"
     "            }\n"
     "        }\n",
     "        if (!descriptor.config.customParameters.empty()) {\n"
     "            std::string parsingError;\n"
     "            auto customParametersJson = json11::Json::parse(descriptor.config.customParameters, parsingError);\n"
     "            if (customParametersJson.is_object()) {\n"
     "                _customParameters = customParametersJson.object_items();\n"
     "            }\n"
     "        }\n"
     "\n"
     "        // pluma: the quality of the call from the server's custom parameters\n"
     "        // (task 077), read before the field trials, which depend on them. An\n"
     "        // absent key keeps upstream's value; the server's kbit/s count 1000\n"
     "        // bit/s, the members hold bit/s.\n"
     "        _audioPtimeMs = getCustomParameterIntOr(_customParameters, \"audio_ptime_ms\", 60, 10, 120);\n"
     "        if (_audioPtimeMs != 10 && _audioPtimeMs != 20 && _audioPtimeMs != 40 && _audioPtimeMs != 120) {\n"
     "            _audioPtimeMs = 60; // the server sends 10, 20, 40, 60 or 120 ms\n"
     "        }\n"
     "        _audioMaxBitrateBps = getCustomParameterKbpsAsBps(_customParameters, \"audio_max_bitrate_kbps\", 32 * 1024, 6, 128);\n"
     "        const int audioMinBitrateBps = getCustomParameterKbpsAsBps(_customParameters, \"audio_min_bitrate_kbps\", 0, 6, 128);\n"
     "        _audioJitterBufferMinDelayMs = getCustomParameterIntOr(_customParameters, \"audio_jitter_min_ms\", 50, 1, 500);\n"
     "        _audioRnnoise = getCustomParameterBool(_customParameters, \"audio_rnnoise\");\n"
     "        _videoMaxBitrateBps = getCustomParameterKbpsAsBps(_customParameters, \"video_max_bitrate_kbps\", 1000 * 1024, 100, 20000);\n"
     "        _screencastMaxBitrateBps = getCustomParameterKbpsAsBps(_customParameters, \"screen_max_bitrate_kbps\", 0, 100, 20000);\n"
     "        _startBitrateBps = getCustomParameterKbpsAsBps(_customParameters, \"start_bitrate_kbps\", 0, 30, 20000);\n"
     "        _videoFps = getCustomParameterIntOr(_customParameters, \"video_fps\", 0, 1, 60);\n"
     "        const int screenFps = getCustomParameterIntOr(_customParameters, \"screen_fps\", 0, 1, 60);\n"
     "        const int screenMaxSidePx = getCustomParameterIntOr(_customParameters, \"screen_max_size_px\", 0, 320, 3840);\n"
     "        // The screen capture is the process's, not the call's: this call owns\n"
     "        // its limits until the destructor clears them; 0 keeps upstream's.\n"
     "        SetCallScreenCaptureLimits(this, screenMaxSidePx, screenFps);\n"
     "\n"
     "        std::string fieldTrials =\n"
     "            \"WebRTC-DataChannel-Dcsctp/Enabled/\"\n"
     "            \"WebRTC-Audio-MinimizeResamplingOnMobile/Enabled/\"\n"
     "            \"WebRTC-Audio-iOS-Holding/Enabled/\"\n"
     "            \"WebRTC-IceFieldTrials/skip_relay_to_non_relay_connections:true/\";\n"
     "        // Without a range the send stream holds Opus at its target (min = max,\n"
     "        // WebRtcAudioSendStream::UpdateAllowedBitrateRange); the trial lets the\n"
     "        // bandwidth estimate move it between the two\n"
     "        // (AudioSendStream::GetMinMaxBitrateConstraints).\n"
     "        if (audioMinBitrateBps != 0 && audioMinBitrateBps <= _audioMaxBitrateBps) {\n"
     "            fieldTrials += \"WebRTC-Audio-Allocation/min:\" + std::to_string(audioMinBitrateBps) + \"bps,max:\" "
     "+ std::to_string(_audioMaxBitrateBps) + \"bps/\";\n"
     "        }\n"
     "        webrtc::field_trial::InitFieldTrialsFromString(PersistentFieldTrials(fieldTrials));\n"
     "        RTC_LOG(LS_INFO) << \"Call quality: ptime \" << _audioPtimeMs << \" ms, audio \" << audioMinBitrateBps << \"-\" "
     "<< _audioMaxBitrateBps << \" bps, jitter floor \" << _audioJitterBufferMinDelayMs << \" ms, rnnoise \" "
     "<< _audioRnnoise << \", video \" << _videoMaxBitrateBps << \", screen \" << _screencastMaxBitrateBps "
     "<< \", start \" << _startBitrateBps << \" bps, camera \" << _videoFps << \" fps, screen \" << screenMaxSidePx "
     "<< \" px at \" << screenFps << \" fps\";\n"),
    (TGCALLS_V2,
     "            callConfig.audio_state = _channelManager->media_engine()->voice().GetAudioState();\n",
     "            callConfig.audio_state = _channelManager->media_engine()->voice().GetAudioState();\n"
     "            // pluma: the start of the bandwidth estimate; upstream keeps WebRTC's 300 kbit/s.\n"
     "            if (_startBitrateBps != 0) {\n"
     "                callConfig.bitrate_config.start_bitrate_bps = _startBitrateBps;\n"
     "            }\n"),
    (TGCALLS_V2,
     "                            outgoingAudioContent.value(),\n                            _threads\n                        ));\n",
     "                            outgoingAudioContent.value(),\n"
     "                            _threads,\n"
     "                            _audioPtimeMs\n"
     "                        ));\n"),
    (TGCALLS_V2,
     "                            _audioLevelUpdated,\n                            _threads\n                        ));\n",
     "                            _audioLevelUpdated,\n"
     "                            _threads,\n"
     "                            _audioJitterBufferMinDelayMs\n"
     "                        ));\n"),
    (TGCALLS_V2,
     "        webrtc::AudioProcessingBuilder builder;\n"
     "        peerConnectionFactoryDependencies.audio_processing = builder.Create();\n",
     "        webrtc::AudioProcessingBuilder builder;\n"
     "#if USE_RNNOISE\n"
     "        // pluma: RNNoise on the captured voice when the server switches it on.\n"
     "        if (_audioRnnoise) {\n"
     "            builder.SetCapturePostProcessing(std::make_unique<RnnoiseCapturePostProcessor>());\n"
     "        }\n"
     "#endif\n"
     "        peerConnectionFactoryDependencies.audio_processing = builder.Create();\n"),
    (TGCALLS_V2,
     "        if (_outgoingAudioChannel) {\n"
     "            _outgoingAudioChannel->setMaxBitrate(32 * 1024);\n"
     "        }\n"
     "        if (_outgoingVideoChannel) {\n"
     "            _outgoingVideoChannel->setMaxBitrate(1000 * 1024);\n"
     "        }\n",
     "        // pluma: the caps of the custom parameters; upstream's are 32 and 1000 kbit, the screen has none.\n"
     "        if (_outgoingAudioChannel) {\n"
     "            _outgoingAudioChannel->setMaxBitrate(_audioMaxBitrateBps);\n"
     "        }\n"
     "        if (_outgoingVideoChannel) {\n"
     "            _outgoingVideoChannel->setMaxBitrate(_videoMaxBitrateBps);\n"
     "        }\n"
     "        if (_outgoingScreencastChannel && _screencastMaxBitrateBps != 0) {\n"
     "            _outgoingScreencastChannel->setMaxBitrate(_screencastMaxBitrateBps);\n"
     "        }\n"),
    (TGCALLS_V2,
     "    std::map<std::string, json11::Json> _customParameters;\n",
     "    std::map<std::string, json11::Json> _customParameters;\n"
     "    // pluma: the quality of the call, read from _customParameters in the\n"
     "    // constructor; upstream's values until then.\n"
     "    int _audioPtimeMs = 60;\n"
     "    int _audioMaxBitrateBps = 32 * 1024;\n"
     "    int _audioJitterBufferMinDelayMs = 50;\n"
     "    bool _audioRnnoise = false;\n"
     "    int _videoMaxBitrateBps = 1000 * 1024;\n"
     "    int _screencastMaxBitrateBps = 0;\n"
     "    int _startBitrateBps = 0;\n"
     "    int _videoFps = 0; // the capture's own adaptation, 25\n"),
    # The screen limits belong to the call that set them until it goes.
    (TGCALLS_V2,
     "    ~InstanceV2ImplInternal() {\n",
     "    ~InstanceV2ImplInternal() {\n"
     "        ClearCallScreenCaptureLimits(this); // pluma: task 077\n"),
    # The camera's frame rate, as on iOS.
    (TGCALLS_V2,
     "                _videoCapture = videoCapture;\n                _screencastCapture = nullptr;\n",
     "                _videoCapture = videoCapture;\n"
     "                _screencastCapture = nullptr;\n"
     "                // pluma: 25 upstream; phoneCall.custom_parameters may set it (task 077).\n"
     "                if (_videoFps != 0) {\n"
     "                    videoCaptureImpl->setAdaptationFramerate(_videoFps);\n"
     "                }\n"),
    (TGCALLS_CAPTURE_HEADER,
     "    void setPreferredAspectRatio(float aspectRatio);\n",
     "    void setPreferredAspectRatio(float aspectRatio);\n"
     "    void setAdaptationFramerate(int framerate); // pluma: task 077\n"),
    (TGCALLS_CAPTURE_HEADER,
     "    bool _isScreenCapture = false;\n",
     "    bool _isScreenCapture = false;\n"
     "    int _adaptationFramerate = 25; // pluma: upstream's literal of updateAspectRateAdaptation (task 077)\n"),
    (TGCALLS_CAPTURE,
     "void VideoCaptureInterfaceObject::setPreferredAspectRatio(float aspectRatio) {\n"
     "    _preferredAspectRatio = aspectRatio;\n"
     "    updateAspectRateAdaptation();\n"
     "}\n",
     "void VideoCaptureInterfaceObject::setPreferredAspectRatio(float aspectRatio) {\n"
     "    _preferredAspectRatio = aspectRatio;\n"
     "    updateAspectRateAdaptation();\n"
     "}\n"
     "\n"
     "// pluma: the frame rate the camera is adapted to, 25 upstream (task 077).\n"
     "void VideoCaptureInterfaceObject::setAdaptationFramerate(int framerate) {\n"
     "    if (_adaptationFramerate != framerate) {\n"
     "        _adaptationFramerate = framerate;\n"
     "        updateAspectRateAdaptation();\n"
     "    }\n"
     "}\n"),
    (TGCALLS_CAPTURE,
     "adaptVideoSource(_videoSource, (int)width, (int)height, 25);\n",
     "adaptVideoSource(_videoSource, (int)width, (int)height, _adaptationFramerate);\n"),
    (TGCALLS_CAPTURE,
     "adaptVideoSource(_videoSource, _videoCapturerResolution.first, _videoCapturerResolution.second, 25);\n",
     "adaptVideoSource(_videoSource, _videoCapturerResolution.first, _videoCapturerResolution.second, "
     "_adaptationFramerate);\n"),
    # The screen limits of the private call in progress, read by the screen
    # capturers of calls on every frame.
    (TGCALLS_SCREEN_SOURCE,
     "\tbool captureMouse = true;\n\n\tstd::string cachedKey() const;\n",
     "\tbool captureMouse = true;\n"
     "\t// pluma: a screen shared in a call follows the limits of the private call\n"
     "\t// in progress (SetCallScreenCaptureLimits, task 077) where it sets them,\n"
     "\t// in place of aspectSize's halving and fps; source previews do not.\n"
     "\tbool followsCallLimits = false;\n"
     "\n"
     "\tstd::string cachedKey() const;\n"),
    (TGCALLS_SCREEN_HELPER_HEADER,
     "bool ShouldBeDesktopCapture(const std::string &uniqueKey);\n",
     "bool ShouldBeDesktopCapture(const std::string &uniqueKey);\n"
     "\n"
     "// pluma: the long side in pixels and the frame rate of a screen shared in\n"
     "// the private call in progress, from its custom_parameters (task 077); 0\n"
     "// keeps the capture's own value. The capture belongs to the process, not to\n"
     "// the call, so the call that set the limits last owns them until it clears\n"
     "// them; a clear by another call does nothing.\n"
     "void SetCallScreenCaptureLimits(const void *call, int maxSide, int fps);\n"
     "void ClearCallScreenCaptureLimits(const void *call);\n"),
    (TGCALLS_SCREEN_HELPER,
     "#include <vector>\n#include <functional>\n",
     "#include <vector>\n#include <functional>\n"
     "// pluma: the screen limits of a private call (task 077).\n"
     "#include <atomic>\n"
     "#include <mutex>\n"),
    (TGCALLS_SCREEN_HELPER,
     "class SourceFrameCallbackImpl : public webrtc::DesktopCapturer::Callback {\n"
     "public:\n"
     "    SourceFrameCallbackImpl(DesktopSize size, int fps);\n",
     "// pluma: the limits of SetCallScreenCaptureLimits. The owner changes under\n"
     "// the mutex; the capture reads the values on every frame without it.\n"
     "std::mutex CallScreenLimitsMutex;\n"
     "const void *CallScreenLimitsOwner = nullptr;\n"
     "std::atomic<int> CallScreenMaxSide{ 0 };\n"
     "std::atomic<int> CallScreenFps{ 0 };\n"
     "\n"
     "class SourceFrameCallbackImpl : public webrtc::DesktopCapturer::Callback {\n"
     "public:\n"
     "    SourceFrameCallbackImpl(DesktopSize size, int fps, bool followsCallLimits);\n"),
    (TGCALLS_SCREEN_HELPER,
     "    DesktopSize size_;\n",
     "    DesktopSize size_;\n"
     "    bool followsCallLimits_ = false; // pluma: task 077\n"),
    (TGCALLS_SCREEN_HELPER,
     "SourceFrameCallbackImpl::SourceFrameCallbackImpl(DesktopSize size, int fps)\n: size_(size) {\n}\n",
     "SourceFrameCallbackImpl::SourceFrameCallbackImpl(DesktopSize size, int fps, bool followsCallLimits)\n"
     ": size_(size)\n"
     ", followsCallLimits_(followsCallLimits) {\n"
     "}\n"),
    (TGCALLS_SCREEN_HELPER,
     "        ? DesktopSize{ frameSize.width() / 2, frameSize.height() / 2 }\n"
     "        : DesktopSize{ frameSize.width(), frameSize.height() };\n",
     "        ? DesktopSize{ frameSize.width() / 2, frameSize.height() / 2 }\n"
     "        : DesktopSize{ frameSize.width(), frameSize.height() };\n"
     "    // pluma: the long side the private call sets, if any: a larger frame is\n"
     "    // scaled down to it whole, a smaller one is sent as it is (task 077).\n"
     "    if (const auto maxSide = followsCallLimits_ ? CallScreenMaxSide.load() : 0) {\n"
     "        const auto longSide = std::max(frameSize.width(), frameSize.height());\n"
     "        fittedSize = (longSide > maxSide)\n"
     "            ? DesktopSize{\n"
     "                int((long long)frameSize.width() * maxSide / longSide),\n"
     "                int((long long)frameSize.height() * maxSide / longSide) }\n"
     "            : DesktopSize{ frameSize.width(), frameSize.height() };\n"
     "    }\n"),
    (TGCALLS_SCREEN_HELPER,
     "    bool _currentlyOnPause = false;\n    double _delayMs = 0.;\n",
     "    bool _currentlyOnPause = false;\n"
     "    double _delayMs = 0.;\n"
     "    bool _followsCallLimits = false; // pluma: task 077\n"),
    (TGCALLS_SCREEN_HELPER,
     ", _callback(data.aspectSize, data.fps)\n, _delayMs(1000. / data.fps) {\n",
     ", _callback(data.aspectSize, data.fps, data.followsCallLimits)\n"
     ", _delayMs(1000. / data.fps)\n"
     ", _followsCallLimits(data.followsCallLimits) {\n"),
    (TGCALLS_SCREEN_HELPER,
     "    _scheduler.runDelayed(_delayMs, [=, this] {\n",
     "    // pluma: the frame rate the private call sets, if any (task 077).\n"
     "    const auto callFps = _followsCallLimits ? CallScreenFps.load() : 0;\n"
     "    _scheduler.runDelayed((callFps > 0) ? (1000. / callFps) : _delayMs, [=, this] {\n"),
    (TGCALLS_SCREEN_HELPER,
     "bool ShouldBeDesktopCapture(const std::string &uniqueKey) {\n"
     "    return (uniqueKey.find(\"desktop_capturer_\") == 0);\n"
     "}\n",
     "bool ShouldBeDesktopCapture(const std::string &uniqueKey) {\n"
     "    return (uniqueKey.find(\"desktop_capturer_\") == 0);\n"
     "}\n"
     "\n"
     "// pluma: task 077.\n"
     "void SetCallScreenCaptureLimits(const void *call, int maxSide, int fps) {\n"
     "    std::lock_guard<std::mutex> lock(CallScreenLimitsMutex);\n"
     "    CallScreenLimitsOwner = call;\n"
     "    CallScreenMaxSide = maxSide;\n"
     "    CallScreenFps = fps;\n"
     "}\n"
     "\n"
     "void ClearCallScreenCaptureLimits(const void *call) {\n"
     "    std::lock_guard<std::mutex> lock(CallScreenLimitsMutex);\n"
     "    if (CallScreenLimitsOwner == call) {\n"
     "        CallScreenLimitsOwner = nullptr;\n"
     "        CallScreenMaxSide = 0;\n"
     "        CallScreenFps = 0;\n"
     "    }\n"
     "}\n"),
    # The screen capturers of calls: Windows and Linux, macOS.
    (TGCALLS_SCREEN_WINDOWS_LINUX,
     "\t\t\t/*.fps = */24.,\n\t\t\t/*.captureMouse = */true,\n\t\t};\n",
     "\t\t\t/*.fps = */24.,\n"
     "\t\t\t/*.captureMouse = */true,\n"
     "\t\t\t/*.followsCallLimits = */true, // pluma: task 077\n"
     "\t\t};\n"),
    (TGCALLS_SCREEN_MACOS,
     "\t        /*.fps = */25,\n\t        /*.captureMouse = */true,\n        };\n",
     "\t        /*.fps = */25,\n"
     "\t        /*.captureMouse = */true,\n"
     "\t        /*.followsCallLimits = */true, // pluma: task 077\n"
     "        };\n"),
)
# The keys the edits read, each exactly once.
CALL_PARAMETER_KEYS = ("audio_ptime_ms", "audio_max_bitrate_kbps", "audio_min_bitrate_kbps", "audio_jitter_min_ms",
                       "audio_rnnoise", "video_max_bitrate_kbps", "screen_max_bitrate_kbps", "start_bitrate_kbps",
                       "video_fps", "screen_fps", "screen_max_size_px")
# What the edits replace may stay nowhere else: another place that sets the
# same value would escape the server's (upstream adding one stops the patch
# until it is read).
CALL_PARAMETERS_GUARDS = (
    (TGCALLS_V2, "kCodecParamPTime", 1),
    (TGCALLS_V2, "audio_jitter_buffer_min_delay_ms", 1),
    (TGCALLS_V2, "InitFieldTrialsFromString(", 1),
    (TGCALLS_V2, "->setMaxBitrate(", 3),
    (TGCALLS_V2, "SetCapturePostProcessing(", 1),
    (TGCALLS_V2, "bitrate_config", 1),
    (TGCALLS_V2, "new OutgoingAudioChannel(", 2),
    (TGCALLS_V2, "new IncomingV2AudioChannel(", 1),
    (CALLS_CALL, "tgcalls::Descriptor descriptor = {", 1),
    (TGCALLS_V2, "setAdaptationFramerate(", 1),
    (TGCALLS_V2, "SetCallScreenCaptureLimits(", 1),
    (TGCALLS_V2, "ClearCallScreenCaptureLimits(", 1),
    (TGCALLS_CAPTURE, "adaptVideoSource(", 2),
    (TGCALLS_SCREEN_HELPER, "OnCaptureResult(", 2),
    (TGCALLS_SCREEN_HELPER, "_scheduler.runDelayed(", 1),
) + tuple((TGCALLS_V2, f'_customParameters, "{key}"', 1) for key in CALL_PARAMETER_KEYS)


def call_parameters(tree):
    for rel, old, new in CALL_PARAMETERS_EDITS:
        tree.replace(rel, old, new)


def verify_call_parameters(tree):
    for rel, old, new in CALL_PARAMETERS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the call parameters from the server (task 077) are not read there")
    for rel, s, count in CALL_PARAMETERS_GUARDS:
        found = tree.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; "
                             "another place sets what the server's call parameters should")


def call_parameters_edited():
    """The files call_parameters() edits."""
    return tuple(sorted({rel for rel, _, _ in CALL_PARAMETERS_EDITS}))


# --- The service account (task 080) -------------------------------------------
# The account of the Pluma server (@support, user.support, no last seen)
# says "service account" where a person's last seen goes, not Telegram's
# "support" (the owner's decision, 2026-11-11). Every status line of a user
# takes the words from Data::OnlineTextSpecial (OnlineText and OnlineTextFull
# of data_peer_values.cpp: the top bar of a chat, the profile, the lists of
# people, the chat preview), which says lng_status_support twice: for
# user.support and for a service user (an id that is a multiple of 1000,
# PeerData::isServiceUser). The key keeps its name and both its uses, and
# gets Pluma's words: no source is edited. This is the built-in English;
# every other language comes from the server's language pack of tdesktop,
# where the server puts the same words under this key in each language
# (pkg/langpack/override.json of the server repository).
PEER_VALUES = SOURCES + "/data/data_peer_values.cpp"
SERVICE_ACCOUNT_KEY = "lng_status_support"
SERVICE_ACCOUNT_TEXT = "service account"
SERVICE_ACCOUNT_OLD = f'"{SERVICE_ACCOUNT_KEY}" = "support";\n'
SERVICE_ACCOUNT_NEW = f'"{SERVICE_ACCOUNT_KEY}" = "{SERVICE_ACCOUNT_TEXT}";\n'
# Who the key is said of. Upstream using it for anyone else, or anywhere
# else, stops the patch until that place is read.
SERVICE_ACCOUNT_USES = tuple(
    f"\t}} else if (user->{check}()) {{\n\t\treturn tr::{SERVICE_ACCOUNT_KEY}(tr::now);\n"
    for check in ("isSupport", "isServiceUser"))


def service_account(tree):
    for s in SERVICE_ACCOUNT_USES:
        tree.expect(PEER_VALUES, s)
    tree.replace(LANG, SERVICE_ACCOUNT_OLD, SERVICE_ACCOUNT_NEW)


def verify_service_account(tree):
    entries = [m["value"] for m in lang_entries(tree.read(LANG)) if m["key"] == SERVICE_ACCOUNT_KEY]
    if entries != [SERVICE_ACCOUNT_TEXT]:
        raise PatchError(f"{LANG}: {SERVICE_ACCOUNT_KEY} is not the text of the service account (task 080)")
    for rel in tree.sources():
        text = tree.scan(rel)
        if rel == PEER_VALUES:
            for s in SERVICE_ACCOUNT_USES:
                if text.count(s) != 1:
                    raise PatchError(f"{rel}: {SERVICE_ACCOUNT_KEY} is not said of {s.split('user->')[1].split('(')[0]} "
                                     "once; who the service account (task 080) is changed")
                text = text.replace(s, "")
        if SERVICE_ACCOUNT_KEY in text:
            raise PatchError(f"{rel}: another use of {SERVICE_ACCOUNT_KEY}, "
                             "which says \"service account\" (task 080)")


def service_account_edited():
    """The files service_account() edits."""
    return (LANG,)


# --- End-to-end group calls (task 094) -----------------------------------------
# Every group call of Pluma is end-to-end (ADR 0060 of the server repository,
# the owner's decision of 2026-11-12): the call of a group or a channel keeps
# the interface and the rights of a chat's call and takes the encryption of a
# conference. Upstream encrypts conferences alone: GroupCall::conference() is
# the origin of the shared call or the start of a conference
# (calls_group_call.cpp 1236-1243), a chat's call is made with
# GroupCallOrigin::Group (data_channel.cpp 1170-1176, data_chat.cpp 242), and
# public_key and block go only with an _e2e (calls_group_call.cpp 1650-1667),
# made in the constructor and in startRejoin() for a conference alone
# (:693-698, :1559-1561). Lines are of the pinned tdesktop and tgcalls, and of
# tde2e at td 51743df, which prepare.py builds (Telegram/build/prepare/
# prepare.py 1978-1981). The edits:
# - GroupCall::e2e(): a conference, or any call but a live story. Not by the
#   server's rtmp_stream, as the task's sketch had it: the server sets that
#   flag (calls_group_call.cpp 2364-2365, data_group_call.cpp 519), and a
#   server must not be able to take a call out of its encryption.
# - _e2e for every such call: in the constructor, in startRejoin(), and in
#   rejoin() when the key of the call has gone to the server already: the
#   chain keeps the key of a join it took (tde2e Call::create refuses a key
#   used before, Call.cpp 608-617, and the server too), and rejoin() runs again without startRejoin()
#   after checkGroupCall misses the ssrc (:3752-3756, checkNextJoinAction
#   :1948-1952), a duplicate ssrc (:1876-1878) or a speaker link
#   (rejoinWithHash :1569-1574).
# - The last block is asked for before every join of a chat's call
#   (refreshLastBlockAndJoin, :1632-1636): upstream skips it while a
#   conference's version is below 2 (Data::GroupCall::blockchainMayBeEmpty),
#   which a conference keeps. On an empty chain the answer has no block and
#   the join is the zero block (tde2e_api.cpp 288-296); two first joins race,
#   the second gets CONF_WRITE_CHAIN_INVALID and asks again (joinFail,
#   :1862-1870).
# - Members of the chain who left the call are removed from it, as a
#   conference's are: Data::GroupCall tracks them for a chat's call too
#   (data_group_call.cpp 71-96, checkStaleParticipants :233-255), the call
#   gives it the members of the chain through lookupReal() and not the
#   conference's _sharedCall (trackParticipantsWithAccess :806-820), and
#   removes them with deleteConferenceCallParticipants(only_left) (:822-860;
#   setupConferenceCall :799-805 for a conference).
# - The participants list shows the emoji of the key and the members of the
#   chain who are not in the call yet for every end-to-end call
#   (calls_group_members.cpp 553, 1768). Not the buttons that add members
#   and share an invite link (:1840): those are a conference's, and a chat's
#   call keeps its own.
# - Rejoins with a new key by the rules of ADR 0060 §5, one rule for the four
#   clients. Upstream rejoins on any failure of tde2e at once ("TdE2E: Got
#   failure, scheduling rejoin!", :786-789) and on GROUPCALL_FORBIDDEN of a
#   write to the chain or of a poll (:848-853, 1909-1917, 1930-1934). A
#   rejoin also follows when sub-chain 0 lags behind the server (it named a
#   block above height + 1 and none applied) for more than 12 seconds, the
#   window tde2e forgets an epoch in plus a margin (tde2e Call.h 98-99), and
#   when for 15 seconds no frame of any sender was decrypted though some
#   came while the chain is current, the watchdog of Web K
#   (groupCallInstance.ts:51); one sender alone failing is that sender's
#   fault, not a reason. At most three rejoins in a rolling five minutes,
#   after 0, 2 and 5 seconds plus up to 1 second at random (each one changes
#   the key of everyone, and members who rejoin at once collide in
#   CONF_WRITE_CHAIN_INVALID); then the call ends with a message
#   (lng_pluma_group_call_e2e_failed), not a loop of joins. A key counts
#   once: tde2e's Call fires a failure for each block of a batch it fails to
#   apply (tde2e_api.cpp 458-505). A rejoin of the transport (a duplicate
#   ssrc, checkGroupCall) does not count, and a join refused with
#   CONF_WRITE_CHAIN_INVALID asks for the last block again at most ten times
#   in a row (joinFail, :1862-1870, retries it without end).
# - The status report of the key, PlumaE2EStatus v1 of ADR 0060 §5: every 5
#   seconds from the join the call sends the SFU of the server, over the
#   data channel tgcalls keeps to it on the main connection (which carries
#   ReceiverVideoConstraints alone today, GroupInstanceCustomImpl.cpp
#   3512-3580), the number of the report since the join, the height of
#   sub-chain 0 applied and the prefix of the hash of its block as the
#   server stores it (tde2e Blockchain.cpp 742-760), the index each
#   sub-chain is polled from, the tde2e error the key failed with
#   (e2e_errors.h 13-40), the epochs of the last frame encrypted, those of
#   the frames decrypted and those that could not be, and per sender the
#   frames decrypted and refused by reason (Decrypt_UnknownEpoch, "Message
#   is too old", "Message is already processed", any other: tde2e Call.cpp
#   349, 482, 485) and how long ago the last was decrypted. Counters and
#   lists of epochs count since the last report; a report is made only
#   while the data channel is open, so what one could not send goes with
#   the next. At most 15 epochs a list, 8 unknown ones, 100 senders and 16
#   KiB, which the server checks (E2E_STATUS_LIMITS). Upstream drops the
#   result of every failed decryption (tde2e_api.cpp 91-100). No key,
#   nonce, emoji or byte of a frame is in it (E2E_STATUS_FIELDS lists every
#   field). tgcalls gains GroupInstanceCustomImpl::sendE2EStatus.
# - No recording: the server does not record a call, which it cannot hear
#   (phone.toggleGroupCallRecord is not served, ADR 0060 §4), so the menu
#   of a call never offers it (calls_group_menu.cpp 510-512, 541-577); a
#   conference has no such entry upstream either.
# - Never as a channel: the choice of whom to join as offers the user alone,
#   and a scheduled call of a channel is no longer joined as the channel
#   (calls_choose_join_as.cpp 343, 412-437). tgcalls gets the user id of a
#   sender from its peer (calls_group_call.cpp 3310, 3435), 0 for a channel,
#   which no key can be found for; the server refuses any other join_as.
# - No RTMP and no live stories (the owner's decisions 4 and 5 of ADR 0060):
#   the menu's "Stream with…" (window_peer_menu.cpp 4401-4403, 4428-4433)
#   and the process behind it (calls_instance.cpp 191, 376-385,
#   calls_instance.h 97-99, 224), the stream URL and key of the call's
#   settings (calls_group_settings.cpp 702-786), calls_group_rtmp.cpp out of
#   the build, a new call never asks for a stream (:1304-1308), the answer
#   to a join is never read as a broadcast stream (:112-122), whose parts
#   come from the server unencrypted (InstanceMode::Stream), and a live
#   story (messageMediaVideoStream, data_stories.cpp 78-96), the one place a
#   GroupCallOrigin::VideoStream call is made, is left out as a story of an
#   unknown type. tdesktop starts no live story itself (it has no
#   stories.startLive).
# Messages in a call (calls_group_call.cpp 2451-2484, calls_group_messages.cpp
# 132, 173) stay upstream's: the server does not serve them.
GROUP_CALL = SOURCES + "/calls/group/calls_group_call.cpp"
GROUP_CALL_H = SOURCES + "/calls/group/calls_group_call.h"
GROUP_CALL_MEMBERS = SOURCES + "/calls/group/calls_group_members.cpp"
GROUP_CALL_MENU = SOURCES + "/calls/group/calls_group_menu.cpp"
GROUP_CALL_SETTINGS = SOURCES + "/calls/group/calls_group_settings.cpp"
GROUP_CALL_RTMP = SOURCES + "/calls/group/calls_group_rtmp."
CHOOSE_JOIN_AS = SOURCES + "/calls/group/calls_choose_join_as.cpp"
CALLS_INSTANCE = SOURCES + "/calls/calls_instance.cpp"
CALLS_INSTANCE_H = SOURCES + "/calls/calls_instance.h"
DATA_GROUP_CALL = SOURCES + "/data/data_group_call.cpp"
DATA_STORIES = SOURCES + "/data/data_stories.cpp"
PEER_MENU = SOURCES + "/window/window_peer_menu.cpp"
TDE2E_API = SOURCES + "/tde2e/tde2e_api.cpp"
TDE2E_API_H = SOURCES + "/tde2e/tde2e_api.h"
TGCALLS_GROUP = TGCALLS + "/tgcalls/group/GroupInstanceCustomImpl.cpp"
TGCALLS_GROUP_H = TGCALLS + "/tgcalls/group/GroupInstanceCustomImpl.h"

# The built-in English, after this entry; other languages come from the
# server's language pack of tdesktop.
GROUP_CALLS_E2E_STRINGS_AFTER = '"lng_confcall_not_accessible" = "This call is no longer accessible.";\n'
GROUP_CALLS_E2E_STRINGS = {
    "lng_pluma_group_call_e2e_failed": "The encryption of this call keeps failing, so you left it. "
                                       "Join it again.",
}

# Every field of the status report, PlumaE2EStatus v1 of ADR 0060 §5, which
# the server checks: it drops a report with any other, without one of these,
# of another version or over the limits.
E2E_STATUS_FIELDS = ("colibriClass", "v", "seq", "height", "lastBlock", "offset0", "offset1", "error",
                     "sendEpochs", "decryptEpochs", "unknownEpochs", "encrypted", "encryptFailed", "senders")
E2E_STATUS_SENDER_FIELDS = ("user", "ok", "unknownEpoch", "tooOld", "duplicate", "failed", "lastOkMs")
# The limits of a report (tde2e_api.cpp) and the rules of a rejoin
# (calls_group_call.cpp), as ADR 0060 §5 sets them: {constant: its value}.
E2E_STATUS_LIMITS = {
    "kStatusReportVersion": "1",
    "kStatusMaxEpochs": "15",
    "kStatusMaxUnknownEpochs": "8",
    "kStatusMaxSenders": "100",
    "kStatusMaxSize": "16 * 1024",
}
E2E_REJOIN_RULES = {
    "kE2ERejoinsLimit": "3",
    "kE2ERejoinsPeriod": "5 * 60 * crl::time(1000)",
    "kE2ERejoinDelays[]": "{ 0, 2 * crl::time(1000), 5 * crl::time(1000) }",
    "kE2ERejoinJitter": "crl::time(1000)",
    "kE2ELaggingPeriod": "12 * crl::time(1000)",
    "kE2EUndecryptablePeriod": "15 * crl::time(1000)",
    "kE2EChainRetries": "10",
    "kE2EStatusPeriod": "5 * crl::time(1000)",
}

GROUP_CALLS_E2E_EDITS = (
    # e2e(), next to conference().
    (GROUP_CALL_H,
     "\t[[nodiscard]] bool conference() const;\n",
     "\t[[nodiscard]] bool conference() const;\n"
     "\t[[nodiscard]] bool e2e() const; // pluma: task 094\n"),
    (GROUP_CALL_H,
     "\tvoid initConferenceE2E();\n",
     "\tvoid initConferenceE2E();\n"
     "\t// pluma: the status report of the end-to-end key and the rules of a\n"
     "\t// rejoin with a new one (task 094, ADR 0060 §5).\n"
     "\tvoid sendE2EStatus();\n"
     "\tvoid checkE2EHealth();\n"
     "\tvoid scheduleE2ERejoin(const QString &reason);\n"),
    (GROUP_CALL_H,
     "\tstd::shared_ptr<TdE2E::EncryptDecrypt> _e2eEncryptDecrypt;\n",
     "\tstd::shared_ptr<TdE2E::EncryptDecrypt> _e2eEncryptDecrypt;\n"
     "\t// pluma: the rejoins with a new key in the period and the one waiting,\n"
     "\t// the timers of the status report and of the rules of a rejoin, the joins\n"
     "\t// retried on a chain that changed meanwhile, and whether the key went to\n"
     "\t// the server (task 094).\n"
     "\tstd::vector<crl::time> _e2eRejoins;\n"
     "\tbase::Timer _e2eRejoinTimer;\n"
     "\tbase::Timer _e2eStatusTimer;\n"
     "\tbase::Timer _e2eCheckTimer;\n"
     "\tint _e2eChainRetries = 0;\n"
     "\tbool _e2eKeySent = false;\n"),
    (GROUP_CALL,
     "constexpr auto kShortPollChainBlocksPerRequest = 50;\n",
     "constexpr auto kShortPollChainBlocksPerRequest = 50;\n"
     "// pluma: the rules of a rejoin with a new end-to-end key and its status\n"
     "// report (task 094, ADR 0060 §5). At most kE2ERejoinsLimit rejoins in a\n"
     "// rolling kE2ERejoinsPeriod, each after its delay of kE2ERejoinDelays plus up\n"
     "// to kE2ERejoinJitter at random; sub-chain 0 lagging behind the server for\n"
     "// kE2ELaggingPeriod, or no frame decrypted for kE2EUndecryptablePeriod, are\n"
     "// reasons for one, checked each kE2ECheckPeriod. A join refused because the\n"
     "// chain changed meanwhile is retried at most kE2EChainRetries times in a row.\n"
     "constexpr auto kE2ERejoinsLimit = 3;\n"
     "constexpr auto kE2ERejoinsPeriod = 5 * 60 * crl::time(1000);\n"
     "constexpr crl::time kE2ERejoinDelays[] = { 0, 2 * crl::time(1000), 5 * crl::time(1000) };\n"
     "constexpr auto kE2ERejoinJitter = crl::time(1000);\n"
     "constexpr auto kE2ELaggingPeriod = 12 * crl::time(1000);\n"
     "constexpr auto kE2EUndecryptablePeriod = 15 * crl::time(1000);\n"
     "constexpr auto kE2ECheckPeriod = crl::time(1000);\n"
     "constexpr auto kE2EChainRetries = 10;\n"
     "constexpr auto kE2EStatusPeriod = 5 * crl::time(1000);\n"
     "static_assert(std::size(kE2ERejoinDelays) == kE2ERejoinsLimit);\n"),
    # The answer to a join is never a broadcast stream.
    (GROUP_CALL,
     "\tif (document.object().value(\"stream\").toBool()) {\n"
     "\t\treturn JoinBroadcastStream{\n"
     "\t\t\t.rtmp = document.object().value(\"rtmp\").toBool(),\n"
     "\t\t\t.rtmpInfo = {\n"
     "\t\t\t\t.url = document.object().value(\"rtmp_stream_url\").toString(),\n"
     "\t\t\t\t.key = document.object().value(\"rtmp_stream_key\").toString(),\n"
     "\t\t\t},\n"
     "\t\t};\n"
     "\t}\n",
     "\t// pluma: never a broadcast stream, RTMP or not (task 094): its parts\n"
     "\t// come from the server unencrypted, so \"stream\" in the answer would take\n"
     "\t// an end-to-end call out of its encryption.\n"),
    (GROUP_CALL,
     "\t} else if (!_sharedCall && (startInfo.migrating || startInfo.show)) {\n"
     "\t\tinitConferenceE2E();\n"
     "\t}\n",
     "\t} else if (!_sharedCall && (startInfo.migrating || startInfo.show)) {\n"
     "\t\tinitConferenceE2E();\n"
     "\t} else if (e2e()) {\n"
     "\t\t// pluma: a call of a group or a channel takes the encryption of a\n"
     "\t\t// conference (task 094).\n"
     "\t\tinitConferenceE2E();\n"
     "\t}\n"),
    (GROUP_CALL,
     "\tconst auto tde2eUserId = TdE2E::MakeUserId(_peer->session().user());\n"
     "\t_e2e = std::make_unique<TdE2E::Call>(tde2eUserId);\n",
     "\tconst auto tde2eUserId = TdE2E::MakeUserId(_peer->session().user());\n"
     "\t_e2e = std::make_unique<TdE2E::Call>(tde2eUserId);\n"
     "\t_e2eKeySent = false; // pluma: task 094\n"),
    (GROUP_CALL,
     "\t_e2e->failures() | rpl::on_next([=] {\n"
     "\t\tLOG((\"TdE2E: Got failure, scheduling rejoin!\"));\n"
     "\t\tcrl::on_main(this, [=] { startRejoin(); });\n"
     "\t}, _e2e->lifetime());\n",
     "\t// pluma: one failure of a key is one rejoin: a batch of blocks fires a\n"
     "\t// failure for each block it fails to apply (TdE2E::Call::apply). The\n"
     "\t// rejoin goes by the rules of scheduleE2ERejoin (task 094).\n"
     "\t_e2e->failures() | rpl::take(1) | rpl::on_next([=] {\n"
     "\t\tcrl::on_main(this, [=] {\n"
     "\t\t\tscheduleE2ERejoin(u\"Got failure\"_q);\n"
     "\t\t});\n"
     "\t}, _e2e->lifetime());\n"),
    (GROUP_CALL,
     "void GroupCall::trackParticipantsWithAccess() {\n"
     "\tif (!_sharedCall || !_e2e) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\n"
     "\t_e2e->participantsSetValue(\n"
     "\t) | rpl::on_next([=](const TdE2E::ParticipantsSet &set) {\n"
     "\t\tauto users = base::flat_set<UserId>();\n"
     "\t\tusers.reserve(set.list.size());\n"
     "\t\tfor (const auto &id : set.list) {\n"
     "\t\t\tusers.emplace(UserId(id.v));\n"
     "\t\t}\n"
     "\t\t_sharedCall->setParticipantsWithAccess(std::move(users));\n"
     "\t}, _e2e->lifetime());\n"
     "}\n",
     "void GroupCall::trackParticipantsWithAccess() {\n"
     "\tif (!_e2e) { // pluma: a call of a group or a channel too (task 094)\n"
     "\t\treturn;\n"
     "\t}\n"
     "\n"
     "\t_e2e->participantsSetValue(\n"
     "\t) | rpl::on_next([=](const TdE2E::ParticipantsSet &set) {\n"
     "\t\tauto users = base::flat_set<UserId>();\n"
     "\t\tusers.reserve(set.list.size());\n"
     "\t\tfor (const auto &id : set.list) {\n"
     "\t\t\tusers.emplace(UserId(id.v));\n"
     "\t\t}\n"
     "\t\t// pluma: the call's Data::GroupCall, a conference's or a chat's.\n"
     "\t\tif (const auto real = lookupReal()) {\n"
     "\t\t\treal->setParticipantsWithAccess(std::move(users));\n"
     "\t\t}\n"
     "\t}, _e2e->lifetime());\n"
     "}\n"
     "\n"
     "void GroupCall::sendE2EStatus() {\n"
     "\t// pluma: the status of the end-to-end key, to the server's SFU over the\n"
     "\t// data channel of the main connection (task 094, ADR 0060 §5). The chain\n"
     "\t// is read here, on the main thread; tgcalls makes the report only while\n"
     "\t// the data channel is open, so the frames of one it could not send go\n"
     "\t// with the next.\n"
     "\tif (!_instance || !_e2e || !_e2eEncryptDecrypt) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconst auto status = _e2e->status();\n"
     "\tconst auto frames = _e2eEncryptDecrypt;\n"
     "\t_instance->sendE2EStatus([=] {\n"
     "\t\treturn TdE2E::StatusReport(status, *frames).toStdString();\n"
     "\t});\n"
     "}\n"
     "\n"
     "void GroupCall::checkE2EHealth() {\n"
     "\t// pluma: rules 2 and 4 of a rejoin (task 094, ADR 0060 §5); none is\n"
     "\t// checked while a join or a rejoin goes.\n"
     "\tconst auto state = _state.current();\n"
     "\tif (!_e2e\n"
     "\t\t|| !_e2eEncryptDecrypt\n"
     "\t\t|| (state != State::Joined && state != State::Connecting)\n"
     "\t\t|| _joinState.action != JoinAction::None\n"
     "\t\t|| _e2eRejoinTimer.isActive()) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconst auto now = crl::now();\n"
     "\tconst auto lagging = _e2e->laggingSince(now);\n"
     "\tif (lagging && now - lagging > kE2ELaggingPeriod) {\n"
     "\t\tscheduleE2ERejoin(u\"Chain lags behind the server\"_q);\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t// Every sender who sent frames for the period failed to be decrypted,\n"
     "\t// though the chain is current: what is wrong is on this side. One sender\n"
     "\t// alone failing is that sender's fault, caught by its own rules.\n"
     "\tconst auto frames = _e2eEncryptDecrypt->health();\n"
     "\tif (!lagging\n"
     "\t\t&& frames.failingSince\n"
     "\t\t&& now - frames.failingSince >= kE2EUndecryptablePeriod\n"
     "\t\t&& now - frames.lastFailure < kE2EUndecryptablePeriod) {\n"
     "\t\tscheduleE2ERejoin(u\"No frame decrypted\"_q);\n"
     "\t}\n"
     "}\n"
     "\n"
     "void GroupCall::scheduleE2ERejoin(const QString &reason) {\n"
     "\t// pluma: a rejoin with a new key by the rules of ADR 0060 §5 (task 094),\n"
     "\t// one at a time: at most kE2ERejoinsLimit in kE2ERejoinsPeriod, each\n"
     "\t// after a longer delay, so that members who rejoin at once do not\n"
     "\t// collide (each rejoin changes the key of everyone in the call). Then\n"
     "\t// the call ends with a message, not a loop of joins.\n"
     "\tif (_e2eRejoinTimer.isActive()) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconst auto now = crl::now();\n"
     "\t_e2eRejoins.erase(ranges::remove_if(_e2eRejoins, [&](crl::time at) {\n"
     "\t\treturn (at + kE2ERejoinsPeriod <= now);\n"
     "\t}), end(_e2eRejoins));\n"
     "\tconst auto index = int(_e2eRejoins.size());\n"
     "\tif (index >= kE2ERejoinsLimit) {\n"
     "\t\tLOG((\"TdE2E: %1, too many rejoins, hanging up!\").arg(reason));\n"
     "\t\tUi::Toast::Show(tr::lng_pluma_group_call_e2e_failed(tr::now));\n"
     "\t\thangup();\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t_e2eRejoins.push_back(now);\n"
     "\tconst auto delay = kE2ERejoinDelays[index]\n"
     "\t\t+ base::RandomIndex(int(kE2ERejoinJitter) + 1);\n"
     "\tLOG((\"TdE2E: %1, scheduling rejoin in %2 ms!\").arg(reason).arg(delay));\n"
     "\t_e2eRejoinTimer.setCallback([=] {\n"
     "\t\tconst auto state = _state.current();\n"
     "\t\tif (state == State::Joining\n"
     "\t\t\t|| state == State::Joined\n"
     "\t\t\t|| state == State::Connecting) {\n"
     "\t\t\tstartRejoin();\n"
     "\t\t}\n"
     "\t});\n"
     "\t_e2eRejoinTimer.callOnce(delay);\n"
     "}\n"),
    (GROUP_CALL,
     "void GroupCall::subscribeToReal(not_null<Data::GroupCall*> real) {\n"
     "\t_listenersHidden = real->listenersHidden();\n",
     "void GroupCall::subscribeToReal(not_null<Data::GroupCall*> real) {\n"
     "\t_listenersHidden = real->listenersHidden();\n"
     "\n"
     "\t// pluma: the members of the chain who left a call of a group or a\n"
     "\t// channel are removed from it, as a conference's are\n"
     "\t// (setupConferenceCall; task 094).\n"
     "\tif (!_sharedCall) {\n"
     "\t\treal->staleParticipantIds(\n"
     "\t\t) | rpl::on_next([=](const base::flat_set<UserId> &staleIds) {\n"
     "\t\t\tif (_e2e) {\n"
     "\t\t\t\tremoveConferenceParticipants(staleIds, true);\n"
     "\t\t\t}\n"
     "\t\t}, _lifetime);\n"
     "\t}\n"),
    (GROUP_CALL,
     "bool GroupCall::videoStream() const {\n",
     "bool GroupCall::e2e() const {\n"
     "\t// pluma: every group call but a live story is end-to-end, a call of a\n"
     "\t// group or a channel by the encryption of a conference (task 094). Not\n"
     "\t// by the server's rtmp_stream: the server may not turn it off.\n"
     "\treturn conference() || !videoStream();\n"
     "}\n"
     "\n"
     "bool GroupCall::videoStream() const {\n"),
    # A new call is never an RTMP stream.
    (GROUP_CALL,
     "void GroupCall::start(TimeId scheduleDate, bool rtmp) {\n"
     "\tusing Flag = MTPphone_CreateGroupCall::Flag;\n"
     "\t_createRequestId = _api.request(MTPphone_CreateGroupCall(\n"
     "\t\tMTP_flags((scheduleDate ? Flag::f_schedule_date : Flag(0))\n"
     "\t\t\t| (rtmp ? Flag::f_rtmp_stream : Flag(0))),\n",
     "void GroupCall::start(TimeId scheduleDate, bool) {\n"
     "\tusing Flag = MTPphone_CreateGroupCall::Flag;\n"
     "\t_createRequestId = _api.request(MTPphone_CreateGroupCall(\n"
     "\t\t// pluma: never an RTMP stream (task 094).\n"
     "\t\tMTP_flags(scheduleDate ? Flag::f_schedule_date : Flag(0)),\n"),
    (GROUP_CALL,
     "\tif (conference()) {\n"
     "\t\tinitConferenceE2E();\n"
     "\t}\n"
     "\tsetState(State::Joining);\n"
     "\trejoin();\n",
     "\tif (e2e()) { // pluma: task 094\n"
     "\t\tinitConferenceE2E();\n"
     "\t}\n"
     "\tsetState(State::Joining);\n"
     "\trejoin();\n"),
    (GROUP_CALL,
     "\t_joinState.action = JoinAction::Joining;\n"
     "\t_joinState.ssrc = 0;\n",
     "\t// pluma: a join of an end-to-end call takes a new key once the old one\n"
     "\t// went to the server: the chain keeps it (task 094).\n"
     "\tif (_e2eKeySent && e2e()) {\n"
     "\t\tinitConferenceE2E();\n"
     "\t}\n"
     "\t_joinState.action = JoinAction::Joining;\n"
     "\t_joinState.ssrc = 0;\n"),
    (GROUP_CALL,
     "\t\t\t} else if (conference()\n"
     "\t\t\t\t&& _sharedCall\n"
     "\t\t\t\t&& !_sharedCall->blockchainMayBeEmpty()\n"
     "\t\t\t\t&& !_e2e->hasLastBlock0()) {\n",
     "\t\t\t} else if (e2e()\n"
     "\t\t\t\t// pluma: a call of a group or a channel asks for the last\n"
     "\t\t\t\t// block before every join; a conference skips it while its\n"
     "\t\t\t\t// chain may be empty, as upstream does (task 094).\n"
     "\t\t\t\t&& !(_sharedCall && _sharedCall->blockchainMayBeEmpty())\n"
     "\t\t\t\t&& !_e2e->hasLastBlock0()) {\n"),
    (GROUP_CALL,
     "\t\tUi::Toast::Show(u\"Could not generate join block.\"_q);\n"
     "\t\treturn;\n"
     "\t}\n",
     "\t\tUi::Toast::Show(u\"Could not generate join block.\"_q);\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t_e2eKeySent = (_e2e != nullptr); // pluma: task 094\n"),
    (GROUP_CALL,
     "\tconst auto joinBlock = _e2e->makeJoinBlock().data;\n"
     "\tAssert(!joinBlock.isEmpty());\n",
     "\tconst auto joinBlock = _e2e->makeJoinBlock().data;\n"
     "\tAssert(!joinBlock.isEmpty());\n"
     "\t_e2eKeySent = true; // pluma: task 094\n"),
    (GROUP_CALL,
     "\tif (_e2e) {\n"
     "\t\t_e2e->joined();\n",
     "\tif (_e2e) {\n"
     "\t\t_e2e->joined();\n"
     "\t\t// pluma: a new join: the report's number and its counters start\n"
     "\t\t// again, the first report goes in kE2EStatusPeriod and the rules of a\n"
     "\t\t// rejoin are checked from now (task 094, ADR 0060 §5).\n"
     "\t\t_e2eChainRetries = 0;\n"
     "\t\tif (_e2eEncryptDecrypt) {\n"
     "\t\t\t_e2eEncryptDecrypt->reset();\n"
     "\t\t}\n"
     "\t\t_e2eStatusTimer.setCallback([=] { sendE2EStatus(); });\n"
     "\t\t_e2eStatusTimer.callEach(kE2EStatusPeriod);\n"
     "\t\t_e2eCheckTimer.setCallback([=] { checkE2EHealth(); });\n"
     "\t\t_e2eCheckTimer.callEach(kE2ECheckPeriod);\n"),
    (GROUP_CALL,
     "\tif (_e2e) {\n"
     "\t\tif (error.startsWith(u\"CONF_WRITE_CHAIN_INVALID\"_q)) {\n"
     "\t\t\tif (_id) {\n"
     "\t\t\t\trefreshLastBlockAndJoin();\n"
     "\t\t\t} else {\n"
     "\t\t\t\thangup();\n"
     "\t\t\t}\n"
     "\t\t\treturn;\n"
     "\t\t}\n"
     "\t}\n",
     "\tif (_e2e) {\n"
     "\t\tif (error.startsWith(u\"CONF_WRITE_CHAIN_INVALID\"_q)) {\n"
     "\t\t\t// pluma: the chain changed meanwhile; asked for again at most\n"
     "\t\t\t// kE2EChainRetries times in a row, then it is the error of a join\n"
     "\t\t\t// (task 094, ADR 0060 §5).\n"
     "\t\t\tif (!_id) {\n"
     "\t\t\t\thangup();\n"
     "\t\t\t\treturn;\n"
     "\t\t\t} else if (++_e2eChainRetries <= kE2EChainRetries) {\n"
     "\t\t\t\trefreshLastBlockAndJoin();\n"
     "\t\t\t\treturn;\n"
     "\t\t\t}\n"
     "\t\t}\n"
     "\t}\n"),
    # GROUPCALL_FORBIDDEN on a write to the chain or a poll of it: a rejoin by
    # the rules (task 094).
    (GROUP_CALL,
     "\t\t\t\t\"Rejoin after error '%1' in delete confcall participants\"\n"
     "\t\t\t\t).arg(type));\n"
     "\t\t\tstartRejoin();\n",
     "\t\t\t\t\"Rejoin after error '%1' in delete confcall participants\"\n"
     "\t\t\t\t).arg(type));\n"
     "\t\t\tscheduleE2ERejoin(type); // pluma: task 094\n"),
    (GROUP_CALL,
     "\t\t\tLOG((\"Call Info: Rejoin after error '%1' in get chain blocks.\"\n"
     "\t\t\t\t).arg(error.type()));\n"
     "\t\t\tstartRejoin();\n",
     "\t\t\tLOG((\"Call Info: Rejoin after error '%1' in get chain blocks.\"\n"
     "\t\t\t\t).arg(error.type()));\n"
     "\t\t\tscheduleE2ERejoin(error.type()); // pluma: task 094\n"),
    (GROUP_CALL,
     "\t\t\tLOG((\"Call Info: Rejoin after error '%1' in send confcall block.\"\n"
     "\t\t\t\t).arg(type));\n"
     "\t\t\tstartRejoin();\n",
     "\t\t\tLOG((\"Call Info: Rejoin after error '%1' in send confcall block.\"\n"
     "\t\t\t\t).arg(type));\n"
     "\t\t\tscheduleE2ERejoin(type); // pluma: task 094\n"),
    # No recording: the server does not record a call.
    (GROUP_CALL_MENU,
     "\tconst auto addEditRecording = !conference\n"
     "\t\t&& call->canManage()\n"
     "\t\t&& !real->scheduleDate();\n",
     "\t// pluma: no recording: the server does not record a call, which is end\n"
     "\t// to end (phone.toggleGroupCallRecord is not served; task 094, ADR 0060\n"
     "\t// §4).\n"
     "\tconst auto addEditRecording = false;\n"),
    (DATA_GROUP_CALL,
     "\tif (_conference) {\n"
     "\t\tsession().data().registerGroupCall(this);\n"
     "\n"
     "\t\t_participantUpdates.events(\n",
     "\tif (_conference || _videoStream) {\n"
     "\t\tsession().data().registerGroupCall(this);\n"
     "\t}\n"
     "\t// pluma: the members of the chain who left a call of a group or a\n"
     "\t// channel are found as a conference's are (task 094).\n"
     "\tif (!_videoStream) {\n"
     "\t\t_participantUpdates.events(\n"),
    (DATA_GROUP_CALL,
     "\t\t}, _checkStaleLifetime);\n"
     "\t} else if (_videoStream) {\n"
     "\t\tsession().data().registerGroupCall(this);\n"
     "\t}\n",
     "\t\t}, _checkStaleLifetime);\n"
     "\t}\n"),
    (GROUP_CALL_MEMBERS,
     "void Members::Controller::setupWithAccessUsers() {\n"
     "\tconst auto conference = _call->sharedCall().get();\n"
     "\tif (!_call->conference() || !conference) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconference->participantsWithAccessValue(\n"
     "\t) | rpl::on_next([=](base::flat_set<UserId> &&nowIds) {\n",
     "void Members::Controller::setupWithAccessUsers() {\n"
     "\t// pluma: the members of the chain of a call of a group or a channel\n"
     "\t// too (task 094).\n"
     "\tif (!_call->e2e()) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t_call->real(\n"
     "\t) | rpl::map([](not_null<Data::GroupCall*> real) {\n"
     "\t\treturn real->participantsWithAccessValue();\n"
     "\t}) | rpl::flatten_latest(\n"
     "\t) | rpl::on_next([=](base::flat_set<UserId> &&nowIds) {\n"),
    (GROUP_CALL_MEMBERS,
     ", _fingerprint(call->conference()\n",
     ", _fingerprint(call->e2e() // pluma: task 094\n"),
    # Never as a channel.
    (CHOOSE_JOIN_AS,
     "\tconst auto self = peer->session().user();\n"
     "\tauto info = JoinInfo{ .peer = peer, .joinAs = self };\n",
     "\tconst auto self = peer->session().user();\n"
     "\t// pluma: only the user joins a group call, which is end-to-end, never\n"
     "\t// as a channel (task 094).\n"
     "\tlist = { not_null<PeerData*>(self) };\n"
     "\tauto info = JoinInfo{ .peer = peer, .joinAs = self };\n"),
    (CHOOSE_JOIN_AS,
     "\t\t\tJoinInfo{ .peer = peer, .joinAs = peer },\n",
     "\t\t\t// pluma: never as the channel (task 094).\n"
     "\t\t\tJoinInfo{ .peer = peer, .joinAs = peer->session().user() },\n"),
    # No RTMP.
    (PEER_MENU,
     "\tconst auto rtmpCallback = [=] {\n"
     "\t\tCore::App().calls().showStartWithRtmp(controller->uiShow(), peer);\n"
     "\t};\n",
     ""),
    (PEER_MENU,
     "\t\t\t&st::menuIconReschedule);\n"
     "\t\taddAction(\n"
     "\t\t\t(livestream\n"
     "\t\t\t\t? tr::lng_menu_start_group_call_with_channel\n"
     "\t\t\t\t: tr::lng_menu_start_group_call_with)(tr::now),\n"
     "\t\t\trtmpCallback,\n"
     "\t\t\t&st::menuIconStartStreamWith);\n",
     "\t\t\t&st::menuIconReschedule);\n"
     "\t\t// pluma: no \"Stream with...\": no RTMP (task 094).\n"),
    (CALLS_INSTANCE,
     ", _chooseJoinAs(std::make_unique<Group::ChooseJoinAsProcess>())\n"
     ", _startWithRtmp(std::make_unique<Group::StartRtmpProcess>()) {\n",
     ", _chooseJoinAs(std::make_unique<Group::ChooseJoinAsProcess>()) {\n"),
    (CALLS_INSTANCE,
     "void Instance::showStartWithRtmp(\n"
     "\t\tstd::shared_ptr<Ui::Show> show,\n"
     "\t\tnot_null<PeerData*> peer) {\n"
     "\t_startWithRtmp->start(peer, show, [=](Group::JoinInfo info) {\n"
     "\t\tconfirmLeaveCurrent(show, peer, {}, [=](auto) {\n"
     "\t\t\t_startWithRtmp->close();\n"
     "\t\t\tcreateGroupCall(std::move(info), MTP_inputGroupCall({}, {}));\n"
     "\t\t});\n"
     "\t});\n"
     "}\n"
     "\n",
     ""),
    (CALLS_INSTANCE_H,
     "\tvoid showStartWithRtmp(\n"
     "\t\tstd::shared_ptr<Ui::Show> show,\n"
     "\t\tnot_null<PeerData*> peer);\n",
     ""),
    (CALLS_INSTANCE_H,
     "\tconst std::unique_ptr<Group::StartRtmpProcess> _startWithRtmp;\n",
     ""),
    (CALLS_INSTANCE_H,
     "class StartRtmpProcess;\n",
     ""),
    (CMAKE_APP,
     "    calls/group/calls_group_rtmp.cpp\n"
     "    calls/group/calls_group_rtmp.h\n",
     ""),
    # No live stories.
    (DATA_STORIES,
     "\t\tconst std::shared_ptr<GroupCall> &existingCall) {\n"
     "\treturn media.match([&](const MTPDmessageMediaPhoto &data)\n",
     "\t\t[[maybe_unused]] const std::shared_ptr<GroupCall> &existingCall) {\n"
     "\treturn media.match([&](const MTPDmessageMediaPhoto &data)\n"),
    (DATA_STORIES,
     "\t}, [&](const MTPDmessageMediaVideoStream &data) {\n"
     "\t\tconst auto rtmp = data.is_rtmp_stream();\n"
     "\t\treturn std::make_optional(data.vcall().match([&](\n"
     "\t\t\t\tconst MTPDinputGroupCall &data) {\n"
     "\t\t\tauto call = (existingCall\n"
     "\t\t\t\t&& existingCall->peer() == peer\n"
     "\t\t\t\t&& existingCall->id() == data.vid().v)\n"
     "\t\t\t\t? existingCall\n"
     "\t\t\t\t: std::make_shared<Data::GroupCall>(\n"
     "\t\t\t\t\tpeer,\n"
     "\t\t\t\t\tdata.vid().v,\n"
     "\t\t\t\t\tdata.vaccess_hash().v,\n"
     "\t\t\t\t\tTimeId(),\n"
     "\t\t\t\t\trtmp,\n"
     "\t\t\t\t\tGroupCallOrigin::VideoStream);\n"
     "\t\t\treturn StoryMedia{ std::move(call) };\n"
     "\t\t}, [](const auto &) {\n"
     "\t\t\treturn StoryMedia();\n"
     "\t\t}));\n",
     "\t}, [&](const MTPDmessageMediaVideoStream &) {\n"
     "\t\t// pluma: no live stories (task 094): a live story is a group call\n"
     "\t\t// without end-to-end encryption, which the server does not serve. The\n"
     "\t\t// story is left out, as one of an unknown type.\n"
     "\t\treturn std::optional<StoryMedia>();\n"),
    # The counters of the frames and the status of the chain (tde2e).
    (TDE2E_API_H,
     "#include \"base/basic_types.h\"\n"
     "#include \"base/flat_set.h\"\n",
     "#include \"base/basic_types.h\"\n"
     "#include \"base/flat_map.h\" // pluma: task 094\n"
     "#include \"base/flat_set.h\"\n"),
    (TDE2E_API_H,
     "#include <crl/crl_time.h>\n",
     "#include <crl/crl_time.h>\n"
     "\n"
     "#include <array> // pluma: task 094\n"
     "#include <mutex>\n"),
    (TDE2E_API_H,
     "\tvoid setCallId(CallId id);\n"
     "\tvoid clearCallId(CallId fromId);\n"
     "\n"
     "private:\n"
     "\tstd::atomic<uint64> _id = 0;\n"
     "\n"
     "};\n",
     "\tvoid setCallId(CallId id);\n"
     "\tvoid clearCallId(CallId fromId);\n"
     "\n"
     "\t// pluma: what the frames of the call met, for the status report of the\n"
     "\t// key and the rules of a rejoin (task 094, ADR 0060 §5). Epochs go by\n"
     "\t// the first 8 bytes of their hash.\n"
     "\tusing EpochPrefix = std::array<uint8, 8>;\n"
     "\tstruct SenderFrames {\n"
     "\t\tint64 ok = 0;\n"
     "\t\tint64 unknownEpoch = 0;\n"
     "\t\tint64 tooOld = 0;\n"
     "\t\tint64 duplicate = 0;\n"
     "\t\tint64 failed = 0;\n"
     "\t};\n"
     "\t// The frames since the last report, but sendEpochs, the epochs of the\n"
     "\t// last frame encrypted, and lastOk, when each sender was last decrypted\n"
     "\t// since the join; seq numbers the reports since the join.\n"
     "\tstruct Frames {\n"
     "\t\tint64 seq = 0;\n"
     "\t\tbase::flat_map<int64, SenderFrames> senders;\n"
     "\t\tbase::flat_map<int64, crl::time> lastOk;\n"
     "\t\tstd::vector<EpochPrefix> sendEpochs;\n"
     "\t\tstd::vector<EpochPrefix> decryptEpochs;\n"
     "\t\tstd::vector<EpochPrefix> unknownEpochs;\n"
     "\t\tint64 encrypted = 0;\n"
     "\t\tint64 encryptFailed = 0;\n"
     "\t};\n"
     "\t// The frames of the next report, numbered; its counters start again.\n"
     "\t[[nodiscard]] Frames takeFrames();\n"
     "\t// Since when no frame was decrypted though some were refused (with\n"
     "\t// Decrypt_UnknownEpoch or any error but a frame too old or seen\n"
     "\t// already), 0 while the last frame met was decrypted, and when one was\n"
     "\t// refused last.\n"
     "\tstruct Health {\n"
     "\t\tcrl::time failingSince = 0;\n"
     "\t\tcrl::time lastFailure = 0;\n"
     "\t};\n"
     "\t[[nodiscard]] Health health() const;\n"
     "\t// A new join: everything starts again.\n"
     "\tvoid reset();\n"
     "\n"
     "private:\n"
     "\tvoid countEncrypted(const EncryptionBuffer *result, int32_t prefix);\n"
     "\tvoid countDecrypted(\n"
     "\t\tint64_t userId,\n"
     "\t\tconst EncryptionBuffer &data,\n"
     "\t\tstd::optional<int> errorCode,\n"
     "\t\tconst std::string &errorMessage);\n"
     "\n"
     "\tstd::atomic<uint64> _id = 0;\n"
     "\tmutable std::mutex _framesMutex;\n"
     "\tFrames _frames;\n"
     "\tHealth _health;\n"
     "\n"
     "};\n"),
    (TDE2E_API_H,
     "\t[[nodiscard]] auto participantsSetValue() const\n"
     "\t\t-> rpl::producer<ParticipantsSet>;\n",
     "\t[[nodiscard]] auto participantsSetValue() const\n"
     "\t\t-> rpl::producer<ParticipantsSet>;\n"
     "\n"
     "\t// pluma: this side of the chain, for the status report of the key\n"
     "\t// (task 094, ADR 0060 §5): the height of sub-chain 0 applied, -1\n"
     "\t// without a state (before the join or after a failure); the first 8\n"
     "\t// bytes of SHA-256 of the block at that height in the form the server\n"
     "\t// stores it, empty without a state; the index each sub-chain is polled\n"
     "\t// from next, -1 while unknown; the tde2e error the call failed with.\n"
     "\tstruct Status {\n"
     "\t\tint height = -1;\n"
     "\t\tQByteArray lastBlock;\n"
     "\t\tint offsets[2] = { -1, -1 };\n"
     "\t\tint error = 0;\n"
     "\t};\n"
     "\t[[nodiscard]] Status status() const;\n"
     "\t// pluma: since when sub-chain 0 lags behind the server: the server named\n"
     "\t// a block above the one to apply next, and none was applied since; 0\n"
     "\t// while it does not lag (task 094, ADR 0060 §5).\n"
     "\t[[nodiscard]] crl::time laggingSince(crl::time now);\n"),
    (TDE2E_API_H,
     "\tstd::optional<CallFailure> _failure;\n",
     "\tstd::optional<CallFailure> _failure;\n"
     "\t// pluma: the tde2e error of the failure, the hash prefix of the block of\n"
     "\t// sub-chain 0 applied last, the index the server named after its last\n"
     "\t// block, and the height sub-chain 0 lags at and since when (task 094).\n"
     "\tint _failureCode = 0;\n"
     "\tQByteArray _appliedBlock0;\n"
     "\tint _serverNext0 = 0;\n"
     "\tint _laggingHeight = -1;\n"
     "\tcrl::time _laggingSince = 0;\n"),
    (TDE2E_API_H,
     "\trpl::lifetime _lifetime;\n"
     "\n"
     "};\n"
     "\n"
     "} // namespace TdE2E\n",
     "\trpl::lifetime _lifetime;\n"
     "\n"
     "};\n"
     "\n"
     "// pluma: the PlumaE2EStatus v1 message of the data channel (task 094, ADR\n"
     "// 0060 §5), of the status of the chain read on the main thread; it takes the\n"
     "// frames counted since the last report.\n"
     "[[nodiscard]] QByteArray StatusReport(\n"
     "\tconst Call::Status &status,\n"
     "\tEncryptDecrypt &frames);\n"
     "\n"
     "} // namespace TdE2E\n"),
    (TDE2E_API,
     "#include <td/e2e/e2e_api.h>\n",
     "#include <td/e2e/e2e_api.h>\n"
     "\n"
     "// pluma: the status report of the key (task 094).\n"
     "#include <QtCore/QCryptographicHash>\n"
     "#include <QtCore/QJsonArray>\n"
     "#include <QtCore/QJsonDocument>\n"
     "#include <QtCore/QJsonObject>\n"),
    (TDE2E_API,
     "#define LOG_AND_FAIL(error, reason) \\\n"
     "\tLOG_ERROR(error); \\\n"
     "\tfail(reason)\n",
     "#define LOG_AND_FAIL(error, reason) \\\n"
     "\tLOG_ERROR(error); \\\n"
     "\t_failureCode = int(error.code); /* pluma: task 094 */ \\\n"
     "\tfail(reason)\n"),
    (TDE2E_API,
     "constexpr auto kShortPollChainBlocksWaitFor = crl::time(1000);\n",
     "constexpr auto kShortPollChainBlocksWaitFor = crl::time(1000);\n"
     "\n"
     "// pluma: the status report of the key, PlumaE2EStatus v1 of ADR 0060 §5\n"
     "// (task 094): its version and limits, which the server checks, and the\n"
     "// header of a frame of tde2e (Call.cpp 286-350: the size of the unencrypted\n"
     "// prefix in the last 4 bytes; after the prefix a 32-bit head whose low byte\n"
     "// counts the epochs, at most 15, then their 32-byte hashes).\n"
     "constexpr auto kStatusReportVersion = 1;\n"
     "constexpr auto kStatusMaxEpochs = 15;\n"
     "constexpr auto kStatusMaxUnknownEpochs = 8;\n"
     "constexpr auto kStatusMaxSenders = 100;\n"
     "constexpr auto kStatusMaxSize = 16 * 1024;\n"
     "constexpr auto kFrameMaxEpochs = 15;\n"
     "constexpr auto kFrameEpochHashSize = 32;\n"
     "\n"
     "// The first 8 bytes of the hashes of the epochs of a frame of size bytes\n"
     "// whose header starts at offset.\n"
     "template <typename Callback>\n"
     "void ForEachFrameEpoch(\n"
     "\t\tconst EncryptionBuffer &frame,\n"
     "\t\tsize_t size,\n"
     "\t\tsize_t offset,\n"
     "\t\tCallback &&callback) {\n"
     "\tif (offset > size || size - offset < 4) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconst auto head = uint32(frame[offset])\n"
     "\t\t| (uint32(frame[offset + 1]) << 8)\n"
     "\t\t| (uint32(frame[offset + 2]) << 16)\n"
     "\t\t| (uint32(frame[offset + 3]) << 24);\n"
     "\tconst auto count = int(head & 0xFF);\n"
     "\tif ((head >> 8) != 0 || count > kFrameMaxEpochs) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tauto at = offset + 4;\n"
     "\tfor (auto i = 0; i != count; ++i, at += kFrameEpochHashSize) {\n"
     "\t\tif (size - at < size_t(kFrameEpochHashSize)) {\n"
     "\t\t\treturn;\n"
     "\t\t}\n"
     "\t\tauto prefix = EncryptDecrypt::EpochPrefix();\n"
     "\t\tstd::copy_n(frame.begin() + at, prefix.size(), prefix.begin());\n"
     "\t\tcallback(prefix);\n"
     "\t}\n"
     "}\n"
     "\n"
     "// The epochs of an encrypted frame as it comes to be decrypted: the size of\n"
     "// its unencrypted prefix in its last 4 bytes.\n"
     "template <typename Callback>\n"
     "void ForEachIncomingFrameEpoch(\n"
     "\t\tconst EncryptionBuffer &frame,\n"
     "\t\tCallback &&callback) {\n"
     "\tif (frame.size() < 4) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\tconst auto tail = frame.size() - 4;\n"
     "\tconst auto prefix = size_t(frame[tail])\n"
     "\t\t| (size_t(frame[tail + 1]) << 8)\n"
     "\t\t| (size_t(frame[tail + 2]) << 16)\n"
     "\t\t| (size_t(frame[tail + 3]) << 24);\n"
     "\tForEachFrameEpoch(frame, tail, prefix, callback);\n"
     "}\n"
     "\n"
     "void AddEpoch(\n"
     "\t\tstd::vector<EncryptDecrypt::EpochPrefix> &list,\n"
     "\t\tconst EncryptDecrypt::EpochPrefix &prefix,\n"
     "\t\tint limit) {\n"
     "\tif (int(list.size()) < limit\n"
     "\t\t&& std::find(begin(list), end(list), prefix) == end(list)) {\n"
     "\t\tlist.push_back(prefix);\n"
     "\t}\n"
     "}\n"
     "\n"
     "[[nodiscard]] QString EpochPrefixHex(\n"
     "\t\tconst EncryptDecrypt::EpochPrefix &prefix) {\n"
     "\treturn QString::fromLatin1(QByteArray(\n"
     "\t\treinterpret_cast<const char*>(prefix.data()),\n"
     "\t\tint(prefix.size())).toHex());\n"
     "}\n"
     "\n"
     "// The first 8 bytes of SHA-256 of a block of sub-chain 0 in the form the\n"
     "// server stores it, as the client sent it: the server gives a block out with\n"
     "// its magic plus 1 (tde2e Blockchain.cpp 742-760).\n"
     "[[nodiscard]] QByteArray StoredBlockPrefix(const QByteArray &block) {\n"
     "\tif (block.size() < 4) {\n"
     "\t\treturn QByteArray();\n"
     "\t}\n"
     "\tauto local = block;\n"
     "\tauto magic = uint32();\n"
     "\tmemcpy(&magic, local.constData(), sizeof(magic));\n"
     "\t--magic;\n"
     "\tmemcpy(local.data(), &magic, sizeof(magic));\n"
     "\treturn QCryptographicHash::hash(\n"
     "\t\tlocal,\n"
     "\t\tQCryptographicHash::Sha256).left(8);\n"
     "}\n"),
    (TDE2E_API,
     "\t\tconst auto result = encrypt\n"
     "\t\t\t? tde2e_api::call_encrypt(\n"
     "\t\t\t\tlibId,\n"
     "\t\t\t\tchannelId,\n"
     "\t\t\t\tslice,\n"
     "\t\t\t\tsize_t(unencryptedPrefixSize))\n"
     "\t\t\t: tde2e_api::call_decrypt(libId, userId, channelId, slice);\n"
     "\t\tif (!result.is_ok()) {\n"
     "\t\t\treturn {};\n"
     "\t\t}\n"
     "\t\tconst auto &value = result.value();\n"
     "\t\tconst auto start = reinterpret_cast<const uint8_t*>(value.data());\n"
     "\t\tconst auto end = start + value.size();\n"
     "\t\treturn { start, end };\n"
     "\t};\n"
     "}\n",
     "\t\tconst auto result = encrypt\n"
     "\t\t\t? tde2e_api::call_encrypt(\n"
     "\t\t\t\tlibId,\n"
     "\t\t\t\tchannelId,\n"
     "\t\t\t\tslice,\n"
     "\t\t\t\tsize_t(unencryptedPrefixSize))\n"
     "\t\t\t: tde2e_api::call_decrypt(libId, userId, channelId, slice);\n"
     "\t\tif (!result.is_ok()) {\n"
     "\t\t\t// pluma: counted for the status report (task 094).\n"
     "\t\t\tif (encrypt) {\n"
     "\t\t\t\tthat->countEncrypted(nullptr, unencryptedPrefixSize);\n"
     "\t\t\t} else {\n"
     "\t\t\t\tthat->countDecrypted(\n"
     "\t\t\t\t\tuserId,\n"
     "\t\t\t\t\tdata,\n"
     "\t\t\t\t\tint(result.error().code),\n"
     "\t\t\t\t\tresult.error().message);\n"
     "\t\t\t}\n"
     "\t\t\treturn {};\n"
     "\t\t}\n"
     "\t\tconst auto &value = result.value();\n"
     "\t\tconst auto start = reinterpret_cast<const uint8_t*>(value.data());\n"
     "\t\tconst auto end = start + value.size();\n"
     "\t\tauto buffer = EncryptionBuffer{ start, end };\n"
     "\t\tif (encrypt) {\n"
     "\t\t\tthat->countEncrypted(&buffer, unencryptedPrefixSize);\n"
     "\t\t} else {\n"
     "\t\t\tthat->countDecrypted(userId, data, std::nullopt, std::string());\n"
     "\t\t}\n"
     "\t\treturn buffer;\n"
     "\t};\n"
     "}\n"
     "\n"
     "void EncryptDecrypt::countEncrypted(\n"
     "\t\tconst EncryptionBuffer *result,\n"
     "\t\tint32_t prefix) {\n"
     "\tconst auto lock = std::lock_guard(_framesMutex);\n"
     "\tif (!result) {\n"
     "\t\t++_frames.encryptFailed;\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t++_frames.encrypted;\n"
     "\t_frames.sendEpochs.clear();\n"
     "\tForEachFrameEpoch(\n"
     "\t\t*result,\n"
     "\t\tresult->size(),\n"
     "\t\tsize_t(prefix),\n"
     "\t\t[&](const EpochPrefix &p) {\n"
     "\t\t\tAddEpoch(_frames.sendEpochs, p, kStatusMaxEpochs);\n"
     "\t\t});\n"
     "}\n"
     "\n"
     "void EncryptDecrypt::countDecrypted(\n"
     "\t\tint64_t userId,\n"
     "\t\tconst EncryptionBuffer &data,\n"
     "\t\tstd::optional<int> errorCode,\n"
     "\t\tconst std::string &errorMessage) {\n"
     "\tconst auto now = crl::now();\n"
     "\tconst auto lock = std::lock_guard(_framesMutex);\n"
     "\tauto &sender = _frames.senders[userId];\n"
     "\tif (!errorCode) {\n"
     "\t\t++sender.ok;\n"
     "\t\t_frames.lastOk[userId] = now;\n"
     "\t\t_health.failingSince = 0;\n"
     "\t\tForEachIncomingFrameEpoch(data, [&](const EpochPrefix &p) {\n"
     "\t\t\tAddEpoch(_frames.decryptEpochs, p, kStatusMaxEpochs);\n"
     "\t\t});\n"
     "\t\treturn;\n"
     "\t} else if (*errorCode\n"
     "\t\t== int(tde2e_api::ErrorCode::Decrypt_UnknownEpoch)) {\n"
     "\t\t++sender.unknownEpoch;\n"
     "\t\tForEachIncomingFrameEpoch(data, [&](const EpochPrefix &p) {\n"
     "\t\t\tAddEpoch(_frames.unknownEpochs, p, kStatusMaxUnknownEpochs);\n"
     "\t\t});\n"
     "\t} else if (errorMessage == \"Message is too old\") {\n"
     "\t\t++sender.tooOld;\n"
     "\t\treturn;\n"
     "\t} else if (errorMessage == \"Message is already processed\") {\n"
     "\t\t++sender.duplicate;\n"
     "\t\treturn;\n"
     "\t} else {\n"
     "\t\t++sender.failed;\n"
     "\t}\n"
     "\tif (!_health.failingSince) {\n"
     "\t\t_health.failingSince = now;\n"
     "\t}\n"
     "\t_health.lastFailure = now;\n"
     "}\n"
     "\n"
     "auto EncryptDecrypt::takeFrames() -> Frames {\n"
     "\tconst auto lock = std::lock_guard(_framesMutex);\n"
     "\t++_frames.seq;\n"
     "\tauto result = _frames;\n"
     "\t_frames.senders.clear();\n"
     "\t_frames.decryptEpochs.clear();\n"
     "\t_frames.unknownEpochs.clear();\n"
     "\t_frames.encrypted = 0;\n"
     "\t_frames.encryptFailed = 0;\n"
     "\treturn result;\n"
     "}\n"
     "\n"
     "auto EncryptDecrypt::health() const -> Health {\n"
     "\tconst auto lock = std::lock_guard(_framesMutex);\n"
     "\treturn _health;\n"
     "}\n"
     "\n"
     "void EncryptDecrypt::reset() {\n"
     "\tconst auto lock = std::lock_guard(_framesMutex);\n"
     "\t_frames = Frames();\n"
     "\t_health = Health();\n"
     "}\n"),
    # The block of sub-chain 0 applied last, and the index the server named
    # after its last block (task 094).
    (TDE2E_API,
     "\t\tconst auto result = tde2e_api::call_apply_block(\n"
     "\t\t\tlibId(),\n"
     "\t\t\tSlice(last.data));\n"
     "\t\tif (!result.is_ok()) {\n"
     "\t\t\tLOG_AND_FAIL(result.error(), CallFailure::Unknown);\n"
     "\t\t} else {\n"
     "\t\t\t_participantsSet = ParseParticipantsSet(result.value());\n"
     "\t\t}\n",
     "\t\tconst auto result = tde2e_api::call_apply_block(\n"
     "\t\t\tlibId(),\n"
     "\t\t\tSlice(last.data));\n"
     "\t\tif (!result.is_ok()) {\n"
     "\t\t\tLOG_AND_FAIL(result.error(), CallFailure::Unknown);\n"
     "\t\t} else {\n"
     "\t\t\t_appliedBlock0 = StoredBlockPrefix(last.data); // pluma: task 094\n"
     "\t\t\t_participantsSet = ParseParticipantsSet(result.value());\n"
     "\t\t}\n"),
    (TDE2E_API,
     "\tsetId({ uint64(id.value()) });\n",
     "\tsetId({ uint64(id.value()) });\n"
     "\t_appliedBlock0 = StoredBlockPrefix(last.data); // pluma: task 094\n"),
    (TDE2E_API,
     "\t\t\t\tconst auto result = tde2e_api::call_apply_block(\n"
     "\t\t\t\t\tlibId(),\n"
     "\t\t\t\t\tslice);\n"
     "\t\t\t\tif (!result.is_ok()) {\n"
     "\t\t\t\t\tLOG_AND_FAIL(result.error(), CallFailure::Unknown);\n"
     "\t\t\t\t\treturn;\n"
     "\t\t\t\t}\n"
     "\t\t\t\t_participantsSet = ParseParticipantsSet(result.value());\n",
     "\t\t\t\tconst auto result = tde2e_api::call_apply_block(\n"
     "\t\t\t\t\tlibId(),\n"
     "\t\t\t\t\tslice);\n"
     "\t\t\t\tif (!result.is_ok()) {\n"
     "\t\t\t\t\tLOG_AND_FAIL(result.error(), CallFailure::Unknown);\n"
     "\t\t\t\t\treturn;\n"
     "\t\t\t\t}\n"
     "\t\t\t\t// pluma: task 094.\n"
     "\t\t\t\t_appliedBlock0 = StoredBlockPrefix(waiting.begin()->second.data);\n"
     "\t\t\t\t_participantsSet = ParseParticipantsSet(result.value());\n"),
    (TDE2E_API,
     "\tExpects(subchain >= 0 && subchain < kSubChainsCount);\n"
     "\n"
     "\tif (!subchain && !blocks.empty() && indexAfterLast > _lastBlock0Height) {\n",
     "\tExpects(subchain >= 0 && subchain < kSubChainsCount);\n"
     "\n"
     "\tif (!subchain) {\n"
     "\t\t_serverNext0 = std::max(_serverNext0, indexAfterLast); // pluma: task 094\n"
     "\t}\n"
     "\tif (!subchain && !blocks.empty() && indexAfterLast > _lastBlock0Height) {\n"),
    (TDE2E_API,
     "rpl::producer<ParticipantsSet> Call::participantsSetValue() const {\n"
     "\treturn _participantsSet.value();\n"
     "}\n",
     "rpl::producer<ParticipantsSet> Call::participantsSetValue() const {\n"
     "\treturn _participantsSet.value();\n"
     "}\n"
     "\n"
     "Call::Status Call::status() const {\n"
     "\tauto result = Status();\n"
     "\tif (_id) {\n"
     "\t\tfor (auto i = 0; i != kSubChainsCount; ++i) {\n"
     "\t\t\tresult.offsets[i] = _subchains[i].height;\n"
     "\t\t}\n"
     "\t}\n"
     "\tif (_failure) {\n"
     "\t\tresult.error = _failureCode\n"
     "\t\t\t? _failureCode\n"
     "\t\t\t: int(tde2e_api::ErrorCode::UnknownError);\n"
     "\t\treturn result;\n"
     "\t} else if (!_id || _appliedBlock0.isEmpty()) {\n"
     "\t\treturn result;\n"
     "\t}\n"
     "\tconst auto height = tde2e_api::call_get_height(libId());\n"
     "\tif (height.is_ok()) {\n"
     "\t\tresult.height = height.value();\n"
     "\t\tresult.lastBlock = _appliedBlock0;\n"
     "\t}\n"
     "\treturn result;\n"
     "}\n"
     "\n"
     "crl::time Call::laggingSince(crl::time now) {\n"
     "\tauto height = std::optional<int>();\n"
     "\tif (!failed() && _id) {\n"
     "\t\tconst auto result = tde2e_api::call_get_height(libId());\n"
     "\t\tif (result.is_ok()) {\n"
     "\t\t\theight = result.value();\n"
     "\t\t}\n"
     "\t}\n"
     "\tif (!height || _serverNext0 <= *height + 1) {\n"
     "\t\t_laggingSince = 0;\n"
     "\t} else if (!_laggingSince || _laggingHeight != *height) {\n"
     "\t\t_laggingSince = now;\n"
     "\t\t_laggingHeight = *height;\n"
     "\t}\n"
     "\treturn _laggingSince;\n"
     "}\n"
     "\n"
     "QByteArray StatusReport(\n"
     "\t\tconst Call::Status &status,\n"
     "\t\tEncryptDecrypt &frames) {\n"
     "\tconst auto taken = frames.takeFrames();\n"
     "\tconst auto now = crl::now();\n"
     "\tconst auto epochs = [](\n"
     "\t\t\tconst std::vector<EncryptDecrypt::EpochPrefix> &list) {\n"
     "\t\tauto result = QJsonArray();\n"
     "\t\tfor (const auto &prefix : list) {\n"
     "\t\t\tresult.push_back(EpochPrefixHex(prefix));\n"
     "\t\t}\n"
     "\t\treturn result;\n"
     "\t};\n"
     "\tstruct Sender {\n"
     "\t\tint64 user = 0;\n"
     "\t\tEncryptDecrypt::SenderFrames frames;\n"
     "\t\tint64 lastOkMs = -1;\n"
     "\t};\n"
     "\tauto senders = std::vector<Sender>();\n"
     "\tsenders.reserve(taken.senders.size());\n"
     "\tfor (const auto &[user, counted] : taken.senders) {\n"
     "\t\tconst auto i = taken.lastOk.find(user);\n"
     "\t\tsenders.push_back({\n"
     "\t\t\t.user = user,\n"
     "\t\t\t.frames = counted,\n"
     "\t\t\t.lastOkMs = (i != end(taken.lastOk)) ? (now - i->second) : -1,\n"
     "\t\t});\n"
     "\t}\n"
     "\t// Over the limits, the senders decrypted longest ago are left out; the\n"
     "\t// rest stay in the order of their ids.\n"
     "\tconst auto leaveOutOldest = [&] {\n"
     "\t\tsenders.erase(std::max_element(\n"
     "\t\t\tbegin(senders),\n"
     "\t\t\tend(senders),\n"
     "\t\t\t[](const Sender &a, const Sender &b) {\n"
     "\t\t\t\treturn a.lastOkMs < b.lastOkMs;\n"
     "\t\t\t}));\n"
     "\t};\n"
     "\twhile (int(senders.size()) > kStatusMaxSenders) {\n"
     "\t\tleaveOutOldest();\n"
     "\t}\n"
     "\tconst auto serialize = [&] {\n"
     "\t\tauto list = QJsonArray();\n"
     "\t\tfor (const auto &sender : senders) {\n"
     "\t\t\tlist.push_back(QJsonObject{\n"
     "\t\t\t\t{ u\"user\"_q, qint64(sender.user) },\n"
     "\t\t\t\t{ u\"ok\"_q, qint64(sender.frames.ok) },\n"
     "\t\t\t\t{ u\"unknownEpoch\"_q, qint64(sender.frames.unknownEpoch) },\n"
     "\t\t\t\t{ u\"tooOld\"_q, qint64(sender.frames.tooOld) },\n"
     "\t\t\t\t{ u\"duplicate\"_q, qint64(sender.frames.duplicate) },\n"
     "\t\t\t\t{ u\"failed\"_q, qint64(sender.frames.failed) },\n"
     "\t\t\t\t{ u\"lastOkMs\"_q, qint64(sender.lastOkMs) },\n"
     "\t\t\t});\n"
     "\t\t}\n"
     "\t\treturn QJsonDocument(QJsonObject{\n"
     "\t\t\t{ u\"colibriClass\"_q, u\"PlumaE2EStatus\"_q },\n"
     "\t\t\t{ u\"v\"_q, kStatusReportVersion },\n"
     "\t\t\t{ u\"seq\"_q, qint64(taken.seq) },\n"
     "\t\t\t{ u\"height\"_q, status.height },\n"
     "\t\t\t{ u\"lastBlock\"_q, QString::fromLatin1(status.lastBlock.toHex()) },\n"
     "\t\t\t{ u\"offset0\"_q, status.offsets[0] },\n"
     "\t\t\t{ u\"offset1\"_q, status.offsets[1] },\n"
     "\t\t\t{ u\"error\"_q, status.error },\n"
     "\t\t\t{ u\"sendEpochs\"_q, epochs(taken.sendEpochs) },\n"
     "\t\t\t{ u\"decryptEpochs\"_q, epochs(taken.decryptEpochs) },\n"
     "\t\t\t{ u\"unknownEpochs\"_q, epochs(taken.unknownEpochs) },\n"
     "\t\t\t{ u\"encrypted\"_q, qint64(taken.encrypted) },\n"
     "\t\t\t{ u\"encryptFailed\"_q, qint64(taken.encryptFailed) },\n"
     "\t\t\t{ u\"senders\"_q, list },\n"
     "\t\t}).toJson(QJsonDocument::Compact);\n"
     "\t};\n"
     "\tauto result = serialize();\n"
     "\twhile (result.size() > kStatusMaxSize && !senders.empty()) {\n"
     "\t\tleaveOutOldest();\n"
     "\t\tresult = serialize();\n"
     "\t}\n"
     "\treturn result;\n"
     "}\n"),
    # tgcalls sends the report over its data channel to the SFU.
    (TGCALLS_GROUP_H,
     "    void internal_addCustomNetworkEvent(bool isRemoteConnected);\n"
     "\n"
     "private:\n",
     "    void internal_addCustomNetworkEvent(bool isRemoteConnected);\n"
     "\n"
     "    // pluma: a status report of the call's end-to-end key to the SFU over\n"
     "    // the data channel, made only while it is open (task 094).\n"
     "    void sendE2EStatus(std::function<std::string()> makeReport);\n"
     "\n"
     "private:\n"),
    (TGCALLS_GROUP,
     "    void maybeUpdateRemoteVideoConstraints() {\n"
     "        if (!_isDataChannelOpen) {\n",
     "    // pluma: the status report of the end-to-end key (task 094, ADR 0060\n"
     "    // §5). It is made only while the data channel is open: the frames it\n"
     "    // counts stay for the next one otherwise.\n"
     "    void sendE2EStatus(std::function<std::string()> const &makeReport) {\n"
     "        if (!_isDataChannelOpen) {\n"
     "            return;\n"
     "        }\n"
     "        auto report = makeReport();\n"
     "        if (report.empty()) {\n"
     "            return;\n"
     "        }\n"
     "        _networkManager->perform([report = std::move(report)](GroupNetworkManager *networkManager) {\n"
     "            networkManager->sendDataChannelMessage(report);\n"
     "        });\n"
     "    }\n"
     "\n"
     "    void maybeUpdateRemoteVideoConstraints() {\n"
     "        if (!_isDataChannelOpen) {\n"),
    (TGCALLS_GROUP,
     "void GroupInstanceCustomImpl::internal_addCustomNetworkEvent(bool isRemoteConnected) {\n"
     "    _internal->perform([isRemoteConnected](GroupInstanceCustomInternal *internal) {\n"
     "        internal->internal_addCustomNetworkEvent(isRemoteConnected);\n"
     "    });\n"
     "}\n",
     "void GroupInstanceCustomImpl::internal_addCustomNetworkEvent(bool isRemoteConnected) {\n"
     "    _internal->perform([isRemoteConnected](GroupInstanceCustomInternal *internal) {\n"
     "        internal->internal_addCustomNetworkEvent(isRemoteConnected);\n"
     "    });\n"
     "}\n"
     "\n"
     "void GroupInstanceCustomImpl::sendE2EStatus(std::function<std::string()> makeReport) {\n"
     "    _internal->perform([makeReport = std::move(makeReport)](GroupInstanceCustomInternal *internal) {\n"
     "        internal->sendE2EStatus(makeReport);\n"
     "    });\n"
     "}\n"),
)

# Blocks removed whole: (file, head, tail, what takes their place, texts the
# block must hold).
GROUP_CALLS_E2E_SPANS = (
    # The stream URL and key in the settings of a call (shown for an RTMP
    # stream alone).
    (GROUP_CALL_SETTINGS,
     "\tif (rtmp && !call->rtmpInfo().url.isEmpty()) {\n",
     "\t\tstate->data.fire(call->rtmpInfo());\n"
     "\n"
     "\t\taddDivider();\n"
     "\t\tUi::AddSkip(layout);\n"
     "\t}\n",
     "\t// pluma: no stream URL and key: no RTMP (task 094).\n",
     ("MTPphone_GetGroupCallStreamRtmpUrl(", "StartRtmpProcess::FillRtmpRows(")),
)


def group_calls_e2e_strings():
    return "".join(f'"{key}" = "{value}";\n' for key, value in GROUP_CALLS_E2E_STRINGS.items())


def group_calls_e2e(tree):
    for rel, old, new in GROUP_CALLS_E2E_EDITS:
        tree.replace(rel, old, new)
    for rel, head, tail, block, had in GROUP_CALLS_E2E_SPANS:
        tree.replace_block(rel, head, tail, block, must_contain=had)
    tree.replace(LANG, GROUP_CALLS_E2E_STRINGS_AFTER, GROUP_CALLS_E2E_STRINGS_AFTER + group_calls_e2e_strings())


# What the edits leave, each exactly so many times: another place that checks
# conference() or joins, creates or streams a call stops the patch until it is
# read.
GROUP_CALLS_E2E_GUARDS = (
    (GROUP_CALL, "conference()", 10),
    (GROUP_CALL, "e2e()", 5),
    (GROUP_CALL, "initConferenceE2E();", 5),
    (GROUP_CALL, "removeConferenceParticipants(", 3),
    # A rejoin with a new key goes by the rules (scheduleE2ERejoin); the
    # rejoins left are those of the transport and of membership.
    (GROUP_CALL, "scheduleE2ERejoin(", 7),
    (GROUP_CALL, "startRejoin();", 9),
    # The report goes over the main connection alone.
    (GROUP_CALL, "sendE2EStatus(", 3),
    (GROUP_CALL, "_instance->sendE2EStatus(", 1),
    (GROUP_CALL, "setInstanceMode(InstanceMode::Stream)", 1),
    (GROUP_CALL, "JoinBroadcastStream{", 0),
    (GROUP_CALL, 'value("stream")', 0),
    (GROUP_CALL_MEMBERS, "conference()", 2),
    (DATA_GROUP_CALL, "session().data().registerGroupCall(this);", 1),
    (TDE2E_API, "tde2e_api::call_encrypt(", 1),
    (TDE2E_API, "tde2e_api::call_decrypt(", 1),
    (TGCALLS_GROUP, "sendDataChannelMessage(", 2),
)
# The same in every source: {text: {file: count}}, every other file none.
GROUP_CALLS_E2E_SOURCES = {
    "MTPphone_JoinGroupCall(": {GROUP_CALL: 1},
    "MTPphone_CreateGroupCall(": {GROUP_CALL: 1},
    "MTPphone_GetGroupCallJoinAs(": {CHOOSE_JOIN_AS: 1},
    "f_rtmp_stream": {},
    "showStartWithRtmp": {},
    "StartRtmpProcess": {GROUP_CALL_RTMP + "cpp": 10, GROUP_CALL_RTMP + "h": 3},
    "MTPphone_GetGroupCallStreamRtmpUrl(": {GROUP_CALL_RTMP + "cpp": 1},
    "GroupCallOrigin::VideoStream": {GROUP_CALL: 1, DATA_GROUP_CALL: 2},
    "StartLive": {},
    # No recording but in the menu's entry that never shows.
    "toggleRecording(": {GROUP_CALL: 1, GROUP_CALL_H: 1, GROUP_CALL_MENU: 1},
    "Box(StartGroupCallRecordingBox": {GROUP_CALL_MENU: 1},
}


def verify_group_calls_e2e(tree):
    entries = [(m["key"], m["value"]) for m in lang_entries(tree.read(LANG))]
    for key, value in GROUP_CALLS_E2E_STRINGS.items():
        if entries.count((key, value)) != 1 or [k for k, _ in entries].count(key) != 1:
            raise PatchError(f"{LANG}: {key} is not the text of end-to-end group calls (task 094)")
    for rel, old, new in GROUP_CALLS_E2E_EDITS:
        text = tree.read(rel)
        # An edit that removes the text leaves nothing to find but its absence.
        if (new and text.count(new) != 1) or old in (text.replace(new, "") if new else text):
            raise PatchError(f"{rel}: the edit of end-to-end group calls (task 094) is not there")
    for rel, head, _, block, had in GROUP_CALLS_E2E_SPANS:
        text = tree.read(rel)
        if head in text or text.count(block) != 1 or any(s in text for s in had):
            raise PatchError(f"{rel}: the block removed for end-to-end group calls (task 094) is still there")
    for rel, s, count in GROUP_CALLS_E2E_GUARDS:
        found = tree.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; "
                             "another place decides what end-to-end group calls (task 094) should")
    for rel in tree.sources():
        text = tree.scan(rel)
        for s, allowed in GROUP_CALLS_E2E_SOURCES.items():
            if text.count(s) != allowed.get(rel, 0):
                raise PatchError(f"{rel}: {text.count(s)} occurrences of {s!r}, expected {allowed.get(rel, 0)}; "
                                 "another way into a group call that is not end-to-end (task 094)")
    if "calls_group_rtmp" in tree.read(CMAKE_APP):
        raise PatchError(f"{CMAKE_APP}: still builds the RTMP stream of a group call (task 094)")
    api = tree.read(TDE2E_API)
    report = api[api.find("QByteArray StatusReport("):]
    keys = set(re.findall(r'u"(\w+)"_q', report[:report.find("\n}\n")])) - {"PlumaE2EStatus"}
    if keys != set(E2E_STATUS_FIELDS) | set(E2E_STATUS_SENDER_FIELDS):
        raise PatchError(f"{TDE2E_API}: the status report holds {', '.join(sorted(keys))}, "
                         "not the fields of E2E_STATUS_FIELDS (task 094)")
    for rel, values in ((TDE2E_API, E2E_STATUS_LIMITS), (GROUP_CALL, E2E_REJOIN_RULES)):
        text = tree.read(rel)
        for name, value in values.items():
            found = re.findall(rf"^constexpr [\w:]+ {re.escape(name)} = (.*);$", text, re.M)
            if found != [value]:
                raise PatchError(f"{rel}: {name} is {', '.join(found) or 'missing'}, not {value} "
                                 "of ADR 0060 §5 (task 094)")


def group_calls_e2e_edited():
    """The files group_calls_e2e() edits."""
    return tuple(sorted({rel for rel, _, _ in GROUP_CALLS_E2E_EDITS}
                        | {rel for rel, _, _, _, _ in GROUP_CALLS_E2E_SPANS} | {LANG}))


# The colours of calls (task 094 of the server repository; the owner's
# decision of 2026-11-12, variant A "sage"). Telegram's iOS app draws its
# call screen in three gradients of four points, by the state of the call
# (CallBackgroundLayer.swift 108-124, PrivateCallScreen.swift 799-812 of the
# pinned iOS): connecting 568FD6/626ED5/A667D5/7664DA, connected
# ACBD65/459F8D/53A4D1/3E917A, weak signal C0508D/F09536/CE5081/FC7C4C.
# Pluma's, the same points in the same order: connecting #3a4a3c #4f6e52
# #2c3a2d #5b7a5e, connected #5b7a5e #6f8f72 #4f6e52 #7fa082, weak signal
# #8a5a44 #a86b4c #7a4e3b #b97a55. Telegram Desktop has no such gradients:
# its one-to-one call fills the background with callBgOpaque, or with the
# peer's colours of their profile (calls_panel_background.cpp 62-95), and its
# group call draws in the call palette of lib_ui's colors.palette, the same
# in every theme the theme does not override. So:
# - the one-to-one call takes the gradients of the iOS app, in Pluma's
#   colours, where it filled callBgOpaque (new keys callBgConnecting1-4,
#   callBgConnected1-4, callBgWeak1-4; PanelBackground::setState from the
#   call's state and signal bars, as iOS chooses it); the peer's own colours
#   stay upstream's;
# - the call palette takes Pluma's colours by meaning: the backgrounds of the
#   one-to-one and group calls, their lists and menus the dark sage of the
#   connecting gradient and of the palette of task 017 (#2c3a2d, #36473a,
#   #3a4a3c, #4f6e52); Telegram's blue and purple (muted, the members'
#   status) the connecting gradient or the sage accent of the dark themes
#   (#9dbb9f); green (speaking, live) the connected gradient and the light
#   sage #b2ceb4; red and pink (muted by an admin, a raised hand, the bar
#   of a scheduled call) the weak signal's;
# - the answer and hang-up buttons and leaving a call keep the green and
#   red every call app has, the ones of Classic in every theme (Telegram's
#   Night and the night base answer in blue);
# - the volume of a member, red to blue in the code (calls_volume_item.cpp
#   262-267), the weak signal's to the accent.
# Every theme the app carries takes them: Classic (colors.palette), Tinted
# (night.tdesktop-theme) and Telegram's themes and bases (TELEGRAM_THEMES),
# which leave the new keys to Classic. verify_call_colors() stops a call
# palette with any other colour (but white and grey) and any of Telegram's
# call colours in the sources of calls.
# As (key, Telegram's value in Classic or None for a new key, Pluma's value).
CALL_COLORS = (
    ("callBg", "#26282cf2", "#2c3a2df2"),
    ("callBgOpaque", "#1b1f23", "#2c3a2d"),
    ("callBgButton", "#1b1f237f", "#2c3a2d7f"),
    ("callAnswerBg", "#66c95b", "#66c95b"),
    ("callAnswerRipple", "#52b149", "#52b149"),
    ("callAnswerBgOuter", "#50eb4126", "#50eb4126"),
    ("callHangupBg", "#d75a5a", "#d75a5a"),
    ("callHangupRipple", "#c04646", "#c04646"),
    ("groupCallBg", "#1a2026", "#2c3a2d"),
    ("groupCallActiveFg", "#4db8ff", "#9dbb9f"),
    ("groupCallMembersBg", "#2c333d", "#36473a"),
    ("groupCallMembersBgOver", "#323a45", "#3a4a3c"),
    ("groupCallMembersBgRipple", "#39424f", "#4f6e52"),
    ("groupCallMemberActiveIcon", "#8deb90", "#b2ceb4"),
    ("groupCallMemberActiveStatus", "#8deb90", "#b2ceb4"),
    ("groupCallMemberInactiveStatus", "#61c0ff", "#9dbb9f"),
    ("groupCallMemberMutedIcon", "#ed7372", "#b97a55"),
    ("groupCallLive1", "#0dcc39", "#6f8f72"),
    ("groupCallLive2", "#0bb6bd", "#7fa082"),
    ("groupCallMuted1", "#0992ef", "#4f6e52"),
    ("groupCallMuted2", "#16ccfb", "#5b7a5e"),
    ("groupCallForceMutedBar1", "#c65493", "#8a5a44"),
    ("groupCallForceMutedBar2", "#7a6af1", "#5b7a5e"),
    ("groupCallForceMutedBar3", "#5f95e8", "#4f6e52"),
    ("groupCallForceMuted1", "#4f9cff", "#4f6e52"),
    ("groupCallForceMuted2", "#9b52e9", "#5b7a5e"),
    ("groupCallForceMuted3", "#eb5353", "#a86b4c"),
    ("groupCallMenuBg", "#292d33", "#36473a"),
    ("groupCallMenuBgOver", "#343940", "#3a4a3c"),
    ("groupCallMenuBgRipple", "#3a4047", "#4f6e52"),
    ("groupCallLeaveBg", "#f75c5c7f", "#f75c5c7f"),
    ("groupCallLeaveBgRipple", "#f75c5c9e", "#f75c5c9e"),
    ("callBgConnecting1", None, "#3a4a3c"),
    ("callBgConnecting2", None, "#4f6e52"),
    ("callBgConnecting3", None, "#2c3a2d"),
    ("callBgConnecting4", None, "#5b7a5e"),
    ("callBgConnected1", None, "#5b7a5e"),
    ("callBgConnected2", None, "#6f8f72"),
    ("callBgConnected3", None, "#4f6e52"),
    ("callBgConnected4", None, "#7fa082"),
    ("callBgWeak1", None, "#8a5a44"),
    ("callBgWeak2", None, "#a86b4c"),
    ("callBgWeak3", None, "#7a4e3b"),
    ("callBgWeak4", None, "#b97a55"),
)
# The keys of colors.palette that draw calls: the one-to-one call and the
# group call, their top bars and buttons. Not the arrows of the list of calls
# (callArrow*) or the bar of a call in the main window (callBar*), which
# follow the theme's accent.
CALL_KEYS = re.compile(r"(?:call|groupCall)\w+")
CALL_KEYS_OUTSIDE = re.compile(r"callArrow\w*|callBar\w*")
# Telegram's colours of calls, which no source of calls may hold: the
# gradients of its iOS app, the volume colours of tdesktop and the colours
# CALL_COLORS replaces.
TELEGRAM_CALL_COLORS = ("568fd6", "626ed5", "a667d5", "7664da", "acbd65", "459f8d", "53a4d1", "3e917a",
                        "c0508d", "f09536", "ce5081", "fc7c4c", "f66464", "d0b738", "24cd80", "3bbcec")
PANEL_BACKGROUND = SOURCES + "/calls/calls_panel_background.cpp"
PANEL_BACKGROUND_H = SOURCES + "/calls/calls_panel_background.h"
CALLS_PANEL = SOURCES + "/calls/calls_panel.cpp"
VOLUME_ITEM = SOURCES + "/calls/group/calls_volume_item.cpp"

CALL_COLORS_EDITS = (
    (PANEL_BACKGROUND_H,
     "\t[[nodiscard]] QColor cardOverlay() const;\n"
     "\n"
     "private:\n",
     "\t[[nodiscard]] QColor cardOverlay() const;\n"
     "\n"
     "\t// pluma: the state of the call the background shows when the peer has\n"
     "\t// no colours of their own, as Telegram's iOS app shows it (task 094).\n"
     "\tenum class State {\n"
     "\t\tConnecting,\n"
     "\t\tConnected,\n"
     "\t\tWeakSignal,\n"
     "\t};\n"
     "\tvoid setState(State state);\n"
     "\n"
     "private:\n"),
    (PANEL_BACKGROUND_H,
     "\tstd::optional<Data::ColorProfileSet> _colors;\n",
     "\tstd::optional<Data::ColorProfileSet> _colors;\n"
     "\tState _state = State::Connecting; // pluma: task 094\n"),
    (PANEL_BACKGROUND,
     "constexpr auto kDarkOverlayOpacity = 0.14;\n"
     "constexpr auto kDarkenAboveLightness = 0.3;\n"
     "\n"
     "} // namespace\n",
     "constexpr auto kDarkOverlayOpacity = 0.14;\n"
     "constexpr auto kDarkenAboveLightness = 0.3;\n"
     "\n"
     "// pluma: the gradient of each state of the call, in Pluma's colours of\n"
     "// calls (task 094): Telegram's iOS app draws its call screen in three such\n"
     "// gradients, while connecting, connected and on a weak signal\n"
     "// (CallBackgroundLayer.swift 108-124), where Telegram Desktop fills one\n"
     "// colour. The last colour is the middle of the gradient (updateBrush).\n"
     "[[nodiscard]] std::vector<QColor> StateColors(PanelBackground::State state) {\n"
     "\tswitch (state) {\n"
     "\tcase PanelBackground::State::Connected: return {\n"
     "\t\tst::callBgConnected1->c,\n"
     "\t\tst::callBgConnected2->c,\n"
     "\t\tst::callBgConnected3->c,\n"
     "\t\tst::callBgConnected4->c,\n"
     "\t};\n"
     "\tcase PanelBackground::State::WeakSignal: return {\n"
     "\t\tst::callBgWeak1->c,\n"
     "\t\tst::callBgWeak2->c,\n"
     "\t\tst::callBgWeak3->c,\n"
     "\t\tst::callBgWeak4->c,\n"
     "\t};\n"
     "\tcase PanelBackground::State::Connecting: break;\n"
     "\t}\n"
     "\treturn {\n"
     "\t\tst::callBgConnecting1->c,\n"
     "\t\tst::callBgConnecting2->c,\n"
     "\t\tst::callBgConnecting3->c,\n"
     "\t\tst::callBgConnecting4->c,\n"
     "\t};\n"
     "}\n"
     "\n"
     "} // namespace\n"),
    (PANEL_BACKGROUND,
     "\tupdateColors();\n"
     "\tupdateEmojiId();\n"
     "\n"
     "\t_peer->session().changes().peerFlagsValue(\n",
     "\tupdateColors();\n"
     "\tupdateEmojiId();\n"
     "\n"
     "\t// pluma: the gradient of the call's state is made of the palette, which\n"
     "\t// upstream's fill of callBgOpaque read on each paint (task 094).\n"
     "\tstyle::PaletteChanged(\n"
     "\t) | rpl::on_next([=] {\n"
     "\t\t_brushSize = QSize();\n"
     "\t\tif (_updateCallback) {\n"
     "\t\t\t_updateCallback();\n"
     "\t\t}\n"
     "\t}, _lifetime);\n"
     "\n"
     "\t_peer->session().changes().peerFlagsValue(\n"),
    (PANEL_BACKGROUND,
     "\tif (!_colors || _colors->bg.empty()) {\n"
     "\t\tfor (const auto &rect : region) {\n"
     "\t\t\tp.fillRect(rect, st::callBgOpaque);\n"
     "\t\t}\n"
     "\t\treturn;\n"
     "\t}\n"
     "\n"
     "\tconst auto &colors = _colors->bg;\n"
     "\tif (colors.size() == 1) {\n",
     "\t// pluma: without colours of the peer's own, the gradient of the call's\n"
     "\t// state (task 094).\n"
     "\tconst auto own = _colors && !_colors->bg.empty();\n"
     "\tconst auto colors = own ? _colors->bg : StateColors(_state);\n"
     "\tif (colors.size() == 1) {\n"),
    (PANEL_BACKGROUND,
     "\t\tfor (const auto &rect : region) {\n"
     "\t\t\tp.fillRect(rect, _brush);\n"
     "\t\t}\n"
     "\t}\n"
     "\n"
     "\tconst auto emojiId = _currentEmojiId;\n",
     "\t\tfor (const auto &rect : region) {\n"
     "\t\t\tp.fillRect(rect, _brush);\n"
     "\t\t}\n"
     "\t}\n"
     "\tif (!own) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\n"
     "\tconst auto emojiId = _currentEmojiId;\n"),
    (PANEL_BACKGROUND,
     "rpl::lifetime &PanelBackground::lifetime() {\n"
     "\treturn _lifetime;\n"
     "}\n",
     "void PanelBackground::setState(State state) {\n"
     "\tif (_state == state) {\n"
     "\t\treturn;\n"
     "\t}\n"
     "\t_state = state;\n"
     "\t_brushSize = QSize();\n"
     "\tif (_updateCallback) {\n"
     "\t\t_updateCallback();\n"
     "\t}\n"
     "}\n"
     "\n"
     "rpl::lifetime &PanelBackground::lifetime() {\n"
     "\treturn _lifetime;\n"
     "}\n"),
    (CALLS_PANEL,
     "\t_background = std::make_unique<PanelBackground>(\n"
     "\t\t_user,\n"
     "\t\t[=] {\n"
     "\t\t\tupdateTextColors();\n"
     "\t\t\twidget()->update();\n"
     "\t\t});\n",
     "\t_background = std::make_unique<PanelBackground>(\n"
     "\t\t_user,\n"
     "\t\t[=] {\n"
     "\t\t\tupdateTextColors();\n"
     "\t\t\twidget()->update();\n"
     "\t\t});\n"
     "\n"
     "\t// pluma: the background shows the state of the call as Telegram's iOS\n"
     "\t// app does (PrivateCallScreen.swift 799-812): connecting until the call\n"
     "\t// is established and after it ends, then connected, or a weak signal\n"
     "\t// with no bar of it, which iOS takes as a quality of 0.2 or less of 4\n"
     "\t// bars (CallControllerNodeV2.swift 484) (task 094).\n"
     "\trpl::combine(\n"
     "\t\t_call->stateValue(),\n"
     "\t\t_call->signalBarCountValue()\n"
     "\t) | rpl::on_next([=](State state, int bars) {\n"
     "\t\tusing BackgroundState = PanelBackground::State;\n"
     "\t\t_background->setState((state != State::Established)\n"
     "\t\t\t? BackgroundState::Connecting\n"
     "\t\t\t: (bars == 0)\n"
     "\t\t\t? BackgroundState::WeakSignal\n"
     "\t\t\t: BackgroundState::Connected);\n"
     "\t}, _callLifetime);\n"),
    (VOLUME_ITEM,
     "\tconst auto colors = std::array<QColor, 4>{ {\n"
     "\t\tUi::ColorFromSerialized(0xF66464),\n"
     "\t\tUi::ColorFromSerialized(0xD0B738),\n"
     "\t\tUi::ColorFromSerialized(0x24CD80),\n"
     "\t\tUi::ColorFromSerialized(0x3BBCEC),\n"
     "\t} };\n",
     "\t// pluma: Pluma's colours of calls from quiet to loud, as Telegram's red,\n"
     "\t// yellow, green and blue: those of a weak signal, of a connected call and\n"
     "\t// the accent (task 094).\n"
     "\tconst auto colors = std::array<QColor, 4>{ {\n"
     "\t\tUi::ColorFromSerialized(0xB97A55),\n"
     "\t\tUi::ColorFromSerialized(0xA86B4C),\n"
     "\t\tUi::ColorFromSerialized(0x7FA082),\n"
     "\t\tUi::ColorFromSerialized(0x9DBB9F),\n"
     "\t} };\n"),
)


def call_colors_table():
    """The rows of CALL_COLORS as brand tables have them: key, Telegram's
    value ("-" for a new key), Pluma's."""
    return [(key, old or "-", new) for key, old, new in CALL_COLORS]


def theme_call_colors(text, where):
    """The colours of a theme with every key of CALL_COLORS it sets made
    Pluma's; a key it leaves out stays to Classic."""
    for key, _, new in CALL_COLORS:
        line = re.compile(rf"^{key}:[^;\n]*;", re.M)
        found = len(line.findall(text))
        if found > 1:
            raise PatchError(f"{where}: {found} occurrences of '{key}:', expected one or none")
        text = line.sub(f"{key}: {new};", text)
    return text


def call_colors(tree):
    """Pluma's colours of calls (task 094): CALL_COLORS in every theme, the
    gradients of the one-to-one call and the volume (CALL_COLORS_EDITS)."""
    tree.write(PALETTE, recolor(tree.read(PALETTE), call_colors_table(), PALETTE))
    night = night_colors(tree.read_bytes(NIGHT_THEME))
    tree.write_bytes(NIGHT_THEME, night_theme(theme_call_colors(night, NIGHT_THEME)))
    for rel in TELEGRAM_THEMES:
        data = tree.read_bytes(rel)
        tree.write_bytes(rel, with_colors(data, theme_call_colors(zipped_colors(data, rel), rel)))
    for rel, old, new in CALL_COLORS_EDITS:
        tree.replace(rel, old, new)


def is_neutral(value):
    """White, black or a grey: #rrggbb(aa) whose channels differ by less than
    an eighth."""
    m = re.fullmatch(r"#([0-9a-fA-F]{6})([0-9a-fA-F]{2})?", value)
    if not m:
        return False
    channels = [int(m.group(1)[i:i + 2], 16) for i in (0, 2, 4)]
    return max(channels) - min(channels) < 0.12 * 255


def call_sources(tree):
    """The sources that draw calls: those of calls/ and the call controls
    and bars of ui/."""
    return [rel for rel in tree.sources()
            if rel.startswith(SOURCES + "/calls/")
            or re.match(re.escape(SOURCES) + r"/ui/(?:controls/call_|chat/group_call_)", rel)]


def verify_call_colors(tree):
    """Pluma's colours of calls in every theme the app carries and nothing of
    Telegram's in the sources of calls (task 094)."""
    day = palette_values(tree.read(PALETTE))
    themes = [(PALETTE, day), (NIGHT_THEME, {**day, **palette_values(night_colors(tree.read_bytes(NIGHT_THEME)))})]
    themes += [(rel, {**day, **palette_values(zipped_colors(tree.read_bytes(rel), rel))}) for rel in TELEGRAM_THEMES]
    pluma = {key: new for key, _, new in CALL_COLORS}
    keys = [key for key in day if CALL_KEYS.fullmatch(key) and not CALL_KEYS_OUTSIDE.fullmatch(key)]
    for key in pluma:
        if key not in keys:
            raise PatchError(f"{PALETTE}: no {key} of the colours of calls (task 094)")
    for where, values in themes:
        for key in keys:
            color = resolve(values, key)
            if key in pluma:
                if color.lower() != pluma[key]:
                    raise PatchError(f"{where}: {key} of calls is {color}, not Pluma's {pluma[key]} (task 094)")
            elif not is_neutral(color):
                raise PatchError(f"{where}: {key} of calls is {color}, not a colour of CALL_COLORS (task 094)")
    for rel, old, new in CALL_COLORS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of the colours of calls (task 094) is not there")
    telegram = re.compile(r"(?:#|0x)(" + "|".join(TELEGRAM_CALL_COLORS + tuple(
        old[1:7] for _, old, new in CALL_COLORS if old and old != new)) + r")(?![0-9a-fA-F])", re.I)
    styles = [p.relative_to(tree.root).as_posix() for p in sorted((tree.root / SOURCES / "calls").rglob("*.style"))]
    for rel in call_sources(tree) + styles:
        m = telegram.search(tree.read(rel))
        if m:
            raise PatchError(f"{rel}: Telegram's colour of calls {m.group(0)} (task 094)")


def call_colors_edited():
    """The text files call_colors() edits."""
    return tuple(dict.fromkeys((PALETTE,) + tuple(rel for rel, _, _ in CALL_COLORS_EDITS)))


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
    ap.add_argument("--update-keys", required=True, help="the folder of Pluma's update root key and manifest (config/update)")
    ap.add_argument("--build", type=int, default=0, help="the build number, added to AppVersion")
    ap.add_argument("--update-prefix", default="", help="the update prefix instead of PLUMA_UPDATE_PREFIX (a development build)")
    ap.add_argument("--data-name", default="", help="the name of the data folder instead of the app's (a development build)")
    a = ap.parse_args(args)
    try:
        app = load_env(a.app)
        if a.update_prefix:
            app["PLUMA_UPDATE_PREFIX"] = a.update_prefix
        if a.data_name:
            app["PLUMA_DATA_NAME"] = a.data_name
        c = Config(load_env(a.upstream), app, a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text(), read_update_keys(a.update_keys), a.build)
        tree = Tree(a.source)
        if (tree.root / MARKER).exists():
            raise PatchError(f"{a.source} is patched already; fetch it again (ci/fetch-upstream.sh)")
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    address = c.ipv4 + (f", {c.ipv6}" if c.ipv6 else "")
    print(f"patch: {c.app_id} \"{c.app_name}\" {c.release_version}, api_id {c.api_id}, layer {c.layer}, "
          f"server {address} port {c.port}, server key {c.fingerprint:#018x} ({c.fingerprint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
