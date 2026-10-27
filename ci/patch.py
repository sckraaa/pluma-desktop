#!/usr/bin/env python3
"""Turns a checkout of telegramdesktop/tdesktop into the Pluma desktop client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. After the edits the result is checked
again: no Telegram datacenter address or server key is left in the client's
sources, the fallbacks that reach Telegram are never started, and the
identity is Pluma's.

The api_id and api_hash are not edits: the build passes them to CMake
(-D TDESKTOP_API_ID / TDESKTOP_API_HASH), together with the options that
compile out the updater and the crash reports (the patch makes CMake refuse
a configuration without them).

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import hashlib
import ipaddress
import pathlib
import re
import sys
import uuid

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
DESKTOP_FILE = "lib/xdg/org.telegram.desktop.desktop"
QT_VERSION_PY = "Telegram/build/qt_version.py"
PREPARE = "Telegram/build/prepare/prepare.py"
DOCKER_ENV = "Telegram/build/docker/centos_env"
BUILDING_WIN = "docs/building-win.md"
LINUX_WORKFLOW = ".github/workflows/linux.yml"
# In the cmake_helpers submodule at cmake/.
CMAKE_VARIABLES = "cmake/variables.cmake"

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
UPSTREAM_PATHS = (".gitmodules", SOURCES, CMAKE_APP, CMAKE_OPTIONS, PLIST, WIN_RC, DESKTOP_FILE,
                  QT_VERSION_PY, PREPARE, DOCKER_ENV, BUILDING_WIN, LINUX_WORKFLOW)
# The same for files of submodules: (submodule, path inside it).
SUBMODULE_PATHS = (("cmake", "variables.cmake"),)

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
        try:
            return (self.root / rel).read_bytes().decode("utf-8")
        except FileNotFoundError:
            raise PatchError(f"{rel}: missing; upstream moved it, or the checkout lacks it")

    def scan(self, rel):
        """A file to search, whatever its encoding."""
        return (self.root / rel).read_bytes().decode("utf-8", errors="replace")

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))

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
          PLIST, DESKTOP_FILE, PREPARE)


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
)


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
    for rel in EDITED:
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

    # tg:// and tonsite:// stay with Telegram Desktop on the same computer:
    # no registration at the first start; "registertg" typed in Settings
    # still takes them over on request, under Pluma's own names.
    tree.replace_body(APPLICATION, "void Application::autoRegisterUrlScheme() {\n", "\n}\n",
                      "\t// pluma: tg:// and tonsite:// links stay with Telegram Desktop on the\n"
                      "\t// same computer; \"registertg\" typed in Settings takes them over.",
                      must_contain=("RegisterUrlScheme();", "OptionSkipUrlSchemeRegister"))
    tree.replace(APPLICATION, '\t\t.shortAppName = u"tdesktop"_q,\n', '\t\t.shortAppName = u"pluma"_q,\n', count=2)
    tree.replace_block(PLIST, "\t<key>CFBundleURLTypes</key>\n", "\n\t</array>\n", "",
                       must_contain=("<string>tg</string>", "<string>tonsite</string>"))

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
               # The links stay with Telegram Desktop.
               ("MimeType=x-scheme-handler/tg;x-scheme-handler/tonsite;\n", ""),
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
    if re.search(r"void Application::autoRegisterUrlScheme\(\) \{\n[^}]*RegisterUrlScheme\(", tree.read(APPLICATION)):
        raise PatchError(f"{APPLICATION}: still registers tg:// at the first start")

    for rel, traces in ((VERSION_H, ('"Telegram Desktop"', '"Telegram"_cs', "Unofficial")),
                        (CONFIG_H, ("87A94AB0-E370-4cde-98D3-ACC110C5967D",)),
                        (LAUNCHER, ('u"TelegramDesktop"_q',)),
                        (LINUX, ('return u"org.telegram.desktop', "/.TelegramDesktop/")),
                        (DESKTOP_FILE, ("Telegram", "x-scheme-handler/tg")),
                        (WIN_APP_ID, ('L"Telegram.TelegramDesktop";', "Telegram.lnk")),
                        (WIN_TOAST, ("F11932D3-6110-4BBC-9B02-B2EC07A1BD19",)),
                        (WIN_SPECIFIC, ("Telegram.lnk",)),
                        (WIN_RC, ("Telegram FZ-LLC", "Telegram Desktop")),
                        (CMAKE_APP, ("com.tdesktop.Telegram",)),
                        (PLIST, ("<string>tg</string>", "Telegram Desktop"))):
        text = tree.read(rel)
        for s in traces:
            if s in text:
                raise PatchError(f"{rel}: Telegram Desktop's {s!r} is still there")
    prepare = tree.read(PREPARE)
    if "mingw-w64-x86_64-" in prepare or "msys64\\\\mingw64" in prepare:
        raise PatchError(f"{PREPARE}: still asks MSYS2 for the msvcrt-based packages it removed")
    if "dump_syms.vcxproj" in prepare:
        raise PatchError(f"{PREPARE}: still builds breakpad's dump_syms on Windows")
    if f'constexpr auto AppName = "{c.app_name}"_cs;' not in tree.read(VERSION_H):
        raise PatchError(f"{VERSION_H}: the app is not {c.app_name}")
    if f'return u"{c.app_id}"_q;' not in tree.read(LINUX):
        raise PatchError(f"{LINUX}: the application ID is not {c.app_id}")


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if args == ["--paths"]:
        print("\n".join(UPSTREAM_PATHS))
        return 0
    if args == ["--submodule-paths"]:
        print("\n".join(f"{sub} {path}" for sub, path in SUBMODULE_PATHS))
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 epilog="patch.py --paths and --submodule-paths print the upstream paths the patch reads.")
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
