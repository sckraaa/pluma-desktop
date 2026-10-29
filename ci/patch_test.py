#!/usr/bin/env python3
import io
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Telegram's production and test server keys, as tdesktop carries them,
# with the fingerprints the server announces for them.
TELEGRAM_PROD = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----"""

TELEGRAM_TEST = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----"""

# A 2048-bit key of no server, for a server build.
OTHER_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAmVCNU9+WBRzHykS1SspkijEuCZxIep2MXqf7c0d+6QcgEdMWTZjh
wBLkrfGiDtNvsVD5ij8JQZpFJvXohmKdh5UZb0mBLKOJFCpvSqSp0Ia3GJxkUG1t
BTvVvC34pf0wLoJQPULUs5bORnzubr+MEIn5maS2yXyI0blKrop9utO3ke7FSpAw
Q6c0Bs+LgoJq8vAhBsetZWVRImNPx8jgrnGts/oIvepCds6NQjPNEsEcraWHoVrM
pPrdMoxq2eXN5HmKAGwqJc68udQzrXH3tF0evqNMI2g2dUI/gjsD5F7q4/gJbAC8
b9dKEFwjKCugpszC92HAbuFIxS8VG/fNvQIDAQAB
-----END RSA PUBLIC KEY-----"""

# A 1024-bit key.
SHORT_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALq+uxafbIeJrZUD2Toafbh0znXSHjOEGmp0OYsbqh1WOL//KGwa8WcM
vJey5IOJDKqmyFBURdP6+0IuF3RgEvhPrCXTLFLSWgGTIZOUGkGO/NOVyzzKP9I4
cHpcIp/hW3HkD564M7f9BbGSkXItXbTwpiEWj0kXJ0b0I1OSFYxRAgMBAAE=
-----END RSA PUBLIC KEY-----"""

# Telegram's key of its update packages, which may stay in config.h and
# _other/packer.cpp only.
UPDATE_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMA4ViQrjkPZ9xj0lrer3r23JvxOnrtE8nI69XLGSr+sRERz9YnUptnU
BZpkIfKaRcl6XzNJiN28cVwO1Ui5JSa814UAiDHzWUqCaXUiUEQ6NmNTneiGx2sQ
+9PKKlb8mmr3BB9A45ZNwLT6G9AK3+qkZLHojeSA+m84/a6GP4svAgMBAAE=
-----END RSA PUBLIC KEY-----"""

DEV_KEY = (ROOT / "config/dev/server_public.pem").read_text()


def fingerprint(pem):
    return patch.key_fingerprint(*patch.parse_pkcs1_public_key(pem))


def cpp_literal(pem):
    """A key as tdesktop writes it in a string literal."""
    n, e = patch.parse_pkcs1_public_key(pem)
    return 'const char *k = "\\\n' + patch.cpp_key(patch.canonical_pem(n, e)) + '";\n'


class KeyTest(unittest.TestCase):
    def test_telegram_fingerprints(self):
        self.assertEqual(fingerprint(TELEGRAM_PROD), 0xD09D1D85DE64FD85)
        self.assertEqual(fingerprint(TELEGRAM_TEST), 0xB25898DF208D2603)
        self.assertEqual((fingerprint(TELEGRAM_PROD), fingerprint(TELEGRAM_TEST)), patch.TELEGRAM_FINGERPRINTS)

    def test_dev_key_fingerprint(self):
        # The fingerprint the server prints for the development key
        # (tools/genserverkey in the server repository).
        self.assertEqual(fingerprint(DEV_KEY), 14037083214707814241)

    def test_canonical_pem_round_trip(self):
        n, e = patch.parse_pkcs1_public_key(TELEGRAM_PROD)
        self.assertEqual("\n".join(patch.canonical_pem(n, e)), TELEGRAM_PROD)

    def test_rejects_other_formats(self):
        with self.assertRaises(patch.PatchError):
            patch.parse_pkcs1_public_key(TELEGRAM_PROD.replace("RSA PUBLIC KEY", "PUBLIC KEY"))
        with self.assertRaises(patch.PatchError):
            patch.parse_pkcs1_public_key(TELEGRAM_PROD.replace("5nKaMBwK", "5nKa*BwK"))

    def test_cpp_literal_holds_the_key(self):
        literal = cpp_literal(DEV_KEY)
        self.assertTrue(literal.startswith('const char *k = "\\\n-----BEGIN RSA PUBLIC KEY-----\\n\\\nMIIB'))
        self.assertTrue(literal.endswith('\\n\\\n-----END RSA PUBLIC KEY-----";\n'))
        n, e = patch.parse_pkcs1_public_key(DEV_KEY)
        self.assertEqual([k[:2] for k in patch.embedded_keys(literal)], [(n, e)])


def config(**over):
    upstream = patch.load_env(ROOT / "upstream.env")
    app = patch.load_env(ROOT / "config/app.env")
    app.update(over.pop("app", {}))
    args = dict(server_ipv4="203.0.113.7", server_port="443", server_ipv6="", rsa_pem=OTHER_KEY)
    args.update(over)
    return patch.Config(upstream, app, **args)


class ConfigTest(unittest.TestCase):
    def test_repository_config(self):
        c = config(server_ipv6="2001:db8::1")
        self.assertEqual((c.app_name, c.app_id, c.api_id, c.layer), ("Pluma", "chat.pluma.desktop", 10003, 228))
        self.assertEqual(c.ipv6, "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(c.aumid, "Pluma.PlumaDesktop")
        self.assertEqual(len({c.app_guid, c.instance_guid, c.toast_clsid}), 3)

    def test_dev_server(self):
        dev = patch.load_env(ROOT / "config/dev/server.env")
        c = config(server_ipv4=dev["PLUMA_SERVER_IPV4"], server_port=dev["PLUMA_SERVER_PORT"], rsa_pem=DEV_KEY)
        self.assertEqual((c.ipv4, c.port, c.fingerprint), ("127.0.0.1", 10443, 14037083214707814241))

    def test_rejects(self):
        telegram_guid = "53F49750-6209-4FBF-9CA8-7A333C87D1ED"
        for over in (
            {"server_ipv4": "pluma.chat"},
            {"server_ipv4": "2001:db8::1"},
            {"server_ipv4": "149.154.167.50"},
            {"server_ipv6": "2001:67c:4e8:f002::a"},
            {"server_ipv6": "203.0.113.7"},
            {"server_port": "0"},
            {"server_port": "https"},
            {"rsa_pem": SHORT_KEY},
            {"rsa_pem": TELEGRAM_PROD},
            {"app": {"PLUMA_API_HASH": "C62739C93DC105640862BF4DCEA3BA1D"}},
            {"app": {"PLUMA_API_ID": "0"}},
            {"app": {"PLUMA_APP_NAME": "Pluma Desktop"}},
            {"app": {"PLUMA_APP_NAME": "TelegramPluma"}},
            {"app": {"PLUMA_APP_ID": "org.telegram.desktop"}},
            {"app": {"PLUMA_APP_ID": "Pluma"}},
            {"app": {"PLUMA_WINDOWS_APP_USER_MODEL_ID": "Telegram.TelegramDesktop"}},
            {"app": {"PLUMA_WINDOWS_APP_USER_MODEL_ID": "Pluma Desktop"}},
            {"app": {"PLUMA_WINDOWS_APP_GUID": telegram_guid}},
            {"app": {"PLUMA_INSTANCE_GUID": "87a94ab0-e370-4cde-98d3-acc110c5967d"}},
            {"app": {"PLUMA_TOAST_ACTIVATOR_CLSID": "not-a-guid"}},
            {"app": {"PLUMA_TOAST_ACTIVATOR_CLSID": "BB4EA67A-F90A-4B50-B202-49660CE32557"}},
        ):
            with self.subTest(over=over), self.assertRaises(patch.PatchError):
                config(**over)


class ScanTest(unittest.TestCase):
    def test_finds_telegram_addresses(self):
        text = ('{ 1, "149.154.175.50" , 443 }, { 2, "95.161.76.100", 443 }, '
                '{ 1, "2001:0b28:f23d:f001:0000:0000:0000:000a", 443 }, "2001:67c:4e8:f004::b"')
        self.assertEqual(patch.telegram_addresses(text),
                         ["149.154.175.50", "95.161.76.100", "2001:b28:f23d:f001::a", "2001:67c:4e8:f004::b"])

    def test_ignores_other_numbers(self):
        text = 'AppVersionStr = "7.0.9"; "127.0.0.1"; 1.149.154.175; "2001:db8::1"; 12:30:45; "8.8.8.8"'
        self.assertEqual(patch.telegram_addresses(text), [])

    def test_keys_in_cpp_literals(self):
        found = patch.embedded_keys(cpp_literal(TELEGRAM_TEST))
        self.assertEqual([k[:2] for k in found], [patch.parse_pkcs1_public_key(TELEGRAM_TEST)])
        self.assertEqual(found[0][2], patch.TELEGRAM_KEY_LINES[1])

    def test_ignores_code_around_the_markers(self):
        # mtproto_rsa_public_key.cpp tells the formats apart.
        source = 'if (array.indexOf("BEGIN RSA PUBLIC KEY") >= 0) {\n// "-----BEGIN RSA PUBLIC KEY----- ..." format\n'
        self.assertEqual(patch.embedded_keys(source), [])

    def test_constructions(self):
        for text in ("_loader = std::make_unique<SpecialConfigRequest>([=] {",
                     "x = std::make_unique<details::DomainResolver>(f);",
                     "auto r = new MTP::details::DomainResolver(f);",
                     "SpecialConfigRequest request(callback, false, domain);",
                     "DomainResolver{f}"):
            with self.subTest(text=text):
                self.assertIsNotNone(patch.CONSTRUCTION.search(text))
        for text in ("std::unique_ptr<SpecialConfigRequest> _specialLoader;", "class DomainResolver;",
                     "// (MTP::details::DomainResolver).", "#include \"mtproto/special_config_request.h\""):
            with self.subTest(text=text):
                self.assertIsNone(patch.CONSTRUCTION.search(text))


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        for rel in (patch.VERSION_H, patch.CMAKE_APP):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        (root / "a.txt").write_bytes(b"one two two\nvoid f() {\n\tbody;\n}\n")
        (root / "b.txt").write_bytes(b"one\r\ntwo\r\n")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_replace_counts(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "two", "2")
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "three", "3")
        self.tree.replace("a.txt", "two", "2", count=2)
        self.assertTrue(self.tree.read("a.txt").startswith("one 2 2\n"))

    def test_replace_body(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "\tother;", must_contain=("missing",))
        self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "\tother;", must_contain=("body;",))
        self.assertEqual(self.tree.read("a.txt"), "one two two\nvoid f() {\n\tother;\n}\n")

    def test_replace_block(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_block("a.txt", "void g() {", "\n}\n", "")
        self.tree.replace_block("a.txt", "void f() {", "\n}\n", "int x;\n", must_contain=("body;",))
        self.assertEqual(self.tree.read("a.txt"), "one two two\nint x;\n")

    def test_keeps_line_endings(self):
        self.tree.replace("b.txt", "two", "2")
        self.assertEqual((self.tree.root / "b.txt").read_bytes(), b"one\r\n2\r\n")
        with self.assertRaises(patch.PatchError):
            self.tree.lf_only("b.txt")
        self.tree.lf_only("a.txt")

    def test_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(patch.PatchError):
            patch.Tree(d)


class BrandTest(unittest.TestCase):
    def test_strings_table(self):
        strings = patch.load_strings()
        self.assertEqual(strings["lng_intro_qr_title"], 1)
        self.assertNotIn("lng_about_text1_api", strings)

    def test_name_telegram(self):
        self.assertEqual(patch.name_telegram("Telegram Desktop and Telegram's cloud", "Pluma"),
                         ("Pluma and Pluma's cloud", 2))
        self.assertEqual(patch.name_telegram("See https://telegram.org/faq and t.me/TelegramTips on Telegram.", "Pluma"),
                         ("See https://telegram.org/faq and t.me/TelegramTips on Pluma.", 1))
        self.assertEqual(patch.name_telegram("{telegram}", "Pluma"), ("{telegram}", 0))

    def test_lang_entries(self):
        text = '/*\nTelegram\n*/\n"lng_a" = "Open Telegram";\n"lng_b" =  "x \\"Telegram\\"";\n'
        self.assertEqual(patch.lang_counts(text), {"lng_a": 1, "lng_b": 1})
        with self.assertRaises(patch.PatchError):
            patch.lang_counts(text + '"lng_c" = "multi\nline";\n')

    def test_code_telegram(self):
        text = ('// Telegram\n#include "telegram.h"\nauto a = u"Telegram Desktop"_q; auto b = "TelegramWebviewProxy";\n'
                'auto c = "https://desktop.telegram.org"; auto d = \'"\'; auto e = R"(Telegram)";\n')
        self.assertEqual(patch.code_telegram(text), 2)


# --- the patch on the pinned upstream ------------------------------------------

S = patch.SOURCES
DC, INSTANCE, LOADER, LINUX, WIN_APP_ID = patch.DC_OPTIONS, patch.INSTANCE, patch.CONFIG_LOADER, patch.LINUX, patch.WIN_APP_ID

# Damage to each place the patch edits or checks, as (file, text in the
# pinned upstream, replacement): every one must stop the patch with an error
# that names the file.
DAMAGE = (
    (patch.API_TL, "// LAYER 228\n", "// LAYER 229\n"),
    (patch.VERSION_H, 'AppVersionStr = "7.0.9";', 'AppVersionStr = "7.0.10";'),
    (patch.QT_VERSION_PY, "os.environ['QT'] = '6.11.1'", "os.environ['QT'] = '6.12.0'"),
    (patch.BUILDING_WIN, "**10.0.26100.0** SDK version", "**10.0.26200.0** SDK version"),
    (patch.BUILDING_WIN, "-vcvars_ver=14.44", "-vcvars_ver=14.50"),
    (patch.LINUX_WORKFLOW, "/download/v4.13.6/ccache-4.13.6-", "/download/v4.14.0/ccache-4.14.0-"),
    (patch.DOCKER_ENV + "/build.sh", 'cmake --build ../out --config "${CONFIG:-Release}"', "cmake --build ../out --config Release"),
    (patch.DOCKER_ENV + "/gen_dockerfile.py", 'LTO=checkEnv("LTO", True),', 'LTO=checkEnv("ENABLE_LTO", True),'),
    (patch.PREPARE, "        elif arg == 'silent':\n", "        elif arg == 'quiet':\n"),
    # The MSYS2 backport: a changed package list, and an upstream that has
    # the fix already (the backport must go then).
    (patch.PREPARE, "        mingw-w64-x86_64-gperf ^\n", "        mingw-w64-x86_64-gperf-git ^\n"),
    (patch.PREPARE, "'ThirdParty\\\\msys64\\\\mingw64\\\\bin'", "'ThirdParty\\\\msys64\\\\ucrt64\\\\bin'"),
    (patch.PREPARE, "    gyp dump_syms.gyp --format=msvs\n", "    gyp dump_syms.gyp --format=msvs --depth=.\n"),
    # The macOS release variants: a Qt stage with another scope in between
    # (as a later upstream has), a tg_owt that joins its Debug builds otherwise.
    (patch.PREPARE, "    CONFIGURATIONS=-debug-and-release\nmac:\n",
     "    CONFIGURATIONS=-debug-and-release\nmac_asserts:\n    ASSERTS=-force-asserts\nmac:\n"),
    (patch.PREPARE, "    lipo -create Debug.arm64/libtg_owt.a Debug.x86_64/libtg_owt.a -output Debug/libtg_owt.a\n",
     "    lipo -create Debug.*/libtg_owt.a -output Debug/libtg_owt.a\n"),
    (patch.PREPARE, "stage('python', \"\"\"\n",
     "stage('python', \"\"\"\nwin:\n    pacman -S --noconfirm mingw-w64-x86_64-cmake\n"),
    (patch.CMAKE_VARIABLES, "option(DESKTOP_APP_DISABLE_AUTOUPDATE ", "option(DESKTOP_APP_NO_AUTOUPDATE "),
    (DC, '{ 5, "149.154.171.5"  , 443 },', '{ 5, "149.154.171.6"  , 443 },'),
    (DC, "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g", "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4h"),
    (DC, "\t\t: gsl::make_span(kPublicRSAKeys);\n", "\t\t: gsl::make_span(kProductionPublicRSAKeys);\n"),
    (DC, "void DcOptions::constructFromBuiltIn() {\n", "void DcOptions::constructFromBuiltIn(bool test) {\n"),
    (patch.INSTANCE_H, "kDefaultMainDc = 2;", "kDefaultMainDc = 4;"),
    (LOADER, "void ConfigLoader::createSpecialLoader() {\n", "void ConfigLoader::createSpecialLoader(bool force) {\n"),
    (INSTANCE, "void Instance::Private::syncHttpUnixtime() {\n", "void Instance::Private::syncHttpUnixtime(bool force) {\n"),
    (INSTANCE, "\t\t_domainResolver = std::make_unique<DomainResolver>([=](\n", "\t\t_domainResolver.reset(new DomainResolver([=](\n"),
    (patch.SPECIAL_CONFIG, 'constexpr auto kPublicKey = "', 'constexpr auto kSpecialConfigKey = "'),
    (patch.PROXY_DATA, "return (type == Type::Socks5 || type == Type::Mtproto)", "return (type == Type::Mtproto)"),
    (patch.CMAKE_OPTIONS, "    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE)\n",
     "    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE=1)\n"),
    (patch.APPLICATION, "\t\tInvokeQueued(this, [] { RegisterUrlScheme(); });\n", "\t\tInvokeQueued(this, [] { RegisterUrlSchemes(); });\n"),
    (patch.APPLICATION, '\t\t.protocol = u"tg"_q,\n', '\t\t.protocol = u"telegram"_q,\n'),
    (patch.PLIST, "\t\t\t\t<string>tonsite</string>\n", ""),
    (patch.VERSION_H, '"Telegram Desktop"_cs', '"Telegram"_cs'),
    (patch.CONFIG_H, "87A94AB0-E370-4cde-98D3-ACC110C5967D", "87A94AB0-E370-4CDE-98D3-ACC110C5967D"),
    (patch.LAUNCHER, 'setApplicationName(u"TelegramDesktop"_q)', 'setApplicationName(u"Telegram"_q)'),
    (LINUX, '\t\treturn u"org.telegram.desktop"_q;\n', '\t\treturn u"org.telegram.Desktop"_q;\n'),
    (LINUX, 'u"/.TelegramDesktop/"_q', 'u"/.telegram-desktop/"_q'),
    (patch.DESKTOP_FILE, "Name=Telegram\n", "Name=Telegram Desktop\n"),
    (patch.DESKTOP_FILE, "MimeType=x-scheme-handler/tg;x-scheme-handler/tonsite;\n", "MimeType=x-scheme-handler/tg;\n"),
    (WIN_APP_ID, 'L"Telegram.TelegramDesktop";', 'L"Telegram.Desktop";'),
    (WIN_APP_ID, '\tQString path = systemShortcutPath() + u"Telegram.lnk"_q;\n', '\tQString path = systemShortcutPath() + u"Telegram Desktop.lnk"_q;\n'),
    (patch.WIN_TOAST, '("F11932D3-6110-4BBC-9B02-B2EC07A1BD19")', '("F11932D3-6110-4BBC-9B02-B2EC07A1BD20")'),
    (patch.WIN_SPECIFIC, '+ "\\\\Telegram.lnk";\n\t\t}\n\t\tif (SUCCEEDED(commonDesktopRes))', '+ "\\\\Telegram Desktop.lnk";\n\t\t}\n\t\tif (SUCCEEDED(commonDesktopRes))'),
    (patch.WIN_RC, 'VALUE "FileDescription", "Telegram Desktop"', 'VALUE "FileDescription", "Telegram"'),
    (patch.CMAKE_APP, 'set(bundle_identifier "com.tdesktop.Telegram")', 'set(bundle_identifier "com.tdesktop.TelegramDesktop")'),
    # The brand: the strings that name Telegram, what stays, the code.
    (patch.LANG, '"lng_menu_contacts" = "Contacts";', '"lng_menu_contacts" = "Telegram Contacts";'),
    (patch.LANG, '"lng_open_from_tray" = "Open Telegram";', '"lng_open_from_tray" = "Open Telegram Desktop or Telegram";'),
    (patch.LANG, '"lng_about_text1_api" = "Telegram API";', '"lng_about_text1_api" = "the Telegram API";'),
    (S + "/intro/intro_start.cpp", 'u"Telegram Desktop"_q', 'u"Telegram"_q'),
    (patch.EXPORT_HTML, '" joined Telegram";', '" has joined Telegram";'),
    (S + "/window/main_window.cpp", "namespace {\n", 'namespace {\nconst auto kTitle = "Telegram";\n'),
    # plm:// links.
    (patch.INTRO_QR, '"tg://login?token="', '"https://t.me/login?token="'),
    (S + "/core/sandbox.cpp", "namespace {\n", 'namespace {\nconst auto kLink = "tg://resolve";\n'),
    (patch.TEXT_ENTITY, 'addOne(QString::fromLatin1("tg")); // local urls', 'addOne(QString::fromLatin1("tg")); // local'),
    (patch.QTHELP_URL, '|| equals(qstr("tg"))', '|| equals(qstr("tg")) || equals(qstr("tg2"))'),
    # Line endings the patch would not match.
    (patch.LAUNCHER, "void Launcher::init() {\n", "void Launcher::init() {\r\n"),
    # Traces of Telegram elsewhere in the sources: verify() must find them.
    (S + "/mtproto/session_private.cpp", "namespace MTP {\n",
     'namespace MTP {\nconst auto kFallback = "149.154.167.51";\n'),
    (S + "/mtproto/connection_tcp.cpp", "namespace MTP {\n",
     'namespace MTP {\nconst auto kFallback = "2001:67c:4e8:f004::b";\n'),
    (S + "/core/sandbox.cpp", "namespace {\n",
     "namespace {\n// MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n"),
    (S + "/core/sandbox.cpp", "namespace {\n", "namespace {\n" + cpp_literal(DEV_KEY)),
    (S + "/core/sandbox.cpp", "namespace {\n", "namespace {\n" + cpp_literal(UPDATE_KEY)),
    (LOADER, "void ConfigLoader::refreshSpecialLoader() {\n",
     "void ConfigLoader::refreshSpecialLoader() {\n"
     "\t_specialLoader = std::make_unique<SpecialConfigRequest>(nullptr, false, QString(), QString());\n"),
    (INSTANCE, "void Instance::Private::start() {\n",
     "void Instance::Private::start() {\n\t_domainResolver.reset(new details::DomainResolver(nullptr));\n"),
)


def prepare_scopes(text, part):
    """The platform scopes (win, mac, ...) of the lines of part, a text of
    one stage of prepare.py, as its filterByPlatform reads them: a line
    "name:" opens a scope, a lone "release:" keeps the platform's, and the
    lines before the first scope are common to all platforms."""
    def scopes(lines, scope):
        found = set()
        for line in lines:
            m = re.match(r"(!?)([a-z0-9_]+):", line)
            if m and m.group(2) not in ("depends", "version"):
                if m.group(2) != "release":
                    scope = m.group(1) + m.group(2)
            elif line.strip():
                found.add(scope)
        return found, scope

    start = text.index(part)
    _, scope = scopes(text[text.rindex("stage(", 0, start):start].split("\n")[1:], "common")
    return scopes(part.split("\n"), scope)[0]


def upstream_files():
    """The files the patch reads, as {path: bytes} of the pinned commit, or
    None without a checkout of it in ./upstream (ci/fetch-upstream.sh)."""
    env = patch.load_env(ROOT / "upstream.env")
    git = ["git", "-C", str(ROOT / "upstream")]
    try:
        head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    if head != env["UPSTREAM_REF"]:
        return None
    archives = [("", subprocess.run(git + ["archive", "--format=tar", "HEAD", *patch.UPSTREAM_PATHS],
                                    capture_output=True, check=True).stdout)]
    for sub in sorted({s for s, _ in patch.SUBMODULE_PATHS}):
        paths = [p for s, p in patch.SUBMODULE_PATHS if s == sub]
        archives.append((sub + "/", subprocess.run(["git", "-C", str(ROOT / "upstream" / sub), "archive", "--format=tar",
                                                    "HEAD", *paths], capture_output=True, check=True).stdout))
    files = {}
    for prefix, archive in archives:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for m in tar.getmembers():
                if m.isfile():
                    files[prefix + m.name] = tar.extractfile(m).read()
    return files


class RecordingTree(patch.Tree):
    """A tree that remembers what the patch wrote."""

    def __init__(self, root, written):
        super().__init__(root)
        self.written = written

    def write(self, rel, text):
        self.written.add(str(rel))
        super().write(rel, text)


@unittest.skipIf(not os.environ.get("CI") and upstream_files() is None,
                 "no checkout of the pinned upstream (ci/fetch-upstream.sh sparse)")
class UpstreamTest(unittest.TestCase):
    """The patch on the commit upstream.env pins. CI fetches it first, and
    there these tests never skip."""

    @classmethod
    def setUpClass(cls):
        cls.files = upstream_files()
        if cls.files is None:
            raise AssertionError("no checkout of the pinned upstream in ./upstream (ci/fetch-upstream.sh sparse)")
        cls.dir = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.dir.name)
        for name, data in cls.files.items():
            p = cls.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.written = set()

    def tearDown(self):
        # Back to the pinned upstream: what the patch or a test wrote.
        for rel in self.written:
            if rel in self.files:
                (self.root / rel).write_bytes(self.files[rel])
            else:
                (self.root / rel).unlink(missing_ok=True)
        self.written.clear()

    def run_patch(self, **over):
        c = config(**over)
        tree = RecordingTree(self.root, self.written)
        patch.patch(tree, c)
        patch.verify(tree, c)
        return tree, c

    def test_patch(self):
        tree, c = self.run_patch(server_ipv6="2001:db8::7", server_port="8443")
        dc = tree.read(DC)
        self.assertIn('\tapplyOneGuarded(1, Flag::f_static | 0, "203.0.113.7", 8443, {});\n', dc)
        self.assertIn('\tapplyOneGuarded(1, Flag::f_static | Flag::f_ipv6, "2001:0db8:0000:0000:0000:0000:0000:0007", 8443, {});\n', dc)
        self.assertEqual(dc.count(c.rsa_pem[1] + "\\n\\\n"), 2)
        self.assertEqual(tree.read(patch.SPECIAL_CONFIG).count(c.rsa_pem[1]), 1)
        self.assertNotIn("SpecialConfigRequest>(", tree.read(LOADER) + tree.read(INSTANCE))
        self.assertNotIn("DomainResolver>(", tree.read(INSTANCE))
        self.assertIn("static constexpr auto kDefaultMainDc = 1;", tree.read(patch.INSTANCE_H))
        self.assertIn(patch.CMAKE_DEFINITIONS, tree.read(patch.CMAKE_OPTIONS))
        version = tree.read(patch.VERSION_H)
        self.assertIn('constexpr auto AppName = "Pluma"_cs;\n', version)
        self.assertIn(f'constexpr auto AppId = "{{{c.app_guid}}}"_cs;', version)
        self.assertIn(f'"{{{c.instance_guid}}}"', tree.read(patch.CONFIG_H))
        self.assertIn('\t\treturn u"chat.pluma.desktop"_q;\n', tree.read(LINUX))
        self.assertIn('L"Pluma.PlumaDesktop";', tree.read(WIN_APP_ID))
        self.assertEqual(tree.read(WIN_APP_ID).count('"Pluma.lnk"_q'), 2)
        self.assertIn(f'DECLSPEC_UUID("{c.toast_clsid}")', tree.read(patch.WIN_TOAST))
        self.assertIn('set(bundle_identifier "chat.pluma.desktop")', tree.read(patch.CMAKE_APP))
        plist = tree.read(patch.PLIST)
        self.assertIn("<key>CFBundleURLSchemes</key>\n\t\t\t<array>\n\t\t\t\t<string>plm</string>\n\t\t\t</array>", plist)
        self.assertIn("\t<key>CFBundleName</key>\n\t<string>Pluma</string>\n", plist)
        desktop = tree.read(patch.DESKTOP_FILE)
        self.assertIn("\nExec=Pluma -- %U\n", desktop)
        self.assertIn("\nMimeType=x-scheme-handler/plm;\n", desktop)
        self.assertIn("server key 0x", tree.read(patch.MARKER))
        prepare = tree.read(patch.PREPARE)
        self.assertIn("    'ThirdParty\\\\msys64\\\\ucrt64\\\\bin',\n", prepare)
        self.assertIn("msys2-base-x86_64-20260927.sfx.exe", prepare)
        self.assertEqual(prepare.count("        mingw-w64-ucrt-x86_64-"), 5)
        self.assertNotIn("dump_syms.vcxproj", prepare)
        self.assertIn("xcodebuild -project dump_syms.xcodeproj", prepare)
        # macOS: Qt and tg_owt in their release variants alone; Windows
        # builds both, Qt with debug information, as before.
        self.assertIn('release:\n    CONFIGURATIONS=-release\nmac:\n    rm -rf "$USED_PREFIX/Qt-$QT"\n'
                      '    ./configure -prefix "$USED_PREFIX/Qt-$QT" \\\n        $CONFIGURATIONS \\\n'
                      '        -opensource \\\n', prepare)
        self.assertNotIn("Debug.x86_64/libtg_owt.a", prepare)
        self.assertIn("lipo -create Release.arm64/libtg_owt.a Release.x86_64/libtg_owt.a", prepare)
        self.assertIn("    SET CONFIGURATIONS=-debug-and-release\n", prepare)
        self.assertEqual(prepare.count("-force-debug-info"), 2)

    def test_brand(self):
        tree, _ = self.run_patch()
        # The name.
        lang = tree.read(patch.LANG)
        for line in ('"lng_intro_qr_title" = "Scan From Mobile Pluma";\n', '"lng_premium_summary_title" = "Pluma Premium";\n',
                     '"lng_telegram_features_url" = "https://t.me/TelegramTips";\n',
                     '"lng_about_text1_api" = "Telegram API";\n', '"lng_auction_change_to_me" =  "Do you want'):
            self.assertIn(line, lang)
        self.assertEqual(patch.lang_counts(self.files[patch.LANG].decode("utf-8")), patch.load_strings())
        self.assertEqual(patch.lang_counts(lang), {})
        self.assertIn('box->setTitle(u"Pluma"_q);', tree.read(patch.ABOUT_BOX))
        self.assertIn('setTitleText(rpl::single(u"Pluma"_q));', tree.read(S + "/intro/intro_start.cpp"))
        # plm:// links.
        self.assertIn('_qrCodes.fire_copy("plm://login?token=" + encoded);', tree.read(patch.INTRO_QR))
        self.assertIn('return openCustomUrl("plm://", LocalUrlHandlers(), url, context);', tree.read(patch.APPLICATION))
        application = tree.read(patch.APPLICATION)
        self.assertIn('\t\t.protocol = u"plm"_q,\n\t\t.protocolName = u"Pluma Link"_q,\n', application)
        self.assertNotIn('u"tonsite"_q,\n\t\t.protocolName', application)
        self.assertIn('addOne(QString::fromLatin1("plm"));', tree.read(patch.TEXT_ENTITY))

    def test_build_edits_stay_in_their_platform(self):
        """Each edit of prepare.py changes the commands of one platform only
        (filterByPlatform's scopes), so the stage keys of the other platform,
        and its cached libraries, stay as they are."""
        tree, _ = self.run_patch()
        pinned, patched = self.files[patch.PREPARE].decode("utf-8"), tree.read(patch.PREPARE)
        scopes = []
        for rel, old, new in patch.BUILD_EDITS:
            if rel == patch.PREPARE:
                old_scopes = prepare_scopes(pinned, old)
                self.assertEqual(len(old_scopes), 1, old[:60])
                if new:
                    self.assertEqual(prepare_scopes(patched, new), old_scopes, new[:60])
                scopes.append(old_scopes.pop())
        self.assertEqual(scopes, ["win", "mac", "mac"])

    def test_dev_server(self):
        dev = patch.load_env(ROOT / "config/dev/server.env")
        tree, _ = self.run_patch(server_ipv4=dev["PLUMA_SERVER_IPV4"], server_port=dev["PLUMA_SERVER_PORT"], rsa_pem=DEV_KEY)
        dc = tree.read(DC)
        self.assertIn('\tapplyOneGuarded(1, Flag::f_static | 0, "127.0.0.1", 10443, {});\n', dc)
        self.assertNotIn("Flag::f_ipv6, \"", dc)

    def test_patched_tree_is_refused(self):
        self.run_patch()
        with self.assertRaises(patch.PatchError):
            self.run_patch()

    def test_damage(self):
        for rel, old, new in DAMAGE:
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                text = self.files[rel].decode("utf-8")
                self.assertIn(old, text, "the damage does not apply to the pinned upstream")
                self.written.add(rel)
                (self.root / rel).write_bytes(text.replace(old, new).encode("utf-8"))
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))


if __name__ == "__main__":
    unittest.main()
