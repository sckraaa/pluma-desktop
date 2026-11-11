#!/usr/bin/env python3
import base64
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import ed25519  # noqa: E402
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

# Telegram's former key of its update packages, which may stay in
# _other/packer.cpp only.
UPDATE_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMA4ViQrjkPZ9xj0lrer3r23JvxOnrtE8nI69XLGSr+sRERz9YnUptnU
BZpkIfKaRcl6XzNJiN28cVwO1Ui5JSa814UAiDHzWUqCaXUiUEQ6NmNTneiGx2sQ
+9PKKlb8mmr3BB9A45ZNwLT6G9AK3+qkZLHojeSA+m84/a6GP4svAgMBAAE=
-----END RSA PUBLIC KEY-----"""

# Telegram's root key of its update packages (update system v2).
TELEGRAM_UPDATE_ROOT = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARgB8IFZWA08OzifsbPQ3SRdGbON2ecPVsMm1Qo7QNR0=
-----END PUBLIC KEY-----
"""

DEV_KEY = (ROOT / "config/dev/server_public.pem").read_text()

# Pluma's update root key and manifest, of throwaway keys: (root, manifest,
# signature) as bytes, and the same for a manifest made in the test.
ROOT_SEED, RELEASE_SEED = bytes(range(1, 33)), bytes(range(33, 65))


def update_manifest(**over):
    x = base64.urlsafe_b64encode(ed25519.public_key(RELEASE_SEED)).rstrip(b"=").decode()
    data = {"format": 1, "manifest_version": 1, "issued": 1762646400,
            "keys": [{"id": "pluma-1", "alg": "Ed25519", "x": x}],
            "channels": {"stable": [["pluma-1"]]}, "revoked": []}
    data.update(over)
    return json.dumps(data, separators=(",", ":")).encode()


def update_keys(manifest=None, seed=ROOT_SEED):
    manifest = manifest or update_manifest()
    return (ed25519.public_pem(ed25519.public_key(seed)).encode(), manifest, ed25519.sign(seed, manifest))


UPDATE_KEYS = update_keys()


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
    args = dict(server_ipv4="203.0.113.7", server_port="443", server_ipv6="", rsa_pem=OTHER_KEY,
                update_keys=UPDATE_KEYS, build=57)
    args.update(over)
    return patch.Config(upstream, app, **args)


class ConfigTest(unittest.TestCase):
    def test_repository_config(self):
        c = config(server_ipv6="2001:db8::1")
        self.assertEqual((c.app_name, c.app_id, c.api_id, c.layer), ("Pluma", "chat.pluma.desktop", 10003, 233))
        self.assertEqual(c.ipv6, "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(c.aumid, "Pluma.PlumaDesktop")
        self.assertEqual(len({c.app_guid, c.instance_guid, c.toast_clsid}), 3)

    def test_dev_server(self):
        dev = patch.load_env(ROOT / "config/dev/server.env")
        c = config(server_ipv4=dev["PLUMA_SERVER_IPV4"], server_port=dev["PLUMA_SERVER_PORT"], rsa_pem=DEV_KEY)
        self.assertEqual((c.ipv4, c.port, c.fingerprint), ("127.0.0.1", 10443, 14037083214707814241))

    def test_data_folder(self):
        # A build for the real server keeps its data in the app's folder; a
        # development build in one of its own, so that neither reads the
        # other's (the server's address among it).
        self.assertEqual(config().data_name, "Pluma")
        dev = patch.load_env(ROOT / "config/dev/server.env")
        self.assertEqual(config(app={"PLUMA_DATA_NAME": dev["PLUMA_DATA_NAME"]}).data_name, "PlumaDev")
        for bad in ("pluma dev", "TelegramDev", "P"):
            with self.subTest(name=bad), self.assertRaises(patch.PatchError):
                config(app={"PLUMA_DATA_NAME": bad})

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
            {"update_keys": (b"not a key",) + UPDATE_KEYS[1:]},
            {"update_keys": (TELEGRAM_UPDATE_ROOT.encode(),) + UPDATE_KEYS[1:]},
            {"update_keys": UPDATE_KEYS[:2] + (bytes(64),)},
            {"update_keys": update_keys(b"not json")},
            {"update_keys": update_keys(update_manifest(format=2))},
            {"update_keys": update_keys(update_manifest(channels={"beta": [["pluma-1"]]}))},
            {"update_keys": update_keys(update_manifest(channels={"stable": [["nobody"]]}))},
            {"update_keys": update_keys(update_manifest(channels={"stable": [["pluma-1"]], "beta": [["pluma-1"]]}))},
            {"update_keys": update_keys(update_manifest(revoked=["pluma-1"]))},
            {"update_keys": update_keys(update_manifest(keys=[{"id": "pluma-1", "alg": "ES256", "crv": "P-256",
                                                                "x": "A" * 43, "y": "A" * 43}]))},
            {"update_keys": update_keys(update_manifest(keys=[{"id": "pluma-1", "alg": "Ed25519",
                                                                "x": "C8sDZ7G_3-v5DPKBjqcU6hCNFJjC1z8ggFcCyoVLtC0"}]))},
            {"app": {"PLUMA_UPDATE_PREFIX": "http://pluma.chat/dl/desktop"}},
            {"app": {"PLUMA_UPDATE_PREFIX": "https://pluma.chat/dl/desktop/"}},
            {"app": {"PLUMA_UPDATE_PREFIX": "https://td.telegram.org"}},
            {"build": -1},
            {"build": 100000},
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
    def test_tree_is_the_assets(self):
        tree = patch.BRAND / "tree"
        files = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(path for path, _ in patch.ASSETS))
        self.assertEqual(len(set(path for path, _ in patch.ASSETS)), len(patch.ASSETS))

    def test_strings_table(self):
        strings = patch.load_strings()
        self.assertEqual(strings["lng_intro_qr_title"], 1)
        self.assertNotIn("lng_about_text1_api", strings)

    def test_palette_tables(self):
        day = patch.load_table(patch.BRAND / "palette-day.txt")
        night = patch.load_table(patch.BRAND / "palette-night.txt")
        self.assertIn(("windowBgActive", "#40a7e3", "#5b7a5e"), day)
        self.assertIn(("windowBg", "#17212b", "#131513"), night)
        # People's colours are IDENTITY_COLORS's, the same in every theme.
        people = {key for key, _, _, _ in patch.IDENTITY_COLORS}
        self.assertEqual([key for key, _, _ in day + night if key in people], [])

    def test_identity_tables(self):
        # Every theme names Telegram's values of the keys that differ by theme.
        own = {key for key, telegram, _, _ in patch.IDENTITY_COLORS if telegram is None}
        for theme, (_, names) in patch.IDENTITY_THEMES.items():
            with self.subTest(theme=theme):
                self.assertEqual(set(names), own)
        self.assertEqual(set(patch.IDENTITY_THEMES), {patch.PALETTE, patch.NIGHT_THEME, *patch.TELEGRAM_THEMES})
        for key, telegram, on_light, on_dark in patch.IDENTITY_COLORS:
            with self.subTest(key=key):
                self.assertTrue(telegram is None or patch.is_blue(telegram))
                self.assertFalse(any(patch.is_blue(color) for color in (on_light, on_dark) if color))
        # The export's avatars: the middle of the sage and the teal gradients.
        self.assertEqual(patch.middle("#000000", "#ffffff"), "#808080")
        self.assertEqual((patch.export_userpic(4), patch.export_userpic(7)), ("#6d8d70", "#44b4ae"))

    def test_identity(self):
        light = ("historyPeer4NameFg: windowActiveTextFg; // blue\nhistoryPeer4UserpicBg: #5caffa;\n"
                 "historyPeer4UserpicBg2: #408acf | historyPeer4UserpicBg;\nhistoryPeer7NameFg: #2996ad;\n"
                 "historyPeer7UserpicBg: #5bcbe3;\nhistoryPeer7UserpicBg2: #359ad4 | historyPeer7UserpicBg;\n")
        self.assertEqual(patch.identity(light, patch.PALETTE),
                         "historyPeer4NameFg: #4f6e52; // blue\nhistoryPeer4UserpicBg: #7fa082;\n"
                         "historyPeer4UserpicBg2: #5b7a5e | historyPeer4UserpicBg;\nhistoryPeer7NameFg: #1f8a80;\n"
                         "historyPeer7UserpicBg: #5bcbc4;\nhistoryPeer7UserpicBg2: #2c9c98 | historyPeer7UserpicBg;\n")
        # A dark theme has a cyan name of its own.
        dark = light.replace("windowActiveTextFg", "#65bdf3").replace("#2996ad", "#62d4e3")
        self.assertEqual(patch.palette_values(patch.identity(dark, patch.NIGHT_THEME)),
                         {"historyPeer4NameFg": "#9dbb9f", "historyPeer4UserpicBg": "#7fa082",
                          "historyPeer4UserpicBg2": "#5b7a5e | historyPeer4UserpicBg",
                          "historyPeer7NameFg": "#53ccc6", "historyPeer7UserpicBg": "#5bcbc4",
                          "historyPeer7UserpicBg2": "#2c9c98 | historyPeer7UserpicBg"})
        # Another colour, a key twice or none, a changed name kept: the patch
        # stops.
        for theme, text in ((patch.PALETTE, light.replace("#5caffa", "#5caffb")),
                            (patch.PALETTE, light + "historyPeer4UserpicBg: #5caffa;\n"),
                            (patch.PALETTE, light.replace("historyPeer7NameFg:", "historyPeer7NameFgOld:")),
                            (patch.NIGHT_THEME, dark.replace("#62d4e3", "#62d4e4"))):
            with self.subTest(text=text), self.assertRaises(patch.PatchError):
                patch.identity(text, theme)

    def test_with_colors(self):
        theme = patch.theme_zip(((patch.THEME_COLORS, b"a: #111111;\n"), ("background.jpg", b"\xff\xd8jpeg")))
        out = patch.with_colors(theme, "a: #222222;\n")
        self.assertEqual(out, patch.with_colors(theme, "a: #222222;\n"))
        self.assertEqual(patch.zipped_colors(out, "t"), "a: #222222;\n")
        with zipfile.ZipFile(io.BytesIO(out)) as z:
            self.assertEqual(z.namelist(), [patch.THEME_COLORS, "background.jpg"])
            self.assertEqual(z.read("background.jpg"), b"\xff\xd8jpeg")
        for data in (patch.theme_zip((("background.png", b""),)), b"colors"):
            with self.subTest(data=data[:8]), self.assertRaises(patch.PatchError):
                patch.zipped_colors(data, "t")

    def test_verified_badge_table(self):
        # The rosette is the accent of each palette and the check the colour
        # of text on it; neither is a blue.
        day = dict((key, new) for key, _, new in patch.load_table(patch.BRAND / "palette-day.txt"))
        night = dict((key, new) for key, _, new in patch.load_table(patch.BRAND / "palette-night.txt"))
        self.assertEqual(patch.VERIFIED_BADGE["dialogsVerifiedIconBg"], (day["windowBgActive"], night["windowBgActive"]))
        self.assertEqual(patch.VERIFIED_BADGE["profileVerifiedCheckBg"], (day["windowBgActive"], night["windowBgActive"]))
        self.assertEqual(patch.VERIFIED_BADGE["profileVerifiedCheckFg"], ("#ffffff", night["profileVerifiedCheckFg"]))
        self.assertEqual(patch.VERIFIED_BADGE["dialogsVerifiedIconFgActive"],
                         (day["dialogsBgActive"], night["dialogsBgActive"]))
        for key, colors in patch.VERIFIED_BADGE.items():
            with self.subTest(key=key):
                self.assertEqual(len(colors), 2)
                self.assertFalse(any(patch.is_blue(color) for color in colors))

    def test_verified_badge(self):
        day = "".join(f"{key}: {light};\n" for key, (light, _) in patch.VERIFIED_BADGE.items())
        night = {key: dark for key, (_, dark) in patch.VERIFIED_BADGE.items()}
        style = ('dialogsVerifiedIcon: icon {\n\t{ "dialogs/dialogs_verified_star", dialogsVerifiedIconBg },\n'
                 '\t{ "dialogs/dialogs_verified_check", dialogsVerifiedIconFg },\n}\n'
                 'infoVerifiedStar: icon {{ "profile_verified_star", profileVerifiedCheckBg }};\n')
        cover = 'verified: icon {{ "profile_verified_star", groupCallMembersFg }};\n'
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)

            def write(rel, text):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            for rel in (patch.VERSION_H, patch.CMAKE_APP):
                write(rel, "")
            write(patch.SOURCES + "/dialogs/dialogs.style", style)
            write(patch.VERIFIED_ON_COVER[1], cover)
            tree = patch.Tree(root)
            values = patch.palette_values(day)
            patch.verify_verified_badge(tree, values, {**values, **night})
            # A reference resolves to the colour it names.
            referred = {**values, "windowBgActive": "#5b7a5e", "dialogsVerifiedIconBg": "windowBgActive"}
            patch.verify_verified_badge(tree, referred, {**referred, **night})
            # Another colour in either theme, a key gone, another key in a
            # style, the cover's colour elsewhere, no icon at all: verify()
            # stops.
            for light, dark, rel, text in (
                    ({**values, "profileVerifiedCheckBg": "#8a5cf5"}, None, None, None),
                    (values, {"dialogsVerifiedIconFg": "#ffffff"}, None, None),
                    ({k: v for k, v in values.items() if k != "dialogsVerifiedIconFgActive"}, None, None, None),
                    (values, None, patch.SOURCES + "/dialogs/dialogs.style",
                     style.replace("dialogsVerifiedIconBg }", "activeButtonBg }")),
                    (values, None, patch.SOURCES + "/info/info.style", cover),
                    (values, None, patch.SOURCES + "/dialogs/dialogs.style", "")):
                with self.subTest(rel=rel, text=text):
                    if rel:
                        write(rel, text)
                    if rel == patch.SOURCES + "/dialogs/dialogs.style" and not text:
                        (root / patch.VERIFIED_ON_COVER[1]).unlink()
                    with self.assertRaises(patch.PatchError):
                        patch.verify_verified_badge(tree, light, {**light, **night, **(dark or {})})
                    write(patch.SOURCES + "/dialogs/dialogs.style", style)
                    write(patch.VERIFIED_ON_COVER[1], cover)
                    (root / patch.SOURCES / "info/info.style").unlink(missing_ok=True)

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

    def test_recolor(self):
        text = "a: #111111; // one\nb: a;\nc: #222222 | a;\n"
        self.assertEqual(patch.recolor(text, [("a", "#111111", "#333333"), ("c", "#222222 | a", "#444444"),
                                              ("d", "-", "#555555")], "t"),
                         "a: #333333; // one\nb: a;\nc: #444444;\nd: #555555; // pluma\n")
        for rows in ([("a", "#111112", "#333333")], [("b", "c", "#333333")], [("a", "-", "#333333")]):
            with self.subTest(rows=rows), self.assertRaises(patch.PatchError):
                patch.recolor(text, rows, "t")

    def test_load_table_errors(self):
        with tempfile.TemporaryDirectory() as d:
            for line in ("a #111 -> #222", "a: #111 #222", "a: #111 -> #222\na: #333 -> #444"):
                with self.subTest(line=line), self.assertRaises(patch.PatchError):
                    path = pathlib.Path(d) / "t.txt"
                    path.write_text(line + "\n")
                    patch.load_table(path)

    def test_is_blue(self):
        for color in ("#40a7e3", "#5288c1", "#2b5278", "#6ab3f3cc", "#3390ec"):
            with self.subTest(color=color):
                self.assertTrue(patch.is_blue(color))
        for color in ("#5b7a5e", "#9dbb9f", "#131513", "#17212b", "#997be1", "#ffffff", "windowBg"):
            with self.subTest(color=color):
                self.assertFalse(patch.is_blue(color))

    def test_resolve(self):
        values = patch.palette_values("a: #111111;\nb: a;\nc: #222222 | b;\nd: c; // x\n")
        self.assertEqual([patch.resolve(values, k) for k in "abcd"], ["#111111", "#111111", "#222222", "#222222"])

    def test_night_theme_is_stable(self):
        a = patch.night_theme("windowBg: #131513;\n")
        self.assertEqual(a, patch.night_theme("windowBg: #131513;\n"))
        self.assertEqual(patch.night_colors(a), "windowBg: #131513;\n")
        with zipfile.ZipFile(io.BytesIO(a)) as z:
            self.assertEqual(z.read(patch.NIGHT_BACKGROUND)[:8], b"\x89PNG\r\n\x1a\n")

    def test_link_literals(self):
        text = ('// t.me/x\nauto a = u"https://t.me/x"_q; auto b = u"^(www\\.)?(t\\.me)$"_q;\n'
                r'auto c = R"((?:t\.me|pluma\.chat)\/)"; auto d = "part.messages"; auto e = "at.me"; /* t.me */' '\n'
                'auto f = u"pluma.chat/+"_q; auto g = "web.pluma.chat"; auto h = "pluma.chatroom";\n')
        self.assertEqual(patch.link_literals(text, patch.LINK_TME), 3)
        self.assertEqual(patch.link_literals(text, patch.LINK_PLUMA), 3)

    def test_code_telegram(self):
        text = ('// Telegram\n#include "telegram.h"\nauto a = u"Telegram Desktop"_q; auto b = "TelegramWebviewProxy";\n'
                'auto c = "https://desktop.telegram.org"; auto d = \'"\'; auto e = R"(Telegram)";\n')
        self.assertEqual(patch.code_telegram(text), 2)


# --- the patch on the pinned upstream ------------------------------------------

S = patch.SOURCES
DC, INSTANCE, LOADER, LINUX, WIN_APP_ID = patch.DC_OPTIONS, patch.INSTANCE, patch.CONFIG_LOADER, patch.LINUX, patch.WIN_APP_ID
BIRTHDAY = patch.BIRTHDAY_CONTACTS

# Damage to each place the patch edits or checks, as (file, text in the
# pinned upstream, replacement): every one must stop the patch with an error
# that names the file.
DAMAGE = (
    (patch.API_TL, "// LAYER 233\n", "// LAYER 234\n"),
    (patch.VERSION_H, 'AppVersionStr = "7.4.1";', 'AppVersionStr = "7.4.2";'),
    (patch.QT_VERSION_PY, "os.environ['QT'] = '6.11.2'", "os.environ['QT'] = '6.12.0'"),
    (patch.BUILDING_WIN, "**10.0.26100.0** SDK version", "**10.0.26200.0** SDK version"),
    (patch.BUILDING_WIN, "-vcvars_ver=14.44", "-vcvars_ver=14.50"),
    (patch.LINUX_WORKFLOW, "/download/v4.13.6/ccache-4.13.6-", "/download/v4.14.0/ccache-4.14.0-"),
    (patch.DOCKER_ENV + "/build.sh", 'cmake --build ../out --config "${CONFIG:-Release}" ${KEEP_GOING:+-- -k 0}', "cmake --build ../out --config Release"),
    (patch.DOCKER_ENV + "/build.sh", './configure.sh "$@"', './configure.sh'),
    (patch.DOCKER_ENV + "/gen_dockerfile.py", 'LTO=checkEnv("LTO", True),', 'LTO=checkEnv("ENABLE_LTO", True),'),
    (patch.PREPARE, "        elif arg == 'silent':\n", "        elif arg == 'quiet':\n"),
    # Back to packages MSYS2 has removed.
    (patch.PREPARE, "        mingw-w64-ucrt-x86_64-gperf ^\n", "        mingw-w64-x86_64-gperf ^\n"),
    (patch.PREPARE, "optionsList = [\n    'qt5',\n", "optionsList = [\n"),
    (patch.PREPARE, "    gyp dump_syms.gyp --format=msvs\n", "    gyp dump_syms.gyp --format=msvs --depth=.\n"),
    # The macOS release variants: a Qt stage with another scope in between
    # (as a later upstream has), a tg_owt that joins its Debug builds otherwise.
    (patch.PREPARE, "    CONFIGURATIONS=-debug-and-release\nmac_asserts:\n",
     "    CONFIGURATIONS=-debug-and-release\nmac_qt:\n    QT_EXTRA=1\nmac_asserts:\n"),
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
    # Updates: the keys, the file names of the feed, the universal package
    # for armac, the version compared, the empty MTProto checker.
    (patch.UPDATE_ROOT, "MCowBQYDK2VwAyEARgB8IFZWA08OzifsbPQ3SRdGbON2ecPVsMm1Qo7QNR0=", "MCowBQYDK2VwAyEARgB8IFZWA08OzifsbPQ3SRdGbON2ecPVsMm1Qo7QNR1="),
    (patch.UPDATE_MANIFEST, '"manifest_version":2', '"manifest_version":3'),
    (patch.UPDATE_CHECKER, "\t\t\tstd::make_unique<MtpChecker>(\n", "\t\t\tstd::make_unique<MtpUpdateChecker>(\n"),
    (patch.UPDATE_CHECKER, '"^td-update-(win|mac|linux)-(x86|x64|arm)-\\\\d+"', '"^td-update-(win|mac|linux|freebsd)-(x86|x64|arm)-\\\\d+"'),
    (patch.UPDATE_CHECKER, "\t\t: uint64(AppVersion);\n", "\t\t: uint64(CurrentBuild);\n"),
    (patch.UPDATE_CHECKER, "\t\t} else if (versionNum <= AppVersion) {\n", "\t\t} else if (versionNum < AppVersion) {\n"),
    (patch.UPDATE_CHANNEL, "\t\tquint32(AppVersion),\n", "\t\tquint32(AppVersion + 1),\n"),
    (patch.UPDATE_UNPACK, "\t\t|| sourceSize != compressedSize\n", ""),
    (patch.UPDATE_VERIFY, '\t} else if (key == "armac") {\n\t\treturn Target{ Os::Mac, Arch::Arm };\n', '\t} else if (key == "armac") {\n\t\treturn Target{ Os::Mac, Arch::X86 };\n'),
    (patch.CMAKE_OPTIONS, "    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE)\n",
     "    target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE=1)\n"),
    (patch.APPLICATION, "\t\tInvokeQueued(this, [] { RegisterUrlScheme(); });\n", "\t\tInvokeQueued(this, [] { RegisterUrlSchemes(); });\n"),
    (patch.APPLICATION, '\t\t.protocol = u"tg"_q,\n', '\t\t.protocol = u"telegram"_q,\n'),
    (patch.PLIST, "\t\t\t\t<string>tonsite</string>\n", ""),
    (patch.PLIST, "\t\t\t\t<string>ton</string>\n", ""),
    (patch.VERSION_H, '"Telegram Desktop"_cs', '"Telegram"_cs'),
    (patch.CONFIG_H, "87A94AB0-E370-4cde-98D3-ACC110C5967D", "87A94AB0-E370-4CDE-98D3-ACC110C5967D"),
    (patch.LAUNCHER, 'setApplicationName(u"TelegramDesktop"_q)', 'setApplicationName(u"Telegram"_q)'),
    (LINUX, '\t\treturn u"org.telegram.desktop"_q;\n', '\t\treturn u"org.telegram.Desktop"_q;\n'),
    (LINUX, 'u"/.TelegramDesktop/"_q', 'u"/.telegram-desktop/"_q'),
    (patch.DESKTOP_FILE, "Name=Telegram\n", "Name=Telegram Desktop\n"),
    (patch.DESKTOP_FILE, "MimeType=x-scheme-handler/tg;x-scheme-handler/tonsite;x-scheme-handler/ton;\n", "MimeType=x-scheme-handler/tg;\n"),
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
    # pluma.chat links: the hosts recognised, the links built, a new t.me
    # link or one gone, and an upstream that takes .chat as a domain itself.
    (patch.LOCAL_URL_HANDLERS, r'u"^(https?://)?(www\\.)?(telegram\\.(me|dog)|t\\.me)/(.+)$"_q',
     r'u"^(https?://)?(www\\.)?(telegram\\.(me|dog)|t\\.me)/(.*)$"_q'),
    (patch.CLICK_HANDLER_TYPES, r'"(^|\\.)(telegram\\.(me|dog)|t\\.me)$",', r'"(^|\\.)(telegram\\.(me|dog|org)|t\\.me)$",'),
    (patch.CLICK_HANDLER_TYPES, '\t\tu"fragment.com"_q,\n', '\t\tu"tdesktop.com"_q,\n'),
    (patch.CLICK_HANDLER_TYPES, '\t\tu"whitelisted_domains"_q,\n', '\t\tu"allowed_domains"_q,\n'),
    (patch.CLICK_HANDLER_TYPES, '\t\t|| !HostInDomains(url.host(), WhitelistedDomains(my))\n',
     '\t\t|| !HostInDomains(url.host().toLower(), WhitelistedDomains(my))\n'),
    (patch.CLICK_HANDLER_TYPES, '[[nodiscard]] bool HostInAnyWhitelist(const QString &host) {\n',
     '[[nodiscard]] bool HostInAnyList(const QString &host) {\n'),
    # A check of the whitelist that the patch does not know.
    (patch.CLICK_HANDLER_TYPES, 'bool UrlRequiresConfirmation(\n',
     'bool UrlOnList(const QString &host) {\n\treturn HostInDomains(host, DefaultWhitelistedDomains());\n}\n\n'
     'bool UrlRequiresConfirmation(\n'),
    (S + "/boxes/connection_box.cpp", "(?:www\\.)?(?:t\\.me|telegram\\.me|telegram\\.dog)", "(?:www\\.)?(?:t\\.me|telegram\\.me)"),
    (S + "/boxes/peers/edit_peer_invite_links.cpp", '\t\tu"t.me/joinchat/"_q,\n', '\t\tu"telegram.me/joinchat/"_q,\n'),
    (S + "/mtproto/mtproto_config.h", 'internalLinksDomain = u"https://t.me/"_q;', 'internalLinksDomain = u"https://telegram.me/"_q;'),
    (S + "/history/history_item.cpp", 'u"https://t.me/c/%1/%2"_q', 'u"https://t.me/c/%1/%2/"_q'),
    (S + "/core/sandbox.cpp", "namespace {\n", 'namespace {\nconst auto kLink = "https://t.me/durov";\n'),
    (S + "/boxes/sticker_set_box.cpp", 'u"https://t.me/stickers"_q', 'u"https://telegram.me/stickers"_q'),
    (patch.TEXT_ENTITY, '\taddOne(QString::fromLatin1("cat"));\n',
     '\taddOne(QString::fromLatin1("cat"));\n\taddOne(QString::fromLatin1("chat"));\n'),
    # The colours.
    (patch.PALETTE, "windowBgActive: #40a7e3;", "windowBgActive: #40a7e4;"),
    (patch.PALETTE, "// basic\n", "// basic\nnewAccentFg: #3390ec;\n"),
    (patch.EMBEDDED_THEMES, '\t\t\tqColor("5288c1")\n\t\t},', '\t\t\tqColor("5288c2")\n\t\t},'),
    (patch.INTRO_QR, "QColor(0x40, 0xA7, 0xE3); // Default windowBgActive.", "QColor(0x40, 0xA7, 0xE3);"),
    # People's colours: another cyan name, the export's rule of blue avatars.
    (patch.PALETTE, "historyPeer7NameFg: #2996ad;", "historyPeer7NameFg: #2996ae;"),
    # The verified badge: a colour of its own (not blue), its icons in other
    # keys.
    (patch.PALETTE, "dialogsVerifiedIconBg: windowBgActive;", "dialogsVerifiedIconBg: #8a5cf5;"),
    (S + "/dialogs/dialogs.style", '{ "dialogs/dialogs_verified_star", dialogsVerifiedIconBgOver },',
     '{ "dialogs/dialogs_verified_star", activeButtonBg },'),
    (S + "/info/info.style", '{{ "profile_verified_check", profileVerifiedCheckFg }}',
     '{{ "profile_verified_check", windowFgActive }}'),
    (patch.EXPORT_CSS, ".userpic4,\n.media_audio_file .fill,", ".userpic4,\n.media_audio .fill,"),
    # The ways into Telegram's services.
    (patch.SETTINGS_MAIN, "OpenAskQuestionConfirm(controller); },", "OpenAskQuestion(controller); },"),
    (patch.SETTINGS_INTRO, "\t\tOpenFaq(nullptr);\n", "\t\tOpenFaq({});\n"),
    (patch.ABOUT_BOX, "\taddText(Text3());\n", "\taddText(Text3(), true);\n"),
    (patch.MAIN_MENU, 'u"https://desktop.telegram.org"_q));', 'u"https://telegram.org/apps"_q));'),
    (patch.BANNED_BOX, '"login@stel.com"', '"recover@telegram.org"'),
    (patch.DATA_PEER, "static auto result = Window::LogoNoMargin().scaledToWidth(", "static auto result = Window::Logo().scaledToWidth("),
    (patch.ENTITLEMENTS, "<key>com.apple.security.device.camera</key>", "<key>com.apple.security.device.usb</key>"),
    # The banner of contacts' birthdays: the Premium check, the gift box, the
    # offer of a gift, the toast of its closing.
    (BIRTHDAY, "\treturn session->premiumCanBuy()\n", "\treturn session->premiumPossible()\n"),
    (BIRTHDAY, "\t\t\t\tUi::ChooseStarGiftRecipient(controller);\n", "\t\t\t\tUi::ChooseStarGiftRecipient(controller, users);\n"),
    (BIRTHDAY, "? tr::lng_dialogs_suggestions_birthday_contact_about(", "? tr::lng_dialogs_suggestions_birthday_gift_about("),
    (BIRTHDAY, "tr::lng_dialogs_suggestions_birthday_contact_dismiss(", "tr::lng_dialogs_suggestions_birthday_contacts_dismiss("),
    # The gift of a chat and of a profile on a contact's birthday.
    (patch.HISTORY_WIDGET, "\t\t&& !user->isBot()\n\t\t&& ((disallowed & Type::SendHide)\n",
     "\t\t&& !user->isBot()\n\t\t&& !user->isInaccessible()\n\t\t&& ((disallowed & Type::SendHide)\n"),
    (patch.PROFILE_ACTIONS, "const auto disable = !today && user->session().premiumCanBuy();",
     "const auto disable = !today && user->session().premiumPossible();"),
    # The tags of Saved Messages: each Premium check the patch replaces, and
    # what it leaves to upstream (the limit of tags, no custom emoji).
    (patch.MAIN_SESSION_H, "\t[[nodiscard]] bool premiumCanBuy() const;\n", "\t[[nodiscard]] bool premiumCanBuy();\n"),
    (patch.MAIN_SESSION, "\treturn _premiumPossible.current();\n", "\treturn _premiumPossible.current() && !premium();\n"),
    (patch.SECTION_WIDGET, "\t\tif (controller->session().premium()) {\n\t\t\treturn false;\n",
     "\t\tif (controller->session().premiumPossible()) {\n\t\t\treturn false;\n"),
    (patch.VIEW_ELEMENT, "\t\t\t\t\tif (item->history()->session().premium()) {\n",
     "\t\t\t\t\tif (item->history()->session().premiumPossible()) {\n"),
    (patch.REACTIONS_SELECTOR, "\t\t: item->history()->session().premium()\n",
     "\t\t: item->history()->session().premiumPossible()\n"),
    (patch.SEARCH_TAGS, "\t\tData::AmPremiumValue(&owner->session())\n", "\t\tData::AmPremiumValue(owner)\n"),
    (patch.DATA_REACTIONS, ': config->get<int>("reactions_user_max_default", 1);',
     ": 1;"),
    (patch.DATA_REACTIONS, "\t\tresult.customAllowed = premiumPossible;\n",
     "\t\tresult.customAllowed = true;\n"),
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
    # mac_asserts is a further condition on macOS, not another platform.
    return {s[:-len("_asserts")] if s.endswith("_asserts") else s for s in scopes(part.split("\n"), scope)[0]}


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

    def write_bytes(self, rel, data):
        self.written.add(str(rel))
        super().write_bytes(rel, data)


# Every premium sticker edit, damaged in the pinned upstream, stops the patch
# with the file's name.
DAMAGE += tuple((rel, old, old.replace("premium", "promium").replace("Premium", "Promium").replace("Bottom", "Top").replace("_lockIcon", "_icon"))
                for rel, old, _, _ in patch.PREMIUM_STICKERS)
# Every edit of the AI editor, damaged in the pinned upstream, stops the patch
# with the file's name.
DAMAGE += tuple((rel, old, old.replace("\t", "    ", 1)) for rel, old, _ in patch.NO_AI_EDITOR_EDITS)
# Every edit of the call parameters, damaged in the pinned upstream (tdesktop
# and its tgcalls), stops the patch with the file's name.
DAMAGE += tuple((rel, old, old[:-2] + "~" + old[-1]) for rel, old, _ in patch.CALL_PARAMETERS_EDITS)


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

    def test_updates(self):
        tree, c = self.run_patch()
        version = tree.read(patch.VERSION_H)
        # AppVersion stays upstream's; the updater compares the build number.
        self.assertIn("constexpr auto AppVersion = 7004001;\n", version)
        self.assertIn("constexpr auto PlumaBuild = 57; // pluma: the build number, which the updater compares\n", version)
        self.assertEqual(c.release_version, "7.4.1.00057")
        self.assertIn('\treturn AutoupdatePrefix("https://pluma.chat/dl/desktop"); // pluma: the Pluma server\n',
                      tree.read(patch.LOCAL_STORAGE))
        self.assertEqual(tree.read_bytes(patch.UPDATE_ROOT), UPDATE_KEYS[0])
        self.assertEqual(tree.read_bytes(patch.UPDATE_MANIFEST), UPDATE_KEYS[1])
        self.assertEqual(tree.read_bytes(patch.UPDATE_MANIFEST_SIG), UPDATE_KEYS[2])
        checker = tree.read(patch.UPDATE_CHECKER)
        self.assertNotIn("MtpChecker>(", checker)
        self.assertIn("\t\tstartImplementation(&_mtpImplementation, nullptr);\n", checker)
        self.assertNotIn("<= AppVersion", checker)
        self.assertNotIn(": uint64(AppVersion);", checker)
        self.assertEqual(checker.count("PlumaBuild"), 2)
        self.assertIn('"^(tx64upd|tmacupd|tlinuxupd)\\\\d+$|"', checker)
        self.assertIn('u"tupdates/temp/Pluma.app/Contents/Frameworks/Updater"_q', checker)
        channel = tree.read(patch.UPDATE_CHANNEL)
        self.assertIn("quint32(PlumaBuild), // pluma", channel)
        self.assertNotIn("quint32(AppVersion)", channel)
        self.assertIn('key == "armac") {\n\t\t// pluma: one universal package serves Intel and Apple processors.\n\t\treturn Target{ Os::Mac, Arch::X64 };\n',
                      tree.read(patch.UPDATE_VERIFY))
        self.assertIn('NSString *appName = @"Pluma.app";', tree.read(patch.UPDATER_OSX))
        win = tree.read(patch.UPDATER_WIN)
        self.assertIn("Uninstall\\\\{BB4EA67A-F90A-4B50-B202-49660CE32557}_is1", win)
        self.assertIn('const WCHAR *appURL = L"https://pluma.chat";', win)
        self.assertNotIn('L"Telegram Desktop"', win)
        self.assertIn('L"Failed to update Pluma :(', win)

    def test_update_keys_are_verified(self):
        """verify() looks at the keys on their own: Telegram's left in the
        tree, a manifest edited after the patch."""
        for rel, data in ((patch.UPDATE_ROOT, self.files[patch.UPDATE_ROOT]),
                          (patch.UPDATE_MANIFEST, self.files[patch.UPDATE_MANIFEST]),
                          (patch.UPDATE_MANIFEST_SIG, bytes(64))):
            with self.subTest(rel=rel):
                self.tearDown()
                tree, c = self.run_patch()
                tree.write_bytes(rel, data)
                with self.assertRaisesRegex(patch.PatchError, "update"):
                    patch.verify(tree, c)

    def test_wallet_is_off(self):
        tree, _ = self.run_patch()
        self.assertIn('return get<bool>(u"wallet_available"_q, false);', tree.read(S + "/main/main_app_config.cpp"))

    def test_no_star_store_or_transcription_on_new_surfaces(self):
        tree, _ = self.run_patch()
        message = tree.read(S + "/history/view/history_view_message.cpp")
        self.assertIn("if ((from->isPremium() // pluma: no star by a name (ADR 0041)\n", message)
        self.assertIn("if (false // pluma: the server has no transcription to offer\n\t\t&& _data->isVideoMessage()\n",
                      tree.read(S + "/history/view/media/history_view_gif.cpp"))
        self.assertIn("badge->showOn(rpl::single(session->premiumBadgesShown()));",
                      tree.read(S + "/settings/sections/settings_privacy_security.cpp"))
        self.assertIn("if (true // pluma: the server does not serve account.updateEmojiStatus\n",
                      tree.read(S + "/menu/menu_emoji_status.cpp"))
        self.assertIn("\t\t&& session().premiumCanBuy()\n\t\t&& ((disallowed & Type::SendHide)\n",
                      tree.read(S + "/history/view/controls/history_view_compose_controls.cpp"))
        self.assertIn("return rpl::single(controller->session().premiumCanBuy());",
                      tree.read(S + "/info/profile/info_profile_qr_gifts.cpp"))

    def test_scheme_lists_take_plm(self):
        tree, c = self.run_patch()
        for rel, _, new in patch.SCHEME_LISTS:
            self.assertIn('u"plm"_q, // pluma\n', tree.read(rel))
        rel = patch.SCHEME_LISTS[0][0]
        tree.write(rel, tree.read(rel).replace('\t\tu"plm"_q, // pluma\n', ""))
        with self.assertRaisesRegex(patch.PatchError, "does not take plm"):
            patch.verify(tree, c)

    def test_new_hosts_stop_the_patch(self):
        for literal in ('u"https://toncenter.com"_q', 'u"https://telegram.org/x"_q', 'u"https://tonviewer.com/x"_q',
                        'u"https://x.fragment.com/"_q'):
            with self.subTest(literal=literal):
                self.tearDown()
                tree, c = self.run_patch()
                rel = S + "/core/sandbox.cpp"
                tree.write(rel, f'const auto kUrl = {literal};\n' + tree.read(rel))
                with self.assertRaisesRegex(patch.PatchError, "HOSTS_KEPT"):
                    patch.verify(tree, c)

    def test_build_scripts_keep_the_updater(self):
        # The upstream's option defaults to ON without a special target
        # (cmake/variables.cmake 14-39); the patch stops on ON.
        for script in ("ci/build-linux.sh", "ci/macos.sh", "ci/windows.sh"):
            text = (ROOT / script).read_text()
            self.assertIn("-D DESKTOP_APP_DISABLE_AUTOUPDATE=OFF", text, script)
            self.assertIn("-D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON", text, script)

    def test_update_prefix_of_a_development_build(self):
        tree, _ = self.run_patch(app={"PLUMA_UPDATE_PREFIX": "https://127.0.0.1/dl/desktop"})
        self.assertIn('AutoupdatePrefix("https://127.0.0.1/dl/desktop")', tree.read(patch.LOCAL_STORAGE))

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
        self.assertIn('release:\n    CONFIGURATIONS=-release\nmac_asserts:\n    ASSERTS=-force-asserts\nmac:\n    rm -rf "$USED_PREFIX/Qt-$QT"\n'
                      '    ./configure -prefix "$USED_PREFIX/Qt-$QT" \\\n        $CONFIGURATIONS \\\n'
                      '        $ASSERTS \\\n        -opensource \\\n', prepare)
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
        # Telegram is left in the texts of the login code screens alone,
        # which name the real one (task 076).
        self.assertEqual(patch.lang_counts(lang), {k: patch.name_telegram(v, "")[1]
                                                   for k, v in patch.LOGIN_CODE_STRINGS.items() if "Telegram" in v})
        self.assertIn('box->setTitle(u"Pluma"_q);', tree.read(patch.ABOUT_BOX))
        self.assertIn('setTitleText(rpl::single(u"Pluma"_q));', tree.read(S + "/intro/intro_start.cpp"))
        # plm:// links.
        self.assertIn('_qrCodes.fire_copy("plm://login?token=" + encoded);', tree.read(patch.INTRO_QR))
        self.assertIn('return openCustomUrl("plm://", LocalUrlHandlers(), url, context);', tree.read(patch.APPLICATION))
        application = tree.read(patch.APPLICATION)
        self.assertIn('\t\t.protocol = u"plm"_q,\n\t\t.protocolName = u"Pluma Link"_q,\n', application)
        self.assertNotIn('u"tonsite"_q,\n\t\t.protocolName', application)
        self.assertIn('addOne(QString::fromLatin1("plm"));', tree.read(patch.TEXT_ENTITY))
        # The icons and the colours.
        for path, _ in patch.ASSETS:
            self.assertEqual(tree.read_bytes(path), (patch.BRAND / "tree" / path).read_bytes())
        self.assertIn("\nwindowBgActive: #5b7a5e; //", tree.read(patch.PALETTE))
        night = patch.palette_values(patch.night_colors(tree.read_bytes(patch.NIGHT_THEME)))
        self.assertEqual((night["windowBg"], night["msgOutBg"], night["historyPeerSavedMessagesBg"]),
                         ("#131513", "#2c3a2d", "#7fa082"))
        self.assertIn('qColor("9dbb9f") // pluma', tree.read(patch.EMBEDDED_THEMES))
        self.assertIn("QColor(0x5B, 0x7A, 0x5E)", tree.read(patch.CONNECTION_BOX))
        # What leads to Telegram's services.
        self.assertNotIn("Text3", tree.read(patch.ABOUT_BOX))
        self.assertNotIn("login@stel.com", tree.read(patch.BANNED_BOX))
        self.assertNotIn("desktop.telegram.org", tree.read(patch.MAIN_MENU))
        self.assertNotIn("isNotificationsUser()", tree.read(patch.DATA_PEER))
        self.assertNotIn("OpenFaq", tree.read(patch.SETTINGS_INTRO))
        self.assertIn("void BuildHelpSection(SectionBuilder &builder) {\n\t// pluma:", tree.read(patch.SETTINGS_MAIN))

    def test_people_colours(self):
        """People's blue is sage and cyan teal in every theme, the dark ones
        with names of their own; the themes of Telegram keep their other
        colours and files; the export's avatars take the middle of the
        gradients."""
        def files(data):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return {name: z.read(name) for name in z.namelist()}

        tree, _ = self.run_patch()
        palette = patch.palette_values(tree.read(patch.PALETTE))
        self.assertEqual([palette[key] for key in ("historyPeer4NameFg", "historyPeer4NameFgSelected",
                                                   "historyPeer4UserpicBg", "historyPeer4UserpicBg2",
                                                   "historyPeer7NameFg", "historyPeer7UserpicBg2")],
                         ["#4f6e52", "historyPeer4NameFg", "#7fa082", "#5b7a5e | historyPeer4UserpicBg",
                          "#1f8a80", "#2c9c98 | historyPeer7UserpicBg"])
        night = patch.palette_values(patch.night_colors(tree.read_bytes(patch.NIGHT_THEME)))
        self.assertEqual([night[key] for key in ("historyPeer4NameFg", "historyPeer4UserpicBg2",
                                                 "historyPeer7NameFg", "historyPeer7UserpicBg")],
                         ["#9dbb9f", "#5b7a5e", "#53ccc6", "#5bcbc4"])
        for rel in patch.TELEGRAM_THEMES:
            with self.subTest(rel=rel):
                dark = patch.IDENTITY_THEMES[rel][0]
                people = {key: on_dark if dark else on_light for key, _, on_light, on_dark in patch.IDENTITY_COLORS}
                pinned, patched = files(self.files[rel]), files(tree.read_bytes(rel))
                self.assertEqual(list(pinned), list(patched))
                for name in pinned:
                    if name != patch.THEME_COLORS:
                        self.assertEqual(pinned[name], patched[name])
                before, after = (patch.palette_values(f[patch.THEME_COLORS].decode("utf-8")) for f in (pinned, patched))
                self.assertEqual({key: after[key] for key in after if after[key] != before[key]},
                                 {key: color for key, color in people.items() if color})
        # The avatars of Saved Messages, Replies and My Notes: Classic and
        # Tinted take the palettes' sage; Day, Night and the bases refer to
        # the blue slot for the second colour (the day base for the first too)
        # and leave the rest to Classic, so sage too.
        day = patch.palette_values(tree.read(patch.PALETTE))
        saved = {}
        for rel in patch.IDENTITY_THEMES:
            values = {**day, **patch.palette_values(tree.read(rel) if rel == patch.PALETTE
                                                    else patch.zipped_colors(tree.read_bytes(rel), rel))}
            saved[rel] = tuple(patch.resolve(values, key)
                               for key in ("historyPeerSavedMessagesBg", "historyPeerSavedMessagesBg2"))
        self.assertEqual(saved, {patch.PALETTE: ("#6f8f72", "#5b7a5e"), patch.NIGHT_THEME: ("#7fa082", "#5b7a5e"),
                                 patch.DAY_BLUE_THEME: ("#6f8f72", "#5b7a5e"),
                                 patch.NIGHT_GREEN_THEME: ("#6f8f72", "#5b7a5e"),
                                 patch.DAY_BASE_THEME: ("#7fa082", "#5b7a5e"),
                                 patch.NIGHT_BASE_THEME: ("#6f8f72", "#5b7a5e")})
        css = tree.read(patch.EXPORT_CSS)
        self.assertIn(".color_blue,\n.media_audio_file .fill,\n.media_voice_message .fill {\n"
                      "    background-color: #4f9cd9;\n}\n"
                      ".userpic4 {\n    background-color: #6d8d70; /* pluma */\n}\n", css)
        self.assertIn(".color_sea,\n.media_location .fill,\n.media_video .fill {\n"
                      "    background-color: #47bcd1;\n}\n"
                      ".userpic7 {\n    background-color: #44b4ae; /* pluma */\n}\n", css)

    def test_people_colours_are_verified(self):
        """verify() finds people's colours other than IDENTITY_COLORS's in a
        theme or in the export, Telegram's blue among them, however the edits
        were made."""
        tree, c = self.run_patch()
        damage = (
            # Not blue: only the check of IDENTITY_COLORS sees these.
            (patch.PALETTE, lambda d: d.replace(b"historyPeer4NameFg: #4f6e52;", b"historyPeer4NameFg: #5b7a5e;")),
            (patch.NIGHT_THEME, lambda d: patch.night_theme(patch.night_colors(d).replace(
                "historyPeer7NameFg: #53ccc6;", "historyPeer7NameFg: #1f8a80;"))),
            # Telegram's blue back in its themes, and in the export.
            (patch.DAY_BLUE_THEME, lambda d: patch.with_colors(d, patch.zipped_colors(d, "").replace(
                "historyPeer4NameFg: #4f6e52;", "historyPeer4NameFg: windowActiveTextFg;"))),
            (patch.NIGHT_BASE_THEME, lambda d: patch.with_colors(d, patch.zipped_colors(d, "").replace(
                "historyPeer4UserpicBg2: #5b7a5e;", "historyPeer4UserpicBg2: #408acf;"))),
            (patch.EXPORT_CSS, lambda d: d + b".userpic4 {\n    background-color: #4f9cd9;\n}\n"),
        )
        for rel, damaged in damage:
            with self.subTest(rel=rel):
                patched = tree.read_bytes(rel)
                self.assertNotEqual(damaged(patched), patched, "the damage does not apply to the patched file")
                tree.write_bytes(rel, damaged(patched))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))
                tree.write_bytes(rel, patched)

    def test_people_colours_kept(self):
        """A colour of IDENTITY_COLORS set to None stays Telegram's as
        written, a reference to another key too, and verify() accepts it."""
        table = tuple((key, telegram, None if key == "historyPeer4NameFg" else on_light, on_dark)
                      for key, telegram, on_light, on_dark in patch.IDENTITY_COLORS)
        with unittest.mock.patch.object(patch, "IDENTITY_COLORS", table):
            tree, _ = self.run_patch()
        for rel, colors in ((patch.PALETTE, tree.read(patch.PALETTE)),
                            (patch.DAY_BLUE_THEME, patch.zipped_colors(tree.read_bytes(patch.DAY_BLUE_THEME), ""))):
            with self.subTest(rel=rel):
                self.assertEqual(patch.palette_values(colors)["historyPeer4NameFg"], "windowActiveTextFg")

    def test_verified_badge(self):
        """The verified badge is Pluma's accent with the colour of text on it
        in Classic and Tinted, everywhere it is drawn; Day, Night and the
        bases keep Telegram's, which follows their accent."""
        tree, c = self.run_patch()
        day = patch.palette_values(tree.read(patch.PALETTE))
        night = {**day, **patch.palette_values(patch.night_colors(tree.read_bytes(patch.NIGHT_THEME)))}
        for i, values in enumerate((day, night)):
            self.assertEqual({key: patch.resolve(values, key) for key in patch.VERIFIED_BADGE},
                             {key: colors[i] for key, colors in patch.VERIFIED_BADGE.items()})
        upstream = patch.palette_values(self.files[patch.PALETTE].decode("utf-8"))
        for rel in patch.TELEGRAM_THEMES:
            with self.subTest(rel=rel):
                before = {**upstream, **patch.palette_values(patch.zipped_colors(self.files[rel], rel))}
                after = {**day, **patch.palette_values(patch.zipped_colors(tree.read_bytes(rel), rel))}
                self.assertEqual({key: after[key] for key in patch.VERIFIED_BADGE},
                                 {key: before[key] for key in patch.VERIFIED_BADGE})
        # The accent picker of Tinted keeps the check readable on the accent.
        self.assertIn('{ qstr("profileVerifiedCheckFg"), Pair{ cColor("9dbb9f"), cColor("ffffff") } }',
                      tree.read(patch.EMBEDDED_THEMES))
        # verify() finds another colour of the badge in either theme,
        # however the edits were made.
        damage = (
            (patch.PALETTE, lambda d: d.replace(b"\nprofileVerifiedCheckBg: windowBgActive;",
                                                b"\nprofileVerifiedCheckBg: #8a5cf5;")),
            (patch.NIGHT_THEME, lambda d: patch.night_theme(patch.night_colors(d).replace(
                "dialogsVerifiedIconFg: #131513;", "dialogsVerifiedIconFg: #ffffff;"))),
        )
        for rel, damaged in damage:
            with self.subTest(rel=rel):
                patched = tree.read_bytes(rel)
                self.assertNotEqual(damaged(patched), patched, "the damage does not apply to the patched file")
                tree.write_bytes(rel, damaged(patched))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))
                self.assertIn("verified badge", str(e.exception))
                tree.write_bytes(rel, patched)

    def test_birthday_banner(self):
        """The banner of contacts' birthdays shows without Premium, a click
        opens the chat or a box "Birthdays" with them, and no text of it
        offers a gift."""
        tree, _ = self.run_patch()
        text = tree.read(BIRTHDAY)
        self.assertIn("\treturn session->promoSuggestions().current(kSugBirthdayContacts.utf8());\n}\n", text)
        self.assertIn("\t\t\tif (isSingle) {\n\t\t\t\tcontroller->showPeerHistory(first);\n\t\t\t} else {\n"
                      "\t\t\t\tcontroller->show(Box<PeerListBox>(\n"
                      "\t\t\t\t\tstd::make_unique<BirthdayContactsController>(\n", text)
        self.assertIn("class BirthdayContactsController final : public ContactsBoxController {\n", text)
        # Its search filters the few rows by name and sends no contacts.search.
        self.assertIn("\t: ContactsBoxController(session, nullptr)\n", text)
        self.assertIn("\t\t\t\t\t\tbox->setTitle(tr::lng_gift_subtitle_birthdays());\n"
                      "\t\t\t\t\t\tbox->addButton(tr::lng_close(), [=] {\n", text)
        self.assertIn("\t\tcontent->setHideCallback([=] {\n\t\t\tpromo->dismiss(kSugBirthdayContacts.utf8());\n"
                      "\t\t\trecompute();\n\t\t});\n", text)
        self.assertIn('#include "boxes/peer_list_controllers.h"\n', text)
        for gone in ("premiumCanBuy", "StarGift", "star_gift_box.h", "showToast", "_birthday_contact_about",
                     "_birthday_contacts_about", "_birthday_contact_dismiss"):
            self.assertNotIn(gone, text)
        # Its texts are keys of the built-in English, and none offers a gift.
        lang = {m["key"].split("#")[0]: m["value"] for m in patch.lang_entries(tree.read(patch.LANG))}
        keys = set(re.findall(r"\btr::(lng_\w+)\(", text))
        self.assertEqual(keys, {"lng_dialogs_suggestions_birthday_contact_title",
                                "lng_dialogs_suggestions_birthday_contacts_title", "lng_context_send_message",
                                "lng_gift_subtitle_birthdays", "lng_close"})
        self.assertEqual(lang["lng_context_send_message"], "Send message")
        self.assertEqual(lang["lng_gift_subtitle_birthdays"], "Birthdays")
        for key in keys:
            self.assertNotIn("gift", lang[key].lower(), key)
        # The chat it opens and the contact's profile offer no gift while
        # Premium cannot be bought.
        self.assertIn("\t\t&& !user->isBot()\n\t\t// pluma: no gift while Premium cannot be bought.\n"
                      "\t\t&& session().premiumCanBuy()\n\t\t&& ((disallowed & Type::SendHide)\n",
                      tree.read(patch.HISTORY_WIDGET))
        self.assertIn("\t\tconst auto disable = !today || !user->session().premiumCanBuy();\n",
                      tree.read(patch.PROFILE_ACTIONS))
        # The banner shows although it loads the birthdays first: upstream
        # hands a wrap made late over itself since 7.4 (deliver() of
        # TopBarSuggestionValue); the patch no longer does.
        self.assertIn("\t\t\t\t\t\tdeliver();\n", tree.read(S + "/dialogs/dialogs_top_bar_suggestion.cpp"))

    def test_premium_stickers(self):
        """Premium stickers work without Premium: the function stands at the
        gates of premium stickers alone, and custom emoji keep their lock."""
        tree, _ = self.run_patch()
        self.assertIn("\t[[nodiscard]] bool premiumPossible() const;\n\t// pluma: premium stickers, which need Premium upstream.\n"
                      "\t[[nodiscard]] bool premiumStickersAvailable() const;\n", tree.read(patch.MAIN_SESSION_H))
        self.assertIn("\nbool Session::premiumStickersAvailable() const {\n\t// pluma: for every user, Premium or not; the "
                      "server has no Premium.\n\treturn true;\n}\n", tree.read(patch.MAIN_SESSION))
        self.assertIn("\t\t|| document->session().premium()\n\t\t|| document->session().premiumStickersAvailable()) {\n"
                      "\t\treturn false;\n\t}\n\tShowStickerPreviewBox(std::move(show), document);\n", tree.read(patch.SECTION_WIDGET))
        self.assertEqual(tree.read(patch.STICKERS_LIST_WIDGET).count("&& !session().premiumStickersAvailable();\n"), 6)
        self.assertIn("\t\t_premium = premium || unlocked;\n", tree.read(patch.STICKER_SET_BOX))
        # Emoji still show the lock.
        self.assertIn(", _premiumMark(std::make_unique<StickerPremiumMark>(\n\t&session(),\n\tst::emojiPremiumLock))\n",
                      tree.read(patch.SOURCES + "/chat_helpers/emoji_list_widget.cpp"))
        self.assertNotIn("premiumStickersAvailable", tree.read(patch.SOURCES + "/chat_helpers/emoji_list_widget.cpp"))
        # Only the gates ask it.
        users = {rel for rel in tree.sources() if "premiumStickersAvailable" in tree.read(rel)}
        expected = {rel for rel, _, new, _ in patch.PREMIUM_STICKERS if "premiumStickersAvailable" in new}
        self.assertEqual(users, expected)
        self.assertIn("premiumStickersAvailable", tree.read(patch.STICKER_SET_BOX))
        for rel, old, _, count in patch.PREMIUM_STICKERS:
            with self.subTest(rel=rel, old=old[:50]):
                self.assertEqual(self.files[rel].decode("utf-8").count(old), count)

    def test_saved_tags(self):
        """The tags of Saved Messages work without Premium: savedTagsAvailable()
        takes the place of premium() at the tag gates alone, and the limit of
        tags and the custom emoji stay upstream's."""
        tree, _ = self.run_patch()
        self.assertIn("\t[[nodiscard]] bool premiumCanBuy() const;\n\t// pluma: the tags of Saved Messages, which need "
                      "Premium upstream.\n\t[[nodiscard]] bool savedTagsAvailable() const;\n",
                      tree.read(patch.MAIN_SESSION_H))
        self.assertIn("\nbool Session::savedTagsAvailable() const {\n\t// pluma: for every user, Premium or not; the "
                      "server has no Premium.\n\treturn true;\n}\n", tree.read(patch.MAIN_SESSION))
        gates = {
            patch.SECTION_WIDGET: "\tif (item->reactionsAreTags()) {\n\t\t// pluma: the tags without Premium.\n"
                                  "\t\tif (controller->session().savedTagsAvailable()) {\n\t\t\treturn false;\n\t\t}\n"
                                  "\t\tShowPremiumPreviewBox(controller, PremiumFeature::TagsForMessages);\n",
            patch.VIEW_ELEMENT: "\t\t\t\t\tif (item->history()->session().savedTagsAvailable()) {\n"
                                "\t\t\t\t\t\tconst auto tag = Data::SearchTagToQuery(id);\n",
            patch.REACTIONS_SELECTOR: "\t\t: item->history()->session().savedTagsAvailable()\n"
                                      "\t\t? TextWithEntities{ tr::lng_add_tag_about(tr::now) }\n",
            patch.SEARCH_TAGS: "\t\tstd::move(tags),\n\t\t// pluma: not Data::AmPremiumValue.\n"
                               "\t\trpl::single(owner->session().savedTagsAvailable())\n\t) | rpl::on_next([=](\n",
        }
        for rel, s in gates.items():
            with self.subTest(rel=rel):
                self.assertIn(s, tree.read(rel))
        self.assertNotIn("Data::AmPremiumValue(", tree.read(patch.SEARCH_TAGS))
        # Nothing else asks for it: no other Premium feature opens.
        users = {rel for rel in tree.sources() if "savedTagsAvailable" in tree.read(rel)}
        self.assertEqual(users, {patch.MAIN_SESSION_H, patch.MAIN_SESSION, *gates})
        for rel in gates:
            self.assertEqual(tree.read(rel).count("savedTagsAvailable()"), 1, rel)
        # Each file changes by the patch's lines alone: one premium() less,
        # and the text is upstream's otherwise.
        for rel, old, new in patch.SAVED_TAGS:
            with self.subTest(rel=rel):
                expected = self.files[rel].decode("utf-8").replace(old, new)
                for sticker_rel, sticker_old, sticker_new, _ in patch.PREMIUM_STICKERS:
                    if sticker_rel == rel:
                        expected = expected.replace(sticker_old, sticker_new)
                for link_rel, link, _ in patch.LINK_BUILDERS:  # a topic link of VIEW_ELEMENT
                    if link_rel == rel:
                        expected = expected.replace(link, link.replace("t.me", patch.LINK_HOST))
                for premium_rel, premium_old, premium_new in patch.PREMIUM_FOR_EVERYONE_EDITS:  # the star by a name
                    if premium_rel == rel:
                        expected = expected.replace(premium_old, premium_new)
                self.assertEqual(tree.read(rel), expected)
        # The rest stays upstream's: the server's limit of tags on a message
        # for a user without Premium, no custom emoji among the tags.
        reactions = tree.read(patch.DATA_REACTIONS)
        for s in patch.SAVED_TAGS_KEPT:
            self.assertIn(s, reactions)
        # No new text: the hint is a key the built-in English has.
        lang = {m["key"].split("#")[0]: m["value"] for m in patch.lang_entries(tree.read(patch.LANG))}
        self.assertEqual(lang["lng_add_tag_about"], "Tag this message with an emoji for quick search.")

    def test_links(self):
        """pluma.chat links beside t.me's: the expressions the app matches
        links with, read from the patched sources, and the links it builds."""
        tree, _ = self.run_patch()

        def literals(text):
            # The string literals of a C++ fragment, as the compiler joins them.
            return "".join(m.group(1).encode().decode("unicode_escape")
                           for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', text))

        handlers = tree.read(patch.LOCAL_URL_HANDLERS)
        line = handlers[handlers.index("\tauto telegramMeMatch = "):]
        convert = re.compile(literals(line[:line.index("_q")]), re.I)
        for url, path in (("https://pluma.chat/durov", "durov"), ("pluma.chat/+AbC-d_1", "+AbC-d_1"),
                          ("HTTP://PLUMA.CHAT/c/1/2", "c/1/2"), ("https://pluma.chat/addstickers/set", "addstickers/set"),
                          ("https://t.me/durov", "durov"), ("https://www.telegram.me/durov", "durov"),
                          ("telegram.dog/+123", "+123")):
            m = convert.search(url)
            self.assertIsNotNone(m, url)
            self.assertEqual(m.group(5), path, url)
        for url in ("https://web.pluma.chat/x", "https://www.pluma.chat/x", "https://notpluma.chat/x",
                    "https://pluma.chat.example.com/x", "https://pluma.chat/", "https://example.com/pluma.chat/x"):
            self.assertIsNone(convert.search(url), url)

        # The site's own pages: the converter returns them before the line
        # above, as they are, so they open in the browser.
        start = handlers.index("QString TryConvertUrlToLocal(QString url) {\n")
        site_at = handlers.index("\tif (regex_match(u\"^(https?://)?pluma", start)
        self.assertLess(site_at, handlers.index("\tauto telegramMeMatch = ", start))
        self.assertEqual(handlers[site_at:].split("\n")[1:3], ["\t\treturn url;", "\t}"])
        site = re.compile(literals(handlers[site_at:handlers.index("_q", site_at)]), re.I)
        self.assertEqual(len(patch.SITE_PATHS), 21)
        for url in ("https://pluma.chat", "pluma.chat", "https://pluma.chat/", "https://pluma.chat/?utm=1",
                    "https://pluma.chat#top", "https://pluma.chat/iphone", "HTTPS://PLUMA.CHAT/Android/",
                    "https://pluma.chat/windows?ref=x", "https://pluma.chat/en", "https://pluma.chat/en/iphone",
                    "https://pluma.chat/dl/desktop/x.zip", "https://pluma.chat/_l/abc", "https://pluma.chat/assets/a.css",
                    "https://pluma.chat/.well-known/apple-app-site-association", "https://pluma.chat/favicon.svg",
                    "https://pluma.chat/og.png", "https://pluma.chat/apple-touch-icon.png", "https://pluma.chat/404.html",
                    "https://pluma.chat/progress.json?t=1", "https://pluma.chat/collect", "https://pluma.chat/pero#a",
                    "http://pluma.chat/ipad", "pluma.chat/mac", "pluma.chat/linux", "pluma.chat/web", "pluma.chat/app",
                    "pluma.chat/ios"):
            self.assertIsNotNone(site.search(url), url)
        for url in ("https://pluma.chat/durov", "https://pluma.chat/+AbC-d_1", "https://pluma.chat/c/1/2",
                    "https://pluma.chat/addstickers/set", "https://pluma.chat/iphoneuser", "https://pluma.chat/myapp",
                    "https://pluma.chat/en_x", "https://pluma.chat/og.pngx", "https://pluma.chat/ogxpng",
                    "https://pluma.chat/joinchat/abc", "https://pluma.chat/proxy?server=a", "https://t.me/iphone",
                    "https://www.pluma.chat/iphone", "https://web.pluma.chat/", "https://pluma.chat.example.com/",
                    "https://example.com/pluma.chat/iphone"):
            self.assertIsNone(site.search(url), url)

        types = tree.read(patch.CLICK_HANDLER_TYPES)
        start = types.index("bool IsTelegramShortLinkHost(")
        short = re.compile(literals(types[start:types.index("url.host()", start)]), re.I)
        start = types.index("DefaultWhitelistedDomains() {")
        domains = re.findall(r'u"([a-z.]+)"_q', types[start:types.index("}", start)])
        self.assertIn("pluma.chat", domains)

        start = types.index("bool HostOpensWithoutAsking(")
        under = re.search(r'!host\.endsWith\(u"([a-z.]+)"_q, Qt::CaseInsensitive\)\n\t\t&& HostInDomains\(host, domains\);',
                          types[start:]).group(1)

        def in_list(host):
            # HostInDomains: the domain itself or a name under it.
            host = host.lower()
            return any(host == d or host.endswith("." + d) for d in domains)

        def trusted(host):
            return not host.lower().endswith(under) and in_list(host)

        for host, is_short, is_trusted in (("pluma.chat", True, True), ("PLUMA.chat", True, True),
                                           ("web.pluma.chat", False, False), ("WWW.Pluma.Chat", False, False),
                                           ("evilpluma.chat", False, False),
                                           ("pluma.chat.example.com", False, False), ("t.me", True, True),
                                           ("user.t.me", True, True), ("telegram.org", False, True),
                                           ("telegra.ph", False, True), ("fragment.com", False, True),
                                           ("example.com", False, False)):
            self.assertEqual(bool(short.search(host)), is_short, host)
            self.assertEqual(trusted(host), is_trusted, host)
        # The tokens of a foreign login are stripped from the web client too.
        self.assertTrue(in_list("web.pluma.chat"))
        self.assertIn("return HostInDomains(host, DefaultWhitelistedDomains())\n", types)
        # The server's list, which names pluma.chat alone, only adds.
        self.assertIn("\tauto result = DefaultWhitelistedDomains();\n", types)
        self.assertIn("\t\t|| !HostOpensWithoutAsking(url.host(), WhitelistedDomains(my)) // pluma\n", types)
        self.assertIn("\treturn !HostOpensWithoutAsking( // pluma\n\t\turl.host(),\n", types)

        box = tree.read(S + "/boxes/connection_box.cpp")
        raw = box[box.index('R"((?:https?:'):]
        proxy = re.compile(raw[3:raw.index(')",')], re.I)
        self.assertEqual(proxy.findall("pluma.chat/proxy?server=a&port=1 and www.t.me/socks?server=b"),
                         ["pluma.chat/proxy?server=a&port=1", "www.t.me/socks?server=b"])

        # The links the app builds, and the names of invite links.
        for rel, text in ((S + "/mtproto/mtproto_config.h", 'QString internalLinksDomain = u"https://pluma.chat/"_q;\n'),
                          (S + "/boxes/language_box.cpp", 'const auto link = u"https://pluma.chat/setlanguage/"_q + row->data.id;'),
                          (S + "/history/history_item.cpp", 'u"https://pluma.chat/c/%1/%2"_q'),
                          (S + "/settings/sections/settings_information.cpp", 'return empty ? "pluma.chat/username" : label;'),
                          (S + "/boxes/peers/create_managed_bot_box.cpp", 'u"pluma.chat/"_q + full);'),
                          (S + "/boxes/choose_filter_box.cpp", 'startsWith(u"https://pluma.chat/"_q)) { // pluma\n\t\t\ttext = text.mid(19);'),
                          (S + "/boxes/peers/edit_peer_invite_links.cpp", '.replace(\n\t\tu"pluma.chat/+"_q, // pluma\n\t\tQString()\n\t);'),
                          (patch.TEXT_ENTITY, 'addOne(QString::fromLatin1("chat")); // pluma')):
            self.assertIn(text, tree.read(rel), rel)
        self.assertEqual(len("https://pluma.chat/"), 19)
        builders = {rel for rel, _, _ in patch.LINK_BUILDERS}
        for rel in builders - {S + "/boxes/peers/create_managed_bot_box.cpp"}:
            self.assertNotIn('"https://t.me/', tree.read(rel), rel)
        # Each file differs from the pinned upstream by its edits alone (and
        # by the other edits there: plm:// in place of tg://, the tags of
        # Saved Messages, the colour of QR codes, the name).
        for rel in patch.links_edited():
            if rel == patch.TEXT_ENTITY:
                continue  # its plm, which the brand's checks cover
            text = self.files[rel].decode("utf-8")
            edits = ([(o, n) for r, o, n in patch.LINK_HOSTS + patch.SAVED_TAGS + patch.QR_COLORS + patch.BIRTHDAY_GIFTS if r == rel]
                     + [(o, n) for r, o, n, _ in patch.PREMIUM_STICKERS if r == rel]
                     + [(o, n.replace("{name}", "Pluma")) for r, o, n, _ in patch.CODE_NAMES if r == rel]
                     + [(o, o.replace("t.me", patch.LINK_HOST)) for r, o, _ in patch.LINK_BUILDERS if r == rel])
            for old, new in edits:
                text = text.replace(old, new)
            self.assertEqual(tree.read(rel).replace("plm://", "tg://"), text, rel)
        self.assertEqual(tree.read(patch.TEXT_ENTITY).count('addOne(QString::fromLatin1("chat"));'), 1)

    def test_site_links_are_verified(self):
        """verify() stops a converter that takes a page of the site as a
        username, or a username as a page, however the edits were made."""
        tree, c = self.run_patch()
        rel = patch.LOCAL_URL_HANDLERS
        patched = tree.read(rel)
        for old, new in (("|collect|", "|"), ("|/?([?#].*)?)$", ")$"), ("([/?#].*)?|", "(.*)?|"),
                         ("favicon\\\\.svg", "favicon.svg"), ("\t\treturn url;\n\t}\n\t// pluma: pluma.chat", "\t}\n\t// pluma: pluma.chat")):
            with self.subTest(old=old):
                self.assertEqual(patched.count(old), 1, old)
                tree.write_bytes(rel, patched.replace(old, new).encode())
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn("local_url_handlers.cpp", str(e.exception))
                tree.write_bytes(rel, patched.encode())
        # The check sits after the converter's other edits too: moved below
        # the line that takes pluma.chat as the app's, it stops the patch.
        line = patched[patched.index("\t// pluma: the pages of the site"):patched.index("\t// pluma: pluma.chat links are internal")]
        moved = patched.replace(line, "")
        at = moved.index("\tif (telegramMeMatch) {\n")
        tree.write_bytes(rel, (moved[:at] + line + moved[at:]).encode())
        with self.assertRaises(patch.PatchError):
            patch.verify(tree, c)
        tree.write_bytes(rel, patched.encode())
        patch.verify(tree, c)

    def test_help_and_gift_links(self):
        """plm://settings/faq, /ask-question and /features have no route, and
        the links to the gift box ask whether Premium can be bought; a new
        way to either stops the patch."""
        tree, c = self.run_patch()
        text = tree.read(patch.DEEP_LINKS_SETTINGS)
        for gone in ('u"faq"_q', 'u"ask-question"_q', 'u"features"_q', "ShowFaq", "OpenFaq(", "OpenFeatures(",
                     "OpenAskQuestionConfirm("):
            self.assertNotIn(gone, text)
        self.assertEqual(len(re.findall(
            r"if \(!ctx\.controller->session\(\)\.premiumCanBuy\(\)\) \{\n\t\t\t\treturn Result::Unsupported;\n\t\t\t\}\n"
            r"\t\t\tUi::(?:ChooseStarGiftRecipient|ShowStarGiftBox)\(", text)), 2)
        handlers = tree.read(patch.LOCAL_URL_HANDLERS)
        self.assertIn("\tif (!controller || !controller->session().premiumCanBuy()) {\n\t\treturn false;\n\t}\n"
                      "\tUi::ChooseStarGiftRecipient(controller);\n", handlers)
        route = 'router.add(u"settings"_q, {\n\t\t.path = u"saved-messages"_q,\n'
        self.assertIn(route, text)
        for added, what in (("\t\t::Settings::OpenFaq(nullptr);\n", "FAQ"),
                            ("\t\tUi::ShowStarGiftBox(ctx.controller, ctx.controller->session().user());\n", "gift")):
            with self.subTest(what=what):
                tree.write(patch.DEEP_LINKS_SETTINGS, text.replace("\t" + route, added + "\t" + route, 1))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn("deep_links_settings.cpp", str(e.exception))

    def test_login_code_screens(self):
        """The screens of the login code (task 076): Pluma's texts naming
        the real Telegram, kept by key and exact value; one tg:// link, to
        Telegram's settings; no Fragment screen. Each check stops a tree
        that lacks what it checks."""
        tree, c = self.run_patch()
        lang = tree.read(patch.LANG)
        self.assertIn('"lng_intro_fragment_button" = "Open Fragment";\n"lng_pluma_code_telegram_title" = "Check Telegram";\n',
                      lang)
        self.assertIn('"lng_pluma_code_failed_about" = "The code for **{phone_number}** didn\'t reach your Telegram. '
                      'Let Telegram find you by your number: **Settings \u2192 Privacy and Security \u2192 Phone Number '
                      '\u2192 Who can find me by my number? \u2192 Everybody**.\\n\\nNo Telegram? Ask the administrator '
                      'for the code and enter it here.";\n', lang)
        self.assertIn('"lng_pluma_code_resend_in" = "Send again in {time}";\n', lang)
        code = tree.read(patch.INTRO_CODE)
        self.assertEqual(code.count("tg://"), 1)
        self.assertIn('\t\tFile::OpenUrl(u"tg://settings/phone_privacy"_q);\n', code)
        self.assertNotIn("introFragmentButton", code)
        self.assertNotIn("getData()->codeByTelegram = false;", code)
        self.assertIn("\t\tgetData()->codeUndelivered = true; // pluma\n", tree.read(patch.INTRO_STEP))

        def stops(rel, text, where):
            tree.write(rel, text)
            with self.assertRaises(patch.PatchError) as e:
                patch.verify(tree, c)
            self.assertIn(where, str(e.exception))
            tree.write(rel, patched)

        # The texts: renamed, renamed and changed, lost, or a new one naming
        # Telegram beside them.
        patched = lang
        failed = '"lng_pluma_code_failed_title" = "Code didn\'t reach Telegram";\n'
        stops(patch.LANG, lang.replace(failed, failed.replace("Telegram", "Pluma")), "lng_pluma_code_failed_title")
        stops(patch.LANG, lang.replace(failed, failed.replace("reach", "get to")), "lng_pluma_code_failed_title")
        stops(patch.LANG, lang.replace(failed, ""), "lng_pluma_code_failed_title")
        stops(patch.LANG, lang.replace(failed, failed + '"lng_pluma_code_other" = "Open Telegram";\n'),
              "lng_pluma_code_other")
        # The code: another tg:// link, or none; an edit or a function undone.
        patched = code
        stops(patch.INTRO_CODE, code.replace("File::OpenUrl(getData()->codeByFragmentUrl);",
                                             'File::OpenUrl(u"tg://resolve?domain=x"_q);'), "intro_code.cpp")
        stops(patch.INTRO_CODE, code.replace(patch.TELEGRAM_SETTINGS_LINK, 'u"tg://settings"_q'), "intro_code.cpp")
        stops(patch.INTRO_CODE, code.replace(patch.TELEGRAM_SETTINGS_LINK, 'u"plm://settings/phone_privacy"_q'),
              "intro_code.cpp")
        for rel, old, new in patch.LOGIN_CODE_EDITS:
            with self.subTest(rel=rel, new=new[:60]):
                patched = tree.read(rel)
                stops(rel, patched.replace(new, old), pathlib.PurePath(rel).name)
        patched = code
        for head, body, _ in patch.LOGIN_CODE_BODIES:
            with self.subTest(head=head):
                stops(patch.INTRO_CODE, code.replace(body, "\t_code->requestCode();"), "intro_code.cpp")
        patch.verify(tree, c)

    def test_login_code_screens_layout(self):
        """The description of the screens of task 076 moves the content
        under it by what it has over upstream's three lines, the native
        screens not at all; the content rises and the window keeps its
        height so that the next button and the language link stay in view;
        the button and the slide follow the description."""
        tree, _ = self.run_patch()
        S = patch.SOURCES

        def body(rel, head):
            text = tree.read(rel)
            start = text.index(head)
            return text[start:text.index("\n}\n", start)]

        code = tree.read(patch.INTRO_CODE)
        self.assertIn("\t\tconst auto room = st::introDescription.style.lineHeight * 3;\n"
                      "\t\tsetContentShift((mode == Mode::Telegram || mode == Mode::Undelivered)\n"
                      "\t\t\t? std::max(height - room, 0)\n\t\t\t: 0);\n", code)
        self.assertNotIn("introLinkTop;\n\t\tsetContentShift", code)
        top = body(patch.INTRO_STEP, "int Step::contentTop() const {\n")
        self.assertLess(top.index("height() - st::introNextTop - shift - ContentBelowNextTop());"),
                        top.index("accumulate_max(result, st::introStepTopMin);"))
        shift = body(patch.INTRO_STEP, "void Step::setContentShift(int shift) { // pluma\n")
        self.assertIn("_contentShiftAnimation.start(", shift)
        self.assertIn("st::introStepTopMin\n\t\t\t+ st::introNextTop\n\t\t\t+ shift\n\t\t\t+ ContentBelowNextTop())",
                      shift)
        # The slide shows the whole of both steps.
        step = tree.read(patch.INTRO_STEP)
        self.assertIn("\t\tauto rightSnapshot = prepareSlideAnimation(_slideTop, _slideHeight);\n", step)
        self.assertIn("\t\t\t[=] { update(0, _slideTop, width(), _slideHeight); }, // pluma\n", step)
        self.assertNotIn("st::introStepWidth, st::introStepHeight));", step)
        # The next button moves with the slide and with the description.
        widget = tree.read(patch.INTRO_WIDGET)
        self.assertIn("\t\t_nextMoveAnimation.start(\n", body(patch.INTRO_WIDGET, "void Widget::historyMove("))
        self.assertIn("\t\tshown * _nextMoveAnimation.value(1.)); // pluma\n", widget)
        self.assertIn("\t\t\t_requiredHeight = height;\n", body(patch.INTRO_WIDGET, "void Widget::setupStep() {\n"))
        # The window keeps the height the intro needs, and drops it with it.
        self.assertIn("\t\t+ st::windowMinHeight\n\t\t+ bodyMinHeightAdd(); // pluma",
                      body(S + "/window/main_window.cpp", "int MainWindow::computeMinHeight() const {\n"))
        main = tree.read(S + "/mainwindow.cpp")
        self.assertIn("\t\t? std::max(_intro->requiredHeight() - st::windowMinHeight, 0)\n", main)
        self.assertIn("\t\trecountGeometryConstraints();\n",
                      body(S + "/mainwindow.cpp", "void MainWindow::setupIntro("))
        self.assertIn("\t\tsetMinimumSize(QSize(computeMinWidth(), computeMinHeight()));\n",
                      body(S + "/mainwindow.cpp", "void MainWindow::clearWidgetsHook() {\n"))

    def test_login_code_screens_resend(self):
        """The answers of auth.resendCode on the screens of task 076: the
        countdown of FLOOD_WAIT, the administrator when nothing more can be
        sent, the phone entry when the code expired; no link while a request
        is on its way or the step slides."""
        tree, _ = self.run_patch()
        code = tree.read(patch.INTRO_CODE)
        start = code.index("void CodeWidget::noTelegramCodeFail(")
        fail = code[start:code.index("\n}\n", start)]
        # The state first, then the row, then what may leave the step.
        order = ["_resendFloodUntil = crl::now() + seconds * crl::time(1000);",
                 "getData()->codeResendable = false;",
                 "updateCallText();",
                 "showCodeError(tr::lng_flood_error());",
                 "showAdministratorBox(); // pluma",
                 "goBack();"]
        self.assertEqual([fail.index(s) for s in order], sorted(fail.index(s) for s in order))
        self.assertNotIn('error.type() != u"SEND_CODE_UNAVAILABLE"_q', fail)
        start = code.index("void CodeWidget::updateCallText() {\n")
        row = code[start:code.index("\n}\n", start)]
        self.assertIn("\t\t\t_resendFloodUntil);\n", row)
        self.assertIn("\t\t_noTelegramCode->setVisible(text.isEmpty() && !animating());\n", row)
        self.assertIn("\t\t\t? tr::lng_pluma_code_sending(tr::now)\n", row)
        self.assertEqual(code.count("\t\tshowAdministratorBox();\n"), 1)
        self.assertEqual(code.count("Ui::MakeInformBox({\n\t\t.text = tr::lng_pluma_code_admin_text(),"), 1)

    def test_telegram_plane_in_a_new_icon(self):
        """The plane of the 7.4 notice is Pluma's mark; another file drawing
        Telegram's stops the patch."""
        tree, _ = self.run_patch()
        rel = patch.ICONS + "/chat/unsupported_plane.svg"
        self.assertNotIn(patch.TELEGRAM_PLANE, tree.read(rel))
        self.assertEqual(tree.read_bytes(rel), (patch.BRAND / "tree" / rel).read_bytes())
        self.assertIn(patch.TELEGRAM_PLANE, self.files[rel].decode("utf-8"))
        new = patch.ICONS + "/chat/another_plane.svg"
        tree.write_bytes(new, self.files[rel])
        with self.assertRaises(patch.PatchError) as e:
            patch.verify(tree, config())
        self.assertIn("another_plane.svg", str(e.exception))

    def test_changed_binary_files(self):
        """An icon or a zipped theme of another release stops the patch."""
        for rel in (patch.ASSETS[0][0], patch.NIGHT_THEME, *patch.TELEGRAM_THEMES):
            with self.subTest(rel=rel):
                self.tearDown()
                self.written.add(rel)
                (self.root / rel).write_bytes(self.files[rel] + b"\0")
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(rel, str(e.exception))

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


class PremiumForEveryoneTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.PREMIUM_FOR_EVERYONE_EDITS):
        for rel in (patch.VERSION_H, patch.CMAKE_APP):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        files = {}
        for edit in edits:
            rel, old = edit[0], edit[1]
            count = edit[3] if len(edit) > 3 else 1
            files[rel] = files.get(rel, "") + (old + "x\n") * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                patch.verify_premium_for_everyone(tree)
            patch.premium_for_everyone(tree)
            patch.verify_premium_for_everyone(tree)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.premium_for_everyone(tree)

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.premium_for_everyone(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.premium_for_everyone(tree)
            for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
                rel, old, new = edit[0], edit[1], edit[2]
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(file=rel), self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                    patch.verify_premium_for_everyone(tree)
                tree.write(rel, patched)
            patch.verify_premium_for_everyone(tree)


class LoginCodeScreensTest(unittest.TestCase):
    """The edits of task 076 on files made of the texts they expect."""

    def tree(self, root, edits=patch.LOGIN_CODE_EDITS):
        for rel in (patch.VERSION_H, patch.CMAKE_APP):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        files = {patch.LANG: patch.LOGIN_CODE_STRINGS_AFTER}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        for head, _, had in patch.LOGIN_CODE_BODIES:
            files[patch.INTRO_CODE] += head + "".join(f"\t{s}\n" for s in had) + "}\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "task 076"):
                patch.verify_login_code_screens(tree)
            patch.login_code_screens(tree)
            patch.verify_login_code_screens(tree)
            entries = {m["key"]: m["value"] for m in patch.lang_entries(tree.read(patch.LANG))}
            self.assertEqual({k: v for k, v in entries.items() if k.startswith("lng_pluma_code_")},
                             patch.LOGIN_CODE_STRINGS)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.login_code_screens(tree)

    def test_texts(self):
        # The texts of the task, in tdesktop's placeholders and markup; each
        # names the real Telegram where the task's text does.
        s = patch.LOGIN_CODE_STRINGS
        self.assertEqual(len(s), 12)
        self.assertIn("**{phone_number}**", s["lng_pluma_code_telegram_about"])
        self.assertIn("**{phone_number}**", s["lng_pluma_code_failed_about"])
        self.assertTrue(s["lng_pluma_code_resend_in"].endswith(" {time}"))
        for key in ("lng_pluma_code_telegram_title", "lng_pluma_code_telegram_about", "lng_pluma_code_telegram_button",
                    "lng_pluma_code_failed_title", "lng_pluma_code_failed_about", "lng_pluma_code_failed_button"):
            self.assertIn("Telegram", s[key], key)
        for value in s.values():
            self.assertNotIn("SMS", value)
            self.assertIsNotNone(patch.LANG_ENTRY.fullmatch(f'"k" = "{value}";'), value)

    def test_upstream_changed(self):
        for i, (rel, old, new) in enumerate(patch.LOGIN_CODE_EDITS):
            changed = old[:-2] + "~" + old[-1]
            edits = [e if j != i else (rel, changed, new) for j, e in enumerate(patch.LOGIN_CODE_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.login_code_screens(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.login_code_screens(tree)
            for rel, old, new in patch.LOGIN_CODE_EDITS:
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(rel=rel, new=new[:60]), self.assertRaisesRegex(patch.PatchError, "task 076"):
                    patch.verify_login_code_screens(tree)
                tree.write(rel, patched)
            code = tree.read(patch.INTRO_CODE)
            for head, body, _ in patch.LOGIN_CODE_BODIES:
                tree.write(patch.INTRO_CODE, code.replace(head + body, head + "\t_isFragment;"))
                with self.subTest(head=head), self.assertRaisesRegex(patch.PatchError, "task 076"):
                    patch.verify_login_code_screens(tree)
            tree.write(patch.INTRO_CODE, code + "\t_isFragment = false;\n")
            with self.assertRaisesRegex(patch.PatchError, "Fragment"):
                patch.verify_login_code_screens(tree)
            tree.write(patch.INTRO_CODE, code)
            lang = tree.read(patch.LANG)
            for key, value in patch.LOGIN_CODE_STRINGS.items():
                entry = f'"{key}" = "{value}";\n'
                for broken in (lang.replace(entry, ""), lang.replace(entry, entry.replace("Telegram", "Pluma")),
                               lang + entry):
                    if broken == lang:
                        continue
                    tree.write(patch.LANG, broken)
                    with self.subTest(key=key), self.assertRaisesRegex(patch.PatchError, key):
                        patch.verify_login_code_screens(tree)
            tree.write(patch.LANG, lang)
            patch.verify_login_code_screens(tree)


class NoAiEditorTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect and the ways to
    # the editor the guards count.
    def tree(self, root, edits=patch.NO_AI_EDITOR_EDITS):
        for rel in (patch.VERSION_H, patch.CMAKE_APP):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        files = {}
        for rel, s, count in patch.NO_AI_EDITOR_GUARDS:
            files[rel] = files.get(rel, "") + (s + "\n") * count
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                patch.verify_no_ai_editor(tree)
            patch.no_ai_editor(tree)
            patch.verify_no_ai_editor(tree)
            with self.assertRaises(patch.PatchError):
                patch.no_ai_editor(tree)

    def test_buttons_never_show(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.no_ai_editor(tree)
            self.assertIn("\tif (true // pluma:", tree.read(patch.AI_BUTTON_FACTORY))
            self.assertIn("\tif (false // pluma:", tree.read(patch.AI_IV_EDITOR))
            self.assertNotIn("ComposeAiApplyInPlace", tree.read(patch.AI_SHORTCUTS))

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.NO_AI_EDITOR_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.NO_AI_EDITOR_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.no_ai_editor(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.no_ai_editor(tree)
            for i, (rel, old, new) in enumerate(patch.NO_AI_EDITOR_EDITS):
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(edit=i), self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                    patch.verify_no_ai_editor(tree)
                tree.write(rel, patched)
            patch.verify_no_ai_editor(tree)

    def test_another_way_in(self):
        for rel, s, _ in patch.NO_AI_EDITOR_GUARDS:
            with self.subTest(file=rel, text=s), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.no_ai_editor(tree)
                tree.write(rel, tree.read(rel) + s + "\n")
                with self.assertRaisesRegex(patch.PatchError, "another way into the AI editor"):
                    patch.verify_no_ai_editor(tree)

    def test_lf_only_covers_the_edits(self):
        self.assertEqual(set(patch.no_ai_editor_edited()), {rel for rel, _, _ in patch.NO_AI_EDITOR_EDITS})


class CallParametersTest(unittest.TestCase):
    """The edits of task 077 on files made of the texts they expect, with
    as many of the guarded texts as the patched pinned upstream has."""

    def tree(self, root, edits=patch.CALL_PARAMETERS_EDITS):
        for rel in (patch.VERSION_H, patch.CMAKE_APP):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        files = {}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        patched = dict(files)
        for rel, old, new in patch.CALL_PARAMETERS_EDITS:
            patched[rel] = patched[rel].replace(old, new)
        for rel, s, count in patch.CALL_PARAMETERS_GUARDS:
            missing = count - patched[rel].count(s)
            self.assertGreaterEqual(missing, 0, s)
            files[rel] += (s + "\n") * missing
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "task 077"):
                patch.verify_call_parameters(tree)
            patch.call_parameters(tree)
            patch.verify_call_parameters(tree)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.call_parameters(tree)

    def test_defaults_are_upstreams(self):
        # Without a key every value is the pinned tgcalls' own (A/B against
        # Telegram): Opus 60 ms at 32 * 1024 bit/s, a jitter floor of 50 ms,
        # the camera at 1000 * 1024 bit/s, no cap on the screen, no start
        # bitrate, no RNNoise, and upstream's field trials, extended only by
        # a range from the server.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.call_parameters(tree)
            v2 = tree.read(patch.TGCALLS_V2)
            for key, default in (("audio_ptime_ms", "60"), ("audio_max_bitrate_kbps", "32 * 1024"),
                                 ("audio_min_bitrate_kbps", "0"), ("audio_jitter_min_ms", "50"),
                                 ("video_max_bitrate_kbps", "1000 * 1024"), ("screen_max_bitrate_kbps", "0"),
                                 ("start_bitrate_kbps", "0"), ("video_fps", "0"), ("screen_fps", "0"),
                                 ("screen_max_size_px", "0")):
                self.assertRegex(v2, rf'_customParameters, "{key}", {re.escape(default)}, \d+, \d+\);\n', key)
            for member in ("int _audioPtimeMs = 60;", "int _audioMaxBitrateBps = 32 * 1024;",
                           "int _audioJitterBufferMinDelayMs = 50;", "bool _audioRnnoise = false;",
                           "int _videoMaxBitrateBps = 1000 * 1024;", "int _screencastMaxBitrateBps = 0;",
                           "int _startBitrateBps = 0;", "int _videoFps = 0;"):
                self.assertIn(f"    {member}", v2)
            # The camera keeps upstream's 25 unless the call sets a rate; the
            # screen keeps upstream's size and rate unless the call sets limits.
            self.assertIn("                if (_videoFps != 0) {\n", v2)
            self.assertIn("    int _adaptationFramerate = 25;", tree.read(patch.TGCALLS_CAPTURE_HEADER))
            self.assertEqual(tree.read(patch.TGCALLS_CAPTURE).count(", _adaptationFramerate);\n"), 2)
            self.assertIn("SetCallScreenCaptureLimits(this, screenMaxSidePx, screenFps);\n", v2)
            helper = tree.read(patch.TGCALLS_SCREEN_HELPER)
            self.assertIn("std::atomic<int> CallScreenMaxSide{ 0 };\nstd::atomic<int> CallScreenFps{ 0 };\n", helper)
            self.assertIn("    if (const auto maxSide = followsCallLimits_ ? CallScreenMaxSide.load() : 0) {\n", helper)
            self.assertIn("(callFps > 0) ? (1000. / callFps) : _delayMs", helper)
            self.assertIn("\tbool followsCallLimits = false;\n", tree.read(patch.TGCALLS_SCREEN_SOURCE))
            self.assertIn("        if (_outgoingScreencastChannel && _screencastMaxBitrateBps != 0) {\n", v2)
            self.assertIn("            if (_startBitrateBps != 0) {\n", v2)
            self.assertIn("        if (audioMinBitrateBps != 0 && audioMinBitrateBps <= _audioMaxBitrateBps) {\n", v2)
            trials = re.search(r'std::string fieldTrials =\n((?:            "[^"]*";?\n)+)', v2)
            pinned_old = next(old for _, old, _ in patch.CALL_PARAMETERS_EDITS if "InitFieldTrialsFromString(\n" in old)
            pinned = re.search(r'InitFieldTrialsFromString\(\n((?:            "[^"]*"\n)+)        \);', pinned_old)
            self.assertIsNotNone(trials)
            self.assertIsNotNone(pinned)
            self.assertEqual(re.findall(r'"([^"]*)"', trials.group(1)), re.findall(r'"([^"]*)"', pinned.group(1)))
            self.assertIn(".customParameters = (call.vcustom_parameters()\n", tree.read(patch.CALLS_CALL))

    def test_keys(self):
        # The keys the edits read are the server's (pkg/phonecalls/parameters.go
        # of the server repository), each listed in the comment of
        # CALL_PARAMETERS_EDITS with its range, which the reads use.
        keys = set()
        for _, _, new in patch.CALL_PARAMETERS_EDITS:
            keys |= set(re.findall(r'_customParameters, "([a-z0-9_]+)"', new))
        self.assertEqual(keys, set(patch.CALL_PARAMETER_KEYS))
        source = pathlib.Path(patch.__file__).read_text()
        reads = "".join(new for _, _, new in patch.CALL_PARAMETERS_EDITS)
        for key in keys:
            documented = re.search(rf"#   {key} +[^\n]*(?:\n#    +[^\n]*)*", source)
            self.assertIsNotNone(documented, key)
            limits = re.search(rf'_customParameters, "{key}", [^,]+, (\d+), (\d+)\);', reads)
            if key == "audio_ptime_ms":
                # The server's packet times, not every value of 10-120.
                self.assertIn("(10, 20, 40, 60 or 120)", documented.group(0))
                self.assertIn("if (_audioPtimeMs != 10 && _audioPtimeMs != 20 && _audioPtimeMs != 40 "
                              "&& _audioPtimeMs != 120) {\n            _audioPtimeMs = 60;", reads)
            elif limits:
                self.assertIn(f"({limits.group(1)}-{limits.group(2)})", documented.group(0), key)
            else:
                self.assertIn("(true/false)", documented.group(0), key)

    def test_screen_limits(self):
        # The screen capturers of calls, on Windows and Linux and on macOS,
        # follow the limits; nothing else sets the flag, so the previews of the
        # source chooser (desktop_capture_choose_source.cpp) keep their own.
        edited = [(rel, new) for rel, _, new in patch.CALL_PARAMETERS_EDITS if "followsCallLimits = */true" in new]
        self.assertEqual({rel for rel, _ in edited}, {patch.TGCALLS_SCREEN_WINDOWS_LINUX, patch.TGCALLS_SCREEN_MACOS})
        # A clear by a call that is no longer the owner keeps the limits of the
        # call that set them last; the engine sets them once and clears them in
        # its destructor.
        helper = next(new for rel, old, new in patch.CALL_PARAMETERS_EDITS
                      if rel == patch.TGCALLS_SCREEN_HELPER and "ShouldBeDesktopCapture" in old)
        self.assertIn("    if (CallScreenLimitsOwner == call) {\n", helper)
        self.assertIn("    std::lock_guard<std::mutex> lock(CallScreenLimitsMutex);\n", helper)
        destructor = next(new for rel, old, new in patch.CALL_PARAMETERS_EDITS if "~InstanceV2ImplInternal" in old)
        self.assertIn("ClearCallScreenCaptureLimits(this);", destructor)

    def test_upstream_changed(self):
        for i, (rel, old, new) in enumerate(patch.CALL_PARAMETERS_EDITS):
            changed = old[:-2] + "~" + old[-1]
            edits = [e if j != i else (rel, changed, new) for j, e in enumerate(patch.CALL_PARAMETERS_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.call_parameters(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.call_parameters(tree)
            for i, (rel, old, new) in enumerate(patch.CALL_PARAMETERS_EDITS):
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(edit=i), self.assertRaisesRegex(patch.PatchError, "task 077"):
                    patch.verify_call_parameters(tree)
                tree.write(rel, patched)
            patch.verify_call_parameters(tree)

    def test_another_place(self):
        for rel, s, _ in patch.CALL_PARAMETERS_GUARDS:
            with self.subTest(file=rel, text=s), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.call_parameters(tree)
                tree.write(rel, tree.read(rel) + s + "\n")
                with self.assertRaisesRegex(patch.PatchError, "another place sets"):
                    patch.verify_call_parameters(tree)

    def test_lf_only_covers_the_edits(self):
        self.assertEqual(set(patch.call_parameters_edited()), {rel for rel, _, _ in patch.CALL_PARAMETERS_EDITS})
        self.assertEqual({s for s, _ in patch.SUBMODULE_PATHS if s == patch.TGCALLS}, {patch.TGCALLS})
        self.assertEqual({patch.TGCALLS + "/" + p for s, p in patch.SUBMODULE_PATHS if s == patch.TGCALLS},
                         {rel for rel in patch.call_parameters_edited() if rel.startswith(patch.TGCALLS + "/")})


if __name__ == "__main__":
    unittest.main()
