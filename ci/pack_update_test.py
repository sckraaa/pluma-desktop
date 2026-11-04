#!/usr/bin/env python3
import hashlib
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import pack_update  # noqa: E402


def keypair(d, bits=1024):
    """A throwaway key: the private PEM and the public PKCS#1 PEM."""
    key, public = d / f"key{bits}.pem", d / f"public{bits}.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), str(bits)], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(key), "-RSAPublicKey_out", "-out", str(public)],
                   check=True, capture_output=True)
    return key, public


class PackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.dir.name)
        cls.key, cls.public = keypair(cls.root)
        cls.other_key, cls.other_public = keypair(pathlib.Path(tempfile.mkdtemp(dir=cls.dir.name)))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def files(self, name):
        d = pathlib.Path(tempfile.mkdtemp(dir=self.dir.name)) / name
        d.mkdir()
        return d

    def test_linux(self):
        d = self.files("linux")
        (d / "Telegram").write_bytes(b"\x7fELF binary")
        (d / "Updater").write_bytes(b"\x7fELF updater")
        os.chmod(d / "Telegram", 0o755)
        os.chmod(d / "Updater", 0o755)
        package = pack_update.pack([d / "Telegram", d / "Updater"], 7000066, "linux", self.key)
        version, files = pack_update.read_back(package, "linux", self.public)
        self.assertEqual(version, 7000066)
        self.assertEqual(files, [("Telegram", b"\x7fELF binary", True), ("Updater", b"\x7fELF updater", True)])
        # The header: signature, the SHA-1 of the rest, the size, xz.
        signed = package[148:]
        self.assertEqual(package[128:148], hashlib.sha1(signed).digest())
        self.assertEqual(signed[4:10], b"\xfd7zXZ\x00")
        # The stream, as Packer writes it: version, count, the first name.
        body = pack_update.lzma.decompress(signed[4:])
        self.assertEqual(struct.unpack("<i", signed[:4])[0], len(body))
        self.assertEqual(body[:8], struct.pack(">II", 7000066, 2))
        self.assertEqual(body[8:12 + 16], struct.pack(">I", 16) + "Telegram".encode("utf-16-be"))

    def test_windows(self):
        d = self.files("windows")
        (d / "Telegram.exe").write_bytes(b"MZ app" * 1000)
        (d / "Updater.exe").write_bytes(b"MZ updater")
        package = pack_update.pack([d / "Telegram.exe", d / "Updater.exe"], 7000066, "windows", self.key)
        # The LZMA properties of LzmaCompress(level 9, 64 MB, lc 4, lp 0, pb 2).
        self.assertEqual(package[148:153], bytes([0x5E, 0, 0, 0, 4]))
        version, files = pack_update.read_back(package, "windows", self.public)
        self.assertEqual(files, [("Telegram.exe", b"MZ app" * 1000, False), ("Updater.exe", b"MZ updater", False)])

    def test_macos_bundle(self):
        d = self.files("mac")
        app = d / "Pluma.app"
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Frameworks").mkdir()
        (app / "Contents/MacOS/Telegram").write_bytes(b"macho")
        os.chmod(app / "Contents/MacOS/Telegram", 0o755)
        (app / "Contents/Frameworks/Updater").write_bytes(b"updater")
        os.chmod(app / "Contents/Frameworks/Updater", 0o755)
        (app / "Contents/Info.plist").write_bytes(b"<plist/>")
        (app / "Contents/.DS_Store").write_bytes(b"x")
        os.symlink("Info.plist", app / "Contents/link")
        package = pack_update.pack([app], 7000066, "macos", self.key)
        _, files = pack_update.read_back(package, "macos", self.public)
        self.assertEqual(sorted((n, x) for n, _, x in files), [
            ("Pluma.app/Contents/Frameworks/Updater", True),
            ("Pluma.app/Contents/Info.plist", False),
            ("Pluma.app/Contents/MacOS/Telegram", True),
        ])

    def test_another_key(self):
        d = self.files("key")
        (d / "Telegram").write_bytes(b"x")
        package = pack_update.pack([d / "Telegram"], 7000066, "linux", self.key)
        with self.assertRaisesRegex(pack_update.PackError, "signature"):
            pack_update.read_back(package, "linux", self.other_public)
        broken = bytearray(package)
        broken[-1] ^= 1
        with self.assertRaisesRegex(pack_update.PackError, "SHA-1"):
            pack_update.read_back(bytes(broken), "linux", self.public)

    def test_rejects(self):
        d = self.files("rejects")
        (d / "Telegram").write_bytes(b"x")
        with self.assertRaisesRegex(pack_update.PackError, "version"):
            pack_update.pack([d / "Telegram"], 0, "linux", self.key)
        with self.assertRaisesRegex(pack_update.PackError, "missing"):
            pack_update.pack([d / "Updater"], 7000066, "linux", self.key)
        with self.assertRaisesRegex(pack_update.PackError, "1024 bits"):
            big, _ = keypair(pathlib.Path(tempfile.mkdtemp(dir=self.dir.name)), 2048)
            pack_update.pack([d / "Telegram"], 7000066, "linux", big)

    def test_main(self):
        d = self.files("main")
        (d / "Telegram").write_bytes(b"x")
        out = d.parent / "tlinuxupd7000066"
        self.assertEqual(pack_update.main(["--os", "linux", "--version", "7000066", "--key", str(self.key),
                                           "--public-key", str(self.public), "--out", str(out), str(d / "Telegram")]), 0)
        self.assertEqual(pack_update.read_back(out.read_bytes(), "linux", self.public)[0], 7000066)
        self.assertEqual(pack_update.main(["--os", "linux", "--version", "7000066", "--key", str(self.key),
                                           "--public-key", str(self.other_public), "--out", str(out) + "x",
                                           str(d / "Telegram")]), 1)
        self.assertFalse(pathlib.Path(str(out) + "x").exists())


if __name__ == "__main__":
    unittest.main()
