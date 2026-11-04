#!/usr/bin/env python3
"""Packs an update package of the desktop app, in the format of tdesktop's
updater (task 054 of the server repository).

    pack_update.py --os windows|macos|linux --version <AppVersion>
                   --key <private.pem> --public-key <config/update_public.pem>
                   --out <file> <path>...

The format is Packer's (Telegram/SourceFiles/_other/packer.cpp 240-470 at
a1e89e1f), which the app reads back in UnpackUpdate (core/update_checker.cpp
327-560):

  - a QDataStream (Qt_5_1, big-endian) of quint32 version, quint32 files and,
    per file, its QString name, quint32 size, QByteArray data and, except on
    Windows, bool executable;
  - compressed: on Windows raw LZMA with LzmaCompress's settings (level 9,
    64 MB dictionary, lc 4, lp 0, pb 2, fast bytes 273) and its 5 bytes of
    properties, elsewhere xz (preset 9 extreme, CRC64);
  - after a header of an RSA signature (128 bytes: the key is 1024 bits), the
    SHA-1 of what follows the SHA-1, the properties (Windows), and the
    uncompressed size (int32, little-endian);
  - the signature is RSA_sign(NID_sha1) of that SHA-1, PKCS #1 v1.5, which
    `openssl dgst -sha1 -sign` makes.

The names are the paths relative to the folder of the first path, as Packer
takes them; a folder brings its files, hidden files and symbolic links left
out as Packer leaves them. Pluma packs the binary under upstream's name
(Telegram.exe, Telegram): the Updater renames it to the installed one.

Before it writes the file, the package is read back as the app reads it and
its signature checked with the public key the app carries.
"""

import argparse
import hashlib
import lzma
import os
import pathlib
import stat
import struct
import subprocess
import sys
import tempfile

SIGNATURE_LEN = 128
SHA1_LEN = 20
# LzmaCompress(..., level 9, dictSize 64 MB, lc 4, lp 0, pb 2, fb 273, 2)
# in packer.cpp 297; its properties are lc + 9 * (lp + 5 * pb) and the
# dictionary size, little-endian (LzmaEnc.c, LzmaEnc_WriteProperties).
LZMA_DICT = 64 << 20
LZMA_LC, LZMA_LP, LZMA_PB, LZMA_NICE = 4, 0, 2, 273
LZMA_PROPS = bytes([LZMA_LC + 9 * (LZMA_LP + 5 * LZMA_PB)]) + struct.pack("<I", LZMA_DICT)
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "dict_size": LZMA_DICT, "lc": LZMA_LC, "lp": LZMA_LP,
                 "pb": LZMA_PB, "nice_len": LZMA_NICE, "mode": lzma.MODE_NORMAL}]
# The version is Pluma's build number, which its updater compares
# (PlumaBuild); 0x7FFFFFFF marks an alpha package, which Pluma does not make.
MIN_VERSION, MAX_VERSION = 1, 999999999
MAX_SIZE = 1 << 30  # the largest uncompressed size the app takes


class PackError(Exception):
    pass


def collect(paths):
    """The files to pack as (name, path), names relative to the folder of
    the first path."""
    if not paths:
        raise PackError("no path to pack")
    root = pathlib.Path(paths[0]).resolve().parent
    out = []

    def add(p):
        if p.name.startswith(".") or p.is_symlink():
            return
        if p.is_dir():
            for child in sorted(p.iterdir()):
                add(child)
        elif p.is_file():
            out.append((p.resolve().relative_to(root).as_posix(), p))
        else:
            raise PackError(f"{p}: not a file or a folder")

    for path in paths:
        p = pathlib.Path(path)
        if not p.exists():
            raise PackError(f"{p}: missing")
        if p.resolve().parent != root and root not in p.resolve().parents:
            raise PackError(f"{p}: not in {root}, the folder of the first path")
        add(p)
    if not out:
        raise PackError("no file to pack")
    names = [n for n, _ in out]
    if len(set(names)) != len(names):
        raise PackError("a file named twice")
    return out


def qstring(s):
    data = s.encode("utf-16-be")
    return struct.pack(">I", len(data)) + data


def qbytes(b):
    return struct.pack(">I", len(b)) + b


def serialize(files, version, windows):
    out = [struct.pack(">II", version, len(files))]
    for name, path in files:
        data = path.read_bytes()
        out.append(qstring(name) + struct.pack(">I", len(data)) + qbytes(data))
        if not windows:
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            out.append(b"\x01" if executable else b"\x00")
    return b"".join(out)


def compress(data, windows):
    if windows:
        return LZMA_PROPS, lzma.compress(data, format=lzma.FORMAT_RAW, filters=LZMA_FILTERS)
    return b"", lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=9 | lzma.PRESET_EXTREME)


def openssl(*args, stdin=None):
    r = subprocess.run(["openssl", *args], input=stdin, capture_output=True)
    if r.returncode != 0:
        raise PackError(f"openssl {args[0]}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def sign(digest_input, key):
    """RSA_sign(NID_sha1) over SHA-1(digest_input): PKCS #1 v1.5."""
    signature = openssl("dgst", "-sha1", "-sign", str(key), stdin=digest_input)
    if len(signature) != SIGNATURE_LEN:
        raise PackError(f"the signature is {len(signature)} bytes; the key must be RSA, 1024 bits")
    return signature


def pack(paths, version, os_name, key):
    if os_name not in ("windows", "macos", "linux"):
        raise PackError(f"--os {os_name!r}: windows, macos or linux")
    if not MIN_VERSION <= version <= MAX_VERSION:
        raise PackError(f"version {version}: {MIN_VERSION} to {MAX_VERSION}")
    windows = os_name == "windows"
    body = serialize(collect(paths), version, windows)
    if len(body) > MAX_SIZE:
        raise PackError(f"{len(body)} bytes uncompressed; the app takes at most {MAX_SIZE}")
    props, compressed = compress(body, windows)
    signed = props + struct.pack("<i", len(body)) + compressed
    return sign(signed, key) + hashlib.sha1(signed).digest() + signed


def read_back(package, os_name, public_key):
    """Reads a package as UnpackUpdate does and returns (version, files),
    files as (name, data, executable)."""
    windows = os_name == "windows"
    props_len = len(LZMA_PROPS) if windows else 0
    header = SIGNATURE_LEN + SHA1_LEN + props_len + 4
    if len(package) <= header:
        raise PackError("the package is shorter than its header")
    signature, sha1, signed = package[:SIGNATURE_LEN], package[SIGNATURE_LEN:SIGNATURE_LEN + SHA1_LEN], package[SIGNATURE_LEN + SHA1_LEN:]
    if hashlib.sha1(signed).digest() != sha1:
        raise PackError("the SHA-1 does not match")
    with tempfile.TemporaryDirectory() as d:
        spki = pathlib.Path(d) / "public.pem"
        openssl("rsa", "-RSAPublicKey_in", "-in", str(public_key), "-pubout", "-out", str(spki))
        sig = pathlib.Path(d) / "signature"
        sig.write_bytes(signature)
        r = subprocess.run(["openssl", "dgst", "-sha1", "-verify", str(spki), "-signature", str(sig)],
                           input=signed, capture_output=True)
        if r.returncode != 0:
            raise PackError("the signature does not verify with the public key")
    props = signed[:props_len]
    (size,) = struct.unpack("<i", signed[props_len:props_len + 4])
    compressed = signed[props_len + 4:]
    if not 0 < size <= MAX_SIZE:
        raise PackError(f"uncompressed size {size}")
    if windows:
        if props != LZMA_PROPS:
            raise PackError("LZMA properties")
        body = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=LZMA_FILTERS).decompress(compressed, size)
    else:
        body = lzma.decompress(compressed, format=lzma.FORMAT_XZ)
    if len(body) != size:
        raise PackError(f"{len(body)} bytes uncompressed, the header says {size}")

    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(body):
            raise PackError("the stream ends early")
        pos += n
        return body[pos - n:pos]

    version, count = struct.unpack(">II", take(8))
    if version == 0x7FFFFFFF or not count:
        raise PackError("an alpha package or no files")
    files = []
    for _ in range(count):
        (name_len,) = struct.unpack(">I", take(4))
        name = take(name_len).decode("utf-16-be")
        (size_field,) = struct.unpack(">I", take(4))
        (data_len,) = struct.unpack(">I", take(4))
        data = take(data_len)
        if size_field != data_len:
            raise PackError(f"{name}: size {size_field}, data {data_len}")
        executable = False
        if not windows:
            executable = take(1) != b"\x00"
        files.append((name, data, executable))
    if pos != len(body):
        raise PackError("bytes after the last file")
    return version, files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--os", required=True, choices=("windows", "macos", "linux"))
    ap.add_argument("--version", required=True, type=int, help="the build number, which the updater compares")
    ap.add_argument("--key", required=True, help="the private key, PEM")
    ap.add_argument("--public-key", required=True, help="the public key the app carries, PKCS#1 PEM")
    ap.add_argument("--out", required=True)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    try:
        package = pack(a.paths, a.version, a.os, a.key)
        version, files = read_back(package, a.os, a.public_key)
        if version != a.version:
            raise PackError(f"read back version {version}")
        out = pathlib.Path(a.out)
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_bytes(package)
        os.replace(tmp, out)
    except (PackError, OSError, lzma.LZMAError) as e:
        print(f"pack_update: {e}", file=sys.stderr)
        return 1
    print(f"pack_update: {out} ({len(package)} bytes), {a.os} {version}, {len(files)} files: "
          + ", ".join(n + ("*" if x else "") for n, _, x in files[:6]) + (" ..." if len(files) > 6 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
