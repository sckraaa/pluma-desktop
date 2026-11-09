#!/usr/bin/env python3
"""Packs an update package of the desktop app, in the format of tdesktop's
updater (tasks 054 and 074 of the server repository).

    pack_update.py --format v2 --os windows|macos|linux --version <build>
                   --key <release key, Ed25519> --update-keys <config/update>
                   --out <file> <path>...
    pack_update.py --format v1 --os windows|macos|linux --version <build>
                   --key <RSA key> --public-key <config/update_public.pem>
                   --out <file> <path>...

The body is the same in both, Packer's (Telegram/SourceFiles/_other/packer.cpp
240-470 at a1e89e1f):

  - a QDataStream (Qt_5_1, big-endian) of quint32 version, quint32 files and,
    per file, its QString name, quint32 size, QByteArray data and, except on
    Windows, bool executable;
  - compressed: on Windows raw LZMA with LzmaCompress's settings (level 9,
    64 MB dictionary, lc 4, lp 0, pb 2, fast bytes 273) and its 5 bytes of
    properties, elsewhere xz (preset 9 extreme, CRC64), with the uncompressed
    size (int32, little-endian).

Format v1 is what the apps up to tdesktop 7.0.9 read (UnpackUpdate,
core/update_checker.cpp 327-560 at a1e89e1f): an RSA signature (128 bytes: the
key is 1024 bits), the SHA-1 of what follows the SHA-1, then the above; the
signature is RSA_sign(NID_sha1) of that SHA-1, PKCS #1 v1.5, which
`openssl dgst -sha1 -sign` makes. Only the one release that carries the
installed apps to the new updater is packed so: release/update-format.

Format v2 is what the apps from tdesktop 7.4.1 read (core/update_verify.cpp,
ParseEnvelope and VerifyUpdate at 157f5cfc): little-endian, "TDUP", uint32 2,
uint8 channel (0, stable), uint8 os, uint8 arch, uint64 version
(<build> << 32), uint64 created, uint32 manifest size, the manifest; then the
signed region's end, uint32 size and the root signature of the manifest,
uint32 count and, per signature, uint32 size and key id, uint32 size and the
signature; uint32 payload size and the payload, which is the body above.
A signature is Ed25519 over the signed region and the SHA-256 of the payload.
The one release key signs, named in the manifest of config/update.

The names are the paths relative to the folder of the first path, as Packer
takes them; a folder brings its files, hidden files and symbolic links left
out as Packer leaves them. Pluma packs the binary under upstream's name
(Telegram.exe, Telegram): the Updater renames it to the installed one.

Before it writes the file, the package is read back as the app reads it and
its signature checked with the public key the app carries.
"""

import argparse
import base64
import hashlib
import json
import lzma
import os
import pathlib
import stat
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ed25519  # noqa: E402

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
MAX_PAYLOAD = 256 << 20  # the largest payload of a v2 package the app takes

ENVELOPE_MAGIC, ENVELOPE_FORMAT, CHANNEL_STABLE = b"TDUP", 2, 0
# Os and Arch of core/update_verify.h. Pluma's macOS package is one universal
# app: it is built for mac, and the patch lets armac take it.
ENVELOPE_TARGET = {"windows": (0, 1), "macos": (1, 1), "linux": (2, 1)}
UPDATE_KEY_FILES = ("root-public.pem", "manifest.min.json", "manifest.sig")


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


def payload_of(paths, version, os_name):
    """The compressed body with its header (the properties on Windows, the
    uncompressed size): what follows the signatures of a package."""
    if os_name not in ("windows", "macos", "linux"):
        raise PackError(f"--os {os_name!r}: windows, macos or linux")
    if not MIN_VERSION <= version <= MAX_VERSION:
        raise PackError(f"version {version}: {MIN_VERSION} to {MAX_VERSION}")
    windows = os_name == "windows"
    body = serialize(collect(paths), version, windows)
    if len(body) > MAX_SIZE:
        raise PackError(f"{len(body)} bytes uncompressed; the app takes at most {MAX_SIZE}")
    props, compressed = compress(body, windows)
    return props + struct.pack("<i", len(body)) + compressed


def pack(paths, version, os_name, key):
    """A package of format v1."""
    signed = payload_of(paths, version, os_name)
    return sign(signed, key) + hashlib.sha1(signed).digest() + signed


def read_update_keys(folder):
    """The root public key, the manifest and its signature in a folder."""
    out = []
    for name in UPDATE_KEY_FILES:
        try:
            out.append((pathlib.Path(folder) / name).read_bytes())
        except OSError as e:
            raise PackError(f"{folder}/{name}: {e.strerror}")
    return tuple(out)


def release_key_id(manifest, seed):
    """The id under which the manifest names this release key for stable."""
    x = base64.urlsafe_b64encode(ed25519.public_key(seed)).rstrip(b"=").decode()
    data = json.loads(manifest)
    stable = [i for group in data["channels"]["stable"] for i in group]
    for key in data["keys"]:
        if key["alg"] == "Ed25519" and key["x"] == x and key["id"] in stable and key["id"] not in data["revoked"]:
            return key["id"].encode("ascii")
    raise PackError("the key does not sign for the channel stable in the manifest")


def envelope_signed_region(os_name, version, created, manifest):
    os_code, arch = ENVELOPE_TARGET[os_name]
    return (ENVELOPE_MAGIC + struct.pack("<IBBBQQI", ENVELOPE_FORMAT, CHANNEL_STABLE, os_code, arch,
                                         version << 32, created, len(manifest)) + manifest)


def pack_v2(paths, version, os_name, seed, manifest, manifest_signature, created=None):
    """A package of format v2."""
    payload = payload_of(paths, version, os_name)
    if len(payload) > MAX_PAYLOAD:
        raise PackError(f"{len(payload)} bytes; the app takes a payload of at most {MAX_PAYLOAD}")
    region = envelope_signed_region(os_name, version, int(time.time()) if created is None else created, manifest)
    key_id = release_key_id(manifest, seed)
    signature = ed25519.sign(seed, region + hashlib.sha256(payload).digest())
    return (region + struct.pack("<I", len(manifest_signature)) + manifest_signature
            + struct.pack("<II", 1, len(key_id)) + key_id
            + struct.pack("<I", len(signature)) + signature
            + struct.pack("<I", len(payload)) + payload)


def read_back_v2(package, os_name, root, manifest, manifest_signature):
    """Reads a package as VerifyUpdate and the rest of UnpackUpdateV2 do and
    returns (version, files)."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(package):
            raise PackError("the envelope ends early")
        pos += n
        return package[pos - n:pos]

    def u32():
        return struct.unpack("<I", take(4))[0]

    if take(4) != ENVELOPE_MAGIC or u32() != ENVELOPE_FORMAT:
        raise PackError("not an envelope of format 2")
    channel, os_code, arch = take(1)[0], take(1)[0], take(1)[0]
    if channel != CHANNEL_STABLE or (os_code, arch) != ENVELOPE_TARGET[os_name]:
        raise PackError("the envelope's channel or target")
    (full_version, created) = struct.unpack("<QQ", take(16))
    size = u32()
    carried = take(size)
    region = package[:pos]
    if carried != manifest:
        raise PackError("the envelope's manifest is not the one of the app")
    signature = take(u32())
    if signature != manifest_signature:
        raise PackError("the manifest's signature")
    try:
        root_key = ed25519.parse_public_pem(root.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as e:
        raise PackError(f"the root key: {e}")
    if not ed25519.verify(root_key, carried, signature):
        raise PackError("the manifest's signature does not verify with the root key")
    count = u32()
    if count != 1:
        raise PackError(f"{count} signatures")
    key_id = take(u32())
    signature = take(u32())
    payload = take(u32())
    if pos != len(package):
        raise PackError("bytes after the payload")
    if not 0 < created:
        raise PackError("the envelope's time")
    if len(payload) > MAX_PAYLOAD:
        raise PackError("the payload is too large")
    data = json.loads(carried)
    keys = {k["id"]: k for k in data["keys"]}
    groups = data["channels"]["stable"]
    name = key_id.decode("ascii")
    if len(groups) != 1 or name not in groups[0] or name in data["revoked"] or name not in keys:
        raise PackError("the signature's key is not the stable channel's")
    x = base64.urlsafe_b64decode(keys[name]["x"] + "=" * (-len(keys[name]["x"]) % 4))
    if not ed25519.verify(x, region + hashlib.sha256(payload).digest(), signature):
        raise PackError("the signature does not verify with the manifest's key")
    version, files = read_body(payload, os_name)
    if full_version != version << 32:
        raise PackError(f"the envelope's version {full_version:#x}, the body's {version}")
    return version, files


def read_back(package, os_name, public_key):
    """Reads a package of format v1 as UnpackUpdate does and returns
    (version, files), files as (name, data, executable)."""
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
    return read_body(signed, os_name)


def read_body(signed, os_name):
    """(version, files) of the compressed body with its header."""
    windows = os_name == "windows"
    props_len = len(LZMA_PROPS) if windows else 0
    if len(signed) <= props_len + 4:
        raise PackError("the package is shorter than its header")
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
    ap.add_argument("--format", choices=("v1", "v2"), default="v2", help="the package's format (release/update-format)")
    ap.add_argument("--version", required=True, type=int, help="the build number, which the updater compares")
    ap.add_argument("--key", required=True, help="the private key, PEM (v2: Ed25519 PKCS#8; v1: RSA)")
    ap.add_argument("--public-key", help="v1: the public key the app carries, PKCS#1 PEM")
    ap.add_argument("--update-keys", help="v2: the folder of the root key and manifest (config/update)")
    ap.add_argument("--out", required=True)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    try:
        if a.format == "v2":
            if not a.update_keys:
                raise PackError("--update-keys is needed for format v2")
            root, manifest, manifest_signature = read_update_keys(a.update_keys)
            try:
                seed = ed25519.parse_private_pem(pathlib.Path(a.key).read_text())
            except (ValueError, OSError) as e:
                raise PackError(f"the release key: {e}")
            package = pack_v2(a.paths, a.version, a.os, seed, manifest, manifest_signature)
            version, files = read_back_v2(package, a.os, root, manifest, manifest_signature)
        else:
            if not a.public_key:
                raise PackError("--public-key is needed for format v1")
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
