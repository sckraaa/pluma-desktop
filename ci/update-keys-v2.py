#!/usr/bin/env python3
"""Makes the Ed25519 keys of update packages of format v2, once, and writes
the public files of config/update: the part of ci/update-key.sh that the
standard library does (no openssl of the system does Ed25519 everywhere).

The private keys stay in $PLUMA_UPDATE_KEY_DIR, mode 0600: update-root.pem
and update-release.pem. With them in place the manifest is written again as
it stands; nothing secret is printed.
"""

import base64
import json
import os
import pathlib
import secrets
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ed25519  # noqa: E402

KEY_ID = "pluma-1"


def load_or_make(path):
    if path.exists() and path.stat().st_size:
        return ed25519.parse_private_pem(path.read_text())
    seed = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(ed25519.private_pem(seed))
    print(f"update-keys-v2: a new key in {path}; back it up off-line")
    return seed


def main():
    folder = pathlib.Path(os.environ.get("PLUMA_UPDATE_KEY_DIR") or pathlib.Path.home() / "pluma-secrets/desktop")
    folder.mkdir(parents=True, exist_ok=True)
    root = load_or_make(folder / "update-root.pem")
    release = load_or_make(folder / "update-release.pem")
    x = base64.urlsafe_b64encode(ed25519.public_key(release)).rstrip(b"=").decode()
    manifest = json.dumps({
        "format": 1,
        "manifest_version": 1,
        "issued": int(time.time()),
        "keys": [{"id": KEY_ID, "alg": "Ed25519", "x": x}],
        "channels": {"stable": [[KEY_ID]]},
        "revoked": [],
    }, separators=(",", ":")).encode()
    out = pathlib.Path(__file__).resolve().parent.parent / "config/update"
    out.mkdir(parents=True, exist_ok=True)
    (out / "root-public.pem").write_text(ed25519.public_pem(ed25519.public_key(root)))
    (out / "manifest.min.json").write_bytes(manifest)
    (out / "manifest.sig").write_bytes(ed25519.sign(root, manifest))
    print(f"update-keys-v2: the public root key, the manifest and its signature are in {out}")


if __name__ == "__main__":
    main()
