"""Ed25519 (RFC 8032) and the PEM forms of its keys, standard library only:
the build scripts run on systems whose openssl cannot be relied on for it
(LibreSSL on macOS), and the patch takes nothing but the standard library.

The signature is deterministic, so signing needs no randomness. It is not
constant-time, which is acceptable where it runs: a one-shot release job
that signs a package and exits.
"""

import base64
import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_BASE_Y = 4 * pow(5, _P - 2, _P) % _P

# The DER of a public key (SubjectPublicKeyInfo) and of a private key
# (PKCS#8) up to the 32 bytes of the key (RFC 8410).
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


class KeyError_(ValueError):
    pass


def _sha512(data):
    return hashlib.sha512(data).digest()


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


_BASE_X = _recover_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(a, b):
    # Extended coordinates, the unified addition of RFC 8032 5.1.4.
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, point):
    result = _IDENTITY
    while s > 0:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _equal(a, b):
    return ((a[0] * b[2] - b[0] * a[2]) % _P == 0
            and (a[1] * b[2] - b[1] * a[2]) % _P == 0)


def _compress(point):
    zinv = pow(point[2], _P - 2, _P)
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand(seed):
    if len(seed) != 32:
        raise KeyError_("an Ed25519 private key is 32 bytes")
    digest = _sha512(seed)
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed):
    """The 32 bytes of the public key of a 32-byte private key."""
    return _compress(_mul(_expand(seed)[0], _BASE))


def sign(seed, message):
    scalar, prefix = _expand(seed)
    public = _compress(_mul(scalar, _BASE))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    big_r = _compress(_mul(r, _BASE))
    k = int.from_bytes(_sha512(big_r + public + message), "little") % _L
    return big_r + ((r + k * scalar) % _L).to_bytes(32, "little")


def verify(public, message, signature):
    """Whether the signature is good, as OpenSSL's EVP_DigestVerify decides
    it for a canonical signature."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    big_r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or big_r is None or s >= _L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public + message), "little") % _L
    return _equal(_mul(s, _BASE), _add(big_r, _mul(k, a)))


def _pem_body(text, label):
    lines = [l.strip() for l in text.strip().splitlines()]
    if not lines or lines[0] != f"-----BEGIN {label}-----" or lines[-1] != f"-----END {label}-----":
        raise KeyError_(f"expected a PEM of {label}")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise KeyError_("the PEM body is not base64")


def _pem(der, label):
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def parse_public_pem(text):
    """The 32 bytes of an Ed25519 public key in a PEM (SubjectPublicKeyInfo,
    what PEM_read_bio_PUBKEY of the updater reads)."""
    der = _pem_body(text, "PUBLIC KEY")
    if len(der) != len(_SPKI_PREFIX) + 32 or not der.startswith(_SPKI_PREFIX):
        raise KeyError_("not an Ed25519 public key")
    return der[len(_SPKI_PREFIX):]


def parse_private_pem(text):
    """The 32 bytes of an Ed25519 private key in a PEM (PKCS#8)."""
    der = _pem_body(text, "PRIVATE KEY")
    if len(der) != len(_PKCS8_PREFIX) + 32 or not der.startswith(_PKCS8_PREFIX):
        raise KeyError_("not an Ed25519 private key")
    return der[len(_PKCS8_PREFIX):]


def public_pem(public):
    return _pem(_SPKI_PREFIX + public, "PUBLIC KEY")


def private_pem(seed):
    return _pem(_PKCS8_PREFIX + seed, "PRIVATE KEY")
