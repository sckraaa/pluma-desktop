#!/usr/bin/env python3
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import ed25519  # noqa: E402

# RFC 8032, section 7.1, tests 1 and 2.
VECTORS = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
)


class Ed25519Test(unittest.TestCase):
    def test_vectors(self):
        for seed, public, message, signature in VECTORS:
            seed, public, message, signature = (bytes.fromhex(x) for x in (seed, public, message, signature))
            self.assertEqual(ed25519.public_key(seed), public)
            self.assertEqual(ed25519.sign(seed, message), signature)
            self.assertTrue(ed25519.verify(public, message, signature))
            self.assertFalse(ed25519.verify(public, message + b"x", signature))
            broken = bytearray(signature)
            broken[0] ^= 1
            self.assertFalse(ed25519.verify(public, message, bytes(broken)))

    def test_pem_round_trip(self):
        seed = bytes(range(32))
        public = ed25519.public_key(seed)
        self.assertEqual(ed25519.parse_private_pem(ed25519.private_pem(seed)), seed)
        self.assertEqual(ed25519.parse_public_pem(ed25519.public_pem(public)), public)
        for bad in ("nothing", ed25519.private_pem(seed), ed25519.public_pem(public).replace("PUBLIC KEY", "RSA PUBLIC KEY")):
            with self.assertRaises(ValueError):
                ed25519.parse_public_pem(bad)
        with self.assertRaises(ValueError):
            ed25519.parse_private_pem(ed25519.public_pem(public))


if __name__ == "__main__":
    unittest.main()
