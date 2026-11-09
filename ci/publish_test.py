#!/usr/bin/env python3
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

import ed25519
from pack_update_test import keypair, update_keys_dir

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci/publish.sh"
VERSION = next(line.split("=", 1)[1] for line in (ROOT / "upstream.env").read_text().splitlines()
               if line.startswith("UPSTREAM_VERSION="))

# Fakes of the macOS tools and of curl that publish.sh calls, each logging
# its arguments to $FAKE_LOG. The "DMG" is a tar, as sign_test.py's fake
# dmgbuild makes it; hdiutil unpacks it at the mount point. stapler validate
# fails when $FAKE_UNSTAPLED is set; curl records the form and answers 200.
FAKES = {
    "hdiutil": """#!/usr/bin/env bash
echo "hdiutil $*" >>"$FAKE_LOG"
case $1 in
attach) mnt= ; while [ $# -gt 1 ]; do [ "$1" = -mountpoint ] && mnt=$2; shift; done; tar -C "$mnt" -xf "$1" ;;
detach) find "$2" -mindepth 1 -delete ;;
*) exit 1 ;;
esac
""",
    "ditto": '#!/usr/bin/env bash\necho "ditto $*" >>"$FAKE_LOG"\ncp -R "$1" "$2"\n',
    "codesign": '#!/usr/bin/env bash\necho "codesign $*" >>"$FAKE_LOG"\n',
    "xcrun": """#!/usr/bin/env bash
echo "xcrun $*" >>"$FAKE_LOG"
[ "$1 $2" = "stapler validate" ] && [ -n "${FAKE_UNSTAPLED:-}" ] && exit 65
exit 0
""",
    "curl": """#!/usr/bin/env bash
echo "curl $*" >>"$FAKE_LOG"
printf 200
""",
}


class PublishMacosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.key, cls.public = keypair(pathlib.Path(cls.keys.name))
        cls.update_keys, cls.release_seed = update_keys_dir(pathlib.Path(cls.keys.name) / "v2")
        cls.release_pem = pathlib.Path(cls.keys.name) / "release.pem"
        cls.release_pem.write_text(ed25519.private_pem(cls.release_seed))

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)
        bin_ = self.d / "bin"
        bin_.mkdir()
        for name, text in FAKES.items():
            (bin_ / name).write_text(text)
            (bin_ / name).chmod(0o755)
        stage = self.d / "stage"
        (stage / "Pluma.app/Contents/MacOS").mkdir(parents=True)
        (stage / "Pluma.app/Contents/MacOS/Telegram").write_text("binary")
        (stage / "Applications").symlink_to("/Applications")
        self.dmg = self.d / f"pluma-desktop-{VERSION}-macos.dmg"
        with tarfile.open(self.dmg, "w") as t:
            t.add(stage, arcname=".")
        self.log = self.d / "log"
        self.log.touch()
        self.env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(self.log),
                        BUILD_NUMBER="41", PLUMA_UPDATE_KEY_FILE=str(self.key),
                        PLUMA_UPDATE_PUBLIC_KEY=str(self.public), RELEASES_UPLOAD_TOKEN="token",
                        PLUMA_RELEASES_URL="https://pluma.example", RUNNER_TEMP=str(self.d))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, installer, **fake):
        env = dict(self.env, **{f"FAKE_{k.upper()}": str(v) for k, v in fake.items()})
        return subprocess.run(["bash", str(SCRIPT), "macos", str(installer)], env=env, capture_output=True, text=True)

    def calls(self):
        return self.log.read_text().splitlines()

    def test_dmg(self):
        # The site gets the DMG itself, the updater a package of the app
        # inside it.
        run = self.run_script(self.dmg)
        self.assertEqual(run.returncode, 0, run.stderr)
        calls = self.calls()
        curl = next(c for c in calls if c.startswith("curl "))
        self.assertIn(f"installer.universal=@{self.dmg};filename=Pluma-{VERSION}.00041-macos-universal.dmg", curl)
        self.assertIn("update.universal=@", curl)
        self.assertIn(";filename=tmacupd41", curl)
        self.assertIn(f"xcrun stapler validate {self.dmg}", calls)
        attach = next(i for i, c in enumerate(calls) if c.startswith("hdiutil attach -readonly"))
        detach = next(i for i, c in enumerate(calls) if c.startswith("hdiutil detach"))
        self.assertLess(attach, detach)
        self.assertLess(detach, calls.index(curl))

    def test_format_v2(self):
        run = subprocess.run(["bash", str(SCRIPT), "macos", str(self.dmg)],
                             env=dict(self.env, PLUMA_UPDATE_FORMAT="v2", PLUMA_UPDATE_KEY_FILE="",
                                      PLUMA_UPDATE_KEY_V2_FILE=str(self.release_pem),
                                      PLUMA_UPDATE_KEYS=str(self.update_keys)),
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        curl = next(c for c in self.calls() if c.startswith("curl "))
        self.assertIn(";filename=tmacupd41", curl)

    def test_update_format(self):
        run = subprocess.run(["bash", str(SCRIPT), "macos", str(self.dmg)],
                             env=dict(self.env, PLUMA_UPDATE_FORMAT="v3"), capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertIn("is v3", run.stderr)
        self.assertIn((ROOT / "release/update-format").read_text().strip(), ("v1", "v2"))

    def test_not_stapled(self):
        run = self.run_script(self.dmg, unstapled=1)
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(any(c.startswith(("curl", "hdiutil attach")) for c in self.calls()))

    def test_zip_refused(self):
        z = self.d / f"pluma-desktop-{VERSION}-macos.zip"
        z.write_text("zip")
        run = self.run_script(z)
        self.assertEqual(run.returncode, 2)
        self.assertIn("is the DMG", run.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
