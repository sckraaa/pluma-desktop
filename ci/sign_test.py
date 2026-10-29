#!/usr/bin/env python3
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci/sign-macos.sh"
ID = "2efe2717-52ef-43a5-96dc-0797e4ca1041"

# Fakes of the macOS tools sign-macos.sh calls. Each logs its arguments to
# $FAKE_LOG; the fakes come first on PATH, so no real keychain is touched.
# notarytool answers as $FAKE_* say: submit prints $FAKE_SUBMIT and exits
# $FAKE_SUBMIT_RC, wait exits $FAKE_WAIT_RC, info reports $FAKE_STATUS.
FAKES = {
    "xcrun": """#!/usr/bin/env bash
echo "xcrun $*" >>"$FAKE_LOG"
case "$1 $2" in
"notarytool submit") echo "$FAKE_SUBMIT"; exit "${FAKE_SUBMIT_RC:-0}" ;;
"notarytool wait") exit "${FAKE_WAIT_RC:-0}" ;;
"notarytool info") printf '{"id":"%s","status":"%s"}\\n' "$3" "$FAKE_STATUS" ;;
"notarytool log") echo '{"issues":[]}' ;;
"stapler "*) ;;
*) exit 1 ;;
esac
""",
    "security": """#!/usr/bin/env bash
echo "security $*" >>"$FAKE_LOG"
if [ "$1" = find-identity ]; then
	echo '  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Test (TEAMID1234)"'
fi
""",
    "codesign": '#!/usr/bin/env bash\necho "codesign $*" >>"$FAKE_LOG"\n',
    "spctl": '#!/usr/bin/env bash\necho "spctl $*" >>"$FAKE_LOG"\n',
    # ditto -x -k ZIP DIR and ditto -c -k --keepParent SRC ZIP, for Linux.
    "ditto": """#!/usr/bin/env bash
echo "ditto $*" >>"$FAKE_LOG"
exec python3 -I -c '
import os, sys, zipfile
a = sys.argv[1:]
if a[:2] == ["-x", "-k"]:
    zipfile.ZipFile(a[2]).extractall(a[3])
elif a[:3] == ["-c", "-k", "--keepParent"]:
    src, parent = a[3].rstrip("/"), os.path.dirname(a[3].rstrip("/"))
    with zipfile.ZipFile(a[4], "w") as z:
        for root, _, files in os.walk(src):
            for f in files:
                p = os.path.join(root, f)
                z.write(p, os.path.relpath(p, parent))
else:
    sys.exit("fake ditto: " + " ".join(a))
' "$@"
""",
}


class SignTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)
        bin_ = self.d / "bin"
        bin_.mkdir()
        for name, text in FAKES.items():
            (bin_ / name).write_text(text)
            (bin_ / name).chmod(0o755)
        self.zip = self.d / "pluma-desktop-1.0-macos.zip"
        with zipfile.ZipFile(self.zip, "w") as z:
            z.writestr("Pluma.app/Contents/Info.plist", "<plist/>")
        self.out = self.d / "out"
        self.log = self.d / "log"
        self.log.touch()
        self.env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(self.log),
                        PLUMA_NOTARY_KEY="key.p8", PLUMA_NOTARY_KEY_ID="KEYID", PLUMA_NOTARY_ISSUER_ID="issuer",
                        PLUMA_DEVELOPER_ID_P12="id.p12", PLUMA_DEVELOPER_ID_PASSWORD="secret",
                        GITHUB_ACTIONS="true")

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args, **fake):
        env = dict(self.env, **{f"FAKE_{k.upper()}": str(v) for k, v in fake.items()})
        return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)

    def calls(self):
        return self.log.read_text().splitlines()

    def assert_delivered(self, *names):
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), sorted(names))
        sha = (self.out / f"{self.zip.name}.sha256").read_text()
        self.assertRegex(sha, rf"^[0-9a-f]{{64}}  {re.escape(self.zip.name)}\n$")
        with zipfile.ZipFile(self.out / self.zip.name) as z:
            self.assertEqual(z.namelist(), ["Pluma.app/Contents/Info.plist"])

    def test_sign_accepted(self):
        run = self.run_script("sign", str(self.zip), str(self.out),
                              submit=json.dumps({"id": ID, "status": "Accepted"}))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("notarized", run.stdout)
        self.assert_delivered(self.zip.name, f"{self.zip.name}.sha256")
        calls = self.calls()
        self.assertTrue(any(c.startswith("codesign --force --deep --timestamp --options runtime") for c in calls))
        self.assertIn("xcrun stapler staple", "\n".join(calls))

    def test_sign_outlasted(self):
        # notarytool stops waiting with 124, and Apple keeps checking.
        run = self.run_script("sign", str(self.zip), str(self.out), submit_rc=124,
                              submit=json.dumps({"id": ID, "message": "Timeout of 1800 second(s) was reached"}))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"still checking submission {ID}", run.stdout)
        self.assert_delivered(self.zip.name, f"{self.zip.name}.sha256", f"{self.zip.name}.notary-id")
        self.assertEqual((self.out / f"{self.zip.name}.notary-id").read_text(), ID + "\n")
        self.assertNotIn("stapler", "\n".join(self.calls()))

    def test_sign_rejected(self):
        run = self.run_script("sign", str(self.zip), str(self.out),
                              submit=json.dumps({"id": ID, "status": "Invalid"}))
        self.assertEqual(run.returncode, 1)
        self.assertIn("notarization: Invalid", run.stderr)
        self.assertIn(f"xcrun notarytool log {ID}", "\n".join(self.calls()))
        self.assertFalse(self.out.exists())

    def test_sign_on_a_runner_only(self):
        self.env["GITHUB_ACTIONS"] = ""
        run = self.run_script("sign", str(self.zip), str(self.out))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_staple_accepted(self):
        run = self.run_script("staple", str(self.zip), ID, str(self.out), status="Accepted")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_delivered(self.zip.name, f"{self.zip.name}.sha256")
        calls = "\n".join(self.calls())
        self.assertIn("xcrun stapler staple", calls)
        self.assertNotIn("codesign", calls)
        self.assertNotIn("security", calls)

    def test_staple_still_checking(self):
        run = self.run_script("staple", str(self.zip), ID, str(self.out), wait_rc=124, status="In Progress")
        self.assertEqual(run.returncode, 75)
        self.assertIn("run it again later", run.stderr)
        self.assertFalse(self.out.exists())

    def test_staple_rejected(self):
        run = self.run_script("staple", str(self.zip), ID, str(self.out), status="Invalid")
        self.assertEqual(run.returncode, 1)
        self.assertIn(f"xcrun notarytool log {ID}", "\n".join(self.calls()))
        self.assertFalse(self.out.exists())

    def test_staple_needs_no_developer_id(self):
        del self.env["PLUMA_DEVELOPER_ID_P12"], self.env["PLUMA_DEVELOPER_ID_PASSWORD"], self.env["GITHUB_ACTIONS"]
        run = self.run_script("staple", str(self.zip), ID, str(self.out), status="Accepted")
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_staple_checks_the_id(self):
        run = self.run_script("staple", str(self.zip), "not-an-id", str(self.out))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
