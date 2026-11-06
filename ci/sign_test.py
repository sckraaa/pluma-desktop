#!/usr/bin/env python3
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci/sign-macos.sh"
ID = "2efe2717-52ef-43a5-96dc-0797e4ca1041"

# Fakes of the macOS tools sign-macos.sh calls. Each logs its arguments to
# $FAKE_LOG; the fakes come first on PATH, so no real keychain is touched.
# notarytool answers as $FAKE_* say: submit uploads as $FAKE_ID unless
# $FAKE_UPLOAD_FAILS, wait stops early when $FAKE_WAIT_RC is 124, info
# reports $FAKE_STATUS unless $FAKE_INFO_FAILS. The fake dmgbuild makes the
# "DMG" a tar of the app and the link to /Applications, which the fake
# hdiutil unpacks at the mount point, so make-dmg.sh's checks run on Linux.
FAKES = {
    "dmgbuild": """#!/usr/bin/env bash
echo "dmgbuild $*" >>"$FAKE_LOG"
app= dmg=${@: -1}
for a in "$@"; do case $a in app=*) app=${a#app=} ;; esac; done
stage=$(mktemp -d)
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
tar -C "$stage" -cf "$dmg" .
rm -rf "$stage"
""",
    "hdiutil": """#!/usr/bin/env bash
echo "hdiutil $*" >>"$FAKE_LOG"
case $1 in
attach) mnt= ; while [ $# -gt 1 ]; do [ "$1" = -mountpoint ] && mnt=$2; shift; done; tar -C "$mnt" -xf "$1" ;;
detach) find "$2" -mindepth 1 -delete ;;
*) exit 1 ;;
esac
""",
    "xcrun": """#!/usr/bin/env bash
echo "xcrun $*" >>"$FAKE_LOG"
case "$1 $2" in
"notarytool submit")
	if [ -n "${FAKE_UPLOAD_FAILS:-}" ]; then
		echo "Error: HTTP status code: 401. Unable to authenticate." >&2
		exit 69
	fi
	printf '{"id":"%s","message":"Successfully uploaded file","path":"%s"}\\n' "$FAKE_ID" "$3" ;;
"notarytool wait")
	if [ "${FAKE_WAIT_RC:-0}" = 124 ]; then
		# As notarytool: the answer of a wait cut short goes to stderr.
		printf '{"id":"%s","message":"Timeout of 600 second(s) was reached before processing completed."}\\n' "$3" >&2
		exit 124
	fi
	printf '{"id":"%s","status":"%s"}\\n' "$3" "$FAKE_STATUS" ;;
"notarytool info")
	if [ -n "${FAKE_INFO_FAILS:-}" ]; then
		echo "Error: The request timed out." >&2
		exit 1
	fi
	printf '{"id":"%s","status":"%s","name":"notarize.zip"}\\n' "$3" "$FAKE_STATUS" ;;
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
        self.dmg = self.d / "pluma-desktop-1.0-macos.dmg"
        self.env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(self.log),
                        PLUMA_DMGBUILD=str(bin_ / "dmgbuild"),
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
        sha = (self.out / f"{self.dmg.name}.sha256").read_text()
        self.assertRegex(sha, rf"^[0-9a-f]{{64}}  {re.escape(self.dmg.name)}\n$")
        # The DMG holds the app and the link to /Applications.
        with tarfile.open(self.out / self.dmg.name) as t:
            members = {m.name.removeprefix("./"): m for m in t.getmembers()}
        self.assertIn("Pluma.app/Contents/Info.plist", members)
        self.assertTrue(members["Applications"].issym())
        self.assertEqual(members["Applications"].linkname, "/Applications")

    def signed_dmg(self):
        # The DMG of sign, for staple.
        run = self.run_script("sign", str(self.zip), str(self.out), id=ID, wait_rc=124, status="In Progress")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.dmg.write_bytes((self.out / self.dmg.name).read_bytes())
        for p in self.out.iterdir():
            p.unlink()
        self.out.rmdir()
        self.log.write_text("")

    def test_sign_accepted(self):
        run = self.run_script("sign", str(self.zip), str(self.out), id=ID, status="Accepted")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("notarized", run.stdout)
        self.assert_delivered(self.dmg.name, f"{self.dmg.name}.sha256")
        calls = self.calls()
        app = next(i for i, c in enumerate(calls) if c.startswith("codesign --force --deep --timestamp --options runtime"))
        build = next(i for i, c in enumerate(calls) if c.startswith("dmgbuild "))
        sign_dmg = next(i for i, c in enumerate(calls) if c.startswith("codesign --force --timestamp") and "-i chat.pluma.desktop.dmg" in c)
        submit = next(i for i, c in enumerate(calls) if c.startswith("xcrun notarytool submit"))
        staple = calls.index(f"xcrun stapler staple {calls[submit].split()[3]}")
        # The app is signed before it goes into the DMG, the DMG before
        # Apple gets it, and the ticket is stapled to the DMG Apple checked.
        self.assertLess(app, build)
        self.assertLess(build, sign_dmg)
        self.assertLess(sign_dmg, submit)
        self.assertLess(submit, staple)
        self.assertTrue(calls[submit].split()[3].endswith(".dmg"), calls[submit])
        self.assertTrue(any(c.startswith("hdiutil detach") for c in calls))

    def test_sign_outlasted(self):
        # notarytool stops waiting with 124, its answer on stderr, and
        # Apple keeps checking.
        run = self.run_script("sign", str(self.zip), str(self.out), id=ID, wait_rc=124, status="In Progress")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"submission {ID}: In Progress", run.stdout)
        self.assert_delivered(self.dmg.name, f"{self.dmg.name}.sha256", f"{self.dmg.name}.notary-id")
        self.assertEqual((self.out / f"{self.dmg.name}.notary-id").read_text(), ID + "\n")
        self.assertNotIn("stapler", "\n".join(self.calls()))

    def test_sign_keeps_the_app_when_apple_cannot_be_asked(self):
        run = self.run_script("sign", str(self.zip), str(self.out), id=ID, wait_rc=124, info_fails=1)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_delivered(self.dmg.name, f"{self.dmg.name}.sha256", f"{self.dmg.name}.notary-id")

    def test_sign_rejected(self):
        run = self.run_script("sign", str(self.zip), str(self.out), id=ID, status="Invalid")
        self.assertEqual(run.returncode, 1)
        self.assertIn(f"submission {ID}: Invalid", run.stderr)
        self.assertIn(f"xcrun notarytool log {ID}", "\n".join(self.calls()))
        self.assertFalse(self.out.exists())

    def test_sign_upload_failed(self):
        run = self.run_script("sign", str(self.zip), str(self.out), upload_fails=1)
        self.assertEqual(run.returncode, 1)
        self.assertIn("upload to Apple failed", run.stderr)
        self.assertNotIn("notarytool wait", "\n".join(self.calls()))
        self.assertFalse(self.out.exists())

    def test_sign_on_a_runner_only(self):
        self.env["GITHUB_ACTIONS"] = ""
        run = self.run_script("sign", str(self.zip), str(self.out))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_staple_accepted(self):
        self.signed_dmg()
        run = self.run_script("staple", str(self.dmg), ID, str(self.out), status="Accepted")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_delivered(self.dmg.name, f"{self.dmg.name}.sha256")
        calls = self.calls()
        self.assertTrue(any(c.startswith("xcrun stapler staple") and c.endswith(".dmg") for c in calls), calls)
        self.assertFalse(any(c.startswith("codesign --force") for c in calls), calls)
        self.assertNotIn("security", "\n".join(calls))
        self.assertNotIn("dmgbuild", "\n".join(calls))

    def test_staple_takes_the_dmg(self):
        run = self.run_script("staple", str(self.zip), ID, str(self.out), status="Accepted")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_staple_still_checking(self):
        self.signed_dmg()
        run = self.run_script("staple", str(self.dmg), ID, str(self.out), wait_rc=124, status="In Progress")
        self.assertEqual(run.returncode, 75)
        self.assertIn("In Progress", run.stderr)
        self.assertIn("run it again later", run.stderr)
        self.assertFalse(self.out.exists())

    def test_staple_rejected(self):
        self.signed_dmg()
        run = self.run_script("staple", str(self.dmg), ID, str(self.out), status="Invalid")
        self.assertEqual(run.returncode, 1)
        self.assertIn(f"xcrun notarytool log {ID}", "\n".join(self.calls()))
        self.assertFalse(self.out.exists())

    def test_staple_needs_no_developer_id(self):
        self.signed_dmg()
        del self.env["PLUMA_DEVELOPER_ID_P12"], self.env["PLUMA_DEVELOPER_ID_PASSWORD"], self.env["GITHUB_ACTIONS"]
        run = self.run_script("staple", str(self.dmg), ID, str(self.out), status="Accepted")
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_staple_checks_the_id(self):
        run = self.run_script("staple", str(self.dmg), "not-an-id", str(self.out))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
