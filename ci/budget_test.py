#!/usr/bin/env python3
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci/cache-budget.sh"

# The repository's GitHub Actions cache holds 10 GB; the caps leave 1 GB of
# it free (README, Caches).
LIMIT_MB = 10000
BUDGET_MB = 9000

# Answers `gh cache list` with the lines of $FAKE_GH_ENTRIES (id, key, ref,
# bytes, as the --jq of cache-budget.sh prints them) and logs the ids that
# `gh cache delete` gets to $FAKE_GH_DELETED.
FAKE_GH = """#!/usr/bin/env bash
case "$1 $2" in
"cache list") cat "$FAKE_GH_ENTRIES" ;;
"cache delete") echo "${@: -1}" >>"$FAKE_GH_DELETED" ;;
*) exit 1 ;;
esac
"""


def caps():
    """The caps of ci/cache-budget.sh, as {kind: MB}."""
    text = SCRIPT.read_text()
    return {kind: int(mb) for kind, mb in re.findall(r"^\s*([a-z]+-[a-z]+)\) echo (\d+) ;;$", text, re.M)}


def reserve():
    return int(re.search(r"^reserve=(\d+)$", SCRIPT.read_text(), re.M).group(1))


class BudgetTest(unittest.TestCase):
    def test_caps_fit(self):
        self.assertTrue(caps())
        self.assertLessEqual(sum(caps().values()), BUDGET_MB)
        self.assertLessEqual(sum(caps().values()) + reserve(), LIMIT_MB)

    def test_readme_lists_the_caps(self):
        readme = (ROOT / "README.md").read_text()
        table = re.findall(r"^\| `([a-z]+-[a-z]+)-…` \| (\d+) MB \|", readme, re.M)
        self.assertEqual({kind: int(mb) for kind, mb in table}, caps())

    def test_workflow_kinds(self):
        """Every kind the workflow saves has a cap, and prune-caches knows it."""
        workflow = (ROOT / ".github/workflows/desktop.yml").read_text()
        saved = set(re.findall(r"ci/cache-budget\.sh room ([a-z]+-[a-z]+) ", workflow))
        prune = re.search(r"ci/prune-caches\.sh (.*)$", workflow, re.M).group(1)
        self.assertEqual(saved, set(caps()))
        self.assertEqual(set(re.findall(r"([a-z]+-[a-z]+)-(?: |$)", prune)), set(caps()))


class AdmitTest(unittest.TestCase):
    """cache-budget.sh admit against a fake gh."""

    MAIN = "refs/heads/main"

    def admit(self, kind, mb, entries):
        """Runs admit with the cache holding entries, [(id, key, ref, MB)].
        Returns (save, the ids deleted, the output)."""
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            gh = d / "bin/gh"
            gh.parent.mkdir()
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            (d / "entries").write_text("".join(f"{i}\t{key}\t{ref}\t{mb * 1000000 + 4321}\n"
                                               for i, key, ref, mb in entries))
            (d / "deleted").touch()
            env = dict(os.environ, PATH=f"{gh.parent}{os.pathsep}{os.environ['PATH']}",
                       FAKE_GH_ENTRIES=str(d / "entries"), FAKE_GH_DELETED=str(d / "deleted"),
                       GITHUB_REPOSITORY="owner/repo", GITHUB_REF=self.MAIN, GITHUB_OUTPUT=str(d / "output"))
            run = subprocess.run(["bash", str(SCRIPT), "admit", kind, str(mb)], env=env,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            output = (d / "output").read_text()
            save = re.fullmatch(r"save=(true|false)\n", output).group(1) == "true"
            return save, (d / "deleted").read_text().split(), run.stdout

    def entries(self, macos_libs=4816, windows_libs=1198):
        """The cache as it is before the first run of the caps."""
        return [
            (1, "macos-libs-151cea36f83f14c8-1446d4164b2bfce8", self.MAIN, macos_libs),
            (2, "windows-libs-151cea36f83f14c8-3513a4cfab44c63f", self.MAIN, windows_libs),
            (3, "linux-ccache-765a3d46-40551444062-1", self.MAIN, 888),
        ]

    def test_within_cap(self):
        save, deleted, out = self.admit("macos-libs", 1300, self.entries())
        self.assertTrue(save)
        self.assertEqual(deleted, ["1"])
        self.assertNotIn("::error::", out)

    def test_over_cap_in_place_of_a_larger_entry(self):
        # The old entry is over the cap itself: keeping it would let the
        # cache pass 10 GB once the compiler caches are saved.
        save, deleted, out = self.admit("macos-libs", 3500, self.entries())
        self.assertTrue(save)
        self.assertEqual(deleted, ["1"])
        self.assertIn("::error::", out)

    def test_over_cap_within_the_reserve(self):
        save, deleted, out = self.admit("macos-libs", 2900, self.entries(macos_libs=1900))
        self.assertTrue(save)
        self.assertEqual(deleted, ["1"])
        self.assertIn("::error::", out)

    def test_over_cap_past_the_reserve(self):
        save, deleted, out = self.admit("macos-libs", 3100, self.entries(macos_libs=1900))
        self.assertFalse(save)
        self.assertEqual(deleted, [])
        self.assertIn("::error::", out)

    def test_overruns_of_other_kinds(self):
        # windows-libs is 750 MB over its cap: 300 MB more do not fit.
        save, deleted, _ = self.admit("macos-libs", 2300, self.entries(macos_libs=1900, windows_libs=2500))
        self.assertFalse(save)
        self.assertEqual(deleted, [])
        save, deleted, _ = self.admit("macos-libs", 2200, self.entries(macos_libs=1900, windows_libs=2500))
        self.assertTrue(save)
        self.assertEqual(deleted, ["1"])

    def test_other_branches_count_whole(self):
        entries = self.entries(macos_libs=1900) + [
            (4, "macos-libs-151cea36f83f14c8-0000000000000000", "refs/pull/7/merge", 800),
            (5, "windows-ccache-765a3d46-1-1", "refs/heads/topic", 100)]
        save, deleted, _ = self.admit("macos-libs", 2100, entries)
        self.assertTrue(save)
        self.assertEqual(deleted, ["1"])
        save, deleted, _ = self.admit("macos-libs", 2200, entries)
        self.assertFalse(save)
        self.assertEqual(deleted, [])

    def test_empty_cache(self):
        save, deleted, _ = self.admit("windows-ccache", 1400, [])
        self.assertTrue(save)
        self.assertEqual(deleted, [])

    def test_unknown_kind(self):
        run = subprocess.run(["bash", str(SCRIPT), "cap", "linux-libs"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)


if __name__ == "__main__":
    unittest.main()
