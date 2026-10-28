#!/usr/bin/env python3
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The repository's GitHub Actions cache holds 10 GB; the caps leave 1 GB of
# it free (README, Caches).
BUDGET_MB = 9000


def caps():
    """The caps of ci/cache-budget.sh, as {kind: MB}."""
    text = (ROOT / "ci/cache-budget.sh").read_text()
    return {kind: int(mb) for kind, mb in re.findall(r"^([a-z]+-[a-z]+)\) cap=(\d+) ;;$", text, re.M)}


class BudgetTest(unittest.TestCase):
    def test_caps_fit(self):
        self.assertTrue(caps())
        self.assertLessEqual(sum(caps().values()), BUDGET_MB)

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


if __name__ == "__main__":
    unittest.main()
