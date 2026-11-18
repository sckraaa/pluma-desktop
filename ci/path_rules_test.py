#!/usr/bin/env python3
"""The rules of the path selection (task 113), path-selection/rules_test.cpp:
plain C++ without Qt, built and run with the system's compiler. CI has one
and never skips."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPILER = os.environ.get("CXX") or shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")


@unittest.skipIf(not os.environ.get("CI") and not COMPILER, "no C++ compiler")
class PathRulesTest(unittest.TestCase):
    def test_rules(self):
        if not COMPILER:
            raise AssertionError("no C++ compiler (CXX, c++, g++, clang++)")
        with tempfile.TemporaryDirectory() as tmp:
            binary = pathlib.Path(tmp) / "rules_test"
            source = ROOT / "path-selection" / "rules_test.cpp"
            build = subprocess.run([COMPILER, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
                                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                                    "-o", str(binary), str(source)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("path rules: ok", run.stdout)


if __name__ == "__main__":
    unittest.main()
