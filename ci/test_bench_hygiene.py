#!/usr/bin/env python3
"""Hygiene regressions for benchmark evidence generation."""

import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "bench" / "harness" / "footprint_probe.py"
SPEC = importlib.util.spec_from_file_location("footprint_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
footprint_probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(footprint_probe)


class BenchEvidenceHygieneTests(unittest.TestCase):
    def test_norm_home_replaces_only_the_real_home_prefix(self):
        home = os.path.join("home", "example")
        if os.name == "nt":
            home = os.path.join("C:\\", "Users", "example")
        with mock.patch.object(footprint_probe.os.path, "expanduser", return_value=home):
            self.assertEqual("~", footprint_probe.norm_home(home))
            nested = os.path.join(home, ".cache", "uv")
            self.assertEqual(
                "~" + os.path.normpath(nested)[len(os.path.normpath(home)):],
                footprint_probe.norm_home(nested),
            )
            self.assertEqual(home + "2", footprint_probe.norm_home(home + "2"))
            self.assertIsNone(footprint_probe.norm_home(None))
            self.assertEqual("", footprint_probe.norm_home(""))


if __name__ == "__main__":
    unittest.main()
