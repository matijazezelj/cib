import importlib
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="cib-test-")
os.environ.setdefault("SBOM_DIR", os.path.join(_TMP, "sboms"))
os.environ.setdefault("DATA_DIR", _TMP)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
checker = importlib.import_module("checker")


class TestEolCycle(unittest.TestCase):
    def test_cycles_match_endoflife_date(self):
        cases = [
            ("debian", "13.6", "13"),
            ("debian", "12", "12"),
            ("rhel", "9.4", "9"),
            ("rocky-linux", "9.4", "9"),
            ("ubuntu", "22.04", "22.04"),
            ("alpine", "3.19.0", "3.19"),
        ]
        for product, name, cycle in cases:
            self.assertEqual(checker._parse_version_cycle(name, product), cycle, (product, name))
