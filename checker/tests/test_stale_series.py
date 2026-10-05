import importlib
import os
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="cib-test-")
os.environ.setdefault("SBOM_DIR", os.path.join(_TMP, "sboms"))
os.environ.setdefault("DATA_DIR", _TMP)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
checker = importlib.import_module("checker")


def vm(results_by_metric):
    def get(url, params, timeout):
        name = params["query"].split("(", 1)[1].split("[", 1)[0]
        resp = mock.Mock()
        resp.json.return_value = {"data": {"result": results_by_metric.get(name, [])}}
        return resp
    return get


class TestZeroStaleSeries(unittest.TestCase):
    def setUp(self):
        checker._emitted.clear()
        self.pushed = []
        p = mock.patch.object(checker.SESSION, "post", side_effect=lambda url, data, **kw: self.pushed.append(data) or mock.Mock())
        p.start()
        self.addCleanup(p.stop)

    def test_replaced_image_is_zeroed_current_one_is_not(self):
        old = {"__name__": "cib_image_eol", "image": "corentinth/it-tools:latest", "os": "alpine",
               "version": "3.20.3", "eol_date": "2026-04-01", "host": "docker-vm"}
        checker.push_eol_metrics("homelab/it-tools:nginx1.31",
                                 {"family": "alpine", "version": "3.24.2", "eol_date": "2028-06-01", "is_eol": False},
                                 host="docker-vm")
        self.pushed.clear()
        with mock.patch.object(checker.SESSION, "get", side_effect=vm({"cib_image_eol": [{"metric": old}]})):
            checker.zero_stale_series({"docker-vm"})
        self.assertEqual(len(self.pushed), 1)
        self.assertIn('cib_image_eol{eol_date="2026-04-01",host="docker-vm",image="corentinth/it-tools:latest"', self.pushed[0])
        self.assertIn("} 0 ", self.pushed[0])

    def test_series_emitted_this_scan_is_kept(self):
        checker.push_policy_metrics('we"ird\\name', {"cpu_limit": False}, host="docker-vm")
        self.pushed.clear()
        live = {"__name__": "cib_policy_violation", "container": 'we"ird\\name', "check": "cpu_limit", "host": "docker-vm"}
        with mock.patch.object(checker.SESSION, "get", side_effect=vm({"cib_policy_violation": [{"metric": live}]})):
            checker.zero_stale_series({"docker-vm"})
        self.assertEqual(self.pushed, [])

    def test_unreachable_host_is_left_alone(self):
        gone = {"__name__": "cib_license_violations_total", "image": "x:1", "host": "dockerhost-vm"}
        with mock.patch.object(checker.SESSION, "get", side_effect=vm({"cib_license_violations_total": [{"metric": gone}]})):
            checker.zero_stale_series({"docker-vm"})
        self.assertEqual(self.pushed, [])
