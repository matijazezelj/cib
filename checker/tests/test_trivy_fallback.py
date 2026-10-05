import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="cib-test-")
os.environ.setdefault("SBOM_DIR", os.path.join(_TMP, "sboms"))
os.environ.setdefault("DATA_DIR", _TMP)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
checker = importlib.import_module("checker")


def done(rc, out=b""):
    return subprocess.CompletedProcess([], rc, stdout=out, stderr=b"FATAL not found in tar")


class TestRegistryFallback(unittest.TestCase):
    def test_daemon_failure_retries_remote_by_digest(self):
        ref = "gotenberg/gotenberg@sha256:abc"
        with mock.patch.object(checker, "_registry_ref", return_value=ref), \
             mock.patch.object(checker.subprocess, "run", side_effect=[done(1), done(0, b'{"Metadata": {}}')]) as run:
            self.assertEqual(checker.scan_trivy_json("gotenberg/gotenberg:latest", "tcp://h:2377"), {"Metadata": {}})
        retry = run.call_args_list[1].args[0]
        self.assertEqual(retry[-3:], ["--image-src", "remote", ref])
        self.assertNotIn("--docker-host", retry)

    def test_success_does_not_retry(self):
        with mock.patch.object(checker.subprocess, "run", return_value=done(0, b"{}")) as run:
            checker.scan_trivy_json("img", "")
        self.assertEqual(run.call_count, 1)

    def test_no_digest_keeps_original_failure(self):
        with mock.patch.object(checker, "_registry_ref", return_value=None), \
             mock.patch.object(checker.subprocess, "run", return_value=done(1)) as run:
            self.assertIsNone(checker.scan_trivy_json("local-only:dev", ""))
        self.assertEqual(run.call_count, 1)
