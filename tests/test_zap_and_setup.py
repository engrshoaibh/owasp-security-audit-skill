"""Safety tests for zap_web_scan.py and setup_tools.py (no ZAP, Docker or network needed).

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import setup_tools  # noqa: E402
import zap_web_scan as zap  # noqa: E402


def fake_run_factory(captured: list, write_report: Path | None = None):
    def fake_run(cmd, *args, **kwargs):
        captured.append(cmd)
        if write_report is not None:
            write_report.write_text('{"site": []}', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return fake_run


class DockerScanSafety(unittest.TestCase):
    def test_api_scan_without_authorization_uses_safe_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            captured: list = []
            with mock.patch.object(zap.subprocess, "run", fake_run_factory(captured, work / "zap-api-report.json")):
                zap.run_docker_scan("http://localhost:8000/openapi.json", "api", "openapi", work)
            self.assertIn("-S", captured[0])

    def test_api_scan_with_authorization_runs_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            captured: list = []
            with mock.patch.object(zap.subprocess, "run", fake_run_factory(captured, work / "zap-api-report.json")):
                zap.run_docker_scan("http://localhost:8000/openapi.json", "api", "openapi", work, authorized=True)
            self.assertNotIn("-S", captured[0])

    def test_full_scan_requires_authorization(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(PermissionError):
            zap.run_docker_scan("http://localhost:3000", "full", "openapi", Path(tmp))

    def test_missing_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured: list = []
            with mock.patch.object(zap.subprocess, "run", fake_run_factory(captured)), \
                    self.assertRaises(zap.ScanIncomplete):
                zap.run_docker_scan("http://localhost:3000", "baseline", "openapi", Path(tmp))


class DaemonScanSafety(unittest.TestCase):
    def test_full_daemon_scan_requires_authorization(self):
        with mock.patch.object(zap, "zap_api_get") as api, self.assertRaises(PermissionError):
            zap.run_daemon_scan("http://127.0.0.1:8080", "k", "http://localhost:3000", "full", 10)
        api.assert_not_called()

    def test_api_key_sent_as_header_not_query(self):
        captured = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(req, timeout=0):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            return Resp()

        with mock.patch.object(zap.urllib.request, "urlopen", fake_urlopen):
            zap.zap_api_get("http://127.0.0.1:8080", "/JSON/core/view/version/", api_key="s3cr3tkey")
        self.assertNotIn("s3cr3tkey", captured["url"])
        self.assertEqual(captured["headers"].get("X-zap-api-key"), "s3cr3tkey")


class SearchPath(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "uses a POSIX executable bit")
    def test_package_manager_not_resolved_from_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "brew"
            planted.write_text("#!/bin/sh\necho pwned\n")
            planted.chmod(planted.stat().st_mode | stat.S_IEXEC)
            old_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                with mock.patch.dict(os.environ, {"PATH": os.pathsep.join([".", tmp, "/usr/bin"])}):
                    found = setup_tools._which_outside_cwd("brew")
            finally:
                os.chdir(old_cwd)
            self.assertNotEqual(found, str(planted))


if __name__ == "__main__":
    unittest.main()
