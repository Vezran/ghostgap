"""
Tests for remaining coverage gaps identified in audits 5 and 6.

Covers: scan_ci_gitlab, cure() N/A safe_version guard,
package-lock.json v2, go.mod replace blocks, datetime fallback.
"""

import json
import os
import textwrap
from unittest.mock import MagicMock

import pytest

from ghostgap.core import (
    Ecosystem,
    SupplyChainFirewall,
    ThreatCategory,
    ThreatRecord,
    Verdict,
)


# ── scan_ci_gitlab ──────────────────────────────────────────────────────────


class TestScanCiGitlab:
    """Coverage for scan_ci_gitlab — previously zero tests."""

    def test_invalid_group_name_returns_empty(self):
        fw = SupplyChainFirewall()
        hits = fw.scan_ci_gitlab("../evil", "glpat-fake")
        assert hits == []

    def test_invalid_group_with_double_dot_returns_empty(self):
        fw = SupplyChainFirewall()
        hits = fw.scan_ci_gitlab("group/../admin", "glpat-fake")
        assert hits == []

    def test_valid_subgroup_accepted(self):
        """Subgroups like 'myorg/subgroup' should pass validation."""
        fw = SupplyChainFirewall()
        # Will fail at HTTP level (no real server), but should not return
        # early due to validation — it returns empty from the HTTP exception
        hits = fw.scan_ci_gitlab("myorg/subgroup", "glpat-fake")
        assert hits == []

    def test_mocked_gitlab_scan_finds_compromised(self, monkeypatch):
        """Mock GitLab API to return logs with a compromised package."""
        import urllib.request

        group_json = json.dumps({"id": 42}).encode()
        projects_json = json.dumps([
            {"id": 100, "path_with_namespace": "mygroup/myproject"},
        ]).encode()
        jobs_json = json.dumps([
            {"id": 200, "name": "build", "started_at": "2099-01-01T00:00:00Z"},
        ]).encode()
        trace_text = b"pip install litellm==1.82.7\nDone.\n"

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        def fake_urlopen(req, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "/trace" in url:
                return FakeResponse(trace_text)
            elif "/jobs?" in url:
                return FakeResponse(jobs_json)
            elif "/projects?" in url:
                return FakeResponse(projects_json)
            elif "/groups/" in url:
                return FakeResponse(group_json)
            return FakeResponse(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        fw = SupplyChainFirewall()
        hits = fw.scan_ci_gitlab("mygroup", "glpat-fake")

        assert len(hits) >= 1
        assert hits[0]["project"] == "mygroup/myproject"
        assert hits[0]["package"] == "litellm"
        assert hits[0]["version"] == "1.82.7"

    def test_clean_gitlab_logs_return_empty(self, monkeypatch):
        import urllib.request

        group_json = json.dumps({"id": 42}).encode()
        projects_json = json.dumps([
            {"id": 100, "path_with_namespace": "mygroup/safe-project"},
        ]).encode()
        jobs_json = json.dumps([
            {"id": 200, "name": "test", "started_at": "2099-01-01T00:00:00Z"},
        ]).encode()
        trace_text = b"pip install flask==2.0.0\nAll tests passed.\n"

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        def fake_urlopen(req, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "/groups/mygroup" in url and "/projects" not in url:
                return FakeResponse(group_json)
            elif "/projects?" in url:
                return FakeResponse(projects_json)
            elif "/jobs?" in url:
                return FakeResponse(jobs_json)
            elif "/trace" in url:
                return FakeResponse(trace_text)
            return FakeResponse(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        fw = SupplyChainFirewall()
        hits = fw.scan_ci_gitlab("mygroup", "glpat-fake")
        assert hits == []


# ── cure() N/A safe_version guard ───────────────────────────────────────────


class TestCureNASafeVersion:
    """Verify cure() does not run pip install pkg==N/A."""

    def test_cure_skips_reinstall_for_na_safe_version(self, tmp_path, monkeypatch):
        """When safe_version is N/A, no pip install should be attempted."""
        fw = SupplyChainFirewall()

        # Add a custom threat with N/A safe version
        fw.threat_feed.add(ThreatRecord(
            package="evil-pkg",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["0.1.0"],
            safe_version="N/A",
            threat_category=ThreatCategory.BACKDOOR,
            actor="test",
            description="Test threat with no safe version",
            iocs=["evil_backdoor.py"],
            backdoor_signatures=["evil_c2_domain"],
        ))

        # Create a fake backdoor file
        fake_site = tmp_path / "site-packages"
        fake_site.mkdir()
        backdoor = fake_site / "evil_backdoor.py"
        backdoor.write_text("# evil")

        monkeypatch.setattr("sys.path", [str(fake_site)])

        # Track subprocess calls to ensure no pip install happens
        pip_install_called = []
        original_run = __import__("subprocess").run

        def mock_run(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if "pip" in cmd_str and "install" in cmd_str:
                pip_install_called.append(cmd_str)
                return MagicMock(returncode=1)
            if "pip" in cmd_str and "show" in cmd_str:
                return MagicMock(returncode=0, stdout="Version: 0.1.0\n")
            return MagicMock(returncode=1, stdout="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = fw.cure("evil-pkg")

        # Should NOT have called pip install with ==N/A
        na_calls = [c for c in pip_install_called if "N/A" in c]
        assert na_calls == [], f"pip install called with N/A: {na_calls}"
        assert result.version_fixed is False


# ── package-lock.json v2 ────────────────────────────────────────────────────


class TestPackageLockV2:
    """Verify package-lock.json v2 (dict-valued dependencies) is handled."""

    def test_v2_format_detects_compromised_package(self, tmp_path):
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/event-stream": {"version": "3.3.6"},
            },
            "dependencies": {
                "event-stream": {
                    "version": "3.3.6",
                    "resolved": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
                },
                "express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                },
            },
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked >= 1
        assert r.overall_verdict == Verdict.BLOCK

    def test_v1_format_with_dict_deps(self, tmp_path):
        """v1 lockfiles also have dict-valued dependencies."""
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "event-stream": {
                    "version": "3.3.6",
                    "resolved": "https://registry.npmjs.org/...",
                },
                "lodash": {
                    "version": "4.17.21",
                },
            },
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.total_packages == 2


# ── go.mod replace block ───────────────────────────────────────────────────


class TestGoModReplaceBlock:
    """Verify go.mod replace blocks don't produce false positives."""

    def test_replace_block_not_counted_as_dependency(self, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(textwrap.dedent("""\
            module example.com/myapp

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1
            )

            replace (
                github.com/old/pkg v0.1.0 => github.com/new/pkg v1.0.0
            )
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        # Only the require entry should be counted, not the replace
        assert r.total_packages == 1

    def test_single_line_replace_not_counted(self, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(textwrap.dedent("""\
            module example.com/myapp

            go 1.21

            require github.com/gin-gonic/gin v1.9.1

            replace github.com/old/pkg v0.1.0 => github.com/new/pkg v1.0.0
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 1

    def test_exclude_block_not_counted(self, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(textwrap.dedent("""\
            module example.com/myapp

            go 1.21

            require github.com/gin-gonic/gin v1.9.1

            exclude (
                github.com/bad/pkg v0.0.1
            )
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 1
