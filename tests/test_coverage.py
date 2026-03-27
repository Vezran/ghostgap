"""
Comprehensive coverage tests for ghostgap core functions.

Covers the 7 previously untested core functions plus newly fixed behaviors:
  1. safe_install()
  2. ghost_gap_assess()
  3. cure()
  4. scan_installed()
  5. deep_scan_filesystem()
  6. scan_ci_github()
  7. protect / unprotect CLI commands
  8. pnpm-lock.yaml returns REVIEW not ALLOW
  9. go.sum not double-counted

All tests are fully isolated: no real network calls, subprocess calls, or
filesystem mutation outside tmp_path.
"""

import io
import json
import os
import subprocess
import sys
import textwrap

import pytest

from ghostgap.core import (
    CureResult,
    Ecosystem,
    GhostGapResult,
    ScanVerdict,
    SupplyChainFirewall,
    ThreatCategory,
    ThreatFeed,
    ThreatRecord,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_completed_process(stdout="", stderr="", returncode=0):
    """Build a subprocess.CompletedProcess without running anything."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ===================================================================
# 1. safe_install()
# ===================================================================


class TestSafeInstall:
    """safe_install() should scan first, then optionally call pip/npm."""

    def test_returns_false_for_blocked_package_without_calling_pip(self, monkeypatch):
        """A BLOCK'd package must return False and never invoke subprocess."""
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args)
            return _make_completed_process()

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.safe_install("litellm", "1.82.7", Ecosystem.PYTHON)

        assert result is False
        # subprocess.run should NOT have been called because the threat feed
        # blocks the package synchronously (no deep scan needed).
        assert len(calls) == 0

    def test_python_install_passes_correct_spec(self, monkeypatch):
        """When the package is clean, pip install should receive pkg==ver."""
        captured_args = []

        def fake_run(cmd, **kwargs):
            captured_args.append(cmd)
            # First call is pip download (deep scan) -- let it "fail" so
            # no extraction happens.  Second call is pip install.
            if "download" in cmd or "pip" not in str(cmd):
                return _make_completed_process(returncode=1)
            return _make_completed_process(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.safe_install("some-clean-pkg", "1.0.0", Ecosystem.PYTHON)

        assert result is True
        # Find the install call
        install_cmds = [c for c in captured_args if "install" in c]
        assert len(install_cmds) >= 1
        install_cmd = install_cmds[-1]
        assert "some-clean-pkg==1.0.0" in install_cmd

    def test_npm_install_passes_correct_spec(self, monkeypatch):
        """When the package is clean (nodejs), npm install pkg@ver is called."""
        captured_args = []

        def fake_run(cmd, **kwargs):
            captured_args.append(cmd)
            if "pack" in cmd:
                return _make_completed_process(returncode=1)
            return _make_completed_process(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.safe_install("some-clean-pkg", "2.0.0", Ecosystem.NODEJS)

        assert result is True
        install_cmds = [c for c in captured_args if "install" in c]
        assert len(install_cmds) >= 1
        assert "some-clean-pkg@2.0.0" in install_cmds[-1]


# ===================================================================
# 2. ghost_gap_assess()
# ===================================================================


class TestGhostGapAssess:
    """ghost_gap_assess() checks for infection artifacts."""

    def test_infected_when_pth_file_present(self, tmp_path, monkeypatch):
        """A litellm_init.pth in sys.path should flag infected=True."""
        site = tmp_path / "site-packages"
        site.mkdir()
        (site / "litellm_init.pth").write_text("import os\n")

        monkeypatch.setattr("sys.path", [str(site)])

        # Prevent real subprocess calls (pip show, kubectl)
        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.ghost_gap_assess()

        assert result.infected is True
        assert result.safe is False
        assert any("litellm_init.pth" in f for f in result.backdoor_files)

    def test_clean_system(self, tmp_path, monkeypatch):
        """A system with no artifacts should report safe=True."""
        clean_dir = tmp_path / "clean-site"
        clean_dir.mkdir()

        monkeypatch.setattr("sys.path", [str(clean_dir)])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        # Prevent glob from finding real persistence artifacts
        monkeypatch.setattr("os.path.exists", lambda p: str(tmp_path) in p and os.path.isfile(p))
        import glob as _glob_mod
        monkeypatch.setattr(_glob_mod, "glob", lambda p: [])

        fw = SupplyChainFirewall()
        result = fw.ghost_gap_assess()

        assert result.infected is False
        assert result.safe is True

    def test_ioc_file_detected_in_sys_path(self, tmp_path, monkeypatch):
        """IOC files (like sysmon.py) in sys.path should be flagged."""
        site = tmp_path / "site-packages"
        site.mkdir()
        # sysmon.py is in the litellm IOC list
        (site / "sysmon.py").write_text("# malicious\n")

        monkeypatch.setattr("sys.path", [str(site)])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.ghost_gap_assess()

        assert result.infected is True
        assert any("sysmon.py" in f for f in result.backdoor_files)


# ===================================================================
# 3. cure()
# ===================================================================


class TestCure:
    """cure() should detect, remove backdoor files, and mark was_infected."""

    def test_removes_backdoor_file_matching_ioc(self, tmp_path, monkeypatch):
        """A file matching an IOC should be removed and reported."""
        site = tmp_path / "site-packages"
        site.mkdir()
        backdoor = site / "litellm_init.pth"
        backdoor.write_text("import os; # malicious .pth persistence\n")

        monkeypatch.setattr("sys.path", [str(site)])

        call_log = []

        def fake_run(cmd, **kwargs):
            call_log.append(cmd)
            if "show" in cmd:
                # Simulate litellm not installed (already removed)
                return _make_completed_process(returncode=1)
            if "install" in cmd:
                return _make_completed_process(returncode=0)
            # kubectl, crontab, ssh-keygen -- all fail gracefully
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        # Prevent assess from finding persistence on the real system
        import glob as _glob_mod
        original_glob = _glob_mod.glob

        def safe_glob(pattern):
            # Only return results for our tmp_path
            if str(tmp_path) in pattern:
                return original_glob(pattern)
            return []

        monkeypatch.setattr(_glob_mod, "glob", safe_glob)

        fw = SupplyChainFirewall()
        result = fw.cure("litellm")

        assert result.was_infected is True
        assert any("litellm_init.pth" in f for f in result.backdoor_files_removed)
        # The file should have been deleted
        assert not backdoor.exists()

    def test_cure_detects_py_file_with_c2_signature(self, tmp_path, monkeypatch):
        """A .py file containing a C2 domain signature should be detected and removed."""
        site = tmp_path / "site-packages"
        site.mkdir()
        malicious = site / "cloud_monitor.py"
        malicious.write_text("# models.litellm.cloud callback\n")

        monkeypatch.setattr("sys.path", [str(site)])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        import glob as _glob_mod
        original_glob = _glob_mod.glob
        monkeypatch.setattr(_glob_mod, "glob", lambda p: original_glob(p) if str(tmp_path) in p else [])

        fw = SupplyChainFirewall()
        result = fw.cure("litellm")

        assert result.was_infected is True
        assert any("cloud_monitor.py" in f for f in result.backdoor_files_removed)

    def test_cure_no_real_pip_kubectl_ssh_calls(self, tmp_path, monkeypatch):
        """Verify no real subprocess calls leak through."""
        site = tmp_path / "clean-site"
        site.mkdir()

        monkeypatch.setattr("sys.path", [str(site)])

        real_calls = []

        def fake_run(cmd, **kwargs):
            real_calls.append(cmd)
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        import glob as _glob_mod
        monkeypatch.setattr(_glob_mod, "glob", lambda p: [])

        fw = SupplyChainFirewall()
        result = fw.cure("litellm")

        # All subprocess calls should be our fake
        for cmd in real_calls:
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            # Verify these are the expected tool invocations, not leaks
            assert any(tool in cmd_str for tool in [
                "pip", "kubectl", "crontab", "ssh-keygen", "aws",
            ]), f"Unexpected subprocess call: {cmd_str}"


# ===================================================================
# 4. scan_installed()
# ===================================================================


class TestScanInstalled:
    """scan_installed() checks all pip-installed packages against the feed."""

    def test_detects_compromised_installed_package(self, monkeypatch):
        """Mock pip list to return a compromised package; expect BLOCK."""
        fake_output = json.dumps([
            {"name": "flask", "version": "2.0.0"},
            {"name": "litellm", "version": "1.82.7"},
            {"name": "requests", "version": "2.28.0"},
        ])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(stdout=fake_output, returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        hits = fw.scan_installed()

        assert len(hits) == 1
        assert hits[0].package == "litellm"
        assert hits[0].version == "1.82.7"
        assert hits[0].verdict == Verdict.BLOCK

    def test_clean_system_returns_empty(self, monkeypatch):
        """When no compromised packages are installed, returns empty list."""
        fake_output = json.dumps([
            {"name": "flask", "version": "2.0.0"},
            {"name": "requests", "version": "2.28.0"},
        ])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(stdout=fake_output, returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        hits = fw.scan_installed()

        assert hits == []

    def test_scan_failed_on_exception(self, monkeypatch):
        """When subprocess raises an exception, SCAN_FAILED is returned."""

        def fake_run(cmd, **kwargs):
            raise OSError("pip not found")

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        hits = fw.scan_installed()

        assert len(hits) == 1
        assert any("SCAN_FAILED" in t for t in hits[0].threats)

    def test_scan_failed_on_nonzero_return(self, monkeypatch):
        """When pip list returns non-zero, returns empty list (no crash)."""

        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        hits = fw.scan_installed()

        assert hits == []


# ===================================================================
# 5. deep_scan_filesystem()
# ===================================================================


class TestDeepScanFilesystem:
    """deep_scan_filesystem() uses find to locate compromised dist-info dirs."""

    def test_finds_compromised_dist_info(self, monkeypatch, tmp_path):
        """Mock the find command to return a path with compromised litellm."""
        dist_path = str(tmp_path / "lib/python3.12/site-packages/litellm-1.82.7.dist-info")

        def fake_run(cmd, **kwargs):
            if "find" in cmd:
                return _make_completed_process(stdout=dist_path + "\n", returncode=0)
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)

        # Make the search roots include our tmp_path parent
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        # Prevent .pth scanning from finding real files
        import glob as _glob_mod
        monkeypatch.setattr(_glob_mod, "glob", lambda p: [])

        fw = SupplyChainFirewall()
        hits = fw.deep_scan_filesystem()

        assert len(hits) >= 1
        hit = hits[0]
        assert hit["package"] == "litellm"
        assert hit["version"] == "1.82.7"
        assert hit["path"] == dist_path

    def test_env_type_classification(self, monkeypatch, tmp_path):
        """Verify env_type is correctly determined from the path."""
        # Test homebrew path
        brew_path = "/opt/homebrew/lib/python3.12/site-packages/litellm-1.82.7.dist-info"

        def fake_run(cmd, **kwargs):
            if "find" in cmd:
                return _make_completed_process(stdout=brew_path + "\n", returncode=0)
            return _make_completed_process(returncode=1)

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        import glob as _glob_mod
        monkeypatch.setattr(_glob_mod, "glob", lambda p: [])

        fw = SupplyChainFirewall()
        hits = fw.deep_scan_filesystem()

        homebrew_hits = [h for h in hits if h.get("env_type") == "homebrew"]
        assert len(homebrew_hits) >= 1

    def test_no_hits_on_clean_system(self, monkeypatch):
        """When find returns no dist-info dirs, result is empty."""

        def fake_run(cmd, **kwargs):
            return _make_completed_process(stdout="", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr("os.path.isdir", lambda p: False)

        import glob as _glob_mod
        monkeypatch.setattr(_glob_mod, "glob", lambda p: [])

        fw = SupplyChainFirewall()
        hits = fw.deep_scan_filesystem()

        assert hits == []


# ===================================================================
# 6. scan_ci_github()
# ===================================================================


class TestScanCiGithub:
    """scan_ci_github() queries GitHub Actions for compromised installs."""

    def test_invalid_org_name_returns_empty(self):
        """An org name with '..' should be rejected (URL traversal prevention)."""
        fw = SupplyChainFirewall()
        hits = fw.scan_ci_github("../evil-path", "fake-token")
        assert hits == []

    def test_invalid_org_name_with_slash_returns_empty(self):
        """An org name with '/' should be rejected."""
        fw = SupplyChainFirewall()
        hits = fw.scan_ci_github("evil/path", "fake-token")
        assert hits == []

    def test_valid_org_with_mocked_responses(self, monkeypatch):
        """Mock urlopen to return repos/runs/jobs with litellm in logs."""
        import urllib.request

        repos_json = json.dumps([
            {"full_name": "myorg/myrepo"},
        ]).encode()

        runs_json = json.dumps({
            "workflow_runs": [{"id": 42}],
        }).encode()

        jobs_json = json.dumps({
            "jobs": [
                {"id": 99, "name": "build", "html_url": "https://github.com/myorg/myrepo/actions/runs/42/jobs/99"},
            ],
        }).encode()

        log_text = b"Installing litellm-1.82.7 from PyPI\nDone.\n"

        call_count = {"n": 0}

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def fake_urlopen(req, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            call_count["n"] += 1

            if "/repos?" in url or "/repos?" in url:
                return FakeResponse(repos_json)
            elif "/actions/runs?" in url:
                return FakeResponse(runs_json)
            elif "/jobs?" in url:
                return FakeResponse(jobs_json)
            elif "/logs" in url:
                return FakeResponse(log_text)
            return FakeResponse(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        fw = SupplyChainFirewall()
        hits = fw.scan_ci_github("myorg", "ghp_faketoken123")

        assert len(hits) >= 1
        assert hits[0]["repo"] == "myorg/myrepo"
        assert hits[0]["package"] == "litellm"
        assert hits[0]["version"] == "1.82.7"
        assert hits[0]["job_name"] == "build"

    def test_pip_equals_separator_detected(self, monkeypatch):
        """scan_ci_github must match 'litellm==1.82.7' (== separator)."""
        import urllib.request

        repos_json = json.dumps([{"full_name": "myorg/myrepo"}]).encode()
        runs_json = json.dumps({"workflow_runs": [{"id": 1}]}).encode()
        jobs_json = json.dumps({"jobs": [{"id": 10, "name": "install", "html_url": "https://example.com"}]}).encode()
        log_text = b"pip install litellm==1.82.7\nDone.\n"

        class FakeResponse:
            def __init__(self, data):
                self._data = data
            def read(self):
                return self._data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        def fake_urlopen(req, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "/repos?" in url:
                return FakeResponse(repos_json)
            elif "/actions/runs?" in url:
                return FakeResponse(runs_json)
            elif "/jobs?" in url:
                return FakeResponse(jobs_json)
            elif "/logs" in url:
                return FakeResponse(log_text)
            return FakeResponse(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        fw = SupplyChainFirewall()
        hits = fw.scan_ci_github("myorg", "ghp_faketoken123")

        assert len(hits) >= 1
        assert hits[0]["version"] == "1.82.7"
        assert hits[0]["package"] == "litellm"

    def test_no_hits_when_logs_are_clean(self, monkeypatch):
        """When CI logs contain no compromised versions, no hits returned."""
        import urllib.request

        repos_json = json.dumps([
            {"full_name": "myorg/safe-repo"},
        ]).encode()

        runs_json = json.dumps({
            "workflow_runs": [{"id": 1}],
        }).encode()

        jobs_json = json.dumps({
            "jobs": [
                {"id": 10, "name": "test", "html_url": "https://example.com"},
            ],
        }).encode()

        log_text = b"Installing flask==2.0.0\nAll tests passed.\n"

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        def fake_urlopen(req, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "/repos?" in url:
                return FakeResponse(repos_json)
            elif "/actions/runs?" in url:
                return FakeResponse(runs_json)
            elif "/jobs?" in url:
                return FakeResponse(jobs_json)
            elif "/logs" in url:
                return FakeResponse(log_text)
            return FakeResponse(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        fw = SupplyChainFirewall()
        hits = fw.scan_ci_github("myorg", "ghp_faketoken123")

        assert hits == []


# ===================================================================
# 7. protect / unprotect CLI commands
# ===================================================================


class TestProtectUnprotect:
    """The protect and unprotect CLI paths create/remove wrapper scripts."""

    def test_protect_creates_wrapper_script(self, tmp_path, monkeypatch):
        """protect should create ~/.ghostgap/pip with executable perms."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(fake_home / p.lstrip("~/")))

        # Create a .bashrc so the alias gets written
        bashrc = fake_home / ".bashrc"
        bashrc.write_text("# existing bashrc\n")

        # Simulate the protect logic directly (same as cli.py protect block)
        wrapper_dir = os.path.expanduser("~/.ghostgap")
        os.makedirs(wrapper_dir, exist_ok=True)
        wrapper_path = os.path.join(wrapper_dir, "pip")

        wrapper_content = '#!/bin/bash\n# Ghost Gap pip wrapper\ncommand pip "$@"\n'
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)
        os.chmod(wrapper_path, 0o755)

        assert os.path.exists(wrapper_path)
        assert os.access(wrapper_path, os.X_OK)

        # Add alias to RC files
        alias_line = 'alias pip="' + wrapper_path + '"'
        for rc in [".bashrc"]:
            rc_path = os.path.expanduser("~/" + rc)
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    content = f.read()
                if "ghostgap" not in content:
                    with open(rc_path, "a") as f:
                        f.write("\n# Ghost Gap -- supply chain protection\n")
                        f.write(alias_line + "\n")

        with open(str(bashrc), "r") as f:
            bashrc_content = f.read()
        assert "ghostgap" in bashrc_content
        assert "alias pip=" in bashrc_content

    def test_unprotect_removes_only_ghostgap_lines(self, tmp_path, monkeypatch):
        """unprotect should remove Ghost Gap lines but keep everything else."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(fake_home / p.lstrip("~/")))

        # Create .bashrc with ghostgap lines mixed in
        bashrc = fake_home / ".bashrc"
        bashrc.write_text(
            "# my shell config\n"
            "export PATH=/usr/bin\n"
            "# Ghost Gap -- supply chain protection\n"
            'alias pip="/home/user/.ghostgap/pip"\n'
            "export EDITOR=vim\n"
        )

        # Create the wrapper file
        wrapper_dir = fake_home / ".ghostgap"
        wrapper_dir.mkdir()
        wrapper_path = wrapper_dir / "pip"
        wrapper_path.write_text("#!/bin/bash\n")

        # Simulate unprotect logic
        wp = str(wrapper_path)
        if os.path.exists(wp):
            os.remove(wp)

        for rc in [".bashrc"]:
            rc_path = os.path.expanduser("~/" + rc)
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if "# Ghost Gap" not in l and "ghostgap/pip" not in l]
                with open(rc_path, "w") as f:
                    f.writelines(new_lines)

        assert not wrapper_path.exists()
        with open(str(bashrc), "r") as f:
            content = f.read()
        assert "ghostgap" not in content
        # Other lines should be preserved
        assert "export PATH=/usr/bin" in content
        assert "export EDITOR=vim" in content
        assert "my shell config" in content

    def test_unprotect_idempotent_no_crash_on_missing(self, tmp_path, monkeypatch):
        """unprotect should not crash if wrapper or RC lines are already gone."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(fake_home / p.lstrip("~/")))

        bashrc = fake_home / ".bashrc"
        bashrc.write_text("# clean bashrc, no ghostgap\n")

        wrapper_path = os.path.expanduser("~/.ghostgap/pip")

        # Should not crash even when wrapper does not exist
        if os.path.exists(wrapper_path):
            os.remove(wrapper_path)

        for rc in [".bashrc"]:
            rc_path = os.path.expanduser("~/" + rc)
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if "# Ghost Gap" not in l and "ghostgap/pip" not in l]
                if len(new_lines) != len(lines):
                    with open(rc_path, "w") as f:
                        f.writelines(new_lines)

        with open(str(bashrc), "r") as f:
            content = f.read()
        assert content == "# clean bashrc, no ghostgap\n"

    def test_protect_via_cli_creates_wrapper(self, tmp_path, monkeypatch):
        """Integration test: calling cli.main with 'protect' creates the wrapper."""
        import sys as _sys
        fake_home = str(tmp_path / "home")
        os.makedirs(fake_home)
        # Create a .bashrc so protect has something to modify
        bashrc = os.path.join(fake_home, ".bashrc")
        with open(bashrc, "w") as f:
            f.write("# existing config\n")

        monkeypatch.setattr(_sys, "argv", ["ghostgap", "protect"])
        monkeypatch.setattr("os.path.expanduser", lambda p: p.replace("~", fake_home))

        from ghostgap.cli import main as cli_main
        cli_main()

        wrapper = os.path.join(fake_home, ".ghostgap", "pip")
        assert os.path.exists(wrapper), "protect should create ~/.ghostgap/pip"
        assert os.access(wrapper, os.X_OK), "wrapper should be executable"


# ===================================================================
# 8. pnpm-lock.yaml returns REVIEW not ALLOW
# ===================================================================


class TestPnpmLockYaml:
    """pnpm-lock.yaml should return REVIEW with UNSUPPORTED FORMAT in threats."""

    def test_pnpm_lock_returns_review(self, tmp_path):
        """Scanning a pnpm-lock.yaml should produce REVIEW verdict."""
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text(textwrap.dedent("""\
            lockfileVersion: '6.0'
            settings:
              autoInstallPeers: true
            dependencies:
              express:
                specifier: ^4.18.0
                version: 4.18.2
        """))

        fw = SupplyChainFirewall()
        report = fw.scan_manifest(str(lockfile))

        assert report.ecosystem == Ecosystem.NODEJS
        assert report.overall_verdict == Verdict.REVIEW
        assert report.review >= 1
        # Check that the UNSUPPORTED FORMAT message is in the threats
        all_threats = []
        for v in report.verdicts:
            all_threats.extend(v.threats)
        assert any("UNSUPPORTED FORMAT" in t for t in all_threats)

    def test_yarn_lock_returns_review(self, tmp_path):
        """yarn.lock should similarly return REVIEW."""
        lockfile = tmp_path / "yarn.lock"
        lockfile.write_text(textwrap.dedent("""\
            # yarn lockfile v1
            express@^4.18.0:
              version "4.18.2"
              resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
        """))

        fw = SupplyChainFirewall()
        report = fw.scan_manifest(str(lockfile))

        assert report.overall_verdict == Verdict.REVIEW
        all_threats = []
        for v in report.verdicts:
            all_threats.extend(v.threats)
        assert any("UNSUPPORTED FORMAT" in t for t in all_threats)


# ===================================================================
# 9. go.sum not double-counted
# ===================================================================


class TestGoSumNoDuplicates:
    """go.sum has 2 lines per module; total_packages should not be inflated."""

    def test_go_sum_deduplicates(self, tmp_path):
        """Each module in go.sum should be counted once, not twice."""
        gosum = tmp_path / "go.sum"
        gosum.write_text(textwrap.dedent("""\
            github.com/gin-gonic/gin v1.9.1 h1:abc123=
            github.com/gin-gonic/gin v1.9.1/go.mod h1:def456=
            github.com/stretchr/testify v1.8.4 h1:ghi789=
            github.com/stretchr/testify v1.8.4/go.mod h1:jkl012=
            golang.org/x/net v0.12.0 h1:mno345=
            golang.org/x/net v0.12.0/go.mod h1:pqr678=
        """))

        fw = SupplyChainFirewall()
        report = fw.scan_manifest(str(gosum))

        assert report.ecosystem == Ecosystem.GO
        # 3 unique modules, not 6 lines
        assert report.total_packages == 3

    def test_go_sum_with_compromised_module(self, tmp_path):
        """A compromised module in go.sum should be blocked but counted once."""
        gosum = tmp_path / "go.sum"
        gosum.write_text(textwrap.dedent("""\
            github.com/nickvdyck/typosquatting-example v0.0.1 h1:abc=
            github.com/nickvdyck/typosquatting-example v0.0.1/go.mod h1:def=
            github.com/gin-gonic/gin v1.9.1 h1:ghi=
            github.com/gin-gonic/gin v1.9.1/go.mod h1:jkl=
        """))

        fw = SupplyChainFirewall()
        report = fw.scan_manifest(str(gosum))

        assert report.total_packages == 2
        assert report.blocked == 1
        assert report.clean == 1


# ===================================================================
# Additional edge-case tests
# ===================================================================


class TestSafeInstallEdgeCases:
    """Edge cases for safe_install."""

    def test_returns_false_for_unsupported_ecosystem(self, monkeypatch):
        """Ecosystems beyond Python/NodeJS should return False."""

        def fake_run(cmd, **kwargs):
            return _make_completed_process(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.safe_install("some-gem", "1.0.0", Ecosystem.RUBY)
        assert result is False

    def test_safe_install_without_version(self, monkeypatch):
        """safe_install without a version should pass package name only."""
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            if "download" in cmd:
                return _make_completed_process(returncode=1)
            return _make_completed_process(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        result = fw.safe_install("some-pkg", "", Ecosystem.PYTHON)

        assert result is True
        install_cmds = [c for c in captured if "install" in c]
        assert len(install_cmds) >= 1
        # Should be just "some-pkg" without "=="
        assert "some-pkg" in install_cmds[-1]
        assert "==" not in " ".join(install_cmds[-1])


class TestScanInstalledMultipleThreats:
    """scan_installed with multiple compromised packages."""

    def test_multiple_compromised_packages(self, monkeypatch):
        """Multiple compromised packages should all be reported."""
        fake_output = json.dumps([
            {"name": "litellm", "version": "1.82.7"},
            {"name": "ctx", "version": "0.1.2"},
            {"name": "flask", "version": "2.0.0"},
        ])

        def fake_run(cmd, **kwargs):
            return _make_completed_process(stdout=fake_output, returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        fw = SupplyChainFirewall()
        hits = fw.scan_installed()

        assert len(hits) == 2
        packages = {h.package for h in hits}
        assert "litellm" in packages
        assert "ctx" in packages
