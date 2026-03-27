"""
Tests that verify the audit fixes hold.

Each test targets a specific finding from the security/logic audit.
"""

import json
import os
import re
import textwrap

import pytest

from ghostgap.core import (
    Ecosystem,
    SupplyChainFirewall,
    ThreatCategory,
    ThreatFeed,
    ThreatRecord,
    Verdict,
)


# ── Fix: Version normalization (PEP 440 variants) ──────────────────────────


class TestVersionNormalization:
    """Finding: exact string match bypassed by post/pre/rc/local suffixes."""

    def test_post_release_detected(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.7.post1", Ecosystem.PYTHON) is not None

    def test_pre_release_detected(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.7rc1", Ecosystem.PYTHON) is not None

    def test_local_version_detected(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.7+local", Ecosystem.PYTHON) is not None

    def test_dev_version_detected(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.7.dev0", Ecosystem.PYTHON) is not None

    def test_exact_match_still_works(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.7", Ecosystem.PYTHON) is not None

    def test_safe_version_still_safe(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.6", Ecosystem.PYTHON) is None

    def test_unrelated_version_safe(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.83.0", Ecosystem.PYTHON) is None


# ── Fix: Requirements parser handles extras ─────────────────────────────────


class TestExtrasInRequirements:
    """Finding: litellm[proxy]==1.82.7 was not detected."""

    def test_extras_detected(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("litellm[proxy]==1.82.7\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.overall_verdict == Verdict.BLOCK

    def test_multiple_extras_detected(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("litellm[proxy,extra]==1.82.7\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1

    def test_extras_without_version(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask[async]\nrequests\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 2
        assert r.blocked == 0


# ── Fix: ThreatFeed case normalization ──────────────────────────────────────


class TestCaseNormalization:
    """Finding: _load_builtin didn't lowercase, add() did."""

    def test_add_mixed_case_found_on_lookup(self):
        feed = ThreatFeed()
        feed.add(ThreatRecord(
            package="MyEvilPkg",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["1.0.0"],
            safe_version="0.9.0",
            threat_category=ThreatCategory.BACKDOOR,
            actor="test",
            description="Test",
        ))
        # Lookup with lowercase
        assert feed.check("myevilpkg", "1.0.0", Ecosystem.PYTHON) is not None
        # Lookup with original case
        assert feed.check("MyEvilPkg", "1.0.0", Ecosystem.PYTHON) is not None


# ── Fix: pom.xml parser handles <scope> between tags ───────────────────────


class TestPomXmlParser:
    """Finding: regex required groupId→artifactId→version with no gaps."""

    def test_scope_between_artifact_and_version(self, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(textwrap.dedent("""\
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <scope>compile</scope>
                  <version>2.14.1</version>
                </dependency>
              </dependencies>
            </project>
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1, "Log4Shell should be detected even with <scope> between tags"

    def test_multiple_tags_between(self, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(textwrap.dedent("""\
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <scope>compile</scope>
                  <optional>false</optional>
                  <version>2.14.1</version>
                </dependency>
              </dependencies>
            </project>
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1


# ── Fix: Obfuscation score denominator ──────────────────────────────────────


class TestObfuscationScore:
    """Verify obfuscation score formula in production code."""

    def test_formula_uses_correct_denominator(self):
        """Verify core.py uses max(total_py, 1) not total_py * 2."""
        import inspect
        from ghostgap.core import SupplyChainFirewall
        source = inspect.getsource(SupplyChainFirewall._deep_scan_python)
        assert "max(total_py, 1)" in source, "Formula should use max(total_py, 1)"
        assert "total_py * 2" not in source, "Old dampener total_py * 2 should be removed"


# ── Fix: Launcher detects dist-packages ─────────────────────────────────────


class TestLauncherDistPackages:
    """Finding: launcher only checked site-packages, not dist-packages."""

    def test_dist_packages_detected(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        dist_dir = tmp_path / "dist-packages"
        dist_dir.mkdir()
        (dist_dir / "litellm_init.pth").write_text("import os\n")

        monkeypatch.setattr("sys.path", [str(dist_dir)])
        threats = _check_for_malicious_pth()
        assert len(threats) >= 1

    def test_site_packages_still_detected(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        (site_dir / "litellm_init.pth").write_text("import os\n")

        monkeypatch.setattr("sys.path", [str(site_dir)])
        threats = _check_for_malicious_pth()
        assert len(threats) >= 1


# ── Fix: Launcher scans entire directory after litellm_init.pth ─────────────


class TestLauncherFullDirectoryScan:
    """Finding: continue after litellm_init.pth skipped rest of directory."""

    def test_second_malicious_pth_also_detected(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        (site_dir / "litellm_init.pth").write_text("import os\n")
        (site_dir / "sneaky.pth").write_text("import os; models.litellm.cloud\n")

        monkeypatch.setattr("sys.path", [str(site_dir)])
        threats = _check_for_malicious_pth()
        assert len(threats) >= 2, "Both malicious .pth files should be detected"


# ── Fix: Verdict logic for credential+network ──────────────────────────────


class TestVerdictCredentialNetwork:
    """Verify credential access + network indicators triggers REVIEW."""

    def test_verdict_logic_has_creds_network_branch(self):
        """Verify the production code has the credential+network REVIEW branch."""
        import inspect
        from ghostgap.core import SupplyChainFirewall
        source = inspect.getsource(SupplyChainFirewall.scan_before_install)
        assert "has_creds and len(verdict.network_indicators)" in source, (
            "Production code should have credential+network REVIEW branch"
        )


class TestExtrasEdgeCases:
    """Additional edge cases for requirements.txt parsing."""

    def test_extras_with_version_range_not_false_positive(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("litellm[proxy]>=1.82.9,<2.0\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 0

    def test_vcs_url_not_matched_as_package(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("git+https://github.com/example/repo.git#egg=pkg\nhttps://example.com/pkg.tar.gz\nflask==2.0.0\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 1  # Only flask

    def test_empty_requirements_file(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 0
        assert r.overall_verdict == Verdict.ALLOW

    def test_empty_package_json(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text("{}")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 0
        assert r.overall_verdict == Verdict.ALLOW


class TestPackageLockV3:
    """Test package-lock.json v3 format (npm 7+)."""

    def test_v3_format_detects_compromised_package(self, tmp_path):
        import json
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/event-stream": {"version": "3.3.6"},
            }
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.total_packages == 2  # express + event-stream (not root)

    def test_v3_format_clean(self, tmp_path):
        import json
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app"},
                "node_modules/express": {"version": "4.18.0"},
            }
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 0
        assert r.total_packages == 1
