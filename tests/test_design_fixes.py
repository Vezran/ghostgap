"""
Tests for design fixes: pyproject.toml (PEP 621 + Poetry), Pipfile,
Pipfile.lock parsing, and ci_gate strict mode.
"""

import json

import pytest

from ghostgap.core import (
    Ecosystem,
    SupplyChainFirewall,
    Verdict,
)


# -- pyproject.toml PEP 621 format ------------------------------------------


class TestPyprojectPEP621:
    def test_pyproject_pep621_compromised(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '    "litellm==1.82.7",\n'
            '    "flask>=2.0",\n'
            "]\n"
        )
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.total_packages == 2

    def test_pyproject_clean(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\n'
            'dependencies = ["flask>=2.0", "requests"]\n'
        )
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 0


# -- pyproject.toml Poetry format --------------------------------------------


class TestPyprojectPoetry:
    def test_pyproject_poetry_compromised(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[tool.poetry.dependencies]\n"
            'python = "^3.8"\n'
            'litellm = "1.82.7"\n'
            'flask = "^2.0"\n'
        )
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1


# -- Pipfile format ----------------------------------------------------------


class TestPipfile:
    def test_pipfile_compromised(self, tmp_path):
        f = tmp_path / "Pipfile"
        f.write_text(
            "[packages]\n"
            'litellm = "==1.82.7"\n'
            'flask = "*"\n'
        )
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1


# -- Pipfile.lock format -----------------------------------------------------


class TestPipfileLock:
    def test_pipfile_lock_compromised(self, tmp_path):
        f = tmp_path / "Pipfile.lock"
        f.write_text(
            json.dumps(
                {
                    "_meta": {"hash": {"sha256": "abc"}},
                    "default": {
                        "litellm": {"version": "==1.82.7"},
                        "flask": {"version": "==2.0.0"},
                    },
                    "develop": {},
                }
            )
        )
        fw = SupplyChainFirewall()
        r = fw.scan_manifest(str(f))
        assert r.blocked == 1
        assert r.total_packages == 2


# -- ci_gate strict mode -----------------------------------------------------


class TestCIGateStrict:
    def test_ci_gate_strict_blocks_review(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM node\nRUN npm install\n")
        fw = SupplyChainFirewall()
        # Without strict: REVIEW passes (returns 0)
        assert fw.ci_gate(str(f)) == 0
        # With strict: REVIEW blocked (returns 1)
        assert fw.ci_gate(str(f), strict=True) == 1

    def test_ci_gate_strict_clean_still_passes(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\n")
        fw = SupplyChainFirewall()
        assert fw.ci_gate(str(f), strict=True) == 0
