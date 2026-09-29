"""Tests for Ghostgap's enums + dataclass models.

Structural correctness checks — no filesystem, no network. These tests
protect against accidental enum value changes (which would break every
downstream consumer relying on the string values like ``"block"``) and
default-value drift in the dataclasses.
"""

from __future__ import annotations

import pytest

from ghostgap.core import (
    CureResult,
    Ecosystem,
    GhostGapResult,
    ManifestReport,
    ScanVerdict,
    ThreatCategory,
    ThreatRecord,
    Verdict,
)


# ── Verdict enum ────────────────────────────────────────────────────


class TestVerdict:
    def test_values_are_lowercase_strings(self):
        assert Verdict.ALLOW.value == "allow"
        assert Verdict.REVIEW.value == "review"
        assert Verdict.BLOCK.value == "block"

    def test_no_unexpected_members(self):
        """Adding a new verdict changes the public contract — every
        downstream switch statement needs to grow a branch."""
        assert {v.value for v in Verdict} == {"allow", "review", "block"}


# ── Ecosystem enum ──────────────────────────────────────────────────


class TestEcosystem:
    EXPECTED = {
        "python", "nodejs", "rust", "ruby", "go", "java", "php", "docker",
    }

    def test_known_ecosystems(self):
        assert {e.value for e in Ecosystem} == self.EXPECTED

    def test_ecosystem_lookup_by_value(self):
        """Callers sometimes receive the string value over the wire
        (e.g. from a CI gate) and must be able to round-trip."""
        assert Ecosystem("python") is Ecosystem.PYTHON
        assert Ecosystem("nodejs") is Ecosystem.NODEJS

    def test_invalid_ecosystem_raises(self):
        with pytest.raises(ValueError):
            Ecosystem("perl")


# ── ThreatCategory enum ─────────────────────────────────────────────


class TestThreatCategory:
    def test_covers_primary_attack_classes(self):
        names = {c.name for c in ThreatCategory}
        # Core categories the feed + verdict logic rely on
        for required in (
            "BACKDOOR",
            "CREDENTIAL_THEFT",
            "CRYPTOMINER",
            "TYPOSQUAT",
            "DEPENDENCY_CONFUSION",
            "OBFUSCATED_CODE",
            "DATA_EXFILTRATION",
            "PROTEST_WARE",
        ):
            assert required in names

    def test_install_script_value(self):
        assert ThreatCategory.INSTALL_SCRIPT.value == "malicious_install_script"


# ── ThreatRecord ───────────────────────────────────────────────────


class TestThreatRecord:
    def test_minimal_construction(self):
        record = ThreatRecord(
            package="evil",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["1.0.0"],
            safe_version="0.9.0",
            threat_category=ThreatCategory.BACKDOOR,
        )
        assert record.package == "evil"
        # Defaults
        assert record.actor == ""
        assert record.cve_id == ""
        assert record.iocs == []
        assert record.persistence_paths == []
        assert record.backdoor_signatures == []

    def test_mutable_defaults_not_shared(self):
        """dataclass(field(default_factory=list)) should give each
        instance its own list — a regression here would cause IoCs
        from one ThreatRecord to leak into another."""
        a = ThreatRecord(
            package="a", ecosystem=Ecosystem.PYTHON, bad_versions=[],
            safe_version="", threat_category=ThreatCategory.BACKDOOR,
        )
        b = ThreatRecord(
            package="b", ecosystem=Ecosystem.PYTHON, bad_versions=[],
            safe_version="", threat_category=ThreatCategory.BACKDOOR,
        )
        a.iocs.append("poison")
        assert b.iocs == []


# ── ScanVerdict ────────────────────────────────────────────────────


class TestScanVerdict:
    def test_default_verdict_is_allow(self):
        v = ScanVerdict(
            package="requests",
            version="2.32.0",
            ecosystem=Ecosystem.PYTHON,
            verdict=Verdict.ALLOW,
        )
        assert v.verdict is Verdict.ALLOW
        assert v.threats == []
        assert v.threat_category is None
        assert v.obfuscation_score == 0.0
        assert v.scan_time_ms == 0.0


# ── ManifestReport ─────────────────────────────────────────────────


class TestManifestReport:
    def test_default_overall_allow(self):
        r = ManifestReport(manifest_path="x", ecosystem=Ecosystem.PYTHON)
        assert r.overall_verdict is Verdict.ALLOW
        assert r.total_packages == 0
        assert r.clean == 0
        assert r.review == 0
        assert r.blocked == 0
        assert r.verdicts == []


# ── GhostGapResult ─────────────────────────────────────────────────


class TestGhostGapResult:
    def test_defaults_claim_safe(self):
        r = GhostGapResult()
        assert r.safe is True
        assert r.infected is False
        assert r.compromised_version == ""
        assert r.backdoor_files == []


# ── CureResult ─────────────────────────────────────────────────────


class TestCureResult:
    def test_defaults(self):
        r = CureResult()
        assert r.was_infected is False
        assert r.system_clean is False
        assert r.version_fixed is False
        assert r.credentials_rotated == {}
