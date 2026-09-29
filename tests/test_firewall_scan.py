"""Tests for :meth:`SupplyChainFirewall.scan_before_install`.

These tests never hit the network or run pip/npm — the deep-scan path
is exercised with mocked dependencies. The threat-feed fast-path is
deterministic and hermetic on its own.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ghostgap.core import (
    Ecosystem,
    ScanVerdict,
    SupplyChainFirewall,
    ThreatCategory,
    Verdict,
)


@pytest.fixture
def fw() -> SupplyChainFirewall:
    return SupplyChainFirewall()


# ── Known-compromised short-circuit ────────────────────────────────


class TestKnownCompromised:
    def test_blocks_litellm_1_82_7(self, fw):
        result = fw.scan_before_install("litellm", "1.82.7", Ecosystem.PYTHON)
        assert result.verdict is Verdict.BLOCK
        assert result.threat_category is ThreatCategory.CREDENTIAL_THEFT
        assert any("KNOWN COMPROMISED" in t for t in result.threats)
        assert "1.82.6" in result.recommendation  # safe version

    def test_blocks_event_stream_3_3_6(self, fw):
        result = fw.scan_before_install("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert result.verdict is Verdict.BLOCK

    def test_allows_litellm_safe_version(self, fw):
        """1.82.6 is not in the bad_versions list for either litellm
        record, so it must be allowed. This is the canonical "don't
        false-positive" test."""
        result = fw.scan_before_install("litellm", "1.82.6", Ecosystem.PYTHON)
        assert result.verdict is not Verdict.BLOCK

    def test_known_compromised_skips_deep_scan(self, fw):
        """When the threat feed already says BLOCK, the expensive
        subprocess-based deep scan must NOT run — that's the whole
        point of the fast path."""
        with patch.object(fw, "_deep_scan_python") as deep:
            fw.scan_before_install("litellm", "1.82.7", Ecosystem.PYTHON)
            deep.assert_not_called()

    def test_scan_time_populated(self, fw):
        result = fw.scan_before_install("litellm", "1.82.7", Ecosystem.PYTHON)
        assert result.scan_time_ms >= 0


# ── Clean package path ─────────────────────────────────────────────


class TestCleanPath:
    def test_unknown_package_allowed_with_empty_deep_scan(self, fw):
        """With the deep scanner patched to do nothing, an unknown
        package should land in ALLOW."""
        with patch.object(fw, "_deep_scan_python"):
            result = fw.scan_before_install(
                "definitely-not-a-real-package-xyz",
                "1.0.0",
                Ecosystem.PYTHON,
            )
        assert result.verdict is Verdict.ALLOW

    def test_default_version_becomes_latest(self, fw):
        with patch.object(fw, "_deep_scan_python"):
            result = fw.scan_before_install("some-pkg", ecosystem=Ecosystem.PYTHON)
        assert result.version == "latest"


# ── Obfuscation-driven verdict logic ───────────────────────────────


class TestObfuscationVerdict:
    """The post-deep-scan verdict logic is the heart of Ghostgap's
    false-positive defence. These tests exercise each branch by
    patching the deep scanner to write specific side effects into
    the verdict, then asserting the resolved verdict."""

    def _patched_fw(self, fw, *, obf: float = 0.0, creds=None, threats=None, network=None):
        """Return a context manager that replaces _deep_scan_python
        with a stub populating the verdict in-place."""
        def stub(package, version, verdict):
            verdict.obfuscation_score = obf
            if creds:
                verdict.credential_access = list(creds)
            if threats:
                verdict.threats = list(threats)
            if network:
                verdict.network_indicators = list(network)

        return patch.object(fw, "_deep_scan_python", side_effect=stub)

    def test_heavy_obfuscation_alone_blocks(self, fw):
        with self._patched_fw(fw, obf=0.8):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.BLOCK
        assert "Heavy code obfuscation" in result.recommendation

    def test_creds_plus_moderate_obf_blocks(self, fw):
        with self._patched_fw(fw, obf=0.3, creds=["a.py: .ssh/id_rsa"]):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.BLOCK
        assert "Credential access combined" in result.recommendation

    def test_moderate_obf_alone_is_review(self, fw):
        with self._patched_fw(fw, obf=0.3):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.REVIEW

    def test_excessive_cred_paths_triggers_review(self, fw):
        with self._patched_fw(fw, obf=0.0, creds=[f"f{i}: pat" for i in range(20)]):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.REVIEW

    def test_few_creds_only_allows(self, fw):
        """Cloud tools (litellm, boto3, awscli) legitimately reference
        credential paths. Few cred refs + no obfuscation = ALLOW."""
        with self._patched_fw(fw, obf=0.0, creds=["f: .aws/credentials"]):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.ALLOW
        assert "common in cloud/infra tools" in result.recommendation

    def test_network_indicators_only_allows(self, fw):
        with self._patched_fw(fw, obf=0.0, network=["f: requests.post("]):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.ALLOW

    def test_completely_clean_allows_with_clean_recommendation(self, fw):
        with self._patched_fw(fw):
            result = fw.scan_before_install("x", "1.0", Ecosystem.PYTHON)
        assert result.verdict is Verdict.ALLOW
        assert "No threats" in result.recommendation


# ── History tracking ───────────────────────────────────────────────


class TestHistory:
    def test_every_scan_recorded(self, fw):
        assert fw.history == []
        fw.scan_before_install("litellm", "1.82.7", Ecosystem.PYTHON)
        with patch.object(fw, "_deep_scan_python"):
            fw.scan_before_install("clean-pkg", "1.0", Ecosystem.PYTHON)
        assert len(fw.history) == 2
        assert all(isinstance(v, ScanVerdict) for v in fw.history)

    def test_history_preserves_order(self, fw):
        fw.scan_before_install("litellm", "1.82.7", Ecosystem.PYTHON)
        fw.scan_before_install("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert fw.history[0].package == "litellm"
        assert fw.history[1].package == "event-stream"
