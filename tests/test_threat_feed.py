"""Tests for :class:`ThreatFeed`.

These tests assert the built-in feed contains the expected advisories
and that :meth:`check` correctly matches packages + versions. A
regression in ``_load_builtin`` (e.g. a threat record dropped during
a refactor) would silently stop blocking known-bad packages — exactly
the bug this suite exists to prevent.
"""

from __future__ import annotations

import pytest

from ghostgap.core import (
    Ecosystem,
    ThreatCategory,
    ThreatFeed,
    ThreatRecord,
)


@pytest.fixture
def feed() -> ThreatFeed:
    return ThreatFeed()


# ── Built-in feed coverage ─────────────────────────────────────────


class TestBuiltinFeed:
    def test_feed_is_non_empty(self, feed):
        assert feed.total_threats > 0

    def test_feed_covers_multiple_ecosystems(self, feed):
        """The built-in feed should span at least Python + Node.js —
        the two ecosystems the firewall cares about most."""
        assert "python" in feed.ecosystems
        assert "nodejs" in feed.ecosystems

    def test_feed_includes_log4shell(self, feed):
        """Log4Shell is table stakes. If the Java feed lost log4j-core
        we'd silently stop blocking every Log4Shell pin."""
        record = feed.get_threat(
            "org.apache.logging.log4j:log4j-core", Ecosystem.JAVA
        )
        assert record is not None
        assert record.cve_id == "CVE-2021-44228"
        assert record.threat_category is ThreatCategory.BACKDOOR

    def test_feed_includes_litellm_supply_chain(self, feed):
        """The March 2026 LiteLLM supply-chain attack is the flagship
        case this tool was built for. Its presence is non-negotiable."""
        record = feed.check("litellm", "1.82.7", Ecosystem.PYTHON)
        assert record is not None
        assert record.threat_category is ThreatCategory.CREDENTIAL_THEFT
        assert "litellm_init.pth" in record.iocs

    def test_feed_includes_event_stream(self, feed):
        """event-stream 3.3.6 is the canonical npm supply-chain case."""
        record = feed.check("event-stream", "3.3.6", Ecosystem.NODEJS)
        assert record is not None


# ── check() by version ─────────────────────────────────────────────


class TestCheckByVersion:
    def test_exact_match_returns_record(self, feed):
        assert feed.check("litellm", "1.82.7", Ecosystem.PYTHON) is not None

    def test_safe_version_returns_none(self, feed):
        """Using the ``safe_version`` must NOT be flagged."""
        assert feed.check("litellm", "1.82.6", Ecosystem.PYTHON) is None

    def test_unknown_package_returns_none(self, feed):
        assert feed.check("nonexistent-xyz", "1.0.0", Ecosystem.PYTHON) is None

    def test_wrong_ecosystem_returns_none(self, feed):
        """``litellm`` lives in the Python feed — a Node.js check must
        not cross-match."""
        assert feed.check("litellm", "1.82.7", Ecosystem.NODEJS) is None

    def test_case_insensitive_package_match(self, feed):
        assert feed.check("LiteLLM", "1.82.7", Ecosystem.PYTHON) is not None
        assert feed.check("LITELLM", "1.82.7", Ecosystem.PYTHON) is not None

    def test_multiple_records_for_same_package(self, feed):
        """The Python feed lists litellm twice — once for the supply
        chain attack, once for the older guardrail bug. Both must be
        reachable depending on the version queried."""
        supply_chain = feed.check("litellm", "1.82.7", Ecosystem.PYTHON)
        guardrail_bug = feed.check("litellm", "1.82.1", Ecosystem.PYTHON)
        assert supply_chain is not None
        assert guardrail_bug is not None
        assert supply_chain.actor != guardrail_bug.actor


# ── get_threat() version-agnostic ──────────────────────────────────


class TestGetThreat:
    def test_returns_first_record(self, feed):
        record = feed.get_threat("ultralytics", Ecosystem.PYTHON)
        assert record is not None
        assert record.package == "ultralytics"

    def test_unknown_returns_none(self, feed):
        assert feed.get_threat("nonexistent", Ecosystem.PYTHON) is None

    def test_case_insensitive(self, feed):
        assert feed.get_threat("EVENT-STREAM", Ecosystem.NODEJS) is not None


# ── add() custom records ───────────────────────────────────────────


class TestAddCustomRecord:
    def test_add_new_record(self, feed):
        initial = feed.total_threats
        feed.add(ThreatRecord(
            package="custom-evil",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["9.9.9"],
            safe_version="1.0.0",
            threat_category=ThreatCategory.BACKDOOR,
        ))
        assert feed.total_threats == initial + 1
        assert feed.check("custom-evil", "9.9.9", Ecosystem.PYTHON) is not None

    def test_add_second_record_same_package(self, feed):
        """Adding a second record for the same package + ecosystem
        should extend the list, not replace it."""
        feed.add(ThreatRecord(
            package="custom",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["1.0.0"],
            safe_version="",
            threat_category=ThreatCategory.BACKDOOR,
        ))
        feed.add(ThreatRecord(
            package="custom",
            ecosystem=Ecosystem.PYTHON,
            bad_versions=["2.0.0"],
            safe_version="",
            threat_category=ThreatCategory.CRYPTOMINER,
        ))
        one = feed.check("custom", "1.0.0", Ecosystem.PYTHON)
        two = feed.check("custom", "2.0.0", Ecosystem.PYTHON)
        assert one is not None and one.threat_category is ThreatCategory.BACKDOOR
        assert two is not None and two.threat_category is ThreatCategory.CRYPTOMINER


# ── list_all() + total_threats ─────────────────────────────────────


class TestListAll:
    def test_list_all_returns_every_record(self, feed):
        records = feed.list_all()
        assert len(records) == feed.total_threats

    def test_list_all_items_are_threat_records(self, feed):
        for record in feed.list_all():
            assert isinstance(record, ThreatRecord)

    def test_ecosystems_matches_records(self, feed):
        """Every ecosystem in .ecosystems must be produced by at least
        one list_all entry."""
        record_ecosystems = {r.ecosystem.value for r in feed.list_all()}
        assert feed.ecosystems == record_ecosystems
