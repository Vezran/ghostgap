"""Ghost Gap — Supply Chain Firewall for pip and npm."""

__version__ = "1.0.0"

from ghostgap.core import (
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

__all__ = [
    "Ecosystem",
    "GhostGapResult",
    "ManifestReport",
    "ScanVerdict",
    "SupplyChainFirewall",
    "ThreatCategory",
    "ThreatFeed",
    "ThreatRecord",
    "Verdict",
]
