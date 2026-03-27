"""Ghost Gap — Supply Chain Firewall for pip and npm."""

__version__ = "1.0.0"

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

__all__ = [
    "CureResult",
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
