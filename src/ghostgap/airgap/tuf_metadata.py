"""TUF metadata generator for air-gap bundles.

Generates The Update Framework (TUF) metadata files:
  - root.json     — trusted keys and role definitions
  - targets.json  — hashes + sizes of every artifact
  - snapshot.json — versions of all metadata files
  - timestamp.json — freshness indicator with expiry
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TufTarget:
    """A single artifact tracked by TUF."""

    path: str
    sha256: str
    size: int


@dataclass
class TufMetadataGenerator:
    """Generate TUF-compliant metadata for a set of targets.

    Parameters
    ----------
    spec_version : str
        TUF spec version (default ``"1.0.31"``).
    key_id : str
        Hex key identifier used in role definitions.
    expires_days : int
        Number of days until metadata expires (default 365).
    """

    spec_version: str = "1.0.31"
    key_id: str = ""
    expires_days: int = 365
    _targets: List[TufTarget] = field(default_factory=list, repr=False)

    # ── Public API ────────────────────────────────────────────────────

    def add_target(self, path: str, data: bytes) -> TufTarget:
        """Register an artifact by its path and raw bytes."""
        digest = hashlib.sha256(data).hexdigest()
        target = TufTarget(path=path, sha256=digest, size=len(data))
        self._targets.append(target)
        return target

    def add_target_from_file(self, file_path: str, target_path: Optional[str] = None) -> TufTarget:
        """Register an artifact from the filesystem."""
        with open(file_path, "rb") as fh:
            data = fh.read()
        rel = target_path or os.path.basename(file_path)
        return self.add_target(rel, data)

    def generate_root(self, version: int = 1) -> dict:
        """Build ``root.json`` content."""
        return {
            "signed": {
                "_type": "root",
                "spec_version": self.spec_version,
                "version": version,
                "expires": self._expires_iso(),
                "consistent_snapshot": False,
                "keys": {
                    self.key_id: {
                        "keytype": "ed25519",
                        "scheme": "ed25519",
                        "keyval": {"public": self.key_id},
                    }
                },
                "roles": {
                    role: {
                        "keyids": [self.key_id],
                        "threshold": 1,
                    }
                    for role in ("root", "targets", "snapshot", "timestamp")
                },
            },
            "signatures": [],
        }

    def generate_targets(self, version: int = 1) -> dict:
        """Build ``targets.json`` content."""
        targets_map: Dict[str, dict] = {}
        for t in self._targets:
            targets_map[t.path] = {
                "length": t.size,
                "hashes": {"sha256": t.sha256},
            }
        return {
            "signed": {
                "_type": "targets",
                "spec_version": self.spec_version,
                "version": version,
                "expires": self._expires_iso(),
                "targets": targets_map,
            },
            "signatures": [],
        }

    def generate_snapshot(self, targets_version: int = 1, version: int = 1) -> dict:
        """Build ``snapshot.json`` content."""
        return {
            "signed": {
                "_type": "snapshot",
                "spec_version": self.spec_version,
                "version": version,
                "expires": self._expires_iso(),
                "meta": {
                    "targets.json": {"version": targets_version},
                },
            },
            "signatures": [],
        }

    def generate_timestamp(self, snapshot_version: int = 1, version: int = 1) -> dict:
        """Build ``timestamp.json`` content."""
        return {
            "signed": {
                "_type": "timestamp",
                "spec_version": self.spec_version,
                "version": version,
                "expires": self._expires_iso(),
                "meta": {
                    "snapshot.json": {"version": snapshot_version},
                },
            },
            "signatures": [],
        }

    def generate_all(self, version: int = 1) -> Dict[str, dict]:
        """Generate all four TUF metadata files.

        Returns a dict mapping filename to metadata dict.
        """
        return {
            "root.json": self.generate_root(version),
            "targets.json": self.generate_targets(version),
            "snapshot.json": self.generate_snapshot(version, version),
            "timestamp.json": self.generate_timestamp(version, version),
        }

    def write_all(self, output_dir: str, version: int = 1) -> List[str]:
        """Write all TUF metadata files to *output_dir*.

        Returns list of written file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        paths = []
        for name, data in self.generate_all(version).items():
            path = os.path.join(output_dir, name)
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2)
            paths.append(path)
        return paths

    # ── Internals ─────────────────────────────────────────────────────

    def _expires_iso(self) -> str:
        """Return an ISO-8601 timestamp *expires_days* from now."""
        future = time.time() + (self.expires_days * 86400)
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(future))
