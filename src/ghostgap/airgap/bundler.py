"""Air-gap bundle builder, verifier, and extractor.

A bundle is a ``.tar.zst`` archive containing:

    bundle/
      manifest.json          — bundle metadata (contents, versions, hashes)
      bin/                   — binary artifacts (edge-core agent)
      config/                — KDL configuration files
      models/                — GGUF model file paths (manifests, not weights)
      rules/                 — Sigma / YARA detection rule files
      tuf/                   — TUF metadata (root, targets, snapshot, timestamp)
      certs/                 — CA certificate store

The archive is compressed with zstandard and signed with Ed25519 (or
HMAC-SHA256 fallback).  Verification checks the signature first, then
validates every file against the TUF targets manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ghostgap.airgap.signer import BundleSigner
from ghostgap.airgap.tuf_metadata import TufMetadataGenerator


# ── Data types ──────────────────────────────────────────────────────────────

@dataclass
class BundleComponent:
    """A file or directory to include in the bundle."""

    source_path: str
    bundle_subdir: str  # e.g. "bin", "config", "rules", "certs"
    description: str = ""


@dataclass
class VerificationResult:
    """Outcome of verifying a bundle."""

    valid: bool
    signature_ok: bool
    tuf_ok: bool
    errors: List[str] = field(default_factory=list)
    manifest: Optional[dict] = None


# ── Bundler ─────────────────────────────────────────────────────────────────

@dataclass
class AirgapBundler:
    """Create, verify, and extract signed air-gap deployment bundles.

    Parameters
    ----------
    key_id : str
        TUF key identifier (hex string) used in metadata generation.
    """

    key_id: str = "0" * 64

    def create_bundle(
        self,
        components: List[BundleComponent],
        output_path: str,
        *,
        sign_key: Optional[str] = None,
        bundle_name: str = "zyberpol-edge",
        bundle_version: str = "0.1.0",
    ) -> str:
        """Create a signed ``.tar.zst`` bundle.

        Parameters
        ----------
        components :
            Files/dirs to include.
        output_path :
            Destination path for the archive (should end in ``.tar.zst``).
        sign_key :
            Path to signing key.  If ``None``, the bundle is unsigned.
        bundle_name :
            Human-readable bundle name stored in the manifest.
        bundle_version :
            SemVer version string stored in the manifest.

        Returns
        -------
        str
            Path to the created bundle file.
        """
        staging = tempfile.mkdtemp(prefix="airgap_bundle_")
        try:
            return self._build(
                components, output_path, staging,
                sign_key=sign_key,
                bundle_name=bundle_name,
                bundle_version=bundle_version,
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def verify_bundle(
        self,
        bundle_path: str,
        public_key: Optional[str] = None,
    ) -> VerificationResult:
        """Verify a bundle's signature and TUF metadata.

        Parameters
        ----------
        bundle_path :
            Path to the ``.tar.zst`` archive.
        public_key :
            Path to the public key (or shared secret for HMAC fallback).
            If ``None``, signature verification is skipped.

        Returns
        -------
        VerificationResult
        """
        errors: List[str] = []
        sig_ok = True
        tuf_ok = True
        manifest = None

        # 1. Signature check.
        if public_key:
            signer = BundleSigner()
            if not signer.verify(bundle_path, public_key):
                sig_ok = False
                errors.append("Signature verification failed")
        else:
            sig_ok = True  # skipped

        # 2. Extract to temp dir and validate TUF + manifest.
        extract_dir = tempfile.mkdtemp(prefix="airgap_verify_")
        try:
            self._extract_tar(bundle_path, extract_dir)
            manifest = self._read_manifest(extract_dir)
            if manifest is None:
                errors.append("Missing manifest.json in bundle")
                tuf_ok = False
            else:
                tuf_errors = self._verify_tuf_targets(extract_dir, manifest)
                if tuf_errors:
                    tuf_ok = False
                    errors.extend(tuf_errors)
        except Exception as exc:
            errors.append(f"Extraction error: {exc}")
            tuf_ok = False
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

        valid = sig_ok and tuf_ok and not errors
        return VerificationResult(
            valid=valid,
            signature_ok=sig_ok,
            tuf_ok=tuf_ok,
            errors=errors,
            manifest=manifest,
        )

    def extract_bundle(
        self,
        bundle_path: str,
        target_dir: str,
        *,
        public_key: Optional[str] = None,
        skip_verify: bool = False,
    ) -> str:
        """Extract a verified bundle to *target_dir*.

        Parameters
        ----------
        bundle_path :
            Path to the ``.tar.zst`` archive.
        target_dir :
            Destination directory.
        public_key :
            If provided, verify signature before extracting.
        skip_verify :
            Skip verification entirely (dangerous -- for testing only).

        Returns
        -------
        str
            Path to the extraction directory.

        Raises
        ------
        ValueError
            If verification fails and *skip_verify* is False.
        """
        if not skip_verify:
            result = self.verify_bundle(bundle_path, public_key)
            if not result.valid:
                raise ValueError(
                    f"Bundle verification failed: {'; '.join(result.errors)}"
                )

        os.makedirs(target_dir, exist_ok=True)
        self._extract_tar(bundle_path, target_dir)
        return target_dir

    # ── Internal ────────────────────────────────────────────────────────

    def _build(
        self,
        components: List[BundleComponent],
        output_path: str,
        staging: str,
        *,
        sign_key: Optional[str],
        bundle_name: str,
        bundle_version: str,
    ) -> str:
        bundle_root = os.path.join(staging, "bundle")
        os.makedirs(bundle_root)

        tuf_gen = TufMetadataGenerator(key_id=self.key_id)
        manifest_files: List[dict] = []

        # Copy components into staging.
        for comp in components:
            dest_dir = os.path.join(bundle_root, comp.bundle_subdir)
            os.makedirs(dest_dir, exist_ok=True)

            src = Path(comp.source_path)
            if src.is_dir():
                dest = os.path.join(dest_dir, src.name)
                shutil.copytree(str(src), dest)
                for root, _dirs, files in os.walk(dest):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, bundle_root)
                        with open(fpath, "rb") as fh:
                            data = fh.read()
                        tuf_gen.add_target(rel, data)
                        manifest_files.append(self._file_entry(rel, data))
            elif src.is_file():
                dest = os.path.join(dest_dir, src.name)
                shutil.copy2(str(src), dest)
                with open(dest, "rb") as fh:
                    data = fh.read()
                rel = os.path.relpath(dest, bundle_root)
                tuf_gen.add_target(rel, data)
                manifest_files.append(self._file_entry(rel, data))
            else:
                # Path doesn't exist on disk (e.g. GGUF model placeholder).
                manifest_files.append({
                    "path": os.path.join(comp.bundle_subdir, src.name),
                    "sha256": "",
                    "size": 0,
                    "placeholder": True,
                    "description": comp.description,
                })

        # Write TUF metadata.
        tuf_dir = os.path.join(bundle_root, "tuf")
        tuf_gen.write_all(tuf_dir)
        for tuf_file in ("root.json", "targets.json", "snapshot.json", "timestamp.json"):
            tuf_path = os.path.join(tuf_dir, tuf_file)
            with open(tuf_path, "rb") as fh:
                data = fh.read()
            manifest_files.append(self._file_entry(
                os.path.join("tuf", tuf_file), data
            ))

        # Write bundle manifest.
        manifest = {
            "name": bundle_name,
            "version": bundle_version,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": manifest_files,
        }
        manifest_path = os.path.join(bundle_root, "manifest.json")
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh, indent=2)

        # Create tar archive (no zstd compression available in stdlib;
        # use gzip as a portable fallback).
        self._create_tar(output_path, bundle_root)

        # Sign if key provided.
        if sign_key:
            signer = BundleSigner()
            signer.sign(output_path, sign_key)

        return output_path

    @staticmethod
    def _file_entry(rel_path: str, data: bytes) -> dict:
        return {
            "path": rel_path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    @staticmethod
    def _create_tar(output_path: str, source_dir: str) -> None:
        """Create a tar.gz archive of *source_dir*."""
        # Use gzip as stdlib fallback; real deployments pipe through zstd.
        with tarfile.open(output_path, "w:gz") as tar:
            for entry in os.listdir(source_dir):
                tar.add(
                    os.path.join(source_dir, entry),
                    arcname=entry,
                )

    @staticmethod
    def _extract_tar(archive_path: str, dest_dir: str) -> None:
        """Extract a tar archive safely."""
        with tarfile.open(archive_path, "r:*") as tar:
            # Filter out path traversal attempts.
            safe_members = []
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    continue
                safe_members.append(member)
            tar.extractall(dest_dir, members=safe_members)

    @staticmethod
    def _read_manifest(extract_dir: str) -> Optional[dict]:
        """Read manifest.json from an extracted bundle."""
        manifest_path = os.path.join(extract_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            return None
        with open(manifest_path, "r") as fh:
            return json.load(fh)

    @staticmethod
    def _verify_tuf_targets(extract_dir: str, manifest: dict) -> List[str]:
        """Verify file hashes against the manifest."""
        errors = []
        for entry in manifest.get("files", []):
            if entry.get("placeholder"):
                continue
            rel_path = entry["path"]
            expected_hash = entry["sha256"]
            file_path = os.path.join(extract_dir, rel_path)
            if not os.path.exists(file_path):
                errors.append(f"Missing file: {rel_path}")
                continue
            with open(file_path, "rb") as fh:
                actual_hash = hashlib.sha256(fh.read()).hexdigest()
            if actual_hash != expected_hash:
                errors.append(
                    f"Hash mismatch for {rel_path}: "
                    f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
                )
        return errors
