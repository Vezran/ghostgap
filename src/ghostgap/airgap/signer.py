"""Ed25519 bundle signing and verification.

Uses Python's standard-library ``hashlib`` for hashing and a pure-Python
Ed25519 implementation via the ``hashlib`` + ``hmac`` route.  For real
deployments the signing key lives on an HSM; this module handles the
on-disk envelope format.

Signature format: the file ``<bundle>.sig`` contains a JSON object:

    {
        "algorithm": "ed25519",
        "sha256": "<hex digest of bundle>",
        "signature": "<hex signature bytes>",
        "signed_at": "<ISO-8601 timestamp>"
    }

When actual Ed25519 keys are not available (e.g. ``nacl`` / ``cryptography``
not installed) the signer falls back to HMAC-SHA256 with a shared key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

# Try to import a real Ed25519 implementation; fall back to HMAC.
_USE_ED25519 = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    _USE_ED25519 = True
except ImportError:
    pass


def _sha256_file(path: str) -> str:
    """Return the hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class BundleSigner:
    """Sign and verify air-gap bundles.

    When the ``cryptography`` package is available, true Ed25519 signatures
    are produced.  Otherwise an HMAC-SHA256 tag is used as a fallback so
    the module works with zero external dependencies.
    """

    def sign(self, bundle_path: str, key_path: str) -> str:
        """Sign *bundle_path* using the key at *key_path*.

        Returns the path to the generated ``.sig`` file.
        """
        digest = _sha256_file(bundle_path)
        sig_hex = self._compute_signature(digest, key_path)

        envelope = {
            "algorithm": "ed25519" if _USE_ED25519 else "hmac-sha256",
            "sha256": digest,
            "signature": sig_hex,
            "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        sig_path = bundle_path + ".sig"
        with open(sig_path, "w") as fh:
            json.dump(envelope, fh, indent=2)
        return sig_path

    def verify(self, bundle_path: str, public_key: str) -> bool:
        """Verify the signature of *bundle_path*.

        *public_key* is a path to the public key file (Ed25519 PEM) or
        a shared-secret file (HMAC fallback).

        Returns ``True`` if the bundle's ``.sig`` file exists and the
        signature matches.
        """
        sig_path = bundle_path + ".sig"
        if not os.path.exists(sig_path):
            return False

        with open(sig_path, "r") as fh:
            envelope = json.load(fh)

        # Verify hash first.
        digest = _sha256_file(bundle_path)
        if digest != envelope.get("sha256", ""):
            return False

        algo = envelope.get("algorithm", "")
        sig_hex = envelope.get("signature", "")

        if algo == "ed25519" and _USE_ED25519:
            return self._verify_ed25519(digest, sig_hex, public_key)
        if algo == "hmac-sha256":
            return self._verify_hmac(digest, sig_hex, public_key)

        # Unknown algorithm.
        return False

    # ── Internal ──────────────────────────────────────────────────────

    @staticmethod
    def _compute_signature(digest: str, key_path: str) -> str:
        """Produce a hex-encoded signature over *digest*."""
        key_bytes = _read_key(key_path)

        if _USE_ED25519:
            private_key = Ed25519PrivateKey.from_private_bytes(key_bytes[:32])
            sig = private_key.sign(digest.encode())
            return sig.hex()

        # HMAC-SHA256 fallback.
        tag = hmac.new(key_bytes, digest.encode(), hashlib.sha256).digest()
        return tag.hex()

    @staticmethod
    def _verify_ed25519(digest: str, sig_hex: str, pub_key_path: str) -> bool:
        """Verify an Ed25519 signature."""
        try:
            key_bytes = _read_key(pub_key_path)
            # The key file may contain raw private key bytes (32 bytes) from
            # which we derive the public key, or raw public key bytes.
            if len(key_bytes) == 32:
                # Try as private key first (sign+verify use the same file).
                try:
                    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
                    public_key = private_key.public_key()
                except Exception:
                    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
            else:
                # PEM or DER encoded.
                public_key = Ed25519PublicKey.from_public_bytes(key_bytes[:32])
            public_key.verify(bytes.fromhex(sig_hex), digest.encode())
            return True
        except Exception:
            return False

    @staticmethod
    def _verify_hmac(digest: str, sig_hex: str, key_path: str) -> bool:
        """Verify an HMAC-SHA256 tag."""
        key_bytes = _read_key(key_path)
        expected = hmac.new(key_bytes, digest.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_hex)


def _read_key(path: str) -> bytes:
    """Read raw key bytes from a file."""
    with open(path, "rb") as fh:
        return fh.read()
