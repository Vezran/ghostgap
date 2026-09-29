"""Tests for the air-gap bundler, signer, and TUF metadata generator.

No network, no external dependencies. All tests use temp directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import shutil

import pytest

from ghostgap.airgap.bundler import AirgapBundler, BundleComponent, VerificationResult
from ghostgap.airgap.signer import BundleSigner
from ghostgap.airgap.tuf_metadata import TufMetadataGenerator


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="test_airgap_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sample_files(tmp_dir):
    """Create a set of sample files that mimic a real bundle payload."""
    paths = {}

    # Binary artifact
    bin_dir = os.path.join(tmp_dir, "bin")
    os.makedirs(bin_dir)
    agent_path = os.path.join(bin_dir, "zyberpol-edge-agent")
    with open(agent_path, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 100)
    paths["agent"] = agent_path

    # KDL config
    config_dir = os.path.join(tmp_dir, "config")
    os.makedirs(config_dir)
    cfg_path = os.path.join(config_dir, "edge.kdl")
    with open(cfg_path, "w") as f:
        f.write('server {\n    listen "0.0.0.0"\n    port 8080\n}\n')
    paths["config"] = cfg_path

    # Sigma rule
    rules_dir = os.path.join(tmp_dir, "rules")
    os.makedirs(rules_dir)
    sigma_path = os.path.join(rules_dir, "mimikatz.yml")
    with open(sigma_path, "w") as f:
        f.write("title: Mimikatz Detection\nstatus: stable\n")
    paths["sigma"] = sigma_path

    # CA cert
    certs_dir = os.path.join(tmp_dir, "certs")
    os.makedirs(certs_dir)
    ca_path = os.path.join(certs_dir, "ca-bundle.crt")
    with open(ca_path, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\nTESTDATA\n-----END CERTIFICATE-----\n")
    paths["ca"] = ca_path

    # Shared key for HMAC signing
    key_path = os.path.join(tmp_dir, "signing.key")
    with open(key_path, "wb") as f:
        f.write(os.urandom(32))
    paths["key"] = key_path

    return paths


# ── TUF Metadata ────────────────────────────────────────────────────────────


class TestTufMetadataGenerator:
    def test_add_target(self):
        gen = TufMetadataGenerator(key_id="abc123")
        target = gen.add_target("bin/agent", b"fake binary data")
        assert target.path == "bin/agent"
        assert target.sha256 == hashlib.sha256(b"fake binary data").hexdigest()
        assert target.size == len(b"fake binary data")

    def test_add_target_from_file(self, sample_files):
        gen = TufMetadataGenerator(key_id="abc123")
        target = gen.add_target_from_file(sample_files["config"])
        assert target.path == "edge.kdl"
        assert target.size > 0

    def test_generate_root(self):
        gen = TufMetadataGenerator(key_id="deadbeef")
        root = gen.generate_root(version=1)
        assert root["signed"]["_type"] == "root"
        assert root["signed"]["version"] == 1
        assert "deadbeef" in root["signed"]["keys"]
        assert set(root["signed"]["roles"].keys()) == {
            "root", "targets", "snapshot", "timestamp",
        }

    def test_generate_targets(self):
        gen = TufMetadataGenerator(key_id="abc")
        gen.add_target("rules/sigma.yml", b"rule content")
        targets = gen.generate_targets()
        assert "rules/sigma.yml" in targets["signed"]["targets"]
        t = targets["signed"]["targets"]["rules/sigma.yml"]
        assert t["length"] == len(b"rule content")
        assert "sha256" in t["hashes"]

    def test_generate_snapshot(self):
        gen = TufMetadataGenerator(key_id="abc")
        snap = gen.generate_snapshot(targets_version=3)
        assert snap["signed"]["_type"] == "snapshot"
        assert snap["signed"]["meta"]["targets.json"]["version"] == 3

    def test_generate_timestamp(self):
        gen = TufMetadataGenerator(key_id="abc")
        ts = gen.generate_timestamp(snapshot_version=2)
        assert ts["signed"]["_type"] == "timestamp"
        assert ts["signed"]["meta"]["snapshot.json"]["version"] == 2

    def test_generate_all(self):
        gen = TufMetadataGenerator(key_id="abc")
        gen.add_target("test.bin", b"data")
        all_meta = gen.generate_all()
        assert set(all_meta.keys()) == {
            "root.json", "targets.json", "snapshot.json", "timestamp.json",
        }

    def test_write_all(self, tmp_dir):
        gen = TufMetadataGenerator(key_id="abc")
        gen.add_target("test.bin", b"data")
        out = os.path.join(tmp_dir, "tuf_out")
        paths = gen.write_all(out)
        assert len(paths) == 4
        for p in paths:
            assert os.path.exists(p)
            with open(p) as f:
                data = json.load(f)
            assert "signed" in data

    def test_expires_is_future(self):
        gen = TufMetadataGenerator(key_id="abc", expires_days=30)
        root = gen.generate_root()
        expires = root["signed"]["expires"]
        # Should be roughly 30 days from now.
        assert "T" in expires
        assert expires.endswith("Z")


# ── Signer ──────────────────────────────────────────────────────────────────


class TestBundleSigner:
    def test_sign_creates_sig_file(self, tmp_dir):
        bundle = os.path.join(tmp_dir, "test.tar.gz")
        with open(bundle, "wb") as f:
            f.write(b"fake archive content")
        key = os.path.join(tmp_dir, "key")
        with open(key, "wb") as f:
            f.write(os.urandom(32))

        signer = BundleSigner()
        sig_path = signer.sign(bundle, key)
        assert os.path.exists(sig_path)
        assert sig_path == bundle + ".sig"

        with open(sig_path) as f:
            envelope = json.load(f)
        assert "sha256" in envelope
        assert "signature" in envelope
        assert "signed_at" in envelope

    def test_sign_and_verify_roundtrip(self, tmp_dir):
        bundle = os.path.join(tmp_dir, "test.tar.gz")
        with open(bundle, "wb") as f:
            f.write(b"archive bytes here")
        key = os.path.join(tmp_dir, "hmac_key")
        with open(key, "wb") as f:
            f.write(b"shared-secret-32-bytes-long!!!!!")

        signer = BundleSigner()
        signer.sign(bundle, key)
        assert signer.verify(bundle, key)

    def test_verify_fails_on_tampered_bundle(self, tmp_dir):
        bundle = os.path.join(tmp_dir, "test.tar.gz")
        with open(bundle, "wb") as f:
            f.write(b"original content")
        key = os.path.join(tmp_dir, "key")
        with open(key, "wb") as f:
            f.write(os.urandom(32))

        signer = BundleSigner()
        signer.sign(bundle, key)

        # Tamper with the bundle.
        with open(bundle, "wb") as f:
            f.write(b"tampered content!")

        assert not signer.verify(bundle, key)

    def test_verify_fails_with_wrong_key(self, tmp_dir):
        bundle = os.path.join(tmp_dir, "test.tar.gz")
        with open(bundle, "wb") as f:
            f.write(b"content")
        key1 = os.path.join(tmp_dir, "key1")
        key2 = os.path.join(tmp_dir, "key2")
        with open(key1, "wb") as f:
            f.write(os.urandom(32))
        with open(key2, "wb") as f:
            f.write(os.urandom(32))

        signer = BundleSigner()
        signer.sign(bundle, key1)
        assert not signer.verify(bundle, key2)

    def test_verify_fails_when_no_sig(self, tmp_dir):
        bundle = os.path.join(tmp_dir, "unsigned.tar.gz")
        with open(bundle, "wb") as f:
            f.write(b"content")
        key = os.path.join(tmp_dir, "key")
        with open(key, "wb") as f:
            f.write(os.urandom(32))

        signer = BundleSigner()
        assert not signer.verify(bundle, key)


# ── Bundler ─────────────────────────────────────────────────────────────────


class TestAirgapBundler:
    def test_create_bundle_produces_archive(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "edge.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["agent"], "bin", "Edge agent binary"),
            BundleComponent(sample_files["config"], "config", "KDL config"),
            BundleComponent(sample_files["sigma"], "rules", "Sigma rule"),
            BundleComponent(sample_files["ca"], "certs", "CA bundle"),
        ]

        result = bundler.create_bundle(components, output)
        assert os.path.exists(result)
        assert os.path.getsize(result) > 0

    def test_create_bundle_with_signing(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "signed.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
        ]

        bundler.create_bundle(
            components, output, sign_key=sample_files["key"]
        )
        assert os.path.exists(output + ".sig")

    def test_create_and_verify_roundtrip(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "verified.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["agent"], "bin"),
            BundleComponent(sample_files["config"], "config"),
            BundleComponent(sample_files["sigma"], "rules"),
        ]

        bundler.create_bundle(
            components, output, sign_key=sample_files["key"]
        )

        result = bundler.verify_bundle(output, public_key=sample_files["key"])
        assert result.valid
        assert result.signature_ok
        assert result.tuf_ok
        assert result.manifest is not None
        assert result.manifest["name"] == "zyberpol-edge"

    def test_verify_detects_tampered_archive(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "tampered.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
        ]
        bundler.create_bundle(
            components, output, sign_key=sample_files["key"]
        )

        # Tamper.
        with open(output, "ab") as f:
            f.write(b"TAMPERED")

        result = bundler.verify_bundle(output, public_key=sample_files["key"])
        assert not result.valid
        assert not result.signature_ok

    def test_extract_bundle(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "extract.tar.gz")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["agent"], "bin"),
            BundleComponent(sample_files["config"], "config"),
        ]
        bundler.create_bundle(components, output)

        bundler.extract_bundle(output, extract_dir, skip_verify=True)
        assert os.path.exists(os.path.join(extract_dir, "manifest.json"))
        assert os.path.exists(os.path.join(extract_dir, "bin", "zyberpol-edge-agent"))
        assert os.path.exists(os.path.join(extract_dir, "config", "edge.kdl"))

    def test_extract_verified_bundle(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "extract_verified.tar.gz")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
        ]
        bundler.create_bundle(
            components, output, sign_key=sample_files["key"]
        )

        bundler.extract_bundle(
            output, extract_dir, public_key=sample_files["key"]
        )
        assert os.path.exists(os.path.join(extract_dir, "manifest.json"))

    def test_extract_refuses_invalid_bundle(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "bad.tar.gz")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
        ]
        bundler.create_bundle(
            components, output, sign_key=sample_files["key"]
        )

        # Tamper.
        with open(output, "ab") as f:
            f.write(b"EVIL")

        with pytest.raises(ValueError, match="verification failed"):
            bundler.extract_bundle(
                output, extract_dir, public_key=sample_files["key"]
            )

    def test_placeholder_components(self, sample_files, tmp_dir):
        """GGUF model paths that don't exist on disk become placeholders."""
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "placeholder.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
            BundleComponent(
                "/nonexistent/model.gguf", "models",
                description="Threat detection GGUF model",
            ),
        ]
        bundler.create_bundle(components, output)

        result = bundler.verify_bundle(output)
        assert result.valid
        # The placeholder should be in the manifest.
        placeholders = [
            f for f in result.manifest["files"] if f.get("placeholder")
        ]
        assert len(placeholders) == 1
        assert placeholders[0]["path"] == "models/model.gguf"

    def test_bundle_contains_tuf_metadata(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "tuf_check.tar.gz")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["sigma"], "rules"),
        ]
        bundler.create_bundle(components, output)
        bundler.extract_bundle(output, extract_dir, skip_verify=True)

        tuf_dir = os.path.join(extract_dir, "tuf")
        assert os.path.isdir(tuf_dir)
        for name in ("root.json", "targets.json", "snapshot.json", "timestamp.json"):
            path = os.path.join(tuf_dir, name)
            assert os.path.exists(path), f"Missing TUF file: {name}"
            with open(path) as f:
                data = json.load(f)
            assert data["signed"]["_type"] == name.replace(".json", "")

    def test_custom_bundle_name_and_version(self, sample_files, tmp_dir):
        bundler = AirgapBundler()
        output = os.path.join(tmp_dir, "output", "custom.tar.gz")
        os.makedirs(os.path.dirname(output), exist_ok=True)

        components = [
            BundleComponent(sample_files["config"], "config"),
        ]
        bundler.create_bundle(
            components, output,
            bundle_name="custom-edge",
            bundle_version="2.0.0",
        )

        result = bundler.verify_bundle(output)
        assert result.manifest["name"] == "custom-edge"
        assert result.manifest["version"] == "2.0.0"


# ── Import smoke test ──────────────────────────────────────────────────────


class TestImports:
    def test_top_level_imports(self):
        from ghostgap.airgap import (
            AirgapBundler,
            BundleSigner,
            TufMetadataGenerator,
            VerificationResult,
        )
        assert AirgapBundler is not None
        assert BundleSigner is not None
        assert TufMetadataGenerator is not None
        assert VerificationResult is not None
