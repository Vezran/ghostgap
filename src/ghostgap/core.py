"""
Ghost Gap — Supply Chain Firewall Core
=======================================
Zero dependencies. Python 3.8+. Protects pip and npm.

This module contains:
  - ThreatFeed: Live database of compromised packages
  - SupplyChainFirewall: Scan, block, assess, and cure
  - Ghost Gap: Post-compromise assessment
  - Cure: Automatic infection remediation
"""

from __future__ import annotations

import glob as _glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Set


# ── Self-exclusion ────────────────────────────────────────────────────────────
SELF_DIR = os.path.dirname(os.path.abspath(__file__))


# ── Enums ─────────────────────────────────────────────────────────────────────

class Verdict(Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Ecosystem(Enum):
    PYTHON = "python"
    NODEJS = "nodejs"
    RUST = "rust"
    RUBY = "ruby"
    GO = "go"
    JAVA = "java"
    PHP = "php"
    DOCKER = "docker"


class ThreatCategory(Enum):
    BACKDOOR = "backdoor"
    CREDENTIAL_THEFT = "credential_theft"
    CRYPTOMINER = "cryptominer"
    TYPOSQUAT = "typosquat"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    OBFUSCATED_CODE = "obfuscated_code"
    DATA_EXFILTRATION = "data_exfiltration"
    PROTEST_WARE = "protestware"
    INSTALL_SCRIPT = "malicious_install_script"


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class ThreatRecord:
    """A known compromised package."""
    package: str
    ecosystem: Ecosystem
    bad_versions: List[str]
    safe_version: str
    threat_category: ThreatCategory
    actor: str = ""
    cve_id: str = ""
    description: str = ""
    iocs: List[str] = field(default_factory=list)
    persistence_paths: List[str] = field(default_factory=list)
    backdoor_signatures: List[str] = field(default_factory=list)
    reported_at: str = ""
    source: str = ""


@dataclass
class ScanVerdict:
    """Result of scanning a package."""
    package: str
    version: str
    ecosystem: Ecosystem
    verdict: Verdict
    threats: List[str] = field(default_factory=list)
    threat_category: Optional[ThreatCategory] = None
    credential_access: List[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    network_indicators: List[str] = field(default_factory=list)
    recommendation: str = ""
    scan_time_ms: float = 0.0


@dataclass
class ManifestReport:
    """Result of scanning a manifest file."""
    manifest_path: str
    ecosystem: Ecosystem
    total_packages: int = 0
    clean: int = 0
    review: int = 0
    blocked: int = 0
    verdicts: List[ScanVerdict] = field(default_factory=list)
    overall_verdict: Verdict = Verdict.ALLOW


@dataclass
class GhostGapResult:
    """Post-compromise assessment."""
    infected: bool = False
    backdoor_files: List[str] = field(default_factory=list)
    persistence_artifacts: List[str] = field(default_factory=list)
    rogue_k8s_pods: List[str] = field(default_factory=list)
    exposed_credentials: List[str] = field(default_factory=list)
    exposed_env_vars: List[str] = field(default_factory=list)
    compromised_version: str = ""
    safe: bool = True


@dataclass
class CureResult:
    """Result of curing an infection."""
    was_infected: bool = False
    backdoor_files_removed: List[str] = field(default_factory=list)
    persistence_cleaned: List[str] = field(default_factory=list)
    rogue_pods_detected: List[str] = field(default_factory=list)
    credentials_rotated: Dict[str, bool] = field(default_factory=dict)
    version_fixed: bool = False
    system_clean: bool = False


# ── Credential Paths (50+) ───────────────────────────────────────────────────

CREDENTIAL_PATHS = [
    "~/.ssh/id_*", "~/.ssh/config", "~/.ssh/known_hosts",
    "~/.aws/credentials", "~/.aws/config", "~/.aws/sso/cache/*.json",
    "~/.config/gcloud/application_default_credentials.json", "~/.config/gcloud/*.json",
    "~/.azure/*.json", "~/.azure/azureProfile.json",
    "~/.oci/config", "~/.oci/*.pem",
    "~/.config/doctl/config.yaml", "~/.config/hcloud/cli.toml",
    "~/.kube/config",
    "~/.docker/config.json", "~/.config/containers/auth.json",
    "~/.git-credentials", "~/.gitconfig",
    "~/.config/gh/hosts.yml", "~/.config/glab-cli/config.yml",
    "~/.npmrc", "~/.pypirc",
    "~/.cargo/credentials.toml", "~/.gem/credentials",
    "~/.m2/settings.xml", "~/.gradle/gradle.properties",
    "~/.nuget/NuGet/NuGet.Config", "~/.composer/auth.json",
    "~/.config/openai.token",
    "~/.cache/huggingface/token", "~/.huggingface/token",
    "~/.pgpass", "~/.my.cnf",
    "~/.terraform.d/credentials.tfrc.json",
    "~/.vault-token", "~/.pulumi/credentials.json",
    "~/.config/solana/id.json", "~/.ethereum/keystore/*", "~/.bitcoin/wallet.dat",
    "~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history",
    "~/.gnupg/private*",
    "~/.local/share/keyrings/*",
    ".env*",
]

# ── Code Patterns ────────────────────────────────────────────────────────────

OBFUSCATION_PATTERNS = [
    r"exec\s*\(\s*compile\s*\(",
    r"eval\s*\(\s*base64\.b64decode",
    r"__import__\s*\(\s*['\"]base64",
    r"marshal\.loads\s*\(",
    r"types\.FunctionType\s*\(",
    r"getattr\s*\(\s*__builtins__",
]

EXFILTRATION_PATTERNS = [
    r"requests\.post\s*\(",
    r"urllib\.request\.urlopen",
    r"socket\.socket.*connect",
    r"http\.client\.HTTP",
    r"aiohttp\.ClientSession",
    r"httpx\.(post|put|patch)",
]

CREDENTIAL_CODE_PATTERNS = [
    # These patterns detect code that reads SPECIFIC credential files (not general env var usage)
    r"\.ssh/id_rsa", r"\.ssh/id_ed25519", r"\.ssh/id_ecdsa",
    r"\.aws/credentials", r"\.kube/config",
    r"\.config/gcloud/application_default_credentials",
    r"\.azure/azureProfile", r"\.azure/msal_token",
    r"\.git-credentials",
    r"\.docker/config\.json",
    r"\.npmrc", r"\.pypirc",
    r"\.bash_history", r"\.zsh_history",
    r"\.gnupg/private",
    r"\.config/sysmon",
    # Reading HOME + credential path = credential harvesting pattern
    r"expanduser.*\.ssh", r"expanduser.*\.aws", r"expanduser.*\.kube",
    r"expanduser.*\.gnupg", r"expanduser.*\.docker",
    r"Path\.home\(\).*\.ssh", r"Path\.home\(\).*\.aws",
]

NPM_MALICIOUS_PATTERNS = [
    r"preinstall.*curl", r"preinstall.*wget", r"preinstall.*node\s+-e",
    r"postinstall.*curl", r"postinstall.*wget",
    r"child_process.*exec", r"require\(['\"]child_process",
    r"require\(['\"]net['\"]", r"require\(['\"]dgram['\"]",
    r"Buffer\.from\([^)]{40,},\s*['\"]base64",
]


# ── Threat Feed ──────────────────────────────────────────────────────────────

class ThreatFeed:
    """Live database of known compromised packages across ecosystems."""

    def __init__(self):
        self._db: Dict[str, List[ThreatRecord]] = {}
        self._load_builtin()

    def _load_builtin(self):
        builtin = [
            # ── Python ──
            ThreatRecord(
                package="litellm", ecosystem=Ecosystem.PYTHON,
                bad_versions=["1.82.7", "1.82.8"], safe_version="1.82.6",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="TeamPCP (via Trivy CI/CD supply chain compromise)",
                reported_at="2026-03-24",
                description=(
                    "Supply chain attack via compromised Trivy dependency in CI/CD. "
                    "Attacker bypassed CI/CD and published directly to PyPI. "
                    "v1.82.7: malicious payload in proxy_server.py. "
                    "v1.82.8: added litellm_init.pth persistence + proxy_server.py payload. "
                    "Harvests env vars, SSH keys, AWS/GCP/Azure creds, K8s tokens, DB passwords. "
                    "Encrypts and exfiltrates via POST to models.litellm[.]cloud and checkmarx[.]zone. "
                    "Affected window: March 24 2026, 10:39-16:00 UTC. "
                    "Mandiant engaged for forensic analysis."
                ),
                persistence_paths=[
                    "~/.config/sysmon/sysmon.py",
                    "~/.config/sysmon",
                ],
                backdoor_signatures=[
                    "cloud_stealer", "CloudStealer", "sysmon_collect",
                    "exfiltrate", "steal_creds", "harvest_keys",
                    "send_home", "c2_callback",
                    # Signatures from the actual payload
                    "models.litellm.cloud", "checkmarx.zone",
                    "litellm_init",
                ],
                iocs=[
                    # Files to scan for
                    "sysmon.py", "_sysmon.py", "cloud_monitor.py",
                    "_internal_monitor.py", "_cloud_sync.py", "telemetry_helper.py",
                    # .pth persistence (auto-executed on Python startup)
                    "litellm_init.pth",
                ],
                source="BerriAI/LiteLLM official advisory + Datadog Security Labs",
            ),
            # litellm guardrail logging bug (separate from supply chain attack)
            # Versions before 1.82.3 leaked API keys in spend logs and OTEL traces
            ThreatRecord(
                package="litellm", ecosystem=Ecosystem.PYTHON,
                bad_versions=["1.82.0", "1.82.1", "1.82.2"], safe_version="1.82.3",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="bug (not malicious)",
                reported_at="2026-03-18",
                description=(
                    "Guardrail logging bug: custom guardrails returning full request data "
                    "caused Authorization headers (API keys) to leak into spend logs and "
                    "OpenTelemetry traces. Not a supply chain attack — a software bug. "
                    "Upgrade to 1.82.3+."
                ),
                source="LiteLLM incident report 2026-03-18",
            ),
            ThreatRecord(
                package="ultralytics", ecosystem=Ecosystem.PYTHON,
                bad_versions=["8.3.41", "8.3.42"], safe_version="8.3.40",
                threat_category=ThreatCategory.CRYPTOMINER,
                actor="unknown", reported_at="2024-12",
                description="Cryptominer via compromised GitHub Actions",
                source="Ultralytics advisory",
            ),
            ThreatRecord(
                package="ctx", ecosystem=Ecosystem.PYTHON,
                bad_versions=["0.1.2", "0.2.0"], safe_version="0.1.1",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2022-05",
                description="AWS credential exfiltration via env vars",
                source="PyPI advisory",
            ),
            ThreatRecord(
                package="phpass", ecosystem=Ecosystem.PYTHON,
                bad_versions=["0.9.99"], safe_version="N/A",
                threat_category=ThreatCategory.DEPENDENCY_CONFUSION,
                actor="unknown", reported_at="2022-05",
                description="Dependency confusion stealing env vars",
                source="PyPI advisory",
            ),
            # ── Node.js ──
            ThreatRecord(
                package="event-stream", ecosystem=Ecosystem.NODEJS,
                bad_versions=["3.3.6"], safe_version="3.3.4",
                threat_category=ThreatCategory.BACKDOOR,
                actor="right9ctrl", reported_at="2018-11",
                description="Crypto wallet theft via flatmap-stream",
                source="npm advisory",
            ),
            ThreatRecord(
                package="ua-parser-js", ecosystem=Ecosystem.NODEJS,
                bad_versions=["0.7.29", "0.8.0", "1.0.0"], safe_version="0.7.30",
                threat_category=ThreatCategory.CRYPTOMINER,
                actor="unknown", reported_at="2021-10",
                description="Cryptominer + password stealer via hijacked maintainer",
                source="npm advisory",
            ),
            ThreatRecord(
                package="colors", ecosystem=Ecosystem.NODEJS,
                bad_versions=["1.4.1", "1.4.2"], safe_version="1.4.0",
                threat_category=ThreatCategory.PROTEST_WARE,
                actor="Marak", reported_at="2022-01",
                description="Infinite loop sabotage (protestware)",
                source="npm advisory",
            ),
            ThreatRecord(
                package="node-ipc", ecosystem=Ecosystem.NODEJS,
                bad_versions=["10.1.1", "10.1.2", "10.1.3"], safe_version="10.1.0",
                threat_category=ThreatCategory.PROTEST_WARE,
                actor="RIAEvangelist", reported_at="2022-03",
                description="File overwrite on Russian/Belarusian IPs (protestware)",
                source="npm advisory",
            ),
            ThreatRecord(
                package="coa", ecosystem=Ecosystem.NODEJS,
                bad_versions=["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"],
                safe_version="2.0.2",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2021-11",
                description="Hijacked package stealing passwords via preinstall",
                source="npm advisory",
            ),
            ThreatRecord(
                package="rc", ecosystem=Ecosystem.NODEJS,
                bad_versions=["1.2.9", "1.3.0", "2.3.9"], safe_version="1.2.8",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2021-11",
                description="Hijacked alongside coa to steal credentials",
                source="npm advisory",
            ),
            ThreatRecord(
                package="es5-ext", ecosystem=Ecosystem.NODEJS,
                bad_versions=["0.10.63"], safe_version="0.10.62",
                threat_category=ThreatCategory.PROTEST_WARE,
                actor="medikoo", reported_at="2024-03",
                description="Anti-war message on Russian IPs (protestware)",
                source="npm advisory",
            ),
            ThreatRecord(
                package="@lottiefiles/lottie-player", ecosystem=Ecosystem.NODEJS,
                bad_versions=["2.0.8"], safe_version="2.0.7",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2024-10",
                description="Crypto wallet drainer injected via compromised package",
                source="npm advisory",
            ),
            # ── Ruby ──
            ThreatRecord(
                package="rest-client", ecosystem=Ecosystem.RUBY,
                bad_versions=["1.6.13"], safe_version="1.6.12",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2019-08",
                description="Hijacked gem exfiltrated env vars and URLs to pastebin",
                source="RubyGems advisory",
            ),
            ThreatRecord(
                package="strong_password", ecosystem=Ecosystem.RUBY,
                bad_versions=["0.0.7"], safe_version="0.0.6",
                threat_category=ThreatCategory.BACKDOOR,
                actor="unknown", reported_at="2019-07",
                description="Hijacked gem downloaded and eval'd code from pastebin",
                source="RubyGems advisory",
            ),
            ThreatRecord(
                package="bootstrap-sass", ecosystem=Ecosystem.RUBY,
                bad_versions=["3.2.0.3"], safe_version="3.2.0.2",
                threat_category=ThreatCategory.BACKDOOR,
                actor="unknown", reported_at="2019-04",
                description="Backdoor in gem executes arbitrary code via cookie",
                source="RubyGems advisory",
            ),
            # ── Rust ──
            ThreatRecord(
                package="rustdecimal", ecosystem=Ecosystem.RUST,
                bad_versions=["1.23.1"], safe_version="N/A",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2022-05",
                description="Typosquat of rust_decimal — stole env vars via Telegram bot",
                source="crates.io advisory",
            ),
            ThreatRecord(
                package="cratesio", ecosystem=Ecosystem.RUST,
                bad_versions=["0.1.0"], safe_version="N/A",
                threat_category=ThreatCategory.CREDENTIAL_THEFT,
                actor="unknown", reported_at="2023-08",
                description="Typosquat attempting to steal crates.io API tokens",
                source="crates.io advisory",
            ),
            # ── Go ──
            ThreatRecord(
                package="github.com/nickvdyck/typosquatting-example", ecosystem=Ecosystem.GO,
                bad_versions=["0.0.1"], safe_version="N/A",
                threat_category=ThreatCategory.TYPOSQUAT,
                actor="researcher", reported_at="2023-12",
                description="Demonstrated Go module typosquatting via vanity import paths",
                source="Go security research",
            ),
            # ── Java ──
            ThreatRecord(
                package="org.apache.logging.log4j:log4j-core", ecosystem=Ecosystem.JAVA,
                bad_versions=["2.0", "2.1", "2.2", "2.3", "2.4", "2.4.1", "2.5", "2.6", "2.6.1",
                              "2.6.2", "2.7", "2.8", "2.8.1", "2.8.2", "2.9.0", "2.9.1", "2.10.0",
                              "2.11.0", "2.11.1", "2.11.2", "2.12.0", "2.12.1", "2.13.0", "2.13.1",
                              "2.13.2", "2.13.3", "2.14.0", "2.14.1", "2.15.0", "2.16.0"],
                safe_version="2.17.1",
                threat_category=ThreatCategory.BACKDOOR,
                actor="CVE-2021-44228", cve_id="CVE-2021-44228",
                reported_at="2021-12",
                description="Log4Shell — remote code execution via JNDI injection. Affected virtually all Java applications.",
                source="Apache advisory / CVE-2021-44228",
            ),
            ThreatRecord(
                package="com.google.protobuf:protobuf-java", ecosystem=Ecosystem.JAVA,
                bad_versions=["3.16.0"], safe_version="3.16.1",
                threat_category=ThreatCategory.DEPENDENCY_CONFUSION,
                actor="unknown", reported_at="2021-10",
                description="Dependency confusion attack on Google protobuf",
                source="Maven Central advisory",
            ),
            # ── PHP ──
            ThreatRecord(
                package="phpunit/phpunit", ecosystem=Ecosystem.PHP,
                bad_versions=["4.8.28", "5.6.3"], safe_version="5.6.4",
                threat_category=ThreatCategory.BACKDOOR,
                actor="unknown", reported_at="2017-01",
                description="Backdoor injected into eval-stdin.php allowing remote code execution",
                source="Packagist advisory",
            ),
            # ── Docker ──
            ThreatRecord(
                package="docker.io/library/node", ecosystem=Ecosystem.DOCKER,
                bad_versions=["CVE-2024-21490"], safe_version="latest",
                threat_category=ThreatCategory.BACKDOOR,
                actor="various",
                reported_at="2024-01",
                description="Multiple compromised Docker Hub images with cryptominers and backdoors. Always verify image digests.",
                source="Docker Hub / Sysdig research",
            ),
        ]

        for threat in builtin:
            key = threat.ecosystem.value + "/" + threat.package.lower()
            if key not in self._db:
                self._db[key] = []
            self._db[key].append(threat)

    def check(self, package: str, version: str, ecosystem: Ecosystem) -> Optional[ThreatRecord]:
        key = ecosystem.value + "/" + package.lower()
        # Normalize version: strip PEP 440 pre/post/dev/local suffixes
        base_version = re.split(r'[\+]|\.?(?:post|pre|rc|dev|a|b)\d*', version)[0] if version else ""
        for record in self._db.get(key, []):
            if version in record.bad_versions or base_version in record.bad_versions:
                return record
        return None

    def get_threat(self, package: str, ecosystem: Ecosystem) -> Optional[ThreatRecord]:
        """Get threat record for a package regardless of version."""
        key = ecosystem.value + "/" + package.lower()
        records = self._db.get(key, [])
        return records[0] if records else None

    def add(self, record: ThreatRecord):
        key = record.ecosystem.value + "/" + record.package.lower()
        if key not in self._db:
            self._db[key] = []
        self._db[key].append(record)

    @property
    def total_threats(self) -> int:
        return sum(len(r) for r in self._db.values())

    @property
    def ecosystems(self) -> Set[str]:
        return {k.split("/")[0] for k in self._db}

    def list_all(self) -> List[ThreatRecord]:
        result = []
        for records in self._db.values():
            result.extend(records)
        return result


# ── Supply Chain Firewall ────────────────────────────────────────────────────

class SupplyChainFirewall:
    """Always-on firewall for package installations.

    Usage:
        fw = SupplyChainFirewall()

        # Block before install
        v = fw.scan_before_install("litellm", "1.82.7")

        # Scan manifest
        r = fw.scan_manifest("requirements.txt")

        # Am I safe?
        gap = fw.ghost_gap_assess()

        # Cure an infection
        cure = fw.cure()

        # CI/CD gate
        exit_code = fw.ci_gate("requirements.txt")
    """

    def __init__(self):
        self.threat_feed = ThreatFeed()
        self.history: List[ScanVerdict] = []

    # ── Scan ─────────────────────────────────────────────────────────────

    def scan_before_install(self, package: str, version: str = "",
                            ecosystem: Ecosystem = Ecosystem.PYTHON) -> ScanVerdict:
        start = time.time()
        verdict = ScanVerdict(
            package=package, version=version or "latest",
            ecosystem=ecosystem, verdict=Verdict.ALLOW,
        )

        # 1. Threat feed (instant)
        threat = self.threat_feed.check(package, version, ecosystem)
        if threat:
            verdict.verdict = Verdict.BLOCK
            verdict.threat_category = threat.threat_category
            verdict.threats.append(
                "KNOWN COMPROMISED: " + package + "==" + version +
                " (" + threat.threat_category.value + " by " + threat.actor + ")"
            )
            verdict.recommendation = "BLOCK. Use " + threat.safe_version + " instead."
            verdict.scan_time_ms = (time.time() - start) * 1000
            self.history.append(verdict)
            return verdict

        # 2. Deep scan
        if ecosystem == Ecosystem.PYTHON:
            self._deep_scan_python(package, version, verdict)
        elif ecosystem == Ecosystem.NODEJS:
            self._deep_scan_npm(package, version, verdict)

        # 3. Compute verdict
        # Credential access alone is NOT enough to block — many legit packages
        # (litellm, boto3, awscli) reference credential paths in their source.
        # Only block when combined with obfuscation or exfiltration patterns.
        # Verdict logic: minimize false positives on legitimate infra tools.
        # Cloud tools (litellm, boto3, awscli) legitimately reference credential
        # paths AND make HTTP calls. Only BLOCK when there's real obfuscation.
        has_heavy_obf = verdict.obfuscation_score > 0.5
        has_moderate_obf = verdict.obfuscation_score > 0.2
        has_creds = len(verdict.credential_access) > 0

        if has_heavy_obf:
            # Heavy obfuscation alone = suspicious regardless
            verdict.verdict = Verdict.BLOCK
            verdict.recommendation = "BLOCK: Heavy code obfuscation detected."
        elif has_creds and has_moderate_obf:
            # Credential access + meaningful obfuscation = attack pattern
            verdict.verdict = Verdict.BLOCK
            verdict.recommendation = "BLOCK: Credential access combined with code obfuscation."
        elif has_moderate_obf or (has_creds and len(verdict.credential_access) > 15):
            # Moderate obfuscation alone, or excessive credential paths
            verdict.verdict = Verdict.REVIEW
            verdict.recommendation = "REVIEW: Suspicious patterns detected — manual review recommended."
        elif has_creds and len(verdict.network_indicators) > 0:
            verdict.verdict = Verdict.REVIEW
            verdict.recommendation = "REVIEW: Credential access combined with network activity."
        elif verdict.threats or verdict.network_indicators or has_creds:
            verdict.verdict = Verdict.ALLOW
            verdict.recommendation = "ALLOW: Some patterns found (common in cloud/infra tools)."
        else:
            verdict.recommendation = "ALLOW: No threats detected."

        verdict.scan_time_ms = (time.time() - start) * 1000
        self.history.append(verdict)
        return verdict

    def _deep_scan_python(self, package: str, version: str, verdict: ScanVerdict):
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                spec = package + ("==" + version if version else "")
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "download", "--no-deps", "-d", tmpdir, spec],
                    capture_output=True, text=True, timeout=60,
                )
                if proc.returncode != 0:
                    return

                files = os.listdir(tmpdir)
                if not files:
                    return

                pkg_file = os.path.join(tmpdir, files[0])
                extract_dir = os.path.join(tmpdir, "src")
                os.makedirs(extract_dir, exist_ok=True)

                if pkg_file.endswith((".whl", ".zip")):
                    import zipfile
                    with zipfile.ZipFile(pkg_file, "r") as z:
                        for member in z.namelist():
                            member_path = os.path.realpath(os.path.join(extract_dir, member))
                            if not member_path.startswith(os.path.realpath(extract_dir) + os.sep) and member_path != os.path.realpath(extract_dir):
                                continue
                            z.extract(member, extract_dir)
                elif pkg_file.endswith(".tar.gz"):
                    import tarfile
                    with tarfile.open(pkg_file, "r:gz") as t:
                        if sys.version_info >= (3, 12):
                            t.extractall(extract_dir, filter="data")
                        else:
                            for member in t.getmembers():
                                if member.issym() or member.islnk():
                                    continue
                                dest = os.path.realpath(os.path.join(extract_dir, member.name))
                                if not dest.startswith(os.path.realpath(extract_dir) + os.sep) and dest != os.path.realpath(extract_dir):
                                    continue
                                t.extract(member, extract_dir)

                obf_hits = 0
                total_py = 0

                for root, _, scan_files in os.walk(extract_dir):
                    for f in scan_files:
                        if not f.endswith(".py"):
                            continue
                        total_py += 1
                        fp = os.path.join(root, f)
                        try:
                            if os.path.getsize(fp) > 500_000:
                                continue
                            with open(fp, "r", errors="ignore") as fh:
                                code = fh.read()
                            for pat in CREDENTIAL_CODE_PATTERNS:
                                if re.search(pat, code):
                                    verdict.credential_access.append(f + ": " + pat)
                            for pat in OBFUSCATION_PATTERNS:
                                if re.findall(pat, code):
                                    obf_hits += 1
                                    verdict.threats.append("OBFUSCATION in " + f)
                            for pat in EXFILTRATION_PATTERNS:
                                if re.search(pat, code):
                                    verdict.network_indicators.append(f + ": " + pat)
                        except Exception:
                            pass

                if total_py > 0:
                    verdict.obfuscation_score = min(1.0, obf_hits / max(total_py, 1))
        except Exception:
            verdict.threats.append("SCAN_FAILED: Could not complete deep scan")

    def _deep_scan_npm(self, package: str, version: str, verdict: ScanVerdict):
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                spec = package + ("@" + version if version else "")
                proc = subprocess.run(
                    ["npm", "pack", spec, "--pack-destination", tmpdir],
                    capture_output=True, text=True, timeout=60, cwd=tmpdir,
                )
                if proc.returncode != 0:
                    return

                files = os.listdir(tmpdir)
                if not files:
                    return

                tgz = os.path.join(tmpdir, files[0])
                extract_dir = os.path.join(tmpdir, "src")
                os.makedirs(extract_dir, exist_ok=True)

                import tarfile
                with tarfile.open(tgz, "r:gz") as t:
                    if sys.version_info >= (3, 12):
                        t.extractall(extract_dir, filter="data")
                    else:
                        for member in t.getmembers():
                            if member.issym() or member.islnk():
                                continue
                            dest = os.path.realpath(os.path.join(extract_dir, member.name))
                            if not dest.startswith(os.path.realpath(extract_dir) + os.sep) and dest != os.path.realpath(extract_dir):
                                continue
                            t.extract(member, extract_dir)

                pkg_json = os.path.join(extract_dir, "package", "package.json")
                if os.path.exists(pkg_json):
                    with open(pkg_json) as f:
                        data = json.load(f)
                    scripts = data.get("scripts", {})
                    for hook in ["preinstall", "postinstall", "install", "prepare"]:
                        script = scripts.get(hook, "")
                        if script:
                            for pat in NPM_MALICIOUS_PATTERNS:
                                if re.search(pat, script):
                                    verdict.threats.append("MALICIOUS " + hook.upper() + ": " + script[:100])

                for root, _, scan_files in os.walk(extract_dir):
                    for f in scan_files:
                        if not f.endswith((".js", ".mjs", ".cjs")):
                            continue
                        fp = os.path.join(root, f)
                        try:
                            if os.path.getsize(fp) > 500_000:
                                continue
                            with open(fp, "r", errors="ignore") as fh:
                                code = fh.read()
                            for pat in NPM_MALICIOUS_PATTERNS:
                                if re.search(pat, code):
                                    verdict.threats.append("SUSPICIOUS in " + f)
                        except Exception:
                            pass
        except Exception:
            verdict.threats.append("SCAN_FAILED: Could not complete deep scan")

    # ── Manifest ─────────────────────────────────────────────────────────

    def scan_manifest(self, path: str) -> ManifestReport:
        ecosystem = self._detect_ecosystem(path)
        parsers = {
            Ecosystem.PYTHON: self._scan_python_manifest,
            Ecosystem.NODEJS: self._scan_npm_manifest,
            Ecosystem.RUBY: self._scan_ruby_manifest,
            Ecosystem.RUST: self._scan_rust_manifest,
            Ecosystem.GO: self._scan_go_manifest,
            Ecosystem.JAVA: self._scan_java_manifest,
            Ecosystem.PHP: self._scan_php_manifest,
            Ecosystem.DOCKER: self._scan_dockerfile,
        }
        parser = parsers.get(ecosystem)
        if parser:
            return parser(path)
        return ManifestReport(manifest_path=path, ecosystem=ecosystem)

    def _detect_ecosystem(self, path: str) -> Ecosystem:
        bn = os.path.basename(path).lower()
        # Check by file extension and content patterns
        if bn.endswith(("requirements.txt",)) or bn in ("setup.py", "setup.cfg", "pyproject.toml", "pipfile", "pipfile.lock"):
            return Ecosystem.PYTHON
        elif bn.endswith((".txt",)) and "require" in bn:
            return Ecosystem.PYTHON
        elif bn.endswith("package.json") or bn.endswith("package-lock.json") or bn in ("yarn.lock", "pnpm-lock.yaml"):
            return Ecosystem.NODEJS
        elif "cargo.toml" in bn or "cargo.lock" in bn:
            return Ecosystem.RUST
        elif "gemfile" in bn:
            return Ecosystem.RUBY
        elif bn.endswith("go.mod") or bn.endswith("go.sum"):
            return Ecosystem.GO
        elif bn.endswith("pom.xml") or bn.endswith("build.gradle") or bn.endswith("build.gradle.kts"):
            return Ecosystem.JAVA
        elif "composer.json" in bn or "composer.lock" in bn:
            return Ecosystem.PHP
        elif bn.startswith("dockerfile") or bn == "dockerfile":
            return Ecosystem.DOCKER
        # Fallback: try to detect from content
        try:
            with open(path) as f:
                first_line = f.readline(200)
            if first_line.strip().startswith("{"):
                # JSON file — check if it looks like package.json
                with open(path) as f:
                    data = json.load(f)
                if any(k in data for k in ("dependencies", "devDependencies", "scripts")):
                    return Ecosystem.NODEJS
                if any(k in data for k in ("require", "require-dev")):
                    return Ecosystem.PHP
        except Exception:
            pass
        return Ecosystem.PYTHON

    def _scan_python_manifest(self, path: str) -> ManifestReport:
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.PYTHON)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        for line in content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "://" in line:
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*[><=~!]*\s*=?\s*([^\s;#,\[]*)", line)
            if match:
                pkg = match.group(1).lower()
                ver = match.group(2) or ""
                report.total_packages += 1
                threat = self.threat_feed.check(pkg, ver, Ecosystem.PYTHON)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.PYTHON,
                        verdict=Verdict.BLOCK,
                        threats=["KNOWN COMPROMISED: " + threat.description],
                        recommendation="Use " + threat.safe_version,
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_npm_manifest(self, path: str) -> ManifestReport:
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.NODEJS)
        bn = os.path.basename(path).lower()
        if bn in ("yarn.lock", "pnpm-lock.yaml"):
            # These formats require dedicated parsers not yet implemented
            report.verdicts.append(ScanVerdict(
                package="<lockfile>", version="", ecosystem=Ecosystem.NODEJS,
                verdict=Verdict.REVIEW,
                threats=["UNSUPPORTED FORMAT: " + bn + " — use package.json instead"],
                recommendation="Scan package.json for threat detection",
            ))
            report.review = 1
            report.overall_verdict = Verdict.REVIEW
            return report
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return report

        # Handle package-lock.json v3 format (npm 7+) which uses "packages" key
        if "packages" in data and data.get("lockfileVersion", 0) >= 3:
            packages_map = data.get("packages", {})
            for pkg_path, pkg_info in packages_map.items():
                if not pkg_path or pkg_path == "":
                    continue  # Skip root entry
                # Extract package name from path like "node_modules/event-stream"
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else ""
                if not name:
                    continue
                ver = pkg_info.get("version", "")
                report.total_packages += 1
                threat = self.threat_feed.check(name, ver, Ecosystem.NODEJS)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=name, version=ver, ecosystem=Ecosystem.NODEJS,
                        verdict=Verdict.BLOCK,
                        threats=["KNOWN COMPROMISED: " + threat.description],
                        recommendation="Use " + threat.safe_version,
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1
            report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
            return report

        all_deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            all_deps.update(data.get(key, {}))

        for pkg, ver_spec in all_deps.items():
            report.total_packages += 1
            if isinstance(ver_spec, dict):
                ver = ver_spec.get("version", "")
            else:
                ver = ver_spec.lstrip("^~>=<! ")
            threat = self.threat_feed.check(pkg, ver, Ecosystem.NODEJS)
            if threat:
                report.verdicts.append(ScanVerdict(
                    package=pkg, version=ver, ecosystem=Ecosystem.NODEJS,
                    verdict=Verdict.BLOCK,
                    threats=["KNOWN COMPROMISED: " + threat.description],
                    recommendation="Use " + threat.safe_version,
                ))
                report.blocked += 1
            else:
                report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_ruby_manifest(self, path: str) -> ManifestReport:
        """Parse Gemfile or Gemfile.lock for compromised gems."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.RUBY)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        bn = os.path.basename(path).lower()
        if bn == "gemfile.lock":
            # Parse Gemfile.lock — lines like "    rest-client (1.6.13)"
            for line in content.splitlines():
                m = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
                if m:
                    pkg, ver = m.group(1).lower(), m.group(2)
                    report.total_packages += 1
                    threat = self.threat_feed.check(pkg, ver, Ecosystem.RUBY)
                    if threat:
                        report.verdicts.append(ScanVerdict(
                            package=pkg, version=ver, ecosystem=Ecosystem.RUBY,
                            verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                            recommendation="Use " + threat.safe_version,
                        ))
                        report.blocked += 1
                    else:
                        report.clean += 1
        else:
            # Parse Gemfile — lines like: gem 'rest-client', '~> 1.6.13'
            for line in content.splitlines():
                m = re.match(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?""", line)
                if m:
                    pkg = m.group(1).lower()
                    ver = (m.group(2) or "").lstrip("~>=<! ")
                    report.total_packages += 1
                    threat = self.threat_feed.check(pkg, ver, Ecosystem.RUBY)
                    if threat:
                        report.verdicts.append(ScanVerdict(
                            package=pkg, version=ver or "unpinned", ecosystem=Ecosystem.RUBY,
                            verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                            recommendation="Use " + threat.safe_version,
                        ))
                        report.blocked += 1
                    else:
                        report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_rust_manifest(self, path: str) -> ManifestReport:
        """Parse Cargo.toml or Cargo.lock for compromised crates."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.RUST)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        bn = os.path.basename(path).lower()
        if bn == "cargo.lock":
            # Parse Cargo.lock — blocks like: name = "rustdecimal"\nversion = "1.23.1"
            current_name = ""
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("name = "):
                    current_name = line.split('"')[1].lower() if '"' in line else ""
                elif line.startswith("version = ") and current_name:
                    ver = line.split('"')[1] if '"' in line else ""
                    report.total_packages += 1
                    threat = self.threat_feed.check(current_name, ver, Ecosystem.RUST)
                    if threat:
                        report.verdicts.append(ScanVerdict(
                            package=current_name, version=ver, ecosystem=Ecosystem.RUST,
                            verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                            recommendation="Use " + threat.safe_version,
                        ))
                        report.blocked += 1
                    else:
                        report.clean += 1
                    current_name = ""
        else:
            # Parse Cargo.toml [dependencies] section
            in_deps = False
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("[") and "dependencies" in line.lower():
                    in_deps = True
                    continue
                elif line.startswith("["):
                    in_deps = False
                    continue
                if in_deps and "=" in line:
                    parts = line.split("=", 1)
                    pkg = parts[0].strip().lower().strip('"')
                    ver_raw = parts[1].strip().strip('"').strip("'")
                    # Handle version = "1.0" or version = {version = "1.0"}
                    ver_match = re.search(r"(\d+\.\d+\.\d+)", ver_raw)
                    ver = ver_match.group(1) if ver_match else ""
                    report.total_packages += 1
                    threat = self.threat_feed.check(pkg, ver, Ecosystem.RUST)
                    if threat:
                        report.verdicts.append(ScanVerdict(
                            package=pkg, version=ver or "unpinned", ecosystem=Ecosystem.RUST,
                            verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                        ))
                        report.blocked += 1
                    else:
                        report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_go_manifest(self, path: str) -> ManifestReport:
        """Parse go.mod or go.sum for compromised Go modules."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.GO)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        # go.mod: require ( \n\t github.com/foo/bar v1.2.3 \n )
        # go.sum: github.com/foo/bar v1.2.3 h1:...
        in_require = False
        in_exclude = False
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            # Track block context
            if line.startswith("require ") and "(" not in line:
                # Single-line require: "require github.com/foo/bar v1.2.3"
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    m = re.match(r"^(\S+)\s+v?(\d+\.\d+\.\d+)", parts[1] + " " + parts[2])
                    if m:
                        pkg = m.group(1).lower()
                        ver = m.group(2)
                        report.total_packages += 1
                        threat = self.threat_feed.check(pkg, ver, Ecosystem.GO)
                        if threat:
                            report.verdicts.append(ScanVerdict(
                                package=pkg, version=ver, ecosystem=Ecosystem.GO,
                                verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                            ))
                            report.blocked += 1
                        else:
                            report.clean += 1
                continue
            if line.startswith("require ("):
                in_require = True
                in_exclude = False
                continue
            if line.startswith(("exclude ", "exclude (", "retract ", "retract (", "replace ", "replace (")):
                in_exclude = True
                in_require = False
                continue
            if line == ")":
                in_require = False
                in_exclude = False
                continue
            if line.startswith("module ") or line.startswith("go ") or line.startswith("toolchain "):
                continue
            if in_exclude:
                continue
            if "/go.mod " in line:
                continue
            m = re.match(r"^(\S+)\s+v?(\d+\.\d+\.\d+)", line)
            if m:
                pkg = m.group(1).lower()
                ver = m.group(2)
                report.total_packages += 1
                threat = self.threat_feed.check(pkg, ver, Ecosystem.GO)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.GO,
                        verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_java_manifest(self, path: str) -> ManifestReport:
        """Parse pom.xml or build.gradle for compromised Java packages."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.JAVA)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        bn = os.path.basename(path).lower()
        if bn.endswith("pom.xml"):
            # Parse Maven pom.xml — extract groupId:artifactId and version
            # Simple regex-based parsing (no XML library needed = zero deps)
            deps = re.findall(
                r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<[^/][^>]*>[^<]*</[^>]+>)*\s*<version>([^<]+)</version>",
                content, re.DOTALL,
            )
            for group_id, artifact_id, ver in deps:
                pkg = (group_id + ":" + artifact_id).lower()
                report.total_packages += 1
                threat = self.threat_feed.check(pkg, ver, Ecosystem.JAVA)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.JAVA,
                        verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1
        else:
            # Parse build.gradle — lines like: implementation 'group:artifact:version'
            deps = re.findall(
                r"""(?:implementation|api|compile|runtime)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
                content,
            )
            for group_id, artifact_id, ver in deps:
                pkg = (group_id + ":" + artifact_id).lower()
                report.total_packages += 1
                threat = self.threat_feed.check(pkg, ver, Ecosystem.JAVA)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.JAVA,
                        verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_php_manifest(self, path: str) -> ManifestReport:
        """Parse composer.json or composer.lock for compromised PHP packages."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.PHP)
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return report

        bn = os.path.basename(path).lower()
        if bn == "composer.lock":
            packages = data.get("packages", []) + data.get("packages-dev", [])
            for pkg_data in packages:
                pkg = pkg_data.get("name", "").lower()
                ver = pkg_data.get("version", "").lstrip("v")
                report.total_packages += 1
                threat = self.threat_feed.check(pkg, ver, Ecosystem.PHP)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.PHP,
                        verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1
        else:
            all_deps = {}
            for key in ("require", "require-dev"):
                all_deps.update(data.get(key, {}))
            for pkg, ver_spec in all_deps.items():
                if pkg == "php" or pkg.startswith("ext-"):
                    continue
                report.total_packages += 1
                ver = ver_spec.lstrip("^~>=<! ").split(",")[0].split("|")[0].strip()
                threat = self.threat_feed.check(pkg.lower(), ver, Ecosystem.PHP)
                if threat:
                    report.verdicts.append(ScanVerdict(
                        package=pkg, version=ver, ecosystem=Ecosystem.PHP,
                        verdict=Verdict.BLOCK, threats=["KNOWN COMPROMISED: " + threat.description],
                    ))
                    report.blocked += 1
                else:
                    report.clean += 1

        report.overall_verdict = Verdict.BLOCK if report.blocked > 0 else Verdict.ALLOW
        return report

    def _scan_dockerfile(self, path: str) -> ManifestReport:
        """Scan Dockerfile for compromised base images and risky patterns."""
        report = ManifestReport(manifest_path=path, ecosystem=Ecosystem.DOCKER)
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return report

        for line in content.splitlines():
            line = line.strip()
            if line.upper().startswith("FROM "):
                image = line.split()[1] if len(line.split()) > 1 else ""
                report.total_packages += 1
                # Check for unpinned images (no digest)
                if "@sha256:" not in image and ":" not in image:
                    report.verdicts.append(ScanVerdict(
                        package=image, version="latest (unpinned)", ecosystem=Ecosystem.DOCKER,
                        verdict=Verdict.REVIEW,
                        threats=["UNPINNED IMAGE: " + image + " — use a specific tag or digest"],
                        recommendation="Pin to a specific version or sha256 digest",
                    ))
                    report.review += 1
                elif ":latest" in image:
                    report.verdicts.append(ScanVerdict(
                        package=image, version="latest", ecosystem=Ecosystem.DOCKER,
                        verdict=Verdict.REVIEW,
                        threats=["LATEST TAG: " + image + " — mutable, can change without notice"],
                        recommendation="Pin to a specific version tag",
                    ))
                    report.review += 1
                else:
                    report.clean += 1

            # Check for dangerous patterns
            if line.upper().startswith("RUN "):
                cmd = line[4:].strip()
                # Piping curl/wget to shell
                if re.search(r"(curl|wget)\s+.*\|\s*(bash|sh|python|perl)", cmd):
                    report.verdicts.append(ScanVerdict(
                        package="[RUN instruction]", version="", ecosystem=Ecosystem.DOCKER,
                        verdict=Verdict.BLOCK,
                        threats=["PIPE TO SHELL: " + cmd[:100] + " — remote code execution risk"],
                    ))
                    report.blocked += 1

        if report.blocked > 0:
            report.overall_verdict = Verdict.BLOCK
        elif report.review > 0:
            report.overall_verdict = Verdict.REVIEW
        return report

    # ── Safe Install ─────────────────────────────────────────────────────

    def safe_install(self, package: str, version: str = "",
                     ecosystem: Ecosystem = Ecosystem.PYTHON) -> bool:
        verdict = self.scan_before_install(package, version, ecosystem)
        if verdict.verdict == Verdict.BLOCK:
            return False
        if ecosystem == Ecosystem.PYTHON:
            spec = package + ("==" + version if version else "")
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "install", spec],
                capture_output=True, text=True, timeout=300,
            )
            return proc.returncode == 0
        elif ecosystem == Ecosystem.NODEJS:
            spec = package + ("@" + version if version else "")
            proc = subprocess.run(["npm", "install", spec], capture_output=True, text=True, timeout=300)
            return proc.returncode == 0
        return False

    # ── Ghost Gap ────────────────────────────────────────────────────────

    def ghost_gap_assess(self) -> GhostGapResult:
        """Am I safe? Checks for ghosts left by past infections."""
        result = GhostGapResult()
        home = str(Path.home())

        # Check installed version
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "show", "litellm"],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.split("\n"):
                if line.startswith("Version:"):
                    ver = line.split(":")[1].strip()
                    litellm_threat = self.threat_feed.get_threat("litellm", Ecosystem.PYTHON)
                    if litellm_threat and ver in litellm_threat.bad_versions:
                        result.compromised_version = ver
                        result.infected = True
                        result.safe = False
        except Exception:
            pass

        # Check persistence from ALL known threats
        for record in self.threat_feed.list_all():
            for path in record.persistence_paths:
                expanded = os.path.expanduser(path)
                if os.path.exists(expanded):
                    result.persistence_artifacts.append(expanded)
                    result.infected = True
                    result.safe = False

            # Check IOCs in Python paths
            for ioc in record.iocs:
                for sp in sys.path:
                    if not os.path.isdir(sp):
                        continue
                    target = os.path.join(sp, ioc)
                    if os.path.exists(target) and not os.path.abspath(target).startswith(SELF_DIR):
                        result.backdoor_files.append(target)
                        result.infected = True
                        result.safe = False

        # Generic persistence
        for pattern in ["/tmp/sysmon*", "/tmp/.cloud_sync*", "/tmp/.teampcp*",
                        home + "/.local/bin/sysmon", home + "/.cache/sysmon"]:
            for match in _glob.glob(pattern):
                if os.path.exists(match):
                    result.persistence_artifacts.append(match)
                    result.infected = True
                    result.safe = False

        # .pth file persistence (auto-executed on EVERY Python startup)
        # litellm 1.82.8 dropped litellm_init.pth which runs malicious code
        # every time Python starts — even after pip uninstall
        for sp in sys.path:
            if not os.path.isdir(sp):
                continue
            for pth_file in _glob.glob(os.path.join(sp, "*.pth")):
                basename = os.path.basename(pth_file)
                # Known malicious .pth files
                if basename in ("litellm_init.pth",):
                    result.backdoor_files.append(pth_file)
                    result.infected = True
                    result.safe = False
                    continue
                # Scan any .pth for suspicious content
                try:
                    with open(pth_file, "r", errors="ignore") as fh:
                        content = fh.read()
                    c2_domains = ["models.litellm.cloud", "checkmarx.zone"]
                    for c2 in c2_domains:
                        if c2 in content:
                            result.backdoor_files.append(pth_file)
                            result.infected = True
                            result.safe = False
                            break
                except Exception:
                    pass

        # Check for C2 domains in DNS cache / network connections
        try:
            c2_domains = ["models.litellm.cloud", "checkmarx.zone"]
            # Check /etc/hosts for C2 (attacker may have added entries)
            hosts_file = "/etc/hosts"
            if os.path.exists(hosts_file):
                with open(hosts_file, "r") as fh:
                    hosts_content = fh.read()
                for c2 in c2_domains:
                    if c2 in hosts_content:
                        result.persistence_artifacts.append("/etc/hosts: " + c2)
                        result.infected = True
                        result.safe = False
        except Exception:
            pass

        # Kubernetes
        try:
            proc = subprocess.run(
                ["kubectl", "get", "pods", "-n", "kube-system", "-o", "json"],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                pods = json.loads(proc.stdout)
                known = {"coredns", "kube-proxy", "kube-apiserver", "kube-controller-manager",
                         "kube-scheduler", "etcd", "aws-node", "ebs-csi", "metrics-server",
                         "calico", "flannel", "cilium", "weave", "vpc-cni",
                         "aws-load-balancer-controller"}
                suspicious = ["sysmon", "monitor", "collect", "sync", "pcp", "exfil", "stealer"]
                for pod in pods.get("items", []):
                    name = pod.get("metadata", {}).get("name", "")
                    if not any(k in name.lower() for k in known):
                        if any(s in name.lower() for s in suspicious):
                            result.rogue_k8s_pods.append(name)
                            result.infected = True
                            result.safe = False
        except Exception:
            pass

        # Exposed credentials
        for pattern in CREDENTIAL_PATHS:
            for match in _glob.glob(os.path.expanduser(pattern)):
                if os.path.exists(match):
                    result.exposed_credentials.append(match)

        # Count sensitive env vars (names not exposed to avoid recon)
        sensitive_count = 0
        for key in os.environ:
            ku = key.upper()
            if any(s in ku for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH", "CREDENTIAL", "PRIVATE"]):
                sensitive_count += 1
        if sensitive_count > 0:
            result.exposed_env_vars.append(str(sensitive_count) + " sensitive environment variables present")

        return result

    # ── Cure ─────────────────────────────────────────────────────────────

    def cure(self, package: str = "litellm") -> CureResult:
        """Cure an active infection: remove backdoor, clean persistence, rotate credentials.

        This is the Ghost Gap closer. Updating to a clean version doesn't undo the damage.
        This method finds what the patch missed and fixes it.
        """
        result = CureResult()
        home = str(Path.home())
        threat = self.threat_feed.get_threat(package, Ecosystem.PYTHON)

        # ── Detect ───────────────────────────────────────────────────────
        # Check installed version
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "show", package],
                capture_output=True, text=True, timeout=10,
            )
            current_version = ""
            for line in proc.stdout.split("\n"):
                if line.startswith("Version:"):
                    current_version = line.split(":")[1].strip()

            if threat and current_version in threat.bad_versions:
                result.was_infected = True
        except Exception:
            pass

        # Scan for backdoor files (.py files AND .pth persistence)
        backdoor_files = []
        if threat:
            for sp in sys.path:
                if not os.path.isdir(sp):
                    continue

                # Check for .pth persistence (litellm_init.pth — auto-runs on Python startup)
                for pth_file in _glob.glob(os.path.join(sp, "*.pth")):
                    basename = os.path.basename(pth_file)
                    if basename in threat.iocs:
                        backdoor_files.append(pth_file)
                        result.was_infected = True
                    else:
                        # Check .pth content for C2 domains
                        try:
                            with open(pth_file, "r", errors="ignore") as fh:
                                pth_content = fh.read()
                            for sig in threat.backdoor_signatures:
                                if sig in pth_content:
                                    backdoor_files.append(pth_file)
                                    result.was_infected = True
                                    break
                        except Exception:
                            pass

                # Walk for .py backdoor files
                for root, _, files in os.walk(sp):
                    if root.count(os.sep) - sp.count(os.sep) > 5:
                        continue
                    for f in files:
                        if not f.endswith(".py"):
                            continue
                        fp = os.path.join(root, f)
                        if os.path.abspath(fp).startswith(SELF_DIR):
                            continue
                        # Check filename against IOCs
                        if f in threat.iocs:
                            backdoor_files.append(fp)
                            result.was_infected = True
                            continue
                        # Check content against signatures (including C2 domains)
                        try:
                            if os.path.getsize(fp) > 500000:
                                continue
                            with open(fp, "rb") as fh:
                                content = fh.read()
                            for sig in threat.backdoor_signatures:
                                if sig.encode() in content:
                                    backdoor_files.append(fp)
                                    result.was_infected = True
                                    break
                        except Exception:
                            pass

        # Check persistence
        persistence_found = []
        if threat:
            for path in threat.persistence_paths:
                expanded = os.path.expanduser(path)
                if os.path.exists(expanded):
                    persistence_found.append(expanded)
                    result.was_infected = True

        # Generic persistence
        for pattern in ["/tmp/sysmon*", "/tmp/.sysmon*", "/tmp/.cloud_sync*",
                        "/tmp/.teampcp*", "/tmp/.litellm_*",
                        home + "/.local/bin/sysmon", home + "/.cache/sysmon",
                        home + "/.config/systemd/user/sysmon*",
                        "/etc/systemd/system/sysmon*",
                        home + "/Library/LaunchAgents/com.sysmon*",
                        home + "/Library/LaunchAgents/com.cloud.monitor*"]:
            for match in _glob.glob(os.path.expanduser(pattern)):
                if os.path.exists(match):
                    persistence_found.append(match)
                    result.was_infected = True

        # ── Remove ───────────────────────────────────────────────────────
        # Delete backdoor files
        for f in backdoor_files:
            try:
                if os.path.islink(f):
                    os.unlink(f)
                elif os.path.isdir(f):
                    shutil.rmtree(f)
                else:
                    os.remove(f)
                result.backdoor_files_removed.append(f)
            except Exception:
                pass

        # Delete persistence
        for f in persistence_found:
            try:
                if os.path.islink(f):
                    os.unlink(f)
                elif os.path.isdir(f):
                    shutil.rmtree(f)
                else:
                    os.remove(f)
                result.persistence_cleaned.append(f)
            except Exception:
                pass

        # Clean crontab
        try:
            proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                clean_lines = []
                removed = False
                for line in proc.stdout.split("\n"):
                    if any(s in line.lower() for s in ["sysmon", "cloud_steal", "teampcp", "exfil"]):
                        removed = True
                    else:
                        clean_lines.append(line)
                if removed:
                    subprocess.run(["crontab", "-"], input="\n".join(clean_lines),
                                   capture_output=True, text=True, timeout=5)
                    result.persistence_cleaned.append("crontab")
        except Exception:
            pass

        # Reinstall clean version
        if threat and result.was_infected and threat.safe_version not in ("N/A", ""):
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--force-reinstall",
                 package + "==" + threat.safe_version],
                capture_output=True, text=True, timeout=120,
            )
            result.version_fixed = proc.returncode == 0

        # Kill rogue K8s pods
        try:
            proc = subprocess.run(
                ["kubectl", "get", "pods", "-n", "kube-system", "-o", "json"],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                pods = json.loads(proc.stdout)
                known = {"coredns", "kube-proxy", "kube-apiserver", "kube-controller-manager",
                         "kube-scheduler", "etcd", "aws-node", "ebs-csi", "metrics-server",
                         "calico", "flannel", "cilium", "weave", "vpc-cni",
                         "aws-load-balancer-controller"}
                suspicious = ["sysmon", "pcp", "exfil", "stealer", "cloud_steal"]
                for pod in pods.get("items", []):
                    name = pod.get("metadata", {}).get("name", "")
                    if not any(k in name.lower() for k in known):
                        if any(s in name.lower() for s in suspicious):
                            result.rogue_pods_detected.append(name)
        except Exception:
            pass

        # ── Rotate Credentials ───────────────────────────────────────────
        if result.was_infected:
            result.credentials_rotated = self._rotate_all(home)

        # ── Verify ───────────────────────────────────────────────────────
        gap = self.ghost_gap_assess()
        result.system_clean = gap.safe

        return result

    def _rotate_all(self, home: str) -> Dict[str, bool]:
        """Rotate all compromised credentials."""
        rotated = {}

        # SSH
        ssh_dir = home + "/.ssh"
        if os.path.exists(ssh_dir) and _glob.glob(ssh_dir + "/id_*"):
            backup = ssh_dir + "/COMPROMISED_" + str(int(time.time()))
            os.makedirs(backup, exist_ok=True)
            for f in _glob.glob(ssh_dir + "/id_*"):
                shutil.copy2(f, backup + "/" + os.path.basename(f))
            proc = subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", ssh_dir + "/id_ed25519_rotated",
                 "-N", "", "-C", "rotated-by-ghostgap"],
                capture_output=True, text=True, timeout=10,
            )
            rotated["SSH"] = proc.returncode == 0

        # AWS
        try:
            proc = subprocess.run(["aws", "sts", "get-caller-identity"],
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                identity = json.loads(proc.stdout)
                arn = identity.get("Arn", "")
                username = arn.split("/")[-1] if "/" in arn else ""
                if username and not arn.endswith(":root"):
                    proc2 = subprocess.run(
                        ["aws", "iam", "create-access-key", "--user-name", username],
                        capture_output=True, text=True, timeout=10,
                    )
                    if proc2.returncode == 0:
                        new_key = json.loads(proc2.stdout).get("AccessKey", {})
                        creds_file = home + "/.aws/credentials"
                        if os.path.exists(creds_file):
                            shutil.copy2(creds_file, creds_file + ".compromised_backup")
                        fd = os.open(creds_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "w") as f:
                            f.write("[default]\n")
                            f.write("aws_access_key_id = " + new_key.get("AccessKeyId", "") + "\n")
                            f.write("aws_secret_access_key = " + new_key.get("SecretAccessKey", "") + "\n")
                        rotated["AWS"] = True
                    else:
                        rotated["AWS"] = False
                else:
                    rotated["AWS"] = False
        except Exception:
            rotated["AWS"] = False

        # GCP
        adc = home + "/.config/gcloud/application_default_credentials.json"
        if os.path.exists(adc):
            shutil.copy2(adc, adc + ".compromised_backup")
            os.remove(adc)
            rotated["GCP (revoked — re-auth required)"] = True

        # Azure
        azure_dir = home + "/.azure"
        if os.path.exists(azure_dir) and not os.path.islink(azure_dir):
            backup = azure_dir + "_compromised_" + str(int(time.time()))
            shutil.copytree(azure_dir, backup, symlinks=True)
            for f in _glob.glob(azure_dir + "/*.json"):
                os.remove(f)
            rotated["Azure"] = True

        # K8s
        kube = home + "/.kube/config"
        if os.path.exists(kube):
            shutil.copy2(kube, kube + ".compromised_backup")
            rotated["K8s (backed up — re-gen required)"] = True

        # Git
        git_creds = home + "/.git-credentials"
        if os.path.exists(git_creds):
            shutil.copy2(git_creds, git_creds + ".compromised_backup")
            os.remove(git_creds)
            rotated["Git (revoked — re-auth required)"] = True

        # GitHub CLI
        gh = home + "/.config/gh/hosts.yml"
        if os.path.exists(gh):
            shutil.copy2(gh, gh + ".compromised_backup")
            os.remove(gh)
            rotated["GitHub CLI (revoked — re-auth required)"] = True

        # Docker
        docker_cfg = home + "/.docker/config.json"
        if os.path.exists(docker_cfg):
            shutil.copy2(docker_cfg, docker_cfg + ".compromised_backup")
            try:
                with open(docker_cfg) as f:
                    cfg = json.load(f)
                if "auths" in cfg:
                    cfg["auths"] = {}
                    fd = os.open(docker_cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as f:
                        json.dump(cfg, f, indent=2)
                    rotated["Docker"] = True
            except Exception:
                pass

        # HuggingFace
        for hf in [home + "/.cache/huggingface/token", home + "/.huggingface/token"]:
            if os.path.exists(hf):
                os.remove(hf)
                rotated["HuggingFace (revoked)"] = True

        # Terraform
        tf = home + "/.terraform.d/credentials.tfrc.json"
        if os.path.exists(tf):
            os.remove(tf)
            rotated["Terraform (revoked)"] = True

        return rotated

    # ── CI/CD Gate ────────────────────────────────────────────────────────

    def ci_gate(self, manifest_path: str) -> int:
        report = self.scan_manifest(manifest_path)
        return 1 if report.overall_verdict == Verdict.BLOCK else 0

    # ── Scan Installed Packages ─────────────────────────────────────────

    def scan_installed(self) -> List[ScanVerdict]:
        """Scan ALL currently installed Python packages against the threat feed.

        This catches transitive dependencies — if dspy or an agent framework
        pulled in litellm==1.82.7, this will find it.
        """
        hits = []
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return hits
            packages = json.loads(proc.stdout)
            for pkg in packages:
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")
                threat = self.threat_feed.check(name, version, Ecosystem.PYTHON)
                if threat:
                    hits.append(ScanVerdict(
                        package=name, version=version,
                        ecosystem=Ecosystem.PYTHON, verdict=Verdict.BLOCK,
                        threats=["INSTALLED AND COMPROMISED: " + threat.description],
                        threat_category=threat.threat_category,
                        recommendation="Immediately run: ghostgap cure " + name,
                    ))
        except Exception as e:
            hits.append(ScanVerdict(
                package="<scan-all>", version="", ecosystem=Ecosystem.PYTHON,
                verdict=Verdict.REVIEW,
                threats=["SCAN_FAILED: Could not list installed packages — " + str(e)],
                recommendation="Run 'pip list' manually to verify",
            ))
        return hits

    # ── Deep Filesystem Scan ─────────────────────────────────────────────

    def deep_scan_filesystem(self) -> List[Dict]:
        """Scan ALL Python environments on this machine for compromised packages.

        Unlike sys.path (which only sees the current env), this finds:
        - Homebrew Python
        - pyenv versions
        - conda/miniconda environments
        - virtualenvs and .venvs
        - pipx installations
        - System Python
        - User installs

        SAFETY NOTE: This uses subprocess + find instead of walking Python paths,
        because running Python code on an infected machine auto-loads malicious
        .pth files from site-packages. By using `find` we avoid triggering them.
        """
        hits = []
        # Use system find to locate dist-info dirs without loading Python
        search_roots = ["/usr/lib", "/usr/local/lib"]
        home = str(Path.home())
        search_roots.extend([
            home + "/.local/lib",
            home + "/.pyenv",
            home + "/.conda",
            home + "/miniconda3",
            home + "/anaconda3",
            home + "/.local/share/pipx",
        ])
        # Also check common virtualenv locations
        for venv_pattern in [home + "/*/venv", home + "/*/.venv",
                              home + "/*/env", home + "/*/*/venv",
                              home + "/*/*/.venv"]:
            search_roots.extend(_glob.glob(venv_pattern))

        # Platform-specific
        if sys.platform == "darwin":
            search_roots.extend([
                "/opt/homebrew/lib",
                "/usr/local/Cellar",
                "/Library/Python",
                home + "/Library/Python",
            ])
        elif sys.platform == "linux":
            search_roots.extend([
                "/opt/conda", "/opt/venv",
            ])

        for root in search_roots:
            if not os.path.isdir(root):
                continue

            try:
                proc = subprocess.run(
                    ["find", root, "-maxdepth", "8", "-type", "d", "-name", "*.dist-info"],
                    capture_output=True, text=True, timeout=30,
                )
                for dist_dir in proc.stdout.strip().splitlines():
                    if not dist_dir:
                        continue
                    dirname = os.path.basename(dist_dir)
                    # Parse package name and version from dirname
                    # Format: litellm-1.82.7.dist-info
                    name_ver = dirname.replace(".dist-info", "")
                    parts = name_ver.rsplit("-", 1)
                    if len(parts) != 2:
                        continue
                    pkg_name, pkg_version = parts[0].lower(), parts[1]

                    # Check against threat feed
                    threat = self.threat_feed.check(pkg_name, pkg_version, Ecosystem.PYTHON)
                    if threat:
                        # Classify the environment
                        env_type = "unknown"
                        path_lower = dist_dir.lower()
                        if "homebrew" in path_lower or "cellar" in path_lower:
                            env_type = "homebrew"
                        elif "pyenv" in path_lower:
                            env_type = "pyenv"
                        elif "conda" in path_lower or "miniconda" in path_lower:
                            env_type = "conda"
                        elif "pipx" in path_lower:
                            env_type = "pipx"
                        elif "venv" in path_lower or ".venv" in path_lower:
                            env_type = "virtualenv"
                        elif "/Library/Python" in dist_dir:
                            env_type = "system-user" if "/Users/" in dist_dir else "system"
                        elif dist_dir.startswith("/usr/local"):
                            env_type = "usr-local"

                        hits.append({
                            "package": pkg_name,
                            "version": pkg_version,
                            "path": dist_dir,
                            "env_type": env_type,
                            "threat": threat.threat_category.value,
                            "actor": threat.actor,
                            "safe_version": threat.safe_version,
                        })

                    # Also check for .pth persistence in the same site-packages
                    site_packages = os.path.dirname(dist_dir)
                    for pth in _glob.glob(os.path.join(site_packages, "*.pth")):
                        pth_name = os.path.basename(pth)
                        # Check if it's a known malicious .pth
                        for record in self.threat_feed.list_all():
                            if pth_name in record.iocs:
                                hits.append({
                                    "package": "[.pth persistence]",
                                    "version": pth_name,
                                    "path": pth,
                                    "env_type": env_type if 'env_type' in locals() else "unknown",
                                    "threat": "persistence",
                                    "actor": record.actor,
                                    "safe_version": "delete this file",
                                })
            except Exception:
                continue

        return hits

    # ── CI/CD Pipeline Scan ──────────────────────────────────────────────

    def scan_ci_github(self, org: str, token: str,
                       window_hours: int = 24) -> List[Dict]:
        """Scan GitHub Actions workflow runs for compromised package installs.

        Requires: GITHUB_TOKEN with repo/actions:read scope.

        Args:
            org: GitHub organization name
            token: GitHub personal access token
            window_hours: How far back to scan (default 24h)

        Returns:
            List of hits with repo, job, version, and log context.
        """
        import urllib.request
        from datetime import datetime, timezone, timedelta

        hits = []
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=window_hours)

        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Build per-package bad version map for all Python threats
        bad_versions_by_pkg: Dict[str, Set[str]] = {}
        pkg_names: Set[str] = set()
        for record in self.threat_feed.list_all():
            if record.ecosystem == Ecosystem.PYTHON:
                pkg_names.add(record.package)
                for v in record.bad_versions:
                    bad_versions_by_pkg.setdefault(record.package.lower(), set()).add(v)

        if not pkg_names:
            return hits
        pattern_str = "(" + "|".join(re.escape(p) for p in sorted(pkg_names)) + r")[=\- ]+(\d+\.\d+\.\d+)"
        version_pattern = re.compile(pattern_str, re.IGNORECASE)

        if not re.match(r'^[A-Za-z0-9_.-]+$', org):
            return hits

        # Get repos
        try:
            url = "https://api.github.com/orgs/" + org + "/repos?per_page=100&type=all"
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=30)
            repos = json.loads(resp.read())
        except Exception:
            return hits  # Swallow to prevent token leakage in tracebacks

        for repo in repos:
            full_name = repo.get("full_name", "")
            try:
                # Get recent workflow runs
                created_filter = window_start.strftime("%Y-%m-%dT%H:%M:%SZ") + ".." + now.strftime("%Y-%m-%dT%H:%M:%SZ")
                url = ("https://api.github.com/repos/" + full_name +
                       "/actions/runs?created=" + created_filter + "&per_page=50")
                req = urllib.request.Request(url, headers=headers)
                resp = urllib.request.urlopen(req, timeout=30)
                data = json.loads(resp.read())
                runs = data.get("workflow_runs", [])

                for run in runs:
                    run_id = run.get("id")
                    # Get jobs for this run
                    url = ("https://api.github.com/repos/" + full_name +
                           "/actions/runs/" + str(run_id) + "/jobs?per_page=100")
                    req = urllib.request.Request(url, headers=headers)
                    resp = urllib.request.urlopen(req, timeout=30)
                    jobs_data = json.loads(resp.read())

                    for job in jobs_data.get("jobs", []):
                        job_id = job.get("id")
                        # Fetch job log
                        try:
                            url = ("https://api.github.com/repos/" + full_name +
                                   "/actions/jobs/" + str(job_id) + "/logs")
                            req = urllib.request.Request(url, headers=headers)
                            resp = urllib.request.urlopen(req, timeout=60)
                            log_text = resp.read().decode("utf-8", errors="replace")

                            for line in log_text.splitlines():
                                m = version_pattern.search(line)
                                if m:
                                    pkg_match = m.group(1).lower()
                                    ver_match = m.group(2)
                                    if ver_match in bad_versions_by_pkg.get(pkg_match, set()):
                                        hits.append({
                                            "source": "github",
                                            "repo": full_name,
                                            "run_id": run_id,
                                            "job_id": job_id,
                                            "job_name": job.get("name", ""),
                                            "package": pkg_match,
                                            "version": ver_match,
                                            "log_line": line.strip()[:200],
                                            "url": job.get("html_url", ""),
                                        })
                                        break  # One hit per job is enough
                        except Exception:
                            continue
            except Exception:
                continue

        return hits

    def scan_ci_gitlab(self, group: str, token: str,
                       window_hours: int = 24) -> List[Dict]:
        """Scan GitLab CI/CD pipeline jobs for compromised package installs.

        Requires: GITLAB_TOKEN with read_api scope.

        Args:
            group: GitLab group name
            token: GitLab personal access token
            window_hours: How far back to scan (default 24h)

        Returns:
            List of hits with project, job, version, and log context.
        """
        import urllib.request
        from datetime import datetime, timezone, timedelta

        hits = []
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=window_hours)

        headers = {"PRIVATE-TOKEN": token}

        # Build per-package bad version map for all Python threats
        bad_versions_by_pkg: Dict[str, Set[str]] = {}
        pkg_names: Set[str] = set()
        for record in self.threat_feed.list_all():
            if record.ecosystem == Ecosystem.PYTHON:
                pkg_names.add(record.package)
                for v in record.bad_versions:
                    bad_versions_by_pkg.setdefault(record.package.lower(), set()).add(v)

        if not pkg_names:
            return hits
        pattern_str = "(" + "|".join(re.escape(p) for p in sorted(pkg_names)) + r")[=\- ]+(\d+\.\d+\.\d+)"
        version_pattern = re.compile(pattern_str, re.IGNORECASE)

        if not re.match(r'^[A-Za-z0-9_%-]+(/[A-Za-z0-9_%-]+)*$', group):
            return hits

        # Get group ID
        try:
            url = "https://gitlab.com/api/v4/groups/" + group
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=30)
            group_data = json.loads(resp.read())
            group_id = group_data["id"]
        except Exception:
            return hits

        # Get projects
        try:
            url = ("https://gitlab.com/api/v4/groups/" + str(group_id) +
                   "/projects?include_subgroups=true&per_page=100")
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=30)
            projects = json.loads(resp.read())
        except Exception:
            return hits

        for project in projects:
            pid = project.get("id")
            pname = project.get("path_with_namespace", "")
            try:
                # Get recent jobs
                url = ("https://gitlab.com/api/v4/projects/" + str(pid) +
                       "/jobs?per_page=50&scope[]=success&scope[]=failed")
                req = urllib.request.Request(url, headers=headers)
                resp = urllib.request.urlopen(req, timeout=30)
                jobs = json.loads(resp.read())

                for job in jobs:
                    started = job.get("started_at", "")
                    if started:
                        try:
                            ts = datetime.fromisoformat(started.replace("Z", "+00:00"))
                        except ValueError:
                            # Python 3.8-3.10 doesn't support timezone in fromisoformat
                            ts = datetime.strptime(started.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
                        if ts < window_start:
                            break  # Jobs are in reverse chronological order

                    job_id = job.get("id")
                    # Fetch trace
                    try:
                        url = ("https://gitlab.com/api/v4/projects/" + str(pid) +
                               "/jobs/" + str(job_id) + "/trace")
                        req = urllib.request.Request(url, headers=headers)
                        resp = urllib.request.urlopen(req, timeout=60)
                        trace = resp.read().decode("utf-8", errors="replace")

                        for line in trace.splitlines():
                            m = version_pattern.search(line)
                            if m:
                                pkg_match = m.group(1).lower()
                                ver_match = m.group(2)
                                if ver_match in bad_versions_by_pkg.get(pkg_match, set()):
                                    hits.append({
                                        "source": "gitlab",
                                        "project": pname,
                                        "job_id": job_id,
                                        "job_name": job.get("name", ""),
                                        "package": pkg_match,
                                        "version": ver_match,
                                        "log_line": line.strip()[:200],
                                        "url": "https://gitlab.com/" + pname + "/-/jobs/" + str(job_id),
                                    })
                                    break
                    except Exception:
                        continue
            except Exception:
                continue

        return hits
