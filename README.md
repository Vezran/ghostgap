<p align="center">
  <h1 align="center">Ghost Gap for LiteLLM</h1>
  <p align="center">
    <strong>Supply Chain Firewall for pip, npm, and 6 more ecosystems.</strong><br>
    Zero dependencies. Python 3.8+. Safe on infected machines.
  </p>
  <p align="center">
    <a href="https://pypi.org/project/ghostgap/"><img src="https://img.shields.io/pypi/v/ghostgap?color=blue" alt="PyPI"></a>
    <a href="https://github.com/Vezran/ghostgap/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
    <a href="https://pypi.org/project/ghostgap/"><img src="https://img.shields.io/pypi/pyversions/ghostgap" alt="Python"></a>
  </p>
</p>

---

Updating a compromised package doesn't make you safe. The backdoor already ran. Your keys are already stolen. `litellm_init.pth` is still on your disk auto-executing on every Python startup.

**That's the Ghost Gap** — the damage that patching doesn't fix. This tool closes it.

---

## Quick Start

### If you might be infected — START HERE:
```bash
curl -sSL https://raw.githubusercontent.com/Vezran/ghostgap/main/ghostgap-safe.sh | bash
```
This is **bash, not Python.** It quarantines `litellm_init.pth` using system tools (`find`/`grep`/`mv`), then launches Python with `-S` (skips all `.pth` processing). The malware **never runs. Not even once.**

### If you're already clean:
```bash
pip install ghostgap
ghostgap assess         # Am I safe?
ghostgap cure           # Fix everything
```

> **Why two methods?** Python `.pth` files auto-run during interpreter startup at the C level (`Py_InitializeFromConfig` -> `site.main()` -> `addpackage()` -> line 213), BEFORE any user code. No Python tool — ours or anyone else's — can prevent this. `ghostgap-safe.sh` uses bash + `python -S` to bypass `.pth` entirely. The pip-installed `ghostgap` command **cannot prevent `.pth` execution in its own process** — by the time `main()` runs, all `.pth` code has already executed. Use the pip command on machines you know are clean, or to assess/cure after running the safe bootstrap.

---

## The Problem

```
You:     pip install litellm --upgrade    # "I'm safe now, right?"

Reality: sysmon.py already stole your SSH keys, AWS creds, and K8s config.
         litellm_init.pth is still in site-packages — runs on EVERY Python startup.
         A rogue pod is still running in kube-system.
         Your CI/CD secrets were exfiltrated during the pip install.
         Updating the package didn't undo any of that.
```

LiteLLM's official fix: *"delete some files and rotate keys manually."*

Arthur's community scripts: *"scan your CI logs"* (but their Python scanner [loads the malicious .pth on startup](https://www.linkedin.com/feed/update/urn:li:activity:7310325667481899008/) — the LiteLLM CEO acknowledged this).

ghostgap: one command, finds everything, fixes everything, doesn't trigger the malware.

---

## What Sets Ghost Gap Apart

| Problem | Others | Ghost Gap |
|---------|--------|-----------|
| .pth persistence survives `pip uninstall` | Most scanners don't check .pth files. Python-based scanners **auto-load the malware on startup** | Uses system `find` — never loads .pth. Scans AND deletes them |
| Transitive dependencies (dspy, agent frameworks) | "Check if you installed litellm" | `ghostgap scan-all` checks every installed package |
| CI/CD pipeline exposure | Separate GitHub/GitLab gist scripts | `ghostgap ci-scan github <org>` / `gitlab <group>` built in |
| Credential rotation | "Rotate all secrets manually" | Auto-rotates SSH, AWS, GCP, Azure, K8s, Git, Docker, HF, Terraform |
| K8s rogue pods | Not mentioned in most advisories | Auto-scans kube-system, kills rogue pods + deployments |
| Ongoing protection | Run once, forget | `ghostgap protect` hooks into every `pip install` automatically |
| C2 domain detection | IOC list to check manually | Scans .pth files and source for `models.litellm.cloud` / `checkmarx.zone` |
| Multi-ecosystem | Python only (or npm only) | Python, npm, Ruby, Rust, Go, Java, PHP, Docker |

---

## Install

```bash
pip install ghostgap
```

Or install from source:
```bash
pip install git+https://github.com/Vezran/ghostgap.git
```

---

## All Commands

### Assessment
```bash
ghostgap assess              # Ghost Gap check — am I safe?
ghostgap scan-all            # Check ALL installed packages (catches transitive deps)
ghostgap deep-scan           # Scan ALL Python envs (Homebrew, pyenv, conda, venvs, pipx)
ghostgap feed                # Show all 23 known threats
```

### Cure
```bash
ghostgap cure                # Full remediation (detect + remove + rotate + verify)
ghostgap cure litellm        # Target specific package
```

### Firewall
```bash
ghostgap install requests           # Scan then install (Python)
ghostgap npm-install express        # Scan then install (Node.js)
ghostgap check litellm 1.82.7      # Check without installing
ghostgap check event-stream 3.3.6 --npm
ghostgap protect                    # Auto-protect every pip install
ghostgap unprotect                  # Remove auto-protection
```

### Manifest Scanning
```bash
ghostgap scan requirements.txt     # Python
ghostgap scan package.json         # Node.js
ghostgap scan Gemfile              # Ruby
ghostgap scan Cargo.toml           # Rust
ghostgap scan go.mod               # Go
ghostgap scan pom.xml              # Java
ghostgap scan composer.json        # PHP
ghostgap scan Dockerfile           # Docker (FROM tags + curl|bash)
ghostgap ci requirements.txt       # CI/CD gate (exit 0=clean, 1=blocked)
```

### CI/CD Pipeline Scanning
```bash
ghostgap ci-scan github <org>       # Scan GitHub Actions logs
ghostgap ci-scan gitlab <group>     # Scan GitLab CI logs
```

---

## GitHub Actions

Drop this into `.github/workflows/ghostgap.yml`:

```yaml
name: Ghost Gap
on:
  pull_request:
    paths: ['requirements*.txt', 'package.json', 'pyproject.toml']
  push:
    branches: [main, master]
    paths: ['requirements*.txt', 'package.json']

jobs:
  supply-chain-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ghostgap
      - run: |
          for f in requirements*.txt; do
            [ -f "$f" ] && ghostgap ci "$f"
          done
      - run: ghostgap assess
```

---

## Built-in Threat Feed

### 23 known attacks across 8 ecosystems

#### Python
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| **litellm** | 1.82.7, 1.82.8 | Supply chain attack via Trivy CI/CD compromise. Credential theft + .pth persistence + K8s pod injection | TeamPCP |
| **litellm** | 1.82.0 - 1.82.2 | Guardrail logging bug leaked API keys in spend logs and OTEL traces | software bug |
| ultralytics | 8.3.41, 8.3.42 | Cryptominer via compromised GitHub Actions | unknown |
| ctx | 0.1.2, 0.2.0 | AWS credential exfiltration via env vars | unknown |
| phpass | 0.9.99 | Dependency confusion stealing env vars | unknown |

#### Node.js
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| **event-stream** | 3.3.6 | Crypto wallet theft via flatmap-stream | right9ctrl |
| **ua-parser-js** | 0.7.29, 0.8.0, 1.0.0 | Cryptominer + password stealer via hijacked maintainer | unknown |
| colors | 1.4.1, 1.4.2 | Protestware (infinite loop) | Marak |
| node-ipc | 10.1.1 - 10.1.3 | Protestware (file overwrite on Russian/Belarusian IPs) | RIAEvangelist |
| coa | 2.0.3+ | Credential theft via hijacked preinstall | unknown |
| rc | 1.2.9, 1.3.0, 2.3.9 | Credential theft (hijacked alongside coa) | unknown |
| es5-ext | 0.10.63 | Protestware (anti-war message on Russian IPs) | medikoo |
| @lottiefiles/lottie-player | 2.0.8 | Crypto wallet drainer | unknown |

#### Ruby
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| rest-client | 1.6.13 | Hijacked gem exfiltrated env vars | unknown |
| strong_password | 0.0.7 | Backdoor downloaded and eval'd code from pastebin | unknown |
| bootstrap-sass | 3.2.0.3 | Backdoor via cookie-based arbitrary code execution | unknown |

#### Rust
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| rustdecimal | 1.23.1 | Typosquat of rust_decimal, stole env vars via Telegram | unknown |
| cratesio | 0.1.0 | Typosquat attempting to steal crates.io API tokens | unknown |

#### Java
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| **log4j-core** | 2.0 - 2.16.0 | Log4Shell (CVE-2021-44228) — remote code execution via JNDI injection | CVE-2021-44228 |
| protobuf-java | 3.16.0 | Dependency confusion attack on Google protobuf | unknown |

#### PHP
| Package | Versions | Threat | Actor |
|---------|----------|--------|-------|
| phpunit/phpunit | 4.8.28, 5.6.3 | Backdoor in eval-stdin.php allowing remote code execution | unknown |

#### Docker
| Image | Threat |
|-------|--------|
| Various Docker Hub images | Compromised with cryptominers and backdoors. ghostgap flags unpinned FROM tags and `curl\|bash` in RUN instructions |

---

## The .pth Problem

`.pth` files in Python's `site-packages` are **auto-executed on every Python startup**. Here's the exact CPython code that does it (`Lib/site.py`, line 212-213):

```python
if line.startswith(("import ", "import\t")):
    exec(line)
```

The litellm 1.82.8 attack dropped `litellm_init.pth` which means:

1. Even after `pip uninstall litellm`, the `.pth` file **stays in site-packages**
2. **Every time you run `python`**, it runs the malicious code
3. **Any Python-based scanner** you run on the infected machine **triggers the malware first**
4. This includes pip-audit, safety, Snyk, and the Arthur community scripts

### How ghostgap solves it

**`ghostgap-safe.sh`** is a bash script (not Python) that:
1. Uses `find`/`grep`/`mv` to quarantine malicious `.pth` files — no Python involved
2. Launches Python with `-S` flag (skips `site.py` entirely, so `.pth` files never load)
3. Runs a **safe `.pth` parser** that processes path entries (for namespace packages) but **blocks all executable lines**
4. Runs `ghostgap cure` in this clean Python process

The result: `.pth` malware **never runs**. Not even once. Not in a throwaway process. Not anywhere.

**The pip-installed `ghostgap` command does NOT have this property.** When you run `ghostgap` via pip, Python starts normally, `site.py` processes all `.pth` files, and the malware executes before `main()` is called. The pip command will detect and warn about malicious `.pth` files, but the damage is already done. **Always use `ghostgap-safe.sh` on potentially infected machines.**

### From our CPython forensic

The execution chain is: `Py_InitializeFromConfig()` (C) -> `import site` -> `site.main()` -> `addsitepackages()` -> `addsitedir()` -> `addpackage()` -> `exec(line)`. This happens at the interpreter level before any user Python code runs. There is **no Python-level mechanism** to intercept or prevent `.pth` code execution. The `-S` flag is the only built-in defense, and our safe `.pth` parser is the only way to get site-packages imports working without `.pth` code execution.

---

## Deep Source Scanning

When you run `ghostgap check <package> <version>`, it downloads the package, extracts it, and scans every file for:

- **Credential file access patterns** — references to `~/.ssh/id_*`, `~/.aws/credentials`, `~/.kube/config`, etc.
- **Code obfuscation** — `exec(compile(...))`, `eval(base64.b64decode(...))`, `marshal.loads()`, `__import__('base64')`
- **Data exfiltration indicators** — outbound HTTP calls, socket connections, aiohttp/httpx usage
- **Malicious npm install scripts** — `preinstall`/`postinstall` hooks running curl/wget/node
- **Base64-encoded payloads** — long base64 strings decoded and checked for credential keywords

The verdict logic minimizes false positives: credential access alone is common in cloud tools (boto3, litellm, awscli) and doesn't trigger a block. Only credential access **combined with obfuscation** triggers a block — the actual attack pattern.

---

## Automatic Credential Rotation

`ghostgap cure` rotates:

| Service | What it does |
|---------|-------------|
| **SSH** | Generates new ed25519 key, backs up old keys |
| **AWS** | Creates new IAM access key, deletes old one, updates `~/.aws/credentials` |
| **GCP** | Removes compromised ADC, prompts re-auth |
| **Azure** | Removes all Azure token JSON files, backs up |
| **Kubernetes** | Backs up `~/.kube/config`, prompts re-gen for EKS/GKE/AKS |
| **Git** | Removes `~/.git-credentials`, prompts token revocation |
| **GitHub CLI** | Removes `~/.config/gh/hosts.yml`, prompts `gh auth login` |
| **Docker** | Clears auth tokens from `~/.docker/config.json` |
| **HuggingFace** | Removes cached tokens |
| **Terraform** | Removes Terraform Cloud credentials |

---

## Python API

```python
from ghostgap import SupplyChainFirewall, Ecosystem, Verdict

fw = SupplyChainFirewall()

# Am I safe?
gap = fw.ghost_gap_assess()
print("Safe:", gap.safe)
print("Exposed credentials:", len(gap.exposed_credentials))

# Cure an infection
result = fw.cure()
print("Was infected:", result.was_infected)
print("System clean:", result.system_clean)
print("Credentials rotated:", result.credentials_rotated)

# Scan before install
v = fw.scan_before_install("litellm", "1.82.7")
assert v.verdict == Verdict.BLOCK

# Scan across ecosystems
v = fw.scan_before_install("event-stream", "3.3.6", Ecosystem.NODEJS)
assert v.verdict == Verdict.BLOCK

v = fw.scan_before_install("rest-client", "1.6.13", Ecosystem.RUBY)
assert v.verdict == Verdict.BLOCK

# Scan a manifest
report = fw.scan_manifest("requirements.txt")
print("Blocked:", report.blocked)

# Scan all installed packages
hits = fw.scan_installed()

# CI/CD gate
exit_code = fw.ci_gate("requirements.txt")  # 0=clean, 1=blocked

# Deep filesystem scan (all Python environments)
hits = fw.deep_scan_filesystem()

# CI/CD pipeline scanning
github_hits = fw.scan_ci_github("my-org", token="ghp_...")
gitlab_hits = fw.scan_ci_gitlab("my-group", token="glpat-...")

# Add custom threats to the feed
from ghostgap import ThreatRecord, ThreatCategory
fw.threat_feed.add(ThreatRecord(
    package="evil-package",
    ecosystem=Ecosystem.PYTHON,
    bad_versions=["0.1.0"],
    safe_version="N/A",
    threat_category=ThreatCategory.BACKDOOR,
    actor="attacker",
    description="Custom threat",
))
```

---

## Why Not pip-audit / safety / Snyk?

| Feature | ghostgap | pip-audit | safety | Snyk |
|---------|----------|-----------|--------|------|
| Ghost Gap (post-infection cleanup) | Yes | No | No | No |
| Cure command | Yes | No | No | No |
| Auto credential rotation | Yes | No | No | No |
| Safe on infected machines | **Yes** (bash bootstrap only) | No | No | No |
| .pth persistence detection | Yes | No | No | No |
| K8s rogue pod scanning | Yes | No | No | No |
| CI/CD pipeline scanning | Yes | No | No | No |
| 8 ecosystems in one tool | Yes | pip only | pip only | Yes |
| Manifest scanning (10+ formats) | Yes | pip only | pip only | Yes |
| Deep source code scan | Yes | No | No | Limited |
| Dockerfile scanning | Yes | No | No | Yes |
| Auto-protect pip installs | Yes | No | No | No |
| Zero dependencies | **Yes** | No | No | No |
| Free and open source | Yes | Yes | Freemium | Freemium |

---

## Test Results

Tested against 67 manifest files across 5 ecosystems in a real production codebase (16 microservices, multiple languages):

| Ecosystem | Files | Clean | Blocked | False Positives |
|-----------|-------|-------|---------|-----------------|
| Python | 15 | 15 | 0 | 0 |
| Node.js | 9 | 9 | 0 | 0 |
| Rust | 15 | 15 | 0 | 0 |
| Go | 6 | 6 | 0 | 0 |
| Docker | 22 | 21 | 1 (true positive) | 0 |
| **Total** | **67** | **66** | **1** | **0** |

29/29 unit tests passed across all 8 ecosystems.

---

## Zero Dependencies

ghostgap uses only Python stdlib. No requests, no click, no rich, no pydantic. `pip install ghostgap` adds exactly one package to your environment.

For a supply chain security tool, this isn't a feature — it's a requirement. Every dependency is an attack surface.

---

## Contributing

Found a compromised package we don't cover? Open an issue or PR with the threat record:

```python
ThreatRecord(
    package="package-name",
    ecosystem=Ecosystem.PYTHON,  # or NODEJS, RUBY, RUST, GO, JAVA, PHP, DOCKER
    bad_versions=["1.0.0"],
    safe_version="0.9.0",
    threat_category=ThreatCategory.CREDENTIAL_THEFT,  # or BACKDOOR, CRYPTOMINER, etc.
    actor="attacker-name",
    description="What the attack does",
    source="Advisory URL",
)
```

---

## License

Apache-2.0

---

<p align="center">
  <strong>Vezran x taazbro</strong><br>
  <em>Closing the Ghost Gap — because updating doesn't undo the damage.</em>
</p>
