# Ghost Gap

**Supply Chain Firewall for pip and npm. Zero dependencies. Python 3.8+.**

Updating a compromised package doesn't make you safe. The backdoor already ran. Your keys are already stolen. `litellm_init.pth` is still on your disk auto-executing on every Python startup. **That's the Ghost Gap** — and this tool closes it.

### If you might be infected — START HERE:
```bash
curl -sSL https://raw.githubusercontent.com/Vezran/ghostgap/main/ghostgap-safe.sh | bash
```
This is **bash, not Python.** It quarantines `litellm_init.pth` using system tools, then launches Python with `-S` (skips all .pth processing). The malware **never runs. Not even once.**

### If you're already clean:
```bash
pip install ghostgap
ghostgap assess         # Am I safe?
ghostgap cure           # Fix it
```

> **Why two methods?** Python .pth files run during interpreter startup at the C level, BEFORE any user code. No Python tool can prevent this. `ghostgap-safe.sh` uses bash + `python -S` to bypass .pth entirely. The pip `ghostgap` quarantines .pth and rotates credentials, but the .pth executes one final time during that invocation.

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
Arthur's community scripts: *"scan your CI logs"* (but their Python scanner [loads the malicious .pth on startup](https://www.linkedin.com/feed/update/urn:li:activity:7310325667481899008/)).

Ghost Gap: one command, finds everything, fixes everything, doesn't trigger the malware.

## What sets Ghost Gap apart

| Problem | Others | Ghost Gap |
|---------|--------|-----------|
| .pth persistence survives pip uninstall | Most scanners don't check .pth files. Python-based scanners **auto-load the malware on startup** | Uses system `find` — never loads .pth. Scans AND deletes them |
| Transitive dependencies (dspy, agent frameworks) | "Check if you installed litellm" | `ghostgap scan-all` checks every installed package recursively |
| CI/CD pipeline exposure | Separate GitHub/GitLab gist scripts | `ghostgap ci-scan github <org>` / `ghostgap ci-scan gitlab <group>` built in |
| Credential rotation | "Rotate all secrets manually" | Auto-rotates SSH, AWS, GCP, Azure, K8s, Git, Docker, HF, Terraform |
| K8s rogue pods | Not mentioned in most advisories | Auto-scans kube-system, kills rogue pods + deployments |
| Ongoing protection | Run once, forget | `ghostgap protect` hooks into every pip install automatically |
| C2 domain detection | IOC list to check manually | Scans .pth files, /etc/hosts, Python source for `models.litellm.cloud` and `checkmarx.zone` |

## Install

```bash
pip install ghostgap
```

## Commands

### Assessment
```bash
ghostgap assess         # Ghost Gap check — am I safe?
ghostgap scan-all       # Check ALL installed packages (catches transitive deps)
ghostgap deep-scan      # Scan ALL Python envs (Homebrew, pyenv, conda, venvs, pipx)
```

### Cure
```bash
ghostgap cure           # Full remediation (detect + remove + rotate + verify)
ghostgap cure litellm   # Target specific package
```

### Firewall
```bash
ghostgap install requests          # Scan then install (Python)
ghostgap npm-install express       # Scan then install (Node.js)
ghostgap check litellm 1.82.7     # Check without installing
ghostgap check event-stream 3.3.6 --npm
ghostgap protect                   # Auto-protect every pip install
ghostgap unprotect                 # Remove auto-protection
```

### Manifests
```bash
ghostgap scan requirements.txt
ghostgap scan package.json
ghostgap ci requirements.txt       # CI/CD gate (exit 0=clean, 1=blocked)
```

### CI/CD Pipeline Scanning
```bash
ghostgap ci-scan github <org>       # Scan GitHub Actions logs
ghostgap ci-scan gitlab <group>     # Scan GitLab CI logs
```

### Threat Feed
```bash
ghostgap feed                       # Show all 13 known threats
```

## GitHub Actions

Drop this into `.github/workflows/ghostgap.yml`:

```yaml
name: Ghost Gap
on:
  pull_request:
    paths: ['requirements*.txt', 'package.json', 'pyproject.toml']

jobs:
  supply-chain-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ghostgap
      - run: ghostgap ci requirements.txt
      - run: ghostgap assess
```

## Built-in Threat Feed (13 attacks, 2 ecosystems)

| Package | Ecosystem | Versions | Threat | Actor |
|---------|-----------|----------|--------|-------|
| **litellm** | Python | 1.82.7, 1.82.8 | Supply chain / credential theft | TeamPCP (via Trivy) |
| **litellm** | Python | 1.82.0-1.82.2 | API key leak in logs (bug) | software bug |
| ultralytics | Python | 8.3.41, 8.3.42 | Cryptominer | unknown |
| ctx | Python | 0.1.2, 0.2.0 | Credential theft | unknown |
| **event-stream** | Node.js | 3.3.6 | Crypto wallet backdoor | right9ctrl |
| **ua-parser-js** | Node.js | 0.7.29, 0.8.0, 1.0.0 | Cryptominer + password stealer | unknown |
| colors | Node.js | 1.4.1, 1.4.2 | Protestware (infinite loop) | Marak |
| node-ipc | Node.js | 10.1.1-10.1.3 | Protestware (file overwrite) | RIAEvangelist |
| coa | Node.js | 2.0.3+ | Credential theft | unknown |
| rc | Node.js | 1.2.9, 1.3.0, 2.3.9 | Credential theft | unknown |
| es5-ext | Node.js | 0.10.63 | Protestware | medikoo |
| @lottiefiles/lottie-player | Node.js | 2.0.8 | Crypto wallet drainer | unknown |

## Python API

```python
from ghostgap import SupplyChainFirewall, Verdict

fw = SupplyChainFirewall()

# Am I safe?
gap = fw.ghost_gap_assess()
print("Safe:", gap.safe)

# Cure
result = fw.cure()
print("Clean:", result.system_clean)

# Scan before install
v = fw.scan_before_install("litellm", "1.82.7")
assert v.verdict == Verdict.BLOCK

# Scan all installed packages
hits = fw.scan_installed()

# CI/CD gate
exit_code = fw.ci_gate("requirements.txt")
```

## The .pth Problem

`.pth` files in Python's `site-packages` are **auto-executed on every Python startup**. The litellm 1.82.8 attack dropped `litellm_init.pth` — which means:

1. Even after `pip uninstall litellm`, the `.pth` file stays
2. Every time you run `python`, it executes the malicious code
3. **Any Python-based scanner you run on the infected machine triggers the malware**

Ghost Gap's `deep-scan` uses `find` (a system binary, not Python) to locate compromised files without loading them. This is the only safe way to scan an infected machine.

## Why not pip-audit / safety / Snyk?

| Feature | ghostgap | pip-audit | safety | Snyk |
|---------|----------|-----------|--------|------|
| Ghost Gap (post-infection) | Yes | No | No | No |
| Cure command | Yes | No | No | No |
| Auto credential rotation | Yes | No | No | No |
| K8s pod scanning | Yes | No | No | No |
| .pth persistence detection | Yes | No | No | No |
| Safe on infected machines | Yes | No | No | No |
| CI/CD pipeline scanning | Yes | No | No | No |
| npm + pip in one tool | Yes | pip only | pip only | Yes |
| Deep source code scan | Yes | No | No | Limited |
| Auto-protect pip installs | Yes | No | No | No |
| Zero dependencies | Yes | No | No | No |
| Free & open source | Yes | Yes | Freemium | Freemium |

## Zero Dependencies

ghostgap uses only Python stdlib. No requests, no click, no rich, no pydantic. `pip install ghostgap` adds exactly one package to your environment.

## License

Apache-2.0
