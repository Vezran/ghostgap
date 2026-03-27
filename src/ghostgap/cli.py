#!/usr/bin/env python3
"""
Ghost Gap CLI
==============
Supply Chain Firewall for pip and npm.

Usage:
  ghostgap install <package> [version]      Scan + install (Python)
  ghostgap npm-install <package> [version]   Scan + install (Node.js)
  ghostgap scan <manifest>                  Scan requirements.txt or package.json
  ghostgap check <package> [version]        Check single package (--npm for Node.js)
  ghostgap assess                           Am I safe?
  ghostgap cure [package]                   Cure infection (default: litellm)
  ghostgap feed                             Show threat intelligence database
  ghostgap ci <manifest>                    CI/CD gate (exit 0=clean, 1=blocked)
"""

import os
import sys

# ── Colors ────────────────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _p(msg, color=RESET):
    print(color + msg + RESET, flush=True)


def _ok(msg):
    _p("  \u2713 " + msg, GREEN)


def _warn(msg):
    _p("  \u26a0 " + msg, YELLOW)


def _crit(msg):
    _p("  \u2717 " + msg, RED + BOLD)


def _info(msg):
    _p("  \u2192 " + msg, DIM)


def _header(msg):
    _p("\n" + "\u2500" * 60, CYAN)
    _p("  " + msg, CYAN + BOLD)
    _p("\u2500" * 60, CYAN)


def _banner():
    _p("")
    _p("\u2588" * 60, CYAN + BOLD)
    _p("\u2588\u2588                                                      \u2588\u2588", CYAN + BOLD)
    _p("\u2588\u2588   GHOST GAP                                   \u2588\u2588", CYAN + BOLD)
    _p("\u2588\u2588   Supply Chain Firewall for pip and npm               \u2588\u2588", CYAN + BOLD)
    _p("\u2588\u2588                                                      \u2588\u2588", CYAN + BOLD)
    _p("\u2588" * 60, CYAN + BOLD)


def main():
    """CLI entry point.

    WARNING: When invoked via pip-installed `ghostgap`, .pth files have
    ALREADY EXECUTED before this function runs. The pip entry point cannot
    prevent .pth execution — use ghostgap-safe.sh for infected machines.
    """
    from ghostgap.core import SupplyChainFirewall, Ecosystem, Verdict

    if len(sys.argv) < 2:
        _banner()
        _p("")
        _p("  Usage:", BOLD)
        _p("    ghostgap install <package> [version]      Scan + install (Python)", DIM)
        _p("    ghostgap npm-install <package> [version]   Scan + install (Node.js)", DIM)
        _p("    ghostgap scan <manifest>                  Scan requirements.txt / package.json", DIM)
        _p("    ghostgap check <package> [version]        Check single package (--npm for Node.js)", DIM)
        _p("    ghostgap assess                           Ghost Gap: am I safe?", DIM)
        _p("    ghostgap cure [package]                   Cure infection (default: litellm)", DIM)
        _p("    ghostgap feed                             Show threat intelligence database", DIM)
        _p("    ghostgap ci <manifest>                    CI/CD gate (exit 0=clean, 1=blocked)", DIM)
        _p("    ghostgap deep-scan                         Scan ALL Python envs on this machine", DIM)
        _p("    ghostgap ci-scan github <org>              Scan GitHub Actions for compromised installs", DIM)
        _p("    ghostgap ci-scan gitlab <group>            Scan GitLab CI for compromised installs", DIM)
        _p("    ghostgap scan-all                           Scan ALL installed packages (catches transitive deps)", DIM)
        _p("    ghostgap protect                            Auto-protect all pip installs on this machine", DIM)
        _p("    ghostgap unprotect                          Remove auto-protection", DIM)
        _p("")
        _p("  The Ghost Gap: updating a package doesn't undo the damage.", YELLOW)
        _p("  Run 'ghostgap assess' to check if you're safe.", YELLOW)
        _p("  Run 'ghostgap cure' to fix it.", YELLOW)
        _p("")
        return

    fw = SupplyChainFirewall()
    cmd = sys.argv[1]

    # ── install ──────────────────────────────────────────────────────────
    if cmd == "install":
        pkg = sys.argv[2] if len(sys.argv) > 2 else ""
        ver = sys.argv[3] if len(sys.argv) > 3 else ""
        if not pkg:
            _p("  Usage: ghostgap install <package> [version]")
            return
        _banner()
        _header("Scanning " + pkg + (" " + ver if ver else ""))
        verdict = fw.scan_before_install(pkg, ver, Ecosystem.PYTHON)
        _print_verdict(verdict)
        if verdict.verdict != Verdict.BLOCK:
            _header("Installing")
            success = fw.safe_install(pkg, ver, Ecosystem.PYTHON)
            if success:
                _ok("Installed " + pkg + (" " + ver if ver else ""))
            else:
                _crit("Installation failed")

    # ── npm-install ──────────────────────────────────────────────────────
    elif cmd == "npm-install":
        pkg = sys.argv[2] if len(sys.argv) > 2 else ""
        ver = sys.argv[3] if len(sys.argv) > 3 else ""
        if not pkg:
            _p("  Usage: ghostgap npm-install <package> [version]")
            return
        _banner()
        _header("Scanning npm/" + pkg + (" " + ver if ver else ""))
        verdict = fw.scan_before_install(pkg, ver, Ecosystem.NODEJS)
        _print_verdict(verdict)
        if verdict.verdict != Verdict.BLOCK:
            _header("Installing")
            success = fw.safe_install(pkg, ver, Ecosystem.NODEJS)
            if success:
                _ok("Installed " + pkg)
            else:
                _crit("Installation failed")

    # ── scan ─────────────────────────────────────────────────────────────
    elif cmd == "scan":
        manifest = sys.argv[2] if len(sys.argv) > 2 else ""
        if not manifest:
            _p("  Usage: ghostgap scan <requirements.txt | package.json>")
            return
        _banner()
        _header("Scanning " + manifest)
        report = fw.scan_manifest(manifest)
        _print_manifest_report(report)

    # ── check ────────────────────────────────────────────────────────────
    elif cmd == "check":
        pkg = sys.argv[2] if len(sys.argv) > 2 else ""
        ver = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("-") else ""
        eco = Ecosystem.NODEJS if "--npm" in sys.argv else Ecosystem.PYTHON
        if not pkg:
            _p("  Usage: ghostgap check <package> [version] [--npm]")
            return
        _banner()
        _header("Checking " + pkg + (" " + ver if ver else ""))
        verdict = fw.scan_before_install(pkg, ver, eco)
        _print_verdict(verdict)
        sys.exit(1 if verdict.verdict == Verdict.BLOCK else 0)

    # ── assess ───────────────────────────────────────────────────────────
    elif cmd == "assess":
        _banner()
        _p("")
        _p("  Closing the Ghost Gap: the damage that updating doesn't fix.", DIM)
        _p("  Checking backdoor files, persistence, K8s pods, 50+ credential paths.", DIM)
        _header("Ghost Gap Assessment")
        gap = fw.ghost_gap_assess()
        _print_ghost_gap(gap)

    # ── cure ─────────────────────────────────────────────────────────────
    elif cmd == "cure":
        pkg = sys.argv[2] if len(sys.argv) > 2 else "litellm"
        _banner()
        _p("")
        _p("  The Ghost Gap: updating " + pkg + " doesn't undo the damage.", YELLOW)
        _p("  The backdoor already ran. Your keys are already stolen.", YELLOW)
        _p("  This tool finds what the patch missed and fixes it.", YELLOW)

        _header("STEP 1: Detecting infection")
        _info("Scanning Python paths for backdoor files...")
        _info("Checking persistence at ~/.config/sysmon/sysmon.py...")
        _info("Scanning kube-system for rogue pods...")

        cure_result = fw.cure(pkg)

        if cure_result.was_infected:
            _crit("INFECTION DETECTED")
        else:
            _ok("No active infection found")
            _info("Running credential rotation as a precaution...")

        _header("STEP 2: Removing backdoor")
        if cure_result.backdoor_files_removed:
            for f in cure_result.backdoor_files_removed:
                _ok("Deleted: " + f)
        if cure_result.persistence_cleaned:
            for f in cure_result.persistence_cleaned:
                _ok("Cleaned: " + f)
        if cure_result.rogue_pods_detected:
            for pod in cure_result.rogue_pods_detected:
                _warn("Suspicious pod detected (not auto-deleted): " + pod)
        if cure_result.version_fixed:
            threat = fw.threat_feed.get_threat(pkg, Ecosystem.PYTHON)
            safe_ver = threat.safe_version if threat else "latest"
            _ok("Reinstalled clean " + pkg + "==" + safe_ver)
        if not cure_result.backdoor_files_removed and not cure_result.persistence_cleaned:
            _ok("Nothing to remove")

        _header("STEP 3: Rotating credentials")
        for service, success in cure_result.credentials_rotated.items():
            if success:
                _ok(service + " \u2014 rotated")
            else:
                _warn(service + " \u2014 needs manual rotation")

        if not cure_result.credentials_rotated:
            _ok("No credentials needed rotation (system was clean)")

        _header("STEP 4: Verification")
        if cure_result.system_clean:
            _ok("System is clean")
        else:
            _warn("Some issues may remain \u2014 run 'ghostgap assess' for details")

        # Final verdict
        _p("")
        _p("  \u2554" + "\u2550" * 56 + "\u2557", CYAN + BOLD)
        if cure_result.was_infected and cure_result.system_clean:
            _p("  \u2551                                                        \u2551", GREEN + BOLD)
            _p("  \u2551   \u2713  GHOST GAP CLOSED                                  \u2551", GREEN + BOLD)
            _p("  \u2551   Backdoor removed. Persistence cleaned. Keys rotated. \u2551", GREEN + BOLD)
            _p("  \u2551                                                        \u2551", GREEN + BOLD)
        elif cure_result.was_infected:
            _p("  \u2551                                                        \u2551", RED + BOLD)
            _p("  \u2551   \u26a0  PARTIAL REMEDIATION                                \u2551", RED + BOLD)
            _p("  \u2551   Some threats could not be removed. See details above. \u2551", RED + BOLD)
            _p("  \u2551                                                        \u2551", RED + BOLD)
        else:
            _p("  \u2551                                                        \u2551", GREEN + BOLD)
            _p("  \u2551   \u2713  NO GHOST GAP DETECTED                              \u2551", GREEN + BOLD)
            _p("  \u2551   System was not actively compromised.                 \u2551", GREEN + BOLD)
            _p("  \u2551                                                        \u2551", GREEN + BOLD)
        _p("  \u255a" + "\u2550" * 56 + "\u255d", CYAN + BOLD)

        _p("")
        _p("  MANUAL STEPS STILL REQUIRED:", YELLOW + BOLD)
        _p("   1. Deploy new SSH public key to all servers", YELLOW)
        _p("   2. Run: gcloud auth application-default login", YELLOW)
        _p("   3. Run: az login (if you use Azure)", YELLOW)
        _p("   4. Regenerate K8s config for your clusters", YELLOW)
        _p("   5. Revoke GitHub/GitLab/Bitbucket tokens", YELLOW)
        _p("   6. Rotate ALL API keys in .env files", YELLOW)
        _p("   7. Check CI/CD secrets", YELLOW)
        _p("   8. Review CloudTrail / GCP Audit logs", YELLOW)
        _p("")
        _p("  \u2550" * 58, CYAN)
        _p("  Ghost Gap \u2014 closing the Ghost Gap", CYAN + BOLD)
        _p("  \u2550" * 58, CYAN)
        _p("")

    # ── feed ─────────────────────────────────────────────────────────────
    elif cmd == "feed":
        from ghostgap.core import ThreatCategory
        _banner()
        _header("Threat Intelligence Feed")
        _p("  Total threats: " + str(fw.threat_feed.total_threats), BOLD)
        _p("  Ecosystems:    " + ", ".join(sorted(fw.threat_feed.ecosystems)), BOLD)
        _p("")
        for record in fw.threat_feed.list_all():
            color = RED if record.threat_category in (
                ThreatCategory.CREDENTIAL_THEFT, ThreatCategory.BACKDOOR
            ) else YELLOW
            _p("  " + record.ecosystem.value + "/" + record.package +
               " " + str(record.bad_versions) +
               " \u2014 " + record.threat_category.value +
               " by " + (record.actor or "unknown"), color)
            _p("    " + record.description, DIM)
        _p("")

    # ── ci ───────────────────────────────────────────────────────────────
    elif cmd == "ci":
        manifest = sys.argv[2] if len(sys.argv) > 2 else ""
        if not manifest:
            print("Usage: ghostgap ci <requirements.txt | package.json> [--strict]")
            sys.exit(1)
        strict = "--strict" in sys.argv
        report = fw.scan_manifest(manifest)
        _print_manifest_report(report)
        if report.overall_verdict == Verdict.BLOCK:
            sys.exit(1)
        elif strict and report.overall_verdict == Verdict.REVIEW:
            sys.exit(1)
        else:
            sys.exit(0)

    # ── scan-all ─────────────────────────────────────────────────────────
    elif cmd == "scan-all":
        _banner()
        _header("Scanning all installed packages")
        _p("")
        _info("Checking every installed package against the threat feed...")
        _info("This catches transitive deps (dspy, agent frameworks pulling litellm).")
        _p("")

        hits = fw.scan_installed()
        if hits:
            _crit("FOUND " + str(len(hits)) + " compromised package(s) installed:")
            for v in hits:
                _p("")
                _crit("  " + v.package + "==" + v.version)
                for t in v.threats:
                    _crit("    " + t)
                _warn("  " + v.recommendation)
            _p("")
            _crit("Run 'ghostgap cure' to fix.")
            sys.exit(1)
        else:
            _ok("All installed packages are clean.")
            _info("Checked against " + str(fw.threat_feed.total_threats) + " known threats.")
        _p("")

    # ── deep-scan ────────────────────────────────────────────────────────
    elif cmd == "deep-scan":
        _banner()
        _p("")
        _p("  Deep filesystem scan: checking ALL Python environments.", DIM)
        _p("  Unlike sys.path, this finds Homebrew, pyenv, conda, virtualenvs, pipx.", DIM)
        _p("")
        _p("  SAFETY: Uses system 'find' — does NOT load .pth files from infected envs.", GREEN)
        _header("Scanning all Python environments")

        hits = fw.deep_scan_filesystem()
        if hits:
            _crit("FOUND " + str(len(hits)) + " compromised installation(s):")
            for h in hits:
                _p("")
                _crit("  " + h["package"] + "==" + h["version"])
                _info("  Path:       " + h["path"])
                _info("  Env:        " + h["env_type"])
                _info("  Threat:     " + h["threat"] + " by " + h["actor"])
                _warn("  Safe ver:   " + h["safe_version"])
            _p("")
            _crit("Run 'ghostgap cure' to fix all infections.")
        else:
            _ok("No compromised packages found in any Python environment.")
        _p("")

    # ── ci-scan ─────────────────────────────────────────────────────────
    elif cmd == "ci-scan":
        platform = sys.argv[2] if len(sys.argv) > 2 else ""
        target = sys.argv[3] if len(sys.argv) > 3 else ""

        if platform == "github":
            if not target:
                _p("  Usage: ghostgap ci-scan github <org-name>")
                _p("  Requires: GITHUB_TOKEN env var with repo/actions:read scope", DIM)
                return
            token = os.environ.get("GITHUB_TOKEN", "")
            if not token:
                _crit("Set GITHUB_TOKEN environment variable first.")
                return

            _banner()
            _header("Scanning GitHub Actions: " + target)
            hours = 72
            _info("Looking back " + str(hours) + " hours for compromised package installs...")

            hits = fw.scan_ci_github(target, token, window_hours=hours)
            if hits:
                _crit("FOUND " + str(len(hits)) + " pipeline(s) that installed compromised packages:")
                for h in hits:
                    _p("")
                    _crit("  " + h.get("package", "unknown") + "==" + h["version"])
                    _info("  Repo:    " + h["repo"])
                    _info("  Job:     " + h["job_name"] + " (#" + str(h["job_id"]) + ")")
                    _info("  URL:     " + h["url"])
                    _info("  Log:     " + h["log_line"])
                _p("")
                _crit("These CI/CD environments had their secrets exposed.")
                _crit("Rotate ALL secrets in these repos immediately.")
            else:
                _ok("No compromised package installs found in GitHub Actions.")
            _p("")

        elif platform == "gitlab":
            if not target:
                _p("  Usage: ghostgap ci-scan gitlab <group-name>")
                _p("  Requires: GITLAB_TOKEN env var with read_api scope", DIM)
                return
            token = os.environ.get("GITLAB_TOKEN", "")
            if not token:
                _crit("Set GITLAB_TOKEN environment variable first.")
                return

            _banner()
            _header("Scanning GitLab CI: " + target)
            hours = 72
            _info("Looking back " + str(hours) + " hours for compromised package installs...")

            hits = fw.scan_ci_gitlab(target, token, window_hours=hours)
            if hits:
                _crit("FOUND " + str(len(hits)) + " pipeline(s) that installed compromised packages:")
                for h in hits:
                    _p("")
                    _crit("  " + h.get("package", "unknown") + "==" + h["version"])
                    _info("  Project: " + h["project"])
                    _info("  Job:     " + h["job_name"] + " (#" + str(h["job_id"]) + ")")
                    _info("  URL:     " + h["url"])
                    _info("  Log:     " + h["log_line"])
                _p("")
                _crit("These CI/CD environments had their secrets exposed.")
                _crit("Rotate ALL secrets in these projects immediately.")
            else:
                _ok("No compromised package installs found in GitLab CI.")
            _p("")

        else:
            _p("  Usage: ghostgap ci-scan <github|gitlab> <org/group>")

    # ── protect ──────────────────────────────────────────────────────────
    elif cmd == "protect":
        _banner()
        _header("Setting up auto-protection")
        _info("Creating pip wrapper that scans before every install...")

        # Create a wrapper script
        wrapper_dir = os.path.expanduser("~/.ghostgap")
        os.makedirs(wrapper_dir, exist_ok=True)
        wrapper_path = os.path.join(wrapper_dir, "pip")

        wrapper_content = """#!/bin/bash
# Ghost Gap pip wrapper — scans packages before installing
# Remove with: ghostgap unprotect

if [[ "$1" == "install" && "$#" -gt 1 ]]; then
    # Extract package names (skip flags starting with -)
    for arg in "${@:2}"; do
        if [[ "$arg" != -* && "$arg" != *"/"* ]]; then
            # Split package==version
            pkg=$(echo "$arg" | sed 's/[><=!~].*//')
            ver=$(echo "$arg" | sed -n 's/.*==\([^,]*\).*/\1/p')
            if [ -n "$pkg" ]; then
                if [ -n "$ver" ]; then ghostgap check "$pkg" "$ver" 2>/dev/null; else ghostgap check "$pkg" 2>/dev/null; fi
                exit_code=$?
                if [ $exit_code -eq 1 ]; then
                    echo ""
                    echo "  BLOCKED by Ghost Gap. Run 'ghostgap feed' to see why."
                    echo ""
                    exit 1
                fi
            fi
        fi
    done
fi

# Pass through to real pip
command pip "$@"
"""
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)
        os.chmod(wrapper_path, 0o755)

        # Create shell alias setup
        alias_line = 'alias pip="' + wrapper_path + '"'
        rc_files = []
        for rc in [".bashrc", ".zshrc", ".bash_profile"]:
            rc_path = os.path.expanduser("~/" + rc)
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    content = f.read()
                if "ghostgap" not in content:
                    with open(rc_path, "a") as f:
                        f.write("\n# Ghost Gap — supply chain protection\n")
                        f.write(alias_line + "\n")
                    rc_files.append(rc)

        _ok("Wrapper installed at: " + wrapper_path)
        if rc_files:
            _ok("Shell alias added to: " + ", ".join(rc_files))
        _p("")
        _warn("Restart your shell or run: source ~/." + (rc_files[0] if rc_files else "bashrc"))
        _p("")
        _ok("Every 'pip install' will now be scanned by Ghost Gap.")
        _ok("Compromised packages will be blocked automatically.")
        _p("")
        _info("To remove: ghostgap unprotect")
        _p("")

    elif cmd == "unprotect":
        _banner()
        _header("Removing auto-protection")

        wrapper_dir = os.path.expanduser("~/.ghostgap")
        wrapper_path = os.path.join(wrapper_dir, "pip")

        if os.path.exists(wrapper_path):
            os.remove(wrapper_path)
            _ok("Wrapper removed: " + wrapper_path)

        # Remove alias from shell configs
        for rc in [".bashrc", ".zshrc", ".bash_profile"]:
            rc_path = os.path.expanduser("~/" + rc)
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if "# Ghost Gap" not in l and 'ghostgap/pip' not in l]
                if len(new_lines) != len(lines):
                    with open(rc_path, "w") as f:
                        f.writelines(new_lines)
                    _ok("Cleaned: ~/" + rc)

        _p("")
        _ok("Auto-protection removed. pip will work normally.")
        _info("Restart your shell for changes to take effect.")
        _p("")

    else:
        _p("  Unknown command: " + cmd, RED)
        _p("  Run 'ghostgap' without arguments for help.", DIM)


# ── Output Helpers ───────────────────────────────────────────────────────────

def _print_verdict(verdict):
    from ghostgap.core import Verdict

    _p("")
    if verdict.verdict == Verdict.BLOCK:
        _crit("VERDICT: BLOCK")
        _crit(verdict.recommendation)
    elif verdict.verdict == Verdict.REVIEW:
        _warn("VERDICT: REVIEW")
        _warn(verdict.recommendation)
    else:
        _ok("VERDICT: ALLOW")
        _ok(verdict.recommendation)

    if verdict.threats:
        _p("")
        for t in verdict.threats:
            _crit("  " + t)
    if verdict.credential_access:
        _p("")
        _crit("Credential access detected:")
        for c in verdict.credential_access:
            _crit("  " + c)
    if verdict.obfuscation_score > 0:
        _warn("Obfuscation score: " + str(round(verdict.obfuscation_score, 2)) + "/1.00")

    _p("  Scan time: " + str(round(verdict.scan_time_ms, 1)) + "ms", DIM)
    _p("")


def _print_manifest_report(report):
    from ghostgap.core import Verdict

    _p("")
    _p("  Packages: " + str(report.total_packages), BOLD)
    _ok("Clean:   " + str(report.clean))
    if report.review > 0:
        _warn("Review:  " + str(report.review))
    if report.blocked > 0:
        _crit("Blocked: " + str(report.blocked))

    if report.verdicts:
        _p("")
        for v in report.verdicts:
            color = RED if v.verdict == Verdict.BLOCK else YELLOW
            _p("  " + v.verdict.value.upper() + ": " + v.package + "==" + v.version, color)
            for t in v.threats:
                _p("    " + t, DIM)

    _p("")
    if report.overall_verdict == Verdict.BLOCK:
        _crit("OVERALL: BLOCKED \u2014 compromised packages found")
    else:
        _ok("OVERALL: CLEAN")
    _p("")


def _print_ghost_gap(gap):
    _p("")
    _p("  \u2554" + "\u2550" * 56 + "\u2557", CYAN + BOLD)

    if gap.infected:
        _p("  \u2551                                                        \u2551", RED + BOLD)
        _p("  \u2551   \u2717  YOU ARE NOT SAFE                                  \u2551", RED + BOLD)
        _p("  \u2551                                                        \u2551", RED + BOLD)
        _p("  \u255a" + "\u2550" * 56 + "\u255d", CYAN + BOLD)
        _p("")
        if gap.compromised_version:
            _crit("Running compromised version: litellm==" + gap.compromised_version)
        if gap.backdoor_files:
            _crit("Backdoor files: " + str(len(gap.backdoor_files)))
            for f in gap.backdoor_files:
                _crit("  " + f)
        if gap.persistence_artifacts:
            _crit("Persistence artifacts: " + str(len(gap.persistence_artifacts)))
            for f in gap.persistence_artifacts:
                _crit("  " + f)
        if gap.rogue_k8s_pods:
            _crit("Rogue K8s pods: " + str(len(gap.rogue_k8s_pods)))
            for pod in gap.rogue_k8s_pods:
                _crit("  " + pod)
        _p("")
        _crit("The Ghost Gap: you updated the package, but the backdoor is STILL here.")
        _crit("Run: ghostgap cure")

    elif gap.exposed_credentials:
        _p("  \u2551                                                        \u2551", YELLOW + BOLD)
        _p("  \u2551   \u26a0  NO ACTIVE BACKDOOR \u2014 BUT CHECK YOUR CREDENTIALS  \u2551", YELLOW + BOLD)
        _p("  \u2551                                                        \u2551", YELLOW + BOLD)
        _p("  \u255a" + "\u2550" * 56 + "\u255d", CYAN + BOLD)
        _p("")
        _warn(str(len(gap.exposed_credentials)) + " credential paths exist on this system.")
        _warn("If you EVER had a compromised package installed, rotate them all.")
        _p("")
        _warn("Run: ghostgap cure")

    else:
        _p("  \u2551                                                        \u2551", GREEN + BOLD)
        _p("  \u2551   \u2713  YOU ARE SAFE                                      \u2551", GREEN + BOLD)
        _p("  \u2551                                                        \u2551", GREEN + BOLD)
        _p("  \u255a" + "\u2550" * 56 + "\u255d", CYAN + BOLD)
        _p("")
        _ok("No backdoors. No persistence. No rogue pods.")

    _p("")
    _p("  \u2550" * 58, CYAN)
    _p("  Ghost Gap \u2014 closing the Ghost Gap", CYAN + BOLD)
    _p("  \u2550" * 58, CYAN)
    _p("")


if __name__ == "__main__":
    main()
