"""
Ghost Gap Launcher
==================

IMPORTANT — .pth LIMITATION:

When you run `ghostgap` (installed via pip), Python's interpreter startup
processes ALL .pth files in site-packages BEFORE this code executes.

    CPython startup chain:
    Py_InitializeFromConfig -> import site -> site.main() -> addpackage()
    -> exec(line)  # for every .pth "import ..." line (Lib/site.py:212)

If a malicious .pth file exists (e.g., litellm_init.pth), its code has
ALREADY EXECUTED by the time this function is called. This is a fundamental
limitation of any pip-installed Python tool — not a bug in ghostgap, but
a design constraint of CPython's .pth mechanism.

No Python-level code can prevent .pth execution in its own process.
The -S flag is the only built-in defense, and it must be set BEFORE
the interpreter starts — which a console_script entry point cannot do.

FOR INFECTED MACHINES, use the bash bootstrap instead:

    curl -sSL https://raw.githubusercontent.com/Vezran/ghostgap/main/ghostgap-safe.sh | bash

The bash script uses system tools (find/grep/mv) to quarantine .pth files
BEFORE starting Python, then launches Python with -S. No .pth execution.
"""

import os
import sys


# C2 domains and function names from known litellm supply chain attack
_C2_SIGNATURES = (
    "models.litellm.cloud",
    "checkmarx.zone",
    "cloud_stealer",
    "sysmon_collect",
    "steal_creds",
    "harvest_keys",
    "c2_callback",
)


def _check_for_malicious_pth():
    """Check if known malicious .pth files exist in any site-packages.

    Returns list of (path, reason) tuples. If non-empty, .pth code has
    ALREADY EXECUTED in this process — detection is after the fact.
    """
    threats = []

    for p in sys.path:
        if not p.endswith("site-packages") or not os.path.isdir(p):
            continue

        litellm_pth = os.path.join(p, "litellm_init.pth")
        if os.path.exists(litellm_pth):
            threats.append((litellm_pth, "known malicious .pth (litellm supply chain attack)"))
            continue

        try:
            names = [n for n in os.listdir(p) if n.endswith(".pth") and not n.startswith(".")]
        except OSError:
            continue

        for name in names:
            fullpath = os.path.join(p, name)
            try:
                with open(fullpath, "r", errors="replace") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue
            for sig in _C2_SIGNATURES:
                if sig in content:
                    threats.append((fullpath, "C2 signature: " + sig))
                    break

    return threats


def _warn_pth_compromise(threats):
    """Warn that malicious .pth files were detected — and already executed."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    sys.stderr.write("\n" + RED + BOLD)
    sys.stderr.write("  ==============================================================\n")
    sys.stderr.write("  WARNING: MALICIOUS .pth FILES DETECTED — ALREADY EXECUTED\n")
    sys.stderr.write("  ==============================================================\n")
    sys.stderr.write(RESET + "\n")

    for path, reason in threats:
        sys.stderr.write("  " + RED + BOLD + "  X " + path + RESET + "\n")
        sys.stderr.write("      " + reason + "\n")

    sys.stderr.write("\n" + YELLOW + BOLD)
    sys.stderr.write("  These .pth files executed when Python started this process.\n")
    sys.stderr.write("  Credentials may already be exfiltrated. The ghostgap command\n")
    sys.stderr.write("  (pip-installed) CANNOT prevent .pth execution in its own process.\n")
    sys.stderr.write(RESET + "\n")
    sys.stderr.write(YELLOW)
    sys.stderr.write("  For SAFE remediation on infected machines, use:\n")
    sys.stderr.write("    curl -sSL https://raw.githubusercontent.com/Vezran/ghostgap/main/ghostgap-safe.sh | bash\n")
    sys.stderr.write(RESET + "\n")
    sys.stderr.write("  Continuing with assessment/remediation...\n\n")


def main():
    """Entry point for the pip-installed ghostgap command.

    NOTE: By the time this function runs, CPython has already processed all
    .pth files in site-packages. If a malicious .pth exists, its code has
    already executed. This is unavoidable for any pip-installed Python tool.

    For safe operation on potentially infected machines, use ghostgap-safe.sh.
    """
    threats = _check_for_malicious_pth()
    if threats:
        _warn_pth_compromise(threats)

    from ghostgap.cli import main as cli_main
    cli_main()
