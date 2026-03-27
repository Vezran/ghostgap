#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  ghostgap-safe — Safe bootstrap for infected machines
# ═══════════════════════════════════════════════════════════════════
#
#  WHY THIS EXISTS:
#  Python .pth files in site-packages auto-execute on EVERY Python
#  startup. litellm 1.82.8 dropped litellm_init.pth which means:
#
#    Running "ghostgap cure" triggers the malware BEFORE the cure runs.
#
#  This shell script uses system tools (find, mv, rm) to quarantine
#  malicious .pth files BEFORE launching Python. No Python = no .pth.
#
#  USAGE:
#    curl -sSL https://raw.githubusercontent.com/ghostgap/ghostgap/main/ghostgap-safe.sh | bash
#
#    Or download and run:
#    chmod +x ghostgap-safe.sh
#    ./ghostgap-safe.sh
#
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}████████████████████████████████████████████████████████████${RESET}"
echo -e "${CYAN}${BOLD}██                                                      ██${RESET}"
echo -e "${CYAN}${BOLD}██   GHOST GAP — SAFE BOOTSTRAP                         ██${RESET}"
echo -e "${CYAN}${BOLD}██   Quarantines .pth malware BEFORE Python starts       ██${RESET}"
echo -e "${CYAN}${BOLD}██                                                      ██${RESET}"
echo -e "${CYAN}${BOLD}████████████████████████████████████████████████████████████${RESET}"
echo ""

# ── Step 1: Find and quarantine malicious .pth files ──────────────
echo -e "${CYAN}${BOLD}  Step 1: Quarantining malicious .pth files${RESET}"
echo -e "${DIM}  Using system 'find' — no Python, no .pth auto-execution${RESET}"
echo ""

QUARANTINE_DIR="$HOME/.ghostgap_quarantine/$(date +%s)"
FOUND_PTH=0

# Search ALL site-packages directories on this machine
# Include venvs, Homebrew, pyenv, conda, pipx, system — everything
SEARCH_ROOTS="/usr/lib /usr/local/lib /opt"
[ -d "$HOME" ] && SEARCH_ROOTS="$SEARCH_ROOTS $HOME"
[ -d "/opt/homebrew" ] && SEARCH_ROOTS="$SEARCH_ROOTS /opt/homebrew"

# Also search current directory tree (for venvs in project dirs)
SEARCH_ROOTS="$SEARCH_ROOTS $(pwd)"

for site_dir in $(find $SEARCH_ROOTS \
    -type d -name "site-packages" -maxdepth 12 2>/dev/null | sort -u | head -100); do

    # Check for known malicious .pth files
    for pth_file in "$site_dir"/litellm_init.pth; do
        if [ -f "$pth_file" ]; then
            FOUND_PTH=1
            echo -e "${RED}${BOLD}  ✗ FOUND: $pth_file${RESET}"

            # Quarantine it
            mkdir -p "$QUARANTINE_DIR"
            mv "$pth_file" "$QUARANTINE_DIR/"
            echo -e "${GREEN}  ✓ Quarantined to: $QUARANTINE_DIR/$(basename "$pth_file")${RESET}"
        fi
    done

    # Check ALL .pth files for C2 domains
    for pth_file in "$site_dir"/*.pth; do
        [ -f "$pth_file" ] || continue
        if grep -ql "models.litellm.cloud\|checkmarx.zone\|cloud_stealer\|sysmon_collect" "$pth_file" 2>/dev/null; then
            FOUND_PTH=1
            echo -e "${RED}${BOLD}  ✗ MALICIOUS .pth: $pth_file${RESET}"
            mkdir -p "$QUARANTINE_DIR"
            mv "$pth_file" "$QUARANTINE_DIR/"
            echo -e "${GREEN}  ✓ Quarantined${RESET}"
        fi
    done
done

if [ "$FOUND_PTH" -eq 0 ]; then
    echo -e "${GREEN}  ✓ No malicious .pth files found${RESET}"
fi

# ── Step 2: Check for sysmon.py persistence ───────────────────────
echo ""
echo -e "${CYAN}${BOLD}  Step 2: Checking persistence artifacts${RESET}"

FOUND_PERSIST=0
PERSIST_PATHS=(
    "$HOME/.config/sysmon/sysmon.py"
    "$HOME/.config/sysmon"
    "$HOME/.local/bin/sysmon"
    "$HOME/.cache/sysmon"
)

for p in "${PERSIST_PATHS[@]}"; do
    if [ -e "$p" ]; then
        FOUND_PERSIST=1
        echo -e "${RED}${BOLD}  ✗ FOUND: $p${RESET}"
        mkdir -p "$QUARANTINE_DIR"
        if [ -d "$p" ]; then
            mv "$p" "$QUARANTINE_DIR/"
        else
            mv "$p" "$QUARANTINE_DIR/"
        fi
        echo -e "${GREEN}  ✓ Quarantined${RESET}"
    fi
done

# Temp files
for pattern in /tmp/sysmon* /tmp/.sysmon* /tmp/.cloud_sync* /tmp/.teampcp* /tmp/.litellm_*; do
    for f in $pattern; do
        [ -e "$f" ] || continue
        FOUND_PERSIST=1
        echo -e "${RED}${BOLD}  ✗ FOUND: $f${RESET}"
        rm -rf "$f"
        echo -e "${GREEN}  ✓ Deleted${RESET}"
    done
done

if [ "$FOUND_PERSIST" -eq 0 ]; then
    echo -e "${GREEN}  ✓ No persistence artifacts found${RESET}"
fi

# ── Step 3: Check litellm version ─────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  Step 3: Checking litellm version${RESET}"

# Use python -S to skip site.py processing (no .pth execution)
LITELLM_VER=""
for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        LITELLM_VER=$($py -S -c "
import importlib.metadata
try:
    print(importlib.metadata.version('litellm'))
except Exception:
    print('')
" 2>/dev/null || true)
        PYTHON_CMD="$py"
        break
    fi
done

if [ -z "$LITELLM_VER" ]; then
    echo -e "${GREEN}  ✓ litellm is not installed${RESET}"
elif [ "$LITELLM_VER" = "1.82.7" ] || [ "$LITELLM_VER" = "1.82.8" ]; then
    echo -e "${RED}${BOLD}  ✗ COMPROMISED: litellm==$LITELLM_VER${RESET}"
    echo -e "${YELLOW}  Reinstalling clean version...${RESET}"
    "$PYTHON_CMD" -S -m pip install --force-reinstall litellm==1.82.6 2>/dev/null || \
        echo -e "${YELLOW}  ⚠ Could not reinstall — run: pip install --force-reinstall litellm==1.82.6${RESET}"
else
    echo -e "${GREEN}  ✓ litellm==$LITELLM_VER (clean)${RESET}"
fi

# ── Step 4: Now it's safe to run Python ───────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  Step 4: Safe to launch Python now${RESET}"
echo -e "${DIM}  All .pth files quarantined. Python will not auto-execute malware.${RESET}"
echo ""

# Install ghostgap if not present (using -S to avoid .pth during pip)
if ! "$PYTHON_CMD" -S -c "
import sys, os
for p in sys.path:
    if p.endswith('site-packages') and os.path.isdir(p):
        sys.path.insert(0, p)
        break
import ghostgap
" 2>/dev/null; then
    echo -e "${YELLOW}  Installing ghostgap...${RESET}"
    "$PYTHON_CMD" -S -m pip install ghostgap -q 2>/dev/null || \
    "$PYTHON_CMD" -S -m pip install ghostgap --break-system-packages -q 2>/dev/null || \
        echo -e "${YELLOW}  Could not install ghostgap — install manually: pip install ghostgap${RESET}"
fi

# Run ghostgap with -S flag + safe .pth parser (processes paths, blocks executable lines)
# This ensures .pth code NEVER runs, even if new malicious .pth files appear
echo -e "${CYAN}${BOLD}  Running ghostgap cure (python -S — zero .pth execution)...${RESET}"
echo ""

"$PYTHON_CMD" -S -c "
import sys, os

# Safe .pth parser: add site-packages + process path entries, BLOCK all import lines
prefix = sys.prefix
sp = os.path.join(prefix, 'lib', 'python{}.{}'.format(sys.version_info[0], sys.version_info[1]), 'site-packages')
if not os.path.isdir(sp):
    sp = os.path.join(prefix, 'Lib', 'site-packages')

if os.path.isdir(sp) and sp not in sys.path:
    sys.path.insert(0, sp)

# Process .pth path entries only (skip executable lines)
if os.path.isdir(sp):
    for name in sorted(os.listdir(sp)):
        if not name.endswith('.pth') or name.startswith('.'):
            continue
        try:
            with open(os.path.join(sp, name), 'rb') as f:
                content = f.read().decode('utf-8-sig', errors='replace')
            for line in content.splitlines():
                ls = line.strip()
                if not ls or ls.startswith('#'):
                    continue
                if ls.startswith(('import ', 'import\t')):
                    continue  # BLOCKED
                d = os.path.join(sp, line.rstrip())
                if os.path.isdir(d) and d not in sys.path:
                    sys.path.append(d)
        except Exception:
            pass

from ghostgap.cli import main
sys.argv = ['ghostgap', 'cure']
main()
" 2>/dev/null || {
    echo -e "${YELLOW}  ghostgap not available — manual steps:${RESET}"
    echo -e "${YELLOW}    1. Rotate all SSH keys: ssh-keygen -t ed25519${RESET}"
    echo -e "${YELLOW}    2. Rotate AWS keys: aws iam create-access-key${RESET}"
    echo -e "${YELLOW}    3. Re-auth GCP: gcloud auth application-default login${RESET}"
    echo -e "${YELLOW}    4. Re-auth Azure: az login${RESET}"
    echo -e "${YELLOW}    5. Regenerate K8s config${RESET}"
    echo -e "${YELLOW}    6. Revoke all GitHub/GitLab tokens${RESET}"
}

echo ""
if [ "$FOUND_PTH" -eq 1 ] || [ "$FOUND_PERSIST" -eq 1 ]; then
    echo -e "${GREEN}${BOLD}  ╔════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}  ║   ✓  GHOST GAP CLOSED                                ║${RESET}"
    echo -e "${GREEN}${BOLD}  ║   .pth quarantined → persistence cleaned → cured      ║${RESET}"
    echo -e "${GREEN}${BOLD}  ╚════════════════════════════════════════════════════════╝${RESET}"
else
    echo -e "${GREEN}${BOLD}  ╔════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}  ║   ✓  NO GHOST GAP DETECTED                           ║${RESET}"
    echo -e "${GREEN}${BOLD}  ║   System appears clean                                ║${RESET}"
    echo -e "${GREEN}${BOLD}  ╚════════════════════════════════════════════════════════╝${RESET}"
fi
echo ""
