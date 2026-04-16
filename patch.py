#!/usr/bin/env python3
"""
VulnScan Pro — Master Patch Runner
===================================
Applies all patches in order. Run from the vulnscan project root.

Usage:
    cd ~/vulnscan
    python3 apply_all_patches.py

Individual patches can also be run separately:
    python3 patch_01_legion_searchsploit.py
    python3 patch_02_seclists_msfvenom.py
    python3 patch_03_misc.py
"""
import os, sys, subprocess, shutil
from datetime import datetime

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"
def ok(m): print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

print()
print(BOLD+CYAN+"╔══════════════════════════════════════════════════════╗"+RESET)
print(BOLD+CYAN+"║   VulnScan Pro — Master Patch Runner                ║"+RESET)
print(BOLD+CYAN+"║   Applies all 3 patch files in sequence             ║"+RESET)
print(BOLD+CYAN+"╚══════════════════════════════════════════════════════╝"+RESET)
print()

# ── Pre-flight checks ──────────────────────────────────────────────────────────
missing = [f for f in ["api_server.py","backend.py"] if not os.path.isfile(f)]
if missing:
    fail(f"Must be run from VulnScan project root. Missing: {', '.join(missing)}")
    sys.exit(1)

info(f"Project root: {os.getcwd()}")

PATCHES = [
    "patch_01_legion_searchsploit.py",
    "patch_02_seclists_msfvenom.py",
    "patch_03_misc.py",
]

# Copy patches to current directory if they're elsewhere
script_dir = os.path.dirname(os.path.abspath(__file__))
for pf in PATCHES:
    src_path = os.path.join(script_dir, pf)
    dst_path = os.path.join(os.getcwd(), pf)
    if not os.path.isfile(dst_path) and os.path.isfile(src_path):
        shutil.copy2(src_path, dst_path)
        info(f"Copied {pf} to {os.getcwd()}")

print()
all_ok = True
for i, patch_file in enumerate(PATCHES, 1):
    print(BOLD+f"  ── [{i}/{len(PATCHES)}] Running {patch_file}"+RESET)
    if not os.path.isfile(patch_file):
        fail(f"{patch_file} not found — copy it to {os.getcwd()} and retry")
        all_ok = False
        continue
    result = subprocess.run([sys.executable, patch_file], capture_output=False)
    if result.returncode != 0:
        warn(f"{patch_file} exited with code {result.returncode}")
    print()

# ── Syntax check ───────────────────────────────────────────────────────────────
print(BOLD+"  ── Syntax checks"+RESET)
for f in ["api_server.py","backend.py","database.py"]:
    if not os.path.isfile(f):
        continue
    r = subprocess.run([sys.executable,"-m","py_compile",f],
                       capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"{f} — OK")
    else:
        fail(f"{f} — SYNTAX ERROR:\n    {r.stderr.strip()}")
        all_ok = False

print()
print(BOLD+CYAN+"══════════════════════════════════════════════════════"+RESET)
if all_ok:
    print(f"  {GREEN}All patches applied successfully!{RESET}")
    print()
    print(f"  {CYAN}Restart to activate:{RESET}")
    print(f"    sudo systemctl restart vulnscan")
    print(f"    OR: python3 api_server.py")
    print()
    print(f"  {CYAN}What was patched:{RESET}")
    print(f"    {GREEN}✓{RESET}  Legion: SMB (smbclient), SNMP (snmpwalk), Hydra, Finger — full support")
    print(f"    {GREEN}✓{RESET}  SearchSploit: ANSI codes stripped, formatted table, HOW TO USE per exploit")
    print(f"    {GREEN}✓{RESET}  SecLists: Copy ALL passwords button (up to 500k entries) + Copy Visible")
    print(f"    {GREEN}✓{RESET}  msfvenom: Payload auto-fills format/encoder, LHOST=server IP, one-line agent")
    print(f"           command for target, handler command, session dashboard + shell")
    print(f"    {GREEN}✓{RESET}  Netcat: Shows 'run on other side' command + copy button")
    print(f"    {GREEN}✓{RESET}  Socat: Shows 'run on other side' command + copy button")
    print(f"    {GREEN}✓{RESET}  Hashcat: Auto-detect hash type button, AUTO-CRACK button (rockyou)")
    print(f"    {GREEN}✓{RESET}  Nav search: Works from first character, all tools indexed, arrow key nav")
    print(f"    {GREEN}✓{RESET}  Admin console: 'Add New Monitored Service' section removed")
    print(f"    {GREEN}✓{RESET}  Auditing page: Unified one-line agent, tool selector (Lynis/chkrootkit/rkhunter/OpenVAS)")
else:
    warn("Some patches had issues — check output above")
    warn("Backups saved as api_server.py.*.bak")
print()
