#!/usr/bin/env python3
"""
VulnScan Pro — Patch: Replace 161.118.189.254 with 161.118.189.254
Run from project root: python3 patch_remove_port.py
"""
import os
import shutil
from datetime import datetime

OLD = "161.118.189.254"
NEW = "161.118.189.254"

FILES = [
    "api_server.py",
    "backend.py",
    "mail_config.py",
    "agent/install_agent.sh",
    "agent/install_agent.ps1",
    "agent/lynis_pull_agent.py",
    "agent/universal_agent.py",
    "patch.py",
    "nano.save",
    "README.md",
    "vulnscan_setup.sh",
    "vulnscan_watchdog.sh",
]

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")

applied = 0
skipped = 0
failed  = 0

print()
print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
print(BOLD + CYAN + "║  VulnScan Pro — Remove :5000 from IP addresses      ║" + RESET)
print(BOLD + CYAN + f"║  {OLD}  →  {NEW}          ║" + RESET)
print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
print()

for filepath in FILES:
    if not os.path.isfile(filepath):
        skip(f"{filepath} — not found, skipping")
        skipped += 1
        continue

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    count = content.count(OLD)
    if count == 0:
        skip(f"{filepath} — no occurrences found")
        skipped += 1
        continue

    # Backup
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{filepath}.{ts}.bak"
    shutil.copy2(filepath, bak)

    new_content = content.replace(OLD, NEW)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)

    ok(f"{filepath} — replaced {count} occurrence(s)  [backup: {bak}]")
    applied += count

print()
print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
print(f"  Replacements made : {GREEN}{applied}{RESET}")
print(f"  Files skipped     : {skipped}")
print(f"  Failures          : {RED if failed else ''}{failed}{RESET}")
print()
if applied:
    print(f"  {YELLOW}Restart server to apply changes:{RESET}")
    print(f"    pkill -f api_server.py && python3 api_server.py")
    print(f"    OR: sudo systemctl restart vulnscan")
print()
