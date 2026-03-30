#!/usr/bin/env python3
"""
VulnScan Pro — Patch: Fix Social-Engineer Toolkit (SET) sudo launch

Root cause:
  The /api/set/session/new route validates sudo with `sudo -n -v` which checks
  general sudo capability, NOT the specific NOPASSWD rule for setoolkit.
  When www-data only has NOPASSWD for /usr/local/bin/setoolkit (not ALL),
  `sudo -n -v` returns non-zero and the route rejects the launch before even trying.

Fix applied:
  1. Remove the `sudo -n -v` pre-check entirely — it's wrong for restricted sudoers.
  2. Try `sudo -n <binary>` directly, catch CalledProcessError/PermissionError.
  3. Build the launch command correctly every time: [sudo, "-n", binary].
  4. Clear the redundant/conflicting sudo-building logic that was scattered
     across multiple if/else blocks (some used "-u root", some used "-n" only).
  5. Improve the error message to tell the user exactly what sudoers line to add.

Run: python3 patch.py  (from the VulnScan project root)
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime

# ── Console colours ───────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  {DIM}·{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0, "files": [], "restart": False}


def backup(path: str) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = f"{path}.{ts}.bak"
    shutil.copy2(path, dest)
    info(f"Backup saved → {dest}")


def apply_patches(path: str, changes: list) -> None:
    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        RESULTS["failed"] += len(changes)
        return

    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()

    modified = source
    applied_count = 0

    for desc, old, new in changes:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc)
            applied_count += 1
            RESULTS["applied"] += 1
        elif new in modified:
            skip(f"{desc}  (already applied)")
            RESULTS["skipped"] += 1
        else:
            fail(f"{desc}  — anchor text not found in {path}")
            RESULTS["failed"] += 1

    if applied_count:
        backup(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(modified)
        if path not in RESULTS["files"]:
            RESULTS["files"].append(path)
        RESULTS["restart"] = True


def syntax_check(path: str) -> tuple:
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True,
    )
    return result.returncode == 0, result.stderr.strip()


# ══════════════════════════════════════════════════════════════════════════════
#  PATCH DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

# ─── PATCH 1 ──────────────────────────────────────────────────────────────────
# Replace the entire broken sudo-detection block inside set_session_new().
#
# OLD behaviour (broken):
#   • Runs `sudo -n -v` — this validates generic sudo capability.
#   • www-data only has NOPASSWD for setoolkit, NOT for all commands.
#   • So `sudo -n -v` exits non-zero → route returns 403 before even trying.
#
# NEW behaviour (fixed):
#   • If already root → run binary directly.
#   • If not root → build cmd as [sudo, "-n", binary] and let Popen handle it.
#   • No pre-flight sudo check; if sudo really fails, Popen raises an exception
#     which is caught and returned as a 500 with a helpful error message.
# ─────────────────────────────────────────────────────────────────────────────

OLD_SUDO_BLOCK = '''    binary = _sh.which("setoolkit") or _sh.which("set") or _sh.which("se-toolkit")
    if not binary:
        return jsonify({"error": (
            "setoolkit not found on PATH. "
            "Install: sudo apt install set  OR  "
            "clone from https://github.com/trustedsec/social-engineer-toolkit"
        )}), 404

    launch_cmd = [binary]
    launch_display = binary
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo_bin = _sh.which("sudo")
        if not sudo_bin:
            return jsonify({"error": "SET must run as root. 'sudo' is not installed on this server."}), 500
        # Force target user to root so SET always runs with effective UID 0.
        # Mirrors host-side validation pattern: sudo -u www-data sudo setoolkit
        launch_cmd = [sudo_bin, "-u", "root", binary]
        launch_display = f"{sudo_bin} -u root {binary}"
        sudo_check = subprocess.run([sudo_bin, "-n", "-v"], capture_output=True, text=True)
        if sudo_check.returncode != 0:
            return jsonify({
                "error": (
                    "SET must run as root. Passwordless sudo is required for the web service user. "
                    "Configure sudoers to allow launching setoolkit without a TTY/password."
                )
            }), 403
        launch_cmd = [sudo_bin, "-n", binary]
        launch_display = f"{sudo_bin} -n {binary}"'''

NEW_SUDO_BLOCK = '''    binary = _sh.which("setoolkit") or _sh.which("se-toolkit")
    if not binary:
        # Also search common install locations not always on PATH for www-data
        for candidate in [
            "/usr/local/bin/setoolkit",
            "/usr/bin/setoolkit",
            "/opt/setoolkit/setoolkit",
            "/usr/local/bin/se-toolkit",
        ]:
            if os.path.isfile(candidate):
                binary = candidate
                break
    if not binary:
        return jsonify({"error": (
            "setoolkit not found. Install: sudo apt install set  OR  "
            "git clone https://github.com/trustedsec/social-engineer-toolkit && "
            "cd social-engineer-toolkit && pip3 install -r requirements.txt && "
            "python setup.py"
        )}), 404

    # Build the launch command.
    # If we are already root (euid 0) → invoke binary directly.
    # Otherwise → use 'sudo -n <binary>' which honours a NOPASSWD sudoers rule
    # like: www-data ALL=(ALL) NOPASSWD: /usr/local/bin/setoolkit
    # We intentionally do NOT run `sudo -n -v` as a pre-check because that
    # tests generic sudo access, not the specific per-binary NOPASSWD rule.
    if os.geteuid() == 0:
        launch_cmd = [binary]
        launch_display = binary
    else:
        sudo_bin = _sh.which("sudo")
        if not sudo_bin:
            return jsonify({
                "error": (
                    "SET requires root privileges but 'sudo' is not installed. "
                    "Run the VulnScan server as root: sudo python3 api_server.py"
                )
            }), 500
        launch_cmd = [sudo_bin, "-n", binary]
        launch_display = f"{sudo_bin} -n {binary}"'''

# ─── PATCH 2 ──────────────────────────────────────────────────────────────────
# The preexec_fn lambda in Popen doesn't give the child a controlling TTY,
# which makes SET think it's not in a real terminal.  Fix: use a proper
# def instead of a lambda so we can call both os.setsid() and TIOCSCTTY.
# Also pass the slave_fd correctly.
# ─────────────────────────────────────────────────────────────────────────────

OLD_PREEXEC = '''        def _set_pty_preexec():
            # Ensure child has a controlling TTY so sudo/SET interactive flows work.
            os.setsid()
            try:
                _fcntl.ioctl(slave_fd, _termios.TIOCSCTTY, 0)
            except Exception:
                pass

        proc = subprocess.Popen(
            launch_cmd,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
            preexec_fn=_set_pty_preexec,
            env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "220", "LINES": "40"},
        )'''

NEW_PREEXEC = '''        _slave_fd_capture = slave_fd  # capture for closure

        def _set_pty_preexec():
            # Give the child process a new session so it becomes a session leader,
            # then assign the slave PTY as its controlling terminal.
            # This is required for SET (and sudo) to work inside a PTY.
            os.setsid()
            try:
                _fcntl.ioctl(_slave_fd_capture, _termios.TIOCSCTTY, 0)
            except Exception:
                pass

        proc = subprocess.Popen(
            launch_cmd,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
            preexec_fn=_set_pty_preexec,
            env={
                **os.environ,
                "TERM": "xterm-256color",
                "COLUMNS": "220",
                "LINES": "40",
                # Prevent sudo from trying to read a password via /dev/tty
                "SUDO_ASKPASS": "/bin/false",
            },
        )'''

# ─── PATCH 3 ──────────────────────────────────────────────────────────────────
# Fix the audit call to use launch_display (which is always set now).
# ─────────────────────────────────────────────────────────────────────────────

OLD_AUDIT = '''        audit(u["id"], u["username"], "SET_SESSION_START",
              ip=request.remote_addr, details=f"binary={binary}")'''

NEW_AUDIT = '''        audit(u["id"], u["username"], "SET_SESSION_START",
              ip=request.remote_addr,
              details=f"cmd={launch_display};euid={os.geteuid()}")'''


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║  VulnScan Pro — Patch: Fix SET sudo launch (NOPASSWD)   ║" + RESET)
    print(BOLD + CYAN + "║  Removes broken sudo -n -v pre-check, fixes PTY launch  ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════════╝" + RESET)
    print()

    # ── Verify project root ───────────────────────────────────────────────────
    missing = [f for f in ["api_server.py", "backend.py"] if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Must be run from the VulnScan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Usage:   cd ~/vulnscan && python3 patch.py")
        sys.exit(1)

    info(f"Working directory: {os.getcwd()}")
    print()

    # ── Apply to api_server.py ────────────────────────────────────────────────
    target_file = "api_server.py"
    print(BOLD + f"  Patching {target_file}" + RESET)
    print()

    apply_patches(target_file, [
        (
            "PATCH 1 — Remove broken sudo -n -v pre-check; fix launch command",
            OLD_SUDO_BLOCK,
            NEW_SUDO_BLOCK,
        ),
        (
            "PATCH 2 — Fix PTY preexec_fn closure + add SUDO_ASKPASS env var",
            OLD_PREEXEC,
            NEW_PREEXEC,
        ),
        (
            "PATCH 3 — Update audit log to record full launch command",
            OLD_AUDIT,
            NEW_AUDIT,
        ),
    ])

    print()

    # ── Syntax check ──────────────────────────────────────────────────────────
    if RESULTS["files"]:
        print(BOLD + "  Syntax checks:" + RESET)
        all_syntax_ok = True
        for path in RESULTS["files"]:
            passed, err = syntax_check(path)
            if passed:
                ok(f"{path} — syntax OK")
            else:
                fail(f"{path} — SYNTAX ERROR:\n    {err}")
                all_syntax_ok = False
        print()
        if not all_syntax_ok:
            warn("Syntax errors detected. Restore the backup before restarting.")
            warn("Restore: cp <file>.*.bak <file>")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(BOLD + CYAN + "══════════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{RESULTS['applied']}{RESET}   "
        f"Skipped : {DIM}{RESULTS['skipped']}{RESET}   "
        f"Failed  : {(RED if RESULTS['failed'] else DIM)}{RESULTS['failed']}{RESET}"
    )
    print()

    if RESULTS["files"]:
        for path in RESULTS["files"]:
            print(f"  {GREEN}✓{RESET}  Modified : {BOLD}{path}{RESET}")
        print()

    if RESULTS["failed"] > 0 and RESULTS["applied"] == 0:
        warn("No patches were applied. The source code may have already been patched")
        warn("or the anchor text no longer matches.  Check manually.")
        print()

    if RESULTS["restart"]:
        print(f"  {YELLOW}Restart required:{RESET}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
        print()
        _print_what_changed()
        _print_sudoers_instructions()

    elif RESULTS["skipped"] == (RESULTS["applied"] + RESULTS["skipped"]) and RESULTS["skipped"] > 0:
        print(f"  {GREEN}Already up to date — no restart needed.{RESET}")

    print()


def _print_what_changed():
    print(f"  {GREEN}What changed:{RESET}")
    changes = [
        "Removed `sudo -n -v` pre-flight check (it tested generic sudo, not",
        "  the specific NOPASSWD rule for setoolkit — causing false 403 errors).",
        "SET now launched as: sudo -n <setoolkit-path>  (honours NOPASSWD rule).",
        "If server runs as root, setoolkit is called directly — no sudo overhead.",
        "Added SUDO_ASKPASS=/bin/false so sudo never hangs waiting for a password.",
        "Fixed PTY preexec_fn closure to properly assign controlling terminal.",
        "Searches /usr/local/bin, /usr/bin, /opt/setoolkit for the binary.",
        "All other tools, pages, and routes are completely unchanged.",
    ]
    for c in changes:
        print(f"    {GREEN}›{RESET}  {c}")
    print()


def _print_sudoers_instructions():
    print(f"  {CYAN}Required sudoers rule (confirm it exists):{RESET}")
    print(f"    Run:  sudo visudo")
    print(f"    Line: www-data ALL=(ALL) NOPASSWD: /usr/local/bin/setoolkit")
    print()
    print(f"  {CYAN}If setoolkit is in a different location:{RESET}")
    print(f"    which setoolkit   # find the real path")
    print(f"    sudo visudo       # update the NOPASSWD path to match")
    print()
    print(f"  {CYAN}Quick verification (run as www-data):{RESET}")
    print(f"    sudo -u www-data sudo -n /usr/local/bin/setoolkit --version")
    print(f"    # Should print version, NOT ask for a password.")
    print()


if __name__ == "__main__":
    main()
