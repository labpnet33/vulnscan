#!/usr/bin/env python3
"""
VulnScan Pro — Full Fix & Diagnostic Script (Kali/Debian edition)
=================================================================
Fixes ALL known startup issues on Kali Linux / Debian / Ubuntu:
  1. Missing Python dependencies via apt (correct method for Kali)
  2. Duplicate app.run() outside __main__  →  OSError: Address already in use
  3. Port 5000 already occupied by another process
  4. Stale .pyc cache causing import errors
  5. Final syntax check on all core files

Run:
    python3 vulnscan_fix.py               # auto-finds api_server.py
    python3 vulnscan_fix.py /path/to/api_server.py
"""

import os, re, sys, shutil, subprocess, socket, time
from datetime import datetime

# ── Colours ───────────────────────────────────────────────────────────────────
G = "\033[92m";  R = "\033[91m";  C = "\033[96m"
Y = "\033[93m";  B = "\033[1m";   D = "\033[2m";  X = "\033[0m"

def ok(m):   print(f"  {G}checkmark{X}  {m}".replace("checkmark", "✓"))
def fail(m): print(f"  {R}cross{X}  {m}".replace("cross", "✗"))
def info(m): print(f"  {C}arrow{X}  {m}".replace("arrow", "→"))
def warn(m): print(f"  {Y}bang{X}  {m}".replace("bang", "!"))
def hdr(m):  print(f"\n{B}{C}---  {m}  ---{X}")

RESULTS = {"fixed": 0, "skipped": 0, "failed": 0}

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_api_server(argv):
    if len(argv) > 1 and os.path.isfile(argv[1]):
        return argv[1]
    for p in [
        "api_server.py",
        os.path.expanduser("~/vulnscan/api_server.py"),
        "/opt/vulnscan/api_server.py",
        "/var/www/vulnscan/api_server.py",
    ]:
        if os.path.isfile(p):
            return p
    return None


def backup(path):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst


def syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True,
    )
    return r.returncode == 0, r.stderr.strip()


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def is_debian():
    return shutil.which("apt-get") is not None


def try_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def run_cmd(cmd, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# ══════════════════════════════════════════════════════════════════════════════
# FIX 1 — Install missing Python dependencies
#   On Kali/Debian: use apt-get (avoids externally-managed-environment error)
#   Fallback: pip install (for non-Debian systems or missing apt packages)
# ══════════════════════════════════════════════════════════════════════════════

# (import_name, apt_package, pip_package)
PACKAGES = [
    ("flask",       "python3-flask",        "flask"),
    ("flask_cors",  "python3-flask-cors",   "flask-cors"),
    ("reportlab",   "python3-reportlab",    "reportlab"),
    ("socks",       "python3-socks",        "PySocks"),
    ("paramiko",    "python3-paramiko",     "paramiko"),
]


def install_apt(pkg):
    rc, out, err = run_cmd(["sudo", "apt-get", "install", "-y", "-q", pkg])
    return rc == 0


def install_pip(pkg):
    # Try several pip methods in order
    for cmd in [
        [sys.executable, "-m", "pip", "install", pkg, "--break-system-packages", "-q"],
        [sys.executable, "-m", "pip", "install", pkg, "--user", "-q"],
        [sys.executable, "-m", "pip", "install", pkg, "-q"],
        ["pip3", "install", pkg, "--user", "-q"],
    ]:
        try:
            rc, out, err = run_cmd(cmd)
            if rc == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def fix_dependencies():
    hdr("FIX 1 — Python Dependencies")
    use_apt = is_debian()
    print(f"  Install method: {'apt-get (Kali/Debian)' if use_apt else 'pip'}\n")

    for import_name, apt_pkg, pip_pkg in PACKAGES:
        if try_import(import_name):
            print(f"  {G}ok{X}  {pip_pkg:<18} already installed".replace("ok", "✓"))
            continue

        print(f"  {Y}!!{X}  {pip_pkg:<18} MISSING — installing...".replace("!!", "!"))

        installed = False

        if use_apt:
            # First try apt-get
            if install_apt(apt_pkg):
                print(f"  {G}ok{X}  {pip_pkg:<18} installed via apt ({apt_pkg})".replace("ok", "✓"))
                installed = True
            else:
                # apt failed, fall back to pip
                print(f"  {Y}!!{X}  apt failed for {apt_pkg}, trying pip...".replace("!!", "!"))
                if install_pip(pip_pkg):
                    print(f"  {G}ok{X}  {pip_pkg:<18} installed via pip".replace("ok", "✓"))
                    installed = True
        else:
            if install_pip(pip_pkg):
                print(f"  {G}ok{X}  {pip_pkg:<18} installed via pip".replace("ok", "✓"))
                installed = True

        if not installed:
            print(f"  {R}XX{X}  {pip_pkg:<18} INSTALL FAILED".replace("XX", "✗"))
            if use_apt:
                print(f"       Manual fix:  sudo apt-get install -y {apt_pkg}")
            else:
                print(f"       Manual fix:  pip3 install {pip_pkg}")
            RESULTS["failed"] += 1
        else:
            RESULTS["fixed"] += 1


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2 — Remove duplicate bare app.run() outside __main__
# ══════════════════════════════════════════════════════════════════════════════

BARE_RUN_RE   = re.compile(r'^[ \t]{0,3}app\.run\s*\(.*\)\s*$')
MAIN_GUARD_RE = re.compile(r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:')


def fix_duplicate_apprun(path):
    hdr("FIX 2 — Duplicate app.run() Outside __main__")

    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    output      = []
    removed     = []
    inside_main = False
    main_indent = None

    for lineno, line in enumerate(lines, 1):
        stripped = line.rstrip()

        if MAIN_GUARD_RE.match(line):
            inside_main = True
            main_indent = len(line) - len(line.lstrip())
            output.append(line)
            continue

        if inside_main and main_indent is not None:
            if stripped and not stripped.startswith("#"):
                cur_indent = len(line) - len(line.lstrip())
                if cur_indent <= main_indent and not MAIN_GUARD_RE.match(line):
                    inside_main = False

        if not inside_main and BARE_RUN_RE.match(stripped):
            removed.append((lineno, stripped))
            output.append(
                f"# [vulnscan_fix] removed duplicate app.run() from line {lineno}\n"
            )
            continue

        output.append(line)

    if not removed:
        print(f"  {G}ok{X}  No duplicate app.run() found — already clean".replace("ok", "✓"))
        RESULTS["skipped"] += 1
        return

    print(f"  {Y}!!{X}  Found {len(removed)} duplicate line(s):".replace("!!", "!"))
    for ln, txt in removed:
        print(f"       line {ln}: {D}{txt[:70]}{X}")

    bak = backup(path)
    print(f"  {G}ok{X}  Backup saved -> {bak}".replace("ok", "✓"))

    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(output)

    passed, err = syntax_check(path)
    if passed:
        print(f"  {G}ok{X}  Patched file — syntax OK".replace("ok", "✓"))
        RESULTS["fixed"] += 1
    else:
        print(f"  {R}XX{X}  Syntax error after patch: {err}".replace("XX", "✗"))
        shutil.copy2(bak, path)
        print(f"  {R}XX{X}  Backup restored — patch rolled back".replace("XX", "✗"))
        RESULTS["failed"] += 1


# ══════════════════════════════════════════════════════════════════════════════
# FIX 3 — Free port 5000 if occupied
# ══════════════════════════════════════════════════════════════════════════════

def fix_port(port=5000):
    hdr(f"FIX 3 — Free Port {port}")

    if port_free(port):
        print(f"  {G}ok{X}  Port {port} is already free".replace("ok", "✓"))
        RESULTS["skipped"] += 1
        return

    print(f"  {Y}!!{X}  Port {port} is in use — trying to free it".replace("!!", "!"))
    freed = False

    for cmd in [
        ["sudo", "fuser", "-k", f"{port}/tcp"],
        ["fuser", "-k", f"{port}/tcp"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            time.sleep(1)
            if port_free(port):
                print(f"  {G}ok{X}  Port {port} freed via fuser".replace("ok", "✓"))
                freed = True
                RESULTS["fixed"] += 1
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not freed:
        try:
            r = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True, text=True, timeout=5,
            )
            pids = r.stdout.strip().split()
            if pids:
                subprocess.run(["kill", "-9"] + pids, capture_output=True)
                time.sleep(1)
                if port_free(port):
                    print(f"  {G}ok{X}  Port {port} freed (killed PID {' '.join(pids)})".replace("ok", "✓"))
                    freed = True
                    RESULTS["fixed"] += 1
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not freed:
        print(f"  {Y}!!{X}  Could not auto-free port {port}. Run manually:".replace("!!", "!"))
        print(f"       sudo fuser -k {port}/tcp")
        print(f"       OR use a different port:  PORT=5001 python3 api_server.py")
        RESULTS["failed"] += 1


# ══════════════════════════════════════════════════════════════════════════════
# FIX 4 — Clear stale __pycache__
# ══════════════════════════════════════════════════════════════════════════════

def fix_pycache(directory):
    hdr("FIX 4 — Clear Stale .pyc / __pycache__")
    count = 0
    for root, dirs, files in os.walk(directory):
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                count += 1
        for f in files:
            if f.endswith(".pyc"):
                try:
                    os.remove(os.path.join(root, f))
                    count += 1
                except OSError:
                    pass
    if count:
        print(f"  {G}ok{X}  Removed {count} stale cache item(s)".replace("ok", "✓"))
        RESULTS["fixed"] += 1
    else:
        print(f"  {G}ok{X}  No stale cache found".replace("ok", "✓"))
        RESULTS["skipped"] += 1


# ══════════════════════════════════════════════════════════════════════════════
# FIX 5 — Final syntax check on all core files
# ══════════════════════════════════════════════════════════════════════════════

def fix_syntax_verify(path):
    hdr("FIX 5 — Final Syntax Check")
    proj = os.path.dirname(path)
    all_ok = True
    for name in ["api_server.py", "backend.py", "auth.py", "database.py", "mail_config.py"]:
        fp = os.path.join(proj, name)
        if not os.path.isfile(fp):
            print(f"  {D}  {name:<22} not found — skipping{X}")
            continue
        passed, err = syntax_check(fp)
        if passed:
            print(f"  {G}ok{X}  {name:<22} syntax OK".replace("ok", "✓"))
        else:
            print(f"  {R}XX{X}  {name:<22} SYNTAX ERROR".replace("XX", "✗"))
            print(f"       {err}")
            all_ok = False
            RESULTS["failed"] += 1
    if all_ok:
        print(f"\n  {G}ok{X}  All files passed syntax check".replace("ok", "✓"))


# ══════════════════════════════════════════════════════════════════════════════
# DIAGNOSTICS — full status report
# ══════════════════════════════════════════════════════════════════════════════

def run_diagnostics(path):
    hdr("FULL DIAGNOSTICS")
    proj = os.path.dirname(os.path.abspath(path))

    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Project : {proj}")
    print(f"  OS mode : {'Kali/Debian (apt available)' if is_debian() else 'Other'}")

    # Python packages
    print(f"\n  PYTHON PACKAGES")
    print(f"  {'─'*44}")
    for import_name, apt_pkg, pip_pkg in PACKAGES:
        if try_import(import_name):
            print(f"  {G}ok{X}  {pip_pkg:<20} installed".replace("ok", "✓"))
        else:
            print(f"  {R}XX{X}  {pip_pkg:<20} MISSING  ->  sudo apt-get install {apt_pkg}".replace("XX", "✗"))

    # System tools
    print(f"\n  SYSTEM TOOLS")
    print(f"  {'─'*44}")
    tools = {
        "nmap": True, "dig": True, "nikto": False,
        "lynis": False, "dnsrecon": False, "theHarvester": False,
        "wpscan": False, "tor": False, "proxychains4": False,
        "john": False, "sqlmap": False,
    }
    for tool, required in tools.items():
        found = shutil.which(tool)
        if found:
            print(f"  {G}ok{X}  {tool:<20} {D}{found}{X}".replace("ok", "✓"))
        elif required:
            print(f"  {R}XX{X}  {tool:<20} MISSING (required)  ->  sudo apt-get install {tool}".replace("XX", "✗"))
        else:
            print(f"  {D}  {tool:<20} not installed (optional){X}")

    # Port status
    print(f"\n  PORT STATUS")
    print(f"  {'─'*44}")
    for port, label in [(5000, "VulnScan main"), (5001, "VulnScan fallback"), (9050, "Tor SOCKS5")]:
        status = f"{G}FREE{X}" if port_free(port) else f"{R}IN USE{X}"
        print(f"  {C}:{port:<6}{X}  {label:<20} {status}")

    # How to view logs
    print(f"\n  HOW TO SEE LOGS")
    print(f"  {'─'*44}")
    print(f"  Start server + save logs:")
    print(f"      python3 api_server.py 2>&1 | tee vulnscan.log")
    print(f"  Watch logs in real time (open a second terminal):")
    print(f"      tail -f vulnscan.log")
    print(f"  Start on a different port if 5000 is busy:")
    print(f"      PORT=5001 python3 api_server.py")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print(B + C + "+----------------------------------------------------+" + X)
    print(B + C + "|  VulnScan Pro -- vulnscan_fix.py (Kali edition)   |" + X)
    print(B + C + "|  Fixes deps + port conflicts + syntax errors       |" + X)
    print(B + C + "+----------------------------------------------------+" + X)
    print()

    path = find_api_server(sys.argv)
    if not path:
        print(R + B + "  ERROR: api_server.py not found." + X)
        print("  Run from ~/vulnscan/ or pass the path:")
        print("      python3 vulnscan_fix.py /path/to/api_server.py")
        sys.exit(1)

    path = os.path.abspath(path)
    proj = os.path.dirname(path)
    print(f"  Found: {path}\n")

    fix_dependencies()
    fix_duplicate_apprun(path)
    fix_port(5000)
    fix_pycache(proj)
    fix_syntax_verify(path)
    run_diagnostics(path)

    hdr("SUMMARY")
    print()
    print(
        f"  Fixed   : {G}{RESULTS['fixed']}{X}   "
        f"Skipped : {D}{RESULTS['skipped']}{X}   "
        f"Failed  : {(R if RESULTS['failed'] else D)}{RESULTS['failed']}{X}"
    )
    print()

    if RESULTS["failed"] == 0:
        print(f"  {G}{B}All good! Start VulnScan:{X}\n")
        print(f"      cd {proj}")
        print(f"      python3 api_server.py")
        print()
        print(f"  Open browser:  http://localhost:5000")
    else:
        print(f"  {Y}Some issues need manual attention — see above.{X}")
        print()
        print(f"  Quick manual fix (Kali Linux):")
        print(f"      sudo apt-get install -y python3-socks python3-paramiko \\")
        print(f"           python3-flask python3-flask-cors python3-reportlab")
        print(f"      sudo fuser -k 5000/tcp")
        print(f"      python3 api_server.py 2>&1 | tee vulnscan.log")
    print()


if __name__ == "__main__":
    main()
