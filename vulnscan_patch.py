#!/usr/bin/env python3
"""
vulnscan_patch.py — VulnScan Pro Direct Scan Fix
=================================================
Fixes: "No open ports found in range 1-10000" even when ports ARE open.

Root cause: nmap runs through proxychains4 by default. When Tor is not
running, proxychains silently fails -> nmap returns empty XML -> frontend
shows "No open ports found".

This patcher rewrites backend.py and api_server.py so:
  - Direct nmap is used by default (works immediately, no Tor needed)
  - proxychains/Tor is used ONLY when USE_TOR=1 env var is set
  - All other tool routes (dnsrecon, nikto, harvester, legion, wpscan)
    follow the same direct-first approach
  - The "No open ports" message now shows the real error when nmap fails
  - Global socket monkey-patch is removed (was breaking CVE lookups,
    dir busting, subdomain finder, SSL analysis)

Usage:
    python3 vulnscan_patch.py            # apply patches
    python3 vulnscan_patch.py --dry-run  # preview only, no writes

Creates .bak backup of every modified file before writing.
"""

import os, sys, shutil
from datetime import datetime

# ---- State -------------------------------------------------------------------
DRY_RUN         = "--dry-run" in sys.argv
CHANGES_APPLIED = 0
CHANGES_FAILED  = 0
FILES_BACKED_UP = []
FILES_MODIFIED  = []
RESTART_NEEDED  = False


# ---- Helpers -----------------------------------------------------------------

def backup(path):
    if path in FILES_BACKED_UP:
        return
    bak = path + ".bak"
    shutil.copy2(path, bak)
    FILES_BACKED_UP.append(path)
    print(f"    backup -> {bak}")


def patch(filepath, old, new, desc):
    global CHANGES_APPLIED, CHANGES_FAILED, RESTART_NEEDED

    if not os.path.isfile(filepath):
        print(f"  x  [{desc}]  file not found: {filepath}")
        CHANGES_FAILED += 1
        return False

    content = open(filepath, encoding="utf-8").read()

    if old not in content:
        print(f"  x  [{desc}]  string not found in {filepath}")
        CHANGES_FAILED += 1
        return False

    new_content = content.replace(old, new, 1)

    if not DRY_RUN:
        backup(filepath)
        open(filepath, "w", encoding="utf-8").write(new_content)

    if filepath not in FILES_MODIFIED:
        FILES_MODIFIED.append(filepath)
    if filepath.endswith(".py"):
        RESTART_NEEDED = True

    CHANGES_APPLIED += 1
    suffix = "  (dry-run)" if DRY_RUN else ""
    print(f"  v  [{desc}]{suffix}")
    return True


# ==============================================================================
# PATCH A1 - backend.py: add imports
# ==============================================================================

BACKEND_OLD_IMPORTS = (
    "import json, sys, subprocess, urllib.request, urllib.parse, time, re, socket, ssl\n"
    "import xml.etree.ElementTree as ET\n"
    "from datetime import datetime"
)

BACKEND_NEW_IMPORTS = (
    "import json, sys, subprocess, urllib.request, urllib.parse, time, re, socket, ssl\n"
    "import os, shutil\n"
    "import xml.etree.ElementTree as ET\n"
    "from datetime import datetime"
)

# ==============================================================================
# PATCH A2 - backend.py: replace global socket monkey-patch with safe system
# ==============================================================================

BACKEND_OLD_TOR = """\
# --- TOR / PROXY CONFIGURATION ---------------
# All external connections are routed through Tor (SOCKS5 on 127.0.0.1:9050)
# nmap uses proxychains; Python HTTP uses urllib via SOCKS5 proxy handler

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def get_tor_opener():
    \"\"\"
    Returns a urllib opener that routes through Tor SOCKS5.
    Requires: pip3 install PySocks --break-system-packages
    Falls back to direct if PySocks not available.
    \"\"\"
    try:
        import socks
        import socket as _socket
        # Monkey-patch socket for this process
        socks.set_default_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
        _socket.socket = socks.socksocket
        return urllib.request.build_opener()
    except ImportError:
        print("[!] PySocks not installed — HTTP requests won't use Tor.", file=sys.stderr)
        print("[!] Fix: pip3 install PySocks --break-system-packages", file=sys.stderr)
        return urllib.request.build_opener()

# Build the Tor opener once at module load
_tor_opener = None
def tor_opener():
    global _tor_opener
    if _tor_opener is None:
        _tor_opener = get_tor_opener()
    return _tor_opener

def tor_urlopen(url, headers=None, timeout=30, data=None):
    \"\"\"
    Open a URL through Tor. Wraps urllib with SOCKS5 proxy and custom headers.
    \"\"\"
    req = urllib.request.Request(url, data=data)
    req.add_header("User-Agent", "Mozilla/5.0 VulnScanner/2.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Try to use socks-patched socket
        opener = tor_opener()
        return opener.open(req, timeout=timeout)
    except Exception:
        # Fallback to standard urlopen
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)"""

BACKEND_NEW_TOR = """\
# --- TOR / PROXY CONFIGURATION -----------------------------------------------
# Direct scans are used by default. No Tor required.
# To enable Tor routing: USE_TOR=1 python3 api_server.py
# Requires: tor running on 9050, proxychains4 installed, PySocks installed.

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
USE_TOR        = os.environ.get("USE_TOR", "0") == "1"


def _proxychains_bin():
    \"\"\"Return proxychains binary path, or None if not installed.\"\"\"
    return shutil.which("proxychains4") or shutil.which("proxychains")


def _tor_reachable():
    \"\"\"Return True if Tor SOCKS5 is listening on TOR_SOCKS_PORT.\"\"\"
    try:
        import socket as _s
        s = _s.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def _should_use_tor():
    \"\"\"
    Return True only when: USE_TOR=1 AND proxychains installed AND Tor up.
    Otherwise always False -> scans run directly.
    \"\"\"
    if not USE_TOR:
        return False
    if not _proxychains_bin():
        print("[!] USE_TOR=1 but proxychains not found - using direct scan",
              file=sys.stderr)
        return False
    if not _tor_reachable():
        print("[!] USE_TOR=1 but Tor not reachable on port 9050 - using direct scan",
              file=sys.stderr)
        return False
    return True


def _wrap_cmd(cmd):
    \"\"\"Prepend proxychains to cmd list when Tor is enabled and reachable.\"\"\"
    if _should_use_tor():
        px = _proxychains_bin()
        return [px, "-q"] + cmd
    return cmd


def tor_urlopen(url, headers=None, timeout=30, data=None):
    \"\"\"
    Open a URL. When USE_TOR=1 and Tor is reachable, routes through Tor
    SOCKS5 using a safe per-request handler.
    IMPORTANT: Does NOT monkey-patch the global socket - that would break
    all other urllib/SSL calls (CVE lookups, subdomains, dir busting, etc.)
    Falls back to direct connection when Tor is not available.
    \"\"\"
    req = urllib.request.Request(url, data=data)
    req.add_header("User-Agent", "Mozilla/5.0 VulnScanner/2.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if _should_use_tor():
        try:
            import socks, http.client

            class _SocksHTTPSConn(http.client.HTTPSConnection):
                def connect(self):
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
                    s.settimeout(self.timeout or 30)
                    s.connect((self.host, self.port or 443))
                    self.sock = ctx.wrap_socket(s, server_hostname=self.host)

            class _SocksHTTPSHandler(urllib.request.HTTPSHandler):
                def https_open(self, req2):
                    return self.do_open(_SocksHTTPSConn, req2)

            opener = urllib.request.build_opener(_SocksHTTPSHandler())
            return opener.open(req, timeout=timeout)
        except Exception as exc:
            print(f"[!] Tor urlopen failed ({exc}), falling back to direct",
                  file=sys.stderr)

    # Direct fallback (or default when USE_TOR is not set)
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)"""

# ==============================================================================
# PATCH A3 - backend.py: run_nmap_scan - direct by default
# ==============================================================================

BACKEND_OLD_NMAP = """\
def run_nmap_scan(target):
    \"\"\"
    Runs nmap through proxychains (Tor).
    Uses TCP connect scan with conservative timing for proxy reliability.
    \"\"\"
    try:
        cmd = [
            "proxychains4", "-q",   # -q = quiet mode, suppress proxychains output
            "nmap",
            "-sT",                   # TCP connect scan (REQUIRED for proxychains)
            "-Pn",                   # Skip host discovery (REQUIRED -- ICMP blocked by Tor)
            "-n",                    # No DNS resolution (faster, avoids DNS leaks)
            "--open",                # Only show open ports
            "-T2",                   # Timing: polite -- avoids timeouts through Tor
                                     # T1=sneaky, T2=polite, T3=normal(default), T4=aggressive
            "--host-timeout", "300s",# Abort host after 5 min (Tor is slow)
            "--max-retries", "1",    # Only retry once -- retries waste time on proxies
            "--min-rtt-timeout", "500ms",
            "--max-rtt-timeout", "10000ms",  # Up to 10s per probe (Tor latency)
            "--initial-rtt-timeout", "2000ms",
            "-sV",                   # Version detection
            "--version-intensity", "2",  # Light version detection (fewer probes = faster)
            "--top-ports", "200",    # Scan top 200 ports instead of 1-10000
                                     # Full range through Tor would take 30+ minutes
            "-oX", "-",             # XML output to stdout
            target
        ]

        print(f"[*] Starting proxychains nmap scan on: {target}", file=sys.stderr)
        print(f"[*] Note: Tor routing active -- scan may take 3-10 minutes", file=sys.stderr)

        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600   # 10 minute timeout for full Tor scan
        )

        if r.returncode != 0 and not r.stdout.strip():
            stderr = r.stderr.strip()[:500]
            # Check for common proxychains errors
            if "proxychains" in stderr.lower() or "can't assign" in stderr.lower():
                return {"error": f"proxychains error: {stderr}. Make sure proxychains4 is installed and Tor is running on port {TOR_SOCKS_PORT}."}
            return {"error": f"nmap error (exit {r.returncode}): {stderr}"}

        if not r.stdout.strip():
            return {"error": "nmap produced no output -- target may be unreachable through Tor, or Tor is not running"}

        return parse_nmap_xml(r.stdout)

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 10 minutes. Through Tor this is normal for large ranges. Try a specific IP or reduce scope."}
    except FileNotFoundError as e:
        missing = "proxychains4" if "proxychains" in str(e) else "nmap"
        return {"error": f"{missing} not found. Install: sudo apt install {missing}"}
    except Exception as e:
        return {"error": str(e)}"""

BACKEND_NEW_NMAP = """\
def run_nmap_scan(target):
    \"\"\"
    Runs nmap directly by default (fast, no Tor required).
    Set USE_TOR=1 env var to route through proxychains/Tor instead.
    \"\"\"
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {"error": "nmap not found. Install: sudo apt install nmap"}

    use_tor = _should_use_tor()

    if use_tor:
        # Tor path: TCP connect required, conservative timing
        base_cmd = [
            nmap_bin,
            "-sT", "-Pn", "-n", "--open",
            "-T2",
            "--host-timeout",        "300s",
            "--max-retries",         "1",
            "--min-rtt-timeout",     "500ms",
            "--max-rtt-timeout",     "10000ms",
            "--initial-rtt-timeout", "2000ms",
            "-sV", "--version-intensity", "2",
            "--top-ports", "200",
            "-oX", "-",
            target,
        ]
        cmd = _wrap_cmd(base_cmd)
        scan_timeout = 600
        print(f"[*] nmap via Tor/proxychains -> {target}", file=sys.stderr)
    else:
        # Direct path: SYN scan, T4 timing, top-1000 ports
        cmd = [
            nmap_bin,
            "-sV", "-Pn", "-n", "--open",
            "-T4",
            "--host-timeout", "120s",
            "--max-retries",  "2",
            "--top-ports",    "1000",
            "-oX", "-",
            target,
        ]
        scan_timeout = 300
        print(f"[*] nmap direct scan -> {target}", file=sys.stderr)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_timeout)

        stdout = r.stdout or ""
        stderr = r.stderr or ""

        # Strip proxychains noise from stderr
        stderr_clean = "\\n".join(
            ln for ln in stderr.splitlines()
            if not ln.startswith("|") and "ProxyChains" not in ln
        ).strip()

        if not stdout.strip():
            detail = stderr_clean[:300] if stderr_clean else f"nmap exit code {r.returncode}"
            return {"error": f"nmap produced no output. {detail}"}

        return parse_nmap_xml(stdout)

    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {scan_timeout}s. Try a smaller target range."}
    except FileNotFoundError as exc:
        missing = "proxychains4" if "proxychains" in str(exc) else "nmap"
        return {"error": f"{missing} not found. Install: sudo apt install {missing}"}
    except Exception as exc:
        return {"error": str(exc)}"""

# ==============================================================================
# PATCH A4 - backend.py: network_discovery - direct by default
# ==============================================================================

BACKEND_OLD_DISC = """\
def network_discovery(subnet):
    \"\"\"
    Discover live hosts on a subnet through Tor/proxychains.
    NOTE: Host discovery is very limited through Tor -- only TCP-based
    discovery works. ICMP ping is blocked.
    \"\"\"
    try:
        cmd = [
            "proxychains4", "-q",
            "nmap",
            "-sT",          # TCP connect (proxychains requirement)
            "-Pn",          # No ping (ICMP blocked by Tor)
            "-n",           # No DNS
            "--open",
            "-T2",          # Polite timing
            "--host-timeout", "120s",
            "--max-retries", "1",
            "--top-ports", "10",   # Just check top 10 ports to detect hosts
            "-oX", "-",
            subnet
        ]
        print(f"[*] Network discovery via proxychains: {subnet}", file=sys.stderr)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not r.stdout.strip():
            return {"error": f"No output from nmap: {r.stderr.strip()[:200]}"}

        root = ET.fromstring(r.stdout)
        hosts = []
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            hd = {"status": "up", "ip": "", "mac": "", "vendor": "", "hostnames": []}
            for addr in host.findall("address"):
                at = addr.get("addrtype", "")
                if at == "ipv4":
                    hd["ip"] = addr.get("addr", "")
                elif at == "mac":
                    hd["mac"] = addr.get("addr", "")
                    hd["vendor"] = addr.get("vendor", "")
            hd["hostnames"] = [h.get("name", "") for h in host.findall("hostnames/hostname")]
            if hd["ip"]:
                hosts.append(hd)

        return {"hosts": hosts, "total": len(hosts)}

    except subprocess.TimeoutExpired:
        return {"error": "Network discovery timed out. Subnet scanning through Tor is very slow."}
    except FileNotFoundError:
        return {"error": "proxychains4 or nmap not found. Install: sudo apt install proxychains4 nmap"}
    except Exception as e:
        return {"error": str(e)}"""

BACKEND_NEW_DISC = """\
def network_discovery(subnet):
    \"\"\"
    Discover live hosts on a subnet.
    Direct by default; set USE_TOR=1 to route through proxychains/Tor.
    \"\"\"
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {"error": "nmap not found. Install: sudo apt install nmap"}

    use_tor = _should_use_tor()

    if use_tor:
        base = [nmap_bin, "-sT", "-Pn", "-n", "--open", "-T2",
                "--host-timeout", "120s", "--max-retries", "1",
                "--top-ports", "10", "-oX", "-", subnet]
        cmd = _wrap_cmd(base)
        timeout = 300
    else:
        cmd = [nmap_bin, "-sn", "-n", "--host-timeout", "30s", "-oX", "-", subnet]
        timeout = 120

    print(f"[*] Network discovery ({'Tor' if use_tor else 'direct'}) -> {subnet}",
          file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if not r.stdout.strip():
            return {"error": f"No output from nmap: {r.stderr.strip()[:200]}"}

        root = ET.fromstring(r.stdout)
        hosts = []
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            hd = {"status": "up", "ip": "", "mac": "", "vendor": "", "hostnames": []}
            for addr in host.findall("address"):
                at = addr.get("addrtype", "")
                if at == "ipv4":
                    hd["ip"] = addr.get("addr", "")
                elif at == "mac":
                    hd["mac"] = addr.get("addr", "")
                    hd["vendor"] = addr.get("vendor", "")
            hd["hostnames"] = [h.get("name", "") for h in host.findall("hostnames/hostname")]
            if hd["ip"]:
                hosts.append(hd)

        return {"hosts": hosts, "total": len(hosts)}

    except subprocess.TimeoutExpired:
        return {"error": f"Network discovery timed out after {timeout}s."}
    except FileNotFoundError:
        return {"error": "nmap not found. Install: sudo apt install nmap"}
    except Exception as exc:
        return {"error": str(exc)}"""

# ==============================================================================
# PATCH A5 - backend.py: analyze_ssl - use raw socket, no Tor dependency
# ==============================================================================

BACKEND_OLD_SSL = """\
    try:
        # Try SOCKS5 connection through Tor first
        try:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
            sock.settimeout(30)
            sock.connect((host, port))
        except ImportError:
            # Fallback to direct connection
            sock = socket.create_connection((host, port), timeout=30)"""

BACKEND_NEW_SSL = """\
    try:
        # Use a direct socket for SSL certificate analysis.
        # Routing through Tor adds latency with no benefit here,
        # and would hang if Tor is not running.
        import socket as _raw_socket
        sock = _raw_socket.create_connection((host, port), timeout=30)"""

# ==============================================================================
# PATCH A6 - backend.py: brute_force_ssh - remove broken Tor dependency
# ==============================================================================

BACKEND_OLD_SSH = """\
                    # Try to route SSH through Tor SOCKS5
                    try:
                        import socks
                        proxy_sock = socks.socksocket()
                        proxy_sock.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
                        proxy_sock.settimeout(30)
                        proxy_sock.connect((host, int(port)))
                        client.connect(
                            host, port=int(port),
                            username=username, password=password,
                            timeout=30, banner_timeout=30,
                            sock=proxy_sock
                        )
                    except ImportError:
                        # Fallback: direct connection
                        client.connect(
                            host, port=int(port),
                            username=username, password=password,
                            timeout=30, banner_timeout=30
                        )"""

BACKEND_NEW_SSH = """\
                    client.connect(
                        host, port=int(port),
                        username=username, password=password,
                        timeout=30, banner_timeout=30,
                    )"""

# ==============================================================================
# PATCH B1 - api_server.py: add USE_TOR flag + helpers after TOR constants
# ==============================================================================

API_OLD_TOR_CONSTS = """\
# -- Tor / proxychains config --------------------------------------------------
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050"""

API_NEW_TOR_CONSTS = """\
# -- Tor / proxychains config --------------------------------------------------
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
# Set USE_TOR=1 to enable proxychains/Tor routing for all tool routes.
USE_TOR_ENV = os.environ.get("USE_TOR", "0") == "1"


def _tor_up():
    \"\"\"Return True if Tor SOCKS5 is reachable on TOR_SOCKS_PORT.\"\"\"
    try:
        import socket as _s
        s = _s.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def _use_proxychains():
    \"\"\"
    Return (should_wrap: bool, px_bin: str|None).
    Wraps commands in proxychains ONLY when USE_TOR=1 AND proxychains
    is installed AND Tor is actually reachable.
    \"\"\"
    if not USE_TOR_ENV:
        return False, None
    px = proxychains_cmd()
    if not px:
        return False, None
    if not _tor_up():
        return False, None
    return True, px"""

# ==============================================================================
# PATCH B2 - api_server.py: dnsrecon route
# ==============================================================================

API_OLD_DR = """\
    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    # Build dnsrecon command through proxychains
    # Use --tcp flag so DNS queries go through SOCKS (TCP only -- UDP is blocked by Tor)
    cmd = [px, "-q", binary, "-d", target, "-t", scan_type, "-j", out_file, "--tcp"]
    if ns:
        cmd += ["-n", ns]"""

API_NEW_DR = """\
    wrap, px = _use_proxychains()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    if wrap:
        cmd = [px, "-q", binary, "-d", target, "-t", scan_type, "-j", out_file, "--tcp"]
    else:
        cmd = [binary, "-d", target, "-t", scan_type, "-j", out_file]
    if ns:
        cmd += ["-n", ns]"""

# ==============================================================================
# PATCH B3 - api_server.py: nikto route
# ==============================================================================

API_OLD_NK = """\
    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name

    # Route Nikto through proxychains
    # Also pass -useproxy pointing to Tor SOCKS5 as a secondary proxy option
    cmd = [
        px, "-q",
        binary,
        "-h", target,
        "-p", str(port),
        "-Format", "json",
        "-o", out_file,
        "-nointeractive",
        "-timeout", "30",      # 30s per request (Tor latency)
        "-maxtime", "1800",    # Max 30 min total
    ]"""

API_NEW_NK = """\
    wrap, px = _use_proxychains()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name

    base_cmd = [
        binary,
        "-h", target, "-p", str(port),
        "-Format", "json", "-o", out_file,
        "-nointeractive",
        "-timeout", "30" if wrap else "15",
        "-maxtime", "1800" if wrap else "600",
    ]
    cmd = [px, "-q"] + base_cmd if wrap else base_cmd"""

# ==============================================================================
# PATCH B4 - api_server.py: theHarvester route
# ==============================================================================

API_OLD_HV = """\
    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    px = proxychains_cmd()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "harvest")

        # Route theHarvester through proxychains
        cmd = [px, "-q", binary, "-d", target, "-l", str(limit), "-b", sources, "-f", out_file]"""

API_NEW_HV = """\
    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    wrap, px = _use_proxychains()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "harvest")

        base_cmd = [binary, "-d", target, "-l", str(limit), "-b", sources, "-f", out_file]
        cmd = [px, "-q"] + base_cmd if wrap else base_cmd"""

# ==============================================================================
# PATCH B5 - api_server.py: legion route
# ==============================================================================

API_OLD_LG = """\
    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0

    # Timing map adjusted for Tor
    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T2"}[intensity]

    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({
                "module": mod,
                "summary": f"{mod} not found -- install: sudo apt install {mod}",
                "findings": []
            })
            continue

        modules_run += 1
        findings = []

        try:
            if mod == "nmap":
                # nmap through proxychains
                cmd = [
                    px, "-q", "nmap",
                    "-sT", "-Pn", "-n",    # TCP connect, no ping, no DNS
                    speed,
                    "--open",
                    "--host-timeout", "180s",
                    "--max-retries", "1",
                    "--top-ports", "100",
                    "-sV", "--version-intensity", "2",
                    target
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in proc.stdout.splitlines():
                    m = re.match(r'^(\\d+/\\w+)\\s+open\\s+(\\S+)\\s*(.*)', line)
                    if m:
                        open_ports += 1
                        findings.append({
                            "title": f"Port {m.group(1)} open",
                            "detail": f"{m.group(2)} {m.group(3)}".strip()
                        })

            elif mod == "nikto":
                # Nikto through proxychains
                cmd = [
                    px, "-q", binary,
                    "-h", target,
                    "-nointeractive",
                    "-timeout", "30",
                    "-maxtime", "600",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=700)
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"):
                        findings.append({"title": line.strip()[2:80], "detail": ""})
                        total_issues += 1

            else:
                # Other tools through proxychains
                proc = subprocess.run(
                    [px, "-q", binary, target],
                    capture_output=True, text=True, timeout=180
                )
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})"""

API_NEW_LG = """\
    wrap, px = _use_proxychains()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0

    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T2"}[intensity] if wrap \
        else {"light": "-T3", "normal": "-T4", "aggressive": "-T4"}[intensity]

    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({
                "module": mod,
                "summary": f"{mod} not found -- install: sudo apt install {mod}",
                "findings": []
            })
            continue

        modules_run += 1
        findings = []

        try:
            if mod == "nmap":
                if wrap:
                    base = ["nmap", "-sT", "-Pn", "-n", speed, "--open",
                            "--host-timeout", "180s", "--max-retries", "1",
                            "--top-ports", "100", "-sV", "--version-intensity", "2", target]
                    cmd = [px, "-q"] + base
                    t = 300
                else:
                    cmd = ["nmap", "-sV", "-Pn", "-n", speed, "--open",
                           "--host-timeout", "60s", "--top-ports", "100", target]
                    t = 120
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
                for line in proc.stdout.splitlines():
                    m = re.match(r'^(\\d+/\\w+)\\s+open\\s+(\\S+)\\s*(.*)', line)
                    if m:
                        open_ports += 1
                        findings.append({
                            "title": f"Port {m.group(1)} open",
                            "detail": f"{m.group(2)} {m.group(3)}".strip()
                        })

            elif mod == "nikto":
                base = [binary, "-h", target, "-nointeractive",
                        "-timeout", "30" if wrap else "10",
                        "-maxtime", "600" if wrap else "300"]
                cmd = [px, "-q"] + base if wrap else base
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=700 if wrap else 360)
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"):
                        findings.append({"title": line.strip()[2:80], "detail": ""})
                        total_issues += 1

            else:
                base = [binary, target]
                cmd = [px, "-q"] + base if wrap else base
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})"""

# ==============================================================================
# PATCH B6 - api_server.py: health route - show scan_mode
# ==============================================================================

API_OLD_HEALTH = """\
    return jsonify({
        "status": "ok",
        "version": "3.7",
        "nmap": bool(shutil.which("nmap")),
        "dig": bool(shutil.which("dig")),
        "proxychains4": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "tor_running": tor_running,
        "tor_port": TOR_SOCKS_PORT,
        "python": sys.version
    })"""

API_NEW_HEALTH = """\
    px_bin = shutil.which("proxychains4") or shutil.which("proxychains")
    tor_active = USE_TOR_ENV and bool(px_bin) and tor_running
    return jsonify({
        "status":      "ok",
        "version":     "3.7",
        "nmap":        bool(shutil.which("nmap")),
        "dig":         bool(shutil.which("dig")),
        "proxychains": bool(px_bin),
        "tor_running": tor_running,
        "scan_mode":   "tor+proxychains" if tor_active else "direct",
        "tor_hint":    "Set USE_TOR=1 env var to enable Tor routing",
        "python":      sys.version,
    })"""


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    print()
    print("=" * 68)
    print("  VulnScan Pro -- Direct Scan Fix Patcher")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
          + ("  [DRY-RUN]" if DRY_RUN else ""))
    print("=" * 68)
    print()

    # ---- backend.py ----------------------------------------------------------
    print("-- backend.py ---------------------------------------------------")
    patch("backend.py", BACKEND_OLD_IMPORTS,  BACKEND_NEW_IMPORTS,
          "Add `import os, shutil` at module level")
    patch("backend.py", BACKEND_OLD_TOR,      BACKEND_NEW_TOR,
          "Replace global socket monkey-patch with safe USE_TOR opt-in system")
    patch("backend.py", BACKEND_OLD_NMAP,     BACKEND_NEW_NMAP,
          "run_nmap_scan: direct by default, top-1000 ports, T4 timing")
    patch("backend.py", BACKEND_OLD_DISC,     BACKEND_NEW_DISC,
          "network_discovery: direct by default")
    patch("backend.py", BACKEND_OLD_SSL,      BACKEND_NEW_SSL,
          "analyze_ssl: always use raw stdlib socket")
    patch("backend.py", BACKEND_OLD_SSH,      BACKEND_NEW_SSH,
          "brute_force_ssh: remove broken Tor/PySocks dependency")
    print()

    # ---- api_server.py -------------------------------------------------------
    print("-- api_server.py ------------------------------------------------")
    patch("api_server.py", API_OLD_TOR_CONSTS, API_NEW_TOR_CONSTS,
          "Add USE_TOR_ENV + _tor_up() + _use_proxychains() helpers")
    patch("api_server.py", API_OLD_DR,         API_NEW_DR,
          "dnsrecon route: direct by default")
    patch("api_server.py", API_OLD_NK,         API_NEW_NK,
          "nikto route: direct by default")
    patch("api_server.py", API_OLD_HV,         API_NEW_HV,
          "theHarvester route: direct by default")
    patch("api_server.py", API_OLD_LG,         API_NEW_LG,
          "legion route: direct by default, T4 timing")
    patch("api_server.py", API_OLD_HEALTH,     API_NEW_HEALTH,
          "/health: add scan_mode field")
    print()

    # ---- Summary -------------------------------------------------------------
    print("=" * 68)
    print("  SUMMARY")
    print("=" * 68)
    print(f"  Changes applied : {CHANGES_APPLIED}")
    print(f"  Changes failed  : {CHANGES_FAILED}")
    print(f"  Files modified  : {len(FILES_MODIFIED)}")
    for f in FILES_MODIFIED:
        note = f"  (backup: {f}.bak)" if not DRY_RUN else "  (dry-run)"
        print(f"    * {f}{note}")
    print()

    if CHANGES_FAILED:
        print("  WARNING: Some patches were skipped (string not found).")
        print("  The file may already be patched, or the code version differs.")
        print("  Check the 'x' lines above for details.")
        print()

    if DRY_RUN:
        print("  Dry-run complete -- no files written.")
        print("  Remove --dry-run to apply changes.")
    else:
        print("  Done! Restart the server:")
        print()
        print("      python3 api_server.py")
        print()
        print("  To undo all changes, restore from backups:")
        for f in FILES_MODIFIED:
            print(f"      cp {f}.bak {f}")
    print()
    print("  What was fixed:")
    print("  ---------------------------------------------------------------")
    print("  * Scans now run DIRECTLY -- no Tor/proxychains required")
    print("  * nmap scans top-1000 ports at T4 timing (was 200 ports via Tor)")
    print("  * 'No open ports found' now shows the real nmap error if any")
    print("  * CVE lookups, subdomain finder, dir busting all work again")
    print("    (global socket monkey-patch that broke urllib/SSL is removed)")
    print("  * SSL analysis uses raw stdlib socket -- no PySocks needed")
    print("  * SSH brute-force no longer requires PySocks")
    print("  * dnsrecon, nikto, harvester, legion all run directly by default")
    print()
    print("  To re-enable Tor routing (optional, requires Tor + proxychains4):")
    print("      USE_TOR=1 python3 api_server.py")
    print()


if __name__ == "__main__":
    main()
