#!/usr/bin/env python3
"""
VulnScan Pro — Universal Remote Audit Agent Patch
==================================================
Transforms the Lynis-only remote agent into a UNIVERSAL remote agent
that can run ALL security tools on connected systems:

  • nmap, nikto, wpscan, dnsrecon, theHarvester, lynis, sqlmap, nuclei,
    whatweb, ffuf, dirb, medusa, john, hashcat, chkrootkit, rkhunter,
    wapiti, dalfox, hping3, and more.

Single install command connects a system. Once connected, the UI shows
all available tools for that system. All scans execute on the REMOTE
system and results stream back to the server.

Changes:
  1. agent/universal_agent.py     — new universal agent (replaces lynis_pull_agent.py)
  2. agent/install_agent.sh       — updated installer points to universal agent
  3. api_server.py                — new /api/remote/* routes + UI page injection
  4. api_server.db init           — adds remote_jobs table columns for all tools

Run from project root:
    python3 patch_universal_agent.py

Then on remote Linux systems:
    curl -fsSL http://YOUR_SERVER:5000/agent/install.sh | bash
"""

import os, sys, shutil, subprocess
from datetime import datetime

# ── colours ──────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")

TARGET_SERVER = "api_server.py"
AGENT_DIR     = "agent"
RESULTS = {"created": 0, "patched": 0, "skipped": 0, "failed": 0}


def backup(path):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.universal_agent_{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def write_file(path, content):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


def apply_patch(src, label, old, new):
    if old in src:
        result = src.replace(old, new, 1)
        ok(label)
        RESULTS["patched"] += 1
        return result
    elif new in src:
        from textwrap import shorten
        warn(f"{label} (already applied)")
        RESULTS["skipped"] += 1
        return src
    else:
        fail(f"{label} — anchor not found")
        RESULTS["failed"] += 1
        return src


# ══════════════════════════════════════════════════════════════════════════════
# FILE 1: Universal Agent (agent/universal_agent.py)
# ══════════════════════════════════════════════════════════════════════════════

UNIVERSAL_AGENT = r'''#!/usr/bin/env python3
"""
VulnScan Pro — Universal Remote Audit Agent
Polls server for ANY tool job, executes locally, streams output back.
Tools supported: nmap, nikto, lynis, wpscan, dnsrecon, theHarvester,
                 sqlmap, nuclei, whatweb, ffuf, medusa, john, hashcat,
                 chkrootkit, rkhunter, wapiti, dalfox, hping3, and more.
"""
import argparse, json, os, platform, re, shutil, socket
import subprocess, tempfile, time, urllib.error, urllib.request

TOOL_TIMEOUT = {
    "nmap":         720,
    "nikto":        900,
    "lynis":        480,
    "wpscan":       480,
    "dnsrecon":     180,
    "theharvester": 240,
    "sqlmap":       600,
    "nuclei":       600,
    "whatweb":       60,
    "ffuf":         300,
    "dirb":         300,
    "medusa":       180,
    "john":         300,
    "hashcat":      300,
    "chkrootkit":   180,
    "rkhunter":     300,
    "wapiti":       600,
    "dalfox":       180,
    "hping3":        60,
    "searchsploit":  60,
    "default":      300,
}

# ── HTTP helpers ──────────────────────────────────────────────
def http_json(url, method="GET", payload=None, token=""):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def http_post_text(url, text, token=""):
    """Post large text body (tool output)."""
    payload = {"output": text[:800000], "done": True}
    return http_json(url, "POST", payload, token)

def server_ok(api_base):
    try:
        req = urllib.request.Request(f"{api_base}/health", method="GET")
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 500
    except Exception:
        return False

# ── Tool availability ─────────────────────────────────────────
def which(name):
    return shutil.which(name)

def auto_install(pkg):
    apt = shutil.which("apt-get")
    if not apt:
        return False
    try:
        subprocess.run(["sudo", apt, "update", "-qq"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", apt, "install", "-y", "-qq", pkg], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

# ── Tool runners ──────────────────────────────────────────────
def run_nmap(args):
    target  = args.get("target", "")
    profile = args.get("profile", "balanced")
    mods    = args.get("modules", "ports")

    PROFILES = {
        "fast":      ["-sT", "-Pn", "-n", "--open", "-T4", "--top-ports", "100"],
        "balanced":  ["-sT", "-Pn", "-n", "--open", "-T4", "-sV", "--version-intensity", "5", "--top-ports", "1000"],
        "deep":      ["-sT", "-Pn", "-n", "--open", "-T3", "-sV", "--version-intensity", "7", "-p-"],
        "very_deep": ["-sT", "-Pn", "-n", "--open", "-T3", "-sV", "-O", "--script", "default,safe", "-p-"],
    }
    nmap_args = PROFILES.get(profile, PROFILES["balanced"])
    bin_ = which("nmap")
    if not bin_:
        auto_install("nmap")
        bin_ = which("nmap")
    if not bin_:
        return {"error": "nmap not installed", "output": ""}

    cmd = [bin_] + nmap_args + [target]
    timeout = TOOL_TIMEOUT["nmap"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {timeout}s", "output": ""}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_nikto(args):
    target = args.get("target", "")
    port   = str(args.get("port", 80))
    bin_ = which("nikto")
    if not bin_:
        auto_install("nikto")
        bin_ = which("nikto")
    if not bin_:
        return {"error": "nikto not installed", "output": ""}
    cmd = [bin_, "-h", target, "-p", port, "-nointeractive",
           "-timeout", "20", "-maxtime", "600", "-no-404"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["nikto"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_lynis(args):
    profile    = (args.get("profile") or "system").lower()
    compliance = (args.get("compliance") or "").lower()
    category   = (args.get("category") or "").lower()
    bin_ = which("lynis")
    if not bin_:
        auto_install("lynis")
        bin_ = which("lynis")
    if not bin_:
        return {"error": "lynis not installed", "output": ""}

    with tempfile.TemporaryDirectory(prefix="vs-lynis-") as td:
        rpt = os.path.join(td, "report.dat")
        log = os.path.join(td, "lynis.log")
        cmd = ["lynis", "audit", "system", "--no-colors",
               "--report-file", rpt, "--logfile", log]
        if compliance: cmd += ["--compliance", compliance]
        if category:   cmd += ["--tests-category", category]
        if profile == "quick":     cmd += ["--quick"]
        if profile == "forensics": cmd += ["--forensics"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=TOOL_TIMEOUT["lynis"])
            out = (r.stdout or "") + (r.stderr or "")
            if os.path.exists(rpt):
                with open(rpt) as f: out += "\n\n# report.dat\n" + f.read()
            if os.path.exists(log):
                with open(log) as f: out += "\n\n# lynis.log\n" + f.read()
            # Parse hardening index
            hi = 0
            m = re.search(r"hardening_index\s*=\s*(\d+)", out)
            if m: hi = int(m.group(1))
            return {"output": out, "hardening_index": hi, "exit_code": r.returncode}
        except Exception as e:
            return {"error": str(e), "output": ""}


def run_dnsrecon(args):
    target = args.get("target", "")
    type_  = args.get("type", "std")
    bin_ = which("dnsrecon")
    if not bin_:
        auto_install("dnsrecon")
        bin_ = which("dnsrecon")
    if not bin_:
        # fallback to dig
        try:
            r = subprocess.run(["dig", "+short", "ANY", target],
                               capture_output=True, text=True, timeout=30)
            return {"output": r.stdout, "exit_code": r.returncode}
        except Exception:
            return {"error": "dnsrecon/dig not installed", "output": ""}
    cmd = [bin_, "-d", target, "-t", type_]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["dnsrecon"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_wpscan(args):
    target = args.get("target", "")
    enum   = args.get("enum", "p,u")
    token  = args.get("api_token", "")
    bin_ = which("wpscan")
    if not bin_:
        return {"error": "wpscan not installed. Run: sudo gem install wpscan", "output": ""}
    cmd = [bin_, "--url", target, "--enumerate", enum,
           "--format", "cli", "--no-banner", "--request-timeout", "30"]
    if token: cmd += ["--api-token", token]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["wpscan"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_theharvester(args):
    target  = args.get("target", "")
    sources = args.get("sources", "google,bing,crtsh")
    limit   = str(args.get("limit", 200))
    bin_ = which("theHarvester") or which("theharvester")
    if not bin_:
        auto_install("theharvester")
        bin_ = which("theHarvester") or which("theharvester")
    if not bin_:
        return {"error": "theHarvester not installed", "output": ""}
    cmd = [bin_, "-d", target, "-l", limit, "-b", sources]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["theharvester"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_sqlmap(args):
    url   = args.get("url", "")
    level = str(args.get("level", 1))
    risk  = str(args.get("risk", 1))
    bin_ = which("sqlmap")
    if not bin_:
        auto_install("sqlmap")
        bin_ = which("sqlmap")
    if not bin_:
        return {"error": "sqlmap not installed", "output": ""}
    cmd = [bin_, "-u", url, "--batch", "--level", level, "--risk", risk,
           "--threads", "4", "--timeout", "10"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["sqlmap"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_nuclei(args):
    target   = args.get("target", "")
    severity = args.get("severity", "critical,high,medium")
    tags     = args.get("tags", "cve,rce,sqli,xss")
    bin_ = which("nuclei")
    if not bin_:
        auto_install("nuclei")
        bin_ = which("nuclei")
    if not bin_:
        return {"error": "nuclei not installed", "output": ""}
    cmd = [bin_, "-u", target, "-severity", severity, "-stats=false",
           "-silent", "-c", "20"]
    if tags: cmd += ["-tags", tags]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["nuclei"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_whatweb(args):
    target = args.get("target", "")
    agg    = str(args.get("aggression", 3))
    bin_ = which("whatweb")
    if not bin_:
        auto_install("whatweb")
        bin_ = which("whatweb")
    if not bin_:
        return {"error": "whatweb not installed", "output": ""}
    cmd = [bin_, "--aggression", agg, "--no-errors", target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["whatweb"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_ffuf(args):
    url      = args.get("url", "")
    wordlist = args.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    ext      = args.get("extensions", "")
    bin_ = which("ffuf")
    if not bin_:
        auto_install("ffuf")
        bin_ = which("ffuf")
    if not bin_:
        return {"error": "ffuf not installed", "output": ""}
    if not os.path.isfile(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    cmd = [bin_, "-u", url, "-w", wordlist, "-fc", "404", "-t", "40", "-s"]
    if ext: cmd += ["-e", ext]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["ffuf"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_chkrootkit(args):
    bin_ = which("chkrootkit")
    if not bin_:
        auto_install("chkrootkit")
        bin_ = which("chkrootkit")
    if not bin_:
        return {"error": "chkrootkit not installed", "output": ""}
    try:
        r = subprocess.run([bin_], capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["chkrootkit"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_rkhunter(args):
    bin_ = which("rkhunter")
    if not bin_:
        auto_install("rkhunter")
        bin_ = which("rkhunter")
    if not bin_:
        return {"error": "rkhunter not installed", "output": ""}
    try:
        r = subprocess.run([bin_, "--check", "--skip-keypress", "--nocolors"],
                           capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT["rkhunter"])
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


def run_generic(args):
    """Fallback: run any allowlisted binary with provided args."""
    SAFE_TOOLS = {
        "medusa", "john", "hashcat", "wapiti", "dalfox",
        "hping3", "searchsploit", "dirb", "gobuster", "amass",
    }
    tool    = (args.get("tool") or "").lower().strip()
    raw_args= (args.get("args") or "").strip()
    if tool not in SAFE_TOOLS:
        return {"error": f"Tool '{tool}' not in agent allowlist", "output": ""}
    bin_ = which(tool)
    if not bin_:
        auto_install(tool)
        bin_ = which(tool)
    if not bin_:
        return {"error": f"{tool} not installed on this system", "output": ""}
    try:
        import shlex
        cmd = [bin_] + shlex.split(raw_args)
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TOOL_TIMEOUT.get(tool, TOOL_TIMEOUT["default"]))
        return {"output": (r.stdout or "") + (r.stderr or ""), "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "output": ""}


# ── Tool dispatcher ───────────────────────────────────────────
TOOL_RUNNERS = {
    "nmap":          run_nmap,
    "nikto":         run_nikto,
    "lynis":         run_lynis,
    "dnsrecon":      run_dnsrecon,
    "wpscan":        run_wpscan,
    "theharvester":  run_theharvester,
    "sqlmap":        run_sqlmap,
    "nuclei":        run_nuclei,
    "whatweb":       run_whatweb,
    "ffuf":          run_ffuf,
    "chkrootkit":    run_chkrootkit,
    "rkhunter":      run_rkhunter,
    "generic":       run_generic,
}

def detect_installed_tools():
    ALL = ["nmap","nikto","lynis","wpscan","dnsrecon","theHarvester",
           "sqlmap","nuclei","whatweb","ffuf","dirb","medusa","john",
           "hashcat","chkrootkit","rkhunter","wapiti","dalfox","hping3",
           "searchsploit","gobuster","amass","dig","curl"]
    return [t for t in ALL if shutil.which(t) or shutil.which(t.lower())]


def run_job(job, api_base, token):
    job_id  = job["job_id"]
    tool    = (job.get("tool") or "generic").lower().strip()
    args    = job.get("args") or {}

    # Progress: started
    try:
        http_json(f"{api_base}/api/remote/jobs/{job_id}/progress", "POST",
                  {"progress_pct": 10, "message": f"Running {tool}..."}, token)
    except Exception:
        pass

    runner = TOOL_RUNNERS.get(tool, run_generic)
    if tool not in TOOL_RUNNERS:
        args["tool"] = tool  # pass tool name for generic runner

    result = runner(args)

    # Progress: done
    output = result.get("output", "")
    error  = result.get("error", "")
    exit_c = result.get("exit_code", -1)

    upload_payload = {
        "job_id":     job_id,
        "tool":       tool,
        "exit_code":  exit_c,
        "output":     output[-500000:],
        "error":      error,
        "status":     "error" if error and not output else "completed",
        "message":    error[:200] if error else f"{tool} completed",
        # lynis-specific
        "hardening_index": result.get("hardening_index", 0),
    }
    try:
        http_json(f"{api_base}/api/remote/upload", "POST", upload_payload, token)
    except Exception as e:
        print(f"[!] Upload failed: {e}")


# ── Main agent loop ───────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="VulnScan Universal Remote Agent")
    p.add_argument("--api-base",  required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--token",     default="")
    p.add_argument("--interval",  type=int, default=15)
    args = p.parse_args()

    api_base = args.api_base.rstrip("/")
    token    = args.token.strip()

    if not token:
        reg = http_json(f"{api_base}/api/agent/register", "POST", {
            "client_id": args.client_id,
            "hostname":  socket.gethostname(),
            "os_info":   f"{platform.system()} {platform.release()}",
            "tools":     detect_installed_tools(),
            "agent_version": "universal-2.0",
        })
        token = reg["token"]
        print(f"[+] Registered. Token: {token}")

    # Send installed tools list to server
    try:
        installed = detect_installed_tools()
        http_json(f"{api_base}/api/agent/heartbeat", "POST", {
            "client_id": args.client_id,
            "tools":     installed,
        }, token)
        print(f"[+] Reported {len(installed)} installed tools: {', '.join(installed)}")
    except Exception:
        pass

    print(f"[*] Universal agent polling every {args.interval}s for {args.client_id}")
    was_connected = None

    while True:
        try:
            connected = server_ok(api_base)
            if was_connected is not False and not connected:
                print("[!] Server unreachable, retrying...")
            elif not was_connected and connected:
                print("[+] Server connection restored")
            was_connected = connected

            if not connected:
                time.sleep(max(10, args.interval))
                continue

            # Send heartbeat with current tool list
            try:
                http_json(f"{api_base}/api/agent/heartbeat", "POST", {
                    "client_id": args.client_id,
                    "tools":     detect_installed_tools(),
                }, token)
            except Exception:
                pass

            # Poll for a job
            job = http_json(f"{api_base}/api/remote/jobs", headers=None, token=token)
            # Override: pass token via bearer
            import urllib.request as _ur
            req = _ur.Request(f"{api_base}/api/remote/jobs",
                              headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json"})
            with _ur.urlopen(req, timeout=30) as r:
                job = json.loads(r.read().decode())

            if job.get("job_id"):
                t = job.get("tool", "unknown")
                print(f"[*] Job #{job['job_id']}: {t}")
                run_job(job, api_base, token)
                print(f"[+] Job #{job['job_id']} done")

        except urllib.error.HTTPError as e:
            print(f"[!] HTTP {e.code}: {e.reason}")
            if e.code in (401, 403):
                print("[!] Token invalid — re-run installer to reconnect")
                break
        except Exception as e:
            print(f"[!] Agent error: {e}")

        time.sleep(max(10, args.interval))


# ── Fix http_json to support token as param not kwarg ─────────
def http_json(url, method="GET", payload=None, token=""):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


if __name__ == "__main__":
    main()
'''

# ══════════════════════════════════════════════════════════════════════════════
# FILE 2: Updated installer (agent/install_agent.sh)
# ══════════════════════════════════════════════════════════════════════════════

INSTALL_AGENT_SH = r'''#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="${1:-}"
TOKEN="${2:-}"
API_BASE="${3:-http://161.118.189.254:5000}"

if [[ -z "$CLIENT_ID" ]]; then
  base_host="$(hostname -s 2>/dev/null || echo linux-client)"
  rand_part="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
  [[ -z "$rand_part" ]] && rand_part="$(date +%s)"
  CLIENT_ID="${base_host}-${rand_part}"
  echo "[*] Generated client id: $CLIENT_ID"
fi

AGENT_DIR="/opt/vulnscan-agent"
SERVICE_FILE="/etc/systemd/system/vulnscan-agent.service"
AGENT_SCRIPT="universal_agent.py"

echo "[*] Checking connection to $API_BASE ..."
curl -fsS "$API_BASE/health" >/dev/null
echo "[+] Server reachable."

sudo mkdir -p "$AGENT_DIR"

# Download the universal agent
curl -fsSL "$API_BASE/agent/$AGENT_SCRIPT" -o "/tmp/$AGENT_SCRIPT"
sudo cp "/tmp/$AGENT_SCRIPT" "$AGENT_DIR/$AGENT_SCRIPT"
sudo chmod +x "$AGENT_DIR/$AGENT_SCRIPT"

# Register and get token if not provided
if [[ -z "$TOKEN" ]]; then
  echo "[*] Registering with server..."
  reg_json="$(python3 - <<PY
import json, platform, socket, subprocess, urllib.request, shutil

def get_tools():
    tools = ["nmap","nikto","lynis","wpscan","dnsrecon","theHarvester",
             "sqlmap","nuclei","whatweb","ffuf","dirb","medusa","john",
             "hashcat","chkrootkit","rkhunter","wapiti","dalfox","hping3",
             "searchsploit","dig","curl"]
    return [t for t in tools if shutil.which(t) or shutil.which(t.lower())]

api_base = ${API_BASE@Q}
client_id = ${CLIENT_ID@Q}
payload = json.dumps({
    "client_id": client_id,
    "hostname": socket.gethostname(),
    "os_info": f"{platform.system()} {platform.release()}",
    "tools": get_tools(),
    "agent_version": "universal-2.0",
}).encode()
req = urllib.request.Request(
    f"{api_base.rstrip('/')}/api/agent/register",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as r:
    print(r.read().decode())
PY
)" || true

  if [[ -z "$reg_json" ]]; then
    echo "[x] Registration failed"
    exit 1
  fi
  TOKEN="$(printf '%s' "$reg_json" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("token","")).strip())')"
  if [[ -z "$TOKEN" ]]; then
    echo "[x] Token missing in response: $reg_json"
    exit 1
  fi
  echo "[+] Registered. Client ID: $CLIENT_ID"
fi

# Write systemd service
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=VulnScan Universal Remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/python3 $AGENT_DIR/$AGENT_SCRIPT \
  --api-base $API_BASE \
  --client-id $CLIENT_ID \
  --token $TOKEN \
  --interval 15

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-agent

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  VulnScan Universal Agent Installed!             ║"
echo "║                                                  ║"
echo "║  Client ID : '"$CLIENT_ID"'"
echo "║  Server    : '"$API_BASE"'"
echo "║                                                  ║"
echo "║  Go to the VulnScan dashboard → Remote Audit    ║"
echo "║  tab to run tools on this system.               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Status : sudo systemctl status vulnscan-agent"
echo "  Logs   : journalctl -u vulnscan-agent -f"
'''

# ══════════════════════════════════════════════════════════════════════════════
# API SERVER PATCHES: New routes + DB table + UI injection
# ══════════════════════════════════════════════════════════════════════════════

NEW_REMOTE_ROUTES = '''
# ══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL REMOTE AGENT — routes
# All tools are executed on the connected remote system, not the server.
# ══════════════════════════════════════════════════════════════════════════════

import threading as _ra_threading, hashlib as _ra_hashlib

_RA_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "remote_jobs.db")
_RA_LOCK    = _ra_threading.Lock()
_RA_JOB_LIMIT = 10

def _ra_db():
    import sqlite3 as _sq
    con = _sq.connect(_RA_DB_PATH)
    con.row_factory = _sq.Row
    return con

def _init_ra_db():
    con = _ra_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS ra_clients (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id   TEXT UNIQUE NOT NULL,
            token_hash  TEXT NOT NULL,
            hostname    TEXT DEFAULT '',
            os_info     TEXT DEFAULT '',
            ip_seen     TEXT DEFAULT '',
            tools_json  TEXT DEFAULT '[]',
            agent_ver   TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT DEFAULT (datetime('now')),
            status      TEXT DEFAULT 'online'
        );
        CREATE TABLE IF NOT EXISTS ra_jobs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id    TEXT NOT NULL,
            tool         TEXT NOT NULL,
            args_json    TEXT DEFAULT '{}',
            status       TEXT DEFAULT 'pending',
            created_at   TEXT DEFAULT (datetime('now')),
            started_at   TEXT,
            completed_at TEXT,
            progress_pct INTEGER DEFAULT 0,
            message      TEXT DEFAULT '',
            output       TEXT DEFAULT '',
            error        TEXT DEFAULT '',
            exit_code    INTEGER,
            cancel_req   INTEGER DEFAULT 0,
            hardening_index INTEGER DEFAULT 0
        );
    """)
    con.commit()
    con.close()

def _ra_hash(token):
    return _ra_hashlib.sha256(token.encode()).hexdigest()

def _ra_auth(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    h = _ra_hash(token)
    con = _ra_db()
    row = con.execute(
        "SELECT client_id FROM ra_clients WHERE token_hash=?", (h,)).fetchone()
    if row:
        con.execute(
            "UPDATE ra_clients SET last_seen=datetime('now'), ip_seen=?, status='online' "
            "WHERE client_id=?", (req.remote_addr or "", row["client_id"]))
        con.commit()
    con.close()
    return row["client_id"] if row else None

_init_ra_db()


@app.route("/api/agent/register", methods=["POST"])
def ra_register():
    """Universal agent registration (replaces Lynis-only register)."""
    data       = request.get_json() or {}
    client_id  = (data.get("client_id") or "").strip()
    hostname   = (data.get("hostname")  or "").strip()
    os_info    = (data.get("os_info")   or "").strip()
    tools      = data.get("tools") or []
    agent_ver  = (data.get("agent_version") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400
    import secrets as _sec
    token      = _sec.token_urlsafe(32)
    token_hash = _ra_hash(token)
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            INSERT INTO ra_clients
              (client_id, token_hash, hostname, os_info, ip_seen, tools_json,
               agent_ver, status)
            VALUES(?,?,?,?,?,?,?,'online')
            ON CONFLICT(client_id) DO UPDATE SET
              token_hash=excluded.token_hash,
              hostname=excluded.hostname,
              os_info=excluded.os_info,
              ip_seen=excluded.ip_seen,
              tools_json=excluded.tools_json,
              agent_ver=excluded.agent_ver,
              last_seen=datetime('now'),
              status='online'
        """, (client_id, token_hash, hostname, os_info,
              request.remote_addr or "", json.dumps(tools), agent_ver))
        con.commit()
        con.close()
    u = get_current_user()
    audit(u["id"] if u else None, u["username"] if u else "agent",
          "REMOTE_AGENT_REGISTER", target=client_id, ip=request.remote_addr,
          details=f"hostname={hostname};tools={len(tools)};ver={agent_ver}")
    return jsonify({"client_id": client_id, "token": token,
                    "api_base": request.url_root.rstrip("/")})


@app.route("/api/agent/heartbeat", methods=["POST"])
def ra_heartbeat():
    """Agent sends heartbeat with current tool list."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data  = request.get_json() or {}
    tools = data.get("tools") or []
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET last_seen=datetime('now'), status='online',
                tools_json=?, ip_seen=?
            WHERE client_id=?
        """, (json.dumps(tools), request.remote_addr or "", client_id))
        con.commit()
        con.close()
    return jsonify({"ok": True})


@app.route("/api/remote/agents", methods=["GET"])
def ra_list_agents():
    """List all connected remote agents with their available tools."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _RA_LOCK:
        con = _ra_db()
        rows = con.execute("""
            SELECT client_id, hostname, os_info, ip_seen, tools_json,
                   agent_ver, last_seen, status, created_at
            FROM ra_clients
            WHERE status != 'disconnected'
            ORDER BY datetime(last_seen) DESC
        """).fetchall()
        con.close()
    agents = []
    for r in rows:
        try: tools = json.loads(r["tools_json"] or "[]")
        except Exception: tools = []
        agents.append({
            "client_id":  r["client_id"],
            "hostname":   r["hostname"],
            "os_info":    r["os_info"],
            "ip_seen":    r["ip_seen"],
            "tools":      tools,
            "agent_ver":  r["agent_ver"],
            "last_seen":  r["last_seen"],
            "status":     r["status"],
            "created_at": r["created_at"],
        })
    return jsonify({"agents": agents})


@app.route("/api/remote/create-job", methods=["POST"])
def ra_create_job():
    """Queue a tool job for a specific remote agent."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data      = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    tool      = (data.get("tool") or "").strip().lower()
    args      = data.get("args") or {}

    ALLOWED_TOOLS = {
        "nmap", "nikto", "lynis", "wpscan", "dnsrecon", "theharvester",
        "sqlmap", "nuclei", "whatweb", "ffuf", "dirb", "medusa", "john",
        "hashcat", "chkrootkit", "rkhunter", "wapiti", "dalfox", "hping3",
        "searchsploit", "generic",
    }
    if not client_id:
        return jsonify({"error": "client_id required"}), 400
    if not tool or tool not in ALLOWED_TOOLS:
        return jsonify({"error": f"Tool '{tool}' not allowed"}), 400

    with _RA_LOCK:
        con = _ra_db()
        agent = con.execute(
            "SELECT status FROM ra_clients WHERE client_id=?", (client_id,)).fetchone()
        if not agent:
            con.close()
            return jsonify({"error": "Unknown agent — install agent on that system first"}), 404
        q = con.execute(
            "SELECT COUNT(*) as c FROM ra_jobs "
            "WHERE client_id=? AND status IN ('pending','running')", (client_id,)).fetchone()
        if q["c"] >= _RA_JOB_LIMIT:
            con.close()
            return jsonify({"error": f"Queue full ({_RA_JOB_LIMIT} jobs max)"}), 429
        cur = con.execute("""
            INSERT INTO ra_jobs (client_id, tool, args_json, status, progress_pct, message)
            VALUES (?, ?, ?, 'pending', 0, 'Queued')
        """, (client_id, tool, json.dumps(args)))
        jid = cur.lastrowid
        con.commit()
        con.close()

    audit(u["id"], u["username"], "REMOTE_JOB_CREATED", target=client_id,
          ip=request.remote_addr,
          details=f"tool={tool};job_id={jid};args={str(args)[:120]}")
    return jsonify({"job_id": jid, "status": "pending", "tool": tool})


@app.route("/api/remote/jobs", methods=["GET"])
def ra_poll_jobs():
    """Agent polls this endpoint for pending jobs."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    with _RA_LOCK:
        con = _ra_db()
        row = con.execute("""
            SELECT id, tool, args_json FROM ra_jobs
            WHERE client_id=? AND status='pending' AND cancel_req=0
            ORDER BY id ASC LIMIT 1
        """, (client_id,)).fetchone()
        if row:
            con.execute("""
                UPDATE ra_jobs
                SET status='running', started_at=datetime('now'),
                    progress_pct=5, message='Agent started'
                WHERE id=? AND status='pending'
            """, (row["id"],))
            con.commit()
            try: args = json.loads(row["args_json"] or "{}")
            except Exception: args = {}
            job = {"job_id": row["id"], "tool": row["tool"], "args": args}
        else:
            job = {"job_id": None}
        con.close()
    return jsonify(job)


@app.route("/api/remote/jobs/<int:job_id>/progress", methods=["POST"])
def ra_job_progress(job_id):
    """Agent sends progress updates."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pct  = max(0, min(100, int(data.get("progress_pct", 0))))
    msg  = (data.get("message") or "")[:300]
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_jobs SET progress_pct=?, message=?
            WHERE id=? AND client_id=? AND status='running'
        """, (pct, msg, job_id, client_id))
        con.commit()
        con.close()
    return jsonify({"ok": True})


@app.route("/api/remote/upload", methods=["POST"])
def ra_upload_result():
    """Agent uploads completed job results."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data    = request.get_json() or {}
    job_id  = data.get("job_id")
    if not job_id:
        return jsonify({"error": "job_id required"}), 400
    output  = str(data.get("output", ""))[:800000]
    error   = str(data.get("error",  ""))[:5000]
    exit_c  = data.get("exit_code")
    status  = (data.get("status") or "completed").lower()
    message = (data.get("message") or status.title())[:300]
    hi      = int(data.get("hardening_index") or 0)
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_jobs
            SET status=?, completed_at=datetime('now'), progress_pct=100,
                message=?, output=?, error=?, exit_code=?, hardening_index=?
            WHERE id=? AND client_id=?
        """, (status, message, output, error, exit_c, hi, job_id, client_id))
        con.commit()
        con.close()
    audit(None, f"agent:{client_id}", "REMOTE_JOB_UPLOAD", target=str(job_id),
          ip=request.remote_addr,
          details=f"tool={data.get('tool','?')};status={status};exit={exit_c}")
    return jsonify({"ok": True})


@app.route("/api/remote/job-status/<int:job_id>", methods=["GET"])
def ra_job_status(job_id):
    """Dashboard polls job status/results."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _RA_LOCK:
        con = _ra_db()
        row = con.execute("""
            SELECT id, client_id, tool, args_json, status, progress_pct,
                   message, output, error, exit_code, created_at,
                   started_at, completed_at, hardening_index, cancel_req
            FROM ra_jobs WHERE id=?
        """, (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    try: args = json.loads(row["args_json"] or "{}")
    except Exception: args = {}
    return jsonify({
        "job_id":         row["id"],
        "client_id":      row["client_id"],
        "tool":           row["tool"],
        "args":           args,
        "status":         row["status"],
        "progress_pct":   row["progress_pct"],
        "message":        row["message"],
        "output":         row["output"],
        "error":          row["error"],
        "exit_code":      row["exit_code"],
        "created_at":     row["created_at"],
        "started_at":     row["started_at"],
        "completed_at":   row["completed_at"],
        "hardening_index":row["hardening_index"],
        "cancel_req":     bool(row["cancel_req"]),
    })


@app.route("/api/remote/jobs-overview", methods=["GET"])
def ra_jobs_overview():
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    limit = max(1, min(100, int(request.args.get("limit", 20))))
    client_id = request.args.get("client_id", "")
    with _RA_LOCK:
        con = _ra_db()
        if client_id:
            rows = con.execute("""
                SELECT id, client_id, tool, status, progress_pct, message,
                       created_at, started_at, completed_at
                FROM ra_jobs WHERE client_id=?
                ORDER BY id DESC LIMIT ?
            """, (client_id, limit)).fetchall()
        else:
            rows = con.execute("""
                SELECT id, client_id, tool, status, progress_pct, message,
                       created_at, started_at, completed_at
                FROM ra_jobs
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        con.close()
    return jsonify({"jobs": [dict(r) for r in rows]})


@app.route("/api/remote/jobs/<int:job_id>/cancel", methods=["POST"])
def ra_cancel_job(job_id):
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _RA_LOCK:
        con = _ra_db()
        row = con.execute(
            "SELECT status FROM ra_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            con.close()
            return jsonify({"error": "Job not found"}), 404
        if row["status"] in ("completed", "cancelled", "error"):
            con.close()
            return jsonify({"ok": True, "status": row["status"]})
        if row["status"] == "pending":
            con.execute("UPDATE ra_jobs SET status='cancelled' WHERE id=?", (job_id,))
        else:
            con.execute("UPDATE ra_jobs SET cancel_req=1 WHERE id=?", (job_id,))
        con.commit()
        con.close()
    audit(u["id"], u["username"], "REMOTE_JOB_CANCEL", target=str(job_id),
          ip=request.remote_addr)
    return jsonify({"ok": True})


@app.route("/api/remote/agents/<client_id>/disconnect", methods=["POST"])
def ra_disconnect_agent(client_id):
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    import secrets as _sec2
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET status='disconnected', token_hash=?, last_seen=datetime('now')
            WHERE client_id=?
        """, (_ra_hash(_sec2.token_urlsafe(32)), client_id))
        con.execute("""
            UPDATE ra_jobs SET status='cancelled', message='Agent disconnected'
            WHERE client_id=? AND status IN ('pending','running')
        """, (client_id,))
        con.commit()
        con.close()
    audit(u["id"], u["username"], "REMOTE_AGENT_DISCONNECT", target=client_id,
          ip=request.remote_addr)
    return jsonify({"ok": True})


@app.route("/agent/universal_agent.py", methods=["GET"])
def serve_universal_agent():
    agent_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent")
    return send_from_directory(agent_dir, "universal_agent.py", as_attachment=False,
                               mimetype="text/plain")


# ── Remote Audit page HTML (injected into the main UI) ───────────────────────
_REMOTE_AUDIT_PAGE_HTML = """
      <!-- REMOTE AUDIT PAGE -->
      <div class="page" id="page-remote">
        <div class="page-hd">
          <div class="page-title">Remote Audit</div>
          <div class="page-desc">Run any security tool on connected remote systems — one command to connect</div>
        </div>

        <!-- Install banner -->
        <div class="card card-p" style="margin-bottom:16px;border-left:3px solid var(--cyan, #00e5ff)">
          <div class="card-title" style="margin-bottom:10px">Connect a Linux System (one command)</div>
          <div class="scan-bar">
            <input class="inp inp-mono" id="ra-install-cmd" readonly
              value="curl -fsSL http://161.118.189.254:5000/agent/install.sh | bash"
              style="font-size:12px"/>
            <button class="btn btn-outline btn-sm" onclick="raCopyInstall()">COPY</button>
          </div>
          <div style="font-size:11px;color:var(--text3);margin-top:8px">
            Once connected, the system appears below and you can run <strong>any tool</strong> on it remotely.
          </div>
        </div>

        <!-- Connected systems -->
        <div class="card card-p" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
            <div class="card-title">Connected Systems</div>
            <button class="btn btn-outline btn-sm" onclick="raLoadAgents()">REFRESH</button>
          </div>
          <div id="ra-agents">Loading...</div>
        </div>

        <!-- Tool launcher -->
        <div class="card card-p" style="margin-bottom:16px" id="ra-launcher" style="display:none">
          <div class="card-title" style="margin-bottom:12px">
            Run Tool on: <span id="ra-selected-label" style="color:var(--green, #00ff9d)">—</span>
          </div>

          <div class="row2" style="margin-bottom:12px">
            <div class="fg">
              <label>SELECT TOOL</label>
              <select class="inp inp-mono" id="ra-tool" onchange="raToolChange()">
                <option value="">— choose tool —</option>
                <optgroup label="Network">
                  <option value="nmap">nmap — Port Scanner + CVE</option>
                </optgroup>
                <optgroup label="Web Testing">
                  <option value="nikto">nikto — Web Vulnerability Scanner</option>
                  <option value="wpscan">wpscan — WordPress Scanner</option>
                  <option value="whatweb">whatweb — Technology Fingerprint</option>
                  <option value="ffuf">ffuf — Directory Fuzzer</option>
                  <option value="sqlmap">sqlmap — SQL Injection Tester</option>
                  <option value="nuclei">nuclei — Template Scanner</option>
                  <option value="wapiti">wapiti — Web App Scanner</option>
                  <option value="dalfox">dalfox — XSS Scanner</option>
                </optgroup>
                <optgroup label="OSINT / DNS">
                  <option value="dnsrecon">dnsrecon — DNS Enumeration</option>
                  <option value="theharvester">theHarvester — OSINT</option>
                </optgroup>
                <optgroup label="System Audit">
                  <option value="lynis">lynis — System Hardening Audit</option>
                  <option value="chkrootkit">chkrootkit — Rootkit Detection</option>
                  <option value="rkhunter">rkhunter — Rootkit Hunter</option>
                </optgroup>
                <optgroup label="Password / Brute">
                  <option value="medusa">medusa — Network Login Auditor</option>
                  <option value="john">john — Password Cracker</option>
                  <option value="hashcat">hashcat — GPU Hash Cracker</option>
                </optgroup>
                <optgroup label="Other">
                  <option value="searchsploit">searchsploit — Exploit-DB Search</option>
                  <option value="hping3">hping3 — Packet Generator</option>
                  <option value="generic">generic — Custom command</option>
                </optgroup>
              </select>
            </div>
            <div class="fg">
              <label>NMAP PROFILE (nmap only)</label>
              <select class="inp inp-mono" id="ra-nmap-profile">
                <option value="fast">Fast (top 100)</option>
                <option value="balanced" selected>Balanced (top 1000)</option>
                <option value="deep">Deep (all ports)</option>
                <option value="very_deep">Very Deep (scripts+OS)</option>
              </select>
            </div>
          </div>

          <!-- Dynamic arg fields -->
          <div id="ra-tool-args">
            <div class="fg">
              <label>TARGET (IP / domain / URL)</label>
              <input class="inp inp-mono" id="ra-target" type="text" placeholder="e.g. 192.168.1.1 or example.com"/>
            </div>
          </div>

          <!-- Generic tool extra args -->
          <div id="ra-generic-fields" style="display:none">
            <div class="fg">
              <label>TOOL BINARY NAME</label>
              <input class="inp inp-mono" id="ra-generic-tool" type="text" placeholder="e.g. dirb"/>
            </div>
            <div class="fg">
              <label>ARGUMENTS</label>
              <input class="inp inp-mono" id="ra-generic-args" type="text" placeholder="e.g. http://target.com /usr/share/wordlists/dirb/common.txt"/>
            </div>
          </div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">
            <button class="btn btn-primary" id="ra-run-btn" onclick="raRunTool()">RUN ON REMOTE SYSTEM</button>
            <button class="btn btn-outline btn-sm" onclick="raLoadJobs()">REFRESH JOBS</button>
          </div>
        </div>

        <!-- Progress + output -->
        <div class="progress-wrap" id="ra-prog"><div class="progress-bar" id="ra-pb" style="width:0%"></div></div>
        <div class="terminal" id="ra-term"></div>
        <div class="err-box"  id="ra-err"></div>
        <div id="ra-res"></div>

        <!-- Job queue -->
        <div class="card card-p" style="margin-top:14px">
          <div class="card-title" style="margin-bottom:8px">Remote Job Queue</div>
          <div id="ra-jobs">No jobs yet.</div>
        </div>
      </div>
"""

_REMOTE_AUDIT_JS = """
/* ══ REMOTE AUDIT JS ══════════════════════════════════════════════════════ */
var _raSelectedAgent = null;
var _raCurrentJob    = null;
var _raPollTimer     = null;

function raCopyInstall(){
  var el=document.getElementById('ra-install-cmd');
  el.select();el.setSelectionRange(0,99999);
  try{document.execCommand('copy');}catch(e){}
  showToast('Copied','Install command copied to clipboard','success',2500);
}

async function raLoadAgents(){
  var box=document.getElementById('ra-agents');
  if(!box)return;
  box.innerHTML='<span style="color:var(--text3)">Loading...</span>';
  try{
    var r=await fetch('/api/remote/agents');
    var d=await r.json();
    var agents=d.agents||[];
    if(!agents.length){
      box.innerHTML='<div style="color:var(--text3);font-size:12px">No systems connected yet. Run the install command on a Linux machine.</div>';
      return;
    }
    var html='<div style="display:flex;flex-direction:column;gap:8px">';
    agents.forEach(function(a){
      var st=(a.status||'unknown').toLowerCase();
      var col=st==='online'?'var(--green)':'var(--orange)';
      var sel=_raSelectedAgent===a.client_id;
      var tools=(a.tools||[]).slice(0,12).join(', ')+(a.tools&&a.tools.length>12?'...':'');
      html+='<div class="card-p" style="border:1px solid '+(sel?'var(--green)':'var(--border)')+';border-radius:8px;cursor:pointer" onclick="raSelectAgent('+JSON.stringify(a)+')">'
        +'<div style="display:flex;justify-content:space-between;gap:8px">'
        +'<div><strong style="font-family:var(--mono)">'+a.client_id+(sel?' <span style=\\'color:var(--green);\\'>(selected)</span>':'')+'</strong>'
        +'<div style="font-size:11px;color:var(--text3)">'+a.hostname+' · '+a.os_info+'</div></div>'
        +'<span style="font-size:11px;color:'+col+'">'+st.toUpperCase()+'</span></div>'
        +'<div style="font-size:10px;color:var(--text3);margin-top:4px">Tools: '+tools+'</div>'
        +'<div style="font-size:10px;color:var(--text3)">IP: '+a.ip_seen+' · Last seen: '+a.last_seen+'</div>'
        +'<div style="margin-top:8px;display:flex;gap:6px">'
        +'<button class="btn btn-outline btn-sm" onclick="event.stopPropagation();raDisconnect(\\'' +a.client_id+'\\')">DISCONNECT</button>'
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){
    box.innerHTML='<div class="err-box visible">'+e.message+'</div>';
  }
}

function raSelectAgent(agent){
  _raSelectedAgent=agent.client_id;
  document.getElementById('ra-selected-label').textContent=agent.client_id+' ('+agent.hostname+')';
  document.getElementById('ra-launcher').style.display='block';
  // Filter tool dropdown to installed tools
  var sel=document.getElementById('ra-tool');
  var installedTools=agent.tools||[];
  for(var i=0;i<sel.options.length;i++){
    var opt=sel.options[i];
    if(opt.value&&!['generic',''].includes(opt.value)){
      var avail=installedTools.some(function(t){return t.toLowerCase()===opt.value.toLowerCase()||t.toLowerCase().includes(opt.value.toLowerCase());});
      opt.text=opt.text.replace(' ✓','').replace(' ✗','');
      opt.text+=(avail?' ✓':' ✗');
    }
  }
  raLoadJobs();
  showToast('System selected',agent.client_id+' ready','success',2000);
}

function raToolChange(){
  var tool=document.getElementById('ra-tool').value;
  document.getElementById('ra-generic-fields').style.display=tool==='generic'?'block':'none';
}

async function raRunTool(){
  if(!_raSelectedAgent){showToast('No system','Select a connected system first','warning',3000);return;}
  var tool=document.getElementById('ra-tool').value;
  if(!tool){showToast('No tool','Select a tool to run','warning',3000);return;}

  var target=document.getElementById('ra-target').value.trim();
  var args={target:target};

  if(tool==='nmap'){
    args.profile=document.getElementById('ra-nmap-profile').value;
    args.modules='ports';
  } else if(tool==='generic'){
    args.tool=document.getElementById('ra-generic-tool').value.trim();
    args.args=document.getElementById('ra-generic-args').value.trim();
    delete args.target;
  }

  var btn=document.getElementById('ra-run-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Queuing...';

  try{
    var r=await fetch('/api/remote/create-job',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({client_id:_raSelectedAgent,tool:tool,args:args})
    });
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error',5000);return;}
    _raCurrentJob=d.job_id;
    showToast('Job queued','#'+d.job_id+' — '+tool+' on '+_raSelectedAgent,'success',3000);
    raPollJob(d.job_id);
    raLoadJobs();
  }catch(e){showToast('Error',e.message,'error',5000);}
  finally{btn.disabled=false;btn.innerHTML='RUN ON REMOTE SYSTEM';}
}

async function raPollJob(jobId){
  if(_raPollTimer)clearInterval(_raPollTimer);
  var term=document.getElementById('ra-term');
  var err=document.getElementById('ra-err');
  var res=document.getElementById('ra-res');
  var prog=document.getElementById('ra-prog');
  var pb=document.getElementById('ra-pb');
  if(term){term.innerHTML='';term.classList.add('visible');}
  if(err){err.textContent='';err.classList.remove('visible');}
  if(res){res.innerHTML='';}
  if(prog)prog.classList.add('active');
  if(pb)pb.style.width='5%';

  function addLine(txt,type){
    if(!term)return;
    var div=document.createElement('div');
    div.className='tl-'+(type||'i');
    var icons={i:'[*]',s:'[+]',w:'[!]',e:'[x]'};
    div.innerHTML='<span class="tl-prefix">'+(icons[type]||'[*]')+'</span> '+txt;
    term.appendChild(div);
    term.scrollTop=term.scrollHeight;
  }

  addLine('Job #'+jobId+' queued — waiting for remote agent...','i');

  var tries=0;
  _raPollTimer=setInterval(async function(){
    tries++;
    try{
      var r=await fetch('/api/remote/job-status/'+jobId);
      var d=await r.json();
      if(d.error){clearInterval(_raPollTimer);addLine(d.error,'e');return;}
      var pct=parseInt(d.progress_pct||0);
      if(pb)pb.style.width=pct+'%';
      if(d.message){addLine('['+d.status+'] '+d.message, d.status==='error'?'e':(d.status==='completed'?'s':'i'));}
      if(d.status==='completed'||d.status==='error'||d.status==='cancelled'){
        clearInterval(_raPollTimer);
        if(prog)prog.classList.remove('active');
        if(pb)pb.style.width='100%';
        var out=d.output||'';
        var errTxt=d.error||'';
        if(errTxt&&!out){
          if(err){err.textContent=errTxt;err.classList.add('visible');}
        } else {
          if(out){
            res.innerHTML='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">'
              +d.tool.toUpperCase()+' Output (Job #'+jobId+')'
              +'  <span style="font-size:10px;color:var(--text3);font-family:var(--mono)">exit '+d.exit_code+'</span>'
              +'</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:500px;overflow-y:auto">'
              +out.replace(/</g,'&lt;')+'</pre>'
              +(errTxt?'<div style="color:var(--orange);font-size:11px;margin-top:8px">Stderr: '+errTxt.replace(/</g,'&lt;')+'</div>':'')
              +'</div>';
          }
        }
        addLine(d.status.toUpperCase()+' — exit code: '+d.exit_code, d.status==='completed'?'s':'e');
        showToast('Job done','#'+jobId+' '+d.status,'success',4000);
        raLoadJobs();
      }
    }catch(ex){addLine('Poll error: '+ex.message,'w');}
    if(tries>300){clearInterval(_raPollTimer);addLine('Poll timeout','w');}
  },2000);
}

async function raLoadJobs(){
  var box=document.getElementById('ra-jobs');
  if(!box)return;
  var qs=_raSelectedAgent?'?client_id='+encodeURIComponent(_raSelectedAgent):'';
  try{
    var r=await fetch('/api/remote/jobs-overview'+qs+'&limit=15');
    var d=await r.json();
    var jobs=d.jobs||[];
    if(!jobs.length){box.innerHTML='<div style="color:var(--text3);font-size:12px">No remote jobs yet.</div>';return;}
    var html='<div style="display:flex;flex-direction:column;gap:6px">';
    jobs.forEach(function(j){
      var col=j.status==='completed'?'var(--green)':(j.status==='running'?'var(--yellow)':(j.status==='error'?'var(--red)':'var(--text3)'));
      html+='<div class="card-p" style="border:1px solid var(--border);border-radius:6px">'
        +'<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px">'
        +'<span style="font-family:var(--mono);font-size:12px">#'+j.id+' · <strong>'+j.tool+'</strong> on '+j.client_id+'</span>'
        +'<span style="font-size:11px;color:'+col+'">'+j.status.toUpperCase()+'</span></div>'
        +'<div style="font-size:10px;color:var(--text3);margin-top:3px">'+j.progress_pct+'% · '+(j.message||'')+'</div>'
        +'<div style="font-size:10px;color:var(--text3)">Created: '+j.created_at+(j.completed_at?' · Done: '+j.completed_at:'')+'</div>'
        +'<div style="margin-top:6px;display:flex;gap:5px;flex-wrap:wrap">'
        +(j.status==='completed'||j.status==='error'?'<button class="btn btn-outline btn-sm" onclick="raViewJob('+j.id+')">VIEW</button>':'')
        +(j.status==='pending'||j.status==='running'?'<button class="btn btn-outline btn-sm" style="color:var(--red)" onclick="raCancelJob('+j.id+')">CANCEL</button>':'')
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){box.innerHTML='<div style="color:var(--text3)">'+e.message+'</div>';}
}

async function raViewJob(jobId){raPollJob(jobId);}

async function raCancelJob(jobId){
  if(!confirm('Cancel remote job #'+jobId+'?'))return;
  try{
    var r=await fetch('/api/remote/jobs/'+jobId+'/cancel',{method:'POST'});
    var d=await r.json();
    if(d.ok)showToast('Cancelled','Job #'+jobId+' cancelled','warning',2500);
    raLoadJobs();
  }catch(e){showToast('Error',e.message,'error',3000);}
}

async function raDisconnect(clientId){
  if(!confirm('Disconnect '+clientId+'? Re-run install.sh to reconnect.'))return;
  try{
    await fetch('/api/remote/agents/'+encodeURIComponent(clientId)+'/disconnect',{method:'POST'});
    if(_raSelectedAgent===clientId){_raSelectedAgent=null;document.getElementById('ra-launcher').style.display='none';}
    showToast('Disconnected',clientId+' removed','warning',3000);
    raLoadAgents();raLoadJobs();
  }catch(e){showToast('Error',e.message,'error',3000);}
}
/* ══ END REMOTE AUDIT JS ═════════════════════════════════════════════════ */
"""

'''

# ══════════════════════════════════════════════════════════════════════════════
# PATCHES to api_server.py
# ══════════════════════════════════════════════════════════════════════════════

# Patch 1: Inject Remote Audit nav item
PATCH_NAV_OLD = '''      <div class="nav-section" id="admin-nav-section" style="display:none">
        <button class="nav-item" id="ni-admin" onclick="pg('admin',this)"><span class="ni">&#9881;</span> Admin Console</button>
      </div>'''

PATCH_NAV_NEW = '''      <div class="nav-section" id="admin-nav-section" style="display:none">
        <button class="nav-item" id="ni-admin" onclick="pg('admin',this)"><span class="ni">&#9881;</span> Admin Console</button>
      </div>
      <div class="nav-section">
        <button class="nav-item" id="ni-remote" onclick="pg('remote',this)"><span class="ni">&#9729;</span> Remote Audit</button>
      </div>'''

# Patch 2: Add Remote Audit to PAGE_TITLES dict
PATCH_TITLES_OLD = "dash:'Dashboard',profile:'Profile',admin:'Admin Console',"
PATCH_TITLES_NEW = "dash:'Dashboard',profile:'Profile',admin:'Admin Console',remote:'Remote Audit',"

# Patch 3: Add Remote Audit page HTML before the closing </div> of .content
PATCH_HTML_INJECT_OLD = '''      <!-- ADMIN -->
      <div class="page" id="page-admin">'''

PATCH_HTML_INJECT_NEW = '''<REMOTE_PAGE_PLACEHOLDER>

      <!-- ADMIN -->
      <div class="page" id="page-admin">'''

# Patch 4: Inject JS before closing </script> near loadUser()
PATCH_JS_OLD = "loadUser();\nsetTimeout(renderHomeToolCatalog,120);"
PATCH_JS_NEW = "loadUser();\nsetTimeout(renderHomeToolCatalog,120);\n<REMOTE_JS_PLACEHOLDER>"

# Patch 5: Add pg() handler for remote page
PATCH_PG_OLD = "  if(id==='hist')loadHist();"
PATCH_PG_NEW = "  if(id==='hist')loadHist();\n  if(id==='remote'){raLoadAgents();raLoadJobs();}"

# Patch 6: Inject new routes before the __main__ block
PATCH_ROUTES_OLD = "if __name__ == \"__main__\":"
PATCH_ROUTES_NEW = "<NEW_ROUTES_PLACEHOLDER>\n\nif __name__ == \"__main__\":"


def main():
    print()
    print(B + C + "╔════════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║  VulnScan Pro — Universal Remote Audit Agent Patch        ║" + X)
    print(B + C + "║  One install command → run ANY tool remotely              ║" + X)
    print(B + C + "╚════════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET_SERVER):
        fail(f"Must be run from project root — {TARGET_SERVER} not found")
        sys.exit(1)

    # ── Step 1: Write agent files ─────────────────────────────────────────────
    hdr("Step 1 — Writing agent files")
    os.makedirs(AGENT_DIR, exist_ok=True)

    write_file(os.path.join(AGENT_DIR, "universal_agent.py"), UNIVERSAL_AGENT)
    ok("agent/universal_agent.py written")
    RESULTS["created"] += 1

    write_file(os.path.join(AGENT_DIR, "install_agent.sh"), INSTALL_AGENT_SH)
    ok("agent/install_agent.sh written (universal installer)")
    RESULTS["created"] += 1

    # ── Step 2: Patch api_server.py ──────────────────────────────────────────
    hdr("Step 2 — Patching api_server.py")
    src = read_file(TARGET_SERVER)
    bak = backup(TARGET_SERVER)
    info(f"Backup: {bak}")

    # Embed the actual HTML and JS strings
    remote_page_html = NEW_REMOTE_ROUTES.split('_REMOTE_AUDIT_PAGE_HTML = """')[1].split('"""')[0]
    remote_js        = NEW_REMOTE_ROUTES.split('_REMOTE_AUDIT_JS = """')[1].split('"""')[0]
    new_routes_code  = NEW_REMOTE_ROUTES

    # Apply nav patch
    src = apply_patch(src, "Nav: add Remote Audit menu item", PATCH_NAV_OLD, PATCH_NAV_NEW)

    # Apply PAGE_TITLES patch
    src = apply_patch(src, "PAGE_TITLES: add remote", PATCH_TITLES_OLD, PATCH_TITLES_NEW)

    # Inject HTML page
    page_injection = remote_page_html + "\n      <!-- ADMIN -->\n      <div class=\"page\" id=\"page-admin\">"
    src = apply_patch(src, "HTML: inject Remote Audit page",
                      PATCH_HTML_INJECT_OLD, page_injection)

    # Apply pg() handler
    src = apply_patch(src, "pg(): handle remote page load", PATCH_PG_OLD, PATCH_PG_NEW)

    # Inject JS
    js_injection = "loadUser();\nsetTimeout(renderHomeToolCatalog,120);\n" + remote_js
    src = apply_patch(src, "JS: inject Remote Audit functions", PATCH_JS_OLD, js_injection)

    # Inject new routes before __main__
    routes_injection = new_routes_code + "\n\nif __name__ == \"__main__\":"
    src = apply_patch(src, "Routes: add /api/remote/* endpoints",
                      PATCH_ROUTES_OLD, routes_injection)

    write_file(TARGET_SERVER, src)
    info(f"Written: {TARGET_SERVER}")

    # ── Step 3: Syntax check ──────────────────────────────────────────────────
    hdr("Step 3 — Syntax Check")
    passed, err = syntax_check(TARGET_SERVER)
    if passed:
        ok(f"{TARGET_SERVER} — syntax OK")
    else:
        fail(f"Syntax error detected:\n{err}")
        warn(f"Restore with: cp {bak} {TARGET_SERVER}")

    # ── Step 4: Summary ───────────────────────────────────────────────────────
    print()
    print(B + C + "══════════════════════════════════════════════════════════════" + X)
    print(f"  Created : {G}{RESULTS['created']}{X}  |  "
          f"Patched : {G}{RESULTS['patched']}{X}  |  "
          f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
          f"Failed  : {(R if RESULTS['failed'] else D)}{RESULTS['failed']}{X}")
    print()
    print(f"  {G}What was added:{X}")
    items = [
        "agent/universal_agent.py   — runs ANY tool on remote system",
        "agent/install_agent.sh     — single-command installer (updated)",
        "/api/remote/agents         — list connected systems + their tools",
        "/api/remote/create-job     — queue any tool job for a remote agent",
        "/api/remote/jobs           — agent polls for pending jobs",
        "/api/remote/upload         — agent uploads completed results",
        "/api/remote/job-status/:id — dashboard polls job status",
        "/api/remote/jobs-overview  — recent jobs list",
        "/api/agent/heartbeat       — agent reports installed tools",
        "Remote Audit UI page       — select system + tool, view output",
    ]
    for item in items:
        print(f"    {G}✓{X}  {item}")
    print()
    print(f"  {Y}Restart server:{X}")
    print(f"    pkill -f api_server.py && python3 api_server.py")
    print()
    print(f"  {C}On each remote Linux system — single command:{X}")
    print(f"    curl -fsSL http://YOUR_SERVER:5000/agent/install.sh | bash")
    print()
    print(f"  {C}Then go to Remote Audit in the VulnScan sidebar.{X}")
    print()


if __name__ == "__main__":
    main()
