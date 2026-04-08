#!/usr/bin/env python3
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
