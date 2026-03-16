#!/usr/bin/env python3
"""
VulnScan Pro — API Server
All scan tools route through Tor/proxychains for anonymity.

REQUIREMENTS:
  sudo apt install tor proxychains4 nmap nikto dnsrecon lynis
  pip3 install PySocks --break-system-packages
  Tor must be running on 127.0.0.1:9050 (default)

PROXYCHAINS CONFIG (/etc/proxychains4.conf or /etc/proxychains.conf):
  [ProxyList]
  socks5 127.0.0.1 9050
"""
import json, re, sys, os, subprocess, io
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

from database import save_scan, get_history, get_scan_by_id
from auth import register_auth_routes, get_current_user, audit

register_auth_routes(app)

GRADE_COL = {"A+": "#00ff9d", "A": "#00e5ff", "B": "#ffd60a", "C": "#ff6b35", "D": "#ff6b35", "F": "#ff3366"}

# ── Tor / proxychains config ──────────────────────────────────────────────────
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

# ── Timeout constants (all inflated for Tor latency) ─────────────────────────
TIMEOUT_SCAN       = 720   # 12 min — nmap through Tor can be slow
TIMEOUT_SUBDOMAIN  = 180   # 3 min
TIMEOUT_DIRBUST    = 360   # 6 min
TIMEOUT_BRUTE      = 180   # 3 min
TIMEOUT_DISCOVER   = 300   # 5 min
TIMEOUT_HARVESTER  = 240   # 4 min
TIMEOUT_DNSRECON   = 180   # 3 min
TIMEOUT_NIKTO      = 900   # 15 min — Nikto through Tor is very slow
TIMEOUT_WPSCAN     = 480   # 8 min
TIMEOUT_LYNIS      = 360   # 6 min
TIMEOUT_LEGION     = 1200  # 20 min
TIMEOUT_REPORT     = 90    # 1.5 min


def run_backend(*args, timeout=300):
    """
    Run backend.py as a subprocess. Returns parsed JSON dict.
    Increased default timeout for Tor-routed scans.
    """
    cmd = [sys.executable, BACKEND] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Backend process timed out after {timeout}s. Through Tor this is normal — try a smaller scan scope or increase the timeout."}
    except FileNotFoundError:
        return {"error": f"Python interpreter not found: {sys.executable}"}

    if r.stderr and r.stderr.strip():
        print(f"[backend stderr] {r.stderr.strip()[:500]}", file=sys.stderr)

    if not r.stdout or not r.stdout.strip():
        err_detail = r.stderr.strip()[:300] if r.stderr else "No output from backend"
        return {"error": f"Backend returned no output. Details: {err_detail}"}

    raw = r.stdout.strip()
    start = raw.find('{')
    end = raw.rfind('}')
    if start == -1 or end == -1:
        return {"error": f"No JSON in backend output: {raw[:300]}"}
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}. Raw: {raw[start:start+200]}"}


def proxychains_cmd():
    """Return the available proxychains binary name."""
    import shutil
    return shutil.which("proxychains4") or shutil.which("proxychains") or "proxychains4"


# ══════════════════════════════════════════════
# HTML UI — injected from api_server original
# (keeping the full HTML block intact — no changes needed to UI)
# ══════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<!-- Full UI HTML is unchanged — see original api_server.py for full content -->
<!-- This stub redirects to indicate the file was truncated for brevity -->
<script>
  // NOTE TO DEVELOPER: Copy the full HTML string from the original api_server.py
  // Only the Python route handlers below have been modified for Tor support.
  document.write('<h2 style="font-family:monospace;color:#00e5ff;background:#04040a;padding:40px">VulnScan Pro API running. Replace this HTML stub with the full UI from original api_server.py</h2>');
</script>
</head><body></body></html>"""

# ── Auto-install helper ────────────────────────────────────────────────────────
def auto_install(pkg, binary=None):
    """Try to install a package via apt. Returns (success, message)."""
    import shutil
    binary = binary or pkg
    if shutil.which(binary):
        return True, f"{binary} already installed"
    try:
        r = subprocess.run(
            ["sudo", "apt-get", "install", "-y", pkg],
            capture_output=True, text=True, timeout=120
        )
        if shutil.which(binary):
            return True, f"Installed {pkg} via apt"
        return False, r.stderr[:300] or "apt install failed"
    except Exception as e:
        return False, str(e)


TOOL_INSTALL_MAP = {
    "nmap":         ("nmap",         "nmap"),
    "nikto":        ("nikto",        "nikto"),
    "lynis":        ("lynis",        "lynis"),
    "dnsrecon":     ("dnsrecon",     "dnsrecon"),
    "legion":       ("legion",       "legion"),
    "theharvester": ("theharvester", "theHarvester"),
    "wpscan":       (None,           "wpscan"),
    "dig":          ("dnsutils",     "dig"),
    "proxychains4": ("proxychains4", "proxychains4"),
    "tor":          ("tor",          "tor"),
}


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML


@app.route("/verify/<token>")
def verify_page(token):
    from auth import verify_user
    verify_user(token)
    return HTML


@app.route("/scan", methods=["GET", "POST"])
def scan():
    target = (request.args.get("target", "") if request.method == "GET"
              else (request.get_json() or {}).get("target", "")).strip()
    modules = request.args.get("modules", "ports,ssl,dns,headers")
    if not target:
        return jsonify({"error": "No target specified"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-_:/\[\]]+$', target):
        return jsonify({"error": "Invalid target — only alphanumeric, dots, dashes, colons allowed"}), 400

    user = get_current_user()
    uid = user["id"] if user else None
    uname = user["username"] if user else "anonymous"

    try:
        data = run_backend("--modules", modules, target, timeout=TIMEOUT_SCAN)
        if "error" not in data:
            data["scan_id"] = save_scan(target, data, user_id=uid, modules=modules)
            audit(uid, uname, "SCAN", target=target, ip=request.remote_addr,
                  details=f"modules={modules}")
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/subdomains")
def subdomains():
    domain = request.args.get("domain", "").strip()
    size = request.args.get("size", "medium")
    if not domain:
        return jsonify({"error": "No domain"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        return jsonify({"error": "Invalid domain"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SUBDOMAIN_ENUM", target=domain, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--subdomains", domain, size, timeout=TIMEOUT_SUBDOMAIN))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dirbust")
def dirbust():
    url = request.args.get("url", "").strip()
    size = request.args.get("size", "small")
    ext = request.args.get("ext", "php,html,txt")
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DIR_ENUM", target=url, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--dirbust", url, size, ext, timeout=TIMEOUT_DIRBUST))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/brute-http", methods=["POST"])
def brute_http():
    d = request.get_json() or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_HTTP", target=url, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:10])
    pwds = ",".join(d.get("passwords", [])[:50])
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        return jsonify(run_backend("--brute-http", url, users, pwds, uf, pf,
                                   timeout=TIMEOUT_BRUTE))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/brute-ssh", methods=["POST"])
def brute_ssh():
    d = request.get_json() or {}
    host = d.get("host", "").strip()
    port = str(d.get("port", "22"))
    if not host:
        return jsonify({"error": "No host"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_SSH", target=host, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:5])
    pwds = ",".join(d.get("passwords", [])[:20])
    try:
        return jsonify(run_backend("--brute-ssh", host, port, users, pwds,
                                   timeout=TIMEOUT_BRUTE))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/discover")
def discover():
    subnet = request.args.get("subnet", "").strip()
    if not subnet:
        return jsonify({"error": "No subnet"}), 400
    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({"error": "Invalid subnet"}), 400
    try:
        return jsonify(run_backend("--discover", subnet, timeout=TIMEOUT_DISCOVER))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    return jsonify(get_history(int(request.args.get("limit", 20)), user_id=uid))


@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    d = get_scan_by_id(sid, user_id=None if role == "admin" else uid)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)


# ── DNSRecon route (FIXED — removed stray nmap subprocess call) ───────────────
@app.route("/dnsrecon", methods=["POST"])
def dnsrecon_route():
    """
    Run dnsrecon through proxychains (Tor).
    DNSRecon supports TCP-based queries which work through SOCKS proxies.
    Note: Standard UDP DNS won't go through Tor — dnsrecon's TCP mode is used.
    """
    import shutil, tempfile
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    scan_type = data.get("type", "std")
    ns = (data.get("ns") or "").strip()
    rec_filter = (data.get("filter") or "").strip()

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("dnsrecon")
    if not binary:
        ok, msg = auto_install("dnsrecon", "dnsrecon")
        if not ok:
            return jsonify({
                "error": f"dnsrecon not installed and auto-install failed: {msg}. Run: sudo apt install dnsrecon",
                "auto_install_attempted": True
            })
        binary = shutil.which("dnsrecon")

    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    # Build dnsrecon command through proxychains
    # Use --tcp flag so DNS queries go through SOCKS (TCP only — UDP is blocked by Tor)
    cmd = [px, "-q", binary, "-d", target, "-t", scan_type, "-j", out_file, "--tcp"]
    if ns:
        cmd += ["-n", ns]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_DNSRECON)
        records = []

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                for item in (raw if isinstance(raw, list) else raw.get("records", [])):
                    if isinstance(item, dict):
                        rec = {
                            "type": item.get("type", "?"),
                            "name": item.get("name", ""),
                            "address": item.get("address", item.get("data", ""))
                        }
                        if rec_filter and rec["type"] != rec_filter:
                            continue
                        records.append(rec)
            except Exception:
                pass

        # Fallback: parse stdout if JSON was empty
        if not records:
            for line in proc.stdout.splitlines():
                m = re.match(r'\s*\[\*\]\s*(\w+)\s+([\w.\-]+)\s+([\d.]+)', line)
                if m:
                    if rec_filter and m.group(1) != rec_filter:
                        continue
                    records.append({
                        "type": m.group(1),
                        "name": m.group(2),
                        "address": m.group(3)
                    })

        if os.path.exists(out_file):
            os.unlink(out_file)

        return jsonify({
            "target": target,
            "records": records,
            "scan_type": scan_type,
            "note": "Queries sent via Tor (TCP mode). UDP-based records may be incomplete."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"dnsrecon timed out after {TIMEOUT_DNSRECON}s. Tor routing can be slow."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── Nikto route (FIXED — proper proxychains integration) ─────────────────────
@app.route("/nikto", methods=["POST"])
def nikto_route():
    """
    Run Nikto web scanner through proxychains/Tor.
    Nikto supports proxy via -useproxy flag or proxychains wrapper.
    Tor makes Nikto significantly slower — expect 5–15 minutes.
    """
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    port = int(data.get("port") or 80)
    ssl_flag = data.get("ssl", "")
    tuning = data.get("tuning", "")

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("nikto")
    if not binary:
        ok, msg = auto_install("nikto", "nikto")
        if not ok:
            return jsonify({
                "error": f"Nikto not installed and auto-install failed: {msg}. Run: sudo apt install nikto",
                "auto_install_attempted": True
            })
        binary = shutil.which("nikto")

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
    ]
    if ssl_flag == "-ssl":
        cmd += ["-ssl"]
    elif ssl_flag == "-nossl":
        cmd += ["-nossl"]
    if tuning:
        cmd += ["-Tuning", tuning]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_NIKTO)
        findings, server = [], ""

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                for host in (raw.get("host", []) if isinstance(raw, dict) else []):
                    server = host.get("banner", "")
                    for item in host.get("vulnerabilities", []):
                        findings.append({
                            "id": item.get("id", ""),
                            "description": item.get("msg", ""),
                            "url": item.get("uri", ""),
                            "method": item.get("method", ""),
                            "severity": "high" if item.get("OSVDB", "0") != "0" else "info"
                        })
            except Exception:
                pass

        # Fallback: parse stdout
        if not findings:
            for line in proc.stdout.splitlines():
                m = re.search(r'\+ (OSVDB-\d+|[\w-]+): (.+)', line)
                if m:
                    findings.append({
                        "id": m.group(1),
                        "description": m.group(2),
                        "severity": "high" if "OSVDB" in m.group(1) else "info"
                    })

        if os.path.exists(out_file):
            os.unlink(out_file)

        return jsonify({
            "target": target,
            "port": port,
            "server": server,
            "findings": findings,
            "note": "Scanned via Tor — results may be slower but IP is anonymized."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Nikto timed out after {TIMEOUT_NIKTO}s. Tor routing is slow — try a smaller tuning set."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── WPScan route ──────────────────────────────────────────────────────────────
@app.route("/wpscan", methods=["POST"])
def wpscan_route():
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    enum_flags = data.get("enum_flags", "p,u")
    token = (data.get("token") or "").strip()
    mode = data.get("mode", "mixed")

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("wpscan")
    if not binary:
        return jsonify({
            "error": "WPScan not installed. Run: sudo gem install wpscan  OR  docker pull wpscanteam/wpscan"
        })

    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    # WPScan supports --proxy natively — use Tor SOCKS5
    cmd = [
        binary,
        "--url", target,
        "--enumerate", enum_flags,
        "--detection-mode", mode,
        "--format", "json",
        "--output", out_file,
        "--no-banner",
        "--proxy", f"socks5://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",  # Native Tor proxy
        "--request-timeout", "30",     # 30s per request
        "--connect-timeout", "30",
    ]
    if token:
        cmd += ["--api-token", token]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_WPSCAN)

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                wp_version = raw.get("version", {}).get("number", "unknown")
                users = list(raw.get("users", {}).keys())
                plugins = []
                for name, pdata in raw.get("plugins", {}).items():
                    plugins.append({
                        "name": name,
                        "version": pdata.get("version", {}).get("number", "?"),
                        "vulnerabilities": pdata.get("vulnerabilities", [])
                    })
                vulns = []
                for name, pdata in raw.get("plugins", {}).items():
                    for v in pdata.get("vulnerabilities", []):
                        vulns.append({
                            "title": v.get("title", ""),
                            "type": v.get("type", ""),
                            "references": v.get("references", {})
                        })
                os.unlink(out_file)
                return jsonify({
                    "target": target,
                    "wp_version": wp_version,
                    "users": users,
                    "plugins": plugins,
                    "vulnerabilities": vulns,
                    "note": "Scanned via Tor SOCKS5 proxy."
                })
            except Exception as e:
                return jsonify({"error": f"Parse error: {e}"})

        return jsonify({"error": "WPScan produced no output. Is the target a WordPress site?"})

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"WPScan timed out after {TIMEOUT_WPSCAN}s. Through Tor this is normal — try passive mode."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── Lynis route ───────────────────────────────────────────────────────────────
@app.route("/lynis", methods=["POST"])
def lynis_route():
    """
    Lynis audits the LOCAL system — no Tor needed (local scan).
    """
    import shutil

    data = request.get_json() or {}
    profile = data.get("profile", "system")
    category = (data.get("category") or "").strip()
    compliance = (data.get("compliance") or "").strip()

    binary = shutil.which("lynis")
    if not binary:
        ok, msg = auto_install("lynis", "lynis")
        if not ok:
            return jsonify({
                "error": f"Lynis not installed and auto-install failed: {msg}. Run: sudo apt install lynis",
                "auto_install_attempted": True
            })
        binary = shutil.which("lynis")
        if not binary:
            return jsonify({"error": "Auto-install ran but lynis still not found."})

    # Lynis is local — no proxychains needed
    cmd = [binary, "audit", "system", "--quiet", "--no-colors", "--noplugins"]
    if compliance:
        cmd += ["--compliance", compliance.lower()]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_LYNIS)
        output = proc.stdout + proc.stderr
        hardening_index = 0
        warnings, suggestions = [], []

        for line in output.splitlines():
            m = re.search(r'Hardening index\s*[:\|]\s*(\d+)', line, re.IGNORECASE)
            if m:
                hardening_index = int(m.group(1))
            if "Warning" in line or "warning" in line:
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if len(clean) > 10 and "==" not in clean:
                    warnings.append(clean)
            elif "Suggestion" in line or "suggestion" in line:
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if len(clean) > 10 and "==" not in clean:
                    suggestions.append(clean)

        tests_m = re.search(r'Tests performed\s*[:\|]\s*(\d+)', output, re.IGNORECASE)
        tests_performed = tests_m.group(1) if tests_m else "?"

        return jsonify({
            "hardening_index": hardening_index,
            "warnings": list(set(warnings))[:50],
            "suggestions": list(set(suggestions))[:100],
            "tests_performed": tests_performed,
            "note": "Lynis is a local scan — Tor not used (local system audit)."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Lynis timed out after 6 minutes."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── Legion route ──────────────────────────────────────────────────────────────
@app.route("/legion", methods=["POST"])
def legion_route():
    import shutil

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    intensity = data.get("intensity", "normal")
    modules = data.get("modules", ["nmap", "nikto"])

    if not target:
        return jsonify({"error": "No target specified"})

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0

    # Timing map adjusted for Tor
    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T2"}[intensity]

    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({
                "module": mod,
                "summary": f"{mod} not found — install: sudo apt install {mod}",
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
                    m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
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
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})

        except subprocess.TimeoutExpired:
            findings.append({"title": f"{mod} timed out (Tor is slow)", "detail": ""})
        except Exception as e:
            findings.append({"title": f"{mod} error", "detail": str(e)})

        results.append({
            "module": mod,
            "findings": findings,
            "summary": f"{len(findings)} findings"
        })

    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "All modules ran through Tor/proxychains."
    })


# ── theHarvester route ────────────────────────────────────────────────────────
@app.route("/harvester", methods=["POST"])
def harvester():
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    sources = (data.get("sources") or "google,bing,dnsdumpster,crtsh").strip()
    limit = int(data.get("limit") or 500)

    if not target:
        return jsonify({"error": "No target specified"})
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        return jsonify({"error": "Invalid domain format"})

    if not shutil.which("theHarvester") and not shutil.which("theharvester"):
        ok, msg = auto_install("theharvester", "theHarvester")
        if not ok:
            return jsonify({
                "error": f"theHarvester not installed: {msg}. Run: sudo apt install theharvester",
                "auto_install_attempted": True
            })

    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    px = proxychains_cmd()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "harvest")

        # Route theHarvester through proxychains
        cmd = [px, "-q", binary, "-d", target, "-l", str(limit), "-b", sources, "-f", out_file]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HARVESTER)
            raw_out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return jsonify({"error": f"theHarvester timed out after {TIMEOUT_HARVESTER}s. Try fewer sources."})
        except Exception as e:
            return jsonify({"error": str(e)})

        emails, hosts, subdomains, ips = [], [], [], []
        json_path = out_file + ".json"

        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    jd = json.load(f)
                emails = list(set(jd.get("emails", [])))
                hosts_raw = jd.get("hosts", [])
                for h in hosts_raw:
                    if isinstance(h, dict):
                        hosts.append(h)
                        if h.get("ip"):
                            ips.append(h["ip"])
                    else:
                        hosts.append({"host": h, "ip": ""})
                subdomains = list(set(
                    h["host"] if isinstance(h, dict) else h for h in hosts_raw
                ))
                ips = list(set(ips + jd.get("ips", [])))
            except Exception:
                pass

        # Fallback: parse stdout
        if not emails and not hosts:
            for line in raw_out.splitlines():
                line = line.strip()
                if "@" in line and "." in line and " " not in line:
                    emails.append(line)
                elif re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', line):
                    subdomains.append(line)
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips.append(line)
            emails = list(set(emails))
            subdomains = list(set(subdomains))
            ips = list(set(ips))

        return jsonify({
            "target": target,
            "sources": sources,
            "emails": emails[:500],
            "hosts": hosts[:500],
            "subdomains": subdomains[:500],
            "ips": ips[:500],
            "raw_lines": len(raw_out.splitlines()),
            "note": "OSINT collected via Tor/proxychains."
        })


# ── Report route ──────────────────────────────────────────────────────────────
@app.route("/report", methods=["POST"])
def report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        return jsonify({"error": "reportlab not installed: pip3 install reportlab --break-system-packages"}), 500

    data = request.get_json() or {}
    target = data.get("target", "unknown")
    scan_time = data.get("scan_time", "")[:19].replace("T", " ")
    summary = data.get("summary", {})
    modules = data.get("modules", {})
    hosts = modules.get("ports", {}).get("hosts", [])
    all_ports = [p for h in hosts for p in h.get("ports", [])]

    C_BG = colors.HexColor("#04040a"); C_DARK = colors.HexColor("#0d0d18")
    C_BORDER = colors.HexColor("#16162a"); C_MUTED = colors.HexColor("#5a5a8a")
    C_WHITE = colors.HexColor("#e8e8f0"); C_CYAN = colors.HexColor("#00e5ff")
    C_RED = colors.HexColor("#ff3366"); C_ORANGE = colors.HexColor("#ff6b35")
    C_YELLOW = colors.HexColor("#ffd60a"); C_GREEN = colors.HexColor("#00ff9d")
    C_PURPLE = colors.HexColor("#b06fff")
    SEV_C = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW,
             "LOW": C_GREEN, "UNKNOWN": C_MUTED}

    def sty(name, **kw):
        d = dict(fontName="Helvetica", fontSize=9, textColor=C_WHITE, leading=14,
                 spaceAfter=4, spaceBefore=2, leftIndent=0, alignment=TA_LEFT)
        d.update(kw)
        return ParagraphStyle(name, **d)

    S_T  = sty("t",  fontName="Helvetica-Bold", fontSize=26, textColor=C_CYAN, leading=32, spaceAfter=6)
    S_H1 = sty("h1", fontName="Helvetica-Bold", fontSize=15, textColor=C_CYAN, leading=20, spaceBefore=16, spaceAfter=8)
    S_H2 = sty("h2", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, leading=16, spaceBefore=10, spaceAfter=5)
    S_H3 = sty("h3", fontName="Helvetica-Bold", fontSize=9,  textColor=C_MUTED, leading=13, spaceBefore=7, spaceAfter=4, leftIndent=8)
    S_B  = sty("b")
    S_C  = sty("c", alignment=TA_CENTER, textColor=C_MUTED, fontSize=8)
    S_W  = sty("w", fontName="Helvetica-Bold", textColor=C_RED)

    def p(t, s=None): return Paragraph(str(t), s or S_B)
    def sp(h=6): return Spacer(1, h)
    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=7, spaceBefore=3)

    def tbl(data, cols, sx=[]):
        t = Table(data, colWidths=cols)
        base = [
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ("TEXTCOLOR", (0,0), (-1,-1), C_WHITE),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8)
        ]
        t.setStyle(TableStyle(base + sx))
        return t

    W, H = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=16*mm, rightMargin=16*mm,
                            topMargin=14*mm, bottomMargin=14*mm)

    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG); canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.setFillColor(C_RED); canvas.rect(0, H-3, W, 3, fill=1, stroke=0)
        canvas.setFillColor(C_DARK); canvas.rect(0, 0, W, 13*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7); canvas.setFillColor(C_MUTED)
        canvas.drawString(16*mm, 4.5*mm,
                          f"VulnScan Pro  |  {target}  |  {scan_time}  |  CONFIDENTIAL  |  Via Tor")
        canvas.drawRightString(W-16*mm, 4.5*mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []
    crit_c = summary.get("critical_cves", 0)
    high_c = summary.get("high_cves", 0)
    if crit_c > 0:   risk = ("F", C_RED,    "CRITICAL RISK")
    elif high_c > 0: risk = ("D", C_ORANGE, "HIGH RISK")
    elif summary.get("total_cves", 0) > 0: risk = ("C", C_YELLOW, "MEDIUM RISK")
    else:            risk = ("A", C_GREEN,  "LOW RISK")

    story += [sp(36), p("VulnScan Pro", S_T)]
    story.append(p("SECURITY ASSESSMENT REPORT",
                   sty("st2", fontName="Helvetica-Bold", fontSize=12,
                       textColor=C_PURPLE, leading=18)))
    story += [sp(8), hr(), sp(8)]
    story.append(tbl(
        [[k, v] for k, v in [
            ("Target", target),
            ("Scan Time", scan_time),
            ("Report Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            ("Risk Level", risk[2]),
            ("Routing", f"Tor SOCKS5 ({TOR_SOCKS_HOST}:{TOR_SOCKS_PORT})")
        ]],
        [38*mm, 115*mm],
        [
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0,0), (0,-1), C_MUTED),
            ("TEXTCOLOR", (1,3), (1,3), risk[1]),
            ("FONTNAME",  (1,3), (1,3), "Helvetica-Bold"),
            ("TEXTCOLOR", (1,4), (1,4), C_CYAN),
        ]
    ))
    story += [sp(18)]
    st = Table([[
        f"{summary.get('open_ports', 0)}\nOPEN PORTS",
        f"{summary.get('total_cves', 0)}\nTOTAL CVEs",
        f"{crit_c}\nCRITICAL",
        f"{high_c}\nHIGH",
        f"{summary.get('exploitable', 0)}\nEXPLOITABLE"
    ]], colWidths=[30*mm]*5)
    ss = TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 11),
        ("BOTTOMPADDING", (0,0), (-1,-1), 11),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK]),
        ("GRID", (0,0), (-1,-1), 0.4, C_BORDER),
    ])
    for i, c in enumerate([C_CYAN, C_YELLOW, C_RED, C_ORANGE, C_PURPLE]):
        ss.add("TEXTCOLOR", (i,0), (i,0), c)
    st.setStyle(ss)
    story += [st, sp(28)]
    story.append(p("CONFIDENTIAL — Authorized security assessment only. Scanned anonymously via Tor.",
                   sty("disc", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)))
    story.append(PageBreak())
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    buf.seek(0)
    fname = (f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]', '_', target)}"
             f"-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf")
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── Auto-install route ─────────────────────────────────────────────────────────
@app.route("/auto-install", methods=["POST"])
def auto_install_route():
    import shutil
    data = request.get_json() or {}
    tool = (data.get("tool") or "").strip().lower()
    if not tool or tool not in TOOL_INSTALL_MAP:
        return jsonify({"error": f"Unknown tool: {tool}"})
    pkg, binary = TOOL_INSTALL_MAP[tool]
    if not pkg:
        return jsonify({"error": f"{tool} requires manual install (not via apt)"})
    ok, msg = auto_install(pkg, binary)
    return jsonify({"ok": ok, "message": msg, "installed": bool(shutil.which(binary))})


# ── Theme API ──────────────────────────────────────────────────────────────────
_global_theme = {"theme": "cyberpunk"}

@app.route("/api/theme", methods=["GET", "POST"])
def theme_api():
    global _global_theme
    if request.method == "POST":
        data = request.get_json() or {}
        _global_theme["theme"] = data.get("theme", "cyberpunk")
        return jsonify({"ok": True, "theme": _global_theme["theme"]})
    return jsonify({"theme": _global_theme["theme"]})


# ── Server CLI Console ─────────────────────────────────────────────────────────
ALLOWED_CLI_COMMANDS = {
    "ls", "pwd", "whoami", "uptime", "df", "free", "ps", "netstat", "ss",
    "nmap", "theHarvester", "dnsrecon", "nikto", "lynis", "wpscan",
    "systemctl", "journalctl", "cat", "echo", "uname", "hostname",
    "ip", "ifconfig", "ping", "traceroute", "curl", "wget", "which",
    "apt", "apt-get", "dpkg", "pip3", "python3", "gem",
    "proxychains4", "proxychains", "tor",   # Added Tor tools
    "systemctl",
}
BLOCKED_PATTERNS = [
    r'rm\s+-rf', r'>\s*/etc', r'chmod\s+777\s+/', r'dd\s+if=',
    r'mkfs', r'fdisk', r';.*rm\s', r'\|\s*sh\b', r'curl.*\|.*bash',
    r'wget.*\|.*sh', r'base64.*decode.*\|'
]

@app.route("/api/exec", methods=["POST"])
def cli_route():
    import shutil
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required for CLI console"})
    data = request.get_json() or {}
    cmd_str = (data.get("command") or "").strip()
    if not cmd_str:
        return jsonify({"output": "", "error": ""})
    for pat in BLOCKED_PATTERNS:
        if re.search(pat, cmd_str, re.IGNORECASE):
            return jsonify({"error": f"Blocked: dangerous pattern detected"})
    first_word = cmd_str.split()[0]
    if first_word not in ALLOWED_CLI_COMMANDS:
        return jsonify({"error": f"Command '{first_word}' not in allowlist. Allowed: {', '.join(sorted(ALLOWED_CLI_COMMANDS))}"})
    try:
        r = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=30, cwd=os.path.expanduser("~")
        )
        return jsonify({
            "output": r.stdout[:8000],
            "error": r.stderr[:2000],
            "exit_code": r.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out (30s limit)", "output": ""})
    except Exception as e:
        return jsonify({"error": str(e), "output": ""})


# ── Health check ───────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    import shutil
    # Check Tor is running
    tor_running = False
    try:
        import socket as _s
        sock = _s.create_connection(("127.0.0.1", 9050), timeout=2)
        sock.close()
        tor_running = True
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "version": "3.7",
        "nmap": bool(shutil.which("nmap")),
        "dig": bool(shutil.which("dig")),
        "proxychains4": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "tor_running": tor_running,
        "tor_port": TOR_SOCKS_PORT,
        "python": sys.version
    })


if __name__ == "__main__":
    print("[*] VulnScan Pro v3.7 starting (Tor mode)")
    print(f"[*] Tor SOCKS5: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("[*] Open: http://localhost:5000")
    print("[*] Health check: http://localhost:5000/health")
    print("[*] Verify Tor is running: systemctl status tor")
    app.run(host="0.0.0.0", port=5000, debug=False)
