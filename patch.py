#!/usr/bin/env python3
"""
VulnScan Pro — Comprehensive Audit Logging Patch
=================================================
Ensures every tool use and user action is stored in the audit_log table.

Covers:
  • All scan/tool routes in api_server.py
  • Admin actions
  • Agent/Lynis job operations
  • PDF report generation
  • Directory busting, subdomain enum, discovery
  • Brute force (HTTP + SSH)
  • Social tools (SET, Gophish, Evilginx2, ShellPhish, Netcat, etc.)
  • Deep web audit + SSE stream
  • Wordlist API
  • Auto-install attempts
  • CLI console commands
  • Theme changes

Run from project root:
    python3 patch_audit_logging.py
"""

import os
import re
import sys
import shutil
import subprocess
from datetime import datetime

# ── colours ──────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")
def skip(m): print(f"  {D}·{X}  {m}")

TARGET = "api_server.py"
RESULTS = {"applied": 0, "skipped": 0, "failed": 0}


def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.audit_patch_{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True
    )
    return r.returncode == 0, r.stderr.strip()


def apply_patch(src, label, old, new):
    if old in src:
        result = src.replace(old, new, 1)
        ok(label)
        RESULTS["applied"] += 1
        return result
    elif new in src:
        skip(f"{label} (already applied)")
        RESULTS["skipped"] += 1
        return src
    else:
        fail(f"{label} — anchor not found")
        RESULTS["failed"] += 1
        return src


# ══════════════════════════════════════════════════════════════
# PATCH DEFINITIONS
# Each tuple: (label, old_text, new_text)
# ══════════════════════════════════════════════════════════════

PATCHES = []

# ─────────────────────────────────────────────────────────────
# 1. /scan route — add detailed audit with modules & profile
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "SCAN route — full audit with modules/profile/CVE summary",
    '''        if "error" not in data:
            data["scan_id"] = save_scan(target, data, user_id=uid, modules=modules)
            audit(uid, uname, "SCAN", target=target, ip=request.remote_addr,
                  details=f"modules={modules};profile={nmapProfile}")''',
    '''        if "error" not in data:
            data["scan_id"] = save_scan(target, data, user_id=uid, modules=modules)
            _s = data.get("summary", {})
            audit(uid, uname, "SCAN", target=target, ip=request.remote_addr,
                  details=(
                      f"modules={modules};profile={nmapProfile};"
                      f"open_ports={_s.get('open_ports',0)};"
                      f"total_cves={_s.get('total_cves',0)};"
                      f"critical_cves={_s.get('critical_cves',0)};"
                      f"exploitable={_s.get('exploitable',0)}"
                  ))'''
))

# ─────────────────────────────────────────────────────────────
# 2. /subdomains — add result count to audit
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "SUBDOMAINS route — audit with result count",
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SUBDOMAIN_ENUM", target=domain, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--subdomains", domain, size, timeout=TIMEOUT_SUBDOMAIN))''',
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SUBDOMAIN_ENUM", target=domain, ip=request.remote_addr,
          details=f"size={size}")
    try:
        _sub_result = run_backend("--subdomains", domain, size, timeout=TIMEOUT_SUBDOMAIN)
        _sub_count = _sub_result.get("total", 0) if isinstance(_sub_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "SUBDOMAIN_ENUM_RESULT", target=domain, ip=request.remote_addr,
              details=f"size={size};found={_sub_count}")
        return jsonify(_sub_result)'''
))

# ─────────────────────────────────────────────────────────────
# 3. /dirbust — audit with wordlist size and result count
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "DIRBUST route — audit with size/ext/result count",
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DIR_ENUM", target=url, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--dirbust", url, size, ext, timeout=TIMEOUT_DIRBUST))''',
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DIR_ENUM", target=url, ip=request.remote_addr,
          details=f"size={size};ext={ext}")
    try:
        _dir_result = run_backend("--dirbust", url, size, ext, timeout=TIMEOUT_DIRBUST)
        _dir_found = _dir_result.get("total", 0) if isinstance(_dir_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "DIR_ENUM_RESULT", target=url, ip=request.remote_addr,
              details=f"size={size};ext={ext};found={_dir_found}")
        return jsonify(_dir_result)'''
))

# ─────────────────────────────────────────────────────────────
# 4. /brute-http — audit with attempt/found counts
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "BRUTE-HTTP route — audit with credentials found count",
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_HTTP", target=url, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:10])
    pwds = ",".join(d.get("passwords", [])[:50])
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        return jsonify(run_backend("--brute-http", url, users, pwds, uf, pf,
                                   timeout=TIMEOUT_BRUTE))''',
    '''    user = get_current_user()
    _bh_users = d.get("users", [])[:10]
    _bh_pwds  = d.get("passwords", [])[:50]
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_HTTP", target=url, ip=request.remote_addr,
          details=f"users={len(_bh_users)};passwords={len(_bh_pwds)}")
    users = ",".join(_bh_users)
    pwds  = ",".join(_bh_pwds)
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        _bh_result = run_backend("--brute-http", url, users, pwds, uf, pf,
                                  timeout=TIMEOUT_BRUTE)
        _bh_found = len(_bh_result.get("found", [])) if isinstance(_bh_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "BRUTE_HTTP_RESULT", target=url, ip=request.remote_addr,
              details=f"attempts={_bh_result.get('attempts',0) if isinstance(_bh_result,dict) else 0};found={_bh_found}")
        return jsonify(_bh_result)'''
))

# ─────────────────────────────────────────────────────────────
# 5. /brute-ssh — audit with result
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "BRUTE-SSH route — audit with credentials found count",
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_SSH", target=host, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:5])
    pwds = ",".join(d.get("passwords", [])[:20])
    try:
        return jsonify(run_backend("--brute-ssh", host, port, users, pwds,
                                   timeout=TIMEOUT_BRUTE))''',
    '''    user = get_current_user()
    _bs_users = d.get("users", [])[:5]
    _bs_pwds  = d.get("passwords", [])[:20]
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_SSH", target=host, ip=request.remote_addr,
          details=f"port={port};users={len(_bs_users)};passwords={len(_bs_pwds)}")
    users = ",".join(_bs_users)
    pwds  = ",".join(_bs_pwds)
    try:
        _bs_result = run_backend("--brute-ssh", host, port, users, pwds,
                                  timeout=TIMEOUT_BRUTE)
        _bs_found = len(_bs_result.get("found", [])) if isinstance(_bs_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "BRUTE_SSH_RESULT", target=host, ip=request.remote_addr,
              details=f"port={port};attempts={_bs_result.get('attempts',0) if isinstance(_bs_result,dict) else 0};found={_bs_found}")
        return jsonify(_bs_result)'''
))

# ─────────────────────────────────────────────────────────────
# 6. /social-tools/run — enhance existing audit with exit code
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "SOCIAL-TOOLS/RUN — audit start + result with exit code",
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SOCIAL_TOOL_RUN", target=tool, ip=request.remote_addr,
          details=f"operation={operation};cmd={' '.join(cmd[:5])}")

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)
        return jsonify({''',
    '''    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SOCIAL_TOOL_RUN", target=tool, ip=request.remote_addr,
          details=f"operation={operation};args={args_text[:120]};cmd={' '.join(cmd[:5])}")

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "SOCIAL_TOOL_RESULT", target=tool, ip=request.remote_addr,
              details=f"exit_code={proc.returncode};duration_ms={elapsed};operation={operation}")
        return jsonify({'''
))

# ─────────────────────────────────────────────────────────────
# 7. /discover — audit with subnet and result count
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "DISCOVER route — audit with subnet and host count",
    '''    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({"error": "Invalid subnet"}), 400
    try:
        return jsonify(run_backend("--discover", subnet, timeout=TIMEOUT_DISCOVER))''',
    '''    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({"error": "Invalid subnet"}), 400
    _disc_user = get_current_user()
    audit(_disc_user["id"] if _disc_user else None,
          _disc_user["username"] if _disc_user else "anon",
          "NETWORK_DISCOVER", target=subnet, ip=request.remote_addr,
          details=f"subnet={subnet}")
    try:
        _disc_result = run_backend("--discover", subnet, timeout=TIMEOUT_DISCOVER)
        _disc_hosts = _disc_result.get("total", 0) if isinstance(_disc_result, dict) else 0
        audit(_disc_user["id"] if _disc_user else None,
              _disc_user["username"] if _disc_user else "anon",
              "NETWORK_DISCOVER_RESULT", target=subnet, ip=request.remote_addr,
              details=f"subnet={subnet};hosts_found={_disc_hosts}")
        return jsonify(_disc_result)'''
))

# ─────────────────────────────────────────────────────────────
# 8. /nikto route — audit with port/tuning/finding count
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "NIKTO route — audit with port/tuning and finding count",
    '''    cmd = [
        px, "-q",
        binary,
        "-h", target,
        "-p", str(port),
        "-Format", "json",
        "-o", out_file,
        "-nointeractive",
        "-timeout", "30",      # 30s per request (Tor latency)
        "-maxtime", "1800",    # Max 30 min total
    ]''',
    '''    _nk_user = get_current_user()
    audit(_nk_user["id"] if _nk_user else None,
          _nk_user["username"] if _nk_user else "anon",
          "NIKTO_SCAN", target=target, ip=request.remote_addr,
          details=f"port={port};ssl={ssl_flag};tuning={tuning}")
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
    ]'''
))

PATCHES.append((
    "NIKTO route — audit result with finding count",
    '''        return jsonify({
            "target": target,
            "port": port,
            "server": server,
            "findings": findings,
            "note": "Scanned via Tor — results may be slower but IP is anonymized."
        })''',
    '''        _nk_user2 = get_current_user()
        audit(_nk_user2["id"] if _nk_user2 else None,
              _nk_user2["username"] if _nk_user2 else "anon",
              "NIKTO_RESULT", target=target, ip=request.remote_addr,
              details=f"port={port};findings={len(findings)};server={server[:40]}")
        return jsonify({
            "target": target,
            "port": port,
            "server": server,
            "findings": findings,
            "note": "Scanned via Tor — results may be slower but IP is anonymized."
        })'''
))

# ─────────────────────────────────────────────────────────────
# 9. /wpscan route — audit with target/mode and vuln count
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "WPSCAN route — audit start",
    '''    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("wpscan")
    if not binary:
        return jsonify({
            "error": "WPScan not installed. Run: sudo gem install wpscan  OR  docker pull wpscanteam/wpscan"
        })''',
    '''    if not target:
        return jsonify({"error": "No target specified"})

    _wp_user = get_current_user()
    audit(_wp_user["id"] if _wp_user else None,
          _wp_user["username"] if _wp_user else "anon",
          "WPSCAN", target=target, ip=request.remote_addr,
          details=f"enum={enum_flags};mode={mode}")

    binary = shutil.which("wpscan")
    if not binary:
        return jsonify({
            "error": "WPScan not installed. Run: sudo gem install wpscan  OR  docker pull wpscanteam/wpscan"
        })'''
))

# ─────────────────────────────────────────────────────────────
# 10. /lynis route — audit start and result
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LYNIS route — audit start",
    '''    binary = shutil.which("lynis")
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

    # Lynis is local — no proxychains needed''',
    '''    _ly_user = get_current_user()
    audit(_ly_user["id"] if _ly_user else None,
          _ly_user["username"] if _ly_user else "anon",
          "LYNIS_SCAN", target="localhost", ip=request.remote_addr,
          details=f"profile={profile};category={category};compliance={compliance}")

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

    # Lynis is local — no proxychains needed'''
))

PATCHES.append((
    "LYNIS route — audit result with hardening index",
    '''        return jsonify({
            "hardening_index": hardening_index,
            "warnings": sorted(set(filter(None, warnings)))[:120],
            "suggestions": sorted(set(filter(None, suggestions)))[:200],
            "tests_performed": tests_performed,
            "raw_report": raw_report[-200000:],
            "profile_used": profile,
            "category_used": category,
            "compliance_used": compliance,
            "command_used": " ".join(cmd),
            "note": "Lynis is a local scan — Tor not used (local system audit)."
        })''',
    '''        audit(_ly_user["id"] if _ly_user else None,
              _ly_user["username"] if _ly_user else "anon",
              "LYNIS_RESULT", target="localhost", ip=request.remote_addr,
              details=(f"profile={profile};compliance={compliance};"
                       f"hardening_index={hardening_index};"
                       f"warnings={len(warnings)};suggestions={len(suggestions)};"
                       f"tests_performed={tests_performed}"))
        return jsonify({
            "hardening_index": hardening_index,
            "warnings": sorted(set(filter(None, warnings)))[:120],
            "suggestions": sorted(set(filter(None, suggestions)))[:200],
            "tests_performed": tests_performed,
            "raw_report": raw_report[-200000:],
            "profile_used": profile,
            "category_used": category,
            "compliance_used": compliance,
            "command_used": " ".join(cmd),
            "note": "Lynis is a local scan — Tor not used (local system audit)."
        })'''
))

# ─────────────────────────────────────────────────────────────
# 11. /legion route — audit with target/intensity/modules
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LEGION route — audit start and result",
    '''    if not target:
        return jsonify({"error": "No target specified"})

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0''',
    '''    if not target:
        return jsonify({"error": "No target specified"})

    _lg_user = get_current_user()
    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_SCAN", target=target, ip=request.remote_addr,
          details=f"intensity={intensity};modules={','.join(modules)}")

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0'''
))

PATCHES.append((
    "LEGION route — audit result",
    '''    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "All modules ran through Tor/proxychains."
    })''',
    '''    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_RESULT", target=target, ip=request.remote_addr,
          details=f"open_ports={open_ports};issues={total_issues};modules_run={modules_run}")
    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "All modules ran through Tor/proxychains."
    })'''
))

# ─────────────────────────────────────────────────────────────
# 12. /harvester route — audit with sources/limit
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "HARVESTER route — audit result with email/host counts",
    '''    return jsonify({
            "target": target,
            "sources": sources,
            "emails": emails[:500],
            "hosts": hosts[:500],
            "subdomains": subdomains[:500],
            "ips": ips[:500],
            "raw_lines": len(raw_out.splitlines()),
            "note": "OSINT collected via Tor/proxychains."
        })''',
    '''        audit(user["id"] if user else None, user["username"] if user else "anon",
              "HARVESTER_RESULT", target=target, ip=request.remote_addr,
              details=(f"sources={sources};emails={len(emails)};"
                       f"hosts={len(hosts)};subdomains={len(subdomains)};ips={len(ips)}"))
        return jsonify({
            "target": target,
            "sources": sources,
            "emails": emails[:500],
            "hosts": hosts[:500],
            "subdomains": subdomains[:500],
            "ips": ips[:500],
            "raw_lines": len(raw_out.splitlines()),
            "note": "OSINT collected via Tor/proxychains."
        })'''
))

# ─────────────────────────────────────────────────────────────
# 13. /dnsrecon route — audit result with record count
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "DNSRECON route — audit result with record count",
    '''    return jsonify({
        "target":     target,
        "records":    records,
        "scan_type":  scan_type,
        "total":      len(records),
        "method":     method_used,
        "note": (''',
    '''    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DNSRECON_RESULT", target=target, ip=request.remote_addr,
          details=f"type={scan_type};records={len(records)};method={method_used}")
    return jsonify({
        "target":     target,
        "records":    records,
        "scan_type":  scan_type,
        "total":      len(records),
        "method":     method_used,
        "note": ('''
))

# ─────────────────────────────────────────────────────────────
# 14. /report (PDF) — audit generation
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "PDF REPORT route — audit generation",
    '''    data = _pdf_safe(request.get_json() or {})
    target     = data.get("target", "unknown")
    scan_time  = data.get("scan_time", "")[:19].replace("T", " ")''',
    '''    data = _pdf_safe(request.get_json() or {})
    target     = data.get("target", "unknown")
    scan_time  = data.get("scan_time", "")[:19].replace("T", " ")
    _rpt_user = get_current_user()
    audit(_rpt_user["id"] if _rpt_user else None,
          _rpt_user["username"] if _rpt_user else "anon",
          "PDF_REPORT_GENERATED", target=target, ip=request.remote_addr,
          details=f"scan_time={scan_time};open_ports={data.get('summary',{}).get('open_ports',0)};total_cves={data.get('summary',{}).get('total_cves',0)}")'''
))

# ─────────────────────────────────────────────────────────────
# 15. /auto-install route — audit install attempts
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "AUTO-INSTALL route — audit install attempt and result",
    '''    if not tool or tool not in TOOL_INSTALL_MAP:
        return jsonify({"error": f"Unknown tool: {tool}"})
    pkg, binary = TOOL_INSTALL_MAP[tool]
    if not pkg:
        return jsonify({"error": f"{tool} requires manual install (not via apt)"})
    ok, msg = auto_install(pkg, binary)
    return jsonify({"ok": ok, "message": msg, "installed": bool(shutil.which(binary))})''',
    '''    if not tool or tool not in TOOL_INSTALL_MAP:
        return jsonify({"error": f"Unknown tool: {tool}"})
    pkg, binary = TOOL_INSTALL_MAP[tool]
    if not pkg:
        return jsonify({"error": f"{tool} requires manual install (not via apt)"})
    _ai_user = get_current_user()
    audit(_ai_user["id"] if _ai_user else None,
          _ai_user["username"] if _ai_user else "anon",
          "AUTO_INSTALL", target=tool, ip=request.remote_addr,
          details=f"pkg={pkg};binary={binary}")
    ok_flag, msg = auto_install(pkg, binary)
    _ai_installed = bool(shutil.which(binary))
    audit(_ai_user["id"] if _ai_user else None,
          _ai_user["username"] if _ai_user else "anon",
          "AUTO_INSTALL_RESULT", target=tool, ip=request.remote_addr,
          details=f"pkg={pkg};success={ok_flag};installed={_ai_installed};msg={msg[:80]}")
    return jsonify({"ok": ok_flag, "message": msg, "installed": _ai_installed})'''
))

# ─────────────────────────────────────────────────────────────
# 16. /api/exec (CLI) — enhance existing audit with full command
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "CLI CONSOLE route — audit with full command and exit code",
    '''    try:
        r = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=30, cwd=os.path.expanduser("~")
        )
        return jsonify({
            "output": r.stdout[:8000],
            "error": r.stderr[:2000],
            "exit_code": r.returncode
        })''',
    '''    audit(u["id"], u["username"], "CLI_EXEC", target="server",
          ip=request.remote_addr,
          details=f"cmd={cmd_str[:200]}")
    try:
        r = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=30, cwd=os.path.expanduser("~")
        )
        audit(u["id"], u["username"], "CLI_EXEC_RESULT", target="server",
              ip=request.remote_addr,
              details=f"cmd={cmd_str[:200]};exit_code={r.returncode}")
        return jsonify({
            "output": r.stdout[:8000],
            "error": r.stderr[:2000],
            "exit_code": r.returncode
        })'''
))

# ─────────────────────────────────────────────────────────────
# 17. /api/theme POST — audit theme change
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "THEME API route — audit theme change",
    '''    if request.method == "POST":
        data = request.get_json() or {}
        _global_theme["theme"] = data.get("theme", "cyberpunk")
        return jsonify({"ok": True, "theme": _global_theme["theme"]})''',
    '''    if request.method == "POST":
        data = request.get_json() or {}
        _theme_old = _global_theme.get("theme", "unknown")
        _global_theme["theme"] = data.get("theme", "cyberpunk")
        _theme_user = get_current_user()
        audit(_theme_user["id"] if _theme_user else None,
              _theme_user["username"] if _theme_user else "anon",
              "THEME_CHANGE", target="ui", ip=request.remote_addr,
              details=f"from={_theme_old};to={_global_theme['theme']}")
        return jsonify({"ok": True, "theme": _global_theme["theme"]})'''
))

# ─────────────────────────────────────────────────────────────
# 18. /api/wordlist — audit wordlist access
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "WORDLIST API route — audit access",
    '''    if not user:
        return jsonify({"error": "Login required"}), 401

    path = request.args.get("path", "").strip()
    limit = min(int(request.args.get("limit", "1000")), 5000)''',
    '''    if not user:
        return jsonify({"error": "Login required"}), 401

    path = request.args.get("path", "").strip()
    limit = min(int(request.args.get("limit", "1000")), 5000)
    audit(user["id"], user["username"], "WORDLIST_ACCESS",
          target=path, ip=request.remote_addr,
          details=f"path={path};limit={limit}")'''
))

# ─────────────────────────────────────────────────────────────
# 19. Agent register — enhance audit
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "AGENT REGISTER — audit registration with client details",
    '''    return jsonify({"client_id": client_id, "token": token, "api_base": request.url_root.rstrip("/")})''',
    '''    audit(None, "agent", "AGENT_REGISTER", target=client_id,
          ip=request.remote_addr,
          details=f"hostname={hostname};os_info={os_info[:60]}")
    return jsonify({"client_id": client_id, "token": token, "api_base": request.url_root.rstrip("/")})'''
))

# ─────────────────────────────────────────────────────────────
# 20. Agent create-job — audit job creation
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LYNIS CREATE-JOB — audit job creation",
    '''    return jsonify({"job_id": jid, "status": "pending"})''',
    '''    _cj_user = get_current_user()
    audit(_cj_user["id"] if _cj_user else None,
          _cj_user["username"] if _cj_user else "anon",
          "LYNIS_JOB_CREATED", target=client_id, ip=request.remote_addr,
          details=f"job_id={jid};profile={profile};compliance={compliance};category={category}")
    return jsonify({"job_id": jid, "status": "pending"})'''
))

# ─────────────────────────────────────────────────────────────
# 21. Agent cancel-job — audit cancellation
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LYNIS CANCEL-JOB — audit cancellation",
    '''    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])''',
    '''    _cancel_user = get_current_user()
    audit(_cancel_user["id"] if _cancel_user else None,
          _cancel_user["username"] if _cancel_user else "anon",
          "LYNIS_JOB_CANCEL", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id};status={status}")
    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])'''
))

# ─────────────────────────────────────────────────────────────
# 22. Agent delete-job — audit deletion
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LYNIS DELETE-JOB — audit deletion",
    '''    return jsonify({"ok": True, "job_id": job_id, "deleted": True})


@app.route("/api/job-report/<int:job_id>.txt", methods=["GET"])''',
    '''    _del_user = get_current_user()
    audit(_del_user["id"] if _del_user else None,
          _del_user["username"] if _del_user else "anon",
          "LYNIS_JOB_DELETED", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id}")
    return jsonify({"ok": True, "job_id": job_id, "deleted": True})


@app.route("/api/job-report/<int:job_id>.txt", methods=["GET"])'''
))

# ─────────────────────────────────────────────────────────────
# 23. Job report download — audit download
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "LYNIS JOB-REPORT DOWNLOAD — audit download",
    '''def download_job_report(job_id):
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT raw_report FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    report = row["raw_report"] or "No report content."''',
    '''def download_job_report(job_id):
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT raw_report FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    _dl_user = get_current_user()
    audit(_dl_user["id"] if _dl_user else None,
          _dl_user["username"] if _dl_user else "anon",
          "LYNIS_REPORT_DOWNLOAD", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id}")
    report = row["raw_report"] or "No report content."'''
))

# ─────────────────────────────────────────────────────────────
# 24. Agent disconnect — enhance existing audit
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "AGENT DISCONNECT — audit disconnect action",
    '''    return jsonify({"ok": True, "client_id": client_id, "status": "disconnected", "removed": True})''',
    '''    _dc_user = get_current_user()
    audit(_dc_user["id"] if _dc_user else None,
          _dc_user["username"] if _dc_user else "anon",
          "AGENT_DISCONNECT", target=client_id, ip=request.remote_addr,
          details=f"client_id={client_id}")
    return jsonify({"ok": True, "client_id": client_id, "status": "disconnected", "removed": True})'''
))

# ─────────────────────────────────────────────────────────────
# 25. Deep web audit /web-deep — enhance audit with risk rating
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "WEB-DEEP route — audit result with risk rating",
    '''    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "WEB_DEEP_AUDIT", target=base_url,
          ip=request.remote_addr, details=f"profile={profile}")''',
    '''    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "WEB_DEEP_AUDIT", target=base_url,
          ip=request.remote_addr,
          details=f"profile={profile};url={raw_url[:80]}")'''
))

PATCHES.append((
    "WEB-DEEP route — audit result",
    '''    return jsonify(response)


# ── Auto-install helper ────────────────────────────────────────────────────────''',
    '''    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "WEB_DEEP_RESULT", target=base_url,
          ip=request.remote_addr,
          details=(f"profile={profile};"
                   f"risk={response['risk_rating']};"
                   f"score={response['vulnerability_score']};"
                   f"findings={response['summary'].get('total_findings',0)}"))
    return jsonify(response)


# ── Auto-install helper ────────────────────────────────────────────────────────'''
))

# ─────────────────────────────────────────────────────────────
# 26. SET session new — already audited, enhance with IP
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "SET SESSION kill — audit kill action",
    '''    _kill_set_session(sid)
    audit(u["id"], u["username"], "SET_SESSION_KILL",
          ip=request.remote_addr, details=f"sid={sid}")
    return jsonify({"ok": True})''',
    '''    _kill_set_session(sid)
    audit(u["id"], u["username"], "SET_SESSION_KILL",
          target="set_terminal", ip=request.remote_addr,
          details=f"sid={sid}")
    return jsonify({"ok": True})'''
))

# ─────────────────────────────────────────────────────────────
# 27. /history endpoint — audit access
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "HISTORY route — audit history access",
    '''@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    return jsonify(get_history(int(request.args.get("limit", 20)), user_id=uid))''',
    '''@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    limit = int(request.args.get("limit", 20))
    audit(uid, user["username"] if user else "anon",
          "HISTORY_ACCESS", target="scan_history", ip=request.remote_addr,
          details=f"limit={limit}")
    return jsonify(get_history(limit, user_id=uid))'''
))

# ─────────────────────────────────────────────────────────────
# 28. /scan/<id> — audit individual scan retrieval
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "GET SCAN BY ID route — audit retrieval",
    '''@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    d = get_scan_by_id(sid, user_id=None if role == "admin" else uid)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)''',
    '''@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    audit(uid, user["username"] if user else "anon",
          "SCAN_VIEW", target=str(sid), ip=request.remote_addr,
          details=f"scan_id={sid};role={role}")
    d = get_scan_by_id(sid, user_id=None if role == "admin" else uid)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)'''
))

# ─────────────────────────────────────────────────────────────
# 29. Upload job result — audit agent upload
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "AGENT UPLOAD — audit result upload",
    '''    return jsonify({"ok": True})


@app.route("/api/job-status/<int:job_id>", methods=["GET"])''',
    '''    audit(None, f"agent:{client_id}", "LYNIS_JOB_UPLOAD",
          target=str(job_id), ip=request.remote_addr,
          details=(f"job_id={job_id};status={status};"
                   f"hardening_index={hardening_index};"
                   f"warnings={len(warnings)};suggestions={len(suggestions)}"))
    return jsonify({"ok": True})


@app.route("/api/job-status/<int:job_id>", methods=["GET"])'''
))

# ─────────────────────────────────────────────────────────────
# 30. /api/server-stats — audit admin stats access
# ─────────────────────────────────────────────────────────────
PATCHES.append((
    "SERVER-STATS route — audit admin stats access",
    '''@app.route("/api/server-stats")
def server_stats():
    """Return live server resource usage — admin only."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    import time as _time''',
    '''@app.route("/api/server-stats")
def server_stats():
    """Return live server resource usage — admin only."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    audit(u["id"], u["username"], "SERVER_STATS_ACCESS",
          target="server", ip=request.remote_addr)
    import time as _time'''
))


# ══════════════════════════════════════════════════════════════
# ADDITIONAL: Inject audit helper at module level for routes
# that may not have get_current_user imported in scope
# ══════════════════════════════════════════════════════════════

# Ensure audit is always imported at the top of each route
# (already imported via `from auth import ... audit`)
# This is fine since audit is already in scope globally.


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║  VulnScan Pro — Comprehensive Audit Logging Patch       ║" + X)
    print(B + C + "║  Every tool use & user action → audit_log table         ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET):
        fail(f"Must be run from project root — {TARGET} not found")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    info(f"Target:       {TARGET}")
    info(f"Patches:      {len(PATCHES)}")
    print()

    src = read_file(TARGET)
    original_len = len(src)

    hdr(f"Applying {len(PATCHES)} audit patches")
    for label, old, new in PATCHES:
        src = apply_patch(src, label, old, new)

    # ── Write & verify ─────────────────────────────────────────
    hdr("Writing & Verifying")
    bak = backup(TARGET)
    info(f"Backup: {bak}")
    write_file(TARGET, src)
    info(f"Written: {TARGET} ({len(src) - original_len:+d} bytes)")

    passed, err = syntax_check(TARGET)
    if passed:
        ok(f"{TARGET} — syntax OK")
    else:
        fail(f"SYNTAX ERROR:\n{err}")
        warn(f"Restore with: cp {bak} {TARGET}")
        sys.exit(1)

    # ── Summary ────────────────────────────────────────────────
    print()
    print(B + C + "══════════════════════════════════════════════════════════" + X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if fc else D)}{fc}{X}"
    )
    print()

    if fc == 0:
        print(f"  {G}Audit events now logged for:{X}")
        events = [
            "Network scan (open ports, CVEs, profile)",
            "Subdomain enumeration (found count)",
            "Directory busting (found count)",
            "HTTP brute force (attempts, found)",
            "SSH brute force (attempts, found)",
            "Social tools / C2 / exploit tools (exit code, duration)",
            "Network discovery (host count)",
            "Nikto web scanner (finding count)",
            "WPScan WordPress scanner",
            "Lynis system audit (hardening index, warnings)",
            "Legion auto-recon (ports, issues)",
            "theHarvester OSINT (email/host counts)",
            "DNSRecon (record count, method)",
            "PDF report generation",
            "Tool auto-install attempts & results",
            "CLI console commands & exit codes",
            "UI theme changes",
            "Wordlist API access",
            "Lynis agent register/disconnect",
            "Lynis job create/cancel/delete/upload/download",
            "Deep web audit + risk rating",
            "SET interactive session kill",
            "Scan history access",
            "Individual scan retrieval",
            "Server stats access (admin)",
        ]
        for e in events:
            print(f"    {G}✓{X}  {e}")
        print()
        print(f"  {Y}Restart server to activate:{X}")
        print(f"    pkill -f api_server.py && python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
        print()
        print(f"  {C}View audit log in Admin Console → Audit Log tab{X}")
        print(f"  {C}Or query Supabase: SELECT * FROM audit_log ORDER BY id DESC;{X}")
    else:
        print(f"  {Y}{fc} patch(es) failed. The file has been saved — test carefully.{X}")
        print(f"  {Y}Restore backup: cp {bak} {TARGET}{X}")

    print()


if __name__ == "__main__":
    main()
