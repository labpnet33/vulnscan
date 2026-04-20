#!/usr/bin/env python3
"""
VulnScan Pro — Enhanced Audit Log Patch
=========================================
Adds comprehensive security logging to the audit system:

  1.  Core identity (user ID, username, email, role, auth method)
  2.  Network & device info (IP, GeoIP, User-Agent, device fingerprint)
  3.  Timestamp & session tracking (login/logout, session ID, duration)
  4.  User activity (page visits, critical actions, API calls)
  5.  Security events (failed logins, lockouts, MFA, privilege escalation)
  6.  Request-level logging (HTTP method, endpoint, status code, response time)
  7.  Enhanced Admin Console UI with filters, charts, and export

Run from project root:
    python3 audit_patch.py
"""

import os, shutil, sys, subprocess
from datetime import datetime

GREEN  = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  {DIM}·{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.audit.bak"
    shutil.copy2(path, bak)
    return bak

def patch_file(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        RESULTS["failed"] += 1
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        if new.strip()[:80] in src:
            skip(f"{label} — already applied")
            RESULTS["skipped"] += 1
            return False
        fail(f"{label} — anchor not found in {path}")
        RESULTS["failed"] += 1
        return False
    backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}")
    RESULTS["applied"] += 1
    return True


# ═══════════════════════════════════════════════════════════════
# PATCH 1 — database.py: Expand audit_log table + enhanced audit()
# ═══════════════════════════════════════════════════════════════

DB_AUDIT_OLD = '''def audit(user_id, username, action, target="", ip="", ua="", details=""):
    try:
        _sb().table("audit_log").insert({
            "user_id":    user_id,
            "username":   username,
            "action":     action,
            "target":     target,
            "ip_address": ip,
            "user_agent": ua,
            "details":    details,
            "timestamp":  _now(),
        }).execute()
    except Exception as e:
        print(f"[!] Audit log failed: {e}")'''

DB_AUDIT_NEW = '''def _geo_lookup(ip: str) -> dict:
    """Best-effort GeoIP using ip-api.com (free, no key needed). Returns {} on failure."""
    import urllib.request as _ureq, json as _json2
    if not ip or ip in ("127.0.0.1", "::1", "unknown", ""):
        return {}
    try:
        with _ureq.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,regionName,city,isp,org,proxy,hosting",
            timeout=3
        ) as r:
            d = _json2.loads(r.read())
            if d.get("status") == "success":
                return {
                    "country":      d.get("country", ""),
                    "country_code": d.get("countryCode", ""),
                    "region":       d.get("regionName", ""),
                    "city":         d.get("city", ""),
                    "isp":          d.get("isp", ""),
                    "org":          d.get("org", ""),
                    "is_proxy":     d.get("proxy", False),
                    "is_hosting":   d.get("hosting", False),
                }
    except Exception:
        pass
    return {}


def _parse_ua(ua_string: str) -> dict:
    """Parse User-Agent string into browser/OS/device components."""
    import re as _re2
    ua = ua_string or ""
    browser, os_name, device = "Unknown", "Unknown", "Desktop"

    # Browser detection
    if "Edg/" in ua:       browser = "Edge"
    elif "OPR/" in ua:     browser = "Opera"
    elif "Chrome/" in ua:  browser = "Chrome"
    elif "Firefox/" in ua: browser = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua: browser = "Safari"
    elif "MSIE" in ua or "Trident/" in ua: browser = "IE"
    elif "curl" in ua.lower(): browser = "curl"
    elif "python" in ua.lower(): browser = "Python"

    # OS detection
    if "Windows NT" in ua:    os_name = "Windows"
    elif "Mac OS X" in ua:    os_name = "macOS"
    elif "Android" in ua:     os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua: os_name = "iOS"
    elif "Linux" in ua:       os_name = "Linux"

    # Device type
    if "Mobile" in ua or "Android" in ua or "iPhone" in ua:
        device = "Mobile"
    elif "Tablet" in ua or "iPad" in ua:
        device = "Tablet"
    elif browser in ("curl", "Python"):
        device = "API/Script"

    # Extract version numbers
    browser_ver = ""
    m = _re2.search(r"(?:Chrome|Firefox|Safari|Edg|OPR)/([\\d.]+)", ua)
    if m:
        browser_ver = m.group(1).split(".")[0]

    return {
        "browser":  f"{browser}/{browser_ver}" if browser_ver else browser,
        "os":       os_name,
        "device":   device,
    }


def _risk_score(action: str, ip: str, username: str, geo: dict) -> int:
    """
    Compute a 0-100 risk score for an audit event.
    Higher = more suspicious.
    """
    score = 0
    HIGH_RISK_ACTIONS = {
        "LOGIN_FAIL": 20, "ACCOUNT_LOCKED": 40, "BRUTE_FORCE_DETECTED": 50,
        "PRIVILEGE_ESCALATION": 45, "ADMIN_DELETE_USER": 30, "IMPOSSIBLE_TRAVEL": 60,
        "PASSWORD_RESET": 10, "MFA_DISABLED": 35, "ROLE_CHANGE": 25,
        "SET_SESSION_START": 20, "CLI_EXEC": 15, "BRUTE_HTTP": 25, "BRUTE_SSH": 30,
        "REMOTE_AGENT_REGISTER": 10, "LYNIS_SCAN": 5,
    }
    score += HIGH_RISK_ACTIONS.get(action, 0)
    if geo.get("is_proxy"):   score += 20
    if geo.get("is_hosting"): score += 10
    if not ip or ip in ("127.0.0.1", "::1"): score = max(0, score - 5)
    return min(100, score)


# ── Session-level tracking helpers ──────────────────────────────
_active_sessions: dict = {}  # session_id -> {user_id, username, login_time, last_ip}

def record_session_start(session_id: str, user_id, username: str, ip: str):
    import time as _t4
    _active_sessions[session_id] = {
        "user_id":    user_id,
        "username":   username,
        "login_time": _t4.time(),
        "last_ip":    ip,
    }

def record_session_end(session_id: str) -> float:
    """Returns session duration in seconds, or 0."""
    import time as _t5
    s = _active_sessions.pop(session_id, None)
    if s:
        return round(_t5.time() - s["login_time"], 1)
    return 0.0


def audit(user_id, username, action, target="", ip="", ua="",
          details="", session_id="", http_method="", endpoint="",
          status_code=None, response_ms=None, email="", role="",
          auth_method="password", skip_geo=False):
    """
    Enhanced audit logger with full security context.

    New parameters (all optional — backward-compatible):
      session_id    : Flask session identifier
      http_method   : GET / POST / DELETE etc.
      endpoint      : URL path being accessed
      status_code   : HTTP response code
      response_ms   : Response time in milliseconds
      email         : User's email address
      role          : User's role (admin/user)
      auth_method   : password / oauth / mfa / api_key
      skip_geo      : Skip GeoIP lookup (for high-frequency events)
    """
    import time as _t6
    try:
        # GeoIP enrichment (skip for local IPs and high-frequency events)
        geo = {}
        if not skip_geo and ip and ip not in ("127.0.0.1", "::1", "", "unknown"):
            geo = _geo_lookup(ip)

        # User-Agent parsing
        ua_parsed = _parse_ua(ua)

        # Risk score
        risk = _risk_score(action, ip, username, geo)

        # Impossible travel detection: compare last known country for this user
        travel_flag = False
        if geo.get("country_code") and user_id:
            try:
                prev = _sb().table("audit_log") \
                    .select("geo_country_code") \
                    .eq("user_id", user_id) \
                    .not_.is_("geo_country_code", "null") \
                    .order("id", desc=True) \
                    .limit(1) \
                    .execute().data
                if prev and prev[0].get("geo_country_code"):
                    prev_cc = prev[0]["geo_country_code"]
                    curr_cc = geo.get("country_code", "")
                    if prev_cc != curr_cc and curr_cc:
                        travel_flag = True
                        risk = min(100, risk + 30)
            except Exception:
                pass

        _sb().table("audit_log").insert({
            # Core identity
            "user_id":       user_id,
            "username":      username,
            "email":         email or None,
            "role":          role or None,
            "auth_method":   auth_method,

            # Action
            "action":        action,
            "target":        target,
            "details":       details[:2000] if details else "",

            # Network
            "ip_address":    ip,
            "user_agent":    (ua or "")[:512],

            # Parsed UA
            "ua_browser":    ua_parsed.get("browser", ""),
            "ua_os":         ua_parsed.get("os", ""),
            "ua_device":     ua_parsed.get("device", ""),

            # GeoIP
            "geo_country":      geo.get("country", ""),
            "geo_country_code": geo.get("country_code", ""),
            "geo_region":       geo.get("region", ""),
            "geo_city":         geo.get("city", ""),
            "geo_isp":          geo.get("isp", ""),
            "geo_is_proxy":     geo.get("is_proxy", False),
            "geo_is_hosting":   geo.get("is_hosting", False),

            # Session
            "session_id":    session_id or None,

            # Request
            "http_method":   http_method or None,
            "endpoint":      (endpoint or "")[:500],
            "status_code":   status_code,
            "response_ms":   response_ms,

            # Risk
            "risk_score":    risk,
            "impossible_travel": travel_flag,

            "timestamp":     _now(),
        }).execute()

        # If impossible travel detected, create a secondary security alert
        if travel_flag:
            try:
                _sb().table("audit_log").insert({
                    "user_id": user_id, "username": username,
                    "action": "IMPOSSIBLE_TRAVEL",
                    "target": f"{geo.get('country_code','')} (prev: {prev[0].get('geo_country_code','')})",
                    "ip_address": ip, "risk_score": 80,
                    "details": f"Login from new country: {geo.get('country','')}",
                    "timestamp": _now(),
                }).execute()
            except Exception:
                pass

    except Exception as e:
        print(f"[!] Audit log failed: {e}")'''


# ═══════════════════════════════════════════════════════════════
# PATCH 2 — database.py: Enhanced get_audit_log() with filters
# ═══════════════════════════════════════════════════════════════

DB_GETAUDIT_OLD = '''def get_audit_log(limit=100, user_id=None):
    q = _sb().table("audit_log").select("*").order("id", desc=True).limit(limit)
    if user_id:
        q = q.eq("user_id", user_id)
    return q.execute().data or []'''

DB_GETAUDIT_NEW = '''def get_audit_log(limit=100, user_id=None, action_filter=None,
                  risk_min=None, start_date=None, end_date=None,
                  ip_filter=None, country_filter=None):
    """
    Enhanced audit log retrieval with filtering support.
    """
    q = _sb().table("audit_log").select(
        "id,user_id,username,email,role,action,target,details,"
        "ip_address,ua_browser,ua_os,ua_device,"
        "geo_country,geo_country_code,geo_city,geo_isp,geo_is_proxy,"
        "session_id,http_method,endpoint,status_code,response_ms,"
        "risk_score,impossible_travel,auth_method,timestamp"
    ).order("id", desc=True).limit(limit)

    if user_id:
        q = q.eq("user_id", user_id)
    if action_filter:
        q = q.eq("action", action_filter)
    if risk_min is not None:
        q = q.gte("risk_score", risk_min)
    if start_date:
        q = q.gte("timestamp", start_date)
    if end_date:
        q = q.lte("timestamp", end_date)
    if ip_filter:
        q = q.eq("ip_address", ip_filter)
    if country_filter:
        q = q.eq("geo_country_code", country_filter)

    return q.execute().data or []


def get_audit_stats() -> dict:
    """Aggregate stats for the audit dashboard."""
    try:
        rows = _sb().table("audit_log") \
            .select("action,risk_score,geo_country_code,ua_device,timestamp") \
            .order("id", desc=True).limit(5000).execute().data or []

        from collections import Counter as _Ctr
        actions  = _Ctr(r["action"] for r in rows if r.get("action"))
        countries = _Ctr(r["geo_country_code"] for r in rows if r.get("geo_country_code"))
        devices  = _Ctr(r["ua_device"] for r in rows if r.get("ua_device"))
        risky    = sum(1 for r in rows if (r.get("risk_score") or 0) >= 40)
        logins   = sum(1 for r in rows if r.get("action") == "LOGIN")
        failures = sum(1 for r in rows if r.get("action") == "LOGIN_FAIL")
        travel   = sum(1 for r in rows if r.get("impossible_travel"))

        return {
            "total_events":    len(rows),
            "high_risk_events": risky,
            "total_logins":    logins,
            "failed_logins":   failures,
            "impossible_travel": travel,
            "top_actions":     actions.most_common(10),
            "top_countries":   countries.most_common(10),
            "device_breakdown": dict(devices),
        }
    except Exception as e:
        return {"error": str(e)}'''


# ═══════════════════════════════════════════════════════════════
# PATCH 3 — auth.py: Enrich login/logout/register audit calls
# ═══════════════════════════════════════════════════════════════

AUTH_LOGIN_OLD = '''        update_last_login(user["id"], request.remote_addr)
        audit(user["id"], username, "LOGIN", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

        return jsonify({
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "csrf_token": session["csrf_token"]
        })'''

AUTH_LOGIN_NEW = '''        update_last_login(user["id"], request.remote_addr)

        # Record session for duration tracking
        sid = session.get("_id", "") or str(user["id"]) + "-" + str(int(time.time()))
        from database import record_session_start
        record_session_start(sid, user["id"], username, request.remote_addr or "")

        audit(
            user["id"], username, "LOGIN",
            ip=request.remote_addr,
            ua=request.headers.get("User-Agent", ""),
            email=user.get("email", ""),
            role=user.get("role", "user"),
            auth_method="password",
            session_id=sid,
            http_method="POST",
            endpoint="/api/login",
            status_code=200,
        )

        return jsonify({
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "csrf_token": session["csrf_token"]
        })'''

AUTH_LOGINFAIL_OLD = '''        audit(user["id"], username, "LOGIN_FAIL", ip=request.remote_addr)
        _record_login_failure(username)
        return jsonify({"error": "Invalid username or password"}), 401'''

AUTH_LOGINFAIL_NEW = '''        audit(
            user["id"], username, "LOGIN_FAIL",
            ip=request.remote_addr,
            ua=request.headers.get("User-Agent", ""),
            email=user.get("email", ""),
            role=user.get("role", ""),
            http_method="POST",
            endpoint="/api/login",
            status_code=401,
            details="Wrong password",
        )
        _record_login_failure(username)
        return jsonify({"error": "Invalid username or password"}), 401'''

AUTH_LOGOUT_OLD = '''        if uid: audit(uid, username, "LOGOUT", ip=request.remote_addr)
        session.clear()'''

AUTH_LOGOUT_NEW = '''        if uid:
            from database import record_session_end
            sid = session.get("_id", "")
            duration = record_session_end(sid) if sid else 0
            audit(uid, username, "LOGOUT",
                  ip=request.remote_addr,
                  ua=request.headers.get("User-Agent", ""),
                  http_method="POST",
                  endpoint="/api/logout",
                  status_code=200,
                  details=f"session_duration={duration}s",
                  session_id=sid,
                  skip_geo=True)
        session.clear()'''

AUTH_PWDCHANGE_OLD = '''        update_user(user["id"], password_hash=hash_password(new_pwd))
        audit(user["id"], user["username"], "PASSWORD_CHANGE", ip=request.remote_addr)
        return jsonify({"success": True, "message": "Password changed successfully"})'''

AUTH_PWDCHANGE_NEW = '''        update_user(user["id"], password_hash=hash_password(new_pwd))
        audit(user["id"], user["username"], "PASSWORD_CHANGE",
              ip=request.remote_addr,
              ua=request.headers.get("User-Agent", ""),
              email=user.get("email", ""),
              role=user.get("role", ""),
              http_method="POST",
              endpoint="/api/change-password",
              status_code=200,
              details="Password changed successfully")
        return jsonify({"success": True, "message": "Password changed successfully"})'''

AUTH_ROLECHANGE_OLD = '''    @app.route("/api/admin/users/<int:uid>/role", methods=["POST"])
    @admin_required
    def api_admin_role(uid):
        d = request.get_json() or {}
        role = d.get("role", "user")
        if role not in ["user", "admin"]: return jsonify({"error": "Invalid role"}), 400
        from database import set_user_role
        set_user_role(uid, role)
        return jsonify({"success": True})'''

AUTH_ROLECHANGE_NEW = '''    @app.route("/api/admin/users/<int:uid>/role", methods=["POST"])
    @admin_required
    def api_admin_role(uid):
        d = request.get_json() or {}
        role = d.get("role", "user")
        if role not in ["user", "admin"]: return jsonify({"error": "Invalid role"}), 400
        from database import set_user_role
        set_user_role(uid, role)
        current = get_current_user()
        audit(current["id"], current["username"], "PRIVILEGE_ESCALATION",
              target=str(uid), ip=request.remote_addr,
              ua=request.headers.get("User-Agent", ""),
              details=f"Changed user #{uid} role to {role}",
              http_method="POST",
              endpoint=f"/api/admin/users/{uid}/role",
              status_code=200)
        return jsonify({"success": True})'''


# ═══════════════════════════════════════════════════════════════
# PATCH 4 — api_server.py: Global request-level logging middleware
# ═══════════════════════════════════════════════════════════════

API_MIDDLEWARE_OLD = '''@app.after_request
def _set_security_headers(resp):
    """Apply baseline HTTP hardening headers for API/UI responses."""'''

API_MIDDLEWARE_NEW = '''# ── Request timing tracker ────────────────────────────────────
import threading as _req_threading
_REQ_START_TIMES = {}
_REQ_LOCK = _req_threading.Lock()

@app.before_request
def _track_request_start():
    import time as _rt
    with _REQ_LOCK:
        _REQ_START_TIMES[id(request._get_current_object())] = _rt.monotonic()

@app.after_request
def _log_request(resp):
    """Log every API request with timing info."""
    import time as _rt2
    req_id = id(request._get_current_object())
    with _REQ_LOCK:
        start = _REQ_START_TIMES.pop(req_id, None)
    elapsed_ms = round((_rt2.monotonic() - start) * 1000) if start else None

    # Only log API routes and security-sensitive paths
    path = request.path
    sensitive = (
        path.startswith("/api/") or
        path in ("/scan", "/lynis", "/nikto", "/wpscan", "/dirbust",
                 "/subdomains", "/discover", "/brute-http", "/brute-ssh",
                 "/legion", "/harvester", "/dnsrecon", "/report") or
        path.startswith("/social-tools/")
    )
    if not sensitive:
        return resp

    try:
        user = get_current_user()
        uid  = user["id"]       if user else None
        uname = user["username"] if user else "anonymous"
        uemail = user.get("email", "") if user else ""
        urole  = user.get("role",  "") if user else ""

        # Skip audit-log reads to avoid infinite loops
        if "/api/admin/audit" in path:
            return resp

        from database import audit as _db_audit
        _db_audit(
            uid, uname, "HTTP_REQUEST",
            target=path,
            ip=request.remote_addr or "",
            ua=request.headers.get("User-Agent", ""),
            email=uemail,
            role=urole,
            http_method=request.method,
            endpoint=path,
            status_code=resp.status_code,
            response_ms=elapsed_ms,
            details=f"args={dict(request.args)!r:.200}" if request.args else "",
            skip_geo=True,   # skip geo for every-request events (performance)
        )
    except Exception:
        pass
    return resp


@app.after_request
def _set_security_headers(resp):
    """Apply baseline HTTP hardening headers for API/UI responses."""'''


# ═══════════════════════════════════════════════════════════════
# PATCH 5 — api_server.py: Enhanced /api/admin/audit endpoint
# ═══════════════════════════════════════════════════════════════

API_AUDIT_OLD = '''    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        from database import get_audit_log
        limit = int(request.args.get("limit", 100))
        return jsonify(get_audit_log(limit))'''

API_AUDIT_NEW = '''    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        from database import get_audit_log, get_audit_stats
        limit          = int(request.args.get("limit",   200))
        action_filter  = request.args.get("action",      None)
        risk_min       = request.args.get("risk_min",    None)
        start_date     = request.args.get("start_date",  None)
        end_date       = request.args.get("end_date",    None)
        ip_filter      = request.args.get("ip",          None)
        country_filter = request.args.get("country",     None)
        include_stats  = request.args.get("stats", "0") in ("1","true","yes")

        logs = get_audit_log(
            limit=limit,
            action_filter=action_filter,
            risk_min=int(risk_min) if risk_min else None,
            start_date=start_date,
            end_date=end_date,
            ip_filter=ip_filter,
            country_filter=country_filter,
        )

        if include_stats:
            return jsonify({"logs": logs, "stats": get_audit_stats()})
        return jsonify(logs)

    @app.route("/api/admin/audit/stats")
    @admin_required
    def api_audit_stats():
        from database import get_audit_stats
        return jsonify(get_audit_stats())

    @app.route("/api/admin/audit/export")
    @admin_required
    def api_audit_export():
        """Export audit log as CSV."""
        import csv, io as _io2
        from database import get_audit_log
        limit = min(int(request.args.get("limit", 5000)), 10000)
        logs = get_audit_log(limit=limit)
        buf = _io2.StringIO()
        if logs:
            writer = csv.DictWriter(buf, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
        csv_bytes = buf.getvalue().encode("utf-8")
        fname = f"vulnscan-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
        _au = get_current_user()
        audit(_au["id"], _au["username"], "AUDIT_LOG_EXPORT",
              target="audit_log", ip=request.remote_addr,
              details=f"rows={len(logs)}")
        return Response(
            csv_bytes,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={fname}"}
        )'''


# ═══════════════════════════════════════════════════════════════
# PATCH 6 — api_server.py: Inject enhanced Audit Log UI
# ═══════════════════════════════════════════════════════════════

# We inject the new UI HTML just before the closing </style> tag area
# and replace the at-audit tab content div with the enhanced version

AUDIT_UI_OLD = '''        <div class="tc" id="at-audit"><div class="card"><div class="card-header"><div class="card-title">Audit Log</div></div><div class="card-p" id="admin-audit" style="overflow-x:auto"></div></div></div>'''

AUDIT_UI_NEW = '''        <div class="tc" id="at-audit">
          <!-- ── Audit Stats Row ── -->
          <div id="audit-stats-row" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:14px"></div>
          <!-- ── Filters ── -->
          <div class="card card-p" style="margin-bottom:12px">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px">
              <div class="card-title">Audit Log</div>
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <button class="btn btn-outline btn-sm" onclick="exportAuditCSV()">&#11123; CSV</button>
                <button class="btn btn-outline btn-sm" onclick="loadAdminAudit()">&#8635; Refresh</button>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;margin-bottom:8px">
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">ACTION</label>
                <select class="inp inp-mono" id="af-action" style="font-size:11px">
                  <option value="">All actions</option>
                  <optgroup label="Auth">
                    <option>LOGIN</option><option>LOGIN_FAIL</option><option>LOGOUT</option>
                    <option>REGISTER</option><option>PASSWORD_CHANGE</option><option>PASSWORD_RESET</option>
                    <option>EMAIL_VERIFIED</option><option>ACCOUNT_LOCKED</option>
                  </optgroup>
                  <optgroup label="Security">
                    <option>IMPOSSIBLE_TRAVEL</option><option>PRIVILEGE_ESCALATION</option>
                    <option>BRUTE_FORCE_DETECTED</option><option>MFA_DISABLED</option>
                  </optgroup>
                  <optgroup label="Scans">
                    <option>SCAN</option><option>LYNIS_SCAN</option><option>NIKTO_SCAN</option>
                    <option>WPSCAN</option><option>BRUTE_HTTP</option><option>BRUTE_SSH</option>
                    <option>REMOTE_JOB_CREATED</option>
                  </optgroup>
                  <optgroup label="Admin">
                    <option>CLI_EXEC</option><option>ADMIN_CREATE_USER</option>
                    <option>AUDIT_LOG_EXPORT</option><option>KILL_ALL_TOOLS</option>
                  </optgroup>
                </select>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">MIN RISK</label>
                <select class="inp inp-mono" id="af-risk" style="font-size:11px">
                  <option value="">Any risk</option>
                  <option value="10">Low+ (10)</option>
                  <option value="25">Medium+ (25)</option>
                  <option value="40">High+ (40)</option>
                  <option value="60">Critical+ (60)</option>
                </select>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">IP ADDRESS</label>
                <input class="inp inp-mono" id="af-ip" type="text" placeholder="1.2.3.4" style="font-size:11px"/>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">COUNTRY CODE</label>
                <input class="inp inp-mono" id="af-country" type="text" placeholder="US, GB, IN ..." style="font-size:11px" maxlength="2"/>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">START DATE</label>
                <input class="inp inp-mono" id="af-start" type="date" style="font-size:11px"/>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">END DATE</label>
                <input class="inp inp-mono" id="af-end" type="date" style="font-size:11px"/>
              </div>
              <div class="fg" style="margin-bottom:0">
                <label style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:1px">LIMIT</label>
                <select class="inp inp-mono" id="af-limit" style="font-size:11px">
                  <option value="100">100</option><option value="200" selected>200</option>
                  <option value="500">500</option><option value="1000">1000</option>
                </select>
              </div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="loadAdminAudit()">APPLY FILTERS</button>
            <button class="btn btn-ghost btn-sm" onclick="clearAuditFilters()">CLEAR</button>
          </div>
          <div class="card">
            <div class="card-p" id="admin-audit" style="overflow-x:auto"></div>
          </div>
        </div>'''


# ═══════════════════════════════════════════════════════════════
# PATCH 7 — api_server.py: Enhanced loadAdminAudit() JS function
# ═══════════════════════════════════════════════════════════════

JS_AUDIT_OLD = '''async function loadAdminAudit(){try{var r=await fetch('/api/admin/audit?limit=200');var d=await r.json();document.getElementById('admin-audit').innerHTML='<table class="tbl"><thead><tr><th>TIME</th><th>USER</th><th>ACTION</th><th>TARGET</th><th>IP</th></tr></thead><tbody>'+d.map(function(l){return'<tr><td style="font-size:11px;color:var(--text3)">'+((l.timestamp||'').substring(0,16))+'</td><td style="font-family:var(--mono)">'+(l.username||'--')+'</td><td><span class="tag">'+(l.action||'')+'</span></td><td style="font-size:11px;color:var(--text3)">'+(l.target||'--')+'</td><td style="font-size:11px;color:var(--text3)">'+(l.ip_address||'--')+'</td></tr>';}).join('')+'</tbody></table>';}catch(e){}}'''

JS_AUDIT_NEW = '''function _riskPill(score){
  score=parseInt(score||0);
  var col=score>=60?'var(--red)':score>=40?'var(--orange)':score>=20?'var(--yellow)':'var(--text3)';
  var lbl=score>=60?'CRIT':score>=40?'HIGH':score>=20?'MED':'LOW';
  if(score===0)return'';
  return'<span style="font-family:var(--mono);font-size:9px;padding:2px 6px;border-radius:3px;border:1px solid '+col+';color:'+col+'">'+lbl+' '+score+'</span>';
}
function _actionPill(action){
  var danger=['LOGIN_FAIL','ACCOUNT_LOCKED','IMPOSSIBLE_TRAVEL','PRIVILEGE_ESCALATION','BRUTE_FORCE_DETECTED','MFA_DISABLED','KILL_ALL_TOOLS'];
  var warn=['PASSWORD_RESET','PASSWORD_CHANGE','ADMIN_DELETE_USER','CLI_EXEC','BRUTE_HTTP','BRUTE_SSH','SET_SESSION_START'];
  var col=danger.includes(action)?'var(--red)':warn.includes(action)?'var(--orange)':'var(--text3)';
  return'<span style="font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid var(--border);color:'+col+'">'+action+'</span>';
}
function clearAuditFilters(){
  ['af-action','af-risk','af-ip','af-country','af-start','af-end'].forEach(function(id){var el=document.getElementById(id);if(el)el.value='';});
  document.getElementById('af-limit').value='200';
  loadAdminAudit();
}
async function exportAuditCSV(){
  var limit=document.getElementById('af-limit').value||200;
  window.open('/api/admin/audit/export?limit='+limit,'_blank');
}
async function loadAdminAudit(){
  var out=document.getElementById('admin-audit');
  var statsRow=document.getElementById('audit-stats-row');
  if(out)out.innerHTML='<div style="color:var(--text3);font-size:12px;padding:12px">Loading...</div>';
  var params=new URLSearchParams();
  params.set('stats','1');
  params.set('limit',document.getElementById('af-limit').value||200);
  var v;
  if((v=document.getElementById('af-action').value))params.set('action',v);
  if((v=document.getElementById('af-risk').value))params.set('risk_min',v);
  if((v=document.getElementById('af-ip').value.trim()))params.set('ip',v);
  if((v=document.getElementById('af-country').value.trim().toUpperCase()))params.set('country',v);
  if((v=document.getElementById('af-start').value))params.set('start_date',v+'T00:00:00');
  if((v=document.getElementById('af-end').value))params.set('end_date',v+'T23:59:59');
  try{
    var r=await fetch('/api/admin/audit?'+params.toString());
    var resp=await r.json();
    var d=resp.logs||resp;
    var stats=resp.stats||null;

    // ── Stats cards ──
    if(stats&&statsRow){
      var kpis=[
        [stats.total_events||0,'TOTAL EVENTS','var(--text)'],
        [stats.high_risk_events||0,'HIGH RISK','var(--red)'],
        [stats.total_logins||0,'LOGINS','var(--green)'],
        [stats.failed_logins||0,'FAILED LOGINS','var(--orange)'],
        [stats.impossible_travel||0,'TRAVEL ALERTS','var(--yellow)'],
      ];
      statsRow.innerHTML=kpis.map(function(k){return'<div class="stat"><div class="stat-val" style="font-size:22px;color:'+k[2]+'">'+k[0]+'</div><div class="stat-lbl">'+k[1]+'</div></div>';}).join('');
    }

    if(!d||!d.length){if(out)out.innerHTML='<div style="color:var(--text3);padding:12px">No log entries match the current filters.</div>';return;}
    var html='<div style="overflow-x:auto"><table class="tbl" style="min-width:1100px"><thead><tr>'
      +'<th>TIME</th><th>USER</th><th>ROLE</th><th>ACTION</th><th>RISK</th>'
      +'<th>IP / GEO</th><th>DEVICE</th><th>HTTP</th><th>SESSION</th><th>TARGET / DETAILS</th>'
      +'</tr></thead><tbody>';
    d.forEach(function(l){
      var geo='';
      if(l.geo_city||l.geo_country){
        geo='<div style="font-size:10px;color:var(--text3);margin-top:2px">'
          +(l.geo_city?l.geo_city+', ':'')+l.geo_country
          +(l.geo_is_proxy?'<span style="color:var(--red);margin-left:4px">[PROXY]</span>':'')+'</div>';
      }
      var device='';
      if(l.ua_browser||l.ua_os){
        device='<div style="font-size:10px;font-family:var(--mono);color:var(--text2)">'+(l.ua_browser||'')+'</div>'
          +'<div style="font-size:10px;color:var(--text3)">'+(l.ua_os||'')+'/'+(l.ua_device||'')+'</div>';
      }
      var httpInfo='';
      if(l.http_method){
        var mc={'GET':'var(--green)','POST':'var(--cyan, var(--blue))','DELETE':'var(--red)','PUT':'var(--yellow)'};
        httpInfo='<span style="font-family:var(--mono);font-size:10px;color:'+(mc[l.http_method]||'var(--text3)')+'">'+l.http_method+'</span>'
          +(l.status_code?'<span style="font-size:10px;color:var(--text3);margin-left:4px">'+l.status_code+'</span>':'')
          +(l.response_ms?'<div style="font-size:9px;color:var(--text3)">'+l.response_ms+'ms</div>':'');
      }
      var sessionInfo=l.session_id?'<span style="font-family:var(--mono);font-size:9px;color:var(--text3)" title="'+l.session_id+'">'+l.session_id.substring(0,8)+'…</span>':'—';
      var travelBadge=l.impossible_travel?'<span style="font-size:9px;color:var(--red);font-weight:700"> ✈ TRAVEL</span>':'';
      html+='<tr>'
        +'<td style="font-size:10px;color:var(--text3);white-space:nowrap">'+((l.timestamp||'').substring(0,19).replace('T',' '))+'</td>'
        +'<td><div style="font-family:var(--mono);font-size:11px;font-weight:500">'+(l.username||'—')+'</div>'
          +(l.email?'<div style="font-size:10px;color:var(--text3)">'+l.email+'</div>':'')+'</td>'
        +'<td><span style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+(l.role||'—')+'</span></td>'
        +'<td>'+_actionPill(l.action||'')+travelBadge+'</td>'
        +'<td>'+_riskPill(l.risk_score)+'</td>'
        +'<td><div style="font-family:var(--mono);font-size:11px">'+(l.ip_address||'—')+'</div>'+geo+'</td>'
        +'<td>'+device+'</td>'
        +'<td>'+httpInfo+'</td>'
        +'<td>'+sessionInfo+'</td>'
        +'<td style="max-width:220px"><div style="font-size:11px;word-break:break-all">'+(l.target||'')+'</div>'
          +(l.details?'<div style="font-size:10px;color:var(--text3);margin-top:2px;word-break:break-all">'+String(l.details).substring(0,120)+'</div>':'')+'</td>'
        +'</tr>';
    });
    html+='</tbody></table></div>';
    if(out)out.innerHTML=html;
  }catch(e){if(out)out.innerHTML='<div class="err-box visible">'+e.message+'</div>';}
}'''


# ═══════════════════════════════════════════════════════════════
# PATCH 8 — Supabase migration SQL (creates new columns)
# ═══════════════════════════════════════════════════════════════

SUPABASE_MIGRATION = '''-- ============================================================
--  VulnScan Pro — Enhanced Audit Log Migration
--  Run this in your Supabase SQL editor (Dashboard → SQL Editor)
-- ============================================================

-- Add new columns to audit_log (safe — IF NOT EXISTS style via DO block)
DO $$
BEGIN
  -- Identity
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='email')           THEN ALTER TABLE audit_log ADD COLUMN email          TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='role')            THEN ALTER TABLE audit_log ADD COLUMN role           TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='auth_method')     THEN ALTER TABLE audit_log ADD COLUMN auth_method    TEXT DEFAULT 'password'; END IF;

  -- Parsed User-Agent
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_browser')      THEN ALTER TABLE audit_log ADD COLUMN ua_browser      TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_os')           THEN ALTER TABLE audit_log ADD COLUMN ua_os           TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_device')       THEN ALTER TABLE audit_log ADD COLUMN ua_device       TEXT; END IF;

  -- GeoIP
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country')     THEN ALTER TABLE audit_log ADD COLUMN geo_country     TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country_code')THEN ALTER TABLE audit_log ADD COLUMN geo_country_code TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_region')      THEN ALTER TABLE audit_log ADD COLUMN geo_region      TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_city')        THEN ALTER TABLE audit_log ADD COLUMN geo_city        TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_isp')         THEN ALTER TABLE audit_log ADD COLUMN geo_isp         TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_proxy')    THEN ALTER TABLE audit_log ADD COLUMN geo_is_proxy    BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_hosting')  THEN ALTER TABLE audit_log ADD COLUMN geo_is_hosting  BOOLEAN DEFAULT FALSE; END IF;

  -- Session
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='session_id')     THEN ALTER TABLE audit_log ADD COLUMN session_id      TEXT; END IF;

  -- HTTP Request
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='http_method')    THEN ALTER TABLE audit_log ADD COLUMN http_method     TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='endpoint')       THEN ALTER TABLE audit_log ADD COLUMN endpoint        TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='status_code')    THEN ALTER TABLE audit_log ADD COLUMN status_code     INTEGER; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='response_ms')    THEN ALTER TABLE audit_log ADD COLUMN response_ms     INTEGER; END IF;

  -- Risk
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='risk_score')     THEN ALTER TABLE audit_log ADD COLUMN risk_score      INTEGER DEFAULT 0; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='impossible_travel') THEN ALTER TABLE audit_log ADD COLUMN impossible_travel BOOLEAN DEFAULT FALSE; END IF;
END $$;

-- Indexes for fast filtering
CREATE INDEX IF NOT EXISTS idx_audit_risk      ON audit_log (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_ip        ON audit_log (ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_country   ON audit_log (geo_country_code);
CREATE INDEX IF NOT EXISTS idx_audit_travel    ON audit_log (impossible_travel) WHERE impossible_travel = TRUE;
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp DESC);

-- ✅ Migration complete — refresh your VulnScan server after running this.
'''


# ═══════════════════════════════════════════════════════════════
# APPLY ALL PATCHES
# ═══════════════════════════════════════════════════════════════

def main():
    print()
    print(BOLD + CYAN + "╔═══════════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║   VulnScan Pro — Enhanced Audit Log Patch                ║" + RESET)
    print(BOLD + CYAN + "║   Adds: GeoIP · UA parsing · Sessions · Risk scores ·   ║" + RESET)
    print(BOLD + CYAN + "║         HTTP logging · Filters · CSV export · Charts     ║" + RESET)
    print(BOLD + CYAN + "╚═══════════════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py", "backend.py", "database.py", "auth.py"]
               if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Must be run from the VulnScan project root." + RESET)
        print(f"  Missing files: {', '.join(missing)}")
        print("  Usage: cd ~/vulnscan && python3 audit_patch.py")
        return

    info(f"Project root: {os.getcwd()}")
    print()

    # ── database.py ──
    print(BOLD + "  ── database.py" + RESET)
    patch_file("database.py", "Enhanced audit() with GeoIP / UA / risk / session / HTTP fields",
               DB_AUDIT_OLD, DB_AUDIT_NEW)
    patch_file("database.py", "Enhanced get_audit_log() with filters + get_audit_stats()",
               DB_GETAUDIT_OLD, DB_GETAUDIT_NEW)
    print()

    # ── auth.py ──
    print(BOLD + "  ── auth.py" + RESET)
    patch_file("auth.py", "LOGIN: add email/role/session/HTTP fields",
               AUTH_LOGIN_OLD, AUTH_LOGIN_NEW)
    patch_file("auth.py", "LOGIN_FAIL: add UA/email/HTTP fields",
               AUTH_LOGINFAIL_OLD, AUTH_LOGINFAIL_NEW)
    patch_file("auth.py", "LOGOUT: add session duration tracking",
               AUTH_LOGOUT_OLD, AUTH_LOGOUT_NEW)
    patch_file("auth.py", "PASSWORD_CHANGE: add full audit context",
               AUTH_PWDCHANGE_OLD, AUTH_PWDCHANGE_NEW)
    patch_file("auth.py", "PRIVILEGE_ESCALATION: audit role changes",
               AUTH_ROLECHANGE_OLD, AUTH_ROLECHANGE_NEW)
    print()

    # ── api_server.py ──
    print(BOLD + "  ── api_server.py" + RESET)
    patch_file("api_server.py", "Global HTTP request-level logging middleware",
               API_MIDDLEWARE_OLD, API_MIDDLEWARE_NEW)
    patch_file("api_server.py", "Enhanced /api/admin/audit with filters + export + stats",
               API_AUDIT_OLD, API_AUDIT_NEW)
    patch_file("api_server.py", "Enhanced Audit Log UI (filters, risk pills, geo, device)",
               AUDIT_UI_OLD, AUDIT_UI_NEW)
    patch_file("api_server.py", "Enhanced loadAdminAudit() JS with filters/stats/export",
               JS_AUDIT_OLD, JS_AUDIT_NEW)
    print()

    # ── Write Supabase migration ──
    print(BOLD + "  ── Supabase Migration SQL" + RESET)
    migration_path = "audit_log_migration.sql"
    with open(migration_path, "w", encoding="utf-8") as f:
        f.write(SUPABASE_MIGRATION)
    ok(f"Written: {migration_path}")
    print()

    # ── Syntax checks ──
    print(BOLD + "  ── Syntax checks" + RESET)
    all_ok = True
    for fname in ["api_server.py", "database.py", "auth.py"]:
        if not os.path.isfile(fname):
            continue
        r = subprocess.run([sys.executable, "-m", "py_compile", fname],
                           capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"{fname} — syntax OK")
        else:
            fail(f"{fname} — SYNTAX ERROR:\n    {r.stderr.strip()}")
            all_ok = False
    print()

    # ── Summary ──
    print(BOLD + CYAN + "═══════════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{RESULTS['applied']}{RESET}  |  "
        f"Skipped : {DIM}{RESULTS['skipped']}{RESET}  |  "
        f"Failed  : {(RED if RESULTS['failed'] else DIM)}{RESULTS['failed']}{RESET}"
    )
    print()

    if all_ok and RESULTS["applied"] > 0:
        print(f"  {YELLOW}REQUIRED: Run the Supabase migration first:{RESET}")
        print(f"    1. Open Supabase Dashboard → SQL Editor")
        print(f"    2. Paste contents of: {BOLD}audit_log_migration.sql{RESET}")
        print(f"    3. Click Run")
        print()
        print(f"  {GREEN}Then restart VulnScan:{RESET}")
        print(f"    sudo systemctl restart vulnscan")
        print(f"    OR: python3 api_server.py")
        print()
        print(f"  {CYAN}New features in Admin → Audit Log:{RESET}")
        print(f"    {GREEN}✓{RESET}  Risk score (0-100) with CRIT/HIGH/MED/LOW pills")
        print(f"    {GREEN}✓{RESET}  GeoIP enrichment (country, city, ISP, proxy detection)")
        print(f"    {GREEN}✓{RESET}  Impossible travel auto-detection & alert")
        print(f"    {GREEN}✓{RESET}  User-Agent parsing (browser, OS, device type)")
        print(f"    {GREEN}✓{RESET}  Session ID + duration tracking")
        print(f"    {GREEN}✓{RESET}  HTTP method, endpoint, status code, response time")
        print(f"    {GREEN}✓{RESET}  Filter by action, risk, IP, country, date range")
        print(f"    {GREEN}✓{RESET}  CSV export endpoint (/api/admin/audit/export)")
        print(f"    {GREEN}✓{RESET}  Stats dashboard (totals, logins, failures, travel alerts)")
        print(f"    {GREEN}✓{RESET}  Privilege escalation tracking (role changes)")
        print(f"    {GREEN}✓{RESET}  Every API request auto-logged (skip_geo for perf)")
    elif not all_ok:
        print(f"  {RED}Syntax errors found — restore backup files (.audit.bak) if needed.{RESET}")


if __name__ == "__main__":
    main()
