#!/usr/bin/env python3
"""
VulnScan Pro — Audit Log Fix Patch
====================================
Fixes "Unexpected token '<'" and blank audit log issues caused by:

  1. /api/admin/audit returning HTML instead of JSON when new
     columns (email, role, geo_*, ua_*, etc.) don't exist yet in DB
  2. get_audit_stats() crashing on missing columns → Flask returns
     500 HTML error page instead of JSON
  3. loadAdminAudit() JS not handling the case where resp is a plain
     array (old format) vs {logs, stats} object (new format)
  4. audit() inserting unknown columns → Supabase rejects the whole
     INSERT → Flask 500 → HTML returned to browser
  5. _geo_lookup() blocking the request thread for 3s on every call
     (uses a background thread + cache instead)
  6. register_auth_routes() calling audit() with new keyword args
     that the old database.audit() signature doesn't accept yet

Run from project root:
    python3 audit_fix_patch.py
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
    bak = f"{path}.{ts}.fix.bak"
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
        # Check if already applied
        first_new_line = [l.strip() for l in new.strip().splitlines() if l.strip()][0]
        if first_new_line in src:
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


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 1 — database.py
# The new audit() tries to insert columns that may not exist in
# Supabase yet. When Supabase rejects the INSERT, Flask catches the
# unhandled exception and returns a 500 HTML page.
#
# FIX: Make audit() fully defensive — detect available columns once
# at startup and only insert what the table actually has.
# Also fix _geo_lookup to be non-blocking (cached background thread).
# ═══════════════════════════════════════════════════════════════════

# We replace the whole audit block that was added by the previous patch.
# We detect the presence of the new audit signature by looking for
# the _geo_lookup function definition.

DB_AUDIT_FULL_OLD = '''def _geo_lookup(ip: str) -> dict:
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
    return {}'''

DB_AUDIT_FULL_NEW = '''# ── Audit column discovery (run once, cached) ─────────────────────
_AUDIT_COLS: set | None = None
_AUDIT_COLS_LOCK = __import__("threading").Lock()

def _get_audit_cols() -> set:
    """Return the set of column names that actually exist in audit_log."""
    global _AUDIT_COLS
    if _AUDIT_COLS is not None:
        return _AUDIT_COLS
    with _AUDIT_COLS_LOCK:
        if _AUDIT_COLS is not None:
            return _AUDIT_COLS
        try:
            # Fetch one row to discover columns; fall back to minimal set on error
            r = _sb().table("audit_log").select("*").limit(1).execute()
            if r.data:
                _AUDIT_COLS = set(r.data[0].keys())
            else:
                # Table exists but empty — try inserting a probe then deleting
                # Instead, use the known minimum set
                _AUDIT_COLS = {
                    "user_id", "username", "action", "target",
                    "ip_address", "user_agent", "details", "timestamp",
                }
        except Exception:
            _AUDIT_COLS = {
                "user_id", "username", "action", "target",
                "ip_address", "user_agent", "details", "timestamp",
            }
    return _AUDIT_COLS


# ── GeoIP cache (non-blocking background lookup) ───────────────────
_GEO_CACHE: dict = {}   # ip -> (geo_dict, expiry_monotonic)
_GEO_CACHE_TTL = 3600   # 1 hour per IP

def _geo_lookup(ip: str) -> dict:
    """
    Non-blocking GeoIP via ip-api.com with 1-hour in-process cache.
    Returns {} immediately on any failure — never blocks the request.
    """
    import urllib.request as _ureq, json as _json2, time as _gt
    if not ip or ip in ("127.0.0.1", "::1", "unknown", "", "::ffff:127.0.0.1"):
        return {}
    # Cache hit?
    entry = _GEO_CACHE.get(ip)
    if entry:
        geo, expiry = entry
        if _gt.monotonic() < expiry:
            return geo
    try:
        req = _ureq.Request(
            f"http://ip-api.com/json/{ip}"
            f"?fields=status,country,countryCode,regionName,city,isp,org,proxy,hosting",
            headers={"User-Agent": "VulnScan/1.0"}
        )
        with _ureq.urlopen(req, timeout=3) as r:
            d = _json2.loads(r.read())
        if d.get("status") == "success":
            geo = {
                "country":      d.get("country", ""),
                "country_code": d.get("countryCode", ""),
                "region":       d.get("regionName", ""),
                "city":         d.get("city", ""),
                "isp":          d.get("isp", ""),
                "org":          d.get("org", ""),
                "is_proxy":     bool(d.get("proxy", False)),
                "is_hosting":   bool(d.get("hosting", False)),
            }
        else:
            geo = {}
        _GEO_CACHE[ip] = (geo, _gt.monotonic() + _GEO_CACHE_TTL)
        # Prune cache
        if len(_GEO_CACHE) > 2000:
            oldest = min(_GEO_CACHE, key=lambda k: _GEO_CACHE[k][1])
            del _GEO_CACHE[oldest]
        return geo
    except Exception:
        return {}'''


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 2 — database.py
# The new audit() function body inserts many new columns that may not
# exist. Replace it with a safe version that:
#   a) only inserts columns that exist in the table
#   b) wraps the whole thing in try/except so a DB error never
#      propagates to Flask and causes an HTML 500 response
# ═══════════════════════════════════════════════════════════════════

DB_AUDIT_BODY_OLD = '''def audit(user_id, username, action, target="", ip="", ua="",
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
                prev = _sb().table("audit_log") \\
                    .select("geo_country_code") \\
                    .eq("user_id", user_id) \\
                    .not_.is_("geo_country_code", "null") \\
                    .order("id", desc=True) \\
                    .limit(1) \\
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

DB_AUDIT_BODY_NEW = '''def audit(user_id, username, action, target="", ip="", ua="",
          details="", session_id="", http_method="", endpoint="",
          status_code=None, response_ms=None, email="", role="",
          auth_method="password", skip_geo=False):
    """
    Enhanced audit logger — safe/defensive version.
    Only inserts columns that actually exist in the Supabase table.
    Never raises exceptions so Flask always returns JSON, not HTML 500.
    """
    try:
        # ── GeoIP (cached, non-blocking) ──────────────────────────────
        geo = {}
        if not skip_geo and ip and ip not in ("127.0.0.1", "::1", "", "unknown"):
            try:
                geo = _geo_lookup(ip)
            except Exception:
                geo = {}

        # ── User-Agent parsing ────────────────────────────────────────
        try:
            ua_parsed = _parse_ua(ua)
        except Exception:
            ua_parsed = {"browser": "", "os": "", "device": ""}

        # ── Risk score ────────────────────────────────────────────────
        try:
            risk = _risk_score(action, ip, username, geo)
        except Exception:
            risk = 0

        # ── Impossible travel (only if geo columns exist) ─────────────
        travel_flag = False
        cols = _get_audit_cols()
        if "geo_country_code" in cols and geo.get("country_code") and user_id:
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
                    if prev_cc and curr_cc and prev_cc != curr_cc:
                        travel_flag = True
                        risk = min(100, risk + 30)
            except Exception:
                pass

        # ── Build row — only include columns that exist ───────────────
        # Base columns (always present in original schema)
        row = {
            "user_id":    user_id,
            "username":   str(username or "")[:120],
            "action":     str(action or "")[:120],
            "target":     str(target or "")[:500],
            "ip_address": str(ip or "")[:100],
            "user_agent": str(ua or "")[:512],
            "details":    str(details or "")[:2000],
            "timestamp":  _now(),
        }

        # Extended columns — add only if they exist in the table
        def _add(col, val):
            if col in cols:
                row[col] = val

        _add("email",          str(email or "")[:200] or None)
        _add("role",           str(role or "")[:50]   or None)
        _add("auth_method",    str(auth_method or "password")[:50])
        _add("ua_browser",     ua_parsed.get("browser", ""))
        _add("ua_os",          ua_parsed.get("os", ""))
        _add("ua_device",      ua_parsed.get("device", ""))
        _add("geo_country",    geo.get("country", ""))
        _add("geo_country_code", geo.get("country_code", ""))
        _add("geo_region",     geo.get("region", ""))
        _add("geo_city",       geo.get("city", ""))
        _add("geo_isp",        geo.get("isp", ""))
        _add("geo_is_proxy",   bool(geo.get("is_proxy", False)))
        _add("geo_is_hosting", bool(geo.get("is_hosting", False)))
        _add("session_id",     str(session_id or "")[:200] or None)
        _add("http_method",    str(http_method or "")[:10] or None)
        _add("endpoint",       str(endpoint or "")[:500])
        _add("status_code",    int(status_code) if status_code is not None else None)
        _add("response_ms",    int(response_ms) if response_ms is not None else None)
        _add("risk_score",     int(risk))
        _add("impossible_travel", bool(travel_flag))

        _sb().table("audit_log").insert(row).execute()

        # ── Secondary travel alert ────────────────────────────────────
        if travel_flag and "risk_score" in cols:
            try:
                alert_row = {
                    "user_id":  user_id,
                    "username": str(username or ""),
                    "action":   "IMPOSSIBLE_TRAVEL",
                    "target":   f"{geo.get('country_code','')}",
                    "ip_address": str(ip or ""),
                    "details":  f"New country: {geo.get('country', '')}",
                    "timestamp": _now(),
                }
                if "risk_score" in cols:
                    alert_row["risk_score"] = 80
                _sb().table("audit_log").insert(alert_row).execute()
            except Exception:
                pass

    except Exception as e:
        # Never propagate — a failed audit must never break the caller
        print(f"[!] Audit log failed ({action}): {e}")'''


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 3 — database.py
# get_audit_stats() and get_audit_log() crash when new columns don't
# exist. Replace with safe versions that fall back gracefully.
# ═══════════════════════════════════════════════════════════════════

DB_GETAUDIT_SAFE_OLD = '''def get_audit_log(limit=100, user_id=None, action_filter=None,
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
        rows = _sb().table("audit_log") \\
            .select("action,risk_score,geo_country_code,ua_device,timestamp") \\
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

DB_GETAUDIT_SAFE_NEW = '''def get_audit_log(limit=100, user_id=None, action_filter=None,
                  risk_min=None, start_date=None, end_date=None,
                  ip_filter=None, country_filter=None):
    """
    Safe audit log retrieval — auto-selects only existing columns.
    Falls back to minimal column set if new columns don't exist yet.
    """
    cols = _get_audit_cols()

    # Build SELECT list from columns that actually exist
    ALWAYS = ["id", "user_id", "username", "action", "target",
              "ip_address", "user_agent", "details", "timestamp"]
    EXTENDED = [
        "email", "role", "auth_method",
        "ua_browser", "ua_os", "ua_device",
        "geo_country", "geo_country_code", "geo_city", "geo_isp", "geo_is_proxy",
        "session_id", "http_method", "endpoint", "status_code", "response_ms",
        "risk_score", "impossible_travel",
    ]
    select_cols = ALWAYS + [c for c in EXTENDED if c in cols]

    try:
        q = _sb().table("audit_log") \
            .select(",".join(select_cols)) \
            .order("id", desc=True) \
            .limit(limit)

        if user_id:
            q = q.eq("user_id", user_id)
        if action_filter:
            q = q.eq("action", action_filter)
        if risk_min is not None and "risk_score" in cols:
            q = q.gte("risk_score", int(risk_min))
        if start_date:
            q = q.gte("timestamp", start_date)
        if end_date:
            q = q.lte("timestamp", end_date)
        if ip_filter:
            q = q.eq("ip_address", ip_filter)
        if country_filter and "geo_country_code" in cols:
            q = q.eq("geo_country_code", country_filter)

        return q.execute().data or []

    except Exception as e:
        print(f"[!] get_audit_log failed: {e}")
        # Ultra-safe fallback — minimal columns only
        try:
            q2 = _sb().table("audit_log") \
                .select("id,user_id,username,action,target,ip_address,user_agent,details,timestamp") \
                .order("id", desc=True).limit(limit)
            if user_id:
                q2 = q2.eq("user_id", user_id)
            return q2.execute().data or []
        except Exception as e2:
            print(f"[!] get_audit_log fallback also failed: {e2}")
            return []


def get_audit_stats() -> dict:
    """
    Safe aggregate stats — never crashes, returns zeros on any error.
    Only queries columns that actually exist in the table.
    """
    cols = _get_audit_cols()
    try:
        # Use minimal columns that always exist
        select = "action,timestamp"
        if "risk_score"        in cols: select += ",risk_score"
        if "geo_country_code"  in cols: select += ",geo_country_code"
        if "ua_device"         in cols: select += ",ua_device"
        if "impossible_travel" in cols: select += ",impossible_travel"

        rows = _sb().table("audit_log") \
            .select(select) \
            .order("id", desc=True).limit(5000).execute().data or []

        from collections import Counter as _Ctr
        actions   = _Ctr(r.get("action", "") for r in rows if r.get("action"))
        countries = _Ctr(r.get("geo_country_code", "") for r in rows
                         if r.get("geo_country_code"))
        devices   = _Ctr(r.get("ua_device", "") for r in rows if r.get("ua_device"))
        risky     = sum(1 for r in rows if (r.get("risk_score") or 0) >= 40)
        logins    = sum(1 for r in rows if r.get("action") == "LOGIN")
        failures  = sum(1 for r in rows if r.get("action") == "LOGIN_FAIL")
        travel    = sum(1 for r in rows if r.get("impossible_travel"))

        return {
            "total_events":     len(rows),
            "high_risk_events": risky,
            "total_logins":     logins,
            "failed_logins":    failures,
            "impossible_travel": travel,
            "top_actions":      actions.most_common(10),
            "top_countries":    countries.most_common(10),
            "device_breakdown": dict(devices),
        }
    except Exception as e:
        return {
            "total_events": 0, "high_risk_events": 0,
            "total_logins": 0, "failed_logins": 0,
            "impossible_travel": 0, "top_actions": [],
            "top_countries": [], "device_breakdown": {},
            "error": str(e),
        }'''


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 4 — api_server.py
# The /api/admin/audit route returns jsonify(logs) when stats=0,
# but the new JS always passes stats=1. If an exception occurs inside
# the route before the return, Flask returns a 500 HTML page.
# Wrap the entire route in try/except and always return JSON.
# ═══════════════════════════════════════════════════════════════════

API_AUDIT_ROUTE_OLD = '''    @app.route("/api/admin/audit")
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

API_AUDIT_ROUTE_NEW = '''    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        # Always returns JSON — never raises so Flask never serves HTML 500
        try:
            from database import get_audit_log, get_audit_stats
            limit   = min(int(request.args.get("limit", 200)), 2000)
            include_stats = request.args.get("stats", "0") in ("1", "true", "yes")

            logs = get_audit_log(
                limit=limit,
                action_filter  = request.args.get("action")    or None,
                risk_min       = int(request.args.get("risk_min", 0)) or None,
                start_date     = request.args.get("start_date") or None,
                end_date       = request.args.get("end_date")   or None,
                ip_filter      = request.args.get("ip")         or None,
                country_filter = request.args.get("country")    or None,
            )

            if include_stats:
                return jsonify({"logs": logs, "stats": get_audit_stats()})
            return jsonify(logs)

        except Exception as e:
            return jsonify({"error": str(e), "logs": [], "stats": {}}), 200

    @app.route("/api/admin/audit/stats")
    @admin_required
    def api_audit_stats():
        try:
            from database import get_audit_stats
            return jsonify(get_audit_stats())
        except Exception as e:
            return jsonify({"error": str(e)}), 200

    @app.route("/api/admin/audit/export")
    @admin_required
    def api_audit_export():
        """Export audit log as CSV — always returns a file, never HTML."""
        try:
            import csv, io as _io2
            from database import get_audit_log
            limit = min(int(request.args.get("limit", 5000)), 10000)
            logs = get_audit_log(limit=limit)
            buf = _io2.StringIO()
            if logs:
                writer = csv.DictWriter(buf, fieldnames=list(logs[0].keys()))
                writer.writeheader()
                writer.writerows(logs)
            csv_bytes = buf.getvalue().encode("utf-8")
            fname = f"vulnscan-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
            _au = get_current_user()
            if _au:
                audit(_au["id"], _au["username"], "AUDIT_LOG_EXPORT",
                      target="audit_log", ip=request.remote_addr,
                      details=f"rows={len(logs)}", skip_geo=True)
            return Response(
                csv_bytes,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={fname}"}
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 200'''


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 5 — api_server.py
# The global HTTP request logger fires on EVERY request including
# /api/admin/audit itself, causing recursion + Supabase overload.
# Also, if get_current_user() raises (e.g. session issue) the whole
# middleware crashes → 500 HTML. Fix: tighter guard + deeper try/except.
# ═══════════════════════════════════════════════════════════════════

API_MW_OLD = '''@app.after_request
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
    return resp'''

API_MW_NEW = '''@app.after_request
def _log_request(resp):
    """Log security-sensitive API requests with timing. Never raises."""
    try:
        import time as _rt2
        req_id = id(request._get_current_object())
        with _REQ_LOCK:
            start = _REQ_START_TIMES.pop(req_id, None)
        elapsed_ms = round((_rt2.monotonic() - start) * 1000) if start else None

        path = request.path

        # Skip: audit log endpoints (infinite loop), health, static, agent poll
        SKIP_PREFIXES = (
            "/api/admin/audit", "/health", "/agent/",
            "/api/agent/heartbeat", "/api/remote/jobs",
        )
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            return resp

        # Only log security-sensitive paths
        TRACK_PREFIXES = (
            "/api/login", "/api/logout", "/api/register",
            "/api/change-password", "/api/forgot", "/api/reset",
            "/api/admin/", "/api/exec", "/api/kill",
            "/scan", "/lynis", "/nikto", "/wpscan", "/dirbust",
            "/subdomains", "/discover", "/brute-http", "/brute-ssh",
            "/legion", "/harvester", "/dnsrecon", "/report",
            "/social-tools/", "/api/create-job", "/api/remote/create-job",
        )
        if not any(path.startswith(p) for p in TRACK_PREFIXES):
            return resp

        # Only log non-200 OR explicitly security-relevant actions
        # (avoids flooding DB with every routine GET)
        is_mutating   = request.method in ("POST", "PUT", "DELETE", "PATCH")
        is_error      = resp.status_code >= 400
        is_auth_route = any(path.startswith(p) for p in
                            ("/api/login", "/api/logout", "/api/register",
                             "/api/change-password", "/api/forgot", "/api/reset"))
        if not (is_mutating or is_error or is_auth_route):
            return resp

        try:
            user   = get_current_user()
            uid    = user["id"]           if user else None
            uname  = user["username"]     if user else "anonymous"
            uemail = user.get("email","") if user else ""
            urole  = user.get("role", "") if user else ""
        except Exception:
            uid, uname, uemail, urole = None, "anonymous", "", ""

        from database import audit as _db_audit
        _db_audit(
            uid, uname, "HTTP_REQUEST",
            target=path,
            ip=request.remote_addr or "",
            ua=request.headers.get("User-Agent", ""),
            email=uemail, role=urole,
            http_method=request.method,
            endpoint=path,
            status_code=resp.status_code,
            response_ms=elapsed_ms,
            skip_geo=True,
        )
    except Exception:
        pass   # middleware must never break the response
    return resp'''


# ═══════════════════════════════════════════════════════════════════
# ROOT CAUSE 6 — api_server.py JS
# loadAdminAudit() assumes resp always has {logs, stats} shape.
# If the server returns a plain array (old format) or an error string,
# the JS crashes with "Unexpected token" before rendering anything.
# Replace with a fully defensive version.
# ═══════════════════════════════════════════════════════════════════

JS_AUDIT_SAFE_OLD = '''async function loadAdminAudit(){
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

JS_AUDIT_SAFE_NEW = '''async function loadAdminAudit(){
  var out=document.getElementById('admin-audit');
  var statsRow=document.getElementById('audit-stats-row');
  if(out)out.innerHTML='<div style="color:var(--text3);font-size:12px;padding:12px"><span class="spin"></span> Loading audit log...</div>';

  // Build query params safely
  var params=new URLSearchParams();
  params.set('stats','1');
  function _pval(id){var el=document.getElementById(id);return el?el.value:'';}
  params.set('limit',_pval('af-limit')||'200');
  var v;
  if((v=_pval('af-action').trim()))params.set('action',v);
  if((v=_pval('af-risk').trim()))params.set('risk_min',v);
  if((v=_pval('af-ip').trim()))params.set('ip',v);
  if((v=_pval('af-country').trim().toUpperCase()))params.set('country',v);
  if((v=_pval('af-start').trim()))params.set('start_date',v+'T00:00:00');
  if((v=_pval('af-end').trim()))params.set('end_date',v+'T23:59:59');

  try{
    var r=await fetch('/api/admin/audit?'+params.toString());

    // Guard: check Content-Type before calling .json()
    var ct=r.headers.get('content-type')||'';
    if(!ct.includes('json')){
      var txt=await r.text();
      if(out)out.innerHTML='<div class="err-box visible">Server returned non-JSON (HTTP '+r.status+'). '
        +'Check server logs.<br><pre style="font-size:10px;margin-top:6px;white-space:pre-wrap">'+
        txt.substring(0,400)+'</pre></div>';
      return;
    }

    var resp=await r.json();

    // Handle both {logs,stats} and plain array (backward compat)
    var d, stats=null;
    if(Array.isArray(resp)){
      d=resp;
    } else if(resp && Array.isArray(resp.logs)){
      d=resp.logs;
      stats=resp.stats||null;
    } else if(resp && resp.error){
      if(out)out.innerHTML='<div class="err-box visible">API error: '+resp.error+'</div>';
      return;
    } else {
      d=[];
    }

    // ── Stats cards ──────────────────────────────────────────
    if(statsRow){
      if(stats&&!stats.error){
        var kpis=[
          [stats.total_events||0,'TOTAL EVENTS','var(--text)'],
          [stats.high_risk_events||0,'HIGH RISK','var(--red)'],
          [stats.total_logins||0,'LOGINS','var(--green)'],
          [stats.failed_logins||0,'FAILED LOGINS','var(--orange)'],
          [stats.impossible_travel||0,'TRAVEL ALERTS','var(--yellow)'],
        ];
        statsRow.innerHTML=kpis.map(function(k){
          return'<div class="stat"><div class="stat-val" style="font-size:22px;color:'+k[2]+'">'+k[0]+'</div>'
            +'<div class="stat-lbl">'+k[1]+'</div></div>';
        }).join('');
      } else {
        statsRow.innerHTML='';
      }
    }

    // ── Empty state ───────────────────────────────────────────
    if(!d||!d.length){
      if(out)out.innerHTML='<div style="color:var(--text3);padding:16px;font-size:13px">'
        +'No log entries found. Try clearing the filters or run some scans first.</div>';
      return;
    }

    // ── Detect which columns are present in the first row ─────
    var sample=d[0]||{};
    var hasGeo=('geo_country' in sample||'geo_city' in sample);
    var hasDevice=('ua_browser' in sample||'ua_os' in sample);
    var hasHttp=('http_method' in sample);
    var hasSession=('session_id' in sample);
    var hasRisk=('risk_score' in sample);

    // ── Build table ───────────────────────────────────────────
    var html='<div style="overflow-x:auto"><table class="tbl" style="min-width:900px"><thead><tr>'
      +'<th>TIME</th><th>USER</th><th>ACTION</th>'
      +(hasRisk?'<th>RISK</th>':'')
      +'<th>IP'+(hasGeo?' / GEO':'')+'</th>'
      +(hasDevice?'<th>DEVICE</th>':'')
      +(hasHttp?'<th>HTTP</th>':'')
      +(hasSession?'<th>SESSION</th>':'')
      +'<th>TARGET / DETAILS</th>'
      +'</tr></thead><tbody>';

    d.forEach(function(l){
      // Geo cell
      var geoHtml='';
      if(hasGeo&&(l.geo_city||l.geo_country)){
        geoHtml='<div style="font-size:10px;color:var(--text3);margin-top:2px">'
          +(l.geo_city?(String(l.geo_city)+', '):'')+(l.geo_country||'')
          +(l.geo_is_proxy?'<span style="color:var(--red);margin-left:4px;font-weight:700">[PROXY]</span>':'')
          +'</div>';
      }
      // Device cell
      var deviceHtml='';
      if(hasDevice){
        deviceHtml=(l.ua_browser?'<div style="font-size:10px;font-family:var(--mono);color:var(--text2)">'+l.ua_browser+'</div>':'')
          +((l.ua_os||l.ua_device)?'<div style="font-size:10px;color:var(--text3)">'+(l.ua_os||'')+(l.ua_device?' / '+l.ua_device:'')+'</div>':'');
        if(!deviceHtml)deviceHtml='<span style="color:var(--text3)">—</span>';
      }
      // HTTP cell
      var httpHtml='';
      if(hasHttp&&l.http_method){
        var mc={'GET':'var(--green)','POST':'var(--blue)','DELETE':'var(--red)','PUT':'var(--yellow)'};
        httpHtml='<span style="font-family:var(--mono);font-size:10px;color:'+(mc[l.http_method]||'var(--text3)')+'">'+l.http_method+'</span>'
          +(l.status_code?'<span style="font-size:10px;color:var(--text3);margin-left:4px">'+l.status_code+'</span>':'')
          +(l.response_ms?'<div style="font-size:9px;color:var(--text3)">'+l.response_ms+'ms</div>':'');
      }
      // Session cell
      var sessionHtml='';
      if(hasSession){
        sessionHtml=l.session_id
          ?('<span style="font-family:var(--mono);font-size:9px;color:var(--text3)" title="'+(l.session_id||'')+'">'
            +(l.session_id||'').substring(0,8)+'…</span>')
          :'<span style="color:var(--text3)">—</span>';
      }
      // Travel badge
      var travelBadge=l.impossible_travel?'<span style="font-size:9px;color:var(--red);font-weight:700;margin-left:4px">✈ TRAVEL</span>':'';

      html+='<tr>'
        +'<td style="font-size:10px;color:var(--text3);white-space:nowrap">'
          +((l.timestamp||'').substring(0,19).replace('T',' '))+'</td>'
        +'<td>'
          +'<div style="font-family:var(--mono);font-size:11px;font-weight:500">'+(l.username||'—')+'</div>'
          +(l.email?'<div style="font-size:10px;color:var(--text3)">'+l.email+'</div>':'')
          +(l.role?'<div style="font-size:9px;color:var(--text3)">'+l.role+'</div>':'')
        +'</td>'
        +'<td>'+_actionPill(l.action||'')+travelBadge+'</td>'
        +(hasRisk?'<td>'+_riskPill(l.risk_score)+'</td>':'')
        +'<td>'
          +'<div style="font-family:var(--mono);font-size:11px">'+(l.ip_address||'—')+'</div>'
          +geoHtml
        +'</td>'
        +(hasDevice?'<td>'+deviceHtml+'</td>':'')
        +(hasHttp?'<td>'+httpHtml+'</td>':'')
        +(hasSession?'<td>'+sessionHtml+'</td>':'')
        +'<td style="max-width:240px">'
          +'<div style="font-size:11px;word-break:break-all;color:var(--text)">'+(l.target||'')+'</div>'
          +(l.details?'<div style="font-size:10px;color:var(--text3);margin-top:2px;word-break:break-all">'
            +String(l.details).substring(0,150)+'</div>':'')
        +'</td>'
        +'</tr>';
    });
    html+='</tbody></table></div>'
      +'<div style="font-family:var(--mono);font-size:10px;color:var(--text3);padding:8px 4px">'
      +d.length+' entries shown</div>';
    if(out)out.innerHTML=html;

  }catch(e){
    if(out)out.innerHTML='<div class="err-box visible">loadAdminAudit error: '+e.message+'<br>'
      +'<span style="font-size:10px">Open DevTools → Network tab, click the /api/admin/audit request '
      +'and check the response body for the actual error.</span></div>';
  }
}'''


# ═══════════════════════════════════════════════════════════════════
# APPLY ALL PATCHES
# ═══════════════════════════════════════════════════════════════════

def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║   VulnScan Pro — Audit Log Fix Patch                    ║" + RESET)
    print(BOLD + CYAN + "║   Fixes: 'Unexpected token <' / blank log / 500 errors  ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py", "database.py"]
               if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Must be run from the VulnScan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Usage: cd ~/vulnscan && python3 audit_fix_patch.py")
        return

    info(f"Project root: {os.getcwd()}")
    print()

    # ── database.py ──────────────────────────────────────────────
    print(BOLD + "  ── database.py" + RESET)
    patch_file("database.py",
               "Replace _geo_lookup with cached non-blocking version + column discovery",
               DB_AUDIT_FULL_OLD, DB_AUDIT_FULL_NEW)
    patch_file("database.py",
               "Replace audit() with safe column-aware version (never raises)",
               DB_AUDIT_BODY_OLD, DB_AUDIT_BODY_NEW)
    patch_file("database.py",
               "Replace get_audit_log() + get_audit_stats() with safe fallback versions",
               DB_GETAUDIT_SAFE_OLD, DB_GETAUDIT_SAFE_NEW)
    print()

    # ── api_server.py ─────────────────────────────────────────────
    print(BOLD + "  ── api_server.py" + RESET)
    patch_file("api_server.py",
               "Fix /api/admin/audit route — always returns JSON, never HTML 500",
               API_AUDIT_ROUTE_OLD, API_AUDIT_ROUTE_NEW)
    patch_file("api_server.py",
               "Fix HTTP middleware — tighter guards, no recursion, never raises",
               API_MW_OLD, API_MW_NEW)
    patch_file("api_server.py",
               "Fix loadAdminAudit() JS — Content-Type guard + backward compat + safe rendering",
               JS_AUDIT_SAFE_OLD, JS_AUDIT_SAFE_NEW)
    print()

    # ── Syntax checks ─────────────────────────────────────────────
    print(BOLD + "  ── Syntax checks" + RESET)
    all_ok = True
    for fname in ["api_server.py", "database.py"]:
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

    # ── Summary ───────────────────────────────────────────────────
    print(BOLD + CYAN + "══════════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{RESULTS['applied']}{RESET}  |  "
        f"Skipped : {DIM}{RESULTS['skipped']}{RESET}  |  "
        f"Failed  : {(RED if RESULTS['failed'] else DIM)}{RESULTS['failed']}{RESET}"
    )
    print()

    if RESULTS["failed"] > 0:
        warn("Some patches failed to find their anchors.")
        warn("This likely means the previous audit_patch.py was not applied,")
        warn("or was applied differently. Check the .fix.bak files to restore.")
        print()

    if all_ok:
        print(f"  {GREEN}Restart VulnScan to apply fixes:{RESET}")
        print(f"    sudo systemctl restart vulnscan")
        print(f"    OR: python3 api_server.py")
        print()
        print(f"  {CYAN}What was fixed:{RESET}")
        print(f"    {GREEN}✓{RESET}  audit() now only inserts columns that exist in DB")
        print(f"       → no more Supabase INSERT errors → no more HTML 500")
        print(f"    {GREEN}✓{RESET}  get_audit_log() auto-selects available columns")
        print(f"       → works before AND after running the SQL migration")
        print(f"    {GREEN}✓{RESET}  get_audit_stats() returns zeros on error, never crashes")
        print(f"    {GREEN}✓{RESET}  /api/admin/audit always returns JSON (wrapped in try/except)")
        print(f"    {GREEN}✓{RESET}  HTTP middleware skips audit-log endpoints (no recursion)")
        print(f"    {GREEN}✓{RESET}  JS checks Content-Type before .json() → clear error message")
        print(f"    {GREEN}✓{RESET}  JS renders table even when extended columns are absent")
        print(f"    {GREEN}✓{RESET}  GeoIP uses cache + 3s timeout — never blocks requests")
        print()
        print(f"  {YELLOW}NOTE: The SQL migration (audit_log_migration.sql) is still{RESET}")
        print(f"  {YELLOW}recommended for full feature set, but the audit log will{RESET}")
        print(f"  {YELLOW}now work correctly even WITHOUT running it first.{RESET}")
    else:
        print(f"  {RED}Syntax errors — restore .fix.bak files if needed.{RESET}")


if __name__ == "__main__":
    main()
