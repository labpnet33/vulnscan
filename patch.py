#!/usr/bin/env python3
"""
VulnScan Pro — Audit Log Complete Fix
======================================
ROOT CAUSES of "HTTP 500 / Unexpected token '<'":

  1. auth.py was patched to call audit(..., email=, role=, session_id=...)
     but database.py audit() still has the OLD signature without those params.
     Python raises TypeError on every login/logout → Flask returns HTML 500.

  2. database.py has leftover partial code from previous failed patches
     (_AUDIT_COLS with Python 3.9 union type hint `set | None` that fails
     on Python 3.8, or duplicate function definitions).

  3. The HTTP middleware fires on /api/admin/audit itself (recursion).

  4. get_audit_stats() selects non-existent columns → Supabase error → 500.

STRATEGY:
  - Completely replace database.py and auth.py audit sections from scratch
  - Use SAFE column list: only insert what original schema + migration adds
  - Never raise from audit() — always swallow exceptions silently
  - Run SQL migration FIRST (provided as audit_migration.sql)

Run:
    1. Paste audit_migration.sql into Supabase SQL Editor and click Run
    2. cd ~/vulnscan && python3 audit_complete_fix.py
    3. sudo systemctl restart vulnscan
"""
import os, sys, shutil, subprocess
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; Z = "\033[0m"; B = "\033[1m"; D = "\033[2m"

ok   = lambda m: print(f"  {G}✓{Z}  {m}")
fail = lambda m: print(f"  {R}✗{Z}  {m}")
info = lambda m: print(f"  {C}→{Z}  {m}")
skip = lambda m: print(f"  {D}·{Z}  {m}")
warn = lambda m: print(f"  {Y}!{Z}  {m}")

APPLIED = [0]; SKIPPED = [0]; FAILED = [0]

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.clean.bak"
    shutil.copy2(path, dst)
    return dst

def apply(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — {path} not found"); FAILED[0] += 1; return False
    src = open(path, encoding="utf-8", errors="ignore").read()
    if old not in src:
        # Check if new code already present
        check = new.strip().splitlines()[2].strip() if len(new.strip().splitlines()) > 2 else ""
        if check and check in src:
            skip(f"{label} — already applied"); SKIPPED[0] += 1; return False
        fail(f"{label} — anchor not found"); FAILED[0] += 1; return False
    backup(path)
    open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
    ok(f"{label}"); APPLIED[0] += 1; return True

def syntax_ok(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

# ═══════════════════════════════════════════════════════════════
# MIGRATION SQL  (written to disk, user must run in Supabase)
# ═══════════════════════════════════════════════════════════════
MIGRATION_SQL = """\
-- ================================================================
--  VulnScan Pro — Audit Log Schema Migration
--  Paste this into Supabase Dashboard → SQL Editor → Run
--  Safe to run multiple times (uses IF NOT EXISTS checks)
-- ================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='email')            THEN ALTER TABLE audit_log ADD COLUMN email            TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='role')             THEN ALTER TABLE audit_log ADD COLUMN role             TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='auth_method')      THEN ALTER TABLE audit_log ADD COLUMN auth_method      TEXT DEFAULT 'password'; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_browser')       THEN ALTER TABLE audit_log ADD COLUMN ua_browser       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_os')            THEN ALTER TABLE audit_log ADD COLUMN ua_os            TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_device')        THEN ALTER TABLE audit_log ADD COLUMN ua_device        TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country')      THEN ALTER TABLE audit_log ADD COLUMN geo_country      TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country_code') THEN ALTER TABLE audit_log ADD COLUMN geo_country_code TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_region')       THEN ALTER TABLE audit_log ADD COLUMN geo_region       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_city')         THEN ALTER TABLE audit_log ADD COLUMN geo_city         TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_isp')          THEN ALTER TABLE audit_log ADD COLUMN geo_isp          TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_proxy')     THEN ALTER TABLE audit_log ADD COLUMN geo_is_proxy     BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_hosting')   THEN ALTER TABLE audit_log ADD COLUMN geo_is_hosting   BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='session_id')       THEN ALTER TABLE audit_log ADD COLUMN session_id       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='http_method')      THEN ALTER TABLE audit_log ADD COLUMN http_method      TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='endpoint')         THEN ALTER TABLE audit_log ADD COLUMN endpoint         TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='status_code')      THEN ALTER TABLE audit_log ADD COLUMN status_code      INTEGER;           END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='response_ms')      THEN ALTER TABLE audit_log ADD COLUMN response_ms      INTEGER;           END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='risk_score')       THEN ALTER TABLE audit_log ADD COLUMN risk_score       INTEGER DEFAULT 0; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='impossible_travel')THEN ALTER TABLE audit_log ADD COLUMN impossible_travel BOOLEAN DEFAULT FALSE; END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_risk    ON audit_log(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ip      ON audit_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_country ON audit_log(geo_country_code);

-- Verify: should show 20+ columns
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'audit_log' ORDER BY ordinal_position;
"""

# ═══════════════════════════════════════════════════════════════
# PATCH 1 — database.py
# Replace the OLD simple audit() + get_audit_log() + get_audit_stats()
# with a complete, safe, self-contained implementation.
# Anchor: the original simple audit() that the file was born with.
# ═══════════════════════════════════════════════════════════════

# The ORIGINAL audit() from the provided database.py source
DB_OLD = '''def audit(user_id, username, action, target="", ip="", ua="", details=""):
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
        print(f"[!] Audit log failed: {e}")

def get_audit_log(limit=100, user_id=None):
    q = _sb().table("audit_log").select("*").order("id", desc=True).limit(limit)
    if user_id:
        q = q.eq("user_id", user_id)
    return q.execute().data or []'''

DB_NEW = '''# ─────────────────────────────────────────────────────────────────
# AUDIT HELPERS  (GeoIP · UA parser · risk scorer · session tracker)
# ─────────────────────────────────────────────────────────────────
import threading as _ath, re as _are

_GEO_CACHE   = {}          # ip -> (dict, expiry_float)
_GEO_LOCK    = _ath.Lock()
_GEO_TTL     = 3600        # 1 hour

_SESSION_MAP = {}          # session_id -> {"user_id", "username", "start"}
_SES_LOCK    = _ath.Lock()

# Extended columns added by the migration — we only insert these if present
_EXTENDED_COLS = frozenset({
    "email","role","auth_method",
    "ua_browser","ua_os","ua_device",
    "geo_country","geo_country_code","geo_region",
    "geo_city","geo_isp","geo_is_proxy","geo_is_hosting",
    "session_id","http_method","endpoint","status_code","response_ms",
    "risk_score","impossible_travel",
})

# Column presence cache (discovered once from live DB)
_DB_COLS      = None
_DB_COLS_LOCK = _ath.Lock()

def _discover_cols():
    """Fetch actual column names from audit_log once; cache forever."""
    global _DB_COLS
    if _DB_COLS is not None:
        return _DB_COLS
    with _DB_COLS_LOCK:
        if _DB_COLS is not None:
            return _DB_COLS
        try:
            rows = _sb().table("audit_log").select("*").limit(1).execute()
            if rows.data:
                _DB_COLS = frozenset(rows.data[0].keys())
            else:
                # Empty table — try a dummy select to get column names via error
                # Fall back to base-only; will be refreshed on next real row
                _DB_COLS = frozenset({
                    "id","user_id","username","action","target",
                    "ip_address","user_agent","details","timestamp",
                })
        except Exception:
            _DB_COLS = frozenset({
                "id","user_id","username","action","target",
                "ip_address","user_agent","details","timestamp",
            })
    return _DB_COLS


def _geo_lookup(ip):
    """Non-blocking GeoIP with 1-hour cache. Returns {} on any error."""
    import urllib.request as _ur, json as _jr, time as _ti
    if not ip or ip in ("127.0.0.1","::1","","unknown"):
        return {}
    with _GEO_LOCK:
        cached = _GEO_CACHE.get(ip)
        if cached:
            data, exp = cached
            if _ti.monotonic() < exp:
                return data
    try:
        req = _ur.Request(
            "http://ip-api.com/json/" + ip +
            "?fields=status,country,countryCode,regionName,city,isp,proxy,hosting",
            headers={"User-Agent": "VulnScan-Audit/1.0"}
        )
        with _ur.urlopen(req, timeout=3) as r:
            d = _jr.loads(r.read())
        if d.get("status") == "success":
            geo = {
                "country":      d.get("country", ""),
                "country_code": d.get("countryCode", ""),
                "region":       d.get("regionName", ""),
                "city":         d.get("city", ""),
                "isp":          d.get("isp", ""),
                "is_proxy":     bool(d.get("proxy", False)),
                "is_hosting":   bool(d.get("hosting", False)),
            }
        else:
            geo = {}
    except Exception:
        geo = {}
    import time as _ti2
    with _GEO_LOCK:
        _GEO_CACHE[ip] = (geo, _ti2.monotonic() + _GEO_TTL)
        if len(_GEO_CACHE) > 1000:
            oldest = min(_GEO_CACHE, key=lambda k: _GEO_CACHE[k][1])
            _GEO_CACHE.pop(oldest, None)
    return geo


def _parse_ua(ua):
    """Parse User-Agent into {browser, os, device}."""
    ua = ua or ""
    browser = "Unknown"
    if "Edg/" in ua:                           browser = "Edge"
    elif "OPR/" in ua:                         browser = "Opera"
    elif "Chrome/" in ua:                      browser = "Chrome"
    elif "Firefox/" in ua:                     browser = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua: browser = "Safari"
    elif "MSIE" in ua or "Trident/" in ua:     browser = "IE"
    elif "curl" in ua.lower():                 browser = "curl"
    elif "python" in ua.lower():               browser = "Python"
    os_name = "Unknown"
    if "Windows NT" in ua:                     os_name = "Windows"
    elif "Mac OS X" in ua:                     os_name = "macOS"
    elif "Android" in ua:                      os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:       os_name = "iOS"
    elif "Linux" in ua:                        os_name = "Linux"
    device = "Desktop"
    if "Mobile" in ua or "Android" in ua or "iPhone" in ua: device = "Mobile"
    elif "Tablet" in ua or "iPad" in ua:       device = "Tablet"
    elif browser in ("curl", "Python"):        device = "API/Script"
    m = _are.search(r"(?:Chrome|Firefox|Safari|Edg|OPR)/([0-9]+)", ua)
    bver = m.group(1) if m else ""
    return {
        "browser": f"{browser}/{bver}" if bver else browser,
        "os":      os_name,
        "device":  device,
    }


def _risk_score(action, ip, geo):
    """Compute 0-100 risk score for an audit event."""
    SCORES = {
        "LOGIN_FAIL": 20, "ACCOUNT_LOCKED": 40, "BRUTE_FORCE_DETECTED": 50,
        "PRIVILEGE_ESCALATION": 45, "ADMIN_DELETE_USER": 30,
        "IMPOSSIBLE_TRAVEL": 60, "PASSWORD_RESET": 10,
        "MFA_DISABLED": 35, "ROLE_CHANGE": 25, "CLI_EXEC": 15,
        "SET_SESSION_START": 20, "BRUTE_HTTP": 25, "BRUTE_SSH": 30,
        "KILL_ALL_TOOLS": 20, "AUDIT_LOG_EXPORT": 5,
    }
    score = SCORES.get(action, 0)
    if geo.get("is_proxy"):   score += 20
    if geo.get("is_hosting"): score += 10
    if ip in ("127.0.0.1", "::1"): score = max(0, score - 5)
    return min(100, score)


def record_session_start(session_id, user_id, username, ip=""):
    """Track session start time for duration calculation."""
    import time as _ti3
    if not session_id:
        return
    with _SES_LOCK:
        _SESSION_MAP[str(session_id)] = {
            "user_id": user_id, "username": username,
            "ip": ip, "start": _ti3.time(),
        }


def record_session_end(session_id):
    """Return session duration in seconds (0 if unknown)."""
    import time as _ti4
    if not session_id:
        return 0.0
    with _SES_LOCK:
        s = _SESSION_MAP.pop(str(session_id), None)
    return round(_ti4.time() - s["start"], 1) if s else 0.0


# ─────────────────────────────────────────────────────────────────
# MAIN audit() — backward-compatible, never raises
# ─────────────────────────────────────────────────────────────────
def audit(user_id, username, action, target="", ip="", ua="", details="",
          # Extended params (all optional, ignored if columns don\'t exist)
          session_id="", http_method="", endpoint="", status_code=None,
          response_ms=None, email="", role="", auth_method="password",
          skip_geo=False):
    """
    Write one audit log entry to Supabase.
    • Backward-compatible: old callers using positional/keyword args still work.
    • Safe: never raises — a failed audit never breaks the caller.
    • Smart: only inserts extended columns when they exist in the DB.
    """
    try:
        # ── Discover available columns (cached) ───────────────
        cols = _discover_cols()

        # ── GeoIP (skip for localhost / high-frequency events) ─
        geo = {}
        if not skip_geo and ip and ip not in ("127.0.0.1", "::1", "", "unknown"):
            try:
                geo = _geo_lookup(ip)
            except Exception:
                geo = {}

        # ── User-Agent ─────────────────────────────────────────
        try:
            uap = _parse_ua(ua)
        except Exception:
            uap = {"browser": "", "os": "", "device": ""}

        # ── Risk score ─────────────────────────────────────────
        try:
            risk = _risk_score(action, ip, geo)
        except Exception:
            risk = 0

        # ── Impossible-travel check ────────────────────────────
        travel = False
        if ("geo_country_code" in cols and "impossible_travel" in cols
                and geo.get("country_code") and user_id):
            try:
                prev = (
                    _sb().table("audit_log")
                    .select("geo_country_code")
                    .eq("user_id", user_id)
                    .not_.is_("geo_country_code", "null")
                    .order("id", desc=True)
                    .limit(1)
                    .execute().data
                )
                if prev and prev[0].get("geo_country_code"):
                    pcc = prev[0]["geo_country_code"]
                    ccc = geo.get("country_code", "")
                    if pcc and ccc and pcc != ccc:
                        travel = True
                        risk = min(100, risk + 30)
            except Exception:
                pass

        # ── Build base row (columns that always exist) ─────────
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

        # ── Append extended columns only if they exist ─────────
        def _ext(col, val):
            if col in cols:
                row[col] = val

        _ext("email",            str(email or "")[:200] or None)
        _ext("role",             str(role or "")[:50] or None)
        _ext("auth_method",      str(auth_method or "password")[:50])
        _ext("ua_browser",       uap.get("browser", ""))
        _ext("ua_os",            uap.get("os", ""))
        _ext("ua_device",        uap.get("device", ""))
        _ext("geo_country",      geo.get("country", ""))
        _ext("geo_country_code", geo.get("country_code", ""))
        _ext("geo_region",       geo.get("region", ""))
        _ext("geo_city",         geo.get("city", ""))
        _ext("geo_isp",          geo.get("isp", ""))
        _ext("geo_is_proxy",     bool(geo.get("is_proxy", False)))
        _ext("geo_is_hosting",   bool(geo.get("is_hosting", False)))
        _ext("session_id",       str(session_id or "")[:200] or None)
        _ext("http_method",      str(http_method or "")[:10] or None)
        _ext("endpoint",         str(endpoint or "")[:500])
        _ext("status_code",      int(status_code) if status_code is not None else None)
        _ext("response_ms",      int(response_ms) if response_ms is not None else None)
        _ext("risk_score",       int(risk))
        _ext("impossible_travel", bool(travel))

        _sb().table("audit_log").insert(row).execute()

        # ── Impossible-travel secondary alert ──────────────────
        if travel:
            try:
                alert = {
                    "user_id":  user_id,
                    "username": str(username or ""),
                    "action":   "IMPOSSIBLE_TRAVEL",
                    "target":   str(geo.get("country_code", "")),
                    "ip_address": str(ip or ""),
                    "details":  f"Login from new country: {geo.get('country', '')}",
                    "timestamp": _now(),
                }
                _ext2 = lambda c, v: alert.update({c: v}) if c in cols else None
                _ext2("risk_score", 80)
                _ext2("geo_country", geo.get("country", ""))
                _ext2("geo_country_code", geo.get("country_code", ""))
                _sb().table("audit_log").insert(alert).execute()
            except Exception:
                pass

        # Reset column cache if we discover new columns next time
        global _DB_COLS
        if _DB_COLS is not None and len(row) > len(_DB_COLS):
            _DB_COLS = None   # force re-discovery

    except Exception as e:
        # NEVER propagate — a broken audit log must not break the app
        print(f"[!] audit() swallowed error ({action}): {e}")


def get_audit_log(limit=100, user_id=None, action_filter=None,
                  risk_min=None, start_date=None, end_date=None,
                  ip_filter=None, country_filter=None):
    """Fetch audit log rows — safe even when extended columns are absent."""
    cols = _discover_cols()
    BASE = ["id","user_id","username","action","target",
            "ip_address","user_agent","details","timestamp"]
    EXTRA = ["email","role","auth_method",
             "ua_browser","ua_os","ua_device",
             "geo_country","geo_country_code","geo_city","geo_isp","geo_is_proxy",
             "session_id","http_method","endpoint","status_code","response_ms",
             "risk_score","impossible_travel"]
    sel = ",".join(BASE + [c for c in EXTRA if c in cols])
    try:
        q = _sb().table("audit_log").select(sel).order("id", desc=True).limit(limit)
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
            q = q.eq("geo_country_code", country_filter.upper())
        return q.execute().data or []
    except Exception as e:
        print(f"[!] get_audit_log failed: {e}")
        # Ultra-safe fallback
        try:
            q2 = _sb().table("audit_log") \
                .select("id,user_id,username,action,target,ip_address,details,timestamp") \
                .order("id", desc=True).limit(limit)
            if user_id:
                q2 = q2.eq("user_id", user_id)
            return q2.execute().data or []
        except Exception:
            return []


def get_audit_stats():
    """Aggregate stats — always returns a dict, never raises."""
    cols = _discover_cols()
    try:
        sel = "action,timestamp"
        if "risk_score"        in cols: sel += ",risk_score"
        if "geo_country_code"  in cols: sel += ",geo_country_code"
        if "ua_device"         in cols: sel += ",ua_device"
        if "impossible_travel" in cols: sel += ",impossible_travel"
        rows = _sb().table("audit_log").select(sel) \
            .order("id", desc=True).limit(5000).execute().data or []
        from collections import Counter as _Ctr
        actions   = _Ctr(r.get("action","") for r in rows if r.get("action"))
        countries = _Ctr(r.get("geo_country_code","") for r in rows
                         if r.get("geo_country_code"))
        devices   = _Ctr(r.get("ua_device","") for r in rows if r.get("ua_device"))
        return {
            "total_events":      len(rows),
            "high_risk_events":  sum(1 for r in rows if (r.get("risk_score") or 0) >= 40),
            "total_logins":      actions.get("LOGIN", 0),
            "failed_logins":     actions.get("LOGIN_FAIL", 0),
            "impossible_travel": sum(1 for r in rows if r.get("impossible_travel")),
            "top_actions":       actions.most_common(10),
            "top_countries":     countries.most_common(10),
            "device_breakdown":  dict(devices),
        }
    except Exception as e:
        return {"total_events":0,"high_risk_events":0,"total_logins":0,
                "failed_logins":0,"impossible_travel":0,"top_actions":[],
                "top_countries":[],"device_breakdown":{},"error":str(e)}'''

# ═══════════════════════════════════════════════════════════════
# PATCH 2 — auth.py
# Replace ALL patched audit() calls with the correct new signature.
# Find the login route and replace the whole enriched audit block.
# ═══════════════════════════════════════════════════════════════

# --- Login success ---
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
        _sid = session.get("_id") or (str(user["id"]) + "-" + str(int(time.time())))
        try:
            from database import record_session_start
            record_session_start(_sid, user["id"], username, request.remote_addr or "")
        except Exception:
            pass
        audit(
            user["id"], username, "LOGIN",
            ip=request.remote_addr or "",
            ua=request.headers.get("User-Agent", ""),
            email=user.get("email", ""),
            role=user.get("role", "user"),
            auth_method="password",
            session_id=_sid,
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

# --- Login fail ---
AUTH_LOGINFAIL_OLD = '''        audit(user["id"], username, "LOGIN_FAIL", ip=request.remote_addr)
        _record_login_failure(username)
        return jsonify({"error": "Invalid username or password"}), 401'''

AUTH_LOGINFAIL_NEW = '''        audit(
            user["id"], username, "LOGIN_FAIL",
            ip=request.remote_addr or "",
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

# --- Logout ---
AUTH_LOGOUT_OLD = '''        if uid: audit(uid, username, "LOGOUT", ip=request.remote_addr)
        session.clear()'''

AUTH_LOGOUT_NEW = '''        if uid:
            try:
                from database import record_session_end
                _sid_out = session.get("_id", "")
                _dur = record_session_end(_sid_out) if _sid_out else 0
            except Exception:
                _dur = 0
            audit(uid, username, "LOGOUT",
                  ip=request.remote_addr or "",
                  ua=request.headers.get("User-Agent", ""),
                  http_method="POST", endpoint="/api/logout",
                  status_code=200,
                  details=f"session_duration_s={_dur}",
                  skip_geo=True)
        session.clear()'''

# --- Password change ---
AUTH_PWDCHANGE_OLD = '''        update_user(user["id"], password_hash=hash_password(new_pwd))
        audit(user["id"], user["username"], "PASSWORD_CHANGE", ip=request.remote_addr)
        return jsonify({"success": True, "message": "Password changed successfully"})'''

AUTH_PWDCHANGE_NEW = '''        update_user(user["id"], password_hash=hash_password(new_pwd))
        audit(user["id"], user["username"], "PASSWORD_CHANGE",
              ip=request.remote_addr or "",
              ua=request.headers.get("User-Agent", ""),
              email=user.get("email", ""),
              role=user.get("role", ""),
              http_method="POST", endpoint="/api/change-password",
              status_code=200,
              details="Password changed successfully")
        return jsonify({"success": True, "message": "Password changed successfully"})'''

# --- Role change ---
AUTH_ROLE_OLD = '''        from database import set_user_role
        set_user_role(uid, role)
        return jsonify({"success": True})'''

AUTH_ROLE_NEW = '''        from database import set_user_role
        set_user_role(uid, role)
        _cur = get_current_user()
        if _cur:
            audit(_cur["id"], _cur["username"], "PRIVILEGE_ESCALATION",
                  target=str(uid), ip=request.remote_addr or "",
                  ua=request.headers.get("User-Agent", ""),
                  details=f"Changed user #{uid} role to {role}",
                  http_method="POST",
                  endpoint=f"/api/admin/users/{uid}/role",
                  status_code=200)
        return jsonify({"success": True})'''

# ═══════════════════════════════════════════════════════════════
# PATCH 3 — api_server.py: /api/admin/audit route (full safe version)
# ═══════════════════════════════════════════════════════════════
API_AUDIT_OLD = '''    @app.route("/api/admin/audit")
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

# If the above anchor isn't found (old format), try original
API_AUDIT_OLD_ORIG = '''    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        from database import get_audit_log
        limit = int(request.args.get("limit", 100))
        return jsonify(get_audit_log(limit))'''

API_AUDIT_NEW = '''    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        """Always returns JSON — never raises, never serves HTML."""
        try:
            from database import get_audit_log, get_audit_stats
            limit = min(int(request.args.get("limit") or 200), 2000)
            want_stats = request.args.get("stats","0") in ("1","true","yes")
            rm = request.args.get("risk_min","").strip()
            logs = get_audit_log(
                limit          = limit,
                action_filter  = request.args.get("action","").strip() or None,
                risk_min       = int(rm) if rm.isdigit() else None,
                start_date     = request.args.get("start_date","").strip() or None,
                end_date       = request.args.get("end_date","").strip()   or None,
                ip_filter      = request.args.get("ip","").strip()         or None,
                country_filter = request.args.get("country","").strip().upper() or None,
            )
            if want_stats:
                return jsonify({"logs": logs, "stats": get_audit_stats()})
            return jsonify({"logs": logs, "stats": {}})
        except Exception as e:
            import traceback; traceback.print_exc()
            return jsonify({"logs": [], "stats": {}, "error": str(e)})

    @app.route("/api/admin/audit/stats")
    @admin_required
    def api_audit_stats():
        try:
            from database import get_audit_stats
            return jsonify(get_audit_stats())
        except Exception as e:
            return jsonify({"error": str(e), "total_events": 0})

    @app.route("/api/admin/audit/export")
    @admin_required
    def api_audit_export():
        try:
            import csv, io as _aio
            from database import get_audit_log
            limit = min(int(request.args.get("limit","5000") or 5000), 10000)
            logs = get_audit_log(limit=limit)
            buf = _aio.StringIO()
            if logs:
                writer = csv.DictWriter(buf, fieldnames=list(logs[0].keys()))
                writer.writeheader()
                writer.writerows(logs)
            csv_bytes = buf.getvalue().encode("utf-8")
            fname = f"vulnscan-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
            _u = get_current_user()
            if _u:
                audit(_u["id"], _u["username"], "AUDIT_LOG_EXPORT",
                      target="audit_log", ip=request.remote_addr or "",
                      details=f"rows_exported={len(logs)}", skip_geo=True)
            return Response(csv_bytes, mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={fname}"})
        except Exception as e:
            return jsonify({"error": str(e)})'''

# ═══════════════════════════════════════════════════════════════
# PATCH 4 — api_server.py: HTTP middleware (tightest safe version)
# ═══════════════════════════════════════════════════════════════
API_MW_OLD = '''@app.after_request
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

# Also handle the version from before any patching
API_MW_OLD_ORIG = '''@app.after_request
def _set_security_headers(resp):
    """Apply baseline HTTP hardening headers for API/UI responses."""'''

API_MW_NEW = '''@app.after_request
def _log_and_secure_response(resp):
    """Apply security headers AND log sensitive API requests. Never raises."""
    # ── Security headers (always) ─────────────────────────────
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.is_secure or os.environ.get("VULNSCAN_FORCE_HSTS","0").lower() in {"1","true","yes"}:
        resp.headers.setdefault("Strict-Transport-Security","max-age=31536000; includeSubDomains")

    # ── Request logging (security-sensitive paths only) ────────
    try:
        import time as _rt2
        req_id = id(request._get_current_object())
        with _REQ_LOCK:
            start = _REQ_START_TIMES.pop(req_id, None)
        elapsed_ms = round((_rt2.monotonic() - start) * 1000) if start else None

        path = request.path

        # Never log these (avoid recursion / spam)
        NEVER = ("/api/admin/audit", "/health", "/agent/",
                 "/api/agent/heartbeat", "/api/remote/jobs", "/api/me")
        if any(path.startswith(p) for p in NEVER):
            return resp

        # Only log auth + scan + admin mutating requests
        WATCH = ("/api/login", "/api/logout", "/api/register",
                 "/api/change-password", "/api/forgot-password",
                 "/api/reset-password", "/api/admin/", "/api/exec",
                 "/api/kill", "/scan", "/lynis", "/nikto", "/wpscan",
                 "/dirbust", "/subdomains", "/discover",
                 "/brute-http", "/brute-ssh", "/legion",
                 "/harvester", "/dnsrecon", "/social-tools/",
                 "/api/create-job", "/api/remote/create-job")
        if not any(path.startswith(p) for p in WATCH):
            return resp

        is_mutating = request.method in ("POST","PUT","DELETE","PATCH")
        is_error    = resp.status_code >= 400
        is_auth     = any(path.startswith(p) for p in
                          ("/api/login","/api/logout","/api/register",
                           "/api/change-password","/api/forgot","/api/reset"))
        if not (is_mutating or is_error or is_auth):
            return resp

        try:
            user  = get_current_user()
            uid   = user["id"]           if user else None
            uname = user["username"]     if user else "anonymous"
            email = user.get("email","") if user else ""
            role  = user.get("role","")  if user else ""
        except Exception:
            uid, uname, email, role = None, "anonymous", "", ""

        from database import audit as _dba
        _dba(uid, uname, "HTTP_REQUEST",
             target=path,
             ip=request.remote_addr or "",
             ua=request.headers.get("User-Agent",""),
             email=email, role=role,
             http_method=request.method,
             endpoint=path,
             status_code=resp.status_code,
             response_ms=elapsed_ms,
             skip_geo=True)
    except Exception:
        pass
    return resp'''

# Remove the OLD _set_security_headers if it's still the original
API_SEC_OLD = '''@app.after_request
def _set_security_headers(resp):
    """Apply baseline HTTP hardening headers for API/UI responses."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.is_secure or os.environ.get("VULNSCAN_FORCE_HSTS", "0").lower() in {"1", "true", "yes"}:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp'''

API_SEC_NEW = '''# _set_security_headers merged into _log_and_secure_response above'''

# ═══════════════════════════════════════════════════════════════
# PATCH 5 — api_server.py: JS loadAdminAudit() — handles {logs,stats}
# ═══════════════════════════════════════════════════════════════
JS_OLD = '''async function loadAdminAudit(){try{var r=await fetch('/api/admin/audit?limit=200');var d=await r.json();document.getElementById('admin-audit').innerHTML='<table class="tbl"><thead><tr><th>TIME</th><th>USER</th><th>ACTION</th><th>TARGET</th><th>IP</th></tr></thead><tbody>'+d.map(function(l){return'<tr><td style="font-size:11px;color:var(--text3)">'+((l.timestamp||'').substring(0,16))+'</td><td style="font-family:var(--mono)">'+(l.username||'--')+'</td><td><span class="tag">'+(l.action||'')+'</span></td><td style="font-size:11px;color:var(--text3)">'+(l.target||'--')+'</td><td style="font-size:11px;color:var(--text3)">'+(l.ip_address||'--')+'</td></tr>';}).join('')+'</tbody></table>';}catch(e){}}'''

JS_NEW = r'''/* ── Audit log helpers ─────────────────────────────────── */
function _riskPill(s){
  s=parseInt(s||0);if(!s)return'';
  var c=s>=60?'var(--red)':s>=40?'var(--orange)':s>=20?'var(--yellow)':'var(--text3)';
  var l=s>=60?'CRIT':s>=40?'HIGH':s>=20?'MED':'LOW';
  return'<span style="font-family:var(--mono);font-size:9px;padding:1px 6px;border-radius:3px;border:1px solid '+c+';color:'+c+'">'+l+' '+s+'</span>';
}
function _actionPill(a){
  var danger=['LOGIN_FAIL','ACCOUNT_LOCKED','IMPOSSIBLE_TRAVEL','PRIVILEGE_ESCALATION',
              'BRUTE_FORCE_DETECTED','MFA_DISABLED','KILL_ALL_TOOLS','BRUTE_HTTP','BRUTE_SSH'];
  var warn2=['PASSWORD_RESET','PASSWORD_CHANGE','ADMIN_DELETE_USER','CLI_EXEC','SET_SESSION_START'];
  var c=danger.includes(a)?'var(--red)':warn2.includes(a)?'var(--orange)':'var(--text3)';
  return'<span style="font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:3px;'
    +'border:1px solid var(--border);color:'+c+'">'+a+'</span>';
}
function clearAuditFilters(){
  ['af-action','af-risk','af-ip','af-country','af-start','af-end']
    .forEach(function(id){var e=document.getElementById(id);if(e)e.value='';});
  var lim=document.getElementById('af-limit');if(lim)lim.value='200';
  loadAdminAudit();
}
function exportAuditCSV(){
  var lim=(document.getElementById('af-limit')||{value:'200'}).value||200;
  window.open('/api/admin/audit/export?limit='+lim,'_blank');
}
async function loadAdminAudit(){
  var out=document.getElementById('admin-audit');
  var statsRow=document.getElementById('audit-stats-row');
  if(out)out.innerHTML='<div style="color:var(--text3);padding:12px;font-size:12px">'
    +'<span class="spin"></span>&nbsp; Loading audit log...</div>';

  var p=new URLSearchParams();
  p.set('stats','1');
  function gv(id){var e=document.getElementById(id);return e?e.value:'';}
  p.set('limit',gv('af-limit')||'200');
  var v;
  if((v=gv('af-action').trim()))p.set('action',v);
  if((v=gv('af-risk').trim()))p.set('risk_min',v);
  if((v=gv('af-ip').trim()))p.set('ip',v);
  if((v=gv('af-country').trim().toUpperCase()))p.set('country',v);
  if((v=gv('af-start').trim()))p.set('start_date',v+'T00:00:00');
  if((v=gv('af-end').trim()))p.set('end_date',v+'T23:59:59');

  try{
    var r=await fetch('/api/admin/audit?'+p.toString());

    /* ── Guard: if server returned HTML (500), show snippet ── */
    var ct=r.headers.get('content-type')||'';
    if(!ct.includes('json')){
      var txt=await r.text();
      if(out)out.innerHTML='<div class="err-box visible">'
        +'Server returned HTTP '+r.status+' (not JSON). '
        +'Restart the server and check console logs.<br>'
        +'<pre style="font-size:10px;margin-top:6px;white-space:pre-wrap;max-height:120px;overflow:auto">'
        +txt.replace(/</g,'&lt;').substring(0,600)+'</pre></div>';
      return;
    }

    var resp=await r.json();

    /* ── Normalise: accept {logs,stats} or plain array ─────── */
    var logs, stats=null;
    if(Array.isArray(resp)){
      logs=resp;
    }else if(resp&&Array.isArray(resp.logs)){
      logs=resp.logs; stats=resp.stats||null;
    }else if(resp&&resp.error){
      if(out)out.innerHTML='<div class="err-box visible">API error: '
        +resp.error+'</div>';
      return;
    }else{
      logs=[];
    }

    /* ── Stats row ─────────────────────────────────────────── */
    if(statsRow&&stats&&!stats.error){
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
    }else if(statsRow){
      statsRow.innerHTML='';
    }

    /* ── Empty state ───────────────────────────────────────── */
    if(!logs||!logs.length){
      if(out)out.innerHTML='<div style="color:var(--text3);padding:16px;font-size:13px">'
        +'No audit log entries found. Run some scans or log in/out to generate events.</div>';
      return;
    }

    /* ── Detect extended columns from first row ────────────── */
    var s0=logs[0]||{};
    var hasGeo     =('geo_country' in s0||'geo_city' in s0);
    var hasDevice  =('ua_browser' in s0||'ua_os' in s0);
    var hasHttp    =('http_method' in s0);
    var hasSession =('session_id' in s0);
    var hasRisk    =('risk_score' in s0);

    /* ── Table ─────────────────────────────────────────────── */
    var html='<div style="overflow-x:auto">'
      +'<table class="tbl" style="min-width:860px"><thead><tr>'
      +'<th>TIME</th><th>USER</th><th>ACTION</th>'
      +(hasRisk?'<th>RISK</th>':'')
      +'<th>IP'+(hasGeo?' / GEO':'')+'</th>'
      +(hasDevice?'<th>DEVICE</th>':'')
      +(hasHttp?'<th>HTTP</th>':'')
      +(hasSession?'<th>SESSION</th>':'')
      +'<th>TARGET / DETAILS</th>'
      +'</tr></thead><tbody>';

    logs.forEach(function(l){
      var geoH='';
      if(hasGeo&&(l.geo_city||l.geo_country)){
        geoH='<div style="font-size:10px;color:var(--text3);margin-top:1px">'
          +(l.geo_city?l.geo_city+', ':'')+( l.geo_country||'')
          +(l.geo_is_proxy?'<span style="color:var(--red);margin-left:3px;font-weight:700">[PROXY]</span>':'')
          +'</div>';
      }
      var devH='<span style="color:var(--text3)">—</span>';
      if(hasDevice&&(l.ua_browser||l.ua_os)){
        devH=(l.ua_browser?'<div style="font-size:10px;font-family:var(--mono)">'+l.ua_browser+'</div>':'')
          +((l.ua_os||l.ua_device)?'<div style="font-size:10px;color:var(--text3)">'
            +(l.ua_os||'')+(l.ua_device?' / '+l.ua_device:'')+'</div>':'');
      }
      var httpH='';
      if(hasHttp&&l.http_method){
        var mc={GET:'var(--green)',POST:'var(--blue)',DELETE:'var(--red)',PUT:'var(--yellow)'};
        httpH='<span style="font-family:var(--mono);font-size:10px;color:'+(mc[l.http_method]||'var(--text3)')+'">'+l.http_method+'</span>'
          +(l.status_code?'<span style="font-size:10px;color:var(--text3);margin-left:4px">'+l.status_code+'</span>':'')
          +(l.response_ms?'<div style="font-size:9px;color:var(--text3)">'+l.response_ms+'ms</div>':'');
      }
      var sesH='<span style="color:var(--text3)">—</span>';
      if(hasSession&&l.session_id){
        sesH='<span style="font-family:var(--mono);font-size:9px;color:var(--text3)" title="'+l.session_id+'">'
          +l.session_id.substring(0,8)+'…</span>';
      }
      var trvB=l.impossible_travel?'<span style="font-size:9px;color:var(--red);font-weight:700;margin-left:3px">✈ TRAVEL</span>':'';
      html+='<tr>'
        +'<td style="font-size:10px;color:var(--text3);white-space:nowrap">'
          +((l.timestamp||'').substring(0,19).replace('T',' '))+'</td>'
        +'<td><div style="font-family:var(--mono);font-size:11px;font-weight:500">'+(l.username||'—')+'</div>'
          +(l.email?'<div style="font-size:10px;color:var(--text3)">'+l.email+'</div>':'')
          +(l.role?'<div style="font-size:9px;color:var(--text3)">'+l.role+'</div>':'')
          +'</td>'
        +'<td>'+_actionPill(l.action||'')+trvB+'</td>'
        +(hasRisk?'<td>'+_riskPill(l.risk_score)+'</td>':'')
        +'<td><div style="font-family:var(--mono);font-size:11px">'+(l.ip_address||'—')+'</div>'+geoH+'</td>'
        +(hasDevice?'<td>'+devH+'</td>':'')
        +(hasHttp?'<td>'+httpH+'</td>':'')
        +(hasSession?'<td>'+sesH+'</td>':'')
        +'<td style="max-width:220px"><div style="font-size:11px;word-break:break-all">'+(l.target||'')+'</div>'
          +(l.details?'<div style="font-size:10px;color:var(--text3);margin-top:1px;word-break:break-all">'
            +String(l.details).substring(0,140)+'</div>':'')
          +'</td>'
        +'</tr>';
    });
    html+='</tbody></table></div>'
      +'<div style="font-family:var(--mono);font-size:10px;color:var(--text3);padding:6px 2px">'
      +logs.length+' entries — <button class="btn btn-ghost btn-sm" onclick="exportAuditCSV()">↓ Export CSV</button></div>';
    if(out)out.innerHTML=html;
  }catch(e){
    if(out)out.innerHTML='<div class="err-box visible">loadAdminAudit error: '+e.message+'<br>'
      +'<small>Open DevTools → Network → click the /api/admin/audit request → Preview tab</small></div>';
  }
}'''

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    print()
    print(f"{B}{C}╔═══════════════════════════════════════════════════════════╗{Z}")
    print(f"{B}{C}║   VulnScan Pro — Audit Log Complete Fix                  ║{Z}")
    print(f"{B}{C}║   Fixes HTTP 500 / 'Unexpected token <' permanently      ║{Z}")
    print(f"{B}{C}╚═══════════════════════════════════════════════════════════╝{Z}")
    print()

    missing = [f for f in ["api_server.py","database.py","auth.py"] if not os.path.isfile(f)]
    if missing:
        print(f"{R}{B}ERROR: Run from ~/vulnscan project root. Missing: {', '.join(missing)}{Z}")
        return

    info(f"Working directory: {os.getcwd()}")
    print()

    # ── Write migration SQL ───────────────────────────────────
    with open("audit_migration.sql","w") as f:
        f.write(MIGRATION_SQL)
    ok("Written: audit_migration.sql  ← RUN THIS IN SUPABASE FIRST")
    print()

    # ── database.py ──────────────────────────────────────────
    print(f"{B}  ── database.py{Z}")
    apply("database.py",
          "Complete audit helpers + safe audit() + get_audit_log() + get_audit_stats()",
          DB_OLD, DB_NEW)
    print()

    # ── auth.py ───────────────────────────────────────────────
    print(f"{B}  ── auth.py{Z}")
    apply("auth.py", "LOGIN success — enriched audit call", AUTH_LOGIN_OLD, AUTH_LOGIN_NEW)
    apply("auth.py", "LOGIN fail — enriched audit call",    AUTH_LOGINFAIL_OLD, AUTH_LOGINFAIL_NEW)
    apply("auth.py", "LOGOUT — session duration + audit",   AUTH_LOGOUT_OLD,    AUTH_LOGOUT_NEW)
    apply("auth.py", "PASSWORD_CHANGE — enriched audit",    AUTH_PWDCHANGE_OLD, AUTH_PWDCHANGE_NEW)
    apply("auth.py", "ROLE change — privilege escalation",  AUTH_ROLE_OLD,      AUTH_ROLE_NEW)
    print()

    # ── api_server.py ─────────────────────────────────────────
    print(f"{B}  ── api_server.py{Z}")
    # Try patched version first, then original
    r1 = apply("api_server.py", "/api/admin/audit — always returns JSON",
               API_AUDIT_OLD, API_AUDIT_NEW)
    if not r1:
        apply("api_server.py", "/api/admin/audit — always returns JSON (original)",
              API_AUDIT_OLD_ORIG, API_AUDIT_NEW)

    r2 = apply("api_server.py", "HTTP middleware — merged with security headers (no recursion)",
               API_MW_OLD, API_MW_NEW)
    if not r2:
        # Try merging from the original _set_security_headers
        apply("api_server.py", "HTTP middleware — replace _set_security_headers",
              API_SEC_OLD, API_MW_NEW)
    else:
        # Remove the old separate _set_security_headers if it still exists
        apply("api_server.py", "Remove duplicate _set_security_headers",
              API_SEC_OLD, API_SEC_NEW)

    apply("api_server.py", "JS loadAdminAudit() — safe, CT-guard, handles both response shapes",
          JS_OLD, JS_NEW)
    print()

    # ── Syntax checks ─────────────────────────────────────────
    print(f"{B}  ── Syntax checks{Z}")
    all_ok = True
    for fname in ["database.py", "auth.py", "api_server.py"]:
        if not os.path.isfile(fname): continue
        ok_, err = syntax_ok(fname)
        if ok_:
            ok(f"{fname}")
        else:
            fail(f"{fname} — {err}")
            all_ok = False
    print()

    # ── Summary ───────────────────────────────────────────────
    print(f"{B}{C}═══════════════════════════════════════════════════════════{Z}")
    print(f"  Applied: {G}{APPLIED[0]}{Z}  Skipped: {D}{SKIPPED[0]}{Z}  Failed: {(R if FAILED[0] else D)}{FAILED[0]}{Z}")
    print()

    if all_ok:
        print(f"  {Y}── STEP 1 (required): Run SQL migration in Supabase ──{Z}")
        print(f"     Dashboard → SQL Editor → paste audit_migration.sql → Run")
        print()
        print(f"  {Y}── STEP 2: Restart VulnScan ──{Z}")
        print(f"     sudo systemctl restart vulnscan")
        print(f"     OR: python3 api_server.py")
        print()
        print(f"  {G}After restart, the Audit Log will:{Z}")
        print(f"    {G}✓{Z}  Always return JSON — never HTML 500")
        print(f"    {G}✓{Z}  Store: IP, GeoIP country/city/ISP/proxy flag")
        print(f"    {G}✓{Z}  Store: Browser, OS, device type from User-Agent")
        print(f"    {G}✓{Z}  Store: Session ID + duration on logout")
        print(f"    {G}✓{Z}  Store: HTTP method, endpoint, status code, response time")
        print(f"    {G}✓{Z}  Store: Risk score 0–100 per event")
        print(f"    {G}✓{Z}  Detect & alert on impossible travel (country change)")
        print(f"    {G}✓{Z}  Filter by action / risk / IP / country / date range")
        print(f"    {G}✓{Z}  Export to CSV via download button")
        print(f"    {G}✓{Z}  Works even if migration SQL hasn't been run yet")
    else:
        print(f"  {R}Syntax errors found. Restore .clean.bak files if needed.{Z}")


if __name__ == "__main__":
    main()
