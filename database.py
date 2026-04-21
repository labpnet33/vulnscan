#!/usr/bin/env python3
"""
Supabase-backed database manager for VulnScan Pro.
Drop-in replacement for the original SQLite database.py.
All public function signatures are IDENTICAL.

Tables required in Supabase:
  users, scans, audit_log, sessions
"""
import json, os
from datetime import datetime

# ── Load .env if available ─────────────────────────────────────
try:
    from dotenv import load_dotenv
    _env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(_env):
        load_dotenv(_env)
except ImportError:
    pass

# ── Supabase client ────────────────────────────────────────────
def _sb():
    from supabase_config import supabase
    return supabase()

def _sb_retry(fn, retries=2):
    """Execute fn(client) with automatic reconnect on failure."""
    import time as _t3
    from supabase_config import supabase, reset_client
    for attempt in range(retries + 1):
        try:
            return fn(supabase())
        except Exception as e:
            err = str(e).lower()
            # Connection-level errors: reset and retry
            if attempt < retries and any(
                kw in err for kw in ("connection", "timeout", "reset", "closed", "eof")
            ):
                reset_client()
                _t3.sleep(0.5 * (attempt + 1))
                continue
            raise

def _now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

def _row(resp):
    """Return first row from Supabase response or None."""
    data = resp.data
    return data[0] if data else None

# ══════════════════════════════════════════════════════════════
# INIT
# ══════════════════════════════════════════════════════════════

def get_db():
    """Compatibility shim — returns Supabase client."""
    return _sb()

def init_db():
    """Verify Supabase connectivity (replaces SQLite table creation)."""
    try:
        _sb().table("users").select("id").limit(1).execute()
        print("[*] Supabase connection verified — database ready.")
    except Exception as e:
        print(f"[!] Supabase connection failed: {e}")
        print("[!] Make sure SUPABASE_SERVICE_KEY is set in your .env")
        raise

# ══════════════════════════════════════════════════════════════
# USER FUNCTIONS — signatures identical to original
# ══════════════════════════════════════════════════════════════

def create_user(username, email, password_hash, full_name="", role="user",
                is_verified=0, verify_token="", verify_expires=None):
    try:
        _sb().table("users").insert({
            "username":      username.lower().strip(),
            "email":         email.lower().strip(),
            "password_hash": password_hash,
            "full_name":     full_name,
            "role":          role,
            "is_verified":   is_verified,
            "verify_token":  verify_token or None,
            "verify_expires": verify_expires,
            "created_at":    _now(),
        }).execute()
        return True, "User created"
    except Exception as e:
        err = str(e)
        if "username" in err.lower() and ("unique" in err.lower() or "duplicate" in err.lower()):
            return False, "Username already taken"
        if "email" in err.lower() and ("unique" in err.lower() or "duplicate" in err.lower()):
            return False, "Email already registered"
        return False, err

def get_user_by_id(uid):
    r = _sb().table("users").select("*").eq("id", uid).limit(1).execute()
    return _row(r)

def get_user_by_username(username):
    r = _sb().table("users").select("*").eq(
        "username", username.lower().strip()).limit(1).execute()
    return _row(r)

def get_user_by_email(email):
    r = _sb().table("users").select("*").eq(
        "email", email.lower().strip()).limit(1).execute()
    return _row(r)

def get_user_by_token(token, token_type="verify"):
    col = "verify_token" if token_type == "verify" else "reset_token"
    r = _sb().table("users").select("*").eq(col, token).limit(1).execute()
    return _row(r)

def verify_user(token):
    user = get_user_by_token(token, "verify")
    if not user:
        return False
    expires = user.get("verify_expires")
    if expires:
        try:
            if datetime.utcnow() > datetime.fromisoformat(expires):
                return False
        except Exception:
            return False
    _sb().table("users").update({
        "is_verified":   1,
        "verify_token":  None,
        "verify_expires": None,
    }).eq("id", user["id"]).execute()
    return True

def update_user(uid, **kwargs):
    if not kwargs:
        return
    _sb().table("users").update(kwargs).eq("id", uid).execute()

def update_last_login(uid, ip=""):
    # Fetch current login_count first (Supabase can't do col=col+1 directly)
    r = _sb().table("users").select("login_count").eq("id", uid).limit(1).execute()
    row = _row(r)
    current = (row.get("login_count") or 0) if row else 0
    _sb().table("users").update({
        "last_login":  _now(),
        "login_count": current + 1,
    }).eq("id", uid).execute()

def get_all_users(limit=100):
    r = _sb().table("users").select(
        "id,username,email,role,is_verified,is_active,"
        "created_at,last_login,login_count,full_name"
    ).order("id", desc=True).limit(limit).execute()
    return r.data or []

def toggle_user_active(uid):
    r = _sb().table("users").select("is_active").eq("id", uid).limit(1).execute()
    row = _row(r)
    if row is None:
        return
    new_val = 0 if row.get("is_active") else 1
    _sb().table("users").update({"is_active": new_val}).eq("id", uid).execute()

def set_user_role(uid, role):
    _sb().table("users").update({"role": role}).eq("id", uid).execute()

def delete_user(uid):
    _sb().table("users").delete().eq("id", uid).execute()

# ══════════════════════════════════════════════════════════════
# SCAN FUNCTIONS — signatures identical to original
# ══════════════════════════════════════════════════════════════

def save_scan(target, result, user_id=None, modules=""):
    s = result.get("summary", {})
    r = _sb().table("scans").insert({
        "user_id":       user_id,
        "target":        target,
        "scan_time":     result.get("scan_time", _now()),
        "result":        json.dumps(result),
        "open_ports":    s.get("open_ports", 0),
        "total_cves":    s.get("total_cves", 0),
        "critical_cves": s.get("critical_cves", 0),
        "modules":       modules,
    }).execute()
    row = _row(r)
    return row["id"] if row else None

def get_history(limit=20, user_id=None):
    q = _sb().table("scans").select(
        "id,target,scan_time,open_ports,total_cves,critical_cves,modules"
    ).order("id", desc=True).limit(limit)
    if user_id is not None:
        q = q.eq("user_id", user_id)
    return q.execute().data or []

def get_scan_by_id(sid, user_id=None):
    q = _sb().table("scans").select("result").eq("id", sid).limit(1)
    if user_id:
        q = q.eq("user_id", user_id)
    row = _row(q.execute())
    return json.loads(row["result"]) if row else None

def get_scan_stats():
    stats = {}

    # Total scans
    r = _sb().table("scans").select("id", count="exact").execute()
    stats["total_scans"] = r.count or 0

    # CVE sums — page through rows to avoid loading whole table into memory
    stats["total_cves"] = 0
    stats["critical_cves"] = 0
    page_size = 1000
    start = 0
    while True:
        chunk = _sb().table("scans").select("total_cves,critical_cves").range(
            start, start + page_size - 1
        ).execute().data or []
        if not chunk:
            break
        stats["total_cves"] += sum(row.get("total_cves", 0) or 0 for row in chunk)
        stats["critical_cves"] += sum(row.get("critical_cves", 0) or 0 for row in chunk)
        if len(chunk) < page_size:
            break
        start += page_size

    # User counts — page to reduce peak memory
    ru = _sb().table("users").select("id", count="exact").limit(1).execute()
    stats["total_users"] = ru.count or 0
    stats["active_users"] = 0
    stats["verified_users"] = 0
    start = 0
    while True:
        urows = _sb().table("users").select("is_active,is_verified").range(
            start, start + page_size - 1
        ).execute().data or []
        if not urows:
            break
        stats["active_users"] += sum(1 for u in urows if u.get("is_active"))
        stats["verified_users"] += sum(1 for u in urows if u.get("is_verified"))
        if len(urows) < page_size:
            break
        start += page_size

    # Scans today
    today = datetime.utcnow().strftime("%Y-%m-%d")
    rt = _sb().table("scans").select("id", count="exact").like(
        "scan_time", f"{today}%").execute()
    stats["scans_today"] = rt.count or 0

    return stats

# ══════════════════════════════════════════════════════════════
# AUDIT LOG — signatures identical to original
# ══════════════════════════════════════════════════════════════

# ── Audit column discovery (run once, cached) ─────────────────────
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
    m = _re2.search(r"(?:Chrome|Firefox|Safari|Edg|OPR)/([\d.]+)", ua)
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
                prev = _sb().table("audit_log")                     .select("geo_country_code")                     .eq("user_id", user_id)                     .not_.is_("geo_country_code", "null")                     .order("id", desc=True)                     .limit(1)                     .execute().data
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
        print(f"[!] Audit log failed: {e}")

def get_audit_log(limit=100, user_id=None, action_filter=None,
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
        rows = _sb().table("audit_log")             .select("action,risk_score,geo_country_code,ua_device,timestamp")             .order("id", desc=True).limit(5000).execute().data or []

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
        return {"error": str(e)}

# ── Auto-init on import ────────────────────────────────────────
init_db()
