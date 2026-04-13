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

def audit(user_id, username, action, target="", ip="", ua="", details=""):
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
    return q.execute().data or []

# ── Auto-init on import ────────────────────────────────────────
init_db()
