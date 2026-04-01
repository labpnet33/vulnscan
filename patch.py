#!/usr/bin/env python3
"""
VulnScan Pro — database.py Supabase Patch
==========================================
Run from your vulnscan project root:

    python3 patch_database.py

What it does:
  1. Backs up your existing database.py → database.py.TIMESTAMP.bak
  2. Replaces database.py with a Supabase-backed version
  3. Keeps ALL function signatures identical — no changes needed in auth.py or api_server.py
  4. Runs a syntax check on the new file
  5. Tests connectivity to Supabase
"""

import os, sys, shutil, subprocess
from datetime import datetime

# ── colours ───────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"
ok   = lambda m: print(f"  {G}✓{X}  {m}")
fail = lambda m: print(f"  {R}✗{X}  {m}") or sys.exit(1)
warn = lambda m: print(f"  {Y}!{X}  {m}")
info = lambda m: print(f"  {C}→{X}  {m}")
hdr  = lambda m: print(f"\n{B}{C}── {m} ──{X}")

# ══════════════════════════════════════════════════════════════
# NEW database.py CONTENT
# ══════════════════════════════════════════════════════════════

NEW_DATABASE_PY = '''#!/usr/bin/env python3
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
    # Fetch current login_count first (Supabase can\'t do col=col+1 directly)
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

    # CVE sums — fetch all and sum client-side
    r2 = _sb().table("scans").select("total_cves,critical_cves").execute()
    rows = r2.data or []
    stats["total_cves"]    = sum(row.get("total_cves", 0) or 0 for row in rows)
    stats["critical_cves"] = sum(row.get("critical_cves", 0) or 0 for row in rows)

    # User counts
    ru = _sb().table("users").select(
        "id,is_active,is_verified", count="exact").execute()
    urows = ru.data or []
    stats["total_users"]    = ru.count or len(urows)
    stats["active_users"]   = sum(1 for u in urows if u.get("is_active"))
    stats["verified_users"] = sum(1 for u in urows if u.get("is_verified"))

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
'''

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — database.py Supabase Patch          ║" + X)
    print(B + C + "║   Backs up original · replaces with Supabase version  ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════╝" + X)
    print()

    # ── Verify project root ───────────────────────────────────
    if not os.path.isfile("database.py"):
        fail("Must be run from the VulnScan project root (database.py not found)")

    if not os.path.isfile("supabase_config.py"):
        fail("supabase_config.py not found — create it first!\n"
             "  See: https://github.com/your-repo or ask Claude for the file.")

    info(f"Project root : {os.getcwd()}")
    info(f"database.py  : found")
    info(f"supabase_config.py : found")
    print()

    # ── Step 1: Install dependencies ─────────────────────────
    hdr("STEP 1 — Install dependencies")
    for pkg in ["supabase", "python-dotenv"]:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg,
             "--break-system-packages", "-q"],
            capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"pip install {pkg}")
        else:
            warn(f"pip install {pkg} — {r.stderr.strip()[:120]}")

    # ── Step 2: Backup original ───────────────────────────────
    hdr("STEP 2 — Backup original database.py")
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"database.py.{ts}.bak"
    shutil.copy2("database.py", bak)
    ok(f"Backed up → {bak}")

    # ── Step 3: Write new database.py ────────────────────────
    hdr("STEP 3 — Write Supabase database.py")
    with open("database.py", "w", encoding="utf-8") as f:
        f.write(NEW_DATABASE_PY)
    ok("database.py written")

    # ── Step 4: Syntax check ──────────────────────────────────
    hdr("STEP 4 — Syntax check")
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", "database.py"],
        capture_output=True, text=True)
    if r.returncode == 0:
        ok("database.py syntax OK")
    else:
        warn(f"Syntax error:\n{r.stderr.strip()}")
        warn(f"Restoring backup: {bak}")
        shutil.copy2(bak, "database.py")
        fail("Patch failed — original restored from backup")

    # ── Step 5: Connectivity test ─────────────────────────────
    hdr("STEP 5 — Supabase connectivity test")
    try:
        sys.path.insert(0, os.getcwd())
        # Reload in case supabase_config was already imported
        import importlib
        if "supabase_config" in sys.modules:
            importlib.reload(sys.modules["supabase_config"])
        sc = importlib.import_module("supabase_config")
        client = sc.supabase()

        tables = ["users", "scans", "audit_log", "sessions"]
        all_ok = True
        for t in tables:
            try:
                client.table(t).select("id").limit(1).execute()
                ok(f"Table '{t}' reachable")
            except Exception as e:
                warn(f"Table '{t}' — {e}")
                all_ok = False

        if all_ok:
            ok("All tables reachable — Supabase fully connected!")
        else:
            warn("Some tables missing — run the SQL migration in Supabase dashboard")

    except Exception as e:
        warn(f"Connectivity test failed: {e}")
        warn("Check SUPABASE_SERVICE_KEY in your .env file")

    # ── Summary ───────────────────────────────────────────────
    print()
    print(B + C + "══════════════════════════════════════════════════════" + X)
    print(f"\n  {G}Done! What changed:{X}")
    print(f"    {G}✓{X}  database.py → Supabase backend (SQLite removed)")
    print(f"    {G}✓{X}  All function signatures preserved (no other files need changes)")
    print(f"    {G}✓{X}  Original backed up → {bak}")
    print()
    print(f"  {Y}Next steps:{X}")
    print(f"    1. Make sure .env has SUPABASE_SERVICE_KEY set")
    print(f"    2. Restart server: pkill -f api_server.py && python3 api_server.py")
    print(f"    3. Register a user and check Supabase dashboard")
    print()
    print(f"  {C}To rollback:{X}  cp {bak} database.py")
    print()


if __name__ == "__main__":
    main()
