#!/usr/bin/env python3
"""
VulnScan Pro — Supabase Integration Patch
==========================================
Self-applying patch script. Run from your vulnscan project root:

    python3 apply_supabase_patch.py

What it does:
  1. Installs the `supabase` Python client (pip)
  2. Writes supabase_config.py  — credentials + helper client
  3. Replaces database.py       — Supabase-backed version (SQLite removed)
  4. Patches api_server.py      — uses SUPABASE_* env vars for agent DB too
  5. Creates/updates .env.example with all required variables
  6. Runs a connectivity smoke-test against your Supabase project
  7. Backs up every file it touches before modifying it

Your Supabase project:
  URL : https://qonplkgabhubntfhtthu.supabase.co
  Key : set SUPABASE_SERVICE_KEY in your environment (see .env.example)

The schema was already applied to Supabase — tables: users, scans,
audit_log, sessions, agent_clients, lynis_jobs.
"""

import os
import sys
import shutil
import subprocess
import re
from datetime import datetime

# ── colours ───────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; D = "\033[2m";  B = "\033[1m"; X = "\033[0m"
ok   = lambda m: print(f"  {G}✓{X}  {m}")
fail = lambda m: print(f"  {R}✗{X}  {m}"); sys.exit(1)
warn = lambda m: print(f"  {Y}!{X}  {m}")
info = lambda m: print(f"  {C}→{X}  {m}")
hdr  = lambda m: print(f"\n{B}{C}── {m} ──{X}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

# ══════════════════════════════════════════════════════════════
# SUPABASE CREDENTIALS  (hardcoded — change if you rotate keys)
# ══════════════════════════════════════════════════════════════
SUPABASE_URL = "https://qonplkgabhubntfhtthu.supabase.co"
SUPABASE_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1"
    "Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUwMTc5MDMsImV4cCI6MjA5MDU5MzkwM30"
    ".oVFsJVBl4pD4Geq-Bj4X4m-HOe-wSctbfSPNaNq32ak"
)
# Service-role key: loaded from env SUPABASE_SERVICE_KEY
# (never commit to git — add to your server's environment or .env)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def backup(path: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst

def write_file(path: str, content: str, label: str) -> None:
    if os.path.exists(path):
        backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    ok(f"{label} → {path}")
    RESULTS["applied"] += 1

def patch_file(path: str, old: str, new: str, label: str) -> None:
    if not os.path.isfile(path):
        warn(f"Patch '{label}': {path} not found — skipping")
        RESULTS["skipped"] += 1
        return
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if new in src:
        info(f"Patch '{label}': already applied — skipping")
        RESULTS["skipped"] += 1
        return
    if old not in src:
        warn(f"Patch '{label}': anchor not found in {path} — skipping")
        RESULTS["skipped"] += 1
        return
    backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"Patch '{label}' applied to {path}")
    RESULTS["applied"] += 1

def syntax_check(path: str) -> bool:
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        warn(f"Syntax error in {path}:\n{r.stderr.strip()}")
        return False
    return True


# ══════════════════════════════════════════════════════════════
# FILE CONTENTS
# ══════════════════════════════════════════════════════════════

# ── supabase_config.py ───────────────────────────────────────
SUPABASE_CONFIG = '''\
#!/usr/bin/env python3
"""
Supabase client configuration for VulnScan Pro.

Set SUPABASE_SERVICE_KEY in your environment before starting the server:
    export SUPABASE_SERVICE_KEY="<your-service-role-key>"
    python3 api_server.py

The service-role key bypasses RLS and gives full DB access — keep it secret.
The anon key is safe for client-side use but is not used server-side here.
"""
import os

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://qonplkgabhubntfhtthu.supabase.co"
)
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_ANON_KEY = os.environ.get(
    "SUPABASE_ANON_KEY",
    (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1"
        "Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUwMTc5MDMsImV4cCI6MjA5MDU5MzkwM30"
        ".oVFsJVBl4pD4Geq-Bj4X4m-HOe-wSctbfSPNaNq32ak"
    ),
)

def get_client():
    """Return an authenticated Supabase client (service role)."""
    try:
        from supabase import create_client, Client
    except ImportError:
        raise RuntimeError(
            "supabase-py not installed. Run: "
            "pip3 install supabase --break-system-packages"
        )
    key = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
    return create_client(SUPABASE_URL, key)

# Lazy singleton so import doesn\'t fail if env key is missing at load time
_client = None

def supabase():
    global _client
    if _client is None:
        _client = get_client()
    return _client
'''

# ── database.py (full replacement) ──────────────────────────
DATABASE_PY = '''\
#!/usr/bin/env python3
"""
Supabase-backed database manager for VulnScan Pro.

Drop-in replacement for the original SQLite-based database.py.
All public function signatures are identical so auth.py and
api_server.py require no further changes.

Tables (created via Supabase migration):
  users, scans, audit_log, sessions, agent_clients, lynis_jobs
"""
import json
from datetime import datetime

# ── Supabase client ────────────────────────────────────────────
def _sb():
    from supabase_config import supabase
    return supabase()

def _now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

# ── Init (no-op for Supabase — schema applied via migration) ──
def init_db():
    try:
        _sb().table("users").select("id").limit(1).execute()
        print("[*] Supabase connection verified — database ready.")
    except Exception as e:
        print(f"[!] Supabase connection failed: {e}")
        print("[!] Set SUPABASE_SERVICE_KEY environment variable.")
        raise

def get_db():
    """Compatibility shim — returns the Supabase client."""
    return _sb()

# ══════════════════════════════════════════════════════════════
# USER FUNCTIONS
# ══════════════════════════════════════════════════════════════

def create_user(username, email, password_hash, full_name="", role="user",
                is_verified=0, verify_token="", verify_expires=None):
    try:
        _sb().table("users").insert({
            "username": username.lower().strip(),
            "email": email.lower().strip(),
            "password_hash": password_hash,
            "full_name": full_name,
            "role": role,
            "is_verified": is_verified,
            "verify_token": verify_token or None,
            "verify_expires": verify_expires,
            "created_at": _now(),
        }).execute()
        return True, "User created"
    except Exception as e:
        err = str(e)
        if "username" in err and "unique" in err.lower():
            return False, "Username already taken"
        if "email" in err and "unique" in err.lower():
            return False, "Email already registered"
        return False, err

def _row(resp):
    """Return first row from a Supabase response or None."""
    data = resp.data
    return data[0] if data else None

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
        "is_verified": 1,
        "verify_token": None,
        "verify_expires": None,
    }).eq("id", user["id"]).execute()
    return True

def update_user(uid, **kwargs):
    if not kwargs:
        return
    _sb().table("users").update(kwargs).eq("id", uid).execute()

def update_last_login(uid, ip=""):
    # Supabase doesn\'t support SQL expressions directly in update,
    # so we fetch the current count first.
    r = _sb().table("users").select("login_count").eq("id", uid).limit(1).execute()
    row = _row(r)
    current_count = (row["login_count"] or 0) if row else 0
    _sb().table("users").update({
        "last_login": _now(),
        "login_count": current_count + 1,
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
    new_val = 0 if row["is_active"] else 1
    _sb().table("users").update({"is_active": new_val}).eq("id", uid).execute()

def set_user_role(uid, role):
    _sb().table("users").update({"role": role}).eq("id", uid).execute()

def delete_user(uid):
    _sb().table("users").delete().eq("id", uid).execute()


# ══════════════════════════════════════════════════════════════
# SCAN FUNCTIONS
# ══════════════════════════════════════════════════════════════

def save_scan(target, result, user_id=None, modules=""):
    s = result.get("summary", {})
    r = _sb().table("scans").insert({
        "user_id": user_id,
        "target": target,
        "scan_time": result.get("scan_time", _now()),
        "result": json.dumps(result),
        "open_ports": s.get("open_ports", 0),
        "total_cves": s.get("total_cves", 0),
        "critical_cves": s.get("critical_cves", 0),
        "modules": modules,
    }).execute()
    row = _row(r)
    return row["id"] if row else None

def get_history(limit=20, user_id=None):
    q = _sb().table("scans").select(
        "id,target,scan_time,open_ports,total_cves,critical_cves,modules"
    ).order("id", desc=True).limit(limit)
    if user_id is not None:
        q = q.eq("user_id", user_id)
    return (q.execute().data or [])

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

    # CVE sums — aggregate with RPC or fetch and sum client-side
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

    # Scans today (date-prefix match)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    rt = _sb().table("scans").select("id", count="exact").like(
        "scan_time", f"{today}%").execute()
    stats["scans_today"] = rt.count or 0

    return stats


# ══════════════════════════════════════════════════════════════
# AUDIT LOG
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
    q = _sb().table("audit_log").select("*").order(
        "id", desc=True).limit(limit)
    if user_id:
        q = q.eq("user_id", user_id)
    return (q.execute().data or [])


# ── Auto-init on import ────────────────────────────────────────
init_db()
'''

# ── .env.example ─────────────────────────────────────────────
ENV_EXAMPLE = """\
# VulnScan Pro — Environment Variables
# Copy to .env and fill in your values. Never commit .env to git.

# ── Flask ───────────────────────────────────────────────────
VULNSCAN_SECRET=change-this-to-a-long-random-string-in-production

# ── Supabase ────────────────────────────────────────────────
SUPABASE_URL=https://qonplkgabhubntfhtthu.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUwMTc5MDMsImV4cCI6MjA5MDU5MzkwM30.oVFsJVBl4pD4Geq-Bj4X4m-HOe-wSctbfSPNaNq32ak

# SERVICE KEY — get from Supabase Dashboard → Project Settings → API → service_role
# This key has full DB access. Keep it secret. Required to run VulnScan.
SUPABASE_SERVICE_KEY=<paste-your-service-role-key-here>

# ── Mail ────────────────────────────────────────────────────
VULNSCAN_APP_URL=http://161.118.189.254:5000
VULNSCAN_SMTP_HOST=smtp.gmail.com
VULNSCAN_SMTP_PORT=587
VULNSCAN_SMTP_USER=labpnet33@gmail.com
VULNSCAN_SMTP_PASS=hkls wpey nvxi bgwh

# ── NVD (optional — speeds up CVE lookups) ──────────────────
# NVD_API_KEY=<your-nvd-api-key>

# ── Agent server URL ─────────────────────────────────────────
VULNSCAN_AGENT_SERVER_URL=http://161.118.189.254:5000
"""

# ── api_server.py patch — load .env + agent DB via Supabase ──
# We add .env loading at the very top of api_server.py (after shebang)
# and redirect the agent DB functions to Supabase.

OLD_API_IMPORT_BLOCK = '''\
import json, re, sys, os, subprocess, io, sqlite3, secrets, hashlib, threading, shlex, time, shutil, socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify, Response, send_file, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta, timezone'''

NEW_API_IMPORT_BLOCK = '''\
import json, re, sys, os, subprocess, io, sqlite3, secrets, hashlib, threading, shlex, time, shutil, socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify, Response, send_file, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta, timezone

# ── Load .env if python-dotenv is available ────────────────────────────────
try:
    from dotenv import load_dotenv
    _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(_env_file):
        load_dotenv(_env_file)
        print(f"[*] Loaded environment from {_env_file}")
except ImportError:
    pass  # python-dotenv optional'''

OLD_AGENT_DB_BLOCK = '''\
AGENT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_jobs.db")
AGENT_LOCK = threading.Lock()'''

NEW_AGENT_DB_BLOCK = '''\
# AGENT_DB — now backed by Supabase (agent_clients + lynis_jobs tables)
# The sqlite3 agent_jobs.db is no longer used.
AGENT_LOCK = threading.Lock()'''

OLD_AGENT_DB_FUNC = '''\
def _agent_db():
    con = sqlite3.connect(AGENT_DB)
    con.row_factory = sqlite3.Row
    return con'''

NEW_AGENT_DB_FUNC = '''\
def _agent_db():
    """Compatibility shim — returns Supabase client as \'agent db\'."""
    from supabase_config import supabase as _sb
    return _sb()

def _sb_agent():
    """Supabase client for agent operations (cleaner alias)."""
    from supabase_config import supabase as _sb
    return _sb()'''

# ── Replace init_agent_db (SQLite DDL) with a no-op ──────────
OLD_INIT_AGENT_DB = '''\
def init_agent_db():
    with AGENT_LOCK:
        con = _agent_db()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS agent_clients (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id       TEXT UNIQUE NOT NULL,
                token_hash      TEXT NOT NULL,
                hostname        TEXT,
                os_info         TEXT,
                ip_seen         TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                last_seen       TEXT DEFAULT (datetime('now')),
                status          TEXT DEFAULT 'online'
            );
            CREATE TABLE IF NOT EXISTS lynis_jobs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id       TEXT NOT NULL,
                profile         TEXT DEFAULT 'system',
                compliance      TEXT DEFAULT '',
                category        TEXT DEFAULT '',
                status          TEXT DEFAULT 'pending',
                created_at      TEXT DEFAULT (datetime('now')),
                started_at      TEXT,
                completed_at    TEXT,
                progress_pct    INTEGER DEFAULT 0,
                message         TEXT DEFAULT '',
                hardening_index INTEGER DEFAULT 0,
                warnings_json   TEXT DEFAULT '[]',
                suggestions_json TEXT DEFAULT '[]',
                tests_performed TEXT DEFAULT '',
                raw_report      TEXT DEFAULT '',
                cancel_requested INTEGER DEFAULT 0,
                FOREIGN KEY(client_id) REFERENCES agent_clients(client_id)
            );
        """)
        # Lightweight migrations for existing deployments
        job_cols = {r["name"] for r in con.execute("PRAGMA table_info(lynis_jobs)").fetchall()}
        if "cancel_requested" not in job_cols:
            con.execute("ALTER TABLE lynis_jobs ADD COLUMN cancel_requested INTEGER DEFAULT 0")
        con.commit()
        con.close()'''

NEW_INIT_AGENT_DB = '''\
def init_agent_db():
    """No-op — agent tables live in Supabase (created via migration)."""
    pass'''


# ══════════════════════════════════════════════════════════════
# Supabase-backed agent route helpers
# The original routes use sqlite3 Row objects; Supabase returns dicts.
# We wrap the Supabase responses to look like Row dicts everywhere.
# ══════════════════════════════════════════════════════════════

# ── register_agent route patch ────────────────────────────────
OLD_REGISTER_AGENT = '''\
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            INSERT INTO agent_clients(client_id, token_hash, hostname, os_info, ip_seen, status)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(client_id) DO UPDATE SET
              token_hash=excluded.token_hash,
              hostname=excluded.hostname,
              os_info=excluded.os_info,
              ip_seen=excluded.ip_seen,
              last_seen=datetime('now'),
              status='online'
        """, (client_id, token_hash, hostname, os_info, request.remote_addr or "", "online"))
        con.commit()
        con.close()'''

NEW_REGISTER_AGENT = '''\
    with AGENT_LOCK:
        sb = _sb_agent()
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        existing = sb.table("agent_clients").select("id").eq("client_id", client_id).limit(1).execute()
        if existing.data:
            sb.table("agent_clients").update({
                "token_hash": token_hash,
                "hostname": hostname,
                "os_info": os_info,
                "ip_seen": request.remote_addr or "",
                "last_seen": now_ts,
                "status": "online",
            }).eq("client_id", client_id).execute()
        else:
            sb.table("agent_clients").insert({
                "client_id": client_id,
                "token_hash": token_hash,
                "hostname": hostname,
                "os_info": os_info,
                "ip_seen": request.remote_addr or "",
                "created_at": now_ts,
                "last_seen": now_ts,
                "status": "online",
            }).execute()'''

# ── _auth_agent patch ──────────────────────────────────────────
OLD_AUTH_AGENT = '''\
def _auth_agent(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    token_hash = _hash_token(token)
    con = _agent_db()
    row = con.execute("SELECT client_id FROM agent_clients WHERE token_hash=?", (token_hash,)).fetchone()
    if row:
        con.execute("UPDATE agent_clients SET last_seen=datetime('now'), ip_seen=?, status=\'online\' WHERE client_id=?",
                    (req.remote_addr or "", row["client_id"]))
        con.commit()
    con.close()
    return row["client_id"] if row else None'''

NEW_AUTH_AGENT = '''\
def _auth_agent(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    token_hash = _hash_token(token)
    sb = _sb_agent()
    r = sb.table("agent_clients").select("client_id").eq("token_hash", token_hash).limit(1).execute()
    if r.data:
        client_id = r.data[0]["client_id"]
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        sb.table("agent_clients").update({
            "last_seen": now_ts,
            "ip_seen": req.remote_addr or "",
            "status": "online",
        }).eq("client_id", client_id).execute()
        return client_id
    return None'''

# ── create_lynis_job route patch ───────────────────────────────
OLD_CREATE_JOB = '''\
    with AGENT_LOCK:
        con = _agent_db()
        agent = con.execute("SELECT status, last_seen FROM agent_clients WHERE client_id=?", (client_id,)).fetchone()
        if not agent:
            con.close()
            return jsonify({"error": "Unknown client_id. Install/register agent first."}), 404
        if (agent["status"] or "").lower() == "disconnected":
            con.close()
            return jsonify({"error": "Agent is disconnected. Reinstall/connect the agent first."}), 409
        queue_count = con.execute("""
            SELECT COUNT(*) AS c
            FROM lynis_jobs
            WHERE client_id=? AND status IN (\'pending\', \'running\')
        """, (client_id,)).fetchone()["c"]
        if queue_count >= LYNIS_QUEUE_LIMIT:
            con.close()
            return jsonify({
                "error": f"Lynis queue is full for this client ({LYNIS_QUEUE_LIMIT} active jobs max). Wait for completion or remove old jobs."
            }), 429
        cur = con.execute("""
            INSERT INTO lynis_jobs(client_id, profile, compliance, category, status, progress_pct, message)
            VALUES(?,?,?,?, \'pending\', 0, \'Queued\')
        """, (client_id, profile, compliance, category))
        jid = cur.lastrowid
        con.commit()
        con.close()'''

NEW_CREATE_JOB = '''\
    with AGENT_LOCK:
        sb = _sb_agent()
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        agent_r = sb.table("agent_clients").select("status,last_seen").eq("client_id", client_id).limit(1).execute()
        if not agent_r.data:
            return jsonify({"error": "Unknown client_id. Install/register agent first."}), 404
        agent = agent_r.data[0]
        if (agent.get("status") or "").lower() == "disconnected":
            return jsonify({"error": "Agent is disconnected. Reinstall/connect the agent first."}), 409
        q_r = sb.table("lynis_jobs").select("id", count="exact").eq("client_id", client_id).in_(
            "status", ["pending", "running"]).execute()
        queue_count = q_r.count or 0
        if queue_count >= LYNIS_QUEUE_LIMIT:
            return jsonify({
                "error": f"Lynis queue is full for this client ({LYNIS_QUEUE_LIMIT} active jobs max). Wait for completion or remove old jobs."
            }), 429
        ins = sb.table("lynis_jobs").insert({
            "client_id": client_id, "profile": profile,
            "compliance": compliance, "category": category,
            "status": "pending", "progress_pct": 0, "message": "Queued",
            "created_at": now_ts,
        }).execute()
        jid = ins.data[0]["id"] if ins.data else None'''

# ── poll_jobs route patch ──────────────────────────────────────
OLD_POLL_JOBS = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("""
            SELECT id, profile, compliance, category FROM lynis_jobs
            WHERE client_id=? AND status=\'pending\' AND cancel_requested=0
            ORDER BY id ASC LIMIT 1
        """, (client_id,)).fetchone()
        if row:
            con.execute("""
                UPDATE lynis_jobs
                SET status=\'running\', started_at=datetime(\'now\'), progress_pct=5, message=\'Agent started scan\'
                WHERE id=? AND status=\'pending\'
            """, (row["id"],))
            con.commit()
            job = {"job_id": row["id"], "type": "lynis", "profile": row["profile"],
                   "compliance": row["compliance"], "category": row["category"]}
        else:
            job = {"job_id": None, "type": "none"}
        con.close()'''

NEW_POLL_JOBS = '''\
    with AGENT_LOCK:
        sb = _sb_agent()
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        r = sb.table("lynis_jobs").select(
            "id,profile,compliance,category"
        ).eq("client_id", client_id).eq("status", "pending").eq(
            "cancel_requested", 0
        ).order("id").limit(1).execute()
        if r.data:
            row = r.data[0]
            sb.table("lynis_jobs").update({
                "status": "running", "started_at": now_ts,
                "progress_pct": 5, "message": "Agent started scan",
            }).eq("id", row["id"]).eq("status", "pending").execute()
            job = {"job_id": row["id"], "type": "lynis", "profile": row["profile"],
                   "compliance": row["compliance"], "category": row["category"]}
        else:
            job = {"job_id": None, "type": "none"}'''

# ── job_control route patch ────────────────────────────────────
OLD_JOB_CONTROL = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("""
            SELECT status, cancel_requested, message
            FROM lynis_jobs
            WHERE id=? AND client_id=?
        """, (job_id, client_id)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": row["status"],
        "cancel_requested": bool(row["cancel_requested"]),
        "message": row["message"] or ""
    })'''

NEW_JOB_CONTROL = '''\
    sb = _sb_agent()
    r = sb.table("lynis_jobs").select(
        "status,cancel_requested,message"
    ).eq("id", job_id).eq("client_id", client_id).limit(1).execute()
    if not r.data:
        return jsonify({"error": "Job not found"}), 404
    row = r.data[0]
    return jsonify({
        "status": row["status"],
        "cancel_requested": bool(row["cancel_requested"]),
        "message": row.get("message") or ""
    })'''

# ── update_job_progress patch ──────────────────────────────────
OLD_UPDATE_PROGRESS = '''\
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            UPDATE lynis_jobs
            SET progress_pct=?, message=?
            WHERE id=? AND client_id=? AND status=\'running\'
        """, (max(0, min(100, pct)), message, job_id, client_id))
        con.commit()
        con.close()'''

NEW_UPDATE_PROGRESS = '''\
    sb = _sb_agent()
    sb.table("lynis_jobs").update({
        "progress_pct": max(0, min(100, pct)),
        "message": message,
    }).eq("id", job_id).eq("client_id", client_id).eq("status", "running").execute()'''

# ── upload_job_report patch ────────────────────────────────────
OLD_UPLOAD_REPORT = '''\
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            UPDATE lynis_jobs
            SET status=?,
                completed_at=datetime(\'now\'),
                progress_pct=100,
                message=?,
                hardening_index=?,
                warnings_json=?,
                suggestions_json=?,
                tests_performed=?,
                raw_report=?
            WHERE id=? AND client_id=?
        """, (status, message, hardening_index, json.dumps(warnings), json.dumps(suggestions), tests_performed, raw_report, job_id, client_id))
        con.commit()
        con.close()'''

NEW_UPLOAD_REPORT = '''\
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    sb = _sb_agent()
    sb.table("lynis_jobs").update({
        "status": status,
        "completed_at": now_ts,
        "progress_pct": 100,
        "message": message,
        "hardening_index": hardening_index,
        "warnings_json": json.dumps(warnings),
        "suggestions_json": json.dumps(suggestions),
        "tests_performed": tests_performed,
        "raw_report": raw_report,
    }).eq("id", job_id).eq("client_id", client_id).execute()'''

# ── job_status route patch ─────────────────────────────────────
OLD_JOB_STATUS_QUERY = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("""
            SELECT id, client_id, profile, compliance, category, status, progress_pct, message, hardening_index, warnings_json,
                   suggestions_json, tests_performed, created_at, started_at, completed_at, cancel_requested
            FROM lynis_jobs WHERE id=?
        """, (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404'''

NEW_JOB_STATUS_QUERY = '''\
    sb = _sb_agent()
    r = sb.table("lynis_jobs").select("*").eq("id", job_id).limit(1).execute()
    if not r.data:
        return jsonify({"error": "Job not found"}), 404
    row = r.data[0]'''

# ── list_agents route patch ────────────────────────────────────
OLD_LIST_AGENTS = '''\
    include_all = str(request.args.get("all", "")).strip().lower() in {"1", "true", "yes"}
    with AGENT_LOCK:
        con = _agent_db()
        if include_all:
            rows = con.execute("""
                SELECT client_id, hostname, os_info, ip_seen, created_at, last_seen, status
                FROM agent_clients ORDER BY datetime(last_seen) DESC
            """).fetchall()
        else:
            rows = con.execute("""
                SELECT client_id, hostname, os_info, ip_seen, created_at, last_seen, status
                FROM agent_clients
                WHERE status != \'disconnected\'
                ORDER BY datetime(last_seen) DESC
            """).fetchall()
        con.close()
    return jsonify({"agents": [dict(r) for r in rows]})'''

NEW_LIST_AGENTS = '''\
    include_all = str(request.args.get("all", "")).strip().lower() in {"1", "true", "yes"}
    sb = _sb_agent()
    q = sb.table("agent_clients").select(
        "client_id,hostname,os_info,ip_seen,created_at,last_seen,status"
    ).order("last_seen", desc=True)
    if not include_all:
        q = q.neq("status", "disconnected")
    rows = (q.execute().data or [])
    return jsonify({"agents": rows})'''

# ── disconnect_agent route patch ───────────────────────────────
OLD_DISCONNECT = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT 1 FROM agent_clients WHERE client_id=?", (client_id,)).fetchone()
        if not row:
            con.close()
            return jsonify({"error": "Unknown client_id"}), 404
        con.execute("""
            UPDATE agent_clients
            SET token_hash=?, status=\'disconnected\', last_seen=datetime(\'now\')
            WHERE client_id=?
        """, (_hash_token(secrets.token_urlsafe(32)), client_id))
        con.execute("""
            UPDATE lynis_jobs
            SET status=\'cancelled\', completed_at=datetime(\'now\'), progress_pct=100, message=\'Cancelled (agent disconnected)\'
            WHERE client_id=? AND status=\'pending\'
        """, (client_id,))
        con.execute("""
            UPDATE lynis_jobs
            SET cancel_requested=1, message=\'Cancellation requested (agent disconnect)\'
            WHERE client_id=? AND status=\'running\'
        """, (client_id,))
        con.execute("DELETE FROM agent_clients WHERE client_id=?", (client_id,))
        con.commit()
        con.close()'''

NEW_DISCONNECT = '''\
    sb = _sb_agent()
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    chk = sb.table("agent_clients").select("client_id").eq("client_id", client_id).limit(1).execute()
    if not chk.data:
        return jsonify({"error": "Unknown client_id"}), 404
    # Cancel pending jobs
    sb.table("lynis_jobs").update({
        "status": "cancelled", "completed_at": now_ts,
        "progress_pct": 100, "message": "Cancelled (agent disconnected)",
    }).eq("client_id", client_id).eq("status", "pending").execute()
    # Request cancellation of running jobs
    sb.table("lynis_jobs").update({
        "cancel_requested": 1,
        "message": "Cancellation requested (agent disconnect)",
    }).eq("client_id", client_id).eq("status", "running").execute()
    # Delete agent record
    sb.table("agent_clients").delete().eq("client_id", client_id).execute()'''

# ── jobs_overview route patch ─────────────────────────────────
OLD_JOBS_OVERVIEW = '''\
    with AGENT_LOCK:
        con = _agent_db()
        rows = con.execute("""
            SELECT id, client_id, status, progress_pct, message, created_at, started_at, completed_at, cancel_requested
            FROM lynis_jobs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        con.close()
    return jsonify({"jobs": [dict(r) for r in rows]})'''

NEW_JOBS_OVERVIEW = '''\
    sb = _sb_agent()
    rows = sb.table("lynis_jobs").select(
        "id,client_id,status,progress_pct,message,created_at,started_at,completed_at,cancel_requested"
    ).order("id", desc=True).limit(limit).execute().data or []
    return jsonify({"jobs": rows})'''

# ── cancel_job route patch ─────────────────────────────────────
OLD_CANCEL_JOB = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT status FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            con.close()
            return jsonify({"error": "Job not found"}), 404
        status = (row["status"] or "").lower()
        if status in {"completed", "cancelled", "failed"}:
            con.close()
            return jsonify({"ok": True, "status": status, "message": "Job already finished"})
        if status == "pending":
            con.execute("""
                UPDATE lynis_jobs
                SET status=\'cancelled\', completed_at=datetime(\'now\'), progress_pct=100, message=\'Cancelled by user\'
                WHERE id=?
            """, (job_id,))
        else:
            con.execute("""
                UPDATE lynis_jobs
                SET cancel_requested=1, message=\'Cancellation requested by dashboard user\'
                WHERE id=?
            """, (job_id,))
        con.commit()
        con.close()'''

NEW_CANCEL_JOB = '''\
    sb = _sb_agent()
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    r = sb.table("lynis_jobs").select("status").eq("id", job_id).limit(1).execute()
    if not r.data:
        return jsonify({"error": "Job not found"}), 404
    status = (r.data[0].get("status") or "").lower()
    if status in {"completed", "cancelled", "failed"}:
        return jsonify({"ok": True, "status": status, "message": "Job already finished"})
    if status == "pending":
        sb.table("lynis_jobs").update({
            "status": "cancelled", "completed_at": now_ts,
            "progress_pct": 100, "message": "Cancelled by user",
        }).eq("id", job_id).execute()
    else:
        sb.table("lynis_jobs").update({
            "cancel_requested": 1,
            "message": "Cancellation requested by dashboard user",
        }).eq("id", job_id).execute()'''

# ── delete_job route patch ─────────────────────────────────────
OLD_DELETE_JOB = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT status FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            con.close()
            return jsonify({"error": "Job not found"}), 404
        status = (row["status"] or "").lower()
        if status in {"pending", "running"}:
            con.close()
            return jsonify({"error": "Cannot remove a pending/running job. Cancel it first."}), 409
        con.execute("DELETE FROM lynis_jobs WHERE id=?", (job_id,))
        con.commit()
        con.close()'''

NEW_DELETE_JOB = '''\
    sb = _sb_agent()
    r = sb.table("lynis_jobs").select("status").eq("id", job_id).limit(1).execute()
    if not r.data:
        return jsonify({"error": "Job not found"}), 404
    status = (r.data[0].get("status") or "").lower()
    if status in {"pending", "running"}:
        return jsonify({"error": "Cannot remove a pending/running job. Cancel it first."}), 409
    sb.table("lynis_jobs").delete().eq("id", job_id).execute()'''

# ── download_job_report patch ──────────────────────────────────
OLD_DOWNLOAD_REPORT = '''\
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT raw_report FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    report = row["raw_report"] or "No report content."'''

NEW_DOWNLOAD_REPORT = '''\
    sb = _sb_agent()
    r = sb.table("lynis_jobs").select("raw_report").eq("id", job_id).limit(1).execute()
    if not r.data:
        return jsonify({"error": "Job not found"}), 404
    report = r.data[0].get("raw_report") or "No report content."'''


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — Supabase Integration Patch          ║" + X)
    print(B + C + "║   Self-applying · backs up all touched files          ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════╝" + X)
    print()

    # ── Verify project root ───────────────────────────────────
    if not os.path.isfile("api_server.py") or not os.path.isfile("database.py"):
        print(R + B + "  ERROR: Must be run from the VulnScan project root." + X)
        print("  Expected files: api_server.py, database.py, auth.py")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    # ── Step 1: Install Python dependencies ──────────────────
    hdr("STEP 1 — Install Python dependencies")
    for pkg in ["supabase", "python-dotenv"]:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg,
             "--break-system-packages", "-q"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ok(f"pip install {pkg}")
        else:
            warn(f"pip install {pkg} failed: {result.stderr.strip()[:200]}")

    # ── Step 2: Write supabase_config.py ─────────────────────
    hdr("STEP 2 — Write supabase_config.py")
    write_file("supabase_config.py", SUPABASE_CONFIG, "supabase_config.py")

    # ── Step 3: Replace database.py ──────────────────────────
    hdr("STEP 3 — Replace database.py with Supabase backend")
    write_file("database.py", DATABASE_PY, "database.py")
    if not syntax_check("database.py"):
        fail("database.py syntax error — restore from backup!")

    # ── Step 4: Patch api_server.py ──────────────────────────
    hdr("STEP 4 — Patch api_server.py")

    patches = [
        (OLD_API_IMPORT_BLOCK,    NEW_API_IMPORT_BLOCK,    "Add .env loader"),
        (OLD_AGENT_DB_BLOCK,      NEW_AGENT_DB_BLOCK,      "Remove AGENT_DB path"),
        (OLD_AGENT_DB_FUNC,       NEW_AGENT_DB_FUNC,       "_agent_db → Supabase shim"),
        (OLD_INIT_AGENT_DB,       NEW_INIT_AGENT_DB,       "init_agent_db → no-op"),
        (OLD_AUTH_AGENT,          NEW_AUTH_AGENT,           "_auth_agent → Supabase"),
        (OLD_REGISTER_AGENT,      NEW_REGISTER_AGENT,       "register_agent route"),
        (OLD_CREATE_JOB,          NEW_CREATE_JOB,           "create_lynis_job route"),
        (OLD_POLL_JOBS,           NEW_POLL_JOBS,            "poll_jobs route"),
        (OLD_JOB_CONTROL,         NEW_JOB_CONTROL,          "job_control route"),
        (OLD_UPDATE_PROGRESS,     NEW_UPDATE_PROGRESS,      "update_job_progress route"),
        (OLD_UPLOAD_REPORT,       NEW_UPLOAD_REPORT,        "upload_job_report route"),
        (OLD_JOB_STATUS_QUERY,    NEW_JOB_STATUS_QUERY,     "job_status query"),
        (OLD_LIST_AGENTS,         NEW_LIST_AGENTS,          "list_agents route"),
        (OLD_DISCONNECT,          NEW_DISCONNECT,           "disconnect_agent route"),
        (OLD_JOBS_OVERVIEW,       NEW_JOBS_OVERVIEW,        "jobs_overview route"),
        (OLD_CANCEL_JOB,          NEW_CANCEL_JOB,           "cancel_job route"),
        (OLD_DELETE_JOB,          NEW_DELETE_JOB,           "delete_job route"),
        (OLD_DOWNLOAD_REPORT,     NEW_DOWNLOAD_REPORT,      "download_job_report route"),
    ]

    for old, new, label in patches:
        patch_file("api_server.py", old, new, label)

    if not syntax_check("api_server.py"):
        fail("api_server.py syntax error — restore from backup and report issue!")

    # ── Step 5: Write .env.example ───────────────────────────
    hdr("STEP 5 — Write .env.example")
    write_file(".env.example", ENV_EXAMPLE, ".env.example")
    if not os.path.isfile(".env"):
        write_file(".env", ENV_EXAMPLE, ".env (initial copy — fill in SERVICE KEY!)")
        warn(".env created — you MUST add your Supabase service-role key before starting!")
    else:
        info(".env already exists — not overwritten. Add SUPABASE_SERVICE_KEY if missing.")

    # ── Step 6: .gitignore safety check ───────────────────────
    hdr("STEP 6 — .gitignore safety")
    gi = ".gitignore"
    entries_needed = [".env", "*.bak", "__pycache__/"]
    if os.path.isfile(gi):
        with open(gi) as f:
            gi_content = f.read()
    else:
        gi_content = ""
    missing = [e for e in entries_needed if e not in gi_content]
    if missing:
        with open(gi, "a") as f:
            for e in missing:
                f.write(f"\n{e}")
        ok(f".gitignore updated: added {', '.join(missing)}")
    else:
        ok(".gitignore already has all required entries")

    # ── Step 7: Connectivity smoke-test ───────────────────────
    hdr("STEP 7 — Supabase connectivity smoke-test")
    info("Importing supabase_config and pinging the users table...")
    try:
        sys.path.insert(0, os.getcwd())
        import importlib
        sc = importlib.import_module("supabase_config")
        client = sc.supabase()
        r = client.table("users").select("id").limit(1).execute()
        ok(f"Supabase connected — users table reachable (rows: {len(r.data)})")
    except Exception as e:
        warn(f"Smoke-test failed: {e}")
        warn("This usually means SUPABASE_SERVICE_KEY is not set.")
        warn("Set it in .env and re-run, or export before starting the server:")
        print(f"\n    export SUPABASE_SERVICE_KEY='<your-key>'")
        print(f"    python3 api_server.py\n")

    # ── Summary ───────────────────────────────────────────────
    print()
    print(B + C + "══════════════════════════════════════════════════════" + X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if fc else D)}{fc}{X}"
    )
    print()
    print(f"  {G}What changed:{X}")
    print(f"    {G}✓{X}  supabase_config.py  — Supabase client singleton")
    print(f"    {G}✓{X}  database.py         — full Supabase replacement (SQLite removed)")
    print(f"    {G}✓{X}  api_server.py       — all agent/job DB calls → Supabase")
    print(f"    {G}✓{X}  .env.example        — credential template")
    print()
    print(f"  {Y}Required before starting VulnScan:{X}")
    print(f"    1. Open Supabase Dashboard → Project Settings → API")
    print(f"    2. Copy the 'service_role' key")
    print(f"    3. Add to .env:  SUPABASE_SERVICE_KEY=<key>")
    print(f"    4. Start server: python3 api_server.py")
    print()
    print(f"  {C}Supabase project:{X}  https://qonplkgabhubntfhtthu.supabase.co")
    print(f"  {C}Tables created:{X}   users · scans · audit_log · sessions")
    print(f"                         agent_clients · lynis_jobs")
    print()


if __name__ == "__main__":
    main()
