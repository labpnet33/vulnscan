#!/usr/bin/env python3
"""
Unified database manager for VulnScan Pro
Handles: users, sessions, scans, audit logs
"""
import sqlite3, os, json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnscan.db")

def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    # FIX: Wrap in try/except so a DB permission error doesn't crash the whole app on startup
    try:
        con = get_db()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                email           TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT DEFAULT 'user',
                is_verified     INTEGER DEFAULT 0,
                is_active       INTEGER DEFAULT 1,
                verify_token    TEXT,
                verify_expires  TEXT,
                reset_token     TEXT,
                reset_expires   TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                last_login      TEXT,
                login_count     INTEGER DEFAULT 0,
                full_name       TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER,
                target          TEXT,
                scan_time       TEXT,
                result          TEXT,
                open_ports      INTEGER DEFAULT 0,
                total_cves      INTEGER DEFAULT 0,
                critical_cves   INTEGER DEFAULT 0,
                modules         TEXT DEFAULT '',
                status          TEXT DEFAULT 'complete',
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER,
                username        TEXT,
                action          TEXT,
                target          TEXT,
                ip_address      TEXT,
                user_agent      TEXT,
                details         TEXT,
                timestamp       TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER,
                token           TEXT UNIQUE,
                ip_address      TEXT,
                user_agent      TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                expires_at      TEXT,
                is_active       INTEGER DEFAULT 1,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        con.commit()
        # Lightweight migrations for existing DBs
        cols = {r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()}
        if "verify_expires" not in cols:
            con.execute("ALTER TABLE users ADD COLUMN verify_expires TEXT")
            con.commit()

        # Migrate old scans.db if exists
        old_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")
        if os.path.exists(old_db):
            try:
                old = sqlite3.connect(old_db)
                old.row_factory = sqlite3.Row
                rows = old.execute("SELECT * FROM scans").fetchall()
                for row in rows:
                    con.execute(
                        "INSERT OR IGNORE INTO scans(id,target,scan_time,result,open_ports,total_cves,critical_cves) VALUES(?,?,?,?,?,?,?)",
                        (row["id"], row["target"], row["scan_time"], row["result"],
                         row["open_ports"], row["total_cves"], row["critical_cves"]))
                con.commit()
                old.close()
                print("[*] Migrated old scans.db to vulnscan.db")
            except Exception as e:
                print(f"[!] Migration note: {e}")

        con.close()
        print(f"[*] Database ready: {DB_PATH}")

    except sqlite3.OperationalError as e:
        # FIX: Print a clear error instead of crashing silently
        print(f"[!] DATABASE ERROR: Cannot open/create {DB_PATH}")
        print(f"[!] Reason: {e}")
        print(f"[!] Fix: Check directory permissions — run: chmod 755 {os.path.dirname(DB_PATH)}")
        raise
    except Exception as e:
        print(f"[!] Database init failed: {e}")
        raise

# ── User functions ─────────────────────────────
def create_user(username, email, password_hash, full_name="", role="user", is_verified=0, verify_token="", verify_expires=None):
    con = get_db()
    try:
        con.execute(
            "INSERT INTO users(username,email,password_hash,full_name,role,is_verified,verify_token,verify_expires) VALUES(?,?,?,?,?,?,?,?)",
            (username.lower().strip(), email.lower().strip(), password_hash, full_name, role, is_verified, verify_token, verify_expires))
        con.commit()
        return True, "User created"
    except sqlite3.IntegrityError as e:
        if "username" in str(e): return False, "Username already taken"
        if "email" in str(e): return False, "Email already registered"
        return False, str(e)
    finally:
        con.close()

def get_user_by_id(uid):
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    return dict(row) if row else None

def get_user_by_username(username):
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE username=?", (username.lower().strip(),)).fetchone()
    con.close()
    return dict(row) if row else None

def get_user_by_email(email):
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE email=?", (email.lower().strip(),)).fetchone()
    con.close()
    return dict(row) if row else None

def get_user_by_token(token, token_type="verify"):
    col = "verify_token" if token_type == "verify" else "reset_token"
    con = get_db()
    row = con.execute(f"SELECT * FROM users WHERE {col}=?", (token,)).fetchone()
    con.close()
    return dict(row) if row else None

def verify_user(token):
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE verify_token=?", (token,)).fetchone()
    if not row:
        con.close()
        return False
    verify_expires = row["verify_expires"]
    if verify_expires:
        try:
            if datetime.utcnow() > datetime.fromisoformat(verify_expires):
                con.close()
                return False
        except Exception:
            con.close()
            return False
    con.execute("UPDATE users SET is_verified=1, verify_token=NULL, verify_expires=NULL WHERE id=?", (row["id"],))
    con.commit()
    con.close()
    return True

def update_user(uid, **kwargs):
    if not kwargs: return
    con = get_db()
    sets = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [uid]
    con.execute(f"UPDATE users SET {sets} WHERE id=?", vals)
    con.commit()
    con.close()

def update_last_login(uid, ip=""):
    con = get_db()
    con.execute("UPDATE users SET last_login=datetime('now'), login_count=login_count+1 WHERE id=?", (uid,))
    con.commit()
    con.close()

def get_all_users(limit=100):
    con = get_db()
    rows = con.execute(
        "SELECT id,username,email,role,is_verified,is_active,created_at,last_login,login_count,full_name FROM users ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]

def toggle_user_active(uid):
    con = get_db()
    con.execute("UPDATE users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?", (uid,))
    con.commit()
    con.close()

def set_user_role(uid, role):
    con = get_db()
    con.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    con.commit()
    con.close()

def delete_user(uid):
    con = get_db()
    con.execute("DELETE FROM users WHERE id=?", (uid,))
    con.commit()
    con.close()

# ── Scan functions ──────────────────────────────
def save_scan(target, result, user_id=None, modules=""):
    s = result.get("summary", {})
    con = get_db()
    cur = con.execute(
        "INSERT INTO scans(user_id,target,scan_time,result,open_ports,total_cves,critical_cves,modules) VALUES(?,?,?,?,?,?,?,?)",
        (user_id, target, result.get("scan_time", ""), json.dumps(result),
         s.get("open_ports", 0), s.get("total_cves", 0), s.get("critical_cves", 0), modules))
    con.commit()
    sid = cur.lastrowid
    con.close()
    return sid

def get_history(limit=20, user_id=None):
    con = get_db()
    if user_id is not None:
        # Fetch only this user's scans (integer user_id)
        rows = con.execute(
            "SELECT id,target,scan_time,open_ports,total_cves,critical_cves,modules "
            "FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (user_id, limit)).fetchall()
    else:
        # Admin/system call: return all scans regardless of owner
        rows = con.execute(
            "SELECT id,target,scan_time,open_ports,total_cves,critical_cves,modules "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_scan_by_id(sid, user_id=None):
    con = get_db()
    if user_id:
        row = con.execute("SELECT result FROM scans WHERE id=? AND user_id=?", (sid, user_id)).fetchone()
    else:
        row = con.execute("SELECT result FROM scans WHERE id=?", (sid,)).fetchone()
    con.close()
    return json.loads(row["result"]) if row else None

def get_scan_stats():
    con = get_db()
    stats = {}
    stats["total_scans"] = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    stats["total_cves"] = con.execute("SELECT SUM(total_cves) FROM scans").fetchone()[0] or 0
    stats["critical_cves"] = con.execute("SELECT SUM(critical_cves) FROM scans").fetchone()[0] or 0
    stats["total_users"] = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    stats["active_users"] = con.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    stats["verified_users"] = con.execute("SELECT COUNT(*) FROM users WHERE is_verified=1").fetchone()[0]
    stats["scans_today"] = con.execute("SELECT COUNT(*) FROM scans WHERE date(scan_time)=date('now')").fetchone()[0]
    con.close()
    return stats

# ── Audit log functions ─────────────────────────
def audit(user_id, username, action, target="", ip="", ua="", details=""):
    try:
        con = get_db()
        con.execute(
            "INSERT INTO audit_log(user_id,username,action,target,ip_address,user_agent,details) VALUES(?,?,?,?,?,?,?)",
            (user_id, username, action, target, ip, ua, details))
        con.commit()
        con.close()
    except Exception as e:
        # FIX: Don't crash if audit logging fails — just print a warning
        print(f"[!] Audit log failed: {e}")

def get_audit_log(limit=100, user_id=None):
    con = get_db()
    if user_id:
        rows = con.execute("SELECT * FROM audit_log WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit)).fetchall()
    else:
        rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]

# FIX: init_db() is still called on import, but now with proper error handling
init_db()
