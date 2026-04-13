#!/usr/bin/env python3
"""
VulnScan Pro — Patch: Unify agent registration
================================================
Problem: Connected clients appear under Lynis page instead of Remote Audit
         because the install script POSTs to /api/agent/register which writes
         to the OLD `agent_clients` (Lynis) table, NOT the `ra_clients` table
         that Remote Audit reads from.

Fix:
  1. api_server.py  — Make /api/agent/register write to BOTH tables so the
                      same token works for both Lynis jobs AND Remote Audit.
                      Also make /api/remote/agents fall back to agent_clients
                      so existing connected systems appear immediately.
  2. agent/install_agent.sh  — Point registration at /api/agent/register
                                (already correct, no change needed there).
  3. agent/universal_agent.py — Fix heartbeat to also hit /api/agent/heartbeat
                                 (already correct in new version).

Run from project root:
    python3 patch_unify_agents.py
"""
import os, shutil
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN  = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch_file(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        skip(f"{label} — anchor not found (may already be patched)")
        return False
    bak = backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}  [backup: {bak}]")
    return True

def replace_all(path, label, old, new):
    """Replace ALL occurrences (for strings that appear in both HTML and code)."""
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    count = src.count(old)
    if count == 0:
        skip(f"{label} — not found (may already be patched)")
        return 0
    bak = backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new))
    ok(f"{label} — {count} occurrence(s)  [backup: {bak}]")
    return count

print()
print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
print(BOLD + CYAN + "║  VulnScan Pro — Unify Agent Registration             ║" + RESET)
print(BOLD + CYAN + "║  Clients will appear in Remote Audit, not Lynis      ║" + RESET)
print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
print()

SERVER = "api_server.py"

# ══════════════════════════════════════════════════════════════
# PATCH 1
# /api/agent/register currently writes ONLY to agent_clients (Lynis table).
# Make it ALSO write to ra_clients so Remote Audit sees the agent.
# ══════════════════════════════════════════════════════════════

OLD_REGISTER = '''@app.route("/api/agent/register", methods=["POST"])
def register_agent():
    data = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    os_info = (data.get("os_info") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
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
        con.close()
    audit(None, "agent", "AGENT_REGISTER", target=client_id,
          ip=request.remote_addr,
          details=f"hostname={hostname};os_info={os_info[:60]}")
    return jsonify({"client_id": client_id, "token": token, "api_base": request.url_root.rstrip("/")})'''

NEW_REGISTER = '''@app.route("/api/agent/register", methods=["POST"])
def register_agent():
    """
    Unified registration endpoint.
    Writes to BOTH agent_clients (Lynis) AND ra_clients (Remote Audit)
    so the same agent token works for both pages.
    """
    data      = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    hostname  = (data.get("hostname")  or "").strip()
    os_info   = (data.get("os_info")   or "").strip()
    tools     = data.get("tools") or []
    agent_ver = (data.get("agent_version") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400

    token      = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    ip         = request.remote_addr or ""

    # ── Write to Lynis agent_clients table ───────────────────
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            INSERT INTO agent_clients(client_id, token_hash, hostname, os_info, ip_seen, status)
            VALUES(?,?,?,?,?,'online')
            ON CONFLICT(client_id) DO UPDATE SET
              token_hash=excluded.token_hash,
              hostname=excluded.hostname,
              os_info=excluded.os_info,
              ip_seen=excluded.ip_seen,
              last_seen=datetime('now'),
              status='online'
        """, (client_id, token_hash, hostname, os_info, ip))
        con.commit()
        con.close()

    # ── Write to Remote Audit ra_clients table ───────────────
    import json as _json2
    ra_hash_val = _ra_hash(token)
    with _RA_LOCK:
        con2 = _ra_db()
        con2.execute("""
            INSERT INTO ra_clients
              (client_id, token_hash, hostname, os_info, ip_seen,
               tools_json, agent_ver, status)
            VALUES(?,?,?,?,?,?,?,'online')
            ON CONFLICT(client_id) DO UPDATE SET
              token_hash=excluded.token_hash,
              hostname=excluded.hostname,
              os_info=excluded.os_info,
              ip_seen=excluded.ip_seen,
              tools_json=excluded.tools_json,
              agent_ver=excluded.agent_ver,
              last_seen=datetime('now'),
              status='online'
        """, (client_id, ra_hash_val, hostname, os_info, ip,
              _json2.dumps(tools), agent_ver))
        con2.commit()
        con2.close()

    audit(None, "agent", "AGENT_REGISTER", target=client_id,
          ip=ip,
          details=f"hostname={hostname};os_info={os_info[:60]};tools={len(tools)}")
    return jsonify({
        "client_id": client_id,
        "token":     token,
        "api_base":  request.url_root.rstrip("/")
    })'''

patch_file(SERVER, "api_server: /api/agent/register writes to both tables", OLD_REGISTER, NEW_REGISTER)

# ══════════════════════════════════════════════════════════════
# PATCH 2
# /api/agent/heartbeat currently only updates agent_clients.
# Also update ra_clients so Remote Audit shows the agent as online
# and keeps the tools list current.
# ══════════════════════════════════════════════════════════════

OLD_HEARTBEAT = '''@app.route("/api/agent/heartbeat", methods=["POST"])
def ra_heartbeat():
    """Agent sends heartbeat with current tool list."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data  = request.get_json() or {}
    tools = data.get("tools") or []
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET last_seen=datetime('now'), status='online',
                tools_json=?, ip_seen=?
            WHERE client_id=?
        """, (json.dumps(tools), request.remote_addr or "", client_id))
        con.commit()
        con.close()
    return jsonify({"ok": True})'''

NEW_HEARTBEAT = '''@app.route("/api/agent/heartbeat", methods=["POST"])
def ra_heartbeat():
    """
    Agent sends heartbeat with current tool list.
    Accepts Bearer token from EITHER agent_clients OR ra_clients.
    Updates both tables so Lynis page and Remote Audit stay in sync.
    """
    # Try ra_clients auth first, then fall back to agent_clients auth
    client_id = _ra_auth(request)

    # Fallback: check agent_clients token (Lynis table)
    if not client_id:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
            if token:
                th = _hash_token(token)
                con_chk = _agent_db()
                row_chk = con_chk.execute(
                    "SELECT client_id FROM agent_clients WHERE token_hash=?", (th,)
                ).fetchone()
                con_chk.close()
                if row_chk:
                    client_id = row_chk["client_id"]

    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401

    data  = request.get_json() or {}
    tools = data.get("tools") or []
    ip    = request.remote_addr or ""

    # Update ra_clients
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET last_seen=datetime('now'), status='online',
                tools_json=?, ip_seen=?
            WHERE client_id=?
        """, (json.dumps(tools), ip, client_id))
        con.commit()
        con.close()

    # Update agent_clients (Lynis table) as well
    with AGENT_LOCK:
        con2 = _agent_db()
        con2.execute("""
            UPDATE agent_clients
            SET last_seen=datetime('now'), status='online', ip_seen=?
            WHERE client_id=?
        """, (ip, client_id))
        con2.commit()
        con2.close()

    return jsonify({"ok": True})'''

patch_file(SERVER, "api_server: /api/agent/heartbeat syncs both tables", OLD_HEARTBEAT, NEW_HEARTBEAT)

# ══════════════════════════════════════════════════════════════
# PATCH 3
# /api/remote/agents currently reads ONLY ra_clients.
# Make it merge results from BOTH tables so agents registered
# via the old Lynis path also appear in Remote Audit.
# ══════════════════════════════════════════════════════════════

OLD_LIST_AGENTS = '''@app.route("/api/remote/agents", methods=["GET"])
def ra_list_agents():
    """List all connected remote agents with their available tools."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    with _RA_LOCK:
        con = _ra_db()
        rows = con.execute("""
            SELECT client_id, hostname, os_info, ip_seen, tools_json,
                   agent_ver, last_seen, status, created_at
            FROM ra_clients
            WHERE status != 'disconnected'
            ORDER BY datetime(last_seen) DESC
        """).fetchall()
        con.close()
    agents = []
    for r in rows:
        try: tools = json.loads(r["tools_json"] or "[]")
        except Exception: tools = []
        agents.append({
            "client_id":  r["client_id"],
            "hostname":   r["hostname"],
            "os_info":    r["os_info"],
            "ip_seen":    r["ip_seen"],
            "tools":      tools,
            "agent_ver":  r["agent_ver"],
            "last_seen":  r["last_seen"],
            "status":     r["status"],
            "created_at": r["created_at"],
        })
    return jsonify({"agents": agents})'''

NEW_LIST_AGENTS = '''@app.route("/api/remote/agents", methods=["GET"])
def ra_list_agents():
    """
    List all connected remote agents with their available tools.
    Merges ra_clients (Remote Audit) + agent_clients (Lynis) so agents
    registered via either path appear in the Remote Audit panel.
    """
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    seen = {}

    # Primary source: ra_clients
    with _RA_LOCK:
        con = _ra_db()
        rows = con.execute("""
            SELECT client_id, hostname, os_info, ip_seen, tools_json,
                   agent_ver, last_seen, status, created_at
            FROM ra_clients
            WHERE status != 'disconnected'
            ORDER BY datetime(last_seen) DESC
        """).fetchall()
        con.close()
    for r in rows:
        try: tools = json.loads(r["tools_json"] or "[]")
        except Exception: tools = []
        seen[r["client_id"]] = {
            "client_id":  r["client_id"],
            "hostname":   r["hostname"],
            "os_info":    r["os_info"],
            "ip_seen":    r["ip_seen"],
            "tools":      tools,
            "agent_ver":  r["agent_ver"],
            "last_seen":  r["last_seen"],
            "status":     r["status"],
            "created_at": r["created_at"],
        }

    # Fallback source: agent_clients (Lynis table)
    # Include any agents not already in ra_clients
    with AGENT_LOCK:
        con2 = _agent_db()
        rows2 = con2.execute("""
            SELECT client_id, hostname, os_info, ip_seen,
                   last_seen, status, created_at
            FROM agent_clients
            WHERE status != 'disconnected'
            ORDER BY datetime(last_seen) DESC
        """).fetchall()
        con2.close()
    for r in rows2:
        cid = r["client_id"]
        if cid not in seen:
            seen[cid] = {
                "client_id":  cid,
                "hostname":   r["hostname"] or "",
                "os_info":    r["os_info"]  or "",
                "ip_seen":    r["ip_seen"]  or "",
                "tools":      [],
                "agent_ver":  "",
                "last_seen":  r["last_seen"],
                "status":     r["status"],
                "created_at": r["created_at"],
            }
        else:
            # If already in ra_clients but tools list is empty, keep existing
            pass

    agents = sorted(seen.values(),
                    key=lambda x: x.get("last_seen", ""), reverse=True)
    return jsonify({"agents": agents})'''

patch_file(SERVER, "api_server: /api/remote/agents merges both tables", OLD_LIST_AGENTS, NEW_LIST_AGENTS)

# ══════════════════════════════════════════════════════════════
# PATCH 4
# /api/remote/jobs (agent poll) currently only authenticates
# against ra_clients. Allow the Lynis token (agent_clients) too,
# so the universal_agent.py registered via Lynis path can poll.
# ══════════════════════════════════════════════════════════════

OLD_POLL_JOBS = '''@app.route("/api/remote/jobs", methods=["GET"])
def ra_poll_jobs():
    """Agent polls this endpoint for pending jobs."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

NEW_POLL_JOBS = '''@app.route("/api/remote/jobs", methods=["GET"])
def ra_poll_jobs():
    """
    Agent polls this endpoint for pending jobs.
    Accepts token from ra_clients OR agent_clients (Lynis table).
    """
    client_id = _ra_auth(request)

    # Fallback: check agent_clients (Lynis) token
    if not client_id:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
            if token:
                th = _hash_token(token)
                _con = _agent_db()
                _row = _con.execute(
                    "SELECT client_id FROM agent_clients WHERE token_hash=?", (th,)
                ).fetchone()
                _con.close()
                if _row:
                    client_id = _row["client_id"]
                    # Ensure this agent also exists in ra_clients for job polling
                    with _RA_LOCK:
                        _rcon = _ra_db()
                        _existing = _rcon.execute(
                            "SELECT 1 FROM ra_clients WHERE client_id=?", (client_id,)
                        ).fetchone()
                        if not _existing:
                            _rcon.execute("""
                                INSERT OR IGNORE INTO ra_clients
                                  (client_id, token_hash, status)
                                VALUES (?, ?, 'online')
                            """, (client_id, _ra_hash(token)))
                            _rcon.commit()
                        else:
                            _rcon.execute("""
                                UPDATE ra_clients
                                SET last_seen=datetime('now'), status='online',
                                    token_hash=?
                                WHERE client_id=?
                            """, (_ra_hash(token), client_id))
                            _rcon.commit()
                        _rcon.close()

    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

patch_file(SERVER, "api_server: /api/remote/jobs accepts both token types", OLD_POLL_JOBS, NEW_POLL_JOBS)

# ══════════════════════════════════════════════════════════════
# PATCH 5
# /api/remote/upload — same dual-auth fix
# ══════════════════════════════════════════════════════════════

OLD_UPLOAD = '''@app.route("/api/remote/upload", methods=["POST"])
def ra_upload_result():
    """Agent uploads completed job results."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

NEW_UPLOAD = '''@app.route("/api/remote/upload", methods=["POST"])
def ra_upload_result():
    """Agent uploads completed job results. Accepts both token types."""
    client_id = _ra_auth(request)
    if not client_id:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            _tok = auth.split(" ", 1)[1].strip()
            if _tok:
                _th = _hash_token(_tok)
                _uc = _agent_db()
                _ur2 = _uc.execute(
                    "SELECT client_id FROM agent_clients WHERE token_hash=?", (_th,)
                ).fetchone()
                _uc.close()
                if _ur2:
                    client_id = _ur2["client_id"]
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

patch_file(SERVER, "api_server: /api/remote/upload accepts both token types", OLD_UPLOAD, NEW_UPLOAD)

# ══════════════════════════════════════════════════════════════
# PATCH 6
# /api/remote/jobs/<id>/progress — same dual-auth fix
# ══════════════════════════════════════════════════════════════

OLD_PROGRESS = '''@app.route("/api/remote/jobs/<int:job_id>/progress", methods=["POST"])
def ra_job_progress(job_id):
    """Agent sends progress updates."""
    client_id = _ra_auth(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

NEW_PROGRESS = '''@app.route("/api/remote/jobs/<int:job_id>/progress", methods=["POST"])
def ra_job_progress(job_id):
    """Agent sends progress updates. Accepts both token types."""
    client_id = _ra_auth(request)
    if not client_id:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            _tok = auth.split(" ", 1)[1].strip()
            if _tok:
                _th = _hash_token(_tok)
                _pc = _agent_db()
                _pr = _pc.execute(
                    "SELECT client_id FROM agent_clients WHERE token_hash=?", (_th,)
                ).fetchone()
                _pc.close()
                if _pr:
                    client_id = _pr["client_id"]
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401'''

patch_file(SERVER, "api_server: /api/remote/jobs/progress accepts both token types", OLD_PROGRESS, NEW_PROGRESS)

# ══════════════════════════════════════════════════════════════
# PATCH 7
# /api/remote/agents/<client_id>/disconnect
# Also remove from agent_clients when disconnecting from Remote Audit
# ══════════════════════════════════════════════════════════════

OLD_DISCONNECT = '''@app.route("/api/remote/agents/<client_id>/disconnect", methods=["POST"])
def ra_disconnect_agent(client_id):
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    import secrets as _sec2
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET status='disconnected', token_hash=?, last_seen=datetime('now')
            WHERE client_id=?
        """, (_ra_hash(_sec2.token_urlsafe(32)), client_id))
        con.execute("""
            UPDATE ra_jobs SET status='cancelled', message='Agent disconnected'
            WHERE client_id=? AND status IN ('pending','running')
        """, (client_id,))
        con.commit()
        con.close()
    audit(u["id"], u["username"], "REMOTE_AGENT_DISCONNECT", target=client_id,
          ip=request.remote_addr)
    return jsonify({"ok": True})'''

NEW_DISCONNECT = '''@app.route("/api/remote/agents/<client_id>/disconnect", methods=["POST"])
def ra_disconnect_agent(client_id):
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    import secrets as _sec2
    dead_hash = _ra_hash(_sec2.token_urlsafe(32))

    # Disconnect from ra_clients + cancel pending jobs
    with _RA_LOCK:
        con = _ra_db()
        con.execute("""
            UPDATE ra_clients
            SET status='disconnected', token_hash=?, last_seen=datetime('now')
            WHERE client_id=?
        """, (dead_hash, client_id))
        con.execute("""
            UPDATE ra_jobs SET status='cancelled', message='Agent disconnected'
            WHERE client_id=? AND status IN ('pending','running')
        """, (client_id,))
        con.commit()
        con.close()

    # Also disconnect from agent_clients (Lynis table)
    with AGENT_LOCK:
        con2 = _agent_db()
        con2.execute("""
            UPDATE agent_clients
            SET status='disconnected', token_hash=?, last_seen=datetime('now')
            WHERE client_id=?
        """, (dead_hash, client_id))
        con2.execute("""
            DELETE FROM agent_clients WHERE client_id=?
        """, (client_id,))
        con2.commit()
        con2.close()

    audit(u["id"], u["username"], "REMOTE_AGENT_DISCONNECT", target=client_id,
          ip=request.remote_addr)
    return jsonify({"ok": True})'''

patch_file(SERVER, "api_server: disconnect removes from both tables", OLD_DISCONNECT, NEW_DISCONNECT)

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
print()
print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
print(f"  {YELLOW}Done. Restart server:{RESET}")
print(f"    sudo systemctl restart vulnscan")
print()
print(f"  {YELLOW}No need to re-install agent on client — existing agents{RESET}")
print(f"  {YELLOW}will appear in Remote Audit on next heartbeat (~15s).{RESET}")
print()
print(f"  {GREEN}What changed:{RESET}")
print(f"    {GREEN}✓{RESET}  /api/agent/register  → writes to BOTH tables")
print(f"    {GREEN}✓{RESET}  /api/agent/heartbeat → syncs BOTH tables")
print(f"    {GREEN}✓{RESET}  /api/remote/agents   → merges BOTH tables")
print(f"    {GREEN}✓{RESET}  /api/remote/jobs     → accepts Lynis token too")
print(f"    {GREEN}✓{RESET}  /api/remote/upload   → accepts Lynis token too")
print(f"    {GREEN}✓{RESET}  /api/remote/.../progress → accepts Lynis token")
print(f"    {GREEN}✓{RESET}  Disconnect removes agent from both tables")
print()
