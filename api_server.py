#!/usr/bin/env python3
"""VulnScan Pro - Security Scanning Platform"""

from flask import Flask, request, jsonify, session
from functools import wraps
import subprocess, os, json, time, socket, shutil, datetime, threading
import psutil

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vulnscan-secret-2024")

# ── In-memory stores ──────────────────────────────────────────────────────────
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "analyst": {"password": "analyst123", "role": "analyst"},
}
SCAN_RESULTS = {}
scan_counter = 0
scan_lock = threading.Lock()

# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Unauthorized"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Auth endpoints ─────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if user and user["password"] == password:
        session["user"] = username
        session["role"] = user["role"]
        return jsonify({"status": "ok", "user": username, "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok"})

@app.route("/api/me")
def me():
    if session.get("user"):
        return jsonify({"user": session["user"], "role": session["role"]})
    return jsonify({"error": "Not logged in"}), 401

# ── Scan endpoints ─────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
def start_scan():
    global scan_counter
    data = request.json or {}
    target = data.get("target", "").strip()
    scan_type = data.get("type", "basic")
    if not target:
        return jsonify({"error": "Target required"}), 400

    with scan_lock:
        scan_counter += 1
        scan_id = f"scan_{scan_counter:04d}"

    SCAN_RESULTS[scan_id] = {
        "id": scan_id, "target": target, "type": scan_type,
        "status": "running", "started": time.time(),
        "user": session["user"], "output": [], "findings": []
    }

    def run_scan(sid, tgt, stype):
        try:
            SCAN_RESULTS[sid]["output"].append(f"[*] Starting {stype} scan on {tgt}")
            if stype == "ping":
                cmd = ["ping", "-c", "4", tgt]
            elif stype == "ports":
                cmd = ["nmap", "-T4", "--open", tgt] if shutil.which("nmap") else ["echo", f"nmap not available for {tgt}"]
            elif stype == "full":
                cmd = ["nmap", "-T4", "-A", "--open", tgt] if shutil.which("nmap") else ["echo", f"nmap not available for {tgt}"]
            else:
                cmd = ["nmap", "-sV", tgt] if shutil.which("nmap") else ["echo", f"Scanned {tgt}"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out = result.stdout or result.stderr or "No output"
            SCAN_RESULTS[sid]["output"].extend(out.splitlines())
            SCAN_RESULTS[sid]["status"] = "completed"
            SCAN_RESULTS[sid]["finished"] = time.time()
        except subprocess.TimeoutExpired:
            SCAN_RESULTS[sid]["output"].append("[!] Scan timed out")
            SCAN_RESULTS[sid]["status"] = "timeout"
        except Exception as e:
            SCAN_RESULTS[sid]["output"].append(f"[!] Error: {e}")
            SCAN_RESULTS[sid]["status"] = "error"

    t = threading.Thread(target=run_scan, args=(scan_id, target, scan_type), daemon=True)
    t.start()
    return jsonify({"scan_id": scan_id, "status": "started"})

@app.route("/api/scan/<scan_id>")
@login_required
def get_scan(scan_id):
    s = SCAN_RESULTS.get(scan_id)
    if not s:
        return jsonify({"error": "Not found"}), 404
    return jsonify(s)

@app.route("/api/scans")
@login_required
def list_scans():
    scans = sorted(SCAN_RESULTS.values(), key=lambda x: x["started"], reverse=True)
    return jsonify({"scans": scans[:50]})

@app.route("/api/scan/<scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    if scan_id in SCAN_RESULTS:
        del SCAN_RESULTS[scan_id]
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Not found"}), 404

# ── Admin CLI endpoint ─────────────────────────────────────────────────────────
BLOCKED_CMDS = ["rm -rf /", "mkfs", ":(){:|:&};:", "dd if=/dev/zero of=/dev/"]

@app.route("/api/admin/cli", methods=["POST"])
@admin_required
def admin_cli():
    data = request.json or {}
    cmd = data.get("command", "").strip()
    if not cmd:
        return jsonify({"error": "No command"}), 400
    for blocked in BLOCKED_CMDS:
        if blocked in cmd:
            return jsonify({"output": f"[BLOCKED] Command contains forbidden pattern: {blocked}", "exit_code": 1})
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30,
            cwd="/tmp", env={**os.environ, "TERM": "xterm"}
        )
        output = result.stdout
        if result.stderr:
            output += ("\n" if output else "") + result.stderr
        return jsonify({"output": output or "(no output)", "exit_code": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "[TIMEOUT] Command exceeded 30 seconds", "exit_code": 124})
    except Exception as e:
        return jsonify({"output": f"[ERROR] {e}", "exit_code": 1})

# ── System Health endpoint ─────────────────────────────────────────────────────
def get_public_ip():
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as r:
            return r.read().decode().strip()
    except:
        return "unavailable"

def fmt_bytes(n):
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def fmt_uptime(seconds):
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)

SECURITY_TOOLS = ["nmap","nikto","sqlmap","metasploit","hydra","john","hashcat",
                   "wireshark","tcpdump","burpsuite","ffuf","gobuster","masscan","netcat"]

@app.route("/api/health/system")
@admin_required
def system_health():
    cpu = psutil.cpu_percent(interval=0.5)
    cpu_cores = psutil.cpu_count()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime_s = time.time() - psutil.boot_time()
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0,0,0)

    # Network - pick first non-loopback interface
    net_iface = "lo"
    net_rx = net_tx = 0
    stats = psutil.net_io_counters(pernic=True)
    for iface, s in stats.items():
        if iface != "lo":
            net_iface = iface
            net_rx = s.bytes_recv
            net_tx = s.bytes_sent
            break

    procs = list(psutil.process_iter())
    procs_running = sum(1 for p in procs if p.status() == psutil.STATUS_RUNNING)

    tools_status = {}
    for t in SECURITY_TOOLS:
        tools_status[t] = shutil.which(t) is not None

    return jsonify({
        "cpu_percent": round(cpu, 1),
        "cpu_cores": cpu_cores,
        "ram_percent": round(mem.percent, 1),
        "ram_used_gb": round(mem.used / 1e9, 1),
        "ram_total_gb": round(mem.total / 1e9, 1),
        "disk_percent": round(disk.percent, 1),
        "disk_used_gb": round(disk.used / 1e9, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "uptime": fmt_uptime(uptime_s),
        "load_avg": f"{load[0]:.2f} {load[1]:.2f} {load[2]:.2f}",
        "public_ip": get_public_ip(),
        "hostname": socket.gethostname(),
        "net_iface": net_iface,
        "net_rx": fmt_bytes(net_rx),
        "net_tx": fmt_bytes(net_tx),
        "procs_running": procs_running,
        "procs_total": len(procs),
        "tools": tools_status,
    })

# ── Admin user mgmt ────────────────────────────────────────────────────────────
@app.route("/api/admin/users")
@admin_required
def list_users():
    return jsonify({"users": [{"username": u, "role": d["role"]} for u,d in USERS.items()]})

@app.route("/api/admin/users", methods=["POST"])
@admin_required
def create_user():
    data = request.json or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    role = data.get("role","analyst")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if username in USERS:
        return jsonify({"error": "User already exists"}), 409
    USERS[username] = {"password": password, "role": role}
    return jsonify({"status": "created", "username": username})

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@admin_required
def delete_user(username):
    if username == session.get("user"):
        return jsonify({"error": "Cannot delete yourself"}), 400
    if username not in USERS:
        return jsonify({"error": "Not found"}), 404
    del USERS[username]
    return jsonify({"status": "deleted"})

# ── Main HTML UI ───────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan Pro</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d1117;--surface:#161b22;--surface2:#21262d;
    --border:#30363d;--text:#c9d1d9;--muted:#8b949e;
    --green:#3fb950;--blue:#58a6ff;--red:#f85149;
    --orange:#d29922;--purple:#a371f7;--cyan:#39d353
  }
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
  /* ─ Navbar ─ */
  #navbar{
    display:flex;align-items:center;gap:6px;padding:10px 20px;
    background:var(--surface);border-bottom:1px solid var(--border);
    position:sticky;top:0;z-index:100;flex-wrap:wrap
  }
  #navbar .logo{font-weight:700;font-size:1.1rem;color:var(--green);margin-right:10px;white-space:nowrap}
  .nb{
    background:transparent;border:1px solid var(--border);color:var(--muted);
    padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.85rem;
    transition:all .15s;white-space:nowrap
  }
  .nb:hover{border-color:var(--blue);color:var(--blue)}
  .nb.active{background:var(--blue);border-color:var(--blue);color:#fff}
  #nav-console-btn{border-color:#2d5a27;color:var(--green)}
  #nav-console-btn:hover,#nav-console-btn.active{background:var(--green);border-color:var(--green);color:#000}
  .spacer{flex:1}
  #user-badge{
    font-size:.8rem;background:var(--surface2);border:1px solid var(--border);
    border-radius:20px;padding:4px 12px;display:flex;align-items:center;gap:8px
  }
  #user-badge .role{color:var(--orange);font-weight:600}
  #btn-logout{background:none;border:none;color:var(--red);cursor:pointer;font-size:.8rem}
  /* ─ Pages ─ */
  .page{display:none;padding:24px;max-width:1200px;margin:0 auto}
  .page.active{display:block}
  /* ─ Login ─ */
  #page-login{display:flex;align-items:center;justify-content:center;min-height:80vh;padding:20px}
  .login-box{
    background:var(--surface);border:1px solid var(--border);border-radius:12px;
    padding:40px;width:100%;max-width:400px;text-align:center
  }
  .login-box h1{font-size:2rem;color:var(--green);margin-bottom:6px}
  .login-box p{color:var(--muted);margin-bottom:28px;font-size:.9rem}
  .form-group{text-align:left;margin-bottom:16px}
  .form-group label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
  .form-group input,.form-group select{
    width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);
    border-radius:8px;color:var(--text);font-size:.95rem;outline:none;transition:border .15s
  }
  .form-group input:focus,.form-group select:focus{border-color:var(--blue)}
  .btn{
    width:100%;padding:10px;background:var(--green);color:#000;border:none;
    border-radius:8px;font-weight:700;font-size:.95rem;cursor:pointer;transition:opacity .15s
  }
  .btn:hover{opacity:.85}
  .btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
  .btn-sm{
    padding:5px 12px;font-size:.8rem;border-radius:6px;border:none;cursor:pointer;font-weight:600;
    transition:opacity .15s;width:auto
  }
  .btn-sm:hover{opacity:.8}
  .btn-danger{background:var(--red);color:#fff}
  .btn-blue{background:var(--blue);color:#000}
  .btn-green{background:var(--green);color:#000}
  #login-err{color:var(--red);font-size:.85rem;margin-top:12px;min-height:20px}
  /* ─ Cards ─ */
  .card{
    background:var(--surface);border:1px solid var(--border);
    border-radius:10px;padding:20px;margin-bottom:20px
  }
  .card h2{font-size:1rem;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px}
  .card h2 span.icon{font-size:1.2rem}
  /* ─ Scan form ─ */
  .scan-row{display:flex;gap:10px;flex-wrap:wrap}
  .scan-row input{
    flex:1;min-width:200px;padding:9px 14px;background:var(--bg);
    border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.9rem;outline:none
  }
  .scan-row input:focus{border-color:var(--green)}
  .scan-row select{
    padding:9px 14px;background:var(--bg);border:1px solid var(--border);
    border-radius:8px;color:var(--text);font-size:.9rem;outline:none;cursor:pointer
  }
  /* ─ Scan table ─ */
  .scan-table{width:100%;border-collapse:collapse;font-size:.85rem}
  .scan-table th{text-align:left;padding:8px 12px;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600}
  .scan-table td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
  .scan-table tr:last-child td{border-bottom:none}
  .scan-table tr:hover td{background:var(--surface2)}
  .badge{
    display:inline-block;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:600
  }
  .badge-running{background:#1f3a1f;color:var(--green)}
  .badge-completed{background:#1a2f4e;color:var(--blue)}
  .badge-error,.badge-timeout{background:#3a1f1f;color:var(--red)}
  .badge-admin{background:#2d1f4e;color:var(--purple)}
  .badge-analyst{background:#2a2f1a;color:var(--orange)}
  /* ─ Output viewer ─ */
  #scan-output-box{
    background:var(--bg);border:1px solid var(--border);border-radius:8px;
    padding:14px;font-family:'Courier New',monospace;font-size:.8rem;
    line-height:1.6;color:#a8c4a2;max-height:320px;overflow-y:auto;
    white-space:pre-wrap;word-break:break-all
  }
  /* ─ Console / CLI ─ */
  #live-cli-output{
    background:#0a0a0a;border:1px solid var(--border);border-radius:8px;
    padding:14px;height:420px;overflow-y:auto;
    font-family:'Courier New',monospace;font-size:.82rem;line-height:1.55
  }
  .cli-line{display:block;margin:1px 0}
  .cli-cmd-line{color:#3fb950}
  .cli-out-line{color:#b0b8c1}
  .cli-err-line{color:#f85149}
  .cli-sys-line{color:#39d353;font-style:italic}
  .cli-cursor{display:inline-block;width:8px;height:14px;background:var(--green);
    vertical-align:text-bottom;animation:blink 1s step-end infinite}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  .cli-input-row{display:flex;align-items:center;gap:8px;margin-top:10px}
  .cli-prompt{color:var(--green);font-family:'Courier New',monospace;font-size:.85rem;white-space:nowrap}
  .cli-input-row input{
    flex:1;background:#0a0a0a;border:1px solid var(--border);border-radius:6px;
    color:var(--green);font-family:'Courier New',monospace;font-size:.85rem;
    padding:7px 12px;outline:none
  }
  .cli-input-row input:focus{border-color:var(--green)}
  .cli-status-bar{
    font-size:.75rem;color:var(--muted);display:flex;gap:16px;margin-top:6px;padding:4px 0
  }
  .quick-btns{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
  .qbtn{
    background:var(--surface2);border:1px solid var(--border);color:var(--muted);
    padding:4px 10px;border-radius:5px;cursor:pointer;font-size:.75rem;transition:all .15s
  }
  .qbtn:hover{border-color:var(--green);color:var(--green)}
  /* ─ Health grid ─ */
  .health-grid{
    display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;
    margin-top:16px
  }
  .health-card{
    background:var(--surface2);border:1px solid var(--border);border-radius:10px;
    padding:16px;position:relative;overflow:hidden
  }
  .health-card::before{
    content:'';position:absolute;top:0;left:0;right:0;height:3px;
    background:var(--card-color,var(--blue))
  }
  .health-val{font-size:1.6rem;font-weight:700;color:var(--text);margin:4px 0}
  .health-lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .health-sub{font-size:.78rem;color:var(--muted);margin-top:2px}
  .health-bar{
    height:5px;background:var(--border);border-radius:3px;margin-top:10px;overflow:hidden
  }
  .health-bar-fill{height:100%;border-radius:3px;transition:width .5s ease;background:var(--card-color,var(--blue))}
  .tools-grid{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
  .tool-pill{
    font-size:.7rem;padding:2px 8px;border-radius:10px;
    background:#1a2a1a;color:var(--green);border:1px solid #2d5a27
  }
  .tool-pill.missing{background:#2a1a1a;color:var(--muted);border-color:#3a2a2a}
  /* ─ Stats row ─ */
  .stats-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:20px}
  .stat-card{
    background:var(--surface);border:1px solid var(--border);border-radius:8px;
    padding:14px;text-align:center
  }
  .stat-num{font-size:1.8rem;font-weight:700;color:var(--green)}
  .stat-lbl{font-size:.75rem;color:var(--muted);margin-top:2px}
  /* ─ Alert ─ */
  .alert{border-radius:8px;padding:10px 14px;font-size:.85rem;margin-bottom:12px}
  .alert-danger{background:#2a1a1a;border:1px solid var(--red);color:var(--red)}
  .alert-success{background:#1a2a1a;border:1px solid var(--green);color:var(--green)}
  /* ─ Responsive ─ */
  @media(max-width:640px){
    .health-grid{grid-template-columns:1fr 1fr}
    .stats-row{grid-template-columns:1fr 1fr}
  }
</style>
</head>
<body>

<!-- ═══ NAVBAR ═══ -->
<div id="navbar" style="display:none">
  <span class="logo">🛡 VulnScan Pro</span>
  <button class="nb" id="nav-dash-btn"    onclick="pg('dash',this)">📊 Dashboard</button>
  <button class="nb" id="nav-scan-btn"    onclick="pg('scan',this)">🔍 New Scan</button>
  <button class="nb" id="nav-results-btn" onclick="pg('results',this)">📋 Results</button>
  <button class="nb admin-only" id="nav-console-btn" onclick="pg('cli',this)">▶ Console</button>
  <button class="nb admin-only" id="nav-admin-btn"   onclick="pg('admin',this)">⚙ Admin</button>
  <div class="spacer"></div>
  <div id="user-badge">
    <span id="badge-user">—</span>
    <span class="role" id="badge-role">—</span>
    <button id="btn-logout" onclick="doLogout()">Logout</button>
  </div>
</div>

<!-- ═══ LOGIN PAGE ═══ -->
<div id="page-login" class="active">
  <div class="login-box">
    <h1>🛡</h1>
    <h2 style="font-size:1.4rem;margin-bottom:6px">VulnScan Pro</h2>
    <p>Security Scanning Platform</p>
    <div class="form-group">
      <label>Username</label>
      <input id="login-user" type="text" placeholder="admin" autocomplete="username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input id="login-pass" type="password" placeholder="••••••••" autocomplete="current-password"
             onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <button class="btn" onclick="doLogin()">Sign In</button>
    <div id="login-err"></div>
  </div>
</div>

<!-- ═══ DASHBOARD ═══ -->
<div id="page-dash" class="page">
  <h1 style="font-size:1.3rem;margin-bottom:18px">📊 Dashboard</h1>
  <div class="stats-row" id="dash-stats">
    <div class="stat-card"><div class="stat-num" id="ds-total">0</div><div class="stat-lbl">Total Scans</div></div>
    <div class="stat-card"><div class="stat-num" id="ds-running" style="color:var(--orange)">0</div><div class="stat-lbl">Running</div></div>
    <div class="stat-card"><div class="stat-num" id="ds-done" style="color:var(--blue)">0</div><div class="stat-lbl">Completed</div></div>
    <div class="stat-card"><div class="stat-num" id="ds-errors" style="color:var(--red)">0</div><div class="stat-lbl">Errors</div></div>
  </div>
  <div class="card">
    <h2><span class="icon">🕑</span> Recent Scans</h2>
    <table class="scan-table">
      <thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Started</th></tr></thead>
      <tbody id="dash-recent"></tbody>
    </table>
  </div>
</div>

<!-- ═══ NEW SCAN ═══ -->
<div id="page-scan" class="page">
  <h1 style="font-size:1.3rem;margin-bottom:18px">🔍 New Scan</h1>
  <div class="card">
    <h2><span class="icon">🎯</span> Scan Target</h2>
    <div class="scan-row">
      <input id="scan-target" type="text" placeholder="192.168.1.1 or example.com">
      <select id="scan-type">
        <option value="ping">Ping Sweep</option>
        <option value="ports" selected>Port Scan</option>
        <option value="basic">Service Scan</option>
        <option value="full">Full Scan (-A)</option>
      </select>
      <button class="btn btn-sm btn-green" onclick="startScan()">▶ Start Scan</button>
    </div>
    <div id="scan-msg" style="margin-top:10px;font-size:.85rem"></div>
  </div>
  <div class="card" id="scan-output-card" style="display:none">
    <h2><span class="icon">📟</span> Scan Output — <span id="scan-output-id"></span>
      <span id="scan-live-badge" class="badge badge-running" style="margin-left:8px">live</span>
    </h2>
    <div id="scan-output-box"></div>
  </div>
</div>

<!-- ═══ RESULTS ═══ -->
<div id="page-results" class="page">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px">
    <h1 style="font-size:1.3rem">📋 Scan Results</h1>
    <button class="btn btn-sm btn-blue" onclick="loadScans()">↻ Refresh</button>
  </div>
  <div class="card">
    <table class="scan-table">
      <thead><tr><th>ID</th><th>Target</th><th>Type</th><th>User</th><th>Status</th><th>Duration</th><th>Actions</th></tr></thead>
      <tbody id="results-tbody"></tbody>
    </table>
  </div>
  <!-- Detail panel -->
  <div class="card" id="result-detail" style="display:none">
    <h2><span class="icon">📄</span> Output — <span id="detail-id"></span></h2>
    <div id="scan-output-box2" style="
      background:var(--bg);border:1px solid var(--border);border-radius:8px;
      padding:14px;font-family:'Courier New',monospace;font-size:.8rem;
      line-height:1.6;color:#a8c4a2;max-height:320px;overflow-y:auto;
      white-space:pre-wrap;word-break:break-all"></div>
  </div>
</div>

<!-- ═══ CONSOLE (CLI + Health) ═══ -->
<div id="page-cli" class="page">
  <!-- CLI Terminal -->
  <div class="card">
    <h2 style="justify-content:space-between">
      <span><span class="icon">▶</span> Live Terminal</span>
      <button class="btn btn-sm btn-secondary" onclick="cliClear()">CLR</button>
    </h2>
    <div id="live-cli-output"></div>
    <div class="cli-input-row">
      <span class="cli-prompt">root@vulnscan:~$</span>
      <input id="cli-input" type="text" placeholder="enter command…"
             onkeydown="cliKey(event)" autocomplete="off" spellcheck="false">
      <button class="btn btn-sm btn-green" onclick="cliRun()">RUN</button>
    </div>
    <div class="cli-status-bar">
      <span>History: <span id="cli-hist-count">0</span></span>
      <span>Exit: <span id="cli-exit-code">—</span></span>
      <span id="cli-running-indicator" style="color:var(--orange);display:none">⏳ running…</span>
    </div>
    <div class="quick-btns">
      <button class="qbtn" onclick="cliQuick('uptime')">uptime</button>
      <button class="qbtn" onclick="cliQuick('df -h')">df -h</button>
      <button class="qbtn" onclick="cliQuick('free -h')">free -h</button>
      <button class="qbtn" onclick="cliQuick('ps aux --sort=-%cpu | head -10')">top procs</button>
      <button class="qbtn" onclick="cliQuick('ss -tlnp')">ss -tlnp</button>
      <button class="qbtn" onclick="cliQuick('ip addr')">ip addr</button>
      <button class="qbtn" onclick="cliQuick('uname -a')">uname</button>
      <button class="qbtn" onclick="cliQuick('hostname -I')">hostname</button>
      <button class="qbtn" onclick="cliQuick('cat /etc/os-release')">OS info</button>
      <button class="qbtn" onclick="cliQuick('last -10')">last logins</button>
      <button class="qbtn" onclick="cliQuick('journalctl -n 20 --no-pager 2>/dev/null || tail -20 /var/log/syslog 2>/dev/null')">recent logs</button>
      <button class="qbtn" onclick="cliQuick('which nmap nikto sqlmap hydra john hashcat masscan gobuster ffuf netcat 2>/dev/null')">check tools</button>
      <button class="qbtn" onclick="cliQuick('ls /home/')">home dirs</button>
      <button class="qbtn" onclick="cliQuick('systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null')">services</button>
      <button class="qbtn" onclick="cliQuick('env | grep -v PASS | grep -v SECRET | grep -v KEY | sort')">env vars</button>
    </div>
  </div>

  <!-- Server Health -->
  <div class="card" style="margin-top:4px">
    <h2 style="justify-content:space-between">
      <span><span class="icon">🖥</span> Server Health</span>
      <div style="display:flex;align-items:center;gap:10px">
        <span id="health-last-updated" style="font-size:.75rem;color:var(--muted)"></span>
        <button class="btn btn-sm btn-blue" onclick="loadHealthNow()">↻ Refresh</button>
      </div>
    </h2>
    <div class="health-grid" id="health-grid">
      <!-- CPU -->
      <div class="health-card" style="--card-color:#58a6ff">
        <div class="health-lbl">CPU Usage</div>
        <div class="health-val" id="h-cpu">—</div>
        <div class="health-sub" id="h-cpu-cores">— cores</div>
        <div class="health-bar"><div class="health-bar-fill" id="h-cpu-bar" style="width:0%"></div></div>
      </div>
      <!-- Memory -->
      <div class="health-card" style="--card-color:#a371f7">
        <div class="health-lbl">Memory</div>
        <div class="health-val" id="h-ram">—</div>
        <div class="health-sub" id="h-ram-detail">— GB used</div>
        <div class="health-bar"><div class="health-bar-fill" id="h-ram-bar" style="width:0%"></div></div>
      </div>
      <!-- Disk -->
      <div class="health-card" style="--card-color:#d29922">
        <div class="health-lbl">Disk /</div>
        <div class="health-val" id="h-disk">—</div>
        <div class="health-sub" id="h-disk-detail">— GB used</div>
        <div class="health-bar"><div class="health-bar-fill" id="h-disk-bar" style="width:0%"></div></div>
      </div>
      <!-- Uptime -->
      <div class="health-card" style="--card-color:#3fb950">
        <div class="health-lbl">Uptime</div>
        <div class="health-val" id="h-uptime" style="font-size:1.1rem;margin-top:8px">—</div>
        <div class="health-sub" id="h-load">load: —</div>
      </div>
      <!-- Public IP -->
      <div class="health-card" style="--card-color:#39d353">
        <div class="health-lbl">Public IP</div>
        <div class="health-val" id="h-pubip" style="font-size:1rem;margin-top:8px;word-break:break-all">—</div>
        <div class="health-sub" id="h-hostname-h">host: —</div>
      </div>
      <!-- Network -->
      <div class="health-card" style="--card-color:#58a6ff">
        <div class="health-lbl">Network</div>
        <div class="health-val" id="h-net" style="font-size:1rem;margin-top:8px">—</div>
        <div class="health-sub" id="h-net-detail">↓— ↑—</div>
      </div>
      <!-- Processes -->
      <div class="health-card" style="--card-color:#f85149">
        <div class="health-lbl">Processes</div>
        <div class="health-val" id="h-procs">—</div>
        <div class="health-sub" id="h-procs-detail">— running</div>
        <div class="health-bar"><div class="health-bar-fill" id="h-procs-bar" style="width:0%"></div></div>
      </div>
      <!-- Tools -->
      <div class="health-card" style="--card-color:#a371f7;grid-column:span 1">
        <div class="health-lbl">Security Tools</div>
        <div class="health-val" id="h-tools-count">—</div>
        <div class="health-bar"><div class="health-bar-fill" id="h-tools-bar" style="width:0%"></div></div>
        <div class="tools-grid" id="h-tools-list"></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ ADMIN ═══ -->
<div id="page-admin" class="page">
  <h1 style="font-size:1.3rem;margin-bottom:18px">⚙ Admin Panel</h1>
  <!-- User Management -->
  <div class="card">
    <h2><span class="icon">👥</span> User Management</h2>
    <div class="scan-row" style="margin-bottom:14px">
      <input id="new-username" type="text" placeholder="Username">
      <input id="new-password" type="password" placeholder="Password">
      <select id="new-role">
        <option value="analyst">Analyst</option>
        <option value="admin">Admin</option>
      </select>
      <button class="btn btn-sm btn-green" onclick="createUser()">+ Add User</button>
    </div>
    <table class="scan-table">
      <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
      <tbody id="users-tbody"></tbody>
    </table>
  </div>
</div>

<script>
// ─── State ────────────────────────────────────────────────────────────────────
let currentUser = null, currentRole = null;
let cliHistory = [], cliHistIdx = -1;
let healthInterval = null, activePage = '';
let liveScanId = null, liveScanInterval = null;

// ─── Page navigation ──────────────────────────────────────────────────────────
function pg(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b => b.classList.remove('active'));
  const p = document.getElementById('page-' + name);
  if (p) p.classList.add('active');
  if (btn) btn.classList.add('active');
  activePage = name;

  if (name === 'dash') loadDash();
  if (name === 'results') loadScans();
  if (name === 'admin') loadUsers();
  if (name === 'cli') {
    cliWelcome();
    loadHealthNow();
    startHealthAuto();
  } else {
    stopHealthAuto();
  }
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
async function doLogin() {
  const u = document.getElementById('login-user').value.trim();
  const p = document.getElementById('login-pass').value;
  document.getElementById('login-err').textContent = '';
  try {
    const r = await api('/api/login', {method:'POST', body:{username:u, password:p}});
    currentUser = r.user; currentRole = r.role;
    showApp();
  } catch(e) {
    document.getElementById('login-err').textContent = e.message || 'Login failed';
  }
}

async function doLogout() {
  await api('/api/logout', {method:'POST'}).catch(()=>{});
  currentUser = null; currentRole = null;
  document.getElementById('navbar').style.display = 'none';
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-login').classList.add('active');
  document.getElementById('login-pass').value = '';
}

function showApp() {
  document.getElementById('page-login').classList.remove('active');
  document.getElementById('navbar').style.display = 'flex';
  document.getElementById('badge-user').textContent = currentUser;
  document.getElementById('badge-role').textContent = currentRole;
  // Show/hide admin-only items
  document.querySelectorAll('.admin-only').forEach(el => {
    el.style.display = currentRole === 'admin' ? '' : 'none';
  });
  pg('dash', document.getElementById('nav-dash-btn'));
}

// ─── API helper ───────────────────────────────────────────────────────────────
async function api(url, opts={}) {
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: {'Content-Type':'application/json'},
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin'
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString();
}
function fmtDur(s) {
  if (!s.finished) return '—';
  const d = Math.round(s.finished - s.started);
  return d < 60 ? `${d}s` : `${Math.floor(d/60)}m ${d%60}s`;
}
function statusBadge(st) {
  const map = {running:'badge-running',completed:'badge-completed',error:'badge-error',timeout:'badge-timeout'};
  return `<span class="badge ${map[st]||'badge-running'}">${st}</span>`;
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
async function loadDash() {
  const d = await api('/api/scans').catch(()=>({scans:[]}));
  const scans = d.scans || [];
  document.getElementById('ds-total').textContent   = scans.length;
  document.getElementById('ds-running').textContent = scans.filter(s=>s.status==='running').length;
  document.getElementById('ds-done').textContent    = scans.filter(s=>s.status==='completed').length;
  document.getElementById('ds-errors').textContent  = scans.filter(s=>['error','timeout'].includes(s.status)).length;

  const tbody = document.getElementById('dash-recent');
  const recent = scans.slice(0,8);
  tbody.innerHTML = recent.length ? recent.map(s=>`
    <tr>
      <td style="font-family:monospace;color:var(--muted)">${s.id}</td>
      <td><strong>${s.target}</strong></td>
      <td>${s.type}</td>
      <td>${statusBadge(s.status)}</td>
      <td style="color:var(--muted)">${fmtTime(s.started)}</td>
    </tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No scans yet</td></tr>';
}

// ─── Scan ─────────────────────────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById('scan-target').value.trim();
  const type   = document.getElementById('scan-type').value;
  if (!target) { document.getElementById('scan-msg').innerHTML = '<div class="alert alert-danger">Target required</div>'; return; }
  document.getElementById('scan-msg').innerHTML = '<span style="color:var(--muted)">Starting scan…</span>';
  try {
    const r = await api('/api/scan', {method:'POST', body:{target, type}});
    liveScanId = r.scan_id;
    document.getElementById('scan-msg').innerHTML = `<div class="alert alert-success">Scan started: ${r.scan_id}</div>`;
    document.getElementById('scan-output-card').style.display = 'block';
    document.getElementById('scan-output-id').textContent = r.scan_id;
    document.getElementById('scan-live-badge').style.display = 'inline';
    document.getElementById('scan-output-box').textContent = '';
    startLiveScan(r.scan_id);
  } catch(e) {
    document.getElementById('scan-msg').innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
  }
}

function startLiveScan(id) {
  if (liveScanInterval) clearInterval(liveScanInterval);
  liveScanInterval = setInterval(async () => {
    try {
      const s = await api('/api/scan/' + id);
      document.getElementById('scan-output-box').textContent = (s.output || []).join('\n');
      if (s.status !== 'running') {
        clearInterval(liveScanInterval);
        document.getElementById('scan-live-badge').style.display = 'none';
      }
    } catch(e) { clearInterval(liveScanInterval); }
  }, 1500);
}

// ─── Results ──────────────────────────────────────────────────────────────────
async function loadScans() {
  const d = await api('/api/scans').catch(()=>({scans:[]}));
  const tbody = document.getElementById('results-tbody');
  const scans = d.scans || [];
  tbody.innerHTML = scans.length ? scans.map(s=>`
    <tr>
      <td style="font-family:monospace;font-size:.8rem;color:var(--muted)">${s.id}</td>
      <td><strong>${s.target}</strong></td>
      <td>${s.type}</td>
      <td><span class="badge ${s.role==='admin'?'badge-admin':'badge-analyst'}">${s.user||'—'}</span></td>
      <td>${statusBadge(s.status)}</td>
      <td style="color:var(--muted)">${fmtDur(s)}</td>
      <td>
        <button class="btn btn-sm btn-blue" onclick="showScanDetail('${s.id}')">View</button>
        ${currentRole==='admin' ? `<button class="btn btn-sm btn-danger" onclick="deleteScan('${s.id}')" style="margin-left:4px">Del</button>` : ''}
      </td>
    </tr>`).join('') :
    '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No scans yet</td></tr>';
}

async function showScanDetail(id) {
  const s = await api('/api/scan/' + id).catch(()=>null);
  if (!s) return;
  document.getElementById('result-detail').style.display = 'block';
  document.getElementById('detail-id').textContent = id;
  document.getElementById('scan-output-box2').textContent = (s.output||[]).join('\n') || '(no output)';
  document.getElementById('result-detail').scrollIntoView({behavior:'smooth'});
}

async function deleteScan(id) {
  if (!confirm(`Delete scan ${id}?`)) return;
  await api('/api/scan/' + id, {method:'DELETE'}).catch(()=>{});
  loadScans();
}

// ─── CLI Terminal ─────────────────────────────────────────────────────────────
function cliWelcome() {
  const out = document.getElementById('live-cli-output');
  if (out.children.length === 0) {
    cliAppend('sys', '╔══════════════════════════════════════╗');
    cliAppend('sys', '║   VulnScan Pro — Admin Terminal      ║');
    cliAppend('sys', '╚══════════════════════════════════════╝');
    cliAppend('sys', 'Type a command or use quick buttons below.');
    cliAppend('sys', '');
  }
}

function cliAppend(type, text) {
  const out = document.getElementById('live-cli-output');
  const line = document.createElement('span');
  line.className = `cli-line cli-${type}-line`;
  line.textContent = text;
  out.appendChild(line);
  out.appendChild(document.createElement('br'));
  out.scrollTop = out.scrollHeight;
}

function cliKey(e) {
  if (e.key === 'Enter') { cliRun(); return; }
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (cliHistory.length === 0) return;
    cliHistIdx = Math.max(0, cliHistIdx < 0 ? cliHistory.length - 1 : cliHistIdx - 1);
    document.getElementById('cli-input').value = cliHistory[cliHistIdx];
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (cliHistIdx < 0) return;
    cliHistIdx++;
    if (cliHistIdx >= cliHistory.length) { cliHistIdx = -1; document.getElementById('cli-input').value = ''; }
    else document.getElementById('cli-input').value = cliHistory[cliHistIdx];
  }
  if (e.key === 'Tab') {
    e.preventDefault();
    const val = document.getElementById('cli-input').value.trim();
    const hints = ['nmap','nikto','sqlmap','ps','ls','pwd','cat','grep','curl','wget','netstat','ss','ip','uname','df','free','top','htop','ping','traceroute','systemctl','journalctl'];
    const match = hints.filter(h => h.startsWith(val.split(' ').pop()));
    if (match.length === 1 && val.split(' ').length === 1) {
      document.getElementById('cli-input').value = match[0];
    } else if (match.length > 1) {
      cliAppend('sys', 'Hints: ' + match.join('  '));
    }
  }
}

async function cliRun() {
  const input = document.getElementById('cli-input');
  const cmd = input.value.trim();
  if (!cmd) return;

  cliAppend('cmd', '$ ' + cmd);
  cliHistory.push(cmd);
  cliHistIdx = -1;
  document.getElementById('cli-hist-count').textContent = cliHistory.length;
  input.value = '';
  document.getElementById('cli-running-indicator').style.display = 'inline';

  try {
    const r = await api('/api/admin/cli', {method:'POST', body:{command:cmd}});
    const lines = (r.output || '').split('\n');
    lines.forEach(l => cliAppend(r.exit_code === 0 ? 'out' : 'err', l));
    document.getElementById('cli-exit-code').textContent = r.exit_code;
    document.getElementById('cli-exit-code').style.color = r.exit_code === 0 ? 'var(--green)' : 'var(--red)';
  } catch(e) {
    cliAppend('err', '[ERROR] ' + e.message);
  } finally {
    document.getElementById('cli-running-indicator').style.display = 'none';
  }
}

function cliClear() {
  document.getElementById('live-cli-output').innerHTML = '';
  cliWelcome();
}

function cliQuick(cmd) {
  document.getElementById('cli-input').value = cmd;
  cliRun();
}

// ─── Health ───────────────────────────────────────────────────────────────────
function startHealthAuto() {
  stopHealthAuto();
  healthInterval = setInterval(() => { if (activePage === 'cli') loadHealthNow(); }, 30000);
}
function stopHealthAuto() {
  if (healthInterval) { clearInterval(healthInterval); healthInterval = null; }
}

async function loadHealthNow() {
  try {
    const h = await api('/api/health/system');
    setHealth(h);
    document.getElementById('health-last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('health-last-updated').textContent = 'Error loading health';
  }
}

function setBar(id, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(100, pct) + '%';
  if (pct > 85) el.style.background = 'var(--red)';
  else if (pct > 65) el.style.background = 'var(--orange)';
}

function setHealth(h) {
  // CPU
  document.getElementById('h-cpu').textContent = h.cpu_percent + '%';
  document.getElementById('h-cpu-cores').textContent = h.cpu_cores + ' cores';
  setBar('h-cpu-bar', h.cpu_percent);

  // RAM
  document.getElementById('h-ram').textContent = h.ram_percent + '%';
  document.getElementById('h-ram-detail').textContent = `${h.ram_used_gb} / ${h.ram_total_gb} GB`;
  setBar('h-ram-bar', h.ram_percent);

  // Disk
  document.getElementById('h-disk').textContent = h.disk_percent + '%';
  document.getElementById('h-disk-detail').textContent = `${h.disk_used_gb} / ${h.disk_total_gb} GB`;
  setBar('h-disk-bar', h.disk_percent);

  // Uptime
  document.getElementById('h-uptime').textContent = h.uptime;
  document.getElementById('h-load').textContent = 'load: ' + h.load_avg;

  // IP
  document.getElementById('h-pubip').textContent = h.public_ip;
  document.getElementById('h-hostname-h').textContent = 'host: ' + h.hostname;

  // Network
  document.getElementById('h-net').textContent = h.net_iface;
  document.getElementById('h-net-detail').textContent = `↓${h.net_rx}  ↑${h.net_tx}`;

  // Procs
  document.getElementById('h-procs').textContent = h.procs_total;
  document.getElementById('h-procs-detail').textContent = h.procs_running + ' running';
  setBar('h-procs-bar', Math.min(100, (h.procs_total / 500) * 100));

  // Tools
  const tools = h.tools || {};
  const installed = Object.values(tools).filter(Boolean).length;
  const total = Object.keys(tools).length;
  document.getElementById('h-tools-count').textContent = `${installed} / ${total}`;
  setBar('h-tools-bar', total > 0 ? (installed/total)*100 : 0);
  const grid = document.getElementById('h-tools-list');
  grid.innerHTML = Object.entries(tools).map(([t, ok]) =>
    `<span class="tool-pill ${ok ? '' : 'missing'}">${t}</span>`).join('');
}

// ─── Admin ────────────────────────────────────────────────────────────────────
async function loadUsers() {
  const d = await api('/api/admin/users').catch(()=>({users:[]}));
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = (d.users||[]).map(u=>`
    <tr>
      <td>${u.username}</td>
      <td><span class="badge ${u.role==='admin'?'badge-admin':'badge-analyst'}">${u.role}</span></td>
      <td>${u.username !== currentUser ? `<button class="btn btn-sm btn-danger" onclick="deleteUser('${u.username}')">Delete</button>` : '<em style="color:var(--muted)">you</em>'}</td>
    </tr>`).join('');
}

async function createUser() {
  const username = document.getElementById('new-username').value.trim();
  const password = document.getElementById('new-password').value.trim();
  const role = document.getElementById('new-role').value;
  if (!username || !password) { alert('Username and password required'); return; }
  try {
    await api('/api/admin/users', {method:'POST', body:{username, password, role}});
    document.getElementById('new-username').value = '';
    document.getElementById('new-password').value = '';
    loadUsers();
  } catch(e) { alert(e.message); }
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  await api(`/api/admin/users/${username}`, {method:'DELETE'}).catch(e=>alert(e.message));
  loadUsers();
}

// ─── Init ─────────────────────────────────────────────────────────────────────
(async () => {
  try {
    const r = await api('/api/me');
    currentUser = r.user; currentRole = r.role;
    showApp();
  } catch(e) { /* not logged in */ }
})();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] VulnScan Pro running on http://0.0.0.0:{port}")
    print(f"[*] Default credentials: admin/admin123  |  analyst/analyst123")
    app.run(host="0.0.0.0", port=port, debug=False)
