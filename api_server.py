#!/usr/bin/env python3
"""
VulnScan Pro — API Server
All scan tools route through Tor/proxychains for anonymity.

REQUIREMENTS:
  sudo apt install tor proxychains4 nmap nikto dnsrecon lynis
  pip3 install PySocks --break-system-packages
  Tor must be running on 127.0.0.1:9050 (default)

PROXYCHAINS CONFIG (/etc/proxychains4.conf or /etc/proxychains.conf):
  [ProxyList]
  socks5 127.0.0.1 9050
"""
import json, re, sys, os, subprocess, io, sqlite3, secrets, hashlib, threading, shlex, time, shutil
from urllib.parse import urlparse
from flask import Flask, request, jsonify, Response, send_file, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)

CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": re.compile(r"https?://(localhost|127\.0\.0\.1)(:\d+)?$")}})

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

from database import save_scan, get_history, get_scan_by_id
from auth import register_auth_routes, get_current_user, audit

register_auth_routes(app)

GRADE_COL = {"A+": "#00ff9d", "A": "#00e5ff", "B": "#ffd60a", "C": "#ff6b35", "D": "#ff6b35", "F": "#ff3366"}

# ── Tor / proxychains config ──────────────────────────────────────────────────
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

# ── Timeout constants (all inflated for Tor latency) ─────────────────────────
TIMEOUT_SCAN       = 720   # 12 min — nmap through Tor can be slow
TIMEOUT_SUBDOMAIN  = 180   # 3 min
TIMEOUT_DIRBUST    = 360   # 6 min
TIMEOUT_BRUTE      = 180   # 3 min
TIMEOUT_DISCOVER   = 300   # 5 min
TIMEOUT_HARVESTER  = 240   # 4 min
TIMEOUT_DNSRECON   = 180   # 3 min
TIMEOUT_NIKTO      = 900   # 15 min — Nikto through Tor is very slow
TIMEOUT_WPSCAN     = 480   # 8 min
TIMEOUT_LYNIS      = 360   # 6 min
TIMEOUT_LEGION     = 1200  # 20 min
TIMEOUT_REPORT     = 90    # 1.5 min
TIMEOUT_WEB_DEEP   = 1800  # 30 min

AGENT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_jobs.db")
AGENT_LOCK = threading.Lock()
AGENT_SERVER_URL = os.environ.get("VULNSCAN_AGENT_SERVER_URL", "http://161.118.189.254:5000")
LYNIS_QUEUE_LIMIT = 8
LYNIS_OVERVIEW_LIMIT_DEFAULT = 12


def _agent_db():
    con = sqlite3.connect(AGENT_DB)
    con.row_factory = sqlite3.Row
    return con


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
        con.close()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
        con.execute("UPDATE agent_clients SET last_seen=datetime('now'), ip_seen=?, status='online' WHERE client_id=?",
                    (req.remote_addr or "", row["client_id"]))
        con.commit()
    con.close()
    return row["client_id"] if row else None


init_agent_db()


def run_backend(*args, timeout=300):
    """
    Run backend.py as a subprocess. Returns parsed JSON dict.
    Increased default timeout for Tor-routed scans.
    """
    cmd = [sys.executable, BACKEND] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Backend process timed out after {timeout}s. Through Tor this is normal — try a smaller scan scope or increase the timeout."}
    except FileNotFoundError:
        return {"error": f"Python interpreter not found: {sys.executable}"}

    if r.stderr and r.stderr.strip():
        print(f"[backend stderr] {r.stderr.strip()[:500]}", file=sys.stderr)

    if not r.stdout or not r.stdout.strip():
        err_detail = r.stderr.strip()[:300] if r.stderr else "No output from backend"
        return {"error": f"Backend returned no output. Details: {err_detail}"}

    raw = r.stdout.strip()
    start = raw.find('{')
    end = raw.rfind('}')
    if start == -1 or end == -1:
        return {"error": f"No JSON in backend output: {raw[:300]}"}
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}. Raw: {raw[start:start+200]}"}


def proxychains_cmd():
    """Return the available proxychains binary name."""
    import shutil
    return shutil.which("proxychains4") or shutil.which("proxychains") or "proxychains4"


def required_web_tools():
    """Tool suggestions for full web audits on Linux servers."""
    return [
        {"tool": "nmap", "install": "sudo apt install nmap"},
        {"tool": "nikto", "install": "sudo apt install nikto"},
        {"tool": "dnsrecon", "install": "sudo apt install dnsrecon"},
        {"tool": "whatweb", "install": "sudo apt install whatweb"},
        {"tool": "nuclei", "install": "sudo apt install nuclei || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        {"tool": "wpscan", "install": "sudo gem install wpscan"},
        {"tool": "sqlmap", "install": "sudo apt install sqlmap"},
    ]


# ══════════════════════════════════════════════
# HTML UI — injected from api_server original
# (keeping the full HTML block intact — no changes needed to UI)
# ══════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#ffffff;--bg2:#f5f5f5;--bg3:#ebebeb;
  --border:#e0e0e0;--border2:#d0d0d0;
  --text:#0a0a0a;--text2:#444444;--text3:#888888;
  --accent:#0a0a0a;--accent-inv:#ffffff;
  --red:#c0392b;--orange:#d35400;--yellow:#b7860b;--green:#1a7a3a;--blue:#1a5fa8;
  --mono:'DM Mono',monospace;--sans:'DM Sans',sans-serif;
  --radius:6px;--radius-lg:10px;
  --shadow:0 1px 3px rgba(0,0,0,0.08),0 1px 2px rgba(0,0,0,0.06);
  --shadow-md:0 4px 12px rgba(0,0,0,0.1);
  --transition:0.15s ease;
  --ease-spring:cubic-bezier(0.34,1.56,0.64,1);
  --ease-out:cubic-bezier(0.16,1,0.3,1);
}
body.dark{
  --bg:#0a0a0a;--bg2:#111111;--bg3:#1a1a1a;
  --border:#252525;--border2:#333333;
  --text:#f0f0f0;--text2:#aaaaaa;--text3:#666666;
  --accent:#f0f0f0;--accent-inv:#0a0a0a;
  --red:#e05a4e;--orange:#e07840;--yellow:#d4a840;--green:#3db870;--blue:#5a9fe0;
  --shadow:0 1px 3px rgba(0,0,0,0.4),0 1px 2px rgba(0,0,0,0.3);
  --shadow-md:0 4px 12px rgba(0,0,0,0.5);
}
html{scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;
  line-height:1.6;min-height:100vh;transition:background var(--transition),color var(--transition);
  -webkit-font-smoothing:antialiased;isolation:isolate;position:relative;
}
/* Hacker canvas behind everything */
#vs-hacker-canvas{
  position:fixed!important;top:0!important;left:0!important;
  width:100vw!important;height:100vh!important;
  pointer-events:none!important;z-index:-1!important;
}
.layout{display:flex;min-height:100vh;position:relative;z-index:1}
.sidebar{
  width:220px;flex-shrink:0;background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;
  overflow-y:auto;z-index:50;transition:background var(--transition),border-color var(--transition);
}
.main{margin-left:220px;flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{
  height:52px;background:var(--bg);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;padding:0 24px;
  position:sticky;top:0;z-index:40;transition:background var(--transition),border-color var(--transition);
}
.content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden;width:100%;position:relative;z-index:2}
.brand{padding:20px 18px 16px;border-bottom:1px solid var(--border)}
.brand-logo{display:flex;align-items:center;gap:10px;text-decoration:none;cursor:pointer}
.brand-icon{
  width:28px;height:28px;background:var(--accent);border-radius:var(--radius);
  display:flex;align-items:center;justify-content:center;color:var(--accent-inv);font-size:14px;flex-shrink:0;
}
.brand-title{font-size:15px;font-weight:600;color:var(--text);letter-spacing:-0.3px}
.brand-sub{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:1.5px;margin-top:1px}
.nav-section{padding:14px 10px 4px}
.nav-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;padding:0 8px;margin-bottom:4px;font-weight:500}
.nav-item{
  display:flex;align-items:center;gap:9px;padding:7px 8px;border-radius:var(--radius);
  cursor:pointer;font-size:13px;color:var(--text2);
  transition:background var(--transition),color var(--transition),transform 0.14s var(--ease-spring);
  border:none;background:none;width:100%;text-align:left;font-family:var(--sans);
}
.nav-item:hover{background:var(--bg3);color:var(--text);transform:translateX(2px)}
.nav-item.active{background:var(--accent);color:var(--accent-inv);transform:translateX(0)}
.nav-item .ni{font-size:14px;width:18px;text-align:center;flex-shrink:0}
.sidebar-footer{margin-top:auto;padding:12px 10px;border-top:1px solid var(--border)}
.tb-title{font-size:14px;font-weight:500;color:var(--text);letter-spacing:-0.2px}
.tb-right{display:flex;align-items:center;gap:10px}
.theme-toggle{
  width:36px;height:20px;background:var(--border2);border-radius:10px;
  position:relative;cursor:pointer;border:none;
  transition:background 0.28s ease;flex-shrink:0;
}
.theme-toggle::after{
  content:'';position:absolute;top:3px;left:3px;width:14px;height:14px;
  background:var(--accent);border-radius:50%;
  transition:transform 0.28s var(--ease-spring);
}
body.dark .theme-toggle::after{transform:translateX(16px)}
.user-chip{
  display:flex;align-items:center;gap:8px;padding:5px 10px 5px 6px;
  border:1px solid var(--border);border-radius:20px;cursor:pointer;
  transition:border-color var(--transition),background var(--transition);
  background:none;font-family:var(--sans);
}
.user-chip:hover{border-color:var(--border2);background:var(--bg2)}
.user-av{
  width:22px;height:22px;border-radius:50%;background:var(--accent);color:var(--accent-inv);
  font-size:11px;font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0;
}
.user-name{font-size:12px;font-weight:500;color:var(--text)}
.user-role{font-family:var(--mono);font-size:9px;color:var(--text3);margin-top:1px}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:8px 14px;border-radius:var(--radius);font-family:var(--sans);font-size:13px;
  font-weight:500;cursor:pointer;border:1px solid transparent;
  transition:all var(--transition);white-space:nowrap;text-decoration:none;
}
.btn-primary{background:var(--accent);color:var(--accent-inv);border-color:var(--accent)}
.btn-primary:hover{opacity:0.85;transform:translateY(-1px)}
.btn-primary:active{transform:scale(0.97)}
.btn-primary:disabled{opacity:0.4;cursor:not-allowed;transform:none}
.btn-outline{background:none;color:var(--text);border-color:var(--border2)}
.btn-outline:hover{border-color:var(--text);background:var(--bg2)}
.btn-ghost{background:none;color:var(--text2);border-color:transparent}
.btn-ghost:hover{background:var(--bg3);color:var(--text)}
.btn-danger{background:none;color:var(--red);border-color:rgba(192,57,43,0.3)}
.btn-danger:hover{background:rgba(192,57,43,0.08)}
.btn-sm{padding:5px 10px;font-size:12px}
.btn-full{width:100%}
.card{
  background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);
  position:relative;z-index:2;
  transition:border-color var(--transition),background var(--transition),box-shadow 0.2s ease;
}
.card-p{padding:20px}
.card-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.card-title{font-size:13px;font-weight:600;color:var(--text);letter-spacing:-0.1px}
.card-sub{font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:1px;margin-top:3px}
.page-hd{margin-bottom:24px}
.page-title{font-size:22px;font-weight:600;letter-spacing:-0.5px;color:var(--text);line-height:1.2}
.page-desc{font-size:13px;color:var(--text3);margin-top:5px}
.inp{
  width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:var(--radius);
  color:var(--text);padding:9px 12px;font-size:13px;font-family:var(--sans);outline:none;
  transition:border-color var(--transition),box-shadow var(--transition);
}
.inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(10,10,10,0.08)}
body.dark .inp:focus{box-shadow:0 0 0 3px rgba(240,240,240,0.1)}
.inp::placeholder{color:var(--text3)}
.inp-mono{font-family:var(--mono);font-size:13px}
.fg{margin-bottom:14px}
.fg label{display:block;font-size:11px;font-weight:500;color:var(--text3);letter-spacing:0.5px;margin-bottom:5px}
textarea.inp{resize:vertical;min-height:80px}
select.inp{cursor:pointer}
select.inp:not([multiple]){
  appearance:none;-webkit-appearance:none;-moz-appearance:none;
  padding-right:38px;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");
  background-repeat:no-repeat;
  background-position:right 12px center;
  background-size:14px;
}
.scan-bar{display:flex;gap:8px;align-items:center}
.scan-bar .inp{font-family:var(--mono);flex:1}
.pills{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.pill{
  padding:4px 12px;border-radius:20px;font-family:var(--mono);font-size:11px;
  border:1px solid var(--border2);color:var(--text2);background:none;cursor:pointer;
  transition:background 0.18s var(--ease-spring),color 0.14s ease,border-color 0.14s ease,transform 0.14s var(--ease-spring);
}
.pill:hover{transform:scale(1.04)}
.pill:active{transform:scale(0.97)}
.pill.on{background:var(--accent);color:var(--accent-inv);border-color:var(--accent)}
.progress-wrap{height:2px;background:var(--bg3);border-radius:1px;overflow:hidden;margin:12px 0;display:none}
.progress-bar{height:100%;background:var(--accent);border-radius:1px;transition:width 0.3s;position:relative;overflow:hidden}
.progress-bar::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);animation:pbShimmer 1.2s ease infinite}
@keyframes pbShimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.progress-wrap.active{display:block}
.terminal{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:12px 14px;overflow-y:auto;font-family:var(--mono);
  font-size:12px;line-height:1.8;display:none;margin:12px 0;
  position:relative;z-index:2;
}
.terminal.visible{display:block}
.tl-i{color:var(--text3)}.tl-s{color:var(--green)}.tl-w{color:var(--yellow)}.tl-e{color:var(--red)}
.tl-prefix{font-weight:500}
.err-box{
  background:rgba(192,57,43,0.06);border:1px solid rgba(192,57,43,0.2);border-radius:var(--radius);
  padding:10px 14px;color:var(--red);font-size:13px;font-family:var(--mono);display:none;margin:10px 0;
  position:relative;z-index:2;
}
.err-box.visible{display:block}
.notice{
  background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--yellow);
  border-radius:var(--radius);padding:10px 14px;font-size:12px;color:var(--text2);margin-bottom:16px;
  position:relative;z-index:2;
}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:20px;width:100%;position:relative;z-index:2}
.stat{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:14px 12px;text-align:center;
  position:relative;z-index:2;
  transition:background var(--transition),border-color var(--transition);
}
.stat-val{font-family:var(--mono);font-size:26px;font-weight:500;color:var(--text);line-height:1;margin-bottom:4px}
.stat-lbl{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:1.5px}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:18px;overflow-x:auto;position:relative;z-index:2;background:var(--bg)}
.tab{
  padding:9px 16px;font-size:12px;font-family:var(--mono);color:var(--text3);
  background:none;border:none;cursor:pointer;border-bottom:2px solid transparent;
  margin-bottom:-1px;white-space:nowrap;
  transition:color var(--transition),border-color var(--transition);letter-spacing:0.5px;
}
.tab:hover{color:var(--text)}.tab.active{color:var(--text);border-bottom-color:var(--accent)}
.tc{display:none}.tc.active{display:block}
.sev{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:10px;font-weight:500;border:1px solid transparent}
.sev-critical{background:rgba(192,57,43,0.1);color:var(--red);border-color:rgba(192,57,43,0.2)}
.sev-high{background:rgba(211,84,0,0.1);color:var(--orange);border-color:rgba(211,84,0,0.2)}
.sev-medium{background:rgba(183,134,11,0.1);color:var(--yellow);border-color:rgba(183,134,11,0.2)}
.sev-low{background:rgba(26,122,58,0.1);color:var(--green);border-color:rgba(26,122,58,0.2)}
.sev-unknown{background:var(--bg2);color:var(--text3);border-color:var(--border)}
.port-panel{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:8px;width:100%;position:relative;z-index:2;background:var(--bg);transition:border-color var(--transition)}
.port-panel:hover{border-color:var(--border2)}
.port-hd{display:flex;align-items:center;gap:12px;padding:12px 14px;cursor:pointer;user-select:none;flex-wrap:wrap;min-height:52px;background:var(--bg)}
.port-num{font-family:var(--mono);font-size:14px;font-weight:500;color:var(--text);min-width:52px}
.port-svc{font-size:13px;font-weight:500;color:var(--text);flex:1}
.port-ver{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:2px}
.port-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.port-body{padding:14px 20px 20px;border-top:1px solid var(--border);display:none;max-width:100%;overflow-x:auto}
.port-body.open{display:block}
.chev{color:var(--text3);font-size:10px;transition:transform var(--transition);flex-shrink:0}
.chev.open{transform:rotate(180deg)}
.port-score{font-family:var(--mono);font-size:13px;font-weight:600}
.cve-item{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:6px;position:relative;z-index:2}
.cve-hd{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.cve-id{font-family:var(--mono);font-size:12px;font-weight:500;color:var(--text);text-decoration:none}
.cve-id:hover{text-decoration:underline}
.cve-score{font-family:var(--mono);font-size:12px;font-weight:600}
.cve-date{font-family:var(--mono);font-size:10px;color:var(--text3);margin-left:auto}
.cve-desc{font-size:12px;color:var(--text2);line-height:1.7}
.mit-list{margin:0;padding:0;list-style:none}
.mit-item{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;color:var(--text2)}
.mit-item:last-child{border-bottom:none}
.mit-bullet{color:var(--text3);flex-shrink:0;font-size:14px;line-height:1.5}
.sec-label{font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:2px;margin:14px 0 8px}
.ssl-card{border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:8px;display:flex;align-items:flex-start;gap:16px}
.ssl-grade{width:52px;height:52px;border-radius:var(--radius);border:2px solid var(--border2);display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:22px;font-weight:700;flex-shrink:0;color:var(--text)}
.ssl-host{font-size:14px;font-weight:500;color:var(--text)}
.ssl-detail{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:3px}
.ssl-issue{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}
.ssl-issue:last-child{border-bottom:none}
.dns-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-bottom:14px}
.dns-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:12px}
.dns-type{font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:2px;margin-bottom:6px}
.dns-val{font-family:var(--mono);font-size:11px;color:var(--text2);line-height:1.8;word-break:break-all}
.sub-item{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px}
.sub-item:last-child{border-bottom:none}
.hdr-row{display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:11px;flex-wrap:wrap;gap:4px}
.hdr-row:last-child{border-bottom:none}
.hdr-key{color:var(--text3);min-width:180px;flex-shrink:0}
.hdr-val{color:var(--text);word-break:break-all;text-align:right;max-width:380px}
.hdr-grade-big{font-family:var(--mono);font-size:42px;font-weight:700;color:var(--text);line-height:1}
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{font-family:var(--mono);font-size:9px;letter-spacing:2px;color:var(--text3);padding:9px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:500}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--border);color:var(--text);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:var(--bg2)}
.tbl-wrap{overflow-x:auto;width:100%;position:relative;z-index:2;background:var(--bg)}
#res,#hv-res,#nk-res,#wp-res,#ly-res,#lg-res,#dr-res,#sub-res,#dir-res,#bf-res,#disc-res{width:100%;max-width:100%;overflow-x:auto;position:relative;z-index:2}
.tag{display:inline-block;padding:2px 7px;border-radius:3px;font-family:var(--mono);font-size:10px;border:1px solid var(--border);background:var(--bg2);color:var(--text2)}
.host-chip{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;margin-bottom:14px;position:relative;z-index:2}
.host-ip{font-weight:500;color:var(--text)}
.host-up{color:var(--green)}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.kv{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}
.kv-item{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px}
.kv-k{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:1.5px;margin-bottom:4px}
.kv-v{font-size:13px;font-weight:500;color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:10px;font-weight:500}
.badge-admin{background:var(--bg3);color:var(--text2);border:1px solid var(--border2)}
.badge-user{background:var(--bg2);color:var(--text3);border:1px solid var(--border)}
.theme-options{display:flex;gap:10px;margin-top:12px}
.theme-opt{flex:1;padding:14px;border:2px solid var(--border);border-radius:var(--radius-lg);cursor:pointer;background:none;text-align:left;transition:border-color var(--transition);font-family:var(--sans)}
.theme-opt:hover{border-color:var(--border2)}
.theme-opt.active{border-color:var(--accent)}
.theme-swatch{width:100%;height:40px;border-radius:var(--radius);margin-bottom:10px;border:1px solid var(--border)}
.theme-name{font-size:13px;font-weight:500;color:var(--text);margin-bottom:3px}
.theme-desc{font-size:11px;color:var(--text3)}
/* Login overlay -- semi-transparent so hacker bg shows through */
.overlay{
  position:fixed;inset:0;background: var(--bg) !important;
  z-index:200;display:flex;align-items:center;justify-content:center;padding:16px;
  }
body.dark .overlay{background: var(--bg) !important;max-width:380px;position:relative;z-index:1;
  background: var(--bg) !important;border:1px solid var(--border)!important;
  border-radius:14px!important;padding:32px!important;
  box-shadow:0 4px 28px rgba(0,0,0,0.1)!important;
}
body.dark .auth-box{box-shadow:0 4px 36px rgba(0,220,100,0.06),0 2px 16px rgba(0,0,0,0.6)!important
  background: var(--bg) !important;
  border-color: rgba(0,180,60,0.3) !important;}
.auth-logo{display:flex;
  border-color: rgba(0,180,60,0.25) !important;align-items:center;gap:10px;margin-bottom:28px}
.auth-logo-icon{width:32px;height:32px;background:var(--accent);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;color:var(--accent-inv);font-size:16px}
.auth-title{font-size:18px;font-weight:600;color:var(--text);letter-spacing:-0.3px}
.auth-tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}
.auth-tab{padding:8px 14px;font-size:12px;font-family:var(--mono);color:var(--text3);background:none;border:none;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all var(--transition);letter-spacing:0.5px}
.auth-tab.active{color:var(--text);border-bottom-color:var(--accent)}
.auth-msg{padding:9px 12px;border-radius:var(--radius);font-size:12px;font-family:var(--mono);margin-bottom:14px;display:none}
.auth-msg.ok{background:rgba(26,122,58,0.08);border:1px solid rgba(26,122,58,0.2);color:var(--green)}
.auth-msg.err{background:rgba(192,57,43,0.07);border:1px solid rgba(192,57,43,0.2);color:var(--red)}
.auth-link{background:none;border:none;color:var(--text2);cursor:pointer;font-size:12px;font-family:var(--mono);text-decoration:underline;text-underline-offset:2px;padding:0}
.auth-link:hover{color:var(--text)}
.tos-box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;margin-bottom:14px;display:flex;align-items:flex-start;gap:9px}
.tos-box input[type=checkbox]{width:14px;height:14px;margin-top:2px;cursor:pointer;flex-shrink:0;accent-color:var(--accent)}
.tos-box label{font-size:11px;color:var(--text2);line-height:1.6;cursor:pointer}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:300;display:none;align-items:center;justify-content:center;padding:16px;backdrop-filter:blur(4px)}
.modal-bg.open{display:flex}
.modal{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;width:100%;max-width:500px;position:relative;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow-md)}
.modal-close{position:absolute;top:14px;right:14px;background:none;border:none;color:var(--text3);cursor:pointer;font-size:18px;line-height:1;transition:color var(--transition)}
.modal-close:hover{color:var(--text)}
.tos-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:400;display:none;align-items:center;justify-content:center;padding:16px;backdrop-filter:blur(4px)}
.tos-modal-bg.open{display:flex}
.tos-modal{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;width:100%;max-width:560px;max-height:88vh;overflow-y:auto;box-shadow:var(--shadow-md);position:relative}
.tos-section{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-bottom:16px;font-size:12px;color:var(--text2);line-height:1.8}
.tos-section strong{color:var(--text)}
.tos-section h4{font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px}
/* Animations */
@keyframes vs-overlay-in{from{opacity:0}to{opacity:1}}
.overlay{animation:vs-overlay-in 0.35s ease both}
@keyframes vs-box-rise{from{opacity:0;transform:translateY(24px) scale(0.97)}to{opacity:1;transform:translateY(0) scale(1)}}
.auth-box{animation:vs-box-rise 0.5s var(--ease-spring) 0.08s both
  background: var(--bg) !important;}
@keyframes vs-logo-spin{0%{opacity:0;transform:rotate(-18deg) scale(0.7)}65%{transform:rotate(5deg) scale(1.07)}100%{opacity:1;transform:rotate(0deg) scale(1)}}
.auth-logo-icon{animation:vs-logo-spin 0.55s var(--ease-spring) 0.22s both}
@keyframes vs-fade-up{from{opacity:0;transform:translateY(9px)}to{opacity:1;transform:translateY(0)}}
.auth-title{animation:vs-fade-up 0.38s var(--ease-out) 0.32s both}
.auth-tabs{animation:vs-fade-up 0.35s var(--ease-out) 0.42s both}
#form-login .fg:nth-child(1){animation:vs-fade-up 0.32s var(--ease-out) 0.52s both}
#form-login .fg:nth-child(2){animation:vs-fade-up 0.32s var(--ease-out) 0.62s both}
#l-btn{animation:vs-fade-up 0.32s var(--ease-out) 0.72s both}
#form-register .fg:nth-child(1){animation:vs-fade-up 0.32s var(--ease-out) 0.52s both}
#form-register .fg:nth-child(2){animation:vs-fade-up 0.32s var(--ease-out) 0.60s both}
#form-register .fg:nth-child(3){animation:vs-fade-up 0.32s var(--ease-out) 0.68s both}
#form-register .fg:nth-child(4){animation:vs-fade-up 0.32s var(--ease-out) 0.76s both}
@keyframes vs-greet-drop{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
#page-home .page-hd .page-title{animation:vs-greet-drop 0.45s var(--ease-out) 0.05s both}
#page-home .page-hd .page-desc{animation:vs-greet-drop 0.45s var(--ease-out) 0.14s both}
@keyframes vs-stat-pop{from{opacity:0;transform:scale(0.8) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
#home-stats .stat:nth-child(1){animation:vs-stat-pop 0.48s var(--ease-spring) 0.18s both}
#home-stats .stat:nth-child(2){animation:vs-stat-pop 0.48s var(--ease-spring) 0.27s both}
#home-stats .stat:nth-child(3){animation:vs-stat-pop 0.48s var(--ease-spring) 0.36s both}
#home-stats .stat:nth-child(4){animation:vs-stat-pop 0.48s var(--ease-spring) 0.45s both}
@keyframes vs-num-pop{0%{opacity:0;transform:scale(0.55)}65%{transform:scale(1.1)}100%{opacity:1;transform:scale(1)}}
.stat-val.vs-counting{animation:vs-num-pop 0.42s var(--ease-spring) both}
@keyframes vs-card-rise{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
#page-home .card:nth-child(1){animation:vs-card-rise 0.4s var(--ease-out) 0.26s both}
#page-home .card:nth-child(2){animation:vs-card-rise 0.4s var(--ease-out) 0.34s both}
#page-home .card:nth-child(3){animation:vs-card-rise 0.4s var(--ease-out) 0.42s both}
#page-home .card:nth-child(4){animation:vs-card-rise 0.4s var(--ease-out) 0.50s both}
#page-home .card:nth-child(5){animation:vs-card-rise 0.4s var(--ease-out) 0.58s both}
#page-home .card:nth-child(6){animation:vs-card-rise 0.4s var(--ease-out) 0.66s both}
#page-home .notice{animation:vs-card-rise 0.38s var(--ease-out) 0.74s both}
#page-home .card[onclick]{transition:transform 0.18s var(--ease-spring),border-color 0.18s ease,box-shadow 0.18s ease;will-change:transform}
#page-home .card[onclick]:hover{transform:translateY(-4px);box-shadow:0 8px 22px rgba(0,0,0,0.08)}
#page-home .card[onclick]:active{transform:translateY(-1px) scale(0.99)}
body.dark #page-home .card[onclick]:hover{box-shadow:0 8px 26px rgba(0,0,0,0.42)}
@keyframes vs-page-enter{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.page.active{animation:vs-page-enter 0.24s var(--ease-out) both}
@keyframes vs-brand-breathe{0%,100%{opacity:1}50%{opacity:0.65}}
.brand-icon{animation:vs-brand-breathe 3s ease-in-out infinite}
/* Admin */
.admin-tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:18px;overflow-x:auto}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:7px;font-size:12px}
.bar-label{color:var(--text3);font-family:var(--mono);font-size:10px;width:90px;text-align:right;flex-shrink:0}
.bar-track{flex:1;background:var(--bg3);border-radius:2px;height:6px;overflow:hidden}
.bar-fill{height:100%;background:var(--accent);border-radius:2px;transition:width 1s ease}
.bar-val{font-family:var(--mono);font-size:10px;color:var(--text3);width:24px}
.cli-out{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:14px;min-height:300px;max-height:480px;overflow-y:auto;font-family:var(--mono);font-size:12px;line-height:1.8;margin-bottom:10px}
.cli-cmd-line{color:var(--green);margin-top:6px}
.cli-resp{color:var(--text2);white-space:pre-wrap;font-size:11px}
.cli-err{color:var(--red);white-space:pre-wrap;font-size:11px}
.cli-input-row{display:flex;align-items:center;gap:8px}
.cli-prompt{font-family:var(--mono);font-size:12px;color:var(--text3);white-space:nowrap}
.cli-quick{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.cli-quick-btn{font-family:var(--mono);font-size:10px;padding:4px 9px;background:var(--bg2);border:1px solid var(--border);color:var(--text3);border-radius:3px;cursor:pointer;transition:all var(--transition)}
.cli-quick-btn:hover{border-color:var(--border2);color:var(--text)}
.cli-status{font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:6px;display:flex;align-items:center;gap:6px}
.pulse{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulseDot 2s ease infinite;flex-shrink:0}
@keyframes pulseDot{0%{box-shadow:0 0 0 0 rgba(26,122,58,0.7)}70%{box-shadow:0 0 0 8px rgba(26,122,58,0)}100%{box-shadow:0 0 0 0 rgba(26,122,58,0)}}
.srv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:14px}
.srv-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:14px}
.srv-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:8px}
.srv-val{font-family:var(--mono);font-size:22px;font-weight:500;color:var(--text);line-height:1;margin-bottom:4px}
.srv-bar{height:4px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-top:6px}
.srv-bar-fill{height:100%;background:var(--accent);border-radius:2px;transition:width 0.5s ease}
.srv-sub{font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:4px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.host-card{border:1px solid var(--border);border-radius:var(--radius);padding:12px;cursor:pointer;transition:border-color var(--transition),background var(--transition)}
.host-card:hover{border-color:var(--border2);background:var(--bg2)}
.host-card-ip{font-family:var(--mono);font-size:13px;font-weight:500;color:var(--text)}
.host-card-hn{font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:3px}
.found{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:20px;font-family:var(--mono);font-size:11px;color:var(--text2);position:relative;z-index:2}
#toast-container{position:fixed;bottom:20px;right:20px;z-index:999;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;font-size:12px;font-family:var(--mono);box-shadow:var(--shadow-md);pointer-events:all;display:flex;align-items:flex-start;gap:9px;max-width:320px;animation:toastIn 0.25s ease}
.toast.leaving{animation:toastOut 0.2s ease forwards}
@keyframes toastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{to{opacity:0;transform:translateX(20px)}}
.toast-icon{flex-shrink:0;font-size:14px;margin-top:1px}
.toast-body{flex:1}
.toast-title{font-weight:500;color:var(--text);margin-bottom:2px}
.toast-msg{color:var(--text3);font-size:11px;line-height:1.5}
.toast-close{background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;line-height:1;flex-shrink:0}
.toast-close:hover{color:var(--text)}
.toast.success{border-left:3px solid var(--green)}
.toast.error{border-left:3px solid var(--red)}
.toast.info{border-left:3px solid var(--blue)}
.toast.warning{border-left:3px solid var(--yellow)}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
/* SET Terminal */
#set-terminal-output{scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
#set-terminal-output::-webkit-scrollbar{width:5px}
#set-terminal-output::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.set-menu-btn{font-family:var(--mono);font-size:11px;padding:4px 10px}
.set-menu-btn:hover{background:var(--bg3);color:var(--text);transform:scale(1.03)}
.spin{display:inline-block;width:11px;height:11px;border:1.5px solid var(--border2);border-top-color:var(--text);border-radius:50%;animation:sp 0.7s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
.page{display:none}.page.active{display:block;animation:vs-page-enter 0.24s var(--ease-out) both}
@media(max-width:720px){
  .sidebar{transform:translateX(-100%);transition:transform 0.25s ease}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .row2,.row3{grid-template-columns:1fr}
  .theme-options{flex-direction:column}
}
@media(max-width:480px){
  .content{padding:16px}
  .page-title{font-size:18px}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>

<body class="light" id="body">

<!-- ── Auth overlay ── -->
<div class="overlay" id="auth-overlay">
  <div class="auth-box">
    <div class="auth-logo">
      <div class="auth-logo-icon">&#9889;</div>
      <div>
        <div class="auth-title">VulnScan Pro</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:1.5px;margin-top:2px">SECURITY PLATFORM</div>
      </div>
    </div>
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="authTab('login')">LOGIN</button>
      <button class="auth-tab" onclick="authTab('register')">REGISTER</button>
      <button class="auth-tab" onclick="authTab('forgot')">FORGOT</button>
    </div>
    <div id="auth-msg" class="auth-msg"></div>
    <div id="form-login">
      <div class="fg"><label>USERNAME</label><input class="inp inp-mono" id="l-user" type="text" placeholder="username" autocomplete="username"/></div>
      <div class="fg"><label>PASSWORD</label><input class="inp inp-mono" id="l-pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" autocomplete="current-password"/></div>
      <button class="btn btn-primary btn-full" id="l-btn" onclick="doLogin()" style="margin-top:4px">LOGIN</button>
      <div style="text-align:center;margin-top:12px;font-size:12px;color:var(--text3)">
        <button class="auth-link" onclick="authTab('forgot')">Forgot password?</button>
        &nbsp;&middot;&nbsp;
        <button class="auth-link" onclick="authTab('register')">Create account</button>
      </div>
    </div>
    <div id="form-register" style="display:none">
      <div class="fg"><label>FULL NAME</label><input class="inp" id="r-name" type="text" placeholder="Your Name"/></div>
      <div class="fg"><label>USERNAME</label><input class="inp inp-mono" id="r-user" type="text" placeholder="letters, numbers, _ -"/></div>
      <div class="fg"><label>EMAIL</label><input class="inp" id="r-email" type="email" placeholder="you@example.com"/></div>
      <div class="fg"><label>PASSWORD</label><input class="inp inp-mono" id="r-pass" type="password" placeholder="Min 8 chars, 1 uppercase, 1 number"/></div>
      <div class="tos-box">
        <input type="checkbox" id="r-tos-cb" onchange="updateRegisterBtn()"/>
        <label for="r-tos-cb">I have read and agree to the <button type="button" onclick="showTos(event)" style="background:none;border:none;color:var(--text);cursor:pointer;font-size:11px;text-decoration:underline;text-underline-offset:2px;padding:0">Terms of Use</button>. I confirm I <strong>own or have written permission</strong> to scan any target I submit.</label>
      </div>
      <button class="btn btn-primary btn-full" id="r-btn" onclick="doRegister()" disabled style="opacity:0.4;cursor:not-allowed">CREATE ACCOUNT</button>
      <div style="text-align:center;margin-top:12px"><button class="auth-link" onclick="authTab('login')">Already have an account?</button></div>
    </div>
    <div id="form-forgot" style="display:none">
      <div class="fg"><label>EMAIL ADDRESS</label><input class="inp" id="f-email" type="email" placeholder="you@example.com"/></div>
      <button class="btn btn-primary btn-full" onclick="doForgot()">SEND RESET LINK</button>
      <div style="text-align:center;margin-top:12px"><button class="auth-link" onclick="authTab('login')">Back to login</button></div>
    </div>
  </div>
</div>

<!-- ── New User Modal ── -->
<div class="modal-bg" id="new-user-modal" onclick="if(event.target===this)closeNewUserModal()">
  <div class="modal" style="max-width:460px">
    <button class="modal-close" onclick="closeNewUserModal()">&#10005;</button>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:22px">
      <div style="width:38px;height:38px;background:var(--accent);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;color:var(--accent-inv);font-size:18px;flex-shrink:0">&#43;</div>
      <div>
        <div style="font-size:15px;font-weight:600;color:var(--text)">Create New User</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:1.5px;margin-top:2px">ADMIN &middot; USER MANAGEMENT</div>
      </div>
    </div>
    <div id="new-user-modal-msg" class="auth-msg" style="margin-bottom:14px"></div>
    <div id="new-user-form-body">
      <div class="fg"><label>FULL NAME</label><input class="inp" id="nu-full-name" type="text" placeholder="Jane Doe" autocomplete="off"/></div>
      <div class="fg"><label>USERNAME</label><input class="inp inp-mono" id="nu-username" type="text" placeholder="jane.doe" autocomplete="off"/></div>
      <div class="fg"><label>EMAIL ADDRESS</label><input class="inp" id="nu-email" type="email" placeholder="jane@example.com" autocomplete="off"/></div>
      <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--yellow);border-radius:var(--radius);padding:9px 12px;font-size:11px;color:var(--text2);margin-bottom:16px;line-height:1.7">
        &#9432; A temporary password will be generated and sent to the user&apos;s email address automatically.
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn btn-outline" onclick="closeNewUserModal()">CANCEL</button>
        <button class="btn btn-primary" id="nu-submit-btn" onclick="submitNewUser()">
          <span id="nu-btn-text">CREATE USER</span>
        </button>
      </div>
    </div>
    <!-- Success state -->
    <div id="new-user-success-body" style="display:none;text-align:center;padding:8px 0 4px">
      <div style="font-size:40px;margin-bottom:12px">&#10003;</div>
      <div style="font-size:15px;font-weight:600;color:var(--green);margin-bottom:6px">User Created!</div>
      <div id="nu-success-msg" style="font-size:13px;color:var(--text2);line-height:1.7;margin-bottom:18px"></div>
      <button class="btn btn-primary" onclick="closeNewUserModal();loadAdminUsers()">DONE</button>
    </div>
  </div>
</div>

<!-- ── About modal ── -->
<div class="modal-bg" id="about-modal" onclick="if(event.target===this)closeAbout()">
  <div class="modal">
    <button class="modal-close" onclick="closeAbout()">&#10005;</button>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <div style="width:36px;height:36px;background:var(--accent);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;color:var(--accent-inv);font-size:18px;flex-shrink:0">&#9889;</div>
      <div><div style="font-size:16px;font-weight:600;color:var(--text)">VulnScan Pro</div><div style="font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:2px;margin-top:2px">OPEN SOURCE &middot; v3.7</div></div>
    </div>
    <div style="font-size:13px;color:var(--text2);line-height:1.8;margin-bottom:16px">VulnScan Pro is a free, open-source vulnerability assessment platform for security professionals, penetration testers, and system administrators.</div>
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:14px">
      <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px">Creator</div>
      <div style="font-size:13px;color:var(--text2)">Vijay Katariya &mdash; Using Vibe Coding</div>
      <div style="margin-top:8px"><a href="https://github.com/labpnet33/vulnscan" target="_blank" style="font-family:var(--mono);font-size:11px;color:var(--text2);text-decoration:underline;text-underline-offset:2px">github.com/labpnet33/vulnscan</a></div>
    </div>
    <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--yellow);border-radius:var(--radius);padding:10px 12px;font-size:12px;color:var(--text2)">&#9888; <strong>Legal:</strong> Authorized security testing only. Only scan systems you own or have explicit written permission to test.</div>
  </div>
</div>

<!-- ── ToS modal ── -->
<div class="tos-modal-bg" id="tos-modal" onclick="if(event.target===this)closeTos()">
  <div class="tos-modal">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:18px">
      <span style="font-size:20px">&#9888;&#65039;</span>
      <div><div style="font-size:16px;font-weight:600;color:var(--text)">Terms of Use</div><div style="font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:2px;margin-top:2px">READ BEFORE REGISTERING</div></div>
    </div>
    <div style="font-size:12px;line-height:1.9;color:var(--text2)">
      <div class="tos-section"><strong>&#9888; Authorized Use Only</strong><br/>You are strictly prohibited from using this platform to scan any system you do not own or have explicit written authorization to test.</div>
      <div class="tos-section"><h4>1. Sole Responsibility</h4>You are entirely responsible for all actions performed from your account. The platform owner bears zero liability for any damage or legal consequence.</div>
      <div class="tos-section"><h4>2. No Illegal Activity</h4>You agree not to conduct unauthorized access, DoS attacks, data exfiltration, or any activity violating local, national, or international law.</div>
      <div class="tos-section"><h4>3. Indemnification</h4>You agree to indemnify and hold harmless the platform owner from all claims, damages, and costs arising from your use.</div>
      <div class="tos-section"><h4>4. Audit Logging</h4>All scans are logged with timestamps, targets, and IPs. Logs may be provided to law enforcement upon valid legal request.</div>
      <div class="tos-section"><h4>5. No Warranty</h4>Provided "as-is." Scan results are informational only.</div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px;flex-wrap:wrap">
      <button class="btn btn-outline" onclick="closeTos()">DECLINE</button>
      <button class="btn btn-primary" onclick="acceptTos()">I ACCEPT</button>
    </div>
  </div>
</div>

<!-- ── App layout ── -->
<div class="layout">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-logo" onclick="pg('home',null)">
        <div class="brand-icon">&#9889;</div>
        <div><div class="brand-title">VulnScan Pro</div><div class="brand-sub">SECURITY PLATFORM</div></div>
      </div>
    </div>
    <nav>
      <div class="nav-section">
        <div class="nav-label">OVERVIEW</div>
        <button class="nav-item" id="ni-home" onclick="pg('home',this)"><span class="ni">&#9700;</span> Home</button>
        <button class="nav-item" id="ni-dash" onclick="pg('dash',this)"><span class="ni">&#9636;</span> Dashboard</button>
        <button class="nav-item" id="ni-hist" onclick="pg('hist',this)"><span class="ni">&#9632;</span> History</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">INFORMATION</div>
        <button class="nav-item" id="ni-scan" onclick="pg('scan',this)"><span class="ni">&#9675;</span> Network Scanner</button>
        <button class="nav-item" id="ni-dnsrecon" onclick="pg('dnsrecon',this)"><span class="ni">&#9675;</span> DNSRecon</button>
        <button class="nav-item" id="ni-disc" onclick="pg('disc',this)"><span class="ni">&#9675;</span> Net Discovery</button>
        <button class="nav-item" id="ni-harvester" onclick="pg('harvester',this)"><span class="ni">&#9675;</span> theHarvester</button>
        <button class="nav-item" id="ni-sub" onclick="pg('sub',this)"><span class="ni">&#9675;</span> Subdomain Finder</button>
        <button class="nav-item" id="ni-legion" onclick="pg('legion',this)"><span class="ni">&#9675;</span> Legion</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">WEB TESTING</div>
        <button class="nav-item" id="ni-webdeep" onclick="pg('webdeep',this)"><span class="ni">&#9675;</span> Deep Web Audit</button>
        <button class="nav-item" id="ni-nikto" onclick="pg('nikto',this)"><span class="ni">&#9675;</span> Nikto</button>
        <button class="nav-item" id="ni-wpscan" onclick="pg('wpscan',this)"><span class="ni">&#9675;</span> WPScan</button>
        <button class="nav-item" id="ni-dir" onclick="pg('dir',this)"><span class="ni">&#9675;</span> Dir Buster</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">ATTACKS</div>
        <button class="nav-item" id="ni-brute" onclick="pg('brute',this)"><span class="ni">&#9675;</span> Brute Force</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">SOCIAL ENGINEERING</div>
        <button class="nav-item" id="ni-setoolkit" onclick="pg('setoolkit',this)"><span class="ni">&#9675;</span> Social-Engineer Toolkit</button>
        <button class="nav-item" id="ni-gophish" onclick="pg('gophish',this)"><span class="ni">&#9675;</span> Gophish</button>
        <button class="nav-item" id="ni-evilginx2" onclick="pg('evilginx2',this)"><span class="ni">&#9675;</span> Evilginx2</button>
        <button class="nav-item" id="ni-shellphish" onclick="pg('shellphish',this)"><span class="ni">&#9675;</span> ShellPhish</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">C2 / PIVOTING</div>
        <button class="nav-item" id="ni-netcat" onclick="pg('netcat',this)"><span class="ni">&#9675;</span> Netcat</button>
        <button class="nav-item" id="ni-ncat" onclick="pg('ncat',this)"><span class="ni">&#9675;</span> Ncat</button>
        <button class="nav-item" id="ni-socat" onclick="pg('socat',this)"><span class="ni">&#9675;</span> Socat</button>
        <button class="nav-item" id="ni-sliver" onclick="pg('sliver',this)"><span class="ni">&#9675;</span> Sliver</button>
        <button class="nav-item" id="ni-empire" onclick="pg('empire',this)"><span class="ni">&#9675;</span> Empire</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">AUDITING</div>
        <button class="nav-item" id="ni-lynis" onclick="pg('lynis',this)"><span class="ni">&#9675;</span> Lynis</button>
      </div>
      <div class="nav-section" id="admin-nav-section" style="display:none">
        <div class="nav-label">ADMIN</div>
        <button class="nav-item" id="ni-admin" onclick="pg('admin',this)"><span class="ni">&#9632;</span> Admin Console</button>
      </div>
    </nav>
    <div class="sidebar-footer">
      <button class="nav-item" onclick="showAbout()"><span class="ni">&#9432;</span> About</button>
      <button class="nav-item" id="logout-btn" onclick="doLogout()" style="display:none;color:var(--red)"><span class="ni">&#10005;</span> Logout</button>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <div class="tb-title" id="topbar-title">Home</div>
      <div class="tb-right">
        <button class="theme-toggle" id="theme-toggle-btn" onclick="toggleTheme()" title="Toggle dark/light theme" aria-label="Toggle theme"></button>
        <div class="user-chip" id="user-chip" onclick="pg('profile',null)" style="display:none">
          <div class="user-av" id="user-avatar">?</div>
          <div><div class="user-name" id="user-name-disp">User</div><div class="user-role" id="user-role-disp">user</div></div>
        </div>
      </div>
    </header>

    <div class="content">

      <!-- HOME -->
      <div class="page active" id="page-home">
        <div class="page-hd">
          <div class="page-title">Welcome back<span id="home-username-suffix"></span></div>
          <div class="page-desc">Professional security reconnaissance &amp; vulnerability assessment</div>
        </div>
        <div class="stats" id="home-stats">
          <div class="stat"><div class="stat-val" id="hs-scans">--</div><div class="stat-lbl">TOTAL SCANS</div></div>
          <div class="stat"><div class="stat-val" id="hs-cves">--</div><div class="stat-lbl">CVEs FOUND</div></div>
          <div class="stat"><div class="stat-val" id="hs-ports">--</div><div class="stat-lbl">OPEN PORTS</div></div>
          <div class="stat"><div class="stat-val">21</div><div class="stat-lbl">TOOLS</div></div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px">
          <div class="card" style="cursor:pointer" onclick="pg('scan',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Network Scanner</div><div style="font-size:12px;color:var(--text3)">Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS &middot; Headers</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">nmap</span><span class="tag">CVE</span><span class="tag">SSL</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('harvester',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">theHarvester</div><div style="font-size:12px;color:var(--text3)">OSINT emails, subdomains, IPs from public sources</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">OSINT</span><span class="tag">emails</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('sub',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Subdomain Finder</div><div style="font-size:12px;color:var(--text3)">DNS brute-force + crt.sh + HackerTarget passive</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">DNS</span><span class="tag">brute-force</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('nikto',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Nikto</div><div style="font-size:12px;color:var(--text3)">Web vulnerability scanner &middot; 6700+ checks</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">web</span><span class="tag">CVE</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('webdeep',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Deep Web Audit</div><div style="font-size:12px;color:var(--text3)">Nmap + Nikto + Dir Enum + Headers + DNS + optional WPScan in one run</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">full-audit</span><span class="tag">report</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('dir',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Directory Buster</div><div style="font-size:12px;color:var(--text3)">Hidden paths, admin panels, sensitive files</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">HTTP</span><span class="tag">fuzzing</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('lynis',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Lynis</div><div style="font-size:12px;color:var(--text3)">System audit &middot; hardening &middot; compliance</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">local</span><span class="tag">CIS</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('setoolkit',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Social-Engineer Toolkit</div><div style="font-size:12px;color:var(--text3)">Interactive social engineering simulation framework</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">phishing</span><span class="tag">payloads</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('gophish',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Gophish</div><div style="font-size:12px;color:var(--text3)">Phishing campaign manager with landing pages and tracking</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">campaign</span><span class="tag">awareness</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('evilginx2',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">Evilginx2</div><div style="font-size:12px;color:var(--text3)">Reverse-proxy phishing simulation for MFA resilience testing</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">MFA</span><span class="tag">proxy</span></div></div>
          </div>
          <div class="card" style="cursor:pointer" onclick="pg('shellphish',null)" onmouseover="this.style.borderColor='var(--border2)'" onmouseout="this.style.borderColor='var(--border)'">
            <div class="card-p"><div style="font-size:18px;margin-bottom:8px">&#9632;</div><div style="font-weight:600;margin-bottom:4px">ShellPhish</div><div style="font-size:12px;color:var(--text3)">Template-driven phishing simulation framework for labs</div><div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap"><span class="tag">templates</span><span class="tag">ngrok</span></div></div>
          </div>
        </div>
        <div class="notice" style="margin-top:18px">&#9888; <strong>Authorized use only.</strong> Only scan systems you own or have explicit written permission to assess.</div>
      </div>

      <!-- SCANNER -->
      <div class="page" id="page-scan">
        <div class="page-hd"><div class="page-title">Network Scanner</div><div class="page-desc">Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS recon &middot; Header audit</div></div>
        <div class="card card-p" style="margin-bottom:16px">
          <div class="scan-bar">
            <input class="inp inp-mono" id="tgt" type="text" placeholder="IP address or hostname" onkeydown="if(event.key==='Enter')doScan()"/>
            <button class="btn btn-primary" id="sbtn" onclick="doScan()">SCAN</button>
            <button class="btn btn-outline btn-sm" id="sbtn-cancel" onclick="cancelScan('scan')" style="display:none;color:var(--red);border-color:rgba(192,57,43,0.3)">CANCEL</button>
          </div>
          <div class="pills">
            <button class="pill on" id="mod-ports" onclick="tmg('ports',this)">Ports + CVE</button>
            <button class="pill on" id="mod-ssl" onclick="tmg('ssl',this)">SSL/TLS</button>
            <button class="pill on" id="mod-dns" onclick="tmg('dns',this)">DNS</button>
            <button class="pill on" id="mod-headers" onclick="tmg('headers',this)">Headers</button>
          </div>
          <div class="row2" style="margin-top:10px">
            <div class="fg" style="margin-bottom:0">
              <label>NMAP PROFILE</label>
              <select class="inp inp-mono" id="scan-profile">
                <option value="fast">Fast — top 100 ports, no version (-T4, ~30s)</option>
                <option value="balanced" selected>Balanced — top 1000 ports + versions (-T4, ~60s)</option>
                <option value="deep">Deep — all 65535 TCP ports + versions (-T3, ~5min)</option>
                <option value="very_deep">Very Deep — all ports + scripts + OS detect (-T3, ~15min)</option>
              </select>
            </div>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; Scans may take 30--180 seconds depending on target and modules.</div>
        </div>
        <div class="progress-wrap" id="prog"><div class="progress-bar" id="pb" style="width:0%"></div></div>
        <div class="terminal" id="term"></div>
        <div class="err-box" id="err"></div>
        <div id="res"></div>
      </div>

      <!-- DEEP WEB AUDIT -->
      <div class="page" id="page-webdeep">
        <div class="page-hd"><div class="page-title">Deep Web Audit</div><div class="page-desc">Comprehensive website assessment with multiple tools and a risk rating</div></div>
        <div class="notice">&#9888; Authorized use only. Scan only websites you own or are explicitly permitted to assess.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET WEBSITE URL</label><input class="inp inp-mono" id="wd-url" type="text" placeholder="https://example.com" onkeydown="if(event.key==='Enter')doWebDeep()"/></div>
          <div class="row2" style="margin-bottom:8px">
            <div class="fg"><label>DEPTH PROFILE</label><select class="inp inp-mono" id="wd-profile"><option value="balanced" selected>Balanced</option><option value="deep">Deep</option><option value="very_deep">Very Deep</option></select></div>
            <div class="fg"><label>SCAN MODE</label><input class="inp inp-mono" type="text" value="Automated multi-tool web audit" disabled/></div>
          </div>
          <button class="btn btn-primary" id="wd-btn" onclick="doWebDeep()">RUN DEEP WEB AUDIT</button>
          <button class="btn btn-outline btn-sm" id="wd-cancel" onclick="cancelScan('wd')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; This workflow can take 5--30 minutes depending on target size and enabled tools.</div>
        </div>
        <div class="progress-wrap" id="wd-prog"><div class="progress-bar" id="wd-pb" style="width:0%"></div></div>
        <div class="terminal" id="wd-term"></div>
        <div class="err-box" id="wd-err"></div>
        <div id="wd-res"></div>
      </div>

      <!-- HARVESTER -->
      <div class="page" id="page-harvester">
        <div class="page-hd"><div class="page-title">theHarvester</div><div class="page-desc">OSINT email, subdomain, and IP reconnaissance</div></div>
        <div class="notice">&#9888; Only perform reconnaissance on domains you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET DOMAIN</label><input class="inp inp-mono" id="hv-target" type="text" placeholder="example.com"/></div>
            <div class="fg"><label>RESULT LIMIT</label><input class="inp inp-mono" id="hv-limit" type="number" value="500" min="50" max="2000"/></div>
          </div>
          <div class="fg"><label>DATA SOURCES (hold Ctrl/Cmd for multiple)</label>
            <select class="inp inp-mono" id="hv-sources" multiple style="height:90px;padding:6px">
              <option value="google" selected>Google</option><option value="bing" selected>Bing</option>
              <option value="linkedin">LinkedIn</option><option value="dnsdumpster" selected>DNSDumpster</option>
              <option value="crtsh" selected>crt.sh</option><option value="hackertarget">HackerTarget</option>
              <option value="baidu">Baidu</option><option value="yahoo">Yahoo</option>
            </select>
          </div>
          <button class="btn btn-primary" id="hv-btn" onclick="doHarvest()">RUN HARVESTER</button>
          <button class="btn btn-outline btn-sm" id="hv-cancel" onclick="cancelScan('hv')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; May take 30--120s depending on sources.</div>
        </div>
        <div class="progress-wrap" id="hv-prog"><div class="progress-bar" id="hv-pb" style="width:0%"></div></div>
        <div class="terminal" id="hv-term"></div>
        <div class="err-box" id="hv-err"></div>
        <div id="hv-res"></div>
      </div>

      <!-- DNSRECON -->
      <div class="page" id="page-dnsrecon">
        <div class="page-hd"><div class="page-title">DNSRecon</div><div class="page-desc">DNS enumeration and zone analysis</div></div>
        <div class="notice">&#9888; Only enumerate domains you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET DOMAIN</label><input class="inp inp-mono" id="dr-target" type="text" placeholder="example.com"/></div>
            <div class="fg"><label>SCAN TYPE</label>
              <select class="inp inp-mono" id="dr-type">
                <option value="std">Standard (all record types)</option><option value="axfr">Zone Transfer (AXFR)</option>
                <option value="brt">Brute Force subdomains</option><option value="srv">SRV records</option><option value="rvl">Reverse lookup</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:16px">
            <div class="fg"><label>NAMESERVER (optional)</label><input class="inp inp-mono" id="dr-ns" type="text" placeholder="8.8.8.8"/></div>
            <div class="fg"><label>RECORD FILTER</label>
              <select class="inp inp-mono" id="dr-filter">
                <option value="">All records</option><option value="A">A</option><option value="MX">MX</option>
                <option value="NS">NS</option><option value="TXT">TXT</option><option value="SOA">SOA</option><option value="CNAME">CNAME</option>
              </select>
            </div>
          </div>
          <button class="btn btn-primary" id="dr-btn" onclick="doDnsRecon()">RUN DNSRECON</button>
          <button class="btn btn-outline btn-sm" id="dr-cancel" onclick="cancelScan('dr')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
        </div>
        <div class="progress-wrap" id="dr-prog"><div class="progress-bar" id="dr-pb" style="width:0%"></div></div>
        <div class="terminal" id="dr-term"></div>
        <div class="err-box" id="dr-err"></div>
        <div id="dr-res"></div>
      </div>

      <!-- NIKTO -->
      <div class="page" id="page-nikto">
        <div class="page-hd"><div class="page-title">Nikto</div><div class="page-desc">Web server vulnerability scanner</div></div>
        <div class="notice">&#9888; Only scan web servers you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET URL / HOST</label><input class="inp inp-mono" id="nk-target" type="text" placeholder="http://192.168.1.1"/></div>
            <div class="fg"><label>PORT</label><input class="inp inp-mono" id="nk-port" type="number" placeholder="80" value="80" min="1" max="65535"/></div>
          </div>
          <div class="row2" style="margin-bottom:16px">
            <div class="fg"><label>SSL</label><select class="inp inp-mono" id="nk-ssl"><option value="">Auto-detect</option><option value="-ssl">Force SSL</option><option value="-nossl">Disable SSL</option></select></div>
            <div class="fg"><label>TUNING</label><select class="inp inp-mono" id="nk-tuning"><option value="">All tests</option><option value="1">File upload</option><option value="2">Misconfiguration</option><option value="4">XSS</option><option value="8">Command injection</option><option value="9">SQL injection</option></select></div>
          </div>
          <button class="btn btn-primary" id="nk-btn" onclick="doNikto()">RUN NIKTO</button>
          <button class="btn btn-outline btn-sm" id="nk-cancel" onclick="cancelScan('nk')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; Nikto scans may take 2--10 minutes.</div>
        </div>
        <div class="progress-wrap" id="nk-prog"><div class="progress-bar" id="nk-pb" style="width:0%"></div></div>
        <div class="terminal" id="nk-term"></div>
        <div class="err-box" id="nk-err"></div>
        <div id="nk-res"></div>
      </div>

      <!-- WPSCAN -->
      <div class="page" id="page-wpscan">
        <div class="page-hd"><div class="page-title">WPScan</div><div class="page-desc">WordPress security scanner</div></div>
        <div class="notice">&#9888; Only scan WordPress sites you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="wp-target" type="text" placeholder="https://example.com"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ENUMERATION (hold Ctrl/Cmd)</label>
              <select class="inp inp-mono" id="wp-enum" multiple style="height:90px;padding:6px">
                <option value="p" selected>Plugins (vulnerable)</option><option value="t">Themes</option><option value="u" selected>Users</option>
                <option value="vp">Vulnerable plugins only</option><option value="ap">All plugins</option>
                <option value="at">All themes</option><option value="cb">Config backups</option>
              </select>
            </div>
            <div class="fg"><label>DETECTION MODE</label>
              <select class="inp inp-mono" id="wp-mode"><option value="mixed">Mixed (default)</option><option value="passive">Passive</option><option value="aggressive">Aggressive</option></select>
            </div>
          </div>
          <div class="fg"><label>API TOKEN (optional)</label><input class="inp inp-mono" id="wp-token" type="password" placeholder="Get free token at wpscan.com"/></div>
          <button class="btn btn-primary" id="wp-btn" onclick="doWPScan()">RUN WPSCAN</button>
          <button class="btn btn-outline btn-sm" id="wp-cancel" onclick="cancelScan('wp')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
        </div>
        <div class="progress-wrap" id="wp-prog"><div class="progress-bar" id="wp-pb" style="width:0%"></div></div>
        <div class="terminal" id="wp-term"></div>
        <div class="err-box" id="wp-err"></div>
        <div id="wp-res"></div>
      </div>

      <!-- LYNIS -->
      <div class="page" id="page-lynis">
        <div class="page-hd"><div class="page-title">Lynis</div><div class="page-desc">Local system security audit</div></div>
        <div class="notice">&#9432; Run local scan by default, or click a connected agent below to run Lynis remotely on that Linux machine. If you disconnect an agent, run the install curl command again on that Linux host to reconnect.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg" style="margin-bottom:10px">
            <label>ONE-LINE AGENT INSTALL (Linux)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="ly-install-cmd" type="text" readonly value="curl -fsSL http://161.118.189.254:5000/agent/install.sh | bash"/>
              <button class="btn btn-outline btn-sm" onclick="copyLynisInstallCmd()">COPY</button>
            </div>
          </div>
          <div class="card card-p" style="border:1px dashed var(--border2);margin-bottom:12px">
            <div class="card-title" style="margin-bottom:8px">Connected Agent Systems</div>
            <div id="ly-agents" style="color:var(--text3);font-size:12px">Loading agents...</div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>AUDIT PROFILE</label><select class="inp inp-mono" id="ly-profile"><option value="system">Full System Audit</option><option value="quick">Quick Scan</option><option value="forensics">Forensics Mode</option></select></div>
            <div class="fg"><label>COMPLIANCE</label><select class="inp inp-mono" id="ly-compliance"><option value="">None</option><option value="ISO27001">ISO 27001</option><option value="PCI-DSS">PCI-DSS</option><option value="HIPAA">HIPAA</option><option value="CIS">CIS Benchmark</option></select></div>
          </div>
          <div class="fg"><label>FOCUS CATEGORY</label><select class="inp inp-mono" id="ly-category"><option value="">All categories</option><option value="authentication">Authentication</option><option value="networking">Networking</option><option value="storage">Storage</option><option value="kernel">Kernel</option><option value="software">Software</option><option value="logging">Logging</option></select></div>
          <button class="btn btn-primary" id="ly-btn" onclick="doLynis()">RUN LYNIS AUDIT</button>
          <button class="btn btn-outline btn-sm" id="ly-cancel" onclick="cancelScan('ly')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; Full audit may take 2--5 minutes.</div>
        </div>
        <div class="progress-wrap" id="ly-prog"><div class="progress-bar" id="ly-pb" style="width:0%"></div></div>
        <div class="terminal" id="ly-term"></div>
        <div class="err-box" id="ly-err"></div>
        <div id="ly-res"></div>
        <div class="card card-p" style="margin-top:12px">
          <div class="card-title" style="margin-bottom:8px">Lynis Job Queue (latest 12)</div>
          <div id="ly-jobs" style="color:var(--text3);font-size:12px">Loading jobs...</div>
        </div>
      </div>

      <!-- LEGION -->
      <div class="page" id="page-legion">
        <div class="page-hd"><div class="page-title">Legion</div><div class="page-desc">Auto-recon framework</div></div>
        <div class="notice">&#9888; Legion runs multiple active tools. Only scan hosts you own or have written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST / IP</label><input class="inp inp-mono" id="lg-target" type="text" placeholder="192.168.1.1"/></div>
            <div class="fg"><label>INTENSITY</label><select class="inp inp-mono" id="lg-intensity"><option value="light">Light (fast)</option><option value="normal" selected>Normal</option><option value="aggressive">Aggressive</option></select></div>
          </div>
          <div class="fg"><label>MODULES</label>
            <div class="pills" style="margin-top:6px">
              <button class="pill on" id="lg-mod-nmap" onclick="lgMod('nmap',this)">nmap</button>
              <button class="pill on" id="lg-mod-nikto" onclick="lgMod('nikto',this)">nikto</button>
              <button class="pill on" id="lg-mod-smb" onclick="lgMod('smb',this)">SMB</button>
              <button class="pill on" id="lg-mod-snmp" onclick="lgMod('snmp',this)">SNMP</button>
              <button class="pill" id="lg-mod-hydra" onclick="lgMod('hydra',this)">hydra</button>
              <button class="pill" id="lg-mod-finger" onclick="lgMod('finger',this)">finger</button>
            </div>
          </div>
          <button class="btn btn-primary" id="lg-btn" onclick="doLegion()" style="margin-top:12px">RUN LEGION</button>
          <button class="btn btn-outline btn-sm" id="lg-cancel" onclick="cancelScan('lg')" style="display:none;color:var(--red);margin-left:8px">CANCEL</button>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:10px">&#9432; Aggressive scans may take 5--15 minutes.</div>
        </div>
        <div class="progress-wrap" id="lg-prog"><div class="progress-bar" id="lg-pb" style="width:0%"></div></div>
        <div class="terminal" id="lg-term"></div>
        <div class="err-box" id="lg-err"></div>
        <div id="lg-res"></div>
      </div>

      <!-- SUBDOMAIN -->
      <div class="page" id="page-sub">
        <div class="page-hd"><div class="page-title">Subdomain Finder</div><div class="page-desc">DNS brute-force + passive enumeration</div></div>
        <div class="notice">&#9888; Only enumerate domains you own or have written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>DOMAIN</label><input class="inp inp-mono" id="sub-domain" type="text" placeholder="example.com"/></div>
          <div class="fg"><label>WORDLIST SIZE</label><select class="inp inp-mono" id="sub-size"><option value="small">Small (~30 words)</option><option value="medium" selected>Medium (~80 words + crt.sh + HackerTarget)</option></select></div>
          <button class="btn btn-primary" id="sub-btn" onclick="doSub()">FIND SUBDOMAINS</button>
        </div>
        <div id="sub-res"></div>
      </div>

      <!-- DIR BUSTER -->
      <div class="page" id="page-dir">
        <div class="page-hd"><div class="page-title">Directory Buster</div><div class="page-desc">Hidden path and file enumeration</div></div>
        <div class="notice">&#9888; Only scan web servers you own or have written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="dir-url" type="text" placeholder="http://192.168.1.1"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>WORDLIST SIZE</label><select class="inp inp-mono" id="dir-size"><option value="small" selected>Small (~60 paths)</option><option value="medium">Medium (~130 paths)</option></select></div>
            <div class="fg"><label>EXTENSIONS</label><input class="inp inp-mono" id="dir-ext" type="text" value="php,html,txt,bak,zip,json,xml"/></div>
          </div>
          <button class="btn btn-primary" id="dir-btn" onclick="doDir()">START ENUMERATION</button>
        </div>
        <div id="dir-res"></div>
      </div>

      <!-- BRUTE FORCE -->
      <div class="page" id="page-brute">
        <div class="page-hd"><div class="page-title">Brute Force</div><div class="page-desc">Credential testing against HTTP and SSH services</div></div>
        <div class="notice">&#9888; ONLY use on systems you own or have explicit written permission. Unauthorized use is illegal.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ATTACK TYPE</label><select class="inp inp-mono" id="bf-type" onchange="bfTypeChange()"><option value="http">HTTP Form Login</option><option value="ssh">SSH Login</option></select></div>
          <div id="bf-http-fields">
            <div class="row3" style="margin-bottom:8px">
              <div class="fg"><label>LOGIN URL</label><input class="inp inp-mono" id="bf-url" type="text" placeholder="http://host/login"/></div>
              <div class="fg"><label>USER FIELD</label><input class="inp inp-mono" id="bf-ufield" value="username" type="text"/></div>
              <div class="fg"><label>PASS FIELD</label><input class="inp inp-mono" id="bf-pfield" value="password" type="text"/></div>
            </div>
          </div>
          <div id="bf-ssh-fields" style="display:none">
            <div class="row2" style="margin-bottom:8px">
              <div class="fg"><label>HOST</label><input class="inp inp-mono" id="bf-ssh-host" type="text" placeholder="192.168.1.1"/></div>
              <div class="fg"><label>PORT</label><input class="inp inp-mono" id="bf-ssh-port" value="22" type="text"/></div>
            </div>
          </div>
          <!-- Wordlist Mode Selector -->
          <div class="fg">
            <label>USERNAME LIST MODE</label>
            <select class="inp inp-mono" id="bf-user-mode" onchange="bfWordlistMode('user')">
              <option value="manual">Manual Input</option>
              <option value="rockyou_users" selected>rockyou.txt — default usernames &#10003;</option>
              <option value="seclists_common">SecLists: common usernames shortlist</option>
              <option value="seclists_top">SecLists: full names list</option>
              <option value="seclists_default_creds">SecLists: default credential users</option>
            </select>
          </div>
          <div class="fg">
            <label>PASSWORD LIST MODE</label>
            <select class="inp inp-mono" id="bf-pass-mode" onchange="bfWordlistMode('pass')">
              <option value="manual">Manual Input</option>
              <option value="rockyou" selected>rockyou.txt — default passwords &#10003;</option>
              <option value="seclists_10k">SecLists: top 10k passwords</option>
              <option value="seclists_100k">SecLists: top 100k passwords</option>
              <option value="seclists_default_creds_pass">SecLists: default credential passwords</option>
              <option value="seclists_darkweb">SecLists: darkweb2017 top 10k</option>
            </select>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>USERNAMES <span id="bf-user-src-lbl" style="color:var(--text3);font-size:10px">(one per line)</span></label><textarea class="inp inp-mono" id="bf-users" placeholder="admin&#10;root&#10;user"></textarea></div>
            <div class="fg"><label>PASSWORDS <span id="bf-pass-src-lbl" style="color:var(--text3);font-size:10px">(one per line)</span></label><textarea class="inp inp-mono" id="bf-pwds" placeholder="admin&#10;password&#10;123456"></textarea></div>
          </div>
          <div id="bf-wordlist-status" style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px;display:none"></div>
          <button class="btn btn-primary btn-full" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button>
        </div>
        <div id="bf-res"></div>
      </div>

      <!-- SOCIAL-ENGINEER TOOLKIT — Interactive PTY Terminal -->
      <div class="page" id="page-setoolkit">
        <div class="page-hd">
          <div class="page-title">Social-Engineer Toolkit (SET)</div>
          <div class="page-desc">Full interactive terminal — navigate all SET menus directly from your browser</div>
        </div>
        <div class="notice">&#9888; Authorized awareness testing only. All actions are audit-logged. Never use for unauthorized phishing or payload delivery.</div>

        <!-- Quick-select menu panel -->
        <div class="card card-p" style="margin-bottom:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px">
            <div>
              <div class="card-title">SET Interactive Terminal</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px">Type directly in the terminal below, or use the quick-select buttons</div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn btn-primary btn-sm" id="set-launch-btn" onclick="setLaunch()">
                <span id="set-launch-icon">&#9654;</span> LAUNCH SET
              </button>
              <button class="btn btn-outline btn-sm" id="set-kill-btn" onclick="setKill()" style="display:none;color:var(--red);border-color:rgba(192,57,43,0.3)">
                &#9632; KILL SESSION
              </button>
            </div>
          </div>

          <!-- Quick menu buttons — Main menu -->
          <div id="set-quick-panel">
            <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">QUICK SELECT — MAIN MENU</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px" id="set-main-btns">
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('1\n')" title="Social-Engineering Attacks">1 — SE Attacks</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('2\n')" title="Penetration Testing (Fast-Track)">2 — PenTest</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('3\n')" title="Third Party Modules">3 — Third Party</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('4\n')" title="Update SET">4 — Update SET</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('5\n')" title="Update SET Config">5 — SET Config</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('6\n')" title="Help / Credits">6 — Help</button>
            </div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">SOCIAL-ENGINEERING ATTACKS (after selecting 1)</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('1\n')" title="Spear-Phishing">1 — Spear-Phishing</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('2\n')" title="Website Attack Vectors">2 — Website Attacks</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('3\n')" title="Infectious Media Generator">3 — Infectious Media</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('4\n')" title="Create a Payload and Listener">4 — Payload + Listener</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('5\n')" title="Mass Mailer Attack">5 — Mass Mailer</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('6\n')" title="Arduino-Based Attack Vector">6 — Arduino</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('7\n')" title="Wireless Access Point Attack">7 — Wireless AP</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('8\n')" title="QRCode Generator">8 — QRCode</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('9\n')" title="Powershell Attack Vectors">9 — PowerShell</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('10\n')">10 — SMS Spoofing</button>
            </div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">NAVIGATION</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <button class="btn btn-outline btn-sm" onclick="setSend('99\n')" style="color:var(--text2)">&#8592; Back / 99</button>
              <button class="btn btn-outline btn-sm" onclick="setSpecialKey('ctrl_c')" style="color:var(--yellow)">&#9679; Ctrl+C</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('q\n')" style="color:var(--text2)">q — Quit prompt</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('exit\n')" style="color:var(--text2)">exit</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('\n')" style="color:var(--text2)">&#9166; Enter</button>
            </div>
          </div>
        </div>

        <!-- Terminal window -->
        <div class="card" style="margin-bottom:14px">
          <div class="card-header" style="padding:10px 16px">
            <div style="display:flex;align-items:center;gap:8px">
              <div style="width:10px;height:10px;border-radius:50%;background:var(--green)" id="set-status-dot"></div>
              <span style="font-family:var(--mono);font-size:11px;color:var(--text3)" id="set-status-label">Not started — click LAUNCH SET</span>
            </div>
            <div style="display:flex;gap:6px">
              <button class="btn btn-ghost btn-sm" onclick="setTermClear()" title="Clear screen">CLR</button>
              <button class="btn btn-ghost btn-sm" onclick="setTermScroll()" title="Scroll to bottom">&#8595;</button>
            </div>
          </div>

          <!-- The main xterm-like display -->
          <div id="set-terminal-output"
               style="background:#0a0a0a;color:#00e5ff;font-family:var(--mono);font-size:12.5px;
                      line-height:1.65;padding:14px 16px;min-height:360px;max-height:520px;
                      overflow-y:auto;white-space:pre-wrap;word-break:break-all;
                      border-bottom:1px solid var(--border);cursor:text"
               onclick="document.getElementById('set-input-box').focus()">
            <span style="color:var(--text3)">[ SET Interactive Terminal ]  Click LAUNCH SET to begin.</span>
          </div>

          <!-- Inline input row -->
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg2)">
            <span style="font-family:var(--mono);font-size:12px;color:var(--text3);flex-shrink:0">set&gt;</span>
            <input id="set-input-box"
                   class="inp inp-mono"
                   type="text"
                   placeholder="Type a menu number or command, then press Enter..."
                   style="flex:1;background:transparent;border:none;box-shadow:none;padding:4px 0;font-size:12.5px"
                   onkeydown="setInputKey(event)"
                   autocomplete="off" spellcheck="false"/>
            <button class="btn btn-primary btn-sm" onclick="setInputSend()">SEND</button>
          </div>
        </div>

        <!-- Info cards -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px">
          <div class="card card-p">
            <div class="card-title" style="margin-bottom:8px">How to Use</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.8">
              1. Click <strong>LAUNCH SET</strong> to open a live session.<br/>
              2. Wait for the SET menu to appear in the terminal.<br/>
              3. Use the quick buttons or type a number + Enter.<br/>
              4. Navigate sub-menus the same way.<br/>
              5. Use <strong>99</strong> to go back, <strong>Ctrl+C</strong> to interrupt.
            </div>
          </div>
          <div class="card card-p">
            <div class="card-title" style="margin-bottom:8px">Common Workflows</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.8">
              <strong>Phishing simulation:</strong> 1 → 1 → 1<br/>
              <strong>Website clone attack:</strong> 1 → 2 → 2<br/>
              <strong>Payload + listener:</strong> 1 → 4<br/>
              <strong>Mass mailer:</strong> 1 → 5<br/>
              <strong>PowerShell attack:</strong> 1 → 9
            </div>
          </div>
          <div class="card card-p" style="border-left:3px solid var(--yellow)">
            <div class="card-title" style="margin-bottom:8px;color:var(--yellow)">&#9888; Legal Notice</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.8">
              All SET operations are audit-logged. Only use against systems and users you are <strong>explicitly authorized</strong> to test in writing.
            </div>
            <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px">
              <span class="tag">phishing-sim</span><span class="tag">authorized</span><span class="tag">awareness</span>
            </div>
          </div>
        </div>
      </div>

      <!-- GOPHISH -->
      <div class="page" id="page-gophish">
        <div class="page-hd"><div class="page-title">Gophish</div><div class="page-desc">Execute Gophish server commands and inspect output</div></div>
        <div class="notice">&#9888; Use only for approved phishing-awareness campaigns and legal red-team scope.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>OPERATION</label><select class="inp inp-mono" id="gp-op"><option value="help">Help / capability check</option><option value="version">Version check</option><option value="custom">Custom arguments</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="gp-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>CUSTOM ARGUMENTS (for custom mode)</label><input class="inp inp-mono" id="gp-args" type="text" placeholder="-h"/></div>
          <button class="btn btn-primary" id="gp-btn" onclick="runGophish()">RUN GOPHISH</button>
        </div>
        <div class="progress-wrap" id="gp-prog"><div class="progress-bar" id="gp-pb" style="width:0%"></div></div>
        <div class="terminal" id="gp-term"></div>
        <div class="err-box" id="gp-err"></div>
        <div id="gp-res"></div>
        <div class="page-hd"><div class="page-title">Gophish</div><div class="page-desc">Phishing campaign platform for security awareness programs</div></div>
        <div class="notice">&#9888; Restrict campaigns to consented users and approved domains. Keep credentials disabled or safely sandboxed.</div>
        <div class="card card-p" style="margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">What Gophish Is Best For</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.8">Building email templates, importing user groups, launching controlled campaigns, and tracking opens/clicks/reporting rates.</div>
          <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px"><span class="tag">campaigns</span><span class="tag">templates</span><span class="tag">metrics</span></div>
        </div>
        <div class="card card-p">
          <div class="card-title" style="margin-bottom:8px">Quick Commands (Linux)</div>
          <div style="font-family:var(--mono);font-size:11px;line-height:1.8;color:var(--text2)">wget https://github.com/gophish/gophish/releases/latest<br/># Download the latest Linux 64-bit release asset from that page<br/>unzip gophish-*.zip -d gophish &amp;&amp; cd gophish &amp;&amp; ./gophish</div>
          <div style="font-size:11px;color:var(--text3);margin-top:10px">By default, the admin UI starts on port 3333 and the phishing listener on port 80. Configure sending profiles before launching any campaign.</div>
        </div>
      </div>

      <!-- EVILGINX2 -->
      <div class="page" id="page-evilginx2">
        <div class="page-hd"><div class="page-title">Evilginx2</div><div class="page-desc">Execute Evilginx2 commands on server and view process output</div></div>
        <div class="notice">&#9888; High-risk tooling. Run only in explicitly authorized red-team engagements.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>OPERATION</label><select class="inp inp-mono" id="eg-op"><option value="help">Help / capability check</option><option value="version">Version check</option><option value="custom">Custom arguments</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="eg-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>CUSTOM ARGUMENTS (for custom mode)</label><input class="inp inp-mono" id="eg-args" type="text" placeholder="-h"/></div>
          <button class="btn btn-primary" id="eg-btn" onclick="runEvilginx2()">RUN EVILGINX2</button>
        </div>
        <div class="progress-wrap" id="eg-prog"><div class="progress-bar" id="eg-pb" style="width:0%"></div></div>
        <div class="terminal" id="eg-term"></div>
        <div class="err-box" id="eg-err"></div>
        <div id="eg-res"></div>
        <div class="page-hd"><div class="page-title">Evilginx2</div><div class="page-desc">Reverse proxy phishing simulation for advanced red-team exercises</div></div>
        <div class="notice">&#9888; High-risk tool. Use only in a legal red-team scope with explicit authorization and blue-team coordination.</div>
        <div class="card card-p" style="margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">Use It For</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.8">Testing MFA-aware phishing resilience in controlled engagements, validating detection controls, and training incident response teams.</div>
          <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px"><span class="tag">reverse-proxy</span><span class="tag">MFA testing</span><span class="tag">red team</span></div>
        </div>
        <div class="card card-p">
          <div class="card-title" style="margin-bottom:8px">Quick Commands (Linux)</div>
          <div style="font-family:var(--mono);font-size:11px;line-height:1.8;color:var(--text2)">sudo apt install evilginx2<br/>sudo evilginx</div>
          <div style="font-size:11px;color:var(--text3);margin-top:10px">Typical workflow: configure domain and DNS, load phishlet, configure lure URL, run only during approved testing window.</div>
        </div>
      </div>

      <!-- SHELLPHISH -->
      <div class="page" id="page-shellphish">
        <div class="page-hd"><div class="page-title">ShellPhish</div><div class="page-desc">Run ShellPhish script commands and inspect output</div></div>
        <div class="notice">&#9888; Use only in controlled labs or approved awareness simulations.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SCRIPT PATH</label><input class="inp inp-mono" id="sp-script" type="text" value="/opt/shellphish/shellphish.sh"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sp-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>ARGUMENTS</label><input class="inp inp-mono" id="sp-args" type="text" placeholder="--help"/></div>
          <button class="btn btn-primary" id="sp-btn" onclick="runShellPhish()">RUN SHELLPHISH</button>
        </div>
        <div class="progress-wrap" id="sp-prog"><div class="progress-bar" id="sp-pb" style="width:0%"></div></div>
        <div class="terminal" id="sp-term"></div>
        <div class="err-box" id="sp-err"></div>
        <div id="sp-res"></div>
        <div class="page-hd"><div class="page-title">ShellPhish</div><div class="page-desc">Template-based phishing simulation launcher</div></div>
        <div class="notice">&#9888; Use only on authorized targets in isolated labs. This tool is commonly abused in the wild.</div>
        <div class="card card-p" style="margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">Common Lab Workflows</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.8">Spin up prebuilt phishing templates for awareness demos, observe user behavior, and validate endpoint/browser protections in non-production environments.</div>
          <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px"><span class="tag">templates</span><span class="tag">tunnels</span><span class="tag">training labs</span></div>
        </div>
        <div class="card card-p">
          <div class="card-title" style="margin-bottom:8px">Quick Commands (Linux)</div>
          <div style="font-family:var(--mono);font-size:11px;line-height:1.8;color:var(--text2)">sudo apt install git php curl -y<br/>git clone https://github.com/thelinuxchoice/shellphish.git<br/>cd shellphish &amp;&amp; bash shellphish.sh</div>
          <div style="font-size:11px;color:var(--text3);margin-top:10px">Use local tunnel options (localhost.run/ngrok) only for authorized simulations and teardown infrastructure immediately after testing.</div>
        </div>
      </div>

      <!-- C2 / PIVOTING TOOLS -->
      <div class="page" id="page-netcat">
        <div class="page-hd"><div class="page-title">Netcat</div><div class="page-desc">Build listener/connect commands and run netcat on server</div></div>
        <div class="notice">&#9888; Authorized red-team/lab use only.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>MODE</label><select class="inp inp-mono" id="nc-mode"><option value="connect">Connect</option><option value="listen">Listen</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nc-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST</label><input class="inp inp-mono" id="nc-host" type="text" placeholder="127.0.0.1"/></div>
            <div class="fg"><label>PORT</label><input class="inp inp-mono" id="nc-port" type="number" value="4444" min="1" max="65535"/></div>
          </div>
          <div class="fg"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="nc-extra" type="text" placeholder="-v -n"/></div>
          <button class="btn btn-primary" id="nc-btn" onclick="runNetcat()">RUN NETCAT</button>
        </div>
        <div class="progress-wrap" id="nc-prog"><div class="progress-bar" id="nc-pb" style="width:0%"></div></div>
        <div class="terminal" id="nc-term"></div>
        <div class="err-box" id="nc-err"></div>
        <div id="nc-res"></div>
      </div>

      <div class="page" id="page-ncat">
        <div class="page-hd"><div class="page-title">Ncat</div><div class="page-desc">Run ncat with validated arguments</div></div>
        <div class="notice">&#9888; Authorized red-team/lab use only.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>MODE</label><select class="inp inp-mono" id="nct-mode"><option value="connect">Connect</option><option value="listen">Listen</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nct-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST</label><input class="inp inp-mono" id="nct-host" type="text" placeholder="127.0.0.1"/></div>
            <div class="fg"><label>PORT</label><input class="inp inp-mono" id="nct-port" type="number" value="4444" min="1" max="65535"/></div>
          </div>
          <div class="fg"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="nct-extra" type="text" placeholder="-v -n"/></div>
          <button class="btn btn-primary" id="nct-btn" onclick="runNcat()">RUN NCAT</button>
        </div>
        <div class="progress-wrap" id="nct-prog"><div class="progress-bar" id="nct-pb" style="width:0%"></div></div>
        <div class="terminal" id="nct-term"></div>
        <div class="err-box" id="nct-err"></div>
        <div id="nct-res"></div>
      </div>

      <div class="page" id="page-socat">
        <div class="page-hd"><div class="page-title">Socat</div><div class="page-desc">Bridge two sockets/channels with socat</div></div>
        <div class="notice">&#9888; Authorized red-team/lab use only.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>LEFT ADDRESS</label><input class="inp inp-mono" id="sc-left" type="text" placeholder="TCP-LISTEN:4444,reuseaddr,fork"/></div>
            <div class="fg"><label>RIGHT ADDRESS</label><input class="inp inp-mono" id="sc-right" type="text" placeholder="TCP:127.0.0.1:22"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sc-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="sc-extra" type="text" placeholder="-d -d"/></div>
          </div>
          <button class="btn btn-primary" id="sc-btn" onclick="runSocat()">RUN SOCAT</button>
        </div>
        <div class="progress-wrap" id="sc-prog"><div class="progress-bar" id="sc-pb" style="width:0%"></div></div>
        <div class="terminal" id="sc-term"></div>
        <div class="err-box" id="sc-err"></div>
        <div id="sc-res"></div>
      </div>

      <div class="page" id="page-sliver">
        <div class="page-hd"><div class="page-title">Sliver</div><div class="page-desc">Run Sliver client/server binary commands</div></div>
        <div class="notice">&#9888; Authorized red-team engagements only.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>OPERATION</label><select class="inp inp-mono" id="sv-op"><option value="help">Help / capability check</option><option value="version">Version check</option><option value="custom">Custom arguments</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sv-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>CUSTOM ARGUMENTS</label><input class="inp inp-mono" id="sv-args" type="text" placeholder="version"/></div>
          <button class="btn btn-primary" id="sv-btn" onclick="runSliver()">RUN SLIVER</button>
        </div>
        <div class="progress-wrap" id="sv-prog"><div class="progress-bar" id="sv-pb" style="width:0%"></div></div>
        <div class="terminal" id="sv-term"></div>
        <div class="err-box" id="sv-err"></div>
        <div id="sv-res"></div>
      </div>

      <div class="page" id="page-empire">
        <div class="page-hd"><div class="page-title">Empire</div><div class="page-desc">Run Empire framework CLI checks/commands</div></div>
        <div class="notice">&#9888; Authorized red-team engagements only.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>OPERATION</label><select class="inp inp-mono" id="em-op"><option value="help">Help / capability check</option><option value="version">Version check</option><option value="custom">Custom arguments</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="em-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>CUSTOM ARGUMENTS</label><input class="inp inp-mono" id="em-args" type="text" placeholder="server --help"/></div>
          <button class="btn btn-primary" id="em-btn" onclick="runEmpire()">RUN EMPIRE</button>
        </div>
        <div class="progress-wrap" id="em-prog"><div class="progress-bar" id="em-pb" style="width:0%"></div></div>
        <div class="terminal" id="em-term"></div>
        <div class="err-box" id="em-err"></div>
        <div id="em-res"></div>
      </div>

      <!-- NETWORK DISCOVERY -->
      <div class="page" id="page-disc">
        <div class="page-hd"><div class="page-title">Network Discovery</div><div class="page-desc">Discover live hosts on a subnet</div></div>
        <div class="notice">&#9888; Only scan networks you own or have permission to scan.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="scan-bar">
            <input class="inp inp-mono" id="subnet" type="text" placeholder="192.168.1.0/24" onkeydown="if(event.key==='Enter')doDisc()"/>
            <button class="btn btn-primary" id="disc-btn" onclick="doDisc()">DISCOVER</button>
          </div>
        </div>
        <div id="disc-res"></div>
      </div>

      <!-- HISTORY -->
      <div class="page" id="page-hist">
        <div class="page-hd"><div class="page-title">Scan History</div><div class="page-desc">Your previous vulnerability assessments</div></div>
        <div class="card" id="hist-content"><div class="card-p" style="color:var(--text3)">Loading...</div></div>
      </div>

      <!-- DASHBOARD -->
      <div class="page" id="page-dash">
        <div class="page-hd"><div class="page-title">Dashboard</div><div class="page-desc">Security statistics and activity overview</div></div>
        <div id="dash-content"><div style="color:var(--text3);font-size:13px">Run some scans to see statistics.</div></div>
      </div>

      <!-- PROFILE -->
      <div class="page" id="page-profile">
        <div class="page-hd"><div class="page-title">Profile</div><div class="page-desc">Account settings and preferences</div></div>
        <div class="profile-grid">
          <div class="card card-p">
            <div class="card-title" style="margin-bottom:12px">My Account</div>
            <div id="profile-info"></div>
            <div style="margin-top:16px">
              <div class="fg"><label>FULL NAME</label><input class="inp" id="p-name" type="text" placeholder="Your full name"/></div>
              <button class="btn btn-primary btn-full" onclick="saveProfile()">SAVE CHANGES</button>
            </div>
          </div>
          <div class="card card-p">
            <div class="card-title" style="margin-bottom:12px">Change Password</div>
            <div class="fg"><label>CURRENT PASSWORD</label><input class="inp inp-mono" id="cp-old" type="password"/></div>
            <div class="fg"><label>NEW PASSWORD</label><input class="inp inp-mono" id="cp-new" type="password"/></div>
            <div class="fg"><label>CONFIRM NEW PASSWORD</label><input class="inp inp-mono" id="cp-confirm" type="password"/></div>
            <button class="btn btn-primary btn-full" onclick="changePassword()">UPDATE PASSWORD</button>
            <div id="pwd-msg" class="auth-msg" style="margin-top:10px"></div>
          </div>
        </div>
        <div class="card card-p" style="margin-top:16px">
          <div class="card-title" style="margin-bottom:6px">Interface Theme</div>
          <div style="font-size:12px;color:var(--text3);margin-bottom:14px">Saved per-user to your account only.</div>
          <div class="theme-options">
            <button class="theme-opt active" id="theme-opt-light" onclick="applyTheme('light')">
              <div class="theme-swatch" style="background:linear-gradient(135deg,#ffffff,#f5f5f5);border:1px solid #e0e0e0"></div>
              <div class="theme-name">Light</div><div class="theme-desc">Clean white workspace</div>
            </button>
            <button class="theme-opt" id="theme-opt-dark" onclick="applyTheme('dark')">
              <div class="theme-swatch" style="background:linear-gradient(135deg,#0a0a0a,#1a1a1a);border:1px solid #252525"></div>
              <div class="theme-name">Dark</div><div class="theme-desc">Low-light environment</div>
            </button>
          </div>
        </div>
      </div>

      <!-- ADMIN -->
      <div class="page" id="page-admin">
        <div class="page-hd" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px">
          <div>
            <div class="page-title">Admin Console</div>
            <div class="page-desc">User management, server CLI, and platform statistics</div>
          </div>
          <button class="btn btn-primary" onclick="openNewUserModal()" style="flex-shrink:0;margin-top:4px">
            <span style="font-size:15px;line-height:1">&#43;</span> New User
          </button>
        </div>
        <div class="tabs admin-tabs" id="admin-tabs">
          <button class="tab active" onclick="adminTab(event,'at-cli')">Console</button>
          <button class="tab" onclick="adminTab(event,'at-users')">Users</button>
          <button class="tab" onclick="adminTab(event,'at-stats')">Stats</button>
          <button class="tab" onclick="adminTab(event,'at-audit')">Audit Log</button>
          <button class="tab" onclick="adminTab(event,'at-scans')">All Scans</button>
        </div>
        <div class="tc active" id="at-cli">
          <div class="card" style="margin-bottom:14px">
            <div class="card-header">
              <div><div class="card-title">Server Statistics</div></div>
              <div style="display:flex;align-items:center;gap:8px">
                <div class="pulse"></div>
                <span style="font-family:var(--mono);font-size:10px;color:var(--text3)" id="stats-updated">LIVE</span>
                <button class="btn btn-ghost btn-sm" onclick="loadServerStats()">Refresh</button>
              </div>
            </div>
            <div class="card-p">
              <div class="srv-grid">
                <div class="srv-card"><div class="srv-label">CPU USAGE</div><div class="srv-val" id="cpu-val">--</div><div class="srv-bar"><div class="srv-bar-fill" id="cpu-bar" style="width:0%"></div></div><div class="srv-sub" id="cpu-cores">-- cores</div></div>
                <div class="srv-card"><div class="srv-label">MEMORY</div><div class="srv-val" id="mem-val">--</div><div class="srv-bar"><div class="srv-bar-fill" id="mem-bar" style="width:0%"></div></div><div class="srv-sub" id="mem-total">of --</div></div>
                <div class="srv-card"><div class="srv-label">SWAP</div><div class="srv-val" id="swap-val">--</div><div class="srv-bar"><div class="srv-bar-fill" id="swap-bar" style="width:0%"></div></div><div class="srv-sub" id="swap-total">of --</div></div>
                <div class="srv-card"><div class="srv-label">STORAGE (/)</div><div class="srv-val" id="disk-val">--</div><div class="srv-bar"><div class="srv-bar-fill" id="disk-bar" style="width:0%"></div></div><div class="srv-sub" id="disk-total">of --</div></div>
                <div class="srv-card"><div class="srv-label">NETWORK</div><div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-top:6px"><div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:var(--text3)">TX</span><span id="net-tx">--</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">RX</span><span id="net-rx">--</span></div></div><div class="srv-sub" id="net-iface"></div></div>
              </div>
              <div class="row3">
                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:4px">UPTIME</div><div id="sys-uptime" style="font-family:var(--mono);font-size:12px;color:var(--text)">--</div></div>
                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:4px">LOAD AVG</div><div id="sys-load" style="font-family:var(--mono);font-size:12px;color:var(--text)">--</div></div>
                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:4px">PROCESSES</div><div id="sys-procs" style="font-family:var(--mono);font-size:12px;color:var(--text)">--</div></div>
              </div>
            </div>
          </div>
          <div class="card">
            <div class="card-header">
              <div><div class="card-title">Server CLI Console</div><div class="card-sub">ADMIN ONLY -- ALL COMMANDS LOGGED</div></div>
              <div style="display:flex;align-items:center;gap:6px"><div class="pulse"></div><span style="font-family:var(--mono);font-size:10px;color:var(--text3)" id="cli-hostname">loading...</span></div>
            </div>
            <div class="card-p">
              <div class="notice" style="margin-bottom:12px">&#9888; Allowlisted commands only. Type <code style="font-family:var(--mono)">help</code> to list available commands.</div>
              <div class="cli-out" id="cli-output">
                <div style="color:var(--text3);margin-bottom:2px">VulnScan Pro -- Server Console</div>
                <div style="color:var(--text3);border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:10px">User: <span id="cli-user-label" style="color:var(--text)">admin</span></div>
              </div>
              <div class="cli-input-row">
                <span class="cli-prompt">$</span>
                <input class="inp inp-mono" id="cli-input" type="text" placeholder="Enter command... (up/down history, Tab autocomplete)" onkeydown="cliKey(event)" autocomplete="off" spellcheck="false" style="flex:1"/>
                <button class="btn btn-outline btn-sm" onclick="cliRun()">RUN</button>
                <button class="btn btn-ghost btn-sm" onclick="cliClear()">CLR</button>
              </div>
              <div class="cli-status" id="cli-statusbar"><div class="pulse"></div><span>Ready</span></div>
              <div class="cli-quick" id="cli-quick-cmds">
                <button class="cli-quick-btn" onclick="cliQuick('uptime')">uptime</button>
                <button class="cli-quick-btn" onclick="cliQuick('df -h')">df -h</button>
                <button class="cli-quick-btn" onclick="cliQuick('free -h')">free -h</button>
                <button class="cli-quick-btn" onclick="cliQuick('ps aux | head -20')">ps aux</button>
                <button class="cli-quick-btn" onclick="cliQuick('ss -tlnp')">ss -tlnp</button>
                <button class="cli-quick-btn" onclick="cliQuick('uname -a')">uname</button>
                <button class="cli-quick-btn" onclick="cliQuick('ip addr')">ip addr</button>
                <button class="cli-quick-btn" onclick="cliQuick('which nmap nikto lynis dnsrecon theharvester wpscan')">check tools</button>
                <button class="cli-quick-btn" onclick="cliQuick('journalctl -n 30 --no-pager')">recent logs</button>
                <button class="cli-quick-btn" onclick="cliQuick('cat /etc/os-release')">OS info</button>
                <button class="cli-quick-btn" onclick="cliQuick('last -n 10')">last logins</button>
              </div>
            </div>
          </div>
        </div>
        <div class="tc" id="at-users">
          <div class="card">
            <div class="card-header"><div class="card-title">User Management</div></div>
            <div class="card-p" id="admin-users-table" style="overflow-x:auto"><p style="color:var(--text3)">Loading...</p></div>
          </div>
        </div>
        <div class="tc" id="at-stats"><div class="card"><div class="card-header"><div class="card-title">Platform Statistics</div></div><div class="card-p" id="admin-stats"></div></div></div>
        <div class="tc" id="at-audit"><div class="card"><div class="card-header"><div class="card-title">Audit Log</div></div><div class="card-p" id="admin-audit" style="overflow-x:auto"></div></div></div>
        <div class="tc" id="at-scans"><div class="card"><div class="card-header"><div class="card-title">All Scans</div></div><div class="card-p" id="admin-scans" style="overflow-x:auto"></div></div></div>
      </div>

    </div>
  </div>
</div>

<div id="toast-container"></div>

<script>
/* ==== THEME ==== */
var currentTheme='light';
function _themeKey(){return currentUser?'vs2-theme-'+currentUser.username:'vs2-theme-anon';}
function applyTheme(t,save){
  if(save===undefined)save=true;
  currentTheme=t;
  var body=document.getElementById('body');
  body.className=t;
  if(save){try{localStorage.setItem(_themeKey(),t);}catch(e){}}
  var ol=document.getElementById('theme-opt-light');
  var od=document.getElementById('theme-opt-dark');
  if(ol)ol.classList.toggle('active',t==='light');
  if(od)od.classList.toggle('active',t==='dark');
}
function toggleTheme(){applyTheme(currentTheme==='light'?'dark':'light');}
function loadUserTheme(){
  try{var s=localStorage.getItem(_themeKey());applyTheme(s==='dark'?'dark':'light',false);}
  catch(e){applyTheme('light',false);}
}
applyTheme('light',false);

/* ==== TOAST ==== */
function showToast(title,msg,type,duration){
  if(!type)type='info';if(!duration)duration=5000;
  var icons={success:'✓',error:'✕',info:'·',warning:'!'};
  var c=document.getElementById('toast-container');
  var t=document.createElement('div');
  t.className='toast '+type;
  t.innerHTML='<div class="toast-icon">'+icons[type]+'</div><div class="toast-body"><div class="toast-title">'+title+'</div>'+(msg?'<div class="toast-msg">'+msg+'</div>':'')+'</div><button class="toast-close" onclick="dismissToast(this.parentElement)">&#10005;</button>';
  c.appendChild(t);
  var timer=setTimeout(function(){dismissToast(t);},duration);
  t._timer=timer;
  t.addEventListener('click',function(){clearTimeout(t._timer);dismissToast(t);});
}
function dismissToast(el){if(!el||el._dismissed)return;el._dismissed=true;el.classList.add('leaving');setTimeout(function(){el.remove();},200);}
var toast=showToast;

/* ==== CANCEL SCAN ==== */
var scanControllers={};
function cancelScan(prefix){
  if(prefix==='wd'&&_wdES){_wdES.close();_wdES=null;_wdReset();}
  if(scanControllers[prefix]){scanControllers[prefix].abort();delete scanControllers[prefix];}
  var id=prefix==='scan'?'sbtn-cancel':prefix+'-cancel';
  var b=document.getElementById(id);if(b)b.style.display='none';
  showToast('Cancelled','Scan stopped by user.','warning',3000);
}
function setScanRunning(prefix,running){
  var id=prefix==='scan'?'sbtn-cancel':prefix+'-cancel';
  var b=document.getElementById(id);if(b)b.style.display=running?'inline-flex':'none';
}
async function fetchWithTimeout(url,options,timeoutMs,prefix){
  if(!options)options={};if(!timeoutMs)timeoutMs=300000;
  var controller=new AbortController();
  if(prefix)scanControllers[prefix]=controller;
  var timer=setTimeout(function(){controller.abort();},timeoutMs);
  try{var r=await fetch(url,Object.assign({},options,{signal:controller.signal}));clearTimeout(timer);if(prefix)delete scanControllers[prefix];return r;}
  catch(e){clearTimeout(timer);if(prefix)delete scanControllers[prefix];if(e.name==='AbortError')throw new Error('Cancelled or timed out.');throw e;}
}

/* ==== PAGE NAV ==== */
var PAGE_TITLES={home:'Home',scan:'Network Scanner',webdeep:'Deep Web Audit',harvester:'theHarvester',dnsrecon:'DNSRecon',nikto:'Nikto',wpscan:'WPScan',lynis:'Lynis',legion:'Legion',sub:'Subdomain Finder',dir:'Directory Buster',brute:'Brute Force',setoolkit:'Social-Engineer Toolkit',gophish:'Gophish',evilginx2:'Evilginx2',shellphish:'ShellPhish',netcat:'Netcat',ncat:'Ncat',socat:'Socat',sliver:'Sliver',empire:'Empire',disc:'Network Discovery',hist:'Scan History',dash:'Dashboard',profile:'Profile',admin:'Admin Console'};
function saveCurrentPage(id){try{sessionStorage.setItem('vs-page',id);}catch(e){}}
function pg(id,el){
  document.querySelectorAll('.page').forEach(function(e){e.classList.remove('active');});
  document.querySelectorAll('.nav-item').forEach(function(e){e.classList.remove('active');});
  var page=document.getElementById('page-'+id);
  if(!page)return;
  page.classList.add('active');
  var ni=document.getElementById('ni-'+id);if(ni)ni.classList.add('active');
  var tt=document.getElementById('topbar-title');
  if(tt){tt.style.animation='none';requestAnimationFrame(function(){tt.style.animation='';});tt.textContent=PAGE_TITLES[id]||id;}
  saveCurrentPage(id);
  if(id==='hist')loadHist();
  if(id==='dash')loadDash();
  if(id==='admin'){loadAdmin();setTimeout(initCliHeader,400);}
  if(id==='home'){setTimeout(loadHomeStats,80);if(currentUser)vsGreetUser(currentUser.username);}
  if(id==='profile'&&currentUser)loadProfileInfo(currentUser);
  if(id==='brute')setTimeout(bfAutoLoad,300);
  if(id==='lynis'){loadLynisAgents();loadLynisJobs();startLynisAgentWatcher();}
}

/* ==== AUTH ==== */
var currentUser=null;
var busy=false;
var mods={ports:true,ssl:true,dns:true,headers:true};
var nmapProfile='balanced';

function authTab(t){
  document.querySelectorAll('.auth-tab').forEach(function(e,i){
    e.classList.toggle('active',(i===0&&t==='login')||(i===1&&t==='register')||(i===2&&t==='forgot'));
  });
  document.querySelectorAll('[id^="form-"]').forEach(function(e){e.style.display='none';});
  var f=document.getElementById('form-'+t);if(f)f.style.display='block';
  var m=document.getElementById('auth-msg');if(m)m.style.display='none';
}
function authMsg(msg,type){var el=document.getElementById('auth-msg');el.textContent=msg;el.className='auth-msg '+(type||'err');el.style.display='block';}

async function doLogin(){
  var user=document.getElementById('l-user').value.trim();
  var pass=document.getElementById('l-pass').value;
  if(!user||!pass){authMsg('Enter username and password');return;}
  var btn=document.getElementById('l-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Logging in...';
  try{
    var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    var d=await r.json();
    if(d.success){authMsg('Welcome back, '+d.username+'!','ok');setTimeout(function(){document.getElementById('auth-overlay').style.display='none';loadUser();},700);}
    else authMsg(d.error||'Login failed');
  }catch(e){authMsg('Connection error: '+e.message);}
  finally{btn.disabled=false;btn.innerHTML='LOGIN';}
}

async function doRegister(){
  var name=document.getElementById('r-name').value.trim();
  var user=document.getElementById('r-user').value.trim();
  var email=document.getElementById('r-email').value.trim();
  var pass=document.getElementById('r-pass').value;
  if(!user||!email||!pass){authMsg('All fields required');return;}
  var btn=document.getElementById('r-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Creating...';
  try{
    var tosAccepted=document.getElementById('r-tos-cb')?document.getElementById('r-tos-cb').checked:false;
    var r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,email:email,password:pass,full_name:name,tos_accepted:tosAccepted})});
    var d=await r.json();
    if(d.success){authMsg(d.message,'ok');if(d.verified)setTimeout(function(){authTab('login');},2000);}
    else authMsg(d.error||'Registration failed');
  }catch(e){authMsg('Error: '+e.message);}
  finally{btn.disabled=false;btn.innerHTML='CREATE ACCOUNT';}
}

async function doForgot(){
  var email=document.getElementById('f-email').value.trim();
  if(!email){authMsg('Enter your email');return;}
  try{var r=await fetch('/api/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email})});var d=await r.json();authMsg(d.message||d.error,d.success?'ok':'err');}
  catch(e){authMsg('Error: '+e.message);}
}

async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  currentUser=null;
  document.getElementById('auth-overlay').style.display='flex';
  document.getElementById('user-chip').style.display='none';
  document.getElementById('logout-btn').style.display='none';
  var s=document.getElementById('admin-nav-section');if(s)s.style.display='none';
}

async function loadUser(){
  try{
    var r=await fetch('/api/me');var d=await r.json();
    if(d.logged_in){
      currentUser=d;
      document.getElementById('auth-overlay').style.display='none';
      document.getElementById('user-chip').style.display='flex';
      document.getElementById('logout-btn').style.display='flex';
      document.getElementById('user-avatar').textContent=d.username[0].toUpperCase();
      document.getElementById('user-name-disp').textContent=d.username;
      document.getElementById('user-role-disp').textContent=d.role==='admin'?'admin':'user';
      if(d.role==='admin'){var sec=document.getElementById('admin-nav-section');if(sec)sec.style.display='block';}
      loadProfileInfo(d);loadHomeStats();loadUserTheme();
      pg('home',null);
      vsGreetUser(d.username);
    }else{document.getElementById('auth-overlay').style.display='flex';}
  }catch(e){document.getElementById('auth-overlay').style.display='flex';}
}

function loadProfileInfo(u){
  if(!u)return;
  var pn=document.getElementById('p-name');if(pn)pn.value=u.full_name||'';
  var pi=document.getElementById('profile-info');
  if(pi)pi.innerHTML='<div class="kv"><div class="kv-item"><div class="kv-k">USERNAME</div><div class="kv-v">'+u.username+'</div></div><div class="kv-item"><div class="kv-k">ROLE</div><div class="kv-v">'+u.role+'</div></div><div class="kv-item"><div class="kv-k">EMAIL</div><div class="kv-v" style="font-size:12px">'+u.email+'</div></div><div class="kv-item"><div class="kv-k">LOGINS</div><div class="kv-v">'+(u.login_count||0)+'</div></div></div>';
}
async function saveProfile(){
  var name=document.getElementById('p-name').value.trim();
  try{var r=await fetch('/api/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full_name:name})});var d=await r.json();showPwdMsg(d.message||d.error,d.success?'ok':'err');}
  catch(e){showPwdMsg('Error: '+e.message,'err');}
}
async function changePassword(){
  var old=document.getElementById('cp-old').value;
  var nw=document.getElementById('cp-new').value;
  var cf=document.getElementById('cp-confirm').value;
  if(nw!==cf){showPwdMsg('Passwords do not match','err');return;}
  try{var r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:old,new_password:nw})});var d=await r.json();showPwdMsg(d.message||d.error,d.success?'ok':'err');if(d.success){document.getElementById('cp-old').value='';document.getElementById('cp-new').value='';document.getElementById('cp-confirm').value='';}}
  catch(e){showPwdMsg('Error: '+e.message,'err');}
}
function showPwdMsg(msg,type){var el=document.getElementById('pwd-msg');el.textContent=msg;el.className='auth-msg '+(type||'err');el.style.display='block';}

/* ==== TOS ==== */
function showTos(e){e.preventDefault();document.getElementById('tos-modal').classList.add('open');}
function closeTos(){document.getElementById('tos-modal').classList.remove('open');var cb=document.getElementById('r-tos-cb');if(cb)cb.checked=false;updateRegisterBtn();}
function acceptTos(){document.getElementById('tos-modal').classList.remove('open');var cb=document.getElementById('r-tos-cb');if(cb){cb.checked=true;updateRegisterBtn();}}
function updateRegisterBtn(){var cb=document.getElementById('r-tos-cb');var btn=document.getElementById('r-btn');if(!cb||!btn)return;btn.disabled=!cb.checked;btn.style.opacity=cb.checked?'1':'0.4';btn.style.cursor=cb.checked?'pointer':'not-allowed';}

/* ==== ABOUT ==== */
function showAbout(){document.getElementById('about-modal').classList.add('open');}
function closeAbout(){document.getElementById('about-modal').classList.remove('open');}

/* ==== HELPERS ==== */
function sev(level){var m={CRITICAL:'sev-critical',HIGH:'sev-high',MEDIUM:'sev-medium',LOW:'sev-low',UNKNOWN:'sev-unknown'};return'<span class="sev '+(m[level]||'sev-unknown')+'">'+level+'</span>';}
function sevScore(score){if(!score)return'';var l=score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':'LOW';var c={CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--yellow)',LOW:'var(--green)'};return'<span style="font-family:var(--mono);font-size:12px;font-weight:600;color:'+c[l]+'">'+score+'</span>';}
function clrUI(){['term','err','res'].forEach(function(id){var e=document.getElementById(id);if(e){e.innerHTML='';e.className=id==='err'?'err-box':'terminal';if(id==='res')e.style.display='none';}});var prog=document.getElementById('prog');if(prog)prog.classList.remove('active');}
function termLog(id,text,type){var el=document.getElementById(id);if(!el)return;var div=document.createElement('div');div.className='tl-'+type;var pf={i:'[*]',s:'[+]',w:'[!]',e:'[x]'}[type]||'[*]';div.innerHTML='<span class="tl-prefix">'+pf+'</span> '+text;el.appendChild(div);el.scrollTop=el.scrollHeight;}
function showErr(id,msg){var e=document.getElementById(id);if(e){e.textContent=msg;e.classList.add('visible');}}
function showTerminal(id){var e=document.getElementById(id);if(e)e.classList.add('visible');}
var _progTimers={};
function startProg(id){
  if(!id)id='prog';
  var pw=document.getElementById(id);var pb=document.getElementById(id.replace('-prog','-pb').replace('prog','pb'));
  if(pw)pw.classList.add('active');if(pb)pb.style.width='0%';
  var v=0;_progTimers[id]=setInterval(function(){v=Math.min(v+(100-v)*0.04,90);if(pb)pb.style.width=v+'%';},400);
}
function endProg(id){
  if(!id)id='prog';
  clearInterval(_progTimers[id]);
  var pw=document.getElementById(id);var pb=document.getElementById(id.replace('-prog','-pb').replace('prog','pb'));
  if(pb)pb.style.width='100%';
  setTimeout(function(){if(pw)pw.classList.remove('active');},400);
}
function animateCount(el,target){
  if(!el||isNaN(target))return;
  el.classList.add('vs-counting');
  var startT=null,dur=1000;
  function step(ts){if(!startT)startT=ts;var p=Math.min((ts-startT)/dur,1);var ease=1-Math.pow(1-p,3);el.textContent=Math.floor(ease*target);if(p<1)requestAnimationFrame(step);else el.classList.remove('vs-counting');}
  requestAnimationFrame(step);
}
async function loadHomeStats(){
  try{var r=await fetch('/history');var d=await r.json();var scans=Array.isArray(d)?d:(d.scans||[]);var c=0,p=0;scans.forEach(function(s){c+=(s.total_cves||0);p+=(s.open_ports||0);});animateCount(document.getElementById('hs-scans'),scans.length);animateCount(document.getElementById('hs-cves'),c);animateCount(document.getElementById('hs-ports'),p);}
  catch(e){}
}

/* ==== SCAN ==== */
function tmg(m,el){mods[m]=!mods[m];el.classList.toggle('on',mods[m]);}
async function doScan(){
  var target=document.getElementById('tgt').value.trim();
  if(!target||busy)return;
  var profileSel=document.getElementById('scan-profile');
  nmapProfile=(profileSel&&profileSel.value?profileSel.value:'balanced');
  clrUI();busy=true;
  showTerminal('term');startProg('prog');
  var btn=document.getElementById('sbtn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  setScanRunning('scan',true);
  var ml=Object.keys(mods).filter(function(m){return mods[m];}).join(',');
  termLog('term','Target: '+target,'i');termLog('term','Modules: '+ml,'i');termLog('term','Profile: '+nmapProfile,'i');termLog('term','Scanning -- may take 60-180s','w');
  try{
    var r=await fetchWithTimeout('/scan?target='+encodeURIComponent(target)+'&modules='+encodeURIComponent(ml)+'&profile='+encodeURIComponent(nmapProfile),{},300000,'scan');
    var d=await r.json();endProg('prog');
    if(d.error){showErr('err','Error: '+d.error);termLog('term',d.error,'e');}
    else{var ports=d.summary?d.summary.open_ports:0,cves=d.summary?d.summary.total_cves:0;termLog('term','Done -- '+ports+' ports, '+cves+' CVEs','s');renderScan(d);showToast('Scan Complete',ports+' open ports - '+cves+' CVEs','success');}
  }catch(e){endProg('prog');showErr('err','Error: '+e.message);}
  finally{busy=false;btn.disabled=false;btn.innerHTML='SCAN';setScanRunning('scan',false);}
}

function renderScan(data){
  var s=data.summary||{};
  var ports=(data.modules&&data.modules.ports&&data.modules.ports.hosts||[]).flatMap(function(h){return h.ports||[];});
  var html='<div class="stats" style="margin-bottom:16px"><div class="stat"><div class="stat-val">'+ports.length+'</div><div class="stat-lbl">OPEN PORTS</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+(s.critical_cves||0)+'</div><div class="stat-lbl">CRITICAL</div></div><div class="stat"><div class="stat-val" style="color:var(--orange)">'+(s.high_cves||0)+'</div><div class="stat-lbl">HIGH CVEs</div></div><div class="stat"><div class="stat-val">'+(s.total_cves||0)+'</div><div class="stat-lbl">TOTAL CVEs</div></div><div class="stat"><div class="stat-val" style="color:var(--yellow)">'+(s.exploitable||0)+'</div><div class="stat-lbl">EXPLOITABLE</div></div></div>';
  html+='<div class="tabs" style="margin-bottom:16px"><button class="tab active" onclick="swt(event,\'tp\')">Ports</button>'+(data.modules&&data.modules.ssl&&data.modules.ssl.length?'<button class="tab" onclick="swt(event,\'tssl\')">SSL</button>':'')+(data.modules&&data.modules.dns?'<button class="tab" onclick="swt(event,\'tdns\')">DNS</button>':'')+(data.modules&&data.modules.headers?'<button class="tab" onclick="swt(event,\'thdr\')">Headers</button>':'')+'<button class="tab" onclick="exportPDF()">PDF Report</button></div>';
  html+='<div class="tc active" id="tp">';
  var pm=data.modules&&data.modules.ports;
  if(pm&&pm.error){html+='<div class="err-box visible">'+pm.error+'</div>';}
  else{
    (pm&&pm.hosts||[]).forEach(function(host){
      html+='<div class="host-chip"><span class="host-ip">'+host.ip+'</span>'+(host.hostnames&&host.hostnames[0]?'<span style="color:var(--text3);font-size:11px">'+host.hostnames[0]+'</span>':'')+'<span class="host-up">&#9679; '+(host.status||'up')+'</span>'+(host.os?'<span style="color:var(--text3);font-family:var(--mono);font-size:11px">'+host.os+'</span>':'')+'</div>';
      if(!host.ports||!host.ports.length)html+='<div style="color:var(--text3);font-size:13px;padding:12px">No open ports found.</div>';
      (host.ports||[]).forEach(function(port){
        html+='<div class="port-panel"><div class="port-hd" onclick="tp2(this)"><div class="port-num">'+port.port+'</div><div style="flex:1;min-width:0"><div class="port-svc">'+(port.product||port.service||'unknown')+(port.version?' <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">v'+port.version+'</span>':'')+'</div><div class="port-ver">'+(port.protocol||'tcp').toUpperCase()+' - '+(port.service||'')+(port.extrainfo?' - '+port.extrainfo:'')+'</div></div><div class="port-meta">'+sev(port.risk_level)+(port.risk_score?'<span class="port-score" style="color:var(--text2);font-size:12px">'+port.risk_score+'</span>':'')+'</div><span class="chev">&#9660;</span></div>';
        html+='<div class="port-body">';
        if(port.cves&&port.cves.length){html+='<div class="sec-label">VULNERABILITIES ('+port.cves.length+')</div>';port.cves.forEach(function(c){html+='<div class="cve-item"><div class="cve-hd"><a class="cve-id" href="'+(c.references&&c.references[0]?c.references[0]:'https://nvd.nist.gov/vuln/detail/'+c.id)+'" target="_blank">'+c.id+'</a>'+sev(c.severity)+(c.score?sevScore(c.score):'')+(c.has_exploit?'<span class="sev sev-high">EXPLOIT</span>':'')+'<span class="cve-date">'+(c.published||'')+'</span></div><div class="cve-desc">'+(c.description||'')+'</div></div>';});}
        if(port.mitigations&&port.mitigations.length){html+='<div class="sec-label">MITIGATIONS</div><ul class="mit-list">'+port.mitigations.map(function(m){return'<li class="mit-item"><span class="mit-bullet">&#8250;</span><span>'+m+'</span></li>';}).join('')+'</ul>';}
        html+='</div></div>';
      });
    });
    if(!pm||!pm.hosts||!pm.hosts.length)html+='<div style="color:var(--text3);font-size:13px">No hosts found.</div>';
  }
  html+='</div>';
  if(data.modules&&data.modules.ssl&&data.modules.ssl.length){
    html+='<div class="tc" id="tssl">';
    var GC={"A+":"var(--green)","A":"var(--green)","B":"var(--yellow)","C":"var(--orange)","D":"var(--red)","F":"var(--red)","N/A":"var(--text3)"};
    data.modules.ssl.forEach(function(s2){
      if(s2.grade==='N/A'){html+='<div class="ssl-card"><div class="ssl-grade" style="color:var(--text3)">--</div><div><div class="ssl-host">'+s2.host+':'+s2.port+'</div><div class="ssl-detail">SSL not available</div></div></div>';return;}
      var d2=s2.details||{};
      html+='<div class="ssl-card"><div class="ssl-grade" style="color:'+(GC[s2.grade]||'var(--text)')+';border-color:'+(GC[s2.grade]||'var(--border)')+'">'+s2.grade+'</div><div><div class="ssl-host">'+s2.host+':'+s2.port+'</div><div class="ssl-detail">'+(d2.protocol||'?')+' - '+(d2.cipher||'?')+(d2.cipher_bits?' ('+d2.cipher_bits+' bit)':'')+'</div>'+(d2.days_until_expiry!=null?'<div class="ssl-detail" style="color:'+(d2.days_until_expiry<30?'var(--red)':'var(--green)')+'">Expires: '+(d2.expires||'')+' ('+d2.days_until_expiry+' days)</div>':'')+'<div style="margin-top:8px">'+(s2.issues||[]).filter(function(i){return i.severity!=='INFO';}).map(function(iss){return'<div class="ssl-issue">'+sev(iss.severity)+'<span style="font-size:12px;color:var(--text2)">'+iss.msg+'</span></div>';}).join('')+(!(s2.issues||[]).filter(function(i){return i.severity!=='INFO';}).length?'<div style="font-size:12px;color:var(--green)">&#10003; No SSL issues</div>':'')+'</div></div></div>';
    });
    html+='</div>';
  }
  if(data.modules&&data.modules.dns){
    var dns=data.modules.dns;
    html+='<div class="tc" id="tdns"><div class="dns-grid">'+Object.entries(dns.records||{}).map(function(kv){return'<div class="dns-card"><div class="dns-type">'+kv[0]+'</div><div class="dns-val">'+kv[1].join('<br/>')+'</div></div>';}).join('')+'</div>';
    html+='<div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px;font-size:13px"><span>'+(dns.has_spf?'&#10003;':'&#10005;')+' SPF '+(dns.has_spf?'configured':'MISSING')+'</span><span>'+(dns.has_dmarc?'&#10003;':'&#10005;')+' DMARC '+(dns.has_dmarc?'configured':'MISSING')+'</span></div>';
    if(dns.subdomains&&dns.subdomains.length)html+='<div class="sec-label">SUBDOMAINS ('+dns.subdomains.length+')</div><div>'+(dns.subdomains||[]).map(function(s){return'<div class="sub-item"><span>'+s.subdomain+'</span><span style="color:var(--text3);font-family:var(--mono);font-size:11px">'+s.ip+'</span></div>';}).join('')+'</div>';
    html+='</div>';
  }
  if(data.modules&&data.modules.headers){
    var hd=data.modules.headers;var GC2={"A+":"var(--green)","A":"var(--green)","B":"var(--yellow)","C":"var(--orange)","D":"var(--red)","F":"var(--red)"};
    html+='<div class="tc" id="thdr"><div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;flex-wrap:wrap"><div class="hdr-grade-big" style="color:'+(GC2[hd.grade]||'var(--text)')+'">'+hd.grade+'</div><div><div style="font-size:14px;font-weight:500">'+(hd.url||'')+'</div><div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:3px">HTTP '+(hd.status_code||'')+' - Score '+(hd.score||0)+'/100'+(hd.server?' - '+hd.server:'')+'</div></div></div>';
    if(hd.issues&&hd.issues.length){html+='<div class="sec-label">ISSUES</div>'+(hd.issues||[]).map(function(i){return'<div class="ssl-issue">'+sev(i.severity)+'<span style="font-size:12px;margin-left:6px">'+i.msg+'</span></div>';}).join('')+'<div style="margin-bottom:14px"></div>';}
    html+='<div class="sec-label">RESPONSE HEADERS</div><div style="border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">'+Object.entries(hd.headers||{}).slice(0,25).map(function(kv){return'<div class="hdr-row"><span class="hdr-key">'+kv[0]+'</span><span class="hdr-val">'+String(kv[1]).substring(0,100)+'</span></div>';}).join('')+'</div></div>';
  }
  var res=document.getElementById('res');res.innerHTML=html;res.style.display='block';
  window._sd=data;
}

function tp2(hdr){var b=hdr.nextElementSibling;var c=hdr.querySelector('.chev');b.classList.toggle('open');c.classList.toggle('open');}
function swt(e,id){var p=document.getElementById('res');p.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});p.querySelectorAll('.tc').forEach(function(t){t.classList.remove('active');});e.currentTarget.classList.add('active');var tc=document.getElementById(id);if(tc)tc.classList.add('active');}

/* ==== GENERIC TOOL RUNNER ==== */
function mkTool(prefix){
  var logEl=null;
  return{
    start:function(){logEl=document.getElementById(prefix+'-term');if(logEl){logEl.innerHTML='';logEl.classList.add('visible');}var e=document.getElementById(prefix+'-err');if(e){e.textContent='';e.classList.remove('visible');}var r=document.getElementById(prefix+'-res');if(r){r.innerHTML='';r.style.display='none';}startProg(prefix+'-prog');},
    log:function(t,tp){if(!logEl)return;if(!tp)tp='i';var div=document.createElement('div');div.className='tl-'+tp;var pf={i:'[*]',s:'[+]',w:'[!]',e:'[x]'}[tp]||'[*]';div.innerHTML='<span class="tl-prefix">'+pf+'</span> '+t;logEl.appendChild(div);logEl.scrollTop=logEl.scrollHeight;},
    pct:function(v){var pw=document.getElementById(prefix+'-prog');var pb=document.getElementById(prefix+'-pb');if(pw)pw.classList.add('active');if(pb)pb.style.width=Math.max(0,Math.min(100,parseInt(v||0,10)))+'%';},
    end:function(){endProg(prefix+'-prog');},
    err:function(m){var e=document.getElementById(prefix+'-err');if(e){e.textContent='Error: '+m;e.classList.add('visible');}},
    res:function(html){var e=document.getElementById(prefix+'-res');if(e){e.innerHTML=html;e.style.display='block';}}
  };
}
var hvTool=mkTool('hv'),drTool=mkTool('dr'),nkTool=mkTool('nk'),wpTool=mkTool('wp'),lyTool=mkTool('ly'),lgTool=mkTool('lg'),wdTool=mkTool('wd'),setTool=mkTool('set'),gpTool=mkTool('gp'),egTool=mkTool('eg'),spTool=mkTool('sp'),ncTool=mkTool('nc'),nctTool=mkTool('nct'),scTool=mkTool('sc'),svTool=mkTool('sv'),emTool=mkTool('em');

/* ==== DEEP WEB AUDIT ==== */
var _wdES=null;
function _wdReset(){
  var btn=document.getElementById('wd-btn');
  if(btn){btn.disabled=false;btn.innerHTML='RUN DEEP WEB AUDIT';}
  document.getElementById('wd-cancel').style.display='none';
  endProg('wd-prog');
}
function doWebDeep(){
  var url=document.getElementById('wd-url').value.trim();if(!url){alert('Enter a website URL');return;}
  var profile=document.getElementById('wd-profile').value||'balanced';
  var btn=document.getElementById('wd-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Auditing...';
  document.getElementById('wd-cancel').style.display='inline-flex';
  wdTool.start();startProg('wd-prog');
  wdTool.log('Target: '+url,'i');
  wdTool.log('Profile: '+profile+' | 9 tools running — streaming live progress...','w');
  if(_wdES){_wdES.close();_wdES=null;}
  var params=new URLSearchParams({url:url,profile:profile});
  _wdES=new EventSource('/web-deep-stream?'+params.toString());
  _wdES.onmessage=function(e){
    try{
      var d=JSON.parse(e.data);
      // Update progress bar
      var pb=document.getElementById('wd-pb');if(pb)pb.style.width=(d.pct||0)+'%';
      // Log
      if(d.log){
        var tp='i';
        if(d.log.startsWith('[+]'))tp='s';
        else if(d.log.startsWith('[!]'))tp='w';
        else if(d.log.startsWith('[x]'))tp='e';
        wdTool.log('['+d.pct+'%] '+d.log.replace(/^\[.\] /,''),tp);
      }
      if(d.done){
        _wdES.close();_wdES=null;_wdReset();
        if(d.error){wdTool.err(d.error);}
        else if(d.result){
          wdTool.log('Audit complete — '+d.result.risk_rating+' ('+d.result.vulnerability_score+'/100)','s');
          renderWebDeep(d.result);
          showToast('Deep Audit Done','Risk: '+d.result.risk_rating+' | Score: '+d.result.vulnerability_score+'/100','success',7000);
        }
      }
    }catch(ex){wdTool.log('Parse: '+ex.message,'e');}
  };
  _wdES.onerror=function(){
    if(_wdES){_wdES.close();_wdES=null;}
    wdTool.end();wdTool.err('Stream connection lost. Retrying or check server logs.');
    _wdReset();
  };
}
function renderWebDeep(d){
  var s=d.summary||{};
  var tools=d.tools_run||[];
  var req=d.tools_required||[];
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val" style="color:var(--red)">'+(d.vulnerability_score||0)+'</div><div class="stat-lbl">RISK SCORE /100</div></div><div class="stat"><div class="stat-val">'+(d.risk_rating||'UNKNOWN')+'</div><div class="stat-lbl">RATING</div></div><div class="stat"><div class="stat-val">'+(s.total_findings||0)+'</div><div class="stat-lbl">TOTAL FINDINGS</div></div><div class="stat"><div class="stat-val">'+tools.length+'</div><div class="stat-lbl">TOOLS RUN</div></div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Executive Summary</div><div style="font-size:13px;color:var(--text2)">'+(d.executive_summary||'No summary available')+'</div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Tool Status</div><div style="display:flex;flex-wrap:wrap;gap:6px">'+tools.map(function(t){return'<span class="tag">'+t.tool+': '+t.status+'</span>';}).join('')+'</div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Install These Tools on Linux Server</div><div style="display:grid;gap:6px">'+req.map(function(t){return'<div style="font-family:var(--mono);font-size:11px"><strong>'+t.tool+'</strong> &middot; '+t.install+'</div>';}).join('')+'</div></div>';
  if(d.key_findings&&d.key_findings.length){html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Key Findings</div><ul class="mit-list">'+d.key_findings.map(function(f){return'<li class="mit-item"><span class="mit-bullet">&#8250;</span><span>'+f+'</span></li>';}).join('')+'</ul></div>';}
  html+='<div class="card"><div class="card-header"><div class="card-title">Detailed JSON Report</div></div><div class="card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+JSON.stringify(d.details||{},null,2)+'</pre></div></div>';
  wdTool.res(html);
}

/* ==== HARVESTER ==== */
async function doHarvest(){
  var target=document.getElementById('hv-target').value.trim();if(!target){alert('Enter a domain');return;}
  var srcEl=document.getElementById('hv-sources');var sources=Array.from(srcEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var limit=document.getElementById('hv-limit').value||500;
  var btn=document.getElementById('hv-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  hvTool.start();hvTool.log('Target: '+target,'i');hvTool.log('Sources: '+sources,'i');hvTool.log('Launching theHarvester...','w');
  try{
    var r=await fetchWithTimeout('/harvester',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target,sources:sources,limit:parseInt(limit)})},180000,'hv');
    var d=await r.json();hvTool.end();
    if(d.error){hvTool.log(d.error,'e');hvTool.err(d.error);}
    else{hvTool.log('Done -- '+(d.emails?d.emails.length:0)+' emails, '+(d.hosts?d.hosts.length:0)+' hosts','s');renderHarvest(d);showToast('theHarvester','Found '+(d.emails?d.emails.length:0)+' emails','success');}
  }catch(e){hvTool.end();hvTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HARVESTER';}
}
function renderHarvest(d){
  var emails=d.emails||[],hosts=d.hosts||[],subs=d.subdomains||[],ips=d.ips||[];
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">'+emails.length+'</div><div class="stat-lbl">EMAILS</div></div><div class="stat"><div class="stat-val">'+hosts.length+'</div><div class="stat-lbl">HOSTS</div></div><div class="stat"><div class="stat-val">'+subs.length+'</div><div class="stat-lbl">SUBDOMAINS</div></div><div class="stat"><div class="stat-val">'+ips.length+'</div><div class="stat-lbl">IPs</div></div></div>';
  if(emails.length)html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Emails ('+emails.length+')</div><div style="display:flex;flex-wrap:wrap;gap:6px">'+emails.map(function(e){return'<span class="tag">'+e+'</span>';}).join('')+'</div></div>';
  if(subs.length)html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Subdomains ('+subs.length+')</div><div style="display:flex;flex-wrap:wrap;gap:6px">'+subs.map(function(s){return'<span class="tag">'+s+'</span>';}).join('')+'</div></div>';
  if(hosts.length)html+='<div class="card" style="margin-bottom:10px"><div class="card-header"><div class="card-title">Hosts</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>HOST</th><th>IP</th></tr></thead><tbody>'+hosts.map(function(h){return'<tr><td>'+(h.host||h)+'</td><td style="color:var(--text3)">'+(h.ip||'--')+'</td></tr>';}).join('')+'</tbody></table></div></div>';
  hvTool.res(html);
}

/* ==== DNSRECON ==== */
async function doDnsRecon(){
  var target=document.getElementById('dr-target').value.trim();if(!target){alert('Enter a domain');return;}
  var type=document.getElementById('dr-type').value;var ns=document.getElementById('dr-ns').value.trim();var filter=document.getElementById('dr-filter').value;
  var btn=document.getElementById('dr-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  drTool.start();drTool.log('Target: '+target,'i');drTool.log('Type: '+type,'i');
  try{
    var r=await fetchWithTimeout('/dnsrecon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target,type:type,ns:ns,filter:filter})},120000,'dr');
    var d=await r.json();drTool.end();
    if(d.error){drTool.log(d.error,'e');drTool.err(d.error);}
    else{drTool.log('Done -- '+(d.records?d.records.length:0)+' records','s');renderDnsRecon(d);}
  }catch(e){drTool.end();drTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN DNSRECON';}
}
function renderDnsRecon(d){
  var recs=d.records||[];var byType={};recs.forEach(function(r){if(!byType[r.type])byType[r.type]=[];byType[r.type].push(r);});
  var html='<div class="stat" style="margin-bottom:14px;display:inline-block"><div class="stat-val">'+recs.length+'</div><div class="stat-lbl">RECORDS</div></div>';
  Object.entries(byType).forEach(function(kv){html+='<div class="card" style="margin-bottom:8px"><div class="card-header"><div class="card-title">'+kv[0]+' Records ('+kv[1].length+')</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>NAME</th><th>VALUE</th><th>TTL</th></tr></thead><tbody>'+kv[1].map(function(r){return'<tr><td>'+(r.name||'--')+'</td><td>'+(r.address||r.value||'--')+'</td><td style="color:var(--text3)">'+(r.ttl||'--')+'</td></tr>';}).join('')+'</tbody></table></div></div>';});
  drTool.res(html);
}

/* ==== NIKTO ==== */
async function doNikto(){
  var target=document.getElementById('nk-target').value.trim();if(!target){alert('Enter a target');return;}
  var port=document.getElementById('nk-port').value||80;var ssl_flag=document.getElementById('nk-ssl').value;var tuning=document.getElementById('nk-tuning').value;
  var btn=document.getElementById('nk-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  nkTool.start();nkTool.log('Target: '+target+' port '+port,'i');nkTool.log('This may take several minutes','w');
  try{
    var r=await fetchWithTimeout('/nikto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target,port:parseInt(port),ssl:ssl_flag,tuning:tuning})},600000,'nk');
    var d=await r.json();nkTool.end();
    if(d.error){nkTool.log(d.error,'e');nkTool.err(d.error);}
    else{nkTool.log('Done -- '+(d.findings?d.findings.length:0)+' findings','s');renderNikto(d);}
  }catch(e){nkTool.end();nkTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NIKTO';}
}
function renderNikto(d){
  var f=d.findings||[];var crit=f.filter(function(x){return x.severity==='high';}).length;
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">'+f.length+'</div><div class="stat-lbl">FINDINGS</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+crit+'</div><div class="stat-lbl">HIGH</div></div><div class="stat"><div class="stat-val">'+(d.server||'--')+'</div><div class="stat-lbl">SERVER</div></div></div>';
  if(f.length)html+='<div class="card"><div class="card-header"><div class="card-title">Findings</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>ID</th><th>DESCRIPTION</th><th>URL</th></tr></thead><tbody>'+f.map(function(x){return'<tr><td style="font-family:var(--mono);font-size:11px">'+(x.id||'--')+'</td><td style="color:'+(x.severity==='high'?'var(--red)':x.severity==='medium'?'var(--orange)':'var(--text)')+'">'+(x.description||'--')+'</td><td style="font-size:11px;color:var(--text3)">'+(x.url||'')+'</td></tr>';}).join('')+'</tbody></table></div></div>';
  else html+='<div style="color:var(--green);font-size:13px">&#10003; No findings detected.</div>';
  nkTool.res(html);
}

/* ==== WPSCAN ==== */
async function doWPScan(){
  var target=document.getElementById('wp-target').value.trim();if(!target){alert('Enter a URL');return;}
  var enumEl=document.getElementById('wp-enum');var flags=Array.from(enumEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var token=document.getElementById('wp-token').value.trim();var mode=document.getElementById('wp-mode').value;
  var btn=document.getElementById('wp-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  wpTool.start();wpTool.log('Target: '+target,'i');
  try{
    var r=await fetchWithTimeout('/wpscan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target,enum_flags:flags,token:token,mode:mode})},300000,'wp');
    var d=await r.json();wpTool.end();
    if(d.error){wpTool.err(d.error);}
    else{wpTool.log('Done -- '+(d.vulnerabilities?d.vulnerabilities.length:0)+' vulns','s');renderWPScan(d);}
  }catch(e){wpTool.end();wpTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WPSCAN';}
}
function renderWPScan(d){
  var v=d.vulnerabilities||[],u=d.users||[],p=d.plugins||[];
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val" style="color:var(--red)">'+v.length+'</div><div class="stat-lbl">VULNS</div></div><div class="stat"><div class="stat-val">'+p.length+'</div><div class="stat-lbl">PLUGINS</div></div><div class="stat"><div class="stat-val">'+u.length+'</div><div class="stat-lbl">USERS</div></div><div class="stat"><div class="stat-val">'+(d.wp_version||'?')+'</div><div class="stat-lbl">WP VER</div></div></div>';
  if(v.length)html+='<div class="card" style="margin-bottom:8px"><div class="card-header"><div class="card-title">Vulnerabilities</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>TITLE</th><th>TYPE</th><th>REF</th></tr></thead><tbody>'+v.map(function(x){return'<tr><td style="color:var(--red)">'+(x.title||'--')+'</td><td style="color:var(--orange)">'+(x.type||'--')+'</td><td style="font-size:11px;color:var(--text3)">'+(x.references&&x.references.cve?x.references.cve.join(', '):'--')+'</td></tr>';}).join('')+'</tbody></table></div></div>';
  if(u.length)html+='<div class="card card-p" style="margin-bottom:8px"><div class="card-title" style="margin-bottom:8px">Users</div><div style="display:flex;flex-wrap:wrap;gap:6px">'+u.map(function(x){return'<span class="tag">'+x+'</span>';}).join('')+'</div></div>';
  if(p.length)html+='<div class="card"><div class="card-header"><div class="card-title">Plugins</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>PLUGIN</th><th>VERSION</th><th>VULNS</th></tr></thead><tbody>'+p.map(function(x){return'<tr><td>'+(x.name||'--')+'</td><td style="color:var(--text3)">'+(x.version||'--')+'</td><td style="color:'+(x.vulnerabilities&&x.vulnerabilities.length?'var(--red)':'var(--green)')+'">'+(x.vulnerabilities?x.vulnerabilities.length:0)+'</td></tr>';}).join('')+'</tbody></table></div></div>';
  wpTool.res(html);
}

/* ==== SET INTERACTIVE TERMINAL ==== */
var _setSid = null;
var _setES  = null;
var _setHistory = [];
var _setHistIdx = -1;
var _setAnsiRe  = /[\x1B\x9B][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]/g;
var _setCRRe    = /\r/g;

function _setAppend(raw) {
  var el = document.getElementById('set-terminal-output');
  if (!el) return;
  // Strip ANSI escape codes, keep printable text + newlines
  var clean = raw.replace(_setAnsiRe, '').replace(_setCRRe, '');
  el.textContent += clean;
  // Auto-scroll
  el.scrollTop = el.scrollHeight;
}

function setTermClear() {
  var el = document.getElementById('set-terminal-output');
  if (el) el.textContent = '';
}

function setTermScroll() {
  var el = document.getElementById('set-terminal-output');
  if (el) el.scrollTop = el.scrollHeight;
}

function _setSetStatus(label, color, showKill) {
  var dot   = document.getElementById('set-status-dot');
  var lbl   = document.getElementById('set-status-label');
  var kill  = document.getElementById('set-kill-btn');
  var launch= document.getElementById('set-launch-btn');
  if (dot)    dot.style.background = color;
  if (lbl)    lbl.textContent      = label;
  if (kill)   kill.style.display   = showKill ? 'inline-flex' : 'none';
  // Keep launch enabled so clicking LAUNCH SET always restarts a fresh session.
  if (launch) launch.disabled      = false;
}

async function setLaunch() {
  // Kill any existing session first
  if (_setSid) { await setKill(); }
  setTermClear();
  _setAppend('Launching SET session...\n');
  _setSetStatus('Connecting...', 'var(--yellow)', false);

  try {
    var r = await fetch('/api/set/session/new', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    });
    var d = await r.json();
    if (d.error) {
      _setAppend('[ERROR] ' + d.error + '\n');
      _setSetStatus('Error — SET not found', 'var(--red)', false);
      showToast('SET Error', d.error, 'error', 7000);
      return;
    }
    _setSid = d.session_id;
    _setAppend('[+] Session started (binary: ' + d.binary + ')\n');
    _setSetStatus('Session active', 'var(--green)', true);
    showToast('SET Launched', 'Interactive terminal ready', 'success', 3000);
    _setStartStream();
  } catch(e) {
    _setAppend('[ERROR] ' + e.message + '\n');
    _setSetStatus('Launch failed', 'var(--red)', false);
  }
}

function _setStartStream() {
  if (_setES) { _setES.close(); _setES = null; }
  if (!_setSid) return;

  _setES = new EventSource('/api/set/session/' + _setSid + '/stream');

  _setES.onmessage = function(ev) {
    try {
      var msg = JSON.parse(ev.data);
      if (msg.type === 'output') {
        _setAppend(msg.text);
      } else if (msg.type === 'exit') {
        _setAppend(msg.text || '\n[Session ended]\n');
        _setSetStatus('Session ended', 'var(--text3)', false);
        _setES.close(); _setES = null; _setSid = null;
      } else if (msg.type === 'error') {
        _setAppend('[ERROR] ' + msg.text + '\n');
        _setSetStatus('Error', 'var(--red)', false);
      }
      // heartbeat: ignore
    } catch(e) {}
  };

  _setES.onerror = function() {
    _setAppend('\n[Stream lost — session may have ended]\n');
    _setSetStatus('Disconnected', 'var(--red)', false);
    if (_setES) { _setES.close(); _setES = null; }
  };
}

async function setKill() {
  if (_setES) { _setES.close(); _setES = null; }
  if (_setSid) {
    try {
      await fetch('/api/set/session/' + _setSid + '/kill', {method: 'POST'});
    } catch(e) {}
    _setSid = null;
  }
  _setSetStatus('Killed', 'var(--red)', false);
  _setAppend('\n[Session killed]\n');
  showToast('SET session killed', '', 'warning', 2500);
}

async function setSend(text) {
  if (!_setSid) {
    showToast('No active SET session', 'Click LAUNCH SET first', 'warning', 3000);
    return;
  }
  try {
    await fetch('/api/set/session/' + _setSid + '/input', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text: text})
    });
  } catch(e) {
    _setAppend('[send error] ' + e.message + '\n');
  }
}

async function setSpecialKey(key) {
  if (!_setSid) {
    showToast('No active SET session', 'Click LAUNCH SET first', 'warning', 3000);
    return;
  }
  try {
    await fetch('/api/set/session/' + _setSid + '/input', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: key})
    });
  } catch(e) {}
}

function setInputSend() {
  var inp = document.getElementById('set-input-box');
  if (!inp) return;
  var val = inp.value;
  if (!val && val !== '0') return;
  if (_setHistory[0] !== val) _setHistory.unshift(val);
  if (_setHistory.length > 50) _setHistory.pop();
  _setHistIdx = -1;
  inp.value = '';
  setSend(val + '\n');
}

function setInputKey(e) {
  var inp = document.getElementById('set-input-box');
  if (e.key === 'Enter') {
    e.preventDefault();
    setInputSend();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (_setHistIdx < _setHistory.length - 1) {
      _setHistIdx++;
      inp.value = _setHistory[_setHistIdx] || '';
    }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (_setHistIdx > 0) { _setHistIdx--; inp.value = _setHistory[_setHistIdx] || ''; }
    else { _setHistIdx = -1; inp.value = ''; }
  } else if (e.key === 'c' && e.ctrlKey) {
    e.preventDefault();
    setSpecialKey('ctrl_c');
  } else if (e.key === 'd' && e.ctrlKey) {
    e.preventDefault();
    setSpecialKey('ctrl_d');
  }
}

/* Keep old renderSocialTool for Gophish/Evilginx2/ShellPhish */
function renderSocialTool(toolObj,d){
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">'+(d.tool||'tool').toUpperCase()+'</div><div class="stat-lbl">TOOL</div></div><div class="stat"><div class="stat-val">'+(d.exit_code===null?'--':d.exit_code)+'</div><div class="stat-lbl">EXIT CODE</div></div><div class="stat"><div class="stat-val">'+(d.duration_ms||0)+'</div><div class="stat-lbl">DURATION (ms)</div></div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Command Executed</div><div style="font-family:var(--mono);font-size:11px;color:var(--text2);word-break:break-all">'+(d.command||'n/a')+'</div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">stdout</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">'+(d.stdout||'(empty)')+'</pre></div>';
  html+='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">stderr</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">'+(d.stderr||'(empty)')+'</pre></div>';
  toolObj.res(html);
}
async function runSetToolkit(){
  /* SET now uses the interactive terminal above — this stub keeps
     any residual references from breaking the page. */
  setLaunch();
}
async function runGophish(){
  var op=document.getElementById('gp-op').value, args=document.getElementById('gp-args').value.trim(), timeout=parseInt(document.getElementById('gp-timeout').value||'90',10);
  var btn=document.getElementById('gp-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  gpTool.start();gpTool.log('Executing Gophish operation: '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'gophish',operation:op,args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'gp');
    var d=await r.json();gpTool.end();if(d.error){gpTool.err(d.error);}else{gpTool.log('Gophish command completed','s');renderSocialTool(gpTool,d);}
  }catch(e){gpTool.end();gpTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN GOPHISH';}
}
async function runEvilginx2(){
  var op=document.getElementById('eg-op').value, args=document.getElementById('eg-args').value.trim(), timeout=parseInt(document.getElementById('eg-timeout').value||'90',10);
  var btn=document.getElementById('eg-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  egTool.start();egTool.log('Executing Evilginx2 operation: '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'evilginx2',operation:op,args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'eg');
    var d=await r.json();egTool.end();if(d.error){egTool.err(d.error);}else{egTool.log('Evilginx2 command completed','s');renderSocialTool(egTool,d);}
  }catch(e){egTool.end();egTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN EVILGINX2';}
}
async function runShellPhish(){
  var scriptPath=document.getElementById('sp-script').value.trim(), args=document.getElementById('sp-args').value.trim(), timeout=parseInt(document.getElementById('sp-timeout').value||'90',10);
  var btn=document.getElementById('sp-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  spTool.start();spTool.log('Executing ShellPhish script: '+scriptPath,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'shellphish',operation:'custom',args:args,script_path:scriptPath,timeout:timeout})},Math.max(20000,timeout*1000+5000),'sp');
    var d=await r.json();spTool.end();if(d.error){spTool.err(d.error);}else{spTool.log('ShellPhish command completed','s');renderSocialTool(spTool,d);}
  }catch(e){spTool.end();spTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SHELLPHISH';}
}
async function runNetcat(){
  var mode=document.getElementById('nc-mode').value, host=document.getElementById('nc-host').value.trim(), port=parseInt(document.getElementById('nc-port').value||'0',10), extra=document.getElementById('nc-extra').value.trim(), timeout=parseInt(document.getElementById('nc-timeout').value||'90',10);
  if(!port||port<1||port>65535){alert('Enter a valid port');return;}
  if(mode==='connect'&&!host){alert('Enter target host for connect mode');return;}
  var args=(mode==='listen'?('-l -p '+port):((host+' '+port)))+(extra?' '+extra:'');
  var btn=document.getElementById('nc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  ncTool.start();ncTool.log('Executing netcat mode: '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'netcat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'nc');
    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat command completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}
async function runNcat(){
  var mode=document.getElementById('nct-mode').value, host=document.getElementById('nct-host').value.trim(), port=parseInt(document.getElementById('nct-port').value||'0',10), extra=document.getElementById('nct-extra').value.trim(), timeout=parseInt(document.getElementById('nct-timeout').value||'90',10);
  if(!port||port<1||port>65535){alert('Enter a valid port');return;}
  if(mode==='connect'&&!host){alert('Enter target host for connect mode');return;}
  var args=(mode==='listen'?('-l -p '+port):((host+' '+port)))+(extra?' '+extra:'');
  var btn=document.getElementById('nct-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  nctTool.start();nctTool.log('Executing ncat mode: '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'ncat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'nct');
    var d=await r.json();nctTool.end();if(d.error){nctTool.err(d.error);}else{nctTool.log('Ncat command completed','s');renderSocialTool(nctTool,d);}
  }catch(e){nctTool.end();nctTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NCAT';}
}
async function runSocat(){
  var left=document.getElementById('sc-left').value.trim(), right=document.getElementById('sc-right').value.trim(), extra=document.getElementById('sc-extra').value.trim(), timeout=parseInt(document.getElementById('sc-timeout').value||'90',10);
  if(!left||!right){alert('Enter both left and right addresses');return;}
  var args=(extra?extra+' ':'')+left+' '+right;
  var btn=document.getElementById('sc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  scTool.start();scTool.log('Executing socat bridge','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'socat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'sc');
    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log('Socat command completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}
async function runSliver(){
  var op=document.getElementById('sv-op').value, args=document.getElementById('sv-args').value.trim(), timeout=parseInt(document.getElementById('sv-timeout').value||'90',10);
  var btn=document.getElementById('sv-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  svTool.start();svTool.log('Executing Sliver operation: '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'sliver',operation:op,args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'sv');
    var d=await r.json();svTool.end();if(d.error){svTool.err(d.error);}else{svTool.log('Sliver command completed','s');renderSocialTool(svTool,d);}
  }catch(e){svTool.end();svTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SLIVER';}
}
async function runEmpire(){
  var op=document.getElementById('em-op').value, args=document.getElementById('em-args').value.trim(), timeout=parseInt(document.getElementById('em-timeout').value||'90',10);
  var btn=document.getElementById('em-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  emTool.start();emTool.log('Executing Empire operation: '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'empire',operation:op,args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'em');
    var d=await r.json();emTool.end();if(d.error){emTool.err(d.error);}else{emTool.log('Empire command completed','s');renderSocialTool(emTool,d);}
  }catch(e){emTool.end();emTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN EMPIRE';}
}

/* ==== LYNIS ==== */
var _lyAgentTimer=null;
var _lySelectedAgentId='';
var _lyCurrentJobId=null;
function copyLynisInstallCmd(){
  var el=document.getElementById('ly-install-cmd');
  if(!el)return;
  el.select();el.setSelectionRange(0,99999);
  try{document.execCommand('copy');}catch(e){}
}
async function loadLynisAgents(){
  var box=document.getElementById('ly-agents');if(!box)return;
  try{
    var r=await fetchWithTimeout('/api/agents',{},15000,'ly');
    var d=await r.json();var agents=d.agents||[];
    if(!agents.length){box.innerHTML='<div style="color:var(--text3)">No agent connected yet. Install with the command above.</div>';return;}
    var html='<div style="display:flex;flex-direction:column;gap:6px">';
    agents.forEach(function(a){
      var st=(a.status||'unknown').toLowerCase();var col=st==='online'?'var(--green)':'var(--orange)';
      var selected=_lySelectedAgentId===a.client_id;
      html+='<div class="card-p" style="border:1px solid '+(selected?'var(--green)':'var(--border)')+';border-radius:8px;cursor:pointer" onclick="pickLynisAgent(\''+a.client_id+'\')"><div style="display:flex;justify-content:space-between;gap:8px"><div><strong>'+a.client_id+(selected?' <span style=&quot;color:var(--green);font-size:11px&quot;>(selected)</span>':'')+'</strong><div style="font-size:11px;color:var(--text3)">'+(a.hostname||'')+' · '+(a.os_info||'')+'</div></div><div style="font-size:11px;color:'+col+'">'+st.toUpperCase()+'</div></div><div style="font-size:10px;color:var(--text3);margin-top:4px">Last seen: '+(a.last_seen||'--')+' · IP: '+(a.ip_seen||'--')+'</div><div style="margin-top:8px"><button class="btn btn-outline btn-sm" onclick="event.stopPropagation();disconnectLynisAgent(\''+a.client_id+'\')">DISCONNECT</button></div></div>';
    });
    html+='</div><div style="font-size:11px;color:var(--green);margin-top:8px">&#10003; New system detected items appear here automatically.</div>';
    box.innerHTML=html;
    updateLynisAgentBadge();
  }catch(e){
    box.innerHTML='<div class="err-box visible">Failed to load agents: '+e.message+'</div>';
  }
}
function pickLynisAgent(clientId){
  _lySelectedAgentId=clientId;
  updateLynisAgentBadge();
  loadLynisAgents();
}
function clearLynisAgentSelection(){
  _lySelectedAgentId='';
  updateLynisAgentBadge();
  loadLynisAgents();
}
function updateLynisAgentBadge(){
  var el=document.getElementById('ly-selected-agent');if(!el)return;
  el.textContent=_lySelectedAgentId?('Remote agent selected: '+_lySelectedAgentId):'No remote agent selected (local scan mode).';
}
async function disconnectLynisAgent(clientId){
  if(!confirm('Disconnect '+clientId+'? This removes it from dashboard and invalidates its token. Reconnect later by running the curl installer again on that Linux host.'))return;
  try{
    var r=await fetchWithTimeout('/api/agents/'+encodeURIComponent(clientId)+'/disconnect',{method:'POST'},20000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    if(_lySelectedAgentId===clientId)_lySelectedAgentId='';
    lyTool.log('Disconnected '+clientId+'. Re-run curl installer on client to reconnect.','w');
    loadLynisAgents();loadLynisJobs();
  }catch(e){lyTool.err('Disconnect failed: '+e.message);}
}
function startLynisAgentWatcher(){
  if(_lyAgentTimer)clearInterval(_lyAgentTimer);
  _lyAgentTimer=setInterval(function(){
    var page=document.getElementById('page-lynis');
    if(page&&page.classList.contains('active')){loadLynisAgents();loadLynisJobs();}
  },10000);
}
async function doLynis(){
  var profile=document.getElementById('ly-profile').value;var category=document.getElementById('ly-category').value;var compliance=document.getElementById('ly-compliance').value;
  var clientId=_lySelectedAgentId;
  var useRemote=!!clientId;
  var btn=document.getElementById('ly-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Auditing...';
  lyTool.start();lyTool.log('Lynis audit starting...','i');lyTool.log('Profile: '+profile+(compliance?' - Compliance: '+compliance:''),'w');
  try{
    if(useRemote){
      lyTool.log('Queueing remote job for client: '+clientId,'i');
      var jr=await fetchWithTimeout('/api/create-job',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:clientId,profile:profile,category:category,compliance:compliance})},30000,'ly');
      var jd=await jr.json();if(jd.error)throw new Error(jd.error);
      _lyCurrentJobId=jd.job_id;
      lyTool.log('Job #'+jd.job_id+' queued. Waiting for agent...','w');
      loadLynisJobs();
      await pollLynisJob(jd.job_id);
    }else{
      var r=await fetchWithTimeout('/lynis',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:profile,category:category,compliance:compliance})},300000,'ly');
      var d=await r.json();lyTool.end();
      if(d.error){lyTool.log(d.error,'e');lyTool.err(d.error);}
      else{lyTool.log('Audit complete -- Hardening Index: '+(d.hardening_index||'?'),(d.hardening_index>=70?'s':'w'));renderLynis(d);}
    }
  }catch(e){lyTool.end();lyTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN LYNIS AUDIT';}
}
async function pollLynisJob(jobId){
  var tries=0;
  while(tries<180){
    tries++;
    var r=await fetchWithTimeout('/api/job-status/'+jobId,{},15000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    var pct=parseInt(d.progress_pct||0);lyTool.pct(pct);
    if(d.message)lyTool.log('['+d.status+'] '+d.message,(d.status==='completed'?'s':(d.status==='cancelled'?'w':'i')));
    if(d.status==='completed'){
      lyTool.end();
      renderLynis(d);
      loadLynisJobs();
      return;
    }
    if(d.status==='cancelled'){
      lyTool.end();lyTool.err('Job cancelled.');
      loadLynisJobs();
      return;
    }
    await new Promise(function(res){setTimeout(res,2000);});
  }
  throw new Error('Timed out waiting for remote Lynis agent to finish');
}
async function loadLynisJobs(){
  var box=document.getElementById('ly-jobs');if(!box)return;
  try{
    var r=await fetchWithTimeout('/api/jobs-overview?limit=12',{},15000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    var jobs=d.jobs||[];
    if(!jobs.length){box.innerHTML='<div style="color:var(--text3)">No Lynis jobs yet.</div>';return;}
    var html='<div style="display:flex;flex-direction:column;gap:6px">';
    jobs.forEach(function(j){
      var st=(j.status||'unknown').toLowerCase();
      var col=st==='completed'?'var(--green)':(st==='running'?'var(--yellow)':(st==='pending'?'var(--orange)':(st==='cancelled'?'var(--red)':'var(--text3')));
      var canCancel=(st==='pending'||st==='running');
      var canView=(st==='completed'||st==='failed'||st==='cancelled');
      html+='<div class="card-p" style="border:1px solid var(--border);border-radius:8px"><div style="display:flex;justify-content:space-between;gap:8px"><div><strong>Job #'+j.id+'</strong> · <span style="font-family:var(--mono)">'+j.client_id+'</span></div><div style="color:'+col+';font-size:11px">'+st.toUpperCase()+'</div></div><div style="font-size:11px;color:var(--text3);margin-top:4px">Progress: '+(j.progress_pct||0)+'% · '+(j.message||'')+'</div><div style="font-size:10px;color:var(--text3);margin-top:4px">Created: '+(j.created_at||'--')+(j.started_at?' · Started: '+j.started_at:'')+(j.completed_at?' · Completed: '+j.completed_at:'')+'</div><div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">'+(canCancel?'<button class="btn btn-outline btn-sm" onclick="cancelLynisJob('+j.id+')">CANCEL JOB</button>':'')+(canView?'<button class="btn btn-outline btn-sm" onclick="viewLynisJobReport('+j.id+')">VIEW REPORT</button><a class="btn btn-outline btn-sm" href="/api/job-report/'+j.id+'.txt" target="_blank">RAW</a>':'')+'<button class="btn btn-outline btn-sm" style="color:var(--red)" onclick="removeLynisJob('+j.id+')">REMOVE JOB</button></div></div>';
    });
    html+='</div>';
    box.innerHTML=html;
  }catch(e){
    box.innerHTML='<div class="err-box visible">Failed to load jobs: '+e.message+'</div>';
  }
}
async function cancelLynisJob(jobId){
  if(!confirm('Cancel Lynis job #'+jobId+'?'))return;
  try{
    var r=await fetchWithTimeout('/api/jobs/'+jobId+'/cancel',{method:'POST'},20000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    lyTool.log('Cancellation requested for job #'+jobId,'w');
    loadLynisJobs();
  }catch(e){lyTool.err('Cancel failed: '+e.message);}
}
async function viewLynisJobReport(jobId){
  try{
    var r=await fetchWithTimeout('/api/job-status/'+jobId,{},15000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    lyTool.log('Loaded report for job #'+jobId,'s');
    renderLynis(d);
  }catch(e){lyTool.err('View report failed: '+e.message);}
}
async function removeLynisJob(jobId){
  if(!confirm('Remove Lynis job #'+jobId+' and its saved report?'))return;
  try{
    var r=await fetchWithTimeout('/api/jobs/'+jobId,{method:'DELETE'},20000,'ly');
    var d=await r.json();if(d.error)throw new Error(d.error);
    if(_lyCurrentJobId===jobId)_lyCurrentJobId=null;
    lyTool.log('Removed Lynis job #'+jobId,'w');
    loadLynisJobs();
  }catch(e){lyTool.err('Remove job failed: '+e.message);}
}
function renderLynis(d){
  var w=d.warnings||[],sg=d.suggestions||[],sc=d.hardening_index||0;
  var sc_col=sc>=80?'var(--green)':sc>=60?'var(--yellow)':sc>=40?'var(--orange)':'var(--red)';
  var grade=sc>=80?'Good':(sc>=60?'Needs Improvement':(sc>=40?'At Risk':'Critical'));
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val" style="color:'+sc_col+'">'+sc+'</div><div class="stat-lbl">HARDENING INDEX</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+w.length+'</div><div class="stat-lbl">WARNINGS</div></div><div class="stat"><div class="stat-val" style="color:var(--yellow)">'+sg.length+'</div><div class="stat-lbl">SUGGESTIONS</div></div><div class="stat"><div class="stat-val">'+(d.tests_performed||'--')+'</div><div class="stat-lbl">TESTS</div></div></div>';
  html+='<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:6px">Security Posture Summary</div><div style="font-size:12px;line-height:1.6">Overall posture: <strong style="color:'+sc_col+'">'+grade+'</strong>. '+(w.length?('Address '+Math.min(w.length,10)+' high-priority warning(s) first. '):'No warnings detected. ')+'Use the suggestions list as a hardening checklist.</div></div>';
  if(d.job_id)html+='<div style="margin-bottom:10px"><a class="btn btn-outline btn-sm" href="/api/job-report/'+d.job_id+'.txt" target="_blank">DOWNLOAD RAW REPORT</a> <span style="font-size:11px;color:var(--text3);margin-left:6px">Job #'+d.job_id+'</span></div>';
  if(w.length)html+='<div class="card card-p" style="margin-bottom:8px"><div class="card-title" style="margin-bottom:8px;color:var(--red)">Warnings (Top '+Math.min(w.length,40)+')</div>'+w.slice(0,40).map(function(x){return'<div style="border-bottom:1px solid var(--border);padding:7px 0;font-family:var(--mono);font-size:11px;color:var(--orange)">'+x+'</div>';}).join('')+(w.length>40?'<div style="color:var(--text3);font-size:11px;padding-top:8px">...and '+(w.length-40)+' more warning entries</div>':'')+'</div>';
  if(sg.length)html+='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Suggestions (Top '+Math.min(sg.length,40)+' of '+sg.length+')</div>'+sg.slice(0,40).map(function(x){return'<div style="border-bottom:1px solid var(--border);padding:6px 0;font-family:var(--mono);font-size:11px;color:var(--text2)">&#8250; '+x+'</div>';}).join('')+(sg.length>40?'<div style="color:var(--text3);font-size:11px;padding-top:8px">...and '+(sg.length-40)+' more</div>':'')+'</div>';
  if(!w.length&&!sg.length)html+='<div class="card card-p" style="color:var(--text3)">No warning/suggestion details were returned by this run. Open RAW report for full output.</div>';
  lyTool.res(html);
}

/* ==== LEGION ==== */
var lgMods={'nmap':true,'nikto':true,'smb':true,'snmp':true,'hydra':false,'finger':false};
function lgMod(m,el){lgMods[m]=!lgMods[m];el.classList.toggle('on',lgMods[m]);}
async function doLegion(){
  var target=document.getElementById('lg-target').value.trim();if(!target){alert('Enter a target');return;}
  var intensity=document.getElementById('lg-intensity').value;
  var modules=Object.entries(lgMods).filter(function(kv){return kv[1];}).map(function(kv){return kv[0];});
  var btn=document.getElementById('lg-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  lgTool.start();lgTool.log('Target: '+target,'i');lgTool.log('Modules: '+modules.join(', '),'i');lgTool.log('Intensity: '+intensity,'w');
  try{
    var r=await fetchWithTimeout('/legion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target,intensity:intensity,modules:modules})},900000,'lg');
    var d=await r.json();lgTool.end();
    if(d.error){lgTool.err(d.error);}
    else{lgTool.log('Legion complete','s');renderLegion(d);}
  }catch(e){lgTool.end();lgTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN LEGION';}
}
function renderLegion(d){
  var html='<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">'+(d.open_ports||0)+'</div><div class="stat-lbl">OPEN PORTS</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+(d.total_issues||0)+'</div><div class="stat-lbl">ISSUES</div></div><div class="stat"><div class="stat-val">'+(d.modules_run||0)+'</div><div class="stat-lbl">MODULES</div></div></div>';
  (d.results||[]).forEach(function(r){html+='<div class="card" style="margin-bottom:8px"><div class="card-header"><div class="card-title">'+(r.module?r.module.toUpperCase():'MODULE')+'</div></div>';if(r.findings&&r.findings.length)html+='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>FINDING</th><th>DETAIL</th></tr></thead><tbody>'+r.findings.map(function(f){return'<tr><td>'+(f.title||f)+'</td><td style="color:var(--text3);font-size:11px">'+(f.detail||'')+'</td></tr>';}).join('')+'</tbody></table></div>';else html+='<div class="card-p" style="color:var(--text3);font-size:12px">'+(r.summary||'No findings')+'</div>';html+='</div>';});
  lgTool.res(html);
}

/* ==== SUBDOMAIN ==== */
async function doSub(){
  var domain=document.getElementById('sub-domain').value.trim();var size=document.getElementById('sub-size').value;
  if(!domain)return;
  var btn=document.getElementById('sub-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  document.getElementById('sub-res').innerHTML='<div style="color:var(--text3);font-size:13px">Enumerating subdomains for <strong>'+domain+'</strong>...</div>';
  try{
    var r=await fetchWithTimeout('/subdomains?domain='+encodeURIComponent(domain)+'&size='+size,{},120000);
    var d=await r.json();
    if(d.error){document.getElementById('sub-res').innerHTML='<div class="err-box visible">'+d.error+'</div>';return;}
    var html='<div class="found" style="margin-bottom:12px">'+d.total+' subdomains found &nbsp;&middot;&nbsp; '+((d.sources||[]).join(', '))+'</div>';
    html+='<div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>SUBDOMAIN</th><th>IP</th><th>SOURCE</th><th></th></tr></thead><tbody>';
    (d.subdomains||[]).forEach(function(s){html+='<tr><td style="font-family:var(--mono)">'+(s.subdomain||'')+'</td><td style="color:var(--text3)">'+(s.ip||'')+'</td><td><span class="tag">'+(s.source||'dns')+'</span></td><td><button class="btn btn-ghost btn-sm" onclick="scanFromSub(\''+s.subdomain+'\')">Scan</button></td></tr>';});
    html+='</tbody></table></div></div>';
    document.getElementById('sub-res').innerHTML=html;
  }catch(e){document.getElementById('sub-res').innerHTML='<div class="err-box visible">'+e.message+'</div>';}
  finally{btn.disabled=false;btn.innerHTML='FIND SUBDOMAINS';}
}
function scanFromSub(d){document.getElementById('tgt').value=d;pg('scan',null);doScan();}

/* ==== DIR BUSTER ==== */
async function doDir(){
  var url=document.getElementById('dir-url').value.trim();var size=document.getElementById('dir-size').value;var ext=document.getElementById('dir-ext').value.trim();
  if(!url)return;
  var btn=document.getElementById('dir-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  document.getElementById('dir-res').innerHTML='<div style="color:var(--text3);font-size:13px">Enumerating directories...</div>';
  try{
    var r=await fetchWithTimeout('/dirbust?url='+encodeURIComponent(url)+'&size='+size+'&ext='+encodeURIComponent(ext),{},180000);
    var d=await r.json();
    if(d.error){document.getElementById('dir-res').innerHTML='<div class="err-box visible">'+d.error+'</div>';return;}
    var html='<div class="found" style="margin-bottom:12px">'+d.total+' paths found &nbsp;&middot;&nbsp; '+d.scanned+' scanned</div>';
    html+='<div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>URL</th><th>STATUS</th><th>SIZE</th><th>SEVERITY</th><th>NOTE</th></tr></thead><tbody>';
    (d.found||[]).forEach(function(f){var sc=f.status;var sc_col=sc===200?'var(--green)':sc<400?'var(--yellow)':'var(--orange)';html+='<tr><td><a href="'+f.url+'" target="_blank" style="font-family:var(--mono);font-size:11px;color:var(--text)">'+f.url+'</a></td><td style="font-family:var(--mono);font-weight:500;color:'+sc_col+'">'+sc+'</td><td style="color:var(--text3)">'+(f.size||'?')+'</td><td>'+sev(f.severity)+'</td><td style="color:var(--text3);font-size:11px">'+(f.note||'')+'</td></tr>';});
    html+='</tbody></table></div></div>';
    document.getElementById('dir-res').innerHTML=html;
  }catch(e){document.getElementById('dir-res').innerHTML='<div class="err-box visible">'+e.message+'</div>';}
  finally{btn.disabled=false;btn.innerHTML='START ENUMERATION';}
}

/* ==== BRUTE FORCE ==== */
var _bfWordlists={};
function bfTypeChange(){var t=document.getElementById('bf-type').value;document.getElementById('bf-http-fields').style.display=t==='http'?'block':'none';document.getElementById('bf-ssh-fields').style.display=t==='ssh'?'block':'none';}
async function bfWordlistMode(which){
  var modeEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-mode');
  var textEl=document.getElementById('bf-'+(which==='user'?'users':'pwds'));
  var lblEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-src-lbl');
  var statusEl=document.getElementById('bf-wordlist-status');
  var mode=modeEl.value;
  if(mode==='manual'){textEl.disabled=false;lblEl.textContent='(one per line)';return;}
  var pathMap={
    rockyou_users:'/usr/share/wordlists/rockyou.txt',
    seclists_common:'/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
    seclists_top:'/usr/share/seclists/Usernames/Names/names.txt',
    seclists_default_creds:'/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt',
    rockyou:'/usr/share/wordlists/rockyou.txt',
    seclists_10k:'/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    seclists_100k:'/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt',
    seclists_default_creds_pass:'/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt',
    seclists_darkweb:'/usr/share/seclists/Passwords/darkweb2017-top10000.txt'
  };
  var filePath=pathMap[mode];
  if(!filePath){textEl.disabled=false;return;}
  statusEl.style.display='block';
  statusEl.textContent='[*] Loading wordlist: '+filePath+'...';
  textEl.disabled=true;lblEl.textContent='(from: '+filePath.split('/').pop()+')';
  try{
    var r=await fetch('/api/wordlist?path='+encodeURIComponent(filePath)+'&limit='+(which==='user'?'200':'1000'));
    var d=await r.json();
    if(d.error){statusEl.textContent='[!] '+d.error;textEl.disabled=false;return;}
    textEl.value=d.words.join('\n');
    statusEl.textContent='[+] Loaded '+d.words.length+' entries from '+d.filename;
    _bfWordlists[which]={path:filePath,count:d.words.length};
  }catch(e){statusEl.textContent='[!] Failed to load wordlist: '+e.message;textEl.disabled=false;}
}
async function doBrute(){
  var type=document.getElementById('bf-type').value;
  var users=document.getElementById('bf-users').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
  var pwds=document.getElementById('bf-pwds').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
  if(!users.length||!pwds.length){alert('Enter at least one username and password');return;}
  var btn=document.getElementById('bf-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Attacking...';
  document.getElementById('bf-res').innerHTML='<div style="color:var(--text3);font-size:13px">Running -- '+users.length+' users x '+pwds.length+' passwords...</div>';
  try{
    var url='/brute-http',body={users:users,passwords:pwds};
    // Pass wordlist paths for server-side use if large lists selected
    if(_bfWordlists.user&&_bfWordlists.user.count>200)body.user_wordlist_path=_bfWordlists.user.path;
    if(_bfWordlists.pass&&_bfWordlists.pass.count>1000)body.pass_wordlist_path=_bfWordlists.pass.path;
    if(type==='http'){body.url=document.getElementById('bf-url').value.trim();body.user_field=document.getElementById('bf-ufield').value||'username';body.pass_field=document.getElementById('bf-pfield').value||'password';}
    else{url='/brute-ssh';body.host=document.getElementById('bf-ssh-host').value.trim();body.port=document.getElementById('bf-ssh-port').value||'22';}
    var r=await fetchWithTimeout(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)},120000);
    var d=await r.json();
    var found=d.found||[];
    document.getElementById('bf-res').innerHTML='<div class="found" style="margin-bottom:12px">'+found.length+' credentials found &nbsp;&middot;&nbsp; '+(d.attempts||0)+' attempts</div>'+(found.length?'<div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>USERNAME</th><th>PASSWORD</th><th>STATUS</th></tr></thead><tbody>'+found.map(function(f){return'<tr><td style="font-family:var(--mono)">'+f.username+'</td><td style="font-family:var(--mono);color:var(--red);font-weight:500">'+f.password+'</td><td style="color:var(--green)">SUCCESS</td></tr>';}).join('')+'</tbody></table></div></div>':'<div style="color:var(--green);font-size:13px">No valid credentials found.</div>');
  }catch(e){document.getElementById('bf-res').innerHTML='<div class="err-box visible">'+e.message+'</div>';}
  finally{btn.disabled=false;btn.innerHTML='START BRUTE FORCE';}
}

/* ==== DISCOVER ==== */
async function doDisc(){
  var subnet=document.getElementById('subnet').value.trim();if(!subnet)return;
  var btn=document.getElementById('disc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  document.getElementById('disc-res').innerHTML='<div style="color:var(--text3)">Scanning subnet...</div>';
  try{
    var r=await fetchWithTimeout('/discover?subnet='+encodeURIComponent(subnet),{},120000);
    var d=await r.json();
    if(d.error){document.getElementById('disc-res').innerHTML='<div class="err-box visible">'+d.error+'</div>';return;}
    document.getElementById('disc-res').innerHTML='<div class="found" style="margin-bottom:12px">'+(d.total||0)+' hosts found</div><div class="host-grid">'+(d.hosts||[]).map(function(h){return'<div class="host-card" onclick="scanDisc(\''+h.ip+'\')"><div class="host-card-ip">'+h.ip+'</div>'+(h.hostnames&&h.hostnames[0]?'<div class="host-card-hn">'+h.hostnames[0]+'</div>':'')+(h.vendor?'<div style="font-size:10px;color:var(--text3);margin-top:2px">'+h.vendor+'</div>':'')+'<div style="font-size:10px;color:var(--text3);margin-top:6px">Click to scan &#8250;</div></div>';}).join('')+'</div>';
  }catch(e){document.getElementById('disc-res').innerHTML='<div class="err-box visible">'+e.message+'</div>';}
  finally{btn.disabled=false;btn.innerHTML='DISCOVER';}
}
function scanDisc(ip){document.getElementById('tgt').value=ip;pg('scan',null);doScan();}

/* ==== HISTORY ==== */
async function loadHist(){
  try{
    var r=await fetch('/history');var d=await r.json();
    if(!Array.isArray(d)||!d.length){document.getElementById('hist-content').innerHTML='<div class="card-p" style="color:var(--text3)">No scans yet.</div>';return;}
    document.getElementById('hist-content').innerHTML='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th></th></tr></thead><tbody>'+d.map(function(s){return'<tr><td style="color:var(--text3)">#'+s.id+'</td><td style="font-family:var(--mono)">'+s.target+'</td><td style="color:var(--text3);font-size:11px">'+((s.scan_time||'').replace('T',' ').substring(0,19))+'</td><td>'+s.open_ports+'</td><td>'+s.total_cves+'</td><td style="color:'+(s.critical_cves>0?'var(--red)':'var(--text3)')+'">'+s.critical_cves+'</td><td><button class="btn btn-ghost btn-sm" onclick="loadScan('+s.id+')">View</button></td></tr>';}).join('')+'</tbody></table></div>';
  }catch(e){document.getElementById('hist-content').innerHTML='<div class="card-p" style="color:var(--red)">'+e.message+'</div>';}
}
async function loadScan(id){
  pg('scan',null);clrUI();
  try{var r=await fetch('/scan/'+id);var d=await r.json();document.getElementById('tgt').value=d.target||'';renderScan(d);}
  catch(e){showErr('err','Error: '+e.message);}
}

/* ==== DASHBOARD ==== */
async function loadDash(){
  try{
    var r=await fetch('/history?limit=100');var d=await r.json();
    if(!d.length){document.getElementById('dash-content').innerHTML='<div style="color:var(--text3)">Run some scans first.</div>';return;}
    var tc=d.reduce(function(a,s){return a+s.total_cves;},0),cr=d.reduce(function(a,s){return a+s.critical_cves;},0),tp=d.reduce(function(a,s){return a+s.open_ports;},0);
    var mx=Math.max.apply(null,d.map(function(s){return s.total_cves;}).concat([1]));
    document.getElementById('dash-content').innerHTML='<div class="stats" style="margin-bottom:18px"><div class="stat"><div class="stat-val">'+d.length+'</div><div class="stat-lbl">SCANS</div></div><div class="stat"><div class="stat-val">'+tc+'</div><div class="stat-lbl">TOTAL CVEs</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+cr+'</div><div class="stat-lbl">CRITICAL</div></div><div class="stat"><div class="stat-val">'+tp+'</div><div class="stat-lbl">OPEN PORTS</div></div></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px"><div class="card card-p"><div class="card-title" style="margin-bottom:12px">Top Targets by CVEs</div>'+d.slice(0,6).map(function(s){return'<div class="bar-row"><span class="bar-label">'+s.target.substring(0,14)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+((s.total_cves/mx)*100)+'%"></div></div><span class="bar-val" style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+s.total_cves+'</span></div>';}).join('')+'</div><div class="card card-p"><div class="card-title" style="margin-bottom:12px">Recent Activity</div>'+d.slice(0,8).map(function(s){return'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="font-family:var(--mono)">'+s.target+'</span><span style="color:'+(s.critical_cves>0?'var(--red)':'var(--text3)')+'">'+(s.critical_cves>0?s.critical_cves+' critical':s.total_cves+' CVEs')+'</span></div>';}).join('')+'</div></div>';
  }catch(e){document.getElementById('dash-content').innerHTML='<div style="color:var(--red)">'+e.message+'</div>';}
}

/* ==== ADMIN ==== */
function adminTab(e,id){
  document.querySelectorAll('#admin-tabs .tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('#page-admin .tc').forEach(function(t){t.classList.remove('active');});
  e.currentTarget.classList.add('active');document.getElementById(id).classList.add('active');
  if(id==='at-users')loadAdminUsers();if(id==='at-stats')loadAdminStats();
  if(id==='at-audit')loadAdminAudit();if(id==='at-scans')loadAdminScans();
  if(id==='at-cli'){loadServerStats();initCliHeader();}
  if(id!=='at-cli'&&window._statsInterval){clearInterval(window._statsInterval);window._statsInterval=null;}
}
async function loadAdmin(){loadServerStats();setTimeout(initCliHeader,400);}
var _statsInterval=null;
function fmtBytes(b){if(b===null||b===undefined)return'--';if(b>=1073741824)return(b/1073741824).toFixed(1)+'G';if(b>=1048576)return(b/1048576).toFixed(1)+'M';if(b>=1024)return(b/1024).toFixed(1)+'K';return b+'B';}
function setBar(id,pct){var el=document.getElementById(id);if(!el)return;el.style.width=Math.min(100,pct)+'%';}
async function loadServerStats(){
  try{
    var r=await fetch('/api/server-stats');var d=await r.json();if(d.error)return;
    var cpuPct=d.cpu_percent||0;var cpuEl=document.getElementById('cpu-val');if(cpuEl)cpuEl.textContent=cpuPct+'%';setBar('cpu-bar',cpuPct);var coresEl=document.getElementById('cpu-cores');if(coresEl)coresEl.textContent=(d.cpu_count||'?')+' cores';
    var memPct=d.memory?d.memory.percent:0;var memEl=document.getElementById('mem-val');if(memEl)memEl.textContent=memPct+'%';setBar('mem-bar',memPct);var memTot=document.getElementById('mem-total');if(memTot)memTot.textContent='of '+fmtBytes(d.memory?d.memory.total:0);
    var swapPct=d.swap?d.swap.percent:0;var swapEl=document.getElementById('swap-val');if(swapEl)swapEl.textContent=swapPct+'%';setBar('swap-bar',swapPct);var swapTot=document.getElementById('swap-total');if(swapTot)swapTot.textContent='of '+fmtBytes(d.swap?d.swap.total:0);
    var diskPct=d.disk?d.disk.percent:0;var diskEl=document.getElementById('disk-val');if(diskEl)diskEl.textContent=diskPct+'%';setBar('disk-bar',diskPct);var diskTot=document.getElementById('disk-total');if(diskTot)diskTot.textContent='of '+fmtBytes(d.disk?d.disk.total:0);
    var txEl=document.getElementById('net-tx');var rxEl=document.getElementById('net-rx');if(txEl)txEl.textContent=fmtBytes(d.net?d.net.bytes_sent:0);if(rxEl)rxEl.textContent=fmtBytes(d.net?d.net.bytes_recv:0);var ifaceEl=document.getElementById('net-iface');if(ifaceEl)ifaceEl.textContent=d.net?d.net.iface||'':'';
    var upEl=document.getElementById('sys-uptime');if(upEl&&d.uptime)upEl.textContent=d.uptime;var ldEl=document.getElementById('sys-load');if(ldEl&&d.load_avg)ldEl.textContent=d.load_avg;var prEl=document.getElementById('sys-procs');if(prEl)prEl.textContent=(d.process_count||'?')+' procs';
    var tsEl=document.getElementById('stats-updated');if(tsEl)tsEl.textContent='UPDATED '+new Date().toLocaleTimeString();
  }catch(e){}
  if(!window._statsInterval)window._statsInterval=setInterval(function(){var cp=document.getElementById('at-cli');if(cp&&cp.classList.contains('active'))loadServerStats();else{clearInterval(window._statsInterval);window._statsInterval=null;}},3000);
}
async function loadAdminUsers(){
  try{var r=await fetch('/api/admin/users');var d=await r.json();document.getElementById('admin-users-table').innerHTML='<table class="tbl"><thead><tr><th>#</th><th>USERNAME</th><th>EMAIL</th><th>ROLE</th><th>ACTIVE</th><th>LOGINS</th><th>LAST LOGIN</th><th>ACTIONS</th></tr></thead><tbody>'+d.map(function(u){return'<tr><td style="color:var(--text3)">#'+u.id+'</td><td style="font-family:var(--mono)">'+u.username+'</td><td style="font-size:11px;color:var(--text3)">'+u.email+'</td><td><span class="badge '+(u.role==='admin'?'badge-admin':'badge-user')+'">'+u.role+'</span></td><td style="color:'+(u.is_active?'var(--green)':'var(--red)')+'">'+( u.is_active?'Active':'Disabled')+'</td><td style="color:var(--text3)">'+(u.login_count||0)+'</td><td style="font-size:11px;color:var(--text3)">'+((u.last_login||'never').substring(0,16))+'</td><td style="display:flex;gap:4px;flex-wrap:wrap"><button class="btn btn-outline btn-sm" onclick="toggleUser('+u.id+')">'+(u.is_active?'Disable':'Enable')+'</button><button class="btn btn-outline btn-sm" onclick="setRole('+u.id+',\''+(u.role==='admin'?'user':'admin')+'\')">'+(u.role==='admin'?'User':'Admin')+'</button><button class="btn btn-danger btn-sm" onclick="deleteUser('+u.id+')">Del</button></td></tr>';}).join('')+'</tbody></table>';}catch(e){}
}
async function adminCreateUser(){
  var fullName=(document.getElementById('au-full-name')||{}).value||'';
  var username=(document.getElementById('au-username')||{}).value||'';
  var email=(document.getElementById('au-email')||{}).value||'';
  var msg=document.getElementById('admin-create-user-msg');
  if(msg){msg.className='auth-msg';msg.textContent='';}
  try{
    var r=await fetch('/api/admin/users/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full_name:fullName,username:username,email:email})});
    var d=await r.json();
    if(msg){
      msg.className='auth-msg '+(d.success?'ok':'err');
      msg.textContent=d.message||d.error||'Request completed.';
    }
    if(d.success){
      document.getElementById('au-full-name').value='';
      document.getElementById('au-username').value='';
      document.getElementById('au-email').value='';
      loadAdminUsers();
    }
  }catch(e){
    if(msg){msg.className='auth-msg err';msg.textContent='Failed to create user: '+e.message;}
  }
}
async function toggleUser(id){await fetch('/api/admin/users/'+id+'/toggle',{method:'POST'});loadAdminUsers();}
async function setRole(id,role){await fetch('/api/admin/users/'+id+'/role',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:role})});loadAdminUsers();}
async function deleteUser(id){if(!confirm('Delete this user?'))return;await fetch('/api/admin/users/'+id,{method:'DELETE'});loadAdminUsers();}
async function loadAdminStats(){try{var r=await fetch('/api/admin/stats');var d=await r.json();document.getElementById('admin-stats').innerHTML='<div class="stats"><div class="stat"><div class="stat-val">'+(d.total_users||0)+'</div><div class="stat-lbl">USERS</div></div><div class="stat"><div class="stat-val">'+(d.verified_users||0)+'</div><div class="stat-lbl">VERIFIED</div></div><div class="stat"><div class="stat-val">'+(d.total_scans||0)+'</div><div class="stat-lbl">SCANS</div></div><div class="stat"><div class="stat-val">'+(d.scans_today||0)+'</div><div class="stat-lbl">TODAY</div></div><div class="stat"><div class="stat-val" style="color:var(--red)">'+(d.critical_cves||0)+'</div><div class="stat-lbl">CRITICAL</div></div><div class="stat"><div class="stat-val">'+(d.total_cves||0)+'</div><div class="stat-lbl">TOTAL CVEs</div></div></div>';}catch(e){}}
async function loadAdminAudit(){try{var r=await fetch('/api/admin/audit?limit=200');var d=await r.json();document.getElementById('admin-audit').innerHTML='<table class="tbl"><thead><tr><th>TIME</th><th>USER</th><th>ACTION</th><th>TARGET</th><th>IP</th></tr></thead><tbody>'+d.map(function(l){return'<tr><td style="font-size:11px;color:var(--text3)">'+((l.timestamp||'').substring(0,16))+'</td><td style="font-family:var(--mono)">'+(l.username||'--')+'</td><td><span class="tag">'+(l.action||'')+'</span></td><td style="font-size:11px;color:var(--text3)">'+(l.target||'--')+'</td><td style="font-size:11px;color:var(--text3)">'+(l.ip_address||'--')+'</td></tr>';}).join('')+'</tbody></table>';}catch(e){}}
async function loadAdminScans(){try{var r=await fetch('/api/admin/scans');var d=await r.json();document.getElementById('admin-scans').innerHTML='<table class="tbl"><thead><tr><th>#</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th></th></tr></thead><tbody>'+d.map(function(s){return'<tr><td style="color:var(--text3)">#'+s.id+'</td><td style="font-family:var(--mono)">'+s.target+'</td><td style="font-size:11px;color:var(--text3)">'+((s.scan_time||'').replace('T',' ').substring(0,19))+'</td><td>'+s.open_ports+'</td><td>'+s.total_cves+'</td><td style="color:'+(s.critical_cves>0?'var(--red)':'var(--text3)')+'">'+s.critical_cves+'</td><td><button class="btn btn-ghost btn-sm" onclick="loadScan('+s.id+')">View</button></td></tr>';}).join('')+'</tbody></table>';}catch(e){}}

/* ==== CLI ==== */
var _cliHistory=[],_cliHistIdx=-1;
function initCliHeader(){
  try{fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:'hostname'})}).then(function(r){return r.json();}).then(function(d){var el=document.getElementById('cli-hostname');if(el&&d.output)el.textContent=d.output.trim();}).catch(function(){});}catch(e){}
  var ul=document.getElementById('cli-user-label');if(ul&&currentUser)ul.textContent=currentUser.username;
}
async function cliRun(){
  var inp=document.getElementById('cli-input');var out=document.getElementById('cli-output');var sb=document.getElementById('cli-statusbar');
  if(!inp||!out)return;var cmd=inp.value.trim();if(!cmd)return;
  if(_cliHistory[0]!==cmd)_cliHistory.unshift(cmd);if(_cliHistory.length>50)_cliHistory.pop();_cliHistIdx=-1;
  var ts=new Date().toLocaleTimeString();
  out.innerHTML+='<div class="cli-cmd-line"><span style="color:var(--text3)">['+ts+']</span> $ '+cmd.replace(/</g,'&lt;')+'</div>';
  inp.value='';if(sb)sb.innerHTML='<div class="pulse"></div><span>Running...</span>';
  try{
    var r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:cmd})});
    var d=await r.json();
    if(d.error)out.innerHTML+='<div class="cli-err">'+d.error.replace(/</g,'&lt;')+'</div>';
    if(d.output)out.innerHTML+='<div class="cli-resp">'+d.output.replace(/</g,'&lt;')+'</div>';
    if(!d.output&&!d.error)out.innerHTML+='<div style="color:var(--text3);font-size:11px">(no output)</div>';
    if(sb)sb.innerHTML='<div class="pulse"></div><span>Ready | '+_cliHistory.length+' in history | Exit: '+(d.exit_code!=null?d.exit_code:'?')+'</span>';
  }catch(e){out.innerHTML+='<div class="cli-err">Network error: '+e.message+'</div>';if(sb)sb.innerHTML='<div class="pulse" style="background:var(--red)"></div><span>Error</span>';}
  out.scrollTop=out.scrollHeight;
}
function cliKey(e){
  var inp=document.getElementById('cli-input');if(!inp)return;
  if(e.key==='Enter'){e.preventDefault();cliRun();}
  else if(e.key==='ArrowUp'){e.preventDefault();if(_cliHistIdx<_cliHistory.length-1){_cliHistIdx++;inp.value=_cliHistory[_cliHistIdx]||'';}}
  else if(e.key==='ArrowDown'){e.preventDefault();if(_cliHistIdx>0){_cliHistIdx--;inp.value=_cliHistory[_cliHistIdx]||'';}else{_cliHistIdx=-1;inp.value='';}}
}
function cliClear(){var out=document.getElementById('cli-output');if(out)out.innerHTML='<div style="color:var(--text3);font-size:11px">Terminal cleared.</div>';}
function cliQuick(cmd){var inp=document.getElementById('cli-input');if(inp){inp.value=cmd;cliRun();}}

/* ==== PDF REPORT ==== */
async function exportPDF(){
  var data=window._sd;if(!data){alert('Run a scan first');return;}
  try{var r=await fetchWithTimeout('/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)},60000);if(!r.ok)throw new Error(await r.text());var blob=await r.blob();var url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download='vulnscan-'+(data.target||'report')+'-'+new Date().toISOString().slice(0,10)+'.pdf';document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);}
  catch(e){alert('PDF failed: '+e.message);}
}

/* ==== EMAIL VERIFY ==== */
var vt=new URLSearchParams(location.search).get('verify');
if(vt){fetch('/api/verify/'+vt).then(function(r){return r.json();}).then(function(d){if(d.success){authMsg(d.message+' You can now login.','ok');authTab('login');}else authMsg(d.error||'Verification failed','err');});}

/* ==== KEYBOARD ==== */
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){closeAbout();document.getElementById('tos-modal').classList.remove('open');}
  if(e.key==='Enter'&&document.getElementById('l-pass')===document.activeElement)doLogin();
});

/* ==== ANIMATION HELPERS ==== */
function typeWriter(el,text,cursor){
  cursor=cursor||'';el.textContent='';var i=0;
  function tick(){if(i<=text.length){el.textContent=text.slice(0,i)+(i<text.length?cursor:'');i++;setTimeout(tick,i===1?320:52);}}
  tick();
}
function vsGreetUser(username){
  var suf=document.getElementById('home-username-suffix');
  if(suf&&!suf.textContent)typeWriter(suf,', '+username,'_');
}

/* ==== HACKER BACKGROUND ==== */
(function(){
  var cv, cx, W = 0, H = 0;

  /* ---- colour: dark chars on light, light chars on dark ---- */
  function isDark() {
    var b = document.getElementById('body');
    return b && b.classList.contains('dark');
  }
  /* head of each column -- brightest char */
  function headRGB()  { return isDark() ? [60, 120, 60]  : [40, 40, 40]; }
  /* trail colour */
  function trailRGB() { return isDark() ? [0,  90, 30]  : [30, 30, 30]; }
  /* fade rect colour matches the page background */
  function fadeFill() {
    return isDark()
      ? 'rgba(10,10,10,0.25)'
      : 'rgba(255,255,255,0.30)';
  }

  /* ---- character set ---- */
  var CHARS = ('01ABCDEF0123456789<>{}[]|/:?!@#$%^&*nmap ssh ftp http ssl tls cve xss sqli rce').split('');
  function rndChar() { return CHARS[Math.floor(Math.random() * CHARS.length)]; }

  /* ---- columns ---- */
  var COL_W = 20, FONT_SZ = 9, columns = [];

  function initColumns() {
    columns = [];
    var n = Math.ceil(W / COL_W);
    for (var i = 0; i < n; i++) {
      var col = {
        x: i * COL_W,
        y: Math.random() * -H,
        speed: 0.3 + Math.random() * 0.7,
        len:   7 + Math.floor(Math.random() * 12),
        chars: [],
        tick:  0,
        mutRate: 0.03 + Math.random() * 0.05
      };
      for (var j = 0; j < 22; j++) col.chars.push(rndChar());
      columns.push(col);
    }
  }

  function drawRain() {
    var HEAD  = headRGB();
    var TRAIL = trailRGB();
    /* base opacity: subtle on both themes */
    var baseAlpha = isDark() ? 0.18 : 0.12;

    cx.font = FONT_SZ + 'px "DM Mono","Courier New",monospace';
    cx.textAlign = 'center';

    for (var i = 0; i < columns.length; i++) {
      var col = columns[i];
      col.tick++;

      /* advance column */
      if (col.tick % Math.max(1, Math.round(3 / col.speed)) === 0) {
        col.y += COL_W;
        col.chars.unshift(rndChar());
        if (col.chars.length > col.len + 2) col.chars.pop();
      }

      /* random char mutation */
      if (Math.random() < col.mutRate) {
        col.chars[Math.floor(Math.random() * col.chars.length)] = rndChar();
      }

      /* draw each char in this column */
      for (var k = 0; k < col.chars.length; k++) {
        var cy = col.y - k * COL_W;
        if (cy < -COL_W || cy > H + COL_W) continue;

        var t = 1 - (k / col.len);
        if (t < 0) t = 0;

        var r, g, b, a;
        if (k === 0) {
          /* head: brightest */
          r = HEAD[0]; g = HEAD[1]; b = HEAD[2];
          a = baseAlpha;
        } else {
          /* trail: fades out */
          r = Math.round(TRAIL[0] * t);
          g = Math.round(TRAIL[1] * t);
          b = Math.round(TRAIL[2] * t);
          a = baseAlpha * t * 0.6;
        }

        cx.fillStyle = 'rgba(' + r + ',' + g + ',' + b + ',' + a.toFixed(3) + ')';
        cx.fillText(col.chars[k], col.x + COL_W / 2, cy);
      }

      /* reset column when it scrolls off bottom */
      if (col.y - col.len * COL_W > H) {
        col.y     = -COL_W * (2 + Math.random() * 8);
        col.speed = 0.3 + Math.random() * 0.7;
        col.len   = 7 + Math.floor(Math.random() * 12);
        col.chars = [];
        for (var j2 = 0; j2 < 22; j2++) col.chars.push(rndChar());
      }
    }
  }

  /* ---- resize ---- */
  function resize() {
    if (!cv) return;
    var dpr = window.devicePixelRatio || 1;
    W = window.innerWidth;
    H = window.innerHeight;
    cx.setTransform(1, 0, 0, 1, 0, 0);
    cv.width  = W * dpr;
    cv.height = H * dpr;
    cv.style.width  = W + 'px';
    cv.style.height = H + 'px';
    cx.setTransform(dpr, 0, 0, dpr, 0, 0);
    initColumns();
  }

  /* ---- main loop ---- */
  function loop() {
    requestAnimationFrame(loop);
    /* semi-transparent fill creates the trail smear */
    cx.fillStyle = fadeFill();
    cx.fillRect(0, 0, W, H);
    drawRain();
  }

  /* ---- init ---- */
  function init() {
    if (document.getElementById('vs-hacker-canvas')) return;
    cv = document.createElement('canvas');
    cv.id = 'vs-hacker-canvas';
    cv.style.cssText = [
      'position:fixed',
      'top:0', 'left:0',
      'width:100vw', 'height:100vh',
      'pointer-events:none',  /* NEVER blocks clicks */
      'z-index:-1'            /* always behind everything */
    ].join(';');
    document.body.insertBefore(cv, document.body.firstChild);
    cx = cv.getContext('2d');
    window.addEventListener('resize', resize);
    resize();
    loop();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    setTimeout(init, 0);
  }
})();

loadUser();

/* ==== NEW USER MODAL ==== */
function openNewUserModal(){
  // Reset form state
  var form=document.getElementById('new-user-form-body');
  var succ=document.getElementById('new-user-success-body');
  var msg=document.getElementById('new-user-modal-msg');
  var btn=document.getElementById('nu-submit-btn');
  if(form)form.style.display='block';
  if(succ)succ.style.display='none';
  if(msg){msg.textContent='';msg.style.display='none';}
  if(btn){btn.disabled=false;document.getElementById('nu-btn-text').textContent='CREATE USER';}
  var f=document.getElementById('nu-full-name');var u=document.getElementById('nu-username');var e=document.getElementById('nu-email');
  if(f)f.value='';if(u)u.value='';if(e)e.value='';
  document.getElementById('new-user-modal').classList.add('open');
  setTimeout(function(){if(f)f.focus();},120);
}
function closeNewUserModal(){
  document.getElementById('new-user-modal').classList.remove('open');
}
function showNewUserMsg(msg,type){
  var el=document.getElementById('new-user-modal-msg');
  el.textContent=msg;
  el.className='auth-msg '+(type||'err');
  el.style.display='block';
}
async function submitNewUser(){
  var fullName=(document.getElementById('nu-full-name')||{}).value||'';
  var username=(document.getElementById('nu-username')||{}).value||'';
  var email=(document.getElementById('nu-email')||{}).value||'';
  if(!username.trim()||!email.trim()){showNewUserMsg('Username and email are required.','err');return;}
  var btn=document.getElementById('nu-submit-btn');
  var btnTxt=document.getElementById('nu-btn-text');
  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span> Creating...';
  try{
    var r=await fetch('/api/admin/users/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full_name:fullName.trim(),username:username.trim(),email:email.trim()})});
    var d=await r.json();
    if(d.success){
      // Show success state
      document.getElementById('new-user-form-body').style.display='none';
      var succ=document.getElementById('new-user-success-body');
      var succMsg=document.getElementById('nu-success-msg');
      if(succMsg)succMsg.textContent='User "'+username.trim()+'" has been created and login credentials have been sent to '+email.trim()+'.';
      succ.style.display='block';
      showToast('User Created','Credentials sent to '+email.trim(),'success',5000);
    } else {
      showNewUserMsg(d.error||'Failed to create user.','err');
      btn.disabled=false;
      btnTxt.textContent='CREATE USER';
    }
  }catch(e){
    showNewUserMsg('Network error: '+e.message,'err');
    btn.disabled=false;
    btnTxt.textContent='CREATE USER';
  }
}
/* End new user modal */
</script>
</body>
</html>"""
# ── Auto-install helper ────────────────────────────────────────────────────────
def auto_install(pkg, binary=None):
    """Try to install a package via apt. Returns (success, message)."""
    import shutil
    binary = binary or pkg
    if shutil.which(binary):
        return True, f"{binary} already installed"
    try:
        r = subprocess.run(
            ["sudo", "apt-get", "install", "-y", pkg],
            capture_output=True, text=True, timeout=120
        )
        if shutil.which(binary):
            return True, f"Installed {pkg} via apt"
        return False, r.stderr[:300] or "apt install failed"
    except Exception as e:
        return False, str(e)


TOOL_INSTALL_MAP = {
    "nmap":         ("nmap",         "nmap"),
    "nikto":        ("nikto",        "nikto"),
    "lynis":        ("lynis",        "lynis"),
    "dnsrecon":     ("dnsrecon",     "dnsrecon"),
    "legion":       ("legion",       "legion"),
    "theharvester": ("theharvester", "theHarvester"),
    "wpscan":       (None,           "wpscan"),
    "dig":          ("dnsutils",     "dig"),
    "proxychains4": ("proxychains4", "proxychains4"),
    "tor":          ("tor",          "tor"),
}


def _normalize_target_url(url):
    raw = (url or "").strip()
    if not raw:
        return "", "", ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = (parsed.netloc or parsed.path).split("@")[-1]
    host = host.split(":")[0].strip().lower()
    if not host or not re.match(r"^[a-z0-9.\-]+$", host):
        return "", "", ""
    base = f"{parsed.scheme}://{host}"
    return raw, base, host


def _run_nikto_for_webdeep(target):
    import shutil, tempfile
    binary = shutil.which("nikto")
    if not binary:
        return {"status": "skipped", "reason": "nikto not installed", "findings": []}
    px = proxychains_cmd()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name
    cmd = [px, "-q", binary, "-h", target, "-Format", "json", "-o", out_file, "-nointeractive", "-maxtime", "1200"]
    findings = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_NIKTO)
        if os.path.exists(out_file):
            with open(out_file) as f:
                raw = json.load(f)
            for host in (raw.get("host", []) if isinstance(raw, dict) else []):
                for item in host.get("vulnerabilities", []):
                    findings.append({
                        "id": item.get("id", ""),
                        "description": item.get("msg", ""),
                        "uri": item.get("uri", ""),
                        "severity": "high" if item.get("OSVDB", "0") != "0" else "info"
                    })
        if not findings and proc.stdout:
            for line in proc.stdout.splitlines():
                m = re.search(r'\+ (OSVDB-\d+|[\w-]+): (.+)', line)
                if m:
                    findings.append({"id": m.group(1), "description": m.group(2), "severity": "high"})
        return {"status": "ok", "findings": findings}
    except Exception as e:
        return {"status": "error", "error": str(e), "findings": findings}
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)


def _run_whatweb_for_webdeep(target):
    import shutil
    binary = shutil.which("whatweb")
    if not binary:
        return {"status": "skipped", "reason": "whatweb not installed", "technologies": []}
    try:
        proc = subprocess.run(
            [binary, "--log-brief=-", "--no-errors", target],
            capture_output=True, text=True, timeout=180
        )
        line = ""
        for raw in proc.stdout.splitlines():
            if raw.strip():
                line = raw.strip()
                break
        tech = []
        if line:
            parts = line.split("[", 1)
            if len(parts) == 2:
                tech = [t.strip(" ]") for t in parts[1].split(",") if t.strip()]
        return {"status": "ok", "technologies": tech, "raw": proc.stdout[:1000]}
    except Exception as e:
        return {"status": "error", "error": str(e), "technologies": []}


def _run_nuclei_for_webdeep(target):
    import shutil, json as _json
    binary = shutil.which("nuclei")
    if not binary:
        return {"status": "skipped", "reason": "nuclei not installed", "findings": []}
    try:
        proc = subprocess.run(
            [binary, "-u", target, "-jsonl", "-severity", "critical,high,medium", "-silent", "-stats=false"],
            capture_output=True, text=True, timeout=300
        )
        findings = []
        for line in (proc.stdout or "").splitlines()[:150]:
            try:
                item = _json.loads(line)
                info = item.get("info", {})
                findings.append({
                    "template": item.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": str(info.get("severity", "unknown")).lower(),
                    "matched_at": item.get("matched-at", "")
                })
            except Exception:
                continue
        return {"status": "ok", "findings": findings}
    except Exception as e:
        return {"status": "error", "error": str(e), "findings": []}


def _run_sqlmap_for_webdeep(target):
    import shutil
    binary = shutil.which("sqlmap")
    if not binary:
        return {"status": "skipped", "reason": "sqlmap not installed", "findings": []}
    try:
        proc = subprocess.run(
            [binary, "-u", target, "--batch", "--crawl=1", "--level=1", "--risk=1", "--threads=2", "--timeout=8"],
            capture_output=True, text=True, timeout=420
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        hits = []
        for line in output.splitlines():
            ll = line.lower()
            if "is vulnerable" in ll or "sql injection vulnerability" in ll:
                hits.append(line.strip())
        return {"status": "ok", "findings": hits[:25], "raw_tail": output[-1200:]}
    except Exception as e:
        return {"status": "error", "error": str(e), "findings": []}


def _rate_web_findings(scan_data, nikto_data, dir_data, header_data, nuclei_data=None, sqlmap_data=None):
    critical = int((scan_data.get("summary") or {}).get("critical_cves", 0))
    high = int((scan_data.get("summary") or {}).get("high_cves", 0))
    nikto_high = sum(1 for f in nikto_data.get("findings", []) if f.get("severity") == "high")
    dir_hits = len((dir_data or {}).get("found", []))
    hdr_issues = len([i for i in (header_data or {}).get("issues", []) if i.get("severity") in {"HIGH", "MEDIUM"}])
    nuclei_high = len([f for f in (nuclei_data or {}).get("findings", []) if f.get("severity") in {"critical", "high"}])
    sqlmap_hits = len((sqlmap_data or {}).get("findings", []))
    score = min(100, critical * 22 + high * 10 + nikto_high * 4 + min(25, dir_hits // 3) + hdr_issues * 3 + nuclei_high * 8 + sqlmap_hits * 10)
    rating = "LOW" if score <= 15 else "MEDIUM" if score <= 35 else "HIGH" if score <= 60 else "CRITICAL"
    return score, rating, {
        "critical_cves": critical,
        "high_cves": high,
        "nikto_high": nikto_high,
        "sensitive_paths": dir_hits,
        "header_issues": hdr_issues,
        "nuclei_high": nuclei_high,
        "sqlmap_hits": sqlmap_hits,
        "total_findings": critical + high + nikto_high + dir_hits + hdr_issues + nuclei_high + sqlmap_hits
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML


@app.route("/verify/<token>")
def verify_page(token):
    from auth import verify_user
    verify_user(token)
    return HTML


@app.route("/web-deep", methods=["POST"])
def web_deep():
    data = request.get_json() or {}
    input_url = (data.get("url") or "").strip()
    profile = (data.get("profile") or "deep").strip().lower()
    if profile not in {"balanced", "deep", "very_deep"}:
        profile = "deep"
    raw_url, base_url, host = _normalize_target_url(input_url)
    if not host:
        return jsonify({"error": "Invalid website URL"}), 400

    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "WEB_DEEP_AUDIT", target=base_url, ip=request.remote_addr, details=f"profile={profile}")

    network = run_backend("--modules", "ports,ssl,dns,headers", "--nmap-profile", profile, host, timeout=min(TIMEOUT_WEB_DEEP, TIMEOUT_SCAN))
    dir_enum = run_backend("--dirbust", base_url, "medium", "php,html,js,txt,bak,zip,env,log", timeout=min(TIMEOUT_WEB_DEEP, TIMEOUT_DIRBUST))
    nikto = _run_nikto_for_webdeep(raw_url)
    whatweb = _run_whatweb_for_webdeep(raw_url)
    nuclei = _run_nuclei_for_webdeep(raw_url)
    sqlmap = _run_sqlmap_for_webdeep(raw_url)
    headers = ((network.get("modules") or {}).get("headers") or {})
    score, rating, summary = _rate_web_findings(network, nikto, dir_enum, headers, nuclei_data=nuclei, sqlmap_data=sqlmap)

    response = {
        "target": base_url,
        "vulnerability_score": score,
        "risk_rating": rating,
        "summary": summary,
        "tools_required": required_web_tools(),
        "tools_run": [
            {"tool": "nmap", "status": "ok" if "error" not in ((network.get("modules") or {}).get("ports") or {}) else "error"},
            {"tool": "nikto", "status": nikto.get("status", "error")},
            {"tool": "dirbust", "status": "ok" if "error" not in dir_enum else "error"},
            {"tool": "dns+headers+ssl", "status": "ok" if "error" not in network else "error"},
            {"tool": "whatweb", "status": whatweb.get("status", "error")},
            {"tool": "nuclei", "status": nuclei.get("status", "error")},
            {"tool": "sqlmap", "status": sqlmap.get("status", "error")},
        ],
        "key_findings": [
            f"Critical CVEs: {summary['critical_cves']}",
            f"High CVEs: {summary['high_cves']}",
            f"Nikto high findings: {summary['nikto_high']}",
            f"Interesting paths discovered: {summary['sensitive_paths']}",
            f"Header security issues: {summary['header_issues']}",
            f"Nuclei critical/high findings: {summary['nuclei_high']}",
            f"Potential SQL injection findings: {summary['sqlmap_hits']}",
        ],
        "executive_summary": f"Automated deep web audit completed for {base_url}. Risk rating is {rating} with score {score}/100.",
        "details": {
            "network_scan": network,
            "nikto": nikto,
            "directory_enum": dir_enum,
            "whatweb": whatweb,
            "nuclei": nuclei,
            "sqlmap": sqlmap,
        }
    }
    return jsonify(response)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    target = (request.args.get("target", "") if request.method == "GET"
              else (request.get_json() or {}).get("target", "")).strip()
    modules = request.args.get("modules", "ports,ssl,dns,headers")
    profile = request.args.get("profile", "balanced").strip().lower()
    if profile not in {"fast", "balanced", "deep", "very_deep"}:
        profile = "balanced"
    if not target:
        return jsonify({"error": "No target specified"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-_:/\[\]]+$', target):
        return jsonify({"error": "Invalid target — only alphanumeric, dots, dashes, colons allowed"}), 400

    user = get_current_user()
    uid = user["id"] if user else None
    uname = user["username"] if user else "anonymous"

    try:
        data = run_backend("--modules", modules, "--nmap-profile", profile, target, timeout=TIMEOUT_SCAN)
        if "error" not in data:
            data["scan_id"] = save_scan(target, data, user_id=uid, modules=modules)
            audit(uid, uname, "SCAN", target=target, ip=request.remote_addr,
                  details=f"modules={modules};profile={profile}")
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/subdomains")
def subdomains():
    domain = request.args.get("domain", "").strip()
    size = request.args.get("size", "medium")
    if not domain:
        return jsonify({"error": "No domain"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        return jsonify({"error": "Invalid domain"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SUBDOMAIN_ENUM", target=domain, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--subdomains", domain, size, timeout=TIMEOUT_SUBDOMAIN))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dirbust")
def dirbust():
    url = request.args.get("url", "").strip()
    size = request.args.get("size", "small")
    ext = request.args.get("ext", "php,html,txt")
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DIR_ENUM", target=url, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--dirbust", url, size, ext, timeout=TIMEOUT_DIRBUST))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/brute-http", methods=["POST"])
def brute_http():
    d = request.get_json() or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_HTTP", target=url, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:10])
    pwds = ",".join(d.get("passwords", [])[:50])
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        return jsonify(run_backend("--brute-http", url, users, pwds, uf, pf,
                                   timeout=TIMEOUT_BRUTE))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/brute-ssh", methods=["POST"])
def brute_ssh():
    d = request.get_json() or {}
    host = d.get("host", "").strip()
    port = str(d.get("port", "22"))
    if not host:
        return jsonify({"error": "No host"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_SSH", target=host, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:5])
    pwds = ",".join(d.get("passwords", [])[:20])
    try:
        return jsonify(run_backend("--brute-ssh", host, port, users, pwds,
                                   timeout=TIMEOUT_BRUTE))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _social_tool_binary(tool_name: str, script_path: str = ""):
    tool_name = (tool_name or "").strip().lower()
    if tool_name == "setoolkit":
        return shutil.which("setoolkit"), []
    if tool_name == "gophish":
        return shutil.which("gophish"), []
    if tool_name == "evilginx2":
        return shutil.which("evilginx2") or shutil.which("evilginx"), []
    if tool_name == "shellphish":
        candidate = (script_path or "").strip()
        if candidate and os.path.isfile(candidate):
            return "/bin/bash", [candidate]
        for p in [
            "/opt/shellphish/shellphish.sh",
            "/usr/local/bin/shellphish.sh",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "shellphish.sh"),
        ]:
            if os.path.isfile(p):
                return "/bin/bash", [p]
        return None, []
    if tool_name == "netcat":
        return shutil.which("netcat") or shutil.which("nc"), []
    if tool_name == "ncat":
        return shutil.which("ncat"), []
    if tool_name == "socat":
        return shutil.which("socat"), []
    if tool_name == "sliver":
        return shutil.which("sliver-client") or shutil.which("sliver"), []
    if tool_name == "empire":
        return shutil.which("empire"), []
    return None, []


def _safe_cli_args(args_text: str):
    args_text = (args_text or "").strip()
    if not args_text:
        return []
    if len(args_text) > 400:
        raise ValueError("Arguments too long (max 400 chars).")
    if re.search(r"[;&|`$><]", args_text):
        raise ValueError("Arguments contain disallowed shell characters.")
    parsed = shlex.split(args_text)
    if len(parsed) > 30:
        raise ValueError("Too many arguments (max 30).")
    for tok in parsed:
        if len(tok) > 120:
            raise ValueError("Argument token too long.")
        if not re.match(r"^[a-zA-Z0-9._:/,@%+=\-]+$", tok):
            raise ValueError(f"Unsafe argument token: {tok}")
    return parsed


# ── SET Interactive Terminal (PTY-based) ──────────────────────────────────────
import threading as _threading
import queue as _queue
import uuid as _uuid
import fcntl as _fcntl
import pty as _pty
import select as _select
import termios as _termios
import struct as _struct

# Session store: session_id → {"proc", "master_fd", "output_q", "alive", "created"}
_SET_SESSIONS = {}
_SET_SESSIONS_LOCK = _threading.Lock()
_SET_SESSION_TTL = 1800  # 30 minutes

def _reap_old_set_sessions():
    """Kill sessions older than TTL."""
    now = datetime.now(timezone.utc).timestamp()
    with _SET_SESSIONS_LOCK:
        dead = [sid for sid, s in _SET_SESSIONS.items()
                if now - s.get("created", now) > _SET_SESSION_TTL]
        for sid in dead:
            _kill_set_session(sid, locked=True)

def _kill_set_session(sid, locked=False):
    """Terminate a SET session. Call with locked=True if already holding the lock."""
    def _do_kill():
        s = _SET_SESSIONS.pop(sid, None)
        if not s:
            return
        s["alive"] = False
        try:
            s["proc"].terminate()
        except Exception:
            pass
        try:
            os.close(s["master_fd"])
        except Exception:
            pass
    if locked:
        _do_kill()
    else:
        with _SET_SESSIONS_LOCK:
            _do_kill()

def _set_session_reader(sid, master_fd, output_q):
    """Background thread: read PTY output → push to queue."""
    buf = b""
    while True:
        with _SET_SESSIONS_LOCK:
            alive = _SET_SESSIONS.get(sid, {}).get("alive", False)
        if not alive:
            break
        try:
            r, _, _ = _select.select([master_fd], [], [], 0.3)
            if r:
                chunk = os.read(master_fd, 4096)
                if not chunk:
                    break
                buf += chunk
                # Push whole UTF-8 decoded chunk; replace bad bytes
                output_q.put(chunk.decode("utf-8", errors="replace"))
                buf = b""
        except OSError:
            break
        except Exception:
            break
    output_q.put(None)  # sentinel: stream ended


@app.route("/api/set/session/new", methods=["POST"])
def set_session_new():
    """
    Start a new SET PTY session.
    Returns: { session_id, ok }
    """
    import shutil as _sh
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    binary = _sh.which("setoolkit") or _sh.which("set") or _sh.which("se-toolkit")
    if not binary:
        return jsonify({"error": (
            "setoolkit not found on PATH. "
            "Install: sudo apt install set  OR  "
            "clone from https://github.com/trustedsec/social-engineer-toolkit"
        )}), 404

    launch_cmd = [binary]
    launch_display = binary
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo_bin = _sh.which("sudo")
        if not sudo_bin:
            return jsonify({"error": "SET must run as root. 'sudo' is not installed on this server."}), 500
        # Force target user to root so SET always runs with effective UID 0.
        # Mirrors host-side validation pattern: sudo -u www-data sudo setoolkit
        launch_cmd = [sudo_bin, "-u", "root", binary]
        launch_display = f"{sudo_bin} -u root {binary}"
        sudo_check = subprocess.run([sudo_bin, "-n", "-v"], capture_output=True, text=True)
        if sudo_check.returncode != 0:
            return jsonify({
                "error": (
                    "SET must run as root. Passwordless sudo is required for the web service user. "
                    "Configure sudoers to allow launching setoolkit without a TTY/password."
                )
            }), 403
        launch_cmd = [sudo_bin, "-n", binary]
        launch_display = f"{sudo_bin} -n {binary}"

    _reap_old_set_sessions()

    sid = str(_uuid.uuid4())
    try:
        master_fd, slave_fd = _pty.openpty()

        # Set window size so SET menus render correctly (80×24)
        winsize = _struct.pack("HHHH", 40, 220, 0, 0)
        _fcntl.ioctl(slave_fd, _termios.TIOCSWINSZ, winsize)

        def _set_pty_preexec():
            # Ensure child has a controlling TTY so sudo/SET interactive flows work.
            os.setsid()
            try:
                _fcntl.ioctl(slave_fd, _termios.TIOCSCTTY, 0)
            except Exception:
                pass

        proc = subprocess.Popen(
            launch_cmd,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
            preexec_fn=_set_pty_preexec,
            env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "220", "LINES": "40"},
        )
        os.close(slave_fd)

        output_q = _queue.Queue(maxsize=2000)
        alive_flag = {"alive": True}

        session = {
            "proc":       proc,
            "master_fd":  master_fd,
            "output_q":   output_q,
            "alive":      True,
            "created":    datetime.now(timezone.utc).timestamp(),
            "binary":     launch_display,
            "user":       u["username"],
        }
        with _SET_SESSIONS_LOCK:
            _SET_SESSIONS[sid] = session

        t = _threading.Thread(
            target=_set_session_reader,
            args=(sid, master_fd, output_q),
            daemon=True,
        )
        t.start()

        audit(u["id"], u["username"], "SET_SESSION_START",
              ip=request.remote_addr, details=f"binary={launch_display}")

        return jsonify({"session_id": sid, "ok": True, "binary": launch_display})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/set/session/<sid>/stream")
def set_session_stream(sid):
    """
    SSE endpoint — streams PTY output for a given session.
    The client connects here and receives text/event-stream chunks.
    """
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    with _SET_SESSIONS_LOCK:
        session = _SET_SESSIONS.get(sid)

    if not session:
        def _gone():
            yield "data: " + json.dumps({"type": "error", "text": "Session not found or expired."}) + "\n\n"
        return Response(_gone(), mimetype="text/event-stream")

    def _gen():
        q = session["output_q"]
        while True:
            try:
                chunk = q.get(timeout=25)
            except _queue.Empty:
                # Heartbeat so the connection stays alive
                yield "data: " + json.dumps({"type": "heartbeat"}) + "\n\n"
                continue

            if chunk is None:
                # Reader thread ended — process exited
                yield "data: " + json.dumps({"type": "exit", "text": "\r\n[SET session ended]\r\n"}) + "\n\n"
                _kill_set_session(sid)
                break

            yield "data: " + json.dumps({"type": "output", "text": chunk}) + "\n\n"

    return Response(
        _gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/set/session/<sid>/input", methods=["POST"])
def set_session_input(sid):
    """
    Send keystrokes / a line to the SET PTY.
    Body: { "text": "1\n" }   — text to write verbatim to the PTY
    OR:   { "key": "ctrl_c" }  — named special key
    """
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    with _SET_SESSIONS_LOCK:
        session = _SET_SESSIONS.get(sid)

    if not session or not session["alive"]:
        return jsonify({"error": "Session not found or already closed"}), 404

    data = request.get_json() or {}
    text = data.get("text", "")
    key  = data.get("key", "")

    SPECIAL = {
        "ctrl_c": b"\x03",
        "ctrl_d": b"\x04",
        "ctrl_z": b"\x1a",
        "enter":  b"\n",
        "up":     b"\x1b[A",
        "down":   b"\x1b[B",
        "q":      b"q\n",
        "99":     b"99\n",
        "back":   b"99\n",
    }

    try:
        if key and key in SPECIAL:
            raw = SPECIAL[key]
        elif text is not None:
            raw = (str(text)).encode("utf-8", errors="replace")
        else:
            return jsonify({"error": "Provide text or key"}), 400

        os.write(session["master_fd"], raw)
        return jsonify({"ok": True})

    except OSError as e:
        _kill_set_session(sid)
        return jsonify({"error": f"Write failed — session may have ended: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/set/session/<sid>/kill", methods=["POST"])
def set_session_kill(sid):
    """Terminate a SET session cleanly."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    _kill_set_session(sid)
    audit(u["id"], u["username"], "SET_SESSION_KILL",
          ip=request.remote_addr, details=f"sid={sid}")
    return jsonify({"ok": True})


@app.route("/api/set/sessions", methods=["GET"])
def set_sessions_list():
    """List active SET sessions (admin only)."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    _reap_old_set_sessions()
    with _SET_SESSIONS_LOCK:
        sessions = [
            {"sid": sid, "user": s["user"], "alive": s["alive"],
             "binary": s["binary"],
             "created": datetime.fromtimestamp(s["created"], tz=timezone.utc).isoformat()}
            for sid, s in _SET_SESSIONS.items()
        ]
    return jsonify({"sessions": sessions})


@app.route("/social-tools/run", methods=["POST"])
def social_tool_run():
    data = request.get_json() or {}
    tool = (data.get("tool") or "").strip().lower()
    operation = (data.get("operation") or "help").strip().lower()
    args_text = (data.get("args") or "").strip()
    script_path = (data.get("script_path") or "").strip()
    timeout = int(data.get("timeout") or 90)
    timeout = max(10, min(600, timeout))

    if tool not in {"setoolkit", "gophish", "evilginx2", "shellphish", "netcat", "ncat", "socat", "sliver", "empire"}:
        return jsonify({"error": "Unsupported tool."}), 400
    if operation not in {"help", "version", "custom"}:
        operation = "help"

    binary, prefix_args = _social_tool_binary(tool, script_path=script_path)
    if not binary:
        return jsonify({"error": f"{tool} is not installed or script path is invalid on server."}), 400

    try:
        custom_args = _safe_cli_args(args_text) if operation == "custom" else []
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    if operation == "help":
        op_args = ["--help"]
    elif operation == "version":
        op_args = ["--version"]
    else:
        op_args = custom_args or ["--help"]

    cmd = [binary] + prefix_args + op_args

    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "SOCIAL_TOOL_RUN", target=tool, ip=request.remote_addr,
          details=f"operation={operation};cmd={' '.join(cmd[:5])}")

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)
        return jsonify({
            "tool": tool,
            "operation": operation,
            "command": " ".join(cmd),
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[-50000:],
            "stderr": (proc.stderr or "")[-50000:],
            "duration_ms": elapsed,
        })
    except subprocess.TimeoutExpired as te:
        elapsed = int((time.monotonic() - start) * 1000)
        return jsonify({
            "tool": tool,
            "operation": operation,
            "command": " ".join(cmd),
            "exit_code": None,
            "stdout": ((te.stdout or "") if te.stdout else "")[-20000:],
            "stderr": ((te.stderr or "") if te.stderr else "")[-20000:],
            "duration_ms": elapsed,
            "error": f"Command timed out after {timeout}s."
        }), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/discover")
def discover():
    subnet = request.args.get("subnet", "").strip()
    if not subnet:
        return jsonify({"error": "No subnet"}), 400
    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({"error": "Invalid subnet"}), 400
    try:
        return jsonify(run_backend("--discover", subnet, timeout=TIMEOUT_DISCOVER))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    return jsonify(get_history(int(request.args.get("limit", 20)), user_id=uid))


@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    d = get_scan_by_id(sid, user_id=None if role == "admin" else uid)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)


# ── DNSRecon route (v5 — multi-layer fallback, no broken --tcp) ──────────────
@app.route("/dnsrecon", methods=["POST"])
def dnsrecon_route():
    """
    DNS enumeration with three-layer fallback:
      1. dnsrecon binary  (no --tcp — dnsrecon doesn't support that flag)
      2. dig              (standard DNS tool)
      3. Python socket    (always available)
    DNS uses UDP — not proxied through Tor SOCKS.
    """
    import shutil as _sh, tempfile, socket as _sock

    data = request.get_json() or {}
    target    = (data.get("target") or "").strip()
    scan_type = data.get("type", "std")
    ns        = (data.get("ns") or "").strip()
    rec_filter= (data.get("filter") or "").strip().upper()

    if not target:
        return jsonify({"error": "No target specified"})

    user = get_current_user()
    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "DNSRECON", target=target, ip=request.remote_addr)

    records, method_used = [], "none"

    # ── Layer 1: dnsrecon ─────────────────────────────────────────────────
    binary = _sh.which("dnsrecon")
    if binary:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_file = tf.name
        # Run dnsrecon directly — no proxychains, no --tcp (neither is supported for DNS)
        cmd = [binary, "-d", target, "-t", scan_type, "-j", out_file]
        if ns:
            cmd += ["-n", ns]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_DNSRECON)
            # Parse JSON output
            if os.path.exists(out_file) and os.path.getsize(out_file) > 5:
                try:
                    with open(out_file) as f:
                        raw = json.load(f)
                    items = raw if isinstance(raw, list) else raw.get("records", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        rtype = str(item.get("type", "?")).upper()
                        if rec_filter and rtype != rec_filter:
                            continue
                        records.append({
                            "type":    rtype,
                            "name":    item.get("name", item.get("host", "")),
                            "address": item.get("address", item.get("data",
                                       item.get("target", item.get("strings", "")))),
                            "ttl":     str(item.get("ttl", "")),
                        })
                    if records:
                        method_used = "dnsrecon-json"
                except Exception:
                    pass
            # Fallback: parse stdout text output
            if not records and proc.stdout:
                for line in proc.stdout.splitlines():
                    m = re.search(r'\[\*\]\s+(\w+)\s+([\w.\-*@]+)\s+([\S]+)', line)
                    if m:
                        rtype = m.group(1).upper()
                        if rec_filter and rtype != rec_filter:
                            continue
                        records.append({"type": rtype, "name": m.group(2),
                                        "address": m.group(3), "ttl": ""})
                if records:
                    method_used = "dnsrecon-stdout"
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    # ── Layer 2: dig ──────────────────────────────────────────────────────
    if not records and _sh.which("dig"):
        rtypes = [rec_filter] if rec_filter else ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
        resolver = f"@{ns}" if ns else "@8.8.8.8"
        for rtype in rtypes:
            try:
                cmd2 = ["dig", "+noall", "+answer", "+time=5", "+tries=2",
                        resolver, rtype, target]
                proc2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
                for line in proc2.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and not line.startswith(";"):
                        records.append({
                            "type":    parts[3].upper(),
                            "name":    parts[0].rstrip("."),
                            "address": " ".join(parts[4:]).rstrip("."),
                            "ttl":     parts[1],
                        })
            except Exception:
                pass
        if records:
            method_used = "dig"

    # ── Layer 3: Python socket ────────────────────────────────────────────
    if not records:
        try:
            ip = _sock.gethostbyname(target)
            if not rec_filter or rec_filter == "A":
                records.append({"type":"A","name":target,"address":ip,"ttl":""})
            method_used = "python-socket"
        except Exception:
            pass
        # nslookup for MX
        if not rec_filter or rec_filter in ("MX","NS"):
            try:
                proc3 = subprocess.run(["nslookup","-type=MX",target],
                                        capture_output=True, text=True, timeout=10)
                for ln in proc3.stdout.splitlines():
                    if "mail exchanger" in ln.lower():
                        records.append({"type":"MX","name":target,
                                        "address":ln.split("=")[-1].strip(),"ttl":""})
            except Exception:
                pass

    return jsonify({
        "target":     target,
        "records":    records,
        "scan_type":  scan_type,
        "total":      len(records),
        "method":     method_used,
        "note": (
            "dnsrecon ran directly (DNS is UDP — cannot proxy through Tor)."
            if "dnsrecon" in method_used else
            f"Fallback method used: {method_used}. "
            "Install dnsrecon for full results: sudo apt install dnsrecon"
        )
    })


# ── Nikto route (FIXED — proper proxychains integration) ─────────────────────
@app.route("/nikto", methods=["POST"])
def nikto_route():
    """
    Run Nikto web scanner through proxychains/Tor.
    Nikto supports proxy via -useproxy flag or proxychains wrapper.
    Tor makes Nikto significantly slower — expect 5–15 minutes.
    """
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    port = int(data.get("port") or 80)
    ssl_flag = data.get("ssl", "")
    tuning = data.get("tuning", "")

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("nikto")
    if not binary:
        ok, msg = auto_install("nikto", "nikto")
        if not ok:
            return jsonify({
                "error": f"Nikto not installed and auto-install failed: {msg}. Run: sudo apt install nikto",
                "auto_install_attempted": True
            })
        binary = shutil.which("nikto")

    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name

    # Route Nikto through proxychains
    # Also pass -useproxy pointing to Tor SOCKS5 as a secondary proxy option
    cmd = [
        px, "-q",
        binary,
        "-h", target,
        "-p", str(port),
        "-Format", "json",
        "-o", out_file,
        "-nointeractive",
        "-timeout", "30",      # 30s per request (Tor latency)
        "-maxtime", "1800",    # Max 30 min total
    ]
    if ssl_flag == "-ssl":
        cmd += ["-ssl"]
    elif ssl_flag == "-nossl":
        cmd += ["-nossl"]
    if tuning:
        cmd += ["-Tuning", tuning]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_NIKTO)
        findings, server = [], ""

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                for host in (raw.get("host", []) if isinstance(raw, dict) else []):
                    server = host.get("banner", "")
                    for item in host.get("vulnerabilities", []):
                        findings.append({
                            "id": item.get("id", ""),
                            "description": item.get("msg", ""),
                            "url": item.get("uri", ""),
                            "method": item.get("method", ""),
                            "severity": "high" if item.get("OSVDB", "0") != "0" else "info"
                        })
            except Exception:
                pass

        # Fallback: parse stdout
        if not findings:
            for line in proc.stdout.splitlines():
                m = re.search(r'\+ (OSVDB-\d+|[\w-]+): (.+)', line)
                if m:
                    findings.append({
                        "id": m.group(1),
                        "description": m.group(2),
                        "severity": "high" if "OSVDB" in m.group(1) else "info"
                    })

        if os.path.exists(out_file):
            os.unlink(out_file)

        return jsonify({
            "target": target,
            "port": port,
            "server": server,
            "findings": findings,
            "note": "Scanned via Tor — results may be slower but IP is anonymized."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Nikto timed out after {TIMEOUT_NIKTO}s. Tor routing is slow — try a smaller tuning set."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── WPScan route ──────────────────────────────────────────────────────────────
@app.route("/wpscan", methods=["POST"])
def wpscan_route():
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    enum_flags = data.get("enum_flags", "p,u")
    token = (data.get("token") or "").strip()
    mode = data.get("mode", "mixed")

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("wpscan")
    if not binary:
        return jsonify({
            "error": "WPScan not installed. Run: sudo gem install wpscan  OR  docker pull wpscanteam/wpscan"
        })

    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    # WPScan supports --proxy natively — use Tor SOCKS5
    cmd = [
        binary,
        "--url", target,
        "--enumerate", enum_flags,
        "--detection-mode", mode,
        "--format", "json",
        "--output", out_file,
        "--no-banner",
        "--proxy", f"socks5://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",  # Native Tor proxy
        "--request-timeout", "30",     # 30s per request
        "--connect-timeout", "30",
    ]
    if token:
        cmd += ["--api-token", token]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_WPSCAN)

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                wp_version = raw.get("version", {}).get("number", "unknown")
                users = list(raw.get("users", {}).keys())
                plugins = []
                for name, pdata in raw.get("plugins", {}).items():
                    plugins.append({
                        "name": name,
                        "version": pdata.get("version", {}).get("number", "?"),
                        "vulnerabilities": pdata.get("vulnerabilities", [])
                    })
                vulns = []
                for name, pdata in raw.get("plugins", {}).items():
                    for v in pdata.get("vulnerabilities", []):
                        vulns.append({
                            "title": v.get("title", ""),
                            "type": v.get("type", ""),
                            "references": v.get("references", {})
                        })
                os.unlink(out_file)
                return jsonify({
                    "target": target,
                    "wp_version": wp_version,
                    "users": users,
                    "plugins": plugins,
                    "vulnerabilities": vulns,
                    "note": "Scanned via Tor SOCKS5 proxy."
                })
            except Exception as e:
                return jsonify({"error": f"Parse error: {e}"})

        return jsonify({"error": "WPScan produced no output. Is the target a WordPress site?"})

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"WPScan timed out after {TIMEOUT_WPSCAN}s. Through Tor this is normal — try passive mode."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── Lynis route ───────────────────────────────────────────────────────────────
@app.route("/lynis", methods=["POST"])
def lynis_route():
    """
    Lynis audits the LOCAL system — no Tor needed (local scan).
    """
    import shutil

    data = request.get_json() or {}
    profile = (data.get("profile") or "system").strip().lower()
    category = (data.get("category") or "").strip()
    compliance = (data.get("compliance") or "").strip()

    binary = shutil.which("lynis")
    if not binary:
        ok, msg = auto_install("lynis", "lynis")
        if not ok:
            return jsonify({
                "error": f"Lynis not installed and auto-install failed: {msg}. Run: sudo apt install lynis",
                "auto_install_attempted": True
            })
        binary = shutil.which("lynis")
        if not binary:
            return jsonify({"error": "Auto-install ran but lynis still not found."})

    # Lynis is local — no proxychains needed
    report_file = "/tmp/vulnscan-lynis-report.dat"
    log_file = "/tmp/vulnscan-lynis.log"
    cmd = [
        binary, "audit", "system", "--no-colors",
        "--report-file", report_file, "--logfile", log_file
    ]
    if compliance:
        cmd += ["--compliance", compliance.lower()]
    if category:
        cmd += ["--tests-category", category.lower()]
    if profile == "quick":
        cmd += ["--quick"]
    elif profile == "forensics":
        cmd += ["--forensics"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_LYNIS)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        hardening_index = 0
        warnings, suggestions = [], []
        tests_performed = "?"

        report_content = ""
        if os.path.exists(report_file):
            with open(report_file, "r", encoding="utf-8", errors="ignore") as rf:
                report_content = rf.read()
            for line in report_content.splitlines():
                line = line.strip()
                if line.startswith("hardening_index="):
                    try:
                        hardening_index = int(line.split("=", 1)[1].strip())
                    except Exception:
                        pass
                elif line.startswith("tests_performed="):
                    tests_performed = line.split("=", 1)[1].strip() or tests_performed
                elif line.startswith("warning[]="):
                    warnings.append(line.split("=", 1)[1].strip())
                elif line.startswith("suggestion[]="):
                    suggestions.append(line.split("=", 1)[1].strip())

        for line in output.splitlines():
            m = re.search(r'Hardening index\s*[:\|]\s*(\d+)', line, re.IGNORECASE)
            if m:
                hardening_index = int(m.group(1))
            if "Warning" in line or "warning" in line:
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if len(clean) > 10 and "==" not in clean:
                    warnings.append(clean)
            elif "Suggestion" in line or "suggestion" in line:
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if len(clean) > 10 and "==" not in clean:
                    suggestions.append(clean)

        tests_m = re.search(r'Tests performed\s*[:\|]\s*(\d+)', output, re.IGNORECASE)
        if tests_m:
            tests_performed = tests_m.group(1)
        if hardening_index == 0:
            h_m = re.search(r'hardening_index\s*=\s*(\d+)', report_content, re.IGNORECASE)
            if h_m:
                hardening_index = int(h_m.group(1))
        if tests_performed in {"", "?"} and report_content:
            t_m = re.search(r'tests_performed\s*=\s*(\d+)', report_content, re.IGNORECASE)
            if t_m:
                tests_performed = t_m.group(1)
        raw_report = output
        if report_content:
            raw_report += "\n\n# /tmp/vulnscan-lynis-report.dat\n" + report_content
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="ignore") as lf:
                log_content = lf.read()
                raw_report += "\n\n# /tmp/vulnscan-lynis.log\n" + log_content
                if not warnings:
                    for ln in log_content.splitlines():
                        if "warning[" in ln.lower() or "warning:" in ln.lower():
                            warnings.append(ln.strip())
                if not suggestions:
                    for ln in log_content.splitlines():
                        if "suggestion[" in ln.lower() or "suggestion:" in ln.lower():
                            suggestions.append(ln.strip())

        return jsonify({
            "hardening_index": hardening_index,
            "warnings": sorted(set(filter(None, warnings)))[:120],
            "suggestions": sorted(set(filter(None, suggestions)))[:200],
            "tests_performed": tests_performed,
            "raw_report": raw_report[-200000:],
            "profile_used": profile,
            "category_used": category,
            "compliance_used": compliance,
            "command_used": " ".join(cmd),
            "note": "Lynis is a local scan — Tor not used (local system audit)."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Lynis timed out after 6 minutes."})
    except Exception as e:
        return jsonify({"error": str(e)})


# ── Lynis remote-agent orchestration ─────────────────────────────────────────
@app.route("/api/agent/register", methods=["POST"])
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
    return jsonify({"client_id": client_id, "token": token, "api_base": request.url_root.rstrip("/")})


@app.route("/api/create-job", methods=["POST"])
def create_lynis_job():
    data = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    profile = (data.get("profile") or "system").strip() or "system"
    compliance = (data.get("compliance") or "").strip()
    category = (data.get("category") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
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
            WHERE client_id=? AND status IN ('pending', 'running')
        """, (client_id,)).fetchone()["c"]
        if queue_count >= LYNIS_QUEUE_LIMIT:
            con.close()
            return jsonify({
                "error": f"Lynis queue is full for this client ({LYNIS_QUEUE_LIMIT} active jobs max). Wait for completion or remove old jobs."
            }), 429
        cur = con.execute("""
            INSERT INTO lynis_jobs(client_id, profile, compliance, category, status, progress_pct, message)
            VALUES(?,?,?,?, 'pending', 0, 'Queued')
        """, (client_id, profile, compliance, category))
        jid = cur.lastrowid
        con.commit()
        con.close()
    return jsonify({"job_id": jid, "status": "pending"})


@app.route("/api/jobs", methods=["GET"])
def poll_jobs():
    client_id = _auth_agent(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("""
            SELECT id, profile, compliance, category FROM lynis_jobs
            WHERE client_id=? AND status='pending' AND cancel_requested=0
            ORDER BY id ASC LIMIT 1
        """, (client_id,)).fetchone()
        if row:
            con.execute("""
                UPDATE lynis_jobs
                SET status='running', started_at=datetime('now'), progress_pct=5, message='Agent started scan'
                WHERE id=? AND status='pending'
            """, (row["id"],))
            con.commit()
            job = {"job_id": row["id"], "type": "lynis", "profile": row["profile"],
                   "compliance": row["compliance"], "category": row["category"]}
        else:
            job = {"job_id": None, "type": "none"}
        con.close()
    return jsonify(job)


@app.route("/api/jobs/<int:job_id>/control", methods=["GET"])
def job_control(job_id):
    client_id = _auth_agent(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
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
    })


@app.route("/api/jobs/<int:job_id>/progress", methods=["POST"])
def update_job_progress(job_id):
    client_id = _auth_agent(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pct = int(data.get("progress_pct", 0))
    message = (data.get("message") or "").strip()[:300]
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            UPDATE lynis_jobs
            SET progress_pct=?, message=?
            WHERE id=? AND client_id=? AND status='running'
        """, (max(0, min(100, pct)), message, job_id, client_id))
        con.commit()
        con.close()
    return jsonify({"ok": True})


@app.route("/api/upload", methods=["POST"])
def upload_job_report():
    client_id = _auth_agent(request)
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    job_id = data.get("job_id")
    if not job_id:
        return jsonify({"error": "job_id is required"}), 400
    hardening_index = int(data.get("hardening_index", 0))
    warnings = data.get("warnings") or []
    suggestions = data.get("suggestions") or []
    tests_performed = str(data.get("tests_performed", ""))
    raw_report = str(data.get("raw_report", ""))[:200000]
    status = (data.get("status") or "completed").strip().lower()
    if status not in {"completed", "cancelled", "failed"}:
        status = "completed"
    message = (data.get("message") or ("Completed" if status == "completed" else status.title())).strip()[:300]
    with AGENT_LOCK:
        con = _agent_db()
        con.execute("""
            UPDATE lynis_jobs
            SET status=?,
                completed_at=datetime('now'),
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
        con.close()
    return jsonify({"ok": True})


@app.route("/api/job-status/<int:job_id>", methods=["GET"])
def job_status(job_id):
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("""
            SELECT id, client_id, profile, compliance, category, status, progress_pct, message, hardening_index, warnings_json,
                   suggestions_json, tests_performed, created_at, started_at, completed_at, cancel_requested
            FROM lynis_jobs WHERE id=?
        """, (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": row["id"],
        "client_id": row["client_id"],
        "profile_used": row["profile"] or "system",
        "compliance_used": row["compliance"] or "",
        "category_used": row["category"] or "",
        "status": row["status"],
        "progress_pct": row["progress_pct"],
        "message": row["message"],
        "hardening_index": row["hardening_index"],
        "warnings": json.loads(row["warnings_json"] or "[]"),
        "suggestions": json.loads(row["suggestions_json"] or "[]"),
        "tests_performed": row["tests_performed"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "cancel_requested": bool(row["cancel_requested"]),
    })


@app.route("/api/agents", methods=["GET"])
def list_agents():
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
                WHERE status != 'disconnected'
                ORDER BY datetime(last_seen) DESC
            """).fetchall()
        con.close()
    return jsonify({"agents": [dict(r) for r in rows]})


@app.route("/api/agents/<client_id>/disconnect", methods=["POST"])
def disconnect_agent(client_id):
    client_id = (client_id or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT 1 FROM agent_clients WHERE client_id=?", (client_id,)).fetchone()
        if not row:
            con.close()
            return jsonify({"error": "Unknown client_id"}), 404
        con.execute("""
            UPDATE agent_clients
            SET token_hash=?, status='disconnected', last_seen=datetime('now')
            WHERE client_id=?
        """, (_hash_token(secrets.token_urlsafe(32)), client_id))
        con.execute("""
            UPDATE lynis_jobs
            SET status='cancelled', completed_at=datetime('now'), progress_pct=100, message='Cancelled (agent disconnected)'
            WHERE client_id=? AND status='pending'
        """, (client_id,))
        con.execute("""
            UPDATE lynis_jobs
            SET cancel_requested=1, message='Cancellation requested (agent disconnect)'
            WHERE client_id=? AND status='running'
        """, (client_id,))
        con.execute("DELETE FROM agent_clients WHERE client_id=?", (client_id,))
        con.commit()
        con.close()
    return jsonify({"ok": True, "client_id": client_id, "status": "disconnected", "removed": True})


@app.route("/api/jobs-overview", methods=["GET"])
def jobs_overview():
    limit = max(1, min(200, int(request.args.get("limit", LYNIS_OVERVIEW_LIMIT_DEFAULT))))
    with AGENT_LOCK:
        con = _agent_db()
        rows = con.execute("""
            SELECT id, client_id, status, progress_pct, message, created_at, started_at, completed_at, cancel_requested
            FROM lynis_jobs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        con.close()
    return jsonify({"jobs": [dict(r) for r in rows]})


@app.route("/api/jobs/<int:job_id>/cancel", methods=["POST"])
def cancel_job(job_id):
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
                SET status='cancelled', completed_at=datetime('now'), progress_pct=100, message='Cancelled by user'
                WHERE id=?
            """, (job_id,))
        else:
            con.execute("""
                UPDATE lynis_jobs
                SET cancel_requested=1, message='Cancellation requested by dashboard user'
                WHERE id=?
            """, (job_id,))
        con.commit()
        con.close()
    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])
def delete_job(job_id):
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
        con.close()
    return jsonify({"ok": True, "job_id": job_id, "deleted": True})


@app.route("/api/job-report/<int:job_id>.txt", methods=["GET"])
def download_job_report(job_id):
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT raw_report FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    report = row["raw_report"] or "No report content."
    buf = io.BytesIO(report.encode("utf-8", errors="ignore"))
    return send_file(buf, as_attachment=True, download_name=f"lynis-job-{job_id}.txt", mimetype="text/plain")


@app.route("/agent/install.sh", methods=["GET"])
def agent_install_script():
    script = f"""#!/usr/bin/env bash
set -euo pipefail
SERVER_URL="${{SERVER_URL:-{AGENT_SERVER_URL}}}"
CLIENT_ID="${{1:-}}"
TOKEN="${{2:-}}"
if [[ -z "$CLIENT_ID" ]]; then
  base_host="$(hostname -s 2>/dev/null || echo linux-client)"
  rand_part="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
  if [[ -z "$rand_part" ]]; then rand_part="$(date +%s)"; fi
  CLIENT_ID="${{base_host}}-${{rand_part}}"
  echo "[*] Generated random client id: $CLIENT_ID"
fi
echo "[*] Checking server connectivity: $SERVER_URL"
curl -fsS "$SERVER_URL/health" >/dev/null
echo "[+] Connected to VulnScan server"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL "$SERVER_URL/agent/lynis_pull_agent.py" -o "$TMP_DIR/lynis_pull_agent.py"
curl -fsSL "$SERVER_URL/agent/install_agent.sh" -o "$TMP_DIR/install_agent.sh"
chmod +x "$TMP_DIR/install_agent.sh" "$TMP_DIR/lynis_pull_agent.py"
bash "$TMP_DIR/install_agent.sh" "$CLIENT_ID" "$TOKEN" "$SERVER_URL"
echo "[+] Agent installed. Refresh Lynis dashboard: new system should appear shortly."
"""
    return Response(script, mimetype="text/x-shellscript")


@app.route("/agent/<path:filename>", methods=["GET"])
def agent_file(filename):
    agent_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent")
    if filename not in {"install_agent.sh", "lynis_pull_agent.py"}:
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(agent_dir, filename, as_attachment=False)


# ── Legion route ──────────────────────────────────────────────────────────────
@app.route("/legion", methods=["POST"])
def legion_route():
    import shutil

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    intensity = data.get("intensity", "normal")
    modules = data.get("modules", ["nmap", "nikto"])

    if not target:
        return jsonify({"error": "No target specified"})

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0

    # Timing map adjusted for Tor
    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T2"}[intensity]

    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({
                "module": mod,
                "summary": f"{mod} not found — install: sudo apt install {mod}",
                "findings": []
            })
            continue

        modules_run += 1
        findings = []

        try:
            if mod == "nmap":
                # nmap through proxychains
                cmd = [
                    px, "-q", "nmap",
                    "-sT", "-Pn", "-n",    # TCP connect, no ping, no DNS
                    speed,
                    "--open",
                    "--host-timeout", "180s",
                    "--max-retries", "1",
                    "--top-ports", "100",
                    "-sV", "--version-intensity", "2",
                    target
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in proc.stdout.splitlines():
                    m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
                    if m:
                        open_ports += 1
                        findings.append({
                            "title": f"Port {m.group(1)} open",
                            "detail": f"{m.group(2)} {m.group(3)}".strip()
                        })

            elif mod == "nikto":
                # Nikto through proxychains
                cmd = [
                    px, "-q", binary,
                    "-h", target,
                    "-nointeractive",
                    "-timeout", "30",
                    "-maxtime", "600",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=700)
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"):
                        findings.append({"title": line.strip()[2:80], "detail": ""})
                        total_issues += 1

            else:
                # Other tools through proxychains
                proc = subprocess.run(
                    [px, "-q", binary, target],
                    capture_output=True, text=True, timeout=180
                )
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})

        except subprocess.TimeoutExpired:
            findings.append({"title": f"{mod} timed out (Tor is slow)", "detail": ""})
        except Exception as e:
            findings.append({"title": f"{mod} error", "detail": str(e)})

        results.append({
            "module": mod,
            "findings": findings,
            "summary": f"{len(findings)} findings"
        })

    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "All modules ran through Tor/proxychains."
    })


# ── theHarvester route ────────────────────────────────────────────────────────
@app.route("/harvester", methods=["POST"])
def harvester():
    import shutil, tempfile

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    sources = (data.get("sources") or "google,bing,dnsdumpster,crtsh").strip()
    limit = int(data.get("limit") or 500)

    if not target:
        return jsonify({"error": "No target specified"})
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        return jsonify({"error": "Invalid domain format"})

    if not shutil.which("theHarvester") and not shutil.which("theharvester"):
        ok, msg = auto_install("theharvester", "theHarvester")
        if not ok:
            return jsonify({
                "error": f"theHarvester not installed: {msg}. Run: sudo apt install theharvester",
                "auto_install_attempted": True
            })

    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    px = proxychains_cmd()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "harvest")

        # Route theHarvester through proxychains
        cmd = [px, "-q", binary, "-d", target, "-l", str(limit), "-b", sources, "-f", out_file]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HARVESTER)
            raw_out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return jsonify({"error": f"theHarvester timed out after {TIMEOUT_HARVESTER}s. Try fewer sources."})
        except Exception as e:
            return jsonify({"error": str(e)})

        emails, hosts, subdomains, ips = [], [], [], []
        json_path = out_file + ".json"

        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    jd = json.load(f)
                emails = list(set(jd.get("emails", [])))
                hosts_raw = jd.get("hosts", [])
                for h in hosts_raw:
                    if isinstance(h, dict):
                        hosts.append(h)
                        if h.get("ip"):
                            ips.append(h["ip"])
                    else:
                        hosts.append({"host": h, "ip": ""})
                subdomains = list(set(
                    h["host"] if isinstance(h, dict) else h for h in hosts_raw
                ))
                ips = list(set(ips + jd.get("ips", [])))
            except Exception:
                pass

        # Fallback: parse stdout
        if not emails and not hosts:
            for line in raw_out.splitlines():
                line = line.strip()
                if "@" in line and "." in line and " " not in line:
                    emails.append(line)
                elif re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', line):
                    subdomains.append(line)
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips.append(line)
            emails = list(set(emails))
            subdomains = list(set(subdomains))
            ips = list(set(ips))

        return jsonify({
            "target": target,
            "sources": sources,
            "emails": emails[:500],
            "hosts": hosts[:500],
            "subdomains": subdomains[:500],
            "ips": ips[:500],
            "raw_lines": len(raw_out.splitlines()),
            "note": "OSINT collected via Tor/proxychains."
        })


# ── Report route ──────────────────────────────────────────────────────────────
# ── Deep Web Audit — SSE streaming endpoint ──────────────────────────────────
@app.route("/web-deep-stream")
def web_deep_stream():
    """
    Server-Sent Events endpoint.
    Streams one JSON event per tool as it completes, with % progress.
    Final event has done=True and the complete result dict.
    """
    import threading, queue, time as _t

    input_url = request.args.get("url", "").strip()
    profile   = request.args.get("profile", "balanced").strip().lower()
    if profile not in {"balanced", "deep", "very_deep"}:
        profile = "balanced"

    raw_url, base_url, host = _normalize_target_url(input_url)
    if not host:
        def _err():
            yield 'data: ' + json.dumps({"pct":0,"done":True,"error":"Invalid URL"}) + '\n\n'
        return Response(_err(), mimetype="text/event-stream")

    user = get_current_user()
    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "WEB_DEEP_STREAM", target=base_url,
          ip=request.remote_addr, details=f"profile={profile}")

    q = queue.Queue()

    # (end_pct, label, key)
    STAGES = [
        (8,  "HTTP Headers",              "headers"),
        (16, "SSL/TLS Analysis",          "ssl"),
        (24, "DNS Records",               "dns"),
        (38, "Port Scan (nmap)",          "ports"),
        (50, "Directory Enumeration",     "dirbust"),
        (63, "Nikto Web Scanner",         "nikto"),
        (73, "WhatWeb Fingerprint",       "whatweb"),
        (84, "Nuclei Templates",          "nuclei"),
        (93, "SQLMap Injection Check",    "sqlmap"),
        (100,"Building Report",           "final"),
    ]

    def _worker():
        store = {}
        try:
            for pct, label, key in STAGES:
                q.put({"pct": pct-1, "stage": label,
                       "log": f"[*] {label}...", "done": False})
                try:
                    if key == "headers":
                        r = run_backend("--modules", "headers", host, timeout=60)
                        store["headers"] = (r.get("modules") or {}).get("headers") or {}
                        n = len(store["headers"].get("issues", []))
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Headers — {n} issue(s)", "done":False})

                    elif key == "ssl":
                        r = run_backend("--modules", "ssl", host, timeout=60)
                        store["ssl"] = (r.get("modules") or {}).get("ssl") or []
                        g = store["ssl"][0].get("grade","?") if store["ssl"] else "N/A"
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] SSL — grade: {g}", "done":False})

                    elif key == "dns":
                        r = run_backend("--modules", "dns", host, timeout=60)
                        store["dns"] = (r.get("modules") or {}).get("dns") or {}
                        s = len(store["dns"].get("subdomains", []))
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] DNS — {s} subdomains found", "done":False})

                    elif key == "ports":
                        r = run_backend("--modules", "ports",
                                        "--nmap-profile", profile, host, timeout=TIMEOUT_SCAN)
                        store["ports"] = r
                        op = sum(len(h.get("ports",[])) for h in (r.get("hosts") or []))
                        cv = len([c for h in (r.get("hosts") or [])
                                  for p in h.get("ports",[]) for c in p.get("cves",[])])
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Ports — {op} open, {cv} CVEs", "done":False})

                    elif key == "dirbust":
                        r = run_backend("--dirbust", base_url, "medium",
                                        "php,html,js,txt,bak,zip,env,log",
                                        timeout=TIMEOUT_DIRBUST)
                        store["dirbust"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Dirs — {r.get('total',0)} path(s) found",
                               "done":False})

                    elif key == "nikto":
                        r = _run_nikto_for_webdeep(raw_url)
                        store["nikto"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Nikto — {len(r.get('findings',[]))} finding(s)",
                               "done":False})

                    elif key == "whatweb":
                        r = _run_whatweb_for_webdeep(raw_url)
                        store["whatweb"] = r
                        tech = ", ".join(r.get("technologies",[])[:4]) or "none"
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] WhatWeb — {tech}", "done":False})

                    elif key == "nuclei":
                        r = _run_nuclei_for_webdeep(raw_url)
                        store["nuclei"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Nuclei — {len(r.get('findings',[]))} finding(s)",
                               "done":False})

                    elif key == "sqlmap":
                        r = _run_sqlmap_for_webdeep(raw_url)
                        store["sqlmap"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] SQLMap — {len(r.get('findings',[]))} indicator(s)",
                               "done":False})

                    elif key == "final":
                        net = store.get("ports", {})
                        if "modules" not in net:
                            net["modules"] = {}
                        net["modules"]["headers"] = store.get("headers", {})
                        net["modules"]["ssl"]     = store.get("ssl", [])
                        net["modules"]["dns"]     = store.get("dns", {})

                        hdr = store.get("headers", {})
                        score, rating, summary = _rate_web_findings(
                            net, store.get("nikto",{}),
                            store.get("dirbust",{}), hdr,
                            nuclei_data=store.get("nuclei",{}),
                            sqlmap_data=store.get("sqlmap",{}))

                        all_cves = [c for h in (net.get("hosts") or [])
                                    for p in h.get("ports",[])
                                    for c in p.get("cves",[])]
                        net_sum = {
                            "open_ports":   sum(len(h.get("ports",[])) for h in (net.get("hosts") or [])),
                            "total_cves":   len(all_cves),
                            "critical_cves":sum(1 for c in all_cves if c.get("severity")=="CRITICAL"),
                            "high_cves":    sum(1 for c in all_cves if c.get("severity")=="HIGH"),
                            "exploitable":  sum(1 for c in all_cves if c.get("has_exploit")),
                        }

                        result = {
                            "target":              base_url,
                            "vulnerability_score": score,
                            "risk_rating":         rating,
                            "summary":             {**summary, **net_sum},
                            "tools_required":      required_web_tools(),
                            "tools_run": [
                                {"tool":k,"status":"ok" if v else "no-output"}
                                for k,v in store.items()
                            ],
                            "key_findings": [
                                f"Open ports: {net_sum['open_ports']}",
                                f"Total CVEs: {net_sum['total_cves']}",
                                f"Critical CVEs: {net_sum['critical_cves']}",
                                f"Nikto findings: {summary['nikto_high']}",
                                f"Sensitive paths: {summary['sensitive_paths']}",
                                f"Header issues: {summary['header_issues']}",
                                f"Nuclei findings: {summary['nuclei_high']}",
                                f"SQLi indicators: {summary['sqlmap_hits']}",
                            ],
                            "executive_summary": (
                                f"Deep web audit complete for {base_url}. "
                                f"Risk: {rating} ({score}/100). "
                                f"{net_sum['open_ports']} open ports, "
                                f"{net_sum['total_cves']} CVEs."
                            ),
                            "details": {
                                "network_scan":    net,
                                "nikto":           store.get("nikto",{}),
                                "directory_enum":  store.get("dirbust",{}),
                                "whatweb":         store.get("whatweb",{}),
                                "nuclei":          store.get("nuclei",{}),
                                "sqlmap":          store.get("sqlmap",{}),
                            }
                        }
                        q.put({"pct":100,"stage":"Done",
                               "log":f"[+] Complete — {rating} ({score}/100)",
                               "done":True, "result":result})
                        return

                except Exception as e:
                    q.put({"pct":pct,"stage":label,
                           "log":f"[!] {label} error: {str(e)[:100]}","done":False})

        except Exception as e:
            q.put({"pct":100,"done":True,"error":str(e),"result":{}})

    threading.Thread(target=_worker, daemon=True).start()

    def _stream():
        while True:
            try:
                msg = q.get(timeout=1800)
                yield "data: " + json.dumps(msg) + "\n\n"
                if msg.get("done"):
                    break
            except Exception:
                yield 'data: ' + json.dumps({"pct":100,"done":True,
                                              "error":"Stream timeout"}) + "\n\n"
                break

    return Response(_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.route("/report", methods=["POST"])
def report():
    """
    PDF report generation — styled to match the VulnScan Pro website theme.
    Dark cyberpunk aesthetic: #04040a background, #00e5ff cyan accents,
    neon severity colours, monospace fonts, and a matrix-green footer strip.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak,
                                        KeepTogether)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        from reportlab.pdfgen.canvas import Canvas
    except ImportError:
        return jsonify({"error": "reportlab not installed: pip3 install reportlab --break-system-packages"}), 500

    data = request.get_json() or {}
    target     = data.get("target", "unknown")
    scan_time  = data.get("scan_time", "")[:19].replace("T", " ")
    summary    = data.get("summary", {})
    modules    = data.get("modules", {})
    hosts      = modules.get("ports", {}).get("hosts", [])
    all_ports  = [p for h in hosts for p in h.get("ports", [])]
    ssl_list   = modules.get("ssl", [])
    dns_data   = modules.get("dns", {})
    hdr_data   = modules.get("headers", {})

    # ── Website-matched colour palette ────────────────────────────────────────
    C_BG       = colors.HexColor("#04040a")   # page background  (body)
    C_DARK     = colors.HexColor("#0d0d18")   # card / row bg    (--bg2)
    C_DARKER   = colors.HexColor("#111111")   # alternate row    (--bg3)
    C_BORDER   = colors.HexColor("#1e1e2e")   # grid lines       (--border)
    C_BORDER2  = colors.HexColor("#2a2a3a")   # stronger border  (--border2)
    C_MUTED    = colors.HexColor("#666688")   # label text       (--text3)
    C_BODY     = colors.HexColor("#aaaacc")   # body text        (--text2)
    C_WHITE    = colors.HexColor("#f0f0f0")   # heading text     (--text)
    C_CYAN     = colors.HexColor("#00e5ff")   # primary accent   (--accent cyan)
    C_GREEN    = colors.HexColor("#00ff9d")   # success / low
    C_YELLOW   = colors.HexColor("#ffd60a")   # medium
    C_ORANGE   = colors.HexColor("#ff6b35")   # high
    C_RED      = colors.HexColor("#ff3366")   # critical
    C_PURPLE   = colors.HexColor("#b06fff")   # brand purple
    C_BLUE     = colors.HexColor("#5a9fe0")   # info
    C_MATRIX   = colors.HexColor("#003c1a")   # matrix green strip

    SEV_MAP = {
        "CRITICAL": C_RED,
        "HIGH":     C_ORANGE,
        "MEDIUM":   C_YELLOW,
        "LOW":      C_GREEN,
        "INFO":     C_BLUE,
        "UNKNOWN":  C_MUTED,
    }

    # ── Helper: ParagraphStyle factory ────────────────────────────────────────
    def sty(name, **kw):
        defaults = dict(fontName="Courier", fontSize=8, textColor=C_BODY,
                        leading=13, spaceAfter=3, spaceBefore=2,
                        leftIndent=0, alignment=TA_LEFT)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    # Style catalogue — mirrors the website's typographic hierarchy
    S_TITLE    = sty("title",  fontName="Helvetica-Bold", fontSize=28,
                     textColor=C_CYAN, leading=34, spaceAfter=4, spaceBefore=0)
    S_SUBTITLE = sty("sub",    fontName="Courier-Bold", fontSize=11,
                     textColor=C_PURPLE, leading=16, spaceAfter=2, letterSpacing=2)
    S_H1       = sty("h1",    fontName="Helvetica-Bold", fontSize=13,
                     textColor=C_CYAN, leading=18, spaceBefore=18, spaceAfter=8)
    S_H2       = sty("h2",    fontName="Helvetica-Bold", fontSize=10,
                     textColor=C_WHITE, leading=15, spaceBefore=12, spaceAfter=5)
    S_LABEL    = sty("lbl",   fontName="Courier-Bold", fontSize=8,
                     textColor=C_MUTED, leading=12, letterSpacing=1.5)
    S_BODY     = sty("body")
    S_MONO     = sty("mono",  fontName="Courier", fontSize=8, textColor=C_BODY)
    S_MONO_SM  = sty("monosm",fontName="Courier", fontSize=7, textColor=C_MUTED)
    S_CENTER   = sty("ctr",   alignment=TA_CENTER, textColor=C_MUTED, fontSize=7)
    S_WARN     = sty("warn",  fontName="Courier-Bold", textColor=C_RED)
    S_DISC     = sty("disc",  fontName="Courier", fontSize=7, textColor=C_MUTED,
                     alignment=TA_CENTER, leading=11)

    def p(t, s=None):    return Paragraph(str(t), s or S_BODY)
    def sp(h=6):         return Spacer(1, h)
    def hr(col=None):
        return HRFlowable(width="100%", thickness=0.4,
                          color=col or C_BORDER, spaceAfter=6, spaceBefore=4)

    # ── Table helper — website card style ─────────────────────────────────────
    def tbl(rows, cols, extra_styles=None, hdr_row=False):
        t = Table(rows, colWidths=cols, repeatRows=1 if hdr_row else 0)
        base = [
            ("FONTNAME",       (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE",       (0, 0), (-1, -1), 7.5),
            ("TEXTCOLOR",      (0, 0), (-1, -1), C_BODY),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_DARKER]),
            ("GRID",           (0, 0), (-1, -1), 0.25, C_BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ]
        if hdr_row:
            base += [
                ("BACKGROUND",  (0, 0), (-1, 0), C_BORDER2),
                ("FONTNAME",    (0, 0), (-1, 0), "Courier-Bold"),
                ("FONTSIZE",    (0, 0), (-1, 0), 7),
                ("TEXTCOLOR",   (0, 0), (-1, 0), C_MUTED),
            ]
        t.setStyle(TableStyle(base + (extra_styles or [])))
        return t

    # ── Severity pill (coloured box in table cells) ───────────────────────────
    def sev_cell(level):
        col = SEV_MAP.get(level, C_MUTED)
        return p(f'<font color="#{col.hexval()[1:].upper()}">[{level}]</font>',
                 sty("sc", fontName="Courier-Bold", fontSize=7, textColor=col))

    W, H = A4
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=12*mm,  bottomMargin=16*mm,
    )

    # ── Page canvas: background, neon top bar, footer strip ───────────────────
    def draw_page(canvas, doc):
        canvas.saveState()

        # Full-page dark background
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)

        # Top accent bar — cyan gradient simulation (two rects)
        canvas.setFillColor(C_CYAN)
        canvas.rect(0, H - 2.5, W * 0.6, 2.5, fill=1, stroke=0)
        canvas.setFillColor(C_PURPLE)
        canvas.rect(W * 0.6, H - 2.5, W * 0.4, 2.5, fill=1, stroke=0)

        # Left margin neon line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.3)
        canvas.line(14*mm, 18*mm, 14*mm, H - 6*mm)

        # Footer strip — matrix green
        canvas.setFillColor(C_MATRIX)
        canvas.rect(0, 0, W, 14*mm, fill=1, stroke=0)
        canvas.setStrokeColor(C_GREEN)
        canvas.setLineWidth(0.5)
        canvas.line(0, 14*mm, W, 14*mm)

        # Footer text
        canvas.setFont("Courier", 6.5)
        canvas.setFillColor(C_GREEN)
        canvas.drawString(15*mm, 5*mm,
            f"⚡ VULNSCAN PRO  |  {target}  |  {scan_time}  |  CONFIDENTIAL")
        canvas.setFillColor(C_MUTED)
        canvas.drawRightString(W - 15*mm, 5*mm, f"PAGE {doc.page}")

        # Watermark on pages > 1
        if doc.page > 1:
            canvas.saveState()
            canvas.setFont("Helvetica-Bold", 52)
            canvas.setFillColor(colors.HexColor("#0a0a16"))
            canvas.translate(W / 2, H / 2)
            canvas.rotate(38)
            canvas.drawCentredString(0, 0, "CONFIDENTIAL")
            canvas.restoreState()

        canvas.restoreState()

    # ── Determine risk posture ─────────────────────────────────────────────────
    crit_c  = summary.get("critical_cves", 0)
    high_c  = summary.get("high_cves", 0)
    med_c   = summary.get("medium_cves",  0)
    expl_c  = summary.get("exploitable",  0)
    ports_c = summary.get("open_ports",   0)
    cvs_c   = summary.get("total_cves",   0)

    if crit_c > 0:      risk_label, risk_col, risk_grade = "CRITICAL RISK", C_RED,    "F"
    elif high_c > 0:    risk_label, risk_col, risk_grade = "HIGH RISK",     C_ORANGE, "D"
    elif cvs_c > 0:     risk_label, risk_col, risk_grade = "MEDIUM RISK",   C_YELLOW, "C"
    else:               risk_label, risk_col, risk_grade = "LOW RISK",      C_GREEN,  "A"

    # ══════════════════════════════════════════════════════════════════════════
    # BUILD STORY
    # ══════════════════════════════════════════════════════════════════════════
    story = []

    # ── Cover / Title section ─────────────────────────────────────────────────
    story += [sp(32)]

    # Brand badge row: icon box + title
    badge_tbl = Table(
        [[
            p('<font color="#00e5ff">⚡</font>',
              sty("ic", fontName="Helvetica-Bold", fontSize=24,
                  textColor=C_CYAN, leading=28)),
            [
                p("VulnScan Pro", S_TITLE),
                p("SECURITY ASSESSMENT REPORT",
                  sty("st2", fontName="Courier-Bold", fontSize=9,
                      textColor=C_PURPLE, leading=13, letterSpacing=2)),
            ]
        ]],
        colWidths=[22*mm, None]
    )
    badge_tbl.setStyle(TableStyle([
        ("VALIGN",  (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
    ]))
    story.append(badge_tbl)
    story += [sp(10), hr(C_CYAN), sp(6)]

    # Meta info table (target, time, risk)
    story.append(tbl(
        [
            [p("TARGET",      S_LABEL), p(target,    S_MONO)],
            [p("SCAN TIME",   S_LABEL), p(scan_time, S_MONO)],
            [p("REPORT DATE", S_LABEL),
             p(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), S_MONO)],
            [p("RISK LEVEL",  S_LABEL),
             p(f'<font color="#{risk_col.hexval()[1:].upper()}">{risk_label}</font>',
               sty("rl", fontName="Courier-Bold", fontSize=9,
                   textColor=risk_col))],
            [p("ROUTING",     S_LABEL),
             p(f"Tor SOCKS5 ({TOR_SOCKS_HOST}:{TOR_SOCKS_PORT})", S_MONO)],
        ],
        [38*mm, 130*mm],
        extra_styles=[
            ("FONTNAME",  (0, 0), (0, -1), "Courier-Bold"),
            ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
        ]
    ))

    story += [sp(18)]

    # ── KPI stats row — mirrors the website's .stats grid ─────────────────────
    kpi_items = [
        (str(ports_c), "OPEN PORTS",   C_CYAN),
        (str(cvs_c),   "TOTAL CVEs",   C_YELLOW),
        (str(crit_c),  "CRITICAL",     C_RED),
        (str(high_c),  "HIGH",         C_ORANGE),
        (str(expl_c),  "EXPLOITABLE",  C_PURPLE),
    ]
    kpi_cells = [[
        p(f'<font color="#{col.hexval()[1:].upper()}">{val}</font>'
          f'<br/><font color="#{C_MUTED.hexval()[1:].upper()}">{lbl}</font>',
          sty(f"kpi{i}", fontName="Courier-Bold", fontSize=16,
              textColor=col, leading=20, alignment=TA_CENTER))
        for i, (val, lbl, col) in enumerate(kpi_items)
    ]]
    kpi_tbl = Table(kpi_cells, colWidths=[34*mm] * 5)
    kpi_tbl.setStyle(TableStyle([
        ("ALIGN",          (0,0), (-1,-1), "CENTER"),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",     (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 12),
        ("BACKGROUND",     (0,0), (-1,-1), C_DARK),
        ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOX",            (0,0), (-1,-1), 0.6, C_BORDER2),
    ]))
    story.append(kpi_tbl)
    story += [sp(14)]

    # Disclaimer + page break
    story.append(p(
        "CONFIDENTIAL — Authorized security assessment only. "
        "Scanned anonymously via Tor. Not for public distribution.",
        S_DISC))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2 — PORT FINDINGS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(p("01  PORT FINDINGS", S_H1))
    story.append(hr(C_CYAN))

    for host in hosts:
        ip  = host.get("ip",  "?")
        hn  = host.get("hostnames", [])
        hos = hn[0] if hn else ""
        os_ = host.get("os", "")

        # Host chip — matches .host-chip in the website
        host_info = f'<font color="#{C_CYAN.hexval()[1:].upper()}">{ip}</font>'
        if hos:
            host_info += f'  <font color="#{C_MUTED.hexval()[1:].upper()}">{hos}</font>'
        if os_:
            host_info += f'  <font color="#{C_MUTED.hexval()[1:].upper()}">[{os_}]</font>'
        story.append(p(host_info,
                       sty("hchip", fontName="Courier-Bold", fontSize=8,
                           textColor=C_WHITE, leading=13)))
        story.append(sp(5))

        ports = host.get("ports", [])
        if not ports:
            story.append(p("No open ports found.", S_MONO_SM))
            continue

        # Ports table header
        port_rows = [[
            p("PORT",    S_LABEL), p("PROTOCOL", S_LABEL),
            p("SERVICE", S_LABEL), p("VERSION",  S_LABEL),
            p("RISK",    S_LABEL), p("CVEs",     S_LABEL),
        ]]
        for port in ports:
            svc   = port.get("service",  "")
            prod  = port.get("product",  svc)
            ver   = port.get("version",  "")
            rl    = port.get("risk_level", "UNKNOWN")
            score = port.get("risk_score", "")
            ncves = len(port.get("cves", []))
            risk_color = SEV_MAP.get(rl, C_MUTED)

            port_rows.append([
                p(str(port.get("port", "")),
                  sty("pn", fontName="Courier-Bold", fontSize=8,
                      textColor=C_CYAN)),
                p(port.get("protocol", "tcp").upper(), S_MONO),
                p(prod[:22],   S_MONO),
                p(ver[:18],    S_MONO_SM),
                p(f'<font color="#{risk_color.hexval()[1:].upper()}">'
                  f'{rl}</font>{"  " + str(score) if score else ""}',
                  sty("rc", fontName="Courier-Bold", fontSize=7,
                      textColor=risk_color)),
                p(str(ncves) if ncves else "—",
                  sty("cv", fontName="Courier-Bold", fontSize=8,
                      textColor=C_RED if ncves else C_MUTED)),
            ])

        story.append(KeepTogether([
            tbl(port_rows, [14*mm, 18*mm, 38*mm, 30*mm, 28*mm, 14*mm],
                hdr_row=True)
        ]))
        story.append(sp(10))

        # Per-port CVE detail blocks
        for port in ports:
            cves = port.get("cves", [])
            if not cves:
                continue
            svc  = port.get("service",  "")
            prod = port.get("product",  svc)
            port_num = port.get("port", "")

            story.append(p(
                f'<font color="#{C_CYAN.hexval()[1:].upper()}">'
                f'Port {port_num}</font>  '
                f'<font color="#{C_MUTED.hexval()[1:].upper()}">'
                f'{prod} — {len(cves)} vulnerabilit{"y" if len(cves)==1 else "ies"}</font>',
                sty("ph", fontName="Courier-Bold", fontSize=8,
                    textColor=C_WHITE, leading=13, spaceBefore=8)))

            cve_rows = [[
                p("CVE ID",       S_LABEL),
                p("SEVERITY",     S_LABEL),
                p("CVSS",         S_LABEL),
                p("PUBLISHED",    S_LABEL),
                p("DESCRIPTION",  S_LABEL),
            ]]
            for cve in cves:
                sev   = cve.get("severity", "UNKNOWN")
                col   = SEV_MAP.get(sev, C_MUTED)
                score = cve.get("score", "")
                desc  = cve.get("description", "")[:90]
                if len(cve.get("description", "")) > 90:
                    desc += "…"
                cve_rows.append([
                    p(f'<link href="{cve.get("references", [""])[0] or "https://nvd.nist.gov"}">'
                      f'<font color="#{C_CYAN.hexval()[1:].upper()}">'
                      f'{cve.get("id","")}</font></link>',
                      sty("ci", fontName="Courier-Bold", fontSize=7, textColor=C_CYAN)),
                    p(f'<font color="#{col.hexval()[1:].upper()}">{sev}</font>',
                      sty("cs", fontName="Courier-Bold", fontSize=7, textColor=col)),
                    p(str(score) if score else "—",
                      sty("csc", fontName="Courier-Bold", fontSize=7, textColor=col)),
                    p(cve.get("published", "")[:10], S_MONO_SM),
                    p(desc, S_MONO_SM),
                ])

            story.append(KeepTogether([
                tbl(cve_rows, [28*mm, 18*mm, 12*mm, 18*mm, 66*mm], hdr_row=True)
            ]))

            # Mitigations
            mits = port.get("mitigations", [])
            if mits:
                story.append(sp(4))
                story.append(p("MITIGATIONS", S_LABEL))
                for m in mits[:6]:
                    story.append(p(
                        f'<font color="#{C_GREEN.hexval()[1:].upper()}">&rsaquo;</font>  {m}',
                        sty("mi", fontName="Courier", fontSize=7,
                            textColor=C_BODY, leading=12, leftIndent=6)))

        story.append(sp(8))

    # ══════════════════════════════════════════════════════════════════════════
    # SSL / TLS SECTION
    # ══════════════════════════════════════════════════════════════════════════
    if ssl_list:
        story.append(PageBreak())
        story.append(p("02  SSL / TLS ANALYSIS", S_H1))
        story.append(hr(C_CYAN))

        GRADE_COL = {
            "A+": C_GREEN, "A": C_GREEN, "B": C_YELLOW,
            "C": C_ORANGE, "D": C_RED,   "F": C_RED, "N/A": C_MUTED,
        }
        for s in ssl_list:
            grade   = s.get("grade",   "N/A")
            gcol    = GRADE_COL.get(grade, C_MUTED)
            details = s.get("details", {})
            issues  = [i for i in s.get("issues", []) if i.get("severity") != "INFO"]

            ssl_meta = [
                [
                    p(f'<font color="#{gcol.hexval()[1:].upper()}">{grade}</font>',
                      sty("sg", fontName="Helvetica-Bold", fontSize=30,
                          textColor=gcol, leading=36, alignment=TA_CENTER)),
                    [
                        p(f'{s.get("host","?")}:{s.get("port",443)}',
                          sty("sh", fontName="Courier-Bold", fontSize=9,
                              textColor=C_WHITE)),
                        p(f'{details.get("protocol","?")}  ·  '
                          f'{details.get("cipher","?")}  '
                          f'({details.get("cipher_bits","?")} bit)', S_MONO_SM),
                        p(f'Expires: {details.get("expires","?")}  '
                          f'({details.get("days_until_expiry","?")} days)',
                          sty("sx", fontName="Courier", fontSize=7,
                              textColor=(C_RED if (details.get("days_until_expiry") or 999) < 30
                                         else C_GREEN))) if details.get("expires") else sp(1),
                    ]
                ]
            ]
            ssl_tbl = Table(ssl_meta, colWidths=[18*mm, None])
            ssl_tbl.setStyle(TableStyle([
                ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",     (0,0), (-1,-1), 8),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 8),
                ("LEFTPADDING",    (0,0), (-1,-1), 8),
                ("BACKGROUND",     (0,0), (-1,-1), C_DARK),
                ("BOX",            (0,0), (-1,-1), 0.4, C_BORDER2),
            ]))
            story.append(ssl_tbl)

            if issues:
                iss_rows = [[p("SEVERITY", S_LABEL), p("ISSUE", S_LABEL)]]
                for iss in issues:
                    ic = SEV_MAP.get(iss.get("severity",""), C_MUTED)
                    iss_rows.append([
                        p(f'<font color="#{ic.hexval()[1:].upper()}">'
                          f'{iss.get("severity","")}</font>',
                          sty("is", fontName="Courier-Bold", fontSize=7, textColor=ic)),
                        p(iss.get("msg", ""), S_MONO_SM),
                    ])
                story.append(tbl(iss_rows, [22*mm, 120*mm], hdr_row=True))

            story.append(sp(10))

    # ══════════════════════════════════════════════════════════════════════════
    # DNS SECTION
    # ══════════════════════════════════════════════════════════════════════════
    if dns_data and dns_data.get("records"):
        story.append(PageBreak())
        story.append(p("03  DNS RECONNAISSANCE", S_H1))
        story.append(hr(C_CYAN))

        records = dns_data.get("records", {})
        for rtype, values in records.items():
            if not values:
                continue
            story.append(p(rtype, sty("rt", fontName="Courier-Bold", fontSize=8,
                                       textColor=C_MUTED, spaceBefore=6)))
            rrows = [[p("VALUE", S_LABEL)]]
            for v in values:
                rrows.append([p(str(v)[:100], S_MONO_SM)])
            story.append(tbl(rrows, [142*mm], hdr_row=True))

        # SPF / DMARC posture
        story.append(sp(8))
        posture_rows = [
            [p("CHECK", S_LABEL), p("STATUS", S_LABEL), p("DETAIL", S_LABEL)],
            [
                p("SPF", S_MONO),
                p(f'<font color="#{(C_GREEN if dns_data.get("has_spf") else C_RED).hexval()[1:].upper()}">'
                  f'{"CONFIGURED" if dns_data.get("has_spf") else "MISSING"}</font>',
                  sty("spf", fontName="Courier-Bold", fontSize=7,
                      textColor=C_GREEN if dns_data.get("has_spf") else C_RED)),
                p("Sender Policy Framework" + (""  if dns_data.get("has_spf")
                  else " — email spoofing risk"), S_MONO_SM),
            ],
            [
                p("DMARC", S_MONO),
                p(f'<font color="#{(C_GREEN if dns_data.get("has_dmarc") else C_RED).hexval()[1:].upper()}">'
                  f'{"CONFIGURED" if dns_data.get("has_dmarc") else "MISSING"}</font>',
                  sty("dmarc", fontName="Courier-Bold", fontSize=7,
                      textColor=C_GREEN if dns_data.get("has_dmarc") else C_RED)),
                p("Domain-based Message Authentication" + ("" if dns_data.get("has_dmarc")
                  else " — email spoofing risk"), S_MONO_SM),
            ],
        ]
        story.append(tbl(posture_rows, [22*mm, 28*mm, 92*mm], hdr_row=True))

        # Subdomains
        subs = dns_data.get("subdomains", [])
        if subs:
            story.append(sp(8))
            story.append(p(f"SUBDOMAINS DISCOVERED ({len(subs)})", S_LABEL))
            sub_rows = [[p("SUBDOMAIN", S_LABEL), p("IP", S_LABEL)]]
            for s in subs[:30]:
                sub_rows.append([
                    p(s.get("subdomain",""),
                      sty("sd", fontName="Courier", fontSize=7, textColor=C_CYAN)),
                    p(s.get("ip",""), S_MONO_SM),
                ])
            story.append(tbl(sub_rows, [90*mm, 52*mm], hdr_row=True))

    # ══════════════════════════════════════════════════════════════════════════
    # HTTP HEADERS SECTION
    # ══════════════════════════════════════════════════════════════════════════
    if hdr_data and hdr_data.get("headers"):
        story.append(PageBreak())
        story.append(p("04  HTTP HEADER ANALYSIS", S_H1))
        story.append(hr(C_CYAN))

        hdr_grade = hdr_data.get("grade", "?")
        hdr_score = hdr_data.get("score", 0)
        GRADE_COL2 = {"A+": C_GREEN, "A": C_GREEN, "B": C_YELLOW,
                      "C": C_ORANGE, "D": C_RED, "F": C_RED}
        hgcol = GRADE_COL2.get(hdr_grade, C_MUTED)

        # Grade + URL row
        grade_row = Table(
            [[
                p(hdr_grade,
                  sty("hg", fontName="Helvetica-Bold", fontSize=28,
                      textColor=hgcol, leading=32, alignment=TA_CENTER)),
                [
                    p(hdr_data.get("url", ""), sty("hu", fontName="Courier-Bold",
                      fontSize=8, textColor=C_WHITE)),
                    p(f'HTTP {hdr_data.get("status_code","")}  ·  '
                      f'Score {hdr_score}/100  ·  '
                      f'{hdr_data.get("server","")}', S_MONO_SM),
                ]
            ]],
            colWidths=[18*mm, None]
        )
        grade_row.setStyle(TableStyle([
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("BACKGROUND",    (0,0), (-1,-1), C_DARK),
            ("BOX",           (0,0), (-1,-1), 0.4, C_BORDER2),
        ]))
        story.append(grade_row)
        story.append(sp(8))

        # Issues
        hdr_issues = [i for i in hdr_data.get("issues", []) if i.get("severity") != "INFO"]
        if hdr_issues:
            story.append(p("SECURITY ISSUES", S_LABEL))
            iss_rows = [[p("SEVERITY", S_LABEL), p("FINDING", S_LABEL)]]
            for iss in hdr_issues:
                ic = SEV_MAP.get(iss.get("severity",""), C_MUTED)
                iss_rows.append([
                    p(f'<font color="#{ic.hexval()[1:].upper()}">'
                      f'{iss.get("severity","")}</font>',
                      sty("hi", fontName="Courier-Bold", fontSize=7, textColor=ic)),
                    p(iss.get("msg",""), S_MONO_SM),
                ])
            story.append(tbl(iss_rows, [22*mm, 120*mm], hdr_row=True))
            story.append(sp(8))

        # Raw headers
        story.append(p("RESPONSE HEADERS", S_LABEL))
        h_rows = [[p("HEADER", S_LABEL), p("VALUE", S_LABEL)]]
        for k, v in list(hdr_data.get("headers", {}).items())[:25]:
            h_rows.append([
                p(k[:30],       sty("hk", fontName="Courier-Bold", fontSize=7, textColor=C_MUTED)),
                p(str(v)[:80],  S_MONO_SM),
            ])
        story.append(tbl(h_rows, [50*mm, 92*mm], hdr_row=True))

    # ══════════════════════════════════════════════════════════════════════════
    # FINAL PAGE — Recommendations summary
    # ══════════════════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(p("05  RECOMMENDATIONS SUMMARY", S_H1))
    story.append(hr(C_CYAN))

    all_mits = []
    for h in hosts:
        for port in h.get("ports", []):
            for m in port.get("mitigations", []):
                if m not in all_mits:
                    all_mits.append(m)

    if all_mits:
        mit_rows = [[p("#", S_LABEL), p("RECOMMENDATION", S_LABEL)]]
        for i, m in enumerate(all_mits[:40], 1):
            col = C_RED if "URGENT" in m else (C_ORANGE if "patch" in m.lower() else C_BODY)
            mit_rows.append([
                p(str(i), sty("mn", fontName="Courier-Bold", fontSize=7, textColor=C_MUTED)),
                p(m, sty("mt", fontName="Courier", fontSize=7, textColor=col, leading=12)),
            ])
        story.append(tbl(mit_rows, [10*mm, 132*mm], hdr_row=True))
    else:
        story.append(p("No specific recommendations at this time.", S_MONO_SM))

    story += [sp(20)]
    story.append(p(
        "This report was generated by VulnScan Pro — an open-source security assessment platform.  "
        "All findings are informational only. Always verify results before remediation.  "
        "Unauthorised scanning is illegal — ensure you have written permission for all tested systems.",
        S_DISC))

    # ── Build PDF ──────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buf.seek(0)

    fname = (f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]', '_', target)}"
             f"-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf")
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── Auto-install route ─────────────────────────────────────────────────────────
@app.route("/auto-install", methods=["POST"])
def auto_install_route():
    import shutil
    data = request.get_json() or {}
    tool = (data.get("tool") or "").strip().lower()
    if not tool or tool not in TOOL_INSTALL_MAP:
        return jsonify({"error": f"Unknown tool: {tool}"})
    pkg, binary = TOOL_INSTALL_MAP[tool]
    if not pkg:
        return jsonify({"error": f"{tool} requires manual install (not via apt)"})
    ok, msg = auto_install(pkg, binary)
    return jsonify({"ok": ok, "message": msg, "installed": bool(shutil.which(binary))})


# ── Theme API ──────────────────────────────────────────────────────────────────
_global_theme = {"theme": "cyberpunk"}

@app.route("/api/theme", methods=["GET", "POST"])
def theme_api():
    global _global_theme
    if request.method == "POST":
        data = request.get_json() or {}
        _global_theme["theme"] = data.get("theme", "cyberpunk")
        return jsonify({"ok": True, "theme": _global_theme["theme"]})
    return jsonify({"theme": _global_theme["theme"]})


# ── Server CLI Console ─────────────────────────────────────────────────────────
ALLOWED_CLI_COMMANDS = {
    "ls", "pwd", "whoami", "uptime", "df", "free", "ps", "netstat", "ss",
    "nmap", "theHarvester", "dnsrecon", "nikto", "lynis", "wpscan",
    "systemctl", "journalctl", "cat", "echo", "uname", "hostname",
    "ip", "ifconfig", "ping", "traceroute", "curl", "wget", "which",
    "apt", "apt-get", "dpkg", "pip3", "python3", "gem",
    "proxychains4", "proxychains", "tor",   # Added Tor tools
    "systemctl",
}
BLOCKED_PATTERNS = [
    r'rm\s+-rf', r'>\s*/etc', r'chmod\s+777\s+/', r'dd\s+if=',
    r'mkfs', r'fdisk', r';.*rm\s', r'\|\s*sh\b', r'curl.*\|.*bash',
    r'wget.*\|.*sh', r'base64.*decode.*\|'
]

@app.route("/api/exec", methods=["POST"])
def cli_route():
    import shutil
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required for CLI console"})
    data = request.get_json() or {}
    cmd_str = (data.get("command") or "").strip()
    if not cmd_str:
        return jsonify({"output": "", "error": ""})
    for pat in BLOCKED_PATTERNS:
        if re.search(pat, cmd_str, re.IGNORECASE):
            return jsonify({"error": f"Blocked: dangerous pattern detected"})
    first_word = cmd_str.split()[0]
    if first_word not in ALLOWED_CLI_COMMANDS:
        return jsonify({"error": f"Command '{first_word}' not in allowlist. Allowed: {', '.join(sorted(ALLOWED_CLI_COMMANDS))}"})
    try:
        r = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=30, cwd=os.path.expanduser("~")
        )
        return jsonify({
            "output": r.stdout[:8000],
            "error": r.stderr[:2000],
            "exit_code": r.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out (30s limit)", "output": ""})
    except Exception as e:
        return jsonify({"error": str(e), "output": ""})


# ── Health check ───────────────────────────────────────────────────────────────
# ── Wordlist API endpoint ─────────────────────────────────────────────────────
@app.route("/api/wordlist")
def wordlist_api():
    """Serve wordlist file contents for brute force UI. Admin or authenticated users only."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    path = request.args.get("path", "").strip()
    limit = min(int(request.args.get("limit", "1000")), 5000)

    ALLOWED_DIRS = [
        "/usr/share/wordlists/",
        "/usr/share/seclists/",
        "/usr/share/john/",
        "/usr/share/dict/",
    ]
    allowed = any(os.path.abspath(path).startswith(d) for d in ALLOWED_DIRS)
    if not allowed:
        return jsonify({"error": "Path not in allowed wordlist directories"}), 403

    if not os.path.isfile(path):
        # Try to find best available alternative
        alternatives = {
            "/usr/share/wordlists/rockyou.txt": [
                "/usr/share/john/password.lst",
                "/usr/share/dict/words",
            ],
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt": [
                "/usr/share/seclists/Usernames/Names/names.txt",
                "/usr/share/wordlists/rockyou.txt",
            ],
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt": [
                "/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt",
                "/usr/share/wordlists/rockyou.txt",
                "/usr/share/john/password.lst",
            ],
        }
        fallbacks = alternatives.get(path, [])
        found_alt = next((p for p in fallbacks if os.path.isfile(p)), None)
        if found_alt:
            path = found_alt
        else:
            # Scan the allowed dir for best match
            for d in ALLOWED_DIRS:
                if os.path.isdir(d):
                    for root, dirs, files in os.walk(d):
                        for fn in files:
                            fp = os.path.join(root, fn)
                            if os.path.isfile(fp) and os.path.getsize(fp) > 100:
                                path = fp
                                break
                        if path != request.args.get("path", ""):
                            break
            if not os.path.isfile(path):
                return jsonify({"error": f"Wordlist not found: {path}. Install: sudo apt install wordlists seclists"})

    try:
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#") and len(w) <= 128:
                    words.append(w)
                if len(words) >= limit:
                    break
        return jsonify({
            "path": path,
            "filename": os.path.basename(path),
            "words": words,
            "total_loaded": len(words),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    import shutil
    # Check Tor is running
    tor_running = False
    try:
        import socket as _s
        sock = _s.create_connection(("127.0.0.1", 9050), timeout=2)
        sock.close()
        tor_running = True
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "version": "3.7",
        "nmap": bool(shutil.which("nmap")),
        "dig": bool(shutil.which("dig")),
        "proxychains4": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "tor_running": tor_running,
        "tor_port": TOR_SOCKS_PORT,
        "python": sys.version
    })


# ── Server Statistics route ───────────────────────────────────────────────────
@app.route("/api/server-stats")
def server_stats():
    """Return live server resource usage — admin only."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    import time as _time

    stats = {}

    # ── CPU ──────────────────────────────────────────────────────────────────
    try:
        # Read two samples of /proc/stat 200ms apart for delta-based CPU %
        def read_cpu():
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()
            total = sum(int(x) for x in parts[1:])
            idle  = int(parts[4])
            return total, idle

        t1, i1 = read_cpu()
        _time.sleep(0.2)
        t2, i2 = read_cpu()
        delta_total = t2 - t1
        delta_idle  = i2 - i1
        cpu_pct = round((1 - delta_idle / delta_total) * 100, 1) if delta_total else 0

        import os as _os
        cpu_count = _os.cpu_count() or 1
        stats["cpu_percent"] = cpu_pct
        stats["cpu_count"]   = cpu_count
    except Exception as e:
        stats["cpu_percent"] = None
        stats["cpu_count"]   = None

    # ── Memory ───────────────────────────────────────────────────────────────
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":")
                mem[k.strip()] = int(v.split()[0]) * 1024  # kB → bytes

        total     = mem.get("MemTotal", 0)
        free      = mem.get("MemFree", 0)
        buffers   = mem.get("Buffers", 0)
        cached    = mem.get("Cached", 0) + mem.get("SReclaimable", 0)
        available = mem.get("MemAvailable", free + buffers + cached)
        used      = total - available
        pct       = round(used / total * 100, 1) if total else 0

        stats["memory"] = {
            "total":     total,
            "used":      used,
            "available": available,
            "percent":   pct,
        }

        # Swap
        swap_total = mem.get("SwapTotal", 0)
        swap_free  = mem.get("SwapFree", 0)
        swap_used  = swap_total - swap_free
        swap_pct   = round(swap_used / swap_total * 100, 1) if swap_total else 0
        stats["swap"] = {
            "total":   swap_total,
            "used":    swap_used,
            "free":    swap_free,
            "percent": swap_pct,
        }
    except Exception:
        stats["memory"] = None
        stats["swap"]   = None

    # ── Disk (root filesystem) ────────────────────────────────────────────────
    try:
        import os as _os
        st = _os.statvfs("/")
        disk_total = st.f_blocks * st.f_frsize
        disk_free  = st.f_bfree  * st.f_frsize
        disk_used  = disk_total  - disk_free
        disk_pct   = round(disk_used / disk_total * 100, 1) if disk_total else 0
        stats["disk"] = {
            "total":   disk_total,
            "used":    disk_used,
            "free":    disk_free,
            "percent": disk_pct,
        }
    except Exception:
        stats["disk"] = None

    # ── Network ───────────────────────────────────────────────────────────────
    try:
        best_iface = None
        best_rx    = 0

        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]  # skip header rows

        net_data = {}
        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            rx = int(parts[1])
            tx = int(parts[9])
            net_data[iface] = {"bytes_recv": rx, "bytes_sent": tx}
            if rx > best_rx:
                best_rx    = rx
                best_iface = iface

        if best_iface:
            stats["net"] = {
                "iface":      best_iface,
                "bytes_recv": net_data[best_iface]["bytes_recv"],
                "bytes_sent": net_data[best_iface]["bytes_sent"],
            }
        else:
            stats["net"] = None
    except Exception:
        stats["net"] = None

    # ── Uptime & Load ─────────────────────────────────────────────────────────
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        days  = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins  = int((secs % 3600)  // 60)
        if days:
            stats["uptime"] = f"{days}d {hours}h {mins}m"
        elif hours:
            stats["uptime"] = f"{hours}h {mins}m"
        else:
            stats["uptime"] = f"{mins}m"
    except Exception:
        stats["uptime"] = None

    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        stats["load_avg"]      = f"{parts[0]}  {parts[1]}  {parts[2]}"
        stats["process_count"] = int(parts[3].split("/")[1])
    except Exception:
        stats["load_avg"]      = None
        stats["process_count"] = None

    return jsonify(stats)

if __name__ == "__main__":
    print("[*] VulnScan Pro v3.7 starting (Tor mode)")
    print(f"[*] Tor SOCKS5: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("[*] Open: http://localhost:5000")
    print("[*] Health check: http://localhost:5000/health")
    print("[*] Verify Tor is running: systemctl status tor")
    app.run(host="0.0.0.0", port=5000, debug=False)
