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
import json, re, sys, os, subprocess, io, sqlite3, secrets, hashlib, threading, shlex, time, shutil, socket
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
<html lang="en" class="h-full">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VulnScan // Cyber-Brutalist Spatial</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            'c-primary': '#00FF41',
            'c-bg': '#000000',
            'c-surface': '#0A0A0A',
            'c-text': '#E0E0E0',
            'c-muted': '#333333',
            'c-accent': '#FF003C',
          },
          fontFamily: {
            mono: ['"JetBrains Mono"', 'monospace'],
          },
          boxShadow: {
            brutal: '4px 4px 0px 0px #00FF41',
            'brutal-accent': '4px 4px 0px 0px #FF003C',
          },
          backgroundImage: {
            'spatial-grid': 'linear-gradient(to right, #111111 1px, transparent 1px), linear-gradient(to bottom, #111111 1px, transparent 1px)',
          }
        }
      }
    }
  </script>
  <style>
    * { border-radius: 0 !important; }
    body { font-family: 'JetBrains Mono', monospace; }
    .glow { text-shadow: 0 0 8px rgba(0,255,65,0.55); }
    .glitch { animation: glitch .28s steps(2) infinite; }
    @keyframes glitch {
      0% { transform: translate(0, 0); color:#E0E0E0; }
      25% { transform: translate(-1px, 1px); color:#FF003C; }
      50% { transform: translate(1px, -1px); color:#E0E0E0; }
      75% { transform: translate(-1px, 0); color:#FF003C; }
      100% { transform: translate(0, 0); color:#E0E0E0; }
    }
    .scan-lines::before {
      content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 40;
      background: repeating-linear-gradient(to bottom, transparent 0px, transparent 2px, rgba(0,255,65,.04) 3px, transparent 4px);
    }
  </style>
</head>
<body class="h-full bg-c-bg text-c-text bg-spatial-grid bg-[size:40px_40px] scan-lines overflow-hidden">
  <div class="absolute inset-0 bg-gradient-to-br from-black via-c-bg to-[#020802] pointer-events-none"></div>

  <main class="relative z-10 h-full p-6">
    <section id="nexus-screen" class="h-full">
      <div class="mx-auto w-[400px] border border-c-primary bg-c-surface shadow-brutal px-4 py-3 flex items-center justify-between uppercase text-xs tracking-wide">
        <span id="hud-clock" class="glow"></span>
        <span>[proxy: active]</span>
        <button id="new-target-btn" class="w-[120px] h-10 border border-c-primary text-c-primary hover:bg-c-primary hover:text-c-bg active:translate-x-[2px] active:translate-y-[2px] active:shadow-none shadow-brutal font-bold">[new_target]</button>
      </div>

      <div class="mt-8 h-[78vh] relative border border-c-muted">
        <svg class="absolute inset-0 w-full h-full pointer-events-none">
          <line x1="16%" y1="22%" x2="44%" y2="48%" stroke="#333333" stroke-width="1"/>
          <line x1="44%" y1="48%" x2="78%" y2="30%" stroke="#333333" stroke-width="1"/>
          <line x1="44%" y1="48%" x2="72%" y2="70%" stroke="#333333" stroke-width="1"/>
        </svg>

        <article class="absolute left-[14%] top-[18%] w-[100px] h-[100px] border border-c-primary bg-c-surface p-2 text-[12px] cursor-pointer">
          <p>10.0.0.12</p><p class="text-c-primary">● ONLINE</p>
        </article>
        <article class="absolute left-[42%] top-[44%] w-[100px] h-[100px] border border-c-primary bg-c-surface p-2 text-[12px] cursor-pointer">
          <p>10.0.0.21</p><p class="text-c-primary">● ONLINE</p>
        </article>
        <article class="absolute left-[76%] top-[26%] w-[100px] h-[100px] border border-c-accent bg-c-surface p-2 text-[12px] cursor-pointer glitch">
          <p>10.0.0.66</p><p class="text-c-accent">● ALERT</p>
        </article>
        <article class="absolute left-[70%] top-[66%] w-[100px] h-[100px] border border-c-primary bg-c-surface p-2 text-[12px] cursor-pointer">
          <p>10.0.0.99</p><p class="text-c-primary">● ONLINE</p>
        </article>

        <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
          <p class="text-c-muted text-lg tracking-widest"><span class="text-c-primary">_</span> NODE_TOPOLOGY_ACTIVE</p>
        </div>
      </div>
    </section>

    <aside id="target-panel" class="hidden absolute top-6 right-6 w-[400px] h-[calc(100vh-48px)] bg-c-surface border border-c-muted p-5 shadow-brutal z-20">
      <h2 class="text-2xl font-bold uppercase tracking-tight mb-6">Target Injection</h2>
      <label class="block text-xs uppercase mb-2">Target IP / Domain</label>
      <input id="target-input" class="w-full h-12 bg-c-bg border border-c-muted px-3 text-c-primary text-lg focus:outline-none focus:border-c-primary focus:shadow-brutal" placeholder="ENTER_TARGET_IP..." />

      <div class="mt-8 space-y-4 uppercase text-sm">
        <label class="flex items-center gap-3 cursor-pointer"><input type="checkbox" class="peer hidden"><span class="w-6 h-6 border border-c-primary inline-flex items-center justify-center"><span class="hidden peer-checked:block w-4 h-4 bg-c-primary"></span></span><span>Nmap</span></label>
        <label class="flex items-center gap-3 cursor-pointer"><input type="checkbox" class="peer hidden"><span class="w-6 h-6 border border-c-primary inline-flex items-center justify-center"><span class="hidden peer-checked:block w-4 h-4 bg-c-primary"></span></span><span>Dirb</span></label>
        <label class="flex items-center gap-3 cursor-pointer"><input type="checkbox" class="peer hidden"><span class="w-6 h-6 border border-c-primary inline-flex items-center justify-center"><span class="hidden peer-checked:block w-4 h-4 bg-c-primary"></span></span><span>Nikto</span></label>
      </div>

      <button id="execute-btn" class="mt-8 w-full h-12 border border-c-primary text-c-primary font-bold uppercase shadow-brutal hover:bg-c-primary hover:text-c-bg">[execute]</button>
    </aside>

    <section id="execution-screen" class="hidden h-full relative">
      <div class="absolute left-4 top-4 w-[60vw] h-[70vh] border border-c-primary bg-c-surface shadow-brutal p-4">
        <h3 class="uppercase mb-3 text-sm glow">Execution Terminal</h3>
        <pre id="terminal-log" class="h-[calc(100%-28px)] overflow-auto text-[14px] leading-[1.2]">INITIALIZING_HANDSHAKE...</pre>
      </div>
      <div class="absolute right-4 top-4 w-[28vw] border border-c-muted bg-c-surface p-4">
        <p class="uppercase mb-2">CPU [||||||    ] 60%</p>
        <p class="uppercase">MEM [||||      ] 40%</p>
      </div>
      <button id="abort-btn" class="absolute right-4 bottom-4 w-[200px] h-[60px] border border-c-accent text-c-accent font-bold shadow-brutal-accent hover:bg-c-accent hover:text-c-bg">[SIGINT / ABORT]</button>
      <button id="open-matrix" class="absolute left-4 bottom-4 h-12 px-6 border border-c-primary text-c-primary shadow-brutal hover:bg-c-primary hover:text-c-bg">[THREAT_MATRIX]</button>
    </section>

    <section id="matrix-screen" class="hidden h-full p-4">
      <div class="h-full border border-c-muted bg-c-surface p-4">
        <div class="grid grid-cols-4 gap-4 mb-4 text-xs uppercase">
          <div class="border border-c-accent p-3">Critical: 4</div>
          <div class="border border-c-primary p-3">High: 9</div>
          <div class="border border-c-primary p-3">Medium: 14</div>
          <div class="border border-c-primary p-3">Low: 27</div>
        </div>
        <div class="grid grid-cols-4 text-xs uppercase border-b border-c-muted py-2">
          <span>ID</span><span>Severity</span><span>CWE_DESC</span><span>Endpoint</span>
        </div>
        <div class="grid grid-cols-4 text-xs h-10 items-center border-b border-dashed border-c-muted hover:bg-[#111111] cursor-crosshair"><span>VS-122</span><span><span class="inline-block px-2 py-1 bg-c-accent text-c-bg font-bold">critical</span></span><span>RCE via deserialization</span><span>/api/v1/upload</span></div>
        <div class="grid grid-cols-4 text-xs h-10 items-center border-b border-dashed border-c-muted hover:bg-[#111111] cursor-crosshair"><span>VS-184</span><span>high</span><span>SQL Injection</span><span>/auth/login</span></div>
        <div class="grid grid-cols-4 text-xs h-10 items-center border-b border-dashed border-c-muted hover:bg-[#111111] cursor-crosshair"><span>VS-211</span><span>medium</span><span>Missing CSP Header</span><span>/</span></div>
        <button id="dump-btn" class="absolute right-8 bottom-8 h-12 px-6 border border-c-primary text-c-primary shadow-brutal hover:bg-c-primary hover:text-c-bg">[DUMP_JSON]</button>
      </div>
    </section>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const screens = ['nexus-screen','execution-screen','matrix-screen'];
    const showScreen = (id) => screens.forEach(s => $(s).classList.toggle('hidden', s !== id));

    setInterval(() => {
      $('hud-clock').textContent = new Date().toISOString().replace('T',' ').slice(0,19) + 'Z';
    }, 500);

    $('new-target-btn').onclick = () => $('target-panel').classList.toggle('hidden');

    $('execute-btn').onclick = () => {
      $('target-panel').classList.add('hidden');
      showScreen('execution-screen');
      const log = $('terminal-log');
      const lines = [
        '[*] Proxy tunnel established via SOCKS5',
        '[*] Target resolved: 10.0.0.0/24',
        '[*] Running nmap -sV -A --top-ports 500',
        '[SUCCESS] 443/tcp open https',
        '[VULN] CVE-2023-4911 libc privilege escalation',
        '[*] Directory brute-force queued',
      ];
      let i = 0;
      const timer = setInterval(() => {
        if (i >= lines.length) return clearInterval(timer);
        log.textContent += "\n" + lines[i++];
        log.scrollTop = log.scrollHeight;
      }, 450);
      $('abort-btn').onclick = () => {
        document.body.classList.add('bg-white');
        setTimeout(()=>document.body.classList.remove('bg-white'), 50);
        log.textContent += "\n[ABORTED] Signal SIGINT received.";
        log.classList.add('text-c-muted');
      };
    };

    $('open-matrix').onclick = () => showScreen('matrix-screen');
    $('dump-btn').onclick = (e) => { e.target.textContent = '[DUMP_COMPLETE]'; };
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
    # Core existing tools
    "nmap":         ("nmap",         "nmap"),
    "nikto":        ("nikto",        "nikto"),
    "lynis":        ("lynis",        "lynis"),
    "dnsrecon":     ("dnsrecon",     "dnsrecon"),
    "legion":       ("legion",       "legion"),
    "theharvester": ("theharvester", "theHarvester"),
    "wpscan":       (None,            "wpscan"),
    "dig":          ("dnsutils",     "dig"),
    "proxychains4": ("proxychains4", "proxychains4"),
    "tor":          ("tor",          "tor"),

    # Added tools (categorized in setup/install script)
    "wapiti":       ("wapiti",       "wapiti"),
    "whatweb":      ("whatweb",      "whatweb"),
    "medusa":       ("medusa",       "medusa"),
    "hashcat":      ("hashcat",      "hashcat"),
    "john":         ("john",         "john"),
    "openvas":      ("openvas",      "openvas"),
    "chkrootkit":   ("chkrootkit",   "chkrootkit"),
    "rkhunter":     ("rkhunter",     "rkhunter"),
    "searchsploit": ("exploitdb",    "searchsploit"),
    "hping3":       ("hping3",       "hping3"),
    "scapy":        ("python3-scapy", "scapy"),
    "yersinia":     ("yersinia",     "yersinia"),
    "ffuf":         ("ffuf",         "ffuf"),
    "dalfox":       ("dalfox",       "dalfox"),
    "sqlmap":       ("sqlmap",       "sqlmap"),
    "kxss":         (None,            "kxss"),
    "seclists":     ("seclists",     "seclists"),
    "nuclei":       ("nuclei",       "nuclei"),
    "grype":        ("grype",        "grype"),
    "msfvenom":     ("metasploit-framework", "msfvenom"),
    "pwncat":       ("pwncat",       "pwncat"),
    "rlwrap":       ("rlwrap",       "rlwrap"),
    "radare2":      ("radare2",      "radare2"),
    "ligolo-ng":    ("ligolo-ng",    "ligolo-ng"),
    "chisel":       ("chisel",       "chisel"),
    "pspy":         (None,            "pspy"),
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
          "SUBDOMAIN_ENUM", target=domain, ip=request.remote_addr,
          details=f"size={size}")
    try:
        _sub_result = run_backend("--subdomains", domain, size, timeout=TIMEOUT_SUBDOMAIN)
        _sub_count = _sub_result.get("total", 0) if isinstance(_sub_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "SUBDOMAIN_ENUM_RESULT", target=domain, ip=request.remote_addr,
              details=f"size={size};found={_sub_count}")
        return jsonify(_sub_result)
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
          "DIR_ENUM", target=url, ip=request.remote_addr,
          details=f"size={size};ext={ext}")
    try:
        _dir_result = run_backend("--dirbust", url, size, ext, timeout=TIMEOUT_DIRBUST)
        _dir_found = _dir_result.get("total", 0) if isinstance(_dir_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "DIR_ENUM_RESULT", target=url, ip=request.remote_addr,
              details=f"size={size};ext={ext};found={_dir_found}")
        return jsonify(_dir_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/brute-http", methods=["POST"])
def brute_http():
    d = request.get_json() or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    _bh_users = d.get("users", [])[:10]
    _bh_pwds  = d.get("passwords", [])[:50]
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_HTTP", target=url, ip=request.remote_addr,
          details=f"users={len(_bh_users)};passwords={len(_bh_pwds)}")
    users = ",".join(_bh_users)
    pwds  = ",".join(_bh_pwds)
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        _bh_result = run_backend("--brute-http", url, users, pwds, uf, pf,
                                  timeout=TIMEOUT_BRUTE)
        _bh_found = len(_bh_result.get("found", [])) if isinstance(_bh_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "BRUTE_HTTP_RESULT", target=url, ip=request.remote_addr,
              details=f"attempts={_bh_result.get('attempts',0) if isinstance(_bh_result,dict) else 0};found={_bh_found}")
        return jsonify(_bh_result)
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
    _bs_users = d.get("users", [])[:5]
    _bs_pwds  = d.get("passwords", [])[:20]
    audit(user["id"] if user else None, user["username"] if user else "anon",
          "BRUTE_SSH", target=host, ip=request.remote_addr,
          details=f"port={port};users={len(_bs_users)};passwords={len(_bs_pwds)}")
    users = ",".join(_bs_users)
    pwds  = ",".join(_bs_pwds)
    try:
        _bs_result = run_backend("--brute-ssh", host, port, users, pwds,
                                  timeout=TIMEOUT_BRUTE)
        _bs_found = len(_bs_result.get("found", [])) if isinstance(_bs_result, dict) else 0
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "BRUTE_SSH_RESULT", target=host, ip=request.remote_addr,
              details=f"port={port};attempts={_bs_result.get('attempts',0) if isinstance(_bs_result,dict) else 0};found={_bs_found}")
        return jsonify(_bs_result)
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
        # Generic tool passthrough — binary name == tool name
    generic_tools = {
        "ffuf": "ffuf", "nuclei": "nuclei", "whatweb": "whatweb",
        "wapiti": "wapiti", "dalfox": "dalfox", "sqlmap": "sqlmap",
        "kxss": "kxss", "medusa": "medusa", "hping3": "hping3",
        "scapy": "scapy3", "yersinia": "yersinia", "hashcat": "hashcat",
        "john": "john", "searchsploit": "searchsploit", "seclists": "ls",
        "ligolo-ng": "ligolo-ng", "chisel": "chisel", "rlwrap": "rlwrap",
        "pspy": "pspy", "msfvenom": "msfvenom", "pwncat": "pwncat",
        "grype": "grype", "radare2": "r2", "openvas": "openvas",
        "chkrootkit": "chkrootkit", "rkhunter": "rkhunter",
    }
    if tool_name in generic_tools:
        return shutil.which(generic_tools[tool_name]) or generic_tools[tool_name], []
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
          target="set_terminal", ip=request.remote_addr,
          details=f"sid={sid}")
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

    if tool not in {"setoolkit", "gophish", "evilginx2", "shellphish", "netcat", "ncat", "socat", "sliver", "empire", "ffuf", "nuclei", "whatweb", "wapiti", "dalfox", "sqlmap", "kxss", "medusa", "hping3", "scapy", "yersinia", "hashcat", "john", "searchsploit", "seclists", "ligolo-ng", "chisel", "rlwrap", "pspy", "msfvenom", "pwncat", "grype", "radare2", "openvas", "chkrootkit", "rkhunter"}:
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
          details=f"operation={operation};args={args_text[:120]};cmd={' '.join(cmd[:5])}")

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = int((time.monotonic() - start) * 1000)
        audit(user["id"] if user else None, user["username"] if user else "anon",
              "SOCIAL_TOOL_RESULT", target=tool, ip=request.remote_addr,
              details=f"exit_code={proc.returncode};duration_ms={elapsed};operation={operation}")
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
    _disc_user = get_current_user()
    audit(_disc_user["id"] if _disc_user else None,
          _disc_user["username"] if _disc_user else "anon",
          "NETWORK_DISCOVER", target=subnet, ip=request.remote_addr,
          details=f"subnet={subnet}")
    try:
        _disc_result = run_backend("--discover", subnet, timeout=TIMEOUT_DISCOVER)
        _disc_hosts = _disc_result.get("total", 0) if isinstance(_disc_result, dict) else 0
        audit(_disc_user["id"] if _disc_user else None,
              _disc_user["username"] if _disc_user else "anon",
              "NETWORK_DISCOVER_RESULT", target=subnet, ip=request.remote_addr,
              details=f"subnet={subnet};hosts_found={_disc_hosts}")
        return jsonify(_disc_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    limit = int(request.args.get("limit", 20))
    audit(uid, user["username"] if user else "anon",
          "HISTORY_ACCESS", target="scan_history", ip=request.remote_addr,
          details=f"limit={limit}")
    return jsonify(get_history(limit, user_id=uid))


@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    audit(uid, user["username"] if user else "anon",
          "SCAN_VIEW", target=str(sid), ip=request.remote_addr,
          details=f"scan_id={sid};role={role}")
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

    audit(user["id"] if user else None, user["username"] if user else "anon",
          "DNSRECON_RESULT", target=target, ip=request.remote_addr,
          details=f"type={scan_type};records={len(records)};method={method_used}")
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
    _nk_user = get_current_user()
    audit(_nk_user["id"] if _nk_user else None,
          _nk_user["username"] if _nk_user else "anon",
          "NIKTO_SCAN", target=target, ip=request.remote_addr,
          details=f"port={port};ssl={ssl_flag};tuning={tuning}")
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

        _nk_user2 = get_current_user()
        audit(_nk_user2["id"] if _nk_user2 else None,
              _nk_user2["username"] if _nk_user2 else "anon",
              "NIKTO_RESULT", target=target, ip=request.remote_addr,
              details=f"port={port};findings={len(findings)};server={server[:40]}")
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

    _wp_user = get_current_user()
    audit(_wp_user["id"] if _wp_user else None,
          _wp_user["username"] if _wp_user else "anon",
          "WPSCAN", target=target, ip=request.remote_addr,
          details=f"enum={enum_flags};mode={mode}")

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

    _ly_user = get_current_user()
    audit(_ly_user["id"] if _ly_user else None,
          _ly_user["username"] if _ly_user else "anon",
          "LYNIS_SCAN", target="localhost", ip=request.remote_addr,
          details=f"profile={profile};category={category};compliance={compliance}")

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

        audit(_ly_user["id"] if _ly_user else None,
              _ly_user["username"] if _ly_user else "anon",
              "LYNIS_RESULT", target="localhost", ip=request.remote_addr,
              details=(f"profile={profile};compliance={compliance};"
                       f"hardening_index={hardening_index};"
                       f"warnings={len(warnings)};suggestions={len(suggestions)};"
                       f"tests_performed={tests_performed}"))
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
    audit(None, "agent", "AGENT_REGISTER", target=client_id,
          ip=request.remote_addr,
          details=f"hostname={hostname};os_info={os_info[:60]}")
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
    _cj_user = get_current_user()
    audit(_cj_user["id"] if _cj_user else None,
          _cj_user["username"] if _cj_user else "anon",
          "LYNIS_JOB_CREATED", target=client_id, ip=request.remote_addr,
          details=f"job_id={jid};profile={profile};compliance={compliance};category={category}")
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
    audit(None, f"agent:{client_id}", "LYNIS_JOB_UPLOAD",
          target=str(job_id), ip=request.remote_addr,
          details=(f"job_id={job_id};status={status};"
                   f"hardening_index={hardening_index};"
                   f"warnings={len(warnings)};suggestions={len(suggestions)}"))
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
    _dc_user = get_current_user()
    audit(_dc_user["id"] if _dc_user else None,
          _dc_user["username"] if _dc_user else "anon",
          "AGENT_DISCONNECT", target=client_id, ip=request.remote_addr,
          details=f"client_id={client_id}")
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
    _cancel_user = get_current_user()
    audit(_cancel_user["id"] if _cancel_user else None,
          _cancel_user["username"] if _cancel_user else "anon",
          "LYNIS_JOB_CANCEL", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id};status={status}")
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
    _del_user = get_current_user()
    audit(_del_user["id"] if _del_user else None,
          _del_user["username"] if _del_user else "anon",
          "LYNIS_JOB_DELETED", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id}")
    return jsonify({"ok": True, "job_id": job_id, "deleted": True})


@app.route("/api/job-report/<int:job_id>.txt", methods=["GET"])
def download_job_report(job_id):
    with AGENT_LOCK:
        con = _agent_db()
        row = con.execute("SELECT raw_report FROM lynis_jobs WHERE id=?", (job_id,)).fetchone()
        con.close()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    _dl_user = get_current_user()
    audit(_dl_user["id"] if _dl_user else None,
          _dl_user["username"] if _dl_user else "anon",
          "LYNIS_REPORT_DOWNLOAD", target=str(job_id), ip=request.remote_addr,
          details=f"job_id={job_id}")
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

@app.route("/agent/install.ps1", methods=["GET"])
def agent_install_script_ps1():
    script = f"""param(
  [string]$ClientId = "",
  [string]$Token = "",
  [string]$ServerUrl = "{AGENT_SERVER_URL}"
)
$ErrorActionPreference = "Stop"
function Write-Info($m) {{ Write-Host "[*] $m" -ForegroundColor Cyan }}
function Write-Ok($m) {{ Write-Host "[+] $m" -ForegroundColor Green }}
function Write-Err($m) {{ Write-Host "[x] $m" -ForegroundColor Red }}
Write-Info "Preparing VulnScan Lynis agent install for Windows host"
Write-Info "This installer runs the Linux agent through WSL (required by Lynis)."
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {{
  Write-Err "WSL is not installed. Install it first: wsl --install"
  exit 1
}}
if ([string]::IsNullOrWhiteSpace($ClientId)) {{
  $hostname = $env:COMPUTERNAME
  $rand = -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object {{[char]$_}})
  $ClientId = "$hostname-$rand".ToLower()
}}
Write-Info "Testing server connectivity: $ServerUrl"
Invoke-WebRequest -UseBasicParsing -Uri "$ServerUrl/health" -TimeoutSec 15 | Out-Null
Write-Ok "Connected to VulnScan server"
$cmd = "curl -fsSL '$ServerUrl/agent/install.sh' | bash -s -- '$ClientId' '$Token' '$ServerUrl'"
Write-Info "Running Linux installer in WSL..."
wsl.exe bash -lc $cmd
if ($LASTEXITCODE -ne 0) {{
  Write-Err "WSL install command failed."
  exit $LASTEXITCODE
}}
Write-Ok "Agent install command completed in WSL."
"""
    return Response(script, mimetype="text/plain; charset=utf-8")


@app.route("/agent/<path:filename>", methods=["GET"])
def agent_file(filename):
    agent_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent")
    if filename not in {"install_agent.sh", "install_agent.ps1", "lynis_pull_agent.py"}:
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

    _lg_user = get_current_user()
    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_SCAN", target=target, ip=request.remote_addr,
          details=f"intensity={intensity};modules={','.join(modules)}")

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

    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_RESULT", target=target, ip=request.remote_addr,
          details=f"open_ports={open_ports};issues={total_issues};modules_run={modules_run}")
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

            audit(user["id"] if user else None, user["username"] if user else "anon",
              "HARVESTER_RESULT", target=target, ip=request.remote_addr,
              details=(f"sources={sources};emails={len(emails)};"
                       f"hosts={len(hosts)};subdomains={len(subdomains)};ips={len(ips)}"))
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

    def _pdf_safe(obj):
        if isinstance(obj, dict):
            return {k: _pdf_safe(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_pdf_safe(v) for v in obj]
        if isinstance(obj, str):
            return obj.encode("latin-1", "replace").decode("latin-1")
        return obj

    data = _pdf_safe(request.get_json() or {})
    target     = data.get("target", "unknown")
    scan_time  = data.get("scan_time", "")[:19].replace("T", " ")
    _rpt_user = get_current_user()
    audit(_rpt_user["id"] if _rpt_user else None,
          _rpt_user["username"] if _rpt_user else "anon",
          "PDF_REPORT_GENERATED", target=target, ip=request.remote_addr,
          details=f"scan_time={scan_time};open_ports={data.get('summary',{}).get('open_ports',0)};total_cves={data.get('summary',{}).get('total_cves',0)}")
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
    _ai_user = get_current_user()
    audit(_ai_user["id"] if _ai_user else None,
          _ai_user["username"] if _ai_user else "anon",
          "AUTO_INSTALL", target=tool, ip=request.remote_addr,
          details=f"pkg={pkg};binary={binary}")
    ok_flag, msg = auto_install(pkg, binary)
    _ai_installed = bool(shutil.which(binary))
    audit(_ai_user["id"] if _ai_user else None,
          _ai_user["username"] if _ai_user else "anon",
          "AUTO_INSTALL_RESULT", target=tool, ip=request.remote_addr,
          details=f"pkg={pkg};success={ok_flag};installed={_ai_installed};msg={msg[:80]}")
    return jsonify({"ok": ok_flag, "message": msg, "installed": _ai_installed})


# ── Theme API ──────────────────────────────────────────────────────────────────
_global_theme = {"theme": "cyberpunk"}

@app.route("/api/theme", methods=["GET", "POST"])
def theme_api():
    global _global_theme
    if request.method == "POST":
        data = request.get_json() or {}
        _theme_old = _global_theme.get("theme", "unknown")
        _global_theme["theme"] = data.get("theme", "cyberpunk")
        _theme_user = get_current_user()
        audit(_theme_user["id"] if _theme_user else None,
              _theme_user["username"] if _theme_user else "anon",
              "THEME_CHANGE", target="ui", ip=request.remote_addr,
              details=f"from={_theme_old};to={_global_theme['theme']}")
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

MONITORED_SERVICES = {
    "apache2": {
        "key": "apache2",
        "label": "Apache Service",
        "kind": "systemctl",
        "unit": "apache2",
    },
    "supabase": {
        "key": "supabase",
        "label": "Supabase",
        "kind": "command",
        "check_cmd": """cd ~/vulnscan && python3 -c "from dotenv import load_dotenv; load_dotenv('.env'); from supabase_config import supabase; supabase().table('users').select('id').limit(1).execute(); print('OK')" """,
        "control_cmds": {
            "start": "cd ~/vulnscan && supabase start",
            "stop": "cd ~/vulnscan && supabase stop",
            "restart": "cd ~/vulnscan && supabase stop && supabase start",
        },
    },
}

def _safe_service_row(svc):
    return {
        "key": svc.get("key"),
        "label": svc.get("label"),
        "kind": svc.get("kind"),
        "unit": svc.get("unit", ""),
    }

def _service_status(svc):
    kind = svc.get("kind")
    if kind == "systemctl":
        unit = svc.get("unit")
        if not unit:
            return {"status": "unknown", "detail": "Missing unit"}
        proc = subprocess.run(
            f"systemctl is-active {shlex.quote(unit)}",
            shell=True, capture_output=True, text=True, timeout=8
        )
        out = (proc.stdout or proc.stderr or "").strip()
        if proc.returncode == 0 and out == "active":
            return {"status": "running", "detail": out}
        if out:
            return {"status": "stopped", "detail": out}
        return {"status": "unknown", "detail": f"exit={proc.returncode}"}
    if kind == "command":
        check_cmd = (svc.get("check_cmd") or "").strip()
        if not check_cmd:
            return {"status": "unknown", "detail": "Missing check command"}
        proc = subprocess.run(
            check_cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        detail = (proc.stdout or proc.stderr or "").strip()
        return {
            "status": "running" if proc.returncode == 0 else "stopped",
            "detail": detail[:240],
        }
    return {"status": "unknown", "detail": "Unsupported service type"}

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
    audit(u["id"], u["username"], "CLI_EXEC", target="server",
          ip=request.remote_addr,
          details=f"cmd={cmd_str[:200]}")
    try:
        r = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=30, cwd=os.path.expanduser("~")
        )
        audit(u["id"], u["username"], "CLI_EXEC_RESULT", target="server",
              ip=request.remote_addr,
              details=f"cmd={cmd_str[:200]};exit_code={r.returncode}")
        return jsonify({
            "output": r.stdout[:8000],
            "error": r.stderr[:2000],
            "exit_code": r.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out (30s limit)", "output": ""})
    except Exception as e:
        return jsonify({"error": str(e), "output": ""})

@app.route("/api/admin/services")
def admin_services():
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    rows = []
    for svc in MONITORED_SERVICES.values():
        st = _service_status(svc)
        rows.append({
            **_safe_service_row(svc),
            "status": st.get("status", "unknown"),
            "detail": st.get("detail", ""),
        })
    audit(u["id"], u["username"], "ADMIN_SERVICES_VIEW", target="services", ip=request.remote_addr)
    return jsonify({"services": rows, "count": len(rows)})

@app.route("/api/admin/services", methods=["POST"])
def admin_add_service():
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json() or {}
    key = (data.get("key") or data.get("unit") or data.get("label") or "").strip().lower().replace(" ", "-")
    label = (data.get("label") or key or "Service").strip()
    kind = (data.get("kind") or "systemctl").strip().lower()
    if not key:
        return jsonify({"error": "Service key/label is required"}), 400
    if key in MONITORED_SERVICES:
        return jsonify({"error": "Service already exists"}), 400
    if kind == "systemctl":
        unit = (data.get("unit") or key).strip()
        MONITORED_SERVICES[key] = {"key": key, "label": label, "kind": "systemctl", "unit": unit}
    elif kind == "command":
        check_cmd = (data.get("check_cmd") or "").strip()
        if not check_cmd:
            return jsonify({"error": "check_cmd is required for command services"}), 400
        MONITORED_SERVICES[key] = {
            "key": key, "label": label, "kind": "command", "check_cmd": check_cmd,
            "control_cmds": data.get("control_cmds") or {}
        }
    else:
        return jsonify({"error": "Invalid kind. Use systemctl or command"}), 400
    audit(u["id"], u["username"], "ADMIN_SERVICE_ADD", target=key, ip=request.remote_addr, details=f"kind={kind}")
    return jsonify({"ok": True, "service": _safe_service_row(MONITORED_SERVICES[key])})

@app.route("/api/admin/services/<key>/action", methods=["POST"])
def admin_service_action(key):
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    svc = MONITORED_SERVICES.get(key)
    if not svc:
        return jsonify({"error": "Unknown service"}), 404
    data = request.get_json() or {}
    action = (data.get("action") or "").strip().lower()
    if action not in {"start", "stop", "restart"}:
        return jsonify({"error": "Invalid action"}), 400
    if svc.get("kind") == "systemctl":
        cmd = f"systemctl {action} {shlex.quote(svc.get('unit',''))}"
    else:
        cmd = ((svc.get("control_cmds") or {}).get(action) or "").strip()
    if not cmd:
        return jsonify({"error": f"No {action} command configured for this service"}), 400
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    out = (proc.stdout or "")[:2000]
    err = (proc.stderr or "")[:2000]
    st = _service_status(svc)
    audit(u["id"], u["username"], "ADMIN_SERVICE_ACTION", target=key, ip=request.remote_addr,
          details=f"action={action};exit={proc.returncode}")
    return jsonify({
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": out,
        "error": err,
        "status": st.get("status", "unknown"),
        "detail": st.get("detail", ""),
    })


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
    audit(user["id"], user["username"], "WORDLIST_ACCESS",
          target=path, ip=request.remote_addr,
          details=f"path={path};limit={limit}")

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
    audit(u["id"], u["username"], "SERVER_STATS_ACCESS",
          target="server", ip=request.remote_addr)
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

def _pick_available_port(start_port: int, host: str = "0.0.0.0", attempts: int = 20) -> int:
    """Return the first available TCP port starting at start_port."""
    for port in range(start_port, start_port + max(1, attempts)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    raise OSError(f"No free port found in range {start_port}-{start_port + max(1, attempts) - 1}")


if __name__ == "__main__":
    host = os.environ.get("VULNSCAN_HOST", "0.0.0.0")
    requested_port = int(os.environ.get("PORT") or os.environ.get("VULNSCAN_PORT") or "5000")
    try:
        port = _pick_available_port(requested_port, host=host, attempts=20)
    except OSError as e:
        print(f"[!] Failed to find open listen port: {e}")
        raise

    if port != requested_port:
        print(f"[!] Port {requested_port} is busy; using {port} instead.")

    print("[*] VulnScan Pro v3.7 starting (Tor mode)")
    print(f"[*] Tor SOCKS5: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print(f"[*] Open: http://localhost:{port}")
    print(f"[*] Health check: http://localhost:{port}/health")
    print("[*] Verify Tor is running: systemctl status tor")
    app.run(host=host, port=port, debug=False)
