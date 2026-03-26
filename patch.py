#!/usr/bin/env python3
"""
VulnScan Pro — Patch: SET Interactive Terminal Integration
Adds a full PTY-based interactive terminal for Social-Engineer Toolkit.

Run: python3 patch_set.py  (from project root)
"""
import os, shutil, subprocess, sys
from datetime import datetime

GREEN  = "\033[92m"; RED    = "\033[91m"; CYAN   = "\033[96m"
YELLOW = "\033[93m"; RESET  = "\033[0m";  BOLD   = "\033[1m"; DIM = "\033[2m"

def ok(m):   print(f"  {GREEN}✓{RESET} {m}")
def fail(m): print(f"  {RED}✗{RESET} {m}")
def info(m): print(f"  {CYAN}→{RESET} {m}")
def skip(m): print(f"  {DIM}·{RESET} {m}")

R = {"applied": 0, "skipped": 0, "failed": 0, "files": [], "restart": False}

def backup(p):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(p, f"{p}.{ts}.bak")

def patch(path, changes):
    if not os.path.isfile(path):
        fail(f"Not found: {path}")
        R["failed"] += len(changes)
        return
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    out = src
    applied = 0
    for desc, old, new in changes:
        if old in out:
            out = out.replace(old, new, 1)
            ok(desc)
            applied += 1
            R["applied"] += 1
        elif new in out:
            skip(f"{desc} (already applied)")
            R["skipped"] += 1
        else:
            fail(f"{desc} — anchor not found")
            R["failed"] += 1
    if applied:
        backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        if path not in R["files"]:
            R["files"].append(path)
        R["restart"] = True

def syntax(p):
    r = subprocess.run([sys.executable, "-m", "py_compile", p],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — api_server.py: Add /set-terminal SSE + /set-input endpoints
# ══════════════════════════════════════════════════════════════════════════════

# Anchor: insert the new SET routes just before the existing /social-tools/run route
OLD_SOCIAL_ANCHOR = '''@app.route("/social-tools/run", methods=["POST"])
def social_tool_run():'''

NEW_SOCIAL_ANCHOR = '''# ── SET Interactive Terminal (PTY-based) ──────────────────────────────────────
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

    _reap_old_set_sessions()

    sid = str(_uuid.uuid4())
    try:
        master_fd, slave_fd = _pty.openpty()

        # Set window size so SET menus render correctly (80×24)
        winsize = _struct.pack("HHHH", 40, 220, 0, 0)
        _fcntl.ioctl(slave_fd, _termios.TIOCSWINSZ, winsize)

        proc = subprocess.Popen(
            [binary],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
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
            "binary":     binary,
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
              ip=request.remote_addr, details=f"binary={binary}")

        return jsonify({"session_id": sid, "ok": True, "binary": binary})

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
            yield "data: " + json.dumps({"type": "error", "text": "Session not found or expired."}) + "\\n\\n"
        return Response(_gone(), mimetype="text/event-stream")

    def _gen():
        q = session["output_q"]
        while True:
            try:
                chunk = q.get(timeout=25)
            except _queue.Empty:
                # Heartbeat so the connection stays alive
                yield "data: " + json.dumps({"type": "heartbeat"}) + "\\n\\n"
                continue

            if chunk is None:
                # Reader thread ended — process exited
                yield "data: " + json.dumps({"type": "exit", "text": "\\r\\n[SET session ended]\\r\\n"}) + "\\n\\n"
                _kill_set_session(sid)
                break

            yield "data: " + json.dumps({"type": "output", "text": chunk}) + "\\n\\n"

    return Response(
        _gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/set/session/<sid>/input", methods=["POST"])
def set_session_input(sid):
    """
    Send keystrokes / a line to the SET PTY.
    Body: { "text": "1\\n" }   — text to write verbatim to the PTY
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
        "ctrl_c": b"\\x03",
        "ctrl_d": b"\\x04",
        "ctrl_z": b"\\x1a",
        "enter":  b"\\n",
        "up":     b"\\x1b[A",
        "down":   b"\\x1b[B",
        "q":      b"q\\n",
        "99":     b"99\\n",
        "back":   b"99\\n",
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
def social_tool_run():'''


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — HTML: Replace SET page with full interactive terminal UI
# ══════════════════════════════════════════════════════════════════════════════

OLD_SET_PAGE = '''      <!-- SOCIAL-ENGINEER TOOLKIT -->
      <div class="page" id="page-setoolkit">
        <div class="page-hd"><div class="page-title">Social-Engineer Toolkit (SET)</div><div class="page-desc">Run SET commands from server and view live output</div></div>
        <div class="notice">&#9888; Authorized awareness testing only. This executes real SET commands on your server.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>OPERATION</label><select class="inp inp-mono" id="set-op"><option value="help">Help / capability check</option><option value="version">Version check</option><option value="custom">Custom arguments</option></select></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="set-timeout" type="number" value="90" min="10" max="600"/></div>
          </div>
          <div class="fg"><label>CUSTOM ARGUMENTS (for custom mode)</label><input class="inp inp-mono" id="set-args" type="text" placeholder="--help"/></div>
          <button class="btn btn-primary" id="set-btn" onclick="runSetToolkit()">RUN SET</button>
        </div>
        <div class="progress-wrap" id="set-prog"><div class="progress-bar" id="set-pb" style="width:0%"></div></div>
        <div class="terminal" id="set-term"></div>
        <div class="err-box" id="set-err"></div>
        <div id="set-res"></div>
        <div class="page-hd"><div class="page-title">Social-Engineer Toolkit (SET)</div><div class="page-desc">Interactive social engineering simulation framework</div></div>
        <div class="notice">&#9888; Use only for internal awareness assessments with written authorization. Never use for unauthorized phishing or payload delivery.</div>
        <div class="card card-p" style="margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">Recommended Use Cases</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.8">Email phishing simulations, clone-page credential capture in controlled labs, and awareness testing with approved target lists.</div>
          <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px"><span class="tag">spear-phishing</span><span class="tag">web templates</span><span class="tag">payload generation</span></div>
        </div>
        <div class="card card-p">
          <div class="card-title" style="margin-bottom:8px">Quick Commands (Linux)</div>
          <div style="font-family:var(--mono);font-size:11px;line-height:1.8;color:var(--text2)">sudo apt install set<br/>sudo setoolkit</div>
          <div style="font-size:11px;color:var(--text3);margin-top:10px">Workflow: Social-Engineering Attacks &rarr; Spear-Phishing &rarr; Select payload/template &rarr; send only to approved recipients.</div>
        </div>
      </div>'''

NEW_SET_PAGE = '''      <!-- SOCIAL-ENGINEER TOOLKIT — Interactive PTY Terminal -->
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
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('1\\n')" title="Social-Engineering Attacks">1 — SE Attacks</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('2\\n')" title="Penetration Testing (Fast-Track)">2 — PenTest</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('3\\n')" title="Third Party Modules">3 — Third Party</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('4\\n')" title="Update SET">4 — Update SET</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('5\\n')" title="Update SET Config">5 — SET Config</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('6\\n')" title="Help / Credits">6 — Help</button>
            </div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">SOCIAL-ENGINEERING ATTACKS (after selecting 1)</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('1\\n')" title="Spear-Phishing">1 — Spear-Phishing</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('2\\n')" title="Website Attack Vectors">2 — Website Attacks</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('3\\n')" title="Infectious Media Generator">3 — Infectious Media</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('4\\n')" title="Create a Payload and Listener">4 — Payload + Listener</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('5\\n')" title="Mass Mailer Attack">5 — Mass Mailer</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('6\\n')" title="Arduino-Based Attack Vector">6 — Arduino</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('7\\n')" title="Wireless Access Point Attack">7 — Wireless AP</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('8\\n')" title="QRCode Generator">8 — QRCode</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('9\\n')" title="Powershell Attack Vectors">9 — PowerShell</button>
              <button class="btn btn-outline btn-sm set-menu-btn" onclick="setSend('10\\n')">10 — SMS Spoofing</button>
            </div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">NAVIGATION</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <button class="btn btn-outline btn-sm" onclick="setSend('99\\n')" style="color:var(--text2)">&#8592; Back / 99</button>
              <button class="btn btn-outline btn-sm" onclick="setSpecialKey('ctrl_c')" style="color:var(--yellow)">&#9679; Ctrl+C</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('q\\n')" style="color:var(--text2)">q — Quit prompt</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('exit\\n')" style="color:var(--text2)">exit</button>
              <button class="btn btn-outline btn-sm" onclick="setSend('\\n')" style="color:var(--text2)">&#9166; Enter</button>
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
      </div>'''


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 3 — HTML JS: Replace runSetToolkit() with full PTY session management
# ══════════════════════════════════════════════════════════════════════════════

OLD_SET_JS = '''/* ==== SOCIAL ENGINEERING TOOLS ==== */
function renderSocialTool(toolObj,d){
  var html=\'<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">\'+(d.tool||\'tool\').toUpperCase()+\'</div><div class="stat-lbl">TOOL</div></div><div class="stat"><div class="stat-val">\'+(d.exit_code===null?\'--\':d.exit_code)+\'</div><div class="stat-lbl">EXIT CODE</div></div><div class="stat"><div class="stat-val">\'+(d.duration_ms||0)+\'</div><div class="stat-lbl">DURATION (ms)</div></div></div>\';
  html+=\'<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Command Executed</div><div style="font-family:var(--mono);font-size:11px;color:var(--text2);word-break:break-all">\'+(d.command||\'n/a\')+\'</div></div>\';
  html+=\'<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">stdout</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">\'+(d.stdout||\'(empty)\')+\'</pre></div>\';
  html+=\'<div class="card card-p"><div class="card-title" style="margin-bottom:8px">stderr</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">\'+(d.stderr||\'(empty)\')+\'</pre></div>\';
  toolObj.res(html);
}
async function runSetToolkit(){
  var op=document.getElementById(\'set-op\').value, args=document.getElementById(\'set-args\').value.trim(), timeout=parseInt(document.getElementById(\'set-timeout\').value||\'90\',10);
  var btn=document.getElementById(\'set-btn\');btn.disabled=true;btn.innerHTML=\'<span class="spin"></span> Running...\';
  setTool.start();setTool.log(\'Executing SET operation: \'+op,\'i\');
  try{
    var r=await fetchWithTimeout(\'/social-tools/run\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({tool:\'setoolkit\',operation:op,args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),\'set\');
    var d=await r.json();setTool.end();if(d.error){setTool.err(d.error);}else{setTool.log(\'SET completed\',\'s\');renderSocialTool(setTool,d);}
  }catch(e){setTool.end();setTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML=\'RUN SET\';}
}'''

NEW_SET_JS = '''/* ==== SET INTERACTIVE TERMINAL ==== */
var _setSid = null;
var _setES  = null;
var _setHistory = [];
var _setHistIdx = -1;
var _setAnsiRe  = /[\\x1B\\x9B][[\\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]/g;
var _setCRRe    = /\\r/g;

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
  if (launch) launch.disabled      = showKill;
}

async function setLaunch() {
  // Kill any existing session first
  if (_setSid) { await setKill(); }
  setTermClear();
  _setAppend('Launching SET session...\\n');
  _setSetStatus('Connecting...', 'var(--yellow)', false);

  try {
    var r = await fetch('/api/set/session/new', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    });
    var d = await r.json();
    if (d.error) {
      _setAppend('[ERROR] ' + d.error + '\\n');
      _setSetStatus('Error — SET not found', 'var(--red)', false);
      showToast('SET Error', d.error, 'error', 7000);
      return;
    }
    _setSid = d.session_id;
    _setAppend('[+] Session started (binary: ' + d.binary + ')\\n');
    _setSetStatus('Session active', 'var(--green)', true);
    showToast('SET Launched', 'Interactive terminal ready', 'success', 3000);
    _setStartStream();
  } catch(e) {
    _setAppend('[ERROR] ' + e.message + '\\n');
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
        _setAppend(msg.text || '\\n[Session ended]\\n');
        _setSetStatus('Session ended', 'var(--text3)', false);
        _setES.close(); _setES = null; _setSid = null;
      } else if (msg.type === 'error') {
        _setAppend('[ERROR] ' + msg.text + '\\n');
        _setSetStatus('Error', 'var(--red)', false);
      }
      // heartbeat: ignore
    } catch(e) {}
  };

  _setES.onerror = function() {
    _setAppend('\\n[Stream lost — session may have ended]\\n');
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
  _setAppend('\\n[Session killed]\\n');
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
    _setAppend('[send error] ' + e.message + '\\n');
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
  setSend(val + '\\n');
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
  var html=\'<div class="stats" style="margin-bottom:14px"><div class="stat"><div class="stat-val">\'+(d.tool||\'tool\').toUpperCase()+\'</div><div class="stat-lbl">TOOL</div></div><div class="stat"><div class="stat-val">\'+(d.exit_code===null?\'--\':d.exit_code)+\'</div><div class="stat-lbl">EXIT CODE</div></div><div class="stat"><div class="stat-val">\'+(d.duration_ms||0)+\'</div><div class="stat-lbl">DURATION (ms)</div></div></div>\';
  html+=\'<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">Command Executed</div><div style="font-family:var(--mono);font-size:11px;color:var(--text2);word-break:break-all">\'+(d.command||\'n/a\')+\'</div></div>\';
  html+=\'<div class="card card-p" style="margin-bottom:10px"><div class="card-title" style="margin-bottom:8px">stdout</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">\'+(d.stdout||\'(empty)\')+\'</pre></div>\';
  html+=\'<div class="card card-p"><div class="card-title" style="margin-bottom:8px">stderr</div><pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">\'+(d.stderr||\'(empty)\')+\'</pre></div>\';
  toolObj.res(html);
}
async function runSetToolkit(){
  /* SET now uses the interactive terminal above — this stub keeps
     any residual references from breaking the page. */
  setLaunch();
}'''


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 4 — CSS: Add SET terminal styling
# ══════════════════════════════════════════════════════════════════════════════

OLD_CSS_ANCHOR = '''::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}'''

NEW_CSS_ANCHOR = '''::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
/* SET Terminal */
#set-terminal-output{scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
#set-terminal-output::-webkit-scrollbar{width:5px}
#set-terminal-output::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.set-menu-btn{font-family:var(--mono);font-size:11px;padding:4px 10px}
.set-menu-btn:hover{background:var(--bg3);color:var(--text);transform:scale(1.03)}'''


# ══════════════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════════════

PATCHES = [
    ("api_server.py", [
        ("SET: add PTY session manager + /api/set/* routes",
         OLD_SOCIAL_ANCHOR, NEW_SOCIAL_ANCHOR),
        ("SET: replace old page HTML with interactive terminal UI",
         OLD_SET_PAGE, NEW_SET_PAGE),
        ("SET: replace runSetToolkit() JS with full PTY client",
         OLD_SET_JS, NEW_SET_JS),
        ("SET: add terminal CSS overrides",
         OLD_CSS_ANCHOR, NEW_CSS_ANCHOR),
    ]),
]


def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║  VulnScan Pro — Patch: SET Interactive Terminal     ║" + RESET)
    print(BOLD + CYAN + "║  PTY-based full menu navigation in the browser      ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py", "backend.py"] if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Not in project root. Missing: " + ", ".join(missing) + RESET)
        print("  Run: cd ~/vulnscan && python3 patch_set.py")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    for fname, changes in PATCHES:
        print(BOLD + f"  ── {fname}" + RESET)
        patch(fname, changes)
        print()

    if R["files"]:
        print(BOLD + "  Syntax checks:" + RESET)
        for p in R["files"]:
            flag, err = syntax(p)
            if flag:
                ok(f"{p} — OK")
            else:
                fail(f"{p} — SYNTAX ERROR:\n    {err}")
        print()

    print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{R['applied']}{RESET}  |  "
        f"Skipped : {DIM}{R['skipped']}{RESET}  |  "
        f"Failed  : {RED if R['failed'] else DIM}{R['failed']}{RESET}"
    )
    print()

    if R["files"]:
        for f in R["files"]:
            print(f"  {GREEN}✓{RESET}  {f}  {DIM}(backup: {f}.*.bak){RESET}")
        print()

    if R["applied"] > 0:
        print(f"  {YELLOW}Restart required:{RESET}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
        print()
        print(f"  {GREEN}What changed:{RESET}")
        print(f"    {GREEN}✓{RESET} New routes: /api/set/session/new, /stream, /input, /kill, /sessions")
        print(f"    {GREEN}✓{RESET} SET page now shows a live PTY terminal with scrollable output")
        print(f"    {GREEN}✓{RESET} Quick-select buttons for all main menu options (1–10 + sub-menus)")
        print(f"    {GREEN}✓{RESET} Inline text input with history (↑/↓), Ctrl+C, Ctrl+D support")
        print(f"    {GREEN}✓{RESET} Session auto-killed on TTL (30 min) + kill button in UI")
        print(f"    {GREEN}✓{RESET} All other pages (Gophish, Evilginx2, ShellPhish) unchanged")
        print()
        print(f"  {CYAN}Install SET if not present:{RESET}")
        print(f"    sudo apt install set")
        print(f"    OR: git clone https://github.com/trustedsec/social-engineer-toolkit")
        print(f"        cd social-engineer-toolkit && pip3 install -r requirements.txt")
        print(f"        python3 setup.py")
    elif R["skipped"] > 0:
        print(f"  {GREEN}Already up to date — no restart needed.{RESET}")

    print()


if __name__ == "__main__":
    main()
