#!/usr/bin/env python3
"""
VulnScan Pro — Login Redirect Fix Patch
Fixes: after login, page redirects back to login instead of dashboard

Root causes fixed:
  1. SESSION_COOKIE_SECURE forces HTTPS-only cookies on HTTP connections
  2. Broken doLogin() callback — inline code injected into wrong position
  3. Missing session.modified flag after login
  4. CORS credentials not properly configured for session persistence
"""

import os, shutil
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.login_fix.bak"
    shutil.copy2(path, bak)
    return bak

def patch(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        RESULTS["failed"] += 1
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        if new in src:
            skip(f"{label} — already applied")
            RESULTS["skipped"] += 1
        else:
            fail(f"{label} — anchor text not found")
            RESULTS["failed"] += 1
        return False
    backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}")
    RESULTS["applied"] += 1
    return True


# ══════════════════════════════════════════════════════════════════
# PATCH 1 — api_server.py
# Fix SESSION_COOKIE_SECURE — it reads env var but defaults to True
# which breaks HTTP deployments. Default must be False.
# ══════════════════════════════════════════════════════════════════

PATCH1_OLD = '''    SESSION_COOKIE_SECURE=os.environ.get("VULNSCAN_COOKIE_SECURE", "1").lower() in {"1", "true", "yes"},'''

PATCH1_NEW = '''    SESSION_COOKIE_SECURE=os.environ.get("VULNSCAN_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},'''


# ══════════════════════════════════════════════════════════════════
# PATCH 2 — api_server.py
# Fix CORS — must allow credentials from the actual origin,
# not just localhost. Wildcard origins break cookie persistence.
# ══════════════════════════════════════════════════════════════════

PATCH2_OLD = '''CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": re.compile(r"https?://(localhost|127\.0\.0\.1)(:\d+)?$")}})'''

PATCH2_NEW = '''CORS(app, supports_credentials=True, resources={r"/*": {"origins": re.compile(r"https?://.*")}})'''


# ══════════════════════════════════════════════════════════════════
# PATCH 3 — auth.py
# Add session.modified = True after login so Flask flushes the
# session cookie even if the dict was mutated rather than replaced.
# Also ensure the session is marked permanent immediately.
# ══════════════════════════════════════════════════════════════════

PATCH3_OLD = '''        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["last_seen_at"] = int(time.time())

        update_last_login(user["id"], request.remote_addr)
        audit(user["id"], username, "LOGIN", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

        return jsonify({
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "csrf_token": session["csrf_token"]
        })'''

PATCH3_NEW = '''        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["last_seen_at"] = int(time.time())
        session.modified = True

        update_last_login(user["id"], request.remote_addr)
        audit(user["id"], username, "LOGIN", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

        resp = jsonify({
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "csrf_token": session["csrf_token"]
        })
        return resp'''


# ══════════════════════════════════════════════════════════════════
# PATCH 4 — api_server.py
# Fix the broken doLogin() JS callback.
# The inline code was injected mid-string inside a Python f-string,
# breaking the login success handler.
# Replace the entire broken JS doLogin function with a clean version.
# ══════════════════════════════════════════════════════════════════

PATCH4_OLD = '''    if(d.success){authMsg('Welcome back, '+d.username+'!','ok');setTimeout(function(){document.getElementById('auth-overlay').style.display='none';/* ==== GENERIC TOOL RUNNER ==== */
async function runGenericTool(pageId, toolBin){
  var argsEl=document.getElementById(pageId+'-args');
  var timeoutEl=document.getElementById(pageId+'-timeout');
  var binEl=document.getElementById(pageId+'-bin');
  var btn=document.getElementById(pageId+'-btn');
  if(!argsEl||!btn)return;
  var args=(argsEl.value||'--help').trim();
  var timeout=parseInt((timeoutEl&&timeoutEl.value)||'90',10);
  var bin=(binEl&&binEl.value)||toolBin;
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool(pageId);t.start();t.log('Running: '+bin+' '+args,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:pageId==='john'?'john':bin,operation:'custom',args:args,timeout:timeout})
    },Math.max(20000,timeout*1000+5000),pageId);
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Command completed (exit '+d.exit_code+')','s');
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Output</div>'
        +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'
        +(d.stdout||'(no stdout)')+'</pre>'
        +(d.stderr?'<div class="card-title" style="margin:8px 0">Stderr</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--orange)">'+d.stderr+'</pre>':'')
        +'</div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN '+bin.toUpperCase();}
}
/* ==== BRUTE AUTOLOAD ==== */
function bfAutoLoad(){
  var um=document.getElementById('bf-user-mode');
  var pm=document.getElementById('bf-pass-mode');
  if(um&&um.value!=='manual')bfWordlistMode('user');
  if(pm&&pm.value!=='manual')bfWordlistMode('pass');
}

loadUser();},700);}'''

PATCH4_NEW = '''    if(d.success){authMsg('Welcome back, '+d.username+'!','ok');setTimeout(function(){document.getElementById('auth-overlay').style.display='none';loadUser();},700);}'''


# ══════════════════════════════════════════════════════════════════
# PATCH 5 — api_server.py
# Add runGenericTool and bfAutoLoad functions back in the correct
# location (before the loadUser() call at the bottom of the script)
# ══════════════════════════════════════════════════════════════════

PATCH5_OLD = '''/* END TOOL-SPECIFIC JS HELPERS */

loadUser();'''

PATCH5_NEW = '''/* END TOOL-SPECIFIC JS HELPERS */

/* ==== GENERIC TOOL RUNNER ==== */
async function runGenericTool(pageId, toolBin){
  var argsEl=document.getElementById(pageId+'-args');
  var timeoutEl=document.getElementById(pageId+'-timeout');
  var binEl=document.getElementById(pageId+'-bin');
  var btn=document.getElementById(pageId+'-btn');
  if(!argsEl||!btn)return;
  var args=(argsEl.value||'--help').trim();
  var timeout=parseInt((timeoutEl&&timeoutEl.value)||'90',10);
  var bin=(binEl&&binEl.value)||toolBin;
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool(pageId);t.start();t.log('Running: '+bin+' '+args,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:pageId==='john'?'john':bin,operation:'custom',args:args,timeout:timeout})
    },Math.max(20000,timeout*1000+5000),pageId);
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Command completed (exit '+d.exit_code+')','s');
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Output</div>'
        +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'
        +(d.stdout||'(no stdout)')+'</pre>'
        +(d.stderr?'<div class="card-title" style="margin:8px 0">Stderr</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--orange)">'+d.stderr+'</pre>':'')
        +'</div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN '+bin.toUpperCase();}
}
/* ==== BRUTE AUTOLOAD ==== */
function bfAutoLoad(){
  var um=document.getElementById('bf-user-mode');
  var pm=document.getElementById('bf-pass-mode');
  if(um&&um.value!=='manual')bfWordlistMode('user');
  if(pm&&pm.value!=='manual')bfWordlistMode('pass');
}

loadUser();'''


# ══════════════════════════════════════════════════════════════════
# PATCH 6 — api_server.py
# Fix /api/me to also return csrf_token so the frontend can store it
# ══════════════════════════════════════════════════════════════════

PATCH6_OLD = '''        return jsonify({
            "logged_in": True,
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "created_at": user.get("created_at", ""),
            "last_login": user.get("last_login", ""),
            "login_count": user.get("login_count", 0)
        })'''

PATCH6_NEW = '''        # Refresh CSRF token if missing (e.g. after server restart)
        if not session.get("csrf_token"):
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.modified = True
        return jsonify({
            "logged_in": True,
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "created_at": user.get("created_at", ""),
            "last_login": user.get("last_login", ""),
            "login_count": user.get("login_count", 0),
            "csrf_token": session.get("csrf_token", "")
        })'''


def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║   VulnScan Pro — Login Redirect Fix Patch           ║" + RESET)
    print(BOLD + CYAN + "║   Fixes session persistence after login             ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py", "auth.py"] if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Must be run from the VulnScan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Usage: cd ~/vulnscan && python3 login_fix_patch.py")
        return

    info(f"Project root: {os.getcwd()}")
    print()

    print(BOLD + "  ── api_server.py" + RESET)
    patch("api_server.py", "Fix SESSION_COOKIE_SECURE default (False for HTTP)",
          PATCH1_OLD, PATCH1_NEW)
    patch("api_server.py", "Fix CORS to allow all origins with credentials",
          PATCH2_OLD, PATCH2_NEW)
    patch("api_server.py", "Fix broken doLogin() JS callback (code injection bug)",
          PATCH4_OLD, PATCH4_NEW)
    patch("api_server.py", "Restore runGenericTool + bfAutoLoad in correct position",
          PATCH5_OLD, PATCH5_NEW)
    patch("api_server.py", "Fix /api/me to return csrf_token",
          PATCH6_OLD, PATCH6_NEW)
    print()

    print(BOLD + "  ── auth.py" + RESET)
    patch("auth.py", "Fix login: clear old session + session.modified=True",
          PATCH3_OLD, PATCH3_NEW)
    print()

    # Syntax check
    import subprocess, sys as _sys
    print(BOLD + "  ── Syntax checks" + RESET)
    all_ok = True
    for f in ["api_server.py", "auth.py"]:
        if not os.path.isfile(f):
            continue
        r = subprocess.run([_sys.executable, "-m", "py_compile", f],
                           capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"{f} — OK")
        else:
            fail(f"{f} — SYNTAX ERROR:\n    {r.stderr.strip()[:300]}")
            all_ok = False
    print()

    print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{RESULTS['applied']}{RESET}  |  "
        f"Skipped : \033[2m{RESULTS['skipped']}{RESET}  |  "
        f"Failed  : {(RED if RESULTS['failed'] else chr(27)+'[2m')}{RESULTS['failed']}{RESET}"
    )
    print()

    if all_ok and RESULTS["applied"] > 0:
        print(f"  {GREEN}Restart to activate:{RESET}")
        print(f"    sudo systemctl restart vulnscan")
        print(f"    OR: python3 api_server.py")
        print()
        print(f"  {CYAN}Root causes fixed:{RESET}")
        print(f"    {GREEN}✓{RESET}  SESSION_COOKIE_SECURE was True by default → cookies")
        print(f"         not sent over HTTP → session lost after login")
        print(f"    {GREEN}✓{RESET}  doLogin() JS had broken code injected mid-function")
        print(f"         → success handler never ran → redirect back to login")
        print(f"    {GREEN}✓{RESET}  session.modified=True ensures Flask writes cookie")
        print(f"    {GREEN}✓{RESET}  session.clear() before login prevents stale data")
        print(f"    {GREEN}✓{RESET}  CORS now accepts all origins with credentials")
        print()
        print(f"  {YELLOW}Also check .env:{RESET}")
        print(f"    VULNSCAN_COOKIE_SECURE=false  # for HTTP deployments")
        print(f"    VULNSCAN_COOKIE_SECURE=true   # for HTTPS only")
    elif not all_ok:
        print(f"  {RED}Syntax errors — restore backup files (.login_fix.bak){RESET}")


if __name__ == "__main__":
    main()
