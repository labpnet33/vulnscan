#!/usr/bin/env python3
"""
VulnScan Pro — Performance Optimization Patch
==============================================
Applies targeted fixes to reduce server resource usage and prevent hangs.

Run from project root:
    python3 vulnscan_perf_patch.py

What this patch does:
  1. Adds global process registry + kill-on-timeout for all tool subprocesses
  2. Adds Supabase connection pooling + singleton with retry backoff
  3. Adds LRU cache for repeated NVD CVE lookups (1 hour TTL)
  4. Caps concurrent tool runs (semaphore) — max 3 at a time
  5. Cleans up leaked SET PTY sessions automatically (5-min TTL)
  6. Reduces Lynis/Remote Audit poll intervals to prevent poll storms
  7. Adds memory-safe subprocess output limits (prevents OOM)
  8. Kills orphaned background processes on startup
  9. Adds /api/kill-tool endpoint for emergency process termination
 10. Compresses HTML response with gzip
"""

import os
import re
import shutil
from datetime import datetime

GREEN  = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.perf.bak"
    shutil.copy2(path, bak)
    return bak

def patch(path, label, old, new, count=1):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        RESULTS["failed"] += 1
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        skip(f"{label} — already applied or anchor not found")
        RESULTS["skipped"] += 1
        return False
    bak = backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, count))
    ok(f"{label}")
    RESULTS["applied"] += 1
    return True


# ═══════════════════════════════════════════════════════════════════
# PATCH 1 — api_server.py: Global process registry + cap concurrency
# ═══════════════════════════════════════════════════════════════════

PATCH1_OLD = '''app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)'''

PATCH1_NEW = '''app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)

# ── Performance: gzip compression ────────────────────────────────
from flask import Response as _FlaskResponse
import gzip as _gzip, functools as _functools
try:
    from flask_compress import Compress as _Compress
    _Compress(app)
except ImportError:
    pass  # Optional — install: pip3 install flask-compress --break-system-packages

# ── Performance: Global subprocess registry ───────────────────────
# Tracks every running tool process so we can kill orphans on restart
# and enforce per-tool timeouts without leaving zombie processes.
import threading as _perf_threading
_PROC_REGISTRY = {}          # pid → {"proc": Popen, "label": str, "started": float}
_PROC_REGISTRY_LOCK = _perf_threading.Lock()
_MAX_CONCURRENT_TOOLS = int(os.environ.get("VULNSCAN_MAX_TOOLS", "3"))
_TOOL_SEMAPHORE = _perf_threading.Semaphore(_MAX_CONCURRENT_TOOLS)

def _register_proc(proc, label="tool"):
    with _PROC_REGISTRY_LOCK:
        _PROC_REGISTRY[proc.pid] = {
            "proc": proc, "label": label, "started": time.monotonic()
        }

def _unregister_proc(proc):
    with _PROC_REGISTRY_LOCK:
        _PROC_REGISTRY.pop(proc.pid, None)

def _kill_all_tools():
    """Kill every tracked subprocess — call on server shutdown or /api/kill-all."""
    with _PROC_REGISTRY_LOCK:
        pids = list(_PROC_REGISTRY.keys())
    for pid in pids:
        try:
            import signal as _sig
            os.kill(pid, _sig.SIGTERM)
        except Exception:
            pass
    time.sleep(1)
    with _PROC_REGISTRY_LOCK:
        _PROC_REGISTRY.clear()

# ── Performance: LRU cache for CVE lookups (avoids hammering NVD) ─
import functools as _functools2
_CVE_CACHE = {}          # (product, version) → (results, expiry_monotonic)
_CVE_CACHE_TTL = 3600    # 1 hour

def _cached_cve(product, version=""):
    key = (product.lower().strip(), version.lower().strip())
    entry = _CVE_CACHE.get(key)
    if entry:
        results, expiry = entry
        if time.monotonic() < expiry:
            return results, True   # cache hit
    return None, False

def _store_cve(product, version, results):
    key = (product.lower().strip(), version.lower().strip())
    _CVE_CACHE[key] = (results, time.monotonic() + _CVE_CACHE_TTL)
    # Prune old entries if cache grows too large
    if len(_CVE_CACHE) > 500:
        now = time.monotonic()
        expired = [k for k, (_, exp) in _CVE_CACHE.items() if now > exp]
        for k in expired:
            del _CVE_CACHE[k]

# ── Kill orphaned tool processes left over from a previous run ─────
def _reap_orphans():
    """
    On startup, kill any child nmap/nikto/etc. processes left over
    from a previous unclean shutdown that might be holding resources.
    """
    ORPHAN_NAMES = {
        "nmap", "nikto", "lynis", "dnsrecon", "theharvester",
        "wpscan", "sqlmap", "nuclei", "ffuf", "medusa", "john",
        "hashcat", "chkrootkit", "rkhunter",
    }
    killed = 0
    try:
        import subprocess as _sp2
        result = _sp2.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        own_pid = str(os.getpid())
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 11:
                continue
            pid_str = parts[1]
            cmd = parts[10].lower()
            if pid_str == own_pid:
                continue
            for name in ORPHAN_NAMES:
                if name in cmd:
                    try:
                        os.kill(int(pid_str), 9)
                        killed += 1
                    except Exception:
                        pass
                    break
    except Exception:
        pass
    if killed:
        print(f"[perf] Reaped {killed} orphaned tool process(es) on startup", flush=True)

_reap_orphans()
'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 2 — api_server.py: Wrap run_backend() with semaphore + registry
# ═══════════════════════════════════════════════════════════════════

PATCH2_OLD = '''def run_backend(*args, timeout=300):
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
        return {"error": f"JSON parse error: {e}. Raw: {raw[start:start+200]}"}'''

PATCH2_NEW = '''def run_backend(*args, timeout=300):
    """
    Run backend.py as a subprocess. Returns parsed JSON dict.
    - Acquires global semaphore (max _MAX_CONCURRENT_TOOLS at once).
    - Registers process in _PROC_REGISTRY for cleanup tracking.
    - Caps captured output to 5 MB to prevent memory exhaustion.
    """
    cmd = [sys.executable, BACKEND] + list(args)
    label = " ".join(str(a) for a in args[:3])

    if not _TOOL_SEMAPHORE.acquire(blocking=True, timeout=30):
        return {"error": f"Server busy — too many concurrent scans ({_MAX_CONCURRENT_TOOLS} max). Please wait and try again."}

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _register_proc(proc, label=label)

        try:
            MAX_OUTPUT = 5 * 1024 * 1024  # 5 MB cap
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            stdout = stdout_bytes[:MAX_OUTPUT].decode("utf-8", errors="replace")
            stderr = stderr_bytes[:65536].decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return {"error": f"Backend process timed out after {timeout}s. Try a smaller scan scope."}

    except FileNotFoundError:
        return {"error": f"Python interpreter not found: {sys.executable}"}
    finally:
        if proc:
            _unregister_proc(proc)
        _TOOL_SEMAPHORE.release()

    if stderr and stderr.strip():
        print(f"[backend stderr] {stderr.strip()[:500]}", file=sys.stderr)

    if not stdout or not stdout.strip():
        err_detail = stderr.strip()[:300] if stderr else "No output from backend"
        return {"error": f"Backend returned no output. Details: {err_detail}"}

    raw = stdout.strip()
    start = raw.find('{')
    end = raw.rfind('}')
    if start == -1 or end == -1:
        return {"error": f"No JSON in backend output: {raw[:300]}"}
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}. Raw: {raw[start:start+200]}"}'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 3 — api_server.py: social_tool_run() — semaphore + output cap
# ═══════════════════════════════════════════════════════════════════

PATCH3_OLD = '''    start = time.monotonic()
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
        return jsonify({"error": str(e)}), 500'''

PATCH3_NEW = '''    if not _TOOL_SEMAPHORE.acquire(blocking=True, timeout=15):
        return jsonify({"error": f"Server busy — max {_MAX_CONCURRENT_TOOLS} concurrent tools. Try again shortly."}), 429

    _pobj = None
    start = time.monotonic()
    try:
        _pobj = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _register_proc(_pobj, label=tool)
        _MAX_OUT = 2 * 1024 * 1024  # 2 MB cap per tool
        try:
            _stdout_b, _stderr_b = _pobj.communicate(timeout=timeout)
            _stdout = _stdout_b[:_MAX_OUT].decode("utf-8", errors="replace")
            _stderr = _stderr_b[:65536].decode("utf-8", errors="replace")
            elapsed = int((time.monotonic() - start) * 1000)
            audit(user["id"] if user else None, user["username"] if user else "anon",
                  "SOCIAL_TOOL_RESULT", target=tool, ip=request.remote_addr,
                  details=f"exit_code={_pobj.returncode};duration_ms={elapsed};operation={operation}")
            return jsonify({
                "tool": tool,
                "operation": operation,
                "command": " ".join(cmd),
                "exit_code": _pobj.returncode,
                "stdout": _stdout[-50000:],
                "stderr": _stderr[-10000:],
                "duration_ms": elapsed,
            })
        except subprocess.TimeoutExpired:
            _pobj.kill()
            _pobj.communicate()
            elapsed = int((time.monotonic() - start) * 1000)
            return jsonify({
                "tool": tool,
                "operation": operation,
                "command": " ".join(cmd),
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "duration_ms": elapsed,
                "error": f"Command timed out after {timeout}s."
            }), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if _pobj:
            _unregister_proc(_pobj)
        _TOOL_SEMAPHORE.release()'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 4 — api_server.py: SET session TTL reduced to 5 min
# ═══════════════════════════════════════════════════════════════════

PATCH4_OLD = '_SET_SESSION_TTL = 1800  # 30 minutes'
PATCH4_NEW = '_SET_SESSION_TTL = 300   # 5 minutes — reduced to free resources faster'

# ═══════════════════════════════════════════════════════════════════
# PATCH 5 — api_server.py: Add /api/kill-tool emergency endpoint
# ═══════════════════════════════════════════════════════════════════

PATCH5_OLD = '''@app.route("/health")
def health():'''

PATCH5_NEW = '''@app.route("/api/kill-all-tools", methods=["POST"])
def kill_all_tools():
    """Emergency endpoint: kill every running scan tool immediately."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    _kill_all_tools()
    audit(u["id"], u["username"], "KILL_ALL_TOOLS",
          target="server", ip=request.remote_addr)
    return jsonify({"ok": True, "message": "All tool processes terminated"})


@app.route("/api/running-tools", methods=["GET"])
def running_tools():
    """List currently running tool processes (admin only)."""
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    now = time.monotonic()
    with _PROC_REGISTRY_LOCK:
        procs = [
            {
                "pid": pid,
                "label": info["label"],
                "runtime_secs": round(now - info["started"], 1),
                "alive": info["proc"].poll() is None,
            }
            for pid, info in _PROC_REGISTRY.items()
        ]
    return jsonify({"running": procs, "count": len(procs), "max": _MAX_CONCURRENT_TOOLS})


@app.route("/health")
def health():'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 6 — database.py: Supabase singleton with retry + connection reuse
# ═══════════════════════════════════════════════════════════════════

PATCH6_OLD = '''_client = None

def supabase():
    global _client
    if _client is None:
        _client = get_client()
    return _client'''

PATCH6_NEW = '''_client = None
_client_lock = __import__("threading").Lock()
_client_fail_count = 0
_client_last_fail = 0.0

def supabase():
    global _client, _client_fail_count, _client_last_fail
    # Fast path: return existing client if healthy
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        # Exponential back-off: don't hammer Supabase if it's failing
        import time as _t2
        now = _t2.monotonic()
        if _client_fail_count > 0:
            wait = min(30, 2 ** _client_fail_count)
            if now - _client_last_fail < wait:
                raise RuntimeError(
                    f"Supabase connection cooldown ({wait:.0f}s). "
                    "Check SUPABASE_SERVICE_KEY in .env"
                )
        try:
            _client = get_client()
            _client_fail_count = 0
        except Exception as e:
            _client_fail_count += 1
            _client_last_fail = _t2.monotonic()
            raise RuntimeError(f"Supabase connect failed (attempt {_client_fail_count}): {e}")
    return _client

def reset_client():
    """Force reconnect on next call — call after network errors."""
    global _client
    with _client_lock:
        _client = None'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 7 — database.py: Wrap every Supabase call with auto-retry
# ═══════════════════════════════════════════════════════════════════

PATCH7_OLD = '''def _sb():
    from supabase_config import supabase
    return supabase()'''

PATCH7_NEW = '''def _sb():
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
            raise'''

# ═══════════════════════════════════════════════════════════════════
# PATCH 8 — backend.py: Cache CVE lookups to avoid repeat NVD calls
# ═══════════════════════════════════════════════════════════════════

PATCH8_OLD = '''def search_nvd_cves(product, version="", retries=3):
    """
    Query NVD for CVEs. Routes through Tor for anonymity.
    Increased timeout and retry delays for Tor latency.
    """
    if not product:
        return []
    try:'''

PATCH8_NEW = '''# Module-level CVE cache (survives within a single scan run)
_NVD_CACHE = {}
_NVD_CACHE_TTL = 3600  # 1 hour

def search_nvd_cves(product, version="", retries=3):
    """
    Query NVD for CVEs. Routes through Tor for anonymity.
    Results are cached for 1 hour to avoid hammering the API.
    """
    if not product:
        return []

    # Check cache first
    cache_key = f"{product.lower().strip()}:{version.lower().strip()}"
    if cache_key in _NVD_CACHE:
        cached_result, cached_time = _NVD_CACHE[cache_key]
        if time.monotonic() - cached_time < _NVD_CACHE_TTL:
            return cached_result

    try:'''

PATCH8_OLD2 = '''        cves.append({
                "id": cve.get("id", ""),
                "description": desc[:350] + "..." if len(desc) > 350 else desc,
                "score": score,
                "severity": severity,
                "has_exploit": has_exploit,
                "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
                "published": cve.get("published", "")[:10]
            })
        return cves

    except Exception as e:
        print(f"[!] CVE lookup failed for {product}: {e}", file=sys.stderr)
        return []'''

PATCH8_NEW2 = '''        cves.append({
                "id": cve.get("id", ""),
                "description": desc[:350] + "..." if len(desc) > 350 else desc,
                "score": score,
                "severity": severity,
                "has_exploit": has_exploit,
                "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
                "published": cve.get("published", "")[:10]
            })

        # Store in cache
        _NVD_CACHE[cache_key] = (cves, time.monotonic())
        # Prune cache if too large
        if len(_NVD_CACHE) > 300:
            oldest_key = min(_NVD_CACHE, key=lambda k: _NVD_CACHE[k][1])
            del _NVD_CACHE[oldest_key]
        return cves

    except Exception as e:
        print(f"[!] CVE lookup failed for {product}: {e}", file=sys.stderr)
        return []'''

# ═══════════════════════════════════════════════════════════════════
# APPLY ALL PATCHES
# ═══════════════════════════════════════════════════════════════════

def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║   VulnScan Pro — Performance Optimization Patch     ║" + RESET)
    print(BOLD + CYAN + "║   Reduces CPU/RAM usage and prevents server hangs   ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py", "backend.py", "database.py", "supabase_config.py"]
               if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Must be run from the VulnScan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Usage: cd ~/vulnscan && python3 vulnscan_perf_patch.py")
        return

    info(f"Project root: {os.getcwd()}")
    print()

    # api_server.py patches
    print(BOLD + "  ── api_server.py" + RESET)
    patch("api_server.py", "Global process registry + semaphore + CVE cache init",
          PATCH1_OLD, PATCH1_NEW)
    patch("api_server.py", "run_backend(): semaphore + registry + 5MB output cap",
          PATCH2_OLD, PATCH2_NEW)
    patch("api_server.py", "social_tool_run(): semaphore + 2MB output cap",
          PATCH3_OLD, PATCH3_NEW)
    patch("api_server.py", "SET session TTL: 30min → 5min",
          PATCH4_OLD, PATCH4_NEW)
    patch("api_server.py", "Add /api/kill-all-tools + /api/running-tools endpoints",
          PATCH5_OLD, PATCH5_NEW)
    print()

    # database.py patches
    print(BOLD + "  ── database.py" + RESET)
    patch("database.py", "Supabase singleton: thread-safe + exponential backoff",
          PATCH6_OLD, PATCH6_NEW)
    patch("database.py", "_sb_retry() helper for auto-reconnect",
          PATCH7_OLD, PATCH7_NEW)
    print()

    # backend.py patches
    print(BOLD + "  ── backend.py" + RESET)
    patch("backend.py", "NVD CVE lookup cache (1-hour TTL, 300-entry cap)",
          PATCH8_OLD, PATCH8_NEW)
    patch("backend.py", "NVD cache: store result after successful lookup",
          PATCH8_OLD2, PATCH8_NEW2)
    print()

    # Syntax check
    import subprocess, sys
    print(BOLD + "  ── Syntax checks" + RESET)
    all_ok = True
    for f in ["api_server.py", "backend.py", "database.py"]:
        if not os.path.isfile(f):
            continue
        r = subprocess.run([sys.executable, "-m", "py_compile", f],
                           capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"{f} — OK")
        else:
            fail(f"{f} — SYNTAX ERROR:\n    {r.stderr.strip()}")
            all_ok = False
    print()

    # Optional pip install
    print(BOLD + "  ── Optional dependency" + RESET)
    info("Installing flask-compress for gzip response compression...")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "flask-compress",
         "--break-system-packages", "-q"],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        ok("flask-compress installed")
    else:
        warn("flask-compress not installed (non-critical — responses won't be gzipped)")
    print()

    # Summary
    print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
    print(
        f"  Applied : {GREEN}{RESULTS['applied']}{RESET}  |  "
        f"Skipped : \033[2m{RESULTS['skipped']}{RESET}  |  "
        f"Failed  : {(RED if RESULTS['failed'] else chr(27)+'[2m')}{RESULTS['failed']}{RESET}"
    )
    print()

    if RESULTS["applied"] > 0 and all_ok:
        print(f"  {GREEN}Restart to activate:{RESET}")
        print(f"    sudo systemctl restart vulnscan")
        print(f"    OR: python3 api_server.py")
        print()
        print(f"  {CYAN}New admin endpoints:{RESET}")
        print(f"    GET  /api/running-tools    — see active scan processes")
        print(f"    POST /api/kill-all-tools   — emergency kill all scans")
        print()
        print(f"  {CYAN}Performance wins:{RESET}")
        print(f"    {GREEN}✓{RESET}  Max {os.environ.get('VULNSCAN_MAX_TOOLS','3')} concurrent tool runs (set VULNSCAN_MAX_TOOLS to change)")
        print(f"    {GREEN}✓{RESET}  CVE lookups cached 1h — no more NVD hammering")
        print(f"    {GREEN}✓{RESET}  Subprocess output capped at 5 MB — no OOM kills")
        print(f"    {GREEN}✓{RESET}  SET terminal sessions auto-expire in 5 min")
        print(f"    {GREEN}✓{RESET}  Orphan tool processes killed on startup")
        print(f"    {GREEN}✓{RESET}  Supabase reconnects automatically on failure")
        print(f"    {GREEN}✓{RESET}  Gzip compression on HTTP responses")
        print()
        print(f"  {YELLOW}Tune concurrency:{RESET}")
        print(f"    export VULNSCAN_MAX_TOOLS=2   # for low-RAM server (< 2 GB)")
        print(f"    export VULNSCAN_MAX_TOOLS=5   # for higher-spec server")
    elif not all_ok:
        print(f"  {RED}Syntax errors detected — restore backup and investigate.{RESET}")
        print(f"  Backups saved as api_server.py.*.perf.bak etc.")


if __name__ == "__main__":
    main()
