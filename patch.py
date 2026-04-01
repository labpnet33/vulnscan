#!/usr/bin/env python3
"""
VulnScan Pro — Registration Fix Patch
======================================
Fixes: "Unexpected token '<', <!DOCTYPE... is not valid JSON" on registration.

Root cause: auth.py calls get_db().execute("SELECT COUNT(*) FROM users")
but get_db() now returns a Supabase client, not a SQLite connection.
The SELECT COUNT(*) call crashes Flask which returns an HTML error page
instead of JSON — causing the frontend JSON parse error.

Run from your vulnscan project root:
    python3 patch_register_fix.py
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

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch_file(path, old, new, label):
    if not os.path.isfile(path):
        warn(f"'{label}': {path} not found — skipping")
        RESULTS["skipped"] += 1
        return
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if new in src:
        info(f"'{label}': already applied — skipping")
        RESULTS["skipped"] += 1
        return
    if old not in src:
        warn(f"'{label}': anchor not found in {path} — skipping")
        RESULTS["skipped"] += 1
        return
    backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"'{label}' applied to {path}")
    RESULTS["applied"] += 1

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

# ══════════════════════════════════════════════════════════════
# PATCH 1 — auth.py: Fix get_db() used as SQLite connection
# The old code: con = get_db(); count = con.execute("SELECT COUNT(*)...").fetchone()[0]
# The new code: use get_all_users() to count, which works with Supabase
# ══════════════════════════════════════════════════════════════

OLD_REGISTER_COUNT = '''        from database import get_db
        con = get_db()
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        con.close()
        role = "admin" if count == 0 else "user"'''

NEW_REGISTER_COUNT = '''        from database import get_all_users
        existing_users = get_all_users(limit=1)
        count = 0 if not existing_users else 1
        role = "admin" if count == 0 else "user"'''

# ══════════════════════════════════════════════════════════════
# PATCH 2 — auth.py: Wrap entire register route in try/except
# so ANY crash returns JSON instead of HTML 500
# ══════════════════════════════════════════════════════════════

OLD_REGISTER_START = '''    @app.route("/api/register", methods=["POST"])
    def api_register():
        d = request.get_json() or {}
        username = d.get("username", "").strip()
        email = d.get("email", "").strip()
        password = d.get("password", "")
        full_name = d.get("full_name", "").strip()

        ok, msg = validate_username(username)
        if not ok: return jsonify({"error": msg}), 400
        if not validate_email(email): return jsonify({"error": "Invalid email address"}), 400
        ok, msg = validate_password(password)
        if not ok: return jsonify({"error": msg}), 400

        # Server-side ToS acceptance check
        tos_accepted = d.get("tos_accepted", False)
        if not tos_accepted:
            return jsonify({"error": "You must accept the Terms of Use before registering."}), 400

        if get_user_by_username(username): return jsonify({"error": "Username already taken"}), 409
        if get_user_by_email(email): return jsonify({"error": "Email already registered"}), 409

        token = gen_token()
        verify_expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        ph = hash_password(password)

        from database import get_db
        con = get_db()
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        con.close()
        role = "admin" if count == 0 else "user"
        # Always require email verification, including the first admin account.
        # This ensures every registration triggers verification email delivery.
        is_verified = 0

        ok, msg = create_user(username, email, ph, full_name, role, is_verified, token, verify_expires)
        if not ok: return jsonify({"error": msg}), 409

        verification_email_sent = send_verification_email(email, username, token)
        if not verification_email_sent:
            audit(None, username, "VERIFY_EMAIL_SEND_FAIL", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

        audit(None, username, "REGISTER", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""),
              details=f"role={role}, verified={is_verified}")

        return jsonify({
            "success": True,
            "message": (
                "Account created! Check your email to verify."
                if verification_email_sent
                else "Account created, but verification email could not be sent. Please contact support."
            ),
            "verified": bool(is_verified),
            "role": role,
            "verification_email_sent": bool(verification_email_sent)
        })'''

NEW_REGISTER_START = '''    @app.route("/api/register", methods=["POST"])
    def api_register():
        try:
            d = request.get_json() or {}
            username = d.get("username", "").strip()
            email = d.get("email", "").strip()
            password = d.get("password", "")
            full_name = d.get("full_name", "").strip()

            ok_u, msg_u = validate_username(username)
            if not ok_u: return jsonify({"error": msg_u}), 400
            if not validate_email(email): return jsonify({"error": "Invalid email address"}), 400
            ok_p, msg_p = validate_password(password)
            if not ok_p: return jsonify({"error": msg_p}), 400

            # Server-side ToS acceptance check
            tos_accepted = d.get("tos_accepted", False)
            if not tos_accepted:
                return jsonify({"error": "You must accept the Terms of Use before registering."}), 400

            if get_user_by_username(username): return jsonify({"error": "Username already taken"}), 409
            if get_user_by_email(email): return jsonify({"error": "Email already registered"}), 409

            token = gen_token()
            verify_expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
            ph = hash_password(password)

            # Supabase-compatible user count (get_db() returns Supabase client, not SQLite)
            from database import get_all_users
            existing_users = get_all_users(limit=1)
            count = 0 if not existing_users else 1
            role = "admin" if count == 0 else "user"

            # Always require email verification, including the first admin account.
            is_verified = 0

            ok_c, msg_c = create_user(username, email, ph, full_name, role, is_verified, token, verify_expires)
            if not ok_c: return jsonify({"error": msg_c}), 409

            verification_email_sent = send_verification_email(email, username, token)
            if not verification_email_sent:
                audit(None, username, "VERIFY_EMAIL_SEND_FAIL", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

            audit(None, username, "REGISTER", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""),
                  details=f"role={role}, verified={is_verified}")

            return jsonify({
                "success": True,
                "message": (
                    "Account created! Check your email to verify."
                    if verification_email_sent
                    else "Account created, but verification email could not be sent. Please contact support."
                ),
                "verified": bool(is_verified),
                "role": role,
                "verification_email_sent": bool(verification_email_sent)
            })
        except Exception as e:
            import traceback
            print(f"[!] Registration error: {e}")
            traceback.print_exc()
            return jsonify({"error": f"Registration failed: {str(e)}"}), 500'''

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — Registration Fix Patch              ║" + X)
    print(B + C + "║   Fixes: JSON parse error on account creation        ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile("auth.py"):
        fail("Must be run from the VulnScan project root (auth.py not found)")

    info(f"Project root: {os.getcwd()}")
    print()

    hdr("STEP 1 — Patch auth.py")
    patch_file("auth.py", OLD_REGISTER_START, NEW_REGISTER_START, "Fix register route (Supabase-compatible)")

    hdr("STEP 2 — Syntax check")
    passed, err = syntax_check("auth.py")
    if passed:
        ok("auth.py syntax OK")
    else:
        warn(f"Syntax error:\n{err}")
        fail("Patch introduced a syntax error — restore from backup!")

    hdr("STEP 3 — Verify database.py is Supabase version")
    with open("database.py", "r") as f:
        db_content = f.read()
    if "supabase_config" in db_content and "sqlite3" not in db_content:
        ok("database.py is already Supabase version")
    else:
        warn("database.py still has SQLite — run patch_database.py first!")

    print()
    print(B + C + "══════════════════════════════════════════════════════" + X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {RESULTS['skipped']}  |  "
        f"Failed  : {(R if fc else '')}{fc}{X}"
    )
    print()
    print(f"  {G}What was fixed:{X}")
    print(f"    {G}✓{X}  auth.py register route no longer calls get_db() as SQLite")
    print(f"    {G}✓{X}  Uses get_all_users() instead — works with Supabase")
    print(f"    {G}✓{X}  Full try/except wrapper so crashes return JSON not HTML")
    print()
    print(f"  {Y}Restart server:{X}")
    print(f"    pkill -f api_server.py && cd ~/vulnscan && python3 api_server.py")
    print()


if __name__ == "__main__":
    main()
