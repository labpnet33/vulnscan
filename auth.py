#!/usr/bin/env python3
"""
Authentication module for VulnScan Pro
Handles: register, login, logout, verify email, password reset, session management
"""
import os, secrets, hashlib, re, string
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session
from database import (get_user_by_username, get_user_by_email, get_user_by_id,
                      get_user_by_token, create_user, update_user, verify_user, delete_user,
                      update_last_login, audit)

SECRET_KEY = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")

# ── Password hashing ───────────────────────────
def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"

def verify_password(password, stored):
    try:
        salt, h = stored.split(":")
        new_h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return secrets.compare_digest(h, new_h.hex())
    except Exception:
        return False

# ── Token generation ───────────────────────────
def gen_token(length=32):
    return secrets.token_urlsafe(length)

# ── Validation ─────────────────────────────────
def validate_password(pwd):
    if len(pwd) < 8: return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', pwd): return False, "Password must contain an uppercase letter"
    if not re.search(r'[0-9]', pwd): return False, "Password must contain a number"
    return True, "OK"

def validate_email(email):
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))

def validate_username(username):
    if len(username) < 3: return False, "Username must be at least 3 characters"
    if len(username) > 30: return False, "Username too long"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username): return False, "Username can only contain letters, numbers, _ and -"
    return True, "OK"

# ── Session helpers ────────────────────────────
def get_current_user():
    uid = session.get("user_id")
    if not uid: return None
    return get_user_by_id(uid)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Login required", "redirect": "/login"}), 401
        if not user.get("is_active"):
            session.clear()
            return jsonify({"error": "Account disabled"}), 403
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Login required", "redirect": "/login"}), 401
        if user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def optional_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# ── Email sending ──────────────────────────────
def send_verification_email(email, username, token):
    try:
        from mail_config import send_mail, APP_URL
        subject = "Verify your VulnScan Pro account"
        link = f"{APP_URL}/verify/{token}"
        body = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:Helvetica,sans-serif;background-color:#04040a;color:#e8e8f0;margin:0;padding:0}}
.container{{background:#0d0d18;border:1px solid #16162a;border-radius:12px;max-width:600px;margin:20px auto;overflow:hidden}}
.header{{background:linear-gradient(90deg,#00e5ff,#b06fff);padding:30px;text-align:center}}
.header h1{{margin:0;color:white;font-size:28px;font-weight:800}}
.content{{padding:40px 30px}}
.content h2{{color:#00e5ff;font-size:20px;margin-top:0}}
.content p{{color:#c0c0d0;line-height:1.8;font-size:14px}}
.button{{display:block;width:fit-content;background:linear-gradient(135deg,#ff3366,#ff6b35);color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;margin:25px 0}}
.warning{{background:#16162a;border-left:4px solid #ffd60a;padding:12px 15px;margin:20px 0;border-radius:4px;font-size:12px;color:#c0c0d0}}
.footer{{background:#0d0d18;padding:20px 30px;text-align:center;border-top:1px solid #16162a;font-size:11px;color:#5a5a8a}}
code{{background:#16162a;padding:8px 12px;border-radius:4px;word-break:break-all;display:block;margin-top:8px}}
</style></head><body>
<div class="container">
  <div class="header"><h1>🔐 VulnScan Pro</h1></div>
  <div class="content">
    <h2>Welcome, {username}!</h2>
    <p>Thank you for registering. Click below to verify your email:</p>
    <a href="{link}" class="button">VERIFY EMAIL ADDRESS</a>
    <p style="text-align:center;color:#5a5a8a;font-size:12px">Or copy this link:<code>{link}</code></p>
    <div class="warning">⏰ <strong>Link expires in 24 hours.</strong> If you did not register, ignore this email.</div>
  </div>
  <div class="footer"><p>© 2024 VulnScan Pro. Security Intelligence Platform.</p></div>
</div></body></html>"""
        return send_mail(email, subject, body, is_html=True)
    except ImportError:
        print(f"[!] Email not configured. Verify token for {username}: {token}")
        return True
    except Exception as e:
        print(f"[!] Email send failed: {e}")
        return False

def send_reset_email(email, username, token):
    try:
        from mail_config import send_mail, APP_URL
        subject = "VulnScan Pro — Password Reset"
        link = f"{APP_URL}/reset-password/{token}"
        body = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:Helvetica,sans-serif;background-color:#04040a;color:#e8e8f0;margin:0;padding:0}}
.container{{background:#0d0d18;border:1px solid #16162a;border-radius:12px;max-width:600px;margin:20px auto;overflow:hidden}}
.header{{background:linear-gradient(90deg,#ff6b35,#ff3366);padding:30px;text-align:center}}
.header h1{{margin:0;color:white;font-size:28px;font-weight:800}}
.content{{padding:40px 30px}}
.content h2{{color:#ff6b35;font-size:20px;margin-top:0}}
.content p{{color:#c0c0d0;line-height:1.8;font-size:14px}}
.button{{display:block;width:fit-content;background:linear-gradient(135deg,#00e5ff,#00ff9d);color:#04040a;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;margin:25px 0}}
.alert{{background:#1a1a2e;border-left:4px solid #ff3366;padding:12px 15px;margin:20px 0;border-radius:4px;font-size:12px;color:#c0c0d0}}
.footer{{background:#0d0d18;padding:20px 30px;text-align:center;border-top:1px solid #16162a;font-size:11px;color:#5a5a8a}}
code{{background:#16162a;padding:8px 12px;border-radius:4px;word-break:break-all;display:block;margin-top:8px}}
</style></head><body>
<div class="container">
  <div class="header"><h1>🔑 Password Reset</h1></div>
  <div class="content">
    <h2>Reset Your Password</h2>
    <p>Hi {username},</p>
    <p>Click the button below to set a new password:</p>
    <a href="{link}" class="button">RESET PASSWORD</a>
    <p style="text-align:center;color:#5a5a8a;font-size:12px">Or copy this link:<code>{link}</code></p>
    <div class="alert">⏱️ <strong>Link expires in 1 hour.</strong> If you did not request this, ignore this email.</div>
  </div>
  <div class="footer"><p>© 2024 VulnScan Pro. Security Intelligence Platform.</p></div>
</div></body></html>"""
        return send_mail(email, subject, body, is_html=True)
    except Exception as e:
        print(f"[!] Reset email failed: {e}")
        return False

def generate_temp_password(length=14):
    chars = string.ascii_letters + string.digits
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        ok, _ = validate_password(pwd)
        if ok:
            return pwd

def send_admin_created_account_email(email, username, temp_password):
    try:
        from mail_config import send_mail
        subject = "VulnScan Pro — Your account has been created"
        body = f"""Hello {username},

An administrator created your VulnScan Pro account.

Username: {username}
Temporary password: {temp_password}

Please login and change your password immediately from the Profile page.
"""
        return send_mail(email, subject, body, is_html=False)
    except Exception as e:
        print(f"[!] Admin-created account email failed: {e}")
        return False

# ── Auth routes registration ────────────────────
def register_auth_routes(app):

    @app.route("/api/register", methods=["POST"])
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
        ph = hash_password(password)

        from database import get_db
        con = get_db()
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        con.close()
        role = "admin" if count == 0 else "user"
        # Always require email verification, including the first admin account.
        # This ensures every registration triggers verification email delivery.
        is_verified = 0

        ok, msg = create_user(username, email, ph, full_name, role, is_verified, token)
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
        })

    @app.route("/api/login", methods=["POST"])
    def api_login():
        d = request.get_json() or {}
        username = d.get("username", "").strip()
        password = d.get("password", "")

        user = get_user_by_username(username)
        if not user: return jsonify({"error": "Invalid username or password"}), 401
        if not verify_password(password, user["password_hash"]):
            audit(user["id"], username, "LOGIN_FAIL", ip=request.remote_addr)
            return jsonify({"error": "Invalid username or password"}), 401
        if not user["is_active"]: return jsonify({"error": "Account is disabled. Contact admin."}), 403
        if not user["is_verified"]: return jsonify({"error": "Please verify your email first. Check your inbox.", "unverified": True}), 403

        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        update_last_login(user["id"], request.remote_addr)
        audit(user["id"], username, "LOGIN", ip=request.remote_addr, ua=request.headers.get("User-Agent", ""))

        return jsonify({
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", "")
        })

    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        username = session.get("username", "")
        uid = session.get("user_id")
        if uid: audit(uid, username, "LOGOUT", ip=request.remote_addr)
        session.clear()
        return jsonify({"success": True})

    @app.route("/api/me")
    def api_me():
        user = get_current_user()
        if not user: return jsonify({"logged_in": False})
        return jsonify({
            "logged_in": True,
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "created_at": user.get("created_at", ""),
            "last_login": user.get("last_login", ""),
            "login_count": user.get("login_count", 0)
        })

    @app.route("/api/verify/<token>")
    def api_verify(token):
        if verify_user(token):
            user = get_user_by_token(token)
            if user: audit(user["id"], user["username"], "EMAIL_VERIFIED", ip=request.remote_addr)
            return jsonify({"success": True, "message": "Email verified! You can now login."})
        return jsonify({"error": "Invalid or expired verification link"}), 400

    @app.route("/api/forgot-password", methods=["POST"])
    def api_forgot():
        d = request.get_json() or {}
        email = d.get("email", "").strip()
        user = get_user_by_email(email)
        if not user:
            return jsonify({"success": True, "message": "If that email exists, a reset link was sent."})
        token = gen_token()
        expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        update_user(user["id"], reset_token=token, reset_expires=expires)
        send_reset_email(email, user["username"], token)
        audit(user["id"], user["username"], "PASSWORD_RESET_REQUEST", ip=request.remote_addr)
        return jsonify({"success": True, "message": "If that email exists, a reset link was sent."})

    @app.route("/api/reset-password", methods=["POST"])
    def api_reset():
        d = request.get_json() or {}
        token = d.get("token", "")
        password = d.get("password", "")
        user = get_user_by_token(token, "reset")
        if not user: return jsonify({"error": "Invalid or expired reset link"}), 400
        expires = user.get("reset_expires", "")
        if expires and datetime.utcnow() > datetime.fromisoformat(expires):
            return jsonify({"error": "Reset link has expired"}), 400
        ok, msg = validate_password(password)
        if not ok: return jsonify({"error": msg}), 400
        ph = hash_password(password)
        update_user(user["id"], password_hash=ph, reset_token=None, reset_expires=None)
        audit(user["id"], user["username"], "PASSWORD_RESET", ip=request.remote_addr)
        return jsonify({"success": True, "message": "Password updated. You can now login."})

    @app.route("/api/change-password", methods=["POST"])
    @login_required
    def api_change_password():
        user = get_current_user()
        d = request.get_json() or {}
        old_pwd = d.get("old_password", "")
        new_pwd = d.get("new_password", "")
        if not verify_password(old_pwd, user["password_hash"]):
            return jsonify({"error": "Current password is incorrect"}), 400
        ok, msg = validate_password(new_pwd)
        if not ok: return jsonify({"error": msg}), 400
        update_user(user["id"], password_hash=hash_password(new_pwd))
        audit(user["id"], user["username"], "PASSWORD_CHANGE", ip=request.remote_addr)
        return jsonify({"success": True, "message": "Password changed successfully"})

    @app.route("/api/profile", methods=["POST"])
    @login_required
    def api_profile():
        user = get_current_user()
        d = request.get_json() or {}
        full_name = d.get("full_name", "").strip()[:100]
        update_user(user["id"], full_name=full_name)
        return jsonify({"success": True, "message": "Profile updated"})

    # ── Admin routes ──────────────────────────
    @app.route("/api/admin/users")
    @admin_required
    def api_admin_users():
        from database import get_all_users
        return jsonify(get_all_users())

    @app.route("/api/admin/users/create", methods=["POST"])
    @admin_required
    def api_admin_create_user():
        import threading
        d = request.get_json() or {}
        full_name = d.get("full_name", "").strip()
        username = d.get("username", "").strip()
        email = d.get("email", "").strip()

        ok, msg = validate_username(username)
        if not ok: return jsonify({"error": msg}), 400
        if not validate_email(email): return jsonify({"error": "Invalid email address"}), 400
        if get_user_by_username(username): return jsonify({"error": "Username already taken"}), 409
        if get_user_by_email(email): return jsonify({"error": "Email already registered"}), 409

        temp_password = generate_temp_password()
        ph = hash_password(temp_password)
        ok, msg = create_user(username, email, ph, full_name, role="user", is_verified=1, verify_token="")
        if not ok: return jsonify({"error": msg}), 409

        current = get_current_user()
        audit(current["id"], current["username"], "ADMIN_CREATE_USER", ip=request.remote_addr,
              ua=request.headers.get("User-Agent", ""), details=f"created={username}")

        # Send email in background thread so UI response is instant
        def _send_bg(em, un, pw):
            try:
                send_admin_created_account_email(em, un, pw)
            except Exception as e:
                print(f"[!] Background email failed for {un}: {e}")

        t = threading.Thread(target=_send_bg, args=(email, username, temp_password), daemon=True)
        t.start()

        return jsonify({"success": True, "message": f"User {username} created. Credentials are being emailed to {email}."})

    @app.route("/api/admin/users/<int:uid>/toggle", methods=["POST"])
    @admin_required
    def api_admin_toggle(uid):
        current = get_current_user()
        if uid == current["id"]: return jsonify({"error": "Cannot disable yourself"}), 400
        from database import toggle_user_active
        toggle_user_active(uid)
        return jsonify({"success": True})

    @app.route("/api/admin/users/<int:uid>/role", methods=["POST"])
    @admin_required
    def api_admin_role(uid):
        d = request.get_json() or {}
        role = d.get("role", "user")
        if role not in ["user", "admin"]: return jsonify({"error": "Invalid role"}), 400
        from database import set_user_role
        set_user_role(uid, role)
        return jsonify({"success": True})

    @app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
    @admin_required
    def api_admin_delete_user(uid):
        current = get_current_user()
        if uid == current["id"]: return jsonify({"error": "Cannot delete yourself"}), 400
        from database import delete_user
        delete_user(uid)
        return jsonify({"success": True})

    @app.route("/api/admin/stats")
    @admin_required
    def api_admin_stats():
        from database import get_scan_stats
        return jsonify(get_scan_stats())

    @app.route("/api/admin/audit")
    @admin_required
    def api_admin_audit():
        from database import get_audit_log
        limit = int(request.args.get("limit", 100))
        return jsonify(get_audit_log(limit))

    @app.route("/api/admin/scans")
    @admin_required
    def api_admin_scans():
        from database import get_history
        return jsonify(get_history(limit=200))
