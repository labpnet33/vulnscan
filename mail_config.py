#!/usr/bin/env python3
"""
Email configuration for VulnScan Pro
Edit SMTP settings below to enable email verification
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Configure via environment variables (recommended) ──────────────────
# Set these in your shell or systemd unit:
#   export VULNSCAN_APP_URL="https://your-server.com"
#   export VULNSCAN_SMTP_USER="you@gmail.com"
#   export VULNSCAN_SMTP_PASS="your-app-password"
import os as _mail_os
APP_URL    = _mail_os.environ.get("VULNSCAN_APP_URL",  "http://161.118.189.254:5000")
SMTP_HOST  = _mail_os.environ.get("VULNSCAN_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(_mail_os.environ.get("VULNSCAN_SMTP_PORT", "587"))
SMTP_USER  = _mail_os.environ.get("VULNSCAN_SMTP_USER", "labpnet33@gmail.com").strip()
# Some providers display app-passwords in 4-char groups (e.g. "abcd efgh ijkl mnop").
# Strip spaces so SMTP auth uses the raw token.
SMTP_PASS  = _mail_os.environ.get("VULNSCAN_SMTP_PASS", "hkls wpey nvxi bgwh").replace(" ", "").strip()
SMTP_TIMEOUT = int(_mail_os.environ.get("VULNSCAN_SMTP_TIMEOUT", "20"))
FROM_EMAIL = _mail_os.environ.get("VULNSCAN_FROM_EMAIL",
             f"VulnScan Pro <{SMTP_USER}>" if SMTP_USER else "VulnScan Pro <noreply@localhost>")
# ──────────────────────────────────────────────

def send_mail(to_email, subject, body, is_html=False):
    try:
        msg = MIMEMultipart()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html" if is_html else "plain"))
        smtp_cls = smtplib.SMTP_SSL if SMTP_PORT == 465 else smtplib.SMTP
        with smtp_cls(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            if SMTP_PORT != 465:
                server.ehlo()
                server.starttls()
                server.ehlo()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[+] Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False
