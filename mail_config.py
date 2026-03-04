#!/usr/bin/env python3
"""
Email configuration for VulnScan Pro
Edit SMTP settings below to enable email verification
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Configure these ────────────────────────────
APP_URL      = "http://161.118.189.254:5000"  # Change to your server URL
SMTP_HOST    = "smtp.gmail.com"               # or smtp.outlook.com etc
SMTP_PORT    = 587
SMTP_USER    = "labpnet33@gmail.com"          # Your email
SMTP_PASS    = "hkls wpey nvxi bgwh"          # Gmail: use App Password
FROM_EMAIL   = "VulnScan Pro <labpnet33@gmail.com>"
# ──────────────────────────────────────────────

def send_mail(to_email, subject, body, is_html=False):
    try:
        msg = MIMEMultipart()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html" if is_html else "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[+] Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False
