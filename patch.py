#!/usr/bin/env python3
"""
VulnScan Pro — Patch Script
Adds Terms of Service / legal disclaimer checkbox to the registration form.
Run from project root: python3 patch.py
"""

import os
import re
import shutil
from datetime import datetime

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")

# ── Track changes ─────────────────────────────────────────────────────────────
changes_applied = 0
files_modified  = []
restart_needed  = False


def backup(path):
    """Create a timestamped .bak file before patching."""
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def patch_file(path, patches):
    """
    Apply a list of (description, old_text, new_text) patches to a file.
    Returns (applied_count, failed_count).
    """
    global changes_applied, files_modified, restart_needed

    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        return 0, len(patches)

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    applied = 0
    failed  = 0
    modified_content = content

    for desc, old, new in patches:
        if old in modified_content:
            modified_content = modified_content.replace(old, new, 1)
            ok(desc)
            applied += 1
        elif new in modified_content:
            ok(f"{desc}  (already applied — skipped)")
        else:
            fail(f"{desc}")
            failed += 1

    if applied > 0:
        bak = backup(path)
        info(f"Backup created: {bak}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified_content)
        changes_applied += applied
        if path not in files_modified:
            files_modified.append(path)
        restart_needed = True

    return applied, failed


# ══════════════════════════════════════════════════════════════════════════════
#  PATCH 1 — api_server.py  ·  Terms of Service checkbox in HTML
# ══════════════════════════════════════════════════════════════════════════════

# The ToS modal HTML — injected right before the closing </body> tag of the
# embedded HTML string inside api_server.py.
TOS_MODAL = r"""
<!-- ══ TERMS OF SERVICE MODAL ══ -->
<div id="tos-modal" style="display:none;position:fixed;inset:0;background:rgba(4,4,10,0.97);z-index:500;align-items:center;justify-content:center;backdrop-filter:blur(14px)" onclick="if(event.target===this)closeTos()">
  <div style="background:var(--s1);border:1px solid rgba(255,214,10,0.35);border-radius:18px;padding:36px;width:100%;max-width:620px;position:relative;margin:16px;max-height:90vh;overflow-y:auto">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <span style="font-size:28px">⚠️</span>
      <div>
        <div style="font-size:20px;font-weight:800;color:var(--yellow);letter-spacing:-0.5px">Legal Disclaimer & Terms of Use</div>
        <div style="font-size:11px;color:var(--m);font-family:'JetBrains Mono',monospace;letter-spacing:2px;margin-top:3px">READ CAREFULLY BEFORE REGISTERING</div>
      </div>
    </div>
    <div style="height:1px;background:linear-gradient(90deg,var(--yellow),transparent);margin-bottom:20px"></div>
    <div style="font-size:13px;line-height:1.9;color:#c0c0d0;font-family:'JetBrains Mono',monospace">

      <div style="background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.25);border-radius:8px;padding:14px;margin-bottom:16px">
        <strong style="color:var(--red)">⚠ AUTHORIZED USE ONLY</strong><br/>
        VulnScan Pro is a professional security assessment tool. You are <strong style="color:var(--red)">strictly prohibited</strong> from using this platform to scan, probe, attack, or enumerate any system, network, or web application that you do not own or have <strong>explicit written authorization</strong> to test.
      </div>

      <p><strong style="color:var(--yellow)">1. Sole Responsibility</strong><br/>
      By registering you acknowledge that <em>you</em> are entirely and solely responsible for all scans, queries, and actions performed from your account. The platform owner, developers, and hosting providers bear <strong>zero liability</strong> for any damage, data loss, legal consequence, or harm resulting from your use of this tool.</p>

      <p><strong style="color:var(--yellow)">2. No Illegal Activity</strong><br/>
      You agree NOT to use VulnScan Pro to conduct unauthorized access, denial-of-service attacks, credential stuffing, data exfiltration, or any other activity that violates local, national, or international law — including but not limited to the <em>Computer Fraud and Abuse Act (CFAA)</em>, the <em>Computer Misuse Act (UK)</em>, <em>EU Directive 2013/40/EU</em>, and equivalent legislation worldwide.</p>

      <p><strong style="color:var(--yellow)">3. Indemnification</strong><br/>
      You agree to indemnify, defend, and hold harmless the platform owner and all affiliated parties from any claims, damages, losses, liabilities, and costs (including attorney fees) arising from your use or misuse of this platform.</p>

      <p><strong style="color:var(--yellow)">4. Audit Logging</strong><br/>
      All scans and administrative actions are logged with timestamps, targets, and IP addresses. These logs may be provided to law enforcement upon valid legal request.</p>

      <p><strong style="color:var(--yellow)">5. No Warranty</strong><br/>
      This platform is provided "as-is" without warranty of any kind. Scan results are for informational purposes only and should be validated by a qualified security professional before acting on them.</p>

      <p><strong style="color:var(--yellow)">6. Account Termination</strong><br/>
      Any account found to be in violation of these terms will be immediately disabled and relevant logs will be preserved for potential legal proceedings.</p>

    </div>
    <div style="height:1px;background:var(--b2);margin:20px 0"></div>
    <div style="display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap">
      <button onclick="closeTos()" style="padding:10px 22px;background:transparent;border:1px solid var(--b2);color:var(--m);border-radius:8px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12px">DECLINE</button>
      <button onclick="acceptTos()" style="padding:10px 22px;background:linear-gradient(135deg,var(--yellow),var(--orange));color:#000;border:none;border-radius:8px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700">I ACCEPT — CONTINUE</button>
    </div>
  </div>
</div>
"""

# JavaScript for the ToS modal (appended inside the existing <script> block,
# just before loadUser(); at the very bottom).
TOS_JS = r"""
// ── ToS Modal ──────────────────────────────────────────────────────────────
function showTos(e) {
  e.preventDefault();
  // Validate required fields first
  const name  = document.getElementById("r-name").value.trim();
  const user  = document.getElementById("r-user").value.trim();
  const email = document.getElementById("r-email").value.trim();
  const pass  = document.getElementById("r-pass").value;
  if (!user || !email || !pass) {
    authMsg("Please fill in all fields before reading the Terms of Use.");
    return;
  }
  const m = document.getElementById("tos-modal");
  m.style.display = "flex";
  setTimeout(() => m.style.opacity = "1", 10);
}
function closeTos() {
  const m = document.getElementById("tos-modal");
  m.style.display = "none";
  const cb = document.getElementById("r-tos-cb");
  if (cb) cb.checked = false;
  updateRegisterBtn();
}
function acceptTos() {
  document.getElementById("tos-modal").style.display = "none";
  const cb = document.getElementById("r-tos-cb");
  if (cb) { cb.checked = true; updateRegisterBtn(); }
}
function updateRegisterBtn() {
  const cb  = document.getElementById("r-tos-cb");
  const btn = document.getElementById("r-btn");
  if (!cb || !btn) return;
  btn.disabled = !cb.checked;
  btn.style.opacity = cb.checked ? "1" : "0.45";
  btn.style.cursor  = cb.checked ? "pointer" : "not-allowed";
}
"""

# ── ToS checkbox HTML — replaces the existing register button ─────────────────
OLD_REGISTER_BTN = '<button class="btn btn-p" id="r-btn" onclick="doRegister()" style="margin-top:4px">CREATE ACCOUNT</button>'

NEW_REGISTER_BTN = '''\
<!-- ToS checkbox -->
<div style="background:rgba(255,214,10,0.05);border:1px solid rgba(255,214,10,0.2);border-radius:8px;padding:12px 14px;margin-bottom:14px;display:flex;align-items:flex-start;gap:10px">
  <input type="checkbox" id="r-tos-cb" onchange="updateRegisterBtn()" style="width:16px;height:16px;margin-top:2px;accent-color:var(--yellow);cursor:pointer;flex-shrink:0"/>
  <label for="r-tos-cb" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#c0c0d0;line-height:1.7;cursor:pointer">
    I have read and agree to the
    <button type="button" onclick="showTos(event)" style="background:none;border:none;color:var(--yellow);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;text-decoration:underline;padding:0">Terms of Use &amp; Legal Disclaimer</button>.
    I confirm that I <strong style="color:var(--red)">own or have written permission</strong> to scan any target I submit.
    I accept full legal responsibility for my actions. The platform owner is
    <strong style="color:var(--red)">not liable</strong> for any illegal or unauthorized activity I conduct.
  </label>
</div>
<button class="btn btn-p" id="r-btn" onclick="doRegister()" style="margin-top:4px" disabled>CREATE ACCOUNT</button>'''

# ── Inject ToS modal HTML before </body> ──────────────────────────────────────
OLD_BODY_CLOSE = "</body>\n</html>"
NEW_BODY_CLOSE = TOS_MODAL + "\n</body>\n</html>"

# ── Inject ToS JS before loadUser(); ─────────────────────────────────────────
OLD_LOAD_USER = "loadUser();\n</script>"
NEW_LOAD_USER  = TOS_JS + "\nloadUser();\n</script>"


# ══════════════════════════════════════════════════════════════════════════════
#  PATCH 2 — auth.py  ·  server-side: reject registrations without ToS flag
# ══════════════════════════════════════════════════════════════════════════════

OLD_AUTH_VALIDATE = """\
        ok, msg = validate_password(password)
        if not ok: return jsonify({"error": msg}), 400

        if get_user_by_username(username): return jsonify({"error": "Username already taken"}), 409"""

NEW_AUTH_VALIDATE = """\
        ok, msg = validate_password(password)
        if not ok: return jsonify({"error": msg}), 400

        # Server-side ToS acceptance check
        tos_accepted = d.get("tos_accepted", False)
        if not tos_accepted:
            return jsonify({"error": "You must accept the Terms of Use before registering."}), 400

        if get_user_by_username(username): return jsonify({"error": "Username already taken"}), 409"""


# ── Patch the doRegister() JS to send tos_accepted ───────────────────────────
OLD_DO_REGISTER_BODY = """\
    const r=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,email,password:pass,full_name:name})});"""

NEW_DO_REGISTER_BODY = """\
    const tosAccepted = document.getElementById("r-tos-cb")?.checked || false;
    const r=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,email,password:pass,full_name:name,tos_accepted:tosAccepted})});"""


# ══════════════════════════════════════════════════════════════════════════════
#  Run all patches
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global changes_applied, files_modified, restart_needed

    print(f"\n{BOLD}{CYAN}VulnScan Pro — Patch: Terms of Service Checkbox{RESET}")
    print("=" * 58)

    # ── api_server.py ─────────────────────────────────────────
    print(f"\n{BOLD}[1/2] Patching api_server.py{RESET}")
    patch_file("api_server.py", [
        (
            "Inject ToS modal HTML before </body>",
            OLD_BODY_CLOSE,
            NEW_BODY_CLOSE,
        ),
        (
            "Replace register button with ToS checkbox + button",
            OLD_REGISTER_BTN,
            NEW_REGISTER_BTN,
        ),
        (
            "Inject ToS JavaScript before loadUser()",
            OLD_LOAD_USER,
            NEW_LOAD_USER,
        ),
        (
            "Send tos_accepted flag in doRegister() fetch call",
            OLD_DO_REGISTER_BODY,
            NEW_DO_REGISTER_BODY,
        ),
    ])

    # ── auth.py ───────────────────────────────────────────────
    print(f"\n{BOLD}[2/2] Patching auth.py{RESET}")
    patch_file("auth.py", [
        (
            "Server-side: reject registration if ToS not accepted",
            OLD_AUTH_VALIDATE,
            NEW_AUTH_VALIDATE,
        ),
    ])

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{'=' * 58}")
    print(f"{BOLD}SUMMARY{RESET}")
    print(f"  Changes applied : {GREEN}{changes_applied}{RESET}")
    print(f"  Files modified  : {YELLOW}{len(files_modified)}{RESET}")
    for f in files_modified:
        print(f"    • {f}")
    if restart_needed:
        print(f"\n  {YELLOW}⚡ Restart required:{RESET}")
        print(f"     sudo systemctl restart vulnscan")
        print(f"     — or —")
        print(f"     python3 api_server.py")
    else:
        print(f"\n  {GREEN}No restart needed.{RESET}")

    if changes_applied == 0:
        print(f"\n  {YELLOW}No changes were made. The patch may already be applied,")
        print(f"  or the source strings did not match. Check .bak files if needed.{RESET}")

    print()


if __name__ == "__main__":
    main()
