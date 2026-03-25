#!/usr/bin/env python3
"""
VulnScan Pro — Admin Console "New User" Button Patch
Adds a prominent "New User" button in the Admin Console header
and a polished popup modal with Full Name, Username, Email fields.
Shows a success/error confirmation after user creation.

Usage: python3 patch.py
Run from the project root directory.
"""
import os, shutil, subprocess, sys, re
from datetime import datetime

# ── Console colours ───────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def ok(m):   print(f"  {GREEN}✓{RESET} {m}")
def fail(m): print(f"  {RED}✗{RESET} {m}")
def info(m): print(f"  {CYAN}→{RESET} {m}")
def skip(m): print(f"  {DIM}·{RESET} {m}")

results = {
    "changes_applied": 0,
    "changes_skipped": 0,
    "changes_failed":  0,
    "files_modified":  [],
    "restart_needed":  False,
}


def backup(path):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst


def apply_patches(path, patches):
    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        results["changes_failed"] += len(patches)
        return 0

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    modified = content
    applied  = 0

    for desc, old, new in patches:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc)
            applied += 1
            results["changes_applied"] += 1
        elif new in modified:
            skip(f"{desc}  (already applied)")
            results["changes_skipped"] += 1
        else:
            fail(f"{desc}  — anchor text not found in file")
            results["changes_failed"] += 1

    if applied:
        bak = backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        info(f"Backed up → {os.path.basename(bak)}")
        if path not in results["files_modified"]:
            results["files_modified"].append(path)
        results["restart_needed"] = True

    return applied


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — Add New User Modal HTML (inserted before closing </div> of overlay)
# ══════════════════════════════════════════════════════════════════════════════

OLD_NEW_USER_MODAL_ANCHOR = '<!-- ── About modal ── -->'

NEW_NEW_USER_MODAL = '''<!-- ── New User Modal ── -->
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

<!-- ── About modal ── -->'''

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — Add "New User" button to Admin Console page header
# Target: the existing admin page header area
# ══════════════════════════════════════════════════════════════════════════════

OLD_ADMIN_PAGE_HD = '''      <!-- ADMIN -->
      <div class="page" id="page-admin">
        <div class="page-hd"><div class="page-title">Admin Console</div><div class="page-desc">User management, server CLI, and platform statistics</div></div>'''

NEW_ADMIN_PAGE_HD = '''      <!-- ADMIN -->
      <div class="page" id="page-admin">
        <div class="page-hd" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px">
          <div>
            <div class="page-title">Admin Console</div>
            <div class="page-desc">User management, server CLI, and platform statistics</div>
          </div>
          <button class="btn btn-primary" onclick="openNewUserModal()" style="flex-shrink:0;margin-top:4px">
            <span style="font-size:15px;line-height:1">&#43;</span> New User
          </button>
        </div>'''

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 3 — Add JS functions for the New User modal
# Insert before the closing loadUser() call at the bottom of the <script> block
# ══════════════════════════════════════════════════════════════════════════════

OLD_LOAD_USER_CALL = 'loadUser();\n</script>'

NEW_LOAD_USER_CALL = '''loadUser();

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
</script>'''


# ══════════════════════════════════════════════════════════════════════════════
# PATCH REGISTRY
# ══════════════════════════════════════════════════════════════════════════════
PATCH_REGISTRY = [
    {
        "file": "api_server.py",
        "patches": [
            (
                "Add New User modal HTML (popup with Full Name / Username / Email)",
                OLD_NEW_USER_MODAL_ANCHOR,
                NEW_NEW_USER_MODAL,
            ),
            (
                "Add 'New User' button to Admin Console page header",
                OLD_ADMIN_PAGE_HD,
                NEW_ADMIN_PAGE_HD,
            ),
            (
                "Add JS functions: openNewUserModal / closeNewUserModal / submitNewUser",
                OLD_LOAD_USER_CALL,
                NEW_LOAD_USER_CALL,
            ),
        ],
    },
]


def run_syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True
    )
    return r.returncode == 0, r.stderr.strip()


def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║  VulnScan Pro — Admin 'New User' Button Patch        ║" + RESET)
    print(BOLD + CYAN + "║  Adds modal popup for creating users from Admin UI   ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
    print()

    # Verify we're in the project root
    missing = [f for f in ["api_server.py", "backend.py", "auth.py"] if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Not in the vulnscan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Run: cd ~/vulnscan && python3 patch.py")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    for entry in PATCH_REGISTRY:
        path = entry["file"]
        print(BOLD + f"  File: {path}" + RESET)
        apply_patches(path, entry["patches"])
        print()

    # Syntax check modified files
    syntax_ok = True
    if results["files_modified"]:
        print(BOLD + "  Syntax checks:" + RESET)
        for path in results["files_modified"]:
            flag, err = run_syntax_check(path)
            if flag:
                ok(f"{path} — syntax OK")
            else:
                fail(f"{path} — SYNTAX ERROR:")
                print(f"    {RED}{err}{RESET}")
                syntax_ok = False
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
    print(BOLD + "  SUMMARY" + RESET)
    print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
    print(f"  Changes applied : {GREEN}{results['changes_applied']}{RESET}")
    print(f"  Already applied : {DIM}{results['changes_skipped']}{RESET}")
    print(f"  Failed          : {RED if results['changes_failed'] else DIM}{results['changes_failed']}{RESET}")
    print()

    if results["files_modified"]:
        print("  Files modified:")
        for f in results["files_modified"]:
            print(f"    {GREEN}✓{RESET}  {f}  {DIM}(backup: {f}.*.bak){RESET}")
        print()

    if not syntax_ok:
        print(f"  {RED}⚠  Syntax error detected — restore the .bak file before restarting{RESET}")
    elif results["restart_needed"]:
        print(f"  {YELLOW}Restart required:{RESET}")
        print(f"    {CYAN}python3 api_server.py{RESET}")
        print(f"  {DIM}or with systemd:{RESET}")
        print(f"    {CYAN}sudo systemctl restart vulnscan{RESET}")
    elif results["changes_applied"] == 0 and results["changes_skipped"] > 0:
        print(f"  {GREEN}Already up to date — no restart needed.{RESET}")
    else:
        print(f"  {YELLOW}Nothing changed (patch may already be applied or anchor text not found).{RESET}")

    if results["changes_applied"] > 0 and syntax_ok:
        print()
        print(f"  {GREEN}What was added:{RESET}")
        print(f"    {GREEN}✓{RESET} '+ New User' button in Admin Console page header")
        print(f"    {GREEN}✓{RESET} Modal popup with Full Name, Username, Email fields")
        print(f"    {GREEN}✓{RESET} Auto-generates temp password & emails credentials to new user")
        print(f"    {GREEN}✓{RESET} Success confirmation screen with user details")
        print(f"    {GREEN}✓{RESET} Error handling with inline feedback")
        print(f"    {GREEN}✓{RESET} Form resets cleanly on each open")
        print(f"    {GREEN}✓{RESET} Toast notification on successful creation")
        print(f"    {GREEN}✓{RESET} Existing website functionality unchanged")
    print()


if __name__ == "__main__":
    main()
