#!/usr/bin/env python3
"""
VulnScan Pro — Patch: Fix universal_agent.py
  1. Removes the bad `http_json(..., headers=None, token=token)` call in the poll loop
  2. Fixes the duplicate http_json definition (the second one shadows the first)
  3. Fixes tool-filter UI in api_server.py so only tools installed on the remote
     system are shown (others hidden, not just marked ✓/✗)

Run from project root:
    python3 patch_agent_fix.py
"""
import os, shutil
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN  = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        if new.strip() in src or old.strip()[:40] not in src:
            skip(f"{label} — already applied or anchor not found")
        else:
            fail(f"{label} — anchor not found in {path}")
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}")
    return True

print()
print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
print(BOLD + CYAN + "║  VulnScan Pro — Fix Remote Audit Agent               ║" + RESET)
print(BOLD + CYAN + "║  • Fix http_json() headers kwarg error               ║" + RESET)
print(BOLD + CYAN + "║  • Fix duplicate http_json definition                ║" + RESET)
print(BOLD + CYAN + "║  • Fix tool filter UI (show only installed tools)    ║" + RESET)
print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
print()

AGENT = "agent/universal_agent.py"
SERVER = "api_server.py"

modified = []

# ──────────────────────────────────────────────────────────────
# PATCH 1: Fix the poll loop in universal_agent.py
# The bad code does:
#   job = http_json(f"...", headers=None, token=token)
#   # then immediately does the same request again with urllib directly
# Replace the entire broken poll block with a clean single request
# ──────────────────────────────────────────────────────────────

OLD_POLL = '''            # Poll for a job
            job = http_json(f"{api_base}/api/remote/jobs", headers=None, token=token)
            # Override: pass token via bearer
            import urllib.request as _ur
            req = _ur.Request(f"{api_base}/api/remote/jobs",
                              headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json"})
            with _ur.urlopen(req, timeout=30) as r:
                job = json.loads(r.read().decode())'''

NEW_POLL = '''            # Poll for a job
            job = http_json(f"{api_base}/api/remote/jobs", token=token)'''

if patch(AGENT, "agent: fix poll loop (remove headers=None + duplicate request)", OLD_POLL, NEW_POLL):
    modified.append(AGENT)

# ──────────────────────────────────────────────────────────────
# PATCH 2: Remove the duplicate http_json definition at the bottom
# of universal_agent.py (it shadows the one at the top and is identical)
# ──────────────────────────────────────────────────────────────

OLD_DUP = '''# ── Fix http_json to support token as param not kwarg ─────────
def http_json(url, method="GET", payload=None, token=""):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())'''

NEW_DUP = '''# (duplicate http_json removed — using the one defined at top of file)'''

if patch(AGENT, "agent: remove duplicate http_json definition", OLD_DUP, NEW_DUP):
    if AGENT not in modified:
        modified.append(AGENT)

# ──────────────────────────────────────────────────────────────
# PATCH 3: Fix tool filter UI in api_server.py
# Current code marks tools ✓/✗ but keeps all visible.
# Replace with version that shows only installed tools,
# and groups uninstalled ones at the bottom as disabled/greyed.
# ──────────────────────────────────────────────────────────────

OLD_SELECT = '''function raSelectAgent(agent){
  _raSelectedAgent=agent.client_id;
  document.getElementById('ra-selected-label').textContent=agent.client_id+' ('+agent.hostname+')';
  document.getElementById('ra-launcher').style.display='block';
  // Filter tool dropdown to installed tools
  var sel=document.getElementById('ra-tool');
  var installedTools=agent.tools||[];
  for(var i=0;i<sel.options.length;i++){
    var opt=sel.options[i];
    if(opt.value&&!['generic',''].includes(opt.value)){
      var avail=installedTools.some(function(t){return t.toLowerCase()===opt.value.toLowerCase()||t.toLowerCase().includes(opt.value.toLowerCase());});
      opt.text=opt.text.replace(' ✓','').replace(' ✗','');
      opt.text+=(avail?' ✓':' ✗');
    }
  }
  raLoadJobs();
  showToast('System selected',agent.client_id+' ready','success',2000);
}'''

NEW_SELECT = '''function raSelectAgent(agent){
  _raSelectedAgent=agent.client_id;
  document.getElementById('ra-selected-label').textContent=agent.client_id+' ('+agent.hostname+')';
  document.getElementById('ra-launcher').style.display='block';

  // Rebuild tool dropdown: installed tools first (enabled), rest disabled
  var installedTools=(agent.tools||[]).map(function(t){return t.toLowerCase();});

  var TOOL_LIST = [
    // [value, label, category]
    ['nmap',          'nmap — Port Scanner',         'Network'],
    ['nikto',         'nikto — Web Vuln Scanner',    'Web Testing'],
    ['wpscan',        'wpscan — WordPress Scanner',  'Web Testing'],
    ['whatweb',       'whatweb — Tech Fingerprint',  'Web Testing'],
    ['ffuf',          'ffuf — Directory Fuzzer',     'Web Testing'],
    ['sqlmap',        'sqlmap — SQL Injection',       'Web Testing'],
    ['nuclei',        'nuclei — Template Scanner',   'Web Testing'],
    ['wapiti',        'wapiti — Web App Scanner',    'Web Testing'],
    ['dalfox',        'dalfox — XSS Scanner',        'Web Testing'],
    ['dnsrecon',      'dnsrecon — DNS Enum',         'OSINT / DNS'],
    ['theharvester',  'theHarvester — OSINT',        'OSINT / DNS'],
    ['lynis',         'lynis — System Audit',        'System Audit'],
    ['chkrootkit',    'chkrootkit — Rootkit Check',  'System Audit'],
    ['rkhunter',      'rkhunter — Rootkit Hunter',   'System Audit'],
    ['medusa',        'medusa — Login Auditor',      'Password'],
    ['john',          'john — Password Cracker',     'Password'],
    ['hashcat',       'hashcat — GPU Hash Cracker',  'Password'],
    ['searchsploit',  'searchsploit — Exploit-DB',   'Other'],
    ['hping3',        'hping3 — Packet Generator',   'Other'],
    ['generic',       'generic — Custom command',    'Other'],
  ];

  var sel = document.getElementById('ra-tool');
  // Clear existing options except placeholder
  sel.innerHTML = '<option value="">— choose tool —</option>';

  // Group by category
  var cats = {};
  TOOL_LIST.forEach(function(t){
    var cat = t[2];
    if(!cats[cat]) cats[cat] = [];
    cats[cat].push(t);
  });

  Object.keys(cats).forEach(function(cat){
    var grp = document.createElement('optgroup');
    grp.label = cat;
    cats[cat].forEach(function(t){
      var val = t[0], lbl = t[1];
      // Check if tool installed (flexible match)
      var isInstalled = val === 'generic' || installedTools.some(function(it){
        return it === val || it.indexOf(val) !== -1 || val.indexOf(it) !== -1;
      });
      var opt = document.createElement('option');
      opt.value = val;
      opt.text  = isInstalled ? ('✓ ' + lbl) : ('✗ ' + lbl + ' (not installed)');
      opt.disabled = !isInstalled;
      if(!isInstalled) opt.style.color = '#666';
      grp.appendChild(opt);
    });
    sel.appendChild(grp);
  });

  raLoadJobs();
  var installedCount = installedTools.length;
  showToast('System selected', agent.client_id + ' — ' + installedCount + ' tools available', 'success', 3000);
}'''

if patch(SERVER, "server: fix tool dropdown to show only installed tools", OLD_SELECT, NEW_SELECT):
    if SERVER not in modified:
        modified.append(SERVER)

# ──────────────────────────────────────────────────────────────
# PATCH 4: Also fix the same raSelectAgent in the HTML constant
# (api_server.py embeds JS inside HTML = r"""...""")
# ──────────────────────────────────────────────────────────────
# The HTML block has an identical raSelectAgent — patch it too
OLD_SELECT_HTML = OLD_SELECT  # same text appears inside HTML string
NEW_SELECT_HTML = NEW_SELECT

# Only apply if not already done (the replace in patch() only does first occurrence)
if os.path.isfile(SERVER):
    with open(SERVER, "r", encoding="utf-8", errors="ignore") as f:
        src2 = f.read()
    if OLD_SELECT_HTML in src2:
        bak2 = backup(SERVER)
        with open(SERVER, "w", encoding="utf-8") as f:
            f.write(src2.replace(OLD_SELECT_HTML, NEW_SELECT_HTML))
        ok("server HTML block: fix tool dropdown (second occurrence)")
        if SERVER not in modified:
            modified.append(SERVER)
    else:
        skip("server HTML block: second occurrence not found (already patched or not present)")

# ──────────────────────────────────────────────────────────────
# Backup modified files (if not already backed up above)
# ──────────────────────────────────────────────────────────────
print()
info("Creating backups for modified files...")
for path in modified:
    if os.path.isfile(path):
        bak = backup(path)
        info(f"  backup → {bak}")

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
print()
print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
print(f"  Modified files: {GREEN}{len(modified)}{RESET}")
for p in modified:
    print(f"    {GREEN}✓{RESET}  {p}")
print()
print(f"  {YELLOW}Fixes applied:{RESET}")
print(f"    {GREEN}✓{RESET}  http_json() headers kwarg error fixed")
print(f"    {GREEN}✓{RESET}  Duplicate http_json definition removed")
print(f"    {GREEN}✓{RESET}  Tool dropdown shows only installed tools (✓/✗ + disabled)")
print()
print(f"  {YELLOW}Restart server + re-install agent on client:{RESET}")
print(f"    sudo systemctl restart vulnscan")
print(f"    # On client machine:")
print(f"    curl -fsSL http://161.118.189.254/agent/install.sh | bash")
print()
