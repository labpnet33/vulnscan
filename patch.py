#!/usr/bin/env python3
"""
VulnScan Pro — Patch Script
Adds new tools to their respective nav categories,
makes all nav categories collapsible, and injects
stub pages + route stubs for the new tools.

Run from project root:  python3 vulnscan_patch.py
"""

import os
import re
import sys
import shutil
from datetime import datetime

# ── Colours ──────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
C = "\033[96m"
Y = "\033[93m"
D = "\033[2m"
B = "\033[1m"
X = "\033[0m"

ok   = lambda m: print(f"  {G}✓{X}  {m}")
fail = lambda m: print(f"  {R}✗{X}  {m}")
info = lambda m: print(f"  {C}→{X}  {m}")
warn = lambda m: print(f"  {Y}!{X}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0, "files": [], "restart": False}

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(path, f"{path}.{ts}.bak")


def apply(path, changes):
    """Apply list of (label, old, new) to file. Returns True if any applied."""
    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        RESULTS["failed"] += len(changes)
        return False

    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()

    modified = src
    applied = 0

    for label, old, new in changes:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(label)
            applied += 1
            RESULTS["applied"] += 1
        elif new in modified:
            print(f"  {D}·{X}  {label} (already applied)")
            RESULTS["skipped"] += 1
        else:
            fail(f"{label} — anchor not found in {path}")
            RESULTS["failed"] += 1

    if applied:
        backup(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(modified)
        if path not in RESULTS["files"]:
            RESULTS["files"].append(path)
        RESULTS["restart"] = True

    return applied > 0


def syntax_check(path):
    import subprocess
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


# ─────────────────────────────────────────────────────────────
# PATCH 1 — Replace entire <nav> block in api_server.py HTML
#           with collapsible categories + new tools
# ─────────────────────────────────────────────────────────────

OLD_NAV = """      <div class="nav-section">
        <div class="nav-label">OVERVIEW</div>
        <button class="nav-item" id="ni-home" onclick="pg('home',this)"><span class="ni">&#9700;</span> Home</button>
        <button class="nav-item" id="ni-dash" onclick="pg('dash',this)"><span class="ni">&#9636;</span> Dashboard</button>
        <button class="nav-item" id="ni-hist" onclick="pg('hist',this)"><span class="ni">&#9632;</span> History</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">INFORMATION</div>
        <button class="nav-item" id="ni-scan" onclick="pg('scan',this)"><span class="ni">&#9675;</span> Network Scanner</button>
        <button class="nav-item" id="ni-dnsrecon" onclick="pg('dnsrecon',this)"><span class="ni">&#9675;</span> DNSRecon</button>
        <button class="nav-item" id="ni-disc" onclick="pg('disc',this)"><span class="ni">&#9675;</span> Net Discovery</button>
        <button class="nav-item" id="ni-harvester" onclick="pg('harvester',this)"><span class="ni">&#9675;</span> theHarvester</button>
        <button class="nav-item" id="ni-sub" onclick="pg('sub',this)"><span class="ni">&#9675;</span> Subdomain Finder</button>
        <button class="nav-item" id="ni-legion" onclick="pg('legion',this)"><span class="ni">&#9675;</span> Legion</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">WEB TESTING</div>
        <button class="nav-item" id="ni-webdeep" onclick="pg('webdeep',this)"><span class="ni">&#9675;</span> Deep Web Audit</button>
        <button class="nav-item" id="ni-nikto" onclick="pg('nikto',this)"><span class="ni">&#9675;</span> Nikto</button>
        <button class="nav-item" id="ni-wpscan" onclick="pg('wpscan',this)"><span class="ni">&#9675;</span> WPScan</button>
        <button class="nav-item" id="ni-dir" onclick="pg('dir',this)"><span class="ni">&#9675;</span> Dir Buster</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">ATTACKS</div>
        <button class="nav-item" id="ni-brute" onclick="pg('brute',this)"><span class="ni">&#9675;</span> Brute Force</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">SOCIAL ENGINEERING</div>
        <button class="nav-item" id="ni-setoolkit" onclick="pg('setoolkit',this)"><span class="ni">&#9675;</span> Social-Engineer Toolkit</button>
        <button class="nav-item" id="ni-gophish" onclick="pg('gophish',this)"><span class="ni">&#9675;</span> Gophish</button>
        <button class="nav-item" id="ni-evilginx2" onclick="pg('evilginx2',this)"><span class="ni">&#9675;</span> Evilginx2</button>
        <button class="nav-item" id="ni-shellphish" onclick="pg('shellphish',this)"><span class="ni">&#9675;</span> ShellPhish</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">C2 / PIVOTING</div>
        <button class="nav-item" id="ni-netcat" onclick="pg('netcat',this)"><span class="ni">&#9675;</span> Netcat</button>
        <button class="nav-item" id="ni-ncat" onclick="pg('ncat',this)"><span class="ni">&#9675;</span> Ncat</button>
        <button class="nav-item" id="ni-socat" onclick="pg('socat',this)"><span class="ni">&#9675;</span> Socat</button>
        <button class="nav-item" id="ni-sliver" onclick="pg('sliver',this)"><span class="ni">&#9675;</span> Sliver</button>
        <button class="nav-item" id="ni-empire" onclick="pg('empire',this)"><span class="ni">&#9675;</span> Empire</button>
      </div>
      <div class="nav-section">
        <div class="nav-label">AUDITING</div>
        <button class="nav-item" id="ni-lynis" onclick="pg('lynis',this)"><span class="ni">&#9675;</span> Lynis</button>
      </div>
      <div class="nav-section" id="admin-nav-section" style="display:none">
        <div class="nav-label">ADMIN</div>
        <button class="nav-item" id="ni-admin" onclick="pg('admin',this)"><span class="ni">&#9632;</span> Admin Console</button>
      </div>"""

NEW_NAV = """      <style>
.nav-section{padding:4px 10px}
.nav-cat-toggle{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:6px 8px;border-radius:var(--radius);user-select:none}
.nav-cat-toggle:hover{background:var(--bg3)}
.nav-cat-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;font-weight:500}
.nav-cat-arrow{font-size:9px;color:var(--text3);transition:transform 0.2s}
.nav-cat-arrow.open{transform:rotate(180deg)}
.nav-cat-items{overflow:hidden;transition:max-height 0.25s ease,opacity 0.2s}
.nav-cat-items.collapsed{max-height:0!important;opacity:0;pointer-events:none}
.nav-cat-items.expanded{opacity:1}
      </style>
      <script>
function navToggle(id){
  var items=document.getElementById('nc-'+id);
  var arrow=document.getElementById('na-'+id);
  if(!items)return;
  var collapsed=items.classList.contains('collapsed');
  items.classList.toggle('collapsed',!collapsed);
  items.classList.toggle('expanded',collapsed);
  if(arrow)arrow.classList.toggle('open',collapsed);
  try{localStorage.setItem('vs-nav-'+id,collapsed?'1':'0');}catch(e){}
}
function navRestore(){
  ['overview','information','webtesting','attacks','webapp','passwords','recon','exploitation','auditing','c2','social','reverseeng','tunneling','admin'].forEach(function(id){
    var items=document.getElementById('nc-'+id);
    var arrow=document.getElementById('na-'+id);
    if(!items)return;
    var stored;try{stored=localStorage.getItem('vs-nav-'+id);}catch(e){}
    var open=(stored===null)?1:(stored==='1'?1:0);
    items.classList.toggle('collapsed',!open);
    items.classList.toggle('expanded',!!open);
    if(arrow)arrow.classList.toggle('open',!!open);
  });
}
document.addEventListener('DOMContentLoaded',navRestore);
      </script>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('overview')">
          <span class="nav-cat-label">OVERVIEW</span>
          <span class="nav-cat-arrow open" id="na-overview">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-overview" style="max-height:200px">
          <button class="nav-item" id="ni-home" onclick="pg('home',this)"><span class="ni">&#9700;</span> Home</button>
          <button class="nav-item" id="ni-dash" onclick="pg('dash',this)"><span class="ni">&#9636;</span> Dashboard</button>
          <button class="nav-item" id="ni-hist" onclick="pg('hist',this)"><span class="ni">&#9632;</span> History</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('information')">
          <span class="nav-cat-label">INFORMATION</span>
          <span class="nav-cat-arrow open" id="na-information">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-information" style="max-height:400px">
          <button class="nav-item" id="ni-scan" onclick="pg('scan',this)"><span class="ni">&#9675;</span> Network Scanner</button>
          <button class="nav-item" id="ni-dnsrecon" onclick="pg('dnsrecon',this)"><span class="ni">&#9675;</span> DNSRecon</button>
          <button class="nav-item" id="ni-disc" onclick="pg('disc',this)"><span class="ni">&#9675;</span> Net Discovery</button>
          <button class="nav-item" id="ni-harvester" onclick="pg('harvester',this)"><span class="ni">&#9675;</span> theHarvester</button>
          <button class="nav-item" id="ni-sub" onclick="pg('sub',this)"><span class="ni">&#9675;</span> Subdomain Finder</button>
          <button class="nav-item" id="ni-legion" onclick="pg('legion',this)"><span class="ni">&#9675;</span> Legion</button>
          <button class="nav-item" id="ni-searchsploit" onclick="pg('searchsploit',this)"><span class="ni">&#9675;</span> SearchSploit</button>
          <button class="nav-item" id="ni-seclists" onclick="pg('seclists',this)"><span class="ni">&#9675;</span> SecLists</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('webtesting')">
          <span class="nav-cat-label">WEB TESTING</span>
          <span class="nav-cat-arrow open" id="na-webtesting">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-webtesting" style="max-height:500px">
          <button class="nav-item" id="ni-webdeep" onclick="pg('webdeep',this)"><span class="ni">&#9675;</span> Deep Web Audit</button>
          <button class="nav-item" id="ni-nikto" onclick="pg('nikto',this)"><span class="ni">&#9675;</span> Nikto</button>
          <button class="nav-item" id="ni-wpscan" onclick="pg('wpscan',this)"><span class="ni">&#9675;</span> WPScan</button>
          <button class="nav-item" id="ni-dir" onclick="pg('dir',this)"><span class="ni">&#9675;</span> Dir Buster</button>
          <button class="nav-item" id="ni-ffuf" onclick="pg('ffuf',this)"><span class="ni">&#9675;</span> ffuf</button>
          <button class="nav-item" id="ni-nuclei" onclick="pg('nuclei',this)"><span class="ni">&#9675;</span> Nuclei</button>
          <button class="nav-item" id="ni-whatweb" onclick="pg('whatweb',this)"><span class="ni">&#9675;</span> WhatWeb</button>
          <button class="nav-item" id="ni-wapiti" onclick="pg('wapiti',this)"><span class="ni">&#9675;</span> Wapiti</button>
          <button class="nav-item" id="ni-dalfox" onclick="pg('dalfox',this)"><span class="ni">&#9675;</span> Dalfox</button>
          <button class="nav-item" id="ni-sqlmap" onclick="pg('sqlmap',this)"><span class="ni">&#9675;</span> SQLMap</button>
          <button class="nav-item" id="ni-kxss" onclick="pg('kxss',this)"><span class="ni">&#9675;</span> kxss</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('attacks')">
          <span class="nav-cat-label">ATTACKS</span>
          <span class="nav-cat-arrow open" id="na-attacks">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-attacks" style="max-height:300px">
          <button class="nav-item" id="ni-brute" onclick="pg('brute',this)"><span class="ni">&#9675;</span> Brute Force</button>
          <button class="nav-item" id="ni-medusa" onclick="pg('medusa',this)"><span class="ni">&#9675;</span> Medusa</button>
          <button class="nav-item" id="ni-hping3" onclick="pg('hping3',this)"><span class="ni">&#9675;</span> hping3</button>
          <button class="nav-item" id="ni-scapy" onclick="pg('scapy',this)"><span class="ni">&#9675;</span> Scapy</button>
          <button class="nav-item" id="ni-yersinia" onclick="pg('yersinia',this)"><span class="ni">&#9675;</span> Yersinia</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('passwords')">
          <span class="nav-cat-label">PASSWORD ATTACKS</span>
          <span class="nav-cat-arrow open" id="na-passwords">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-passwords" style="max-height:200px">
          <button class="nav-item" id="ni-hashcat" onclick="pg('hashcat',this)"><span class="ni">&#9675;</span> Hashcat</button>
          <button class="nav-item" id="ni-john" onclick="pg('john',this)"><span class="ni">&#9675;</span> John the Ripper</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('social')">
          <span class="nav-cat-label">SOCIAL ENGINEERING</span>
          <span class="nav-cat-arrow open" id="na-social">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-social" style="max-height:300px">
          <button class="nav-item" id="ni-setoolkit" onclick="pg('setoolkit',this)"><span class="ni">&#9675;</span> Social-Engineer Toolkit</button>
          <button class="nav-item" id="ni-gophish" onclick="pg('gophish',this)"><span class="ni">&#9675;</span> Gophish</button>
          <button class="nav-item" id="ni-evilginx2" onclick="pg('evilginx2',this)"><span class="ni">&#9675;</span> Evilginx2</button>
          <button class="nav-item" id="ni-shellphish" onclick="pg('shellphish',this)"><span class="ni">&#9675;</span> ShellPhish</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('c2')">
          <span class="nav-cat-label">C2 / PIVOTING</span>
          <span class="nav-cat-arrow open" id="na-c2">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-c2" style="max-height:400px">
          <button class="nav-item" id="ni-netcat" onclick="pg('netcat',this)"><span class="ni">&#9675;</span> Netcat</button>
          <button class="nav-item" id="ni-ncat" onclick="pg('ncat',this)"><span class="ni">&#9675;</span> Ncat</button>
          <button class="nav-item" id="ni-socat" onclick="pg('socat',this)"><span class="ni">&#9675;</span> Socat</button>
          <button class="nav-item" id="ni-sliver" onclick="pg('sliver',this)"><span class="ni">&#9675;</span> Sliver</button>
          <button class="nav-item" id="ni-empire" onclick="pg('empire',this)"><span class="ni">&#9675;</span> Empire</button>
          <button class="nav-item" id="ni-ligolo" onclick="pg('ligolo',this)"><span class="ni">&#9675;</span> Ligolo-ng</button>
          <button class="nav-item" id="ni-chisel" onclick="pg('chisel',this)"><span class="ni">&#9675;</span> Chisel</button>
          <button class="nav-item" id="ni-rlwrap" onclick="pg('rlwrap',this)"><span class="ni">&#9675;</span> rlwrap</button>
          <button class="nav-item" id="ni-pspy" onclick="pg('pspy',this)"><span class="ni">&#9675;</span> pspy</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('exploitation')">
          <span class="nav-cat-label">EXPLOIT / PAYLOAD</span>
          <span class="nav-cat-arrow open" id="na-exploitation">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-exploitation" style="max-height:200px">
          <button class="nav-item" id="ni-msfvenom" onclick="pg('msfvenom',this)"><span class="ni">&#9675;</span> msfvenom</button>
          <button class="nav-item" id="ni-pwncat" onclick="pg('pwncat',this)"><span class="ni">&#9675;</span> pwncat</button>
          <button class="nav-item" id="ni-grype" onclick="pg('grype',this)"><span class="ni">&#9675;</span> Grype</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('reverseeng')">
          <span class="nav-cat-label">REVERSE ENGINEERING</span>
          <span class="nav-cat-arrow open" id="na-reverseeng">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-reverseeng" style="max-height:200px">
          <button class="nav-item" id="ni-radare2" onclick="pg('radare2',this)"><span class="ni">&#9675;</span> Radare2</button>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-cat-toggle" onclick="navToggle('auditing')">
          <span class="nav-cat-label">AUDITING</span>
          <span class="nav-cat-arrow open" id="na-auditing">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-auditing" style="max-height:300px">
          <button class="nav-item" id="ni-lynis" onclick="pg('lynis',this)"><span class="ni">&#9675;</span> Lynis</button>
          <button class="nav-item" id="ni-openvas" onclick="pg('openvas',this)"><span class="ni">&#9675;</span> OpenVAS</button>
          <button class="nav-item" id="ni-chkrootkit" onclick="pg('chkrootkit',this)"><span class="ni">&#9675;</span> chkrootkit</button>
          <button class="nav-item" id="ni-rkhunter" onclick="pg('rkhunter',this)"><span class="ni">&#9675;</span> rkhunter</button>
        </div>
      </div>

      <div class="nav-section" id="admin-nav-section" style="display:none">
        <div class="nav-cat-toggle" onclick="navToggle('admin')">
          <span class="nav-cat-label">ADMIN</span>
          <span class="nav-cat-arrow open" id="na-admin">&#9660;</span>
        </div>
        <div class="nav-cat-items expanded" id="nc-admin" style="max-height:100px">
          <button class="nav-item" id="ni-admin" onclick="pg('admin',this)"><span class="ni">&#9632;</span> Admin Console</button>
        </div>
      </div>"""


# ─────────────────────────────────────────────────────────────
# PATCH 2 — Add PAGE_TITLES entries for new tools
# ─────────────────────────────────────────────────────────────

OLD_TITLES = "var PAGE_TITLES={home:'Home',scan:'Network Scanner',webdeep:'Deep Web Audit',harvester:'theHarvester',dnsrecon:'DNSRecon',nikto:'Nikto',wpscan:'WPScan',lynis:'Lynis',legion:'Legion',sub:'Subdomain Finder',dir:'Directory Buster',brute:'Brute Force',setoolkit:'Social-Engineer Toolkit',gophish:'Gophish',evilginx2:'Evilginx2',shellphish:'ShellPhish',netcat:'Netcat',ncat:'Ncat',socat:'Socat',sliver:'Sliver',empire:'Empire',disc:'Network Discovery',hist:'Scan History',dash:'Dashboard',profile:'Profile',admin:'Admin Console'};"

NEW_TITLES = "var PAGE_TITLES={home:'Home',scan:'Network Scanner',webdeep:'Deep Web Audit',harvester:'theHarvester',dnsrecon:'DNSRecon',nikto:'Nikto',wpscan:'WPScan',lynis:'Lynis',legion:'Legion',sub:'Subdomain Finder',dir:'Directory Buster',brute:'Brute Force',setoolkit:'Social-Engineer Toolkit',gophish:'Gophish',evilginx2:'Evilginx2',shellphish:'ShellPhish',netcat:'Netcat',ncat:'Ncat',socat:'Socat',sliver:'Sliver',empire:'Empire',disc:'Network Discovery',hist:'Scan History',dash:'Dashboard',profile:'Profile',admin:'Admin Console',ffuf:'ffuf',nuclei:'Nuclei',whatweb:'WhatWeb',wapiti:'Wapiti',dalfox:'Dalfox',sqlmap:'SQLMap',kxss:'kxss',medusa:'Medusa',hping3:'hping3',scapy:'Scapy',yersinia:'Yersinia',hashcat:'Hashcat',john:'John the Ripper',searchsploit:'SearchSploit',seclists:'SecLists',ligolo:'Ligolo-ng',chisel:'Chisel',rlwrap:'rlwrap',pspy:'pspy',msfvenom:'msfvenom',pwncat:'pwncat',grype:'Grype',radare2:'Radare2',openvas:'OpenVAS',chkrootkit:'chkrootkit',rkhunter:'rkhunter'};"


# ─────────────────────────────────────────────────────────────
# PATCH 3 — Insert stub pages for all new tools into the HTML
#           (placed just before the closing </div> of .content)
# ─────────────────────────────────────────────────────────────

# We anchor on the last existing page block closing tag before </div></div>
# Pick the ADMIN page block end as the anchor
OLD_PAGES_ANCHOR = """      <!-- ADMIN -->
      <div class="page" id="page-admin">"""

# Build compact generic page HTML for every new tool
def _stub_page(page_id, title, desc, tool_bin, install_cmd, category, notice_text=None):
    notice = notice_text or f"&#9888; Authorized use only. Only run {title} on systems you own or have explicit written permission to test."
    return f"""
      <!-- {title.upper()} -->
      <div class="page" id="page-{page_id}">
        <div class="page-hd"><div class="page-title">{title}</div><div class="page-desc">{desc}</div></div>
        <div class="notice">{notice}</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="{page_id}-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="{page_id}-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="{page_id}-bin" type="text" value="{tool_bin}"/></div>
          </div>
          <button class="btn btn-primary" id="{page_id}-btn" onclick="runGenericTool('{page_id}','{tool_bin}')">RUN {title.upper()}</button>
        </div>
        <div class="progress-wrap" id="{page_id}-prog"><div class="progress-bar" id="{page_id}-pb" style="width:0%"></div></div>
        <div class="terminal" id="{page_id}-term"></div>
        <div class="err-box" id="{page_id}-err"></div>
        <div id="{page_id}-res"></div>
        <div class="card card-p" style="margin-top:10px">
          <div class="card-title" style="margin-bottom:8px">Quick Install</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text2)">{install_cmd}</div>
          <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px"><span class="tag">{category}</span><span class="tag">{tool_bin}</span></div>
        </div>
      </div>"""

NEW_TOOL_STUBS = ""

_new_tools = [
    ("ffuf",        "ffuf",               "Fast web fuzzer for content discovery and parameter fuzzing",         "ffuf",          "sudo apt install ffuf",                     "web-testing"),
    ("nuclei",      "Nuclei",             "Template-based vulnerability scanner with thousands of community checks", "nuclei",     "sudo apt install nuclei",                   "web-testing"),
    ("whatweb",     "WhatWeb",            "Web technology fingerprinter — identify CMS, frameworks, servers",   "whatweb",       "sudo apt install whatweb",                  "web-testing"),
    ("wapiti",      "Wapiti",             "Web application vulnerability scanner (SQLi, XSS, file disclosure)", "wapiti",        "sudo apt install wapiti",                   "web-testing"),
    ("dalfox",      "Dalfox",             "XSS parameter analysis and scanning tool",                           "dalfox",        "go install github.com/hahwul/dalfox/v2@latest", "web-testing"),
    ("sqlmap",      "SQLMap",             "Automatic SQL injection detection and exploitation tool",             "sqlmap",        "sudo apt install sqlmap",                   "web-testing"),
    ("kxss",        "kxss",               "XSS parameter finder and reflection checker",                        "kxss",          "go install github.com/Emoe/kxss@latest",    "web-testing"),
    ("medusa",      "Medusa",             "Fast parallel network login auditor (multi-protocol brute force)",   "medusa",        "sudo apt install medusa",                   "attacks"),
    ("hping3",      "hping3",             "TCP/IP packet assembler and analyzer for network testing",           "hping3",        "sudo apt install hping3",                   "network-attack"),
    ("scapy",       "Scapy",              "Interactive packet manipulation and network analysis framework",      "scapy",         "sudo apt install python3-scapy",             "network-attack"),
    ("yersinia",    "Yersinia",           "Network protocol attacks (STP, CDP, DTP, DHCP, 802.1Q, VTP, HSRP)", "yersinia",      "sudo apt install yersinia",                 "network-attack"),
    ("hashcat",     "Hashcat",            "World's fastest GPU-based password recovery utility",                "hashcat",       "sudo apt install hashcat",                  "passwords"),
    ("john",        "John the Ripper",    "Versatile password cracker supporting many hash formats",            "john",          "sudo apt install john",                     "passwords"),
    ("searchsploit","SearchSploit",       "Command-line search tool for Exploit-DB offline archive",            "searchsploit",  "sudo apt install exploitdb",                "information"),
    ("seclists",    "SecLists",           "Collection of security wordlists for fuzzing and enumeration",       "seclists",      "sudo apt install seclists",                 "information"),
    ("ligolo",      "Ligolo-ng",          "Advanced tunneling tool for network pivoting via TUN interface",     "ligolo-ng",     "sudo apt install ligolo-ng",                "tunneling"),
    ("chisel",      "Chisel",             "Fast TCP/UDP tunnel over HTTP using SSH transport",                  "chisel",        "sudo apt install chisel",                   "tunneling"),
    ("rlwrap",      "rlwrap",             "Readline wrapper — adds command history to any CLI tool",            "rlwrap",        "sudo apt install rlwrap",                   "tunneling"),
    ("pspy",        "pspy",               "Process spy — monitor Linux processes without root privileges",      "pspy",          "Download from github.com/DominicBreuker/pspy", "tunneling"),
    ("msfvenom",    "msfvenom",           "Metasploit payload generator and encoder",                           "msfvenom",      "sudo apt install metasploit-framework",      "exploit"),
    ("pwncat",      "pwncat",             "Feature-rich reverse/bind shell handler with post-exploitation",     "pwncat",        "pip3 install pwncat-cs --break-system-packages", "exploit"),
    ("grype",       "Grype",              "Vulnerability scanner for container images and filesystems",         "grype",         "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh", "exploit"),
    ("radare2",     "Radare2",            "Reverse engineering framework — disassembly, analysis, debugging",   "radare2",       "sudo apt install radare2",                  "reverse-eng"),
    ("openvas",     "OpenVAS",            "Open vulnerability assessment system — comprehensive network scanner","openvas",      "sudo apt install openvas",                  "auditing"),
    ("chkrootkit",  "chkrootkit",         "Local rootkit detector — checks for known rootkit signatures",       "chkrootkit",    "sudo apt install chkrootkit",               "auditing"),
    ("rkhunter",    "rkhunter",           "Rootkit Hunter — scans for rootkits, backdoors, and exploits",       "rkhunter",      "sudo apt install rkhunter",                 "auditing"),
]

for args in _new_tools:
    NEW_TOOL_STUBS += _stub_page(*args)

NEW_PAGES_ANCHOR = NEW_TOOL_STUBS + "\n\n      <!-- ADMIN -->\n      <div class=\"page\" id=\"page-admin\">"


# ─────────────────────────────────────────────────────────────
# PATCH 4 — Add runGenericTool() JS helper before loadUser()
# ─────────────────────────────────────────────────────────────

OLD_JS_LOADUSER = "loadUser();"

NEW_JS_LOADUSER = """/* ==== GENERIC TOOL RUNNER ==== */
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

loadUser();"""


# ─────────────────────────────────────────────────────────────
# PATCH 5 — Extend /social-tools/run allowed tools list
# ─────────────────────────────────────────────────────────────

OLD_TOOL_ALLOW = '    if tool not in {"setoolkit", "gophish", "evilginx2", "shellphish", "netcat", "ncat", "socat", "sliver", "empire"}:'

NEW_TOOL_ALLOW = '    if tool not in {"setoolkit", "gophish", "evilginx2", "shellphish", "netcat", "ncat", "socat", "sliver", "empire", "ffuf", "nuclei", "whatweb", "wapiti", "dalfox", "sqlmap", "kxss", "medusa", "hping3", "scapy", "yersinia", "hashcat", "john", "searchsploit", "seclists", "ligolo-ng", "chisel", "rlwrap", "pspy", "msfvenom", "pwncat", "grype", "radare2", "openvas", "chkrootkit", "rkhunter"}:'


# ─────────────────────────────────────────────────────────────
# PATCH 6 — Extend _social_tool_binary() for new tools
# ─────────────────────────────────────────────────────────────

OLD_TOOL_BINARY_END = '    return None, []'

NEW_TOOL_BINARY_END = '''    # Generic tool passthrough — binary name == tool name
    generic_tools = {
        "ffuf": "ffuf", "nuclei": "nuclei", "whatweb": "whatweb",
        "wapiti": "wapiti", "dalfox": "dalfox", "sqlmap": "sqlmap",
        "kxss": "kxss", "medusa": "medusa", "hping3": "hping3",
        "scapy": "scapy3", "yersinia": "yersinia", "hashcat": "hashcat",
        "john": "john", "searchsploit": "searchsploit", "seclists": "ls",
        "ligolo-ng": "ligolo-ng", "chisel": "chisel", "rlwrap": "rlwrap",
        "pspy": "pspy", "msfvenom": "msfvenom", "pwncat": "pwncat",
        "grype": "grype", "radare2": "r2", "openvas": "openvas",
        "chkrootkit": "chkrootkit", "rkhunter": "rkhunter",
    }
    if tool_name in generic_tools:
        return shutil.which(generic_tools[tool_name]) or generic_tools[tool_name], []
    return None, []'''


# ─────────────────────────────────────────────────────────────
# PATCH 7 — Remove duplicate bfAutoLoad definition
#           (it was inside pg() before — now in generic runner)
# ─────────────────────────────────────────────────────────────

OLD_BFAUTO = "  if(id==='brute')setTimeout(bfAutoLoad,300);"
NEW_BFAUTO = "  if(id==='brute')setTimeout(function(){bfAutoLoad&&bfAutoLoad();},300);"


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print()
    print(B+C+"╔══════════════════════════════════════════════════════╗"+X)
    print(B+C+"║  VulnScan Pro — Collapsible Nav + New Tools Patch   ║"+X)
    print(B+C+"╚══════════════════════════════════════════════════════╝"+X)
    print()

    missing = [f for f in ["api_server.py", "backend.py"] if not os.path.isfile(f)]
    if missing:
        print(R+B+f"  ERROR: Must be run from the VulnScan project root."+X)
        print(f"  Missing: {', '.join(missing)}")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    TARGET = "api_server.py"
    print(B+f"  ── Patching {TARGET}"+X)

    apply(TARGET, [
        ("Nav: collapsible categories + new tool entries",
         OLD_NAV, NEW_NAV),
        ("JS: PAGE_TITLES expanded with new tools",
         OLD_TITLES, NEW_TITLES),
        ("HTML: stub pages for all new tools",
         OLD_PAGES_ANCHOR, NEW_PAGES_ANCHOR),
        ("JS: runGenericTool() helper + loadUser()",
         OLD_JS_LOADUSER, NEW_JS_LOADUSER),
        ("Route: /social-tools/run allowed tools expanded",
         OLD_TOOL_ALLOW, NEW_TOOL_ALLOW),
        ("_social_tool_binary: generic tool passthrough",
         OLD_TOOL_BINARY_END, NEW_TOOL_BINARY_END),
        ("pg(): safe bfAutoLoad call",
         OLD_BFAUTO, NEW_BFAUTO),
    ])

    print()

    # Syntax check
    if RESULTS["files"]:
        print(B+"  Syntax checks:"+X)
        all_ok = True
        for path in RESULTS["files"]:
            passed, err = syntax_check(path)
            if passed:
                ok(f"{path} — syntax OK")
            else:
                fail(f"{path} — SYNTAX ERROR: {err}")
                all_ok = False
        print()
        if not all_ok:
            warn("Syntax error detected. Restore with:  cp api_server.py.*.bak api_server.py")
    else:
        if RESULTS["skipped"]:
            info("All patches already applied — nothing to do.")
        elif RESULTS["failed"]:
            warn("No files modified (all patches failed to find their anchors).")

    # Summary
    print(B+C+"══════════════════════════════════════════════════════"+X)
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if RESULTS['failed'] else D)}{RESULTS['failed']}{X}"
    )
    print()

    for path in RESULTS["files"]:
        print(f"  {G}✓{X}  Modified : {path}  {D}(backup saved){X}")

    if RESULTS["restart"]:
        print()
        print(f"  {Y}Restart server to apply changes:{X}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
        print()
        print(f"  {G}What changed:{X}")
        print(f"    {G}✓{X}  All nav categories are now collapsible (state persisted in localStorage)")
        print(f"    {G}✓{X}  26 new tools added across Information, Web Testing, Attacks,")
        print(f"         Password Attacks, Auditing, Exploit/Payload, Reverse Engineering,")
        print(f"         C2/Pivoting (new) categories")
        print(f"    {G}✓{X}  Each new tool gets a stub page with args input + output terminal")
        print(f"    {G}✓{X}  /social-tools/run endpoint accepts all new tool names")
        print(f"    {G}✓{X}  runGenericTool() JS helper handles all new tool pages uniformly")
    elif RESULTS["skipped"]:
        print(f"  {G}Already up to date.{X}")

    print()


if __name__ == "__main__":
    main()
