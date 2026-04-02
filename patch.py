#!/usr/bin/env python3
"""
VulnScan Pro — Comprehensive UI Improvements Patch
===================================================
Addresses all 13 requirements:
 1.  Home screen shows all tools categorized
 2.  Dashboard shows more detailed information
 3.  All category collapse panels closed by default
 4.  Only one category expandable at a time
 5.  Admin Console removed from nav category list
 6.  Home, Dashboard, History removed from nav category list
 7.  Different theme for category headers vs tool items
 8.  Admin Services Quick Add allows free-text entry
 9.  Admin Services allows editing existing services
10.  Scan completion notification for every tool
11.  Cancel button for ALL tool actions
12.  Quick Install section removed from all tool pages
13.  (combined with above)

Run from project root:
    python3 patch_ui_improvements.py
"""

import os, re, sys, shutil
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")

TARGET = "api_server.py"
RESULTS = {"applied": 0, "skipped": 0, "failed": 0}


def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.ui_patch_{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def apply_patch(src, label, old, new):
    if old in src:
        result = src.replace(old, new, 1)
        ok(label)
        RESULTS["applied"] += 1
        return result
    elif new in src:
        from patch_ui_improvements import skip
        pass
    if new in src:
        print(f"  {D}·{X}  {label} (already applied)")
        RESULTS["skipped"] += 1
        return src
    else:
        fail(f"{label} — anchor not found")
        RESULTS["failed"] += 1
        return src


def apply_patch_safe(src, label, old, new):
    if old in src:
        result = src.replace(old, new, 1)
        ok(label)
        RESULTS["applied"] += 1
        return result
    elif new in src:
        print(f"  {D}·{X}  {label} (already applied)")
        RESULTS["skipped"] += 1
        return src
    else:
        fail(f"{label} — anchor not found")
        RESULTS["failed"] += 1
        return src


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║  VulnScan Pro — Comprehensive UI Improvements Patch      ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET):
        fail(f"Must be run from project root — {TARGET} not found")
        sys.exit(1)

    src = read_file(TARGET)
    bak = backup(TARGET)
    info(f"Backup: {bak}")

    # ══════════════════════════════════════════════════════════
    # PATCH 1: Fix navToggle JS — all closed by default,
    #          one-open-at-a-time, remove Admin/Overview from nav
    # ══════════════════════════════════════════════════════════
    hdr("Patch 1 — Nav: closed by default, one-open-at-a-time, category styling")

    OLD_NAV_TOGGLE = r"""function navToggle(id){
  var items=document.getElementById('nc-'+id);
  var arrow=document.getElementById('na-'+id);
  if(!items)return;
  var collapsed=items.classList.contains('collapsed');
  if(collapsed){
    document.querySelectorAll('.nav-cat-items.expanded').forEach(function(openItems){
      if(openItems.id===('nc-'+id))return;
      openItems.classList.remove('expanded');
      openItems.classList.add('collapsed');
      var aid=openItems.id.replace(/^nc-/,'');
      var ael=document.getElementById('na-'+aid);
      if(ael)ael.classList.remove('open');
      try{localStorage.setItem('vs-nav-'+aid,'0');}catch(e){}
    });
  }
  items.classList.toggle('collapsed',!collapsed);
  items.classList.toggle('expanded',collapsed);
  if(arrow)arrow.classList.toggle('open',collapsed);
  try{localStorage.setItem('vs-nav-'+id,collapsed?'1':'0');}catch(e){}
}
function navRestore(){
  var openedOne=false;
  ['overview','information','webtesting','attacks','webapp','passwords','recon','exploitation','auditing','c2','social','reverseeng','tunneling','admin'].forEach(function(id){
    var items=document.getElementById('nc-'+id);
    var arrow=document.getElementById('na-'+id);
    if(!items)return;
    var stored;try{stored=localStorage.getItem('vs-nav-'+id);}catch(e){}
    // Default is NOW CLOSED (0) — user preference overrides on repeat visits
    var open=(stored===null)?0:(stored==='1'?1:0);
    if(openedOne&&open)open=0;
    if(open)openedOne=true;
    items.classList.toggle('collapsed',!open);
    items.classList.toggle('expanded',!!open);
    if(arrow)arrow.classList.toggle('open',!!open);
  });
}
function navPruneSections(){
  var overview=document.getElementById('nc-overview');
  if(overview&&overview.closest('.nav-section'))overview.closest('.nav-section').style.display='none';
  var adminSec=document.getElementById('admin-nav-section');
  if(adminSec)adminSec.style.display='none';
}
document.addEventListener('DOMContentLoaded',navRestore);
document.addEventListener('DOMContentLoaded',navPruneSections);"""

    NEW_NAV_TOGGLE = r"""function navToggle(id){
  var items=document.getElementById('nc-'+id);
  var arrow=document.getElementById('na-'+id);
  if(!items)return;
  var collapsed=items.classList.contains('collapsed');
  /* Close ALL other open sections first (one-open-at-a-time) */
  document.querySelectorAll('.nav-cat-items.expanded').forEach(function(openItems){
    if(openItems.id===('nc-'+id))return;
    openItems.style.maxHeight='0px';
    openItems.classList.remove('expanded');
    openItems.classList.add('collapsed');
    var aid=openItems.id.replace(/^nc-/,'');
    var ael=document.getElementById('na-'+aid);
    if(ael)ael.classList.remove('open');
    try{localStorage.setItem('vs-nav-'+aid,'0');}catch(e){}
  });
  if(collapsed){
    items.style.maxHeight=items.scrollHeight+'px';
    setTimeout(function(){if(items.classList.contains('expanded'))items.style.maxHeight='none';},300);
  } else {
    items.style.maxHeight=items.scrollHeight+'px';
    requestAnimationFrame(function(){items.style.maxHeight='0px';});
  }
  items.classList.toggle('collapsed',!collapsed);
  items.classList.toggle('expanded',collapsed);
  if(arrow)arrow.classList.toggle('open',collapsed);
  try{localStorage.setItem('vs-nav-'+id,collapsed?'1':'0');}catch(e){}
}
function navRestore(){
  /* All sections CLOSED by default — never auto-open */
  ['information','webtesting','attacks','webapp','passwords','recon','exploitation','auditing','c2','social','reverseeng','tunneling'].forEach(function(id){
    var items=document.getElementById('nc-'+id);
    var arrow=document.getElementById('na-'+id);
    if(!items)return;
    items.style.maxHeight='0px';
    items.classList.add('collapsed');
    items.classList.remove('expanded');
    if(arrow)arrow.classList.remove('open');
    try{localStorage.removeItem('vs-nav-'+id);}catch(e){}
  });
}
function navPruneSections(){
  /* Hide overview section (Home/Dash/History handled by topbar) */
  var overview=document.getElementById('nc-overview');
  if(overview&&overview.closest('.nav-section'))overview.closest('.nav-section').style.display='none';
  /* Hide admin section from regular nav */
  var adminSec=document.getElementById('admin-nav-section');
  if(adminSec)adminSec.style.display='none';
}
document.addEventListener('DOMContentLoaded',navRestore);
document.addEventListener('DOMContentLoaded',navPruneSections);"""

    src = apply_patch_safe(src, "Nav toggle — closed by default, one-open-at-a-time", OLD_NAV_TOGGLE, NEW_NAV_TOGGLE)

    # ══════════════════════════════════════════════════════════
    # PATCH 2: Category header styling — distinct from tool items
    # ══════════════════════════════════════════════════════════
    hdr("Patch 2 — Category header distinct styling")

    OLD_CAT_STYLE = """.nav-cat-toggle{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:6px 8px;border-radius:var(--radius);user-select:none;background:linear-gradient(180deg,rgba(127,140,141,.12),rgba(127,140,141,.06));border:1px solid rgba(127,140,141,.25)}
.nav-cat-toggle:hover{background:linear-gradient(180deg,rgba(52,152,219,.16),rgba(52,152,219,.08));border-color:rgba(52,152,219,.35)}
.nav-cat-label{font-family:var(--mono);font-size:9px;color:var(--text2);letter-spacing:2px;font-weight:700}
.nav-cat-arrow{font-size:9px;color:var(--text3);transition:transform 0.2s}
.nav-cat-arrow.open{transform:rotate(180deg)}
.nav-cat-items{overflow:hidden;transition:max-height 0.25s ease,opacity 0.2s}
.nav-cat-items.collapsed{max-height:0!important;opacity:0;pointer-events:none}
.nav-cat-items.expanded{opacity:1}"""

    NEW_CAT_STYLE = """.nav-cat-toggle{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:7px 10px;border-radius:var(--radius);user-select:none;background:var(--accent);border:1px solid var(--accent);margin:2px 0;transition:opacity 0.15s ease,transform 0.15s ease}
.nav-cat-toggle:hover{opacity:0.85;transform:translateX(1px)}
.nav-cat-label{font-family:var(--mono);font-size:9px;color:var(--accent-inv);letter-spacing:2px;font-weight:700}
.nav-cat-arrow{font-size:9px;color:var(--accent-inv);opacity:0.7;transition:transform 0.25s ease}
.nav-cat-arrow.open{transform:rotate(180deg);opacity:1}
.nav-cat-items{overflow:hidden;transition:max-height 0.3s ease,opacity 0.25s ease;max-height:0;opacity:0}
.nav-cat-items.collapsed{max-height:0!important;opacity:0;pointer-events:none}
.nav-cat-items.expanded{opacity:1}
.nav-cat-items .nav-item{padding-left:16px;border-left:2px solid var(--border);margin-left:6px;border-radius:0 var(--radius) var(--radius) 0}
.nav-cat-items .nav-item:hover{border-left-color:var(--accent)}
.nav-cat-items .nav-item.active{border-left-color:var(--accent)}"""

    src = apply_patch_safe(src, "Category header styling — distinct accent background", OLD_CAT_STYLE, NEW_CAT_STYLE)

    # ══════════════════════════════════════════════════════════
    # PATCH 3: Home screen tool catalog — show all tools
    # ══════════════════════════════════════════════════════════
    hdr("Patch 3 — Home screen comprehensive tool catalog")

    OLD_HOME_CATALOG = """function renderHomeToolCatalog(){
  var out=document.getElementById('home-tool-catalog');
  if(!out)return;
  var sections=Array.from(document.querySelectorAll('.nav-section')).filter(function(sec){
    if(sec.style.display==='none')return false;
    var labelEl=sec.querySelector('.nav-cat-label');
    var items=sec.querySelectorAll('.nav-item');
    if(!labelEl||!items.length)return false;
    return true;
  });
  out.innerHTML=sections.map(function(sec){
    var label=sec.querySelector('.nav-cat-label').textContent.trim();
    var tools=Array.from(sec.querySelectorAll('.nav-item')).map(function(btn){
      var pid=btn.id.replace(/^ni-/,'');
      var nm=(btn.textContent||'').replace(/\\s+/g,' ').trim();
      return '<button class="tag" style="cursor:pointer" onclick="pg(\\''+pid+'\\',null)">'+nm+'</button>';
    }).join('');
    return '<div style="border:1px solid var(--border);border-radius:10px;padding:10px;background:var(--bg2)">'+
      '<div style="font-size:11px;color:var(--text3);letter-spacing:1px;margin-bottom:8px">'+label+'</div>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap">'+tools+'</div></div>';
  }).join('');
}"""

    NEW_HOME_CATALOG = """/* Full tool catalog for home screen — static definition so it always renders
   correctly regardless of nav section visibility state */
var HOME_TOOL_CATALOG = [
  {label:'INFORMATION', color:'#5a9fe0', tools:[
    {id:'scan',name:'Network Scanner',desc:'Port scan · CVE lookup · SSL · DNS · Headers'},
    {id:'dnsrecon',name:'DNSRecon',desc:'DNS enumeration and zone analysis'},
    {id:'disc',name:'Net Discovery',desc:'Discover live hosts on a subnet'},
    {id:'harvester',name:'theHarvester',desc:'OSINT emails, subdomains, IPs'},
    {id:'sub',name:'Subdomain Finder',desc:'DNS brute-force + passive enumeration'},
    {id:'legion',name:'Legion',desc:'Auto-recon framework'},
    {id:'searchsploit',name:'SearchSploit',desc:'Exploit-DB offline search'},
    {id:'seclists',name:'SecLists',desc:'Security wordlists browser'},
  ]},
  {label:'WEB TESTING', color:'#00e5ff', tools:[
    {id:'webdeep',name:'Deep Web Audit',desc:'Full multi-tool website assessment'},
    {id:'nikto',name:'Nikto',desc:'Web server vulnerability scanner'},
    {id:'wpscan',name:'WPScan',desc:'WordPress security scanner'},
    {id:'dir',name:'Dir Buster',desc:'Hidden paths and file enumeration'},
    {id:'ffuf',name:'ffuf',desc:'Fast web fuzzer'},
    {id:'nuclei',name:'Nuclei',desc:'Template-based vuln scanner'},
    {id:'whatweb',name:'WhatWeb',desc:'Web technology fingerprinter'},
    {id:'wapiti',name:'Wapiti',desc:'Web app vulnerability scanner'},
    {id:'dalfox',name:'Dalfox',desc:'XSS parameter analysis'},
    {id:'sqlmap',name:'SQLMap',desc:'SQL injection detection'},
    {id:'kxss',name:'kxss',desc:'XSS reflection checker'},
  ]},
  {label:'ATTACKS', color:'#ff6b35', tools:[
    {id:'brute',name:'Brute Force',desc:'Credential testing HTTP/SSH'},
    {id:'medusa',name:'Medusa',desc:'Fast parallel network login auditor'},
    {id:'hping3',name:'hping3',desc:'TCP/IP packet assembler'},
    {id:'scapy',name:'Scapy',desc:'Interactive packet manipulation'},
    {id:'yersinia',name:'Yersinia',desc:'Network protocol attacks'},
  ]},
  {label:'PASSWORD ATTACKS', color:'#ff3366', tools:[
    {id:'hashcat',name:'Hashcat',desc:'GPU-based password recovery'},
    {id:'john',name:'John the Ripper',desc:'Versatile password cracker'},
  ]},
  {label:'SOCIAL ENGINEERING', color:'#b06fff', tools:[
    {id:'setoolkit',name:'SET',desc:'Social-Engineer Toolkit'},
    {id:'gophish',name:'Gophish',desc:'Phishing campaign manager'},
    {id:'evilginx2',name:'Evilginx2',desc:'Reverse-proxy phishing simulation'},
    {id:'shellphish',name:'ShellPhish',desc:'Template-driven phishing framework'},
  ]},
  {label:'C2 / PIVOTING', color:'#ffd60a', tools:[
    {id:'netcat',name:'Netcat',desc:'TCP/UDP networking utility'},
    {id:'ncat',name:'Ncat',desc:'Nmap Netcat replacement'},
    {id:'socat',name:'Socat',desc:'Bidirectional data relay'},
    {id:'sliver',name:'Sliver',desc:'C2 framework'},
    {id:'empire',name:'Empire',desc:'Post-exploitation framework'},
    {id:'ligolo',name:'Ligolo-ng',desc:'Advanced tunneling tool'},
    {id:'chisel',name:'Chisel',desc:'TCP/UDP tunnel over HTTP'},
    {id:'rlwrap',name:'rlwrap',desc:'Readline wrapper for CLI tools'},
    {id:'pspy',name:'pspy',desc:'Process spy without root'},
  ]},
  {label:'EXPLOIT / PAYLOAD', color:'#e05a4e', tools:[
    {id:'msfvenom',name:'msfvenom',desc:'Metasploit payload generator'},
    {id:'pwncat',name:'pwncat',desc:'Feature-rich reverse shell handler'},
    {id:'grype',name:'Grype',desc:'Container vulnerability scanner'},
  ]},
  {label:'REVERSE ENGINEERING', color:'#00ff9d', tools:[
    {id:'radare2',name:'Radare2',desc:'Reverse engineering framework'},
  ]},
  {label:'AUDITING', color:'#3db870', tools:[
    {id:'lynis',name:'Lynis',desc:'System audit · hardening · compliance'},
    {id:'openvas',name:'OpenVAS',desc:'Open vulnerability assessment'},
    {id:'chkrootkit',name:'chkrootkit',desc:'Local rootkit detector'},
    {id:'rkhunter',name:'rkhunter',desc:'Rootkit Hunter'},
  ]},
];

function renderHomeToolCatalog(){
  var out=document.getElementById('home-tool-catalog');
  if(!out)return;
  out.innerHTML=HOME_TOOL_CATALOG.map(function(cat){
    var tools=cat.tools.map(function(t){
      return '<div class="home-tool-card" onclick="pg(\''+t.id+'\',null)" title="'+t.desc+'">'+
        '<div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px">'+t.name+'</div>'+
        '<div style="font-size:10px;color:var(--text3);line-height:1.4">'+t.desc+'</div>'+
        '</div>';
    }).join('');
    return '<div class="home-cat-block">'+
      '<div class="home-cat-label" style="border-left-color:'+cat.color+'">'+cat.label+'</div>'+
      '<div class="home-tools-grid">'+tools+'</div>'+
      '</div>';
  }).join('');
}"""

    src = apply_patch_safe(src, "Home tool catalog — comprehensive static definition", OLD_HOME_CATALOG, NEW_HOME_CATALOG)

    # Add CSS for home tool cards
    OLD_HOME_CSS_ANCHOR = """.found{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:20px;font-family:var(--mono);font-size:11px;color:var(--text2);position:relative;z-index:2}"""

    NEW_HOME_CSS_ANCHOR = """.found{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:20px;font-family:var(--mono);font-size:11px;color:var(--text2);position:relative;z-index:2}
.home-cat-block{margin-bottom:18px}
.home-cat-label{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--text2);letter-spacing:2px;padding:4px 0 4px 10px;border-left:3px solid var(--accent);margin-bottom:10px}
.home-tools-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.home-tool-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;cursor:pointer;transition:border-color 0.15s ease,transform 0.15s ease,box-shadow 0.15s ease}
.home-tool-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:var(--shadow-md)}
.home-tool-card:active{transform:translateY(0) scale(0.98)}"""

    src = apply_patch_safe(src, "Home tool card CSS styles", OLD_HOME_CSS_ANCHOR, NEW_HOME_CSS_ANCHOR)

    # ══════════════════════════════════════════════════════════
    # PATCH 4: Dashboard — more detailed information
    # ══════════════════════════════════════════════════════════
    hdr("Patch 4 — Dashboard more detailed information")

    OLD_DASH = """async function loadDash(){
  try{
    var r=await fetch('/history?limit=100');var d=await r.json();
    if(!d.length){document.getElementById('dash-content').innerHTML='<div style="color:var(--text3)">Run some scans first.</div>';return;}
    var tc=d.reduce(function(a,s){return a+s.total_cves;},0),cr=d.reduce(function(a,s){return a+s.critical_cves;},0),tp=d.reduce(function(a,s){return a+s.open_ports;},0);
    var avg=(tc/d.length)||0;
    var risky=d.filter(function(s){return (s.critical_cves||0)>0;}).length;
    var last=d[0]||{};
    var recent7=d.slice(0,7).reduce(function(a,s){return a+s.total_cves;},0);
    var mx=Math.max.apply(null,d.map(function(s){return s.total_cves;}).concat([1]));
    document.getElementById('dash-content').innerHTML=
      '<div class="stats" style="margin-bottom:18px">'+
        '<div class="stat"><div class="stat-val">'+d.length+'</div><div class="stat-lbl">SCANS</div></div>'+
        '<div class="stat"><div class="stat-val">'+tc+'</div><div class="stat-lbl">TOTAL CVEs</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--red)">'+cr+'</div><div class="stat-lbl">CRITICAL</div></div>'+
        '<div class="stat"><div class="stat-val">'+tp+'</div><div class="stat-lbl">OPEN PORTS</div></div>'+
        '<div class="stat"><div class="stat-val">'+avg.toFixed(1)+'</div><div class="stat-lbl">AVG CVE / SCAN</div></div>'+
        '<div class="stat"><div class="stat-val">'+risky+'</div><div class="stat-lbl">RISKY TARGETS</div></div>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px">'+
        '<div class="card card-p"><div class="card-title" style="margin-bottom:12px">Top Targets by CVEs</div>'+d.slice(0,6).map(function(s){return'<div class="bar-row"><span class="bar-label">'+s.target.substring(0,16)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+((s.total_cves/mx)*100)+'%"></div></div><span class="bar-val" style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+s.total_cves+'</span></div>';}).join('')+'</div>'+
        '<div class="card card-p"><div class="card-title" style="margin-bottom:12px">Recent Activity</div>'+d.slice(0,10).map(function(s){return'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="font-family:var(--mono)">'+s.target+'</span><span style="color:'+(s.critical_cves>0?'var(--red)':'var(--text3)')+'">'+(s.critical_cves>0?s.critical_cves+' critical':s.total_cves+' CVEs')+'</span></div>';}).join('')+'</div>'+
        '<div class="card card-p"><div class="card-title" style="margin-bottom:12px">Risk Summary</div>'+
          '<div style="display:grid;gap:8px;font-size:12px">'+
            '<div><span style="color:var(--text3)">Latest target:</span> <span style="font-family:var(--mono)">'+(last.target||'--')+'</span></div>'+
            '<div><span style="color:var(--text3)">Latest scan:</span> '+((last.scan_time||'').replace('T',' ').substring(0,19)||'--')+'</div>'+
            '<div><span style="color:var(--text3)">CVEs in last 7 scans:</span> '+recent7+'</div>'+
            '<div><span style="color:var(--text3)">Critical rate:</span> '+((cr/Math.max(tc,1))*100).toFixed(1)+'%</div>'+
          '</div></div>'+
      '</div>';
  }catch(e){document.getElementById('dash-content').innerHTML='<div style="color:var(--red)">'+e.message+'</div>';}
}"""

    NEW_DASH = """async function loadDash(){
  try{
    var r=await fetch('/history?limit=200');var d=await r.json();
    var el=document.getElementById('dash-content');
    if(!d.length){el.innerHTML='<div style="color:var(--text3)">Run some scans first.</div>';return;}
    var tc=d.reduce(function(a,s){return a+s.total_cves;},0);
    var cr=d.reduce(function(a,s){return a+s.critical_cves;},0);
    var tp=d.reduce(function(a,s){return a+s.open_ports;},0);
    var avg=(tc/d.length)||0;
    var risky=d.filter(function(s){return(s.critical_cves||0)>0;}).length;
    var clean=d.filter(function(s){return(s.total_cves||0)===0;}).length;
    var last=d[0]||{};
    var recent7=d.slice(0,7).reduce(function(a,s){return a+s.total_cves;},0);
    var mx=Math.max.apply(null,d.map(function(s){return s.total_cves;}).concat([1]));
    var critRate=((cr/Math.max(tc,1))*100).toFixed(1);
    /* Severity breakdown */
    var highC=d.reduce(function(a,s){return a+(s.high_cves||0);},0);
    /* Top 5 unique targets */
    var targetMap={};d.forEach(function(s){if(!targetMap[s.target])targetMap[s.target]={cves:0,scans:0,critical:0};targetMap[s.target].cves+=s.total_cves;targetMap[s.target].scans++;targetMap[s.target].critical+=s.critical_cves;});
    var topTargets=Object.entries(targetMap).sort(function(a,b){return b[1].cves-a[1].cves;}).slice(0,8);
    /* Last 30 days activity */
    var now=new Date();
    var days30=d.filter(function(s){return s.scan_time&&(now-new Date(s.scan_time))<30*86400000;});
    /* Modules used */
    var modMap={};d.forEach(function(s){(s.modules||'').split(',').forEach(function(m){if(m.trim())modMap[m.trim()]=(modMap[m.trim()]||0)+1;});});
    var topMods=Object.entries(modMap).sort(function(a,b){return b[1]-a[1];}).slice(0,6);
    el.innerHTML=
      '<div class="stats" style="margin-bottom:18px">'+
        '<div class="stat"><div class="stat-val">'+d.length+'</div><div class="stat-lbl">TOTAL SCANS</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--yellow)">'+tc+'</div><div class="stat-lbl">TOTAL CVEs</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--red)">'+cr+'</div><div class="stat-lbl">CRITICAL</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--orange)">'+highC+'</div><div class="stat-lbl">HIGH</div></div>'+
        '<div class="stat"><div class="stat-val">'+tp+'</div><div class="stat-lbl">OPEN PORTS</div></div>'+
        '<div class="stat"><div class="stat-val">'+avg.toFixed(1)+'</div><div class="stat-lbl">AVG CVE/SCAN</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--red)">'+risky+'</div><div class="stat-lbl">RISKY TARGETS</div></div>'+
        '<div class="stat"><div class="stat-val" style="color:var(--green)">'+clean+'</div><div class="stat-lbl">CLEAN SCANS</div></div>'+
        '<div class="stat"><div class="stat-val">'+days30.length+'</div><div class="stat-lbl">LAST 30 DAYS</div></div>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:14px">'+

        /* KPI cards */
        '<div class="card card-p">'+
          '<div class="card-title" style="margin-bottom:12px">Risk Overview</div>'+
          '<div style="display:grid;gap:8px;font-size:12px">'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text3)">Critical rate</span><span style="color:var(--red);font-family:var(--mono);font-weight:600">'+critRate+'%</span></div>'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text3)">Risky targets</span><span style="color:var(--orange);font-family:var(--mono)">'+risky+' / '+Object.keys(targetMap).length+'</span></div>'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text3)">CVEs last 7 scans</span><span style="font-family:var(--mono)">'+recent7+'</span></div>'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text3)">Avg open ports</span><span style="font-family:var(--mono)">'+(tp/d.length).toFixed(1)+'</span></div>'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text3)">Latest target</span><span style="font-family:var(--mono);color:var(--text)">'+(last.target||'--').substring(0,20)+'</span></div>'+
            '<div style="display:flex;justify-content:space-between;padding:7px 0"><span style="color:var(--text3)">Latest scan</span><span style="font-family:var(--mono);font-size:11px">'+((last.scan_time||'').replace('T',' ').substring(0,16)||'--')+'</span></div>'+
          '</div>'+
        '</div>'+

        /* Top targets */
        '<div class="card card-p">'+
          '<div class="card-title" style="margin-bottom:12px">Top Targets by CVEs</div>'+
          topTargets.map(function(kv){return'<div class="bar-row"><span class="bar-label">'+kv[0].substring(0,16)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+((kv[1].cves/mx)*100)+'%"></div></div><span class="bar-val" style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+kv[1].cves+'</span></div>';}).join('')+
        '</div>'+

        /* Modules used */
        (topMods.length?'<div class="card card-p"><div class="card-title" style="margin-bottom:12px">Most Used Modules</div>'+topMods.map(function(kv){return'<div class="bar-row"><span class="bar-label">'+kv[0].substring(0,16)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+((kv[1]/d.length)*100)+'%"></div></div><span class="bar-val" style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+kv[1]+'</span></div>';}).join('')+'</div>':'')+

      '</div>'+

      /* Recent activity table */
      '<div class="card">'+
        '<div class="card-header"><div class="card-title">Recent Scan Activity</div></div>'+
        '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CRITICAL</th><th>CVEs</th><th>MODULES</th><th></th></tr></thead><tbody>'+
        d.slice(0,20).map(function(s){return'<tr>'+
          '<td style="color:var(--text3);font-family:var(--mono)">#'+s.id+'</td>'+
          '<td style="font-family:var(--mono)">'+s.target+'</td>'+
          '<td style="color:var(--text3);font-size:11px">'+((s.scan_time||'').replace('T',' ').substring(0,16))+'</td>'+
          '<td style="font-family:var(--mono)">'+s.open_ports+'</td>'+
          '<td style="color:'+(s.critical_cves>0?'var(--red)':'var(--green)')+';font-weight:600">'+s.critical_cves+'</td>'+
          '<td style="color:'+(s.total_cves>0?'var(--yellow)':'var(--text3)')+'">'+s.total_cves+'</td>'+
          '<td style="font-size:10px;color:var(--text3)">'+((s.modules||'ports').split(',').join(' · '))+'</td>'+
          '<td><button class="btn btn-ghost btn-sm" onclick="loadScan('+s.id+')">View</button></td>'+
        '</tr>';}).join('')+
        '</tbody></table></div>'+
      '</div>';
  }catch(e){document.getElementById('dash-content').innerHTML='<div style="color:var(--red)">'+e.message+'</div>';}
}"""

    src = apply_patch_safe(src, "Dashboard — detailed stats with breakdown tables", OLD_DASH, NEW_DASH)

    # ══════════════════════════════════════════════════════════
    # PATCH 5: Universal tool completion notification
    # ══════════════════════════════════════════════════════════
    hdr("Patch 5 — Universal tool completion notifications")

    # Patch fetchWithTimeout to always push completion for ALL tools
    OLD_FETCH_COMPLETION = """        if(prefix&&r&&r.ok&&/^\\/(scan|harvester|dnsrecon|nikto|wpscan|legion|subdomains|dirbust|discover|social-tools\\/run|lynis)/.test((url||'')))pushToolCompletion(prefix,url);
        return r;"""

    NEW_FETCH_COMPLETION = """        /* Push completion notification for every tool that has a prefix */
        if(prefix&&r)pushToolCompletion(prefix,url);
        return r;"""

    src = apply_patch_safe(src, "fetchWithTimeout — push completion for ALL tools", OLD_FETCH_COMPLETION, NEW_FETCH_COMPLETION)

    # ══════════════════════════════════════════════════════════
    # PATCH 6: Cancel buttons for ALL tools
    # ══════════════════════════════════════════════════════════
    hdr("Patch 6 — Cancel buttons for all tools via mkTool wrapper")

    # Enhance mkTool to register scanControllers entry and show cancel button
    OLD_MKTOOL = """function mkTool(prefix){
  var logEl=null;
  return{
    start:function(){logEl=document.getElementById(prefix+'-term');if(logEl){logEl.innerHTML='';logEl.classList.add('visible');}var e=document.getElementById(prefix+'-err');if(e){e.textContent='';e.classList.remove('visible');}var r=document.getElementById(prefix+'-res');if(r){r.innerHTML='';r.style.display='none';}startProg(prefix+'-prog');},"""

    NEW_MKTOOL = """function mkTool(prefix){
  var logEl=null;
  var _controller=null;
  return{
    start:function(){
      logEl=document.getElementById(prefix+'-term');
      if(logEl){logEl.innerHTML='';logEl.classList.add('visible');}
      var e=document.getElementById(prefix+'-err');if(e){e.textContent='';e.classList.remove('visible');}
      var r=document.getElementById(prefix+'-res');if(r){r.innerHTML='';r.style.display='none';}
      startProg(prefix+'-prog');
      /* Show cancel button */
      var cb=document.getElementById(prefix+'-cancel');
      if(!cb){
        /* Dynamically create cancel button next to run button */
        var runBtn=document.getElementById(prefix+'-btn');
        if(runBtn&&runBtn.parentNode){
          cb=document.createElement('button');
          cb.id=prefix+'-cancel';
          cb.className='btn btn-outline btn-sm';
          cb.style.cssText='color:var(--red);border-color:rgba(192,57,43,0.3);margin-left:8px';
          cb.textContent='CANCEL';
          cb.onclick=function(){cancelScan(prefix);};
          runBtn.parentNode.insertBefore(cb,runBtn.nextSibling);
        }
      }
      if(cb)cb.style.display='inline-flex';
      setScanRunning(prefix,true);
    },"""

    src = apply_patch_safe(src, "mkTool.start — show cancel button for all tools", OLD_MKTOOL, NEW_MKTOOL)

    # Also update mkTool.end to hide cancel button
    OLD_MKTOOL_END = """    end:function(){endProg(prefix+'-prog');},"""
    NEW_MKTOOL_END = """    end:function(){
      endProg(prefix+'-prog');
      var cb=document.getElementById(prefix+'-cancel');
      if(cb)cb.style.display='none';
      setScanRunning(prefix,false);
    },"""

    src = apply_patch_safe(src, "mkTool.end — hide cancel button when done", OLD_MKTOOL_END, NEW_MKTOOL_END)

    # ══════════════════════════════════════════════════════════
    # PATCH 7: Admin Services — free text + edit existing
    # ══════════════════════════════════════════════════════════
    hdr("Patch 7 — Admin Services: free text entry + edit existing")

    OLD_SVC_PANEL = """          <div class="card">
            <div class="card-header"><div class="card-title">Add New Monitored Service</div></div>
            <div class="card-p">
              <div class="grid3">
                <div class="fg">
                  <label>Quick Add</label>
                  <select class="inp inp-mono" id="svc-preset" onchange="applyServicePreset()">
                    <option value="">-- Select preset --</option>
                    <option value="apache2">Apache service</option>
                    <option value="supabase">Supabase connectivity</option>
                  </select>
                </div>
                <div class="fg"><label>Display Name</label><input class="inp inp-mono" id="svc-label" type="text" placeholder="My Service"/></div>
                <div class="fg"><label>Service Key</label><input class="inp inp-mono" id="svc-key" type="text" placeholder="my-service"/></div>
              </div>
              <div class="grid3">
                <div class="fg">
                  <label>Service Type</label>
                  <select class="inp inp-mono" id="svc-kind">
                    <option value="systemctl">systemctl unit</option>
                    <option value="command">custom command check</option>
                  </select>
                </div>
                <div class="fg"><label>Systemd Unit</label><input class="inp inp-mono" id="svc-unit" type="text" placeholder="apache2"/></div>
                <div class="fg"><label>Check Command (command type)</label><input class="inp inp-mono" id="svc-check" type="text" placeholder="python3 health_check.py"/></div>
              </div>
              <div style="margin-top:10px"><button class="btn btn-primary" onclick="addMonitoredService()">Add Service</button></div>
              <div id="svc-msg" style="margin-top:10px;color:var(--text3);font-size:12px"></div>
            </div>
          </div>"""

    NEW_SVC_PANEL = """          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title" id="svc-form-title">Add New Monitored Service</div>
                <div class="card-sub" id="svc-form-mode-lbl">NEW SERVICE</div>
              </div>
              <button class="btn btn-ghost btn-sm" id="svc-cancel-edit" onclick="cancelServiceEdit()" style="display:none">Cancel Edit</button>
            </div>
            <div class="card-p">
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
                <span style="font-size:11px;color:var(--text3)">Quick presets:</span>
                <button class="btn btn-outline btn-sm" onclick="applyServicePreset('apache2')">Apache</button>
                <button class="btn btn-outline btn-sm" onclick="applyServicePreset('supabase')">Supabase</button>
                <button class="btn btn-outline btn-sm" onclick="applyServicePreset('nginx')">Nginx</button>
                <button class="btn btn-outline btn-sm" onclick="applyServicePreset('clear')">Clear Form</button>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
                <div class="fg"><label>DISPLAY NAME</label><input class="inp inp-mono" id="svc-label" type="text" placeholder="My Service"/></div>
                <div class="fg"><label>SERVICE KEY (unique ID)</label><input class="inp inp-mono" id="svc-key" type="text" placeholder="my-service"/></div>
                <div class="fg"><label>SERVICE TYPE</label>
                  <select class="inp inp-mono" id="svc-kind" onchange="svcKindChange()">
                    <option value="systemctl">systemctl unit</option>
                    <option value="command">custom command</option>
                  </select>
                </div>
              </div>
              <div id="svc-systemctl-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
                <div class="fg"><label>SYSTEMD UNIT NAME</label><input class="inp inp-mono" id="svc-unit" type="text" placeholder="apache2"/></div>
                <div class="fg"><label>DESCRIPTION (optional)</label><input class="inp inp-mono" id="svc-desc" type="text" placeholder="Web server"/></div>
              </div>
              <div id="svc-command-fields" style="display:none;margin-bottom:10px">
                <div class="fg"><label>CHECK COMMAND (runs to verify service health)</label><input class="inp inp-mono" id="svc-check" type="text" placeholder="python3 health_check.py  OR  curl -fs http://localhost:8080/health"/></div>
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:8px">
                  <div class="fg"><label>START COMMAND (optional)</label><input class="inp inp-mono" id="svc-start" type="text" placeholder="systemctl start my-service"/></div>
                  <div class="fg"><label>STOP COMMAND (optional)</label><input class="inp inp-mono" id="svc-stop" type="text" placeholder="systemctl stop my-service"/></div>
                  <div class="fg"><label>RESTART COMMAND (optional)</label><input class="inp inp-mono" id="svc-restart" type="text" placeholder="systemctl restart my-service"/></div>
                </div>
              </div>
              <div style="display:flex;gap:8px;margin-top:10px">
                <button class="btn btn-primary" id="svc-submit-btn" onclick="submitServiceForm()">ADD SERVICE</button>
                <button class="btn btn-ghost btn-sm" onclick="loadAdminServices()">Refresh List</button>
              </div>
              <div id="svc-msg" style="margin-top:10px;color:var(--text3);font-size:12px"></div>
            </div>
          </div>"""

    src = apply_patch_safe(src, "Admin Services panel — free text + edit support", OLD_SVC_PANEL, NEW_SVC_PANEL)

    # Add JS for service form
    OLD_SVC_JS = """function applyServicePreset(){
  var p=(document.getElementById('svc-preset')||{}).value||'';
  if(p==='apache2'){
    document.getElementById('svc-label').value='Apache Service';
    document.getElementById('svc-key').value='apache2';
    document.getElementById('svc-kind').value='systemctl';
    document.getElementById('svc-unit').value='apache2';
    document.getElementById('svc-check').value='';
  }else if(p==='supabase'){
    document.getElementById('svc-label').value='Supabase';
    document.getElementById('svc-key').value='supabase';
    document.getElementById('svc-kind').value='command';
    document.getElementById('svc-unit').value='';
    document.getElementById('svc-check').value='cd ~/vulnscan && python3 -c \\"from dotenv import load_dotenv; load_dotenv(\\'.env\\'); from supabase_config import supabase; supabase().table(\\'users\\').select(\\'id\\').limit(1).execute(); print(\\'✓ Supabase Database Connected!\\')\\"';
  }
}
async function addMonitoredService(){
  var label=(document.getElementById('svc-label')||{}).value||'';
  var key=(document.getElementById('svc-key')||{}).value||'';
  var kind=(document.getElementById('svc-kind')||{}).value||'systemctl';
  var unit=(document.getElementById('svc-unit')||{}).value||'';
  var checkCmd=(document.getElementById('svc-check')||{}).value||'';
  var msg=document.getElementById('svc-msg');
  try{
    var r=await fetch('/api/admin/services',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label,key:key,kind:kind,unit:unit,check_cmd:checkCmd})});
    var d=await r.json();
    if(!r.ok||d.error){if(msg){msg.style.color='var(--red)';msg.textContent=d.error||'Failed to add service';}return;}
    if(msg){msg.style.color='var(--green)';msg.textContent='Service added and monitoring started.';}
    loadAdminServices();
  }catch(e){
    if(msg){msg.style.color='var(--red)';msg.textContent='Error: '+e.message;}
  }
}"""

    NEW_SVC_JS = """var _svcEditKey=null;
function svcKindChange(){
  var kind=(document.getElementById('svc-kind')||{}).value||'systemctl';
  var sf=document.getElementById('svc-systemctl-fields');
  var cf=document.getElementById('svc-command-fields');
  if(sf)sf.style.display=kind==='systemctl'?'grid':'none';
  if(cf)cf.style.display=kind==='command'?'block':'none';
}
function applyServicePreset(p){
  if(p==='apache2'||p==='nginx'){
    var svcName=p==='apache2'?'Apache':'Nginx';
    document.getElementById('svc-label').value=svcName+' Web Server';
    document.getElementById('svc-key').value=p;
    document.getElementById('svc-kind').value='systemctl';
    document.getElementById('svc-unit').value=p;
    if(document.getElementById('svc-check'))document.getElementById('svc-check').value='';
    svcKindChange();
  }else if(p==='supabase'){
    document.getElementById('svc-label').value='Supabase';
    document.getElementById('svc-key').value='supabase';
    document.getElementById('svc-kind').value='command';
    document.getElementById('svc-unit').value='';
    if(document.getElementById('svc-check'))document.getElementById('svc-check').value='cd ~/vulnscan && python3 -c "from dotenv import load_dotenv; load_dotenv(\\'.env\\'); from supabase_config import supabase; supabase().table(\\'users\\').select(\\'id\\').limit(1).execute(); print(\\'OK\\')"';
    svcKindChange();
  }else if(p==='clear'){
    ['svc-label','svc-key','svc-unit','svc-check','svc-desc','svc-start','svc-stop','svc-restart'].forEach(function(id){var el=document.getElementById(id);if(el)el.value='';});
    _svcEditKey=null;
    var ft=document.getElementById('svc-form-title');if(ft)ft.textContent='Add New Monitored Service';
    var fl=document.getElementById('svc-form-mode-lbl');if(fl)fl.textContent='NEW SERVICE';
    var sb=document.getElementById('svc-submit-btn');if(sb)sb.textContent='ADD SERVICE';
    var ce=document.getElementById('svc-cancel-edit');if(ce)ce.style.display='none';
  }
}
function editService(key){
  /* Populate form with existing service data for editing */
  var rows=document.querySelectorAll('[data-svc-key="'+key+'"]');
  var label=key,kind='systemctl',unit=key,checkCmd='',startCmd='',stopCmd='',restartCmd='';
  if(rows.length){
    var row=rows[0];
    label=row.getAttribute('data-svc-label')||key;
    kind=row.getAttribute('data-svc-kind')||'systemctl';
    unit=row.getAttribute('data-svc-unit')||key;
    checkCmd=row.getAttribute('data-svc-check')||'';
    startCmd=row.getAttribute('data-svc-start')||'';
    stopCmd=row.getAttribute('data-svc-stop')||'';
    restartCmd=row.getAttribute('data-svc-restart')||'';
  }
  _svcEditKey=key;
  document.getElementById('svc-label').value=label;
  document.getElementById('svc-key').value=key;
  document.getElementById('svc-kind').value=kind;
  if(document.getElementById('svc-unit'))document.getElementById('svc-unit').value=unit;
  if(document.getElementById('svc-check'))document.getElementById('svc-check').value=checkCmd;
  if(document.getElementById('svc-start'))document.getElementById('svc-start').value=startCmd;
  if(document.getElementById('svc-stop'))document.getElementById('svc-stop').value=stopCmd;
  if(document.getElementById('svc-restart'))document.getElementById('svc-restart').value=restartCmd;
  svcKindChange();
  var ft=document.getElementById('svc-form-title');if(ft)ft.textContent='Edit Service: '+key;
  var fl=document.getElementById('svc-form-mode-lbl');if(fl)fl.textContent='EDITING';
  var sb=document.getElementById('svc-submit-btn');if(sb)sb.textContent='SAVE CHANGES';
  var ce=document.getElementById('svc-cancel-edit');if(ce)ce.style.display='inline-flex';
  /* Scroll to form */
  var card=document.getElementById('svc-submit-btn');if(card)card.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function cancelServiceEdit(){
  _svcEditKey=null;
  ['svc-label','svc-key','svc-unit','svc-check','svc-desc','svc-start','svc-stop','svc-restart'].forEach(function(id){var el=document.getElementById(id);if(el)el.value='';});
  var ft=document.getElementById('svc-form-title');if(ft)ft.textContent='Add New Monitored Service';
  var fl=document.getElementById('svc-form-mode-lbl');if(fl)fl.textContent='NEW SERVICE';
  var sb=document.getElementById('svc-submit-btn');if(sb)sb.textContent='ADD SERVICE';
  var ce=document.getElementById('svc-cancel-edit');if(ce)ce.style.display='none';
}
async function submitServiceForm(){
  var label=(document.getElementById('svc-label')||{}).value||'';
  var key=(document.getElementById('svc-key')||{}).value||'';
  var kind=(document.getElementById('svc-kind')||{}).value||'systemctl';
  var unit=(document.getElementById('svc-unit')||{}).value||'';
  var checkCmd=(document.getElementById('svc-check')||{}).value||'';
  var startCmd=(document.getElementById('svc-start')||{}).value||'';
  var stopCmd=(document.getElementById('svc-stop')||{}).value||'';
  var restartCmd=(document.getElementById('svc-restart')||{}).value||'';
  var msg=document.getElementById('svc-msg');
  var isEdit=!!_svcEditKey;
  try{
    var endpoint=isEdit?'/api/admin/services/'+encodeURIComponent(_svcEditKey):'/api/admin/services';
    var method=isEdit?'PUT':'POST';
    var r=await fetch(endpoint,{method:method,headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:label,key:key,kind:kind,unit:unit,check_cmd:checkCmd,
        control_cmds:{start:startCmd,stop:stopCmd,restart:restartCmd}})});
    var d=await r.json();
    if(!r.ok||d.error){if(msg){msg.style.color='var(--red)';msg.textContent=d.error||'Failed';}return;}
    if(msg){msg.style.color='var(--green)';msg.textContent=isEdit?'Service updated.':'Service added.';}
    cancelServiceEdit();
    loadAdminServices();
  }catch(e){if(msg){msg.style.color='var(--red)';msg.textContent='Error: '+e.message;}}
}
async function addMonitoredService(){submitServiceForm();}"""

    src = apply_patch_safe(src, "Admin Services JS — free text, presets, edit mode", OLD_SVC_JS, NEW_SVC_JS)

    # Patch loadAdminServices to add edit buttons and data attributes
    OLD_LOAD_SVC = """async function loadAdminServices(){
  try{
    var r=await fetch('/api/admin/services');var d=await r.json();
    var list=(d.services||[]);
    var html='<table class="tbl"><thead><tr><th>SERVICE</th><th>TYPE</th><th>UNIT</th><th>STATUS</th><th>DETAIL</th><th>ACTIONS</th></tr></thead><tbody>';
    html+=list.map(function(s){return '<tr><td style="font-family:var(--mono)">'+(s.label||s.key)+'</td><td style="color:var(--text3)">'+(s.kind||'--')+'</td><td style="font-family:var(--mono);font-size:11px">'+(s.unit||'--')+'</td><td>'+svcPill(s.status||'unknown')+'</td><td style="font-size:11px;color:var(--text3);max-width:300px">'+((s.detail||'--').replace(/</g,'&lt;'))+'</td><td style="display:flex;gap:4px;flex-wrap:wrap"><button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'start\')">Start</button><button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'stop\')">Stop</button><button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'restart\')">Restart</button></td></tr>';}).join('');
    html+='</tbody></table>';
    document.getElementById('admin-services-table').innerHTML=html;"""

    NEW_LOAD_SVC = """async function loadAdminServices(){
  try{
    var r=await fetch('/api/admin/services');var d=await r.json();
    var list=(d.services||[]);
    var html='<table class="tbl"><thead><tr><th>SERVICE</th><th>TYPE</th><th>UNIT/CMD</th><th>STATUS</th><th>DETAIL</th><th>ACTIONS</th></tr></thead><tbody>';
    html+=list.map(function(s){
      var unitInfo=(s.kind==='systemctl'?(s.unit||'--'):(s.check_cmd||'custom').substring(0,30));
      return '<tr data-svc-key="'+s.key+'" data-svc-label="'+(s.label||'')+'" data-svc-kind="'+(s.kind||'')+'" data-svc-unit="'+(s.unit||'')+'" data-svc-check="'+(s.check_cmd||'')+'" data-svc-start="'+(s.start_cmd||'')+'" data-svc-stop="'+(s.stop_cmd||'')+'" data-svc-restart="'+(s.restart_cmd||'')+'">'+
        '<td style="font-family:var(--mono);font-weight:500">'+(s.label||s.key)+'</td>'+
        '<td><span class="tag">'+(s.kind||'--')+'</span></td>'+
        '<td style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+unitInfo+'</td>'+
        '<td>'+svcPill(s.status||'unknown')+'</td>'+
        '<td style="font-size:11px;color:var(--text3);max-width:220px">'+((s.detail||'--').replace(/</g,'&lt;').substring(0,80))+'</td>'+
        '<td style="display:flex;gap:4px;flex-wrap:wrap">'+
          '<button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'start\')">Start</button>'+
          '<button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'stop\')">Stop</button>'+
          '<button class="btn btn-outline btn-sm" onclick="serviceAction(\''+s.key+'\',\'restart\')">Restart</button>'+
          '<button class="btn btn-outline btn-sm" style="color:var(--blue)" onclick="editService(\''+s.key+'\')">Edit</button>'+
        '</td></tr>';
    }).join('');
    html+='</tbody></table>';
    document.getElementById('admin-services-table').innerHTML=html;"""

    src = apply_patch_safe(src, "loadAdminServices — add edit buttons and data attributes", OLD_LOAD_SVC, NEW_LOAD_SVC)

    # Add PUT route for editing services in Python
    OLD_SVC_POST_ROUTE = """@app.route("/api/admin/services", methods=["POST"])
def admin_add_service():
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json() or {}
    key = (data.get("key") or data.get("unit") or data.get("label") or "").strip().lower().replace(" ", "-")
    label = (data.get("label") or key or "Service").strip()
    kind = (data.get("kind") or "systemctl").strip().lower()
    if not key:
        return jsonify({"error": "Service key/label is required"}), 400
    if key in MONITORED_SERVICES:
        return jsonify({"error": "Service already exists"}), 400"""

    NEW_SVC_POST_ROUTE = """@app.route("/api/admin/services/<svc_key>", methods=["PUT"])
def admin_edit_service(svc_key):
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    if svc_key not in MONITORED_SERVICES:
        return jsonify({"error": "Service not found"}), 404
    data = request.get_json() or {}
    label = (data.get("label") or svc_key).strip()
    kind = (data.get("kind") or "systemctl").strip().lower()
    unit = (data.get("unit") or "").strip()
    check_cmd = (data.get("check_cmd") or "").strip()
    control_cmds = data.get("control_cmds") or {}
    svc = MONITORED_SERVICES[svc_key]
    svc["label"] = label
    svc["kind"] = kind
    if kind == "systemctl":
        svc["unit"] = unit or svc_key
    else:
        svc["check_cmd"] = check_cmd
        svc["control_cmds"] = control_cmds
        # also expose individual cmds for JS data attrs
        svc["start_cmd"] = control_cmds.get("start", "")
        svc["stop_cmd"] = control_cmds.get("stop", "")
        svc["restart_cmd"] = control_cmds.get("restart", "")
    audit(u["id"], u["username"], "ADMIN_SERVICE_EDIT", target=svc_key,
          ip=request.remote_addr, details=f"kind={kind}")
    return jsonify({"ok": True})


@app.route("/api/admin/services", methods=["POST"])
def admin_add_service():
    u = get_current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json() or {}
    key = (data.get("key") or data.get("unit") or data.get("label") or "").strip().lower().replace(" ", "-")
    label = (data.get("label") or key or "Service").strip()
    kind = (data.get("kind") or "systemctl").strip().lower()
    if not key:
        return jsonify({"error": "Service key/label is required"}), 400
    if key in MONITORED_SERVICES:
        return jsonify({"error": "Service already exists"}), 400"""

    src = apply_patch_safe(src, "Add PUT /api/admin/services/<key> edit route", OLD_SVC_POST_ROUTE, NEW_SVC_POST_ROUTE)

    # Also expose start/stop/restart cmds in the admin_services GET response
    OLD_SVC_GET_ROW = """    for svc in MONITORED_SERVICES.values():
        st = _service_status(svc)
        rows.append({
            **_safe_service_row(svc),
            "status": st.get("status", "unknown"),
            "detail": st.get("detail", ""),
        })"""

    NEW_SVC_GET_ROW = """    for svc in MONITORED_SERVICES.values():
        st = _service_status(svc)
        ctrl = svc.get("control_cmds") or {}
        rows.append({
            **_safe_service_row(svc),
            "status": st.get("status", "unknown"),
            "detail": st.get("detail", ""),
            "check_cmd": svc.get("check_cmd", ""),
            "start_cmd": ctrl.get("start", svc.get("start_cmd", "")),
            "stop_cmd": ctrl.get("stop", svc.get("stop_cmd", "")),
            "restart_cmd": ctrl.get("restart", svc.get("restart_cmd", "")),
        })"""

    src = apply_patch_safe(src, "admin_services GET — expose control cmds for edit", OLD_SVC_GET_ROW, NEW_SVC_GET_ROW)

    # ══════════════════════════════════════════════════════════
    # PATCH 8: Remove Quick Install cards from tool pages
    # ══════════════════════════════════════════════════════════
    hdr("Patch 8 — Remove Quick Install cards via JS")

    OLD_REMOVE_QUICK = """function removeQuickInstallCards(){
  document.querySelectorAll('.card .card-title').forEach(function(t){
    if((t.textContent||'').trim().toLowerCase()==='quick install'){
      var card=t.closest('.card');
      if(card)card.remove();
    }
  });
}"""

    NEW_REMOVE_QUICK = """function removeQuickInstallCards(){
  document.querySelectorAll('.card .card-title, .card-p .card-title').forEach(function(t){
    var txt=(t.textContent||'').trim().toLowerCase();
    if(txt==='quick install'||txt==='install'){
      var card=t.closest('.card');
      if(card)card.remove();
    }
  });
  /* Also remove standalone install divs */
  document.querySelectorAll('[data-quick-install]').forEach(function(el){el.remove();});
}
/* Run on every page navigation */
var _origPg=pg;
function pg(id,el){
  _origPg(id,el);
  setTimeout(removeQuickInstallCards,80);
  setTimeout(removeQuickInstallCards,400);
}"""

    src = apply_patch_safe(src, "removeQuickInstallCards — improved removal logic", OLD_REMOVE_QUICK, NEW_REMOVE_QUICK)

    # ══════════════════════════════════════════════════════════
    # Write file and verify syntax
    # ══════════════════════════════════════════════════════════
    hdr("Writing & Verifying")
    write_file(TARGET, src)
    info(f"Written: {TARGET}")

    import subprocess
    r = subprocess.run([sys.executable, "-m", "py_compile", TARGET], capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"{TARGET} — syntax OK")
    else:
        fail(f"SYNTAX ERROR:\n{r.stderr.strip()}")
        warn(f"Restore with: cp {bak} {TARGET}")
        sys.exit(1)

    # Summary
    print()
    print(B + C + "══════════════════════════════════════════════════════════" + X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if fc else D)}{fc}{X}"
    )
    print()
    if fc == 0:
        print(f"  {G}All improvements applied:{X}")
        improvements = [
            "Home screen — all tools in categorized grid with descriptions",
            "Dashboard — 9 KPI stats + top targets + modules + full activity table",
            "Nav categories — all CLOSED by default",
            "Nav categories — one-open-at-a-time accordion",
            "Nav — Admin Console & Home/Dash/History removed from category list",
            "Nav category headers — distinct accent background styling",
            "Tool items — indented with left border, distinct from headers",
            "Admin Services — free-text entry for new service",
            "Admin Services — preset buttons (Apache, Nginx, Supabase)",
            "Admin Services — Edit button per service with form population",
            "Admin Services — PUT endpoint for editing",
            "Scan notifications — pushed for EVERY tool execution",
            "Cancel button — auto-created for ALL tools via mkTool",
            "Quick Install cards — removed from all tool pages",
        ]
        for i in improvements:
            print(f"    {G}✓{X}  {i}")
        print()
        print(f"  {Y}Restart server:{X} pkill -f api_server.py && python3 api_server.py")
    else:
        print(f"  {Y}{fc} patch(es) failed. Check anchors above.{X}")
        print(f"  {Y}Restore: cp {bak} {TARGET}{X}")
    print()


if __name__ == "__main__":
    main()
