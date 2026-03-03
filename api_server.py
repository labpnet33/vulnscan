#!/usr/bin/env python3
import json, re, sys, os, sqlite3, subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")

# ── Database ──────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, scan_time TEXT, result TEXT,
        open_ports INTEGER, total_cves INTEGER, critical_cves INTEGER)""")
    con.commit(); con.close()

def save_scan(target, result):
    s = result.get("summary",{})
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("INSERT INTO scans(target,scan_time,result,open_ports,total_cves,critical_cves) VALUES(?,?,?,?,?,?)",
        (target, result.get("scan_time",""), json.dumps(result),
         s.get("open_ports",0), s.get("total_cves",0), s.get("critical_cves",0)))
    con.commit(); scan_id=cur.lastrowid; con.close()
    return scan_id

def get_history(limit=20):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT id,target,scan_time,open_ports,total_cves,critical_cves FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [{"id":r[0],"target":r[1],"scan_time":r[2],"open_ports":r[3],"total_cves":r[4],"critical_cves":r[5]} for r in rows]

def get_scan_by_id(scan_id):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT result FROM scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    return json.loads(row[0]) if row else None

init_db()

# ── HTML UI ───────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Syne:wght@400;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;
  --t:#e8e8f0;--m:#5a5a8a;--cyan:#00e5ff;--green:#00ff9d;
  --red:#ff3366;--orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--t);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden}
/* Grid bg */
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,229,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}

/* ── Header ── */
header{position:sticky;top:0;z-index:100;background:rgba(4,4,10,0.9);backdrop-filter:blur(20px);border-bottom:1px solid var(--b);padding:0 32px;display:flex;align-items:center;justify-content:space-between;height:60px}
.brand{display:flex;align-items:center;gap:12px}
.brand-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--red),var(--orange));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 20px rgba(255,51,102,0.4)}
.brand-name{font-size:18px;font-weight:800;letter-spacing:-0.5px;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-tag{font-size:9px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-top:1px}
nav{display:flex;gap:4px}
.nav-btn{padding:7px 16px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px;border-radius:6px;transition:all 0.2s}
.nav-btn:hover,.nav-btn.active{background:var(--b);color:var(--cyan)}

/* ── Layout ── */
.container{max-width:1100px;margin:0 auto;padding:28px 20px;position:relative;z-index:1}
.page{display:none}.page.active{display:block}

/* ── Cards ── */
.card{background:var(--s1);border:1px solid var(--b);border-radius:14px;padding:22px;margin-bottom:18px}
.card-title{font-size:10px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-bottom:14px;font-weight:500}

/* ── Scan Input ── */
.scan-hero{text-align:center;padding:40px 0 28px}
.scan-hero h2{font-size:32px;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.scan-hero p{color:var(--m);font-size:13px;font-family:'JetBrains Mono',monospace}
.scan-box{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}
.scan-input{flex:1;min-width:220px;background:var(--s2);border:1px solid var(--b2);border-radius:10px;color:var(--cyan);padding:13px 18px;font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:border 0.2s}
.scan-input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.08)}
.scan-input::placeholder{color:#2a2a45}
.btn{padding:13px 24px;border:none;border-radius:10px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;letter-spacing:1px;transition:all 0.2s;white-space:nowrap}
.btn-scan{background:linear-gradient(135deg,var(--red),#c0102a);color:#fff;box-shadow:0 4px 20px rgba(255,51,102,0.3)}
.btn-scan:hover{transform:translateY(-1px);box-shadow:0 6px 25px rgba(255,51,102,0.4)}
.btn-scan:disabled{background:var(--b);color:var(--m);cursor:not-allowed;transform:none;box-shadow:none}
.btn-ghost{background:transparent;color:var(--m);border:1px solid var(--b2)}
.btn-ghost:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-sm{padding:6px 14px;font-size:10px}

/* Module toggles */
.modules{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;justify-content:center}
.mod-toggle{padding:6px 14px;border:1px solid var(--b2);border-radius:20px;cursor:pointer;font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--m);background:transparent;transition:all 0.2s}
.mod-toggle.on{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.08)}

/* ── Terminal ── */
#terminal{background:#020208;border:1px solid var(--b);border-radius:10px;padding:14px 16px;margin-bottom:18px;max-height:180px;overflow-y:auto;display:none;font-family:'JetBrains Mono',monospace;font-size:12px}
.tl{line-height:1.9;color:#5a5a8a}
.ti .p{color:var(--cyan)}.ts .p{color:var(--green)}.tw .p{color:var(--yellow)}.te .p{color:var(--red)}
#progress{height:2px;background:var(--b);border-radius:1px;margin-bottom:18px;display:none;overflow:hidden}
#progress-bar{height:100%;width:0;background:linear-gradient(90deg,var(--red),var(--orange),var(--yellow));transition:width 0.3s;border-radius:1px}

/* ── Error ── */
#error-box{background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.25);border-radius:10px;padding:14px 18px;color:var(--red);font-size:13px;margin-bottom:18px;display:none;font-family:'JetBrains Mono',monospace}

/* ── Summary Stats ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--s2);border:1px solid var(--b2);border-radius:10px;padding:16px;text-align:center;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;inset:0;opacity:0.04;border-radius:10px}
.stat-val{font-size:28px;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}
.stat-lbl{color:var(--m);font-size:9px;letter-spacing:2px;margin-top:6px;font-family:'JetBrains Mono',monospace}

/* ── Tab bar ── */
.tab-bar{display:flex;gap:6px;margin-bottom:20px;border-bottom:1px solid var(--b);padding-bottom:0;flex-wrap:wrap}
.tab{padding:10px 18px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.2s}
.tab:hover{color:var(--t)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tab-content{display:none}.tab-content.active{display:block}

/* ── Port Cards ── */
.port-card{border-radius:10px;background:rgba(255,255,255,0.015);margin-bottom:10px;overflow:hidden;transition:all 0.2s}
.port-header{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:14px;flex-wrap:wrap;user-select:none}
.port-num{padding:7px 14px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-weight:800;font-size:16px;min-width:72px;text-align:center;letter-spacing:1px}
.port-info{flex:1;min-width:0}
.port-name{font-weight:700;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.port-sub{color:var(--m);font-size:11px;margin-top:2px;font-family:'JetBrains Mono',monospace}
.port-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{border-radius:5px;padding:3px 9px;font-size:10px;font-weight:700;letter-spacing:1px;font-family:'JetBrains Mono',monospace;border:1px solid transparent}
.exploit-badge{background:rgba(176,111,255,0.15);color:var(--purple);border-color:rgba(176,111,255,0.3);font-size:9px;padding:2px 7px}
.score-num{font-weight:800;font-size:14px;font-family:'JetBrains Mono',monospace}
.chev{color:var(--m);font-size:11px;transition:transform 0.25s;flex-shrink:0}
.port-body{padding:0 18px 18px;border-top:1px solid var(--b);display:none}
.port-body.open{display:block}
.sec-title{color:var(--m);font-size:9px;letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin:16px 0 8px}

/* CVE items */
.cve-item{background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px;margin-bottom:7px}
.cve-top{display:flex;align-items:center;gap:8px;margin-bottom:7px;flex-wrap:wrap}
.cve-id{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;text-decoration:none}
.cve-id:hover{text-decoration:underline}
.cve-date{color:var(--m);font-size:10px;margin-left:auto;font-family:'JetBrains Mono',monospace}
.cve-desc{color:#8e8e93;font-size:12px;line-height:1.7}

/* Mitigations */
.mit-list{background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px}
.mit-item{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid var(--b);font-size:12px;line-height:1.6;color:#c0c0d0}
.mit-item:last-child{border-bottom:none}
.mit-arr{color:var(--green);font-family:'JetBrains Mono',monospace;flex-shrink:0;margin-top:1px}

/* ── SSL Panel ── */
.ssl-card{background:var(--s2);border-radius:10px;padding:18px;margin-bottom:12px;border:1px solid var(--b2)}
.grade-circle{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:900;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.ssl-header{display:flex;align-items:center;gap:18px;margin-bottom:14px}
.ssl-details{display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;font-family:'JetBrains Mono',monospace}
.ssl-detail{background:var(--bg);border-radius:6px;padding:8px 10px;color:var(--m)}
.ssl-detail span{color:var(--t);display:block;margin-top:2px;word-break:break-all}
.issue-item{display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-bottom:1px solid var(--b);font-size:12px}
.issue-item:last-child{border-bottom:none}

/* ── DNS Panel ── */
.dns-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-bottom:14px}
.dns-rec{background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px}
.dns-type{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--cyan);letter-spacing:2px;margin-bottom:6px}
.dns-val{font-size:11px;color:#8e8e93;line-height:1.7;font-family:'JetBrains Mono',monospace;word-break:break-all}
.sub-item{background:var(--s2);border:1px solid var(--b2);border-radius:6px;padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;display:flex;justify-content:space-between;margin-bottom:5px}
.check-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--b);font-size:12px}
.check-row:last-child{border-bottom:none}
.check-icon{font-size:14px;flex-shrink:0}

/* ── Headers Panel ── */
.header-grade{font-size:52px;font-weight:900;font-family:'JetBrains Mono',monospace;line-height:1}
.hdr-list{background:var(--s2);border-radius:8px;overflow:hidden;border:1px solid var(--b2)}
.hdr-item{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;border-bottom:1px solid var(--b);font-size:12px;font-family:'JetBrains Mono',monospace;flex-wrap:wrap;gap:8px}
.hdr-item:last-child{border-bottom:none}
.hdr-key{color:var(--m);flex-shrink:0;min-width:200px}
.hdr-val{color:var(--t);word-break:break-all;text-align:right;max-width:400px}

/* ── Network Discovery ── */
.host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.host-tile{background:var(--s2);border:1px solid var(--b2);border-radius:10px;padding:14px;cursor:pointer;transition:all 0.2s}
.host-tile:hover{border-color:var(--cyan);background:rgba(0,229,255,0.04)}
.host-ip{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;color:var(--cyan)}
.host-name{color:var(--m);font-size:11px;margin-top:3px;font-family:'JetBrains Mono',monospace}
.host-vendor{color:#636366;font-size:10px;margin-top:2px}

/* ── History Table ── */
.hist-table{width:100%;border-collapse:collapse;font-size:12px;font-family:'JetBrains Mono',monospace}
.hist-table th{color:var(--m);font-size:9px;letter-spacing:2px;padding:10px 12px;text-align:left;border-bottom:1px solid var(--b)}
.hist-table td{padding:10px 12px;border-bottom:1px solid var(--b);color:var(--t);vertical-align:middle}
.hist-table tr:hover td{background:rgba(255,255,255,0.02)}
.hist-table tr:last-child td{border-bottom:none}
.link-btn{background:transparent;border:1px solid var(--b2);color:var(--cyan);padding:4px 10px;border-radius:5px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:10px}
.link-btn:hover{background:rgba(0,229,255,0.08)}

/* ── Dashboard ── */
.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:20px}
.bar-chart{display:flex;flex-direction:column;gap:8px}
.bar-row{display:flex;align-items:center;gap:10px;font-size:11px;font-family:'JetBrains Mono',monospace}
.bar-label{color:var(--m);width:80px;text-align:right;flex-shrink:0}
.bar-track{flex:1;background:var(--b);border-radius:3px;height:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;transition:width 1s ease}
.bar-val{color:var(--t);width:30px;flex-shrink:0}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--b2);border-radius:3px}

/* ── Spinner ── */
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── Responsive ── */
@media(max-width:600px){
  header{padding:0 16px}
  .container{padding:16px 12px}
  nav .nav-btn span{display:none}
}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-icon">&#9889;</div>
    <div><div class="brand-name">VulnScan Pro</div><div class="brand-tag">SECURITY INTELLIGENCE</div></div>
  </div>
  <nav>
    <button class="nav-btn active" onclick="showPage('scan')">&#128269; <span>Scanner</span></button>
    <button class="nav-btn" onclick="showPage('discover')">&#127760; <span>Discover</span></button>
    <button class="nav-btn" onclick="showPage('history')">&#128196; <span>History</span></button>
    <button class="nav-btn" onclick="showPage('dashboard')">&#128202; <span>Dashboard</span></button>
  </nav>
</header>

<div class="container">

<!-- ═══ SCAN PAGE ═══ -->
<div class="page active" id="page-scan">
  <div class="scan-hero">
    <h2>Vulnerability Intelligence</h2>
    <p>Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS recon &middot; Header audit</p>
    <div class="scan-box">
      <input class="scan-input" id="target" type="text" placeholder="Enter IP address or hostname  e.g. 192.168.1.1" onkeydown="if(event.key==='Enter')startScan()"/>
      <button class="btn btn-scan" id="sbtn" onclick="startScan()">SCAN</button>
      <button class="btn btn-ghost" onclick="loadDemo()">DEMO</button>
    </div>
    <div class="modules">
      <button class="mod-toggle on" id="mod-ports" onclick="toggleMod('ports')">&#128268; Ports+CVE</button>
      <button class="mod-toggle on" id="mod-ssl" onclick="toggleMod('ssl')">&#128274; SSL/TLS</button>
      <button class="mod-toggle on" id="mod-dns" onclick="toggleMod('dns')">&#127758; DNS Recon</button>
      <button class="mod-toggle on" id="mod-headers" onclick="toggleMod('headers')">&#128196; Web Headers</button>
    </div>
  </div>

  <div id="progress"><div id="progress-bar"></div></div>
  <div id="terminal"></div>
  <div id="error-box"></div>
  <div id="results"></div>
</div>

<!-- ═══ DISCOVER PAGE ═══ -->
<div class="page" id="page-discover">
  <div class="card">
    <div class="card-title">NETWORK DISCOVERY</div>
    <div class="scan-box">
      <input class="scan-input" id="subnet" type="text" placeholder="Subnet e.g. 192.168.1.0/24" onkeydown="if(event.key==='Enter')discoverNetwork()"/>
      <button class="btn btn-scan" id="dbtn" onclick="discoverNetwork()">DISCOVER</button>
    </div>
    <p style="color:var(--m);font-size:11px;margin-top:10px;font-family:'JetBrains Mono',monospace">&#9888; Only scan networks you own or have permission to scan</p>
  </div>
  <div id="discover-results"></div>
</div>

<!-- ═══ HISTORY PAGE ═══ -->
<div class="page" id="page-history">
  <div class="card">
    <div class="card-title">SCAN HISTORY</div>
    <div id="history-content"><p style="color:var(--m);font-size:13px">Loading history...</p></div>
  </div>
</div>

<!-- ═══ DASHBOARD PAGE ═══ -->
<div class="page" id="page-dashboard">
  <div class="card">
    <div class="card-title">SECURITY DASHBOARD</div>
    <div id="dash-content"><p style="color:var(--m);font-size:13px">Run some scans to see statistics here.</p></div>
  </div>
</div>

</div><!-- /container -->

<script>
// ── Constants ─────────────────────────────────
const SEV={
  CRITICAL:{c:"#ff3366",b:"rgba(255,51,102,0.12)",i:"&#9762;"},
  HIGH:{c:"#ff6b35",b:"rgba(255,107,53,0.12)",i:"&#9888;"},
  MEDIUM:{c:"#ffd60a",b:"rgba(255,214,10,0.1)",i:"&#9889;"},
  LOW:{c:"#00ff9d",b:"rgba(0,255,157,0.08)",i:"&#10003;"},
  UNKNOWN:{c:"#5a5a8a",b:"rgba(90,90,138,0.1)",i:"?"}
};
const GRADE_COL={"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"};

// ── Modules state ──────────────────────────────
const mods={ports:true,ssl:true,dns:true,headers:true};
function toggleMod(m){
  mods[m]=!mods[m];
  document.getElementById("mod-"+m).classList.toggle("on",mods[m]);
}

// ── Pages ──────────────────────────────────────
function showPage(p){
  document.querySelectorAll(".page").forEach(el=>el.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(el=>el.classList.remove("active"));
  document.getElementById("page-"+p).classList.add("active");
  event.currentTarget.classList.add("active");
  if(p==="history")loadHistory();
  if(p==="dashboard")loadDashboard();
}

// ── Logging ────────────────────────────────────
let logEl;
function initLog(){logEl=document.getElementById("terminal");logEl.innerHTML="";logEl.style.display="block";}
function lg(t,tp="i"){
  const pfx={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";
  const d=document.createElement("div");d.className="tl t"+tp;
  d.innerHTML="<span class='p'>"+pfx+"</span> "+t;
  logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight;
}
function clearUI(){
  ["terminal","error-box","results"].forEach(id=>{const e=document.getElementById(id);e.innerHTML="";e.style.display="none";});
  document.getElementById("progress").style.display="none";
}

// ── Progress ───────────────────────────────────
let progVal=0,progTimer=null;
function startProgress(){
  progVal=0;document.getElementById("progress").style.display="block";
  document.getElementById("progress-bar").style.width="0%";
  progTimer=setInterval(()=>{
    progVal=Math.min(progVal+(100-progVal)*0.04,92);
    document.getElementById("progress-bar").style.width=progVal+"%";
  },400);
}
function endProgress(){
  clearInterval(progTimer);
  document.getElementById("progress-bar").style.width="100%";
  setTimeout(()=>document.getElementById("progress").style.display="none",500);
}

// ── Badge & helpers ────────────────────────────
function bdg(lv,small=false){
  const s=SEV[lv]||SEV.UNKNOWN;
  return `<span class="badge${small?' btn-sm':''}" style="background:${s.b};color:${s.c};border-color:${s.c}40">${s.i} ${lv}</span>`;
}

// ── Main Scan ──────────────────────────────────
let busy=false;
async function startScan(){
  const target=document.getElementById("target").value.trim();
  if(!target||busy)return;
  clearUI();busy=true;initLog();startProgress();
  const btn=document.getElementById("sbtn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  const modList=Object.keys(mods).filter(m=>mods[m]).join(",");
  lg("Target: "+target);
  lg("Modules: "+modList,"i");
  lg("Starting scan — may take 30–120 seconds","w");
  try{
    const r=await fetch("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(modList));
    const data=await r.json();
    endProgress();
    if(data.error){
      document.getElementById("error-box").textContent="Error: "+data.error;
      document.getElementById("error-box").style.display="block";
      lg(data.error,"e");
    } else {
      const ports=(data.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
      lg("Scan complete — "+ports.length+" open ports, "+
         (data.summary?.total_cves||0)+" CVEs found","s");
      renderResults(data);
    }
  }catch(e){
    endProgress();
    document.getElementById("error-box").textContent="Cannot reach backend: "+e.message;
    document.getElementById("error-box").style.display="block";
  }finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}
}

// ── Render All Results ─────────────────────────
function renderResults(data){
  const s=data.summary||{};
  const ports=(data.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
  const crit=s.critical_cves||0,high=s.high_cves||0,cv=s.total_cves||0,exp=s.exploitable||0;

  let html="";

  // Summary stats
  html+=`<div class="stats-grid">
    <div class="stat-card"><div class="stat-val" style="color:#00e5ff">${ports.length}</div><div class="stat-lbl">OPEN PORTS</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#ff3366">${crit}</div><div class="stat-lbl">CRITICAL CVEs</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#ff6b35">${high}</div><div class="stat-lbl">HIGH CVEs</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#ffd60a">${cv}</div><div class="stat-lbl">TOTAL CVEs</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#b06fff">${exp}</div><div class="stat-lbl">EXPLOITABLE</div></div>
  </div>`;

  // Tabs
  const hasTabs=data.modules;
  html+=`<div class="tab-bar">
    <button class="tab active" onclick="switchTab(event,'tab-ports')">&#128268; Ports & CVEs</button>
    ${data.modules?.ssl?`<button class="tab" onclick="switchTab(event,'tab-ssl')">&#128274; SSL/TLS</button>`:''}
    ${data.modules?.dns?`<button class="tab" onclick="switchTab(event,'tab-dns')">&#127758; DNS Recon</button>`:''}
    ${data.modules?.headers?`<button class="tab" onclick="switchTab(event,'tab-headers')">&#128196; Headers</button>`:''}
    <button class="tab" onclick="exportPDF()">&#128196; PDF Report</button>
  </div>`;

  // ── Ports tab ──
  html+=`<div class="tab-content active" id="tab-ports">`;
  if(ports.length===0){
    html+=`<p style="color:var(--m);padding:20px 0;font-size:13px">No open ports found on target.</p>`;
  }
  (data.modules?.ports?.hosts||[]).forEach(host=>{
    html+=`<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
      <span style="color:var(--cyan);background:rgba(0,229,255,0.07);padding:4px 12px;border-radius:5px;border:1px solid rgba(0,229,255,0.2);font-family:'JetBrains Mono',monospace;font-size:12px">${host.ip||""}</span>
      ${host.hostnames?.[0]?`<span style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace">${host.hostnames[0]}</span>`:""}
      <span style="color:var(--green);font-size:12px">&#9679; ${host.status||"up"}</span>
      ${host.os?`<span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">OS: ${host.os}</span>`:""}
    </div>`;
    host.ports.forEach((port,i)=>{
      const sv=SEV[port.risk_level]||SEV.UNKNOWN;
      const hasExploit=port.cves?.some(c=>c.has_exploit);
      html+=`<div class="port-card" style="border:1px solid ${sv.c}25;border-left:3px solid ${sv.c}">
        <div class="port-header" onclick="tp(this)">
          <div class="port-num" style="background:${sv.b};color:${sv.c}">${port.port}</div>
          <div class="port-info">
            <div class="port-name">${port.product||port.service||"unknown"}
              ${port.version?`<span style="color:var(--m);font-size:11px;font-weight:400"> v${port.version}</span>`:""}
            </div>
            <div class="port-sub">${(port.protocol||"tcp").toUpperCase()} &middot; ${port.service||""}${port.extrainfo?" &middot; "+port.extrainfo:""}</div>
          </div>
          <div class="port-meta">
            ${hasExploit?`<span class="exploit-badge badge">&#9760; EXPLOIT</span>`:""}
            ${bdg(port.risk_level)}
            ${port.risk_score?`<span class="score-num" style="color:${sv.c}">${port.risk_score}</span>`:""}
            <span class="chev">&#9660;</span>
          </div>
        </div>
        <div class="port-body">
          ${port.cves?.length?`
            <div class="sec-title">VULNERABILITIES (${port.cves.length})</div>
            ${port.cves.map(c=>{const cs=SEV[c.severity]||SEV.UNKNOWN;return`
            <div class="cve-item">
              <div class="cve-top">
                <a class="cve-id" href="${c.references?.[0]||"https://nvd.nist.gov/vuln/detail/"+c.id}" target="_blank">${c.id}</a>
                ${bdg(c.severity,true)}
                ${c.score?`<span style="color:${cs.c};font-weight:700;font-size:12px;font-family:'JetBrains Mono',monospace">CVSS ${c.score}</span>`:""}
                ${c.has_exploit?`<span class="exploit-badge badge">&#9760; PUBLIC EXPLOIT</span>`:""}
                <span class="cve-date">${c.published||""}</span>
              </div>
              <div class="cve-desc">${c.description||""}</div>
            </div>`;}).join("")}`:""}
          ${port.mitigations?.length?`
            <div class="sec-title">MITIGATIONS</div>
            <div class="mit-list">${port.mitigations.map(m=>`
              <div class="mit-item"><span class="mit-arr">&rsaquo;</span><span>${m}</span></div>`).join("")}
            </div>`:""}
          ${port.cpe?.length?`<div style="margin-top:10px">${port.cpe.map(c=>`<span style="background:var(--b2);color:var(--m);border-radius:4px;padding:2px 8px;font-size:10px;font-family:'JetBrains Mono',monospace;margin-right:5px">${c}</span>`).join("")}</div>`:""}
        </div>
      </div>`;
    });
  });
  html+=`</div>`;

  // ── SSL tab ──
  if(data.modules?.ssl){
    html+=`<div class="tab-content" id="tab-ssl">`;
    data.modules.ssl.forEach(s=>{
      const gc=GRADE_COL[s.grade]||"#ff3366";
      html+=`<div class="ssl-card">
        <div class="ssl-header">
          <div class="grade-circle" style="background:${gc}18;color:${gc};border:2px solid ${gc}40">${s.grade}</div>
          <div>
            <div style="font-weight:700;font-size:15px">${s.host}:${s.port}</div>
            <div style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace;margin-top:3px">
              ${s.details?.protocol||"unknown"} &middot; ${s.details?.cipher||"unknown"}
              ${s.details?.cipher_bits?" ("+s.details.cipher_bits+" bit)":""}
            </div>
            ${s.details?.days_until_expiry!=null?`<div style="color:${s.details.days_until_expiry<30?"#ff3366":"#00ff9d"};font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3p
