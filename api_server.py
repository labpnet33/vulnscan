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
    GRADE_COL_PDF = {"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"}
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
            ${s.details?.days_until_expiry!=null?`<div style="color:${s.details.days_until_expiry<30?"#ff3366":"#00ff9d"};font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3px">
              Expires: ${s.details.expires||""} (${s.details.days_until_expiry} days)</div>`:""}
          </div>
        </div>
        <div class="ssl-details">
          ${s.details?.subject?`<div class="ssl-detail">Subject<span>${s.details.subject}</span></div>`:""}
          ${s.details?.issuer?`<div class="ssl-detail">Issuer<span>${s.details.issuer}</span></div>`:""}
        </div>
        ${s.issues?.length?`<div style="margin-top:12px">${s.issues.map(iss=>{const sv=SEV[iss.severity]||SEV.UNKNOWN;return`
          <div class="issue-item">
            <span style="color:${sv.c};flex-shrink:0;font-size:10px">${bdg(iss.severity,true)}</span>
            <span style="font-size:12px;color:#c0c0d0">${iss.msg}</span>
          </div>`;}).join("")}</div>`:"<p style='color:var(--green);font-size:12px;margin-top:10px'>&#10003; No SSL issues found</p>"}
      </div>`;
    });
    html+=`</div>`;
  }

  // ── DNS tab ──
  if(data.modules?.dns){
    const dns=data.modules.dns;
    html+=`<div class="tab-content" id="tab-dns">
      <div class="card-title" style="margin-bottom:12px">DNS RECORDS</div>
      <div class="dns-grid">`;
    Object.entries(dns.records||{}).forEach(([type,vals])=>{
      html+=`<div class="dns-rec"><div class="dns-type">${type}</div>
        <div class="dns-val">${vals.join("<br/>")}</div></div>`;
    });
    html+=`</div>
      <div class="card-title" style="margin-bottom:10px">EMAIL SECURITY</div>
      <div class="card" style="padding:14px">
        <div class="check-row"><span class="check-icon">${dns.has_spf?"✅":"❌"}</span><span style="font-size:13px">SPF Record ${dns.has_spf?"configured":"missing — email spoofing risk"}</span></div>
        <div class="check-row"><span class="check-icon">${dns.has_dmarc?"✅":"❌"}</span><span style="font-size:13px">DMARC Record ${dns.has_dmarc?"configured":"missing — email not protected"}</span></div>
      </div>`;
    if(dns.subdomains?.length){
      html+=`<div class="card-title" style="margin-bottom:10px">SUBDOMAINS FOUND (${dns.subdomains.length})</div>`;
      dns.subdomains.forEach(s=>{
        html+=`<div class="sub-item"><span>${s.subdomain}</span><span style="color:var(--m)">${s.ip}</span></div>`;
      });
    }
    if(dns.issues?.length){
      html+=`<div class="card-title" style="margin-top:14px;margin-bottom:10px">DNS ISSUES</div>`;
      dns.issues.forEach(iss=>{
        const sv=SEV[iss.severity]||SEV.UNKNOWN;
        html+=`<div class="issue-item">${bdg(iss.severity,true)}<span style="font-size:12px;color:#c0c0d0;margin-left:8px">${iss.msg}</span></div>`;
      });
    }
    html+=`</div>`;
  }

  // ── Headers tab ──
  if(data.modules?.headers){
    const hd=data.modules.headers;
    const gc=GRADE_COL[hd.grade]||"#ff3366";
    html+=`<div class="tab-content" id="tab-headers">
      <div style="display:flex;align-items:center;gap:24px;margin-bottom:20px;flex-wrap:wrap">
        <div class="header-grade" style="color:${gc}">${hd.grade}</div>
        <div>
          <div style="font-size:14px;font-weight:600">${hd.url||hd.server||"Web Server"}</div>
          <div style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace;margin-top:4px">
            HTTP ${hd.status_code||""} &middot; Score: ${hd.score||0}/100
            ${hd.server?" &middot; "+hd.server:""}
          </div>
          ${hd.technologies?.length?`<div style="margin-top:6px">${hd.technologies.map(t=>`<span style="background:var(--b2);color:var(--m);border-radius:4px;padding:2px 8px;font-size:10px;font-family:'JetBrains Mono',monospace;margin-right:5px">${t}</span>`).join("")}</div>`:""}
        </div>
      </div>
      ${hd.issues?.length?`<div class="card-title" style="margin-bottom:10px">HEADER ISSUES</div>
        <div class="mit-list" style="margin-bottom:16px">${hd.issues.map(iss=>{const sv=SEV[iss.severity]||SEV.UNKNOWN;return`
          <div class="issue-item">${bdg(iss.severity,true)}<span style="font-size:12px;color:#c0c0d0;margin-left:8px">${iss.msg}</span></div>`;}).join("")}
        </div>`:""}
      <div class="card-title" style="margin-bottom:10px">RESPONSE HEADERS</div>
      <div class="hdr-list">${Object.entries(hd.headers||{}).slice(0,30).map(([k,v])=>`
        <div class="hdr-item"><span class="hdr-key">${k}</span><span class="hdr-val">${String(v).substring(0,120)}</span></div>`).join("")}
      </div>
    </div>`;
  }

  document.getElementById("results").innerHTML=html;
  document.getElementById("results").style.display="block";

  // Store for PDF
  window._lastScanData=data;
}

// ── Tab switching ──────────────────────────────
function switchTab(e,id){
  const parent=e.currentTarget.closest(".container,.results-wrap")||document.getElementById("results");
  parent.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  parent.querySelectorAll(".tab-content").forEach(t=>t.classList.remove("active"));
  e.currentTarget.classList.add("active");
  const tc=document.getElementById(id);
  if(tc)tc.classList.add("active");
}

// ── Port toggle ────────────────────────────────
function tp(hdr){
  const body=hdr.nextElementSibling;
  const chev=hdr.querySelector(".chev");
  body.classList.toggle("open");
  chev.style.transform=body.classList.contains("open")?"rotate(180deg)":"none";
}

// ── Network Discovery ──────────────────────────
async function discoverNetwork(){
  const subnet=document.getElementById("subnet").value.trim();
  if(!subnet)return;
  const btn=document.getElementById("dbtn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("discover-results").innerHTML=`<p style="color:var(--m);font-size:13px;padding:10px 0">Scanning subnet — please wait...</p>`;
  try{
    const r=await fetch("/discover?subnet="+encodeURIComponent(subnet));
    const data=await r.json();
    if(data.error){
      document.getElementById("discover-results").innerHTML=`<div style="color:var(--red);font-size:13px;padding:10px 0">Error: ${data.error}</div>`;
    } else {
      let html=`<div class="card"><div class="card-title">${data.total||0} HOSTS FOUND</div><div class="host-grid">`;
      (data.hosts||[]).forEach(h=>{
        html+=`<div class="host-tile" onclick="scanHost('${h.ip}')">
          <div class="host-ip">${h.ip}</div>
          ${h.hostnames?.[0]?`<div class="host-name">${h.hostnames[0]}</div>`:""}
          ${h.vendor?`<div class="host-vendor">${h.vendor}</div>`:""}
          <div style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace;margin-top:8px">Click to scan &rsaquo;</div>
        </div>`;
      });
      html+=`</div></div>`;
      document.getElementById("discover-results").innerHTML=html;
    }
  }catch(e){
    document.getElementById("discover-results").innerHTML=`<div style="color:var(--red);font-size:13px">Error: ${e.message}</div>`;
  }finally{btn.disabled=false;btn.innerHTML="DISCOVER";}
}

function scanHost(ip){
  document.getElementById("target").value=ip;
  showPageDirect("scan");
  startScan();
}

function showPageDirect(p){
  document.querySelectorAll(".page").forEach(el=>el.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(el=>el.classList.remove("active"));
  document.getElementById("page-"+p).classList.add("active");
  document.querySelector(`.nav-btn[onclick*="${p}"]`)?.classList.add("active");
}

// ── History ────────────────────────────────────
async function loadHistory(){
  try{
    const r=await fetch("/history");
    const data=await r.json();
    if(!data.length){
      document.getElementById("history-content").innerHTML=`<p style="color:var(--m);font-size:13px">No scan history yet. Run your first scan!</p>`;
      return;
    }
    let html=`<div style="overflow-x:auto"><table class="hist-table">
      <thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>`;
    data.forEach(s=>{
      const hasRisk=s.critical_cves>0;
      html+=`<tr>
        <td style="color:var(--m)">#${s.id}</td>
        <td style="color:var(--cyan)">${s.target}</td>
        <td style="color:var(--m)">${s.scan_time?.replace("T"," ").substring(0,19)||""}</td>
        <td>${s.open_ports}</td>
        <td>${s.total_cves}</td>
        <td style="color:${hasRisk?"#ff3366":"#00ff9d"}">${s.critical_cves}</td>
        <td><button class="link-btn" onclick="loadScanById(${s.id})">VIEW</button></td>
      </tr>`;
    });
    html+=`</tbody></table></div>`;
    document.getElementById("history-content").innerHTML=html;
  }catch(e){
    document.getElementById("history-content").innerHTML=`<p style="color:var(--red);font-size:13px">Error loading history: ${e.message}</p>`;
  }
}

async function loadScanById(id){
  showPageDirect("scan");
  clearUI();
  try{
    const r=await fetch("/scan/"+id);
    const data=await r.json();
    document.getElementById("target").value=data.target||"";
    renderResults(data);
    initLog();
    lg("Loaded scan #"+id+" for "+data.target,"s");
  }catch(e){
    document.getElementById("error-box").textContent="Failed to load scan: "+e.message;
    document.getElementById("error-box").style.display="block";
  }
}

// ── Dashboard ──────────────────────────────────
async function loadDashboard(){
  try{
    const r=await fetch("/history?limit=100");
    const data=await r.json();
    if(!data.length){
      document.getElementById("dash-content").innerHTML=`<p style="color:var(--m);font-size:13px">Run some scans to see statistics here.</p>`;
      return;
    }
    const totalScans=data.length;
    const totalCVEs=data.reduce((a,s)=>a+s.total_cves,0);
    const totalCrit=data.reduce((a,s)=>a+s.critical_cves,0);
    const totalPorts=data.reduce((a,s)=>a+s.open_ports,0);
    const maxCVE=Math.max(...data.map(s=>s.total_cves),1);
    const top5=data.slice(0,5);

    let html=`<div class="stats-grid" style="margin-bottom:20px">
      <div class="stat-card"><div class="stat-val" style="color:var(--cyan)">${totalScans}</div><div class="stat-lbl">TOTAL SCANS</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--yellow)">${totalCVEs}</div><div class="stat-lbl">TOTAL CVEs</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--red)">${totalCrit}</div><div class="stat-lbl">CRITICAL CVEs</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--green)">${totalPorts}</div><div class="stat-lbl">OPEN PORTS</div></div>
    </div>
    <div class="dash-grid">
      <div class="card"><div class="card-title">TOP TARGETS BY CVE COUNT</div>
        <div class="bar-chart">
          ${top5.map(s=>`<div class="bar-row">
            <span class="bar-label" style="font-size:10px;color:var(--m)">${s.target.substring(0,12)}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${(s.total_cves/maxCVE*100)}%;background:linear-gradient(90deg,var(--red),var(--orange))"></div></div>
            <span class="bar-val">${s.total_cves}</span>
          </div>`).join("")}
        </div>
      </div>
      <div class="card"><div class="card-title">RECENT ACTIVITY</div>
        ${data.slice(0,8).map(s=>`<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--b);font-size:11px;font-family:'JetBrains Mono',monospace">
          <span style="color:var(--cyan)">${s.target}</span>
          <span style="color:${s.critical_cves>0?"var(--red)":"var(--m)"}">
            ${s.critical_cves>0?"&#9762; "+s.critical_cves+" crit":s.total_cves+" CVEs"}
          </span>
        </div>`).join("")}
      </div>
    </div>`;
    document.getElementById("dash-content").innerHTML=html;
  }catch(e){
    document.getElementById("dash-content").innerHTML=`<p style="color:var(--red);font-size:13px">Error: ${e.message}</p>`;
  }
}

// ── PDF Export ─────────────────────────────────
async function exportPDF(){
  const data=window._lastScanData;
  if(!data){alert("Run a scan first to generate a report");return;}
  try{
    const r=await fetch("/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=`vulnscan-${data.target}-${new Date().toISOString().slice(0,10)}.txt`;
    a.click();URL.revokeObjectURL(url);
  }catch(e){alert("Report export failed: "+e.message);}
}

// ── Demo ────────────────────────────────────────
function loadDemo(){
  clearUI();initLog();lg("Loading demo scan results...","i");
  setTimeout(()=>{
    lg("Demo loaded — sample data for 192.168.1.1","s");
    renderResults(DEMO_DATA);
  },600);
}

// ── Demo data ──────────────────────────────────
const DEMO_DATA={
  target:"192.168.1.1",scan_time:new Date().toISOString(),
  summary:{open_ports:3,total_cves:4,critical_cves:2,high_cves:1,exploitable:1},
  modules:{
    ports:{hosts:[{ip:"192.168.1.1",status:"up",hostnames:["router.local"],os:"Linux 3.x",ports:[
      {port:22,protocol:"tcp",service:"ssh",product:"OpenSSH",version:"7.4",extrainfo:"protocol 2.0",risk_level:"HIGH",risk_score:9.8,
       cves:[{id:"CVE-2023-38408",description:"PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.",score:9.8,severity:"CRITICAL",has_exploit:true,published:"2023-07-20",references:["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]}],
       mitigations:["URGENT: Patch immediately — public exploit available","Upgrade OpenSSH to 9.3p2+","Set PermitRootLogin no","Use SSH key auth","Deploy fail2ban"]},
      {port:80,protocol:"tcp",service:"http",product:"Apache httpd",version:"2.4.51",extrainfo:"",risk_level:"CRITICAL",risk_score:9.8,
       cves:[{id:"CVE-2021-41773",description:"Path traversal and RCE in Apache 2.4.49 allows attackers to access files outside document root and execute code.",score:9.8,severity:"CRITICAL",has_exploit:false,published:"2021-10-05",references:["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]}],
       mitigations:["Upgrade Apache to 2.4.52 immediately","Enable HTTPS, redirect HTTP","Implement CSP headers","Disable directory listing"]},
      {port:3306,protocol:"tcp",service:"mysql",product:"MySQL",version:"5.7.38",extrainfo:"Community Server",risk_level:"MEDIUM",risk_score:4.9,
       cves:[{id:"CVE-2022-21417",description:"MySQL Server vulnerability allows high privileged attacker to cause crash via multiple network protocols.",score:4.9,severity:"MEDIUM",has_exploit:false,published:"2022-04-19",references:["https://nvd.nist.gov/vuln/detail/CVE-2022-21417"]}],
       mitigations:["Bind MySQL to localhost only","Never expose to internet","Use strong passwords","Upgrade to MySQL 8.0 LTS"]}
    ]}]},
    ssl:[{host:"192.168.1.1",port:443,grade:"B",details:{protocol:"TLSv1.2",cipher:"ECDHE-RSA-AES256-GCM-SHA384",cipher_bits:256,subject:"*.example.com",issuer:"Let's Encrypt",expires:"Oct 15 00:00:00 2025 GMT",days_until_expiry:45},issues:[{severity:"LOW",msg:"TLS 1.3 not enabled — consider upgrading"}]}],
    dns:{target:"192.168.1.1",has_spf:false,has_dmarc:false,records:{A:["192.168.1.1"],NS:["ns1.example.com"],MX:["10 mail.example.com"]},subdomains:[{subdomain:"www.example.com",ip:"192.168.1.1"},{subdomain:"mail.example.com",ip:"192.168.1.2"}],issues:[{severity:"HIGH",msg:"No SPF record — email spoofing risk"},{severity:"MEDIUM",msg:"No DMARC record — email not protected"}]},
    headers:{url:"http://192.168.1.1",status_code:200,grade:"D",score:35,server:"Apache/2.4.51",technologies:["Apache/2.4.51"],headers:{"Server":"Apache/2.4.51","Content-Type":"text/html","Connection":"keep-alive"},issues:[{severity:"HIGH",msg:"HSTS not set"},{severity:"HIGH",msg:"No CSP header — XSS risk"},{severity:"MEDIUM",msg:"No X-Frame-Options — Clickjacking risk"},{severity:"MEDIUM",msg:"No X-Content-Type-Options"}]}
  }
};
</script>
</body>
</html>"""

# ── Flask Routes ───────────────────────────────
@app.route("/")
def index():
    return HTML

@app.route("/scan", methods=["GET","POST"])
def scan():
    target=(request.args.get("target","") if request.method=="GET" else (request.get_json() or {}).get("target","")).strip()
    modules=request.args.get("modules","ports,ssl,dns,headers")
    if not target: return jsonify({"error":"No target specified"}),400
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$',target): return jsonify({"error":"Invalid target"}),400
    try:
        mod_list=modules.split(",")
        r=subprocess.run([sys.executable,BACKEND,"--modules",",".join(mod_list),target],
                         capture_output=True,text=True,timeout=200)
        # fallback: call without --modules if backend doesn't support it
        if not r.stdout:
            r=subprocess.run([sys.executable,BACKEND,target],capture_output=True,text=True,timeout=200)
        if r.stdout:
            # Find the first { and last } to extract clean JSON
            raw = r.stdout.strip()
            start = raw.find('{')
            end = raw.rfind('}')
            if start == -1 or end == -1:
                return jsonify({"error": "No JSON in output: " + raw[:200]}), 500
            clean = raw[start:end+1]
            data = json.loads(clean)
            if "error" not in data:
                scan_id=save_scan(target,data)
                data["scan_id"]=scan_id
            return jsonify(data)
        return jsonify({"error":r.stderr or "No output"}),500
    except subprocess.TimeoutExpired: return jsonify({"error":"Scan timed out"}),504
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/discover")
def discover():
    subnet=request.args.get("subnet","").strip()
    if not subnet: return jsonify({"error":"No subnet specified"}),400
    if not re.match(r'^[0-9./]+$',subnet): return jsonify({"error":"Invalid subnet format"}),400
    try:
        r=subprocess.run([sys.executable,BACKEND,"--discover",subnet],capture_output=True,text=True,timeout=120)
        if r.stdout: return jsonify(json.loads(r.stdout))
        return jsonify({"error":r.stderr or "No output"}),500
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/history")
def history():
    limit=int(request.args.get("limit",20))
    return jsonify(get_history(limit))

@app.route("/scan/<int:scan_id>")
def get_scan(scan_id):
    data=get_scan_by_id(scan_id)
    if not data: return jsonify({"error":"Scan not found"}),404
    return jsonify(data)

@app.route("/report", methods=["POST"])
def report():
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    data = request.get_json()
    target = data.get("target", "unknown")
    scan_time = data.get("scan_time", "")[:19].replace("T", " ")
    summary = data.get("summary", {})
    modules = data.get("modules", {})
    hosts = modules.get("ports", {}).get("hosts", [])
    all_ports = [p for h in hosts for p in h.get("ports", [])]
    all_cves = [c for p in all_ports for c in p.get("cves", [])]

    # ── Colours ──
    C_BG       = colors.HexColor("#04040a")
    C_RED      = colors.HexColor("#ff3366")
    C_ORANGE   = colors.HexColor("#ff6b35")
    C_YELLOW   = colors.HexColor("#ffd60a")
    C_GREEN    = colors.HexColor("#00ff9d")
    C_CYAN     = colors.HexColor("#00e5ff")
    C_PURPLE   = colors.HexColor("#b06fff")
    C_DARK     = colors.HexColor("#0d0d18")
    C_BORDER   = colors.HexColor("#16162a")
    C_MUTED    = colors.HexColor("#5a5a8a")
    C_WHITE    = colors.HexColor("#e8e8f0")
    C_CRITICAL = C_RED
    C_HIGH     = C_ORANGE
    C_MEDIUM   = C_YELLOW
    C_LOW      = C_GREEN

    SEV_COLORS = {
        "CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
        "MEDIUM": C_MEDIUM, "LOW": C_LOW, "UNKNOWN": C_MUTED
    }

    def sev_color(s):
        return SEV_COLORS.get(s, C_MUTED)

    # ── Styles ──
    def style(name, **kw):
        base = dict(fontName="Helvetica", fontSize=10, textColor=C_WHITE,
                    backColor=None, leading=14, spaceAfter=4, spaceBefore=2,
                    leftIndent=0, rightIndent=0, alignment=TA_LEFT)
        base.update(kw)
        return ParagraphStyle(name, **base)

    S_TITLE    = style("title",   fontName="Helvetica-Bold", fontSize=28, textColor=C_CYAN,    leading=34, spaceAfter=6)
    S_SUBTITLE = style("sub",     fontName="Helvetica",      fontSize=11, textColor=C_MUTED,   leading=16, spaceAfter=16)
    S_H1       = style("h1",      fontName="Helvetica-Bold", fontSize=16, textColor=C_CYAN,    leading=22, spaceBefore=18, spaceAfter=8)
    S_H2       = style("h2",      fontName="Helvetica-Bold", fontSize=12, textColor=C_WHITE,   leading=18, spaceBefore=12, spaceAfter=6)
    S_H3       = style("h3",      fontName="Helvetica-Bold", fontSize=10, textColor=C_MUTED,   leading=14, spaceBefore=8,  spaceAfter=4, leftIndent=10)
    S_BODY     = style("body",    fontName="Helvetica",      fontSize=9,  textColor=C_WHITE,   leading=14, spaceAfter=4)
    S_BODY_M   = style("bodym",   fontName="Helvetica",      fontSize=9,  textColor=C_MUTED,   leading=14, spaceAfter=3)
    S_CODE     = style("code",    fontName="Courier",        fontSize=8,  textColor=C_CYAN,    leading=12, spaceAfter=3, leftIndent=10)
    S_WARN     = style("warn",    fontName="Helvetica-Bold", fontSize=9,  textColor=C_RED,     leading=13, spaceAfter=3)
    S_LABEL    = style("label",   fontName="Helvetica-Bold", fontSize=7,  textColor=C_MUTED,   leading=10, spaceAfter=2)
    S_CENTER   = style("center",  fontName="Helvetica",      fontSize=9,  textColor=C_MUTED,   leading=13, alignment=TA_CENTER)

    def p(text, st=S_BODY): return Paragraph(str(text), st)
    def sp(h=6): return Spacer(1, h)
    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8, spaceBefore=4)

    def sev_badge_text(level):
        icons = {"CRITICAL":"[CRITICAL]","HIGH":"[HIGH]","MEDIUM":"[MEDIUM]","LOW":"[LOW]","UNKNOWN":"[?]"}
        return icons.get(level, "[?]")

    # ── Overall risk grade ──
    crit_c = summary.get("critical_cves", 0)
    high_c = summary.get("high_cves", 0)
    total_c = summary.get("total_cves", 0)
    if crit_c > 0:   overall = ("F", C_RED,    "CRITICAL RISK")
    elif high_c > 0: overall = ("D", C_ORANGE, "HIGH RISK")
    elif total_c > 0:overall = ("C", C_YELLOW, "MEDIUM RISK")
    else:            overall = ("A", C_GREEN,  "LOW RISK")

    # ── Buffer ──
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)

    # ── Page background ──
    W, H = A4
    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Top accent bar
        canvas.setFillColor(C_RED)
        canvas.rect(0, H-3, W, 3, fill=1, stroke=0)
        # Footer
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, W, 14*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(18*mm, 5*mm, f"VulnScan Pro  |  Confidential Security Report  |  {target}  |  {scan_time}")
        canvas.drawRightString(W-18*mm, 5*mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []

    # ══════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════
    story += [sp(40)]
    story.append(p("VulnScan Pro", S_TITLE))
    story.append(p("SECURITY ASSESSMENT REPORT", style("st2", fontName="Helvetica-Bold", fontSize=13,
                   textColor=C_PURPLE, leading=18, spaceAfter=4, letterSpacing=3)))
    story += [sp(8), hr(), sp(8)]

    # Meta table
    meta_data = [
        ["Target",       target],
        ["Scan Time",    scan_time],
        ["Report Date",  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Overall Risk", overall[2]],
    ]
    meta_table = Table(meta_data, colWidths=[40*mm, 110*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
        ("FONTNAME",    (0,0),(0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,-1), 10),
        ("TEXTCOLOR",   (0,0),(0,-1),  C_MUTED),
        ("TEXTCOLOR",   (1,0),(1,-1),  C_WHITE),
        ("TEXTCOLOR",   (1,3),(1,3),   overall[1]),
        ("FONTNAME",    (1,3),(1,3),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_DARK, C_BG]),
        ("TOPPADDING",  (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("LEFTPADDING", (0,0),(-1,-1), 12),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),4),
    ]))
    story += [meta_table, sp(20)]

    # Big risk summary boxes
    stat_data = [[
        f"{summary.get('open_ports',0)}\nOPEN PORTS",
        f"{summary.get('total_cves',0)}\nTOTAL CVEs",
        f"{summary.get('critical_cves',0)}\nCRITICAL",
        f"{summary.get('high_cves',0)}\nHIGH",
        f"{summary.get('exploitable',0)}\nEXPLOITABLE",
    ]]
    stat_colors = [C_CYAN, C_YELLOW, C_RED, C_ORANGE, C_PURPLE]
    stat_table = Table(stat_data, colWidths=[30*mm]*5)
    ts = TableStyle([
        ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0),(-1,-1), 12),
        ("BOTTOMPADDING",(0,0),(-1,-1),12),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("FONTNAME",    (0,0),(-1,-1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK]),
        ("GRID",        (0,0),(-1,-1), 0.5, C_BORDER),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),4),
    ])
    for i, c in enumerate(stat_colors):
        ts.add("TEXTCOLOR", (i,0),(i,0), c)
    stat_table.setStyle(ts)
    story += [stat_table, sp(30)]

    # Disclaimer
    story.append(p("CONFIDENTIAL — For authorized use only. This report contains sensitive security findings.", style("disc",
        fontName="Helvetica", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER, leading=12)))
    story.append(PageBreak())

    # ══════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ══════════════════════════════════════════
    story.append(p("Executive Summary", S_H1))
    story.append(hr())

    exec_rows = [
        ["Target Host",     target],
        ["Scan Time",       scan_time],
        ["Open Ports",      str(summary.get("open_ports",0))],
        ["Total CVEs",      str(summary.get("total_cves",0))],
        ["Critical CVEs",   str(summary.get("critical_cves",0))],
        ["High CVEs",       str(summary.get("high_cves",0))],
        ["Exploitable CVEs",str(summary.get("exploitable",0))],
        ["Overall Risk",    overall[2]],
    ]
    exec_table = Table(exec_rows, colWidths=[50*mm, 110*mm])
    exec_table.setStyle(TableStyle([
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1),9),
        ("TEXTCOLOR",   (0,0),(0,-1), C_MUTED),
        ("TEXTCOLOR",   (1,0),(1,-1), C_WHITE),
        ("TEXTCOLOR",   (1,7),(1,7),  overall[1]),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK, C_BG]),
        ("TOPPADDING",  (0,0),(-1,-1),7),
        ("BOTTOMPADDING",(0,0),(-1,-1),7),
        ("LEFTPADDING", (0,0),(-1,-1),10),
        ("GRID",        (0,0),(-1,-1),0.3, C_BORDER),
    ]))
    story += [exec_table, sp(14)]

    # Risk narrative
    if crit_c > 0:
        story.append(p(f"CRITICAL RISK: {crit_c} critical severity vulnerabilities were found on {target}. "
                       f"Immediate remediation is required. {summary.get('exploitable',0)} vulnerabilities "
                       f"have known public exploits and could be leveraged by an attacker right now.", S_WARN))
    elif high_c > 0:
        story.append(p(f"HIGH RISK: {high_c} high severity vulnerabilities were identified. "
                       f"Prompt remediation is strongly recommended.", style("hw", fontName="Helvetica-Bold",
                       fontSize=9, textColor=C_ORANGE, leading=13)))
    else:
        story.append(p(f"No critical or high severity vulnerabilities were detected during this scan.", S_BODY))
    story.append(PageBreak())

    # ══════════════════════════════════════════
    # PORT SCAN FINDINGS
    # ══════════════════════════════════════════
    story.append(p("Port Scan Findings", S_H1))
    story.append(hr())

    if not all_ports:
        story.append(p("No open ports were detected on the target.", S_BODY_M))
    else:
        # Summary table of all ports
        port_rows = [["PORT", "PROTOCOL", "SERVICE", "PRODUCT", "VERSION", "RISK"]]
        for pt in all_ports:
            sc = sev_color(pt.get("risk_level","UNKNOWN"))
            port_rows.append([
                str(pt.get("port","")),
                pt.get("protocol","tcp").upper(),
                pt.get("service",""),
                pt.get("product",""),
                pt.get("version",""),
                pt.get("risk_level","?"),
            ])
        pt_table = Table(port_rows, colWidths=[18*mm, 22*mm, 25*mm, 40*mm, 28*mm, 25*mm])
        pts = TableStyle([
            ("BACKGROUND",  (0,0),(-1,0),  C_DARK),
            ("TEXTCOLOR",   (0,0),(-1,0),  C_MUTED),
            ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0),(-1,-1), 8),
            ("FONTNAME",    (0,1),(-1,-1), "Helvetica"),
            ("TEXTCOLOR",   (0,1),(-1,-1), C_WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK, C_BG]),
            ("GRID",        (0,0),(-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",  (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING", (0,0),(-1,-1), 6),
            ("ALIGN",       (0,0),(1,-1),  "CENTER"),
        ])
        # Color the risk column
        for i, pt in enumerate(all_ports, 1):
            pts.add("TEXTCOLOR", (5,i),(5,i), sev_color(pt.get("risk_level","UNKNOWN")))
            pts.add("FONTNAME",  (5,i),(5,i), "Helvetica-Bold")
        pt_table.setStyle(pts)
        story += [pt_table, sp(20)]

        # Detailed findings per port
        story.append(p("Detailed Vulnerability Findings", S_H1))
        story.append(hr())

        for pt in all_ports:
            lv = pt.get("risk_level","UNKNOWN")
            sc = sev_color(lv)
            cves = pt.get("cves",[])
            mits = pt.get("mitigations",[])

            # Port header
            hdr_data = [[
                f"Port {pt.get('port','')} / {pt.get('protocol','tcp').upper()}",
                f"{pt.get('product','')} {pt.get('version','')}".strip(),
                f"{lv}  CVSS {pt.get('risk_score','?')}",
            ]]
            hdr_table = Table(hdr_data, colWidths=[35*mm, 90*mm, 40*mm])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,0), C_DARK),
                ("FONTNAME",    (0,0),(0,0),  "Helvetica-Bold"),
                ("FONTNAME",    (1,0),(1,0),  "Helvetica"),
                ("FONTNAME",    (2,0),(2,0),  "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(-1,0), 9),
                ("TEXTCOLOR",   (0,0),(0,0),  C_CYAN),
                ("TEXTCOLOR",   (1,0),(1,0),  C_WHITE),
                ("TEXTCOLOR",   (2,0),(2,0),  sc),
                ("TOPPADDING",  (0,0),(-1,0), 9),
                ("BOTTOMPADDING",(0,0),(-1,0),9),
                ("LEFTPADDING", (0,0),(-1,0), 10),
                ("LINEBELOW",   (0,0),(-1,0), 1.5, sc),
                ("ROUNDEDCORNERS",(0,0),(-1,-1),3),
            ]))
            story += [hdr_table, sp(6)]

            # Service info
            info_row = [["Service", pt.get("service",""), "Extra Info", pt.get("extrainfo","") or "—"]]
            info_table = Table(info_row, colWidths=[20*mm, 55*mm, 20*mm, 65*mm])
            info_table.setStyle(TableStyle([
                ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
                ("FONTNAME",    (0,0),(0,0),   "Helvetica-Bold"),
                ("FONTNAME",    (2,0),(2,0),   "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(-1,-1), 8),
                ("TEXTCOLOR",   (0,0),(0,0),   C_MUTED),
                ("TEXTCOLOR",   (1,0),(1,0),   C_WHITE),
                ("TEXTCOLOR",   (2,0),(2,0),   C_MUTED),
                ("TEXTCOLOR",   (3,0),(3,0),   C_WHITE),
                ("BACKGROUND",  (0,0),(-1,-1), C_BG),
                ("TOPPADDING",  (0,0),(-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING", (0,0),(-1,-1), 8),
                ("GRID",        (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story += [info_table, sp(8)]

            # CVEs
            if cves:
                story.append(p(f"Vulnerabilities ({len(cves)} found)", S_H3))
                for cve in cves:
                    cs = sev_color(cve.get("severity","UNKNOWN"))
                    exploit_txt = "  [PUBLIC EXPLOIT AVAILABLE]" if cve.get("has_exploit") else ""
                    cve_hdr = [[
                        cve.get("id",""),
                        f"{cve.get('severity','?')}  CVSS {cve.get('score','?')}{exploit_txt}",
                        cve.get("published",""),
                    ]]
                    cve_table = Table(cve_hdr, colWidths=[40*mm, 90*mm, 30*mm])
                    cve_table.setStyle(TableStyle([
                        ("BACKGROUND",  (0,0),(-1,0), C_DARK),
                        ("FONTNAME",    (0,0),(0,0),  "Helvetica-Bold"),
                        ("FONTNAME",    (1,0),(1,0),  "Helvetica-Bold"),
                        ("FONTNAME",    (2,0),(2,0),  "Helvetica"),
                        ("FONTSIZE",    (0,0),(-1,0), 8),
                        ("TEXTCOLOR",   (0,0),(0,0),  C_CYAN),
                        ("TEXTCOLOR",   (1,0),(1,0),  cs),
                        ("TEXTCOLOR",   (2,0),(2,0),  C_MUTED),
                        ("TOPPADDING",  (0,0),(-1,0), 6),
                        ("BOTTOMPADDING",(0,0),(-1,0),6),
                        ("LEFTPADDING", (0,0),(-1,0), 8),
                        ("LINEBELOW",   (0,0),(-1,0), 0.5, cs),
                    ]))
                    desc = cve.get("description","")
                    desc_table = Table([[desc]], colWidths=[160*mm])
                    desc_table.setStyle(TableStyle([
                        ("BACKGROUND",  (0,0),(-1,-1), C_BG),
                        ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
                        ("FONTSIZE",    (0,0),(-1,-1), 8),
                        ("TEXTCOLOR",   (0,0),(-1,-1), C_MUTED),
                        ("TOPPADDING",  (0,0),(-1,-1), 6),
                        ("BOTTOMPADDING",(0,0),(-1,-1),6),
                        ("LEFTPADDING", (0,0),(-1,-1), 8),
                        ("GRID",        (0,0),(-1,-1), 0.3, C_BORDER),
                    ]))
                    story += [cve_table, desc_table, sp(5)]

            # Mitigations
            if mits:
                story.append(p("Mitigation Recommendations", S_H3))
                mit_rows = [[f"{'[!]' if i==0 else str(i)}  {m}"] for i,m in enumerate(mits)]
                mit_table = Table(mit_rows, colWidths=[160*mm])
                mt_style = TableStyle([
                    ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
                    ("FONTSIZE",    (0,0),(-1,-1), 8),
                    ("TEXTCOLOR",   (0,0),(-1,-1), C_WHITE),
                    ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_BG, C_DARK]),
                    ("TOPPADDING",  (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ("LEFTPADDING", (0,0),(-1,-1), 10),
                    ("GRID",        (0,0),(-1,-1), 0.3, C_BORDER),
                    ("LINEAFTER",   (0,0),(0,-1),  2, C_GREEN),
                ])
                if mits and "URGENT" in mits[0]:
                    mt_style.add("TEXTCOLOR", (0,0),(0,0), C_RED)
                    mt_style.add("FONTNAME",  (0,0),(0,0), "Helvetica-Bold")
                mit_table.setStyle(mt_style)
                story += [mit_table]

            story += [sp(16), hr()]

    story.append(PageBreak())

    # ══════════════════════════════════════════
    # SSL / TLS SECTION
    # ══════════════════════════════════════════
    ssl_results = modules.get("ssl", [])
    if ssl_results:
        story.append(p("SSL / TLS Analysis", S_H1))
        story.append(hr())
        for ssl_r in ssl_results:
            grade = ssl_r.get("grade","?")
            gc = GRADE_COL_PDF.get(grade, "#ff3366")
            details = ssl_r.get("details",{})
            story.append(p(f"{ssl_r.get('host','')}:{ssl_r.get('port',443)}  —  Grade: {grade}", S_H2))
            ssl_rows = [
                ["Protocol",    details.get("protocol","unknown")],
                ["Cipher",      details.get("cipher","unknown")],
                ["Cipher Bits", str(details.get("cipher_bits","?"))],
                ["Subject",     details.get("subject","")],
                ["Issuer",      details.get("issuer","")],
                ["Expires",     details.get("expires","")],
                ["Days Left",   str(details.get("days_until_expiry","?"))],
            ]
            ssl_table = Table(ssl_rows, colWidths=[40*mm, 120*mm])
            ssl_table.setStyle(TableStyle([
                ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
                ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
                ("FONTSIZE",    (0,0),(-1,-1),8),
                ("TEXTCOLOR",   (0,0),(0,-1), C_MUTED),
                ("TEXTCOLOR",   (1,0),(1,-1), C_WHITE),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK,C_BG]),
                ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
                ("TOPPADDING",  (0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING", (0,0),(-1,-1),8),
            ]))
            story += [ssl_table, sp(8)]
            issues = ssl_r.get("issues",[])
            if issues:
                story.append(p("SSL Issues:", S_H3))
                for iss in issues:
                    sc = sev_color(iss.get("severity","UNKNOWN"))
                    story.append(p(f"  {sev_badge_text(iss['severity'])}  {iss.get('msg','')}", style("si",
                        fontName="Helvetica", fontSize=8, textColor=sc, leading=13, leftIndent=10)))
            story += [sp(10), hr()]
        story.append(PageBreak())

    # ══════════════════════════════════════════
    # DNS RECON SECTION
    # ══════════════════════════════════════════
    dns = modules.get("dns")
    if dns:
        story.append(p("DNS Reconnaissance", S_H1))
        story.append(hr())
        records = dns.get("records",{})
        if records:
            story.append(p("DNS Records", S_H2))
            dns_rows = [["TYPE","VALUE"]]
            for rtype, vals in records.items():
                for v in vals:
                    dns_rows.append([rtype, v])
            dns_table = Table(dns_rows, colWidths=[25*mm, 135*mm])
            dns_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,0),  C_DARK),
                ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTNAME",    (0,1),(-1,-1), "Helvetica"),
                ("FONTSIZE",    (0,0),(-1,-1), 8),
                ("TEXTCOLOR",   (0,0),(-1,0),  C_MUTED),
                ("TEXTCOLOR",   (0,1),(0,-1),  C_CYAN),
                ("TEXTCOLOR",   (1,1),(1,-1),  C_WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK,C_BG]),
                ("GRID",        (0,0),(-1,-1), 0.3, C_BORDER),
                ("TOPPADDING",  (0,0),(-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING", (0,0),(-1,-1), 8),
            ]))
            story += [dns_table, sp(10)]

        # Email security
        story.append(p("Email Security", S_H2))
        spf_ok = dns.get("has_spf",False)
        dmarc_ok = dns.get("has_dmarc",False)
        email_rows = [
            ["SPF Record",   "Configured" if spf_ok else "MISSING — email spoofing risk"],
            ["DMARC Record", "Configured" if dmarc_ok else "MISSING — email not protected"],
        ]
        em_table = Table(email_rows, colWidths=[40*mm, 120*mm])
        em_ts = TableStyle([
            ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1),8),
            ("TEXTCOLOR",   (0,0),(0,-1), C_MUTED),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK,C_BG]),
            ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
            ("TOPPADDING",  (0,0),(-1,-1),7),
            ("BOTTOMPADDING",(0,0),(-1,-1),7),
            ("LEFTPADDING", (0,0),(-1,-1),8),
        ])
        em_ts.add("TEXTCOLOR",(1,0),(1,0), C_GREEN if spf_ok else C_RED)
        em_ts.add("TEXTCOLOR",(1,1),(1,1), C_GREEN if dmarc_ok else C_ORANGE)
        em_table.setStyle(em_ts)
        story += [em_table, sp(10)]

        subs = dns.get("subdomains",[])
        if subs:
            story.append(p(f"Subdomains Found ({len(subs)})", S_H2))
            sub_rows = [["SUBDOMAIN","IP ADDRESS"]] + [[s["subdomain"],s["ip"]] for s in subs]
            sub_table = Table(sub_rows, colWidths=[90*mm, 70*mm])
            sub_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,0), C_DARK),
                ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTNAME",    (0,1),(-1,-1),"Helvetica"),
                ("FONTSIZE",    (0,0),(-1,-1),8),
                ("TEXTCOLOR",   (0,0),(-1,0), C_MUTED),
                ("TEXTCOLOR",   (0,1),(-1,-1),C_WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK,C_BG]),
                ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
                ("TOPPADDING",  (0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING", (0,0),(-1,-1),8),
            ]))
            story += [sub_table, sp(10)]

        dns_issues = dns.get("issues",[])
        if dns_issues:
            story.append(p("DNS Issues", S_H2))
            for iss in dns_issues:
                sc = sev_color(iss.get("severity","UNKNOWN"))
                story.append(p(f"  {sev_badge_text(iss['severity'])}  {iss.get('msg','')}", style("di",
                    fontName="Helvetica", fontSize=8, textColor=sc, leading=14, leftIndent=10)))
        story.append(PageBreak())

    # ══════════════════════════════════════════
    # WEB HEADERS SECTION
    # ══════════════════════════════════════════
    hdrs = modules.get("headers")
    if hdrs:
        story.append(p("Web Headers Analysis", S_H1))
        story.append(hr())
        gc_h = GRADE_COL_PDF.get(hdrs.get("grade","F"),"#ff3366")
        story.append(p(f"Security Grade: {hdrs.get('grade','?')}  |  Score: {hdrs.get('score',0)}/100  |  {hdrs.get('url','')}", S_H2))
        story += [sp(8)]

        hdr_issues = hdrs.get("issues",[])
        if hdr_issues:
            story.append(p("Header Issues", S_H2))
            issue_rows = [["SEVERITY","ISSUE"]] + [[i.get("severity","?"), i.get("msg","")] for i in hdr_issues]
            iss_table = Table(issue_rows, colWidths=[30*mm, 130*mm])
            iss_ts = TableStyle([
                ("BACKGROUND",  (0,0),(-1,0), C_DARK),
                ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTNAME",    (0,1),(-1,-1),"Helvetica"),
                ("FONTSIZE",    (0,0),(-1,-1),8),
                ("TEXTCOLOR",   (0,0),(-1,0), C_MUTED),
                ("TEXTCOLOR",   (1,1),(1,-1), C_WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK,C_BG]),
                ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
                ("TOPPADDING",  (0,0),(-1,-1),6),
                ("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("LEFTPADDING", (0,0),(-1,-1),8),
            ])
            for i, iss in enumerate(hdr_issues, 1):
                iss_ts.add("TEXTCOLOR",(0,i),(0,i), sev_color(iss.get("severity","UNKNOWN")))
                iss_ts.add("FONTNAME", (0,i),(0,i), "Helvetica-Bold")
            iss_table.setStyle(iss_ts)
            story += [iss_table, sp(10)]

        resp_hdrs = hdrs.get("headers",{})
        if resp_hdrs:
            story.append(p("Response Headers", S_H2))
            hdr_rows = [["HEADER","VALUE"]] + [[k, str(v)[:100]] for k,v in list(resp_hdrs.items())[:25]]
            rh_table = Table(hdr_rows, colWidths=[60*mm, 100*mm])
            rh_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,0), C_DARK),
                ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTNAME",    (0,1),(-1,-1),"Helvetica"),
                ("FONTSIZE",    (0,0),(-1,-1),7),
                ("TEXTCOLOR",   (0,0),(-1,0), C_MUTED),
                ("TEXTCOLOR",   (0,1),(0,-1), C_CYAN),
                ("TEXTCOLOR",   (1,1),(1,-1), C_WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK,C_BG]),
                ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
                ("TOPPADDING",  (0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
                ("LEFTPADDING", (0,0),(-1,-1),6),
            ]))
            story += [rh_table]
        story.append(PageBreak())

    # ══════════════════════════════════════════
    # FINAL PAGE — Recommendations
    # ══════════════════════════════════════════
    story.append(p("Remediation Checklist", S_H1))
    story.append(hr())

    all_mits = []
    for pt in all_ports:
        for m in pt.get("mitigations",[]):
            if m not in all_mits:
                all_mits.append(m)

    if all_mits:
        chk_rows = [["", "ACTION ITEM", "PRIORITY"]]
        for i, m in enumerate(all_mits):
            prio = "URGENT" if "URGENT" in m or "immediately" in m.lower() else ("HIGH" if i < 4 else "MEDIUM")
            pc = C_RED if prio=="URGENT" else (C_ORANGE if prio=="HIGH" else C_YELLOW)
            chk_rows.append(["[ ]", m, prio])
        chk_table = Table(chk_rows, colWidths=[10*mm, 130*mm, 22*mm])
        chk_ts = TableStyle([
            ("BACKGROUND",  (0,0),(-1,0), C_DARK),
            ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTNAME",    (0,1),(-1,-1),"Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1),8),
            ("TEXTCOLOR",   (0,0),(-1,0), C_MUTED),
            ("TEXTCOLOR",   (0,1),(0,-1), C_MUTED),
            ("TEXTCOLOR",   (1,1),(1,-1), C_WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK,C_BG]),
            ("GRID",        (0,0),(-1,-1),0.3,C_BORDER),
            ("TOPPADDING",  (0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING", (0,0),(-1,-1),7),
            ("ALIGN",       (2,0),(2,-1), "CENTER"),
        ])
        for i, m in enumerate(all_mits, 1):
            prio = "URGENT" if "URGENT" in m or "immediately" in m.lower() else ("HIGH" if i<4 else "MEDIUM")
            pc = C_RED if prio=="URGENT" else (C_ORANGE if prio=="HIGH" else C_YELLOW)
            chk_ts.add("TEXTCOLOR",(2,i),(2,i),pc)
            chk_ts.add("FONTNAME", (2,i),(2,i),"Helvetica-Bold")
        chk_table.setStyle(chk_ts)
        story += [chk_table, sp(20)]

    story.append(hr())
    story.append(p("Report generated by VulnScan Pro  |  For authorized security assessment use only", S_CENTER))
    story.append(p(f"Scan completed: {scan_time}  |  Target: {target}", S_CENTER))

    # ── Build ──
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    buf.seek(0)

    from flask import Response
    fname = f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]','_',target)}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(buf.read(), mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.route("/health")
def health(): return jsonify({"status":"ok","version":"2.0"})

if __name__=="__main__":
    print("[*] VulnScan Pro v2.0 starting")
    print("[*] Open browser: http://localhost:5000")
    app.run(host="0.0.0.0",port=5000,debug=False)
