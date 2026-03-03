#!/usr/bin/env python3
import json,re,sys,os,sqlite3,subprocess,io
from flask import Flask,request,jsonify,Response
from flask_cors import CORS
from datetime import datetime

app=Flask(__name__)
CORS(app)
BACKEND=os.path.join(os.path.dirname(os.path.abspath(__file__)),"backend.py")
DB_PATH=os.path.join(os.path.dirname(os.path.abspath(__file__)),"scans.db")
GRADE_COL={"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"}

def init_db():
    con=sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,scan_time TEXT,result TEXT,
        open_ports INTEGER,total_cves INTEGER,critical_cves INTEGER)""")
    con.commit(); con.close()

def save_scan(target,result):
    s=result.get("summary",{})
    con=sqlite3.connect(DB_PATH)
    cur=con.execute("INSERT INTO scans(target,scan_time,result,open_ports,total_cves,critical_cves) VALUES(?,?,?,?,?,?)",
        (target,result.get("scan_time",""),json.dumps(result),
         s.get("open_ports",0),s.get("total_cves",0),s.get("critical_cves",0)))
    con.commit(); sid=cur.lastrowid; con.close()
    return sid

def get_history(limit=20):
    con=sqlite3.connect(DB_PATH)
    rows=con.execute("SELECT id,target,scan_time,open_ports,total_cves,critical_cves FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    con.close()
    return [{"id":r[0],"target":r[1],"scan_time":r[2],"open_ports":r[3],"total_cves":r[4],"critical_cves":r[5]} for r in rows]

def get_scan_by_id(sid):
    con=sqlite3.connect(DB_PATH)
    row=con.execute("SELECT result FROM scans WHERE id=?",(sid,)).fetchone()
    con.close()
    return json.loads(row[0]) if row else None

def run_backend(*args,timeout=200):
    cmd=[sys.executable,BACKEND]+list(args)
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
    if not r.stdout: return {"error":r.stderr or "No output"}
    raw=r.stdout.strip()
    start=raw.find('{'); end=raw.rfind('}')
    if start==-1 or end==-1: return {"error":"No JSON in output: "+raw[:200]}
    return json.loads(raw[start:end+1])

init_db()

HTML=r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<style>

/* ── FONT SIZE BOOST ── */
body{font-size:15px}
.nb{font-size:12px !important}
.btn{font-size:13px !important}
.inp,.sel{font-size:15px !important}
.ctitle,.st,.dtype{font-size:11px !important}
.pname{font-size:15px !important}
.psub{font-size:12px !important}
.bdg{font-size:11px !important}
.cdesc,.mi,.cid,.hk,.hv{font-size:13px !important}
.sv{font-size:30px !important}
.sl{font-size:10px !important}
.tl{font-size:13px !important}
.res-tbl td,.res-tbl th{font-size:12px !important}
.hist-tbl td,.hist-tbl th{font-size:12px !important}
.sub-item,.hi,.bar-row{font-size:13px !important}
.hero h2{font-size:32px !important}
.hero p{font-size:14px !important}
.brand-name{font-size:20px !important}

@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Syne:wght@400;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;--t:#e8e8f0;--m:#5a5a8a;
      --cyan:#00e5ff;--green:#00ff9d;--red:#ff3366;--orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--t);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,229,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.025) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
header{position:sticky;top:0;z-index:100;background:rgba(4,4,10,0.92);backdrop-filter:blur(20px);border-bottom:1px solid var(--b);padding:0 24px;display:flex;align-items:center;justify-content:space-between;height:58px;flex-wrap:wrap;gap:8px}
.brand{display:flex;align-items:center;gap:10px}
.brand-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--red),var(--orange));border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 0 18px rgba(255,51,102,0.35)}
.brand-name{font-size:17px;font-weight:800;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-tag{font-size:8px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace}
nav{display:flex;gap:3px;flex-wrap:wrap}
.nb{padding:6px 13px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1px;border-radius:6px;transition:all 0.2s;white-space:nowrap}
.nb:hover,.nb.active{background:var(--b);color:var(--cyan)}
.container{max-width:1100px;margin:0 auto;padding:24px 16px;position:relative;z-index:1}
.page{display:none}.page.active{display:block}
.card{background:var(--s1);border:1px solid var(--b);border-radius:12px;padding:20px;margin-bottom:16px}
.ctitle{font-size:9px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-bottom:12px;font-weight:600}
.hero{text-align:center;padding:32px 0 24px}
.hero h2{font-size:28px;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.hero p{color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
.inp{flex:1;min-width:200px;background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--cyan);padding:12px 16px;font-size:13px;font-family:'JetBrains Mono',monospace;outline:none;transition:border 0.2s}
.inp:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.07)}
.inp::placeholder{color:#252540}
.inp-sm{padding:9px 12px;font-size:12px}
textarea.inp{resize:vertical;min-height:80px}
.btn{padding:12px 22px;border:none;border-radius:9px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:11px;letter-spacing:1px;transition:all 0.2s;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,var(--red),#b0102a);color:#fff;box-shadow:0 4px 18px rgba(255,51,102,0.28)}
.btn-p:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(255,51,102,0.38)}
.btn-p:disabled{background:var(--b);color:var(--m);cursor:not-allowed;transform:none;box-shadow:none}
.btn-g{background:transparent;color:var(--m);border:1px solid var(--b2);padding:12px 18px}
.btn-g:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-sm{padding:6px 12px;font-size:10px}
.mods{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px;justify-content:center}
.mt{padding:5px 13px;border:1px solid var(--b2);border-radius:18px;cursor:pointer;font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--m);background:transparent;transition:all 0.2s}
.mt.on{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.07)}
#term{background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;margin-bottom:16px;max-height:160px;overflow-y:auto;display:none;font-family:'JetBrains Mono',monospace;font-size:11px}
.tl{line-height:1.9;color:#4a4a7a}
.ti .p{color:var(--cyan)}.ts .p{color:var(--green)}.tw .p{color:var(--yellow)}.te .p{color:var(--red)}
#prog{height:2px;background:var(--b);border-radius:1px;margin-bottom:16px;display:none;overflow:hidden}
#pb{height:100%;width:0;background:linear-gradient(90deg,var(--red),var(--orange),var(--yellow));transition:width 0.3s}
#err{background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:12px;margin-bottom:16px;display:none;font-family:'JetBrains Mono',monospace}
#res{display:none}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}
.sc{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:14px;text-align:center}
.sv{font-size:26px;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}
.sl{color:var(--m);font-size:8px;letter-spacing:2px;margin-top:5px;font-family:'JetBrains Mono',monospace}
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--b);flex-wrap:wrap}
.tab{padding:9px 16px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1px;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.2s}
.tab:hover{color:var(--t)}.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tc{display:none}.tc.active{display:block}
.pc{border-radius:9px;background:rgba(255,255,255,0.015);margin-bottom:9px;overflow:hidden}
.ph{padding:13px 16px;cursor:pointer;display:flex;align-items:center;gap:12px;flex-wrap:wrap;user-select:none}
.pn{padding:6px 12px;border-radius:7px;font-family:'JetBrains Mono',monospace;font-weight:800;font-size:15px;min-width:66px;text-align:center}
.pi{flex:1;min-width:0}
.pname{font-weight:700;font-size:13px}
.psub{color:var(--m);font-size:10px;margin-top:2px;font-family:'JetBrains Mono',monospace}
.pm{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bdg{border-radius:4px;padding:2px 8px;font-size:9px;font-weight:700;letter-spacing:1px;font-family:'JetBrains Mono',monospace;border:1px solid transparent}
.chev{color:var(--m);font-size:10px;transition:transform 0.25s;flex-shrink:0}
.pb2{padding:0 16px 16px;border-top:1px solid var(--b);display:none}
.pb2.open{display:block}
.st{color:var(--m);font-size:9px;letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin:14px 0 7px}
.ci{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px;margin-bottom:6px}
.ct{display:flex;align-items:center;gap:7px;margin-bottom:6px;flex-wrap:wrap}
.cid{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-weight:700;font-size:11px;text-decoration:none}
.cid:hover{text-decoration:underline}
.cdate{color:var(--m);font-size:9px;margin-left:auto;font-family:'JetBrains Mono',monospace}
.cdesc{color:#8e8e93;font-size:11px;line-height:1.7}
.ml{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.mi{display:flex;gap:9px;padding:5px 0;border-bottom:1px solid var(--b);font-size:11px;line-height:1.6;color:#c0c0d0}
.mi:last-child{border-bottom:none}
.ma{color:var(--green);font-family:'JetBrains Mono',monospace;flex-shrink:0}
.ssl-card{background:var(--s2);border-radius:9px;padding:16px;margin-bottom:11px;border:1px solid var(--b2)}
.gc{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.ssl-hdr{display:flex;align-items:center;gap:16px;margin-bottom:12px}
.dns-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:9px;margin-bottom:12px}
.dr{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.dtype{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--cyan);letter-spacing:2px;margin-bottom:5px}
.dval{font-size:10px;color:#8e8e93;line-height:1.7;font-family:'JetBrains Mono',monospace;word-break:break-all}
.sub-item{background:var(--s2);border:1px solid var(--b2);border-radius:5px;padding:7px 11px;font-family:'JetBrains Mono',monospace;font-size:11px;display:flex;justify-content:space-between;margin-bottom:4px;align-items:center}
.hdr-grade{font-size:48px;font-weight:900;font-family:'JetBrains Mono',monospace;line-height:1}
.hl{background:var(--s2);border-radius:7px;overflow:hidden;border:1px solid var(--b2)}
.hi{display:flex;justify-content:space-between;align-items:center;padding:7px 13px;border-bottom:1px solid var(--b);font-size:11px;font-family:'JetBrains Mono',monospace;flex-wrap:wrap;gap:6px}
.hi:last-child{border-bottom:none}
.hk{color:var(--m);min-width:180px;flex-shrink:0}.hv{color:var(--t);word-break:break-all;text-align:right;max-width:380px}
.iss-item{display:flex;gap:9px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--b);font-size:11px}
.iss-item:last-child{border-bottom:none}
.hg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px}
.ht{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:13px;cursor:pointer;transition:all 0.2s}
.ht:hover{border-color:var(--cyan)}
.hip{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:var(--cyan)}
.hist-tbl{width:100%;border-collapse:collapse;font-size:11px;font-family:'JetBrains Mono',monospace}
.hist-tbl th{color:var(--m);font-size:8px;letter-spacing:2px;padding:9px 10px;text-align:left;border-bottom:1px solid var(--b)}
.hist-tbl td{padding:9px 10px;border-bottom:1px solid var(--b);color:var(--t);vertical-align:middle}
.hist-tbl tr:hover td{background:rgba(255,255,255,0.015)}
.lbtn{background:transparent;border:1px solid var(--b2);color:var(--cyan);padding:4px 9px;border-radius:4px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:9px}
.lbtn:hover{background:rgba(0,229,255,0.07)}
.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:9px;font-size:10px;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
.bl{color:var(--m);width:75px;text-align:right;flex-shrink:0;font-size:9px}
.bt{flex:1;background:var(--b);border-radius:2px;height:7px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width 1s ease}
.bv{color:var(--t);width:25px;flex-shrink:0}
/* Dir/Sub result table */
.res-tbl{width:100%;border-collapse:collapse;font-size:10px;font-family:'JetBrains Mono',monospace;margin-top:8px}
.res-tbl th{color:var(--m);font-size:8px;letter-spacing:2px;padding:8px 10px;text-align:left;border-bottom:1px solid var(--b);background:var(--s2)}
.res-tbl td{padding:7px 10px;border-bottom:1px solid var(--b);vertical-align:middle;word-break:break-all}
.res-tbl tr:hover td{background:rgba(255,255,255,0.015)}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace;border:1px solid transparent}
/* brute */
.bf-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:600px){.bf-grid{grid-template-columns:1fr}.hero h2{font-size:22px}}
/* form groups */
.fg{margin-bottom:12px}
.fg label{display:block;font-size:9px;color:var(--m);letter-spacing:2px;font-family:'JetBrains Mono',monospace;margin-bottom:5px}
.sel{background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--t);padding:10px 12px;font-size:12px;font-family:'JetBrains Mono',monospace;outline:none;width:100%}
.sel:focus{border-color:var(--cyan)}
/* status badges */
.s200{color:var(--green)}.s301{color:var(--yellow)}.s302{color:var(--yellow)}.s401{color:var(--orange)}.s403{color:var(--orange)}
/* spin */
.spin{display:inline-block;width:11px;height:11px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
.notice{background:rgba(255,214,10,0.06);border:1px solid rgba(255,214,10,0.2);border-radius:8px;padding:10px 14px;color:var(--yellow);font-size:11px;font-family:'JetBrains Mono',monospace;margin-bottom:14px}
.found-badge{background:rgba(0,255,157,0.1);color:var(--green);border:1px solid rgba(0,255,157,0.25);border-radius:5px;padding:3px 9px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-icon">&#9889;</div>
    <div><div class="brand-name">VulnScan Pro</div><div class="brand-tag">SECURITY PLATFORM</div></div>
  </div>
  <nav>
    <button class="nb active" onclick="pg('scan',this)">&#128269; Scanner</button>
    <button class="nb" onclick="pg('sub',this)">&#127760; Subdomains</button>
    <button class="nb" onclick="pg('dir',this)">&#128193; DirBust</button>
    <button class="nb" onclick="pg('brute',this)">&#128272; BruteForce</button>
    <button class="nb" onclick="pg('disc',this)">&#128225; Discover</button>
    <button class="nb" onclick="pg('hist',this)">&#128196; History</button>
    <button class="nb" onclick="pg('dash',this)">&#128202; Dashboard</button>
  </nav>
</header>
<div class="container">

<!-- ═══ SCANNER ═══ -->
<div class="page active" id="page-scan">
  <div class="hero">
    <h2>Vulnerability Intelligence</h2>
    <p>Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS recon &middot; Header audit</p>
    <div class="row">
      <input class="inp" id="tgt" type="text" placeholder="IP address or hostname — e.g. 192.168.1.1" onkeydown="if(event.key==='Enter')doScan()"/>
      <button class="btn btn-p" id="sbtn" onclick="doScan()">SCAN</button>
    </div>
    <div class="mods">
      <button class="mt on" id="mod-ports" onclick="tmg('ports',this)">&#128268; Ports+CVE</button>
      <button class="mt on" id="mod-ssl" onclick="tmg('ssl',this)">&#128274; SSL/TLS</button>
      <button class="mt on" id="mod-dns" onclick="tmg('dns',this)">&#127758; DNS</button>
      <button class="mt on" id="mod-headers" onclick="tmg('headers',this)">&#128196; Headers</button>
    </div>
  </div>
  <div id="prog"><div id="pb"></div></div>
  <div id="term"></div>
  <div id="err"></div>
  <div id="res"></div>
</div>

<!-- ═══ SUBDOMAIN FINDER ═══ -->
<div class="page" id="page-sub">
  <div class="card">
    <div class="ctitle">SUBDOMAIN FINDER</div>
    <div class="notice">&#9888; Only enumerate domains you own or have written permission to test.</div>
    <div class="fg"><label>DOMAIN</label><input class="inp" id="sub-domain" placeholder="example.com" type="text"/></div>
    <div class="fg"><label>WORDLIST SIZE</label>
      <select class="sel" id="sub-size">
        <option value="small">Small (~30 words, faster)</option>
        <option value="medium" selected>Medium (~80 words + crt.sh + HackerTarget)</option>
      </select>
    </div>
    <button class="btn btn-p" id="sub-btn" onclick="doSub()" style="margin-top:4px">FIND SUBDOMAINS</button>
  </div>
  <div id="sub-res"></div>
</div>

<!-- ═══ DIRBUSTER ═══ -->
<div class="page" id="page-dir">
  <div class="card">
    <div class="ctitle">DIRECTORY ENUMERATOR</div>
    <div class="notice">&#9888; Only scan web servers you own or have written permission to test.</div>
    <div class="fg"><label>TARGET URL</label><input class="inp" id="dir-url" placeholder="http://192.168.1.1 or https://example.com" type="text"/></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div class="fg"><label>WORDLIST SIZE</label>
        <select class="sel" id="dir-size">
          <option value="small" selected>Small (~60 paths, fast)</option>
          <option value="medium">Medium (~130 paths)</option>
        </select>
      </div>
      <div class="fg"><label>FILE EXTENSIONS</label>
        <input class="inp inp-sm" id="dir-ext" value="php,html,txt,bak,zip,json,xml" type="text"/>
      </div>
    </div>
    <button class="btn btn-p" id="dir-btn" onclick="doDir()">START ENUMERATION</button>
  </div>
  <div id="dir-res"></div>
</div>

<!-- ═══ BRUTE FORCE ═══ -->
<div class="page" id="page-brute">
  <div class="card">
    <div class="ctitle">LOGIN BRUTE FORCE TESTER</div>
    <div class="notice">&#9888; ONLY use on systems you own or have explicit written permission to test. Unauthorized use is illegal.</div>
    <div class="fg"><label>ATTACK TYPE</label>
      <select class="sel" id="bf-type" onchange="bfTypeChange()">
        <option value="http">HTTP Form Login</option>
        <option value="ssh">SSH Login</option>
      </select>
    </div>
    <div id="bf-http-fields">
      <div class="bf-grid">
        <div class="fg"><label>LOGIN URL</label><input class="inp inp-sm" id="bf-url" placeholder="http://192.168.1.1/login" type="text"/></div>
        <div class="fg"><label>USERNAME FIELD NAME</label><input class="inp inp-sm" id="bf-ufield" placeholder="username" value="username" type="text"/></div>
        <div class="fg"><label>PASSWORD FIELD NAME</label><input class="inp inp-sm" id="bf-pfield" placeholder="password" value="password" type="text"/></div>
      </div>
    </div>
    <div id="bf-ssh-fields" style="display:none">
      <div class="bf-grid">
        <div class="fg"><label>HOST</label><input class="inp inp-sm" id="bf-ssh-host" placeholder="192.168.1.1" type="text"/></div>
        <div class="fg"><label>PORT</label><input class="inp inp-sm" id="bf-ssh-port" placeholder="22" value="22" type="text"/></div>
      </div>
    </div>
    <div class="bf-grid">
      <div class="fg"><label>USERNAMES (one per line)</label>
        <textarea class="inp" id="bf-users" placeholder="admin&#10;root&#10;user&#10;administrator" style="min-height:100px"></textarea>
      </div>
      <div class="fg"><label>PASSWORDS (one per line)</label>
        <textarea class="inp" id="bf-pwds" placeholder="admin&#10;password&#10;123456&#10;admin123&#10;root" style="min-height:100px"></textarea>
      </div>
    </div>
    <button class="btn btn-p" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button>
  </div>
  <div id="bf-res"></div>
</div>

<!-- ═══ NETWORK DISCOVER ═══ -->
<div class="page" id="page-disc">
  <div class="card">
    <div class="ctitle">NETWORK DISCOVERY</div>
    <div class="row">
      <input class="inp" id="subnet" placeholder="192.168.1.0/24" type="text" onkeydown="if(event.key==='Enter')doDisc()"/>
      <button class="btn btn-p" id="disc-btn" onclick="doDisc()">DISCOVER</button>
    </div>
    <p style="color:var(--m);font-size:10px;margin-top:10px;font-family:'JetBrains Mono',monospace">&#9888; Only scan networks you own or have permission to scan</p>
  </div>
  <div id="disc-res"></div>
</div>

<!-- ═══ HISTORY ═══ -->
<div class="page" id="page-hist">
  <div class="card">
    <div class="ctitle">SCAN HISTORY</div>
    <div id="hist-content"><p style="color:var(--m);font-size:12px">Loading...</p></div>
  </div>
</div>

<!-- ═══ DASHBOARD ═══ -->
<div class="page" id="page-dash">
  <div class="card">
    <div class="ctitle">SECURITY DASHBOARD</div>
    <div id="dash-content"><p style="color:var(--m);font-size:12px">Run some scans to see statistics.</p></div>
  </div>
</div>

</div>
<script>
const SEV={CRITICAL:{c:"#ff3366",b:"rgba(255,51,102,0.12)",i:"&#9762;"},HIGH:{c:"#ff6b35",b:"rgba(255,107,53,0.12)",i:"&#9888;"},MEDIUM:{c:"#ffd60a",b:"rgba(255,214,10,0.1)",i:"&#9889;"},LOW:{c:"#00ff9d",b:"rgba(0,255,157,0.08)",i:"&#10003;"},UNKNOWN:{c:"#5a5a8a",b:"rgba(90,90,138,0.1)",i:"?"}};
const GC={"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"};
const mods={ports:true,ssl:true,dns:true,headers:true};
let busy=false,logEl=null,progT=null,progV=0;

// ── Page nav ──
function pg(id,el){
  document.querySelectorAll(".page").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nb").forEach(e=>e.classList.remove("active"));
  document.getElementById("page-"+id).classList.add("active");
  el.classList.add("active");
  if(id==="hist")loadHist();
  if(id==="dash")loadDash();
}

// ── Module toggles ──
function tmg(m,el){mods[m]=!mods[m];el.classList.toggle("on",mods[m]);}

// ── Terminal ──
function initLog(){logEl=document.getElementById("term");logEl.innerHTML="";logEl.style.display="block";}
function lg(t,tp="i"){
  if(!logEl)return;
  const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";
  const d=document.createElement("div");d.className="tl t"+tp;
  d.innerHTML="<span class='p'>"+p+"</span> "+t;logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight;
}
function clrUI(){
  ["term","err","res"].forEach(id=>{const e=document.getElementById(id);if(e){e.innerHTML="";e.style.display="none";}});
  document.getElementById("prog").style.display="none";
}
function showErr(msg){const e=document.getElementById("err");e.textContent="Error: "+msg;e.style.display="block";}
function startProg(){progV=0;document.getElementById("prog").style.display="block";document.getElementById("pb").style.width="0%";progT=setInterval(()=>{progV=Math.min(progV+(100-progV)*0.04,92);document.getElementById("pb").style.width=progV+"%";},400);}
function endProg(){clearInterval(progT);document.getElementById("pb").style.width="100%";setTimeout(()=>document.getElementById("prog").style.display="none",400);}

// ── Helpers ──
function bdg(lv,sm=false){const s=SEV[lv]||SEV.UNKNOWN;return`<span class="bdg${sm?" btn-sm":""}" style="background:${s.b};color:${s.c};border-color:${s.c}40">${s.i} ${lv}</span>`;}
function tag(t,c){return`<span class="tag" style="background:${c}15;color:${c};border-color:${c}30">${t}</span>`;}
function statusCol(s){return s===200?"var(--green)":s<400?"var(--yellow)":"var(--orange)";}

// ── MAIN SCAN ──
async function doScan(){
  const target=document.getElementById("tgt").value.trim();
  if(!target||busy)return;
  clrUI();busy=true;initLog();startProg();
  const btn=document.getElementById("sbtn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  const ml=Object.keys(mods).filter(m=>mods[m]).join(",");
  lg("Target: "+target);lg("Modules: "+ml,"i");lg("Scanning — may take 30–120 seconds","w");
  try{
    const r=await fetch("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(ml));
    const d=await r.json();endProg();
    if(d.error){showErr(d.error);lg(d.error,"e");}
    else{
      const pts=(d.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
      lg("Done — "+pts.length+" ports, "+(d.summary?.total_cves||0)+" CVEs","s");
      renderScan(d);
    }
  }catch(e){endProg();showErr(e.message);}
  finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}
}

// ── RENDER SCAN ──
function renderScan(data){
  const s=data.summary||{};
  const ports=(data.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
  let html=`<div class="sgrid">
    <div class="sc"><div class="sv" style="color:#00e5ff">${ports.length}</div><div class="sl">OPEN PORTS</div></div>
    <div class="sc"><div class="sv" style="color:#ff3366">${s.critical_cves||0}</div><div class="sl">CRITICAL</div></div>
    <div class="sc"><div class="sv" style="color:#ff6b35">${s.high_cves||0}</div><div class="sl">HIGH CVEs</div></div>
    <div class="sc"><div class="sv" style="color:#ffd60a">${s.total_cves||0}</div><div class="sl">TOTAL CVEs</div></div>
    <div class="sc"><div class="sv" style="color:#b06fff">${s.exploitable||0}</div><div class="sl">EXPLOITABLE</div></div>
  </div>`;
  html+=`<div class="tabs">
    <button class="tab active" onclick="swt(event,'tp')">&#128268; Ports</button>
    ${data.modules?.ssl?'<button class="tab" onclick="swt(event,\'tssl\')">&#128274; SSL</button>':""}
    ${data.modules?.dns?'<button class="tab" onclick="swt(event,\'tdns\')">&#127758; DNS</button>':""}
    ${data.modules?.headers?'<button class="tab" onclick="swt(event,\'thdr\')">&#128196; Headers</button>':""}
    <button class="tab" onclick="exportPDF()">&#128196; PDF Report</button>
  </div>`;

  // Ports tab
  html+=`<div class="tc active" id="tp">`;
  (data.modules?.ports?.hosts||[]).forEach(host=>{
    html+=`<div style="display:flex;align-items:center;gap:9px;margin-bottom:12px;flex-wrap:wrap">
      <span style="color:var(--cyan);background:rgba(0,229,255,0.07);padding:3px 11px;border-radius:4px;border:1px solid rgba(0,229,255,0.18);font-family:'JetBrains Mono',monospace;font-size:11px">${host.ip||""}</span>
      ${host.hostnames?.[0]?`<span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">${host.hostnames[0]}</span>`:""}
      <span style="color:var(--green);font-size:11px">&#9679; ${host.status||"up"}</span>
      ${host.os?`<span style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace">OS: ${host.os}</span>`:""}
    </div>`;
    host.ports.forEach((port,i)=>{
      const sv=SEV[port.risk_level]||SEV.UNKNOWN;
      const hx=port.cves?.some(c=>c.has_exploit);
      html+=`<div class="pc" style="border:1px solid ${sv.c}22;border-left:3px solid ${sv.c}">
        <div class="ph" onclick="tp2(this)">
          <div class="pn" style="background:${sv.b};color:${sv.c}">${port.port}</div>
          <div class="pi">
            <div class="pname">${port.product||port.service||"unknown"}${port.version?` <span style="color:var(--m);font-size:10px;font-weight:400">v${port.version}</span>`:""}</div>
            <div class="psub">${(port.protocol||"tcp").toUpperCase()} &middot; ${port.service||""}${port.extrainfo?" &middot; "+port.extrainfo:""}</div>
          </div>
          <div class="pm">
            ${hx?'<span class="bdg" style="background:rgba(176,111,255,0.12);color:#b06fff;border-color:rgba(176,111,255,0.3);font-size:9px">&#9760; EXPLOIT</span>':""}
            ${bdg(port.risk_level)}
            ${port.risk_score?`<span style="color:${sv.c};font-weight:800;font-size:13px;font-family:'JetBrains Mono',monospace">${port.risk_score}</span>`:""}
            <span class="chev">&#9660;</span>
          </div>
        </div>
        <div class="pb2">
          ${port.cves?.length?`<div class="st">VULNERABILITIES (${port.cves.length})</div>${port.cves.map(c=>{const cs=SEV[c.severity]||SEV.UNKNOWN;return`<div class="ci"><div class="ct"><a class="cid" href="${c.references?.[0]||"https://nvd.nist.gov/vuln/detail/"+c.id}" target="_blank">${c.id}</a>${bdg(c.severity,true)}${c.score?`<span style="color:${cs.c};font-weight:700;font-size:10px;font-family:'JetBrains Mono',monospace">CVSS ${c.score}</span>`:""}${c.has_exploit?'<span class="bdg btn-sm" style="background:rgba(176,111,255,0.1);color:#b06fff;border-color:rgba(176,111,255,0.25)">&#9760; PUBLIC EXPLOIT</span>':""}<span class="cdate">${c.published||""}</span></div><div class="cdesc">${c.description||""}</div></div>`;}).join("")}`:""}
          ${port.mitigations?.length?`<div class="st">MITIGATIONS</div><div class="ml">${port.mitigations.map(m=>`<div class="mi"><span class="ma">&rsaquo;</span><span>${m}</span></div>`).join("")}</div>`:""}
        </div>
      </div>`;
    });
  });
  html+=`</div>`;

  // SSL tab
  if(data.modules?.ssl){
    html+=`<div class="tc" id="tssl">`;
    data.modules.ssl.forEach(s=>{
      const gc=GC[s.grade]||"#ff3366";const d=s.details||{};
      html+=`<div class="ssl-card"><div class="ssl-hdr">
        <div class="gc" style="background:${gc}15;color:${gc};border:2px solid ${gc}35">${s.grade}</div>
        <div><div style="font-weight:700;font-size:14px">${s.host}:${s.port}</div>
          <div style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3px">${d.protocol||"?"} &middot; ${d.cipher||"?"} ${d.cipher_bits?"("+d.cipher_bits+" bit)":""}</div>
          ${d.days_until_expiry!=null?`<div style="color:${d.days_until_expiry<30?"var(--red)":"var(--green)"};font-size:10px;font-family:'JetBrains Mono',monospace;margin-top:3px">Expires: ${d.expires||""} (${d.days_until_expiry} days)</div>`:""}
        </div></div>
        ${s.issues?.length?s.issues.map(iss=>{const sv=SEV[iss.severity]||SEV.UNKNOWN;return`<div class="iss-item">${bdg(iss.severity,true)}<span style="font-size:11px;color:#c0c0d0;margin-left:6px">${iss.msg}</span></div>`;}).join(""):"<p style='color:var(--green);font-size:11px'>&#10003; No SSL issues</p>"}
      </div>`;
    });
    html+=`</div>`;
  }

  // DNS tab
  if(data.modules?.dns){
    const dns=data.modules.dns;
    html+=`<div class="tc" id="tdns">
      <div class="dns-grid">${Object.entries(dns.records||{}).map(([t,v])=>`<div class="dr"><div class="dtype">${t}</div><div class="dval">${v.join("<br/>")}</div></div>`).join("")}</div>
      <div class="card" style="padding:12px;margin-bottom:12px">
        <div style="display:flex;gap:14px;flex-wrap:wrap">
          <span style="font-size:12px">${dns.has_spf?"✅":"❌"} SPF ${dns.has_spf?"configured":"MISSING"}</span>
          <span style="font-size:12px">${dns.has_dmarc?"✅":"❌"} DMARC ${dns.has_dmarc?"configured":"MISSING"}</span>
        </div>
      </div>
      ${dns.subdomains?.length?`<div class="st" style="margin-bottom:8px">SUBDOMAINS (${dns.subdomains.length})</div>${dns.subdomains.map(s=>`<div class="sub-item"><span>${s.subdomain}</span><span style="color:var(--m)">${s.ip}</span></div>`).join("")}`:""}
      ${dns.issues?.length?`<div class="st" style="margin-top:12px;margin-bottom:8px">DNS ISSUES</div>${dns.issues.map(i=>`<div class="iss-item">${bdg(i.severity,true)}<span style="margin-left:7px;font-size:11px">${i.msg}</span></div>`).join("")}`:""}
    </div>`;
  }

  // Headers tab
  if(data.modules?.headers){
    const hd=data.modules.headers;const gc=GC[hd.grade]||"#ff3366";
    html+=`<div class="tc" id="thdr">
      <div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;flex-wrap:wrap">
        <div class="hdr-grade" style="color:${gc}">${hd.grade}</div>
        <div><div style="font-size:13px;font-weight:600">${hd.url||""}</div>
          <div style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3px">HTTP ${hd.status_code||""} &middot; Score ${hd.score||0}/100${hd.server?" &middot; "+hd.server:""}</div>
        </div>
      </div>
      ${hd.issues?.length?`<div class="st" style="margin-bottom:8px">ISSUES</div><div class="ml" style="margin-bottom:14px">${hd.issues.map(i=>`<div class="iss-item">${bdg(i.severity,true)}<span style="margin-left:7px;font-size:11px">${i.msg}</span></div>`).join("")}</div>`:""}
      <div class="st" style="margin-bottom:8px">RESPONSE HEADERS</div>
      <div class="hl">${Object.entries(hd.headers||{}).slice(0,25).map(([k,v])=>`<div class="hi"><span class="hk">${k}</span><span class="hv">${String(v).substring(0,100)}</span></div>`).join("")}</div>
    </div>`;
  }

  const r=document.getElementById("res");r.innerHTML=html;r.style.display="block";
  window._sd=data;
}

function tp2(hdr){const b=hdr.nextElementSibling;const c=hdr.querySelector(".chev");b.classList.toggle("open");c.style.transform=b.classList.contains("open")?"rotate(180deg)":"none";}
function swt(e,id){const p=document.getElementById("res");p.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));p.querySelectorAll(".tc").forEach(t=>t.classList.remove("active"));e.currentTarget.classList.add("active");const tc=document.getElementById(id);if(tc)tc.classList.add("active");}

// ── SUBDOMAIN FINDER ──
async function doSub(){
  const domain=document.getElementById("sub-domain").value.trim();
  const size=document.getElementById("sub-size").value;
  if(!domain)return;
  const btn=document.getElementById("sub-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:12px">Enumerating subdomains for <b style="color:var(--cyan)">${domain}</b> — this may take 30–60 seconds...</p></div>`;
  try{
    const r=await fetch("/subdomains?domain="+encodeURIComponent(domain)+"&size="+size);
    const d=await r.json();
    if(d.error){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    let html=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span class="found-badge">${d.total} SUBDOMAINS FOUND</span>
        <span style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace">Sources: ${(d.sources||[]).join(", ")}</span>
      </div>
      <div style="overflow-x:auto"><table class="res-tbl">
        <thead><tr><th>SUBDOMAIN</th><th>IP ADDRESS</th><th>SOURCE</th><th>ACTION</th></tr></thead><tbody>
        ${(d.subdomains||[]).map(s=>`<tr>
          <td style="color:var(--cyan)">${s.subdomain}</td>
          <td style="color:var(--t)">${s.ip}</td>
          <td>${tag(s.source||"dns",s.source==="crt.sh"?"#b06fff":s.source==="hackertarget"?"#00e5ff":"#00ff9d")}</td>
          <td><button class="lbtn" onclick="scanFromSub('${s.subdomain}')">SCAN</button></td>
        </tr>`).join("")}
        </tbody>
      </table></div>
    </div>`;
    document.getElementById("sub-res").innerHTML=html;
  }catch(e){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="FIND SUBDOMAINS";}
}
function scanFromSub(domain){document.getElementById("tgt").value=domain;document.querySelector(".nb").click();doScan();}

// ── DIRBUSTER ──
async function doDir(){
  const url=document.getElementById("dir-url").value.trim();
  const size=document.getElementById("dir-size").value;
  const ext=document.getElementById("dir-ext").value.trim();
  if(!url)return;
  const btn=document.getElementById("dir-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:12px">Enumerating directories on <b style="color:var(--cyan)">${url}</b> — please wait...</p></div>`;
  try{
    const r=await fetch("/dirbust?url="+encodeURIComponent(url)+"&size="+size+"&ext="+encodeURIComponent(ext));
    const d=await r.json();
    if(d.error){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    let html=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span class="found-badge">${d.total} PATHS FOUND</span>
        <span style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace">${d.scanned} scanned &middot; ${d.errors} errors</span>
      </div>
      <div style="overflow-x:auto"><table class="res-tbl">
        <thead><tr><th>URL</th><th>STATUS</th><th>SIZE</th><th>SEVERITY</th><th>NOTE</th></tr></thead><tbody>
        ${(d.found||[]).map(f=>`<tr>
          <td><a href="${f.url}" target="_blank" style="color:var(--cyan);text-decoration:none;font-size:10px">${f.url}</a></td>
          <td style="color:${statusCol(f.status)};font-weight:700">${f.status}</td>
          <td style="color:var(--m)">${f.size||"?"}</td>
          <td>${bdg(f.severity,true)}</td>
          <td style="color:#8e8e93;font-size:10px">${f.note||""}</td>
        </tr>`).join("")}
        </tbody>
      </table></div>
    </div>`;
    document.getElementById("dir-res").innerHTML=html;
  }catch(e){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="START ENUMERATION";}
}

// ── BRUTE FORCE ──
function bfTypeChange(){
  const t=document.getElementById("bf-type").value;
  document.getElementById("bf-http-fields").style.display=t==="http"?"block":"none";
  document.getElementById("bf-ssh-fields").style.display=t==="ssh"?"block":"none";
}
async function doBrute(){
  const type=document.getElementById("bf-type").value;
  const users=document.getElementById("bf-users").value.split("\n").map(s=>s.trim()).filter(Boolean);
  const pwds=document.getElementById("bf-pwds").value.split("\n").map(s=>s.trim()).filter(Boolean);
  if(!users.length||!pwds.length){alert("Enter at least one username and password");return;}
  const btn=document.getElementById("bf-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>ATTACKING...';
  document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:12px">Running brute force — ${users.length} users &times; ${pwds.length} passwords...</p></div>`;
  try{
    let url="/brute-http",body={users,passwords:pwds};
    if(type==="http"){
      body.url=document.getElementById("bf-url").value.trim();
      body.user_field=document.getElementById("bf-ufield").value.trim()||"username";
      body.pass_field=document.getElementById("bf-pfield").value.trim()||"password";
    } else {
      url="/brute-ssh";
      body.host=document.getElementById("bf-ssh-host").value.trim();
      body.port=document.getElementById("bf-ssh-port").value.trim()||"22";
    }
    const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.error){document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    const found=d.found||[];
    let html=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span class="${found.length?"found-badge":"bdg"}" style="${found.length?"":`background:rgba(90,90,138,0.1);color:var(--m);border:1px solid rgba(90,90,138,0.2)`}">${found.length} CREDENTIALS FOUND</span>
        <span style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace">${d.attempts||0} attempts &middot; Status: ${d.status||""}</span>
        ${d.note?`<span style="color:var(--yellow);font-size:10px">${d.note}</span>`:""}
      </div>
      ${found.length?`<table class="res-tbl"><thead><tr><th>USERNAME</th><th>PASSWORD</th><th>STATUS</th></tr></thead><tbody>
        ${found.map(f=>`<tr><td style="color:var(--cyan)">${f.username}</td><td style="color:var(--red);font-weight:700">${f.password}</td><td style="color:var(--green)">&#10003; SUCCESS</td></tr>`).join("")}
      </tbody></table>`:`<p style="color:var(--green);font-size:12px">&#10003; No valid credentials found with provided wordlist.</p>`}
    </div>`;
    document.getElementById("bf-res").innerHTML=html;
  }catch(e){document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="START BRUTE FORCE";}
}

// ── NETWORK DISCOVER ──
async function doDisc(){
  const subnet=document.getElementById("subnet").value.trim();if(!subnet)return;
  const btn=document.getElementById("disc-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:12px">Scanning subnet...</p></div>`;
  try{
    const r=await fetch("/discover?subnet="+encodeURIComponent(subnet));
    const d=await r.json();
    if(d.error){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    let html=`<div class="card"><div class="ctitle">${d.total||0} HOSTS FOUND</div><div class="hg">
      ${(d.hosts||[]).map(h=>`<div class="ht" onclick="scanDisc('${h.ip}')">
        <div class="hip">${h.ip}</div>
        ${h.hostnames?.[0]?`<div style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace;margin-top:3px">${h.hostnames[0]}</div>`:""}
        ${h.vendor?`<div style="color:#636366;font-size:9px;margin-top:2px">${h.vendor}</div>`:""}
        <div style="color:var(--m);font-size:9px;font-family:'JetBrains Mono',monospace;margin-top:7px">Click to scan &rsaquo;</div>
      </div>`).join("")}
    </div></div>`;
    document.getElementById("disc-res").innerHTML=html;
  }catch(e){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="DISCOVER";}
}
function scanDisc(ip){document.getElementById("tgt").value=ip;document.querySelector(".nb").click();doScan();}

// ── HISTORY ──
async function loadHist(){
  try{
    const r=await fetch("/history");const d=await r.json();
    if(!d.length){document.getElementById("hist-content").innerHTML=`<p style="color:var(--m);font-size:12px">No scans yet.</p>`;return;}
    let html=`<div style="overflow-x:auto"><table class="hist-tbl">
      <thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>`;
    d.forEach(s=>{html+=`<tr>
      <td style="color:var(--m)">#${s.id}</td><td style="color:var(--cyan)">${s.target}</td>
      <td style="color:var(--m)">${(s.scan_time||"").replace("T"," ").substring(0,19)}</td>
      <td>${s.open_ports}</td><td>${s.total_cves}</td>
      <td style="color:${s.critical_cves>0?"var(--red)":"var(--green)"}">${s.critical_cves}</td>
      <td><button class="lbtn" onclick="loadScan(${s.id})">VIEW</button></td>
    </tr>`;});
    html+=`</tbody></table></div>`;
    document.getElementById("hist-content").innerHTML=html;
  }catch(e){document.getElementById("hist-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}
}
async function loadScan(id){
  document.querySelector(".nb").click();clrUI();
  try{
    const r=await fetch("/scan/"+id);const d=await r.json();
    document.getElementById("tgt").value=d.target||"";
    renderScan(d);initLog();lg("Loaded scan #"+id,"s");
  }catch(e){showErr(e.message);}
}

// ── DASHBOARD ──
async function loadDash(){
  try{
    const r=await fetch("/history?limit=100");const d=await r.json();
    if(!d.length){document.getElementById("dash-content").innerHTML=`<p style="color:var(--m);font-size:12px">Run some scans first.</p>`;return;}
    const tc=d.reduce((a,s)=>a+s.total_cves,0),cr=d.reduce((a,s)=>a+s.critical_cves,0),tp=d.reduce((a,s)=>a+s.open_ports,0);
    const mx=Math.max(...d.map(s=>s.total_cves),1);
    let html=`<div class="sgrid" style="margin-bottom:18px">
      <div class="sc"><div class="sv" style="color:var(--cyan)">${d.length}</div><div class="sl">SCANS</div></div>
      <div class="sc"><div class="sv" style="color:var(--yellow)">${tc}</div><div class="sl">TOTAL CVEs</div></div>
      <div class="sc"><div class="sv" style="color:var(--red)">${cr}</div><div class="sl">CRITICAL</div></div>
      <div class="sc"><div class="sv" style="color:var(--green)">${tp}</div><div class="sl">OPEN PORTS</div></div>
    </div>
    <div class="dash-grid">
      <div class="card"><div class="ctitle">TOP TARGETS BY CVEs</div>
        ${d.slice(0,6).map(s=>`<div class="bar-row"><span class="bl">${s.target.substring(0,12)}</span><div class="bt"><div class="bf" style="width:${s.total_cves/mx*100}%;background:linear-gradient(90deg,var(--red),var(--orange))"></div></div><span class="bv">${s.total_cves}</span></div>`).join("")}
      </div>
      <div class="card"><div class="ctitle">RECENT ACTIVITY</div>
        ${d.slice(0,8).map(s=>`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-size:10px;font-family:'JetBrains Mono',monospace"><span style="color:var(--cyan)">${s.target}</span><span style="color:${s.critical_cves>0?"var(--red)":"var(--m)"}">${s.critical_cves>0?"&#9762; "+s.critical_cves+" crit":s.total_cves+" CVEs"}</span></div>`).join("")}
      </div>
    </div>`;
    document.getElementById("dash-content").innerHTML=html;
  }catch(e){document.getElementById("dash-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}
}

// ── PDF EXPORT ──
async function exportPDF(){
  const data=window._sd;
  if(!data){alert("Run a scan first");return;}
  try{
    const r=await fetch("/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});
    if(!r.ok){const t=await r.text();throw new Error(t.substring(0,200));}
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=`vulnscan-${data.target||"report"}-${new Date().toISOString().slice(0,10)}.pdf`;
    document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
  }catch(e){alert("PDF export failed: "+e.message);}
}
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────
@app.route("/")
def index(): return HTML

@app.route("/scan",methods=["GET","POST"])
def scan():
    target=(request.args.get("target","") if request.method=="GET" else (request.get_json() or {}).get("target","")).strip()
    modules=request.args.get("modules","ports,ssl,dns,headers")
    if not target: return jsonify({"error":"No target specified"}),400
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$',target): return jsonify({"error":"Invalid target"}),400
    try:
        data=run_backend("--modules",modules,target)
        if "error" not in data: data["scan_id"]=save_scan(target,data)
        return jsonify(data)
    except subprocess.TimeoutExpired: return jsonify({"error":"Scan timed out"}),504
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/subdomains")
def subdomains():
    domain=request.args.get("domain","").strip()
    size=request.args.get("size","medium")
    if not domain: return jsonify({"error":"No domain specified"}),400
    if not re.match(r'^[a-zA-Z0-9.\-]+$',domain): return jsonify({"error":"Invalid domain"}),400
    try: return jsonify(run_backend("--subdomains",domain,size,timeout=120))
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/dirbust")
def dirbust():
    url=request.args.get("url","").strip()
    size=request.args.get("size","small")
    ext=request.args.get("ext","php,html,txt")
    if not url: return jsonify({"error":"No URL specified"}),400
    try: return jsonify(run_backend("--dirbust",url,size,ext,timeout=180))
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/brute-http",methods=["POST"])
def brute_http():
    d=request.get_json() or {}
    url=d.get("url","").strip()
    if not url: return jsonify({"error":"No URL"}),400
    users=",".join(d.get("users",[])[:10])
    pwds=",".join(d.get("passwords",[])[:50])
    uf=d.get("user_field","username"); pf=d.get("pass_field","password")
    try: return jsonify(run_backend("--brute-http",url,users,pwds,uf,pf,timeout=120))
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/brute-ssh",methods=["POST"])
def brute_ssh():
    d=request.get_json() or {}
    host=d.get("host","").strip(); port=str(d.get("port","22"))
    if not host: return jsonify({"error":"No host"}),400
    users=",".join(d.get("users",[])[:5])
    pwds=",".join(d.get("passwords",[])[:20])
    try: return jsonify(run_backend("--brute-ssh",host,port,users,pwds,timeout=120))
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/discover")
def discover():
    subnet=request.args.get("subnet","").strip()
    if not subnet: return jsonify({"error":"No subnet"}),400
    if not re.match(r'^[0-9./]+$',subnet): return jsonify({"error":"Invalid subnet"}),400
    try: return jsonify(run_backend("--discover",subnet,timeout=120))
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/history")
def history():
    return jsonify(get_history(int(request.args.get("limit",20))))

@app.route("/scan/<int:sid>")
def get_scan(sid):
    d=get_scan_by_id(sid)
    return jsonify(d) if d else (jsonify({"error":"Not found"}),404)

@app.route("/report",methods=["POST"])
def report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,HRFlowable,PageBreak
        from reportlab.lib.enums import TA_LEFT,TA_CENTER
    except ImportError:
        return jsonify({"error":"reportlab not installed. Run: pip3 install reportlab --user"}),500

    data=request.get_json() or {}
    target=data.get("target","unknown")
    scan_time=data.get("scan_time","")[:19].replace("T"," ")
    summary=data.get("summary",{})
    modules=data.get("modules",{})
    hosts=modules.get("ports",{}).get("hosts",[])
    all_ports=[p for h in hosts for p in h.get("ports",[])]

    C_BG=colors.HexColor("#04040a"); C_DARK=colors.HexColor("#0d0d18")
    C_BORDER=colors.HexColor("#16162a"); C_MUTED=colors.HexColor("#5a5a8a")
    C_WHITE=colors.HexColor("#e8e8f0"); C_CYAN=colors.HexColor("#00e5ff")
    C_RED=colors.HexColor("#ff3366"); C_ORANGE=colors.HexColor("#ff6b35")
    C_YELLOW=colors.HexColor("#ffd60a"); C_GREEN=colors.HexColor("#00ff9d")
    C_PURPLE=colors.HexColor("#b06fff")
    SEV_C={"CRITICAL":C_RED,"HIGH":C_ORANGE,"MEDIUM":C_YELLOW,"LOW":C_GREEN,"UNKNOWN":C_MUTED}
    GCP={"A+":C_GREEN,"A":C_CYAN,"B":C_YELLOW,"C":C_ORANGE,"D":C_ORANGE,"F":C_RED}

    def sty(name,**kw):
        d=dict(fontName="Helvetica",fontSize=9,textColor=C_WHITE,leading=14,spaceAfter=4,spaceBefore=2,leftIndent=0,alignment=TA_LEFT)
        d.update(kw); return ParagraphStyle(name,**d)
    S_T=sty("t",fontName="Helvetica-Bold",fontSize=26,textColor=C_CYAN,leading=32,spaceAfter=6)
    S_H1=sty("h1",fontName="Helvetica-Bold",fontSize=15,textColor=C_CYAN,leading=20,spaceBefore=16,spaceAfter=8)
    S_H2=sty("h2",fontName="Helvetica-Bold",fontSize=11,textColor=C_WHITE,leading=16,spaceBefore=10,spaceAfter=5)
    S_H3=sty("h3",fontName="Helvetica-Bold",fontSize=9,textColor=C_MUTED,leading=13,spaceBefore=7,spaceAfter=4,leftIndent=8)
    S_B=sty("b"); S_M=sty("m",textColor=C_MUTED)
    S_W=sty("w",fontName="Helvetica-Bold",textColor=C_RED)
    S_C=sty("c",alignment=TA_CENTER,textColor=C_MUTED,fontSize=8)

    def p(t,s=None): return Paragraph(str(t),s or S_B)
    def sp(h=6): return Spacer(1,h)
    def hr(): return HRFlowable(width="100%",thickness=0.5,color=C_BORDER,spaceAfter=7,spaceBefore=3)
    def tbl(data,cols,style_extra=[]):
        t=Table(data,colWidths=cols)
        base=[("FONTSIZE",(0,0),(-1,-1),8),("FONTNAME",(0,0),(-1,-1),"Helvetica"),
              ("TEXTCOLOR",(0,0),(-1,-1),C_WHITE),("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK,C_BG]),
              ("GRID",(0,0),(-1,-1),0.3,C_BORDER),("TOPPADDING",(0,0),(-1,-1),6),
              ("BOTTOMPADDING",(0,0),(-1,-1),6),("LEFTPADDING",(0,0),(-1,-1),8)]
        t.setStyle(TableStyle(base+style_extra)); return t

    W,H=A4
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=16*mm,rightMargin=16*mm,topMargin=14*mm,bottomMargin=14*mm)

    def draw_bg(canvas,doc):
        canvas.saveState()
        canvas.setFillColor(C_BG); canvas.rect(0,0,W,H,fill=1,stroke=0)
        canvas.setFillColor(C_RED); canvas.rect(0,H-3,W,3,fill=1,stroke=0)
        canvas.setFillColor(C_DARK); canvas.rect(0,0,W,13*mm,fill=1,stroke=0)
        canvas.setFont("Helvetica",7); canvas.setFillColor(C_MUTED)
        canvas.drawString(16*mm,4.5*mm,f"VulnScan Pro  |  {target}  |  {scan_time}  |  CONFIDENTIAL")
        canvas.drawRightString(W-16*mm,4.5*mm,f"Page {doc.page}")
        canvas.restoreState()

    story=[]
    crit_c=summary.get("critical_cves",0); high_c=summary.get("high_cves",0)
    if crit_c>0: risk=("F",C_RED,"CRITICAL RISK")
    elif high_c>0: risk=("D",C_ORANGE,"HIGH RISK")
    elif summary.get("total_cves",0)>0: risk=("C",C_YELLOW,"MEDIUM RISK")
    else: risk=("A",C_GREEN,"LOW RISK")

    # Cover
    story+=[sp(36),p("VulnScan Pro",S_T)]
    story.append(p("SECURITY ASSESSMENT REPORT",sty("st2",fontName="Helvetica-Bold",fontSize=12,textColor=C_PURPLE,leading=18,spaceAfter=4)))
    story+=[sp(8),hr(),sp(8)]
    mt=tbl([[k,v] for k,v in [("Target",target),("Scan Time",scan_time),("Report Date",datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),("Risk Level",risk[2])]],
           [38*mm,115*mm],[("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(0,-1),C_MUTED),("TEXTCOLOR",(1,3),(1,3),risk[1]),("FONTNAME",(1,3),(1,3),"Helvetica-Bold")])
    story+=[mt,sp(18)]
    st_data=[[f"{summary.get('open_ports',0)}\nOPEN PORTS",f"{summary.get('total_cves',0)}\nTOTAL CVEs",f"{crit_c}\nCRITICAL",f"{high_c}\nHIGH",f"{summary.get('exploitable',0)}\nEXPLOITABLE"]]
    st=Table(st_data,colWidths=[30*mm]*5)
    st_s=TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                     ("TOPPADDING",(0,0),(-1,-1),11),("BOTTOMPADDING",(0,0),(-1,-1),11),
                     ("FONTSIZE",(0,0),(-1,-1),8),("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),
                     ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK]),("GRID",(0,0),(-1,-1),0.4,C_BORDER)])
    for i,c in enumerate([C_CYAN,C_YELLOW,C_RED,C_ORANGE,C_PURPLE]):
        st_s.add("TEXTCOLOR",(i,0),(i,0),c)
    st.setStyle(st_s); story+=[st,sp(28)]
    story.append(p("CONFIDENTIAL — Authorized security assessment only",sty("disc",fontSize=8,textColor=C_MUTED,alignment=TA_CENTER)))
    story.append(PageBreak())

    # Executive Summary
    story+=[p("Executive Summary",S_H1),hr()]
    story.append(tbl([[k,v] for k,v in [("Target",target),("Open Ports",str(summary.get("open_ports",0))),
        ("Total CVEs",str(summary.get("total_cves",0))),("Critical CVEs",str(crit_c)),
        ("Exploitable",str(summary.get("exploitable",0))),("Overall Risk",risk[2])]],
        [48*mm,105*mm],[("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(0,-1),C_MUTED),
                        ("TEXTCOLOR",(1,5),(1,5),risk[1]),("FONTNAME",(1,5),(1,5),"Helvetica-Bold")]))
    story+=[sp(10)]
    if crit_c>0: story.append(p(f"CRITICAL: {crit_c} critical CVEs found. {summary.get('exploitable',0)} have public exploits. Immediate action required.",S_W))
    story.append(PageBreak())

    # Port Findings
    story+=[p("Port Scan Findings",S_H1),hr()]
    if all_ports:
        rows=[["PORT","PROTOCOL","SERVICE","PRODUCT","VERSION","RISK"]]
        for pt in all_ports: rows.append([str(pt.get("port","")),pt.get("protocol","tcp").upper(),pt.get("service",""),pt.get("product",""),pt.get("version",""),pt.get("risk_level","?")])
        pt=tbl(rows,[16*mm,20*mm,24*mm,38*mm,26*mm,24*mm],[("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(-1,0),C_MUTED),("ALIGN",(0,0),(1,-1),"CENTER")])
        for i,ptt in enumerate(all_ports,1):
            pt.setStyle(TableStyle([("TEXTCOLOR",(5,i),(5,i),SEV_C.get(ptt.get("risk_level","UNKNOWN"),C_MUTED)),("FONTNAME",(5,i),(5,i),"Helvetica-Bold")]))
        story+=[pt,sp(18),p("Detailed Findings",S_H1),hr()]
        for pt2 in all_ports:
            lv=pt2.get("risk_level","UNKNOWN"); sc=SEV_C.get(lv,C_MUTED)
            hh=Table([[f"Port {pt2.get('port','')}/{pt2.get('protocol','tcp').upper()}",f"{pt2.get('product','')} {pt2.get('version','')}".strip(),f"{lv}  CVSS {pt2.get('risk_score','?')}"]],colWidths=[33*mm,88*mm,38*mm])
            hh.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(0,0),"Helvetica-Bold"),("FONTNAME",(2,0),(2,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("TEXTCOLOR",(0,0),(0,0),C_CYAN),("TEXTCOLOR",(1,0),(1,0),C_WHITE),("TEXTCOLOR",(2,0),(2,0),sc),("TOPPADDING",(0,0),(-1,0),8),("BOTTOMPADDING",(0,0),(-1,0),8),("LEFTPADDING",(0,0),(-1,0),9),("LINEBELOW",(0,0),(-1,0),1.5,sc)]))
            story+=[hh,sp(5)]
            for cv in pt2.get("cves",[]):
                cs=SEV_C.get(cv.get("severity","UNKNOWN"),C_MUTED)
                ch=Table([[cv.get("id",""),f"{cv.get('severity','?')}  CVSS {cv.get('score','?')}{'  [PUBLIC EXPLOIT]' if cv.get('has_exploit') else ''}",cv.get("published","")]],colWidths=[38*mm,88*mm,28*mm])
                ch.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(0,0),"Helvetica-Bold"),("FONTNAME",(1,0),(1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("TEXTCOLOR",(0,0),(0,0),C_CYAN),("TEXTCOLOR",(1,0),(1,0),cs),("TEXTCOLOR",(2,0),(2,0),C_MUTED),("TOPPADDING",(0,0),(-1,0),5),("BOTTOMPADDING",(0,0),(-1,0),5),("LEFTPADDING",(0,0),(-1,0),8),("LINEBELOW",(0,0),(-1,0),0.5,cs)]))
                dd=Table([[cv.get("description","")]],colWidths=[154*mm])
                dd.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_BG),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),8),("TEXTCOLOR",(0,0),(-1,-1),C_MUTED),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.3,C_BORDER)]))
                story+=[ch,dd,sp(4)]
            mits=pt2.get("mitigations",[])
            if mits:
                story.append(p("Mitigations",S_H3))
                mr=Table([[m] for m in mits],colWidths=[154*mm])
                ms=TableStyle([("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),8),("TEXTCOLOR",(0,0),(-1,-1),C_WHITE),("ROWBACKGROUNDS",(0,0),(-1,-1),[C_BG,C_DARK]),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),9),("GRID",(0,0),(-1,-1),0.3,C_BORDER),("LINEAFTER",(0,0),(0,-1),2,C_GREEN)])
                if mits and "URGENT" in mits[0]: ms.add("TEXTCOLOR",(0,0),(0,0),C_RED); ms.add("FONTNAME",(0,0),(0,0),"Helvetica-Bold")
                mr.setStyle(ms); story.append(mr)
            story+=[sp(14),hr()]

    story.append(PageBreak())

    # SSL
    ssl_r=modules.get("ssl",[])
    if ssl_r:
        story+=[p("SSL/TLS Analysis",S_H1),hr()]
        for s in ssl_r:
            d2=s.get("details",{})
            story.append(p(f"{s.get('host','')}:{s.get('port',443)}  Grade: {s.get('grade','?')}",S_H2))
            story.append(tbl([[k,v] for k,v in [("Protocol",d2.get("protocol","?")),("Cipher",d2.get("cipher","?")),("Bits",str(d2.get("cipher_bits","?"))),("Subject",d2.get("subject","")),("Issuer",d2.get("issuer","")),("Expires",d2.get("expires","")),("Days Left",str(d2.get("days_until_expiry","?")))]],
                [38*mm,115*mm],[("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(0,-1),C_MUTED)]))
            story.append(sp(8))
            for iss in s.get("issues",[]):
                sc=SEV_C.get(iss.get("severity","UNKNOWN"),C_MUTED)
                story.append(p(f"  [{iss['severity']}]  {iss.get('msg','')}",sty("si",fontName="Helvetica",fontSize=8,textColor=sc,leading=13,leftIndent=10)))
            story+=[sp(10),hr()]
        story.append(PageBreak())

    # DNS
    dns=modules.get("dns")
    if dns:
        story+=[p("DNS Reconnaissance",S_H1),hr()]
        recs=dns.get("records",{})
        if recs:
            rows=[["TYPE","VALUE"]]
            for rt,vals in recs.items():
                for v in vals: rows.append([rt,v])
            story.append(tbl(rows,[23*mm,130*mm],[("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(-1,0),C_MUTED),("TEXTCOLOR",(0,1),(0,-1),C_CYAN)]))
            story.append(sp(10))
        spf=dns.get("has_spf",False); dm=dns.get("has_dmarc",False)
        story.append(tbl([["SPF","Configured" if spf else "MISSING"],["DMARC","Configured" if dm else "MISSING"]],
            [38*mm,115*mm],[("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(0,-1),C_MUTED),
                            ("TEXTCOLOR",(1,0),(1,0),C_GREEN if spf else C_RED),("TEXTCOLOR",(1,1),(1,1),C_GREEN if dm else C_ORANGE)]))
        subs=dns.get("subdomains",[])
        if subs:
            story+=[sp(8),p(f"Subdomains ({len(subs)})",S_H2)]
            story.append(tbl([["SUBDOMAIN","IP"]]+[[s["subdomain"],s["ip"]] for s in subs],[88*mm,65*mm],[("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(-1,0),C_MUTED)]))
        story.append(PageBreak())

    # Headers
    hd=modules.get("headers")
    if hd:
        gc=GCP.get(hd.get("grade","F"),C_RED)
        story+=[p("Web Headers Analysis",S_H1),hr(),p(f"Grade: {hd.get('grade','?')}  |  Score: {hd.get('score',0)}/100  |  {hd.get('url','')}",S_H2),sp(8)]
        hi=hd.get("issues",[])
        if hi:
            story.append(tbl([["SEVERITY","ISSUE"]]+[[i.get("severity","?"),i.get("msg","")] for i in hi],
                [28*mm,125*mm],[("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(-1,0),C_MUTED)]))
            for i,iss in enumerate(hi,1):
                pass # colors set inline if needed
            story.append(sp(10))
        story.append(PageBreak())

    # Checklist
    story+=[p("Remediation Checklist",S_H1),hr()]
    seen=[]
    for pt3 in all_ports:
        for m in pt3.get("mitigations",[]):
            if m not in seen: seen.append(m)
    if seen:
        rows=[["","ACTION","PRIORITY"]]
        for m in seen:
            pr="URGENT" if "URGENT" in m or "immediately" in m.lower() else "HIGH" if seen.index(m)<4 else "MEDIUM"
            rows.append(["[ ]",m,pr])
        ct=tbl(rows,[9*mm,128*mm,20*mm],[("BACKGROUND",(0,0),(-1,0),C_DARK),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(-1,0),C_MUTED),("TEXTCOLOR",(0,1),(0,-1),C_MUTED),("ALIGN",(2,0),(2,-1),"CENTER")])
        for i,m in enumerate(seen,1):
            pr="URGENT" if "URGENT" in m or "immediately" in m.lower() else "HIGH" if i<4 else "MEDIUM"
            pc=C_RED if pr=="URGENT" else (C_ORANGE if pr=="HIGH" else C_YELLOW)
            ct.setStyle(TableStyle([("TEXTCOLOR",(2,i),(2,i),pc),("FONTNAME",(2,i),(2,i),"Helvetica-Bold")]))
        story+=[ct,sp(18)]
    story+=[hr(),p("Generated by VulnScan Pro  |  Confidential Security Assessment",S_C),p(f"Target: {target}  |  {scan_time}",S_C)]

    doc.build(story,onFirstPage=draw_bg,onLaterPages=draw_bg)
    buf.seek(0)
    fname=f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]','_',target)}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(buf.read(),mimetype="application/pdf",headers={"Content-Disposition":f"attachment; filename={fname}"})

@app.route("/health")
def health(): return jsonify({"status":"ok","version":"2.1"})

if __name__=="__main__":
    print("[*] VulnScan Pro v2.1 starting")
    print("[*] Open: http://localhost:5000")
    app.run(host="0.0.0.0",port=5000,debug=False)
