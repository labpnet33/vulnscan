#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess, json, sys, os, re

app = Flask(__name__)
CORS(app)
BACKEND_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

HTML_UI = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>VulnScan</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#050507;color:#e5e5ea;font-family:monospace;min-height:100vh}
header{background:#0a0a0f;border-bottom:1px solid #1c1c1e;padding:20px 32px}
h1{font-size:22px;color:#fff} h1 span{color:#ff2d55}
.sub{color:#636366;font-size:10px;letter-spacing:2px;margin-top:4px}
.container{max-width:900px;margin:0 auto;padding:28px 20px}
.card{background:#0a0a0c;border:1px solid #1c1c1e;border-radius:10px;padding:18px;margin-bottom:18px}
.label{color:#636366;font-size:10px;letter-spacing:2px;margin-bottom:10px}
.row{display:flex;gap:10px;flex-wrap:wrap}
input{flex:1;min-width:180px;background:#050507;border:1px solid #2c2c2e;border-radius:8px;color:#00d4ff;padding:10px 14px;font-size:13px;font-family:monospace;outline:none}
input:focus{border-color:#00d4ff} input::placeholder{color:#3a3a3c}
.btn{padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-family:monospace;font-weight:700;font-size:12px;letter-spacing:1px}
.primary{background:linear-gradient(135deg,#ff2d55,#c02030);color:#fff}
.primary:disabled{background:#1c1c1e;color:#636366;cursor:not-allowed}
.secondary{background:transparent;color:#636366;border:1px solid #2c2c2e}
#log{background:#050507;border:1px solid #1c1c1e;border-radius:8px;padding:12px;margin-bottom:16px;max-height:150px;overflow-y:auto;display:none;font-size:12px;line-height:1.9}
.li{color:#8e8e93}.li .p{color:#00d4ff}.ls .p{color:#30d158}.lw .p{color:#ffd60a}.le .p{color:#ff2d55}
#err{background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.3);border-radius:8px;padding:12px;color:#ff2d55;font-size:13px;margin-bottom:16px;display:none}
#res{display:none}
.stats{display:flex;gap:12px;flex-wrap:wrap;padding:16px;background:#050507;border-radius:8px;border:1px solid #1c1c1e;margin-bottom:16px;text-align:center}
.stat{flex:1;min-width:70px}
.sv{font-size:24px;font-weight:800} .sl{color:#636366;font-size:10px;letter-spacing:1px;margin-top:2px}
.pc{border-radius:6px;margin-bottom:8px;overflow:hidden}
.ph{padding:12px 16px;cursor:pointer;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.pn{padding:5px 12px;border-radius:5px;font-weight:700;font-size:16px;min-width:60px;text-align:center}
.pi{flex:1} .pname{font-weight:600;font-size:13px} .psub{color:#636366;font-size:11px;margin-top:1px}
.bdg{border-radius:4px;padding:1px 7px;font-size:10px;font-weight:700;letter-spacing:1px;border:1px solid transparent}
.chev{color:#636366;font-size:11px;transition:transform 0.2s;margin-left:auto}
.pb{padding:0 16px 16px;border-top:1px solid #1c1c1e;display:none}
.pb.open{display:block}
.stitle{color:#636366;font-size:10px;letter-spacing:2px;font-weight:700;margin:12px 0 7px}
.ci{background:#050507;border:1px solid #1c1c1e;border-radius:5px;padding:10px;margin-bottom:5px}
.ch{display:flex;align-items:center;gap:7px;margin-bottom:5px;flex-wrap:wrap}
.cid{color:#00d4ff;font-weight:700;font-size:11px;text-decoration:none}
.cid:hover{text-decoration:underline}
.cdate{color:#636366;font-size:10px;margin-left:auto}
.cdesc{color:#8e8e93;font-size:11px;line-height:1.6}
.ml{background:#050507;border:1px solid #1c1c1e;border-radius:5px;padding:10px}
.mi{display:flex;gap:7px;padding:4px 0;border-bottom:1px solid #1c1c1e;font-size:11px;line-height:1.6;color:#c7c7cc}
.mi:last-child{border-bottom:none} .ma{color:#30d158;flex-shrink:0}
.info p{color:#8e8e93;font-size:12px;line-height:2.2} .info span{color:#ffd60a}
.info code{color:#00d4ff}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#2c2c2e;border-radius:2px}
.spin{display:inline-block;width:11px;height:11px;border:2px solid #2c2c2e;border-top-color:#00d4ff;border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
</style></head><body>
<header><h1><span>&#9889;</span> VulnScan</h1><p class="sub">PORT SCANNER + CVE INTELLIGENCE</p></header>
<div class="container">
<div class="card">
  <div class="label">TARGET</div>
  <div class="row">
    <input id="tgt" type="text" placeholder="IP address or URL  e.g. 192.168.1.1" onkeydown="if(event.key==='Enter')go()"/>
    <button class="btn primary" id="sbtn" onclick="go()">SCAN</button>
    <button class="btn secondary" onclick="demo()">DEMO</button>
  </div>
</div>
<div id="log"></div>
<div id="err"></div>
<div id="res"></div>
<div class="card info">
  <div class="label">HOW IT WORKS</div>
  <p>
    <span>1.</span> Enter an IP or URL and click SCAN &mdash; nmap detects open ports and service versions<br/>
    <span>2.</span> Each service is checked against <code>nvd.nist.gov</code> for known CVEs<br/>
    <span>3.</span> Mitigation advice is generated automatically per service<br/>
    <span>4.</span> Click DEMO to see a sample result without scanning<br/>
    <span>&#9888;</span> Only scan systems you own or have explicit permission to scan
  </p>
</div>
</div>
<script>
const S={CRITICAL:{c:"#ff2d55",b:"rgba(255,45,85,0.12)",i:"&#9762;"},HIGH:{c:"#ff6b35",b:"rgba(255,107,53,0.12)",i:"&#9888;"},MEDIUM:{c:"#ffd60a",b:"rgba(255,214,10,0.12)",i:"&#9889;"},LOW:{c:"#30d158",b:"rgba(48,209,88,0.12)",i:"&#10003;"},UNKNOWN:{c:"#636366",b:"rgba(99,99,102,0.12)",i:"?"}};
const DM={hosts:[{ip:"192.168.1.1",status:"up",hostnames:["router.local"],ports:[
{port:22,protocol:"tcp",service:"ssh",product:"OpenSSH",version:"7.4",extrainfo:"protocol 2.0",risk_level:"HIGH",risk_score:9.8,cves:[{id:"CVE-2023-38408",description:"PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has insufficiently trustworthy search path, leading to remote code execution.",score:9.8,severity:"CRITICAL",published:"2023-07-20",references:["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]},{id:"CVE-2023-28531",description:"ssh-add in OpenSSH before 9.3 applies destination constraints to smartcard keys incorrectly, allowing bypass of security policies.",score:7.8,severity:"HIGH",published:"2023-03-17",references:["https://nvd.nist.gov/vuln/detail/CVE-2023-28531"]}],mitigations:["URGENT: 2 critical/high CVEs - patch immediately","Upgrade OpenSSH to v9.3p2 or later","Set PermitRootLogin no in sshd_config","Use SSH key auth instead of passwords","Deploy fail2ban against brute-force"]},
{port:80,protocol:"tcp",service:"http",product:"Apache httpd",version:"2.4.51",extrainfo:"",risk_level:"CRITICAL",risk_score:9.8,cves:[{id:"CVE-2021-41773",description:"Path traversal and RCE in Apache 2.4.49 allows attackers to access files outside document root and execute commands.",score:9.8,severity:"CRITICAL",published:"2021-10-05",references:["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]}],mitigations:["URGENT: Upgrade Apache to 2.4.52 or later now","Enable HTTPS, redirect all HTTP traffic","Implement Content Security Policy headers","Disable directory listing and version disclosure"]},
{port:3306,protocol:"tcp",service:"mysql",product:"MySQL",version:"5.7.38",extrainfo:"Community Server",risk_level:"MEDIUM",risk_score:4.9,cves:[{id:"CVE-2022-21417",description:"MySQL Server vulnerability allows high privileged attacker to cause hang or crash via multiple network protocols.",score:4.9,severity:"MEDIUM",published:"2022-04-19",references:["https://nvd.nist.gov/vuln/detail/CVE-2022-21417"]}],mitigations:["Never expose MySQL directly to internet","Bind to localhost: bind-address=127.0.0.1","Use strong passwords, principle of least privilege","Upgrade to MySQL 8.0 LTS"]}
]}],scan_info:{elapsed:"12.34",summary:"Nmap done: 1 IP address (1 host up) scanned"}};
let busy=false;
function lg(t,tp="i"){const el=document.getElementById("log");el.style.display="block";const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="l"+tp;d.innerHTML="<span class='p'>"+p+"</span> "+t;el.appendChild(d);el.scrollTop=el.scrollHeight;}
function clr(){["log","err","res"].forEach(id=>{const e=document.getElementById(id);e.innerHTML="";e.style.display="none";});}
function bdg(lv){const s=S[lv]||S.UNKNOWN;return'<span class="bdg" style="background:'+s.b+';color:'+s.c+';border-color:'+s.c+'40">'+s.i+' '+lv+'</span>';}
function render(data){
  const ap=data.hosts.flatMap(h=>h.ports||[]);
  const cr=ap.filter(p=>p.risk_level==="CRITICAL").length,hi=ap.filter(p=>p.risk_level==="HIGH").length,cv=ap.reduce((a,p)=>a+(p.cves?p.cves.length:0),0);
  let h='<div class="stats">';
  h+='<div class="stat"><div class="sv" style="color:#00d4ff">'+ap.length+'</div><div class="sl">OPEN PORTS</div></div>';
  h+='<div class="stat"><div class="sv" style="color:#ff2d55">'+cr+'</div><div class="sl">CRITICAL</div></div>';
  h+='<div class="stat"><div class="sv" style="color:#ff6b35">'+hi+'</div><div class="sl">HIGH</div></div>';
  h+='<div class="stat"><div class="sv" style="color:#ffd60a">'+cv+'</div><div class="sl">TOTAL CVEs</div></div></div>';
  data.hosts.forEach(function(host){
    h+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">';
    h+='<span style="color:#00d4ff;background:rgba(0,212,255,0.08);padding:3px 10px;border-radius:4px;border:1px solid rgba(0,212,255,0.2);font-size:12px">'+(host.ip||'')+'</span>';
    if(host.hostnames&&host.hostnames[0])h+='<span style="color:#636366;font-size:12px">'+host.hostnames[0]+'</span>';
    h+='<span style="color:#30d158;font-size:12px">&#9679; '+(host.status||'up')+'</span></div>';
    (host.ports||[]).forEach(function(port,i){
      const s=S[port.risk_level]||S.UNKNOWN;
      h+='<div class="pc" style="border:1px solid '+s.c+'30;border-left:3px solid '+s.c+'">';
      h+='<div class="ph" onclick="tp('+i+')">';
      h+='<div class="pn" style="background:'+s.b+';color:'+s.c+'">'+port.port+'</div>';
      h+='<div class="pi"><div class="pname">'+(port.product||port.service||'unknown');
      if(port.version)h+=' <span style="color:#636366;font-size:11px">v'+port.version+'</span>';
      h+='</div><div class="psub">'+((port.protocol||'tcp').toUpperCase())+' &middot; '+(port.service||'');
      if(port.extrainfo)h+=' &middot; '+port.extrainfo;
      h+='</div></div>';
      h+='<div style="display:flex;align-items:center;gap:8px">'+bdg(port.risk_level);
      if(port.risk_score)h+='<span style="color:'+s.c+';font-weight:700;font-size:13px">'+port.risk_score+'</span>';
      h+='<span class="chev" id="cv'+i+'">&#9660;</span></div></div>';
      h+='<div class="pb" id="pb'+i+'">';
      if(port.cves&&port.cves.length){
        h+='<div class="stitle">VULNERABILITIES ('+port.cves.length+')</div>';
        port.cves.forEach(function(c){
          const cs=S[c.severity]||S.UNKNOWN;
          h+='<div class="ci"><div class="ch"><a class="cid" href="'+(c.references&&c.references[0]?c.references[0]:'https://nvd.nist.gov/vuln/detail/'+c.id)+'" target="_blank">'+c.id+'</a>';
          h+=bdg(c.severity);
          if(c.score)h+='<span style="color:'+cs.c+';font-weight:700;font-size:11px">CVSS '+c.score+'</span>';
          h+='<span class="cdate">'+(c.published||'')+'</span></div><div class="cdesc">'+(c.description||'')+'</div></div>';
        });
      }
      if(port.mitigations&&port.mitigations.length){
        h+='<div class="stitle">MITIGATIONS</div><div class="ml">';
        port.mitigations.forEach(function(m){h+='<div class="mi"><span class="ma">&rsaquo;</span><span>'+m+'</span></div>';});
        h+='</div>';
      }
      h+='</div></div>';
    });
  });
  if(data.scan_info&&data.scan_info.summary)h+='<div style="color:#636366;font-size:11px;text-align:center;margin-top:10px">'+data.scan_info.summary+' &middot; '+data.scan_info.elapsed+'s</div>';
  const r=document.getElementById("res");r.innerHTML=h;r.style.display="block";
}
function tp(i){const b=document.getElementById("pb"+i),c=document.getElementById("cv"+i);b.classList.toggle("open");c.style.transform=b.classList.contains("open")?"rotate(180deg)":"none";}
async function go(){
  const tgt=document.getElementById("tgt").value.trim();if(!tgt||busy)return;
  clr();busy=true;const btn=document.getElementById("sbtn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  lg("Target: "+tgt);lg("Starting nmap scan — may take 30 to 120 seconds","w");
  try{
    const r=await fetch("/scan?target="+encodeURIComponent(tgt));
    const d=await r.json();
    if(d.error){const e=document.getElementById("err");e.textContent="Error: "+d.error;e.style.display="block";lg(d.error,"e");}
    else{lg("Scan complete. "+(d.hosts||[]).flatMap(h=>h.ports||[]).length+" ports found","s");render(d);}
  }catch(e){const er=document.getElementById("err");er.textContent="Cannot reach backend: "+e.message;er.style.display="block";}
  finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}
}
function demo(){clr();lg("Loading demo...");setTimeout(()=>{lg("Demo loaded","s");render(DM);},700);}
</script></body></html>"""

@app.route("/")
def index():
    return HTML_UI

@app.route("/scan", methods=["GET","POST"])
def scan():
    target=(request.args.get("target","") if request.method=="GET" else (request.get_json() or {}).get("target","")).strip()
    if not target: return jsonify({"error":"No target specified"}),400
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$',target): return jsonify({"error":"Invalid target format"}),400
    try:
        r=subprocess.run([sys.executable,BACKEND_SCRIPT,target],capture_output=True,text=True,timeout=180)
        if r.stdout: return jsonify(json.loads(r.stdout))
        return jsonify({"error":r.stderr or "No output"}),500
    except subprocess.TimeoutExpired: return jsonify({"error":"Scan timed out"}),504
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/health")
def health(): return jsonify({"status":"ok","message":"VulnScan API is running"})

if __name__=="__main__":
    print("[*] VulnScan starting at http://localhost:5000")
    print("[*] Open browser: http://localhost:5000  or  http://10.0.0.91:5000")
    app.run(host="0.0.0.0",port=5000,debug=False)
