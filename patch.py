#!/usr/bin/env python3
"""
VulnScan Pro — Tool JS Functions Patch v2
==========================================
This patch ONLY injects the JavaScript handler functions for the tool pages.
The HTML for the tool pages is already correctly present in api_server.py.

Run from your vulnscan project root:
    python3 patch_tool_pages_v2.py
"""

import os, sys, shutil, subprocess
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    ok(f"Backup: {bak}")
    return bak

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

TARGET = "api_server.py"

# ══════════════════════════════════════════════════════════════════════════════
# JS HELPERS — these are the tool-specific JavaScript functions
# We inject them right before the closing </script> tag of the main HTML block
# ══════════════════════════════════════════════════════════════════════════════

JS_HELPERS = r"""
/* ══ TOOL-SPECIFIC JS HELPERS (injected by patch_tool_pages_v2.py) ══════════ */

/* ── Generic tool runner ─────────────────────────────────────────────────── */
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
      body:JSON.stringify({tool:bin,operation:'custom',args:args,timeout:timeout})
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

/* ── ffuf ───────────────────────────────────────────────────────────────── */
async function runFfuf(){
  var url=document.getElementById('ffuf-url').value.trim();
  if(!url){alert('Enter a target URL with FUZZ placeholder');return;}
  var wl=document.getElementById('ffuf-wordlist').value.trim();
  var method=document.getElementById('ffuf-method').value;
  var fc=document.getElementById('ffuf-fc').value.trim();
  var mc=document.getElementById('ffuf-mc').value.trim();
  var ext=document.getElementById('ffuf-e').value.trim();
  var threads=document.getElementById('ffuf-threads').value||'40';
  var extra=document.getElementById('ffuf-extra').value.trim();
  var timeout=parseInt(document.getElementById('ffuf-timeout').value||'120',10);
  var args='-u "'+url+'" -w '+wl+' -X '+method+' -t '+threads;
  if(fc)args+=' -fc '+fc;
  if(mc)args+=' -mc '+mc;
  if(ext)args+=' -e '+ext;
  if(extra)args+=' '+extra;
  args+=' -of json -o /tmp/ffuf_out.json';
  var btn=document.getElementById('ffuf-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('ffuf');t.start();t.log('Running: ffuf '+args,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'ffuf',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'ffuf');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('ffuf completed (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Results</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN FFUF';}
}

/* ── nuclei ─────────────────────────────────────────────────────────────── */
async function runNuclei(){
  var target=document.getElementById('nuclei-target').value.trim();
  if(!target){alert('Enter a target URL or host');return;}
  var sevEl=document.getElementById('nuclei-severity');
  var sevs=Array.from(sevEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var tagsEl=document.getElementById('nuclei-tags');
  var tags=Array.from(tagsEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var threads=document.getElementById('nuclei-threads').value||'25';
  var rate=document.getElementById('nuclei-rate').value||'150';
  var timeout=parseInt(document.getElementById('nuclei-timeout').value||'300',10);
  var tplPath=document.getElementById('nuclei-templates').value.trim();
  var args='-u "'+target+'" -t '+threads+' -rate-limit '+rate+' -jsonl -stats=false';
  if(sevs)args+=' -severity '+sevs;
  if(tags)args+=' -tags '+tags;
  if(tplPath)args+=' -t "'+tplPath+'"';
  var btn=document.getElementById('nuclei-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('nuclei');t.start();t.log('Running nuclei against: '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'nuclei',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'nuclei');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var lines=(d.stdout||'').split('\n').filter(Boolean).length;
      t.log('Nuclei done — '+lines+' result line(s)','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Findings</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No findings.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NUCLEI';}
}
async function runNucleiUpdate(){
  var t=mkTool('nuclei');t.start();t.log('Updating nuclei templates...','w');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'nuclei',operation:'custom',args:'-update-templates',timeout:120})},130000,'nuclei');
  var d=await r.json();t.end();
  t.log(d.error||d.stdout||'Update complete','s');
}

/* ── whatweb ────────────────────────────────────────────────────────────── */
async function runWhatWeb(){
  var target=document.getElementById('whatweb-target').value.trim();
  if(!target){alert('Enter a target URL or host');return;}
  var agg=document.getElementById('whatweb-aggression').value||'3';
  var fmt=document.getElementById('whatweb-format').value;
  var timeout=parseInt(document.getElementById('whatweb-timeout').value||'60',10);
  var ua=document.getElementById('whatweb-ua').value.trim();
  var proxy=document.getElementById('whatweb-proxy').value.trim();
  var extra=document.getElementById('whatweb-extra').value.trim();
  var args='"'+target+'" --aggression='+agg+' '+(fmt||'');
  if(ua)args+=' --user-agent="'+ua+'"';
  if(proxy)args+=' --proxy='+proxy;
  if(extra)args+=' '+extra;
  var btn=document.getElementById('whatweb-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('whatweb');t.start();t.log('WhatWeb scanning: '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'whatweb',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'whatweb');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('WhatWeb done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WHATWEB';}
}

/* ── wapiti ─────────────────────────────────────────────────────────────── */
async function runWapiti(){
  var target=document.getElementById('wapiti-target').value.trim();
  if(!target){alert('Enter a target URL');return;}
  var modsEl=document.getElementById('wapiti-modules');
  var mods=Array.from(modsEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var depth=document.getElementById('wapiti-depth').value||'2';
  var scope=document.getElementById('wapiti-scope').value;
  var fmt=document.getElementById('wapiti-format').value||'json';
  var extra=document.getElementById('wapiti-extra').value.trim();
  var timeout=parseInt(document.getElementById('wapiti-timeout').value||'300',10);
  var args='-u "'+target+'" -m '+mods+' --depth '+depth+' --scope '+scope+' -f '+fmt;
  if(extra)args+=' '+extra;
  var btn=document.getElementById('wapiti-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('wapiti');t.start();t.log('Wapiti scanning: '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'wapiti',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'wapiti');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Wapiti done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WAPITI';}
}

/* ── dalfox ─────────────────────────────────────────────────────────────── */
async function runDalfox(){
  var target=document.getElementById('dalfox-target').value.trim();
  if(!target){alert('Enter a target URL');return;}
  var mode=document.getElementById('dalfox-mode').value||'url';
  var fmt=document.getElementById('dalfox-format').value||'--format json';
  var payload=document.getElementById('dalfox-payload').value.trim();
  var header=document.getElementById('dalfox-header').value.trim();
  var timeout=parseInt(document.getElementById('dalfox-timeout').value||'120',10);
  var blind=document.getElementById('dalfox-opt-blind').classList.contains('on');
  var skipbav=document.getElementById('dalfox-opt-skip-bav').classList.contains('on');
  var args=mode+' "'+target+'" '+fmt;
  if(payload)args+=' --custom-payload "'+payload+'"';
  if(header)args+=' -H "'+header+'"';
  if(blind)args+=' --blind';
  if(skipbav)args+=' --skip-bav';
  var btn=document.getElementById('dalfox-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('dalfox');t.start();t.log('Dalfox XSS scan: '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'dalfox',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'dalfox');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Dalfox done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No XSS found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN DALFOX';}
}

/* ── sqlmap ─────────────────────────────────────────────────────────────── */
async function runSqlmap(){
  var url=document.getElementById('sqlmap-url').value.trim();
  if(!url){alert('Enter a target URL');return;}
  var risk=document.getElementById('sqlmap-risk').value||'1';
  var level=document.getElementById('sqlmap-level').value||'1';
  var dbms=document.getElementById('sqlmap-dbms').value;
  var tech=document.getElementById('sqlmap-technique').value;
  var data=document.getElementById('sqlmap-data').value.trim();
  var cookie=document.getElementById('sqlmap-cookie').value.trim();
  var threads=document.getElementById('sqlmap-threads').value||'1';
  var timeout=parseInt(document.getElementById('sqlmap-timeout').value||'300',10);
  var batch=document.getElementById('sqlmap-batch').classList.contains('on');
  var dbs=document.getElementById('sqlmap-dbs').classList.contains('on');
  var tables=document.getElementById('sqlmap-tables').classList.contains('on');
  var dump=document.getElementById('sqlmap-dump').classList.contains('on');
  var randua=document.getElementById('sqlmap-random-agent').classList.contains('on');
  var args='-u "'+url+'" --risk='+risk+' --level='+level+' --threads='+threads;
  if(dbms)args+=' --dbms="'+dbms+'"';
  if(tech)args+=' --technique='+tech;
  if(data)args+=' --data="'+data+'"';
  if(cookie)args+=' --cookie="'+cookie+'"';
  if(batch)args+=' --batch';
  if(dbs)args+=' --dbs';
  if(tables)args+=' --tables';
  if(dump)args+=' --dump';
  if(randua)args+=' --random-agent';
  var btn=document.getElementById('sqlmap-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Testing...';
  var t=mkTool('sqlmap');t.start();t.log('SQLMap testing: '+url,'i');t.log('risk='+risk+' level='+level,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'sqlmap',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'sqlmap');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('SQLMap done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No SQL injection found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SQLMAP';}
}

/* ── kxss ───────────────────────────────────────────────────────────────── */
async function runKxss(){
  var urls=document.getElementById('kxss-urls').value.trim();
  if(!urls){alert('Enter at least one URL with parameters');return;}
  var header=document.getElementById('kxss-header').value.trim();
  var timeout=parseInt(document.getElementById('kxss-timeout').value||'60',10);
  var args='';
  if(header)args+='-H "'+header+'"';
  var btn=document.getElementById('kxss-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Checking...';
  var t=mkTool('kxss');t.start();t.log('kxss checking '+urls.split('\n').length+' URL(s)','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'kxss',operation:'custom',args:'<<< "'+urls.replace(/\n/g,'\\n')+'" '+args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'kxss');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('kxss done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No reflected XSS chars found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN KXSS';}
}

/* ── medusa ─────────────────────────────────────────────────────────────── */
async function runMedusa(){
  var host=document.getElementById('medusa-host').value.trim();
  if(!host){alert('Enter a target host');return;}
  var port=document.getElementById('medusa-port').value.trim();
  var module=document.getElementById('medusa-module').value||'ssh';
  var users=document.getElementById('medusa-users').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
  var passes=document.getElementById('medusa-passes').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
  var threads=document.getElementById('medusa-threads').value||'4';
  var retries=document.getElementById('medusa-retries').value||'3';
  var timeout=parseInt(document.getElementById('medusa-timeout').value||'120',10);
  var extra=document.getElementById('medusa-extra').value.trim();
  if(!users.length||!passes.length){alert('Enter at least one username and one password');return;}
  var args='-h '+host+' -M '+module+' -t '+threads+' -r '+retries;
  if(port)args+=' -n '+port;
  if(users.length===1)args+=' -u '+users[0]; else args+=' -U /tmp/medusa_users.txt';
  if(passes.length===1)args+=' -p '+passes[0]; else args+=' -P /tmp/medusa_pass.txt';
  if(extra)args+=' '+extra;
  var btn=document.getElementById('medusa-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Attacking...';
  var t=mkTool('medusa');t.start();t.log('Medusa '+module+' attack on '+host,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'medusa',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'medusa');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var found=(d.stdout||'').match(/ACCOUNT FOUND/gi)||[];
      t.log('Medusa done — '+found.length+' credential(s) found','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No valid credentials found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN MEDUSA';}
}

/* ── hping3 ─────────────────────────────────────────────────────────────── */
async function runHping3(){
  var host=document.getElementById('hping3-host').value.trim();
  if(!host){alert('Enter a target host');return;}
  var port=document.getElementById('hping3-port').value||'80';
  var mode=document.getElementById('hping3-mode').value||'-S';
  var count=document.getElementById('hping3-count').value||'5';
  var interval=document.getElementById('hping3-interval').value||'1000';
  var datasize=document.getElementById('hping3-data').value||'0';
  var timeout=parseInt(document.getElementById('hping3-timeout').value||'30',10);
  var verbose=document.getElementById('hping3-verbose').classList.contains('on');
  var flood=document.getElementById('hping3-flood').classList.contains('on');
  var fast=document.getElementById('hping3-fast').classList.contains('on');
  var args=mode+' -p '+port+' -c '+count+' -i u'+interval;
  if(datasize>0)args+=' -d '+datasize;
  if(verbose)args+=' -V';
  if(fast)args+=' --fast';
  if(flood)args+=' --flood';
  args+=' '+host;
  var btn=document.getElementById('hping3-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('hping3');t.start();t.log('hping3 '+mode+' -> '+host+':'+port,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hping3',operation:'custom',args:args,timeout:timeout})},Math.max(10000,timeout*1000+5000),'hping3');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('hping3 done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HPING3';}
}

/* ── hashcat ────────────────────────────────────────────────────────────── */
async function runHashcat(){
  var hashes=document.getElementById('hashcat-hashes').value.trim();
  if(!hashes){alert('Enter hashes or a file path');return;}
  var type=document.getElementById('hashcat-type').value||'0';
  var attack=document.getElementById('hashcat-attack').value||'0';
  var wordlist=document.getElementById('hashcat-wordlist').value.trim();
  var rules=document.getElementById('hashcat-rules').value.trim();
  var workload=document.getElementById('hashcat-workload').value||'2';
  var timeout=parseInt(document.getElementById('hashcat-timeout').value||'300',10);
  var args='-m '+type+' -a '+attack+' -w '+workload+' --status --status-timer=5 "'+hashes+'" "'+wordlist+'"';
  if(rules)args+=' -r '+rules;
  args+=' --force';
  var btn=document.getElementById('hashcat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('hashcat');t.start();t.log('Hashcat -m '+type+' -a '+attack,'i');t.log('Wordlist: '+wordlist,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hashcat',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'hashcat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var cracked=(d.stdout||'').match(/Recovered\.+:\s*\d+/i)||[];
      t.log('Hashcat done. '+(cracked[0]||'Check output.'),'s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HASHCAT';}
}

/* ── john ───────────────────────────────────────────────────────────────── */
async function runJohn(){
  var hashes=document.getElementById('john-hashes').value.trim();
  if(!hashes){alert('Enter a hash file path or paste hashes');return;}
  var mode=document.getElementById('john-mode').value||'--wordlist';
  var fmt=document.getElementById('john-format').value;
  var wl=document.getElementById('john-wordlist').value.trim();
  var rules=document.getElementById('john-rules').value;
  var timeout=parseInt(document.getElementById('john-timeout').value||'300',10);
  var args=mode;
  if(mode.includes('wordlist')&&wl)args+='='+wl;
  if(fmt)args+=' '+fmt;
  if(rules&&mode.includes('wordlist'))args+=' '+rules;
  args+=' "'+hashes+'"';
  var btn=document.getElementById('john-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('john');t.start();t.log('John the Ripper: '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'john',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'john');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('John done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN JOHN';}
}
async function runJohnShow(){
  var hashes=document.getElementById('john-hashes').value.trim();
  var fmt=document.getElementById('john-format').value;
  var args='--show '+(fmt||'')+' "'+hashes+'"';
  var t=mkTool('john');t.start();t.log('Showing cracked passwords...','i');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'john',operation:'custom',args:args,timeout:30})},40000,'john');
  var d=await r.json();t.end();
  t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono)">'+(d.stdout||'Nothing cracked yet.')+'</pre></div>');
}

/* ── searchsploit ───────────────────────────────────────────────────────── */
async function runSearchsploit(){
  var cve=document.getElementById('searchsploit-cve').value.trim();
  var query=cve?('--cve '+cve):document.getElementById('searchsploit-query').value.trim();
  if(!query){alert('Enter a search query or CVE');return;}
  var type=document.getElementById('searchsploit-type').value;
  var platform=document.getElementById('searchsploit-platform').value;
  var format=document.getElementById('searchsploit-format').value;
  var strict=document.getElementById('searchsploit-strict').classList.contains('on');
  var caseSens=document.getElementById('searchsploit-case').classList.contains('on');
  var args=query+(type?' '+type:'')+(platform?' '+platform:'')+(format?' '+format:'');
  if(strict)args+=' -w';
  if(caseSens)args+=' -c';
  var btn=document.getElementById('searchsploit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Searching...';
  var t=mkTool('searchsploit');t.start();t.log('Searching Exploit-DB: '+query,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'searchsploit',operation:'custom',args:args,timeout:60})},70000,'searchsploit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Search complete','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No exploits found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}

/* ── msfvenom ───────────────────────────────────────────────────────────── */
async function runMsfvenom(){
  var payloadSel=document.getElementById('msfvenom-payload').value;
  var customPayload=document.getElementById('msfvenom-custom-payload').value.trim();
  var payload=payloadSel==='custom'?customPayload:payloadSel;
  if(!payload){alert('Select or enter a payload');return;}
  var lhost=document.getElementById('msfvenom-lhost').value.trim();
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var format=document.getElementById('msfvenom-format').value||'exe';
  var encoder=document.getElementById('msfvenom-encoder').value;
  var iterations=document.getElementById('msfvenom-iterations').value||'1';
  var extra=document.getElementById('msfvenom-extra').value.trim();
  var timeout=parseInt(document.getElementById('msfvenom-timeout').value||'60',10);
  var args='-p '+payload;
  if(lhost)args+=' LHOST='+lhost;
  args+=' LPORT='+lport+' -f '+format;
  if(encoder)args+=' -e '+encoder+' -i '+iterations;
  if(extra)args+=' '+extra;
  args+=' --platform auto -o /tmp/msfvenom_payload.'+format;
  var btn=document.getElementById('msfvenom-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Generating...';
  var t=mkTool('msfvenom');t.start();t.log('Generating: '+payload,'i');t.log('Format: '+format+' | LHOST: '+lhost+' | LPORT: '+lport,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'msfvenom',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'msfvenom');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Payload generated (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Payload Generated</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Done')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}

/* ── grype ──────────────────────────────────────────────────────────────── */
async function runGrype(){
  var target=document.getElementById('grype-target').value.trim();
  if(!target){alert('Enter a container image or path');return;}
  var scope=document.getElementById('grype-scope').value;
  var severity=document.getElementById('grype-severity').value;
  var format=document.getElementById('grype-format').value||'table';
  var timeout=parseInt(document.getElementById('grype-timeout').value||'180',10);
  var onlyFixed=document.getElementById('grype-only-fixed').classList.contains('on');
  var update=document.getElementById('grype-update-db').classList.contains('on');
  var args='';
  if(update)args+='--update-db ';
  args+='"'+target+'" -o '+format;
  if(scope)args+=' --scope '+scope;
  if(severity)args+=' '+severity;
  if(onlyFixed)args+=' --only-fixed';
  var btn=document.getElementById('grype-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('grype');t.start();t.log('Grype scanning: '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'grype',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'grype');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Grype done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No vulnerabilities found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN GRYPE';}
}

/* ── radare2 ────────────────────────────────────────────────────────────── */
var _r2QuickCmds={
  info:'i\nil\niz\niS\nii\nie',
  functions:'aaa\nafl\naat\naxt',
  strings:'izz\niz\naav',
  imports:'ii\niE\nif',
  sections:'iS\niSS',
  entropy:'p=e 512\nafl~entropy'
};
function r2QuickLoad(preset){
  var el=document.getElementById('radare2-cmds');
  if(el&&_r2QuickCmds[preset])el.value=_r2QuickCmds[preset];
}
async function runRadare2(){
  var file=document.getElementById('radare2-file').value.trim();
  if(!file){alert('Enter a binary file path');return;}
  var cmds=document.getElementById('radare2-cmds').value.trim()||'i';
  var arch=document.getElementById('radare2-arch').value;
  var timeout=parseInt(document.getElementById('radare2-timeout').value||'60',10);
  var cmdline=cmds.split('\n').filter(Boolean).join(';');
  var args='-q '+(arch?arch+' ':'')+'-e log.level=0 -c "'+cmdline+'" -Q "'+file+'"';
  var btn=document.getElementById('radare2-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Analysing...';
  var t=mkTool('radare2');t.start();t.log('r2 '+file,'i');t.log('Commands: '+cmdline.substring(0,80),'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'radare2',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'radare2');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Analysis done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RADARE2';}
}

/* ── openvas ────────────────────────────────────────────────────────────── */
async function runOpenVAS(){
  var op=document.getElementById('openvas-op').value||'--version';
  var timeout=parseInt(document.getElementById('openvas-timeout').value||'60',10);
  var btn=document.getElementById('openvas-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('openvas');t.start();t.log('OpenVAS: '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'openvas',operation:'custom',args:op,timeout:timeout})},Math.max(20000,timeout*1000+5000),'openvas');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN OPENVAS CLI';}
}

/* ── chkrootkit ─────────────────────────────────────────────────────────── */
async function runChkrootkit(){
  var mode=document.getElementById('chkrootkit-mode').value;
  var test=document.getElementById('chkrootkit-test').value;
  var path=document.getElementById('chkrootkit-path').value.trim();
  var timeout=parseInt(document.getElementById('chkrootkit-timeout').value||'120',10);
  var args=mode;
  if(test)args+=' '+test;
  if(path)args+=' -r "'+path+'"';
  var btn=document.getElementById('chkrootkit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('chkrootkit');t.start();t.log('chkrootkit scan starting...','w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'chkrootkit',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'chkrootkit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var inf=(d.stdout||'').match(/INFECTED/gi)||[];
      t.log('Done - '+inf.length+' INFECTED marker(s)','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHKROOTKIT';}
}

/* ── rkhunter ───────────────────────────────────────────────────────────── */
async function runRkhunter(){
  var scantype=document.getElementById('rkhunter-scantype').value||'--check';
  var enable=document.getElementById('rkhunter-enable');
  var enableVals=Array.from(enable.selectedOptions).map(function(o){return o.value;});
  var timeout=parseInt(document.getElementById('rkhunter-timeout').value||'300',10);
  var skipkp=document.getElementById('rkhunter-skip-keypress').classList.contains('on');
  var nocolor=document.getElementById('rkhunter-nocolors').classList.contains('on');
  var appendLog=document.getElementById('rkhunter-append-log').classList.contains('on');
  var args=scantype;
  if(!enableVals.includes('all')&&enableVals.length)args+=' --enable '+enableVals.join(',');
  if(skipkp)args+=' --skip-keypress';
  if(nocolor)args+=' --nocolors';
  if(appendLog)args+=' --append-log';
  var btn=document.getElementById('rkhunter-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('rkhunter');t.start();t.log('rkhunter '+scantype,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'rkhunter',operation:'custom',args:args,timeout:timeout})},Math.max(120000,timeout*1000+5000),'rkhunter');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var warn=(d.stdout||'').match(/Warning:/gi)||[];
      t.log('Done - '+warn.length+' warning(s)','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RKHUNTER';}
}
async function runRkhunterUpdate(){
  var t=mkTool('rkhunter');t.start();t.log('Updating rkhunter database...','i');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'rkhunter',operation:'custom',args:'--update --skip-keypress --nocolors',timeout:120})},130000,'rkhunter');
  var d=await r.json();t.end();t.log(d.error||d.stdout||'Update done','s');
}

/* ── pspy ───────────────────────────────────────────────────────────────── */
async function runPspy(){
  var duration=document.getElementById('pspy-duration').value||'30';
  var interval=document.getElementById('pspy-interval').value||'100';
  var filter=document.getElementById('pspy-filter').value.trim();
  var fs=document.getElementById('pspy-fs').classList.contains('on');
  var timeout=parseInt(duration,10)+5;
  var args='';
  if(fs)args+='-f ';
  args+='-i '+interval+' -p';
  var btn=document.getElementById('pspy-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Monitoring...';
  var t=mkTool('pspy');t.start();t.log('pspy monitoring for '+duration+'s...','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'pspy',operation:'custom',args:args,timeout:parseInt(duration,10)})},Math.max(20000,timeout*1000+5000),'pspy');
    var d=await r.json();t.end();
    var output=d.stdout||'';
    if(filter)output=output.split('\n').filter(function(l){return new RegExp(filter,'i').test(l);}).join('\n');
    t.log('Done - '+(output.split('\n').filter(Boolean).length)+' line(s)','s');
    t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(output||'No processes captured.')+'</pre></div>');
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN PSPY';}
}

/* ── pwncat ─────────────────────────────────────────────────────────────── */
function pwncatModeChange(){
  var mode=document.getElementById('pwncat-mode').value;
  document.getElementById('pwncat-listen-fields').style.display=mode==='listen'?'block':'none';
  document.getElementById('pwncat-connect-fields').style.display=mode==='connect'?'block':'none';
  document.getElementById('pwncat-ssh-fields').style.display=mode==='ssh'?'block':'none';
}
async function runPwncat(){
  var mode=document.getElementById('pwncat-mode').value||'listen';
  var timeout=parseInt(document.getElementById('pwncat-timeout').value||'60',10);
  var args='';
  if(mode==='listen'){
    args='-lp '+document.getElementById('pwncat-lport').value+' --host '+document.getElementById('pwncat-lhost').value;
  }else if(mode==='connect'){
    args='--platform '+document.getElementById('pwncat-platform').value+' '+document.getElementById('pwncat-rhost').value+':'+document.getElementById('pwncat-rport').value;
  }else if(mode==='ssh'){
    var u=document.getElementById('pwncat-sshuser').value.trim();
    var p=document.getElementById('pwncat-sshpass').value.trim();
    args='ssh://'+u+(p?':'+p:'')+'@'+document.getElementById('pwncat-sshhost').value.trim()+':'+document.getElementById('pwncat-sshport').value;
  }else{
    args='--help';
  }
  var btn=document.getElementById('pwncat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('pwncat');t.start();t.log('pwncat '+mode+' mode','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'pwncat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'pwncat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('pwncat done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN PWNCAT';}
}

/* ── ligolo ─────────────────────────────────────────────────────────────── */
function ligoloComponentChange(){
  var comp=document.getElementById('ligolo-component').value;
  document.getElementById('ligolo-proxy-fields').style.display=comp==='proxy'?'block':'none';
  document.getElementById('ligolo-agent-fields').style.display=comp==='agent'?'block':'none';
}
async function runLigolo(){
  var comp=document.getElementById('ligolo-component').value||'proxy';
  var timeout=parseInt(document.getElementById('ligolo-timeout').value||'60',10);
  var args='';
  if(comp==='proxy'){
    var selfcert=document.getElementById('ligolo-selfcert').classList.contains('on');
    args='-laddr '+document.getElementById('ligolo-proxy-listen').value+' -tun '+document.getElementById('ligolo-tun').value;
    if(selfcert)args+=' -selfcert';
  }else if(comp==='agent'){
    var ignorecert=document.getElementById('ligolo-ignore-cert').classList.contains('on');
    args='-connect '+document.getElementById('ligolo-agent-proxy').value.trim();
    if(ignorecert)args+=' -ignore-cert';
  }else{
    args='--help';
  }
  var btn=document.getElementById('ligolo-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('ligolo');t.start();t.log('Ligolo-ng '+comp+' mode','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'ligolo-ng',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'ligolo');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN LIGOLO-NG';}
}

/* ── chisel ─────────────────────────────────────────────────────────────── */
function chiselModeChange(){
  var mode=document.getElementById('chisel-mode').value;
  document.getElementById('chisel-server-fields').style.display=mode==='server'?'block':'none';
  document.getElementById('chisel-client-fields').style.display=mode==='client'?'block':'none';
}
async function runChisel(){
  var mode=document.getElementById('chisel-mode').value||'server';
  var timeout=parseInt(document.getElementById('chisel-timeout').value||'60',10);
  var args=mode+' ';
  if(mode==='server'){
    var socks5=document.getElementById('chisel-socks5').classList.contains('on');
    var reverse=document.getElementById('chisel-reverse').classList.contains('on');
    var auth=document.getElementById('chisel-server-auth').value.trim();
    args+='--port='+document.getElementById('chisel-server-port').value;
    if(auth)args+=' --auth='+auth;
    if(socks5)args+=' --socks5';
    if(reverse)args+=' --reverse';
  }else if(mode==='client'){
    var cauth=document.getElementById('chisel-client-auth').value.trim();
    var tunnels=document.getElementById('chisel-tunnels').value.trim().split('\n').filter(Boolean).join(' ');
    args+=document.getElementById('chisel-server-url').value.trim()+' '+(tunnels||'socks');
    if(cauth)args+=' --auth='+cauth;
  }else{
    args='--help';
  }
  var btn=document.getElementById('chisel-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('chisel');t.start();t.log('Chisel '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'chisel',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'chisel');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHISEL';}
}

/* ── rlwrap ─────────────────────────────────────────────────────────────── */
async function runRlwrap(){
  var cmd=document.getElementById('rlwrap-cmd').value.trim();
  if(!cmd){alert('Enter a command to wrap');return;}
  var hist=document.getElementById('rlwrap-history').value||'1000';
  var wordchars=document.getElementById('rlwrap-wordchars').value||'a-zA-Z0-9_-';
  var timeout=parseInt(document.getElementById('rlwrap-timeout').value||'60',10);
  var ansi=document.getElementById('rlwrap-ansi').classList.contains('on');
  var noecho=document.getElementById('rlwrap-noecho').classList.contains('on');
  var args='-s '+hist+' -w "'+wordchars+'"';
  if(ansi)args+=' -A';
  if(noecho)args+=' -e';
  args+=' '+cmd;
  var btn=document.getElementById('rlwrap-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('rlwrap');t.start();t.log('rlwrap '+cmd,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'rlwrap',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'rlwrap');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RLWRAP';}
}

/* ── scapy ──────────────────────────────────────────────────────────────── */
var _scapyTemplates={
  ping:"from scapy.all import *\ntarget='192.168.1.1'\npkt=IP(dst=target)/ICMP()\nreply=sr1(pkt,timeout=2,verbose=0)\nif reply:\n    print(f'Up: {reply.summary()}')\nelse:\n    print('No response')",
  portscan:"from scapy.all import *\ntarget='192.168.1.1'\nports=[22,80,443,3306,8080]\nfor p in ports:\n    r=sr1(IP(dst=target)/TCP(dport=p,flags='S'),timeout=1,verbose=0)\n    if r and r[TCP].flags==0x12:\n        print(f'Port {p}: OPEN')",
  syn:"from scapy.all import *\ntarget='192.168.1.1'\nans,_=sr(IP(dst=target)/TCP(sport=RandShort(),dport=(1,1024),flags='S'),timeout=2,verbose=0)\nfor s,r in ans:\n    if r[TCP].flags==0x12:\n        print(f'Open: {s[TCP].dport}')",
  arpscan:"from scapy.all import *\nnet='192.168.1.0/24'\nans,_=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=net),timeout=3,verbose=0)\nfor s,r in ans:\n    print(f'{r[ARP].psrc}\t{r[Ether].src}')",
  traceroute:"from scapy.all import *\ntarget='8.8.8.8'\nfor ttl in range(1,30):\n    r=sr1(IP(dst=target,ttl=ttl)/UDP(dport=33434),timeout=1,verbose=0)\n    if not r: print(f'{ttl}: *'); continue\n    print(f'{ttl}: {r.src}')\n    if r.src==target: break"
};
function scapyTemplate(name){
  var el=document.getElementById('scapy-script');
  if(el&&_scapyTemplates[name])el.value=_scapyTemplates[name];
}
async function runScapy(){
  var script=document.getElementById('scapy-script').value.trim();
  if(!script){alert('Enter a Scapy script');return;}
  var timeout=parseInt(document.getElementById('scapy-timeout').value||'30',10);
  var btn=document.getElementById('scapy-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('scapy');t.start();t.log('Running Scapy script...','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'scapy',operation:'custom',args:'-c "'+script.replace(/"/g,'\\"')+'"',timeout:timeout})},Math.max(15000,timeout*1000+5000),'scapy');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Script done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SCAPY SCRIPT';}
}

/* ── yersinia ───────────────────────────────────────────────────────────── */
async function runYersinia(){
  var proto=document.getElementById('yersinia-proto').value||'stp';
  var iface=document.getElementById('yersinia-iface').value||'eth0';
  var action=document.getElementById('yersinia-action').value||'--help';
  var timeout=parseInt(document.getElementById('yersinia-timeout').value||'30',10);
  var args='-I '+iface+' '+action;
  var btn=document.getElementById('yersinia-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('yersinia');t.start();t.log('Yersinia '+proto+' on '+iface,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'yersinia',operation:'custom',args:args,timeout:timeout})},Math.max(10000,timeout*1000+5000),'yersinia');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN YERSINIA';}
}

/* ── seclists ───────────────────────────────────────────────────────────── */
async function runSeclists(){
  var path=document.getElementById('seclists-path').value.trim();
  var lines=document.getElementById('seclists-lines').value||'50';
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
      if(grep)words=words.filter(function(w){return new RegExp(grep,'i').test(w);});
      t.log('Loaded '+d.total_loaded+' entries (showing '+words.length+')','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:6px">'+path+' ('+d.total_loaded+' entries)</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+words.join('\n')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='BROWSE WORDLIST';}
}
async function seclistsCount(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path)return;
  var t=mkTool('seclists');t.start();
  var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=1',{},10000,'seclists');
  var d=await r.json();t.end();
  if(d.error)t.err(d.error);else t.log('File exists. '+d.total_loaded+' entries.','s');
}
function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}catch(e){}}
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
}

/* ── brute autoload helper ──────────────────────────────────────────────── */
function bfAutoLoad(){
  var um=document.getElementById('bf-user-mode');
  var pm=document.getElementById('bf-pass-mode');
  if(um&&um.value!=='manual')bfWordlistMode('user');
  if(pm&&pm.value!=='manual')bfWordlistMode('pass');
}

/* END TOOL-SPECIFIC JS HELPERS */
"""

# ══════════════════════════════════════════════════════════════════════════════
# The anchor we search for is the duplicate JS block that the first patch
# incorrectly inserted.  We'll replace the duplicated functions with our
# clean single copy, or — if the file is clean — just insert before loadUser().
# ══════════════════════════════════════════════════════════════════════════════

# Anchor 1: the broken duplicate block inserted by the first patch
OLD_BROKEN_ANCHOR = "/* ══ TOOL-SPECIFIC JS HELPERS ══════════════════════════════════ */"

# Anchor 2: the original inline functions (already in the file from the HTML blob)
# We look for the start of the original runFfuf / runNuclei section
OLD_INLINE_ANCHOR = "/* ffuf */\nasync function runFfuf() {"

# Anchor 3: safest fallback — just before loadUser() standalone call
LOADUSER_ANCHOR = "\nloadUser();\n"


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — Tool JS Patch v2 (fix broken patch)     ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET):
        fail(f"Must be run from project root — {TARGET} not found")
        sys.exit(1)

    info(f"Target: {TARGET}")

    with open(TARGET, "r", encoding="utf-8") as f:
        src = f.read()

    # ── Strategy: find the last </script> tag inside the HTML string ──────
    # The HTML is stored as a Python raw string assigned to HTML = r"""..."""
    # The JS we want to inject goes BEFORE the final </script></body></html>
    # closing sequence inside that string.

    # The closing sequence in the HTML blob
    CLOSING = "</script>\n</body>\n</html>"
    CLOSING2 = "</script>\\n</body>\\n</html>"   # escaped variant

    # Check which variant exists
    if CLOSING in src:
        anchor = CLOSING
        new_block = JS_HELPERS + "\n" + CLOSING
    elif CLOSING2 in src:
        anchor = CLOSING2
        new_block = JS_HELPERS + "\n" + CLOSING2
    else:
        # Try a looser match
        import re
        m = re.search(r'</script>\s*</body>\s*</html>', src)
        if m:
            anchor = m.group(0)
            new_block = JS_HELPERS + "\n" + anchor
        else:
            fail("Could not locate </script></body></html> anchor in api_server.py")
            fail("The HTML block structure may have changed.")
            sys.exit(1)

    # Count occurrences — we only want to patch once
    count = src.count(anchor)
    if count == 0:
        fail(f"Anchor '{anchor[:60]}...' not found!")
        sys.exit(1)
    if count > 1:
        warn(f"Anchor found {count} times — patching only the LAST occurrence")
        # Replace only last occurrence
        idx = src.rfind(anchor)
        modified = src[:idx] + new_block + src[idx + len(anchor):]
    else:
        modified = src.replace(anchor, new_block, 1)

    # ── Check if JS was already patched ───────────────────────────────────
    PATCH_MARKER = "/* ══ TOOL-SPECIFIC JS HELPERS (injected by patch_tool_pages_v2.py)"
    if PATCH_MARKER in src:
        warn("Patch marker already present — removing old injection first")
        # Remove everything from the marker to the anchor
        start_idx = src.find(PATCH_MARKER)
        end_idx   = src.find(anchor, start_idx)
        if end_idx != -1:
            modified = src[:start_idx] + src[end_idx:]
            # Now re-apply
            count2 = modified.count(anchor)
            if count2 > 1:
                idx2 = modified.rfind(anchor)
                modified = modified[:idx2] + new_block + modified[idx2 + len(anchor):]
            else:
                modified = modified.replace(anchor, new_block, 1)
            ok("Removed old injection, re-applying clean version")
        else:
            warn("Could not cleanly remove old injection — applying anyway")
            modified = src.replace(anchor, new_block, 1) if count == 1 else \
                       src[:src.rfind(anchor)] + new_block + src[src.rfind(anchor)+len(anchor):]

    hdr("Writing patched file")
    backup(TARGET)
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(modified)
    ok("File written")

    hdr("Syntax check")
    passed, err = syntax_check(TARGET)
    if passed:
        ok(f"{TARGET} — Python syntax OK")
    else:
        fail(f"SYNTAX ERROR:\n{err}")
        # Restore from backup
        import glob
        baks = sorted(glob.glob(f"{TARGET}.*.bak"))
        if baks:
            latest = baks[-1]
            shutil.copy2(latest, TARGET)
            warn(f"Restored from backup: {latest}")
        sys.exit(1)

    print()
    print(B + C + "══════════════════════════════════════════════════════════" + X)
    print(f"  {G}Patch applied successfully!{X}")
    print()
    print(f"  {Y}Restart the server:{X}")
    print(f"    pkill -f api_server.py && python3 api_server.py")
    print()


if __name__ == "__main__":
    main()
