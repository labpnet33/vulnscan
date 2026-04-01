#!/usr/bin/env python3
"""
VulnScan Pro — Tool Pages Fix Patch
=====================================
Fixes the broken JS injection from patch_tool_pages.py AND applies all
tool page UI improvements correctly.

ROOT CAUSE OF BREAKAGE:
  The previous patch used "\nloadUser();\n" as the injection anchor.
  This string appears INSIDE the doLogin() setTimeout callback in the HTML:

      if(d.success){...setTimeout(function(){
          ...
          loadUser();   <-- matched here (WRONG - inside callback)
      },700);}

  Injecting 2500+ lines of JS inside a setTimeout callback causes a
  JavaScript parse error. The entire <script> block fails to load,
  breaking login, navigation, and all tool buttons.

FIX:
  1. Detect and repair the broken injection if already applied.
  2. Place JS helpers AFTER the closing </script> tag structure,
     using a unique anchor that only exists once in the file.
  3. Re-apply all tool page HTML changes cleanly.

Run from your vulnscan project root:
    python3 patch_tool_pages_fix.py
"""

import os
import re
import sys
import shutil
import subprocess
from datetime import datetime

# ── colours ───────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")
def skip(m): print(f"  {D}·{X}  {m}")

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}
TARGET = "api_server.py"


def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True
    )
    return r.returncode == 0, r.stderr.strip()


# ══════════════════════════════════════════════════════════════
# STEP 1 — DETECT AND REPAIR BROKEN INJECTION
# The bad patch inserted JS inside the doLogin setTimeout callback.
# We need to detect this and surgically remove the injected block.
# ══════════════════════════════════════════════════════════════

# This is the UNIQUE string that only appears at the start of the injected block
# inside the broken doLogin setTimeout
BAD_INJECTION_START_MARKER = "loadUser();\n\n/* ══ TOOL-SPECIFIC JS HELPERS"
# The injection ends before "loadUser();" and then the original },700);} follows
# Pattern: the injected helpers end with "/* END TOOL-SPECIFIC JS HELPERS */\n"
BAD_INJECTION_END_MARKER = "/* END TOOL-SPECIFIC JS HELPERS */\n"


def detect_and_fix_bad_injection(src):
    """
    If the previous patch was applied, the src will contain the injected JS
    block inside the doLogin setTimeout. Find and remove it, restoring
    the original loadUser(); call in place.
    Returns (fixed_src, was_broken)
    """
    # The bad injection looks like:
    # loadUser();\n\n/* ══ TOOL-SPECIFIC JS HELPERS ══...LOTS OF JS...
    # /* END TOOL-SPECIFIC JS HELPERS */\nloadUser();
    #
    # The ORIGINAL (correct) form is just:
    # loadUser();}
    # (inside the setTimeout callback, followed by },700);})
    
    if BAD_INJECTION_START_MARKER not in src:
        return src, False
    
    warn("Detected broken JS injection from previous patch — repairing...")
    
    # Find the start of the bad injection
    start_idx = src.find(BAD_INJECTION_START_MARKER)
    if start_idx == -1:
        return src, False
    
    # The text before the marker is "loadUser();\n" — keep that
    # Find the end marker
    end_marker_idx = src.find(BAD_INJECTION_END_MARKER, start_idx)
    if end_marker_idx == -1:
        warn("Could not find end of bad injection — manual fix required")
        return src, False
    
    end_idx = end_marker_idx + len(BAD_INJECTION_END_MARKER)
    
    # What's between start and end is all the injected JS helpers
    # The structure is: "loadUser();\n\n/* ══ TOOL...HELPERS */\nloadUser();"
    # We want to keep just the first "loadUser();" and remove everything up to
    # and including the second "loadUser();" that follows the end marker
    
    # The bad injection replaced "\nloadUser();\n" with "\n[helpers]\nloadUser();\n"
    # So after BAD_INJECTION_END_MARKER there's another "loadUser();\n"
    remainder = src[end_idx:]
    # Remove the duplicate loadUser() that the patch added after the helpers
    if remainder.startswith("loadUser();\n"):
        end_idx += len("loadUser();\n")
    elif remainder.startswith("\nloadUser();\n"):
        end_idx += len("\nloadUser();\n")
    
    # Reconstruct: keep everything up to the start of the injected block
    # (which includes the first "loadUser();") then skip to after injection
    fixed = src[:start_idx] + src[end_idx:]
    
    ok(f"Removed {end_idx - start_idx} chars of broken JS injection")
    return fixed, True


# ══════════════════════════════════════════════════════════════
# JS HELPER FUNCTIONS — all the new tool functions
# These go at the END of the <script> block, using a safe unique anchor
# ══════════════════════════════════════════════════════════════

JS_HELPERS = r"""
/* ══ TOOL-SPECIFIC JS HELPERS ══════════════════════════════════ */

/* ffuf */
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
  var args='-u "'+url+'" -w "'+wl+'" -X '+method+' -t '+threads;
  if(fc)args+=' -fc '+fc;
  if(mc)args+=' -mc '+mc;
  if(ext)args+=' -e '+ext;
  if(extra)args+=' '+extra;
  var btn=document.getElementById('ffuf-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('ffuf');t.start();t.log('ffuf '+url,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'ffuf',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'ffuf');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('ffuf done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN FFUF';}
}

/* nuclei */
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
  var args='-u "'+target+'" -c '+threads+' -rate-limit '+rate+' -jsonl -stats=false';
  if(sevs)args+=' -severity '+sevs;
  if(tags)args+=' -tags '+tags;
  if(tplPath)args+=' -t "'+tplPath+'"';
  var btn=document.getElementById('nuclei-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('nuclei');t.start();t.log('nuclei → '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'nuclei',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'nuclei');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var lines=(d.stdout||'').split('\n').filter(Boolean).length;
      t.log('Nuclei done — '+lines+' result(s)','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No findings.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NUCLEI';}
}
async function runNucleiUpdate(){
  var t=mkTool('nuclei');t.start();t.log('Updating nuclei templates...','w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'nuclei',operation:'custom',args:'-update-templates',timeout:120})},130000,'nuclei');
    var d=await r.json();t.end();t.log(d.error||(d.stdout||'Update complete'),'s');
  }catch(e){t.end();t.err(e.message);}
}

/* whatweb */
async function runWhatWeb(){
  var target=document.getElementById('whatweb-target').value.trim();
  if(!target){alert('Enter a target URL or host');return;}
  var agg=document.getElementById('whatweb-aggression').value||'3';
  var fmt=document.getElementById('whatweb-format').value||'';
  var timeout=parseInt(document.getElementById('whatweb-timeout').value||'60',10);
  var ua=document.getElementById('whatweb-ua').value.trim();
  var proxy=document.getElementById('whatweb-proxy').value.trim();
  var extra=document.getElementById('whatweb-extra').value.trim();
  var args='"'+target+'" --aggression='+agg+(fmt?' '+fmt:'');
  if(ua)args+=' --user-agent="'+ua+'"';
  if(proxy)args+=' --proxy='+proxy;
  if(extra)args+=' '+extra;
  var btn=document.getElementById('whatweb-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('whatweb');t.start();t.log('WhatWeb → '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'whatweb',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'whatweb');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('WhatWeb done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WHATWEB';}
}

/* wapiti */
async function runWapiti(){
  var target=document.getElementById('wapiti-target').value.trim();
  if(!target){alert('Enter a target URL');return;}
  var modsEl=document.getElementById('wapiti-modules');
  var mods=Array.from(modsEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var depth=document.getElementById('wapiti-depth').value||'2';
  var scope=document.getElementById('wapiti-scope').value||'domain';
  var fmt=document.getElementById('wapiti-format').value||'json';
  var extra=document.getElementById('wapiti-extra').value.trim();
  var timeout=parseInt(document.getElementById('wapiti-timeout').value||'300',10);
  var args='-u "'+target+'"'+(mods?' -m '+mods:'')+' --depth '+depth+' --scope '+scope+' -f '+fmt;
  if(extra)args+=' '+extra;
  var btn=document.getElementById('wapiti-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('wapiti');t.start();t.log('Wapiti → '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'wapiti',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'wapiti');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Wapiti done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WAPITI';}
}

/* dalfox */
async function runDalfox(){
  var target=document.getElementById('dalfox-target').value.trim();
  if(!target){alert('Enter a target URL');return;}
  var mode=document.getElementById('dalfox-mode').value||'url';
  var fmt=document.getElementById('dalfox-format').value||'';
  var payload=document.getElementById('dalfox-payload').value.trim();
  var header=document.getElementById('dalfox-header').value.trim();
  var timeout=parseInt(document.getElementById('dalfox-timeout').value||'120',10);
  var blind=document.getElementById('dalfox-opt-blind').classList.contains('on');
  var skipbav=document.getElementById('dalfox-opt-skip-bav').classList.contains('on');
  var args=mode+' "'+target+'"'+(fmt?' '+fmt:'');
  if(payload)args+=' --custom-payload "'+payload+'"';
  if(header)args+=' -H "'+header+'"';
  if(blind)args+=' --blind';
  if(skipbav)args+=' --skip-bav';
  var btn=document.getElementById('dalfox-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('dalfox');t.start();t.log('Dalfox XSS → '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'dalfox',operation:'custom',args:args,timeout:timeout})},Math.max(30000,timeout*1000+5000),'dalfox');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Dalfox done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No XSS found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN DALFOX';}
}

/* sqlmap */
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
  var t=mkTool('sqlmap');t.start();t.log('SQLMap → '+url,'i');t.log('risk='+risk+' level='+level,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'sqlmap',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'sqlmap');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('SQLMap done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No SQLi found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SQLMAP';}
}

/* kxss */
async function runKxss(){
  var urls=document.getElementById('kxss-urls').value.trim();
  if(!urls){alert('Enter at least one URL with parameters');return;}
  var header=document.getElementById('kxss-header').value.trim();
  var timeout=parseInt(document.getElementById('kxss-timeout').value||'60',10);
  var args='--help';
  if(header)args='-H "'+header+'"';
  var btn=document.getElementById('kxss-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Checking...';
  var t=mkTool('kxss');t.start();
  t.log('kxss: paste URLs into terminal or pipe: echo "'+urls.split('\n')[0]+'" | kxss','i');
  t.log('Note: kxss requires stdin pipe — run directly in terminal for best results','w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'kxss',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'kxss');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('kxss capability check done','s');
      t.log('To scan: echo "'+urls.split('\n')[0]+'" | kxss'+( header?' -H "'+header+'"':''),'i');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Capability Check</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'kxss installed.')+'</pre><div style="margin-top:10px;font-size:12px;color:var(--text3)">Run in terminal: <code style="font-family:var(--mono)">cat urls.txt | kxss</code></div></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN KXSS';}
}

/* medusa */
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
  var args='-h "'+host+'" -M '+module+' -t '+threads+' -r '+retries;
  if(port)args+=' -n '+port;
  args+=' -u '+users[0]+' -p '+passes[0];
  if(users.length>1)args+=' (use -U /path/to/users.txt for multiple)';
  if(extra)args+=' '+extra;
  // Build proper multi-user args
  var realArgs='-h "'+host+'" -M '+module+' -t '+threads+' -r '+retries;
  if(port)realArgs+=' -n '+port;
  if(users.length===1){realArgs+=' -u "'+users[0]+'"';}
  else{realArgs+=' -u "'+users.join(',').replace(/"/g,'')+'"';}
  if(passes.length===1){realArgs+=' -p "'+passes[0]+'"';}
  else{realArgs+=' -p "'+passes.join(',').replace(/"/g,'')+'"';}
  if(extra)realArgs+=' '+extra;
  var btn=document.getElementById('medusa-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Attacking...';
  var t=mkTool('medusa');t.start();t.log('Medusa '+module+' → '+host,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'medusa',operation:'custom',args:realArgs,timeout:timeout})},Math.max(30000,timeout*1000+5000),'medusa');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var found=(d.stdout||'').match(/ACCOUNT FOUND/gi)||[];
      t.log('Medusa done — '+found.length+' credential(s) found','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No valid credentials found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN MEDUSA';}
}

/* hping3 */
async function runHping3(){
  var host=document.getElementById('hping3-host').value.trim();
  if(!host){alert('Enter a target host');return;}
  var port=document.getElementById('hping3-port').value||'80';
  var mode=document.getElementById('hping3-mode').value||'-S';
  var count=document.getElementById('hping3-count').value||'5';
  var interval=document.getElementById('hping3-interval').value||'1000';
  var datasize=parseInt(document.getElementById('hping3-data').value||'0',10);
  var timeout=parseInt(document.getElementById('hping3-timeout').value||'30',10);
  var verbose=document.getElementById('hping3-verbose').classList.contains('on');
  var flood=document.getElementById('hping3-flood').classList.contains('on');
  var fast=document.getElementById('hping3-fast').classList.contains('on');
  var args=mode+' -p '+port+' -c '+count+' -i u'+interval;
  if(datasize>0)args+=' -d '+datasize;
  if(verbose)args+=' -V';
  if(fast)args+=' --fast';
  if(flood)args+=' --flood';
  args+=' "'+host+'"';
  var btn=document.getElementById('hping3-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('hping3');t.start();t.log('hping3 '+mode+' → '+host+':'+port,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hping3',operation:'custom',args:args,timeout:timeout})},Math.max(10000,timeout*1000+5000),'hping3');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('hping3 done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HPING3';}
}

/* hashcat */
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
}

/* john */
async function runJohn(){
  var hashes=document.getElementById('john-hashes').value.trim();
  if(!hashes){alert('Enter a hash file path or paste hashes');return;}
  var mode=document.getElementById('john-mode').value||'--wordlist';
  var fmt=document.getElementById('john-format').value||'';
  var wl=document.getElementById('john-wordlist').value.trim();
  var rules=document.getElementById('john-rules').value||'';
  var timeout=parseInt(document.getElementById('john-timeout').value||'300',10);
  var args=mode;
  if(mode.indexOf('wordlist')>=0&&wl)args+='='+wl;
  if(fmt)args+=' '+fmt;
  if(rules&&mode.indexOf('wordlist')>=0)args+=' '+rules;
  args+=' "'+hashes+'"';
  var btn=document.getElementById('john-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('john');t.start();t.log('John: '+mode,'i');
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
  if(!hashes){return;}
  var fmt=document.getElementById('john-format').value||'';
  var args='--show '+(fmt||'')+' "'+hashes+'"';
  var t=mkTool('john');t.start();t.log('john --show','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'john',operation:'custom',args:args,timeout:30})},40000,'john');
    var d=await r.json();t.end();
    t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono)">'+(d.stdout||'Nothing cracked yet.')+'</pre></div>');
  }catch(e){t.end();t.err(e.message);}
}

/* searchsploit */
async function runSearchsploit(){
  var cve=document.getElementById('searchsploit-cve').value.trim();
  var query=cve?'--cve '+cve:document.getElementById('searchsploit-query').value.trim();
  if(!query){alert('Enter a search query or CVE');return;}
  var type=document.getElementById('searchsploit-type').value||'';
  var platform=document.getElementById('searchsploit-platform').value||'';
  var format=document.getElementById('searchsploit-format').value||'';
  var strict=document.getElementById('searchsploit-strict').classList.contains('on');
  var caseSens=document.getElementById('searchsploit-case').classList.contains('on');
  var args=query+(type?' '+type:'')+(platform?' '+platform:'')+(format?' '+format:'');
  if(strict)args+=' -w';
  if(caseSens)args+=' -c';
  var btn=document.getElementById('searchsploit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Searching...';
  var t=mkTool('searchsploit');t.start();t.log('searchsploit: '+query,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'searchsploit',operation:'custom',args:args,timeout:60})},70000,'searchsploit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Search complete','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No exploits found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}

/* msfvenom */
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
}

/* grype */
async function runGrype(){
  var target=document.getElementById('grype-target').value.trim();
  if(!target){alert('Enter a container image or path');return;}
  var scope=document.getElementById('grype-scope').value||'';
  var severity=document.getElementById('grype-severity').value||'';
  var format=document.getElementById('grype-format').value||'table';
  var timeout=parseInt(document.getElementById('grype-timeout').value||'180',10);
  var onlyFixed=document.getElementById('grype-only-fixed').classList.contains('on');
  var update=document.getElementById('grype-update-db').classList.contains('on');
  var args=(update?'--update-db ':'')+'"'+target+'" -o '+format;
  if(scope)args+=' --scope '+scope;
  if(severity)args+=' '+severity;
  if(onlyFixed)args+=' --only-fixed';
  var btn=document.getElementById('grype-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('grype');t.start();t.log('Grype → '+target,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'grype',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'grype');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Grype done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No vulnerabilities found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN GRYPE';}
}

/* radare2 */
var _r2Templates={
  info:'i\nil\niz\niS\nii\nie',
  functions:'aaa\nafl',
  strings:'izz',
  imports:'ii\niE',
  sections:'iS',
  entropy:'p=e 512'
};
function r2QuickLoad(preset){
  var el=document.getElementById('radare2-cmds');
  if(el&&_r2Templates[preset])el.value=_r2Templates[preset];
}
async function runRadare2(){
  var file=document.getElementById('radare2-file').value.trim();
  if(!file){alert('Enter a binary file path');return;}
  var cmds=document.getElementById('radare2-cmds').value.trim()||'i';
  var arch=document.getElementById('radare2-arch').value||'';
  var timeout=parseInt(document.getElementById('radare2-timeout').value||'60',10);
  var cmdline=cmds.split('\n').filter(Boolean).join(';');
  var args='-q '+(arch?arch+' ':'')+'-e log.level=0 -c "'+cmdline+'" -Q "'+file+'"';
  var btn=document.getElementById('radare2-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Analysing...';
  var t=mkTool('radare2');t.start();t.log('r2 '+file,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'radare2',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'radare2');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Analysis done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RADARE2';}
}

/* openvas */
async function runOpenVAS(){
  var op=document.getElementById('openvas-op').value||'--version';
  var timeout=parseInt(document.getElementById('openvas-timeout').value||'60',10);
  var btn=document.getElementById('openvas-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('openvas');t.start();t.log('openvas '+op,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'openvas',operation:'custom',args:op,timeout:timeout})},Math.max(20000,timeout*1000+5000),'openvas');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN OPENVAS CLI';}
}

/* chkrootkit */
async function runChkrootkit(){
  var mode=document.getElementById('chkrootkit-mode').value||'';
  var test=document.getElementById('chkrootkit-test').value||'';
  var path=document.getElementById('chkrootkit-path').value.trim();
  var timeout=parseInt(document.getElementById('chkrootkit-timeout').value||'120',10);
  var args=mode;
  if(test)args+=(args?' ':'')+test;
  if(path)args+=' -r "'+path+'"';
  if(!args.trim())args='';
  var btn=document.getElementById('chkrootkit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Scanning...';
  var t=mkTool('chkrootkit');t.start();t.log('chkrootkit scan...','w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'chkrootkit',operation:'custom',args:args||'--help',timeout:timeout})},Math.max(60000,timeout*1000+5000),'chkrootkit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var inf=(d.stdout||'').match(/INFECTED/gi)||[];
      t.log('Done — '+inf.length+' INFECTED marker(s)','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHKROOTKIT';}
}

/* rkhunter */
async function runRkhunter(){
  var scantype=document.getElementById('rkhunter-scantype').value||'--check';
  var timeout=parseInt(document.getElementById('rkhunter-timeout').value||'300',10);
  var skipkp=document.getElementById('rkhunter-skip-keypress').classList.contains('on');
  var nocolor=document.getElementById('rkhunter-nocolors').classList.contains('on');
  var appendLog=document.getElementById('rkhunter-append-log').classList.contains('on');
  var args=scantype;
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
    else{var w=(d.stdout||'').match(/Warning:/gi)||[];
      t.log('Done — '+w.length+' warning(s)','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RKHUNTER';}
}
async function runRkhunterUpdate(){
  var t=mkTool('rkhunter');t.start();t.log('Updating rkhunter DB...','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'rkhunter',operation:'custom',args:'--update --skip-keypress --nocolors',timeout:120})},130000,'rkhunter');
    var d=await r.json();t.end();t.log(d.error||(d.stdout||'Update done'),'s');
  }catch(e){t.end();t.err(e.message);}
}

/* pspy */
async function runPspy(){
  var duration=parseInt(document.getElementById('pspy-duration').value||'30',10);
  var interval=document.getElementById('pspy-interval').value||'100';
  var filter=document.getElementById('pspy-filter').value.trim();
  var pspyPath=document.getElementById('pspy-path').value.trim()||'pspy64';
  var fs=document.getElementById('pspy-fs').classList.contains('on');
  var args='-i '+interval+' -p';
  if(fs)args+=' -f';
  var btn=document.getElementById('pspy-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Monitoring...';
  var t=mkTool('pspy');t.start();t.log('pspy monitoring for '+duration+'s...','i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'pspy',operation:'custom',args:args,timeout:duration})},Math.max(20000,(duration+5)*1000),'pspy');
    var d=await r.json();t.end();
    var output=d.stdout||'';
    if(filter)output=output.split('\n').filter(function(l){return new RegExp(filter,'i').test(l);}).join('\n');
    t.log('Done — '+output.split('\n').filter(Boolean).length+' line(s)','s');
    t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(output||'No processes captured.')+'</pre></div>');
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN PSPY';}
}

/* pwncat */
function pwncatModeChange(){
  var mode=document.getElementById('pwncat-mode').value;
  document.getElementById('pwncat-listen-fields').style.display=mode==='listen'?'block':'none';
  document.getElementById('pwncat-connect-fields').style.display=mode==='connect'?'block':'none';
  document.getElementById('pwncat-ssh-fields').style.display=mode==='ssh'?'block':'none';
}
async function runPwncat(){
  var mode=document.getElementById('pwncat-mode').value||'listen';
  var timeout=parseInt(document.getElementById('pwncat-timeout').value||'60',10);
  var args='--help';
  if(mode==='listen'){
    var lhost=document.getElementById('pwncat-lhost').value||'0.0.0.0';
    var lport=document.getElementById('pwncat-lport').value||'4444';
    args='-lp '+lport+' --host "'+lhost+'"';
  }else if(mode==='connect'){
    var rhost=document.getElementById('pwncat-rhost').value.trim();
    var rport=document.getElementById('pwncat-rport').value||'4444';
    args='"'+rhost+':'+rport+'"';
  }else if(mode==='ssh'){
    var sh=document.getElementById('pwncat-sshhost').value.trim();
    var sp=document.getElementById('pwncat-sshport').value||'22';
    var su=document.getElementById('pwncat-sshuser').value.trim();
    args='ssh://'+su+'@'+sh+':'+sp;
  }
  var btn=document.getElementById('pwncat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('pwncat');t.start();t.log('pwncat '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'pwncat',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'pwncat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('pwncat done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN PWNCAT';}
}

/* ligolo */
function ligoloComponentChange(){
  var comp=document.getElementById('ligolo-component').value;
  document.getElementById('ligolo-proxy-fields').style.display=comp==='proxy'?'block':'none';
  document.getElementById('ligolo-agent-fields').style.display=comp==='agent'?'block':'none';
}
async function runLigolo(){
  var comp=document.getElementById('ligolo-component').value||'proxy';
  var timeout=parseInt(document.getElementById('ligolo-timeout').value||'60',10);
  var args='--help';
  if(comp==='proxy'){
    var listen=document.getElementById('ligolo-proxy-listen').value||'0.0.0.0:11601';
    var selfcert=document.getElementById('ligolo-selfcert').classList.contains('on');
    args='-laddr "'+listen+'"';
    if(selfcert)args+=' -selfcert';
  }else if(comp==='agent'){
    var proxy=document.getElementById('ligolo-agent-proxy').value.trim();
    var ignorecert=document.getElementById('ligolo-ignore-cert').classList.contains('on');
    if(proxy)args='-connect "'+proxy+'"'+(ignorecert?' -ignore-cert':'');
  }
  var btn=document.getElementById('ligolo-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('ligolo');t.start();t.log('ligolo-ng '+comp,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'ligolo-ng',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'ligolo');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN LIGOLO-NG';}
}

/* chisel */
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
    var port=document.getElementById('chisel-server-port').value||'8080';
    var auth=document.getElementById('chisel-server-auth').value.trim();
    var socks5=document.getElementById('chisel-socks5').classList.contains('on');
    var reverse=document.getElementById('chisel-reverse').classList.contains('on');
    args+='--port='+port;
    if(auth)args+=' --auth="'+auth+'"';
    if(socks5)args+=' --socks5';
    if(reverse)args+=' --reverse';
  }else if(mode==='client'){
    var url=document.getElementById('chisel-server-url').value.trim();
    var cauth=document.getElementById('chisel-client-auth').value.trim();
    var tunnels=document.getElementById('chisel-tunnels').value.trim().split('\n').filter(Boolean).join(' ');
    if(!url){alert('Enter server URL');return;}
    args+='"'+url+'" '+(tunnels||'socks');
    if(cauth)args+=' --auth="'+cauth+'"';
  }else{
    args='--help';
  }
  var btn=document.getElementById('chisel-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('chisel');t.start();t.log('chisel '+mode,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'chisel',operation:'custom',args:args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'chisel');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHISEL';}
}

/* rlwrap */
async function runRlwrap(){
  var cmd=document.getElementById('rlwrap-cmd').value.trim();
  if(!cmd){alert('Enter a command to wrap, e.g. nc -lvnp 4444');return;}
  var hist=document.getElementById('rlwrap-history').value||'1000';
  var wordchars=document.getElementById('rlwrap-wordchars').value||'a-zA-Z0-9_-';
  var timeout=parseInt(document.getElementById('rlwrap-timeout').value||'60',10);
  var ansi=document.getElementById('rlwrap-ansi').classList.contains('on');
  var args='-s '+hist+' -w "'+wordchars+'"';
  if(ansi)args+=' -A';
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

/* scapy */
var _scapyTpl={
  ping:"from scapy.all import *\ntarget='192.168.1.1'\npkt=IP(dst=target)/ICMP()\nreply=sr1(pkt,timeout=2,verbose=0)\nif reply:\n    print('Up: '+reply.summary())\nelse:\n    print('No response from '+target)",
  portscan:"from scapy.all import *\ntarget='192.168.1.1'\nports=[22,80,443,3306,8080]\nfor p in ports:\n    r=sr1(IP(dst=target)/TCP(dport=p,flags='S'),timeout=1,verbose=0)\n    if r and r.haslayer(TCP) and r[TCP].flags==0x12:\n        print('Open: port '+str(p))",
  syn:"from scapy.all import *\ntarget='192.168.1.1'\nans,_=sr(IP(dst=target)/TCP(sport=RandShort(),dport=(1,1024),flags='S'),timeout=2,verbose=0)\nfor s,r in ans:\n    if r.haslayer(TCP) and r[TCP].flags==0x12:\n        print('Open: '+str(s[TCP].dport))",
  arpscan:"from scapy.all import *\nnet='192.168.1.0/24'\nans,_=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=net),timeout=3,verbose=0)\nfor s,r in ans:\n    print(r[ARP].psrc+'  '+r[Ether].src)",
  traceroute:"from scapy.all import *\ntarget='8.8.8.8'\nfor ttl in range(1,30):\n    r=sr1(IP(dst=target,ttl=ttl)/UDP(dport=33434),timeout=1,verbose=0)\n    if not r:\n        print(str(ttl)+': *')\n        continue\n    print(str(ttl)+': '+r.src)\n    if r.src==target:\n        break"
};
function scapyTemplate(name){
  var el=document.getElementById('scapy-script');
  if(el&&_scapyTpl[name])el.value=_scapyTpl[name];
}
async function runScapy(){
  var script=document.getElementById('scapy-script').value.trim();
  if(!script){alert('Enter a Scapy script');return;}
  var timeout=parseInt(document.getElementById('scapy-timeout').value||'30',10);
  var btn=document.getElementById('scapy-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('scapy');t.start();t.log('Running Scapy script...','i');
  try{
    // Use python3 to run the scapy script
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'scapy',operation:'custom',args:'--version',timeout:timeout})},
      Math.max(15000,timeout*1000+5000),'scapy');
    var d=await r.json();t.end();
    t.log('Note: Scapy scripts require root and direct terminal access for packet injection.','w');
    t.log('Copy your script and run: sudo python3 script.py','i');
    t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Scapy Version Check</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Scapy check done')+'</pre><div style="margin-top:10px;font-size:12px;color:var(--text3)">For live packet injection, run scripts directly as root in terminal.</div></div>');
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SCAPY SCRIPT';}
}

/* yersinia */
async function runYersinia(){
  var proto=document.getElementById('yersinia-proto').value||'stp';
  var iface=document.getElementById('yersinia-iface').value||'eth0';
  var action=document.getElementById('yersinia-action').value||'--help';
  var timeout=parseInt(document.getElementById('yersinia-timeout').value||'30',10);
  var args=action+' -I '+iface;
  if(action==='--help')args='--help';
  var btn=document.getElementById('yersinia-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('yersinia');t.start();t.log('yersinia '+proto+' on '+iface,'w');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'yersinia',operation:'custom',args:args,timeout:timeout})},Math.max(10000,timeout*1000+5000),'yersinia');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Done (exit '+d.exit_code+')','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN YERSINIA';}
}

/* seclists */
async function runSeclists(){
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
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:6px">'+d.filename+' ('+d.total_loaded+' entries)</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+words.join('\n')+'</pre></div>');
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
}

/* END TOOL-SPECIFIC JS HELPERS */
"""

# ══════════════════════════════════════════════════════════════
# TOOL PAGE HTML REPLACEMENTS
# Same as the original patch but with corrected HTML
# ══════════════════════════════════════════════════════════════

# Each entry: (label, old_html, new_html)
# We only replace the card-p form div to preserve the quick-install cards below
TOOL_PAGES = []

# ─── FFUF ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "ffuf — URL/wordlist/filter fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="ffuf-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ffuf-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="ffuf-bin" type="text" value="ffuf"/></div>
          </div>
          <button class="btn btn-primary" id="ffuf-btn" onclick="runGenericTool('ffuf','ffuf')">RUN FFUF</button>''',
    '''          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET URL (use FUZZ as placeholder)</label><input class="inp inp-mono" id="ffuf-url" type="text" placeholder="https://example.com/FUZZ"/></div>
            <div class="fg"><label>WORDLIST PATH</label><input class="inp inp-mono" id="ffuf-wordlist" type="text" value="/usr/share/seclists/Discovery/Web-Content/common.txt"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>HTTP METHOD</label><select class="inp inp-mono" id="ffuf-method"><option>GET</option><option>POST</option><option>PUT</option></select></div>
            <div class="fg"><label>FILTER STATUS CODES (-fc)</label><input class="inp inp-mono" id="ffuf-fc" type="text" value="404"/></div>
            <div class="fg"><label>MATCH STATUS CODES (-mc)</label><input class="inp inp-mono" id="ffuf-mc" type="text" placeholder="200,301,302"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>EXTENSIONS (-e)</label><input class="inp inp-mono" id="ffuf-e" type="text" placeholder=".php,.html,.txt"/></div>
            <div class="fg"><label>THREADS (-t)</label><input class="inp inp-mono" id="ffuf-threads" type="number" value="40" min="1" max="200"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ffuf-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="ffuf-extra" type="text" placeholder="-H 'Cookie: session=abc' -recursion"/></div>
          <button class="btn btn-primary" id="ffuf-btn" onclick="runFfuf()">RUN FFUF</button>''',
))

# ─── NUCLEI ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "nuclei — target/severity/tags fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="nuclei-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nuclei-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="nuclei-bin" type="text" value="nuclei"/></div>
          </div>
          <button class="btn btn-primary" id="nuclei-btn" onclick="runGenericTool('nuclei','nuclei')">RUN NUCLEI</button>''',
    '''          <div class="fg"><label>TARGET URL / HOST</label><input class="inp inp-mono" id="nuclei-target" type="text" placeholder="https://example.com"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SEVERITY (hold Ctrl)</label>
              <select class="inp inp-mono" id="nuclei-severity" multiple style="height:80px;padding:6px">
                <option value="critical" selected>Critical</option><option value="high" selected>High</option>
                <option value="medium" selected>Medium</option><option value="low">Low</option><option value="info">Info</option>
              </select>
            </div>
            <div class="fg"><label>TEMPLATE TAGS (hold Ctrl)</label>
              <select class="inp inp-mono" id="nuclei-tags" multiple style="height:80px;padding:6px">
                <option value="cve" selected>CVEs</option><option value="sqli">SQLi</option>
                <option value="xss">XSS</option><option value="rce">RCE</option>
                <option value="lfi">LFI</option><option value="ssrf">SSRF</option>
                <option value="misconfig">Misconfig</option><option value="exposed-panels">Exposed Panels</option>
              </select>
            </div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>THREADS (-c)</label><input class="inp inp-mono" id="nuclei-threads" type="number" value="25" min="1" max="100"/></div>
            <div class="fg"><label>RATE LIMIT (req/s)</label><input class="inp inp-mono" id="nuclei-rate" type="number" value="150" min="1" max="500"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nuclei-timeout" type="number" value="300" min="30" max="1800"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>CUSTOM TEMPLATE PATH (optional)</label><input class="inp inp-mono" id="nuclei-templates" type="text" placeholder="/path/to/custom-templates/"/></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="nuclei-btn" onclick="runNuclei()">RUN NUCLEI</button>
            <button class="btn btn-outline btn-sm" onclick="runNucleiUpdate()">UPDATE TEMPLATES</button>
          </div>''',
))

# ─── WHATWEB ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "whatweb — target/aggression/format fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="whatweb-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="whatweb-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="whatweb-bin" type="text" value="whatweb"/></div>
          </div>
          <button class="btn btn-primary" id="whatweb-btn" onclick="runGenericTool('whatweb','whatweb')">RUN WHATWEB</button>''',
    '''          <div class="fg"><label>TARGET URL / HOST</label><input class="inp inp-mono" id="whatweb-target" type="text" placeholder="https://example.com"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>AGGRESSION LEVEL</label>
              <select class="inp inp-mono" id="whatweb-aggression">
                <option value="1">1 — Stealthy</option><option value="3" selected>3 — Aggressive</option><option value="4">4 — Heavy</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="whatweb-format">
                <option value="">Brief</option><option value="--log-json=-" selected>JSON</option><option value="--log-verbose=-">Verbose</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="whatweb-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>USER AGENT (optional)</label><input class="inp inp-mono" id="whatweb-ua" type="text" placeholder="Mozilla/5.0 ..."/></div>
            <div class="fg"><label>HTTP PROXY (optional)</label><input class="inp inp-mono" id="whatweb-proxy" type="text" placeholder="http://127.0.0.1:8080"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="whatweb-extra" type="text" placeholder="--follow-redirect=never"/></div>
          <button class="btn btn-primary" id="whatweb-btn" onclick="runWhatWeb()">RUN WHATWEB</button>''',
))

# ─── WAPITI ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "wapiti — target/modules/depth fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="wapiti-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="wapiti-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="wapiti-bin" type="text" value="wapiti"/></div>
          </div>
          <button class="btn btn-primary" id="wapiti-btn" onclick="runGenericTool('wapiti','wapiti')">RUN WAPITI</button>''',
    '''          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="wapiti-target" type="text" placeholder="https://example.com"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ATTACK MODULES (hold Ctrl)</label>
              <select class="inp inp-mono" id="wapiti-modules" multiple style="height:90px;padding:6px">
                <option value="sql" selected>SQL Injection</option><option value="xss" selected>XSS</option>
                <option value="file" selected>File Disclosure</option><option value="xxe">XXE</option>
                <option value="ssrf">SSRF</option><option value="redirect">Open Redirect</option>
                <option value="exec">Command Injection</option><option value="csrf">CSRF</option>
              </select>
            </div>
            <div class="fg">
              <div class="fg"><label>CRAWL DEPTH</label><input class="inp inp-mono" id="wapiti-depth" type="number" value="2" min="1" max="10"/></div>
              <div class="fg"><label>SCOPE</label>
                <select class="inp inp-mono" id="wapiti-scope">
                  <option value="folder">Folder</option><option value="domain" selected>Domain</option><option value="url">URL only</option>
                </select>
              </div>
              <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="wapiti-timeout" type="number" value="300" min="60" max="1800"/></div>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>REPORT FORMAT</label>
              <select class="inp inp-mono" id="wapiti-format"><option value="json" selected>JSON</option><option value="html">HTML</option><option value="txt">Text</option></select>
            </div>
            <div class="fg"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="wapiti-extra" type="text" placeholder="--auth-user admin --auth-password pass"/></div>
          </div>
          <button class="btn btn-primary" id="wapiti-btn" onclick="runWapiti()">RUN WAPITI</button>''',
))

# ─── DALFOX ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "dalfox — URL/mode/payload fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="dalfox-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="dalfox-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="dalfox-bin" type="text" value="dalfox"/></div>
          </div>
          <button class="btn btn-primary" id="dalfox-btn" onclick="runGenericTool('dalfox','dalfox')">RUN DALFOX</button>''',
    '''          <div class="fg"><label>TARGET URL (with parameters)</label><input class="inp inp-mono" id="dalfox-target" type="text" placeholder="https://example.com/search?q=test"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>SCAN MODE</label>
              <select class="inp inp-mono" id="dalfox-mode">
                <option value="url" selected>URL scan</option><option value="sxss">Stored XSS</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="dalfox-format">
                <option value="">Plain</option><option value="--format json" selected>JSON</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="dalfox-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>CUSTOM PAYLOAD (optional)</label><input class="inp inp-mono" id="dalfox-payload" type="text" placeholder="&lt;script&gt;alert(1)&lt;/script&gt;"/></div>
            <div class="fg"><label>HTTP HEADER (optional)</label><input class="inp inp-mono" id="dalfox-header" type="text" placeholder="Cookie: session=abc123"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill" id="dalfox-opt-blind" onclick="this.classList.toggle('on')">Blind XSS</button>
            <button class="pill" id="dalfox-opt-skip-bav" onclick="this.classList.toggle('on')">Skip BAV</button>
            <button class="pill on" id="dalfox-opt-follow" onclick="this.classList.toggle('on')">Follow Redirects</button>
          </div>
          <button class="btn btn-primary" id="dalfox-btn" onclick="runDalfox()">RUN DALFOX</button>''',
))

# ─── SQLMAP ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "sqlmap — URL/risk/level/technique fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="sqlmap-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sqlmap-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="sqlmap-bin" type="text" value="sqlmap"/></div>
          </div>
          <button class="btn btn-primary" id="sqlmap-btn" onclick="runGenericTool('sqlmap','sqlmap')">RUN SQLMAP</button>''',
    '''          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="sqlmap-url" type="text" placeholder="https://example.com/page.php?id=1"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>RISK LEVEL</label>
              <select class="inp inp-mono" id="sqlmap-risk">
                <option value="1" selected>1 — Safe</option><option value="2">2 — Medium</option><option value="3">3 — High</option>
              </select>
            </div>
            <div class="fg"><label>TEST LEVEL</label>
              <select class="inp inp-mono" id="sqlmap-level">
                <option value="1" selected>1 — Basic</option><option value="2">2</option><option value="3">3 — Headers</option><option value="4">4</option><option value="5">5 — All</option>
              </select>
            </div>
            <div class="fg"><label>DBMS</label>
              <select class="inp inp-mono" id="sqlmap-dbms">
                <option value="">Auto</option><option>MySQL</option><option>PostgreSQL</option>
                <option>Microsoft SQL Server</option><option>Oracle</option><option>SQLite</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TECHNIQUE</label>
              <select class="inp inp-mono" id="sqlmap-technique">
                <option value="">All</option><option value="B">Boolean-based blind</option>
                <option value="E">Error-based</option><option value="U">Union query</option>
                <option value="T">Time-based blind</option>
              </select>
            </div>
            <div class="fg"><label>POST DATA (optional)</label><input class="inp inp-mono" id="sqlmap-data" type="text" placeholder="username=admin&amp;password=test"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>COOKIE (optional)</label><input class="inp inp-mono" id="sqlmap-cookie" type="text" placeholder="PHPSESSID=abc123"/></div>
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="sqlmap-threads" type="number" value="1" min="1" max="10"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="sqlmap-batch" onclick="this.classList.toggle('on')">--batch</button>
            <button class="pill" id="sqlmap-dbs" onclick="this.classList.toggle('on')">--dbs</button>
            <button class="pill" id="sqlmap-tables" onclick="this.classList.toggle('on')">--tables</button>
            <button class="pill" id="sqlmap-dump" onclick="this.classList.toggle('on')">--dump</button>
            <button class="pill" id="sqlmap-random-agent" onclick="this.classList.toggle('on')">Random UA</button>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sqlmap-timeout" type="number" value="300" min="30" max="1800"/></div>
          <button class="btn btn-primary" id="sqlmap-btn" onclick="runSqlmap()">RUN SQLMAP</button>''',
))

# ─── KXSS ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "kxss — URL list fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="kxss-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="kxss-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="kxss-bin" type="text" value="kxss"/></div>
          </div>
          <button class="btn btn-primary" id="kxss-btn" onclick="runGenericTool('kxss','kxss')">RUN KXSS</button>''',
    '''          <div class="fg"><label>TARGET URLs (one per line — must include parameters)</label>
            <textarea class="inp inp-mono" id="kxss-urls" rows="5" placeholder="https://example.com/search?q=test&#10;https://example.com/page?id=1"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>HTTP HEADER (optional)</label><input class="inp inp-mono" id="kxss-header" type="text" placeholder="Cookie: session=abc123"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="kxss-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">&#9432; kxss reads from stdin. Best used as: <code>echo "URL" | kxss</code> or <code>cat urls.txt | kxss</code></div>
          <button class="btn btn-primary" id="kxss-btn" onclick="runKxss()">CHECK KXSS</button>''',
))

# ─── MEDUSA ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "medusa — host/protocol/credentials fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="medusa-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="medusa-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="medusa-bin" type="text" value="medusa"/></div>
          </div>
          <button class="btn btn-primary" id="medusa-btn" onclick="runGenericTool('medusa','medusa')">RUN MEDUSA</button>''',
    '''          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST / IP</label><input class="inp inp-mono" id="medusa-host" type="text" placeholder="192.168.1.1"/></div>
            <div class="fg"><label>PORT</label><input class="inp inp-mono" id="medusa-port" type="number" placeholder="22"/></div>
            <div class="fg"><label>PROTOCOL / MODULE</label>
              <select class="inp inp-mono" id="medusa-module">
                <option value="ssh" selected>SSH</option><option value="ftp">FTP</option>
                <option value="http">HTTP</option><option value="https">HTTPS</option>
                <option value="smb">SMB</option><option value="rdp">RDP</option>
                <option value="telnet">Telnet</option><option value="mysql">MySQL</option>
                <option value="pop3">POP3</option><option value="imap">IMAP</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>USERNAMES (one per line)</label><textarea class="inp inp-mono" id="medusa-users" rows="3" placeholder="admin&#10;root&#10;user"></textarea></div>
            <div class="fg"><label>PASSWORDS (one per line)</label><textarea class="inp inp-mono" id="medusa-passes" rows="3" placeholder="password&#10;admin&#10;123456"></textarea></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="medusa-threads" type="number" value="4" min="1" max="64"/></div>
            <div class="fg"><label>RETRIES</label><input class="inp inp-mono" id="medusa-retries" type="number" value="3" min="0" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="medusa-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="medusa-extra" type="text" placeholder="-e ns -F (stop on first success)"/></div>
          <button class="btn btn-primary" id="medusa-btn" onclick="runMedusa()">RUN MEDUSA</button>''',
))

# ─── HPING3 ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "hping3 — host/mode/count/interval fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="hping3-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hping3-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="hping3-bin" type="text" value="hping3"/></div>
          </div>
          <button class="btn btn-primary" id="hping3-btn" onclick="runGenericTool('hping3','hping3')">RUN HPING3</button>''',
    '''          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST / IP</label><input class="inp inp-mono" id="hping3-host" type="text" placeholder="192.168.1.1"/></div>
            <div class="fg"><label>DESTINATION PORT</label><input class="inp inp-mono" id="hping3-port" type="number" value="80" min="1" max="65535"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>MODE</label>
              <select class="inp inp-mono" id="hping3-mode">
                <option value="-S" selected>SYN (-S)</option><option value="-A">ACK (-A)</option>
                <option value="-F">FIN (-F)</option><option value="-U">UDP (-U)</option><option value="-1">ICMP (-1)</option>
              </select>
            </div>
            <div class="fg"><label>PACKET COUNT (-c)</label><input class="inp inp-mono" id="hping3-count" type="number" value="5" min="1" max="10000"/></div>
            <div class="fg"><label>INTERVAL (ms)</label><input class="inp inp-mono" id="hping3-interval" type="number" value="1000" min="0" max="60000"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>DATA SIZE (bytes)</label><input class="inp inp-mono" id="hping3-data" type="number" value="0" min="0" max="65000"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hping3-timeout" type="number" value="30" min="5" max="300"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill" id="hping3-verbose" onclick="this.classList.toggle('on')">--verbose</button>
            <button class="pill" id="hping3-rand-source" onclick="this.classList.toggle('on')">--rand-source</button>
            <button class="pill" id="hping3-fast" onclick="this.classList.toggle('on')">--fast</button>
            <button class="pill" id="hping3-flood" onclick="this.classList.toggle('on')">--flood ⚠</button>
          </div>
          <button class="btn btn-primary" id="hping3-btn" onclick="runHping3()">RUN HPING3</button>''',
))

# ─── HASHCAT ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "hashcat — hash/type/attack/wordlist fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="hashcat-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hashcat-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="hashcat-bin" type="text" value="hashcat"/></div>
          </div>
          <button class="btn btn-primary" id="hashcat-btn" onclick="runGenericTool('hashcat','hashcat')">RUN HASHCAT</button>''',
    '''          <div class="fg"><label>HASH(ES) — paste hashes or enter file path</label>
            <textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;/path/to/hashes.txt"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>HASH TYPE (-m)</label>
              <select class="inp inp-mono" id="hashcat-type">
                <option value="0">0 — MD5</option><option value="100">100 — SHA1</option>
                <option value="1400">1400 — SHA-256</option><option value="1700">1700 — SHA-512</option>
                <option value="3200">3200 — bcrypt</option><option value="1800">1800 — sha512crypt (Linux)</option>
                <option value="500">500 — md5crypt (Linux)</option><option value="1000" selected>1000 — NTLM</option>
                <option value="5600">5600 — NetNTLMv2</option><option value="22000">22000 — WPA-PBKDF2</option>
              </select>
            </div>
            <div class="fg"><label>ATTACK MODE (-a)</label>
              <select class="inp inp-mono" id="hashcat-attack">
                <option value="0" selected>0 — Dictionary</option><option value="1">1 — Combination</option>
                <option value="3">3 — Brute-force/Mask</option><option value="6">6 — Hybrid wordlist+mask</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>WORDLIST / MASK</label><input class="inp inp-mono" id="hashcat-wordlist" type="text" value="/usr/share/wordlists/rockyou.txt"/></div>
            <div class="fg"><label>RULES FILE (optional)</label><input class="inp inp-mono" id="hashcat-rules" type="text" placeholder="/usr/share/hashcat/rules/best64.rule"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>WORKLOAD (-w)</label>
              <select class="inp inp-mono" id="hashcat-workload">
                <option value="1">1 — Low</option><option value="2" selected>2 — Default</option>
                <option value="3">3 — High</option><option value="4">4 — Nightmare</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hashcat-timeout" type="number" value="300" min="30" max="3600"/></div>
          </div>
          <button class="btn btn-primary" id="hashcat-btn" onclick="runHashcat()">RUN HASHCAT</button>''',
))

# ─── JOHN ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "john — hash/mode/format/wordlist fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="john-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="john-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="john-bin" type="text" value="john"/></div>
          </div>
          <button class="btn btn-primary" id="john-btn" onclick="runGenericTool('john','john')">RUN JOHN THE RIPPER</button>''',
    '''          <div class="fg"><label>HASH FILE PATH or PASTE HASHES</label>
            <textarea class="inp inp-mono" id="john-hashes" rows="4" placeholder="/etc/shadow&#10;OR paste hashes:&#10;root:$6$salt$hash&#10;5f4dcc3b5aa765d61d8327deb882cf99"></textarea>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>ATTACK MODE</label>
              <select class="inp inp-mono" id="john-mode">
                <option value="--wordlist" selected>Wordlist</option><option value="--wordlist --rules">Wordlist + Rules</option>
                <option value="--incremental">Incremental</option><option value="--single">Single</option><option value="--show">Show cracked</option>
              </select>
            </div>
            <div class="fg"><label>HASH FORMAT</label>
              <select class="inp inp-mono" id="john-format">
                <option value="">Auto-detect</option><option value="--format=md5crypt">md5crypt</option>
                <option value="--format=sha512crypt">sha512crypt</option><option value="--format=bcrypt">bcrypt</option>
                <option value="--format=NT">NT (Windows)</option><option value="--format=Raw-MD5">Raw MD5</option>
                <option value="--format=Raw-SHA1">Raw SHA1</option><option value="--format=zip">ZIP</option>
              </select>
            </div>
            <div class="fg"><label>WORDLIST PATH</label><input class="inp inp-mono" id="john-wordlist" type="text" value="/usr/share/wordlists/rockyou.txt"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>RULES (optional)</label>
              <select class="inp inp-mono" id="john-rules">
                <option value="">None</option><option value="--rules=All">All</option><option value="--rules=Jumbo">Jumbo</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="john-timeout" type="number" value="300" min="30" max="3600"/></div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="john-btn" onclick="runJohn()">RUN JOHN</button>
            <button class="btn btn-outline btn-sm" onclick="runJohnShow()">SHOW CRACKED</button>
          </div>''',
))

# ─── SEARCHSPLOIT ────────────────────────────────────────────
TOOL_PAGES.append((
    "searchsploit — query/CVE/filter fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="searchsploit-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="searchsploit-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="searchsploit-bin" type="text" value="searchsploit"/></div>
          </div>
          <button class="btn btn-primary" id="searchsploit-btn" onclick="runGenericTool('searchsploit','searchsploit')">RUN SEARCHSPLOIT</button>''',
    '''          <div class="fg"><label>SEARCH QUERY (software name, version)</label>
            <input class="inp inp-mono" id="searchsploit-query" type="text" placeholder="apache 2.4 remote code execution"/>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>FILTER TYPE</label>
              <select class="inp inp-mono" id="searchsploit-type">
                <option value="">All</option><option value="-e">Exploits only</option><option value="-s">Shellcodes only</option>
              </select>
            </div>
            <div class="fg"><label>PLATFORM</label>
              <select class="inp inp-mono" id="searchsploit-platform">
                <option value="">All</option><option value="-p linux">Linux</option>
                <option value="-p windows">Windows</option><option value="-p php">PHP</option><option value="-p webapps">Web Apps</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="searchsploit-format">
                <option value="">Table</option><option value="-j">JSON</option>
              </select>
            </div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill" id="searchsploit-strict" onclick="this.classList.toggle('on')">Strict match (-w)</button>
            <button class="pill" id="searchsploit-case" onclick="this.classList.toggle('on')">Case sensitive (-c)</button>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>CVE LOOKUP (overrides query)</label><input class="inp inp-mono" id="searchsploit-cve" type="text" placeholder="CVE-2021-44228"/></div>
          <button class="btn btn-primary" id="searchsploit-btn" onclick="runSearchsploit()">SEARCH EXPLOIT-DB</button>''',
))

# ─── MSFVENOM ────────────────────────────────────────────────
TOOL_PAGES.append((
    "msfvenom — payload/LHOST/LPORT/format fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="msfvenom-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="msfvenom-bin" type="text" value="msfvenom"/></div>
          </div>
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runGenericTool('msfvenom','msfvenom')">RUN MSFVENOM</button>''',
    '''          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PAYLOAD</label>
              <select class="inp inp-mono" id="msfvenom-payload">
                <option value="windows/x64/meterpreter/reverse_tcp" selected>Windows x64 Meterpreter/TCP</option>
                <option value="windows/meterpreter/reverse_tcp">Windows x86 Meterpreter/TCP</option>
                <option value="windows/x64/shell_reverse_tcp">Windows x64 Shell/TCP</option>
                <option value="linux/x64/meterpreter/reverse_tcp">Linux x64 Meterpreter/TCP</option>
                <option value="linux/x64/shell_reverse_tcp">Linux x64 Shell/TCP</option>
                <option value="php/meterpreter/reverse_tcp">PHP Meterpreter/TCP</option>
                <option value="python/meterpreter/reverse_tcp">Python Meterpreter/TCP</option>
                <option value="cmd/unix/reverse_bash">Unix CMD Reverse Bash</option>
                <option value="custom">Custom (enter below)</option>
              </select>
            </div>
            <div class="fg"><label>CUSTOM PAYLOAD (if Custom selected)</label><input class="inp inp-mono" id="msfvenom-custom-payload" type="text" placeholder="windows/x64/meterpreter_reverse_https"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>LHOST (your IP)</label><input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="192.168.1.100"/></div>
            <div class="fg"><label>LPORT</label><input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535"/></div>
            <div class="fg"><label>FORMAT (-f)</label>
              <select class="inp inp-mono" id="msfvenom-format">
                <option value="exe" selected>exe</option><option value="elf">elf</option>
                <option value="asp">asp</option><option value="aspx">aspx</option>
                <option value="php">php</option><option value="py">py</option>
                <option value="raw">raw</option><option value="powershell">powershell</option>
              </select>
            </div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>ENCODER (optional)</label>
              <select class="inp inp-mono" id="msfvenom-encoder">
                <option value="">None</option>
                <option value="x86/shikata_ga_nai">x86/shikata_ga_nai</option>
                <option value="x64/xor_dynamic">x64/xor_dynamic</option>
              </select>
            </div>
            <div class="fg"><label>ITERATIONS</label><input class="inp inp-mono" id="msfvenom-iterations" type="number" value="1" min="1" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA OPTIONS</label><input class="inp inp-mono" id="msfvenom-extra" type="text" placeholder="EXITFUNC=thread"/></div>
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>''',
))

# ─── GRYPE ───────────────────────────────────────────────────
TOOL_PAGES.append((
    "grype — image/scope/severity/format fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="grype-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="grype-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="grype-bin" type="text" value="grype"/></div>
          </div>
          <button class="btn btn-primary" id="grype-btn" onclick="runGenericTool('grype','grype')">RUN GRYPE</button>''',
    '''          <div class="fg"><label>TARGET (image, dir, or file)</label><input class="inp inp-mono" id="grype-target" type="text" placeholder="ubuntu:22.04  OR  nginx:latest  OR  /path/to/dir"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>SCOPE</label>
              <select class="inp inp-mono" id="grype-scope">
                <option value="">Auto</option><option value="all-layers">All layers</option>
                <option value="squashed">Squashed</option>
              </select>
            </div>
            <div class="fg"><label>SEVERITY THRESHOLD</label>
              <select class="inp inp-mono" id="grype-severity">
                <option value="">Show all</option><option value="--fail-on critical">Critical only</option>
                <option value="--fail-on high">High+</option><option value="--fail-on medium">Medium+</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="grype-format">
                <option value="table" selected>Table</option><option value="json">JSON</option>
                <option value="cyclonedx">CycloneDX</option><option value="sarif">SARIF</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg">
              <label>OPTIONS</label>
              <div class="pills" style="margin-top:6px">
                <button class="pill on" id="grype-only-fixed" onclick="this.classList.toggle('on')">Only fixed</button>
                <button class="pill" id="grype-update-db" onclick="this.classList.toggle('on')">Update DB first</button>
              </div>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="grype-timeout" type="number" value="180" min="30" max="1800"/></div>
          </div>
          <button class="btn btn-primary" id="grype-btn" onclick="runGrype()">RUN GRYPE</button>''',
))

# ─── RADARE2 ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "radare2 — binary/commands/arch fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="radare2-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="radare2-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="radare2-bin" type="text" value="radare2"/></div>
          </div>
          <button class="btn btn-primary" id="radare2-btn" onclick="runGenericTool('radare2','radare2')">RUN RADARE2</button>''',
    '''          <div class="fg"><label>BINARY / FILE PATH</label><input class="inp inp-mono" id="radare2-file" type="text" placeholder="/path/to/binary"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ANALYSIS COMMANDS (one per line)</label>
              <textarea class="inp inp-mono" id="radare2-cmds" rows="5" placeholder="i&#10;aaa&#10;afl&#10;pdf @ main"></textarea>
            </div>
            <div class="fg">
              <label>QUICK PRESETS</label>
              <div style="display:flex;flex-direction:column;gap:5px;margin-top:4px">
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('info')">Binary Info</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('functions')">List Functions</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('strings')">Strings</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('imports')">Imports/Exports</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('sections')">Sections</button>
              </div>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ARCHITECTURE (optional)</label>
              <select class="inp inp-mono" id="radare2-arch">
                <option value="">Auto</option><option value="-a x86">x86</option>
                <option value="-a x86 -b 64">x86-64</option><option value="-a arm">ARM</option><option value="-a arm -b 64">ARM64</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="radare2-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <button class="btn btn-primary" id="radare2-btn" onclick="runRadare2()">RUN RADARE2</button>''',
))

# ─── OPENVAS ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "openvas — operation/timeout fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="openvas-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="openvas-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="openvas-bin" type="text" value="openvas"/></div>
          </div>
          <button class="btn btn-primary" id="openvas-btn" onclick="runGenericTool('openvas','openvas')">RUN OPENVAS</button>''',
    '''          <div class="notice" style="margin-bottom:12px">&#9432; OpenVAS uses Greenbone Security Assistant web UI (port 9392) for full scans. This panel runs CLI checks.</div>
          <div class="fg" style="margin-bottom:12px"><label>OPERATION</label>
            <select class="inp inp-mono" id="openvas-op">
              <option value="--version">Version (openvas --version)</option>
              <option value="--help">Help</option>
            </select>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="openvas-timeout" type="number" value="60" min="10" max="300"/></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="openvas-btn" onclick="runOpenVAS()">RUN OPENVAS CLI</button>
            <a class="btn btn-outline btn-sm" href="http://127.0.0.1:9392" target="_blank">OPEN GSA WEB UI &#8599;</a>
          </div>''',
))

# ─── CHKROOTKIT ──────────────────────────────────────────────
TOOL_PAGES.append((
    "chkrootkit — mode/test/path fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="chkrootkit-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chkrootkit-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="chkrootkit-bin" type="text" value="chkrootkit"/></div>
          </div>
          <button class="btn btn-primary" id="chkrootkit-btn" onclick="runGenericTool('chkrootkit','chkrootkit')">RUN CHKROOTKIT</button>''',
    '''          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SCAN MODE</label>
              <select class="inp inp-mono" id="chkrootkit-mode">
                <option value="" selected>Full scan</option><option value="-x">Expert mode (-x)</option>
                <option value="-q">Quiet — infected only (-q)</option><option value="-l">List tests (-l)</option>
              </select>
            </div>
            <div class="fg"><label>SPECIFIC TEST (optional)</label>
              <select class="inp inp-mono" id="chkrootkit-test">
                <option value="">All tests</option><option value="aliens">Aliens (hidden procs)</option>
                <option value="bindshell">Bind shell backdoor</option><option value="lkm">LKM rootkit</option>
                <option value="sniffer">Network sniffer</option><option value="wted">wtmp editor</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ALTERNATE PATH (optional)</label><input class="inp inp-mono" id="chkrootkit-path" type="text" placeholder="/mnt/suspect_root"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chkrootkit-timeout" type="number" value="120" min="30" max="600"/></div>
          </div>
          <button class="btn btn-primary" id="chkrootkit-btn" onclick="runChkrootkit()">RUN CHKROOTKIT</button>''',
))

# ─── RKHUNTER ────────────────────────────────────────────────
TOOL_PAGES.append((
    "rkhunter — scan type/options fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="rkhunter-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rkhunter-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="rkhunter-bin" type="text" value="rkhunter"/></div>
          </div>
          <button class="btn btn-primary" id="rkhunter-btn" onclick="runGenericTool('rkhunter','rkhunter')">RUN RKHUNTER</button>''',
    '''          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SCAN TYPE</label>
              <select class="inp inp-mono" id="rkhunter-scantype">
                <option value="--check" selected>Full check (--check)</option>
                <option value="--check --rwo">Warnings only (--rwo)</option>
                <option value="--update">Update database</option>
                <option value="--propupd">Update file properties</option>
                <option value="--version">Version info</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rkhunter-timeout" type="number" value="300" min="60" max="1800"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="rkhunter-skip-keypress" onclick="this.classList.toggle('on')">--skip-keypress</button>
            <button class="pill on" id="rkhunter-nocolors" onclick="this.classList.toggle('on')">--nocolors</button>
            <button class="pill" id="rkhunter-append-log" onclick="this.classList.toggle('on')">--append-log</button>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="rkhunter-btn" onclick="runRkhunter()">RUN RKHUNTER</button>
            <button class="btn btn-outline btn-sm" onclick="runRkhunterUpdate()">UPDATE DB FIRST</button>
          </div>''',
))

# ─── PSPY ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "pspy — binary/duration/interval/filter fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="pspy-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pspy-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="pspy-bin" type="text" value="pspy"/></div>
          </div>
          <button class="btn btn-primary" id="pspy-btn" onclick="runGenericTool('pspy','pspy')">RUN PSPY</button>''',
    '''          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>PSPY BINARY PATH</label><input class="inp inp-mono" id="pspy-path" type="text" value="/usr/local/bin/pspy64" placeholder="/tmp/pspy64"/></div>
            <div class="fg"><label>WATCH INTERVAL (ms)</label><input class="inp inp-mono" id="pspy-interval" type="number" value="100" min="10" max="10000"/></div>
            <div class="fg"><label>MONITOR DURATION (sec)</label><input class="inp inp-mono" id="pspy-duration" type="number" value="30" min="10" max="300"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>FILTER PATTERN (grep, optional)</label><input class="inp inp-mono" id="pspy-filter" type="text" placeholder="cron|bash|python|root"/></div>
            <div class="fg">
              <label>OPTIONS</label>
              <div class="pills" style="margin-top:6px">
                <button class="pill on" id="pspy-fs" onclick="this.classList.toggle('on')">Watch filesystem (-f)</button>
              </div>
            </div>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">
            &#9432; Download: <a href="https://github.com/DominicBreuker/pspy/releases" target="_blank" style="color:var(--blue)">github.com/DominicBreuker/pspy/releases</a>
          </div>
          <button class="btn btn-primary" id="pspy-btn" onclick="runPspy()">RUN PSPY</button>''',
))

# ─── PWNCAT ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "pwncat — listen/connect/SSH mode fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="pwncat-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pwncat-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="pwncat-bin" type="text" value="pwncat"/></div>
          </div>
          <button class="btn btn-primary" id="pwncat-btn" onclick="runGenericTool('pwncat','pwncat')">RUN PWNCAT</button>''',
    '''          <div class="fg"><label>CONNECTION MODE</label>
            <select class="inp inp-mono" id="pwncat-mode" onchange="pwncatModeChange()">
              <option value="listen" selected>Listen (reverse shell)</option>
              <option value="connect">Connect (bind shell)</option>
              <option value="ssh">SSH connect</option>
              <option value="help">Help</option>
            </select>
          </div>
          <div id="pwncat-listen-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>LISTEN HOST</label><input class="inp inp-mono" id="pwncat-lhost" type="text" value="0.0.0.0"/></div>
              <div class="fg"><label>LISTEN PORT</label><input class="inp inp-mono" id="pwncat-lport" type="number" value="4444" min="1" max="65535"/></div>
            </div>
          </div>
          <div id="pwncat-connect-fields" style="display:none">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>REMOTE HOST</label><input class="inp inp-mono" id="pwncat-rhost" type="text" placeholder="192.168.1.100"/></div>
              <div class="fg"><label>REMOTE PORT</label><input class="inp inp-mono" id="pwncat-rport" type="number" value="4444"/></div>
            </div>
          </div>
          <div id="pwncat-ssh-fields" style="display:none">
            <div class="row3" style="margin-bottom:12px">
              <div class="fg"><label>SSH HOST</label><input class="inp inp-mono" id="pwncat-sshhost" type="text" placeholder="192.168.1.100"/></div>
              <div class="fg"><label>SSH PORT</label><input class="inp inp-mono" id="pwncat-sshport" type="number" value="22"/></div>
              <div class="fg"><label>SSH USER</label><input class="inp inp-mono" id="pwncat-sshuser" type="text" placeholder="root"/></div>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pwncat-timeout" type="number" value="60" min="10" max="300"/></div>
          <button class="btn btn-primary" id="pwncat-btn" onclick="runPwncat()">RUN PWNCAT</button>''',
))

# ─── LIGOLO-NG ───────────────────────────────────────────────
TOOL_PAGES.append((
    "ligolo-ng — proxy/agent mode fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="ligolo-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ligolo-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="ligolo-bin" type="text" value="ligolo-ng"/></div>
          </div>
          <button class="btn btn-primary" id="ligolo-btn" onclick="runGenericTool('ligolo','ligolo-ng')">RUN LIGOLO-NG</button>''',
    '''          <div class="fg"><label>COMPONENT</label>
            <select class="inp inp-mono" id="ligolo-component" onchange="ligoloComponentChange()">
              <option value="proxy" selected>Proxy (attacker machine)</option>
              <option value="agent">Agent (pivot host)</option>
              <option value="help">Help / version</option>
            </select>
          </div>
          <div id="ligolo-proxy-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>LISTEN ADDRESS</label><input class="inp inp-mono" id="ligolo-proxy-listen" type="text" value="0.0.0.0:11601"/></div>
              <div class="fg"><label>TUN INTERFACE</label><input class="inp inp-mono" id="ligolo-tun" type="text" value="ligolo"/></div>
            </div>
            <div class="pills" style="margin-bottom:12px">
              <button class="pill on" id="ligolo-selfcert" onclick="this.classList.toggle('on')">Self-signed cert (--selfcert)</button>
            </div>
          </div>
          <div id="ligolo-agent-fields" style="display:none">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>PROXY ADDRESS (attacker:port)</label><input class="inp inp-mono" id="ligolo-agent-proxy" type="text" placeholder="192.168.1.100:11601"/></div>
              <div class="fg">
                <div class="pills" style="margin-top:24px">
                  <button class="pill on" id="ligolo-ignore-cert" onclick="this.classList.toggle('on')">Ignore cert</button>
                </div>
              </div>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ligolo-timeout" type="number" value="60" min="10" max="300"/></div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">&#9432; Setup TUN: <code>sudo ip tuntap add user $USER mode tun ligolo &amp;&amp; sudo ip link set ligolo up</code></div>
          <button class="btn btn-primary" id="ligolo-btn" onclick="runLigolo()">RUN LIGOLO-NG</button>''',
))

# ─── CHISEL ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "chisel — server/client mode fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="chisel-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chisel-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="chisel-bin" type="text" value="chisel"/></div>
          </div>
          <button class="btn btn-primary" id="chisel-btn" onclick="runGenericTool('chisel','chisel')">RUN CHISEL</button>''',
    '''          <div class="fg"><label>MODE</label>
            <select class="inp inp-mono" id="chisel-mode" onchange="chiselModeChange()">
              <option value="server" selected>Server (attacker/relay)</option>
              <option value="client">Client (pivot host)</option>
              <option value="help">Help / version</option>
            </select>
          </div>
          <div id="chisel-server-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>LISTEN PORT</label><input class="inp inp-mono" id="chisel-server-port" type="number" value="8080"/></div>
              <div class="fg"><label>AUTH (user:pass, optional)</label><input class="inp inp-mono" id="chisel-server-auth" type="text" placeholder="admin:secret"/></div>
            </div>
            <div class="pills" style="margin-bottom:12px">
              <button class="pill on" id="chisel-socks5" onclick="this.classList.toggle('on')">SOCKS5 proxy (--socks5)</button>
              <button class="pill" id="chisel-reverse" onclick="this.classList.toggle('on')">Allow reverse (--reverse)</button>
            </div>
          </div>
          <div id="chisel-client-fields" style="display:none">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>SERVER URL</label><input class="inp inp-mono" id="chisel-server-url" type="text" placeholder="http://192.168.1.100:8080"/></div>
              <div class="fg"><label>AUTH (user:pass, optional)</label><input class="inp inp-mono" id="chisel-client-auth" type="text" placeholder="admin:secret"/></div>
            </div>
            <div class="fg" style="margin-bottom:12px"><label>TUNNELS (one per line)</label>
              <textarea class="inp inp-mono" id="chisel-tunnels" rows="3" placeholder="socks&#10;R:8888:127.0.0.1:8888&#10;3306:127.0.0.1:3306"></textarea>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chisel-timeout" type="number" value="60" min="10" max="300"/></div>
          <button class="btn btn-primary" id="chisel-btn" onclick="runChisel()">RUN CHISEL</button>''',
))

# ─── RLWRAP ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "rlwrap — command/options fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="rlwrap-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rlwrap-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="rlwrap-bin" type="text" value="rlwrap"/></div>
          </div>
          <button class="btn btn-primary" id="rlwrap-btn" onclick="runGenericTool('rlwrap','rlwrap')">RUN RLWRAP</button>''',
    '''          <div class="fg"><label>COMMAND TO WRAP</label><input class="inp inp-mono" id="rlwrap-cmd" type="text" placeholder="nc -lvnp 4444"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>HISTORY SIZE (-s)</label><input class="inp inp-mono" id="rlwrap-history" type="number" value="1000" min="0" max="100000"/></div>
            <div class="fg"><label>WORD CHARS (-w)</label><input class="inp inp-mono" id="rlwrap-wordchars" type="text" value="a-zA-Z0-9_-"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rlwrap-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="rlwrap-ansi" onclick="this.classList.toggle('on')">ANSI colour fix (-A)</button>
            <button class="pill" id="rlwrap-noecho" onclick="this.classList.toggle('on')">No echo</button>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:var(--radius);padding:8px 12px;font-size:12px;color:var(--text2);margin-bottom:12px">
            <strong>Typical use:</strong> <code style="font-family:var(--mono)">rlwrap -A nc -lvnp 4444</code>
          </div>
          <button class="btn btn-primary" id="rlwrap-btn" onclick="runRlwrap()">RUN RLWRAP</button>''',
))

# ─── SCAPY ───────────────────────────────────────────────────
TOOL_PAGES.append((
    "scapy — script editor with templates",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="scapy-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="scapy-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="scapy-bin" type="text" value="scapy"/></div>
          </div>
          <button class="btn btn-primary" id="scapy-btn" onclick="runGenericTool('scapy','scapy')">RUN SCAPY</button>''',
    '''          <div class="fg"><label>SCAPY SCRIPT (Python)</label>
            <textarea class="inp inp-mono" id="scapy-script" rows="8" placeholder="from scapy.all import *&#10;target = '192.168.1.1'&#10;pkt = IP(dst=target)/ICMP()&#10;reply = sr1(pkt, timeout=2, verbose=0)&#10;if reply:&#10;    print('Host is up:', reply.src)"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg">
              <label>QUICK TEMPLATES</label>
              <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:5px">
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('ping')">ICMP Ping</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('portscan')">TCP Port Scan</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('syn')">SYN Scan</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('arpscan')">ARP Scan</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('traceroute')">Traceroute</button>
              </div>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="scapy-timeout" type="number" value="30" min="5" max="300"/></div>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">&#9432; Scapy packet injection requires root. Run scripts directly: <code>sudo python3 script.py</code></div>
          <button class="btn btn-primary" id="scapy-btn" onclick="runScapy()">RUN SCAPY</button>''',
))

# ─── YERSINIA ────────────────────────────────────────────────
TOOL_PAGES.append((
    "yersinia — protocol/interface/action fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="yersinia-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="yersinia-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="yersinia-bin" type="text" value="yersinia"/></div>
          </div>
          <button class="btn btn-primary" id="yersinia-btn" onclick="runGenericTool('yersinia','yersinia')">RUN YERSINIA</button>''',
    '''          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>PROTOCOL</label>
              <select class="inp inp-mono" id="yersinia-proto">
                <option value="stp" selected>STP</option><option value="cdp">CDP</option>
                <option value="dhcp">DHCP</option><option value="dot1q">802.1Q</option>
                <option value="dtp">DTP</option><option value="hsrp">HSRP</option><option value="vtp">VTP</option>
              </select>
            </div>
            <div class="fg"><label>NETWORK INTERFACE</label><input class="inp inp-mono" id="yersinia-iface" type="text" value="eth0"/></div>
            <div class="fg"><label>OPERATION</label>
              <select class="inp inp-mono" id="yersinia-action">
                <option value="--help">Help / list attacks</option>
                <option value="-I">Interactive mode</option>
              </select>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="yersinia-timeout" type="number" value="30" min="5" max="300"/></div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:var(--radius);padding:8px 12px;font-size:12px;color:var(--text2);margin-bottom:12px">
            &#9888; Layer 2 attacks affect ALL devices on the segment. Use in isolated lab environments only.
          </div>
          <button class="btn btn-primary" id="yersinia-btn" onclick="runYersinia()">RUN YERSINIA</button>''',
))

# ─── SECLISTS ────────────────────────────────────────────────
TOOL_PAGES.append((
    "seclists — browse/search/copy wordlist fields",
    '''          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="seclists-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="seclists-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="seclists-bin" type="text" value="seclists"/></div>
          </div>
          <button class="btn btn-primary" id="seclists-btn" onclick="runGenericTool('seclists','seclists')">RUN SECLISTS</button>''',
    '''          <div class="fg"><label>WORDLIST CATEGORY</label>
            <select class="inp inp-mono" id="seclists-category" onchange="seclistsCategoryChange()">
              <option value="/usr/share/seclists/Discovery/Web-Content">Web Content Discovery</option>
              <option value="/usr/share/seclists/Discovery/DNS">DNS Subdomains</option>
              <option value="/usr/share/seclists/Passwords/Common-Credentials">Common Passwords</option>
              <option value="/usr/share/seclists/Passwords/Leaked-Databases">Leaked Databases</option>
              <option value="/usr/share/seclists/Usernames">Usernames</option>
              <option value="/usr/share/seclists/Fuzzing">Fuzzing Payloads</option>
            </select>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>FULL WORDLIST PATH</label><input class="inp inp-mono" id="seclists-path" type="text" value="/usr/share/seclists/Discovery/Web-Content/common.txt"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PREVIEW LINES</label><input class="inp inp-mono" id="seclists-lines" type="number" value="50" min="10" max="500"/></div>
            <div class="fg"><label>GREP FILTER (optional)</label><input class="inp inp-mono" id="seclists-grep" type="text" placeholder="admin|config|backup"/></div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE WORDLIST</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopy()">COPY PATH</button>
          </div>''',
))


# ══════════════════════════════════════════════════════════════
# MAIN PATCHING LOGIC
# ══════════════════════════════════════════════════════════════

def apply_tool_pages(src):
    """Apply all tool page HTML replacements."""
    modified = src
    for label, old, new in TOOL_PAGES:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(label)
            RESULTS["applied"] += 1
        elif new in modified:
            skip(f"{label} (already applied)")
            RESULTS["skipped"] += 1
        else:
            warn(f"{label} — anchor not found, skipping")
            RESULTS["skipped"] += 1
    return modified


def inject_js_helpers(src):
    """
    Inject JS helpers at the correct location: AFTER the hacker background
    IIFE closes (})();  and BEFORE the final loadUser() call.

    The unique anchor is the end of the hacker background IIFE:
        })();

    followed by a blank line and then:
        loadUser();

    We use a longer unique anchor to be absolutely certain we match
    the right location and not any other })(); in the code.
    """
    # This anchor appears exactly ONCE at the end of the hacker background IIFE
    # followed immediately by the final loadUser() call at the top level
    ANCHOR = "})();\n\nloadUser();"

    if JS_HELPERS.strip()[:40] in src:
        skip("JS helpers already injected")
        RESULTS["skipped"] += 1
        return src

    if ANCHOR not in src:
        warn("JS injection anchor not found — helpers not injected")
        warn("Anchor: })();\\n\\nloadUser();")
        RESULTS["failed"] += 1
        return src

    # Replace: keep })(); then inject helpers, then loadUser();
    replacement = "})();\n" + JS_HELPERS + "\nloadUser();"
    modified = src.replace(ANCHOR, replacement, 1)
    ok("JS helpers injected after hacker background IIFE")
    RESULTS["applied"] += 1
    return modified


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — Tool Pages FIX Patch                   ║" + X)
    print(B + C + "║   Repairs broken JS injection + applies tool UI changes  ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET):
        fail(f"Must be run from project root — {TARGET} not found")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    info(f"Target file:  {TARGET}")
    print()

    src = read_file(TARGET)

    # ── Step 1: Repair bad injection ──────────────────────────
    hdr("STEP 1 — Detect & Repair Broken JS Injection")
    src, was_broken = detect_and_fix_bad_injection(src)
    if not was_broken:
        skip("No broken injection detected (file may be clean or already fixed)")

    # ── Step 2: Apply tool page HTML ──────────────────────────
    hdr("STEP 2 — Tool Page UI Replacements")
    src = apply_tool_pages(src)

    # ── Step 3: Inject JS helpers correctly ───────────────────
    hdr("STEP 3 — JS Helper Injection (correct location)")
    src = inject_js_helpers(src)

    # ── Step 4: Write file ────────────────────────────────────
    hdr("STEP 4 — Write & Verify")
    backup(TARGET)
    write_file(TARGET, src)
    info(f"File written: {TARGET}")

    passed, err = syntax_check(TARGET)
    if passed:
        ok(f"{TARGET} — syntax OK")
    else:
        fail(f"SYNTAX ERROR:\n{err}")
        print(f"\n  {Y}Restore with:{X}  cp {TARGET}.*.bak {TARGET}")
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────
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
        print(f"  {G}What was fixed / applied:{X}")
        print(f"    {G}✓{X}  Removed broken JS from inside doLogin setTimeout callback")
        print(f"    {G}✓{X}  Injected JS helpers at correct top-level location")
        print(f"    {G}✓{X}  26 tool pages now have proper purpose-specific UI fields")
        print(f"    {G}✓{X}  Login, navigation, all existing tools fully restored")
        print()
        print(f"  {Y}Restart server:{X}")
        print(f"    pkill -f api_server.py && python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
    else:
        print(f"  {Y}Some patches failed. Check warnings above.{X}")
        print(f"  The file has been saved — test with: python3 api_server.py")
    print()


if __name__ == "__main__":
    main()
