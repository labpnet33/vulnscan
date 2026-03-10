#!/usr/bin/env python3
"""
Run this script in the same directory as api_server.py to add cancel buttons.
Usage: python3 apply_cancel_buttons.py
"""
import os, sys, shutil

SRC = "api_server.py"
BAK = "api_server.py.bak"

if not os.path.exists(SRC):
    print(f"[!] {SRC} not found. Run from the VulnScan Pro directory.")
    sys.exit(1)

shutil.copy2(SRC, BAK)
print(f"[*] Backup saved to {BAK}")

with open(SRC, "r") as f:
    c = f.read()

errors = []

def patch(old, new, label):
    global c
    if old not in c:
        errors.append(f"  ✗ NOT FOUND: {label}")
        return False
    c = c.replace(old, new, 1)
    print(f"  ✓ {label}")
    return True

# ── 1. Cancel button CSS ─────────────────────────────────────────────────────
patch(
    ".spin{display:inline-block;width:11px;height:11px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}",
    ".spin{display:inline-block;width:11px;height:11px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}\n.btn-cancel{padding:7px 14px;border:1px solid rgba(255,51,102,0.4);border-radius:9px;cursor:pointer;font-family:var(--font-mono);font-weight:700;font-size:11px;letter-spacing:1px;background:rgba(255,51,102,0.08);color:var(--red);transition:all 0.2s;display:none;align-items:center;gap:6px;vertical-align:middle;margin-left:8px}\n.btn-cancel:hover{background:rgba(255,51,102,0.18);border-color:var(--red);transform:scale(1.04)}\n.btn-cancel.visible{display:inline-flex}",
    "CSS: cancel button styles"
)

# ── 2. Cancel buttons in HTML ─────────────────────────────────────────────────
CANCEL_SVG = '<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="2.2" style="width:10px;height:10px"><line x1="1" y1="1" x2="9" y2="9"/><line x1="9" y1="1" x2="1" y2="9"/></svg>'

def cancel_btn(bid):
    return f'<button class="btn-cancel" id="{bid}-cancel" onclick="cancelScan(\'{bid.split("-")[0]}\')" title="Cancel scan">{CANCEL_SVG} CANCEL</button>'

# Main scan
patch(
    '<button class="btn btn-p" id="sbtn" onclick="doScan()">SCAN</button>',
    f'<button class="btn btn-p" id="sbtn" onclick="doScan()">SCAN</button>{cancel_btn("sbtn")}',
    "HTML: main scan cancel btn"
)

# Harvester
patch(
    '<button class="btn btn-p" id="hv-btn" onclick="doHarvest()" style="width:auto;padding:10px 32px">&#127919; RUN HARVESTER</button>',
    f'<button class="btn btn-p" id="hv-btn" onclick="doHarvest()" style="width:auto;padding:10px 32px">&#127919; RUN HARVESTER</button>{cancel_btn("hv-btn")}',
    "HTML: harvester cancel btn"
)

# DNSRecon
patch(
    '<button class="btn btn-p" id="dr-btn" onclick="doDnsRecon()" style="width:auto;padding:10px 32px">&#127760; RUN DNSRECON</button>',
    f'<button class="btn btn-p" id="dr-btn" onclick="doDnsRecon()" style="width:auto;padding:10px 32px">&#127760; RUN DNSRECON</button>{cancel_btn("dr-btn")}',
    "HTML: dnsrecon cancel btn"
)

# Nikto
patch(
    '<button class="btn btn-p" id="nk-btn" onclick="doNikto()" style="width:auto;padding:10px 32px">&#128200; RUN NIKTO</button>',
    f'<button class="btn btn-p" id="nk-btn" onclick="doNikto()" style="width:auto;padding:10px 32px">&#128200; RUN NIKTO</button>{cancel_btn("nk-btn")}',
    "HTML: nikto cancel btn"
)

# WPScan
patch(
    '<button class="btn btn-p" id="wp-btn" onclick="doWPScan()" style="width:auto;padding:10px 32px">&#128196; RUN WPSCAN</button>',
    f'<button class="btn btn-p" id="wp-btn" onclick="doWPScan()" style="width:auto;padding:10px 32px">&#128196; RUN WPSCAN</button>{cancel_btn("wp-btn")}',
    "HTML: wpscan cancel btn"
)

# Lynis
patch(
    '<button class="btn btn-p" id="ly-btn" onclick="doLynis()" style="width:auto;padding:10px 32px">&#128203; RUN LYNIS AUDIT</button>',
    f'<button class="btn btn-p" id="ly-btn" onclick="doLynis()" style="width:auto;padding:10px 32px">&#128203; RUN LYNIS AUDIT</button>{cancel_btn("ly-btn")}',
    "HTML: lynis cancel btn"
)

# Legion
patch(
    '<button class="btn btn-p" id="lg-btn" onclick="doLegion()" style="width:auto;padding:10px 32px">&#9881; RUN LEGION</button>',
    f'<button class="btn btn-p" id="lg-btn" onclick="doLegion()" style="width:auto;padding:10px 32px">&#9881; RUN LEGION</button>{cancel_btn("lg-btn")}',
    "HTML: legion cancel btn"
)

# Subdomain
patch(
    '<button class="btn btn-p btn-full" id="sub-btn" onclick="doSub()" style="margin-top:4px">FIND SUBDOMAINS</button>',
    f'<button class="btn btn-p btn-full" id="sub-btn" onclick="doSub()" style="margin-top:4px">FIND SUBDOMAINS</button>{cancel_btn("sub-btn")}',
    "HTML: subdomain cancel btn"
)

# Directory
patch(
    '<button class="btn btn-p btn-full" id="dir-btn" onclick="doDir()">START ENUMERATION</button>',
    f'<button class="btn btn-p btn-full" id="dir-btn" onclick="doDir()">START ENUMERATION</button>{cancel_btn("dir-btn")}',
    "HTML: dir enum cancel btn"
)

# Brute force
patch(
    '<button class="btn btn-p btn-full" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button>',
    f'<button class="btn btn-p btn-full" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button>{cancel_btn("bf-btn")}',
    "HTML: brute force cancel btn"
)

# Discover
patch(
    '<button class="btn btn-p" id="disc-btn" onclick="doDisc()">DISCOVER</button>',
    f'<button class="btn btn-p" id="disc-btn" onclick="doDisc()">DISCOVER</button>{cancel_btn("disc-btn")}',
    "HTML: discover cancel btn"
)

# ── 3. Replace JS fetchWithTimeout + add cancel infrastructure ────────────────
old_fetch = 'async function fetchWithTimeout(url,options={},timeoutMs=300000){const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);try{const r=await fetch(url,{...options,signal:controller.signal});clearTimeout(timer);return r;}catch(e){clearTimeout(timer);if(e.name===\'AbortError\')throw new Error(\'Request timed out after \'+Math.round(timeoutMs/1000)+\'s.\');throw e;}}'

new_fetch = '''// ── Cancel infrastructure ─────────────────────────────────────
const _scanControllers={};
function _startScan(key,btnId){
  if(_scanControllers[key])try{_scanControllers[key].abort();}catch(e){}
  const ctrl=new AbortController();
  _scanControllers[key]=ctrl;
  const cb=document.getElementById(btnId+'-cancel');
  if(cb)cb.classList.add('visible');
  return ctrl;
}
function _endScan(key,btnId,btn,label){
  delete _scanControllers[key];
  const cb=document.getElementById(btnId+'-cancel');
  if(cb)cb.classList.remove('visible');
  if(btn){btn.disabled=false;btn.innerHTML=label;}
}
function cancelScan(key){
  const map={
    sbtn:{btnId:'sbtn',label:'SCAN',extra:()=>{clrUI();busy=false;endProg();},msg:null},
    hv:{btnId:'hv-btn',label:'&#127919; RUN HARVESTER',extra:()=>{document.getElementById('hv-prog').style.display='none';},msg:()=>{const e=document.getElementById('hv-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    dr:{btnId:'dr-btn',label:'&#127760; RUN DNSRECON',extra:()=>{document.getElementById('dr-prog').style.display='none';},msg:()=>{const e=document.getElementById('dr-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    nk:{btnId:'nk-btn',label:'&#128200; RUN NIKTO',extra:()=>{document.getElementById('nk-prog').style.display='none';},msg:()=>{const e=document.getElementById('nk-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    wp:{btnId:'wp-btn',label:'&#128196; RUN WPSCAN',extra:()=>{document.getElementById('wp-prog').style.display='none';},msg:()=>{const e=document.getElementById('wp-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    ly:{btnId:'ly-btn',label:'&#128203; RUN LYNIS AUDIT',extra:()=>{document.getElementById('ly-prog').style.display='none';},msg:()=>{const e=document.getElementById('ly-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    lg:{btnId:'lg-btn',label:'&#9881; RUN LEGION',extra:()=>{document.getElementById('lg-prog').style.display='none';},msg:()=>{const e=document.getElementById('lg-err');e.textContent='&#9888; Scan cancelled.';e.style.display='block';}},
    sub:{btnId:'sub-btn',label:'FIND SUBDOMAINS',extra:null,msg:()=>{document.getElementById('sub-res').innerHTML='<div class="card"><p style="color:var(--m)">&#9888; Scan cancelled.</p></div>';}},
    dir:{btnId:'dir-btn',label:'START ENUMERATION',extra:null,msg:()=>{document.getElementById('dir-res').innerHTML='<div class="card"><p style="color:var(--m)">&#9888; Scan cancelled.</p></div>';}},
    bf:{btnId:'bf-btn',label:'START BRUTE FORCE',extra:null,msg:()=>{document.getElementById('bf-res').innerHTML='<div class="card"><p style="color:var(--m)">&#9888; Scan cancelled.</p></div>';}},
    disc:{btnId:'disc-btn',label:'DISCOVER',extra:null,msg:()=>{document.getElementById('disc-res').innerHTML='<div class="card"><p style="color:var(--m)">&#9888; Scan cancelled.</p></div>';}},
  };
  const cfg=map[key];if(!cfg)return;
  if(_scanControllers[key])try{_scanControllers[key].abort();}catch(e){}
  const btn=document.getElementById(cfg.btnId);
  _endScan(key,cfg.btnId,btn,cfg.label);
  if(cfg.extra)cfg.extra();
  if(cfg.msg)cfg.msg();
}
function _mergeSignals(...signals){
  const ctrl=new AbortController();
  for(const s of signals){
    if(!s)continue;
    if(s.aborted){ctrl.abort();break;}
    s.addEventListener('abort',()=>ctrl.abort(),{once:true});
  }
  return ctrl.signal;
}
async function fetchWithTimeout(url,options={},timeoutMs=300000,cancelSignal=null){
  const timerCtrl=new AbortController();
  const timer=setTimeout(()=>timerCtrl.abort(),timeoutMs);
  const sig=cancelSignal?_mergeSignals(timerCtrl.signal,cancelSignal):timerCtrl.signal;
  try{
    const r=await fetch(url,{...options,signal:sig});
    clearTimeout(timer);return r;
  }catch(e){
    clearTimeout(timer);
    if(e.name==='AbortError'){
      if(cancelSignal&&cancelSignal.aborted)throw new Error('cancelled');
      throw new Error('Request timed out after '+Math.round(timeoutMs/1000)+'s.');
    }
    throw e;
  }
}'''

patch(old_fetch, new_fetch, "JS: cancel infrastructure + fetchWithTimeout")

# ── 4. Patch each scan function to use _startScan / _endScan / cancelSignal ──

# doScan
patch(
    'async function doScan(){const target=document.getElementById("tgt").value.trim();if(!target||busy)return;clrUI();busy=true;initLog();startProg();const btn=document.getElementById("sbtn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';const ml=Object.keys(mods).filter(m=>mods[m]).join(",");lg("Target: "+target);lg("Modules: "+ml);lg("Scanning — may take 60–180 seconds","w");try{const r=await fetchWithTimeout("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(ml),{},300000);',
    'async function doScan(){const target=document.getElementById("tgt").value.trim();if(!target||busy)return;clrUI();busy=true;initLog();startProg();const btn=document.getElementById("sbtn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';const _ctrl=_startScan(\'sbtn\',\'sbtn\');const ml=Object.keys(mods).filter(m=>mods[m]).join(",");lg("Target: "+target);lg("Modules: "+ml);lg("Scanning — may take 60–180 seconds","w");try{const r=await fetchWithTimeout("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(ml),{},300000,_ctrl.signal);',
    "JS: doScan - add _startScan + cancelSignal"
)
patch(
    'if(d.error){showErr(d.error);lg(d.error,"e");}else{lg("Done — "+(d.summary?.open_ports||0)+" ports, "+(d.summary?.total_cves||0)+" CVEs","s");renderScan(d);}}catch(e){endProg();showErr(e.message);}finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}}',
    'if(d.error){showErr(d.error);lg(d.error,"e");}else{lg("Done — "+(d.summary?.open_ports||0)+" ports, "+(d.summary?.total_cves||0)+" CVEs","s");renderScan(d);}}catch(e){endProg();if(e.message!==\'cancelled\')showErr(e.message);}finally{_endScan(\'sbtn\',\'sbtn\',btn,\'SCAN\');busy=false;}}',
    "JS: doScan - _endScan in finally"
)

# doHarvest
patch(
    'const btn=document.getElementById("hv-btn");btn.disabled=true;btn.textContent="Running...";hvLogEl=document.getElementById("hv-term");hvLogEl.innerHTML="";hvLogEl.style.display="block";document.getElementById("hv-err").style.display="none";document.getElementById("hv-res").style.display="none";hvStartProg();hvLog("Target: "+target);hvLog("Sources: "+sources);hvLog("Launching theHarvester...","w");try{const r=await fetchWithTimeout("/harvester",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,sources,limit:parseInt(limit)})},180000);',
    'const btn=document.getElementById("hv-btn");btn.disabled=true;btn.textContent="Running...";const _ctrl=_startScan(\'hv\',\'hv-btn\');hvLogEl=document.getElementById("hv-term");hvLogEl.innerHTML="";hvLogEl.style.display="block";document.getElementById("hv-err").style.display="none";document.getElementById("hv-res").style.display="none";hvStartProg();hvLog("Target: "+target);hvLog("Sources: "+sources);hvLog("Launching theHarvester...","w");try{const r=await fetchWithTimeout("/harvester",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,sources,limit:parseInt(limit)})},180000,_ctrl.signal);',
    "JS: doHarvest - add _startScan + cancelSignal"
)
patch(
    'document.getElementById("hv-err").textContent="Error: "+e.message;document.getElementById("hv-err").style.display="block";hvLog(e.message,"e");}finally{btn.disabled=false;btn.textContent="🎯 RUN HARVESTER";}}',
    'if(e.message!==\'cancelled\'){document.getElementById("hv-err").textContent="Error: "+e.message;document.getElementById("hv-err").style.display="block";hvLog(e.message,"e");}else{hvEndProg();}finally{_endScan(\'hv\',\'hv-btn\',btn,\'&#127919; RUN HARVESTER\');}}',
    "JS: doHarvest - _endScan in finally"
)

# doDnsRecon
patch(
    'const btn=document.getElementById("dr-btn");btn.disabled=true;btn.textContent="Running...";drTool.start();drTool.log("Target: "+target);drTool.log("Type: "+type);try{const r=await fetchWithTimeout("/dnsrecon",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,type,ns,filter})},120000);',
    'const btn=document.getElementById("dr-btn");btn.disabled=true;btn.textContent="Running...";const _ctrl=_startScan(\'dr\',\'dr-btn\');drTool.start();drTool.log("Target: "+target);drTool.log("Type: "+type);try{const r=await fetchWithTimeout("/dnsrecon",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,type,ns,filter})},120000,_ctrl.signal);',
    "JS: doDnsRecon - add _startScan + cancelSignal"
)
patch(
    '}catch(e){drTool.end();drTool.err(e.message);}finally{btn.disabled=false;btn.textContent="🌐 RUN DNSRECON";}}',
    '}catch(e){drTool.end();if(e.message!==\'cancelled\')drTool.err(e.message);}finally{_endScan(\'dr\',\'dr-btn\',btn,\'&#127760; RUN DNSRECON\');}}',
    "JS: doDnsRecon - _endScan in finally"
)

# doNikto
patch(
    'const btn=document.getElementById("nk-btn");btn.disabled=true;btn.textContent="Scanning...";nkTool.start();nkTool.log("Target: "+target+" port "+port);nkTool.log("Nikto scan started","w");try{const r=await fetchWithTimeout("/nikto",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,port:parseInt(port),ssl,tuning})},600000);',
    'const btn=document.getElementById("nk-btn");btn.disabled=true;btn.textContent="Scanning...";const _ctrl=_startScan(\'nk\',\'nk-btn\');nkTool.start();nkTool.log("Target: "+target+" port "+port);nkTool.log("Nikto scan started","w");try{const r=await fetchWithTimeout("/nikto",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,port:parseInt(port),ssl,tuning})},600000,_ctrl.signal);',
    "JS: doNikto - add _startScan + cancelSignal"
)
patch(
    '}catch(e){nkTool.end();nkTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📈 RUN NIKTO";}}',
    '}catch(e){nkTool.end();if(e.message!==\'cancelled\')nkTool.err(e.message);}finally{_endScan(\'nk\',\'nk-btn\',btn,\'&#128200; RUN NIKTO\');}}',
    "JS: doNikto - _endScan in finally"
)

# doWPScan
patch(
    'const btn=document.getElementById("wp-btn");btn.disabled=true;btn.textContent="Scanning...";wpTool.start();wpTool.log("Target: "+target);try{const r=await fetchWithTimeout("/wpscan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,enum_flags:enumFlags,token,mode})},300000);',
    'const btn=document.getElementById("wp-btn");btn.disabled=true;btn.textContent="Scanning...";const _ctrl=_startScan(\'wp\',\'wp-btn\');wpTool.start();wpTool.log("Target: "+target);try{const r=await fetchWithTimeout("/wpscan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,enum_flags:enumFlags,token,mode})},300000,_ctrl.signal);',
    "JS: doWPScan - add _startScan + cancelSignal"
)
patch(
    '}catch(e){wpTool.end();wpTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📄 RUN WPSCAN";}}',
    '}catch(e){wpTool.end();if(e.message!==\'cancelled\')wpTool.err(e.message);}finally{_endScan(\'wp\',\'wp-btn\',btn,\'&#128196; RUN WPSCAN\');}}',
    "JS: doWPScan - _endScan in finally"
)

# doLynis
patch(
    'const btn=document.getElementById("ly-btn");btn.disabled=true;btn.textContent="Auditing...";lyTool.start();lyTool.log("Lynis audit starting...");lyTool.log("Profile: "+profile,"w");try{const r=await fetchWithTimeout("/lynis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({profile,category,compliance})},300000);',
    'const btn=document.getElementById("ly-btn");btn.disabled=true;btn.textContent="Auditing...";const _ctrl=_startScan(\'ly\',\'ly-btn\');lyTool.start();lyTool.log("Lynis audit starting...");lyTool.log("Profile: "+profile,"w");try{const r=await fetchWithTimeout("/lynis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({profile,category,compliance})},300000,_ctrl.signal);',
    "JS: doLynis - add _startScan + cancelSignal"
)
patch(
    '}catch(e){lyTool.end();lyTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📋 RUN LYNIS AUDIT";}}',
    '}catch(e){lyTool.end();if(e.message!==\'cancelled\')lyTool.err(e.message);}finally{_endScan(\'ly\',\'ly-btn\',btn,\'&#128203; RUN LYNIS AUDIT\');}}',
    "JS: doLynis - _endScan in finally"
)

# doLegion
patch(
    'const btn=document.getElementById("lg-btn");btn.disabled=true;btn.textContent="Running...";lgTool.start();lgTool.log("Target: "+target);lgTool.log("Modules: "+modules.join(", "));lgTool.log("Intensity: "+intensity,"w");try{const r=await fetchWithTimeout("/legion",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,intensity,modules})},900000);',
    'const btn=document.getElementById("lg-btn");btn.disabled=true;btn.textContent="Running...";const _ctrl=_startScan(\'lg\',\'lg-btn\');lgTool.start();lgTool.log("Target: "+target);lgTool.log("Modules: "+modules.join(", "));lgTool.log("Intensity: "+intensity,"w");try{const r=await fetchWithTimeout("/legion",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,intensity,modules})},900000,_ctrl.signal);',
    "JS: doLegion - add _startScan + cancelSignal"
)
patch(
    '}catch(e){lgTool.end();lgTool.err(e.message);}finally{btn.disabled=false;btn.textContent="⚙ RUN LEGION";}}',
    '}catch(e){lgTool.end();if(e.message!==\'cancelled\')lgTool.err(e.message);}finally{_endScan(\'lg\',\'lg-btn\',btn,\'&#9881; RUN LEGION\');}}',
    "JS: doLegion - _endScan in finally"
)

# doSub
patch(
    'const btn=document.getElementById("sub-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating subdomains for <b style="color:var(--cyan)">${domain}</b>...</p></div>`;try{const r=await fetchWithTimeout("/subdomains?domain="+encodeURIComponent(domain)+"&size="+size,{},120000);',
    'const btn=document.getElementById("sub-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';const _ctrl=_startScan(\'sub\',\'sub-btn\');document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating subdomains for <b style="color:var(--cyan)">${domain}</b>...</p></div>`;try{const r=await fetchWithTimeout("/subdomains?domain="+encodeURIComponent(domain)+"&size="+size,{},120000,_ctrl.signal);',
    "JS: doSub - add _startScan + cancelSignal"
)
patch(
    '}catch(e){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="FIND SUBDOMAINS";}}',
    '}catch(e){if(e.message!==\'cancelled\')document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{_endScan(\'sub\',\'sub-btn\',btn,\'FIND SUBDOMAINS\');}}',
    "JS: doSub - _endScan in finally"
)

# doDir
patch(
    'const btn=document.getElementById("dir-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating directories on <b style="color:var(--cyan)">${url}</b>...</p></div>`;try{const r=await fetchWithTimeout("/dirbust?url="+encodeURIComponent(url)+"&size="+size+"&ext="+encodeURIComponent(ext),{},180000);',
    'const btn=document.getElementById("dir-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';const _ctrl=_startScan(\'dir\',\'dir-btn\');document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating directories on <b style="color:var(--cyan)">${url}</b>...</p></div>`;try{const r=await fetchWithTimeout("/dirbust?url="+encodeURIComponent(url)+"&size="+size+"&ext="+encodeURIComponent(ext),{},180000,_ctrl.signal);',
    "JS: doDir - add _startScan + cancelSignal"
)
patch(
    '}catch(e){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="START ENUMERATION";}}',
    '}catch(e){if(e.message!==\'cancelled\')document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{_endScan(\'dir\',\'dir-btn\',btn,\'START ENUMERATION\');}}',
    "JS: doDir - _endScan in finally"
)

# doBrute
patch(
    'const btn=document.getElementById("bf-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>ATTACKING...\';document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Running — ${users.length} users × ${pwds.length} passwords...</p></div>`;try{let url="/brute-http",body={users,passwords:pwds};',
    'const btn=document.getElementById("bf-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>ATTACKING...\';const _ctrl=_startScan(\'bf\',\'bf-btn\');document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Running — ${users.length} users × ${pwds.length} passwords...</p></div>`;try{let url="/brute-http",body={users,passwords:pwds};',
    "JS: doBrute - add _startScan"
)
patch(
    'const r=await fetchWithTimeout(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)},120000);',
    'const r=await fetchWithTimeout(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)},120000,_ctrl.signal);',
    "JS: doBrute - add cancelSignal to fetchWithTimeout"
)
patch(
    '}catch(e){document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="START BRUTE FORCE";}}',
    '}catch(e){if(e.message!==\'cancelled\')document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{_endScan(\'bf\',\'bf-btn\',btn,\'START BRUTE FORCE\');}}',
    "JS: doBrute - _endScan in finally"
)

# doDisc
patch(
    'const btn=document.getElementById("disc-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--m)">Scanning subnet...</p></div>`;try{const r=await fetchWithTimeout("/discover?subnet="+encodeURIComponent(subnet),{},120000);',
    'const btn=document.getElementById("disc-btn");btn.disabled=true;btn.innerHTML=\'<span class="spin"></span>SCANNING...\';const _ctrl=_startScan(\'disc\',\'disc-btn\');document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--m)">Scanning subnet...</p></div>`;try{const r=await fetchWithTimeout("/discover?subnet="+encodeURIComponent(subnet),{},120000,_ctrl.signal);',
    "JS: doDisc - add _startScan + cancelSignal"
)
patch(
    '}catch(e){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="DISCOVER";}}',
    '}catch(e){if(e.message!==\'cancelled\')document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${e.message}</p></div>`;}finally{_endScan(\'disc\',\'disc-btn\',btn,\'DISCOVER\');}}',
    "JS: doDisc - _endScan in finally"
)

# ── Write result ──────────────────────────────────────────────────────────────
if errors:
    print(f"\n[!] {len(errors)} patches failed:")
    for e in errors:
        print(e)
    print(f"\n[!] Restoring backup...")
    shutil.copy2(BAK, SRC)
    print(f"[!] Backup restored. No changes applied.")
    sys.exit(1)
else:
    with open(SRC, "w") as f:
        f.write(c)
    print(f"\n[+] All patches applied successfully!")
    print(f"[+] {SRC} updated. Backup at {BAK}")
    print(f"[+] Restart the server: python3 api_server.py")
