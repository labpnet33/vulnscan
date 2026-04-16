#!/usr/bin/env python3
"""
Patch 01: Legion SMB/SNMP/Hydra + SearchSploit formatting
Run: python3 patch_01_legion_searchsploit.py
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
    shutil.copy2(path, f"{path}.{ts}.p01.bak")

def patch(path, label, old, new):
    if not os.path.isfile(path):
        fail(f"{label} — file not found: {path}"); RESULTS["failed"]+=1; return False
    with open(path,"r",encoding="utf-8",errors="ignore") as f: src=f.read()
    if old not in src:
        if new.strip()[:80] in src: print(f"  \033[2m·{RESET}  {label} (already applied)"); RESULTS["skipped"]+=1; return False
        fail(f"{label} — anchor not found"); RESULTS["failed"]+=1; return False
    backup(path)
    with open(path,"w",encoding="utf-8") as f: f.write(src.replace(old,new,1))
    ok(label); RESULTS["applied"]+=1; return True

# ── PATCH 1A: Legion route — add SMB/SNMP/Hydra support ──────────────────────

OLD_LEGION = '''@app.route("/legion", methods=["POST"])
def legion_route():
    import shutil

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    intensity = data.get("intensity", "normal")
    modules = data.get("modules", ["nmap", "nikto"])

    if not target:
        return jsonify({"error": "No target specified"})

    _lg_user = get_current_user()
    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_SCAN", target=target, ip=request.remote_addr,
          details=f"intensity={intensity};modules={','.join(modules)}")

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0

    # Timing map adjusted for Tor
    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T2"}[intensity]

    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({
                "module": mod,
                "summary": f"{mod} not found — install: sudo apt install {mod}",
                "findings": []
            })
            continue

        modules_run += 1
        findings = []

        try:
            if mod == "nmap":
                # nmap through proxychains
                cmd = [
                    px, "-q", "nmap",
                    "-sT", "-Pn", "-n",    # TCP connect, no ping, no DNS
                    speed,
                    "--open",
                    "--host-timeout", "180s",
                    "--max-retries", "1",
                    "--top-ports", "100",
                    "-sV", "--version-intensity", "2",
                    target
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in proc.stdout.splitlines():
                    m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
                    if m:
                        open_ports += 1
                        findings.append({
                            "title": f"Port {m.group(1)} open",
                            "detail": f"{m.group(2)} {m.group(3)}".strip()
                        })

            elif mod == "nikto":
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
                    findings.append({"title": f"{mod} output", "detail": proc.stdout[:500]})

        except subprocess.TimeoutExpired:
            findings.append({"title": f"{mod} timed out (Tor is slow)", "detail": ""})
        except Exception as e:
            findings.append({"title": f"{mod} error", "detail": str(e)})

        results.append({
            "module": mod,
            "findings": findings,
            "summary": f"{len(findings)} findings"
        })

    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_RESULT", target=target, ip=request.remote_addr,
          details=f"open_ports={open_ports};issues={total_issues};modules_run={modules_run}")
    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "All modules ran through Tor/proxychains."
    })'''

NEW_LEGION = '''@app.route("/legion", methods=["POST"])
def legion_route():
    import shutil as _lg_shutil, re as _lg_re

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    intensity = data.get("intensity", "normal")
    modules = data.get("modules", ["nmap", "nikto"])

    if not target:
        return jsonify({"error": "No target specified"})

    _lg_user = get_current_user()
    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_SCAN", target=target, ip=request.remote_addr,
          details=f"intensity={intensity};modules={','.join(modules)}")

    px = proxychains_cmd()
    results, open_ports, total_issues, modules_run = [], 0, 0, 0
    speed = {"light": "-T1", "normal": "-T2", "aggressive": "-T3"}[intensity]

    # Discover open ports once for SMB/SNMP targeting
    _discovered_ports = []
    try:
        _np = subprocess.run(
            [px, "-q", "nmap", "-sT", "-Pn", "-n", "--open", "-T2",
             "--top-ports", "200", "-oG", "-", target],
            capture_output=True, text=True, timeout=120
        )
        for _ln in _np.stdout.splitlines():
            for _pm in re.findall(r"(\d+)/open", _ln):
                _discovered_ports.append(int(_pm))
    except Exception:
        pass

    _smb_port_open = any(p in _discovered_ports for p in [139, 445])
    _snmp_target = target

    for mod in modules:
        modules_run += 1
        findings = []

        try:
            # ── nmap ──────────────────────────────────────────────────────────
            if mod == "nmap":
                cmd = [px, "-q", "nmap", "-sT", "-Pn", "-n", "--open",
                       speed, "--host-timeout", "180s", "--max-retries", "1",
                       "--top-ports", "200", "-sV", "--version-intensity", "2", target]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in proc.stdout.splitlines():
                    m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
                    if m:
                        open_ports += 1
                        findings.append({"title": f"Port {m.group(1)} open",
                                         "detail": f"{m.group(2)} {m.group(3)}".strip()})

            # ── nikto ─────────────────────────────────────────────────────────
            elif mod == "nikto":
                binary = _lg_shutil.which("nikto")
                if not binary:
                    findings.append({"title": "nikto not installed",
                                     "detail": "sudo apt install nikto"})
                else:
                    cmd = [px, "-q", binary, "-h", target, "-nointeractive",
                           "-timeout", "30", "-maxtime", "600"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=700)
                    for line in proc.stdout.splitlines():
                        if line.strip().startswith("+"):
                            findings.append({"title": line.strip()[2:120], "detail": ""})
                            total_issues += 1

            # ── smb ───────────────────────────────────────────────────────────
            elif mod == "smb":
                smbclient = _lg_shutil.which("smbclient")
                enum4linux = _lg_shutil.which("enum4linux")
                nmap_bin   = _lg_shutil.which("nmap")

                # smbclient share enumeration
                if smbclient:
                    try:
                        cmd = [px, "-q", smbclient, "-L", f"//{target}", "-N",
                               "--option=client min protocol=SMB2"]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        out = proc.stdout + proc.stderr
                        for line in out.splitlines():
                            ln = line.strip()
                            if ln and not ln.startswith("Anonymous") and not ln.startswith("Sharename"):
                                if any(k in ln for k in ["Disk", "IPC$", "ADMIN$", "print$", "homes"]):
                                    findings.append({"title": f"SMB Share: {ln[:80]}", "detail": "smbclient"})
                                    total_issues += 1
                        if not findings:
                            findings.append({"title": f"SMB probe completed",
                                             "detail": out[:200] or "No shares enumerated"})
                    except Exception as e:
                        findings.append({"title": "smbclient error", "detail": str(e)[:100]})
                elif enum4linux:
                    try:
                        proc = subprocess.run([enum4linux, "-a", target],
                                              capture_output=True, text=True, timeout=90)
                        for line in proc.stdout.splitlines():
                            if any(k in line for k in ["Share", "User", "Group", "Policy"]):
                                findings.append({"title": line.strip()[:100], "detail": "enum4linux"})
                                total_issues += 1
                    except Exception as e:
                        findings.append({"title": "enum4linux error", "detail": str(e)[:100]})
                elif nmap_bin:
                    try:
                        cmd = [px, "-q", nmap_bin, "-sT", "-Pn", "-n",
                               "-p", "139,445", "--script", "smb-enum-shares,smb-security-mode",
                               "--script-timeout", "30s", target]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        for line in proc.stdout.splitlines():
                            ln = line.strip()
                            if ln and "|" in ln:
                                findings.append({"title": ln[:100], "detail": "nmap smb-scripts"})
                                total_issues += 1
                        if not findings:
                            findings.append({"title": "SMB nmap scan complete",
                                             "detail": proc.stdout[:300] or "No SMB findings"})
                    except Exception as e:
                        findings.append({"title": "nmap smb error", "detail": str(e)[:100]})
                else:
                    findings.append({"title": "SMB tools not found",
                                     "detail": "Install: sudo apt install smbclient"})

            # ── snmp ──────────────────────────────────────────────────────────
            elif mod == "snmp":
                snmpwalk  = _lg_shutil.which("snmpwalk")
                snmpcheck = _lg_shutil.which("snmp-check")
                nmap_bin  = _lg_shutil.which("nmap")

                community_strings = ["public", "private", "manager", "community"]
                snmp_found = False

                if snmpwalk:
                    for community in community_strings:
                        try:
                            cmd = [snmpwalk, "-v", "2c", "-c", community,
                                   "-t", "5", "-r", "1", _snmp_target, "system"]
                            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                            if proc.returncode == 0 and proc.stdout.strip():
                                findings.append({"title": f"SNMP community '{community}' ACCESSIBLE",
                                                 "detail": proc.stdout[:300]})
                                total_issues += 1
                                snmp_found = True
                                # Get more info
                                for oid in ["ifDescr", "hrSystemUptime", "sysDescr"]:
                                    try:
                                        p2 = subprocess.run(
                                            [snmpwalk, "-v", "2c", "-c", community,
                                             "-t", "3", "-r", "1", _snmp_target, oid],
                                            capture_output=True, text=True, timeout=15)
                                        if p2.stdout.strip():
                                            findings.append({"title": f"SNMP {oid}",
                                                             "detail": p2.stdout[:200]})
                                    except Exception:
                                        pass
                                break
                        except Exception:
                            pass
                    if not snmp_found:
                        findings.append({"title": "SNMP — no accessible community strings",
                                         "detail": f"Tested: {', '.join(community_strings)}"})
                elif snmpcheck:
                    try:
                        proc = subprocess.run([snmpcheck, "-t", _snmp_target],
                                              capture_output=True, text=True, timeout=60)
                        for line in proc.stdout.splitlines():
                            if line.strip():
                                findings.append({"title": line.strip()[:100], "detail": "snmp-check"})
                    except Exception as e:
                        findings.append({"title": "snmp-check error", "detail": str(e)[:100]})
                elif nmap_bin:
                    try:
                        cmd = [px, "-q", nmap_bin, "-sU", "-p", "161", "--open",
                               "--script", "snmp-info,snmp-sysdescr", "--script-timeout", "20s",
                               "-T2", _snmp_target]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                        for line in proc.stdout.splitlines():
                            ln = line.strip()
                            if ln and "|" in ln:
                                findings.append({"title": ln[:100], "detail": "nmap snmp-scripts"})
                                total_issues += 1
                        if not findings:
                            findings.append({"title": "SNMP nmap scan complete",
                                             "detail": proc.stdout[:300] or "No SNMP findings"})
                    except Exception as e:
                        findings.append({"title": "nmap snmp error", "detail": str(e)[:100]})
                else:
                    findings.append({"title": "SNMP tools not found",
                                     "detail": "Install: sudo apt install snmp"})

            # ── hydra ─────────────────────────────────────────────────────────
            elif mod == "hydra":
                hydra = _lg_shutil.which("hydra")
                if not hydra:
                    findings.append({"title": "hydra not found",
                                     "detail": "sudo apt install hydra"})
                else:
                    # Find a usable service to test
                    service_map = {22: "ssh", 21: "ftp", 80: "http-get",
                                   110: "pop3", 143: "imap", 23: "telnet"}
                    hydra_service = None
                    hydra_port = None
                    for port, svc in service_map.items():
                        if port in _discovered_ports:
                            hydra_service = svc
                            hydra_port = port
                            break
                    if not hydra_service:
                        hydra_service = "ssh"
                        hydra_port = 22

                    # Use a very small wordlist for safety in Legion mode
                    test_users = ["admin", "root", "administrator", "user"]
                    test_passes = ["admin", "password", "123456", "root", "admin123"]

                    import tempfile as _tf
                    with _tf.NamedTemporaryFile(mode="w", suffix=".u", delete=False) as uf:
                        uf.write("\n".join(test_users)); upath = uf.name
                    with _tf.NamedTemporaryFile(mode="w", suffix=".p", delete=False) as pf:
                        pf.write("\n".join(test_passes)); ppath = pf.name
                    try:
                        cmd = [hydra, "-L", upath, "-P", ppath,
                               "-t", "4", "-w", "3", "-f",
                               f"{target}", f"{hydra_service}"]
                        if hydra_port not in [22, 21]:
                            cmd = [hydra, "-L", upath, "-P", ppath,
                                   "-t", "4", "-w", "3", "-f",
                                   "-s", str(hydra_port), target, hydra_service]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                        out = proc.stdout + proc.stderr
                        found_creds = []
                        for line in out.splitlines():
                            if "[" in line and "]" in line and ("login:" in line or "host:" in line):
                                found_creds.append(line.strip())
                                total_issues += 1
                        if found_creds:
                            for cred in found_creds:
                                findings.append({"title": f"CREDENTIAL FOUND: {cred[:100]}",
                                                 "detail": f"Service: {hydra_service}"})
                        else:
                            findings.append({"title": f"Hydra: No default creds on {hydra_service}",
                                             "detail": f"Tested {len(test_users)}u x {len(test_passes)}p"})
                    except subprocess.TimeoutExpired:
                        findings.append({"title": "Hydra timed out", "detail": f"service={hydra_service}"})
                    except Exception as e:
                        findings.append({"title": "Hydra error", "detail": str(e)[:100]})
                    finally:
                        for p in [upath, ppath]:
                            try: os.unlink(p)
                            except Exception: pass

            # ── finger ────────────────────────────────────────────────────────
            elif mod == "finger":
                finger = _lg_shutil.which("finger")
                if not finger:
                    # Try nmap finger script
                    nmap_bin = _lg_shutil.which("nmap")
                    if nmap_bin:
                        try:
                            cmd = [px, "-q", nmap_bin, "-sT", "-Pn", "-n",
                                   "-p", "79", "--open", "--script", "finger",
                                   "--script-timeout", "15s", target]
                            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                            for line in proc.stdout.splitlines():
                                ln = line.strip()
                                if ln and ("|" in ln or "Login" in ln):
                                    findings.append({"title": ln[:100], "detail": "nmap finger"})
                        except Exception as e:
                            findings.append({"title": "finger error", "detail": str(e)[:100]})
                    else:
                        findings.append({"title": "finger not available", "detail": "Port 79 check skipped"})
                else:
                    try:
                        for query in ["root", "admin", "@"]:
                            proc = subprocess.run([finger, f"{query}@{target}"],
                                                  capture_output=True, text=True, timeout=15)
                            if proc.stdout.strip():
                                findings.append({"title": f"finger {query}@{target}",
                                                 "detail": proc.stdout[:200]})
                                total_issues += 1
                    except Exception as e:
                        findings.append({"title": "finger error", "detail": str(e)[:100]})

            else:
                # Generic fallback
                binary = _lg_shutil.which(mod) or _lg_shutil.which(mod.lower())
                if not binary:
                    findings.append({"title": f"{mod} not installed",
                                     "detail": f"sudo apt install {mod}"})
                else:
                    try:
                        proc = subprocess.run([px, "-q", binary, target],
                                              capture_output=True, text=True, timeout=180)
                        if proc.stdout.strip():
                            findings.append({"title": f"{mod} output",
                                             "detail": proc.stdout[:500]})
                    except subprocess.TimeoutExpired:
                        findings.append({"title": f"{mod} timed out", "detail": ""})
                    except Exception as e:
                        findings.append({"title": f"{mod} error", "detail": str(e)[:100]})

        except subprocess.TimeoutExpired:
            findings.append({"title": f"{mod} timed out", "detail": "Tor is slow — try light intensity"})
        except Exception as e:
            findings.append({"title": f"{mod} error", "detail": str(e)[:120]})

        results.append({"module": mod, "findings": findings,
                         "summary": f"{len(findings)} findings"})

    audit(_lg_user["id"] if _lg_user else None,
          _lg_user["username"] if _lg_user else "anon",
          "LEGION_RESULT", target=target, ip=request.remote_addr,
          details=f"open_ports={open_ports};issues={total_issues};modules_run={modules_run}")
    return jsonify({
        "target": target,
        "open_ports": open_ports,
        "total_issues": total_issues,
        "modules_run": modules_run,
        "results": results,
        "note": "Modules ran via Tor/proxychains. SMB/SNMP/Hydra use native tools."
    })'''

# ── PATCH 1B: SearchSploit — strip ANSI codes from output ────────────────────

OLD_SS = '''async function runSearchsploit(){
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
}'''

NEW_SS = '''function _stripAnsi(str){
  // Remove ANSI escape codes (colors, bold, etc.)
  return (str||'').replace(/\x1B\[[0-9;]*[mGKHF]/g,'').replace(/\x1B\[[\d;]*[A-Za-z]/g,'');
}
function _parseSearchsploitOutput(raw){
  var clean=_stripAnsi(raw);
  // Try to parse table format into rows
  var lines=clean.split('\n');
  var rows=[];
  var inTable=false;
  var separator=/^[-=+|─]+$/;
  for(var i=0;i<lines.length;i++){
    var line=lines[i];
    if(line.match(/^\s*[-─═]+/)){inTable=true;continue;}
    if(!line.trim())continue;
    // Detect exploit rows: EDB-ID at end or pipe-separated
    var pipeMatch=line.match(/^\s*(.+?)\s+\|\s+([\w/.\-]+)\s*$/);
    if(pipeMatch){
      rows.push({title:pipeMatch[1].trim(),path:pipeMatch[2].trim()});
    } else if(line.match(/^\s*Exploit Title/i)||line.match(/^-+/)){
      // header/separator — skip
    } else if(inTable&&line.trim().length>5){
      rows.push({title:line.trim(),path:''});
    }
  }
  return {clean:clean,rows:rows};
}
function _renderSearchsploitResults(raw,query){
  var parsed=_parseSearchsploitOutput(raw);
  if(!parsed.rows.length){
    // Just show cleaned plain text
    return '<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Search Results</div>'
      +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'
      +(parsed.clean||'No exploits found for: '+query)+'</pre></div>';
  }
  var html='<div class="stats" style="margin-bottom:12px">'
    +'<div class="stat"><div class="stat-val">'+parsed.rows.length+'</div><div class="stat-lbl">EXPLOITS</div></div>'
    +'</div>';
  html+='<div class="card" style="margin-bottom:10px"><div class="card-header"><div class="card-title">Exploit Results</div>'
    +'<div style="font-size:11px;color:var(--text3)">Click an exploit for usage instructions</div></div>'
    +'<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>TITLE</th><th>PATH</th><th>ACTIONS</th></tr></thead><tbody>';
  parsed.rows.forEach(function(row,idx){
    var edbId=row.path.match(/(\d+)\./);
    var edbNum=edbId?edbId[1]:'';
    var nvdLink=edbNum?'https://www.exploit-db.com/exploits/'+edbNum:'https://www.exploit-db.com';
    var cat='unknown';
    if(row.path.indexOf('remote/')>=0)cat='remote';
    else if(row.path.indexOf('local/')>=0)cat='local';
    else if(row.path.indexOf('webapps/')>=0)cat='webapps';
    else if(row.path.indexOf('dos/')>=0)cat='dos';
    var catCol={'remote':'var(--red)','local':'var(--orange)','webapps':'var(--yellow)','dos':'var(--blue)','unknown':'var(--text3)'};
    html+='<tr>'
      +'<td style="font-family:var(--mono);color:var(--text3)">'+(idx+1)+'</td>'
      +'<td style="font-family:var(--mono);font-size:11px">'+row.title+'</td>'
      +'<td style="font-family:var(--mono);font-size:10px;color:var(--text3)">'+row.path+'</td>'
      +'<td style="white-space:nowrap">'
      +'<button class="btn btn-outline btn-sm" style="margin-right:4px;font-size:10px" '
        +'onclick="showExploitUsage(\''+row.title.replace(/'/g,"\\'").replace(/"/g,'&quot;')+'\',\''+row.path+'\',\''+edbNum+'\')">HOW TO USE</button>'
      +(edbNum?'<a class="btn btn-ghost btn-sm" style="font-size:10px" href="'+nvdLink+'" target="_blank">EDB ↗</a>':'')
      +'</td></tr>';
  });
  html+='</tbody></table></div></div>';
  // Also show raw cleaned output in collapsible
  html+='<details style="margin-top:8px"><summary style="font-family:var(--mono);font-size:11px;color:var(--text3);cursor:pointer">Show raw output</summary>'
    +'<div class="card card-p" style="margin-top:6px"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'
    +parsed.clean+'</pre></div></details>';
  return html;
}
function showExploitUsage(title,path,edbId){
  // Determine exploit type and build usage instructions
  var cat='unknown';
  if(path.indexOf('.py')>=0)cat='python';
  else if(path.indexOf('.rb')>=0)cat='ruby';
  else if(path.indexOf('.sh')>=0)cat='bash';
  else if(path.indexOf('.pl')>=0)cat='perl';
  else if(path.indexOf('.c')>=0)cat='c';
  else if(path.indexOf('.php')>=0)cat='php';
  var edbUrl=edbId?'https://www.exploit-db.com/exploits/'+edbId:'';
  var copyCmd='searchsploit -m '+path;
  var html='<div class="card card-p" style="margin-top:10px;border-left:3px solid var(--cyan)">'
    +'<div class="card-title" style="margin-bottom:10px;color:var(--cyan)">HOW TO USE — '+title+'</div>'
    +'<div style="font-size:12px;color:var(--text2);line-height:1.9">'
    +'<div class="sec-label">STEP 1 — Copy exploit to current directory</div>'
    +'<pre style="background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:11px;margin:4px 0 10px">'+copyCmd+'</pre>'
    +'<div class="sec-label">STEP 2 — Read the exploit header</div>'
    +'<pre style="background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:11px;margin:4px 0 10px">head -50 '+path.split('/').pop()+'</pre>'
    +'<div class="sec-label">STEP 3 — Run the exploit</div><pre style="background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:11px;margin:4px 0 10px">'
    +(cat==='python'?'python3 '+path.split('/').pop()+' <TARGET> [OPTIONS]'
    :cat==='ruby'?'ruby '+path.split('/').pop()+' <TARGET> [OPTIONS]'
    :cat==='bash'?'bash '+path.split('/').pop()+' [OPTIONS]'
    :cat==='c'?'gcc '+path.split('/').pop()+' -o exploit && ./exploit <TARGET>'
    :cat==='perl'?'perl '+path.split('/').pop()+' <TARGET>'
    :'./'+(path.split('/').pop()||'exploit')+' [OPTIONS]')+'</pre>'
    +(edbUrl?'<div style="margin-top:8px"><a class="btn btn-outline btn-sm" href="'+edbUrl+'" target="_blank">View on Exploit-DB ↗</a>'
      +' <a class="btn btn-ghost btn-sm" href="https://nvd.nist.gov/vuln/search/results?query='+encodeURIComponent(title)+'" target="_blank">Search NVD ↗</a></div>':'')
    +'<div style="margin-top:10px;background:rgba(255,214,10,0.08);border:1px solid rgba(255,214,10,0.3);border-radius:4px;padding:8px;font-size:11px;color:var(--yellow)">⚠ Authorized use only. Verify the exploit targets your exact version before running.</div>'
    +'</div></div>';
  var res=document.getElementById('searchsploit-res');
  if(res){
    // Append below existing results
    var existing=res.querySelector('.exploit-usage');
    if(existing)existing.remove();
    var div=document.createElement('div');div.className='exploit-usage';div.innerHTML=html;
    res.appendChild(div);div.scrollIntoView({behavior:'smooth'});
  }
}
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
    else{
      t.log('Search complete','s');
      var rendered=_renderSearchsploitResults(d.stdout||'',query);
      t.res(rendered);
    }
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}'''

print(f"\n{BOLD}{CYAN}Patch 01 — Legion SMB/SNMP/Hydra + SearchSploit formatting{RESET}\n")

patch("api_server.py","Legion: SMB/SNMP/Hydra/finger full module support",OLD_LEGION,NEW_LEGION)

# SearchSploit JS — find in HTML
with open("api_server.py","r",encoding="utf-8",errors="ignore") as f: src=f.read()
if OLD_SS in src:
    backup("api_server.py")
    with open("api_server.py","w",encoding="utf-8") as f: f.write(src.replace(OLD_SS,NEW_SS,1))
    ok("SearchSploit: ANSI strip + formatted table + HOW TO USE")
    RESULTS["applied"]+=1
elif NEW_SS[:60] in src:
    print(f"  \033[2m·{RESET}  SearchSploit formatting (already applied)")
    RESULTS["skipped"]+=1
else:
    fail("SearchSploit JS anchor not found — apply manually")
    RESULTS["failed"]+=1

print(f"\n  Applied:{GREEN}{RESULTS['applied']}{RESET}  Skipped:\033[2m{RESULTS['skipped']}{RESET}  Failed:{RED}{RESULTS['failed']}{RESET}\n")
