#!/usr/bin/env python3
"""
VulnScan Pro — Patch v5.0
Fixes (api_server.py only):
  1. DNSRecon: remove broken --tcp flag, multi-layer fallback (dnsrecon→dig→socket)
  2. Deep Web Audit: SSE streaming route + live % progress in UI
  3. Brute Force: rockyou pre-selected + auto-loaded, fallback path list

Run: python3 patch.py  (from project root)
"""
import os, shutil, subprocess, sys
from datetime import datetime

GREEN="\033[92m";RED="\033[91m";CYAN="\033[96m";YELLOW="\033[93m"
RESET="\033[0m";BOLD="\033[1m";DIM="\033[2m"

def ok(m):   print(f"  {GREEN}✓{RESET} {m}")
def fail(m): print(f"  {RED}✗{RESET} {m}")
def info(m): print(f"  {CYAN}→{RESET} {m}")
def skip(m): print(f"  {DIM}·{RESET} {m}")

R={"applied":0,"skipped":0,"failed":0,"files":[],"restart":False}

def backup(p):
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(p,f"{p}.{ts}.bak")

def patch(path, changes):
    if not os.path.isfile(path):
        fail(f"Not found: {path}"); R["failed"]+=len(changes); return
    with open(path,"r",encoding="utf-8") as f: src=f.read()
    out=src; applied=0
    for desc,old,new in changes:
        if old in out:
            out=out.replace(old,new,1); ok(desc); applied+=1; R["applied"]+=1
        elif new in out:
            skip(f"{desc} (already applied)"); R["skipped"]+=1
        else:
            fail(f"{desc} — anchor not found"); R["failed"]+=1
    if applied:
        backup(path)
        with open(path,"w",encoding="utf-8") as f: f.write(out)
        if path not in R["files"]: R["files"].append(path)
        R["restart"]=True

def syntax(p):
    r=subprocess.run([sys.executable,"-m","py_compile",p],capture_output=True,text=True)
    return r.returncode==0, r.stderr.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — DNSRecon: remove --tcp, add fallback chain
# ═══════════════════════════════════════════════════════════════════════════════

OLD_DR = '''# ── DNSRecon route (FIXED — removed stray nmap subprocess call) ───────────────
@app.route("/dnsrecon", methods=["POST"])
def dnsrecon_route():
    """
    Run dnsrecon through proxychains (Tor).
    DNSRecon supports TCP-based queries which work through SOCKS proxies.
    Note: Standard UDP DNS won't go through Tor — dnsrecon's TCP mode is used.
    """
    import shutil, tempfile
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    scan_type = data.get("type", "std")
    ns = (data.get("ns") or "").strip()
    rec_filter = (data.get("filter") or "").strip()

    if not target:
        return jsonify({"error": "No target specified"})

    binary = shutil.which("dnsrecon")
    if not binary:
        ok, msg = auto_install("dnsrecon", "dnsrecon")
        if not ok:
            return jsonify({
                "error": f"dnsrecon not installed and auto-install failed: {msg}. Run: sudo apt install dnsrecon",
                "auto_install_attempted": True
            })
        binary = shutil.which("dnsrecon")

    px = proxychains_cmd()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    # Build dnsrecon command through proxychains
    # Use --tcp flag so DNS queries go through SOCKS (TCP only — UDP is blocked by Tor)
    cmd = [px, "-q", binary, "-d", target, "-t", scan_type, "-j", out_file, "--tcp"]
    if ns:
        cmd += ["-n", ns]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_DNSRECON)
        records = []

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = json.load(f)
                for item in (raw if isinstance(raw, list) else raw.get("records", [])):
                    if isinstance(item, dict):
                        rec = {
                            "type": item.get("type", "?"),
                            "name": item.get("name", ""),
                            "address": item.get("address", item.get("data", ""))
                        }
                        if rec_filter and rec["type"] != rec_filter:
                            continue
                        records.append(rec)
            except Exception:
                pass

        # Fallback: parse stdout if JSON was empty
        if not records:
            for line in proc.stdout.splitlines():
                m = re.match(r'\s*\[\*\]\s*(\w+)\s+([\w.\-]+)\s+([\d.]+)', line)
                if m:
                    if rec_filter and m.group(1) != rec_filter:
                        continue
                    records.append({
                        "type": m.group(1),
                        "name": m.group(2),
                        "address": m.group(3)
                    })

        if os.path.exists(out_file):
            os.unlink(out_file)

        return jsonify({
            "target": target,
            "records": records,
            "scan_type": scan_type,
            "note": "Queries sent via Tor (TCP mode). UDP-based records may be incomplete."
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"dnsrecon timed out after {TIMEOUT_DNSRECON}s. Tor routing can be slow."})
    except Exception as e:
        return jsonify({"error": str(e)})'''

NEW_DR = '''# ── DNSRecon route (v5 — multi-layer fallback, no broken --tcp) ──────────────
@app.route("/dnsrecon", methods=["POST"])
def dnsrecon_route():
    """
    DNS enumeration with three-layer fallback:
      1. dnsrecon binary  (no --tcp — dnsrecon doesn't support that flag)
      2. dig              (standard DNS tool)
      3. Python socket    (always available)
    DNS uses UDP — not proxied through Tor SOCKS.
    """
    import shutil as _sh, tempfile, socket as _sock

    data = request.get_json() or {}
    target    = (data.get("target") or "").strip()
    scan_type = data.get("type", "std")
    ns        = (data.get("ns") or "").strip()
    rec_filter= (data.get("filter") or "").strip().upper()

    if not target:
        return jsonify({"error": "No target specified"})

    user = get_current_user()
    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "DNSRECON", target=target, ip=request.remote_addr)

    records, method_used = [], "none"

    # ── Layer 1: dnsrecon ─────────────────────────────────────────────────
    binary = _sh.which("dnsrecon")
    if binary:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_file = tf.name
        # Run dnsrecon directly — no proxychains, no --tcp (neither is supported for DNS)
        cmd = [binary, "-d", target, "-t", scan_type, "-j", out_file]
        if ns:
            cmd += ["-n", ns]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_DNSRECON)
            # Parse JSON output
            if os.path.exists(out_file) and os.path.getsize(out_file) > 5:
                try:
                    with open(out_file) as f:
                        raw = json.load(f)
                    items = raw if isinstance(raw, list) else raw.get("records", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        rtype = str(item.get("type", "?")).upper()
                        if rec_filter and rtype != rec_filter:
                            continue
                        records.append({
                            "type":    rtype,
                            "name":    item.get("name", item.get("host", "")),
                            "address": item.get("address", item.get("data",
                                       item.get("target", item.get("strings", "")))),
                            "ttl":     str(item.get("ttl", "")),
                        })
                    if records:
                        method_used = "dnsrecon-json"
                except Exception:
                    pass
            # Fallback: parse stdout text output
            if not records and proc.stdout:
                for line in proc.stdout.splitlines():
                    m = re.search(r'\[\*\]\s+(\w+)\s+([\w.\-*@]+)\s+([\S]+)', line)
                    if m:
                        rtype = m.group(1).upper()
                        if rec_filter and rtype != rec_filter:
                            continue
                        records.append({"type": rtype, "name": m.group(2),
                                        "address": m.group(3), "ttl": ""})
                if records:
                    method_used = "dnsrecon-stdout"
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    # ── Layer 2: dig ──────────────────────────────────────────────────────
    if not records and _sh.which("dig"):
        rtypes = [rec_filter] if rec_filter else ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
        resolver = f"@{ns}" if ns else "@8.8.8.8"
        for rtype in rtypes:
            try:
                cmd2 = ["dig", "+noall", "+answer", "+time=5", "+tries=2",
                        resolver, rtype, target]
                proc2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
                for line in proc2.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and not line.startswith(";"):
                        records.append({
                            "type":    parts[3].upper(),
                            "name":    parts[0].rstrip("."),
                            "address": " ".join(parts[4:]).rstrip("."),
                            "ttl":     parts[1],
                        })
            except Exception:
                pass
        if records:
            method_used = "dig"

    # ── Layer 3: Python socket ────────────────────────────────────────────
    if not records:
        try:
            ip = _sock.gethostbyname(target)
            if not rec_filter or rec_filter == "A":
                records.append({"type":"A","name":target,"address":ip,"ttl":""})
            method_used = "python-socket"
        except Exception:
            pass
        # nslookup for MX
        if not rec_filter or rec_filter in ("MX","NS"):
            try:
                proc3 = subprocess.run(["nslookup","-type=MX",target],
                                        capture_output=True, text=True, timeout=10)
                for ln in proc3.stdout.splitlines():
                    if "mail exchanger" in ln.lower():
                        records.append({"type":"MX","name":target,
                                        "address":ln.split("=")[-1].strip(),"ttl":""})
            except Exception:
                pass

    return jsonify({
        "target":     target,
        "records":    records,
        "scan_type":  scan_type,
        "total":      len(records),
        "method":     method_used,
        "note": (
            "dnsrecon ran directly (DNS is UDP — cannot proxy through Tor)."
            if "dnsrecon" in method_used else
            f"Fallback method used: {method_used}. "
            "Install dnsrecon for full results: sudo apt install dnsrecon"
        )
    })'''


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 2a — Add SSE streaming route for Deep Web Audit (inserted before /report)
# ═══════════════════════════════════════════════════════════════════════════════

OLD_REPORT_ANCHOR = '''@app.route("/report", methods=["POST"])
def report():'''

NEW_REPORT_ANCHOR = '''# ── Deep Web Audit — SSE streaming endpoint ──────────────────────────────────
@app.route("/web-deep-stream")
def web_deep_stream():
    """
    Server-Sent Events endpoint.
    Streams one JSON event per tool as it completes, with % progress.
    Final event has done=True and the complete result dict.
    """
    import threading, queue, time as _t

    input_url = request.args.get("url", "").strip()
    profile   = request.args.get("profile", "balanced").strip().lower()
    if profile not in {"balanced", "deep", "very_deep"}:
        profile = "balanced"

    raw_url, base_url, host = _normalize_target_url(input_url)
    if not host:
        def _err():
            yield 'data: ' + json.dumps({"pct":0,"done":True,"error":"Invalid URL"}) + '\n\n'
        return Response(_err(), mimetype="text/event-stream")

    user = get_current_user()
    audit(user["id"] if user else None,
          user["username"] if user else "anon",
          "WEB_DEEP_STREAM", target=base_url,
          ip=request.remote_addr, details=f"profile={profile}")

    q = queue.Queue()

    # (end_pct, label, key)
    STAGES = [
        (8,  "HTTP Headers",              "headers"),
        (16, "SSL/TLS Analysis",          "ssl"),
        (24, "DNS Records",               "dns"),
        (38, "Port Scan (nmap)",          "ports"),
        (50, "Directory Enumeration",     "dirbust"),
        (63, "Nikto Web Scanner",         "nikto"),
        (73, "WhatWeb Fingerprint",       "whatweb"),
        (84, "Nuclei Templates",          "nuclei"),
        (93, "SQLMap Injection Check",    "sqlmap"),
        (100,"Building Report",           "final"),
    ]

    def _worker():
        store = {}
        try:
            for pct, label, key in STAGES:
                q.put({"pct": pct-1, "stage": label,
                       "log": f"[*] {label}...", "done": False})
                try:
                    if key == "headers":
                        r = run_backend("--modules", "headers", host, timeout=60)
                        store["headers"] = (r.get("modules") or {}).get("headers") or {}
                        n = len(store["headers"].get("issues", []))
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Headers — {n} issue(s)", "done":False})

                    elif key == "ssl":
                        r = run_backend("--modules", "ssl", host, timeout=60)
                        store["ssl"] = (r.get("modules") or {}).get("ssl") or []
                        g = store["ssl"][0].get("grade","?") if store["ssl"] else "N/A"
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] SSL — grade: {g}", "done":False})

                    elif key == "dns":
                        r = run_backend("--modules", "dns", host, timeout=60)
                        store["dns"] = (r.get("modules") or {}).get("dns") or {}
                        s = len(store["dns"].get("subdomains", []))
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] DNS — {s} subdomains found", "done":False})

                    elif key == "ports":
                        r = run_backend("--modules", "ports",
                                        "--nmap-profile", profile, host, timeout=TIMEOUT_SCAN)
                        store["ports"] = r
                        op = sum(len(h.get("ports",[])) for h in (r.get("hosts") or []))
                        cv = len([c for h in (r.get("hosts") or [])
                                  for p in h.get("ports",[]) for c in p.get("cves",[])])
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Ports — {op} open, {cv} CVEs", "done":False})

                    elif key == "dirbust":
                        r = run_backend("--dirbust", base_url, "medium",
                                        "php,html,js,txt,bak,zip,env,log",
                                        timeout=TIMEOUT_DIRBUST)
                        store["dirbust"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Dirs — {r.get('total',0)} path(s) found",
                               "done":False})

                    elif key == "nikto":
                        r = _run_nikto_for_webdeep(raw_url)
                        store["nikto"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Nikto — {len(r.get('findings',[]))} finding(s)",
                               "done":False})

                    elif key == "whatweb":
                        r = _run_whatweb_for_webdeep(raw_url)
                        store["whatweb"] = r
                        tech = ", ".join(r.get("technologies",[])[:4]) or "none"
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] WhatWeb — {tech}", "done":False})

                    elif key == "nuclei":
                        r = _run_nuclei_for_webdeep(raw_url)
                        store["nuclei"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] Nuclei — {len(r.get('findings',[]))} finding(s)",
                               "done":False})

                    elif key == "sqlmap":
                        r = _run_sqlmap_for_webdeep(raw_url)
                        store["sqlmap"] = r
                        q.put({"pct":pct,"stage":label,
                               "log":f"[+] SQLMap — {len(r.get('findings',[]))} indicator(s)",
                               "done":False})

                    elif key == "final":
                        net = store.get("ports", {})
                        if "modules" not in net:
                            net["modules"] = {}
                        net["modules"]["headers"] = store.get("headers", {})
                        net["modules"]["ssl"]     = store.get("ssl", [])
                        net["modules"]["dns"]     = store.get("dns", {})

                        hdr = store.get("headers", {})
                        score, rating, summary = _rate_web_findings(
                            net, store.get("nikto",{}),
                            store.get("dirbust",{}), hdr,
                            nuclei_data=store.get("nuclei",{}),
                            sqlmap_data=store.get("sqlmap",{}))

                        all_cves = [c for h in (net.get("hosts") or [])
                                    for p in h.get("ports",[])
                                    for c in p.get("cves",[])]
                        net_sum = {
                            "open_ports":   sum(len(h.get("ports",[])) for h in (net.get("hosts") or [])),
                            "total_cves":   len(all_cves),
                            "critical_cves":sum(1 for c in all_cves if c.get("severity")=="CRITICAL"),
                            "high_cves":    sum(1 for c in all_cves if c.get("severity")=="HIGH"),
                            "exploitable":  sum(1 for c in all_cves if c.get("has_exploit")),
                        }

                        result = {
                            "target":              base_url,
                            "vulnerability_score": score,
                            "risk_rating":         rating,
                            "summary":             {**summary, **net_sum},
                            "tools_required":      required_web_tools(),
                            "tools_run": [
                                {"tool":k,"status":"ok" if v else "no-output"}
                                for k,v in store.items()
                            ],
                            "key_findings": [
                                f"Open ports: {net_sum['open_ports']}",
                                f"Total CVEs: {net_sum['total_cves']}",
                                f"Critical CVEs: {net_sum['critical_cves']}",
                                f"Nikto findings: {summary['nikto_high']}",
                                f"Sensitive paths: {summary['sensitive_paths']}",
                                f"Header issues: {summary['header_issues']}",
                                f"Nuclei findings: {summary['nuclei_high']}",
                                f"SQLi indicators: {summary['sqlmap_hits']}",
                            ],
                            "executive_summary": (
                                f"Deep web audit complete for {base_url}. "
                                f"Risk: {rating} ({score}/100). "
                                f"{net_sum['open_ports']} open ports, "
                                f"{net_sum['total_cves']} CVEs."
                            ),
                            "details": {
                                "network_scan":    net,
                                "nikto":           store.get("nikto",{}),
                                "directory_enum":  store.get("dirbust",{}),
                                "whatweb":         store.get("whatweb",{}),
                                "nuclei":          store.get("nuclei",{}),
                                "sqlmap":          store.get("sqlmap",{}),
                            }
                        }
                        q.put({"pct":100,"stage":"Done",
                               "log":f"[+] Complete — {rating} ({score}/100)",
                               "done":True, "result":result})
                        return

                except Exception as e:
                    q.put({"pct":pct,"stage":label,
                           "log":f"[!] {label} error: {str(e)[:100]}","done":False})

        except Exception as e:
            q.put({"pct":100,"done":True,"error":str(e),"result":{}})

    threading.Thread(target=_worker, daemon=True).start()

    def _stream():
        while True:
            try:
                msg = q.get(timeout=1800)
                yield "data: " + json.dumps(msg) + "\n\n"
                if msg.get("done"):
                    break
            except Exception:
                yield 'data: ' + json.dumps({"pct":100,"done":True,
                                              "error":"Stream timeout"}) + "\n\n"
                break

    return Response(_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.route("/report", methods=["POST"])
def report():'''


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 2b — Deep Web Audit JS: switch to SSE + live progress
# ═══════════════════════════════════════════════════════════════════════════════

OLD_WD_JS = '''/* ==== DEEP WEB AUDIT ==== */
async function doWebDeep(){
  var url=document.getElementById('wd-url').value.trim();if(!url){alert('Enter a website URL');return;}
  var profile=document.getElementById('wd-profile').value||'balanced';
  var btn=document.getElementById('wd-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Auditing...';
  wdTool.start();wdTool.log('Target: '+url,'i');wdTool.log('Profile: '+profile,'i');wdTool.log('Running full multi-tool audit. This can take a while...','w');
  try{
    var r=await fetchWithTimeout('/web-deep',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url,profile:profile})},1800000,'wd');
    var d=await r.json();wdTool.end();
    if(d.error){wdTool.log(d.error,'e');wdTool.err(d.error);}
    else{wdTool.log('Audit complete -- Rating: '+(d.risk_rating||'UNKNOWN'),'s');renderWebDeep(d);}
  }catch(e){wdTool.end();wdTool.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN DEEP WEB AUDIT';}
}'''

NEW_WD_JS = '''/* ==== DEEP WEB AUDIT ==== */
var _wdES=null;
function _wdReset(){
  var btn=document.getElementById('wd-btn');
  if(btn){btn.disabled=false;btn.innerHTML='RUN DEEP WEB AUDIT';}
  document.getElementById('wd-cancel').style.display='none';
  endProg('wd-prog');
}
function doWebDeep(){
  var url=document.getElementById('wd-url').value.trim();if(!url){alert('Enter a website URL');return;}
  var profile=document.getElementById('wd-profile').value||'balanced';
  var btn=document.getElementById('wd-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span> Auditing...';
  document.getElementById('wd-cancel').style.display='inline-flex';
  wdTool.start();startProg('wd-prog');
  wdTool.log('Target: '+url,'i');
  wdTool.log('Profile: '+profile+' | 9 tools running — streaming live progress...','w');
  if(_wdES){_wdES.close();_wdES=null;}
  var params=new URLSearchParams({url:url,profile:profile});
  _wdES=new EventSource('/web-deep-stream?'+params.toString());
  _wdES.onmessage=function(e){
    try{
      var d=JSON.parse(e.data);
      // Update progress bar
      var pb=document.getElementById('wd-pb');if(pb)pb.style.width=(d.pct||0)+'%';
      // Log
      if(d.log){
        var tp='i';
        if(d.log.startsWith('[+]'))tp='s';
        else if(d.log.startsWith('[!]'))tp='w';
        else if(d.log.startsWith('[x]'))tp='e';
        wdTool.log('['+d.pct+'%] '+d.log.replace(/^\[.\] /,''),tp);
      }
      if(d.done){
        _wdES.close();_wdES=null;_wdReset();
        if(d.error){wdTool.err(d.error);}
        else if(d.result){
          wdTool.log('Audit complete — '+d.result.risk_rating+' ('+d.result.vulnerability_score+'/100)','s');
          renderWebDeep(d.result);
          showToast('Deep Audit Done','Risk: '+d.result.risk_rating+' | Score: '+d.result.vulnerability_score+'/100','success',7000);
        }
      }
    }catch(ex){wdTool.log('Parse: '+ex.message,'e');}
  };
  _wdES.onerror=function(){
    if(_wdES){_wdES.close();_wdES=null;}
    wdTool.end();wdTool.err('Stream connection lost. Retrying or check server logs.');
    _wdReset();
  };
}'''


# ── Patch cancelScan to also close SSE
OLD_CANCEL = '''function cancelScan(prefix){
  if(scanControllers[prefix]){scanControllers[prefix].abort();delete scanControllers[prefix];}
  var id=prefix==='scan'?'sbtn-cancel':prefix+'-cancel';
  var b=document.getElementById(id);if(b)b.style.display='none';
  showToast('Cancelled','Scan stopped by user.','warning',3000);
}'''

NEW_CANCEL = '''function cancelScan(prefix){
  if(prefix==='wd'&&_wdES){_wdES.close();_wdES=null;_wdReset();}
  if(scanControllers[prefix]){scanControllers[prefix].abort();delete scanControllers[prefix];}
  var id=prefix==='scan'?'sbtn-cancel':prefix+'-cancel';
  var b=document.getElementById(id);if(b)b.style.display='none';
  showToast('Cancelled','Scan stopped by user.','warning',3000);
}'''


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 3a — Brute Force HTML: rockyou selected by default
# ═══════════════════════════════════════════════════════════════════════════════

OLD_BF_SEL = '''          <div class="fg">
            <label>USERNAME LIST MODE</label>
            <select class="inp inp-mono" id="bf-user-mode" onchange="bfWordlistMode(\'user\')">
              <option value="manual">Manual Input</option>
              <option value="rockyou_users">rockyou.txt (top usernames)</option>
              <option value="seclists_common">SecLists: common usernames</option>
              <option value="seclists_top">SecLists: top shortlist</option>
              <option value="seclists_default_creds">SecLists: default credentials users</option>
            </select>
          </div>
          <div class="fg">
            <label>PASSWORD LIST MODE</label>
            <select class="inp inp-mono" id="bf-pass-mode" onchange="bfWordlistMode(\'pass\')">
              <option value="manual">Manual Input</option>
              <option value="rockyou">rockyou.txt (top 1000)</option>
              <option value="seclists_10k">SecLists: top 10k passwords</option>
              <option value="seclists_100k">SecLists: top 100k passwords</option>
              <option value="seclists_default_creds_pass">SecLists: default credential passwords</option>
              <option value="seclists_darkweb">SecLists: darkweb 2017 top 10k</option>
            </select>
          </div>'''

NEW_BF_SEL = '''          <div class="fg">
            <label>USERNAME LIST MODE</label>
            <select class="inp inp-mono" id="bf-user-mode" onchange="bfWordlistMode(\'user\')">
              <option value="manual">Manual Input</option>
              <option value="rockyou_users" selected>rockyou.txt — default usernames &#10003;</option>
              <option value="seclists_common">SecLists: common usernames shortlist</option>
              <option value="seclists_top">SecLists: full names list</option>
              <option value="seclists_default_creds">SecLists: default credential users</option>
            </select>
          </div>
          <div class="fg">
            <label>PASSWORD LIST MODE</label>
            <select class="inp inp-mono" id="bf-pass-mode" onchange="bfWordlistMode(\'pass\')">
              <option value="manual">Manual Input</option>
              <option value="rockyou" selected>rockyou.txt — default passwords &#10003;</option>
              <option value="seclists_10k">SecLists: top 10k passwords</option>
              <option value="seclists_100k">SecLists: top 100k passwords</option>
              <option value="seclists_default_creds_pass">SecLists: default credential passwords</option>
              <option value="seclists_darkweb">SecLists: darkweb2017 top 10k</option>
            </select>
          </div>'''


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 3b — Brute Force JS: multi-path fallback + auto-load on page open
# ═══════════════════════════════════════════════════════════════════════════════

OLD_BF_JS = '''// Wordlist path map — ordered by preference (first existing file wins)
var BF_PATH_MAP={
  rockyou_users:['/usr/share/wordlists/rockyou.txt','/usr/share/john/password.lst','/usr/share/dict/words'],
  seclists_common:['/usr/share/seclists/Usernames/top-usernames-shortlist.txt','/usr/share/seclists/Usernames/Names/names.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_top:['/usr/share/seclists/Usernames/Names/names.txt','/usr/share/seclists/Usernames/top-usernames-shortlist.txt'],
  seclists_default_creds:['/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt','/usr/share/wordlists/rockyou.txt'],
  rockyou:['/usr/share/wordlists/rockyou.txt','/usr/share/john/password.lst','/usr/share/dict/words'],
  seclists_10k:['/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt','/usr/share/seclists/Passwords/Common-Credentials/best110.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_100k:['/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt','/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt'],
  seclists_default_creds_pass:['/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_darkweb:['/usr/share/seclists/Passwords/darkweb2017-top10000.txt','/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt','/usr/share/wordlists/rockyou.txt']
};
async function bfWordlistMode(which){
  var modeEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-mode');
  var textEl=document.getElementById('bf-'+(which==='user'?'users':'pwds'));
  var lblEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-src-lbl');
  var statusEl=document.getElementById('bf-wordlist-status');
  var mode=modeEl.value;
  if(mode==='manual'){textEl.disabled=false;lblEl.textContent='(one per line)';return;}
  var paths=BF_PATH_MAP[mode]||[];
  if(!paths.length){textEl.disabled=false;return;}
  statusEl.style.display='block';
  statusEl.textContent='[*] Loading wordlist...';
  textEl.disabled=true;
  // Try each path in order — server will auto-fallback to first existing file
  var loaded=false;
  for(var i=0;i<paths.length&&!loaded;i++){
    var filePath=paths[i];
    try{
      var limit=which==='user'?200:2000;
      var r=await fetch('/api/wordlist?path='+encodeURIComponent(filePath)+'&limit='+limit);
      var d=await r.json();
      if(!d.error&&d.words&&d.words.length){
        textEl.value=d.words.join('\\n');
        textEl.disabled=false;
        lblEl.textContent='(from: '+d.filename+')';
        statusEl.innerHTML='[+] Loaded <strong>'+d.words.length+'</strong> entries from <code style="font-family:var(--mono)">'+d.path+'</code>';
        _bfWordlists[which]={path:d.path,count:d.words.length};
        loaded=true;
      }
    }catch(e){}
  }
  if(!loaded){
    statusEl.textContent='[!] No wordlist found. Install: sudo apt install wordlists seclists';
    textEl.disabled=false;
  }
}
// Auto-load rockyou defaults when page first shows brute force
function bfAutoLoad(){
  var userMode=document.getElementById('bf-user-mode');
  var passMode=document.getElementById('bf-pass-mode');
  if(userMode&&userMode.value==='rockyou_users')bfWordlistMode('user');
  if(passMode&&passMode.value==='rockyou')bfWordlistMode('pass');
}'''

NEW_BF_JS = '''// Wordlist fallback chains — first reachable file wins
var BF_PATH_MAP={
  rockyou_users:['/usr/share/wordlists/rockyou.txt','/usr/share/john/password.lst','/usr/share/dict/words'],
  seclists_common:['/usr/share/seclists/Usernames/top-usernames-shortlist.txt','/usr/share/seclists/Usernames/Names/names.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_top:['/usr/share/seclists/Usernames/Names/names.txt','/usr/share/seclists/Usernames/top-usernames-shortlist.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_default_creds:['/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt','/usr/share/wordlists/rockyou.txt'],
  rockyou:['/usr/share/wordlists/rockyou.txt','/usr/share/john/password.lst','/usr/share/dict/words'],
  seclists_10k:['/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt','/usr/share/seclists/Passwords/Common-Credentials/best110.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_100k:['/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt','/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_default_creds_pass:['/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt','/usr/share/wordlists/rockyou.txt'],
  seclists_darkweb:['/usr/share/seclists/Passwords/darkweb2017-top10000.txt','/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt','/usr/share/wordlists/rockyou.txt']
};
async function bfWordlistMode(which,silent){
  var modeEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-mode');
  var textEl=document.getElementById('bf-'+(which==='user'?'users':'pwds'));
  var lblEl=document.getElementById('bf-'+(which==='user'?'user':'pass')+'-src-lbl');
  var statusEl=document.getElementById('bf-wordlist-status');
  var mode=modeEl?modeEl.value:'manual';
  if(mode==='manual'){if(textEl)textEl.disabled=false;if(lblEl)lblEl.textContent='(one per line)';return;}
  var paths=BF_PATH_MAP[mode]||[];
  if(!paths.length){if(textEl)textEl.disabled=false;return;}
  if(statusEl){statusEl.style.display='block';statusEl.textContent='[*] Loading '+mode+' wordlist...';}
  if(textEl)textEl.disabled=true;
  var limit=which==='user'?200:2000;
  var loaded=false;
  for(var i=0;i<paths.length&&!loaded;i++){
    try{
      var r=await fetch('/api/wordlist?path='+encodeURIComponent(paths[i])+'&limit='+limit);
      var d=await r.json();
      if(!d.error&&d.words&&d.words.length){
        if(textEl){textEl.value=d.words.join('\\n');textEl.disabled=false;}
        if(lblEl)lblEl.textContent='('+d.filename+' — '+d.words.length+' entries)';
        if(statusEl)statusEl.innerHTML='[+] Loaded <strong>'+d.words.length+'</strong> entries from <code style="font-family:var(--mono);font-size:10px">'+d.path+'</code>';
        _bfWordlists[which]={path:d.path,count:d.words.length};
        loaded=true;
        if(!silent)showToast('Wordlist Loaded',d.filename+' ('+d.words.length+' entries)','success',3000);
      }
    }catch(e){}
  }
  if(!loaded){
    if(statusEl)statusEl.textContent='[!] Wordlist not found. sudo apt install wordlists seclists';
    if(textEl)textEl.disabled=false;
    if(!silent)showToast('Wordlist Missing','Install: sudo apt install wordlists seclists','warning',5000);
  }
}
// Auto-load rockyou when user opens brute force page
function bfAutoLoad(){
  var um=document.getElementById('bf-user-mode');
  var pm=document.getElementById('bf-pass-mode');
  if(um&&um.value!=='manual')bfWordlistMode('user',true);
  if(pm&&pm.value!=='manual')bfWordlistMode('pass',true);
}'''


# ── Also auto-call bfAutoLoad when brute page is opened
OLD_PG_HOOK = '''  if(id==='hist')loadHist();
  if(id==='dash')loadDash();
  if(id==='admin'){loadAdmin();setTimeout(initCliHeader,400);}
  if(id==='home'){setTimeout(loadHomeStats,80);if(currentUser)vsGreetUser(currentUser.username);}
  if(id==='profile'&&currentUser)loadProfileInfo(currentUser);'''

NEW_PG_HOOK = '''  if(id==='hist')loadHist();
  if(id==='dash')loadDash();
  if(id==='admin'){loadAdmin();setTimeout(initCliHeader,400);}
  if(id==='home'){setTimeout(loadHomeStats,80);if(currentUser)vsGreetUser(currentUser.username);}
  if(id==='profile'&&currentUser)loadProfileInfo(currentUser);
  if(id==='brute')setTimeout(bfAutoLoad,300);'''


# ═══════════════════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════════════════

PATCHES = [("api_server.py", [
    ("DNSRecon: remove --tcp, add dnsrecon→dig→socket fallback chain",
     OLD_DR, NEW_DR),
    ("Deep Web Audit: add /web-deep-stream SSE route (before /report)",
     OLD_REPORT_ANCHOR, NEW_REPORT_ANCHOR),
    ("Deep Web Audit JS: switch to SSE EventSource with live % progress",
     OLD_WD_JS, NEW_WD_JS),
    ("cancelScan: close SSE stream for web-deep cancel",
     OLD_CANCEL, NEW_CANCEL),
    ("Brute Force HTML: rockyou selected by default in both dropdowns",
     OLD_BF_SEL, NEW_BF_SEL),
    ("Brute Force JS: multi-path fallback + silent auto-load flag",
     OLD_BF_JS, NEW_BF_JS),
    ("pg(): auto-load wordlists when brute force page opens",
     OLD_PG_HOOK, NEW_PG_HOOK),
])]


def main():
    print()
    print(BOLD+CYAN+"╔══════════════════════════════════════════════════════╗"+RESET)
    print(BOLD+CYAN+"║  VulnScan Pro — Patch v5.0                          ║"+RESET)
    print(BOLD+CYAN+"║  DNSRecon fix · Deep Audit SSE · Brute wordlists    ║"+RESET)
    print(BOLD+CYAN+"╚══════════════════════════════════════════════════════╝"+RESET)
    print()

    missing=[f for f in ["api_server.py","backend.py","auth.py"] if not os.path.isfile(f)]
    if missing:
        print(RED+BOLD+"  ERROR: Not in project root. Missing: "+", ".join(missing)+RESET)
        print("  Run: cd ~/vulnscan && python3 patch.py"); sys.exit(1)

    info(f"Project root: {os.getcwd()}"); print()

    for fname, changes in PATCHES:
        print(BOLD+f"  ── {fname}"+RESET)
        patch(fname, changes)
        print()

    if R["files"]:
        print(BOLD+"  Syntax checks:"+RESET)
        for p in R["files"]:
            flag,err=syntax(p)
            if flag: ok(f"{p} — OK")
            else: fail(f"{p} — SYNTAX ERROR: {err}")
        print()

    print(BOLD+CYAN+"══════════════════════════════════════════════════════"+RESET)
    print(f"  Applied : {GREEN}{R['applied']}{RESET}  |  "
          f"Skipped : {DIM}{R['skipped']}{RESET}  |  "
          f"Failed : {RED if R['failed'] else DIM}{R['failed']}{RESET}")
    print()
    if R["files"]:
        for f in R["files"]: print(f"  {GREEN}✓{RESET}  {f}  {DIM}({f}.*.bak){RESET}")
        print()
    if R["applied"]>0:
        print(f"  {YELLOW}Restart:{RESET}  python3 api_server.py  |  sudo systemctl restart vulnscan")
        print()
        print(f"  {GREEN}What changed:{RESET}")
        print(f"    {GREEN}✓{RESET} DNSRecon: no --tcp, tries dnsrecon binary → dig → python socket")
        print(f"    {GREEN}✓{RESET} Deep Web Audit: GET /web-deep-stream SSE, 9 tools, live % per stage")
        print(f"    {GREEN}✓{RESET} Deep Web Audit: progress bar + terminal log update in real time")
        print(f"    {GREEN}✓{RESET} Brute Force: rockyou.txt pre-selected & auto-loaded on page open")
        print(f"    {GREEN}✓{RESET} Brute Force: fallback chain tries multiple paths automatically")
        print()
        print(f"  {CYAN}Install wordlists (if not present):{RESET}")
        print(f"    sudo apt install wordlists seclists")
        print(f"    sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true")
    elif R["skipped"]>0:
        print(f"  {GREEN}Already up to date — no restart needed.{RESET}")
    print()


if __name__=="__main__":
    main()
