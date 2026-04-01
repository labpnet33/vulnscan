#!/usr/bin/env python3
"""
VulnScan Pro — Tool Pages UI Patch
====================================
Replaces generic stub pages with proper, purpose-specific UI fields for every tool.
Each tool page gets the right inputs so users can actually interact with it.

Run from your vulnscan project root:
    python3 patch_tool_pages.py
"""

import os, sys, shutil, subprocess
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

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch_html(path, replacements):
    """Apply list of (label, old_html, new_html) replacements to api_server.py"""
    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        RESULTS["failed"] += len(replacements)
        return

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    modified = src
    applied_count = 0
    backed_up = False

    for label, old, new in replacements:
        if old in modified:
            if not backed_up:
                backup(path)
                backed_up = True
            modified = modified.replace(old, new, 1)
            ok(label)
            applied_count += 1
            RESULTS["applied"] += 1
        elif new in modified:
            skip(f"{label} (already applied)")
            RESULTS["skipped"] += 1
        else:
            warn(f"{label} — anchor not found, skipping")
            RESULTS["skipped"] += 1

    if applied_count:
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


# ══════════════════════════════════════════════════════════════
# TOOL PAGE REPLACEMENTS
# Each tuple: (label, old_html_snippet, new_html_snippet)
# We target the card-p div inside each page's form area.
# ══════════════════════════════════════════════════════════════

TOOL_PAGES = []

# ─── FFUF ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "ffuf — proper URL/wordlist/filter fields",
    '''      <!-- FFUF -->
      <div class="page" id="page-ffuf">
        <div class="page-hd"><div class="page-title">ffuf</div><div class="page-desc">Fast web fuzzer for content discovery and parameter fuzzing</div></div>
        <div class="notice">&#9888; Authorized use only. Only run ffuf on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="ffuf-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ffuf-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="ffuf-bin" type="text" value="ffuf"/></div>
          </div>
          <button class="btn btn-primary" id="ffuf-btn" onclick="runGenericTool('ffuf','ffuf')">RUN FFUF</button>
        </div>''',
    '''      <!-- FFUF -->
      <div class="page" id="page-ffuf">
        <div class="page-hd"><div class="page-title">ffuf</div><div class="page-desc">Fast web fuzzer for content discovery and parameter fuzzing</div></div>
        <div class="notice">&#9888; Authorized use only. Only run ffuf on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET URL (use FUZZ as placeholder)</label><input class="inp inp-mono" id="ffuf-url" type="text" placeholder="https://example.com/FUZZ"/></div>
            <div class="fg"><label>WORDLIST PATH</label><input class="inp inp-mono" id="ffuf-wordlist" type="text" value="/usr/share/seclists/Discovery/Web-Content/common.txt"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>HTTP METHOD</label><select class="inp inp-mono" id="ffuf-method"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select></div>
            <div class="fg"><label>FILTER STATUS CODES</label><input class="inp inp-mono" id="ffuf-fc" type="text" placeholder="404,403" value="404"/></div>
            <div class="fg"><label>MATCH STATUS CODES</label><input class="inp inp-mono" id="ffuf-mc" type="text" placeholder="200,301,302"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>EXTENSIONS</label><input class="inp inp-mono" id="ffuf-e" type="text" placeholder=".php,.html,.txt"/></div>
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="ffuf-threads" type="number" value="40" min="1" max="200"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ffuf-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="ffuf-extra" type="text" placeholder="-H 'Cookie: session=abc' -recursion"/></div>
          <button class="btn btn-primary" id="ffuf-btn" onclick="runFfuf()">RUN FFUF</button>
        </div>''',
))

# ─── NUCLEI ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "nuclei — proper target/template/severity fields",
    '''      <!-- NUCLEI -->
      <div class="page" id="page-nuclei">
        <div class="page-hd"><div class="page-title">Nuclei</div><div class="page-desc">Template-based vulnerability scanner with thousands of community checks</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Nuclei on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="nuclei-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nuclei-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="nuclei-bin" type="text" value="nuclei"/></div>
          </div>
          <button class="btn btn-primary" id="nuclei-btn" onclick="runGenericTool('nuclei','nuclei')">RUN NUCLEI</button>
        </div>''',
    '''      <!-- NUCLEI -->
      <div class="page" id="page-nuclei">
        <div class="page-hd"><div class="page-title">Nuclei</div><div class="page-desc">Template-based vulnerability scanner with thousands of community checks</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Nuclei on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL / HOST</label><input class="inp inp-mono" id="nuclei-target" type="text" placeholder="https://example.com"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SEVERITY FILTER</label>
              <select class="inp inp-mono" id="nuclei-severity" multiple style="height:90px;padding:6px">
                <option value="critical" selected>Critical</option>
                <option value="high" selected>High</option>
                <option value="medium" selected>Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div class="fg"><label>TEMPLATE TAGS / CATEGORIES</label>
              <select class="inp inp-mono" id="nuclei-tags" multiple style="height:90px;padding:6px">
                <option value="cve" selected>CVEs</option>
                <option value="oast">OAST/SSRF</option>
                <option value="sqli">SQL Injection</option>
                <option value="xss">XSS</option>
                <option value="rce">RCE</option>
                <option value="lfi">LFI</option>
                <option value="ssrf">SSRF</option>
                <option value="misconfig">Misconfig</option>
                <option value="exposed-panels">Exposed Panels</option>
              </select>
            </div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="nuclei-threads" type="number" value="25" min="1" max="100"/></div>
            <div class="fg"><label>RATE LIMIT (req/sec)</label><input class="inp inp-mono" id="nuclei-rate" type="number" value="150" min="1" max="500"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="nuclei-timeout" type="number" value="300" min="30" max="1800"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>CUSTOM TEMPLATE PATH (optional)</label><input class="inp inp-mono" id="nuclei-templates" type="text" placeholder="/path/to/custom-templates/"/></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="nuclei-btn" onclick="runNuclei()">RUN NUCLEI</button>
            <button class="btn btn-outline btn-sm" onclick="runNucleiUpdate()">UPDATE TEMPLATES</button>
          </div>
        </div>''',
))

# ─── WHATWEB ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "whatweb — proper target/aggression fields",
    '''      <!-- WHATWEB -->
      <div class="page" id="page-whatweb">
        <div class="page-hd"><div class="page-title">WhatWeb</div><div class="page-desc">Web technology fingerprinter — identify CMS, frameworks, servers</div></div>
        <div class="notice">&#9888; Authorized use only. Only run WhatWeb on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="whatweb-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="whatweb-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="whatweb-bin" type="text" value="whatweb"/></div>
          </div>
          <button class="btn btn-primary" id="whatweb-btn" onclick="runGenericTool('whatweb','whatweb')">RUN WHATWEB</button>
        </div>''',
    '''      <!-- WHATWEB -->
      <div class="page" id="page-whatweb">
        <div class="page-hd"><div class="page-title">WhatWeb</div><div class="page-desc">Web technology fingerprinter — identify CMS, frameworks, servers</div></div>
        <div class="notice">&#9888; Authorized use only. Only run WhatWeb on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL / HOST</label><input class="inp inp-mono" id="whatweb-target" type="text" placeholder="https://example.com"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>AGGRESSION LEVEL</label>
              <select class="inp inp-mono" id="whatweb-aggression">
                <option value="1">1 — Stealthy (passive)</option>
                <option value="3" selected>3 — Aggressive (default)</option>
                <option value="4">4 — Heavy (many requests)</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="whatweb-format">
                <option value="">Brief</option>
                <option value="--log-json=-" selected>JSON</option>
                <option value="--log-xml=-">XML</option>
                <option value="--log-verbose=-">Verbose</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="whatweb-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>USER AGENT (optional)</label><input class="inp inp-mono" id="whatweb-ua" type="text" placeholder="Mozilla/5.0 ..."/></div>
            <div class="fg"><label>HTTP PROXY (optional)</label><input class="inp inp-mono" id="whatweb-proxy" type="text" placeholder="http://127.0.0.1:8080"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="whatweb-extra" type="text" placeholder="--follow-redirect=never --max-threads=4"/></div>
          <button class="btn btn-primary" id="whatweb-btn" onclick="runWhatWeb()">RUN WHATWEB</button>
        </div>''',
))

# ─── WAPITI ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "wapiti — proper target/module fields",
    '''      <!-- WAPITI -->
      <div class="page" id="page-wapiti">
        <div class="page-hd"><div class="page-title">Wapiti</div><div class="page-desc">Web application vulnerability scanner (SQLi, XSS, file disclosure)</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Wapiti on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="wapiti-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="wapiti-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="wapiti-bin" type="text" value="wapiti"/></div>
          </div>
          <button class="btn btn-primary" id="wapiti-btn" onclick="runGenericTool('wapiti','wapiti')">RUN WAPITI</button>
        </div>''',
    '''      <!-- WAPITI -->
      <div class="page" id="page-wapiti">
        <div class="page-hd"><div class="page-title">Wapiti</div><div class="page-desc">Web application vulnerability scanner (SQLi, XSS, file disclosure)</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Wapiti on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="wapiti-target" type="text" placeholder="https://example.com"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ATTACK MODULES (hold Ctrl)</label>
              <select class="inp inp-mono" id="wapiti-modules" multiple style="height:100px;padding:6px">
                <option value="sql" selected>SQL Injection</option>
                <option value="xss" selected>XSS</option>
                <option value="file" selected>File Disclosure / LFI</option>
                <option value="xxe">XXE</option>
                <option value="ssrf">SSRF</option>
                <option value="redirect">Open Redirect</option>
                <option value="exec">Command Injection</option>
                <option value="csrf">CSRF</option>
                <option value="wapp">Technology Detection</option>
                <option value="brute_login_form">Login Brute Force</option>
              </select>
            </div>
            <div class="fg">
              <div class="fg"><label>CRAWL DEPTH</label><input class="inp inp-mono" id="wapiti-depth" type="number" value="2" min="1" max="10"/></div>
              <div class="fg"><label>SCOPE</label>
                <select class="inp inp-mono" id="wapiti-scope">
                  <option value="folder">Folder (same path)</option>
                  <option value="domain" selected>Domain</option>
                  <option value="url">URL only</option>
                  <option value="page">Page</option>
                </select>
              </div>
              <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="wapiti-timeout" type="number" value="300" min="60" max="1800"/></div>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>REPORT FORMAT</label>
              <select class="inp inp-mono" id="wapiti-format">
                <option value="json" selected>JSON</option>
                <option value="html">HTML</option>
                <option value="txt">Text</option>
              </select>
            </div>
            <div class="fg"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="wapiti-extra" type="text" placeholder="--auth-user admin --auth-password pass"/></div>
          </div>
          <button class="btn btn-primary" id="wapiti-btn" onclick="runWapiti()">RUN WAPITI</button>
        </div>''',
))

# ─── DALFOX ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "dalfox — proper URL/mode fields",
    '''      <!-- DALFOX -->
      <div class="page" id="page-dalfox">
        <div class="page-hd"><div class="page-title">Dalfox</div><div class="page-desc">XSS parameter analysis and scanning tool</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Dalfox on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="dalfox-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="dalfox-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="dalfox-bin" type="text" value="dalfox"/></div>
          </div>
          <button class="btn btn-primary" id="dalfox-btn" onclick="runGenericTool('dalfox','dalfox')">RUN DALFOX</button>
        </div>''',
    '''      <!-- DALFOX -->
      <div class="page" id="page-dalfox">
        <div class="page-hd"><div class="page-title">Dalfox</div><div class="page-desc">XSS parameter analysis and scanning tool</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Dalfox on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL (with parameters)</label><input class="inp inp-mono" id="dalfox-target" type="text" placeholder="https://example.com/search?q=test"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>SCAN MODE</label>
              <select class="inp inp-mono" id="dalfox-mode">
                <option value="url" selected>URL scan</option>
                <option value="pipe">Pipe (stdin URLs)</option>
                <option value="file">File (URL list)</option>
                <option value="sxss">Stored XSS</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="dalfox-format">
                <option value="">Plain text</option>
                <option value="--format json" selected>JSON</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="dalfox-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>CUSTOM PAYLOAD (optional)</label><input class="inp inp-mono" id="dalfox-payload" type="text" placeholder="&lt;script&gt;alert(1)&lt;/script&gt;"/></div>
            <div class="fg"><label>HTTP HEADER (optional)</label><input class="inp inp-mono" id="dalfox-header" type="text" placeholder="Cookie: session=abc123"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px">
            <label>OPTIONS</label>
            <div class="pills" style="margin-top:6px">
              <button class="pill" id="dalfox-opt-blind" onclick="this.classList.toggle('on')">Blind XSS</button>
              <button class="pill" id="dalfox-opt-skip-bav" onclick="this.classList.toggle('on')">Skip BAV</button>
              <button class="pill" id="dalfox-opt-only-discovery" onclick="this.classList.toggle('on')">Discovery Only</button>
              <button class="pill on" id="dalfox-opt-follow" onclick="this.classList.toggle('on')">Follow Redirects</button>
            </div>
          </div>
          <button class="btn btn-primary" id="dalfox-btn" onclick="runDalfox()">RUN DALFOX</button>
        </div>''',
))

# ─── SQLMAP ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "sqlmap — proper URL/technique/level fields",
    '''      <!-- SQLMAP -->
      <div class="page" id="page-sqlmap">
        <div class="page-hd"><div class="page-title">SQLMap</div><div class="page-desc">Automatic SQL injection detection and exploitation tool</div></div>
        <div class="notice">&#9888; Authorized use only. Only run SQLMap on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="sqlmap-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sqlmap-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="sqlmap-bin" type="text" value="sqlmap"/></div>
          </div>
          <button class="btn btn-primary" id="sqlmap-btn" onclick="runGenericTool('sqlmap','sqlmap')">RUN SQLMAP</button>
        </div>''',
    '''      <!-- SQLMAP -->
      <div class="page" id="page-sqlmap">
        <div class="page-hd"><div class="page-title">SQLMap</div><div class="page-desc">Automatic SQL injection detection and exploitation tool</div></div>
        <div class="notice">&#9888; Authorized use only. Only run SQLMap on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URL</label><input class="inp inp-mono" id="sqlmap-url" type="text" placeholder="https://example.com/page.php?id=1"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>RISK LEVEL</label>
              <select class="inp inp-mono" id="sqlmap-risk">
                <option value="1" selected>1 — Safe (default)</option>
                <option value="2">2 — Medium</option>
                <option value="3">3 — High (may harm data)</option>
              </select>
            </div>
            <div class="fg"><label>TEST LEVEL</label>
              <select class="inp inp-mono" id="sqlmap-level">
                <option value="1" selected>1 — Basic</option>
                <option value="2">2 — More tests</option>
                <option value="3">3 — Cookie/Referer</option>
                <option value="4">4 — UA/Referer</option>
                <option value="5">5 — All vectors</option>
              </select>
            </div>
            <div class="fg"><label>DBMS</label>
              <select class="inp inp-mono" id="sqlmap-dbms">
                <option value="">Auto-detect</option>
                <option>MySQL</option><option>PostgreSQL</option>
                <option>Microsoft SQL Server</option><option>Oracle</option>
                <option>SQLite</option><option>MariaDB</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TECHNIQUE</label>
              <select class="inp inp-mono" id="sqlmap-technique">
                <option value="">All techniques</option>
                <option value="B">Boolean-based blind</option>
                <option value="E">Error-based</option>
                <option value="U">Union query</option>
                <option value="S">Stacked queries</option>
                <option value="T">Time-based blind</option>
                <option value="Q">Inline queries</option>
              </select>
            </div>
            <div class="fg"><label>HTTP DATA (POST body, optional)</label><input class="inp inp-mono" id="sqlmap-data" type="text" placeholder="username=admin&amp;password=test"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>COOKIE (optional)</label><input class="inp inp-mono" id="sqlmap-cookie" type="text" placeholder="PHPSESSID=abc123; security=low"/></div>
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="sqlmap-threads" type="number" value="1" min="1" max="10"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="sqlmap-batch" onclick="this.classList.toggle('on')">--batch (auto)</button>
            <button class="pill" id="sqlmap-dbs" onclick="this.classList.toggle('on')">Enumerate DBs</button>
            <button class="pill" id="sqlmap-tables" onclick="this.classList.toggle('on')">Enumerate Tables</button>
            <button class="pill" id="sqlmap-dump" onclick="this.classList.toggle('on')">Dump Data</button>
            <button class="pill" id="sqlmap-random-agent" onclick="this.classList.toggle('on')">Random UA</button>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="sqlmap-timeout" type="number" value="300" min="30" max="1800"/></div>
          <button class="btn btn-primary" id="sqlmap-btn" onclick="runSqlmap()">RUN SQLMAP</button>
        </div>''',
))

# ─── KXSS ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "kxss — proper URL/param fields",
    '''      <!-- KXSS -->
      <div class="page" id="page-kxss">
        <div class="page-hd"><div class="page-title">kxss</div><div class="page-desc">XSS parameter finder and reflection checker</div></div>
        <div class="notice">&#9888; Authorized use only. Only run kxss on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="kxss-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="kxss-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="kxss-bin" type="text" value="kxss"/></div>
          </div>
          <button class="btn btn-primary" id="kxss-btn" onclick="runGenericTool('kxss','kxss')">RUN KXSS</button>
        </div>''',
    '''      <!-- KXSS -->
      <div class="page" id="page-kxss">
        <div class="page-hd"><div class="page-title">kxss</div><div class="page-desc">XSS parameter finder — pipe URLs to check for reflected XSS chars</div></div>
        <div class="notice">&#9888; Authorized use only. Only run kxss on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET URLs (one per line — parameters with values required)</label>
            <textarea class="inp inp-mono" id="kxss-urls" rows="5" placeholder="https://example.com/search?q=test&#10;https://example.com/page?id=1&#10;https://example.com/item?name=foo"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>HTTP HEADER (optional)</label><input class="inp inp-mono" id="kxss-header" type="text" placeholder="Cookie: session=abc123"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="kxss-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">&#9432; kxss reads URLs from stdin. Pipe output from other tools (e.g. gau, waybackurls) or paste URLs above.</div>
          <button class="btn btn-primary" id="kxss-btn" onclick="runKxss()">RUN KXSS</button>
        </div>''',
))

# ─── MEDUSA ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "medusa — proper host/protocol/wordlist fields",
    '''      <!-- MEDUSA -->
      <div class="page" id="page-medusa">
        <div class="page-hd"><div class="page-title">Medusa</div><div class="page-desc">Fast parallel network login auditor (multi-protocol brute force)</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Medusa on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="medusa-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="medusa-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="medusa-bin" type="text" value="medusa"/></div>
          </div>
          <button class="btn btn-primary" id="medusa-btn" onclick="runGenericTool('medusa','medusa')">RUN MEDUSA</button>
        </div>''',
    '''      <!-- MEDUSA -->
      <div class="page" id="page-medusa">
        <div class="page-hd"><div class="page-title">Medusa</div><div class="page-desc">Fast parallel network login auditor (multi-protocol brute force)</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Medusa on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST / IP</label><input class="inp inp-mono" id="medusa-host" type="text" placeholder="192.168.1.1"/></div>
            <div class="fg"><label>PORT</label><input class="inp inp-mono" id="medusa-port" type="number" placeholder="22"/></div>
            <div class="fg"><label>PROTOCOL / MODULE</label>
              <select class="inp inp-mono" id="medusa-module">
                <option value="ssh" selected>SSH</option>
                <option value="ftp">FTP</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="smb">SMB</option>
                <option value="rdp">RDP</option>
                <option value="telnet">Telnet</option>
                <option value="mysql">MySQL</option>
                <option value="mssql">MSSQL</option>
                <option value="pop3">POP3</option>
                <option value="imap">IMAP</option>
                <option value="smtp">SMTP</option>
                <option value="vnc">VNC</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>USERNAME / USER LIST</label><textarea class="inp inp-mono" id="medusa-users" rows="3" placeholder="admin&#10;root&#10;user"></textarea></div>
            <div class="fg"><label>PASSWORD / PASS LIST</label><textarea class="inp inp-mono" id="medusa-passes" rows="3" placeholder="password&#10;admin&#10;123456"></textarea></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>THREADS</label><input class="inp inp-mono" id="medusa-threads" type="number" value="4" min="1" max="64"/></div>
            <div class="fg"><label>RETRIES</label><input class="inp inp-mono" id="medusa-retries" type="number" value="3" min="0" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="medusa-timeout" type="number" value="120" min="10" max="600"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA ARGUMENTS</label><input class="inp inp-mono" id="medusa-extra" type="text" placeholder="-e ns (empty/username as pass) -F (stop on first success)"/></div>
          <button class="btn btn-primary" id="medusa-btn" onclick="runMedusa()">RUN MEDUSA</button>
        </div>''',
))

# ─── HPING3 ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "hping3 — proper target/mode/count fields",
    '''      <!-- HPING3 -->
      <div class="page" id="page-hping3">
        <div class="page-hd"><div class="page-title">hping3</div><div class="page-desc">TCP/IP packet assembler and analyzer for network testing</div></div>
        <div class="notice">&#9888; Authorized use only. Only run hping3 on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="hping3-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hping3-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="hping3-bin" type="text" value="hping3"/></div>
          </div>
          <button class="btn btn-primary" id="hping3-btn" onclick="runGenericTool('hping3','hping3')">RUN HPING3</button>
        </div>''',
    '''      <!-- HPING3 -->
      <div class="page" id="page-hping3">
        <div class="page-hd"><div class="page-title">hping3</div><div class="page-desc">TCP/IP packet assembler and analyzer — port scan, firewall testing, DoS simulation</div></div>
        <div class="notice">&#9888; Authorized use only. Only run hping3 on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TARGET HOST / IP</label><input class="inp inp-mono" id="hping3-host" type="text" placeholder="192.168.1.1"/></div>
            <div class="fg"><label>DESTINATION PORT</label><input class="inp inp-mono" id="hping3-port" type="number" value="80" min="1" max="65535"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>MODE</label>
              <select class="inp inp-mono" id="hping3-mode">
                <option value="-S" selected>SYN scan (-S)</option>
                <option value="-A">ACK scan (-A)</option>
                <option value="-F">FIN scan (-F)</option>
                <option value="-R">RST scan (-R)</option>
                <option value="-P">PUSH scan (-P)</option>
                <option value="-U">UDP mode (-U)</option>
                <option value="-1">ICMP mode (-1)</option>
                <option value="--scan">Port range scan</option>
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
            <button class="pill" id="hping3-flood" onclick="this.classList.toggle('on')">--flood (careful!)</button>
          </div>
          <button class="btn btn-primary" id="hping3-btn" onclick="runHping3()">RUN HPING3</button>
        </div>''',
))

# ─── HASHCAT ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "hashcat — proper hash/attack mode fields",
    '''      <!-- HASHCAT -->
      <div class="page" id="page-hashcat">
        <div class="page-hd"><div class="page-title">Hashcat</div><div class="page-desc">World's fastest GPU-based password recovery utility</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Hashcat on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="hashcat-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hashcat-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="hashcat-bin" type="text" value="hashcat"/></div>
          </div>
          <button class="btn btn-primary" id="hashcat-btn" onclick="runGenericTool('hashcat','hashcat')">RUN HASHCAT</button>
        </div>''',
    '''      <!-- HASHCAT -->
      <div class="page" id="page-hashcat">
        <div class="page-hd"><div class="page-title">Hashcat</div><div class="page-desc">GPU-accelerated password recovery — dictionary, mask, and hybrid attacks</div></div>
        <div class="notice">&#9888; Authorized use only. Only crack hashes you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>HASH(ES) TO CRACK (one per line or file path)</label>
            <textarea class="inp inp-mono" id="hashcat-hashes" rows="4" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;e10adc3949ba59abbe56e057f20f883e&#10;/path/to/hashes.txt"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>HASH TYPE (-m)</label>
              <select class="inp inp-mono" id="hashcat-type">
                <option value="0">0 — MD5</option>
                <option value="100">100 — SHA1</option>
                <option value="1400">1400 — SHA-256</option>
                <option value="1700">1700 — SHA-512</option>
                <option value="3200">3200 — bcrypt</option>
                <option value="1800">1800 — sha512crypt (Linux)</option>
                <option value="500">500 — md5crypt (Linux)</option>
                <option value="1000" selected>1000 — NTLM</option>
                <option value="5600">5600 — NetNTLMv2</option>
                <option value="13100">13100 — Kerberoast</option>
                <option value="22000">22000 — WPA-PBKDF2 (PMKID)</option>
              </select>
            </div>
            <div class="fg"><label>ATTACK MODE (-a)</label>
              <select class="inp inp-mono" id="hashcat-attack">
                <option value="0" selected>0 — Dictionary</option>
                <option value="1">1 — Combination</option>
                <option value="3">3 — Brute-force / Mask</option>
                <option value="6">6 — Hybrid (wordlist + mask)</option>
                <option value="7">7 — Hybrid (mask + wordlist)</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>WORDLIST / MASK</label><input class="inp inp-mono" id="hashcat-wordlist" type="text" value="/usr/share/wordlists/rockyou.txt" placeholder="/usr/share/wordlists/rockyou.txt OR ?a?a?a?a?a?a"/></div>
            <div class="fg"><label>RULES FILE (optional)</label><input class="inp inp-mono" id="hashcat-rules" type="text" placeholder="/usr/share/hashcat/rules/best64.rule"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>WORKLOAD PROFILE (-w)</label>
              <select class="inp inp-mono" id="hashcat-workload">
                <option value="1">1 — Low (background)</option>
                <option value="2" selected>2 — Default</option>
                <option value="3">3 — High</option>
                <option value="4">4 — Nightmare (max GPU)</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="hashcat-timeout" type="number" value="300" min="30" max="3600"/></div>
          </div>
          <button class="btn btn-primary" id="hashcat-btn" onclick="runHashcat()">RUN HASHCAT</button>
        </div>''',
))

# ─── JOHN ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "john — proper hash/wordlist/format fields",
    '''      <!-- JOHN THE RIPPER -->
      <div class="page" id="page-john">
        <div class="page-hd"><div class="page-title">John the Ripper</div><div class="page-desc">Versatile password cracker supporting many hash formats</div></div>
        <div class="notice">&#9888; Authorized use only. Only run John the Ripper on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="john-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="john-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="john-bin" type="text" value="john"/></div>
          </div>
          <button class="btn btn-primary" id="john-btn" onclick="runGenericTool('john','john')">RUN JOHN THE RIPPER</button>
        </div>''',
    '''      <!-- JOHN THE RIPPER -->
      <div class="page" id="page-john">
        <div class="page-hd"><div class="page-title">John the Ripper</div><div class="page-desc">Versatile password cracker — auto-detects hash format, supports many attack modes</div></div>
        <div class="notice">&#9888; Authorized use only. Only crack hashes you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>HASH FILE PATH or PASTE HASHES</label>
            <textarea class="inp inp-mono" id="john-hashes" rows="4" placeholder="/etc/shadow&#10;OR paste hashes (user:hash format or raw hashes):&#10;root:$6$rounds=5000$salt$hash&#10;5f4dcc3b5aa765d61d8327deb882cf99"></textarea>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>ATTACK MODE</label>
              <select class="inp inp-mono" id="john-mode">
                <option value="--wordlist" selected>Wordlist</option>
                <option value="--wordlist --rules">Wordlist + Rules</option>
                <option value="--incremental">Incremental (brute)</option>
                <option value="--single">Single (login-based)</option>
                <option value="--show">Show cracked</option>
              </select>
            </div>
            <div class="fg"><label>HASH FORMAT</label>
              <select class="inp inp-mono" id="john-format">
                <option value="">Auto-detect</option>
                <option value="--format=md5crypt">md5crypt (Linux)</option>
                <option value="--format=sha512crypt">sha512crypt (Linux)</option>
                <option value="--format=bcrypt">bcrypt</option>
                <option value="--format=NT">NT (Windows)</option>
                <option value="--format=LM">LM (Windows)</option>
                <option value="--format=Raw-MD5">Raw MD5</option>
                <option value="--format=Raw-SHA1">Raw SHA1</option>
                <option value="--format=Raw-SHA256">Raw SHA256</option>
                <option value="--format=zip">ZIP archive</option>
                <option value="--format=rar">RAR archive</option>
                <option value="--format=pdf">PDF</option>
              </select>
            </div>
            <div class="fg"><label>WORDLIST PATH</label><input class="inp inp-mono" id="john-wordlist" type="text" value="/usr/share/wordlists/rockyou.txt"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>RULES SET (optional)</label>
              <select class="inp inp-mono" id="john-rules">
                <option value="">None (use --wordlist mode)</option>
                <option value="--rules=All">All rules</option>
                <option value="--rules=Jumbo">Jumbo rules</option>
                <option value="--rules=KoreLogic">KoreLogic</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="john-timeout" type="number" value="300" min="30" max="3600"/></div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="john-btn" onclick="runJohn()">RUN JOHN</button>
            <button class="btn btn-outline btn-sm" onclick="runJohnShow()">SHOW CRACKED</button>
          </div>
        </div>''',
))

# ─── SEARCHSPLOIT ────────────────────────────────────────────
TOOL_PAGES.append((
    "searchsploit — proper search fields",
    '''      <!-- SEARCHSPLOIT -->
      <div class="page" id="page-searchsploit">
        <div class="page-hd"><div class="page-title">SearchSploit</div><div class="page-desc">Command-line search tool for Exploit-DB offline archive</div></div>
        <div class="notice">&#9888; Authorized use only. Only run SearchSploit on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="searchsploit-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="searchsploit-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="searchsploit-bin" type="text" value="searchsploit"/></div>
          </div>
          <button class="btn btn-primary" id="searchsploit-btn" onclick="runGenericTool('searchsploit','searchsploit')">RUN SEARCHSPLOIT</button>
        </div>''',
    '''      <!-- SEARCHSPLOIT -->
      <div class="page" id="page-searchsploit">
        <div class="page-hd"><div class="page-title">SearchSploit</div><div class="page-desc">Offline Exploit-DB search — find exploits and shellcodes for any software</div></div>
        <div class="notice">&#9432; SearchSploit is for research purposes. Only use exploits on systems you own or have written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>SEARCH QUERY (software name, CVE, version)</label>
            <input class="inp inp-mono" id="searchsploit-query" type="text" placeholder="apache 2.4 remote code execution"/>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>FILTER TYPE</label>
              <select class="inp inp-mono" id="searchsploit-type">
                <option value="">All (exploits + shellcodes)</option>
                <option value="-e">Exploits only</option>
                <option value="-s">Shellcodes only</option>
              </select>
            </div>
            <div class="fg"><label>PLATFORM</label>
              <select class="inp inp-mono" id="searchsploit-platform">
                <option value="">All platforms</option>
                <option value="-p linux">Linux</option>
                <option value="-p windows">Windows</option>
                <option value="-p php">PHP</option>
                <option value="-p webapps">Web Apps</option>
                <option value="-p hardware">Hardware</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="searchsploit-format">
                <option value="">Table</option>
                <option value="-j">JSON</option>
                <option value="--xml">XML</option>
              </select>
            </div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="searchsploit-strict" onclick="this.classList.toggle('on')">Strict match (-w)</button>
            <button class="pill" id="searchsploit-case" onclick="this.classList.toggle('on')">Case sensitive (-c)</button>
            <button class="pill" id="searchsploit-exclude-dos" onclick="this.classList.toggle('on')">Exclude DoS</button>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>CVE LOOKUP (optional — overrides query)</label><input class="inp inp-mono" id="searchsploit-cve" type="text" placeholder="CVE-2021-44228"/></div>
          <button class="btn btn-primary" id="searchsploit-btn" onclick="runSearchsploit()">SEARCH EXPLOIT-DB</button>
        </div>''',
))

# ─── MSFVENOM ────────────────────────────────────────────────
TOOL_PAGES.append((
    "msfvenom — proper payload/format fields",
    '''      <!-- MSFVENOM -->
      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator and encoder</div></div>
        <div class="notice">&#9888; Authorized use only. Only run msfvenom on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="msfvenom-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="msfvenom-bin" type="text" value="msfvenom"/></div>
          </div>
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runGenericTool('msfvenom','msfvenom')">RUN MSFVENOM</button>
        </div>''',
    '''      <!-- MSFVENOM -->
      <div class="page" id="page-msfvenom">
        <div class="page-hd"><div class="page-title">msfvenom</div><div class="page-desc">Metasploit payload generator — create reverse shells, staged/stageless payloads</div></div>
        <div class="notice">&#9888; Authorized red-team use only. Generated payloads must only be used on systems you own or have explicit written authorization to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PAYLOAD</label>
              <select class="inp inp-mono" id="msfvenom-payload">
                <option value="windows/x64/meterpreter/reverse_tcp" selected>Windows x64 Meterpreter (TCP)</option>
                <option value="windows/meterpreter/reverse_tcp">Windows x86 Meterpreter (TCP)</option>
                <option value="windows/x64/shell_reverse_tcp">Windows x64 Shell (TCP)</option>
                <option value="linux/x64/meterpreter/reverse_tcp">Linux x64 Meterpreter (TCP)</option>
                <option value="linux/x64/shell_reverse_tcp">Linux x64 Shell (TCP)</option>
                <option value="osx/x64/meterpreter_reverse_tcp">macOS x64 Meterpreter (TCP)</option>
                <option value="java/meterpreter/reverse_tcp">Java Meterpreter (TCP)</option>
                <option value="php/meterpreter/reverse_tcp">PHP Meterpreter (TCP)</option>
                <option value="python/meterpreter/reverse_tcp">Python Meterpreter (TCP)</option>
                <option value="cmd/unix/reverse_bash">Unix CMD Reverse Bash</option>
                <option value="custom">Custom (enter below)</option>
              </select>
            </div>
            <div class="fg"><label>CUSTOM PAYLOAD (if Custom selected)</label><input class="inp inp-mono" id="msfvenom-custom-payload" type="text" placeholder="windows/x64/meterpreter_reverse_https"/></div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>LHOST (your IP)</label><input class="inp inp-mono" id="msfvenom-lhost" type="text" placeholder="192.168.1.100"/></div>
            <div class="fg"><label>LPORT</label><input class="inp inp-mono" id="msfvenom-lport" type="number" value="4444" min="1" max="65535"/></div>
            <div class="fg"><label>OUTPUT FORMAT (-f)</label>
              <select class="inp inp-mono" id="msfvenom-format">
                <option value="exe" selected>exe (Windows)</option>
                <option value="elf">elf (Linux)</option>
                <option value="macho">macho (macOS)</option>
                <option value="asp">asp (Web)</option>
                <option value="aspx">aspx (Web)</option>
                <option value="jsp">jsp (Java)</option>
                <option value="php">php (PHP)</option>
                <option value="py">py (Python)</option>
                <option value="rb">rb (Ruby)</option>
                <option value="raw">raw (shellcode)</option>
                <option value="c">c (C shellcode)</option>
                <option value="powershell">powershell</option>
              </select>
            </div>
          </div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>ENCODER (optional)</label>
              <select class="inp inp-mono" id="msfvenom-encoder">
                <option value="">None</option>
                <option value="x86/shikata_ga_nai">x86/shikata_ga_nai</option>
                <option value="x64/xor_dynamic">x64/xor_dynamic</option>
                <option value="cmd/powershell_base64">cmd/powershell_base64</option>
              </select>
            </div>
            <div class="fg"><label>ITERATIONS</label><input class="inp inp-mono" id="msfvenom-iterations" type="number" value="1" min="1" max="10"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="msfvenom-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>EXTRA OPTIONS (EXITFUNC, PREPEND, etc.)</label><input class="inp inp-mono" id="msfvenom-extra" type="text" placeholder="EXITFUNC=thread PrependSetresuid=true"/></div>
          <button class="btn btn-primary" id="msfvenom-btn" onclick="runMsfvenom()">GENERATE PAYLOAD</button>
        </div>''',
))

# ─── GRYPE ───────────────────────────────────────────────────
TOOL_PAGES.append((
    "grype — proper image/path fields",
    '''      <!-- GRYPE -->
      <div class="page" id="page-grype">
        <div class="page-hd"><div class="page-title">Grype</div><div class="page-desc">Vulnerability scanner for container images and filesystems</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Grype on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="grype-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="grype-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="grype-bin" type="text" value="grype"/></div>
          </div>
          <button class="btn btn-primary" id="grype-btn" onclick="runGenericTool('grype','grype')">RUN GRYPE</button>
        </div>''',
    '''      <!-- GRYPE -->
      <div class="page" id="page-grype">
        <div class="page-hd"><div class="page-title">Grype</div><div class="page-desc">Vulnerability scanner for container images, filesystems, and SBOMs</div></div>
        <div class="notice">&#9432; Grype scans containers and local filesystems for known CVEs using the Grype DB.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>TARGET (container image, dir, or file)</label><input class="inp inp-mono" id="grype-target" type="text" placeholder="ubuntu:22.04 OR nginx:latest OR /path/to/project OR sbom.json"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>TARGET TYPE</label>
              <select class="inp inp-mono" id="grype-scope">
                <option value="">Auto-detect</option>
                <option value="all-layers">All layers (image)</option>
                <option value="squashed">Squashed (image)</option>
                <option value="dir:">Directory</option>
                <option value="file:">Single file</option>
              </select>
            </div>
            <div class="fg"><label>SEVERITY THRESHOLD</label>
              <select class="inp inp-mono" id="grype-severity">
                <option value="">Show all</option>
                <option value="--fail-on critical">Critical only</option>
                <option value="--fail-on high">High+</option>
                <option value="--fail-on medium">Medium+</option>
              </select>
            </div>
            <div class="fg"><label>OUTPUT FORMAT</label>
              <select class="inp inp-mono" id="grype-format">
                <option value="table" selected>Table</option>
                <option value="json">JSON</option>
                <option value="cyclonedx">CycloneDX SBOM</option>
                <option value="sarif">SARIF</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg">
              <label>OPTIONS</label>
              <div class="pills" style="margin-top:6px">
                <button class="pill on" id="grype-only-fixed" onclick="this.classList.toggle('on')">Only fixed vulns</button>
                <button class="pill" id="grype-add-cpes" onclick="this.classList.toggle('on')">Add CPEs</button>
                <button class="pill" id="grype-update-db" onclick="this.classList.toggle('on')">Update DB first</button>
              </div>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="grype-timeout" type="number" value="180" min="30" max="1800"/></div>
          </div>
          <button class="btn btn-primary" id="grype-btn" onclick="runGrype()">RUN GRYPE</button>
        </div>''',
))

# ─── RADARE2 ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "radare2 — proper binary/command fields",
    '''      <!-- RADARE2 -->
      <div class="page" id="page-radare2">
        <div class="page-hd"><div class="page-title">Radare2</div><div class="page-desc">Reverse engineering framework — disassembly, analysis, debugging</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Radare2 on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="radare2-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="radare2-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="radare2-bin" type="text" value="radare2"/></div>
          </div>
          <button class="btn btn-primary" id="radare2-btn" onclick="runGenericTool('radare2','radare2')">RUN RADARE2</button>
        </div>''',
    '''      <!-- RADARE2 -->
      <div class="page" id="page-radare2">
        <div class="page-hd"><div class="page-title">Radare2</div><div class="page-desc">Reverse engineering framework — binary analysis, disassembly, patching</div></div>
        <div class="notice">&#9432; Radare2 is a binary analysis tool. Use rarun2 / r2pipe for headless operation. This interface runs r2 with -q (quiet) mode.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>BINARY / FILE PATH</label><input class="inp inp-mono" id="radare2-file" type="text" placeholder="/path/to/binary OR /path/to/firmware.bin"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ANALYSIS COMMANDS (r2 script, one per line)</label>
              <textarea class="inp inp-mono" id="radare2-cmds" rows="6" placeholder="aaa&#10;afl&#10;pdf @ main&#10;iz&#10;iS&#10;ii"></textarea>
            </div>
            <div class="fg">
              <label>QUICK COMMAND SETS</label>
              <div style="display:flex;flex-direction:column;gap:6px;margin-top:6px">
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('info')">Binary Info (i, il, iz)</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('functions')">List Functions (aaa, afl)</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('strings')">Extract Strings (izz)</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('imports')">Imports/Exports (ii, iE)</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('sections')">Sections (iS)</button>
                <button class="btn btn-outline btn-sm" onclick="r2QuickLoad('entropy')">Entropy analysis (p=e)</button>
              </div>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ARCHITECTURE (optional)</label>
              <select class="inp inp-mono" id="radare2-arch">
                <option value="">Auto-detect</option>
                <option value="-a x86">x86</option>
                <option value="-a x86 -b 64">x86-64</option>
                <option value="-a arm">ARM</option>
                <option value="-a arm -b 64">ARM64</option>
                <option value="-a mips">MIPS</option>
              </select>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="radare2-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <button class="btn btn-primary" id="radare2-btn" onclick="runRadare2()">RUN RADARE2</button>
        </div>''',
))

# ─── OPENVAS ─────────────────────────────────────────────────
TOOL_PAGES.append((
    "openvas — proper target/scan config fields",
    '''      <!-- OPENVAS -->
      <div class="page" id="page-openvas">
        <div class="page-hd"><div class="page-title">OpenVAS</div><div class="page-desc">Open vulnerability assessment system — comprehensive network scanner</div></div>
        <div class="notice">&#9888; Authorized use only. Only run OpenVAS on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="openvas-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="openvas-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="openvas-bin" type="text" value="openvas"/></div>
          </div>
          <button class="btn btn-primary" id="openvas-btn" onclick="runGenericTool('openvas','openvas')">RUN OPENVAS</button>
        </div>''',
    '''      <!-- OPENVAS -->
      <div class="page" id="page-openvas">
        <div class="page-hd"><div class="page-title">OpenVAS / GVM</div><div class="page-desc">Comprehensive vulnerability scanner — 100,000+ NVTs, CVE-enriched results</div></div>
        <div class="notice">&#9888; Authorized use only. OpenVAS must be installed and running (gvmd daemon). Only scan systems you own or have written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="notice" style="margin-bottom:14px">&#9432; OpenVAS uses a web interface (Greenbone Security Assistant at port 9392) for full scan management. This panel runs CLI checks and service status.</div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>GVM HOST</label><input class="inp inp-mono" id="openvas-gvmhost" type="text" value="127.0.0.1"/></div>
            <div class="fg"><label>GVM PORT</label><input class="inp inp-mono" id="openvas-gvmport" type="number" value="9390" min="1" max="65535"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>GVM USER</label><input class="inp inp-mono" id="openvas-user" type="text" value="admin"/></div>
            <div class="fg"><label>GVM PASSWORD</label><input class="inp inp-mono" id="openvas-pass" type="password" placeholder="admin"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>OPERATION</label>
            <select class="inp inp-mono" id="openvas-op">
              <option value="--version">Version check (openvas --version)</option>
              <option value="check-setup">Check setup (gvm-check-setup)</option>
              <option value="--get-scanners">List scanners</option>
              <option value="--help">Help</option>
            </select>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="openvas-timeout" type="number" value="60" min="10" max="300"/></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="openvas-btn" onclick="runOpenVAS()">RUN OPENVAS CLI</button>
            <a class="btn btn-outline btn-sm" href="http://127.0.0.1:9392" target="_blank">OPEN GSA WEB UI &#8599;</a>
          </div>
        </div>''',
))

# ─── CHKROOTKIT ──────────────────────────────────────────────
TOOL_PAGES.append((
    "chkrootkit — proper scan options",
    '''      <!-- CHKROOTKIT -->
      <div class="page" id="page-chkrootkit">
        <div class="page-hd"><div class="page-title">chkrootkit</div><div class="page-desc">Local rootkit detector — checks for known rootkit signatures</div></div>
        <div class="notice">&#9888; Authorized use only. Only run chkrootkit on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="chkrootkit-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chkrootkit-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="chkrootkit-bin" type="text" value="chkrootkit"/></div>
          </div>
          <button class="btn btn-primary" id="chkrootkit-btn" onclick="runGenericTool('chkrootkit','chkrootkit')">RUN CHKROOTKIT</button>
        </div>''',
    '''      <!-- CHKROOTKIT -->
      <div class="page" id="page-chkrootkit">
        <div class="page-hd"><div class="page-title">chkrootkit</div><div class="page-desc">Local rootkit detector — checks binaries, processes, and network interfaces for compromise</div></div>
        <div class="notice">&#9432; chkrootkit scans the local system only. Run as root for complete results. False positives are possible — verify findings manually.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SCAN MODE</label>
              <select class="inp inp-mono" id="chkrootkit-mode">
                <option value="" selected>Full scan (all tests)</option>
                <option value="-x">Expert mode (-x, show strings)</option>
                <option value="-q">Quiet (-q, only infected)</option>
                <option value="-l">List tests (-l)</option>
              </select>
            </div>
            <div class="fg"><label>SPECIFIC TEST (optional)</label>
              <select class="inp inp-mono" id="chkrootkit-test">
                <option value="">Run all tests</option>
                <option value="aliens">Aliens (hidden procs)</option>
                <option value="asp">ASP</option>
                <option value="bindshell">Bind shell backdoor</option>
                <option value="lkm">LKM rootkit</option>
                <option value="rexedcs">Rexedcs</option>
                <option value="sniffer">Network sniffer</option>
                <option value="wted">wtmp editor</option>
                <option value="z2">z2 (utmp editor)</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>ALTERNATE PATH TO CHECK (optional)</label><input class="inp inp-mono" id="chkrootkit-path" type="text" placeholder="/mnt/suspect_root"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chkrootkit-timeout" type="number" value="120" min="30" max="600"/></div>
          </div>
          <button class="btn btn-primary" id="chkrootkit-btn" onclick="runChkrootkit()">RUN CHKROOTKIT</button>
        </div>''',
))

# ─── RKHUNTER ────────────────────────────────────────────────
TOOL_PAGES.append((
    "rkhunter — proper scan options",
    '''      <!-- RKHUNTER -->
      <div class="page" id="page-rkhunter">
        <div class="page-hd"><div class="page-title">rkhunter</div><div class="page-desc">Rootkit Hunter — scans for rootkits, backdoors, and exploits</div></div>
        <div class="notice">&#9888; Authorized use only. Only run rkhunter on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="rkhunter-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rkhunter-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="rkhunter-bin" type="text" value="rkhunter"/></div>
          </div>
          <button class="btn btn-primary" id="rkhunter-btn" onclick="runGenericTool('rkhunter','rkhunter')">RUN RKHUNTER</button>
        </div>''',
    '''      <!-- RKHUNTER -->
      <div class="page" id="page-rkhunter">
        <div class="page-hd"><div class="page-title">rkhunter</div><div class="page-desc">Rootkit Hunter — comprehensive backdoor and exploit scanner</div></div>
        <div class="notice">&#9432; rkhunter scans the local system. Run as root for full results. Update signatures before scanning for best coverage.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>SCAN TYPE</label>
              <select class="inp inp-mono" id="rkhunter-scantype">
                <option value="--check" selected>Full check (--check)</option>
                <option value="--check --rwo">Warnings only (--rwo)</option>
                <option value="--update">Update database (--update)</option>
                <option value="--propupd">Update file properties (--propupd)</option>
                <option value="--list">List checks/rootkits</option>
                <option value="--version">Version info</option>
              </select>
            </div>
            <div class="fg"><label>ENABLE TESTS (optional)</label>
              <select class="inp inp-mono" id="rkhunter-enable" multiple style="height:80px;padding:6px">
                <option value="all" selected>ALL</option>
                <option value="rootkits">Rootkits</option>
                <option value="apps">App checks</option>
                <option value="network">Network interfaces</option>
                <option value="filesystem">Filesystem</option>
                <option value="startup_malware">Startup malware</option>
              </select>
            </div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg">
              <label>OPTIONS</label>
              <div class="pills" style="margin-top:6px">
                <button class="pill on" id="rkhunter-skip-keypress" onclick="this.classList.toggle('on')">--skip-keypress</button>
                <button class="pill on" id="rkhunter-nocolors" onclick="this.classList.toggle('on')">--nocolors</button>
                <button class="pill" id="rkhunter-append-log" onclick="this.classList.toggle('on')">--append-log</button>
              </div>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rkhunter-timeout" type="number" value="300" min="60" max="1800"/></div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="rkhunter-btn" onclick="runRkhunter()">RUN RKHUNTER</button>
            <button class="btn btn-outline btn-sm" onclick="runRkhunterUpdate()">UPDATE DB FIRST</button>
          </div>
        </div>''',
))

# ─── PSPY ────────────────────────────────────────────────────
TOOL_PAGES.append((
    "pspy — proper interval/filter fields",
    '''      <!-- PSPY -->
      <div class="page" id="page-pspy">
        <div class="page-hd"><div class="page-title">pspy</div><div class="page-desc">Process spy — monitor Linux processes without root privileges</div></div>
        <div class="notice">&#9888; Authorized use only. Only run pspy on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="pspy-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pspy-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="pspy-bin" type="text" value="pspy"/></div>
          </div>
          <button class="btn btn-primary" id="pspy-btn" onclick="runGenericTool('pspy','pspy')">RUN PSPY</button>
        </div>''',
    '''      <!-- PSPY -->
      <div class="page" id="page-pspy">
        <div class="page-hd"><div class="page-title">pspy</div><div class="page-desc">Process spy — monitor Linux cron jobs and processes without root access</div></div>
        <div class="notice">&#9432; pspy passively monitors /proc for new processes. Useful for finding cron jobs, scripts run by root, and hidden processes during CTF/pentests.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>BINARY ARCHITECTURE</label>
              <select class="inp inp-mono" id="pspy-arch">
                <option value="pspy64" selected>pspy64 (x86-64)</option>
                <option value="pspy32">pspy32 (x86)</option>
                <option value="pspy64s">pspy64s (static)</option>
                <option value="pspy32s">pspy32s (static)</option>
                <option value="pspy">pspy (system)</option>
              </select>
            </div>
            <div class="fg"><label>WATCH INTERVAL (ms)</label><input class="inp inp-mono" id="pspy-interval" type="number" value="100" min="10" max="10000"/></div>
            <div class="fg"><label>MONITOR DURATION (sec)</label><input class="inp inp-mono" id="pspy-duration" type="number" value="30" min="10" max="300"/></div>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>FILTER (grep pattern, optional)</label><input class="inp inp-mono" id="pspy-filter" type="text" placeholder="cron|bash|python|root"/></div>
            <div class="fg"><label>PSPY BINARY PATH</label><input class="inp inp-mono" id="pspy-path" type="text" value="/usr/local/bin/pspy64" placeholder="/tmp/pspy64"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="pspy-fs" onclick="this.classList.toggle('on')">Watch filesystem (-f)</button>
            <button class="pill" id="pspy-color" onclick="this.classList.toggle('on')">Color output</button>
          </div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">
            &#9432; Download pspy from: <a href="https://github.com/DominicBreuker/pspy/releases" target="_blank" style="color:var(--blue)">github.com/DominicBreuker/pspy/releases</a>
          </div>
          <button class="btn btn-primary" id="pspy-btn" onclick="runPspy()">RUN PSPY</button>
        </div>''',
))

# ─── PWNCAT ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "pwncat — proper listener/connect fields",
    '''      <!-- PWNCAT -->
      <div class="page" id="page-pwncat">
        <div class="page-hd"><div class="page-title">pwncat</div><div class="page-desc">Feature-rich reverse/bind shell handler with post-exploitation</div></div>
        <div class="notice">&#9888; Authorized use only. Only run pwncat on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="pwncat-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pwncat-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="pwncat-bin" type="text" value="pwncat"/></div>
          </div>
          <button class="btn btn-primary" id="pwncat-btn" onclick="runGenericTool('pwncat','pwncat')">RUN PWNCAT</button>
        </div>''',
    '''      <!-- PWNCAT -->
      <div class="page" id="page-pwncat">
        <div class="page-hd"><div class="page-title">pwncat-cs</div><div class="page-desc">Advanced reverse/bind shell handler with post-exploitation framework</div></div>
        <div class="notice">&#9888; Authorized red-team use only. Only use on systems you own or have explicit written authorization to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>CONNECTION MODE</label>
            <select class="inp inp-mono" id="pwncat-mode" onchange="pwncatModeChange()">
              <option value="listen" selected>Listen for reverse shell</option>
              <option value="connect">Connect to bind shell</option>
              <option value="ssh">SSH connect</option>
              <option value="help">Help / capability check</option>
            </select>
          </div>
          <div id="pwncat-listen-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>LISTEN HOST</label><input class="inp inp-mono" id="pwncat-lhost" type="text" value="0.0.0.0"/></div>
              <div class="fg"><label>LISTEN PORT</label><input class="inp inp-mono" id="pwncat-lport" type="number" value="4444" min="1" max="65535"/></div>
            </div>
          </div>
          <div id="pwncat-connect-fields" style="display:none">
            <div class="row3" style="margin-bottom:12px">
              <div class="fg"><label>REMOTE HOST</label><input class="inp inp-mono" id="pwncat-rhost" type="text" placeholder="192.168.1.100"/></div>
              <div class="fg"><label>REMOTE PORT</label><input class="inp inp-mono" id="pwncat-rport" type="number" value="4444" min="1" max="65535"/></div>
              <div class="fg"><label>PLATFORM</label>
                <select class="inp inp-mono" id="pwncat-platform">
                  <option value="linux" selected>Linux</option>
                  <option value="windows">Windows</option>
                </select>
              </div>
            </div>
          </div>
          <div id="pwncat-ssh-fields" style="display:none">
            <div class="row3" style="margin-bottom:12px">
              <div class="fg"><label>SSH HOST</label><input class="inp inp-mono" id="pwncat-sshhost" type="text" placeholder="192.168.1.100"/></div>
              <div class="fg"><label>SSH PORT</label><input class="inp inp-mono" id="pwncat-sshport" type="number" value="22"/></div>
              <div class="fg"><label>SSH USER</label><input class="inp inp-mono" id="pwncat-sshuser" type="text" placeholder="root"/></div>
            </div>
            <div class="fg" style="margin-bottom:12px"><label>SSH PASSWORD / KEY</label><input class="inp inp-mono" id="pwncat-sshpass" type="password" placeholder="password or /path/to/key"/></div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="pwncat-timeout" type="number" value="60" min="10" max="300"/></div>
          <button class="btn btn-primary" id="pwncat-btn" onclick="runPwncat()">RUN PWNCAT</button>
        </div>''',
))

# ─── LIGOLO-NG ───────────────────────────────────────────────
TOOL_PAGES.append((
    "ligolo — proper proxy/agent mode fields",
    '''      <!-- LIGOLO-NG -->
      <div class="page" id="page-ligolo">
        <div class="page-hd"><div class="page-title">Ligolo-ng</div><div class="page-desc">Advanced tunneling tool for network pivoting via TUN interface</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Ligolo-ng on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="ligolo-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ligolo-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="ligolo-bin" type="text" value="ligolo-ng"/></div>
          </div>
          <button class="btn btn-primary" id="ligolo-btn" onclick="runGenericTool('ligolo','ligolo-ng')">RUN LIGOLO-NG</button>
        </div>''',
    '''      <!-- LIGOLO-NG -->
      <div class="page" id="page-ligolo">
        <div class="page-hd"><div class="page-title">Ligolo-ng</div><div class="page-desc">Reverse tunneling agent — pivot through compromised hosts via TUN interface</div></div>
        <div class="notice">&#9888; Authorized red-team engagements only. Ligolo-ng requires a TUN interface (root) on the proxy (attacker) side.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>COMPONENT</label>
            <select class="inp inp-mono" id="ligolo-component" onchange="ligoloComponentChange()">
              <option value="proxy" selected>Proxy (run on attacker machine)</option>
              <option value="agent">Agent (deploy on pivot host)</option>
              <option value="help">Help / version</option>
            </select>
          </div>
          <div id="ligolo-proxy-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>PROXY LISTEN ADDR</label><input class="inp inp-mono" id="ligolo-proxy-listen" type="text" value="0.0.0.0:11601"/></div>
              <div class="fg"><label>TUN INTERFACE NAME</label><input class="inp inp-mono" id="ligolo-tun" type="text" value="ligolo"/></div>
            </div>
            <div class="pills" style="margin-bottom:12px">
              <button class="pill on" id="ligolo-selfcert" onclick="this.classList.toggle('on')">Self-signed cert (--selfcert)</button>
              <button class="pill" id="ligolo-verbose-p" onclick="this.classList.toggle('on')">Verbose</button>
            </div>
          </div>
          <div id="ligolo-agent-fields" style="display:none">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>PROXY ADDRESS (attacker:port)</label><input class="inp inp-mono" id="ligolo-agent-proxy" type="text" placeholder="192.168.1.100:11601"/></div>
              <div class="fg"><label>AGENT BINARY PATH</label><input class="inp inp-mono" id="ligolo-agent-bin" type="text" value="/tmp/agent"/></div>
            </div>
            <div class="pills" style="margin-bottom:12px">
              <button class="pill on" id="ligolo-ignore-cert" onclick="this.classList.toggle('on')">Ignore cert (--ignore-cert)</button>
              <button class="pill" id="ligolo-verbose-a" onclick="this.classList.toggle('on')">Verbose</button>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="ligolo-timeout" type="number" value="60" min="10" max="300"/></div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">&#9432; Quick setup: sudo ip tuntap add user $USER mode tun ligolo &amp;&amp; sudo ip link set ligolo up</div>
          <button class="btn btn-primary" id="ligolo-btn" onclick="runLigolo()">RUN LIGOLO-NG</button>
        </div>''',
))

# ─── CHISEL ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "chisel — proper server/client mode fields",
    '''      <!-- CHISEL -->
      <div class="page" id="page-chisel">
        <div class="page-hd"><div class="page-title">Chisel</div><div class="page-desc">Fast TCP/UDP tunnel over HTTP using SSH transport</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Chisel on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="chisel-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="chisel-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="chisel-bin" type="text" value="chisel"/></div>
          </div>
          <button class="btn btn-primary" id="chisel-btn" onclick="runGenericTool('chisel','chisel')">RUN CHISEL</button>
        </div>''',
    '''      <!-- CHISEL -->
      <div class="page" id="page-chisel">
        <div class="page-hd"><div class="page-title">Chisel</div><div class="page-desc">TCP/UDP tunnel over HTTP — SOCKS5, local and remote port forwarding</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Chisel on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>MODE</label>
            <select class="inp inp-mono" id="chisel-mode" onchange="chiselModeChange()">
              <option value="server" selected>Server (run on attacker/relay)</option>
              <option value="client">Client (run on pivot host)</option>
              <option value="help">Help / version</option>
            </select>
          </div>
          <div id="chisel-server-fields">
            <div class="row2" style="margin-bottom:12px">
              <div class="fg"><label>LISTEN PORT</label><input class="inp inp-mono" id="chisel-server-port" type="number" value="8080" min="1" max="65535"/></div>
              <div class="fg"><label>AUTH (user:pass, optional)</label><input class="inp inp-mono" id="chisel-server-auth" type="text" placeholder="admin:secret"/></div>
            </div>
            <div class="pills" style="margin-bottom:12px">
              <button class="pill on" id="chisel-socks5" onclick="this.classList.toggle('on')">SOCKS5 proxy (--socks5)</button>
              <button class="pill" id="chisel-reverse" onclick="this.classList.toggle('on')">Allow reverse (--reverse)</button>
              <button class="pill" id="chisel-tls" onclick="this.classList.toggle('on')">TLS encrypt</button>
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
          <button class="btn btn-primary" id="chisel-btn" onclick="runChisel()">RUN CHISEL</button>
        </div>''',
))

# ─── RLWRAP ──────────────────────────────────────────────────
TOOL_PAGES.append((
    "rlwrap — proper command fields",
    '''      <!-- RLWRAP -->
      <div class="page" id="page-rlwrap">
        <div class="page-hd"><div class="page-title">rlwrap</div><div class="page-desc">Readline wrapper — adds command history to any CLI tool</div></div>
        <div class="notice">&#9888; Authorized use only. Only run rlwrap on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="rlwrap-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rlwrap-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="rlwrap-bin" type="text" value="rlwrap"/></div>
          </div>
          <button class="btn btn-primary" id="rlwrap-btn" onclick="runGenericTool('rlwrap','rlwrap')">RUN RLWRAP</button>
        </div>''',
    '''      <!-- RLWRAP -->
      <div class="page" id="page-rlwrap">
        <div class="page-hd"><div class="page-title">rlwrap</div><div class="page-desc">Readline wrapper — adds history, editing &amp; completion to any shell/REPL</div></div>
        <div class="notice">&#9432; rlwrap is typically used to upgrade a raw netcat shell. Example: rlwrap nc -lvnp 4444</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>COMMAND TO WRAP</label><input class="inp inp-mono" id="rlwrap-cmd" type="text" placeholder="nc -lvnp 4444"/></div>
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>HISTORY SIZE (-s)</label><input class="inp inp-mono" id="rlwrap-history" type="number" value="1000" min="0" max="100000"/></div>
            <div class="fg"><label>WORD CHARS (-w)</label><input class="inp inp-mono" id="rlwrap-wordchars" type="text" placeholder="a-zA-Z0-9_-" value="a-zA-Z0-9_-"/></div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="rlwrap-timeout" type="number" value="60" min="10" max="300"/></div>
          </div>
          <div class="pills" style="margin-bottom:12px">
            <button class="pill on" id="rlwrap-ansi" onclick="this.classList.toggle('on')">ANSI colour fix (-A)</button>
            <button class="pill" id="rlwrap-noecho" onclick="this.classList.toggle('on')">No echo (-e)</button>
            <button class="pill" id="rlwrap-cbreak" onclick="this.classList.toggle('on')">cbreak mode (-c)</button>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:var(--radius);padding:10px 12px;font-size:12px;color:var(--text2);margin-bottom:12px">
            <strong>Typical usage (upgrade netcat shell):</strong><br/>
            <code style="font-family:var(--mono);font-size:11px">rlwrap -A nc -lvnp 4444</code>
          </div>
          <button class="btn btn-primary" id="rlwrap-btn" onclick="runRlwrap()">RUN RLWRAP</button>
        </div>''',
))

# ─── SCAPY ───────────────────────────────────────────────────
TOOL_PAGES.append((
    "scapy — proper script/command fields",
    '''      <!-- SCAPY -->
      <div class="page" id="page-scapy">
        <div class="page-hd"><div class="page-title">Scapy</div><div class="page-desc">Interactive packet manipulation and network analysis framework</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Scapy on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="scapy-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="scapy-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="scapy-bin" type="text" value="scapy"/></div>
          </div>
          <button class="btn btn-primary" id="scapy-btn" onclick="runGenericTool('scapy','scapy')">RUN SCAPY</button>
        </div>''',
    '''      <!-- SCAPY -->
      <div class="page" id="page-scapy">
        <div class="page-hd"><div class="page-title">Scapy</div><div class="page-desc">Python packet manipulation — craft, send, sniff, and dissect packets</div></div>
        <div class="notice">&#9888; Authorized use only. Packet crafting and sending requires root. Only run Scapy on networks you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>SCAPY SCRIPT (Python — runs via python3 -c)</label>
            <textarea class="inp inp-mono" id="scapy-script" rows="8" placeholder="from scapy.all import *&#10;&#10;# Example: ICMP ping&#10;target = '192.168.1.1'&#10;pkt = IP(dst=target)/ICMP()&#10;reply = sr1(pkt, timeout=2, verbose=0)&#10;if reply:&#10;    print(f'Host {target} is up: {reply.summary()}')&#10;else:&#10;    print(f'No response from {target}')"></textarea>
          </div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>QUICK TEMPLATES</label>
              <div style="display:flex;flex-direction:column;gap:5px;margin-top:4px">
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('ping')">ICMP Ping</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('portscan')">TCP Port Scan</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('syn')">SYN Scan</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('arpscan')">ARP Scan (LAN)</button>
                <button class="btn btn-outline btn-sm" onclick="scapyTemplate('traceroute')">Traceroute</button>
              </div>
            </div>
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="scapy-timeout" type="number" value="30" min="5" max="300"/></div>
          </div>
          <button class="btn btn-primary" id="scapy-btn" onclick="runScapy()">RUN SCAPY SCRIPT</button>
        </div>''',
))

# ─── YERSINIA ────────────────────────────────────────────────
TOOL_PAGES.append((
    "yersinia — proper protocol/interface fields",
    '''      <!-- YERSINIA -->
      <div class="page" id="page-yersinia">
        <div class="page-hd"><div class="page-title">Yersinia</div><div class="page-desc">Network protocol attacks (STP, CDP, DTP, DHCP, 802.1Q, VTP, HSRP)</div></div>
        <div class="notice">&#9888; Authorized use only. Only run Yersinia on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="yersinia-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="yersinia-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="yersinia-bin" type="text" value="yersinia"/></div>
          </div>
          <button class="btn btn-primary" id="yersinia-btn" onclick="runGenericTool('yersinia','yersinia')">RUN YERSINIA</button>
        </div>''',
    '''      <!-- YERSINIA -->
      <div class="page" id="page-yersinia">
        <div class="page-hd"><div class="page-title">Yersinia</div><div class="page-desc">Layer 2 protocol attack framework — STP, DHCP, VTP, CDP, HSRP, DTP, 802.1Q</div></div>
        <div class="notice">&#9888; Authorized use only. Layer 2 attacks affect entire network segments. Only run on networks you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="row3" style="margin-bottom:12px">
            <div class="fg"><label>PROTOCOL</label>
              <select class="inp inp-mono" id="yersinia-proto">
                <option value="stp" selected>STP (Spanning Tree)</option>
                <option value="cdp">CDP (Cisco Discovery)</option>
                <option value="dhcp">DHCP</option>
                <option value="dot1q">802.1Q VLAN</option>
                <option value="dtp">DTP (Dynamic Trunking)</option>
                <option value="hsrp">HSRP</option>
                <option value="isl">ISL</option>
                <option value="vtp">VTP</option>
              </select>
            </div>
            <div class="fg"><label>NETWORK INTERFACE</label><input class="inp inp-mono" id="yersinia-iface" type="text" placeholder="eth0" value="eth0"/></div>
            <div class="fg"><label>OPERATION</label>
              <select class="inp inp-mono" id="yersinia-action">
                <option value="--help">Help / list attacks</option>
                <option value="-G">GUI mode</option>
                <option value="-I">Interactive mode</option>
              </select>
            </div>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="yersinia-timeout" type="number" value="30" min="5" max="300"/></div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:var(--radius);padding:10px 12px;font-size:12px;color:var(--text2);margin-bottom:12px">
            &#9888; <strong>Warning:</strong> Layer 2 attacks (especially DHCP starvation, STP root election) will disrupt ALL devices on the broadcast domain. Only use in isolated lab environments.
          </div>
          <button class="btn btn-primary" id="yersinia-btn" onclick="runYersinia()">RUN YERSINIA</button>
        </div>''',
))

# ─── SECLISTS ────────────────────────────────────────────────
TOOL_PAGES.append((
    "seclists — proper browse/search fields",
    '''      <!-- SECLISTS -->
      <div class="page" id="page-seclists">
        <div class="page-hd"><div class="page-title">SecLists</div><div class="page-desc">Collection of security wordlists for fuzzing and enumeration</div></div>
        <div class="notice">&#9888; Authorized use only. Only run SecLists on systems you own or have explicit written permission to test.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>ARGUMENTS / OPTIONS</label><input class="inp inp-mono" id="seclists-args" type="text" placeholder="--help"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>TIMEOUT (sec)</label><input class="inp inp-mono" id="seclists-timeout" type="number" value="90" min="10" max="600"/></div>
            <div class="fg"><label>TOOL BINARY</label><input class="inp inp-mono" id="seclists-bin" type="text" value="seclists"/></div>
          </div>
          <button class="btn btn-primary" id="seclists-btn" onclick="runGenericTool('seclists','seclists')">RUN SECLISTS</button>
        </div>''',
    '''      <!-- SECLISTS -->
      <div class="page" id="page-seclists">
        <div class="page-hd"><div class="page-title">SecLists</div><div class="page-desc">Browse and preview security wordlists installed on this server</div></div>
        <div class="notice">&#9432; SecLists is a wordlist collection — not a tool. Use these lists with ffuf, gobuster, hydra, sqlmap, etc.</div>
        <div class="card card-p" style="margin-bottom:14px">
          <div class="fg"><label>WORDLIST CATEGORY</label>
            <select class="inp inp-mono" id="seclists-category" onchange="seclistsCategoryChange()">
              <option value="/usr/share/seclists/Discovery/Web-Content">Web Content Discovery</option>
              <option value="/usr/share/seclists/Discovery/DNS">DNS Subdomains</option>
              <option value="/usr/share/seclists/Passwords/Common-Credentials">Common Passwords</option>
              <option value="/usr/share/seclists/Passwords/Leaked-Databases">Leaked Databases</option>
              <option value="/usr/share/seclists/Usernames">Usernames</option>
              <option value="/usr/share/seclists/Fuzzing">Fuzzing</option>
              <option value="/usr/share/seclists/Payloads">Payloads</option>
              <option value="/usr/share/seclists/Web-Shells">Web Shells</option>
            </select>
          </div>
          <div class="fg" style="margin-bottom:12px"><label>WORDLIST PATH (full path)</label><input class="inp inp-mono" id="seclists-path" type="text" value="/usr/share/seclists/Discovery/Web-Content/common.txt"/></div>
          <div class="row2" style="margin-bottom:12px">
            <div class="fg"><label>PREVIEW LINES</label><input class="inp inp-mono" id="seclists-lines" type="number" value="50" min="10" max="500"/></div>
            <div class="fg"><label>SEARCH / GREP PATTERN</label><input class="inp inp-mono" id="seclists-grep" type="text" placeholder="admin|config|backup"/></div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" id="seclists-btn" onclick="runSeclists()">BROWSE WORDLIST</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCount()">COUNT ENTRIES</button>
            <button class="btn btn-outline btn-sm" onclick="seclistsCopy()">COPY PATH</button>
          </div>
        </div>''',
))


# ══════════════════════════════════════════════════════════════
# JAVASCRIPT HELPER FUNCTIONS
# These go just before the closing </script> tag in api_server.py
# ══════════════════════════════════════════════════════════════

JS_HELPERS = '''
/* ══ TOOL-SPECIFIC JS HELPERS ══════════════════════════════════ */

/* ffuf */
async function runFfuf() {
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
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Results</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN FFUF';}
}

/* nuclei */
async function runNuclei() {
  var target=document.getElementById('nuclei-target').value.trim();
  if(!target){alert('Enter a target URL or host');return;}
  var sevEl=document.getElementById('nuclei-severity');var sevs=Array.from(sevEl.selectedOptions).map(function(o){return o.value;}).join(',');
  var tagsEl=document.getElementById('nuclei-tags');var tags=Array.from(tagsEl.selectedOptions).map(function(o){return o.value;}).join(',');
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
    else{var lines=(d.stdout||'').split('\n').filter(Boolean).length;t.log('Nuclei done — '+lines+' result line(s)','s');
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Findings</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No findings.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN NUCLEI';}
}
async function runNucleiUpdate(){
  var t=mkTool('nuclei');t.start();t.log('Updating nuclei templates...','w');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'nuclei',operation:'custom',args:'-update-templates',timeout:120})},130000,'nuclei');
  var d=await r.json();t.end();
  t.log(d.error||d.stdout||'Update complete','s');
}

/* whatweb */
async function runWhatWeb() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WHATWEB';}
}

/* wapiti */
async function runWapiti() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN WAPITI';}
}

/* dalfox */
async function runDalfox() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No XSS found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN DALFOX';}
}

/* sqlmap */
async function runSqlmap() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No SQL injection found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SQLMAP';}
}

/* kxss */
async function runKxss() {
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
    // kxss reads from stdin — we pass URLs as stdin via the args field
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'kxss',operation:'custom',args:'<<< "'+urls.replace(/\n/g,'\\n')+'" '+args,timeout:timeout})},Math.max(20000,timeout*1000+5000),'kxss');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('kxss done','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No reflected XSS chars found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN KXSS';}
}

/* medusa */
async function runMedusa() {
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
    else{var found=(d.stdout||'').match(/ACCOUNT FOUND/gi)||[];t.log('Medusa done — '+found.length+' credential(s) found','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No valid credentials found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN MEDUSA';}
}

/* hping3 */
async function runHping3() {
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
  var t=mkTool('hping3');t.start();t.log('hping3 '+mode+' → '+host+':'+port,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hping3',operation:'custom',args:args,timeout:timeout})},Math.max(10000,timeout*1000+5000),'hping3');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('hping3 done','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HPING3';}
}

/* hashcat */
async function runHashcat() {
  var hashes=document.getElementById('hashcat-hashes').value.trim();
  if(!hashes){alert('Enter hashes or a file path');return;}
  var type=document.getElementById('hashcat-type').value||'0';
  var attack=document.getElementById('hashcat-attack').value||'0';
  var wordlist=document.getElementById('hashcat-wordlist').value.trim();
  var rules=document.getElementById('hashcat-rules').value.trim();
  var workload=document.getElementById('hashcat-workload').value||'2';
  var timeout=parseInt(document.getElementById('hashcat-timeout').value||'300',10);
  var hashFile=hashes;
  // if pasted hashes (not a path), it will be written to temp file by the backend
  var args='-m '+type+' -a '+attack+' -w '+workload+' --status --status-timer=5 "'+hashFile+'" "'+wordlist+'"';
  if(rules)args+=' -r '+rules;
  args+=' --force'; // needed for CPU-only environments
  var btn=document.getElementById('hashcat-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Cracking...';
  var t=mkTool('hashcat');t.start();t.log('Hashcat -m '+type+' -a '+attack,'i');t.log('Wordlist: '+wordlist,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'hashcat',operation:'custom',args:args,timeout:timeout})},Math.max(60000,timeout*1000+5000),'hashcat');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{var cracked=(d.stdout||'').match(/Recovered\.+:\s*\d+/i)||[];
      t.log('Hashcat done. '+(cracked[0]||'Check output.'),'s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN HASHCAT';}
}

/* john */
async function runJohn() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN JOHN';}
}
async function runJohnShow() {
  var hashes=document.getElementById('john-hashes').value.trim();
  var fmt=document.getElementById('john-format').value;
  var args='--show '+(fmt||'')+' "'+hashes+'"';
  var t=mkTool('john');t.start();t.log('Showing cracked passwords...','i');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'john',operation:'custom',args:args,timeout:30})},40000,'john');
  var d=await r.json();t.end();
  t.res('<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono)">'+(d.stdout||'Nothing cracked yet.')+'</pre></div>');
}

/* searchsploit */
async function runSearchsploit() {
  var cve=document.getElementById('searchsploit-cve').value.trim();
  var query=cve?('--cve '+cve):document.getElementById('searchsploit-query').value.trim();
  if(!query){alert('Enter a search query or CVE');return;}
  var type=document.getElementById('searchsploit-type').value;
  var platform=document.getElementById('searchsploit-platform').value;
  var format=document.getElementById('searchsploit-format').value;
  var timeout=parseInt('60',10);
  var strict=document.getElementById('searchsploit-strict').classList.contains('on');
  var caseSens=document.getElementById('searchsploit-case').classList.contains('on');
  var args=query+(type?' '+type:'')+(platform?' '+platform:'')+(format?' '+format:'');
  if(strict)args+=' -w';
  if(caseSens)args+=' -c';
  var btn=document.getElementById('searchsploit-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Searching...';
  var t=mkTool('searchsploit');t.start();t.log('Searching Exploit-DB: '+query,'i');
  try{
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'searchsploit',operation:'custom',args:args,timeout:timeout})},70000,'searchsploit');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Search complete','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No exploits found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='SEARCH EXPLOIT-DB';}
}

/* msfvenom */
async function runMsfvenom() {
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
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:8px">Payload Generated</div><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'Done')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='GENERATE PAYLOAD';}
}

/* grype */
async function runGrype() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'No vulnerabilities found.')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN GRYPE';}
}

/* radare2 */
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
async function runRadare2() {
  var file=document.getElementById('radare2-file').value.trim();
  if(!file){alert('Enter a binary file path');return;}
  var cmds=document.getElementById('radare2-cmds').value.trim()||'i';
  var arch=document.getElementById('radare2-arch').value;
  var timeout=parseInt(document.getElementById('radare2-timeout').value||'60',10);
  // Build r2 command: r2 -q -e log.level=1 -c "cmd1;cmd2" -Q file
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RADARE2';}
}

/* openvas */
async function runOpenVAS() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN OPENVAS CLI';}
}

/* chkrootkit */
async function runChkrootkit() {
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
    else{var inf=(d.stdout||'').match(/INFECTED/gi)||[];t.log('Done — '+inf.length+' INFECTED marker(s)','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHKROOTKIT';}
}

/* rkhunter */
async function runRkhunter() {
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
    else{var warn=(d.stdout||'').match(/Warning:/gi)||[];t.log('Done — '+warn.length+' warning(s)','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RKHUNTER';}
}
async function runRkhunterUpdate(){
  var t=mkTool('rkhunter');t.start();t.log('Updating rkhunter database...','i');
  var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'rkhunter',operation:'custom',args:'--update --skip-keypress --nocolors',timeout:120})},130000,'rkhunter');
  var d=await r.json();t.end();t.log(d.error||d.stdout||'Update done','s');
}

/* pspy */
async function runPspy() {
  var bin=document.getElementById('pspy-path').value.trim()||'pspy64';
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
    // Run pspy for the specified duration
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'pspy',operation:'custom',args:args,timeout:parseInt(duration,10)})},Math.max(20000,timeout*1000+5000),'pspy');
    var d=await r.json();t.end();
    var output=d.stdout||'';
    if(filter)output=output.split('\n').filter(function(l){return new RegExp(filter,'i').test(l);}).join('\n');
    t.log('Done — '+(output.split('\n').filter(Boolean).length)+' line(s)','s');
    var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(output||'No processes captured.')+'</pre></div>';
    t.res(html);
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
async function runPwncat() {
  var mode=document.getElementById('pwncat-mode').value||'listen';
  var timeout=parseInt(document.getElementById('pwncat-timeout').value||'60',10);
  var args='';
  if(mode==='listen'){
    var lhost=document.getElementById('pwncat-lhost').value||'0.0.0.0';
    var lport=document.getElementById('pwncat-lport').value||'4444';
    args='-lp '+lport+' --host '+lhost;
  }else if(mode==='connect'){
    var rhost=document.getElementById('pwncat-rhost').value.trim();
    var rport=document.getElementById('pwncat-rport').value||'4444';
    var platform=document.getElementById('pwncat-platform').value||'linux';
    args='--platform '+platform+' '+rhost+':'+rport;
  }else if(mode==='ssh'){
    var sshhost=document.getElementById('pwncat-sshhost').value.trim();
    var sshport=document.getElementById('pwncat-sshport').value||'22';
    var sshuser=document.getElementById('pwncat-sshuser').value.trim();
    var sshpass=document.getElementById('pwncat-sshpass').value.trim();
    args='ssh://'+sshuser+(sshpass?':'+sshpass:'')+'@'+sshhost+':'+sshport;
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN PWNCAT';}
}

/* ligolo */
function ligoloComponentChange(){
  var comp=document.getElementById('ligolo-component').value;
  document.getElementById('ligolo-proxy-fields').style.display=comp==='proxy'?'block':'none';
  document.getElementById('ligolo-agent-fields').style.display=comp==='agent'?'block':'none';
}
async function runLigolo() {
  var comp=document.getElementById('ligolo-component').value||'proxy';
  var timeout=parseInt(document.getElementById('ligolo-timeout').value||'60',10);
  var args='';
  if(comp==='proxy'){
    var listen=document.getElementById('ligolo-proxy-listen').value||'0.0.0.0:11601';
    var tun=document.getElementById('ligolo-tun').value||'ligolo';
    var selfcert=document.getElementById('ligolo-selfcert').classList.contains('on');
    args='-laddr '+listen+' -tun '+tun;
    if(selfcert)args+=' -selfcert';
  }else if(comp==='agent'){
    var proxy=document.getElementById('ligolo-agent-proxy').value.trim();
    var agentBin=document.getElementById('ligolo-agent-bin').value.trim()||'/tmp/agent';
    var ignorecert=document.getElementById('ligolo-ignore-cert').classList.contains('on');
    args='-connect '+proxy;
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN LIGOLO-NG';}
}

/* chisel */
function chiselModeChange(){
  var mode=document.getElementById('chisel-mode').value;
  document.getElementById('chisel-server-fields').style.display=mode==='server'?'block':'none';
  document.getElementById('chisel-client-fields').style.display=mode==='client'?'block':'none';
}
async function runChisel() {
  var mode=document.getElementById('chisel-mode').value||'server';
  var timeout=parseInt(document.getElementById('chisel-timeout').value||'60',10);
  var args=mode+' ';
  if(mode==='server'){
    var port=document.getElementById('chisel-server-port').value||'8080';
    var auth=document.getElementById('chisel-server-auth').value.trim();
    var socks5=document.getElementById('chisel-socks5').classList.contains('on');
    var reverse=document.getElementById('chisel-reverse').classList.contains('on');
    args+='--port='+port;
    if(auth)args+=' --auth='+auth;
    if(socks5)args+=' --socks5';
    if(reverse)args+=' --reverse';
  }else if(mode==='client'){
    var url=document.getElementById('chisel-server-url').value.trim();
    var cauth=document.getElementById('chisel-client-auth').value.trim();
    var tunnels=document.getElementById('chisel-tunnels').value.trim().split('\n').filter(Boolean).join(' ');
    args+=url+' '+(tunnels||'socks');
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN CHISEL';}
}

/* rlwrap */
async function runRlwrap() {
  var cmd=document.getElementById('rlwrap-cmd').value.trim();
  if(!cmd){alert('Enter a command to wrap (e.g. nc -lvnp 4444)');return;}
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN RLWRAP';}
}

/* scapy */
var _scapyTemplates={
  ping:"from scapy.all import *\\ntarget='192.168.1.1'\\npkt=IP(dst=target)/ICMP()\\nreply=sr1(pkt,timeout=2,verbose=0)\\nif reply:\\n    print(f'Up: {reply.summary()}')\\nelse:\\n    print('No response')",
  portscan:"from scapy.all import *\\ntarget='192.168.1.1'\\nports=[22,80,443,3306,8080]\\nfor p in ports:\\n    r=sr1(IP(dst=target)/TCP(dport=p,flags='S'),timeout=1,verbose=0)\\n    if r and r[TCP].flags==0x12:\\n        print(f'Port {p}: OPEN')",
  syn:"from scapy.all import *\\ntarget='192.168.1.1'\\nans,_=sr(IP(dst=target)/TCP(sport=RandShort(),dport=(1,1024),flags='S'),timeout=2,verbose=0)\\nfor s,r in ans:\\n    if r[TCP].flags==0x12:\\n        print(f'Open: {s[TCP].dport}')",
  arpscan:"from scapy.all import *\\nnet='192.168.1.0/24'\\nans,_=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=net),timeout=3,verbose=0)\\nfor s,r in ans:\\n    print(f'{r[ARP].psrc}\\t{r[Ether].src}')",
  traceroute:"from scapy.all import *\\ntarget='8.8.8.8'\\nfor ttl in range(1,30):\\n    r=sr1(IP(dst=target,ttl=ttl)/UDP(dport=33434),timeout=1,verbose=0)\\n    if not r: print(f'{ttl}: *'); continue\\n    print(f'{ttl}: {r.src}')\\n    if r.src==target: break"
};
function scapyTemplate(name){
  var el=document.getElementById('scapy-script');
  if(el&&_scapyTemplates[name])el.value=_scapyTemplates[name].replace(/\\n/g,'\\n');
}
async function runScapy() {
  var script=document.getElementById('scapy-script').value.trim();
  if(!script){alert('Enter a Scapy script');return;}
  var timeout=parseInt(document.getElementById('scapy-timeout').value||'30',10);
  var btn=document.getElementById('scapy-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Running...';
  var t=mkTool('scapy');t.start();t.log('Running Scapy script...','i');
  try{
    // Run via python3 -c "script"
    var r=await fetchWithTimeout('/social-tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'scapy',operation:'custom',args:'-c "'+script.replace(/"/g,'\\"')+'"',timeout:timeout})},Math.max(15000,timeout*1000+5000),'scapy');
    var d=await r.json();t.end();
    if(d.error){t.err(d.error);}
    else{t.log('Script done (exit '+d.exit_code+')','s');
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN SCAPY SCRIPT';}
}

/* yersinia */
async function runYersinia() {
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
      var html='<div class="card card-p"><pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+(d.stdout||d.stderr||'(no output)')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='RUN YERSINIA';}
}

/* seclists */
async function runSeclists() {
  var path=document.getElementById('seclists-path').value.trim();
  var lines=document.getElementById('seclists-lines').value||'50';
  var grep=document.getElementById('seclists-grep').value.trim();
  if(!path){alert('Enter a wordlist path');return;}
  var args='head -n '+lines+' "'+path+'"'+(grep?' | grep -E "'+grep+'"':'');
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
      var html='<div class="card card-p"><div class="card-title" style="margin-bottom:6px">'+path+' ('+d.total_loaded+' entries loaded)</div>'
        +'<pre style="white-space:pre-wrap;font-size:11px;font-family:var(--mono);color:var(--text2)">'+words.join('\n')+'</pre></div>';
      t.res(html);}
  }catch(e){t.end();t.err(e.message);}
  finally{btn.disabled=false;btn.innerHTML='BROWSE WORDLIST';}
}
async function seclistsCount() {
  var path=document.getElementById('seclists-path').value.trim();
  if(!path)return;
  var t=mkTool('seclists');t.start();
  var r=await fetchWithTimeout('/api/wordlist?path='+encodeURIComponent(path)+'&limit=1',{},10000,'seclists');
  var d=await r.json();t.end();
  if(d.error)t.err(d.error);else t.log('File exists. Loaded '+d.total_loaded+' entries (limit 1 shown).','s');
}
function seclistsCopy(){
  var path=document.getElementById('seclists-path').value.trim();
  if(path){try{navigator.clipboard.writeText(path).then(function(){showToast('Copied','Path copied to clipboard','success',2000);});}catch(e){}}
}
function seclistsCategoryChange(){
  var cat=document.getElementById('seclists-category').value;
  // Suggest common files per category
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
'''

# ══════════════════════════════════════════════════════════════
# INJECT JS HELPERS BEFORE loadUser() CALL
# ══════════════════════════════════════════════════════════════

JS_INJECTION = [(
    "Inject tool JS helpers before loadUser() call",
    "\nloadUser();\n",
    "\n" + JS_HELPERS + "\nloadUser();\n",
)]


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║   VulnScan Pro — Tool Pages UI Patch                    ║" + X)
    print(B + C + "║   Replaces generic stubs with proper tool interfaces     ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    target = "api_server.py"

    if not os.path.isfile(target):
        fail(f"Must be run from project root — {target} not found")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    info(f"Target file:  {target}")

    hdr("STEP 1 — Tool Page UI Replacements")
    patch_html(target, TOOL_PAGES)

    hdr("STEP 2 — JavaScript Helper Functions")
    patch_html(target, JS_INJECTION)

    hdr("STEP 3 — Syntax Check")
    passed, err = syntax_check(target)
    if passed:
        ok(f"{target} — syntax OK")
    else:
        fail(f"SYNTAX ERROR:\n{err}")
        print(f"\n  {Y}Restore with:{X}  cp {target}.*.bak {target}")
        sys.exit(1)

    print()
    print(B + C + "══════════════════════════════════════════════════════════" + X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if fc else D)}{fc}{X}"
    )
    print()
    print(f"  {G}Tools updated with proper UI fields:{X}")
    tools = [
        "ffuf       — URL/wordlist/method/filter/threads",
        "nuclei     — target/severity/tags/threads/rate-limit",
        "whatweb    — target/aggression/format/proxy",
        "wapiti     — target/modules/depth/scope/format",
        "dalfox     — URL/mode/payload/header/options",
        "sqlmap     — URL/risk/level/technique/dbms/options",
        "kxss       — multi-URL textarea/header",
        "medusa     — host/protocol/user+pass lists/threads",
        "hping3     — host/mode/count/interval/data-size",
        "hashcat    — hash input/type/attack mode/wordlist/rules",
        "john       — hash input/mode/format/wordlist",
        "searchsploit — query/CVE/type/platform/format",
        "msfvenom   — payload/LHOST/LPORT/format/encoder",
        "grype      — image/scope/severity/format/options",
        "radare2    — binary/commands/quick templates/arch",
        "openvas    — GVM host/operation/web UI link",
        "chkrootkit — mode/specific test/path",
        "rkhunter   — scan type/enable tests/options",
        "pspy       — arch/duration/interval/filter",
        "pwncat     — listen/connect/SSH modes",
        "ligolo-ng  — proxy/agent modes with all options",
        "chisel     — server/client modes with tunnel config",
        "rlwrap     — command wrapper with all options",
        "scapy      — Python script editor + 5 templates",
        "yersinia   — protocol/interface/action",
        "seclists   — browse/search/copy wordlist paths",
    ]
    for t in tools:
        ok(t)
    print()
    print(f"  {Y}Restart server:{X}")
    print(f"    pkill -f api_server.py && python3 api_server.py")
    print()


if __name__ == "__main__":
    main()
