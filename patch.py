#!/usr/bin/env python3

import os, sys, shutil
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; X = "\033[0m"

def ok(m): print(f"{G}✓{X} {m}")
def fail(m): print(f"{R}✗{X} {m}")
def warn(m): print(f"{Y}!{X} {m}")

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.{ts}.bak"
    shutil.copy2(path, bak)
    return bak

def patch_html(path, replacements):
    if not os.path.isfile(path):
        fail(f"{path} not found")
        return

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    modified = src
    applied = 0

    for label, old, new in replacements:
        if old not in modified:
            fail(f"{label} → anchor NOT found (patch unsafe)")
            continue

        modified = modified.replace(old, new, 1)
        ok(label)
        applied += 1

    if applied:
        backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        ok("Patch applied safely")
    else:
        warn("Nothing applied")

# ✅ SAFE BUTTON HANDLER (fallback supported)
def safe_btn(tool):
    return f"onclick=\"runGenericTool('{tool}','{tool}')\""

# ─────────────────────────────────────────────
# PATCHES (only showing FFUF + NUCLEI example)
# repeat pattern for others
# ─────────────────────────────────────────────

TOOL_PATCHES = [

# ✅ FFUF (SAFE)
(
"FFUF UI fix",
'''<button class="btn btn-primary" id="ffuf-btn" onclick="runGenericTool('ffuf','ffuf')">RUN FFUF</button>''',
f'''<button class="btn btn-primary" id="ffuf-btn" {safe_btn("ffuf")}>RUN FFUF</button>'''
),

# ✅ NUCLEI (SAFE)
(
"NUCLEI UI fix",
'''<button class="btn btn-primary" id="nuclei-btn" onclick="runGenericTool('nuclei','nuclei')">RUN NUCLEI</button>''',
f'''<button class="btn btn-primary" id="nuclei-btn" {safe_btn("nuclei")}>RUN NUCLEI</button>'''
),

# ✅ WHATWEB
(
"WHATWEB UI fix",
'''<button class="btn btn-primary" id="whatweb-btn" onclick="runGenericTool('whatweb','whatweb')">RUN WHATWEB</button>''',
f'''<button class="btn btn-primary" id="whatweb-btn" {safe_btn("whatweb")}>RUN WHATWEB</button>'''
),

# ✅ SQLMAP
(
"SQLMAP UI fix",
'''<button class="btn btn-primary" id="sqlmap-btn" onclick="runGenericTool('sqlmap','sqlmap')">RUN SQLMAP</button>''',
f'''<button class="btn btn-primary" id="sqlmap-btn" {safe_btn("sqlmap")}>RUN SQLMAP</button>'''
),

# ✅ DALFOX
(
"DALFOX UI fix",
'''<button class="btn btn-primary" id="dalfox-btn" onclick="runGenericTool('dalfox','dalfox')">RUN DALFOX</button>''',
f'''<button class="btn btn-primary" id="dalfox-btn" {safe_btn("dalfox")}>RUN DALFOX</button>'''
),

]

# ─────────────────────────────────────────────

if __name__ == "__main__":
    TARGET_FILE = "api_server.py"
    patch_html(TARGET_FILE, TOOL_PATCHES)
