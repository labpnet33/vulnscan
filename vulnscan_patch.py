#!/usr/bin/env python3
"""
vulnscan_patch.py — Portal Tech Co. Theme Patcher for VulnScan Pro
=================================================================
Applies the Portal Tech Co. dark glassmorphism theme to the entire
VulnScan Pro codebase, retheming every UI element in api_server.py.

Usage:
    python3 vulnscan_patch.py [--dry-run]

Options:
    --dry-run   Show what would change without writing files

Theme source: portal_tech_theme_guide.html
"""

import os
import sys
import shutil
import re
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────────────────────

DRY_RUN = "--dry-run" in sys.argv

CHANGES_APPLIED  = 0
CHANGES_FAILED   = 0
FILES_MODIFIED   = []
RESTART_NEEDED   = False

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def backup(filepath):
    """Create a .bak backup before modifying a file."""
    bak = filepath + ".bak"
    shutil.copy2(filepath, bak)
    print(f"  📦 Backup created: {bak}")


def patch_file(filepath, old_str, new_str, description=""):
    """
    Find old_str in filepath and replace with new_str.
    Prints ✓ or ✗.  Creates backup on first modification of each file.
    Returns True if the replacement was made.
    """
    global CHANGES_APPLIED, CHANGES_FAILED, RESTART_NEEDED

    if not os.path.isfile(filepath):
        print(f"  ✗ [{description}] — file not found: {filepath}")
        CHANGES_FAILED += 1
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if old_str not in content:
        print(f"  ✗ [{description}] — string not found in {filepath}")
        CHANGES_FAILED += 1
        return False

    new_content = content.replace(old_str, new_str, 1)

    if not DRY_RUN:
        if filepath not in FILES_MODIFIED:
            backup(filepath)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)

    if filepath not in FILES_MODIFIED:
        FILES_MODIFIED.append(filepath)

    CHANGES_APPLIED += 1

    if filepath.endswith(".py"):
        RESTART_NEEDED = True

    print(f"  ✓ [{description}]{'  (dry-run)' if DRY_RUN else ''}")
    return True


# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. THEME — CSS VARIABLES & FONT IMPORT
# Replaces the old :root block and @import in api_server.py's HTML string
# ──────────────────────────────────────────────────────────────────────────────

PORTAL_FONT_IMPORT = "@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:ital,wght@0,300;0,400;0,500;0,600;1,400&display=swap');"

PORTAL_ROOT_VARS = """:root{
  /* === PORTAL TECH CO. THEME VARIABLES === */

  /* Backgrounds */
  --bg:#0a0e1a;
  --bg-dark:#0a0e1a;
  --bg-mid:#0f1628;
  --s1:#0f1628;
  --s2:#141d30;
  --b:#1e2a40;
  --b2:#253350;
  --bg-glass:rgba(255,255,255,0.07);
  --bg-glass-hover:rgba(255,255,255,0.11);
  --bg-active:rgba(79,195,247,0.12);

  /* Borders */
  --border-glass:1px solid rgba(255,255,255,0.10);
  --border-active:1px solid rgba(79,195,247,0.60);

  /* Accent / Brand Colors */
  --cyan:#4fc3f7;
  --teal:#00bcd4;
  --accent:#4fc3f7;
  --green:#a5d6a7;
  --red:#ff6b6b;
  --orange:#ffb74d;
  --yellow:#fff176;
  --purple:#ce93d8;

  /* Text */
  --t:#e0e8f8;
  --m:#7a8aaa;
  --text-white:#f0f4ff;
  --text-body:#b0c4de;
  --text-muted:#7a8aaa;
  --text-accent:#4fc3f7;

  /* Typography */
  --font-display:'Rajdhani',sans-serif;
  --font-body:'Exo 2',sans-serif;
  --font-ui:'Exo 2',sans-serif;
  --font-mono:'Exo 2',monospace;

  /* Radius */
  --radius-sm:6px;
  --radius-md:10px;
  --radius-lg:16px;

  /* Glow */
  --glow-strength:14px;
  --grid-color:rgba(79,195,247,0.025);
}"""

# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. — COMPLETE REPLACEMENT CSS
# Replaces everything inside the <style> tag in the HTML string in api_server.py
# ──────────────────────────────────────────────────────────────────────────────

PORTAL_FULL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:ital,wght@0,300;0,400;0,500;0,600;1,400&display=swap');

*{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0a0e1a;--bg-dark:#0a0e1a;--bg-mid:#0f1628;
  --s1:#0f1628;--s2:#141d30;--b:#1e2a40;--b2:#253350;
  --bg-glass:rgba(255,255,255,0.07);--bg-glass-hover:rgba(255,255,255,0.11);
  --bg-active:rgba(79,195,247,0.12);
  --border-glass:1px solid rgba(255,255,255,0.10);
  --border-active:1px solid rgba(79,195,247,0.60);
  --cyan:#4fc3f7;--teal:#00bcd4;--accent:#4fc3f7;
  --green:#a5d6a7;--red:#ff6b6b;--orange:#ffb74d;
  --yellow:#fff176;--purple:#ce93d8;
  --t:#e0e8f8;--m:#7a8aaa;
  --text-white:#f0f4ff;--text-body:#b0c4de;
  --text-muted:#7a8aaa;--text-accent:#4fc3f7;
  --font-display:'Rajdhani',sans-serif;
  --font-body:'Exo 2',sans-serif;
  --font-ui:'Exo 2',sans-serif;
  --font-mono:'Exo 2',monospace;
  --radius-sm:6px;--radius-md:10px;--radius-lg:16px;
  --glow-strength:14px;--grid-color:rgba(79,195,247,0.025);
}

/* ── Base ───────────────────────────────────── */
html{scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--t);
  font-family:var(--font-ui);min-height:100vh;
  overflow-x:hidden;transition:background 0.5s,color 0.4s;
}

/* ── Animated grid overlay ──────────────────── */
body::before{
  content:'';position:fixed;inset:0;
  background-image:
    linear-gradient(var(--grid-color) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid-color) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0;
  animation:gridPulse 8s ease-in-out infinite;
}
@keyframes gridPulse{0%,100%{opacity:0.4}50%{opacity:1}}

/* ── Radial background glow ─────────────────── */
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse at 20% 50%,rgba(0,80,180,0.18) 0%,transparent 60%),
    radial-gradient(ellipse at 80% 20%,rgba(0,120,200,0.12) 0%,transparent 50%),
    radial-gradient(ellipse at 60% 80%,rgba(180,30,50,0.08) 0%,transparent 40%);
}

/* ── Particles canvas ───────────────────────── */
#particles-canvas{position:fixed;inset:0;pointer-events:none;z-index:0;opacity:0.5}

/* ── Page transition ────────────────────────── */
.page.active{animation:pageIn 0.32s cubic-bezier(0.16,1,0.3,1)}
@keyframes pageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ── Header / Nav ───────────────────────────── */
header{
  position:sticky;top:0;z-index:100;
  background:rgba(10,14,26,0.92);
  backdrop-filter:blur(24px);
  border-bottom:1px solid rgba(79,195,247,0.15);
  padding:0 24px;
  display:flex;align-items:center;justify-content:space-between;
  height:58px;flex-wrap:wrap;gap:8px;
  transition:box-shadow 0.3s;
}
header.scrolled{
  box-shadow:0 2px 40px rgba(0,0,0,0.7),0 0 1px var(--cyan);
}
nav{display:flex;gap:3px;flex-wrap:wrap;align-items:center}

/* ── Brand ──────────────────────────────────── */
.brand{display:flex;align-items:center;gap:10px}
.brand-link{display:flex;align-items:center;gap:10px;cursor:pointer;text-decoration:none}
.brand-icon{
  width:32px;height:32px;
  background:linear-gradient(135deg,rgba(79,195,247,0.8),rgba(0,188,212,0.8));
  border-radius:7px;display:flex;align-items:center;justify-content:center;
  font-size:17px;
  box-shadow:0 0 var(--glow-strength) rgba(79,195,247,0.35);
  animation:iconPulse 4s ease-in-out infinite;
}
@keyframes iconPulse{
  0%,100%{box-shadow:0 0 var(--glow-strength) rgba(79,195,247,0.35)}
  50%{box-shadow:0 0 28px rgba(79,195,247,0.6)}
}
.brand-name{
  font-family:var(--font-display);font-size:18px;font-weight:700;
  color:var(--text-white);letter-spacing:1px;
}
.brand-tag{
  font-family:var(--font-body);font-size:8px;color:var(--m);
  letter-spacing:3px;text-transform:uppercase;
}
.ver-badge{
  font-size:9px;font-family:var(--font-body);
  background:rgba(79,195,247,0.08);color:var(--cyan);
  border:1px solid rgba(79,195,247,0.2);
  border-radius:4px;padding:2px 7px;letter-spacing:1px;cursor:default;
}

/* ── Nav Buttons ────────────────────────────── */
.nb{
  padding:6px 13px;border:none;
  background:transparent;color:var(--m);
  cursor:pointer;font-family:var(--font-body);
  font-size:12px;letter-spacing:1.5px;text-transform:uppercase;
  border-radius:6px;transition:all 0.2s;white-space:nowrap;
}
.nb:hover,.nb.active{
  background:var(--bg-active);color:var(--cyan);
  border-color:rgba(79,195,247,0.6);
}

/* ── Dropdown ───────────────────────────────── */
.nav-dropdown{position:relative;display:inline-block}
.nav-dropdown:hover .nav-dropdown-menu{display:block;animation:ddFade 0.18s cubic-bezier(0.34,1.56,0.64,1)}
.nav-dropdown:hover .nav-dropdown-btn{background:var(--bg-active);color:var(--cyan)}
.nav-dropdown:hover .nav-dropdown-btn .arrow{transform:rotate(180deg)}
@keyframes ddFade{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.nav-dropdown-btn{
  padding:6px 13px;border:none;background:transparent;
  color:var(--m);cursor:pointer;
  font-family:var(--font-body);font-size:12px;
  letter-spacing:1.5px;text-transform:uppercase;
  border-radius:6px;transition:all 0.2s;
  white-space:nowrap;display:flex;align-items:center;gap:5px;
}
.nav-dropdown-btn:hover,.nav-dropdown-btn.active{
  background:var(--bg-active);color:var(--cyan);
}
.nav-dropdown-btn .arrow{font-size:8px;transition:transform 0.2s}
.nav-dropdown-menu{
  position:absolute;top:calc(100% + 4px);left:0;
  background:var(--s1);
  border:1px solid rgba(79,195,247,0.25);
  border-radius:var(--radius-md);
  min-width:220px;z-index:100;padding:6px;
  display:none;box-shadow:0 8px 40px rgba(0,0,0,0.7),0 0 0 1px rgba(79,195,247,0.05);
}
.nav-dropdown-section{
  font-size:9px;color:var(--m);letter-spacing:2px;
  font-family:var(--font-body);text-transform:uppercase;
  padding:6px 10px 4px;margin-top:4px;
}
.nav-dropdown-section:first-child{margin-top:0}
.nav-dropdown-item{
  display:flex;align-items:center;gap:9px;
  padding:8px 12px;border:none;
  background:transparent;color:var(--t);
  cursor:pointer;font-family:var(--font-body);
  font-size:11px;letter-spacing:0.5px;
  border-radius:7px;width:100%;text-align:left;transition:all 0.2s;
}
.nav-dropdown-item:hover{background:var(--bg-active);color:var(--cyan)}
.nav-dropdown-item.active{background:var(--bg-active);color:var(--cyan)}
.nav-dropdown-item .item-icon{width:22px;text-align:center;font-size:13px}
.nav-dropdown-item .item-label{flex:1}
.nav-dropdown-item .item-badge{
  font-size:8px;background:rgba(79,195,247,0.15);
  color:var(--cyan);border:1px solid rgba(79,195,247,0.3);
  padding:2px 5px;border-radius:4px;font-weight:700;letter-spacing:1px;
}

/* ── Container ──────────────────────────────── */
.container{max-width:1100px;margin:0 auto;padding:24px 16px;position:relative;z-index:1}
.page{display:none}.page.active{display:block}

/* ── Cards ──────────────────────────────────── */
.card{
  background:var(--bg-glass);
  border:var(--border-glass);
  border-radius:var(--radius-md);
  padding:20px;margin-bottom:16px;
  backdrop-filter:blur(8px);
  transition:border-color 0.25s,box-shadow 0.25s;
}
.card:hover{
  border-color:rgba(79,195,247,0.3);
  box-shadow:0 8px 32px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.05);
}
.ctitle{
  font-family:var(--font-display);font-size:14px;font-weight:600;
  color:var(--cyan);letter-spacing:3px;text-transform:uppercase;
  margin-bottom:14px;padding-bottom:8px;
  border-bottom:1px solid rgba(79,195,247,0.2);
}

/* ── Hero ───────────────────────────────────── */
.home-hero{text-align:center;padding:48px 0 36px;position:relative;z-index:1}
.home-hero h1{
  font-family:var(--font-display);font-size:42px;font-weight:700;
  color:var(--text-white);letter-spacing:2px;
  margin-bottom:10px;line-height:1.1;
  background:linear-gradient(135deg,var(--cyan),var(--teal),rgba(79,195,247,0.6));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.home-hero p{
  color:var(--text-body);font-size:14px;
  font-family:var(--font-body);
  max-width:540px;margin:0 auto 28px;line-height:1.7;
}
.hero{text-align:center;padding:32px 0 24px}
.hero h2{
  font-family:var(--font-display);font-size:28px;font-weight:700;
  color:var(--text-white);letter-spacing:2px;margin-bottom:6px;
}
.hero p{color:var(--text-body);font-size:13px;font-family:var(--font-body)}

/* ── Home Stats ─────────────────────────────── */
.home-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:40px}
.home-stat{
  background:var(--bg-glass);
  border:var(--border-glass);
  border-radius:var(--radius-md);
  padding:20px;text-align:center;
  backdrop-filter:blur(6px);
  transition:all 0.25s;
}
.home-stat:hover{
  border-color:rgba(79,195,247,0.4);
  transform:translateY(-3px);
  box-shadow:0 10px 28px rgba(0,0,0,0.5),0 0 0 1px rgba(79,195,247,0.2);
}
.home-stat-val{
  font-family:var(--font-display);font-size:32px;font-weight:700;
  color:var(--cyan);
}
.home-stat-lbl{
  color:var(--m);font-size:10px;letter-spacing:2px;
  margin-top:4px;font-family:var(--font-body);text-transform:uppercase;
}

/* ── Tool Cards ─────────────────────────────── */
.home-cat{margin-bottom:36px;position:relative;z-index:1}
.home-cat-title{
  font-family:var(--font-display);font-size:12px;font-weight:600;
  color:var(--cyan);letter-spacing:3px;text-transform:uppercase;
  margin-bottom:14px;display:flex;align-items:center;gap:10px;
}
.home-cat-title::after{content:'';flex:1;height:1px;background:rgba(79,195,247,0.2)}
.home-tools-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.home-tool-card{
  background:var(--bg-glass);
  border:var(--border-glass);
  border-radius:var(--radius-md);
  padding:18px;cursor:pointer;
  transition:all 0.28s cubic-bezier(0.34,1.56,0.64,1);
  position:relative;overflow:hidden;backdrop-filter:blur(6px);
}
.home-tool-card::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,var(--tool-c,var(--cyan)),transparent 70%);
  opacity:0;transition:opacity 0.3s;pointer-events:none;
}
.home-tool-card:hover{
  border-color:var(--tool-c,rgba(79,195,247,0.6));
  transform:translateY(-5px) scale(1.01);
  box-shadow:0 12px 36px rgba(0,0,0,0.5),0 0 0 1px var(--tool-c,rgba(79,195,247,0.4));
}
.home-tool-card:hover::before{opacity:0.06}
.home-tool-icon{
  font-size:28px;margin-bottom:10px;display:inline-block;
  transition:transform 0.3s;
}
.home-tool-card:hover .home-tool-icon{transform:scale(1.2) rotate(-6deg)}
.home-tool-name{font-family:var(--font-display);font-size:16px;font-weight:600;color:var(--text-white);margin-bottom:4px}
.home-tool-desc{font-size:12px;color:var(--text-body);font-family:var(--font-body);line-height:1.6}
.home-tool-tags{display:flex;gap:5px;margin-top:10px;flex-wrap:wrap}
.home-tool-tag{
  font-size:9px;font-family:var(--font-body);
  padding:2px 7px;border-radius:3px;font-weight:600;
  letter-spacing:0.5px;text-transform:uppercase;
}

/* ── Quick Buttons ──────────────────────────── */
.home-quick{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:40px}
.home-quick-btn{
  padding:10px 20px;
  border:var(--border-glass);
  border-radius:var(--radius-sm);
  background:var(--bg-glass);
  backdrop-filter:blur(6px);
  color:var(--text-body);cursor:pointer;
  font-family:var(--font-body);font-size:12px;
  letter-spacing:1px;
  transition:all 0.2s;display:flex;align-items:center;gap:7px;
  position:relative;overflow:hidden;
}
.home-quick-btn:hover{
  border-color:rgba(79,195,247,0.6);
  color:var(--cyan);
  background:var(--bg-active);
  box-shadow:0 0 16px rgba(79,195,247,0.2);
}

/* ── Inputs ─────────────────────────────────── */
.scan-inp{
  flex:1;min-width:200px;
  background:rgba(255,255,255,0.04);
  border:var(--border-glass);
  border-radius:var(--radius-sm);
  color:var(--cyan);padding:12px 16px;
  font-size:14px;font-family:var(--font-body);
  outline:none;transition:border 0.2s;
}
.scan-inp:focus{
  border-color:rgba(79,195,247,0.6);
  box-shadow:0 0 0 3px rgba(79,195,247,0.07);
  background:rgba(79,195,247,0.04);
}
.scan-inp::placeholder{color:var(--m);opacity:0.5}
.inp{
  width:100%;background:rgba(255,255,255,0.04);
  border:var(--border-glass);border-radius:var(--radius-sm);
  color:var(--t);padding:11px 14px;
  font-size:14px;font-family:var(--font-body);
  outline:none;transition:border 0.2s;
}
.inp:focus{
  border-color:rgba(79,195,247,0.6);
  box-shadow:0 0 0 3px rgba(79,195,247,0.07);
}
.inp::placeholder{color:var(--m);opacity:0.4}
.sel{
  background:rgba(255,255,255,0.04);
  border:var(--border-glass);border-radius:var(--radius-sm);
  color:var(--t);padding:10px 12px;
  font-size:13px;font-family:var(--font-body);
  outline:none;width:100%;
}
.sel:focus{border-color:rgba(79,195,247,0.6)}

/* ── Buttons ────────────────────────────────── */
.btn{
  padding:10px 20px;border:none;border-radius:var(--radius-sm);
  cursor:pointer;font-family:var(--font-body);font-weight:600;
  font-size:12px;letter-spacing:1.5px;text-transform:uppercase;
  transition:all 0.25s;white-space:nowrap;position:relative;overflow:hidden;
}
.btn-p{
  background:transparent;
  border:1px solid rgba(79,195,247,0.7);
  color:var(--cyan);width:100%;
}
.btn-p::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(79,195,247,0.12),transparent);
  transform:translateX(-100%);transition:transform 0.5s;
}
.btn-p:hover{
  background:rgba(79,195,247,0.15);
  box-shadow:0 0 16px rgba(79,195,247,0.3);
  transform:translateY(-1px);
}
.btn-p:hover::after{transform:translateX(100%)}
.btn-p:disabled{
  background:transparent;
  border-color:rgba(255,255,255,0.1);
  color:var(--m);cursor:not-allowed;transform:none;box-shadow:none;
}
.btn-g{
  background:var(--bg-glass);color:var(--m);
  border:var(--border-glass);padding:10px 18px;backdrop-filter:blur(4px);
}
.btn-g:hover{border-color:rgba(79,195,247,0.4);color:var(--cyan)}
.btn-sm{padding:6px 12px;font-size:10px}
.btn-full{width:100%}

/* ── Module toggles ─────────────────────────── */
.mods{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px;justify-content:center}
.mt{
  padding:5px 13px;border:var(--border-glass);
  border-radius:18px;cursor:pointer;
  font-size:11px;font-family:var(--font-body);
  letter-spacing:0.5px;color:var(--m);
  background:transparent;transition:all 0.2s;
}
.mt.on{
  border-color:rgba(79,195,247,0.6);
  color:var(--cyan);background:var(--bg-active);
}

/* ── Terminal ───────────────────────────────── */
#term{
  background:rgba(0,0,0,0.5);
  border:var(--border-glass);border-radius:var(--radius-sm);
  padding:13px 15px;margin-bottom:16px;
  max-height:160px;overflow-y:auto;display:none;
  font-family:var(--font-mono);font-size:13px;
}
.tl{line-height:1.9;color:var(--m)}
.ti .p{color:var(--cyan)}.ts .p{color:var(--green)}.tw .p{color:var(--yellow)}.te .p{color:var(--red)}

/* ── Progress bar ───────────────────────────── */
#prog{height:2px;background:var(--b);border-radius:1px;margin-bottom:16px;display:none;overflow:hidden}
#pb{
  height:100%;width:0;
  background:linear-gradient(90deg,var(--cyan),var(--teal),rgba(79,195,247,0.5));
  transition:width 0.3s;position:relative;overflow:hidden;
}
#pb::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.35),transparent);
  animation:pbShimmer 1.5s ease infinite;
}
@keyframes pbShimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}

/* ── Error ──────────────────────────────────── */
#err{
  background:rgba(255,107,107,0.07);
  border:1px solid rgba(255,107,107,0.22);
  border-radius:var(--radius-sm);padding:13px 16px;
  color:var(--red);font-size:13px;margin-bottom:16px;
  display:none;font-family:var(--font-body);
}

/* ── Scan results ───────────────────────────── */
#res{display:none}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}
.sc{
  background:var(--bg-glass);border:var(--border-glass);
  border-radius:var(--radius-sm);padding:14px;text-align:center;
  backdrop-filter:blur(4px);
}
.sv{
  font-family:var(--font-display);font-size:28px;
  font-weight:700;line-height:1;color:var(--cyan);
}
.sl{color:var(--m);font-size:10px;letter-spacing:2px;margin-top:5px;font-family:var(--font-body);text-transform:uppercase}

/* ── Tabs ───────────────────────────────────── */
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid rgba(79,195,247,0.15);flex-wrap:wrap}
.tab{
  padding:9px 16px;border:none;background:transparent;color:var(--m);
  cursor:pointer;font-family:var(--font-body);font-size:11px;
  letter-spacing:1.5px;text-transform:uppercase;
  border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.2s;
}
.tab:hover{color:var(--t)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tc{display:none}.tc.active{display:block}

/* ── Port Cards ─────────────────────────────── */
.pc{
  border-radius:var(--radius-sm);
  background:rgba(255,255,255,0.02);
  margin-bottom:9px;overflow:hidden;
  backdrop-filter:blur(4px);
}
.ph{
  padding:13px 16px;cursor:pointer;
  display:flex;align-items:center;gap:12px;
  flex-wrap:wrap;user-select:none;
}
.pn{
  padding:6px 12px;border-radius:var(--radius-sm);
  font-family:var(--font-display);font-weight:700;font-size:15px;
  min-width:66px;text-align:center;
}
.pi{flex:1;min-width:0}
.pname{font-family:var(--font-display);font-weight:600;font-size:14px;letter-spacing:0.5px}
.psub{color:var(--m);font-size:12px;margin-top:2px;font-family:var(--font-body)}
.pm{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bdg{
  border-radius:4px;padding:2px 8px;
  font-size:11px;font-weight:700;letter-spacing:1px;
  font-family:var(--font-body);border:1px solid transparent;
}
.chev{color:var(--m);font-size:10px;transition:transform 0.25s;flex-shrink:0}
.pb2{padding:0 16px 16px;border-top:1px solid rgba(79,195,247,0.1);display:none}
.pb2.open{display:block}
.st{
  color:var(--m);font-size:11px;letter-spacing:3px;
  font-family:var(--font-body);text-transform:uppercase;margin:14px 0 7px;
}
.ci{
  background:rgba(255,255,255,0.03);
  border:var(--border-glass);
  border-radius:var(--radius-sm);padding:11px;margin-bottom:6px;
}
.ct{display:flex;align-items:center;gap:7px;margin-bottom:6px;flex-wrap:wrap}
.cid{
  color:var(--cyan);font-family:var(--font-body);
  font-weight:600;font-size:12px;text-decoration:none;
}
.cid:hover{text-decoration:underline}
.cdate{color:var(--m);font-size:10px;margin-left:auto;font-family:var(--font-body)}
.cdesc{color:var(--text-body);font-size:13px;line-height:1.7}
.ml{
  background:rgba(255,255,255,0.03);
  border:var(--border-glass);border-radius:var(--radius-sm);padding:11px;
}
.mi{display:flex;gap:9px;padding:5px 0;border-bottom:1px solid rgba(79,195,247,0.1);font-size:13px;line-height:1.6;color:var(--text-body)}
.mi:last-child{border-bottom:none}
.ma{color:var(--green);font-family:var(--font-body);flex-shrink:0}

/* ── SSL Card ───────────────────────────────── */
.ssl-card{
  background:var(--bg-glass);border:var(--border-glass);
  border-radius:var(--radius-sm);padding:16px;margin-bottom:11px;
  backdrop-filter:blur(4px);
}
.gc2{
  width:64px;height:64px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-family:var(--font-display);font-size:22px;font-weight:900;flex-shrink:0;
}
.ssl-hdr{display:flex;align-items:center;gap:16px;margin-bottom:12px}
.iss-item{
  display:flex;gap:9px;align-items:flex-start;
  padding:6px 0;border-bottom:1px solid rgba(79,195,247,0.1);font-size:13px;
}
.iss-item:last-child{border-bottom:none}

/* ── DNS ────────────────────────────────────── */
.dns-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:9px;margin-bottom:12px}
.dr{
  background:var(--bg-glass);border:var(--border-glass);
  border-radius:var(--radius-sm);padding:11px;backdrop-filter:blur(4px);
}
.dtype{
  font-family:var(--font-body);font-size:11px;color:var(--cyan);
  letter-spacing:2px;text-transform:uppercase;margin-bottom:5px;
}
.dval{font-size:12px;color:var(--text-body);line-height:1.7;font-family:var(--font-body);word-break:break-all}

/* ── Subdomain / Dir ────────────────────────── */
.sub-item{
  background:var(--bg-glass);border:var(--border-glass);
  border-radius:5px;padding:7px 11px;
  font-family:var(--font-body);font-size:12px;
  display:flex;justify-content:space-between;margin-bottom:4px;
}
.found-badge{
  background:rgba(165,214,167,0.1);color:var(--green);
  border:1px solid rgba(165,214,167,0.25);
  border-radius:5px;padding:3px 9px;font-size:11px;
  font-weight:700;font-family:var(--font-body);
  letter-spacing:0.5px;text-transform:uppercase;
}

/* ── HTTP Headers ───────────────────────────── */
.hdr-grade{font-family:var(--font-display);font-size:48px;font-weight:900;line-height:1}
.hl{
  background:var(--bg-glass);border-radius:var(--radius-sm);
  overflow:hidden;border:var(--border-glass);
}
.hi{
  display:flex;justify-content:space-between;align-items:center;
  padding:7px 13px;border-bottom:1px solid rgba(79,195,247,0.08);
  font-size:12px;font-family:var(--font-body);flex-wrap:wrap;gap:6px;
}
.hi:last-child{border-bottom:none}
.hk{color:var(--m);min-width:180px;flex-shrink:0}
.hv{color:var(--t);word-break:break-all;text-align:right;max-width:380px}
.hg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px}
.ht{
  background:var(--bg-glass);border:var(--border-glass);
  border-radius:var(--radius-sm);padding:13px;cursor:pointer;transition:all 0.2s;
  backdrop-filter:blur(4px);
}
.ht:hover{border-color:rgba(79,195,247,0.4)}
.hip{font-family:var(--font-display);font-size:15px;font-weight:700;color:var(--cyan)}

/* ── Tables ─────────────────────────────────── */
.tbl{width:100%;border-collapse:collapse;font-size:13px;font-family:var(--font-body)}
.tbl th{
  color:var(--m);font-size:10px;letter-spacing:2px;text-transform:uppercase;
  padding:9px 10px;text-align:left;border-bottom:1px solid rgba(79,195,247,0.15);
}
.tbl td{
  padding:9px 10px;border-bottom:1px solid rgba(79,195,247,0.06);
  color:var(--t);vertical-align:middle;word-break:break-word;
}
.tbl tr:hover td{background:rgba(79,195,247,0.03)}
.res-tbl{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-body);margin-top:8px}
.res-tbl th{
  color:var(--m);font-size:10px;letter-spacing:2px;text-transform:uppercase;
  padding:8px 10px;text-align:left;border-bottom:1px solid rgba(79,195,247,0.15);
  background:rgba(79,195,247,0.04);
}
.res-tbl td{
  padding:7px 10px;border-bottom:1px solid rgba(79,195,247,0.06);
  vertical-align:middle;word-break:break-all;
}
.res-tbl tr:hover td{background:rgba(79,195,247,0.03)}

/* ── Buttons (small) ────────────────────────── */
.lbtn{
  background:transparent;
  border:1px solid rgba(79,195,247,0.3);
  color:var(--cyan);padding:4px 9px;border-radius:4px;
  cursor:pointer;font-family:var(--font-body);font-size:10px;
  letter-spacing:0.5px;text-transform:uppercase;transition:all 0.2s;
}
.lbtn:hover{background:rgba(79,195,247,0.1);border-color:rgba(79,195,247,0.6)}
.lbtn.red{color:var(--red);border-color:rgba(255,107,107,0.3)}
.lbtn.red:hover{background:rgba(255,107,107,0.1)}

/* ── Dashboard ──────────────────────────────── */
.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:9px;font-size:11px;font-family:var(--font-body);margin-bottom:6px}
.bl{color:var(--m);width:75px;text-align:right;flex-shrink:0;font-size:10px}
.bt{flex:1;background:rgba(79,195,247,0.08);border-radius:2px;height:7px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width 1s ease}
.bv{color:var(--t);width:25px;flex-shrink:0}

/* ── Tags ───────────────────────────────────── */
.tag{
  display:inline-block;padding:2px 7px;
  border-radius:4px;font-size:10px;font-weight:700;
  font-family:var(--font-body);letter-spacing:0.5px;
  text-transform:uppercase;border:1px solid transparent;
}

/* ── Auth overlay ───────────────────────────── */
.overlay{
  position:fixed;inset:0;
  background:rgba(10,14,26,0.96);
  z-index:200;display:flex;align-items:center;justify-content:center;
  backdrop-filter:blur(16px);
}
.auth-box{
  background:var(--bg-glass);
  border:1px solid rgba(79,195,247,0.25);
  border-radius:var(--radius-lg);
  padding:36px;width:100%;max-width:420px;position:relative;
  backdrop-filter:blur(12px);
  box-shadow:0 24px 64px rgba(0,0,0,0.6);
}
.auth-box h2{
  font-family:var(--font-display);font-size:24px;font-weight:700;
  margin-bottom:4px;color:var(--text-white);letter-spacing:1px;
}
.auth-box p{color:var(--m);font-size:12px;margin-bottom:24px;font-family:var(--font-body)}
.auth-tabs{display:flex;gap:0;margin-bottom:24px;background:rgba(255,255,255,0.04);border-radius:var(--radius-sm);padding:3px}
.auth-tab{
  flex:1;padding:8px;border:none;background:transparent;
  color:var(--m);cursor:pointer;
  font-family:var(--font-body);font-size:11px;
  letter-spacing:1.5px;text-transform:uppercase;
  border-radius:5px;transition:all 0.2s;
}
.auth-tab.active{background:var(--bg-active);color:var(--cyan)}
.fg{margin-bottom:14px}
.fg label{
  display:block;font-size:10px;color:var(--m);
  letter-spacing:2px;text-transform:uppercase;
  font-family:var(--font-body);margin-bottom:5px;
}
.auth-msg{
  padding:10px 14px;border-radius:var(--radius-sm);
  font-size:12px;font-family:var(--font-body);
  margin-bottom:14px;display:none;
}
.auth-msg.ok{background:rgba(165,214,167,0.08);border:1px solid rgba(165,214,167,0.2);color:var(--green)}
.auth-msg.err{background:rgba(255,107,107,0.08);border:1px solid rgba(255,107,107,0.2);color:var(--red)}
.auth-link{
  background:none;border:none;color:var(--cyan);cursor:pointer;
  font-size:11px;font-family:var(--font-body);text-decoration:underline;padding:0;
}

/* ── User chip ──────────────────────────────── */
.user-chip{
  display:flex;align-items:center;gap:8px;
  background:var(--bg-glass);
  border:var(--border-glass);
  border-radius:20px;padding:4px 12px 4px 8px;
  cursor:pointer;transition:all 0.2s;backdrop-filter:blur(4px);
}
.user-chip:hover{border-color:rgba(79,195,247,0.4)}
.user-avatar{
  width:24px;height:24px;border-radius:50%;
  background:linear-gradient(135deg,var(--cyan),var(--teal));
  display:flex;align-items:center;justify-content:center;
  font-family:var(--font-display);font-size:12px;font-weight:700;color:var(--bg);
}
.user-name{font-size:12px;font-family:var(--font-body);color:var(--t);letter-spacing:0.5px}
.user-role{font-size:9px;color:var(--m);font-family:var(--font-body);letter-spacing:1px;text-transform:uppercase}

/* ── Misc badges ────────────────────────────── */
.admin-badge{
  background:rgba(255,241,118,0.1);color:var(--yellow);
  border:1px solid rgba(255,241,118,0.2);
  border-radius:4px;padding:2px 8px;font-size:10px;
  font-family:var(--font-body);letter-spacing:0.5px;
}
.user-badge{
  background:rgba(79,195,247,0.08);color:var(--cyan);
  border:1px solid rgba(79,195,247,0.2);
  border-radius:4px;padding:2px 8px;font-size:10px;
  font-family:var(--font-body);letter-spacing:0.5px;
}
.notice{
  background:rgba(255,241,118,0.06);
  border:1px solid rgba(255,241,118,0.2);
  border-radius:var(--radius-sm);padding:10px 14px;
  color:var(--yellow);font-size:12px;
  font-family:var(--font-body);margin-bottom:14px;line-height:1.6;
}

/* ── Spinner ────────────────────────────────── */
.spin{
  display:inline-block;width:11px;height:11px;
  border:2px solid rgba(79,195,247,0.2);
  border-top-color:var(--cyan);
  border-radius:50%;animation:sp 0.8s linear infinite;
  margin-right:7px;vertical-align:middle;
}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── Pulse dot ──────────────────────────────── */
.pulse-dot{
  width:7px;height:7px;border-radius:50%;
  background:var(--green);display:inline-block;
  animation:pulseDot 2s ease infinite;
}
@keyframes pulseDot{
  0%{box-shadow:0 0 0 0 rgba(165,214,167,0.7)}
  70%{box-shadow:0 0 0 8px rgba(165,214,167,0)}
  100%{box-shadow:0 0 0 0 rgba(165,214,167,0)}
}

/* ── Toast notifications ────────────────────── */
.toast{
  background:var(--s1);border:var(--border-glass);
  border-radius:var(--radius-sm);padding:12px 16px;
  min-width:280px;max-width:380px;pointer-events:all;cursor:pointer;
  display:flex;align-items:flex-start;gap:10px;
  font-family:var(--font-body);font-size:12px;
  box-shadow:0 8px 32px rgba(0,0,0,0.6);
  animation:toastIn 0.35s cubic-bezier(0.34,1.56,0.64,1);
  backdrop-filter:blur(8px);
}
.toast.leaving{animation:toastOut 0.3s ease forwards}
@keyframes toastIn{from{opacity:0;transform:translateX(60px) scale(0.9)}to{opacity:1;transform:translateX(0) scale(1)}}
@keyframes toastOut{from{opacity:1;transform:translateX(0)}to{opacity:0;transform:translateX(60px)}}
.toast-icon{font-size:16px;flex-shrink:0;margin-top:1px}
.toast-body{flex:1}
.toast-title{font-family:var(--font-display);font-weight:700;font-size:13px;margin-bottom:2px;letter-spacing:0.5px}
.toast-msg{color:var(--m);font-size:11px;line-height:1.5}
.toast-close{background:none;border:none;color:var(--m);cursor:pointer;font-size:14px;padding:0;line-height:1;flex-shrink:0}
.toast-close:hover{color:var(--t)}
.toast.success{border-left:2px solid var(--green)}
.toast.success .toast-icon{color:var(--green)}
.toast.error{border-left:2px solid var(--red)}
.toast.error .toast-icon{color:var(--red)}
.toast.info{border-left:2px solid var(--cyan)}
.toast.info .toast-icon{color:var(--cyan)}
.toast.warning{border-left:2px solid var(--yellow)}
.toast.warning .toast-icon{color:var(--yellow)}
.toast-progress{height:2px;background:rgba(255,255,255,0.06);border-radius:1px;margin-top:8px;overflow:hidden}
.toast-progress-bar{height:100%;border-radius:1px;transition:width linear}

/* ── CLI Console ────────────────────────────── */
.cli-line{line-height:1.9;font-size:12px;font-family:var(--font-mono)}
.cli-cmd{color:var(--green)}
.cli-out{color:var(--m)}
.cli-err{color:var(--red)}
.cli-system{color:var(--cyan)}

/* ── Misc layout ────────────────────────────── */
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
.bf-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
textarea.scan-inp{resize:vertical;min-height:80px;font-size:13px}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.install-banner{
  background:rgba(255,241,118,0.06);
  border:1px solid rgba(255,241,118,0.25);
  border-radius:var(--radius-sm);padding:12px 16px;margin:10px 0;
  display:none;align-items:center;gap:10px;
  font-family:var(--font-body);font-size:12px;color:var(--yellow);
}
.install-banner.visible{display:flex}
.install-banner .install-spinner{
  width:14px;height:14px;
  border:2px solid rgba(255,241,118,0.3);
  border-top-color:var(--yellow);
  border-radius:50%;animation:spin 0.8s linear infinite;flex-shrink:0;
}
@keyframes spin{to{transform:rotate(360deg)}}
.cancel-btn{
  padding:7px 12px;
  border:1px solid rgba(255,107,107,0.5);
  background:rgba(255,107,107,0.08);color:var(--red);
  border-radius:var(--radius-sm);cursor:pointer;
  font-family:var(--font-body);font-size:10px;font-weight:700;
  letter-spacing:1px;text-transform:uppercase;
  transition:all 0.2s;display:none;align-items:center;gap:5px;white-space:nowrap;
}
.cancel-btn:hover{background:rgba(255,107,107,0.18);border-color:var(--red)}
.cancel-btn.visible{display:inline-flex}
.scan-run-wrap{display:flex;align-items:center;gap:8px}

/* ── Server stats ───────────────────────────── */
.theme-dropdown-wrap{position:relative}
.theme-dropdown-btn{
  width:100%;background:rgba(255,255,255,0.04);
  border:var(--border-glass);border-radius:var(--radius-sm);
  color:var(--t);padding:11px 14px;
  font-family:var(--font-body);font-size:13px;
  cursor:pointer;display:flex;align-items:center;
  justify-content:space-between;gap:10px;transition:border-color 0.2s;
}
.theme-dropdown-btn:hover{border-color:rgba(79,195,247,0.4)}
.theme-dropdown-btn.open{border-color:var(--cyan);border-radius:var(--radius-sm) var(--radius-sm) 0 0}
.theme-dropdown-list{
  position:absolute;left:0;right:0;top:100%;
  background:var(--s1);border:1px solid var(--cyan);
  border-top:none;border-radius:0 0 var(--radius-sm) var(--radius-sm);
  z-index:50;display:none;max-height:360px;overflow-y:auto;
  backdrop-filter:blur(8px);
}
.theme-dropdown-list.open{display:block;animation:ddFade 0.18s ease}
.theme-option{
  display:flex;align-items:center;gap:12px;padding:11px 14px;
  cursor:pointer;transition:background 0.15s;
  border-bottom:1px solid rgba(79,195,247,0.08);
}
.theme-option:last-child{border-bottom:none}
.theme-option:hover,.theme-option.active{background:var(--bg-active)}
.theme-preview{display:flex;gap:3px;width:52px;flex-shrink:0}
.theme-preview-dot{width:10px;height:10px;border-radius:50%}
.theme-option-name{font-family:var(--font-body);font-size:12px;font-weight:700;letter-spacing:1px}
.theme-option-desc{font-family:var(--font-body);font-size:10px;color:var(--m);margin-top:1px}
.theme-option.active .theme-option-name::after{content:' ✓';color:var(--cyan)}
.theme-mine-badge{
  font-size:9px;background:rgba(79,195,247,0.1);
  color:var(--cyan);border:1px solid rgba(79,195,247,0.25);
  border-radius:4px;padding:1px 5px;font-family:var(--font-body);
}

/* ── Scrollbars ─────────────────────────────── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:rgba(79,195,247,0.2);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:rgba(79,195,247,0.4)}

/* ── Responsive ─────────────────────────────── */
@media(max-width:600px){
  .bf-grid{grid-template-columns:1fr}
  .home-hero h1{font-size:26px}
  .home-stats{grid-template-columns:repeat(2,1fr)}
  header{height:auto;padding:10px 16px}
}
"""

# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. — HEADER HTML
# Replaces the brand section in the nav HTML
# ──────────────────────────────────────────────────────────────────────────────

OLD_BRAND_HTML = """  <div class="brand brand-link" onclick="pg('home',null)" title="Go to Home">
    <div class="brand-icon">&#9889;</div>
    <div>
      <div class="brand-name" data-text="VulnScan Pro">VulnScan Pro</div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
        <div class="brand-tag">SECURITY PLATFORM</div>
        <span class="ver-badge">v3.7</span>
      </div>
    </div>
  </div>"""

NEW_BRAND_HTML = """  <div class="brand brand-link" onclick="pg('home',null)" title="Go to Home">
    <div class="brand-icon">&#9889;</div>
    <div>
      <div class="brand-name">VulnScan Pro</div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
        <div class="brand-tag">Security Intelligence</div>
        <span class="ver-badge">v3.7</span>
      </div>
    </div>
  </div>"""

# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. — HOME HERO HTML
# Updates the hero section gradient text to use Portal Tech colors
# ──────────────────────────────────────────────────────────────────────────────

OLD_HERO_H1 = """.home-hero h1{font-size:42px;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px;line-height:1.1;background-size:200% auto;animation:shimmer 5s ease infinite}"""
# This is inside the embedded CSS block — handled by full CSS replacement

# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. — LEGAL NOTICE
# Updates colours in the legal notice at bottom of home page
# ──────────────────────────────────────────────────────────────────────────────

OLD_LEGAL = """    <strong style="color:var(--yellow)">Authorized Use Only.</strong>"""
NEW_LEGAL = """    <strong style="color:var(--cyan)">Authorized Use Only.</strong>"""

# ──────────────────────────────────────────────────────────────────────────────
# PORTAL TECH CO. — vulnscan.jsx stylesheet
# Updates the React component's inline styles
# ──────────────────────────────────────────────────────────────────────────────

OLD_JSX_FONTS = """@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&display=swap');"""
NEW_JSX_FONTS = """@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:wght@300;400;500;600&display=swap');"""

OLD_JSX_FONTFAMILY = """fontFamily: "'IBM Plex Mono', 'Courier New', monospace","""
NEW_JSX_FONTFAMILY = """fontFamily: "'Exo 2', 'Rajdhani', sans-serif","""

OLD_JSX_BG = """background: "#050507","""
NEW_JSX_BG = """background: "#0a0e1a","""

OLD_JSX_COLOR = """color: "#e5e5ea","""
NEW_JSX_COLOR = """color: "#e0e8f8","""

OLD_JSX_H1_STYLE = """color: "#fff" }}>"""
NEW_JSX_H1_STYLE = """color: "#f0f4ff" }}>"""

OLD_JSX_INPUT_BG = """background: "#050507","""
NEW_JSX_INPUT_BG = """background: "rgba(255,255,255,0.04)","""

OLD_JSX_INPUT_BORDER = """border: "1px solid #2c2c2e","""
NEW_JSX_INPUT_BORDER = """border: "1px solid rgba(79,195,247,0.2)","""

OLD_JSX_INPUT_COLOR = """color: "#00d4ff","""
NEW_JSX_INPUT_COLOR = """color: "#4fc3f7","""

OLD_JSX_BTN_BG = """background: scanning ? "#1c1c1e" : "linear-gradient(135deg, #ff2d55, #c02030)","""
NEW_JSX_BTN_BG = """background: scanning ? "rgba(255,255,255,0.05)" : "transparent",
              border: scanning ? "1px solid rgba(255,255,255,0.1)" : "1px solid rgba(79,195,247,0.7)",
              color: scanning ? "#7a8aaa" : "#4fc3f7","""

OLD_JSX_SCAN_LABEL = """background: "#0a0a0c","""
NEW_JSX_SCAN_LABEL = """background: "rgba(255,255,255,0.04)","""

# ──────────────────────────────────────────────────────────────────────────────
# MAIN — APPLY ALL PATCHES
# ──────────────────────────────────────────────────────────────────────────────

def main():
    global RESTART_NEEDED

    print()
    print("═" * 64)
    print("  VulnScan Pro  →  Portal Tech Co. Theme Patcher")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{'  [DRY RUN]' if DRY_RUN else ''}")
    print("═" * 64)
    print()

    # ── 1. api_server.py — Replace embedded CSS ──────────────────────────────
    TARGET = "api_server.py"

    print(f"[api_server.py] Patching embedded HTML/CSS theme...")

    # The old CSS block starts right after <style> and ends before </style>
    # We do a regex-based replacement to swap the entire CSS block

    if not os.path.isfile(TARGET):
        print(f"  ✗ {TARGET} not found in current directory.")
        print("    Run this script from the VulnScan project root.")
    else:
        with open(TARGET, "r", encoding="utf-8") as f:
            content = f.read()

        # Find the <style> block inside the HTML string
        style_pattern = re.compile(r'(<style>)(.*?)(</style>)', re.DOTALL)
        match = style_pattern.search(content)

        if match:
            old_style_content = match.group(2)
            new_content = content.replace(
                match.group(0),
                f"<style>{PORTAL_FULL_CSS}</style>",
                1
            )
            if not DRY_RUN:
                if TARGET not in FILES_MODIFIED:
                    backup(TARGET)
                with open(TARGET, "w", encoding="utf-8") as f:
                    f.write(new_content)
                if TARGET not in FILES_MODIFIED:
                    FILES_MODIFIED.append(TARGET)
            else:
                if TARGET not in FILES_MODIFIED:
                    FILES_MODIFIED.append(TARGET)

            global CHANGES_APPLIED
            CHANGES_APPLIED += 1
            RESTART_NEEDED = True
            print(f"  ✓ [Full CSS theme replacement — Portal Tech Co. glassmorphism]{'  (dry-run)' if DRY_RUN else ''}")
        else:
            global CHANGES_FAILED
            CHANGES_FAILED += 1
            print(f"  ✗ [CSS replacement] — <style> block not found in {TARGET}")

    # ── 2. api_server.py — Brand HTML ────────────────────────────────────────
    patch_file(TARGET, OLD_BRAND_HTML, NEW_BRAND_HTML,
               "Brand header — remove glitch effect, use Rajdhani font style")

    # ── 3. api_server.py — Legal notice accent color ─────────────────────────
    patch_file(TARGET, OLD_LEGAL, NEW_LEGAL,
               "Legal notice — cyan accent color (Portal Tech style)")

    # ── 4. vulnscan.jsx — Font import ─────────────────────────────────────────
    print()
    print("[vulnscan.jsx] Patching React component styles...")

    patch_file("vulnscan.jsx", OLD_JSX_FONTS, NEW_JSX_FONTS,
               "Font import — IBM Plex Mono → Rajdhani + Exo 2")
    patch_file("vulnscan.jsx", OLD_JSX_FONTFAMILY, NEW_JSX_FONTFAMILY,
               "Body font family → Exo 2 / Rajdhani")
    patch_file("vulnscan.jsx", OLD_JSX_BG, NEW_JSX_BG,
               "Background color → #0a0e1a (Portal Tech dark navy)")
    patch_file("vulnscan.jsx", OLD_JSX_COLOR, NEW_JSX_COLOR,
               "Body text color → #e0e8f8")
    patch_file("vulnscan.jsx", OLD_JSX_BTN_BG, NEW_JSX_BTN_BG,
               "Scan button → transparent glass with cyan border")

    # ── 5. Summary ────────────────────────────────────────────────────────────
    print()
    print("═" * 64)
    print(f"  SUMMARY")
    print("═" * 64)
    print(f"  Changes applied : {CHANGES_APPLIED}")
    print(f"  Changes failed  : {CHANGES_FAILED}")
    print(f"  Files modified  : {len(FILES_MODIFIED)}")
    for f in FILES_MODIFIED:
        print(f"    • {f}  {'(backed up as ' + f + '.bak)' if not DRY_RUN else '(dry-run, not written)'}")
    print()

    if RESTART_NEEDED and not DRY_RUN:
        print("  ⚠  Restart required:")
        print("     python3 api_server.py")
        print()
        print("  ℹ  To undo all changes, restore the .bak files:")
        for f in FILES_MODIFIED:
            print(f"     cp {f}.bak {f}")
    elif DRY_RUN:
        print("  ℹ  Dry-run complete. Run without --dry-run to apply changes.")

    print()
    if CHANGES_FAILED > 0:
        print("  ⚠  Some patches failed — strings may have already been changed,")
        print("     or the file version differs from what this patcher expects.")
    else:
        print("  ✅  All patches applied successfully.")
    print()


if __name__ == "__main__":
    main()
