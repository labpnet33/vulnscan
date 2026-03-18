#!/usr/bin/env python3
"""
VulnScan Pro -- v4 Patch (clean fix)
Fixes:
  1. Login button broken (pg wrapper captured undefined)
  2. No background animations showing
  3. Admin nav misaligned
  4. Scan output too narrow

Safe to run on a FRESH api_server.py (from patch.py only)
OR on one that already had patch_animations / patch_v3 applied.
Idempotent -- running twice is safe.

Run: python3 patch_v4.py
"""

import os, shutil, re
from datetime import datetime

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print("  " + GREEN + "✓" + RESET + " " + msg)
def fail(msg): print("  " + RED   + "✗" + RESET + " " + msg)
def info(msg): print("  " + CYAN  + "→" + RESET + " " + msg)
def warn(msg): print("  " + YELLOW + "!" + RESET + " " + msg)

changes_applied = 0
files_modified  = []
restart_needed  = False


def backup(path):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = path + "." + ts + ".bak"
    shutil.copy2(path, bak)
    return bak


def apply_patches(path, patches):
    global changes_applied, files_modified, restart_needed
    if not os.path.isfile(path):
        fail("File not found: " + path)
        return 0, len(patches)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    applied = failed = 0
    modified = content
    for desc, old, new in patches:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc)
            applied += 1
        elif new in modified:
            ok(desc + "  (already applied -- skipped)")
        else:
            fail(desc)
            failed += 1
    if applied:
        bak = backup(path)
        info("Backup -> " + bak)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        changes_applied += applied
        if path not in files_modified:
            files_modified.append(path)
        restart_needed = True
    return applied, failed


def remove_broken_patches(path):
    """
    Strip out broken code from previous patch attempts so we start clean.
    Uses regex to remove known bad blocks.
    """
    global changes_applied, files_modified, restart_needed
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    original = content

    # Remove any previous pg() wrapper attempts (they broke login)
    # Pattern: var _pgBase=pg; ... pg=function ...  up to the closing };
    patterns = [
        # pg wrapper from patch_v3
        r'// Animated pg\(\) wrapper\nvar _pgBase=pg;.*?^};\n\n',
        # pg wrapper from patch_animations
        r'// Wrap pg\(\) to re-trigger.*?^pg = function.*?^};\n\n',
        r'// Wrap pg\(\) to replay.*?^pg=function.*?^};\n\n',
        # typewriter injected by old patches (we will re-add correctly)
        r'// Typewriter.*?\ntypeWriter\(.*?^}\n\n',
        r'// Typewriter effect\nfunction typeWriter.*?^}\n\n',
        r'function typeWriter\(el,text,cursor\).*?^}\n\n',
        # orb injection block
        r'// Floating orbs.*?\}\)\(\);\n\n',
        # auth canvas script block injected before about modal
        r'<script>\n\(function\(\)\{\n  var c=document\.getElementById.*?</script>\n',
    ]

    for pat in patterns:
        new_content = re.sub(pat, '', content, flags=re.DOTALL | re.MULTILINE)
        if new_content != content:
            content = new_content
            info("Removed broken previous patch block")

    if content != original:
        bak = backup(path)
        info("Cleanup backup -> " + bak)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        if path not in files_modified:
            files_modified.append(path)
        restart_needed = True
        ok("Cleaned up broken patches from previous runs")
    else:
        ok("No cleanup needed")


# ==========================================================================
#  CSS BLOCK
#  All animation styles in one block, injected before the Responsive section
# ==========================================================================

ANIMATION_CSS = """
/* ================================================================
   VulnScan Pro -- Animation & Background Layer
   ================================================================ */

/* Spring easing tokens */
:root {
  --ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
  --ease-out:    cubic-bezier(0.16, 1,    0.3,  1);
}

/* ------------------------------------------------------------------
   AUTH SCREEN ANIMATIONS
   ------------------------------------------------------------------ */
@keyframes vs-overlay-in {
  from { opacity: 0; }
  to   { opacity: 1; }
}
.overlay { animation: vs-overlay-in 0.35s ease both; }

@keyframes vs-box-rise {
  from { opacity: 0; transform: translateY(24px) scale(0.97); }
  to   { opacity: 1; transform: translateY(0)    scale(1);    }
}
.auth-box { animation: vs-box-rise 0.5s var(--ease-spring) 0.08s both; }

@keyframes vs-logo-spin {
  0%   { opacity: 0; transform: rotate(-18deg) scale(0.7); }
  65%  {             transform: rotate(5deg)   scale(1.07); }
  100% { opacity: 1; transform: rotate(0deg)   scale(1);   }
}
.auth-logo-icon { animation: vs-logo-spin 0.55s var(--ease-spring) 0.22s both; }

@keyframes vs-fade-up {
  from { opacity: 0; transform: translateY(9px); }
  to   { opacity: 1; transform: translateY(0);   }
}
.auth-title { animation: vs-fade-up 0.38s var(--ease-out) 0.32s both; }
.auth-tabs  { animation: vs-fade-up 0.35s var(--ease-out) 0.42s both; }

#form-login .fg:nth-child(1) { animation: vs-fade-up 0.32s var(--ease-out) 0.52s both; }
#form-login .fg:nth-child(2) { animation: vs-fade-up 0.32s var(--ease-out) 0.62s both; }
#l-btn                        { animation: vs-fade-up 0.32s var(--ease-out) 0.72s both; }

#form-register .fg:nth-child(1) { animation: vs-fade-up 0.32s var(--ease-out) 0.52s both; }
#form-register .fg:nth-child(2) { animation: vs-fade-up 0.32s var(--ease-out) 0.60s both; }
#form-register .fg:nth-child(3) { animation: vs-fade-up 0.32s var(--ease-out) 0.68s both; }
#form-register .fg:nth-child(4) { animation: vs-fade-up 0.32s var(--ease-out) 0.76s both; }

.btn-primary:not(:disabled):hover  { transform: translateY(-1px); }
.btn-primary:not(:disabled):active { transform: scale(0.97); }

/* Auth canvas background */
.overlay     { position: relative; overflow: hidden; }
#auth-canvas {
  position: absolute; inset: 0;
  pointer-events: none;
  opacity: 0.28;
  z-index: 0;
}
.auth-box { position: relative; z-index: 1; }

/* ------------------------------------------------------------------
   HOME PAGE ANIMATIONS
   ------------------------------------------------------------------ */

/* Greeting entrance */
@keyframes vs-greet-drop {
  from { opacity: 0; transform: translateY(-10px); }
  to   { opacity: 1; transform: translateY(0); }
}
#page-home .page-hd .page-title { animation: vs-greet-drop 0.45s var(--ease-out) 0.05s both; }
#page-home .page-hd .page-desc  { animation: vs-greet-drop 0.45s var(--ease-out) 0.14s both; }

/* Stat cards pop in */
@keyframes vs-stat-pop {
  from { opacity: 0; transform: scale(0.8) translateY(10px); }
  to   { opacity: 1; transform: scale(1)   translateY(0);    }
}
#home-stats .stat:nth-child(1) { animation: vs-stat-pop 0.48s var(--ease-spring) 0.18s both; }
#home-stats .stat:nth-child(2) { animation: vs-stat-pop 0.48s var(--ease-spring) 0.27s both; }
#home-stats .stat:nth-child(3) { animation: vs-stat-pop 0.48s var(--ease-spring) 0.36s both; }
#home-stats .stat:nth-child(4) { animation: vs-stat-pop 0.48s var(--ease-spring) 0.45s both; }

/* Stat count-up pulse */
@keyframes vs-num-pop {
  0%   { opacity: 0; transform: scale(0.55); }
  65%  {             transform: scale(1.1);  }
  100% { opacity: 1; transform: scale(1);    }
}
.stat-val.vs-counting { animation: vs-num-pop 0.42s var(--ease-spring) both; }

/* Tool cards stagger up */
@keyframes vs-card-rise {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0);    }
}
#page-home .card:nth-child(1) { animation: vs-card-rise 0.4s var(--ease-out) 0.26s both; }
#page-home .card:nth-child(2) { animation: vs-card-rise 0.4s var(--ease-out) 0.34s both; }
#page-home .card:nth-child(3) { animation: vs-card-rise 0.4s var(--ease-out) 0.42s both; }
#page-home .card:nth-child(4) { animation: vs-card-rise 0.4s var(--ease-out) 0.50s both; }
#page-home .card:nth-child(5) { animation: vs-card-rise 0.4s var(--ease-out) 0.58s both; }
#page-home .card:nth-child(6) { animation: vs-card-rise 0.4s var(--ease-out) 0.66s both; }
#page-home .notice            { animation: vs-card-rise 0.38s var(--ease-out) 0.74s both; }

/* Card hover lift */
#page-home .card[onclick] {
  transition: transform 0.18s var(--ease-spring),
              border-color 0.18s ease,
              box-shadow 0.18s ease;
  will-change: transform;
}
#page-home .card[onclick]:hover  { transform: translateY(-4px); box-shadow: 0 8px 22px rgba(0,0,0,0.08); }
#page-home .card[onclick]:active { transform: translateY(-1px) scale(0.99); }
body.dark #page-home .card[onclick]:hover { box-shadow: 0 8px 26px rgba(0,0,0,0.42); }

/* Dot grid background */
#home-dot-grid {
  position: absolute; inset: 0;
  pointer-events: none; overflow: hidden; z-index: 0;
}
#home-dot-grid::before {
  content: '';
  position: absolute; inset: 0;
  background-image: radial-gradient(circle, var(--border2) 1px, transparent 1px);
  background-size: 26px 26px;
  mask-image: radial-gradient(ellipse 75% 60% at 50% 0%, black 0%, transparent 100%);
  -webkit-mask-image: radial-gradient(ellipse 75% 60% at 50% 0%, black 0%, transparent 100%);
  animation: vs-grid-pulse 5s ease-in-out infinite alternate;
}
@keyframes vs-grid-pulse {
  from { opacity: 0.18; background-size: 26px 26px; }
  to   { opacity: 0.4;  background-size: 28px 28px; }
}

/* Horizontal scan line sweeping down */
#home-scan-line {
  position: absolute; left: 0; right: 0; top: 0;
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    var(--border2) 20%,
    var(--border2) 80%,
    transparent 100%);
  animation: vs-scan-sweep 9s ease-in-out infinite;
  animation-delay: 2s;
  pointer-events: none; z-index: 2;
}
@keyframes vs-scan-sweep {
  0%   { transform: translateY(-4px);  opacity: 0;   }
  8%   {                               opacity: 0.7;  }
  92%  {                               opacity: 0.15; }
  100% { transform: translateY(320px); opacity: 0;   }
}

/* Keep home content above the bg layers */
#page-home .page-hd,
#page-home #home-stats,
#page-home > div:not(#home-dot-grid):not(#home-scan-line) {
  position: relative; z-index: 1;
}

/* Floating orbs (injected into body) */
@keyframes vs-orb-float {
  0%,100% { transform: translate(0, 0)   scale(1);    }
  33%     { transform: translate(26px,-34px) scale(1.05); }
  66%     { transform: translate(-16px,18px) scale(0.97); }
}
.vs-orb {
  position: fixed;
  border-radius: 50%;
  pointer-events: none;
  z-index: 0;
  filter: blur(70px);
  animation: vs-orb-float 20s ease-in-out infinite;
  opacity: 0;
  transition: opacity 0.8s ease;
}
.vs-orb.show { opacity: 1; }
.vs-orb-a {
  width: 360px; height: 360px;
  top: -100px; left: -80px;
  background: radial-gradient(circle, rgba(0,0,0,0.035) 0%, transparent 70%);
  animation-delay: 0s;
}
.vs-orb-b {
  width: 280px; height: 280px;
  bottom: -60px; right: -60px;
  background: radial-gradient(circle, rgba(0,0,0,0.028) 0%, transparent 70%);
  animation-delay: -7s;
}
.vs-orb-c {
  width: 220px; height: 220px;
  top: 42%; left: 58%;
  background: radial-gradient(circle, rgba(0,0,0,0.022) 0%, transparent 70%);
  animation-delay: -14s;
}
body.dark .vs-orb-a { background: radial-gradient(circle, rgba(255,255,255,0.038) 0%, transparent 70%); }
body.dark .vs-orb-b { background: radial-gradient(circle, rgba(255,255,255,0.028) 0%, transparent 70%); }
body.dark .vs-orb-c { background: radial-gradient(circle, rgba(255,255,255,0.02)  0%, transparent 70%); }

/* ------------------------------------------------------------------
   GLOBAL MICRO-INTERACTIONS
   ------------------------------------------------------------------ */
@keyframes vs-page-enter {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0);   }
}
.page.active { animation: vs-page-enter 0.24s var(--ease-out) both; }

.nav-item {
  transition: background var(--transition),
              color var(--transition),
              transform 0.14s var(--ease-spring);
}
.nav-item:hover  { transform: translateX(2px); }
.nav-item.active { transform: translateX(0); }

.theme-toggle      { transition: background 0.28s ease; }
.theme-toggle::after { transition: transform 0.28s var(--ease-spring); }

.pill {
  transition: background 0.18s var(--ease-spring),
              color 0.14s ease,
              border-color 0.14s ease,
              transform 0.14s var(--ease-spring);
}
.pill:hover  { transform: scale(1.04); }
.pill:active { transform: scale(0.97); }

@keyframes vs-brand-breathe { 0%,100% { opacity:1; } 50% { opacity:0.65; } }
.brand-icon { animation: vs-brand-breathe 3s ease-in-out infinite; }
.brand-logo:hover .brand-icon { animation: vs-logo-spin 0.5s var(--ease-spring) both; }

/* ================================================================ */
"""

OLD_CSS_ANCHOR = "/* -- Responsive -- */\n@media(max-width:720px){"
NEW_CSS_ANCHOR = ANIMATION_CSS + "/* -- Responsive -- */\n@media(max-width:720px){"


# ==========================================================================
#  HOME PAGE HTML
#  Add dot-grid div + scan-line div + username suffix span
# ==========================================================================

# Pattern A -- totally fresh (no previous patches)
OLD_HOME_A = (
    "      <!-- = HOME = -->\n"
    "      <div class=\"page active\" id=\"page-home\">\n"
    "        <div class=\"page-hd\">\n"
    "          <div class=\"page-title\">Welcome back</div>"
)
NEW_HOME = (
    "      <!-- = HOME = -->\n"
    "      <div class=\"page active\" id=\"page-home\">\n"
    "        <div id=\"home-dot-grid\"></div>\n"
    "        <div id=\"home-scan-line\"></div>\n"
    "        <div class=\"page-hd\">\n"
    "          <div class=\"page-title\">Welcome back<span id=\"home-username-suffix\"></span></div>"
)

# Pattern B -- previous patch added home-grid-bg but not the new names
OLD_HOME_B = (
    "      <!-- = HOME = -->\n"
    "      <div class=\"page active\" id=\"page-home\">\n"
    "        <div id=\"home-grid-bg\"></div>\n"
    "        <div id=\"home-scan-line\"></div>\n"
    "        <div class=\"page-hd\">\n"
    "          <div class=\"page-title\">Welcome back<span id=\"home-username-suffix\"></span></div>"
)
NEW_HOME_B = (
    "      <!-- = HOME = -->\n"
    "      <div class=\"page active\" id=\"page-home\">\n"
    "        <div id=\"home-dot-grid\"></div>\n"
    "        <div id=\"home-scan-line\"></div>\n"
    "        <div class=\"page-hd\">\n"
    "          <div class=\"page-title\">Welcome back<span id=\"home-username-suffix\"></span></div>"
)


# ==========================================================================
#  AUTH CANVAS  (canvas element inside the overlay, script after overlay)
# ==========================================================================

OLD_AUTH_OPEN = (
    "<!-- -- Auth overlay -- -->\n"
    "<div class=\"overlay\" id=\"auth-overlay\">\n"
    "  <div class=\"auth-box\">"
)
NEW_AUTH_OPEN = (
    "<!-- -- Auth overlay -- -->\n"
    "<div class=\"overlay\" id=\"auth-overlay\">\n"
    "  <canvas id=\"auth-canvas\"></canvas>\n"
    "  <div class=\"auth-box\">"
)

# The canvas particle script -- plain ES5, zero special chars
AUTH_CANVAS_JS = (
    "<script>\n"
    "/* Auth screen particle canvas */\n"
    "(function () {\n"
    "  function initAuthCanvas() {\n"
    "    var cv = document.getElementById('auth-canvas');\n"
    "    if (!cv) return;\n"
    "    var cx = cv.getContext('2d');\n"
    "    var W = 0, H = 0, pts = [];\n"
    "\n"
    "    function resize() {\n"
    "      var ov = document.getElementById('auth-overlay');\n"
    "      W = cv.width  = ov ? ov.offsetWidth  : window.innerWidth;\n"
    "      H = cv.height = ov ? ov.offsetHeight : window.innerHeight;\n"
    "    }\n"
    "\n"
    "    function makePt() {\n"
    "      return {\n"
    "        x: Math.random() * W, y: Math.random() * H,\n"
    "        r: Math.random() * 1.5 + 0.3,\n"
    "        vx: (Math.random() - 0.5) * 0.28,\n"
    "        vy: (Math.random() - 0.5) * 0.28,\n"
    "        a: Math.random() * 0.4 + 0.08,\n"
    "        ph: Math.random() * 6.28\n"
    "      };\n"
    "    }\n"
    "\n"
    "    function getColor() {\n"
    "      var b = document.getElementById('body');\n"
    "      return (b && b.classList.contains('dark')) ? '230,230,230' : '20,20,20';\n"
    "    }\n"
    "\n"
    "    function draw(ts) {\n"
    "      requestAnimationFrame(draw);\n"
    "      cx.clearRect(0, 0, W, H);\n"
    "      var col = getColor();\n"
    "      var i, j, p, dx, dy, dist, alpha;\n"
    "      for (i = 0; i < pts.length; i++) {\n"
    "        p = pts[i];\n"
    "        p.x += p.vx; p.y += p.vy;\n"
    "        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;\n"
    "        if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;\n"
    "        alpha = p.a * (0.55 + 0.45 * Math.sin(ts / 2200 + p.ph));\n"
    "        cx.beginPath();\n"
    "        cx.arc(p.x, p.y, p.r, 0, 6.283);\n"
    "        cx.fillStyle = 'rgba(' + col + ',' + alpha.toFixed(3) + ')';\n"
    "        cx.fill();\n"
    "      }\n"
    "      for (i = 0; i < pts.length; i++) {\n"
    "        for (j = i + 1; j < pts.length; j++) {\n"
    "          dx = pts[i].x - pts[j].x;\n"
    "          dy = pts[i].y - pts[j].y;\n"
    "          dist = Math.sqrt(dx * dx + dy * dy);\n"
    "          if (dist < 115) {\n"
    "            cx.beginPath();\n"
    "            cx.moveTo(pts[i].x, pts[i].y);\n"
    "            cx.lineTo(pts[j].x, pts[j].y);\n"
    "            cx.strokeStyle = 'rgba(' + col + ',' + ((1 - dist / 115) * 0.06).toFixed(3) + ')';\n"
    "            cx.lineWidth = 0.5;\n"
    "            cx.stroke();\n"
    "          }\n"
    "        }\n"
    "      }\n"
    "    }\n"
    "\n"
    "    resize();\n"
    "    for (var n = 0; n < 55; n++) pts.push(makePt());\n"
    "    window.addEventListener('resize', resize);\n"
    "    requestAnimationFrame(draw);\n"
    "  }\n"
    "\n"
    "  /* Run after DOM is ready */\n"
    "  if (document.readyState === 'loading') {\n"
    "    document.addEventListener('DOMContentLoaded', initAuthCanvas);\n"
    "  } else {\n"
    "    initAuthCanvas();\n"
    "  }\n"
    "})();\n"
    "</script>\n"
)

OLD_ABOUT_MARKER  = "<!-- -- About modal -- -->"
NEW_ABOUT_MARKER  = AUTH_CANVAS_JS + "<!-- -- About modal -- -->"


# ==========================================================================
#  SCAN OUTPUT WIDTH FIXES
# ==========================================================================

OLD_CONTENT_CSS  = ".content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden}"
NEW_CONTENT_CSS  = ".content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden;width:100%}"

# Fresh version (no previous patch)
OLD_CONTENT_CSS2 = ".content{padding:28px 28px;flex:1}"
NEW_CONTENT_CSS2 = ".content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden;width:100%}"

OLD_PORT_BODY = (
    ".port-body{"
    "padding:0 14px 14px;"
    "border-top:1px solid var(--border);"
    "display:none;"
    "}"
)
NEW_PORT_BODY = (
    ".port-body{"
    "padding:14px 20px 20px;"
    "border-top:1px solid var(--border);"
    "display:none;"
    "max-width:100%;"
    "overflow-x:auto;"
    "}"
)

OLD_TBLWRAP = ".tbl-wrap{overflow-x:auto}"
NEW_TBLWRAP = (
    ".tbl-wrap{overflow-x:auto;width:100%}\n"
    "#res,#hv-res,#nk-res,#wp-res,#ly-res,#lg-res,#dr-res,"
    "#sub-res,#dir-res,#bf-res,#disc-res"
    "{width:100%;max-width:100%;overflow-x:auto}"
)

OLD_SGRID = (
    ".stats{display:grid;"
    "grid-template-columns:repeat(auto-fill,minmax(110px,1fr));"
    "gap:10px;margin-bottom:20px}"
)
NEW_SGRID = (
    ".stats{display:grid;"
    "grid-template-columns:repeat(auto-fill,minmax(120px,1fr));"
    "gap:10px;margin-bottom:20px;width:100%}"
)


# ==========================================================================
#  ADMIN NAV FIX
# ==========================================================================

OLD_ADMIN_NAV = (
    "      <div class=\"nav-section admin-only\" id=\"admin-nav-section\" style=\"display:none\">\n"
    "        <div class=\"nav-label\">ADMIN</div>\n"
    "        <button class=\"nav-item\" id=\"ni-admin\" onclick=\"pg('admin',this)\"><span class=\"ni\">&#9632;</span> Admin Console</button>\n"
    "      </div>"
)

# Fully fresh version
OLD_ADMIN_NAV2 = (
    "      <div class=\"nav-section admin-only\" style=\"display:none\">\n"
    "        <div class=\"nav-label\">ADMIN</div>\n"
    "        <button class=\"nav-item admin-only\" id=\"ni-admin\" onclick=\"pg('admin',this)\" style=\"display:none\"><span class=\"ni\">&#9632;</span> Admin Console</button>\n"
    "      </div>"
)

NEW_ADMIN_NAV = (
    "      <div class=\"nav-section\" id=\"admin-nav-section\" style=\"display:none\">\n"
    "        <div class=\"nav-label\">ADMIN</div>\n"
    "        <button class=\"nav-item\" id=\"ni-admin\" onclick=\"pg('admin',this)\"><span class=\"ni\">&#9632;</span> Admin Console</button>\n"
    "      </div>"
)

# Fix the JS that reveals admin elements
OLD_ADMIN_SHOW_A = (
    "      if(d.role==='admin')document.querySelectorAll('.admin-only').forEach(e=>e.style.display='flex');"
)
OLD_ADMIN_SHOW_B = (
    "      if(d.role==='admin'){\n"
    "        var adminEls=document.querySelectorAll('.admin-only');\n"
    "        adminEls.forEach(function(e){\n"
    "          e.style.display=(e.tagName==='BUTTON')?'flex':'block';\n"
    "        });\n"
    "      }"
)
NEW_ADMIN_SHOW = (
    "      if(d.role==='admin'){\n"
    "        var adminSec=document.getElementById('admin-nav-section');\n"
    "        if(adminSec)adminSec.style.display='block';\n"
    "      }"
)


# ==========================================================================
#  JAVASCRIPT
#  animateCount, loadUser nav, typewriter, orbs
#  ALL injected as a single block before loadUser()
#  CRITICAL: pg() is NOT wrapped -- that broke login.
#  Instead we call a separate vsHomeAnimations() after pg().
# ==========================================================================

OLD_ANIMATE_ORIG = (
    "function animateCount(el,target)"
    "{if(!el||isNaN(target))return;"
    "let startT=null,dur=1000;"
    "function step(ts)"
    "{if(!startT)startT=ts;"
    "const p=Math.min((ts-startT)/dur,1);"
    "const ease=1-Math.pow(1-p,3);"
    "el.textContent=Math.floor(ease*target);"
    "if(p<1)requestAnimationFrame(step);}"
    "requestAnimationFrame(step);}"
)
OLD_ANIMATE_V2 = (
    "function animateCount(el,target)"
    "{if(!el||isNaN(target))return;"
    "el.classList.add('counting');"
    "let startT=null,dur=1000;"
    "function step(ts)"
    "{if(!startT)startT=ts;"
    "const p=Math.min((ts-startT)/dur,1);"
    "const ease=1-Math.pow(1-p,3);"
    "el.textContent=Math.floor(ease*target);"
    "if(p<1)requestAnimationFrame(step);"
    "else el.classList.remove('counting');}"
    "requestAnimationFrame(step);}"
)
NEW_ANIMATE = (
    "function animateCount(el,target)"
    "{if(!el||isNaN(target))return;"
    "el.classList.add('vs-counting');"
    "var startT=null,dur=1000;"
    "function step(ts)"
    "{if(!startT)startT=ts;"
    "var p=Math.min((ts-startT)/dur,1);"
    "var ease=1-Math.pow(1-p,3);"
    "el.textContent=Math.floor(ease*target);"
    "if(p<1)requestAnimationFrame(step);"
    "else el.classList.remove('vs-counting');}"
    "requestAnimationFrame(step);}"
)

# loadUser nav -- always go Home
OLD_NAV_ORIG = (
    "      loadProfileInfo(d);loadHomeStats();loadUserTheme();\n"
    "      const saved=loadSavedPage();\n"
    "      if(saved&&document.getElementById('page-'+saved))pg(saved,null);\n"
    "      else pg('home',null);"
)
OLD_NAV_V2 = (
    "      loadProfileInfo(d);loadHomeStats();loadUserTheme();\n"
    "      pg('home',null);\n"
    "      var _suf=document.getElementById('home-username-suffix');\n"
    "      if(_suf)typeWriter(_suf,', '+d.username,'_');"
)
OLD_NAV_V3 = (
    "      loadProfileInfo(d);loadHomeStats();loadUserTheme();\n"
    "      // Always land on Home after login\n"
    "      pg('home',null);\n"
    "      // Greet user by name\n"
    "      const suf=document.getElementById('home-username-suffix');\n"
    "      if(suf)typeWriter(suf,', '+d.username,'_');"
)
NEW_NAV = (
    "      loadProfileInfo(d);loadHomeStats();loadUserTheme();\n"
    "      pg('home',null);\n"
    "      vsGreetUser(d.username);"
)

# The safe JS injection -- NO pg() wrapping, uses a separate helper
OLD_LOADUSER_CALL = "loadUser();\n</script>"

NEW_LOADUSER_CALL = (
    "/* ---- VulnScan animation helpers ---- */\n"
    "\n"
    "/* Typewriter for greeting */\n"
    "function typeWriter(el, text, cursor) {\n"
    "  cursor = cursor || '';\n"
    "  el.textContent = '';\n"
    "  var i = 0;\n"
    "  function tick() {\n"
    "    if (i <= text.length) {\n"
    "      el.textContent = text.slice(0, i) + (i < text.length ? cursor : '');\n"
    "      i++;\n"
    "      setTimeout(tick, i === 1 ? 320 : 52);\n"
    "    }\n"
    "  }\n"
    "  tick();\n"
    "}\n"
    "\n"
    "/* Greet user on home page */\n"
    "function vsGreetUser(username) {\n"
    "  var suf = document.getElementById('home-username-suffix');\n"
    "  if (suf && !suf.textContent) typeWriter(suf, ', ' + username, '_');\n"
    "}\n"
    "\n"
    "/* Re-play home animations when navigating to home */\n"
    "function vsHomeAnimations() {\n"
    "  setTimeout(loadHomeStats, 80);\n"
    "  if (currentUser) vsGreetUser(currentUser.username);\n"
    "  var home = document.getElementById('page-home');\n"
    "  if (!home) return;\n"
    "  var cards = home.querySelectorAll('.card[onclick]');\n"
    "  for (var ci = 0; ci < cards.length; ci++) {\n"
    "    (function (c) {\n"
    "      c.style.animation = 'none';\n"
    "      requestAnimationFrame(function () { c.style.animation = ''; });\n"
    "    })(cards[ci]);\n"
    "  }\n"
    "}\n"
    "\n"
    "/* Patch pg() AFTER it is defined so login is never broken */\n"
    "document.addEventListener('DOMContentLoaded', function () {\n"
    "  var _origPg = pg;\n"
    "  pg = function (id, el) {\n"
    "    _origPg(id, el);\n"
    "    /* topbar title fade */\n"
    "    var tt = document.getElementById('topbar-title');\n"
    "    if (tt) {\n"
    "      tt.style.animation = 'none';\n"
    "      requestAnimationFrame(function () { tt.style.animation = ''; });\n"
    "    }\n"
    "    if (id === 'home') vsHomeAnimations();\n"
    "  };\n"
    "\n"
    "  /* Inject floating orbs into body */\n"
    "  var orbClasses = ['vs-orb vs-orb-a', 'vs-orb vs-orb-b', 'vs-orb vs-orb-c'];\n"
    "  orbClasses.forEach(function (cls) {\n"
    "    var d = document.createElement('div');\n"
    "    d.className = cls;\n"
    "    document.body.appendChild(d);\n"
    "    setTimeout(function () { d.classList.add('show'); }, 150);\n"
    "  });\n"
    "});\n"
    "\n"
    "loadUser();\n"
    "</script>"
)


# ==========================================================================
#  MAIN
# ==========================================================================

def main():
    print("\n" + BOLD + CYAN + "VulnScan Pro -- v4 Patch (clean fix)" + RESET)
    print("=" * 56)

    F = "api_server.py"

    if not os.path.isfile(F):
        fail("api_server.py not found. Run from your vulnscan project root.")
        return

    print("\n" + BOLD + "[CLEANUP] Remove broken code from previous patch runs" + RESET)
    remove_broken_patches(F)

    print("\n" + BOLD + "[1/7] Animation CSS (all keyframes + orbs + grid)" + RESET)
    apply_patches(F, [
        ("Full animation CSS block", OLD_CSS_ANCHOR, NEW_CSS_ANCHOR),
    ])

    print("\n" + BOLD + "[2/7] Home page HTML: dot-grid + scan-line + greeting span" + RESET)
    apply_patches(F, [
        ("Home hero -- fresh", OLD_HOME_A, NEW_HOME),
        ("Home hero -- upgrade old bg id", OLD_HOME_B, NEW_HOME_B),
    ])

    print("\n" + BOLD + "[3/7] Auth canvas element + particle script" + RESET)
    apply_patches(F, [
        ("Auth overlay: canvas element", OLD_AUTH_OPEN, NEW_AUTH_OPEN),
        ("Auth canvas: particle init script", OLD_ABOUT_MARKER, NEW_ABOUT_MARKER),
    ])

    print("\n" + BOLD + "[4/7] Scan output: full width" + RESET)
    apply_patches(F, [
        ("content area min-width (v2 -- fresh)", OLD_CONTENT_CSS2, NEW_CONTENT_CSS2),
        ("content area min-width (v1 -- already patched)", OLD_CONTENT_CSS, NEW_CONTENT_CSS),
        ("port-body: wider padding", OLD_PORT_BODY, NEW_PORT_BODY),
        ("tbl-wrap + result divs full width", OLD_TBLWRAP, NEW_TBLWRAP),
        ("stats grid full width", OLD_SGRID, NEW_SGRID),
    ])

    print("\n" + BOLD + "[5/7] Admin nav: fix alignment" + RESET)
    apply_patches(F, [
        ("Admin nav section -- fresh", OLD_ADMIN_NAV2, NEW_ADMIN_NAV),
        ("Admin nav section -- previously patched", OLD_ADMIN_NAV, NEW_ADMIN_NAV),
        ("Admin show JS -- arrow fn version", OLD_ADMIN_SHOW_A, NEW_ADMIN_SHOW),
        ("Admin show JS -- fn version", OLD_ADMIN_SHOW_B, NEW_ADMIN_SHOW),
    ])

    print("\n" + BOLD + "[6/7] animateCount: vs-counting class" + RESET)
    apply_patches(F, [
        ("animateCount -- original", OLD_ANIMATE_ORIG, NEW_ANIMATE),
        ("animateCount -- v2 (counting)", OLD_ANIMATE_V2, NEW_ANIMATE),
    ])

    print("\n" + BOLD + "[7/7] JS helpers: typewriter, home anims, safe pg() wrap, orbs" + RESET)
    apply_patches(F, [
        ("loadUser nav -- original", OLD_NAV_ORIG, NEW_NAV),
        ("loadUser nav -- v2", OLD_NAV_V2, NEW_NAV),
        ("loadUser nav -- v3", OLD_NAV_V3, NEW_NAV),
        ("JS helpers + loadUser call", OLD_LOADUSER_CALL, NEW_LOADUSER_CALL),
    ])

    print("\n" + "=" * 56)
    print(BOLD + "SUMMARY" + RESET)
    print("  Changes applied : " + GREEN + str(changes_applied) + RESET)
    print("  Files modified  : " + YELLOW + str(len(files_modified)) + RESET)
    for f in files_modified:
        print("    * " + f)
    if restart_needed:
        print("\n  " + YELLOW + "Restart required:" + RESET)
        print("     python3 api_server.py")
    else:
        print("\n  " + GREEN + "No changes needed." + RESET)
    if changes_applied:
        print("\n  " + GREEN + "Fixed:" + RESET)
        print("    Login     -- pg() wrapper is now safe (DOMContentLoaded)")
        print("    Animations-- floating orbs, dot-grid, scan-line, particle canvas")
        print("    Admin nav -- no more off-grid badge")
        print("    Scan out  -- full width result panels")
        print("    Home      -- greeting typewriter, stat pop, card stagger")
    print()


if __name__ == "__main__":
    main()
