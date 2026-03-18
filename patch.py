#!/usr/bin/env python3
"""
VulnScan Pro -- Background Fix
1. Dark text on light theme, light text on dark theme
2. Remove cursor/pointer follow effect entirely
3. Lower opacity so it never bleeds over UI
4. z-index:-1 guaranteed so nothing is blocked

Run: python3 patch_bgfix.py
"""
import os, shutil
from datetime import datetime

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def ok(m):   print("  " + GREEN + "✓" + RESET + " " + m)
def fail(m): print("  " + RED   + "✗" + RESET + " " + m)
def info(m): print("  " + CYAN  + "→" + RESET + " " + m)

changes_applied = 0
files_modified  = []

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = path + "." + ts + ".bak"
    shutil.copy2(path, bak)
    return bak

def apply(path, patches):
    global changes_applied, files_modified
    if not os.path.isfile(path):
        fail("Not found: " + path)
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    applied = 0
    modified = content
    for desc, old, new in patches:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc)
            applied += 1
        elif new in modified:
            ok(desc + "  (already applied)")
        else:
            fail(desc)
    if applied:
        bak = backup(path)
        info("Backup -> " + bak)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        changes_applied += applied
        if path not in files_modified:
            files_modified.append(path)


# The old hacker background script (find it by its unique opening comment)
OLD_BG_OPEN = "/* ==== HACKER BACKGROUND ==== */\n(function(){"

# New script: rain only, correct colours, NO cursor trace
NEW_BG_SCRIPT = r"""/* ==== HACKER BACKGROUND ==== */
(function(){
  var cv, cx, W = 0, H = 0;

  /* ---- colour: dark chars on light, light chars on dark ---- */
  function isDark() {
    var b = document.getElementById('body');
    return b && b.classList.contains('dark');
  }
  /* head of each column -- brightest char */
  function headRGB()  { return isDark() ? [140,255,140] : [0, 80, 20]; }
  /* trail colour */
  function trailRGB() { return isDark() ? [0, 180, 60]  : [0, 60, 10]; }
  /* fade rect colour matches the page background */
  function fadeFill() {
    return isDark()
      ? 'rgba(10,10,10,0.15)'
      : 'rgba(255,255,255,0.18)';
  }

  /* ---- character set ---- */
  var CHARS = ('01ABCDEF0123456789<>{}[]|/:?!@#$%^&*nmap ssh ftp http ssl tls cve xss sqli rce').split('');
  function rndChar() { return CHARS[Math.floor(Math.random() * CHARS.length)]; }

  /* ---- columns ---- */
  var COL_W = 18, FONT_SZ = 11, columns = [];

  function initColumns() {
    columns = [];
    var n = Math.ceil(W / COL_W);
    for (var i = 0; i < n; i++) {
      var col = {
        x: i * COL_W,
        y: Math.random() * -H,
        speed: 0.3 + Math.random() * 0.7,
        len:   7 + Math.floor(Math.random() * 12),
        chars: [],
        tick:  0,
        mutRate: 0.03 + Math.random() * 0.05
      };
      for (var j = 0; j < 22; j++) col.chars.push(rndChar());
      columns.push(col);
    }
  }

  function drawRain() {
    var HEAD  = headRGB();
    var TRAIL = trailRGB();
    /* base opacity: subtle on both themes */
    var baseAlpha = isDark() ? 0.45 : 0.28;

    cx.font = FONT_SZ + 'px "DM Mono","Courier New",monospace';
    cx.textAlign = 'center';

    for (var i = 0; i < columns.length; i++) {
      var col = columns[i];
      col.tick++;

      /* advance column */
      if (col.tick % Math.max(1, Math.round(3 / col.speed)) === 0) {
        col.y += COL_W;
        col.chars.unshift(rndChar());
        if (col.chars.length > col.len + 2) col.chars.pop();
      }

      /* random char mutation */
      if (Math.random() < col.mutRate) {
        col.chars[Math.floor(Math.random() * col.chars.length)] = rndChar();
      }

      /* draw each char in this column */
      for (var k = 0; k < col.chars.length; k++) {
        var cy = col.y - k * COL_W;
        if (cy < -COL_W || cy > H + COL_W) continue;

        var t = 1 - (k / col.len);
        if (t < 0) t = 0;

        var r, g, b, a;
        if (k === 0) {
          /* head: brightest */
          r = HEAD[0]; g = HEAD[1]; b = HEAD[2];
          a = baseAlpha;
        } else {
          /* trail: fades out */
          r = Math.round(TRAIL[0] * t);
          g = Math.round(TRAIL[1] * t);
          b = Math.round(TRAIL[2] * t);
          a = baseAlpha * t * 0.6;
        }

        cx.fillStyle = 'rgba(' + r + ',' + g + ',' + b + ',' + a.toFixed(3) + ')';
        cx.fillText(col.chars[k], col.x + COL_W / 2, cy);
      }

      /* reset column when it scrolls off bottom */
      if (col.y - col.len * COL_W > H) {
        col.y     = -COL_W * (2 + Math.random() * 8);
        col.speed = 0.3 + Math.random() * 0.7;
        col.len   = 7 + Math.floor(Math.random() * 12);
        col.chars = [];
        for (var j2 = 0; j2 < 22; j2++) col.chars.push(rndChar());
      }
    }
  }

  /* ---- resize ---- */
  function resize() {
    if (!cv) return;
    var dpr = window.devicePixelRatio || 1;
    W = window.innerWidth;
    H = window.innerHeight;
    cx.setTransform(1, 0, 0, 1, 0, 0);
    cv.width  = W * dpr;
    cv.height = H * dpr;
    cv.style.width  = W + 'px';
    cv.style.height = H + 'px';
    cx.setTransform(dpr, 0, 0, dpr, 0, 0);
    initColumns();
  }

  /* ---- main loop ---- */
  function loop() {
    requestAnimationFrame(loop);
    /* semi-transparent fill creates the trail smear */
    cx.fillStyle = fadeFill();
    cx.fillRect(0, 0, W, H);
    drawRain();
  }

  /* ---- init ---- */
  function init() {
    if (document.getElementById('vs-hacker-canvas')) return;
    cv = document.createElement('canvas');
    cv.id = 'vs-hacker-canvas';
    cv.style.cssText = [
      'position:fixed',
      'top:0', 'left:0',
      'width:100vw', 'height:100vh',
      'pointer-events:none',  /* NEVER blocks clicks */
      'z-index:-1'            /* always behind everything */
    ].join(';');
    document.body.insertBefore(cv, document.body.firstChild);
    cx = cv.getContext('2d');
    window.addEventListener('resize', resize);
    resize();
    loop();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    setTimeout(init, 0);
  }
})();"""

# Find the old script end -- it ends just before loadUser();
OLD_BG_END = "\n\nloadUser();\n</script>"
NEW_BG_END = "\n\nloadUser();\n</script>"  # unchanged, we only replace the script body


def replace_bg_script(path):
    """Replace the hacker background block inside the <script> tag."""
    global changes_applied, files_modified
    if not os.path.isfile(path):
        fail("Not found: " + path)
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    start_marker = "/* ==== HACKER BACKGROUND ==== */"
    end_marker   = "\n\nloadUser();\n</script>"

    si = content.find(start_marker)
    if si == -1:
        fail("Hacker background script not found -- run patch_all.py first")
        return

    ei = content.find(end_marker, si)
    if ei == -1:
        fail("Could not find end of background script")
        return

    old_block = content[si:ei]
    if old_block == NEW_BG_SCRIPT:
        ok("Background script (already up to date)")
        return

    bak = backup(path)
    info("Backup -> " + bak)
    new_content = content[:si] + NEW_BG_SCRIPT + content[ei:]
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)
    ok("Background script replaced (no cursor trace, correct colours)")
    changes_applied += 1
    if path not in files_modified:
        files_modified.append(path)


def main():
    print("\n" + BOLD + CYAN + "VulnScan Pro -- Background Fix" + RESET)
    print("=" * 48)
    F = "api_server.py"
    if not os.path.isfile(F):
        fail("api_server.py not found -- run from ~/vulnscan")
        return

    print("\n" + BOLD + "[1/1] Fix background: correct colours, remove cursor trace" + RESET)
    replace_bg_script(F)

    print("\n" + "=" * 48)
    print(BOLD + "SUMMARY" + RESET)
    print("  Changes : " + (GREEN + str(changes_applied) + RESET))
    if files_modified:
        print("\n  Restart: python3 api_server.py")
        print("\n  " + GREEN + "What changed:" + RESET)
        print("    Light theme: dark green chars on white background")
        print("    Dark theme:  bright green chars on black background")
        print("    Cursor/pointer follow effect: REMOVED")
        print("    pointer-events:none kept -- clicks always work")
        print("    z-index:-1 kept -- never overlaps UI")
    else:
        print("  Nothing to do.")
    print()

if __name__ == "__main__":
    main()
