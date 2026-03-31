#!/usr/bin/env python3
"""
VulnScan Pro — Nav Search Popup Fix v3
  • Search popup appears correctly while typing
  • Clicking a suggestion navigates to that tool page
  • Expanding the correct category on navigation
  • Clean removal of any previous search injection

Run from project root:  python3 apply_nav_patch_v3.py
"""

import os, sys, re, shutil, subprocess
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; D = "\033[2m";  B = "\033[1m"; X = "\033[0m"

ok   = lambda m: print(f"  {G}✓{X}  {m}")
fail = lambda m: print(f"  {R}✗{X}  {m}")
info = lambda m: print(f"  {C}→{X}  {m}")
warn = lambda m: print(f"  {Y}!{X}  {m}")
skip = lambda m: print(f"  {D}·{X}  {m}")

TARGET = "api_server.py"
RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

# ── helpers ───────────────────────────────────────────────────

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst

def load():
    with open(TARGET, "r", encoding="utf-8") as f:
        return f.read()

def save(src):
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(src)

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

# ═════════════════════════════════════════════════════════════
# STEP 1 — Remove ALL previous search injections cleanly
# ═════════════════════════════════════════════════════════════

def strip_old_search(src):
    changed = False

    # Remove v1 / v2 HTML blocks
    for marker_start, marker_end in [
        ('<!-- ── Tool Search', '<!-- ── End Tool Search'),
        ('<!-- VulnScan Nav Search', '<!-- /VulnScan Nav Search'),
        ('<!-- VS-NAV-SEARCH-V3', '<!-- /VS-NAV-SEARCH-V3'),
    ]:
        pattern = re.escape(marker_start) + r'.*?' + re.escape(marker_end) + r'[^\n]*\n?'
        new_src, n = re.subn(pattern, '', src, flags=re.DOTALL)
        if n:
            src = new_src
            changed = True

    # Remove nav-all-categories wrapper divs
    src = re.sub(r'\s*<div id="nav-all-categories">\s*\n', '\n', src)
    src = re.sub(r'\s*</div><!-- /#nav-all-categories -->\s*\n', '\n', src)

    # Remove v1/v2 JS blocks
    for js_marker_start, js_marker_end in [
        ('// ── Nav tool search', '// Dismiss search on outside click\ndocument.addEventListener'),
        ('// ── VulnScan Nav Search v2', '// ── /VulnScan Nav Search v2'),
        ('// ── VS-NAV-SEARCH-V3', '// ── /VS-NAV-SEARCH-V3'),
    ]:
        if js_marker_start in src:
            idx_s = src.find(js_marker_start)
            if js_marker_end in src:
                idx_e = src.find(js_marker_end, idx_s) + len(js_marker_end)
                # consume trailing newlines
                while idx_e < len(src) and src[idx_e] in '\n\r':
                    idx_e += 1
                src = src[:idx_s] + src[idx_e:]
            else:
                # just remove everything from marker to next top-level function/comment
                src = src[:idx_s] + src[idx_s:].split('\n\n', 2)[-1]
            changed = True

    if changed:
        ok("Stripped old search injection(s)")
    else:
        skip("No old search artifacts found")
    return src

# ═════════════════════════════════════════════════════════════
# STEP 2 — Default closed: flip ?1: → ?0: in navRestore
# ═════════════════════════════════════════════════════════════

def patch_default_closed(src):
    if 'var open=(stored===null)?0:' in src:
        skip("Default-closed already applied")
        RESULTS["skipped"] += 1
        return src

    new_src, n = re.subn(
        r'(var open=\(stored===null\)\?)1(:)',
        r'\g<1>0\2',
        src
    )
    if n:
        ok("Categories now start collapsed by default")
        RESULTS["applied"] += 1
        return new_src

    fail("Default-closed: pattern not found")
    RESULTS["failed"] += 1
    return src

# ═════════════════════════════════════════════════════════════
# STEP 3 — Inject search HTML (just after <nav> opening tag)
# ═════════════════════════════════════════════════════════════

SEARCH_HTML = '''\
      <!-- VS-NAV-SEARCH-V3 -->
      <div style="padding:8px 10px 4px;position:relative">
        <div style="position:relative">
          <span style="position:absolute;left:9px;top:50%;transform:translateY(-50%);
                       color:var(--text3);font-size:12px;pointer-events:none;z-index:1">&#128269;</span>
          <input
            id="vns-input"
            class="inp inp-mono"
            type="text"
            placeholder="Search tools..."
            autocomplete="off"
            spellcheck="false"
            style="width:100%;padding:6px 10px 6px 28px;font-size:11px;
                   background:var(--bg3);border-color:var(--border)"
          />
        </div>
        <div id="vns-popup"
             style="display:none;position:absolute;left:10px;right:10px;top:calc(100% - 2px);
                    border:1px solid var(--border2);border-radius:0 0 var(--radius) var(--radius);
                    background:var(--bg);box-shadow:var(--shadow-md);
                    max-height:260px;overflow-y:auto;z-index:9999">
        </div>
      </div>
      <!-- /VS-NAV-SEARCH-V3 -->
'''

def patch_search_html(src):
    if 'VS-NAV-SEARCH-V3' in src:
        skip("Search HTML already present")
        RESULTS["skipped"] += 1
        return src

    # Inject right after the opening <nav> tag
    new_src, n = re.subn(
        r'(<nav>)(\s*\n)',
        r'\1\2' + SEARCH_HTML,
        src, count=1
    )
    if n:
        ok("Search HTML injected after <nav>")
        RESULTS["applied"] += 1
        return new_src

    fail("Search HTML: <nav> anchor not found")
    RESULTS["failed"] += 1
    return src

# ═════════════════════════════════════════════════════════════
# STEP 4 — Inject search JS
#
# Placed just before the LAST </script> tag inside the sidebar
# nav block — i.e. the one that closes the navToggle script.
# We identify it by looking for the navRestore DOMContentLoaded
# listener and inserting after it.
# ═════════════════════════════════════════════════════════════

SEARCH_JS = '''\

// ── VS-NAV-SEARCH-V3 ────────────────────────────────────────
(function () {
  'use strict';

  // Build an index of all tool nav buttons once the DOM is ready
  function buildIndex() {
    var items = [];
    var sidebar = document.querySelector('.sidebar');
    if (!sidebar) return items;
    sidebar.querySelectorAll('button.nav-item[onclick]').forEach(function (btn) {
      var oc  = btn.getAttribute('onclick') || '';
      var m   = oc.match(/pg\(['"]([^'"]+)['"]/);
      if (!m) return;
      var pid = m[1];
      // skip non-tool pages
      if (['home','dash','hist','profile','admin'].indexOf(pid) !== -1) return;
      var label = (btn.textContent || '').replace(/[\u25CB\u25CF\u25A0\u25A1\u2022\u26A1\u2699]/gu, '').trim();
      if (!label) return;
      items.push({ label: label, pid: pid });
    });
    return items;
  }

  var _idx = null;
  function getIndex() { return _idx || (_idx = buildIndex()); }

  function highlight(text, q) {
    if (!q) return text;
    var i = text.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return text;
    return text.slice(0, i)
      + '<mark style="background:rgba(255,214,10,0.35);color:inherit;'
      + 'border-radius:2px;padding:0 1px">'
      + text.slice(i, i + q.length) + '</mark>'
      + text.slice(i + q.length);
  }

  function showPopup(items, query) {
    var popup = document.getElementById('vns-popup');
    if (!popup) return;

    if (!items.length) {
      popup.innerHTML =
        '<div style="padding:9px 12px;font-size:11px;'
        + 'color:var(--text3);font-family:var(--mono)">No tools match</div>';
      popup.style.display = 'block';
      return;
    }

    popup.innerHTML = items.slice(0, 25).map(function (item, idx) {
      return '<button data-idx="' + idx + '" data-pid="' + item.pid + '" '
        + 'class="nav-item" '
        + 'style="width:100%;border-radius:0;padding:8px 14px;'
        + 'text-align:left;border:none;border-bottom:1px solid var(--border)" '
        + 'onmousedown="vsNavPick(\'' + item.pid + '\')">'
        + '<span class="ni" style="margin-right:6px">&#9675;</span>'
        + highlight(item.label, query)
        + '</button>';
    }).join('');
    popup.style.display = 'block';
  }

  function hidePopup() {
    var popup = document.getElementById('vns-popup');
    if (popup) { popup.style.display = 'none'; popup.innerHTML = ''; }
  }

  // Exposed globally so inline onclick can call it
  window.vsNavPick = function (pid) {
    // clear search first
    var input = document.getElementById('vns-input');
    if (input) input.value = '';
    hidePopup();
    _idx = null; // rebuild next search

    // navigate
    if (typeof pg === 'function') pg(pid, null);

    // expand the containing category
    var sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;
    sidebar.querySelectorAll('button.nav-item[onclick]').forEach(function (btn) {
      var oc = btn.getAttribute('onclick') || '';
      if (oc.indexOf("'" + pid + "'") !== -1 || oc.indexOf('"' + pid + '"') !== -1) {
        var section = btn.closest('.nav-cat-items');
        if (!section) return;
        var catId = section.id.replace('nc-', '');
        section.classList.remove('collapsed');
        section.classList.add('expanded');
        var arrow = document.getElementById('na-' + catId);
        if (arrow) arrow.classList.add('open');
        try { localStorage.setItem('vs-nav-' + catId, '1'); } catch (e) {}
        setTimeout(function () {
          btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 60);
      }
    });
  };

  // Wire up the input after DOM ready
  document.addEventListener('DOMContentLoaded', function () {
    var input = document.getElementById('vns-input');
    if (!input) return;

    input.addEventListener('input', function () {
      var q = input.value.trim();
      if (!q) { hidePopup(); return; }
      var hits = getIndex().filter(function (item) {
        return item.label.toLowerCase().indexOf(q.toLowerCase()) !== -1
          || item.pid.toLowerCase().indexOf(q.toLowerCase()) !== -1;
      });
      showPopup(hits, q);
    });

    input.addEventListener('keydown', function (e) {
      var popup  = document.getElementById('vns-popup');
      if (!popup || popup.style.display === 'none') return;
      var btns   = Array.from(popup.querySelectorAll('button'));
      var focused = popup.querySelector('button:focus');
      var fi      = focused ? btns.indexOf(focused) : -1;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        var next = fi < btns.length - 1 ? btns[fi + 1] : btns[0];
        next && next.focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (fi <= 0) { input.focus(); return; }
        btns[fi - 1].focus();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        input.value = ''; hidePopup(); input.blur();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (focused) focused.click();
        else if (btns.length) btns[0].click();
      }
    });

    // blur hides popup only if not clicking inside it
    input.addEventListener('blur', function () {
      setTimeout(hidePopup, 150);
    });
  });

}());
// ── /VS-NAV-SEARCH-V3 ───────────────────────────────────────
'''

def patch_search_js(src):
    if 'VS-NAV-SEARCH-V3' in src and 'buildIndex' in src:
        skip("Search JS already present")
        RESULTS["skipped"] += 1
        return src

    # Anchor: the navRestore DOMContentLoaded listener line
    anchor = "document.addEventListener('DOMContentLoaded',navRestore);"
    if anchor not in src:
        fail("Search JS: navRestore anchor not found")
        RESULTS["failed"] += 1
        return src

    new_src = src.replace(anchor, anchor + "\n" + SEARCH_JS, 1)
    ok("Search JS injected (IIFE, namespaced, popup on input)")
    RESULTS["applied"] += 1
    return new_src

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    print()
    print(B+C+"╔══════════════════════════════════════════════════════╗"+X)
    print(B+C+"║  VulnScan Pro — Nav Search Popup Fix v3             ║"+X)
    print(B+C+"╚══════════════════════════════════════════════════════╝"+X)
    print()

    if not os.path.isfile(TARGET):
        print(R+B+"  ERROR: api_server.py not found."+X)
        print("  Run from your VulnScan project root:  cd ~/vulnscan")
        sys.exit(1)

    info(f"Target : {TARGET}  ({os.path.getsize(TARGET)//1024} KB)")
    print()

    src = load()

    print(B+"  ── Step 1  Strip old search injections"+X)
    src = strip_old_search(src)
    print()

    print(B+"  ── Step 2  Categories collapsed by default"+X)
    src = patch_default_closed(src)
    print()

    print(B+"  ── Step 3  Inject search bar HTML"+X)
    src = patch_search_html(src)
    print()

    print(B+"  ── Step 4  Inject search JavaScript"+X)
    src = patch_search_js(src)
    print()

    # Only write if something changed
    if RESULTS["applied"] > 0:
        bak = backup(TARGET)
        save(src)
        info(f"Backup : {bak}")
        print()

        print(B+"  ── Syntax check"+X)
        passed, err = syntax_check(TARGET)
        if passed:
            ok(f"{TARGET} — syntax OK ✓")
        else:
            fail(f"SYNTAX ERROR detected!\n    {err}")
            warn(f"Restoring backup automatically...")
            shutil.copy2(bak, TARGET)
            warn(f"Restored. No changes applied.")
            sys.exit(1)
    else:
        info("Nothing to write — all steps skipped or failed")

    print()
    print(B+C+"══════════════════════════════════════════════════════"+X)
    fc = RESULTS["failed"]
    print(
        f"  Applied : {G}{RESULTS['applied']}{X}  |  "
        f"Skipped : {D}{RESULTS['skipped']}{X}  |  "
        f"Failed  : {(R if fc else D)}{fc}{X}"
    )
    print()

    if RESULTS["applied"] > 0:
        print(f"  {G}What changed:{X}")
        print(f"    {G}✓{X}  All nav categories start COLLAPSED by default")
        print(f"    {G}✓{X}  Search box above nav — type any tool name")
        print(f"    {G}✓{X}  Popup appears instantly while typing")
        print(f"    {G}✓{X}  Clicking a result navigates to that tool page")
        print(f"    {G}✓{X}  Auto-expands the containing category on navigate")
        print(f"    {G}✓{X}  Arrow ↑↓, Enter, Escape keyboard navigation")
        print()
        print(f"  {Y}Restart server:{X}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
    elif fc > 0:
        print(f"  {R}Some steps failed — file was NOT modified.{X}")
        print(f"  Check the error messages above.")
    else:
        print(f"  {G}Already up to date.{X}")

    print()

if __name__ == "__main__":
    main()
