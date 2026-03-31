#!/usr/bin/env python3
"""
VulnScan Pro — Nav Patch v2 (robust)
  • All nav categories collapsed by default
  • Working live search bar above nav
  • Uses regex for reliable matching instead of exact string anchors

Run from project root:  python3 apply_nav_patch_v2.py
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

RESULTS = {"applied": 0, "skipped": 0, "failed": 0}

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst

def syntax_check(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", path],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

# ── Read the file ─────────────────────────────────────────────
TARGET = "api_server.py"

def load():
    with open(TARGET, "r", encoding="utf-8") as f:
        return f.read()

def save(src):
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(src)

# ═════════════════════════════════════════════════════════════
# PATCH A — Make all categories start CLOSED by default
#
# Strategy: find the navRestore function and change the default
# open value from 1 to 0.  We look for the pattern:
#   var open=(stored===null)?1:
# and change the ?1: to ?0:
# ═════════════════════════════════════════════════════════════

def patch_default_closed(src):
    # Pattern: default open value in navRestore
    pattern = r'(var open=\(stored===null\)\?)1(:)'
    replacement = r'\g<1>0\2'
    
    if 'var open=(stored===null)?0:' in src:
        skip("Default-closed: already applied")
        RESULTS["skipped"] += 1
        return src
    
    new_src, count = re.subn(pattern, replacement, src)
    if count:
        ok(f"Default-closed: changed {count} occurrence(s) — categories now start collapsed")
        RESULTS["applied"] += 1
        return new_src
    else:
        fail("Default-closed: pattern not found — skipping")
        RESULTS["failed"] += 1
        return src

# ═════════════════════════════════════════════════════════════
# PATCH B — Remove any broken search injection from v1 patch
#
# The v1 patch may have inserted a broken search block.
# We strip it out so we can inject fresh.
# ═════════════════════════════════════════════════════════════

BROKEN_SEARCH_MARKERS = [
    # The wrapper div injected by v1
    '<!-- ── Tool Search ──────────────────────────── -->',
    '<div id="nav-all-categories">',
    '<!-- /#nav-all-categories -->',
    '// ── Nav tool search ─────────────────────────────────────────',
    'function navSearch(',
    'function navSearchSelect(',
    'function _buildNavIndex(',
]

def remove_v1_search(src):
    """Remove the broken v1 search injection if present."""
    if '<!-- ── Tool Search' not in src and 'function navSearch(' not in src:
        return src, False

    info("Removing v1 search injection (will re-inject cleanly)...")

    # Remove the search bar HTML block
    src = re.sub(
        r'\s*<!-- ── Tool Search ──.*?<!-- ── End Tool Search ─.*?-->\s*',
        '\n',
        src, flags=re.DOTALL
    )

    # Remove the nav-all-categories wrapper open tag
    src = src.replace('      <div id="nav-all-categories">\n', '')
    src = src.replace('<div id="nav-all-categories">', '')

    # Remove the nav-all-categories wrapper close tag
    src = re.sub(r'\s*</div><!-- /#nav-all-categories -->\s*', '\n', src)

    # Remove the navSearch/navSearchSelect/buildNavIndex JS block
    # It starts after "document.addEventListener('DOMContentLoaded',navRestore);"
    # and runs until the end of that <script> block.
    # Strategy: find the block between the navRestore listener and </script>
    # and strip the injected JS from it.
    src = re.sub(
        r'(document\.addEventListener\(\'DOMContentLoaded\',navRestore\);)\s*\n// ── Nav tool search.*?(\s*</script>)',
        r'\1\2',
        src, flags=re.DOTALL
    )

    # Also strip standalone navSearch function if it ended up outside
    src = re.sub(
        r'\n// ── Nav tool search ─+.*?(?=\nfunction [a-zA-Z]|\n/\* ====|\Z)',
        '',
        src, flags=re.DOTALL
    )

    return src, True

# ═════════════════════════════════════════════════════════════
# PATCH C — Inject clean search bar HTML
#
# We inject just before the first nav-section div inside <nav>.
# Anchor: the <nav> open tag followed by whitespace and <style>
# ═════════════════════════════════════════════════════════════

SEARCH_HTML = '''      <!-- VulnScan Nav Search v2 -->
      <div style="padding:8px 10px 2px">
        <div style="position:relative">
          <span id="nav-search-icon" style="position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:12px;pointer-events:none">&#128269;</span>
          <input
            id="nav-search-input"
            class="inp inp-mono"
            type="text"
            placeholder="Search tools..."
            autocomplete="off"
            spellcheck="false"
            oninput="vsNavSearch(this.value)"
            onkeydown="vsNavSearchKey(event)"
            style="width:100%;padding:6px 10px 6px 28px;font-size:11px;background:var(--bg3);border-color:var(--border)"
          />
        </div>
        <div id="nav-search-results" style="display:none;margin-top:3px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);overflow:hidden;max-height:260px;overflow-y:auto;position:relative;z-index:100"></div>
      </div>
      <!-- /VulnScan Nav Search v2 -->
'''

def patch_search_html(src):
    if 'VulnScan Nav Search v2' in src:
        skip("Search HTML: already applied")
        RESULTS["skipped"] += 1
        return src

    # Find <nav> then the first <div class="nav-section"> inside it
    # We insert our search bar between <nav> and the first nav-section
    pattern = r'(<nav>\s*\n)([ \t]*<(?:style|div class="nav-section"|script))'
    
    def replacer(m):
        return m.group(1) + SEARCH_HTML + m.group(2)
    
    new_src, count = re.subn(pattern, replacer, src, count=1)
    if count:
        ok("Search HTML: injected search bar above nav categories")
        RESULTS["applied"] += 1
        return new_src
    else:
        fail("Search HTML: could not find <nav> anchor")
        RESULTS["failed"] += 1
        return src

# ═════════════════════════════════════════════════════════════
# PATCH D — Inject search JS
#
# Injected just before the closing </script> tag of the
# navToggle/navRestore block (which is inside <nav>).
# We find that script block by looking for navRestore and its
# closing </script>.
# ═════════════════════════════════════════════════════════════

SEARCH_JS = '''
// ── VulnScan Nav Search v2 ──────────────────────────────────
var _vsNavIdx = null;

function _vsNavBuild() {
  if (_vsNavIdx) return _vsNavIdx;
  _vsNavIdx = [];
  // Walk every nav-item button in the sidebar
  var sidebar = document.querySelector('.sidebar nav');
  if (!sidebar) return _vsNavIdx;
  sidebar.querySelectorAll('button.nav-item').forEach(function(btn) {
    var raw = btn.textContent || '';
    // strip leading icon chars and whitespace
    var label = raw.replace(/^[\\s\\u25CB\\u25CF\\u25A0\\u25A1\\u2022\\u26A1\\u2699\\u25B6\\u25BA\\u25B8\\u27A4\\u2714\\u2716\\u00B7]+/u, '').trim();
    var oc = btn.getAttribute('onclick') || '';
    var m = oc.match(/pg\\(['"]([^'"]+)['"]/);
    var pageId = m ? m[1] : '';
    if (label && pageId && label !== 'Home' && label !== 'Dashboard' && label !== 'History' && label !== 'Admin Console' && label !== 'About' && label !== 'Logout') {
      _vsNavIdx.push({ label: label, pageId: pageId });
    }
  });
  return _vsNavIdx;
}

function vsNavSearch(query) {
  var results = document.getElementById('nav-search-results');
  if (!results) return;

  query = (query || '').trim();

  if (!query) {
    results.style.display = 'none';
    results.innerHTML = '';
    return;
  }

  var ql = query.toLowerCase();
  var idx = _vsNavBuild();
  var hits = idx.filter(function(item) {
    return item.label.toLowerCase().indexOf(ql) !== -1 ||
           item.pageId.toLowerCase().indexOf(ql) !== -1;
  });

  if (!hits.length) {
    results.innerHTML = '<div style="padding:9px 12px;font-size:11px;color:var(--text3);font-family:var(--mono)">No tools match</div>';
    results.style.display = 'block';
    return;
  }

  results.innerHTML = hits.slice(0, 20).map(function(item) {
    var label = item.label;
    var i = label.toLowerCase().indexOf(ql);
    var hl = i >= 0
      ? label.substring(0, i)
        + '<mark style="background:rgba(255,214,10,0.32);color:inherit;border-radius:2px;padding:0 1px">'
        + label.substring(i, i + query.length)
        + '</mark>'
        + label.substring(i + query.length)
      : label;
    return '<button class="nav-item" style="width:100%;border-radius:0;padding:7px 12px;text-align:left" '
         + 'onclick="vsNavSelect(\'' + item.pageId + '\')" '
         + 'data-page="' + item.pageId + '">'
         + '<span class="ni">&#9675;</span> ' + hl + '</button>';
  }).join('');

  results.style.display = 'block';
}

function vsNavSelect(pageId) {
  // Clear search
  var input   = document.getElementById('nav-search-input');
  var results = document.getElementById('nav-search-results');
  if (input)   { input.value = ''; }
  if (results) { results.innerHTML = ''; results.style.display = 'none'; }

  // Navigate
  pg(pageId, null);

  // Expand the parent category
  var sidebar = document.querySelector('.sidebar nav');
  if (sidebar) {
    sidebar.querySelectorAll('button.nav-item').forEach(function(btn) {
      var oc = btn.getAttribute('onclick') || '';
      if (oc.indexOf("'" + pageId + "'") !== -1 || oc.indexOf('"' + pageId + '"') !== -1) {
        var section = btn.closest('.nav-cat-items');
        if (section) {
          var catId = section.id.replace('nc-', '');
          var arrow = document.getElementById('na-' + catId);
          section.classList.remove('collapsed');
          section.classList.add('expanded');
          if (arrow) arrow.classList.add('open');
          try { localStorage.setItem('vs-nav-' + catId, '1'); } catch(e) {}
        }
        setTimeout(function() { btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, 80);
      }
    });
  }
  _vsNavIdx = null; // rebuild next time
}

function vsNavSearchKey(e) {
  var results = document.getElementById('nav-search-results');
  var input   = document.getElementById('nav-search-input');
  if (!results || results.style.display === 'none') return;
  var btns = Array.from(results.querySelectorAll('button.nav-item'));
  if (!btns.length) return;
  var fi = btns.indexOf(document.activeElement);

  if (e.key === 'ArrowDown') {
    e.preventDefault();
    (fi < btns.length - 1 ? btns[fi + 1] : btns[0]).focus();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (fi <= 0) { input && input.focus(); }
    else btns[fi - 1].focus();
  } else if (e.key === 'Escape') {
    e.preventDefault();
    if (input) input.value = '';
    results.innerHTML = ''; results.style.display = 'none';
    if (input) input.blur();
  } else if (e.key === 'Enter' && fi >= 0) {
    e.preventDefault();
    btns[fi].click();
  }
}

// Dismiss search on outside click
document.addEventListener('click', function(e) {
  var input   = document.getElementById('nav-search-input');
  var results = document.getElementById('nav-search-results');
  if (!input || !results) return;
  if (results.style.display === 'none') return;
  if (!input.contains(e.target) && !results.contains(e.target)) {
    if (input) input.value = '';
    results.innerHTML = ''; results.style.display = 'none';
  }
});
// ── /VulnScan Nav Search v2 ─────────────────────────────────
'''

def patch_search_js(src):
    if 'VulnScan Nav Search v2' in src:
        skip("Search JS: already applied")
        RESULTS["skipped"] += 1
        return src

    # Find the navRestore addEventListener line + the closing </script>
    # that belongs to the same inline <script> inside <nav>
    # Pattern: the DOMContentLoaded navRestore listener followed (possibly
    # after whitespace) by </script>
    pattern = r"(document\.addEventListener\('DOMContentLoaded',navRestore\);)([ \t]*\n[ \t]*</script>)"
    
    replacement = r'\1' + SEARCH_JS + r'\2'
    
    new_src, count = re.subn(pattern, replacement, src, count=1)
    if count:
        ok("Search JS: injected vsNavSearch / vsNavSelect / keyboard handlers")
        RESULTS["applied"] += 1
        return new_src
    else:
        fail("Search JS: could not find navRestore addEventListener anchor")
        RESULTS["failed"] += 1
        return src

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    print()
    print(B+C+"╔══════════════════════════════════════════════════════╗"+X)
    print(B+C+"║  VulnScan Pro — Nav Patch v2 (robust re-apply)      ║"+X)
    print(B+C+"╚══════════════════════════════════════════════════════╝"+X)
    print()

    if not os.path.isfile(TARGET):
        print(R+B+"  ERROR: api_server.py not found."+X)
        print("  Run from the VulnScan project root:  cd ~/vulnscan")
        sys.exit(1)

    info(f"Project root : {os.getcwd()}")
    info(f"Target file  : {TARGET} ({os.path.getsize(TARGET)//1024} KB)")
    print()

    src = load()

    # Step 1 — remove any broken v1 artifacts
    print(B+"  ── Step 1: Clean up v1 injection (if present)"+X)
    src, cleaned = remove_v1_search(src)
    if cleaned:
        ok("Removed v1 search artifacts")
    else:
        skip("No v1 artifacts found")
    print()

    # Step 2 — patch default closed
    print(B+"  ── Step 2: Collapse categories by default"+X)
    src = patch_default_closed(src)
    print()

    # Step 3 — inject search HTML
    print(B+"  ── Step 3: Inject search bar HTML"+X)
    src = patch_search_html(src)
    print()

    # Step 4 — inject search JS
    print(B+"  ── Step 4: Inject search JavaScript"+X)
    src = patch_search_js(src)
    print()

    # Save
    if RESULTS["applied"] > 0:
        bak = backup(TARGET)
        save(src)
        info(f"Backup: {bak}")
        print()

        # Syntax check
        print(B+"  ── Syntax check"+X)
        passed, err = syntax_check(TARGET)
        if passed:
            ok(f"{TARGET} — syntax OK")
        else:
            fail(f"SYNTAX ERROR — restore backup!\n    {err}")
            print()
            warn(f"Restore with:  cp {bak} {TARGET}")
            sys.exit(1)
    else:
        info("No changes written (all skipped or failed)")

    # Summary
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
        print(f"  {G}Changes applied:{X}")
        print(f"    {G}✓{X}  All nav categories start COLLAPSED by default")
        print(f"    {G}✓{X}  Search bar above categories — type any tool name")
        print(f"    {G}✓{X}  Arrow ↑↓ to navigate results, Escape to close")
        print(f"    {G}✓{X}  Selecting a result auto-expands its category")
        print()
        print(f"  {Y}Restart to activate:{X}")
        print(f"    python3 api_server.py")
        print(f"    OR: sudo systemctl restart vulnscan")
    elif RESULTS["failed"] > 0:
        print(f"  {R}Some patches failed — see messages above.{X}")
        print(f"  The file was NOT modified.")
    else:
        print(f"  {G}All patches already applied — no restart needed.{X}")

    print()

if __name__ == "__main__":
    main()
