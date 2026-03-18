#!/usr/bin/env python3
"""
VulnScan Pro -- Scan Output Visibility Fix
Adds position:relative + z-index:2 + explicit background to all
result containers so they always render above the canvas.
Run: python3 patch_scanfix.py
"""
import os, shutil, subprocess, sys
from datetime import datetime

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def ok(m):   print("  " + GREEN + "✓" + RESET + " " + m)
def fail(m): print("  " + RED   + "✗" + RESET + " " + m)
def info(m): print("  " + CYAN  + "→" + RESET + " " + m)

changes = 0

def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(path, path + "." + ts + ".bak")

def apply(path, patches):
    global changes
    if not os.path.isfile(path):
        fail("Not found: " + path); return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    applied = 0
    modified = content
    for desc, old, new in patches:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc); applied += 1
        elif new in modified:
            ok(desc + "  (already applied)")
        else:
            fail(desc)
    if applied:
        backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        changes += applied


PATCHES = [

    (
        ".card z-index:1 -> z-index:2",
        ".card{\n"
        "  background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);\n"
        "  position:relative;z-index:1;\n"
        "  transition:border-color var(--transition),background var(--transition),box-shadow 0.2s ease;\n"
        "}",
        ".card{\n"
        "  background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);\n"
        "  position:relative;z-index:2;\n"
        "  transition:border-color var(--transition),background var(--transition),box-shadow 0.2s ease;\n"
        "}"
    ),

    (
        ".stat: add z-index:2",
        ".stat{\n"
        "  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);\n"
        "  padding:14px 12px;text-align:center;transition:background var(--transition),border-color var(--transition);\n"
        "}",
        ".stat{\n"
        "  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);\n"
        "  padding:14px 12px;text-align:center;\n"
        "  position:relative;z-index:2;\n"
        "  transition:background var(--transition),border-color var(--transition);\n"
        "}"
    ),

    (
        ".port-panel: solid bg + z-index:2",
        ".port-panel{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;"
        "margin-bottom:8px;width:100%;transition:border-color var(--transition)}",
        ".port-panel{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;"
        "margin-bottom:8px;width:100%;position:relative;z-index:2;"
        "background:var(--bg);transition:border-color var(--transition)}"
    ),

    (
        ".port-hd: explicit bg",
        ".port-hd{display:flex;align-items:center;gap:12px;padding:12px 14px;"
        "cursor:pointer;user-select:none;flex-wrap:wrap;min-height:52px}",
        ".port-hd{display:flex;align-items:center;gap:12px;padding:12px 14px;"
        "cursor:pointer;user-select:none;flex-wrap:wrap;min-height:52px;background:var(--bg)}"
    ),

    (
        ".tabs: z-index:2 + bg",
        ".tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);"
        "margin-bottom:18px;overflow-x:auto}",
        ".tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);"
        "margin-bottom:18px;overflow-x:auto;position:relative;z-index:2;background:var(--bg)}"
    ),

    (
        ".stats grid: z-index:2",
        ".stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));"
        "gap:10px;margin-bottom:20px;width:100%}",
        ".stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));"
        "gap:10px;margin-bottom:20px;width:100%;position:relative;z-index:2}"
    ),

    (
        "result divs: z-index:2",
        "#res,#hv-res,#nk-res,#wp-res,#ly-res,#lg-res,#dr-res,"
        "#sub-res,#dir-res,#bf-res,#disc-res"
        "{width:100%;max-width:100%;overflow-x:auto}",
        "#res,#hv-res,#nk-res,#wp-res,#ly-res,#lg-res,#dr-res,"
        "#sub-res,#dir-res,#bf-res,#disc-res"
        "{width:100%;max-width:100%;overflow-x:auto;position:relative;z-index:2}"
    ),

    (
        ".cve-item: z-index:2",
        ".cve-item{background:var(--bg2);border:1px solid var(--border);"
        "border-radius:var(--radius);padding:12px;margin-bottom:6px}",
        ".cve-item{background:var(--bg2);border:1px solid var(--border);"
        "border-radius:var(--radius);padding:12px;margin-bottom:6px;"
        "position:relative;z-index:2}"
    ),

    (
        ".host-chip: z-index:2",
        ".host-chip{display:inline-flex;align-items:center;gap:8px;"
        "font-family:var(--mono);font-size:12px;background:var(--bg2);"
        "border:1px solid var(--border);border-radius:var(--radius);"
        "padding:6px 12px;margin-bottom:14px}",
        ".host-chip{display:inline-flex;align-items:center;gap:8px;"
        "font-family:var(--mono);font-size:12px;background:var(--bg2);"
        "border:1px solid var(--border);border-radius:var(--radius);"
        "padding:6px 12px;margin-bottom:14px;position:relative;z-index:2}"
    ),

    (
        ".tbl-wrap: z-index:2 + bg",
        ".tbl-wrap{overflow-x:auto;width:100%}",
        ".tbl-wrap{overflow-x:auto;width:100%;position:relative;z-index:2;background:var(--bg)}"
    ),

    (
        ".found badge: z-index:2",
        ".found{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;"
        "background:var(--bg2);border:1px solid var(--border);border-radius:20px;"
        "font-family:var(--mono);font-size:11px;color:var(--text2)}",
        ".found{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;"
        "background:var(--bg2);border:1px solid var(--border);border-radius:20px;"
        "font-family:var(--mono);font-size:11px;color:var(--text2);"
        "position:relative;z-index:2}"
    ),

    (
        ".terminal: z-index:2",
        ".terminal{\n"
        "  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);\n"
        "  padding:12px 14px;max-height:160px;overflow-y:auto;font-family:var(--mono);\n"
        "  font-size:12px;line-height:1.8;display:none;margin:12px 0;\n"
        "}",
        ".terminal{\n"
        "  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);\n"
        "  padding:12px 14px;max-height:160px;overflow-y:auto;font-family:var(--mono);\n"
        "  font-size:12px;line-height:1.8;display:none;margin:12px 0;\n"
        "  position:relative;z-index:2;\n"
        "}"
    ),

    (
        ".err-box: z-index:2",
        ".err-box{\n"
        "  background:rgba(192,57,43,0.06);border:1px solid rgba(192,57,43,0.2);"
        "border-radius:var(--radius);\n"
        "  padding:10px 14px;color:var(--red);font-size:13px;font-family:var(--mono);"
        "display:none;margin:10px 0;\n"
        "}",
        ".err-box{\n"
        "  background:rgba(192,57,43,0.06);border:1px solid rgba(192,57,43,0.2);"
        "border-radius:var(--radius);\n"
        "  padding:10px 14px;color:var(--red);font-size:13px;font-family:var(--mono);"
        "display:none;margin:10px 0;\n"
        "  position:relative;z-index:2;\n"
        "}"
    ),

    (
        ".notice: z-index:2",
        ".notice{\n"
        "  background:var(--bg2);border:1px solid var(--border);"
        "border-left:3px solid var(--yellow);\n"
        "  border-radius:var(--radius);padding:10px 14px;"
        "font-size:12px;color:var(--text2);margin-bottom:16px;\n"
        "}",
        ".notice{\n"
        "  background:var(--bg2);border:1px solid var(--border);"
        "border-left:3px solid var(--yellow);\n"
        "  border-radius:var(--radius);padding:10px 14px;"
        "font-size:12px;color:var(--text2);margin-bottom:16px;\n"
        "  position:relative;z-index:2;\n"
        "}"
    ),

    # page-hd and content already have z-index:1, bump to 2
    (
        ".content: z-index:1 -> z-index:2",
        ".content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden;width:100%;position:relative;z-index:1}",
        ".content{padding:24px 28px 40px;flex:1;min-width:0;overflow-x:hidden;width:100%;position:relative;z-index:2}"
    ),

]


def main():
    print("\n" + BOLD + CYAN + "VulnScan Pro -- Scan Output Visibility Fix" + RESET)
    print("=" * 54)

    F = "api_server.py"
    if not os.path.isfile(F):
        fail("api_server.py not found -- run from ~/vulnscan")
        return

    apply(F, PATCHES)

    # Syntax check
    r = subprocess.run([sys.executable, "-m", "py_compile", F],
                       capture_output=True, text=True)
    if r.returncode == 0:
        ok("Syntax check passed")
    else:
        fail("SYNTAX ERROR -- see below")
        print(r.stderr)

    print("\n" + "=" * 54)
    print(BOLD + "SUMMARY" + RESET)
    print("  Changes : " + GREEN + str(changes) + RESET)
    if changes:
        print("\n  Restart: python3 api_server.py")
        print("\n  " + GREEN + "Fixed:" + RESET)
        print("    All cards, stats, port panels, result divs")
        print("    now have position:relative + z-index:2 + solid bg")
        print("    Canvas stays at z-index:-1 -- always behind UI")
    else:
        print("  Nothing changed.")
    print()

if __name__ == "__main__":
    main()
