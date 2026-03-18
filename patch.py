#!/usr/bin/env python3
"""
VulnScan Pro -- Dull Background Fix
Makes matrix rain text much darker and smaller so it sits
quietly in the background without drawing attention.
Run: python3 patch_bgdull.py
"""
import os, re, shutil
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
    return shutil.copy2(path, path + "." + ts + ".bak")

def main():
    global changes
    print("\n" + BOLD + CYAN + "VulnScan Pro -- Dull Background Fix" + RESET)
    print("=" * 46)

    F = "api_server.py"
    if not os.path.isfile(F):
        fail("api_server.py not found -- run from ~/vulnscan")
        return

    with open(F, "r", encoding="utf-8") as f:
        content = f.read()
    original = content

    # ------------------------------------------------------------------
    #  1. Colours -- very dark/muted on light theme, very dim on dark
    # ------------------------------------------------------------------
    colour_patches = [
        # headRGB light: was [0,80,20] -> near-black grey-green
        (
            "function headRGB()  { return isDark() ? [140,255,140] : [0, 80, 20]; }",
            "function headRGB()  { return isDark() ? [60, 120, 60]  : [40, 40, 40]; }"
        ),
        # trailRGB light: was [0,60,10] -> almost invisible
        (
            "function trailRGB() { return isDark() ? [0, 180, 60]  : [0, 60, 10]; }",
            "function trailRGB() { return isDark() ? [0,  90, 30]  : [30, 30, 30]; }"
        ),
        # Alternate values from bgfix patch
        (
            "function headRGB()  { return isDark() ? [140,255,140] : [0, 80, 20]; }",
            "function headRGB()  { return isDark() ? [60, 120, 60]  : [40, 40, 40]; }"
        ),
    ]
    for old, new in colour_patches:
        if old in content:
            content = content.replace(old, new, 1)
            ok("headRGB / trailRGB: colours made much darker")
            changes += 1
            break

    trail_patches = [
        (
            "function trailRGB() { return isDark() ? [0, 180, 60]  : [0, 60, 10]; }",
            "function trailRGB() { return isDark() ? [0,  90, 30]  : [30, 30, 30]; }"
        ),
        (
            "function trailRGB() { return isDark() ? [0, 180, 60]  : [0, 60, 10]; }",
            "function trailRGB() { return isDark() ? [0,  90, 30]  : [30, 30, 30]; }"
        ),
    ]
    for old, new in trail_patches:
        if old in content:
            content = content.replace(old, new, 1)
            ok("trailRGB: dimmed")
            changes += 1
            break

    # ------------------------------------------------------------------
    #  2. Opacity -- cut base alpha significantly
    # ------------------------------------------------------------------
    alpha_patches = [
        # Current values from bgfix
        (
            "var baseAlpha = isDark() ? 0.45 : 0.28;",
            "var baseAlpha = isDark() ? 0.18 : 0.12;"
        ),
        # Older values
        (
            "var baseAlpha = isDark() ? 0.50 : 0.30;",
            "var baseAlpha = isDark() ? 0.18 : 0.12;"
        ),
        (
            "var baseAlpha = isDark() ? 0.55 : 0.35;",
            "var baseAlpha = isDark() ? 0.18 : 0.12;"
        ),
        (
            "var baseAlpha=isDark()?0.55:0.35;",
            "var baseAlpha=isDark()?0.18:0.12;"
        ),
    ]
    for old, new in alpha_patches:
        if old in content:
            content = content.replace(old, new, 1)
            ok("baseAlpha: " + old.split("?")[1].strip()[:20] + " -> 0.18 / 0.12")
            changes += 1
            break

    # ------------------------------------------------------------------
    #  3. Font size -- smaller chars are less distracting
    # ------------------------------------------------------------------
    font_patches = [
        ("var COL_W = 18, FONT_SZ = 11,", "var COL_W = 20, FONT_SZ = 9,"),
        ("var COL_W=16,FONT_SZ=11,",      "var COL_W=20,FONT_SZ=9,"),
        ("var COL_W = 16, FONT_SZ = 11,", "var COL_W = 20, FONT_SZ = 9,"),
    ]
    for old, new in font_patches:
        if old in content:
            content = content.replace(old, new, 1)
            ok("Font: 11px -> 9px, column spacing widened")
            changes += 1
            break

    # ------------------------------------------------------------------
    #  4. Fade rect -- faster fade = shorter, less visible trails
    # ------------------------------------------------------------------
    fade_patches = [
        (
            "'rgba(10,10,10,0.15)'",
            "'rgba(10,10,10,0.25)'"
        ),
        (
            "'rgba(255,255,255,0.18)'",
            "'rgba(255,255,255,0.30)'"
        ),
    ]
    for old, new in fade_patches:
        if old in content:
            content = content.replace(old, new, 1)
            ok("Fade rect: faster fade (shorter trails)")
            changes += 1

    # ------------------------------------------------------------------
    #  Write back
    # ------------------------------------------------------------------
    if content != original:
        backup(F)
        with open(F, "w", encoding="utf-8") as f:
            f.write(content)
        ok("File saved")
    else:
        fail("No changes matched -- printing relevant lines for diagnosis:")
        for i, line in enumerate(original.splitlines(), 1):
            if any(k in line for k in ["headRGB", "trailRGB", "baseAlpha", "FONT_SZ", "fadeFill"]):
                print("  %4d: %s" % (i, line.rstrip()))

    print("\n" + "=" * 46)
    print(BOLD + "SUMMARY" + RESET)
    print("  Changes : " + GREEN + str(changes) + RESET)
    if changes:
        print("\n  Restart: python3 api_server.py")
        print("\n  " + GREEN + "Result:" + RESET)
        print("    Light theme: near-black chars at 12% opacity")
        print("    Dark theme:  dim green chars at 18% opacity")
        print("    Font 9px, wider columns -- less dense, less distracting")
        print("    Faster fade rect -- trails disappear quicker")
    print()

if __name__ == "__main__":
    main()
