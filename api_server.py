#!/usr/bin/env python3
import json, re, sys, os, subprocess, io
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

from database import save_scan, get_history, get_scan_by_id
from auth import register_auth_routes, get_current_user, audit

register_auth_routes(app)

GRADE_COL = {"A+": "#00ff9d", "A": "#00e5ff", "B": "#ffd60a", "C": "#ff6b35", "D": "#ff6b35", "F": "#ff3366"}


def run_backend(*args, timeout=200):
    cmd = [sys.executable, BACKEND] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Backend process timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": f"Python interpreter not found: {sys.executable}"}

    if r.stderr and r.stderr.strip():
        print(f"[backend stderr] {r.stderr.strip()[:500]}", file=sys.stderr)

    if not r.stdout or not r.stdout.strip():
        err_detail = r.stderr.strip()[:300] if r.stderr else "No output from backend"
        return {"error": f"Backend returned no output. Details: {err_detail}"}

    raw = r.stdout.strip()
    start = raw.find('{')
    end = raw.rfind('}')
    if start == -1 or end == -1:
        return {"error": f"No JSON in backend output: {raw[:300]}"}
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}. Raw: {raw[start:start+200]}"}


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Syne:wght@400;600;700;800&family=Orbitron:wght@400;700;900&family=Space+Grotesk:wght@300;400;500;700&family=Playfair+Display:ital,wght@0,400;0,700;1,400&family=Rajdhani:wght@300;400;600;700&family=Share+Tech+Mono&family=Courier+Prime:ital,wght@0,400;0,700;1,400&family=Exo+2:wght@200;400;700;900&family=Monoton&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;
  --t:#e8e8f0;--m:#5a5a8a;
  --cyan:#00e5ff;--green:#00ff9d;--red:#ff3366;--orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;
  --accent:var(--cyan);--grid-color:rgba(0,229,255,0.025);
  --font-head:'Syne',sans-serif;--font-mono:'JetBrains Mono',monospace;
  --noise-opacity:0.03;--scanline-opacity:0.03;--aurora-opacity:0.15;
  --pattern-opacity:0;--bg-overlay:none;
}

/* ═══════════════════════════════════════
   UNIQUE THEMES — Each has its own personality
   ═══════════════════════════════════════ */

/* CYBERPUNK — default neon-noir */
body.theme-cyberpunk{
  --bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;
  --t:#e8e8f0;--m:#5a5a8a;--cyan:#00e5ff;--green:#00ff9d;--red:#ff3366;
  --orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;--accent:#00e5ff;
  --grid-color:rgba(0,229,255,0.025);--font-head:'Orbitron',sans-serif;
  --font-mono:'JetBrains Mono',monospace;--noise-opacity:0.04;
  --aurora-opacity:0.18;
}

/* GHOST — ultra-minimal monochrome with stark geometry */
body.theme-ghost{
  --bg:#f8f8f5;--s1:#f0f0ec;--s2:#e8e8e4;--b:#d0d0cc;--b2:#b8b8b4;
  --t:#111111;--m:#888884;--cyan:#111111;--green:#333;--red:#cc0000;
  --orange:#cc4400;--yellow:#cc8800;--purple:#440088;--accent:#111111;
  --grid-color:rgba(0,0,0,0.04);--font-head:'Space Grotesk',sans-serif;
  --font-mono:'Courier Prime',monospace;--noise-opacity:0.06;
  --aurora-opacity:0;
}

/* PHANTOM — deep obsidian with electric violet */
body.theme-phantom{
  --bg:#0a0008;--s1:#110011;--s2:#180018;--b:#240024;--b2:#300030;
  --t:#f0d0ff;--m:#7a507a;--cyan:#dd00ff;--green:#aa00ff;--red:#ff0066;
  --orange:#cc00cc;--yellow:#ff44ff;--purple:#9900cc;--accent:#dd00ff;
  --grid-color:rgba(221,0,255,0.02);--font-head:'Rajdhani',sans-serif;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.05;
  --aurora-opacity:0.25;
}

/* SOLARIS — brutalist industrial with amber warning */
body.theme-solaris{
  --bg:#100800;--s1:#180d00;--s2:#201200;--b:#301a00;--b2:#402200;
  --t:#fff8e8;--m:#806040;--cyan:#ffaa00;--green:#ffcc00;--red:#ff4400;
  --orange:#ff7700;--yellow:#ffee00;--purple:#cc8800;--accent:#ffaa00;
  --grid-color:rgba(255,170,0,0.025);--font-head:'Exo 2',sans-serif;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.07;
  --aurora-opacity:0.12;
}

/* MATRIX — terminal green on black, retro hacker */
body.theme-matrix{
  --bg:#000300;--s1:#000500;--s2:#000800;--b:#001200;--b2:#001a00;
  --t:#00ff41;--m:#006618;--cyan:#00ff41;--green:#39ff14;--red:#ff4400;
  --orange:#ffaa00;--yellow:#ccff00;--purple:#00ff99;--accent:#00ff41;
  --grid-color:rgba(0,255,65,0.03);--font-head:'Share Tech Mono',monospace;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.04;
  --aurora-opacity:0.08;
}

/* LUXE — editorial dark luxury with gold */
body.theme-luxe{
  --bg:#08060a;--s1:#0e0b12;--s2:#141018;--b:#1e1828;--b2:#282035;
  --t:#f5ede0;--m:#7a6860;--cyan:#c8a96e;--green:#b8d4a8;--red:#cc4444;
  --orange:#d4884c;--yellow:#e8c870;--purple:#9c7fc0;--accent:#c8a96e;
  --grid-color:rgba(200,169,110,0.02);--font-head:'Playfair Display',serif;
  --font-mono:'Courier Prime',monospace;--noise-opacity:0.05;
  --aurora-opacity:0.1;
}

/* ARCTIC — ice and cold steel blue */
body.theme-arctic{
  --bg:#f4f8ff;--s1:#eaf0fb;--s2:#dde8f8;--b:#c8d8f0;--b2:#b0c4e8;
  --t:#1a2a40;--m:#6080a0;--cyan:#0066cc;--green:#00aa55;--red:#cc2244;
  --orange:#dd6600;--yellow:#cc8800;--purple:#7733cc;--accent:#0066cc;
  --grid-color:rgba(0,102,204,0.04);--font-head:'Space Grotesk',sans-serif;
  --font-mono:'JetBrains Mono',monospace;--noise-opacity:0.02;
  --aurora-opacity:0.12;
}

/* BLOOD — crimson noir horror */
body.theme-blood{
  --bg:#080000;--s1:#100000;--s2:#180000;--b:#280000;--b2:#360000;
  --t:#ffd0d0;--m:#804040;--cyan:#ff2020;--green:#ff6040;--red:#ff0000;
  --orange:#ff4000;--yellow:#ff8020;--purple:#cc2060;--accent:#ff2020;
  --grid-color:rgba(255,32,32,0.025);--font-head:'Orbitron',sans-serif;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.06;
  --aurora-opacity:0.2;
}

/* VAPORWAVE — 80s retro synthwave pastel dream */
body.theme-vaporwave{
  --bg:#0d001a;--s1:#130022;--s2:#19002e;--b:#26004a;--b2:#33006a;
  --t:#ffccff;--m:#aa60aa;--cyan:#ff88ff;--green:#44ffcc;--red:#ff4488;
  --orange:#ff88aa;--yellow:#ffccff;--purple:#cc44ff;--accent:#ff88ff;
  --grid-color:rgba(255,136,255,0.03);--font-head:'Monoton',cursive;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.03;
  --aurora-opacity:0.3;
}

/* TERMINAL — classic CRT amber phosphor */
body.theme-terminal{
  --bg:#0a0800;--s1:#100d00;--s2:#181200;--b:#281e00;--b2:#382800;
  --t:#ffcc44;--m:#806622;--cyan:#ffcc44;--green:#ffaa22;--red:#ff4422;
  --orange:#ff8844;--yellow:#ffee66;--purple:#cc8822;--accent:#ffcc44;
  --grid-color:rgba(255,204,68,0.025);--font-head:'Share Tech Mono',monospace;
  --font-mono:'Share Tech Mono',monospace;--noise-opacity:0.08;
  --aurora-opacity:0;
}

html{scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--t);
  font-family:var(--font-head);
  min-height:100vh;overflow-x:hidden;
  transition:background 0.5s,color 0.4s;
}

/* ═══ LAYERED BACKGROUND SYSTEM ═══ */

/* Layer 0: Base animated grid */
body::before{
  content:'';position:fixed;inset:0;
  background-image:linear-gradient(var(--grid-color) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid-color) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0;
  animation:gridPulse 8s ease-in-out infinite;
}
@keyframes gridPulse{0%,100%{opacity:0.5}50%{opacity:1}}

/* Layer 1: Scanlines */
body::after{
  content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
    rgba(0,0,0,var(--scanline-opacity)) 2px,rgba(0,0,0,var(--scanline-opacity)) 4px);
  pointer-events:none;z-index:1;
  animation:scanlineScroll 12s linear infinite;
}
@keyframes scanlineScroll{0%{transform:translateY(0)}100%{transform:translateY(40px)}}

/* ── Canvases (particles, aurora, matrix) ── */
#bg-particles{position:fixed;inset:0;pointer-events:none;z-index:2;opacity:0.6}
#bg-aurora{position:fixed;inset:0;pointer-events:none;z-index:1;opacity:var(--aurora-opacity)}
#bg-matrix-rain{position:fixed;inset:0;pointer-events:none;z-index:2;opacity:0;transition:opacity 1s}
body.theme-matrix #bg-matrix-rain{opacity:0.18}
body.theme-terminal #bg-matrix-rain{opacity:0.1}

/* ── Noise texture overlay ── */
#bg-noise{
  position:fixed;inset:0;pointer-events:none;z-index:3;
  opacity:var(--noise-opacity);
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size:256px 256px;
  mix-blend-mode:overlay;
  animation:noiseShift 0.08s steps(1) infinite;
}
@keyframes noiseShift{
  0%{background-position:0 0}10%{background-position:-40px 20px}
  20%{background-position:20px -60px}30%{background-position:-80px 40px}
  40%{background-position:30px 80px}50%{background-position:-20px -40px}
  60%{background-position:60px 20px}70%{background-position:-60px -80px}
  80%{background-position:40px 60px}90%{background-position:-30px 30px}100%{background-position:0 0}
}

/* ── Geometric floating shapes ── */
#bg-shapes{position:fixed;inset:0;pointer-events:none;z-index:1;overflow:hidden}
.bg-shape{
  position:absolute;border:1px solid var(--accent);
  opacity:0.04;pointer-events:none;
}
.bg-shape.circle{border-radius:50%}
.bg-shape.s1{width:600px;height:600px;top:-200px;left:-200px;animation:shapeFloat1 25s ease-in-out infinite}
.bg-shape.s2{width:400px;height:400px;top:30%;right:-150px;animation:shapeFloat2 18s ease-in-out infinite;border-radius:30% 70% 70% 30%/30% 30% 70% 70%}
.bg-shape.s3{width:300px;height:300px;bottom:10%;left:20%;animation:shapeFloat3 22s ease-in-out infinite}
.bg-shape.s4{width:200px;height:200px;top:20%;left:40%;animation:shapeFloat4 30s linear infinite;border-radius:50%}
.bg-shape.s5{width:150px;height:150px;bottom:20%;right:15%;animation:shapeFloat5 16s ease-in-out infinite}
@keyframes shapeFloat1{0%,100%{transform:rotate(0deg) scale(1)}33%{transform:rotate(120deg) scale(1.1)}66%{transform:rotate(240deg) scale(0.9)}}
@keyframes shapeFloat2{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-60px) rotate(180deg)}}
@keyframes shapeFloat3{0%,100%{transform:rotate(0deg) translateX(0)}50%{transform:rotate(90deg) translateX(30px)}}
@keyframes shapeFloat4{0%{transform:rotate(0deg) scale(1)}100%{transform:rotate(360deg) scale(1.05)}}
@keyframes shapeFloat5{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-40px) scale(1.2)}}

/* ── Pulse rings from center ── */
.pulse-ring{
  position:fixed;border-radius:50%;border:1px solid var(--accent);
  pointer-events:none;z-index:1;
  left:50%;top:50%;transform:translate(-50%,-50%);
  animation:pulseRingExpand 6s ease-out infinite;
  opacity:0;
}
.pulse-ring:nth-child(1){animation-delay:0s}
.pulse-ring:nth-child(2){animation-delay:2s}
.pulse-ring:nth-child(3){animation-delay:4s}
@keyframes pulseRingExpand{
  0%{width:0;height:0;opacity:0.08}
  100%{width:200vmax;height:200vmax;opacity:0}
}

/* ── Vaporwave grid floor (vaporwave theme only) ── */
#bg-vaporwave{
  position:fixed;bottom:0;left:0;right:0;height:60vh;
  pointer-events:none;z-index:1;opacity:0;transition:opacity 0.5s;
  perspective:400px;
  transform-style:preserve-3d;
}
body.theme-vaporwave #bg-vaporwave{opacity:0.15}
.vw-grid{
  position:absolute;inset:0;
  background-image:
    linear-gradient(to bottom,transparent 0%,rgba(255,136,255,0.3) 100%),
    linear-gradient(90deg,rgba(255,136,255,0.4) 1px,transparent 1px),
    linear-gradient(rgba(255,136,255,0.2) 1px,transparent 1px);
  background-size:100% 100%,60px 60px,60px 60px;
  transform:rotateX(60deg);
  animation:vwGridScroll 4s linear infinite;
}
@keyframes vwGridScroll{0%{background-position:0 0,0 0,0 0}100%{background-position:0 0,0 0,0 -60px}}

/* ══ THEME DROPDOWN SYSTEM ══ */
.theme-dropdown-wrap{position:relative;width:100%}
.theme-dropdown-btn{
  width:100%;padding:12px 16px;
  background:var(--s2);border:1px solid var(--b2);border-radius:10px;
  color:var(--t);cursor:pointer;display:flex;align-items:center;justify-content:space-between;
  font-family:var(--font-mono);font-size:12px;letter-spacing:1px;
  transition:all 0.2s;
}
.theme-dropdown-btn:hover{border-color:var(--accent);box-shadow:0 0 12px rgba(0,0,0,0.3)}
.theme-dropdown-btn .tdb-left{display:flex;align-items:center;gap:10px}
.theme-preview-dot{
  width:28px;height:28px;border-radius:6px;flex-shrink:0;
  background:var(--accent);position:relative;overflow:hidden;
  box-shadow:0 0 8px var(--accent);
}
.theme-preview-dot::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,0.3),transparent);
}
.tdb-arrow{transition:transform 0.3s;font-size:10px;color:var(--m)}
.theme-dropdown-btn.open .tdb-arrow{transform:rotate(180deg)}

.theme-dropdown-panel{
  position:absolute;top:calc(100% + 8px);left:0;right:0;
  background:var(--s1);border:1px solid var(--b2);border-radius:12px;
  z-index:500;overflow:hidden;
  max-height:0;opacity:0;pointer-events:none;
  transition:max-height 0.4s cubic-bezier(0.34,1.1,0.64,1),opacity 0.25s ease;
  box-shadow:0 20px 60px rgba(0,0,0,0.6);
}
.theme-dropdown-panel.open{max-height:600px;opacity:1;pointer-events:all}

.theme-option{
  display:flex;align-items:center;gap:14px;padding:14px 16px;
  cursor:pointer;transition:all 0.18s;border-bottom:1px solid var(--b);
  position:relative;overflow:hidden;
}
.theme-option:last-child{border-bottom:none}
.theme-option:hover{background:rgba(255,255,255,0.03)}
.theme-option.active{background:rgba(255,255,255,0.05)}
.theme-option::before{
  content:'';position:absolute;left:0;top:0;bottom:0;
  width:3px;background:var(--opt-accent,var(--accent));
  opacity:0;transition:opacity 0.2s;
}
.theme-option.active::before,.theme-option:hover::before{opacity:1}

.theme-opt-preview{
  width:44px;height:44px;border-radius:8px;flex-shrink:0;
  overflow:hidden;position:relative;
}
.theme-opt-preview .pop{
  position:absolute;inset:0;display:flex;flex-direction:column;
}
.theme-opt-preview .pop-top{height:50%;display:flex;gap:2px;padding:3px}
.theme-opt-preview .pop-bar{flex:1;border-radius:2px}
.theme-opt-preview .pop-bottom{flex:1;padding:0 3px 3px;display:flex;gap:2px;align-items:flex-end}
.theme-opt-preview .pop-line{height:4px;flex:1;border-radius:2px;opacity:0.7}

.theme-opt-info{flex:1;min-width:0}
.theme-opt-name{
  font-family:var(--font-head);font-size:13px;font-weight:700;
  color:var(--t);margin-bottom:3px;
}
.theme-opt-desc{
  font-family:var(--font-mono);font-size:10px;color:var(--m);
  line-height:1.5;letter-spacing:0.5px;
}
.theme-opt-tag{
  font-family:var(--font-mono);font-size:9px;letter-spacing:2px;
  padding:2px 7px;border-radius:4px;border:1px solid;
  opacity:0.7;white-space:nowrap;flex-shrink:0;
}
.theme-opt-check{
  width:20px;height:20px;border-radius:50%;
  border:2px solid var(--b2);display:flex;align-items:center;justify-content:center;
  flex-shrink:0;transition:all 0.2s;font-size:10px;
}
.theme-option.active .theme-opt-check{
  background:var(--opt-accent,var(--accent));
  border-color:var(--opt-accent,var(--accent));color:#000;
}

/* ══ HEADER ══ */
header{
  position:sticky;top:0;z-index:100;
  background:rgba(4,4,10,0.88);backdrop-filter:blur(24px);
  border-bottom:1px solid var(--b);
  padding:0 24px;display:flex;align-items:center;
  justify-content:space-between;height:58px;flex-wrap:wrap;gap:8px;
  transition:box-shadow 0.3s;
}
header.scrolled{box-shadow:0 2px 30px rgba(0,0,0,0.6),0 0 60px rgba(0,0,0,0.2)}
.brand{display:flex;align-items:center;gap:10px}
.brand-icon{
  width:32px;height:32px;
  background:linear-gradient(135deg,var(--red),var(--orange));
  border-radius:7px;display:flex;align-items:center;justify-content:center;
  font-size:17px;box-shadow:0 0 18px rgba(255,51,102,0.35);
}
.brand-name{
  font-size:17px;font-weight:800;
  font-family:var(--font-head);
  background:linear-gradient(90deg,var(--cyan),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-size:200% auto;animation:titleShimmer 4s ease infinite;
}
@keyframes titleShimmer{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.brand-tag{font-size:8px;color:var(--m);letter-spacing:3px;font-family:var(--font-mono)}
nav{display:flex;gap:3px;flex-wrap:wrap;align-items:center}
.nb{
  padding:6px 13px;border:none;background:transparent;
  color:var(--m);cursor:pointer;font-family:var(--font-mono);
  font-size:12px;letter-spacing:1px;border-radius:6px;
  transition:all 0.2s;white-space:nowrap;
}
.nb:hover,.nb.active{background:var(--b);color:var(--cyan)}
.nav-dropdown{position:relative;display:inline-block}
.nav-dropdown:hover .nav-dropdown-menu{display:block;animation:ddFade 0.15s ease}
.nav-dropdown:hover .nav-dropdown-btn{background:var(--b);color:var(--cyan)}
.nav-dropdown:hover .nav-dropdown-btn .arrow{transform:rotate(180deg)}
@keyframes ddFade{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.nav-dropdown-btn{
  padding:6px 13px;border:none;background:transparent;color:var(--m);
  cursor:pointer;font-family:var(--font-mono);font-size:12px;letter-spacing:1px;
  border-radius:6px;transition:all 0.2s;white-space:nowrap;
  display:flex;align-items:center;gap:5px;
}
.nav-dropdown-btn:hover,.nav-dropdown-btn.active{background:var(--b);color:var(--cyan)}
.nav-dropdown-btn .arrow{font-size:8px;transition:transform 0.2s}
.nav-dropdown-menu{
  position:absolute;top:calc(100% + 2px);left:0;
  background:var(--s1);border:1px solid var(--b2);border-radius:10px;
  min-width:220px;z-index:100;padding:6px;display:none;
  box-shadow:0 8px 32px rgba(0,0,0,0.6);
}
.nav-dropdown-section{font-size:9px;color:var(--m);letter-spacing:2px;font-family:var(--font-mono);padding:6px 10px 4px;margin-top:4px}
.nav-dropdown-section:first-child{margin-top:0}
.nav-dropdown-item{
  display:flex;align-items:center;gap:9px;padding:8px 12px;border:none;
  background:transparent;color:var(--t);cursor:pointer;font-family:var(--font-mono);
  font-size:11px;border-radius:7px;width:100%;text-align:left;transition:all 0.2s;
}
.nav-dropdown-item:hover{background:var(--b);color:var(--cyan)}
.nav-dropdown-item.active{background:var(--b);color:var(--cyan)}
.nav-dropdown-item .item-icon{width:22px;text-align:center;font-size:13px}
.nav-dropdown-item .item-label{flex:1}
.nav-dropdown-item .item-badge{font-size:8px;background:var(--cyan);color:var(--bg);padding:2px 5px;border-radius:4px;font-weight:700}
.ver-badge{
  font-size:9px;font-family:var(--font-mono);
  background:rgba(0,229,255,0.08);color:var(--cyan);
  border:1px solid rgba(0,229,255,0.2);border-radius:4px;
  padding:2px 7px;letter-spacing:1px;cursor:default;
}
.brand-link{display:flex;align-items:center;gap:10px;cursor:pointer;text-decoration:none}
.user-chip{
  display:flex;align-items:center;gap:8px;background:var(--s2);
  border:1px solid var(--b2);border-radius:20px;
  padding:4px 12px 4px 8px;cursor:pointer;transition:all 0.2s;
}
.user-chip:hover{border-color:var(--cyan)}
.user-avatar{
  width:24px;height:24px;border-radius:50%;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  display:flex;align-items:center;justify-content:center;
  font-size:11px;font-weight:700;color:var(--bg);
}
.user-name{font-size:12px;font-family:var(--font-mono);color:var(--t)}
.user-role{font-size:9px;color:var(--m);font-family:var(--font-mono)}

/* ══ AUTH OVERLAY ══ */
.overlay{
  position:fixed;inset:0;background:rgba(4,4,10,0.95);
  z-index:200;display:flex;align-items:center;justify-content:center;
  backdrop-filter:blur(10px);
}
.auth-box{
  background:var(--s1);border:1px solid var(--b2);border-radius:16px;
  padding:36px;width:100%;max-width:420px;position:relative;
}
.auth-box h2{
  font-size:22px;font-weight:800;margin-bottom:4px;
  font-family:var(--font-head);
  background:linear-gradient(90deg,var(--cyan),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.auth-box p{color:var(--m);font-size:12px;margin-bottom:24px;font-family:var(--font-mono)}
.auth-tabs{display:flex;gap:0;margin-bottom:24px;background:var(--s2);border-radius:8px;padding:3px}
.auth-tab{
  flex:1;padding:8px;border:none;background:transparent;color:var(--m);
  cursor:pointer;font-family:var(--font-mono);font-size:11px;border-radius:6px;transition:all 0.2s;
}
.auth-tab.active{background:var(--b2);color:var(--cyan)}
.fg{margin-bottom:14px}
.fg label{display:block;font-size:10px;color:var(--m);letter-spacing:2px;font-family:var(--font-mono);margin-bottom:5px}
.inp{
  width:100%;background:var(--s2);border:1px solid var(--b2);border-radius:9px;
  color:var(--t);padding:11px 14px;font-size:14px;font-family:var(--font-mono);
  outline:none;transition:border 0.2s;
}
.inp:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.07)}
.inp::placeholder{color:#252540}
.btn{
  padding:12px 22px;border:none;border-radius:9px;cursor:pointer;
  font-family:var(--font-mono);font-weight:700;font-size:12px;letter-spacing:1px;
  transition:all 0.2s;white-space:nowrap;
}
.btn-p{
  background:linear-gradient(135deg,var(--red),#b0102a);color:#fff;
  box-shadow:0 4px 18px rgba(255,51,102,0.28);width:100%;
}
.btn-p:hover{transform:translateY(-1px)}
.btn-p:disabled{background:var(--b);color:var(--m);cursor:not-allowed;transform:none;box-shadow:none}
.btn-g{background:transparent;color:var(--m);border:1px solid var(--b2);padding:12px 18px}
.btn-g:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-sm{padding:6px 12px;font-size:10px}
.btn-full{width:100%}
.auth-msg{padding:10px 14px;border-radius:7px;font-size:12px;font-family:var(--font-mono);margin-bottom:14px;display:none}
.auth-msg.ok{background:rgba(0,255,157,0.08);border:1px solid rgba(0,255,157,0.2);color:var(--green)}
.auth-msg.err{background:rgba(255,51,102,0.08);border:1px solid rgba(255,51,102,0.2);color:var(--red)}
.auth-link{background:none;border:none;color:var(--cyan);cursor:pointer;font-size:11px;font-family:var(--font-mono);text-decoration:underline;padding:0}

/* ══ LAYOUT ══ */
.container{max-width:1100px;margin:0 auto;padding:24px 16px;position:relative;z-index:10}
.page{display:none}.page.active{display:block;animation:pageIn 0.3s ease}
@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.card{background:var(--s1);border:1px solid var(--b);border-radius:12px;padding:20px;margin-bottom:16px;transition:border-color 0.2s,box-shadow 0.2s}
.card:hover{box-shadow:0 0 0 1px var(--accent),0 4px 24px rgba(0,0,0,0.4)}
.ctitle{font-size:11px;color:var(--m);letter-spacing:3px;font-family:var(--font-mono);margin-bottom:12px;font-weight:600}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}

/* ══ HOME HERO ══ */
.home-hero{text-align:center;padding:48px 0 36px;position:relative}
.home-hero h1{
  font-size:48px;font-weight:800;
  font-family:var(--font-head);
  background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin-bottom:10px;line-height:1.1;
  background-size:200% auto;animation:titleShimmer 4s ease infinite;
  text-shadow:none;
  filter:drop-shadow(0 0 30px rgba(0,229,255,0.15));
}
/* Glitch on brand */
.home-hero h1::before,.home-hero h1::after{
  content:attr(data-text);position:absolute;left:50%;transform:translateX(-50%);
  background:inherit;-webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}
.home-hero h1::before{animation:glitch1 7s infinite;clip-path:polygon(0 0,100% 0,100% 45%,0 45%);top:0}
.home-hero h1::after{animation:glitch2 7s infinite;clip-path:polygon(0 55%,100% 55%,100% 100%,0 100%);top:0}
@keyframes glitch1{0%,93%,100%{transform:translateX(-50%);opacity:0}94%{transform:translate(calc(-50% - 3px),1px);opacity:0.7}96%{transform:translate(calc(-50% + 2px),-1px);opacity:0.5}97%{transform:translateX(-50%);opacity:0}}
@keyframes glitch2{0%,91%,100%{transform:translateX(-50%);opacity:0}92%{transform:translate(calc(-50% + 3px),2px);opacity:0.6}93%{transform:translate(calc(-50% - 1px),0);opacity:0.4}94%{transform:translateX(-50%);opacity:0}}

.home-hero p{color:var(--m);font-size:14px;font-family:var(--font-mono);max-width:540px;margin:0 auto 28px}

.home-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:40px}
.home-stat{
  background:var(--s1);border:1px solid var(--b);border-radius:12px;
  padding:20px;text-align:center;transition:all 0.25s cubic-bezier(0.34,1.56,0.64,1);
  position:relative;overflow:hidden;
}
.home-stat::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,var(--accent),transparent);
  opacity:0;transition:opacity 0.3s;
}
.home-stat:hover{border-color:var(--cyan);transform:translateY(-4px);box-shadow:0 8px 32px rgba(0,0,0,0.4),0 0 0 1px var(--accent)}
.home-stat:hover::before{opacity:0.04}
.home-stat-val{
  font-size:32px;font-weight:800;font-family:var(--font-mono);
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.home-stat-lbl{color:var(--m);font-size:10px;letter-spacing:2px;margin-top:4px;font-family:var(--font-mono)}

.home-cat{margin-bottom:36px}
.home-cat-title{font-size:11px;color:var(--m);letter-spacing:3px;font-family:var(--font-mono);margin-bottom:14px;font-weight:700;display:flex;align-items:center;gap:10px}
.home-cat-title::after{content:'';flex:1;height:1px;background:var(--b)}
.home-tools-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.home-tool-card{
  background:var(--s1);border:1px solid var(--b);border-radius:12px;
  padding:18px;cursor:pointer;transition:all 0.25s cubic-bezier(0.34,1.56,0.64,1);
  position:relative;overflow:hidden;
  animation:cardIn 0.4s ease both;
}
.home-tool-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,var(--tool-c,var(--cyan)),transparent);opacity:0;transition:opacity 0.3s;pointer-events:none}
.home-tool-card:hover{border-color:var(--tool-c,var(--cyan));transform:translateY(-4px) scale(1.01);box-shadow:0 8px 24px rgba(0,0,0,0.4)}
.home-tool-card:hover::before{opacity:0.05}
.home-tool-icon{font-size:28px;margin-bottom:10px;display:inline-block;transition:transform 0.3s}
.home-tool-card:hover .home-tool-icon{transform:scale(1.2) rotate(-5deg)}
.home-tool-name{font-size:15px;font-weight:700;margin-bottom:4px;color:var(--t);font-family:var(--font-head)}
.home-tool-desc{font-size:11px;color:var(--m);font-family:var(--font-mono);line-height:1.6}
.home-tool-tags{display:flex;gap:5px;margin-top:10px;flex-wrap:wrap}
.home-tool-tag{font-size:9px;font-family:var(--font-mono);padding:2px 7px;border-radius:3px;font-weight:700}
.home-quick{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:40px}
.home-quick-btn{
  padding:10px 20px;border:1px solid var(--b2);border-radius:8px;
  background:transparent;color:var(--t);cursor:pointer;font-family:var(--font-mono);
  font-size:12px;transition:all 0.2s;display:flex;align-items:center;gap:7px;
  position:relative;overflow:hidden;
}
.home-quick-btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 40%,rgba(255,255,255,0.06) 50%,transparent 60%);transform:translateX(-100%);transition:transform 0.5s}
.home-quick-btn:hover::after{transform:translateX(100%)}
.home-quick-btn:hover{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.05)}

@keyframes cardIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.home-tool-card:nth-child(1){animation-delay:0.05s}.home-tool-card:nth-child(2){animation-delay:0.1s}
.home-tool-card:nth-child(3){animation-delay:0.15s}.home-tool-card:nth-child(4){animation-delay:0.2s}
.home-tool-card:nth-child(5){animation-delay:0.25s}.home-tool-card:nth-child(6){animation-delay:0.3s}
@keyframes numIn{from{opacity:0;transform:scale(0.7)}to{opacity:1;transform:scale(1)}}
.home-stat-val.loaded{animation:numIn 0.5s cubic-bezier(0.34,1.56,0.64,1)}

/* ══ SCAN PAGE ══ */
.hero{text-align:center;padding:32px 0 24px}
.hero h2{font-size:28px;font-weight:800;font-family:var(--font-head);background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.hero p{color:var(--m);font-size:13px;font-family:var(--font-mono)}
.scan-inp{flex:1;min-width:200px;background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--cyan);padding:12px 16px;font-size:14px;font-family:var(--font-mono);outline:none;transition:border 0.2s}
.scan-inp:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.07)}
.scan-inp::placeholder{color:#252540}
.mods{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px;justify-content:center}
.mt{padding:5px 13px;border:1px solid var(--b2);border-radius:18px;cursor:pointer;font-size:11px;font-family:var(--font-mono);color:var(--m);background:transparent;transition:all 0.2s}
.mt.on{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.07)}
#term{background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;margin-bottom:16px;max-height:160px;overflow-y:auto;display:none;font-family:var(--font-mono);font-size:13px}
.tl{line-height:1.9;color:#4a4a7a}
.ti .p{color:var(--cyan)}.ts .p{color:var(--green)}.tw .p{color:var(--yellow)}.te .p{color:var(--red)}
#prog{height:2px;background:var(--b);border-radius:1px;margin-bottom:16px;display:none;overflow:hidden}
#pb{height:100%;width:0;background:linear-gradient(90deg,var(--red),var(--orange),var(--yellow));transition:width 0.3s}
#err{background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;margin-bottom:16px;display:none;font-family:var(--font-mono)}
#res{display:none}

/* ══ RESULTS ══ */
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}
.sc{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:14px;text-align:center}
.sv{font-size:28px;font-weight:800;font-family:var(--font-mono);line-height:1}
.sl{color:var(--m);font-size:10px;letter-spacing:2px;margin-top:5px;font-family:var(--font-mono)}
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--b);flex-wrap:wrap}
.tab{padding:9px 16px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:var(--font-mono);font-size:11px;letter-spacing:1px;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.2s}
.tab:hover{color:var(--t)}.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tc{display:none}.tc.active{display:block}
.pc{border-radius:9px;background:rgba(255,255,255,0.015);margin-bottom:9px;overflow:hidden}
.ph{padding:13px 16px;cursor:pointer;display:flex;align-items:center;gap:12px;flex-wrap:wrap;user-select:none}
.pn{padding:6px 12px;border-radius:7px;font-family:var(--font-mono);font-weight:800;font-size:15px;min-width:66px;text-align:center}
.pi{flex:1;min-width:0}.pname{font-weight:700;font-size:14px}.psub{color:var(--m);font-size:12px;margin-top:2px;font-family:var(--font-mono)}
.pm{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bdg{border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:1px;font-family:var(--font-mono);border:1px solid transparent}
.chev{color:var(--m);font-size:10px;transition:transform 0.25s;flex-shrink:0}
.pb2{padding:0 16px 16px;border-top:1px solid var(--b);display:none}.pb2.open{display:block}
.st{color:var(--m);font-size:11px;letter-spacing:3px;font-family:var(--font-mono);margin:14px 0 7px}
.ci{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px;margin-bottom:6px}
.ct{display:flex;align-items:center;gap:7px;margin-bottom:6px;flex-wrap:wrap}
.cid{color:var(--cyan);font-family:var(--font-mono);font-weight:700;font-size:12px;text-decoration:none}.cid:hover{text-decoration:underline}
.cdate{color:var(--m);font-size:10px;margin-left:auto;font-family:var(--font-mono)}
.cdesc{color:#8e8e93;font-size:13px;line-height:1.7}
.ml{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.mi{display:flex;gap:9px;padding:5px 0;border-bottom:1px solid var(--b);font-size:13px;line-height:1.6;color:#c0c0d0}.mi:last-child{border-bottom:none}
.ma{color:var(--green);font-family:var(--font-mono);flex-shrink:0}
.ssl-card{background:var(--s2);border-radius:9px;padding:16px;margin-bottom:11px;border:1px solid var(--b2)}
.gc2{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900;font-family:var(--font-mono);flex-shrink:0}
.ssl-hdr{display:flex;align-items:center;gap:16px;margin-bottom:12px}
.iss-item{display:flex;gap:9px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--b);font-size:13px}.iss-item:last-child{border-bottom:none}
.dns-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:9px;margin-bottom:12px}
.dr{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.dtype{font-family:var(--font-mono);font-size:11px;color:var(--cyan);letter-spacing:2px;margin-bottom:5px}
.dval{font-size:12px;color:#8e8e93;line-height:1.7;font-family:var(--font-mono);word-break:break-all}
.sub-item{background:var(--s2);border:1px solid var(--b2);border-radius:5px;padding:7px 11px;font-family:var(--font-mono);font-size:12px;display:flex;justify-content:space-between;margin-bottom:4px}
.hdr-grade{font-size:48px;font-weight:900;font-family:var(--font-mono);line-height:1}
.hl{background:var(--s2);border-radius:7px;overflow:hidden;border:1px solid var(--b2)}
.hi{display:flex;justify-content:space-between;align-items:center;padding:7px 13px;border-bottom:1px solid var(--b);font-size:12px;font-family:var(--font-mono);flex-wrap:wrap;gap:6px}.hi:last-child{border-bottom:none}
.hk{color:var(--m);min-width:180px;flex-shrink:0}.hv{color:var(--t);word-break:break-all;text-align:right;max-width:380px}
.hg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px}
.ht{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:13px;cursor:pointer;transition:all 0.2s}.ht:hover{border-color:var(--cyan)}
.hip{font-family:var(--font-mono);font-size:15px;font-weight:700;color:var(--cyan)}
.tbl{width:100%;border-collapse:collapse;font-size:13px;font-family:var(--font-mono)}
.tbl th{color:var(--m);font-size:10px;letter-spacing:2px;padding:9px 10px;text-align:left;border-bottom:1px solid var(--b)}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--b);color:var(--t);vertical-align:middle;word-break:break-word}
.tbl tr:hover td{background:rgba(255,255,255,0.015)}
.lbtn{background:transparent;border:1px solid var(--b2);color:var(--cyan);padding:4px 9px;border-radius:4px;cursor:pointer;font-family:var(--font-mono);font-size:10px}.lbtn:hover{background:rgba(0,229,255,0.07)}
.lbtn.red{color:var(--red);border-color:rgba(255,51,102,0.3)}.lbtn.red:hover{background:rgba(255,51,102,0.07)}
.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:9px;font-size:11px;font-family:var(--font-mono);margin-bottom:6px}
.bl{color:var(--m);width:75px;text-align:right;flex-shrink:0;font-size:10px}.bt{flex:1;background:var(--b);border-radius:2px;height:7px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width 1s ease}.bv{color:var(--t);width:25px;flex-shrink:0}
.res-tbl{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-mono);margin-top:8px}
.res-tbl th{color:var(--m);font-size:10px;letter-spacing:2px;padding:8px 10px;text-align:left;border-bottom:1px solid var(--b);background:var(--s2)}
.res-tbl td{padding:7px 10px;border-bottom:1px solid var(--b);vertical-align:middle;word-break:break-all}
.res-tbl tr:hover td{background:rgba(255,255,255,0.015)}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;font-family:var(--font-mono);border:1px solid transparent}
.bf-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
textarea.scan-inp{resize:vertical;min-height:80px;font-size:13px}
.sel{background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--t);padding:10px 12px;font-size:13px;font-family:var(--font-mono);outline:none;width:100%}.sel:focus{border-color:var(--cyan)}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.admin-badge{background:rgba(255,214,10,0.1);color:var(--yellow);border:1px solid rgba(255,214,10,0.2);border-radius:4px;padding:2px 8px;font-size:10px;font-family:var(--font-mono)}
.user-badge{background:rgba(0,229,255,0.08);color:var(--cyan);border:1px solid rgba(0,229,255,0.2);border-radius:4px;padding:2px 8px;font-size:10px;font-family:var(--font-mono)}
.notice{background:rgba(255,214,10,0.06);border:1px solid rgba(255,214,10,0.2);border-radius:8px;padding:10px 14px;color:var(--yellow);font-size:12px;font-family:var(--font-mono);margin-bottom:14px}
.found-badge{background:rgba(0,255,157,0.1);color:var(--green);border:1px solid rgba(0,255,157,0.25);border-radius:5px;padding:3px 9px;font-size:11px;font-weight:700;font-family:var(--font-mono)}
.spin{display:inline-block;width:11px;height:11px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
.pulse-dot{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block;animation:pulseDot 2s ease infinite;box-shadow:0 0 0 0 var(--green)}
@keyframes pulseDot{0%{box-shadow:0 0 0 0 rgba(0,255,157,0.6)}70%{box-shadow:0 0 0 8px rgba(0,255,157,0)}100%{box-shadow:0 0 0 0 rgba(0,255,157,0)}}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
@media(max-width:600px){.bf-grid{grid-template-columns:1fr}.hero h2{font-size:22px}header{height:auto;padding:10px 16px}}
</style>
</head>
<body>

<!-- ═══ BACKGROUND LAYERS ═══ -->
<canvas id="bg-aurora"></canvas>
<canvas id="bg-particles"></canvas>
<canvas id="bg-matrix-rain"></canvas>
<div id="bg-noise"></div>
<div id="bg-shapes">
  <div class="bg-shape circle s1"></div>
  <div class="bg-shape s2"></div>
  <div class="bg-shape s3"></div>
  <div class="bg-shape circle s4"></div>
  <div class="bg-shape s5"></div>
</div>
<div id="bg-pulse-rings">
  <div class="pulse-ring"></div>
  <div class="pulse-ring"></div>
  <div class="pulse-ring"></div>
</div>
<div id="bg-vaporwave"><div class="vw-grid"></div></div>

<!-- ══ AUTH OVERLAY ══ -->
<div class="overlay" id="auth-overlay">
  <div class="auth-box">
    <h2>VulnScan Pro</h2>
    <p id="auth-subtitle">Security Intelligence Platform</p>
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="authTab('login')">LOGIN</button>
      <button class="auth-tab" onclick="authTab('register')">REGISTER</button>
      <button class="auth-tab" onclick="authTab('forgot')">FORGOT</button>
    </div>
    <div id="auth-msg" class="auth-msg"></div>
    <div id="form-login">
      <div class="fg"><label>USERNAME</label><input class="inp" id="l-user" type="text" placeholder="your username" autocomplete="username"/></div>
      <div class="fg"><label>PASSWORD</label><input class="inp" id="l-pass" type="password" placeholder="••••••••" autocomplete="current-password"/></div>
      <button class="btn btn-p" id="l-btn" onclick="doLogin()" style="margin-top:4px">LOGIN</button>
      <div style="text-align:center;margin-top:14px">
        <button class="auth-link" onclick="authTab('forgot')">Forgot password?</button>
        &nbsp;·&nbsp;
        <button class="auth-link" onclick="authTab('register')">Create account</button>
      </div>
    </div>
    <div id="form-register" style="display:none">
      <div class="fg"><label>FULL NAME</label><input class="inp" id="r-name" type="text" placeholder="Your Name"/></div>
      <div class="fg"><label>USERNAME</label><input class="inp" id="r-user" type="text" placeholder="username"/></div>
      <div class="fg"><label>EMAIL</label><input class="inp" id="r-email" type="email" placeholder="you@example.com"/></div>
      <div class="fg"><label>PASSWORD</label><input class="inp" id="r-pass" type="password" placeholder="Min 8 chars, 1 uppercase, 1 number"/></div>
      <button class="btn btn-p" id="r-btn" onclick="doRegister()" style="margin-top:4px">CREATE ACCOUNT</button>
      <div style="text-align:center;margin-top:14px"><button class="auth-link" onclick="authTab('login')">Already have an account?</button></div>
    </div>
    <div id="form-forgot" style="display:none">
      <div class="fg"><label>EMAIL ADDRESS</label><input class="inp" id="f-email" type="email" placeholder="you@example.com"/></div>
      <button class="btn btn-p" onclick="doForgot()" style="margin-top:4px">SEND RESET LINK</button>
      <div style="text-align:center;margin-top:14px"><button class="auth-link" onclick="authTab('login')">Back to login</button></div>
    </div>
  </div>
</div>

<!-- ══ ABOUT MODAL ══ -->
<div id="about-modal" style="display:none;position:fixed;inset:0;background:rgba(4,4,10,0.92);z-index:300;align-items:center;justify-content:center;backdrop-filter:blur(12px)" onclick="if(event.target===this)closeAbout()">
  <div style="background:var(--s1);border:1px solid var(--b2);border-radius:18px;padding:40px;width:100%;max-width:560px;position:relative;margin:16px">
    <button onclick="closeAbout()" style="position:absolute;top:16px;right:18px;background:transparent;border:none;color:var(--m);cursor:pointer;font-size:20px;line-height:1">&#10005;</button>
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:24px">
      <div style="width:48px;height:48px;background:linear-gradient(135deg,var(--red),var(--orange));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0;box-shadow:0 0 24px rgba(255,51,102,0.35)">&#9889;</div>
      <div>
        <div style="font-size:22px;font-weight:800;font-family:var(--font-head);background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent">VulnScan Pro</div>
        <div style="font-size:10px;color:var(--m);letter-spacing:3px;font-family:var(--font-mono);margin-top:2px">OPEN SOURCE SECURITY PLATFORM</div>
      </div>
    </div>
    <div style="height:1px;background:linear-gradient(90deg,var(--red),var(--purple),transparent);margin-bottom:22px"></div>
    <p style="color:#c0c0d0;font-size:14px;line-height:1.8;margin:0 0 20px">VulnScan Pro is a free, open-source vulnerability assessment platform designed for security professionals, penetration testers, and system administrators.</p>
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px">
      <div style="width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,var(--cyan),var(--purple));display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:var(--bg);flex-shrink:0">V</div>
      <div>
        <div style="font-size:14px;font-weight:700;color:var(--t)">Vijay Katariya</div>
        <div style="font-size:11px;color:var(--m);font-family:var(--font-mono);margin-top:2px">Creator &amp; Lead Developer · Motalund Organization</div>
      </div>
    </div>
    <div style="background:rgba(255,214,10,0.05);border:1px solid rgba(255,214,10,0.15);border-radius:8px;padding:12px">
      <div style="font-size:11px;color:var(--yellow);font-family:var(--font-mono);line-height:1.7">&#9888; <strong>Legal:</strong> Authorized security testing only. Only scan systems you own or have explicit written permission to test.</div>
    </div>
  </div>
</div>

<!-- ══ HEADER ══ -->
<header>
  <div class="brand brand-link" onclick="pg('home',null)" title="Home">
    <div class="brand-icon">&#9889;</div>
    <div>
      <div class="brand-name" data-text="VulnScan Pro">VulnScan Pro</div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
        <div class="brand-tag">SECURITY PLATFORM</div>
        <span class="ver-badge">v3.5</span>
      </div>
    </div>
  </div>
  <nav id="main-nav">
    <div class="nav-dropdown" id="dd-info">
      <button class="nav-dropdown-btn" id="dd-info-btn">&#128270; Info Gathering <span class="arrow">&#9660;</span></button>
      <div class="nav-dropdown-menu">
        <div class="nav-dropdown-section">&#9632; NETWORK</div>
        <button class="nav-dropdown-item" id="dd-item-scan" onclick="pgFromDd('scan','info')"><span class="item-icon">&#128268;</span><span class="item-label">Network Scanner</span><span class="item-badge">nmap</span></button>
        <button class="nav-dropdown-item" id="dd-item-dnsrecon" onclick="pgFromDd('dnsrecon','info')"><span class="item-icon">&#127760;</span><span class="item-label">DNSRecon</span><span class="item-badge">dns</span></button>
        <button class="nav-dropdown-item" id="dd-item-disc" onclick="pgFromDd('disc','info')"><span class="item-icon">&#128225;</span><span class="item-label">Network Discovery</span><span class="item-badge">subnet</span></button>
        <button class="nav-dropdown-item" id="dd-item-legion" onclick="pgFromDd('legion','info')"><span class="item-icon">&#9881;</span><span class="item-label">Legion</span><span class="item-badge">auto</span></button>
        <div class="nav-dropdown-section">&#9632; OSINT</div>
        <button class="nav-dropdown-item" id="dd-item-harvester" onclick="pgFromDd('harvester','info')"><span class="item-icon">&#127919;</span><span class="item-label">theHarvester</span><span class="item-badge">recon</span></button>
        <button class="nav-dropdown-item" id="dd-item-sub" onclick="pgFromDd('sub','info')"><span class="item-icon">&#127758;</span><span class="item-label">Subdomain Finder</span><span class="item-badge">dns</span></button>
      </div>
    </div>
    <div class="nav-dropdown" id="dd-web">
      <button class="nav-dropdown-btn" id="dd-web-btn">&#127760; Web Testing <span class="arrow">&#9660;</span></button>
      <div class="nav-dropdown-menu">
        <div class="nav-dropdown-section">&#9632; SCANNERS</div>
        <button class="nav-dropdown-item" id="dd-item-nikto" onclick="pgFromDd('nikto','web')"><span class="item-icon">&#128200;</span><span class="item-label">Nikto</span><span class="item-badge">web vuln</span></button>
        <button class="nav-dropdown-item" id="dd-item-wpscan" onclick="pgFromDd('wpscan','web')"><span class="item-icon">&#128196;</span><span class="item-label">WPScan</span><span class="item-badge">wordpress</span></button>
        <div class="nav-dropdown-section">&#9632; ENUMERATION</div>
        <button class="nav-dropdown-item" id="dd-item-dir" onclick="pgFromDd('dir','web')"><span class="item-icon">&#128193;</span><span class="item-label">Directory Buster</span><span class="item-badge">fuzzing</span></button>
      </div>
    </div>
    <div class="nav-dropdown" id="dd-pwd">
      <button class="nav-dropdown-btn" id="dd-pwd-btn">&#128272; Password Attacks <span class="arrow">&#9660;</span></button>
      <div class="nav-dropdown-menu">
        <div class="nav-dropdown-section">&#9632; BRUTE FORCE</div>
        <button class="nav-dropdown-item" id="dd-item-brute" onclick="pgFromDd('brute','pwd')"><span class="item-icon">&#128272;</span><span class="item-label">Brute Force</span><span class="item-badge">http/ssh</span></button>
      </div>
    </div>
    <div class="nav-dropdown" id="dd-audit">
      <button class="nav-dropdown-btn" id="dd-audit-btn">&#128203; System Auditing <span class="arrow">&#9660;</span></button>
      <div class="nav-dropdown-menu">
        <div class="nav-dropdown-section">&#9632; HOST SECURITY</div>
        <button class="nav-dropdown-item" id="dd-item-lynis" onclick="pgFromDd('lynis','audit')"><span class="item-icon">&#128203;</span><span class="item-label">Lynis</span><span class="item-badge">hardening</span></button>
      </div>
    </div>
    <button class="nb" onclick="pg('hist',this)">&#128196; History</button>
    <button class="nb" onclick="pg('dash',this)">&#128202; Dashboard</button>
    <button class="nb admin-only" onclick="pg('admin',this)" style="display:none">&#9881; Admin</button>
    <button class="nb" onclick="showAbout()" style="color:var(--cyan)">&#9432; About</button>
    <div class="user-chip" onclick="pg('profile',this)" id="user-chip" style="display:none">
      <div class="user-avatar" id="user-avatar">?</div>
      <div><div class="user-name" id="user-name-disp">User</div><div class="user-role" id="user-role-disp">user</div></div>
    </div>
    <button class="nb" id="logout-btn" onclick="doLogout()" style="display:none;color:var(--red)">&#10005; Logout</button>
  </nav>
</header>

<div class="container">

<!-- ═══ HOME ═══ -->
<div class="page active" id="page-home">
  <div class="home-hero">
    <h1 data-text="VulnScan Pro">VulnScan Pro</h1>
    <p>Professional security reconnaissance &amp; vulnerability assessment platform. Built for pentesters, sysadmins, and security researchers.</p>
    <div class="home-quick">
      <button class="home-quick-btn" onclick="pgFromDd('scan','info')">&#128268; Quick Network Scan</button>
      <button class="home-quick-btn" onclick="pgFromDd('harvester','info')">&#127919; OSINT Harvest</button>
      <button class="home-quick-btn" onclick="pg('sub',null)">&#127760; Subdomain Finder</button>
      <button class="home-quick-btn" onclick="pg('hist',null)">&#128196; View History</button>
    </div>
  </div>
  <div class="home-stats" id="home-stats">
    <div class="home-stat"><div class="home-stat-val" id="hs-scans">—</div><div class="home-stat-lbl">TOTAL SCANS</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-cves" style="background:linear-gradient(135deg,var(--red),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">—</div><div class="home-stat-lbl">CVEs FOUND</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-ports" style="background:linear-gradient(135deg,var(--yellow),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">—</div><div class="home-stat-lbl">OPEN PORTS</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-tools" style="background:linear-gradient(135deg,var(--green),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent">12</div><div class="home-stat-lbl">TOOLS AVAILABLE</div></div>
  </div>
  <div class="home-cat"><div class="home-cat-title">&#128270; 01 — INFORMATION GATHERING</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--cyan)" onclick="pgFromDd('scan','info')"><div class="home-tool-icon">&#128268;</div><div class="home-tool-name">Network Scanner</div><div class="home-tool-desc">Deep port scanning with nmap, CVE lookups via NVD, SSL analysis, DNS records, and HTTP header auditing.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">nmap</span><span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">CVE</span><span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">SSL</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--cyan)" onclick="pgFromDd('dnsrecon','info')"><div class="home-tool-icon">&#127760;</div><div class="home-tool-name">DNSRecon</div><div class="home-tool-desc">Comprehensive DNS enumeration — zone transfers, record types, reverse lookups, and DNS cache snooping.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">DNS</span><span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">zone transfer</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--yellow)" onclick="pgFromDd('disc','info')"><div class="home-tool-icon">&#128225;</div><div class="home-tool-name">Network Discovery</div><div class="home-tool-desc">Sweep subnets to discover live hosts, identify OS fingerprints, and map your network topology.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">subnet</span><span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">host discovery</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--red)" onclick="pgFromDd('legion','info')"><div class="home-tool-icon">&#9881;</div><div class="home-tool-name">Legion</div><div class="home-tool-desc">Semi-automated network recon and vulnerability assessment framework orchestrating multiple tools.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">auto-recon</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--purple)" onclick="pgFromDd('harvester','info')"><div class="home-tool-icon">&#127919;</div><div class="home-tool-name">theHarvester</div><div class="home-tool-desc">OSINT recon to harvest emails, subdomains, hosts, and IPs from public sources.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">OSINT</span><span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">emails</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--green)" onclick="pgFromDd('sub','info')"><div class="home-tool-icon">&#127758;</div><div class="home-tool-name">Subdomain Finder</div><div class="home-tool-desc">Enumerate subdomains via DNS brute-force and passive sources. Map the full attack surface.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">DNS</span><span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">brute-force</span></div></div>
    </div>
  </div>
  <div class="home-cat"><div class="home-cat-title">&#127760; 02 — WEB APPLICATION TESTING</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--orange)" onclick="pgFromDd('nikto','web')"><div class="home-tool-icon">&#128200;</div><div class="home-tool-name">Nikto</div><div class="home-tool-desc">Web server vulnerability scanner checking for dangerous files, outdated software, and 6700+ known issues.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">web vuln</span><span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">CVE</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--purple)" onclick="pgFromDd('wpscan','web')"><div class="home-tool-icon">&#128196;</div><div class="home-tool-name">WPScan</div><div class="home-tool-desc">WordPress security scanner — vulnerable plugins, themes, weak credentials, and config exposures.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">WordPress</span><span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">plugins</span></div></div>
      <div class="home-tool-card" style="--tool-c:var(--orange)" onclick="pgFromDd('dir','web')"><div class="home-tool-icon">&#128193;</div><div class="home-tool-name">Directory Buster</div><div class="home-tool-desc">Brute-force hidden directories, admin panels, and sensitive files using wordlist-based enumeration.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">HTTP</span><span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">fuzzing</span></div></div>
    </div>
  </div>
  <div class="home-cat"><div class="home-cat-title">&#128272; 03 — PASSWORD ATTACKS</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--red)" onclick="pgFromDd('brute','pwd')"><div class="home-tool-icon">&#128272;</div><div class="home-tool-name">Brute Force</div><div class="home-tool-desc">Credential testing against HTTP login forms and SSH services using custom or built-in wordlists.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">HTTP</span><span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">SSH</span></div></div>
    </div>
  </div>
  <div class="home-cat"><div class="home-cat-title">&#128203; 04 — SYSTEM AUDITING</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--green)" onclick="pgFromDd('lynis','audit')"><div class="home-tool-icon">&#128203;</div><div class="home-tool-name">Lynis</div><div class="home-tool-desc">In-depth local system security audit — OS hardening, packages, file permissions, firewall rules, compliance.</div><div class="home-tool-tags"><span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">hardening</span><span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">compliance</span></div></div>
    </div>
  </div>
  <div style="background:rgba(255,214,10,0.04);border:1px solid rgba(255,214,10,0.12);border-radius:10px;padding:14px 18px;margin-bottom:24px;display:flex;gap:12px;align-items:flex-start">
    <span style="font-size:16px">&#9888;</span>
    <div style="font-size:11px;color:var(--m);font-family:var(--font-mono);line-height:1.8"><strong style="color:var(--yellow)">Authorized Use Only.</strong> VulnScan Pro is designed exclusively for security testing on systems you own or have explicit written permission to assess.</div>
  </div>
</div>

<!-- ═══ SCANNER ═══ -->
<div class="page" id="page-scan">
  <div class="hero"><h2>Vulnerability Intelligence</h2><p>Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS recon &middot; Header audit</p>
    <div class="row"><input class="scan-inp" id="tgt" type="text" placeholder="IP address or hostname  e.g. 192.168.1.1" onkeydown="if(event.key==='Enter')doScan()"/><button class="btn btn-p" id="sbtn" onclick="doScan()">SCAN</button></div>
    <div class="mods">
      <button class="mt on" id="mod-ports" onclick="tmg('ports',this)">&#128268; Ports+CVE</button>
      <button class="mt on" id="mod-ssl" onclick="tmg('ssl',this)">&#128274; SSL/TLS</button>
      <button class="mt on" id="mod-dns" onclick="tmg('dns',this)">&#127758; DNS</button>
      <button class="mt on" id="mod-headers" onclick="tmg('headers',this)">&#128196; Headers</button>
    </div>
    <p style="color:var(--m);font-size:11px;margin-top:12px;font-family:var(--font-mono)">&#9432; Scans may take 30–180 seconds. Please wait.</p>
  </div>
  <div id="prog"><div id="pb"></div></div>
  <div id="term"></div><div id="err"></div><div id="res"></div>
</div>

<!-- ═══ THE HARVESTER ═══ -->
<div class="page" id="page-harvester">
  <div class="card">
    <div class="ctitle">&#127919; theHarvester — OSINT Recon</div>
    <div class="notice">&#9888; Only perform reconnaissance on domains you own or have explicit written permission to test.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>TARGET DOMAIN</label><input class="inp" id="hv-target" type="text" placeholder="e.g. example.com"/></div>
      <div class="fg"><label>DATA SOURCES</label><select class="inp" id="hv-sources" multiple style="height:90px;padding:6px"><option value="google" selected>Google</option><option value="bing" selected>Bing</option><option value="linkedin">LinkedIn</option><option value="dnsdumpster" selected>DNSDumpster</option><option value="crtsh" selected>crt.sh</option><option value="hackertarget">HackerTarget</option><option value="baidu">Baidu</option><option value="yahoo">Yahoo</option></select><div style="font-size:9px;color:var(--m);margin-top:3px;font-family:var(--font-mono)">Hold Ctrl/Cmd to select multiple</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="fg"><label>RESULT LIMIT</label><input class="inp" id="hv-limit" type="number" value="500" min="50" max="2000"/></div>
      <div class="fg"><label>DNS BRUTE-FORCE</label><select class="inp" id="hv-dns"><option value="">Disabled</option><option value="-f /tmp/hv_out -b all --dns-brute">Enable</option></select></div>
      <div class="fg"><label>OUTPUT FORMAT</label><select class="inp" id="hv-fmt"><option value="xml">XML (full)</option><option value="json">JSON</option></select></div>
    </div>
    <button class="btn btn-p" id="hv-btn" onclick="doHarvest()" style="width:auto;padding:10px 32px">&#127919; RUN HARVESTER</button>
    <p style="color:var(--m);font-size:11px;margin-top:12px;font-family:var(--font-mono)">&#9432; Recon may take 30–120 seconds.</p>
    <div id="hv-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="hv-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--purple));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="hv-term" class="terminal" style="display:none;margin-top:14px"></div>
    <div id="hv-err" class="err-box" style="display:none;margin-top:10px"></div>
    <div id="hv-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ DNSRECON ═══ -->
<div class="page" id="page-dnsrecon">
  <div class="card">
    <div class="ctitle">&#127760; DNSRecon — DNS Enumeration</div>
    <div class="notice">&#9888; Only enumerate domains you own or have explicit written permission to test.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>TARGET DOMAIN</label><input class="inp" id="dr-target" type="text" placeholder="e.g. example.com"/></div>
      <div class="fg"><label>SCAN TYPE</label><select class="inp" id="dr-type"><option value="std">Standard (all record types)</option><option value="axfr">Zone Transfer (AXFR)</option><option value="brt">Brute Force subdomains</option><option value="srv">SRV record enumeration</option><option value="rvl">Reverse lookup</option></select></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="fg"><label>NAMESERVER (optional)</label><input class="inp" id="dr-ns" type="text" placeholder="e.g. 8.8.8.8"/></div>
      <div class="fg"><label>RECORD FILTER</label><select class="inp" id="dr-filter"><option value="">All records</option><option value="A">A records</option><option value="MX">MX records</option><option value="NS">NS records</option><option value="TXT">TXT records</option><option value="SOA">SOA records</option><option value="CNAME">CNAME records</option></select></div>
    </div>
    <button class="btn btn-p" id="dr-btn" onclick="doDnsRecon()" style="width:auto;padding:10px 32px">&#127760; RUN DNSRECON</button>
    <p style="color:var(--m);font-size:11px;margin-top:12px;font-family:var(--font-mono)">&#9432; Zone transfers and brute-force scans may take 30–90 seconds.</p>
    <div id="dr-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="dr-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--purple));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="dr-term" style="display:none;margin-top:14px;background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;max-height:160px;overflow-y:auto;font-family:var(--font-mono);font-size:13px"></div>
    <div id="dr-err" style="display:none;margin-top:10px;background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;font-family:var(--font-mono)"></div>
    <div id="dr-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ NIKTO ═══ -->
<div class="page" id="page-nikto">
  <div class="card">
    <div class="ctitle">&#128200; Nikto — Web Vulnerability Scanner</div>
    <div class="notice">&#9888; Only scan web servers you own or have explicit written permission to test.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>TARGET URL / HOST</label><input class="inp" id="nk-target" type="text" placeholder="e.g. http://192.168.1.1 or example.com"/></div>
      <div class="fg"><label>PORT</label><input class="inp" id="nk-port" type="number" placeholder="80" value="80" min="1" max="65535"/></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="fg"><label>SSL</label><select class="inp" id="nk-ssl"><option value="">Auto-detect</option><option value="-ssl">Force SSL</option><option value="-nossl">Disable SSL</option></select></div>
      <div class="fg"><label>TUNING (optional)</label><select class="inp" id="nk-tuning"><option value="">All tests</option><option value="1">File upload</option><option value="2">Misconfiguration</option><option value="4">XSS</option><option value="8">Command injection</option><option value="9">SQL injection</option><option value="b">Software identification</option></select></div>
    </div>
    <button class="btn btn-p" id="nk-btn" onclick="doNikto()" style="width:auto;padding:10px 32px">&#128200; RUN NIKTO</button>
    <div id="nk-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="nk-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--orange),var(--red));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="nk-term" style="display:none;margin-top:14px;background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;max-height:180px;overflow-y:auto;font-family:var(--font-mono);font-size:12px"></div>
    <div id="nk-err" style="display:none;margin-top:10px;background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;font-family:var(--font-mono)"></div>
    <div id="nk-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ WPSCAN ═══ -->
<div class="page" id="page-wpscan">
  <div class="card">
    <div class="ctitle">&#128196; WPScan — WordPress Security Scanner</div>
    <div class="notice">&#9888; Only scan WordPress sites you own or have explicit written permission to test.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>TARGET URL</label><input class="inp" id="wp-target" type="text" placeholder="e.g. https://example.com"/></div>
      <div class="fg"><label>ENUMERATION</label><select class="inp" id="wp-enum" multiple style="height:96px;padding:6px"><option value="p" selected>Plugins (vulnerable)</option><option value="t">Themes</option><option value="u" selected>Users</option><option value="vp">Vulnerable plugins only</option><option value="ap">All plugins</option><option value="at">All themes</option><option value="tt">Timthumbs</option><option value="cb">Config backups</option></select></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="fg"><label>WPScan API TOKEN (optional)</label><input class="inp" id="wp-token" type="password" placeholder="Get free token at wpscan.com"/></div>
      <div class="fg"><label>DETECTION MODE</label><select class="inp" id="wp-mode"><option value="mixed">Mixed (default)</option><option value="passive">Passive (stealthy)</option><option value="aggressive">Aggressive</option></select></div>
    </div>
    <button class="btn btn-p" id="wp-btn" onclick="doWPScan()" style="width:auto;padding:10px 32px">&#128196; RUN WPSCAN</button>
    <div id="wp-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="wp-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--purple),var(--cyan));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="wp-term" style="display:none;margin-top:14px;background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;max-height:180px;overflow-y:auto;font-family:var(--font-mono);font-size:12px"></div>
    <div id="wp-err" style="display:none;margin-top:10px;background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;font-family:var(--font-mono)"></div>
    <div id="wp-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ LYNIS ═══ -->
<div class="page" id="page-lynis">
  <div class="card">
    <div class="ctitle">&#128203; Lynis — System Security Audit</div>
    <div class="notice">&#9432; Lynis audits the <strong>local server</strong> running VulnScan Pro. No target needed.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>AUDIT PROFILE</label><select class="inp" id="ly-profile"><option value="system">Full System Audit</option><option value="quick">Quick Scan</option><option value="forensics">Forensics Mode</option></select></div>
      <div class="fg"><label>FOCUS CATEGORY</label><select class="inp" id="ly-category"><option value="">All categories</option><option value="authentication">Authentication</option><option value="networking">Networking</option><option value="storage">Storage &amp; Filesystems</option><option value="kernel">Kernel &amp; Memory</option><option value="software">Installed Software</option><option value="logging">Logging &amp; Auditing</option></select></div>
    </div>
    <div class="fg" style="margin-bottom:16px"><label>COMPLIANCE STANDARD</label><select class="inp" id="ly-compliance"><option value="">None</option><option value="ISO27001">ISO 27001</option><option value="PCI-DSS">PCI-DSS</option><option value="HIPAA">HIPAA</option><option value="CIS">CIS Benchmark</option></select></div>
    <button class="btn btn-p" id="ly-btn" onclick="doLynis()" style="width:auto;padding:10px 32px">&#128203; RUN LYNIS AUDIT</button>
    <div id="ly-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="ly-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--green),var(--cyan));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="ly-term" style="display:none;margin-top:14px;background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;max-height:200px;overflow-y:auto;font-family:var(--font-mono);font-size:12px"></div>
    <div id="ly-err" style="display:none;margin-top:10px;background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;font-family:var(--font-mono)"></div>
    <div id="ly-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ LEGION ═══ -->
<div class="page" id="page-legion">
  <div class="card">
    <div class="ctitle">&#9881; Legion — Auto-Recon Framework</div>
    <div class="notice">&#9888; Only scan hosts you own or have explicit written permission to test.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg"><label>TARGET HOST / IP</label><input class="inp" id="lg-target" type="text" placeholder="e.g. 192.168.1.1 or example.com"/></div>
      <div class="fg"><label>SCAN INTENSITY</label><select class="inp" id="lg-intensity"><option value="light">Light (fast, low noise)</option><option value="normal" selected>Normal</option><option value="aggressive">Aggressive (thorough)</option></select></div>
    </div>
    <div class="fg" style="margin-bottom:16px"><label>MODULES TO RUN</label>
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px">
        <button class="mt on" id="lg-mod-nmap" onclick="lgMod('nmap',this)">&#128268; nmap</button>
        <button class="mt on" id="lg-mod-nikto" onclick="lgMod('nikto',this)">&#128200; nikto</button>
        <button class="mt on" id="lg-mod-smb" onclick="lgMod('smb',this)">&#128229; SMB</button>
        <button class="mt on" id="lg-mod-snmp" onclick="lgMod('snmp',this)">&#128241; SNMP</button>
        <button class="mt" id="lg-mod-hydra" onclick="lgMod('hydra',this)">&#128272; hydra</button>
        <button class="mt" id="lg-mod-finger" onclick="lgMod('finger',this)">&#128100; finger</button>
      </div>
    </div>
    <button class="btn btn-p" id="lg-btn" onclick="doLegion()" style="width:auto;padding:10px 32px">&#9881; RUN LEGION</button>
    <div id="lg-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="lg-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--red),var(--orange));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="lg-term" style="display:none;margin-top:14px;background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;max-height:200px;overflow-y:auto;font-family:var(--font-mono);font-size:12px"></div>
    <div id="lg-err" style="display:none;margin-top:10px;background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;font-family:var(--font-mono)"></div>
    <div id="lg-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ SUBDOMAIN ═══ -->
<div class="page" id="page-sub"><div class="card"><div class="ctitle">SUBDOMAIN FINDER</div><div class="notice">&#9888; Only enumerate domains you own or have written permission to test.</div><div class="fg"><label>DOMAIN</label><input class="scan-inp" id="sub-domain" placeholder="example.com" type="text" style="width:100%"/></div><div class="fg" style="margin-top:12px"><label>WORDLIST SIZE</label><select class="sel" id="sub-size"><option value="small">Small (~30 words, faster)</option><option value="medium" selected>Medium (~80 words + crt.sh + HackerTarget)</option></select></div><button class="btn btn-p btn-full" id="sub-btn" onclick="doSub()" style="margin-top:4px">FIND SUBDOMAINS</button></div><div id="sub-res"></div></div>
<div class="page" id="page-dir"><div class="card"><div class="ctitle">DIRECTORY ENUMERATOR</div><div class="notice">&#9888; Only scan web servers you own or have written permission to test.</div><div class="fg"><label>TARGET URL</label><input class="scan-inp" id="dir-url" placeholder="http://192.168.1.1 or https://example.com" type="text" style="width:100%"/></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px"><div class="fg"><label>WORDLIST SIZE</label><select class="sel" id="dir-size"><option value="small" selected>Small (~60 paths)</option><option value="medium">Medium (~130 paths)</option></select></div><div class="fg"><label>EXTENSIONS</label><input class="scan-inp" id="dir-ext" value="php,html,txt,bak,zip,json,xml" type="text" style="width:100%"/></div></div><button class="btn btn-p btn-full" id="dir-btn" onclick="doDir()">START ENUMERATION</button></div><div id="dir-res"></div></div>
<div class="page" id="page-brute"><div class="card"><div class="ctitle">LOGIN BRUTE FORCE TESTER</div><div class="notice">&#9888; ONLY use on systems you own or have explicit written permission. Unauthorized use is illegal.</div><div class="fg"><label>ATTACK TYPE</label><select class="sel" id="bf-type" onchange="bfTypeChange()"><option value="http">HTTP Form Login</option><option value="ssh">SSH Login</option></select></div><div id="bf-http-fields"><div class="bf-grid"><div class="fg"><label>LOGIN URL</label><input class="scan-inp" id="bf-url" placeholder="http://192.168.1.1/login" type="text" style="width:100%"/></div><div class="fg"><label>USERNAME FIELD</label><input class="scan-inp" id="bf-ufield" value="username" type="text" style="width:100%"/></div><div class="fg"><label>PASSWORD FIELD</label><input class="scan-inp" id="bf-pfield" value="password" type="text" style="width:100%"/></div></div></div><div id="bf-ssh-fields" style="display:none"><div class="bf-grid"><div class="fg"><label>HOST</label><input class="scan-inp" id="bf-ssh-host" placeholder="192.168.1.1" type="text" style="width:100%"/></div><div class="fg"><label>PORT</label><input class="scan-inp" id="bf-ssh-port" value="22" type="text" style="width:100%"/></div></div></div><div class="bf-grid" style="margin-top:12px"><div class="fg"><label>USERNAMES (one per line)</label><textarea class="scan-inp" id="bf-users" placeholder="admin&#10;root&#10;user"></textarea></div><div class="fg"><label>PASSWORDS (one per line)</label><textarea class="scan-inp" id="bf-pwds" placeholder="admin&#10;password&#10;123456"></textarea></div></div><button class="btn btn-p btn-full" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button></div><div id="bf-res"></div></div>
<div class="page" id="page-disc"><div class="card"><div class="ctitle">NETWORK DISCOVERY</div><div class="row"><input class="scan-inp" id="subnet" placeholder="192.168.1.0/24" type="text" onkeydown="if(event.key==='Enter')doDisc()" style="flex:1"/><button class="btn btn-p" id="disc-btn" onclick="doDisc()">DISCOVER</button></div><p style="color:var(--m);font-size:11px;margin-top:10px;font-family:var(--font-mono)">&#9888; Only scan networks you own or have permission to scan</p></div><div id="disc-res"></div></div>
<div class="page" id="page-hist"><div class="card"><div class="ctitle">SCAN HISTORY</div><div id="hist-content"><p style="color:var(--m);font-size:13px">Loading...</p></div></div></div>
<div class="page" id="page-dash"><div class="card"><div class="ctitle">SECURITY DASHBOARD</div><div id="dash-content"><p style="color:var(--m);font-size:13px">Run some scans to see statistics.</p></div></div></div>

<!-- ═══ PROFILE ═══ -->
<div class="page" id="page-profile">
  <div class="profile-grid">
    <div class="card">
      <div class="ctitle">MY PROFILE</div>
      <div id="profile-info"></div>
      <div style="margin-top:16px">
        <div class="fg"><label>FULL NAME</label><input class="scan-inp" id="p-name" type="text" placeholder="Your full name" style="width:100%"/></div>
        <button class="btn btn-p btn-full" onclick="saveProfile()" style="margin-top:8px">SAVE PROFILE</button>
      </div>
    </div>
    <div class="card">
      <div class="ctitle">CHANGE PASSWORD</div>
      <div class="fg"><label>CURRENT PASSWORD</label><input class="scan-inp" id="cp-old" type="password" placeholder="Current password" style="width:100%"/></div>
      <div class="fg"><label>NEW PASSWORD</label><input class="scan-inp" id="cp-new" type="password" placeholder="New password" style="width:100%"/></div>
      <div class="fg"><label>CONFIRM NEW PASSWORD</label><input class="scan-inp" id="cp-confirm" type="password" placeholder="Confirm new password" style="width:100%"/></div>
      <button class="btn btn-p btn-full" onclick="changePassword()" style="margin-top:8px">CHANGE PASSWORD</button>
      <div id="pwd-msg" class="auth-msg" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- ══ THEME SECTION ══ -->
  <div class="card" style="margin-top:16px">
    <div class="ctitle">&#127912; INTERFACE THEME</div>
    <p style="color:var(--m);font-size:12px;font-family:var(--font-mono);margin-bottom:16px">Each theme has unique fonts, visual effects, and personality — not just colors.</p>

    <!-- Dropdown -->
    <div class="theme-dropdown-wrap" id="theme-dropdown-wrap">
      <button class="theme-dropdown-btn" id="theme-dropdown-btn" onclick="toggleThemeDropdown()">
        <div class="tdb-left">
          <div class="theme-preview-dot" id="theme-preview-dot"></div>
          <div>
            <div style="font-size:13px;font-weight:700;color:var(--t)" id="theme-current-name">CYBERPUNK</div>
            <div style="font-size:10px;color:var(--m);font-family:var(--font-mono);margin-top:1px" id="theme-current-desc">Neon-noir with Orbitron display font</div>
          </div>
        </div>
        <span class="tdb-arrow">▼</span>
      </button>
      <div class="theme-dropdown-panel" id="theme-dropdown-panel">
        <!-- populated by JS -->
      </div>
    </div>

    <!-- Active theme info card -->
    <div id="theme-info-card" style="margin-top:14px;padding:14px;background:var(--s2);border-radius:10px;border:1px solid var(--b2);display:flex;align-items:center;gap:14px">
      <span class="pulse-dot"></span>
      <div style="flex:1">
        <div style="font-size:12px;font-family:var(--font-mono);color:var(--m)">CURRENT THEME</div>
        <div style="font-size:14px;font-weight:700;color:var(--accent);font-family:var(--font-head);margin-top:2px" id="theme-active-display">CYBERPUNK</div>
      </div>
      <div style="font-size:11px;color:var(--m);font-family:var(--font-mono);text-align:right" id="theme-font-display">Font: Orbitron</div>
    </div>
  </div>
</div>

<!-- ═══ ADMIN ═══ -->
<div class="page" id="page-admin">
  <div class="tabs" id="admin-tabs">
    <button class="tab active" onclick="adminTab(event,'at-users')">&#128100; Users</button>
    <button class="tab" onclick="adminTab(event,'at-stats')">&#128202; Stats</button>
    <button class="tab" onclick="adminTab(event,'at-audit')">&#128196; Audit Log</button>
    <button class="tab" onclick="adminTab(event,'at-scans')">&#128269; All Scans</button>
  </div>
  <div class="tc active" id="at-users"><div class="card"><div class="ctitle">USER MANAGEMENT</div><div id="admin-users"><p style="color:var(--m)">Loading...</p></div></div></div>
  <div class="tc" id="at-stats"><div class="card"><div class="ctitle">PLATFORM STATISTICS</div><div id="admin-stats"></div></div></div>
  <div class="tc" id="at-audit"><div class="card"><div class="ctitle">AUDIT LOG</div><div id="admin-audit" style="overflow-x:auto"></div></div></div>
  <div class="tc" id="at-scans"><div class="card"><div class="ctitle">ALL SCANS</div><div id="admin-scans" style="overflow-x:auto"></div></div></div>
</div>

</div><!-- /container -->

<script>
// ══════════════════════════════════════
//  THEME DEFINITIONS — truly unique looks
// ══════════════════════════════════════
const THEMES = [
  {
    id:'cyberpunk', name:'CYBERPUNK', emoji:'⚡',
    desc:'Neon-noir · Orbitron display · Electric blue grid',
    tag:'NEON NOIR', tagColor:'#00e5ff',
    accent:'#00e5ff', bg:'#04040a', s1:'#080810', s2:'#0d0d18',
    previewBars:['#04040a','#00e5ff','#b06fff','#ff3366','#ffd60a'],
    font:'Orbitron'
  },
  {
    id:'ghost', name:'GHOST', emoji:'◻',
    desc:'Ultra-minimal · Courier Prime serif · Stark monochrome',
    tag:'MINIMAL', tagColor:'#111111',
    accent:'#111111', bg:'#f8f8f5', s1:'#f0f0ec', s2:'#e8e8e4',
    previewBars:['#f8f8f5','#111111','#888884','#cc0000','#b8b8b4'],
    font:'Courier Prime'
  },
  {
    id:'phantom', name:'PHANTOM', emoji:'👁',
    desc:'Deep void · Rajdhani military · Electric violet pulses',
    tag:'VOID VIOLET', tagColor:'#dd00ff',
    accent:'#dd00ff', bg:'#0a0008', s1:'#110011', s2:'#180018',
    previewBars:['#0a0008','#dd00ff','#9900cc','#ff0066','#f0d0ff'],
    font:'Rajdhani'
  },
  {
    id:'solaris', name:'SOLARIS', emoji:'☀',
    desc:'Industrial amber · Exo 2 condensed · Forge-hot warnings',
    tag:'BRUTALIST', tagColor:'#ffaa00',
    accent:'#ffaa00', bg:'#100800', s1:'#180d00', s2:'#201200',
    previewBars:['#100800','#ffaa00','#ffee00','#ff4400','#fff8e8'],
    font:'Exo 2'
  },
  {
    id:'matrix', name:'MATRIX', emoji:'▓',
    desc:'Terminal green · Share Tech Mono · Classic hacker rain',
    tag:'TERMINAL', tagColor:'#00ff41',
    accent:'#00ff41', bg:'#000300', s1:'#000500', s2:'#000800',
    previewBars:['#000300','#00ff41','#39ff14','#ccff00','#001a00'],
    font:'Share Tech Mono'
  },
  {
    id:'luxe', name:'LUXE', emoji:'◆',
    desc:'Dark luxury · Playfair Display serif · Gold & velvet',
    tag:'EDITORIAL', tagColor:'#c8a96e',
    accent:'#c8a96e', bg:'#08060a', s1:'#0e0b12', s2:'#141018',
    previewBars:['#08060a','#c8a96e','#9c7fc0','#e8c870','#f5ede0'],
    font:'Playfair Display'
  },
  {
    id:'arctic', name:'ARCTIC', emoji:'❄',
    desc:'Ice & steel · Space Grotesk clean · Cold blue daylight',
    tag:'DAYLIGHT', tagColor:'#0066cc',
    accent:'#0066cc', bg:'#f4f8ff', s1:'#eaf0fb', s2:'#dde8f8',
    previewBars:['#f4f8ff','#0066cc','#7733cc','#00aa55','#1a2a40'],
    font:'Space Grotesk'
  },
  {
    id:'blood', name:'BLOOD', emoji:'🩸',
    desc:'Crimson void · Orbitron horror · Deep red on black',
    tag:'HORROR', tagColor:'#ff2020',
    accent:'#ff2020', bg:'#080000', s1:'#100000', s2:'#180000',
    previewBars:['#080000','#ff2020','#cc2060','#ff8020','#ffd0d0'],
    font:'Orbitron'
  },
  {
    id:'vaporwave', name:'VAPORWAVE', emoji:'🌊',
    desc:'80s retro dream · Monoton display · Synthwave grid floor',
    tag:'RETROWAVE', tagColor:'#ff88ff',
    accent:'#ff88ff', bg:'#0d001a', s1:'#130022', s2:'#19002e',
    previewBars:['#0d001a','#ff88ff','#44ffcc','#cc44ff','#ffccff'],
    font:'Monoton'
  },
  {
    id:'terminal', name:'TERMINAL', emoji:'▶',
    desc:'CRT phosphor amber · Share Tech Mono · Classic console',
    tag:'RETRO CRT', tagColor:'#ffcc44',
    accent:'#ffcc44', bg:'#0a0800', s1:'#100d00', s2:'#181200',
    previewBars:['#0a0800','#ffcc44','#ffaa22','#ff4422','#ffee66'],
    font:'Share Tech Mono'
  }
];

let currentTheme = localStorage.getItem('vs-theme') || 'cyberpunk';
let themeDropdownOpen = false;

function getThemeById(id){ return THEMES.find(t=>t.id===id)||THEMES[0]; }

function applyTheme(id, closeDropdown=true){
  const t = getThemeById(id);
  THEMES.forEach(th=>document.body.classList.remove('theme-'+th.id));
  document.body.classList.add('theme-'+id);
  currentTheme = id;
  localStorage.setItem('vs-theme', id);

  // Update dropdown button
  const dot = document.getElementById('theme-preview-dot');
  if(dot){ dot.style.background = t.accent; dot.style.boxShadow = '0 0 10px '+t.accent+'88'; }
  const nm = document.getElementById('theme-current-name');
  if(nm) nm.textContent = t.name;
  const dc = document.getElementById('theme-current-desc');
  if(dc) dc.textContent = t.desc;

  // Update info card
  const ad = document.getElementById('theme-active-display');
  if(ad) ad.textContent = t.name;
  const fd = document.getElementById('theme-font-display');
  if(fd) fd.textContent = 'Font: '+t.font;

  // Update dropdown active state
  document.querySelectorAll('.theme-option').forEach(el=>{
    const active = el.dataset.themeId === id;
    el.classList.toggle('active', active);
  });

  if(closeDropdown) closeThemeDropdown();
  updateBgEffects();
}

function toggleThemeDropdown(){
  themeDropdownOpen = !themeDropdownOpen;
  const btn = document.getElementById('theme-dropdown-btn');
  const panel = document.getElementById('theme-dropdown-panel');
  btn.classList.toggle('open', themeDropdownOpen);
  panel.classList.toggle('open', themeDropdownOpen);
}

function closeThemeDropdown(){
  themeDropdownOpen = false;
  const btn = document.getElementById('theme-dropdown-btn');
  const panel = document.getElementById('theme-dropdown-panel');
  if(btn) btn.classList.remove('open');
  if(panel) panel.classList.remove('open');
}

document.addEventListener('click', e=>{
  const wrap = document.getElementById('theme-dropdown-wrap');
  if(wrap && !wrap.contains(e.target)) closeThemeDropdown();
});

function buildThemeDropdown(){
  const panel = document.getElementById('theme-dropdown-panel');
  if(!panel) return;
  panel.innerHTML = THEMES.map(t=>`
    <div class="theme-option${t.id===currentTheme?' active':''}"
         data-theme-id="${t.id}"
         style="--opt-accent:${t.accent}"
         onclick="applyTheme('${t.id}')">
      <div class="theme-opt-preview">
        <div class="pop">
          <div class="pop-top">
            ${t.previewBars.slice(0,3).map(c=>`<div class="pop-bar" style="background:${c}"></div>`).join('')}
          </div>
          <div class="pop-bottom">
            ${t.previewBars.slice(2).map(c=>`<div class="pop-line" style="background:${c}"></div>`).join('')}
          </div>
        </div>
      </div>
      <div class="theme-opt-info">
        <div class="theme-opt-name" style="color:${t.accent}">${t.emoji} ${t.name}</div>
        <div class="theme-opt-desc">${t.desc}</div>
      </div>
      <span class="theme-opt-tag" style="color:${t.accent};border-color:${t.accent}40">${t.tag}</span>
      <div class="theme-opt-check">${t.id===currentTheme?'✓':''}</div>
    </div>`).join('');
}

// ══════════════════════════════════
//  BACKGROUND EFFECTS ENGINE
// ══════════════════════════════════

// Aurora / gradient blobs
(function(){
  const canvas = document.getElementById('bg-aurora');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, blobs=[];
  function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
  resize(); window.addEventListener('resize', resize);

  function mkBlob(){ return { x:Math.random()*W, y:Math.random()*H, vx:(Math.random()-0.5)*0.3, vy:(Math.random()-0.5)*0.3, r:150+Math.random()*300, phase:Math.random()*Math.PI*2 }; }
  for(let i=0;i<5;i++) blobs.push(mkBlob());

  function getAccentRgb(){
    const s = getComputedStyle(document.body);
    const hex = (s.getPropertyValue('--cyan')||s.getPropertyValue('--accent')||'#00e5ff').trim().replace('#','');
    if(hex.length===6){ const n=parseInt(hex,16); return [(n>>16)&255,(n>>8)&255,n&255]; }
    return [0,229,255];
  }

  function draw(){
    ctx.clearRect(0,0,W,H);
    const [r,g,b] = getAccentRgb();
    blobs.forEach((blob,i)=>{
      blob.x += blob.vx; blob.y += blob.vy; blob.phase += 0.005;
      if(blob.x<-blob.r) blob.x=W+blob.r; if(blob.x>W+blob.r) blob.x=-blob.r;
      if(blob.y<-blob.r) blob.y=H+blob.r; if(blob.y>H+blob.r) blob.y=-blob.r;
      const alpha = (0.03+0.015*Math.sin(blob.phase)) * (i===0?2:1);
      const grad = ctx.createRadialGradient(blob.x,blob.y,0,blob.x,blob.y,blob.r);
      grad.addColorStop(0,`rgba(${r},${g},${b},${alpha})`);
      grad.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=grad; ctx.beginPath(); ctx.arc(blob.x,blob.y,blob.r,0,Math.PI*2); ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

// Particles with connections
(function(){
  const canvas = document.getElementById('bg-particles');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, pts=[];
  function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
  resize(); window.addEventListener('resize', resize);

  function hexToRgb(hex){ hex=hex.trim().replace('#',''); if(hex.length===3)hex=hex.split('').map(c=>c+c).join(''); const n=parseInt(hex,16); return[(n>>16)&255,(n>>8)&255,n&255]; }
  function getAccent(){ return (getComputedStyle(document.body).getPropertyValue('--accent')||'#00e5ff').trim(); }

  for(let i=0;i<60;i++) pts.push({ x:Math.random()*W, y:Math.random()*H, vx:(Math.random()-0.5)*0.35, vy:(Math.random()-0.5)*0.35, r:Math.random()*1.5+0.3, phase:Math.random()*Math.PI*2 });

  function draw(){
    ctx.clearRect(0,0,W,H);
    let rgb=[0,229,255]; try{rgb=hexToRgb(getAccent());}catch(e){}
    pts.forEach(p=>{ p.x+=p.vx; p.y+=p.vy; p.phase+=0.008; if(p.x<0)p.x=W; if(p.x>W)p.x=0; if(p.y<0)p.y=H; if(p.y>H)p.y=0; });
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y, d=Math.sqrt(dx*dx+dy*dy);
        if(d<130){ ctx.beginPath(); ctx.moveTo(pts[i].x,pts[i].y); ctx.lineTo(pts[j].x,pts[j].y); ctx.strokeStyle=`rgba(${rgb[0]},${rgb[1]},${rgb[2]},${(1-d/130)*0.07})`; ctx.lineWidth=0.5; ctx.stroke(); }
      }
      const a=0.12+0.06*Math.sin(pts[i].phase);
      ctx.beginPath(); ctx.arc(pts[i].x,pts[i].y,pts[i].r,0,Math.PI*2);
      ctx.fillStyle=`rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a})`; ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// Matrix digital rain
(function(){
  const canvas = document.getElementById('bg-matrix-rain');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H;
  const CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノABCDEF0123456789';
  let columns = [], drops = [];
  const FONT_SIZE = 14;

  function init(){
    W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight;
    columns = Math.floor(W/FONT_SIZE);
    drops = Array(columns).fill(1).map(()=>Math.random()*-100);
  }
  init(); window.addEventListener('resize', init);

  function hexToRgb(hex){ hex=(hex||'#00ff41').trim().replace('#',''); if(hex.length===3)hex=hex.split('').map(c=>c+c).join(''); const n=parseInt(hex,16); return[(n>>16)&255,(n>>8)&255,n&255]; }
  function getMatrixColor(){ return (getComputedStyle(document.body).getPropertyValue('--cyan')||'#00ff41').trim(); }

  function draw(){
    const [r,g,b] = hexToRgb(getMatrixColor());
    ctx.fillStyle='rgba(0,0,0,0.05)'; ctx.fillRect(0,0,W,H);
    ctx.font=FONT_SIZE+'px "Share Tech Mono",monospace';
    drops.forEach((y,i)=>{
      const ch = CHARS[Math.floor(Math.random()*CHARS.length)];
      const bright = Math.random()>0.95;
      ctx.fillStyle = bright ? `rgba(255,255,255,0.9)` : `rgba(${r},${g},${b},0.85)`;
      ctx.fillText(ch, i*FONT_SIZE, y*FONT_SIZE);
      if(y*FONT_SIZE>H && Math.random()>0.975) drops[i]=0;
      drops[i]+=0.5;
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

function updateBgEffects(){
  // Pulse rings color update happens via CSS var
  // Shapes border color via CSS var
  // Matrix rain visibility handled by CSS class
}

// ══════════════════════════════════
//  SCROLL HEADER
// ══════════════════════════════════
window.addEventListener('scroll',()=>{ document.querySelector('header').classList.toggle('scrolled',window.scrollY>10); });

// ══════════════════════════════════
//  STAT COUNTER
// ══════════════════════════════════
function animateCount(el, target){
  if(isNaN(target))return;
  let startT=null, dur=1200;
  function step(ts){ if(!startT)startT=ts; const p=Math.min((ts-startT)/dur,1); const ease=1-Math.pow(1-p,3); el.textContent=Math.floor(ease*target); el.classList.add('loaded'); if(p<1)requestAnimationFrame(step); }
  requestAnimationFrame(step);
}

const SEV={CRITICAL:{c:"#ff3366",b:"rgba(255,51,102,0.12)",i:"☢"},HIGH:{c:"#ff6b35",b:"rgba(255,107,53,0.12)",i:"⚠"},MEDIUM:{c:"#ffd60a",b:"rgba(255,214,10,0.1)",i:"⚡"},LOW:{c:"#00ff9d",b:"rgba(0,255,157,0.08)",i:"✓"},UNKNOWN:{c:"#5a5a8a",b:"rgba(90,90,138,0.1)",i:"?"}};
const GC={"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"};
const mods={ports:true,ssl:true,dns:true,headers:true};
let busy=false,logEl=null,progT=null,progV=0,currentUser=null;

function authTab(t){document.querySelectorAll(".auth-tab").forEach(e=>e.classList.remove("active"));document.querySelectorAll("[id^='form-']").forEach(e=>e.style.display="none");event.currentTarget.classList.add("active");document.getElementById("form-"+t).style.display="block";document.getElementById("auth-msg").style.display="none";}
function authMsg(msg,type="err"){const el=document.getElementById("auth-msg");el.textContent=msg;el.className="auth-msg "+type;el.style.display="block";}

async function doLogin(){const user=document.getElementById("l-user").value.trim();const pass=document.getElementById("l-pass").value;if(!user||!pass){authMsg("Enter username and password");return;}const btn=document.getElementById("l-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>LOGGING IN...';try{const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,password:pass})});const d=await r.json();if(d.success){authMsg("Welcome back, "+d.username+"!","ok");setTimeout(()=>{document.getElementById("auth-overlay").style.display="none";loadUser();},800);}else authMsg(d.error||"Login failed");}catch(e){authMsg("Connection error: "+e.message);}finally{btn.disabled=false;btn.innerHTML="LOGIN";}}
async function doRegister(){const name=document.getElementById("r-name").value.trim();const user=document.getElementById("r-user").value.trim();const email=document.getElementById("r-email").value.trim();const pass=document.getElementById("r-pass").value;if(!user||!email||!pass){authMsg("All fields required");return;}const btn=document.getElementById("r-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>CREATING...';try{const r=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,email,password:pass,full_name:name})});const d=await r.json();if(d.success){authMsg(d.message,"ok");if(d.verified)setTimeout(()=>{authTab('login');},2000);}else authMsg(d.error||"Registration failed");}catch(e){authMsg("Error: "+e.message);}finally{btn.disabled=false;btn.innerHTML="CREATE ACCOUNT";}}
async function doForgot(){const email=document.getElementById("f-email").value.trim();if(!email){authMsg("Enter your email");return;}try{const r=await fetch("/api/forgot-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email})});const d=await r.json();authMsg(d.message||d.error,(d.success?"ok":"err"));}catch(e){authMsg("Error: "+e.message);}}
async function doLogout(){await fetch("/api/logout",{method:"POST"});currentUser=null;document.getElementById("auth-overlay").style.display="flex";document.getElementById("user-chip").style.display="none";document.getElementById("logout-btn").style.display="none";document.querySelectorAll(".admin-only").forEach(e=>e.style.display="none");document.getElementById("l-user").value="";document.getElementById("l-pass").value="";authTab("login");}

async function loadUser(){try{const r=await fetch("/api/me");const d=await r.json();if(d.logged_in){currentUser=d;document.getElementById("auth-overlay").style.display="none";document.getElementById("user-chip").style.display="flex";document.getElementById("logout-btn").style.display="block";document.getElementById("user-avatar").textContent=d.username[0].toUpperCase();document.getElementById("user-name-disp").textContent=d.username;document.getElementById("user-role-disp").textContent=d.role==="admin"?"★ ADMIN":"USER";if(d.role==="admin")document.querySelectorAll(".admin-only").forEach(e=>e.style.display="block");loadProfileInfo(d);loadHomeStats();}else{document.getElementById("auth-overlay").style.display="flex";}}catch(e){document.getElementById("auth-overlay").style.display="flex";}}

function loadProfileInfo(u){if(!u)return;document.getElementById("p-name").value=u.full_name||"";document.getElementById("profile-info").innerHTML=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-family:var(--font-mono);font-size:12px"><div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">USERNAME</div><div style="color:var(--cyan)">${u.username}</div></div><div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">ROLE</div><div style="color:${u.role==='admin'?'var(--yellow)':'var(--t)'}">${u.role==='admin'?'★ ADMIN':'USER'}</div></div><div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">EMAIL</div><div>${u.email}</div></div><div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">LOGINS</div><div>${u.login_count||0}</div></div><div style="background:var(--s2);border-radius:6px;padding:10px;grid-column:span 2"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">LAST LOGIN</div><div style="color:var(--m)">${u.last_login||'First login'}</div></div></div>`;}

async function saveProfile(){const name=document.getElementById("p-name").value.trim();try{const r=await fetch("/api/profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({full_name:name})});const d=await r.json();showPwdMsg(d.message||d.error,d.success?"ok":"err");}catch(e){showPwdMsg("Error: "+e.message,"err");}}
async function changePassword(){const old=document.getElementById("cp-old").value;const n=document.getElementById("cp-new").value;const c=document.getElementById("cp-confirm").value;if(n!==c){showPwdMsg("New passwords do not match","err");return;}try{const r=await fetch("/api/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({old_password:old,new_password:n})});const d=await r.json();showPwdMsg(d.message||d.error,d.success?"ok":"err");if(d.success){document.getElementById("cp-old").value="";document.getElementById("cp-new").value="";document.getElementById("cp-confirm").value="";}}catch(e){showPwdMsg("Error: "+e.message,"err");}}
function showPwdMsg(msg,type){const el=document.getElementById("pwd-msg");el.textContent=msg;el.className="auth-msg "+type;el.style.display="block";}

function pg(id,el){document.querySelectorAll(".page").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nb").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nav-dropdown-item").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nav-dropdown-btn").forEach(e=>e.classList.remove("active"));document.getElementById("page-"+id).classList.add("active");if(el)el.classList.add("active");if(id==="hist")loadHist();if(id==="dash")loadDash();if(id==="admin")loadAdmin();if(id==="home")loadHomeStats();if(id==="profile"&&currentUser){loadProfileInfo(currentUser);buildThemeDropdown();}}
function pgFromDd(id,ddId){document.querySelectorAll(".page").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nb").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nav-dropdown-item").forEach(e=>e.classList.remove("active"));document.querySelectorAll(".nav-dropdown-btn").forEach(e=>e.classList.remove("active"));document.getElementById("page-"+id).classList.add("active");const item=document.getElementById("dd-item-"+id);if(item)item.classList.add("active");const btn=document.getElementById("dd-"+ddId+"-btn");if(btn)btn.classList.add("active");if(id==="hist")loadHist();if(id==="dash")loadDash();}

async function loadHomeStats(){try{const r=await fetch("/history");const d=await r.json();const scans=d.scans||d||[];let totalCves=0,totalPorts=0;(Array.isArray(scans)?scans:[]).forEach(s=>{totalCves+=(s.total_cves||0);totalPorts+=(s.open_ports||0);});animateCount(document.getElementById("hs-scans"),(Array.isArray(scans)?scans:[]).length);animateCount(document.getElementById("hs-cves"),totalCves);animateCount(document.getElementById("hs-ports"),totalPorts);}catch(e){["hs-scans","hs-cves","hs-ports"].forEach(id=>{const el=document.getElementById(id);if(el)el.textContent="0";});}}

// Tool runners
let hvLogEl=null,hvProgT=null,hvProgV=0;
function hvLog(t,tp="i"){if(!hvLogEl)return;const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="tl t"+tp;d.innerHTML="<span class='p'>"+p+"</span> "+t;hvLogEl.appendChild(d);hvLogEl.scrollTop=hvLogEl.scrollHeight;}
function hvStartProg(){hvProgV=0;document.getElementById("hv-prog").style.display="block";document.getElementById("hv-pb").style.width="0%";hvProgT=setInterval(()=>{hvProgV=Math.min(hvProgV+(100-hvProgV)*0.035,90);document.getElementById("hv-pb").style.width=hvProgV+"%";},500);}
function hvEndProg(){clearInterval(hvProgT);document.getElementById("hv-pb").style.width="100%";setTimeout(()=>document.getElementById("hv-prog").style.display="none",400);}
async function doHarvest(){const target=document.getElementById("hv-target").value.trim();if(!target){alert("Please enter a target domain");return;}const srcEl=document.getElementById("hv-sources");const sources=Array.from(srcEl.selectedOptions).map(o=>o.value).join(",");const limit=document.getElementById("hv-limit").value||500;const btn=document.getElementById("hv-btn");btn.disabled=true;btn.textContent="Running...";hvLogEl=document.getElementById("hv-term");hvLogEl.innerHTML="";hvLogEl.style.display="block";document.getElementById("hv-err").style.display="none";document.getElementById("hv-res").style.display="none";hvStartProg();hvLog("Target: "+target);hvLog("Sources: "+sources);hvLog("Launching theHarvester...","w");try{const r=await fetchWithTimeout("/harvester",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,sources,limit:parseInt(limit)})},180000);const d=await r.json();hvEndProg();if(d.error){document.getElementById("hv-err").textContent="Error: "+d.error;document.getElementById("hv-err").style.display="block";hvLog(d.error,"e");}else{hvLog("Done — "+(d.emails?.length||0)+" emails, "+(d.hosts?.length||0)+" hosts","s");renderHarvest(d);}}catch(e){hvEndProg();document.getElementById("hv-err").textContent="Error: "+e.message;document.getElementById("hv-err").style.display="block";hvLog(e.message,"e");}finally{btn.disabled=false;btn.textContent="🎯 RUN HARVESTER";}}
function renderHarvest(d){const res=document.getElementById("hv-res");res.style.display="block";const emails=d.emails||[];const hosts=d.hosts||[];const subs=d.subdomains||[];const ips=d.ips||[];let html=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px"><div class="sc"><div class="sv" style="color:var(--cyan)">${emails.length}</div><div class="sl">EMAILS</div></div><div class="sc"><div class="sv" style="color:var(--purple)">${hosts.length}</div><div class="sl">HOSTS</div></div><div class="sc"><div class="sv" style="color:var(--green)">${subs.length}</div><div class="sl">SUBDOMAINS</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${ips.length}</div><div class="sl">IPs FOUND</div></div></div>`;if(emails.length){html+=`<div class="card" style="margin-bottom:12px"><div class="ctitle">EMAILS (${emails.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${emails.map(e=>`<span class="tag" style="background:rgba(0,229,255,0.08);color:var(--cyan);border-color:rgba(0,229,255,0.2)">${e}</span>`).join("")}</div></div>`;}if(subs.length){html+=`<div class="card" style="margin-bottom:12px"><div class="ctitle">SUBDOMAINS (${subs.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${subs.map(s=>`<span class="tag" style="background:rgba(176,111,255,0.08);color:var(--purple);border-color:rgba(176,111,255,0.2)">${s}</span>`).join("")}</div></div>`;}res.innerHTML=html;}

function mkToolRunner(prefix,color){let logEl=null,progT=null,progV=0;return{log(t,tp="i"){if(!logEl)return;const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="tl t"+tp;d.style.color=tp==="s"?"var(--green)":tp==="e"?"var(--red)":tp==="w"?"var(--yellow)":"#4a4a7a";d.innerHTML=`<span style="color:var(--cyan)">${p}</span> `+t;logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight;},start(){progV=0;logEl=document.getElementById(prefix+"-term");logEl.innerHTML="";logEl.style.display="block";document.getElementById(prefix+"-err").style.display="none";document.getElementById(prefix+"-res").style.display="none";document.getElementById(prefix+"-prog").style.display="block";document.getElementById(prefix+"-pb").style.width="0%";progT=setInterval(()=>{progV=Math.min(progV+(100-progV)*0.035,90);document.getElementById(prefix+"-pb").style.width=progV+"%";},500);},end(){clearInterval(progT);document.getElementById(prefix+"-pb").style.width="100%";setTimeout(()=>document.getElementById(prefix+"-prog").style.display="none",400);},err(msg){document.getElementById(prefix+"-err").textContent="Error: "+msg;document.getElementById(prefix+"-err").style.display="block";},res(html){const el=document.getElementById(prefix+"-res");el.innerHTML=html;el.style.display="block";}};}

const drTool=mkToolRunner("dr");
async function doDnsRecon(){const target=document.getElementById("dr-target").value.trim();if(!target){alert("Enter a target domain");return;}const type=document.getElementById("dr-type").value;const ns=document.getElementById("dr-ns").value.trim();const filter=document.getElementById("dr-filter").value;const btn=document.getElementById("dr-btn");btn.disabled=true;btn.textContent="Running...";drTool.start();drTool.log("Target: "+target);drTool.log("Type: "+type);try{const r=await fetchWithTimeout("/dnsrecon",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,type,ns,filter})},120000);const d=await r.json();drTool.end();if(d.error){drTool.err(d.error);}else{drTool.log("Done — "+(d.records?.length||0)+" records","s");renderDnsRecon(d);}}catch(e){drTool.end();drTool.err(e.message);}finally{btn.disabled=false;btn.textContent="🌐 RUN DNSRECON";}}
function renderDnsRecon(d){const recs=d.records||[];const byType={};recs.forEach(r=>{if(!byType[r.type])byType[r.type]=[];byType[r.type].push(r);});let html=`<div class="sc" style="margin-bottom:16px"><div class="sv" style="color:var(--cyan)">${recs.length}</div><div class="sl">RECORDS FOUND</div></div>`;Object.entries(byType).forEach(([type,items])=>{html+=`<div class="card" style="margin-bottom:10px"><div class="ctitle" style="color:var(--cyan)">${type} RECORDS (${items.length})</div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>NAME</th><th>VALUE</th><th>TTL</th></tr></thead><tbody>`;items.forEach(r=>{html+=`<tr><td>${r.name||"—"}</td><td style="color:var(--t)">${r.address||r.value||r.data||"—"}</td><td style="color:var(--m)">${r.ttl||"—"}</td></tr>`;});html+=`</tbody></table></div></div>`;});drTool.res(html);}

const nkTool=mkToolRunner("nk");
async function doNikto(){const target=document.getElementById("nk-target").value.trim();if(!target){alert("Enter a target URL or host");return;}const port=document.getElementById("nk-port").value||80;const ssl=document.getElementById("nk-ssl").value;const tuning=document.getElementById("nk-tuning").value;const btn=document.getElementById("nk-btn");btn.disabled=true;btn.textContent="Scanning...";nkTool.start();nkTool.log("Target: "+target+" port "+port);nkTool.log("Nikto scan started","w");try{const r=await fetchWithTimeout("/nikto",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,port:parseInt(port),ssl,tuning})},600000);const d=await r.json();nkTool.end();if(d.error){nkTool.err(d.error);}else{nkTool.log("Done — "+(d.findings?.length||0)+" findings","s");renderNikto(d);}}catch(e){nkTool.end();nkTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📈 RUN NIKTO";}}
function renderNikto(d){const findings=d.findings||[];const crit=findings.filter(f=>f.severity==="high").length;let html=`<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px"><div class="sc"><div class="sv" style="color:var(--orange)">${findings.length}</div><div class="sl">FINDINGS</div></div><div class="sc"><div class="sv" style="color:var(--red)">${crit}</div><div class="sl">HIGH</div></div><div class="sc"><div class="sv" style="color:var(--green)">${d.server||"—"}</div><div class="sl">SERVER</div></div></div>`;if(findings.length){html+=`<div class="card"><div class="ctitle">FINDINGS</div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>ID</th><th>DESCRIPTION</th><th>URL</th></tr></thead><tbody>`;findings.forEach(f=>{html+=`<tr><td style="color:var(--cyan);white-space:nowrap">${f.id||"—"}</td><td style="color:${f.severity==="high"?"var(--red)":f.severity==="medium"?"var(--orange)":"var(--t)"}">${f.description||f.msg||"—"}</td><td style="color:var(--m);font-size:10px">${f.url||""}</td></tr>`;});html+=`</tbody></table></div></div>`;}else{html+=`<div class="card"><p style="color:var(--green)">✓ No findings detected.</p></div>`;}nkTool.res(html);}

const wpTool=mkToolRunner("wp");
async function doWPScan(){const target=document.getElementById("wp-target").value.trim();if(!target){alert("Enter a target URL");return;}const enumEl=document.getElementById("wp-enum");const enumFlags=Array.from(enumEl.selectedOptions).map(o=>o.value).join(",");const token=document.getElementById("wp-token").value.trim();const mode=document.getElementById("wp-mode").value;const btn=document.getElementById("wp-btn");btn.disabled=true;btn.textContent="Scanning...";wpTool.start();wpTool.log("Target: "+target);try{const r=await fetchWithTimeout("/wpscan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,enum_flags:enumFlags,token,mode})},300000);const d=await r.json();wpTool.end();if(d.error){wpTool.err(d.error);}else{wpTool.log("Done","s");renderWPScan(d);}}catch(e){wpTool.end();wpTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📄 RUN WPSCAN";}}
function renderWPScan(d){const vulns=d.vulnerabilities||[];const users=d.users||[];const plugins=d.plugins||[];let html=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px"><div class="sc"><div class="sv" style="color:var(--red)">${vulns.length}</div><div class="sl">VULNS</div></div><div class="sc"><div class="sv" style="color:var(--purple)">${plugins.length}</div><div class="sl">PLUGINS</div></div><div class="sc"><div class="sv" style="color:var(--cyan)">${users.length}</div><div class="sl">USERS</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${d.wp_version||"?"}</div><div class="sl">VERSION</div></div></div>`;if(vulns.length){html+=`<div class="card" style="margin-bottom:10px"><div class="ctitle" style="color:var(--red)">VULNERABILITIES</div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>TITLE</th><th>TYPE</th><th>REF</th></tr></thead><tbody>${vulns.map(v=>`<tr><td style="color:var(--red)">${v.title||v.name||"—"}</td><td style="color:var(--orange)">${v.type||"—"}</td><td style="color:var(--cyan);font-size:10px">${v.references?.cve?.join(", ")||v.ref||"—"}</td></tr>`).join("")}</tbody></table></div></div>`;}if(users.length){html+=`<div class="card"><div class="ctitle" style="color:var(--cyan)">USERS</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${users.map(u=>`<span class="tag" style="background:rgba(0,229,255,0.08);color:var(--cyan);border-color:rgba(0,229,255,0.2)">${u}</span>`).join("")}</div></div>`;}wpTool.res(html);}

const lyTool=mkToolRunner("ly");
async function doLynis(){const profile=document.getElementById("ly-profile").value;const category=document.getElementById("ly-category").value;const compliance=document.getElementById("ly-compliance").value;const btn=document.getElementById("ly-btn");btn.disabled=true;btn.textContent="Auditing...";lyTool.start();lyTool.log("Lynis audit starting...");lyTool.log("Profile: "+profile,"w");try{const r=await fetchWithTimeout("/lynis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({profile,category,compliance})},300000);const d=await r.json();lyTool.end();if(d.error){lyTool.err(d.error);}else{lyTool.log("Done — Hardening Index: "+(d.hardening_index||"?"),d.hardening_index>=70?"s":"w");renderLynis(d);}}catch(e){lyTool.end();lyTool.err(e.message);}finally{btn.disabled=false;btn.textContent="📋 RUN LYNIS AUDIT";}}
function renderLynis(d){const warnings=d.warnings||[];const suggestions=d.suggestions||[];const score=d.hardening_index||0;const scoreColor=score>=80?"var(--green)":score>=60?"var(--yellow)":score>=40?"var(--orange)":"var(--red)";let html=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px"><div class="sc"><div class="sv" style="color:${scoreColor}">${score}</div><div class="sl">HARDENING INDEX</div></div><div class="sc"><div class="sv" style="color:var(--red)">${warnings.length}</div><div class="sl">WARNINGS</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${suggestions.length}</div><div class="sl">SUGGESTIONS</div></div><div class="sc"><div class="sv" style="color:var(--cyan)">${d.tests_performed||"—"}</div><div class="sl">TESTS RUN</div></div></div>`;if(warnings.length){html+=`<div class="card" style="margin-bottom:10px"><div class="ctitle" style="color:var(--red)">⚠ WARNINGS</div>${warnings.map(w=>`<div style="border-bottom:1px solid var(--b);padding:8px 0;font-size:12px;color:var(--orange);font-family:var(--font-mono)">${w}</div>`).join("")}</div>`;}if(suggestions.length){html+=`<div class="card"><div class="ctitle" style="color:var(--yellow)">💡 SUGGESTIONS (${suggestions.length})</div>${suggestions.slice(0,30).map(s=>`<div style="border-bottom:1px solid var(--b);padding:7px 0;font-size:11px;color:var(--m);font-family:var(--font-mono)">› ${s}</div>`).join("")}${suggestions.length>30?`<div style="color:var(--m);font-size:11px;padding-top:8px">...and ${suggestions.length-30} more</div>`:""}</div>`;}lyTool.res(html);}

const lgMods={"nmap":true,"nikto":true,"smb":true,"snmp":true,"hydra":false,"finger":false};
function lgMod(m,el){lgMods[m]=!lgMods[m];el.classList.toggle("on",lgMods[m]);}
const lgTool=mkToolRunner("lg");
async function doLegion(){const target=document.getElementById("lg-target").value.trim();if(!target){alert("Enter a target host or IP");return;}const intensity=document.getElementById("lg-intensity").value;const modules=Object.entries(lgMods).filter(([,v])=>v).map(([k])=>k);const btn=document.getElementById("lg-btn");btn.disabled=true;btn.textContent="Running...";lgTool.start();lgTool.log("Target: "+target);lgTool.log("Modules: "+modules.join(", "));lgTool.log("Intensity: "+intensity,"w");try{const r=await fetchWithTimeout("/legion",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,intensity,modules})},900000);const d=await r.json();lgTool.end();if(d.error){lgTool.err(d.error);}else{lgTool.log("Legion scan complete","s");renderLegion(d);}}catch(e){lgTool.end();lgTool.err(e.message);}finally{btn.disabled=false;btn.textContent="⚙ RUN LEGION";}}
function renderLegion(d){let html=`<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px"><div class="sc"><div class="sv" style="color:var(--cyan)">${d.open_ports||0}</div><div class="sl">OPEN PORTS</div></div><div class="sc"><div class="sv" style="color:var(--red)">${d.total_issues||0}</div><div class="sl">ISSUES</div></div><div class="sc"><div class="sv" style="color:var(--green)">${d.modules_run||0}</div><div class="sl">MODULES</div></div></div>`;(d.results||[]).forEach(r=>{html+=`<div class="card" style="margin-bottom:10px"><div class="ctitle" style="color:var(--orange)">⚙ ${r.module?.toUpperCase()||"MODULE"}</div>`;if(r.findings?.length){html+=`<div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>FINDING</th><th>DETAIL</th></tr></thead><tbody>${r.findings.map(f=>`<tr><td style="color:var(--t)">${f.title||f}</td><td style="color:var(--m);font-size:10px">${f.detail||""}</td></tr>`).join("")}</tbody></table></div>`;}else{html+=`<p style="color:var(--m);font-size:12px;font-family:var(--font-mono)">${r.summary||"No findings"}</p>`;}html+=`</div>`;});lgTool.res(html);}

function tmg(m,el){mods[m]=!mods[m];el.classList.toggle("on",mods[m]);}
function initLog(){logEl=document.getElementById("term");logEl.innerHTML="";logEl.style.display="block";}
function lg(t,tp="i"){if(!logEl)return;const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="tl t"+tp;d.innerHTML="<span class='p'>"+p+"</span> "+t;logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight;}
function clrUI(){["term","err","res"].forEach(id=>{const e=document.getElementById(id);if(e){e.innerHTML="";e.style.display="none";}});document.getElementById("prog").style.display="none";}
function showErr(msg){const e=document.getElementById("err");e.textContent="Error: "+msg;e.style.display="block";}
function startProg(){progV=0;document.getElementById("prog").style.display="block";document.getElementById("pb").style.width="0%";progT=setInterval(()=>{progV=Math.min(progV+(100-progV)*0.04,92);document.getElementById("pb").style.width=progV+"%";},400);}
function endProg(){clearInterval(progT);document.getElementById("pb").style.width="100%";setTimeout(()=>document.getElementById("prog").style.display="none",400);}

async function fetchWithTimeout(url,options={},timeoutMs=300000){const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);try{const r=await fetch(url,{...options,signal:controller.signal});clearTimeout(timer);return r;}catch(e){clearTimeout(timer);if(e.name==='AbortError')throw new Error('Request timed out after '+Math.round(timeoutMs/1000)+'s.');throw e;}}

async function doScan(){const target=document.getElementById("tgt").value.trim();if(!target||busy)return;clrUI();busy=true;initLog();startProg();const btn=document.getElementById("sbtn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';const ml=Object.keys(mods).filter(m=>mods[m]).join(",");lg("Target: "+target);lg("Modules: "+ml);lg("Scanning — may take 60–180 seconds","w");try{const r=await fetchWithTimeout("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(ml),{},300000);const d=await r.json();endProg();if(d.error){showErr(d.error);lg(d.error,"e");}else{lg("Done — "+(d.summary?.open_ports||0)+" ports, "+(d.summary?.total_cves||0)+" CVEs","s");renderScan(d);}}catch(e){endProg();showErr(e.message);}finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}}

function renderScan(data){const s=data.summary||{};const ports=(data.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);let html=`<div class="sgrid"><div class="sc"><div class="sv" style="color:var(--cyan)">${ports.length}</div><div class="sl">OPEN PORTS</div></div><div class="sc"><div class="sv" style="color:var(--red)">${s.critical_cves||0}</div><div class="sl">CRITICAL</div></div><div class="sc"><div class="sv" style="color:var(--orange)">${s.high_cves||0}</div><div class="sl">HIGH CVEs</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${s.total_cves||0}</div><div class="sl">TOTAL CVEs</div></div><div class="sc"><div class="sv" style="color:var(--purple)">${s.exploitable||0}</div><div class="sl">EXPLOITABLE</div></div></div>`;
html+=`<div class="tabs"><button class="tab active" onclick="swt(event,'tp')">&#128268; Ports</button>${data.modules?.ssl?.length?'<button class="tab" onclick="swt(event,\'tssl\')">&#128274; SSL</button>':""}${data.modules?.dns?'<button class="tab" onclick="swt(event,\'tdns\')">&#127758; DNS</button>':""}${data.modules?.headers?'<button class="tab" onclick="swt(event,\'thdr\')">&#128196; Headers</button>':""}` +
`<button class="tab" onclick="exportPDF()">&#128196; PDF Report</button></div>`;
html+=`<div class="tc active" id="tp">`;
const pm=data.modules?.ports;
if(pm?.error){html+=`<div style="background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-family:var(--font-mono);font-size:13px">⚠ Port scan error: ${pm.error}<br><br>Install nmap: <b>sudo apt-get install nmap dnsutils</b></div>`;}
else{(pm?.hosts||[]).forEach(host=>{html+=`<div style="display:flex;align-items:center;gap:9px;margin-bottom:12px;flex-wrap:wrap"><span style="color:var(--cyan);background:rgba(0,229,255,0.07);padding:3px 11px;border-radius:4px;border:1px solid rgba(0,229,255,0.18);font-family:var(--font-mono);font-size:12px">${host.ip||""}</span>${host.hostnames?.[0]?`<span style="color:var(--m);font-size:12px;font-family:var(--font-mono)">${host.hostnames[0]}</span>`:""}<span style="color:var(--green);font-size:12px">● ${host.status||"up"}</span>${host.os?`<span style="color:var(--m);font-size:11px;font-family:var(--font-mono)">OS: ${host.os}</span>`:""}</div>`;
if(!host.ports||host.ports.length===0){html+=`<p style="color:var(--m);font-size:13px;font-family:var(--font-mono)">No open ports found.</p>`;}
host.ports.forEach(port=>{const sv=SEV[port.risk_level]||SEV.UNKNOWN;const hx=port.cves?.some(c=>c.has_exploit);
html+=`<div class="pc" style="border:1px solid ${sv.c}22;border-left:3px solid ${sv.c}"><div class="ph" onclick="tp2(this)"><div class="pn" style="background:${sv.b};color:${sv.c}">${port.port}</div><div class="pi"><div class="pname">${port.product||port.service||"unknown"}${port.version?` <span style="color:var(--m);font-size:12px;font-weight:400">v${port.version}</span>`:""}</div><div class="psub">${(port.protocol||"tcp").toUpperCase()} · ${port.service||""}${port.extrainfo?" · "+port.extrainfo:""}</div></div><div class="pm">${hx?'<span class="bdg" style="background:rgba(176,111,255,0.12);color:#b06fff;border-color:rgba(176,111,255,0.3);font-size:10px">☠ EXPLOIT</span>':""}${bdg(port.risk_level)}${port.risk_score?`<span style="color:${sv.c};font-weight:800;font-size:14px;font-family:var(--font-mono)">${port.risk_score}</span>`:""}<span class="chev">▼</span></div></div>
<div class="pb2">${port.cves?.length?`<div class="st">VULNERABILITIES (${port.cves.length})</div>${port.cves.map(c=>{const cs=SEV[c.severity]||SEV.UNKNOWN;return`<div class="ci"><div class="ct"><a class="cid" href="${c.references?.[0]||"https://nvd.nist.gov/vuln/detail/"+c.id}" target="_blank">${c.id}</a>${bdg(c.severity,true)}${c.score?`<span style="color:${cs.c};font-weight:700;font-size:11px;font-family:var(--font-mono)">CVSS ${c.score}</span>`:""}${c.has_exploit?'<span class="bdg btn-sm" style="background:rgba(176,111,255,0.1);color:#b06fff;border-color:rgba(176,111,255,0.25)">☠ EXPLOIT</span>':""}<span class="cdate">${c.published||""}</span></div><div class="cdesc">${c.description||""}</div></div>`;}).join("")}`:""}${port.mitigations?.length?`<div class="st">MITIGATIONS</div><div class="ml">${port.mitigations.map(m=>`<div class="mi"><span class="ma">›</span><span>${m}</span></div>`).join("")}</div>`:""}</div></div>`;});});
if(!pm?.hosts?.length){html+=`<p style="color:var(--m);font-size:13px;font-family:var(--font-mono)">⚠ No hosts found. Target may be offline or blocking scans.</p>`;}}
html+=`</div>`;
if(data.modules?.ssl?.length){html+=`<div class="tc" id="tssl">`;data.modules.ssl.forEach(s=>{const gc2=GC[s.grade]||"#ff3366";const d=s.details||{};if(s.grade==="N/A"){html+=`<div class="ssl-card"><p style="color:var(--m);font-size:13px">SSL not available on ${s.host}:${s.port}</p></div>`;return;}html+=`<div class="ssl-card"><div class="ssl-hdr"><div class="gc2" style="background:${gc2}15;color:${gc2};border:2px solid ${gc2}35">${s.grade}</div><div><div style="font-weight:700;font-size:14px">${s.host}:${s.port}</div><div style="color:var(--m);font-size:12px;font-family:var(--font-mono);margin-top:3px">${d.protocol||"?"} · ${d.cipher||"?"} ${d.cipher_bits?"("+d.cipher_bits+" bit)":""}</div>${d.days_until_expiry!=null?`<div style="color:${d.days_until_expiry<30?"var(--red)":"var(--green)"};font-size:11px;font-family:var(--font-mono);margin-top:3px">Expires: ${d.expires||""} (${d.days_until_expiry} days)</div>`:""}</div></div>${s.issues?.filter(i=>i.severity!=="INFO").length?s.issues.filter(i=>i.severity!=="INFO").map(iss=>`<div class="iss-item">${bdg(iss.severity,true)}<span style="font-size:12px;color:#c0c0d0;margin-left:6px">${iss.msg}</span></div>`).join(""):"<p style='color:var(--green);font-size:12px'>✓ No SSL issues</p>"}</div>`;});html+=`</div>`;}
if(data.modules?.dns){const dns=data.modules.dns;html+=`<div class="tc" id="tdns"><div class="dns-grid">${Object.entries(dns.records||{}).map(([t,v])=>`<div class="dr"><div class="dtype">${t}</div><div class="dval">${v.join("<br/>")}</div></div>`).join("")}</div><div class="card" style="padding:12px;margin-bottom:12px"><div style="display:flex;gap:14px;flex-wrap:wrap"><span style="font-size:13px">${dns.has_spf?"✅":"❌"} SPF ${dns.has_spf?"configured":"MISSING"}</span><span style="font-size:13px">${dns.has_dmarc?"✅":"❌"} DMARC ${dns.has_dmarc?"configured":"MISSING"}</span></div></div>${dns.subdomains?.length?`<div class="st" style="margin-bottom:8px">SUBDOMAINS (${dns.subdomains.length})</div>${dns.subdomains.map(s=>`<div class="sub-item"><span>${s.subdomain}</span><span style="color:var(--m)">${s.ip}</span></div>`).join("")}`:""}</div>`;}
if(data.modules?.headers){const hd=data.modules.headers;const gc2=GC[hd.grade]||"#ff3366";html+=`<div class="tc" id="thdr"><div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;flex-wrap:wrap"><div class="hdr-grade" style="color:${gc2}">${hd.grade}</div><div><div style="font-size:14px;font-weight:600">${hd.url||""}</div><div style="color:var(--m);font-size:12px;font-family:var(--font-mono);margin-top:3px">HTTP ${hd.status_code||""} · Score ${hd.score||0}/100${hd.server?" · "+hd.server:""}</div></div></div>${hd.issues?.length?`<div class="st" style="margin-bottom:8px">ISSUES</div><div class="ml" style="margin-bottom:14px">${hd.issues.map(i=>`<div class="iss-item">${bdg(i.severity,true)}<span style="margin-left:7px;font-size:12px">${i.msg}</span></div>`).join("")}</div>`:""}<div class="st" style="margin-bottom:8px">RESPONSE HEADERS</div><div class="hl">${Object.entries(hd.headers||{}).slice(0,25).map(([k,v])=>`<div class="hi"><span class="hk">${k}</span><span class="hv">${String(v).substring(0,100)}</span></div>`).join("")}</div></div>`;}
const r=document.getElementById("res");r.innerHTML=html;r.style.display="block";window._sd=data;}

function bdg(lv,sm=false){const s=SEV[lv]||SEV.UNKNOWN;return`<span class="bdg${sm?" btn-sm":""}" style="background:${s.b};color:${s.c};border-color:${s.c}40">${s.i} ${lv}</span>`;}
function tag(t,c){return`<span class="tag" style="background:${c}15;color:${c};border-color:${c}30">${t}</span>`;}
function statusCol(s){return s===200?"var(--green)":s<400?"var(--yellow)":"var(--orange)";}
function tp2(hdr){const b=hdr.nextElementSibling;const c=hdr.querySelector(".chev");b.classList.toggle("open");c.style.transform=b.classList.contains("open")?"rotate(180deg)":"none";}
function swt(e,id){const p=document.getElementById("res");p.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));p.querySelectorAll(".tc").forEach(t=>t.classList.remove("active"));e.currentTarget.classList.add("active");const tc=document.getElementById(id);if(tc)tc.classList.add("active");}

async function doSub(){const domain=document.getElementById("sub-domain").value.trim();const size=document.getElementById("sub-size").value;if(!domain)return;const btn=document.getElementById("sub-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating subdomains for <b style="color:var(--cyan)">${domain}</b>...</p></div>`;try{const r=await fetchWithTimeout("/subdomains?domain="+encodeURIComponent(domain)+"&size="+size,{},120000);const d=await r.json();if(d.error){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}document.getElementById("sub-res").innerHTML=`<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap"><span class="found-badge">${d.total} SUBDOMAINS FOUND</span><span style="color:var(--m);font-size:11px;font-family:var(--font-mono)">Sources: ${(d.sources||[]).join(", ")}</span></div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>SUBDOMAIN</th><th>IP ADDRESS</th><th>SOURCE</th><th>ACTION</th></tr></thead><tbody>${(d.subdomains||[]).map(s=>`<tr><td style="color:var(--cyan)">${s.subdomain}</td><td>${s.ip}</td><td>${tag(s.source||"dns",s.source==="crt.sh"?"#b06fff":s.source==="hackertarget"?"#00e5ff":"#00ff9d")}</td><td><button class="lbtn" onclick="scanFromSub('${s.subdomain}')">SCAN</button></td></tr>`).join("")}</tbody></table></div></div>`;}catch(e){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="FIND SUBDOMAINS";}}
function scanFromSub(d){document.getElementById("tgt").value=d;pg("scan",document.querySelector(".nb"));doScan();}

async function doDir(){const url=document.getElementById("dir-url").value.trim();const size=document.getElementById("dir-size").value;const ext=document.getElementById("dir-ext").value.trim();if(!url)return;const btn=document.getElementById("dir-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating directories on <b style="color:var(--cyan)">${url}</b>...</p></div>`;try{const r=await fetchWithTimeout("/dirbust?url="+encodeURIComponent(url)+"&size="+size+"&ext="+encodeURIComponent(ext),{},180000);const d=await r.json();if(d.error){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}document.getElementById("dir-res").innerHTML=`<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap"><span class="found-badge">${d.total} PATHS FOUND</span><span style="color:var(--m);font-size:11px;font-family:var(--font-mono)">${d.scanned} scanned · ${d.errors} errors</span></div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>URL</th><th>STATUS</th><th>SIZE</th><th>SEVERITY</th><th>NOTE</th></tr></thead><tbody>${(d.found||[]).map(f=>`<tr><td><a href="${f.url}" target="_blank" style="color:var(--cyan);text-decoration:none;font-size:11px">${f.url}</a></td><td style="color:${statusCol(f.status)};font-weight:700">${f.status}</td><td style="color:var(--m)">${f.size||"?"}</td><td>${bdg(f.severity,true)}</td><td style="color:#8e8e93;font-size:11px">${f.note||""}</td></tr>`).join("")}</tbody></table></div></div>`;}catch(e){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="START ENUMERATION";}}

function bfTypeChange(){const t=document.getElementById("bf-type").value;document.getElementById("bf-http-fields").style.display=t==="http"?"block":"none";document.getElementById("bf-ssh-fields").style.display=t==="ssh"?"block":"none";}
async function doBrute(){const type=document.getElementById("bf-type").value;const users=document.getElementById("bf-users").value.split("\n").map(s=>s.trim()).filter(Boolean);const pwds=document.getElementById("bf-pwds").value.split("\n").map(s=>s.trim()).filter(Boolean);if(!users.length||!pwds.length){alert("Enter at least one username and password");return;}const btn=document.getElementById("bf-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>ATTACKING...';document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Running — ${users.length} users × ${pwds.length} passwords...</p></div>`;try{let url="/brute-http",body={users,passwords:pwds};if(type==="http"){body.url=document.getElementById("bf-url").value.trim();body.user_field=document.getElementById("bf-ufield").value||"username";body.pass_field=document.getElementById("bf-pfield").value||"password";}else{url="/brute-ssh";body.host=document.getElementById("bf-ssh-host").value.trim();body.port=document.getElementById("bf-ssh-port").value||"22";}const r=await fetchWithTimeout(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)},120000);const d=await r.json();const found=d.found||[];document.getElementById("bf-res").innerHTML=`<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:14px"><span class="found-badge">${found.length} CREDENTIALS FOUND</span><span style="color:var(--m);font-size:11px;font-family:var(--font-mono)">${d.attempts||0} attempts</span>${d.note?`<span style="color:var(--yellow);font-size:11px">${d.note}</span>`:""}</div>${found.length?`<table class="res-tbl"><thead><tr><th>USERNAME</th><th>PASSWORD</th><th>STATUS</th></tr></thead><tbody>${found.map(f=>`<tr><td style="color:var(--cyan)">${f.username}</td><td style="color:var(--red);font-weight:700">${f.password}</td><td style="color:var(--green)">✓ SUCCESS</td></tr>`).join("")}</tbody></table>`:`<p style="color:var(--green);font-size:13px">✓ No valid credentials found.</p>`}</div>`;}catch(e){document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="START BRUTE FORCE";}}

async function doDisc(){const subnet=document.getElementById("subnet").value.trim();if(!subnet)return;const btn=document.getElementById("disc-btn");btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--m)">Scanning subnet...</p></div>`;try{const r=await fetchWithTimeout("/discover?subnet="+encodeURIComponent(subnet),{},120000);const d=await r.json();if(d.error){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}document.getElementById("disc-res").innerHTML=`<div class="card"><div class="ctitle">${d.total||0} HOSTS FOUND</div><div class="hg">${(d.hosts||[]).map(h=>`<div class="ht" onclick="scanDisc('${h.ip}')"><div class="hip">${h.ip}</div>${h.hostnames?.[0]?`<div style="color:var(--m);font-size:11px;font-family:var(--font-mono);margin-top:3px">${h.hostnames[0]}</div>`:""}${h.vendor?`<div style="color:#636366;font-size:10px;margin-top:2px">${h.vendor}</div>`:""}<div style="color:var(--m);font-size:10px;font-family:var(--font-mono);margin-top:7px">Click to scan ›</div></div>`).join("")}</div></div>`;}catch(e){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${e.message}</p></div>`;}finally{btn.disabled=false;btn.innerHTML="DISCOVER";}}
function scanDisc(ip){document.getElementById("tgt").value=ip;pg("scan",document.querySelector(".nb"));doScan();}

async function loadHist(){try{const r=await fetch("/history");const d=await r.json();const scans=Array.isArray(d)?d:(d.scans||[]);if(!scans.length){document.getElementById("hist-content").innerHTML=`<p style="color:var(--m);font-size:13px">No scans yet.</p>`;return;}document.getElementById("hist-content").innerHTML=`<div style="overflow-x:auto"><table class="tbl"><thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>${scans.map(s=>`<tr><td style="color:var(--m)">#${s.id}</td><td style="color:var(--cyan)">${s.target}</td><td style="color:var(--m)">${(s.scan_time||"").replace("T"," ").substring(0,19)}</td><td>${s.open_ports}</td><td>${s.total_cves}</td><td style="color:${s.critical_cves>0?"var(--red)":"var(--green)"}">${s.critical_cves}</td><td><button class="lbtn" onclick="loadScan(${s.id})">VIEW</button></td></tr>`).join("")}</tbody></table></div>`;}catch(e){document.getElementById("hist-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}}
async function loadScan(id){pg("scan",document.querySelector(".nb"));clrUI();try{const r=await fetch("/scan/"+id);const d=await r.json();document.getElementById("tgt").value=d.target||"";renderScan(d);initLog();lg("Loaded scan #"+id,"s");}catch(e){showErr(e.message);}}

async function loadDash(){try{const r=await fetch("/history?limit=100");const d=await r.json();const scans=Array.isArray(d)?d:(d.scans||[]);if(!scans.length){document.getElementById("dash-content").innerHTML=`<p style="color:var(--m);font-size:13px">Run some scans first.</p>`;return;}const tc=scans.reduce((a,s)=>a+s.total_cves,0),cr=scans.reduce((a,s)=>a+s.critical_cves,0),tp=scans.reduce((a,s)=>a+s.open_ports,0);const mx=Math.max(...scans.map(s=>s.total_cves),1);document.getElementById("dash-content").innerHTML=`<div class="sgrid" style="margin-bottom:18px"><div class="sc"><div class="sv" style="color:var(--cyan)">${scans.length}</div><div class="sl">SCANS</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${tc}</div><div class="sl">TOTAL CVEs</div></div><div class="sc"><div class="sv" style="color:var(--red)">${cr}</div><div class="sl">CRITICAL</div></div><div class="sc"><div class="sv" style="color:var(--green)">${tp}</div><div class="sl">OPEN PORTS</div></div></div><div class="dash-grid"><div class="card"><div class="ctitle">TOP TARGETS BY CVEs</div>${scans.slice(0,6).map(s=>`<div class="bar-row"><span class="bl">${s.target.substring(0,12)}</span><div class="bt"><div class="bf" style="width:${s.total_cves/mx*100}%;background:linear-gradient(90deg,var(--red),var(--orange))"></div></div><span class="bv">${s.total_cves}</span></div>`).join("")}</div><div class="card"><div class="ctitle">RECENT ACTIVITY</div>${scans.slice(0,8).map(s=>`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-size:12px;font-family:var(--font-mono)"><span style="color:var(--cyan)">${s.target}</span><span style="color:${s.critical_cves>0?"var(--red)":"var(--m)"}">${s.critical_cves>0?"☢ "+s.critical_cves+" crit":s.total_cves+" CVEs"}</span></div>`).join("")}</div></div>`;}catch(e){document.getElementById("dash-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}}

function adminTab(e,id){document.querySelectorAll("#admin-tabs .tab").forEach(t=>t.classList.remove("active"));document.querySelectorAll("#page-admin .tc").forEach(t=>t.classList.remove("active"));e.currentTarget.classList.add("active");document.getElementById(id).classList.add("active");if(id==="at-users")loadAdminUsers();if(id==="at-stats")loadAdminStats();if(id==="at-audit")loadAdminAudit();if(id==="at-scans")loadAdminScans();}
async function loadAdmin(){loadAdminUsers();loadAdminStats();}
async function loadAdminUsers(){try{const r=await fetch("/api/admin/users");const d=await r.json();document.getElementById("admin-users").innerHTML=`<div style="overflow-x:auto"><table class="tbl"><thead><tr><th>ID</th><th>USERNAME</th><th>EMAIL</th><th>ROLE</th><th>VERIFIED</th><th>ACTIVE</th><th>LOGINS</th><th>LAST LOGIN</th><th>ACTIONS</th></tr></thead><tbody>${d.map(u=>`<tr><td style="color:var(--m)">#${u.id}</td><td style="color:var(--cyan)">${u.username}</td><td style="color:var(--m);font-size:11px">${u.email}</td><td>${u.role==="admin"?`<span class="admin-badge">★ ADMIN</span>`:`<span class="user-badge">USER</span>`}</td><td style="color:${u.is_verified?"var(--green)":"var(--red)"}">${u.is_verified?"✅":"❌"}</td><td style="color:${u.is_active?"var(--green)":"var(--red)"}">${u.is_active?"ON":"OFF"}</td><td style="color:var(--m)">${u.login_count||0}</td><td style="color:var(--m);font-size:11px">${(u.last_login||"never").substring(0,16)}</td><td style="display:flex;gap:5px;flex-wrap:wrap"><button class="lbtn" onclick="toggleUser(${u.id})">${u.is_active?"DISABLE":"ENABLE"}</button><button class="lbtn" onclick="setRole(${u.id},'${u.role==="admin"?"user":"admin"}')">${u.role==="admin"?"→USER":"→ADMIN"}</button><button class="lbtn red" onclick="deleteUser(${u.id})">DEL</button></td></tr>`).join("")}</tbody></table></div>`;}catch(e){document.getElementById("admin-users").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}}
async function toggleUser(id){await fetch(`/api/admin/users/${id}/toggle`,{method:"POST"});loadAdminUsers();}
async function setRole(id,role){await fetch(`/api/admin/users/${id}/role`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({role})});loadAdminUsers();}
async function deleteUser(id){if(!confirm("Delete this user?"))return;await fetch(`/api/admin/users/${id}`,{method:"DELETE"});loadAdminUsers();}
async function loadAdminStats(){try{const r=await fetch("/api/admin/stats");const d=await r.json();document.getElementById("admin-stats").innerHTML=`<div class="sgrid"><div class="sc"><div class="sv" style="color:var(--cyan)">${d.total_users||0}</div><div class="sl">TOTAL USERS</div></div><div class="sc"><div class="sv" style="color:var(--green)">${d.verified_users||0}</div><div class="sl">VERIFIED</div></div><div class="sc"><div class="sv" style="color:var(--yellow)">${d.total_scans||0}</div><div class="sl">TOTAL SCANS</div></div><div class="sc"><div class="sv" style="color:var(--orange)">${d.scans_today||0}</div><div class="sl">TODAY</div></div><div class="sc"><div class="sv" style="color:var(--red)">${d.critical_cves||0}</div><div class="sl">CRITICAL CVEs</div></div><div class="sc"><div class="sv" style="color:var(--purple)">${d.total_cves||0}</div><div class="sl">TOTAL CVEs</div></div></div>`;}catch(e){}}
async function loadAdminAudit(){try{const r=await fetch("/api/admin/audit?limit=200");const d=await r.json();document.getElementById("admin-audit").innerHTML=`<table class="tbl"><thead><tr><th>TIME</th><th>USER</th><th>ACTION</th><th>TARGET</th><th>IP</th><th>DETAILS</th></tr></thead><tbody>${d.map(l=>`<tr><td style="color:var(--m);font-size:11px">${(l.timestamp||"").substring(0,16)}</td><td style="color:var(--cyan)">${l.username||"-"}</td><td><span class="tag" style="background:rgba(0,229,255,0.07);color:var(--cyan);border-color:rgba(0,229,255,0.2)">${l.action||""}</span></td><td style="color:var(--m);font-size:11px">${l.target||"-"}</td><td style="color:var(--m);font-size:11px">${l.ip_address||"-"}</td><td style="color:var(--m);font-size:11px">${l.details||""}</td></tr>`).join("")}</tbody></table>`;}catch(e){}}
async function loadAdminScans(){try{const r=await fetch("/api/admin/scans");const d=await r.json();document.getElementById("admin-scans").innerHTML=`<table class="tbl"><thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>${d.map(s=>`<tr><td style="color:var(--m)">#${s.id}</td><td style="color:var(--cyan)">${s.target}</td><td style="color:var(--m);font-size:11px">${(s.scan_time||"").replace("T"," ").substring(0,19)}</td><td>${s.open_ports}</td><td>${s.total_cves}</td><td style="color:${s.critical_cves>0?"var(--red)":"var(--green)"}">${s.critical_cves}</td><td><button class="lbtn" onclick="loadScan(${s.id})">VIEW</button></td></tr>`).join("")}</tbody></table>`;}catch(e){}}

async function exportPDF(){const data=window._sd;if(!data){alert("Run a scan first");return;}try{const r=await fetchWithTimeout("/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)},60000);if(!r.ok)throw new Error(await r.text());const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`vulnscan-${data.target||"report"}-${new Date().toISOString().slice(0,10)}.pdf`;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);}catch(e){alert("PDF failed: "+e.message);}}

function showAbout(){const m=document.getElementById("about-modal");m.style.display="flex";setTimeout(()=>m.style.opacity="1",10);}
function closeAbout(){document.getElementById("about-modal").style.display="none";}

document.addEventListener("keydown",e=>{
  if(e.key==="Escape"){closeAbout();closeThemeDropdown();}
  if(e.key==="Enter"&&document.getElementById("l-pass")===document.activeElement)doLogin();
});

const vt=new URLSearchParams(location.search).get("verify");
if(vt){fetch("/api/verify/"+vt).then(r=>r.json()).then(d=>{if(d.success){authMsg(d.message+" You can now login.","ok");authTab("login");}else authMsg(d.error||"Verification failed","err");});}

// Init
applyTheme(currentTheme, false);
loadUser();
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────
@app.route("/")
def index():
    return HTML

@app.route("/verify/<token>")
def verify_page(token):
    from auth import verify_user
    if verify_user(token):
        return HTML
    return HTML

@app.route("/scan", methods=["GET", "POST"])
def scan():
    target = (request.args.get("target", "") if request.method == "GET"
              else (request.get_json() or {}).get("target", "")).strip()
    modules = request.args.get("modules", "ports,ssl,dns,headers")
    if not target:
        return jsonify({"error": "No target specified"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-_:/\[\]]+$', target):
        return jsonify({"error": "Invalid target — only alphanumeric, dots, dashes, colons allowed"}), 400
    user = get_current_user()
    uid = user["id"] if user else None
    uname = user["username"] if user else "anonymous"
    try:
        data = run_backend("--modules", modules, target)
        if "error" not in data:
            data["scan_id"] = save_scan(target, data, user_id=uid, modules=modules)
            audit(uid, uname, "SCAN", target=target, ip=request.remote_addr, details=f"modules={modules}")
        return jsonify(data)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out after 200s"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/subdomains")
def subdomains():
    domain = request.args.get("domain", "").strip()
    size = request.args.get("size", "medium")
    if not domain:
        return jsonify({"error": "No domain"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        return jsonify({"error": "Invalid domain"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon", "SUBDOMAIN_ENUM",
          target=domain, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--subdomains", domain, size, timeout=120))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dirbust")
def dirbust():
    url = request.args.get("url", "").strip()
    size = request.args.get("size", "small")
    ext = request.args.get("ext", "php,html,txt")
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon", "DIR_ENUM",
          target=url, ip=request.remote_addr)
    try:
        return jsonify(run_backend("--dirbust", url, size, ext, timeout=180))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/brute-http", methods=["POST"])
def brute_http():
    d = request.get_json() or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon", "BRUTE_HTTP",
          target=url, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:10])
    pwds = ",".join(d.get("passwords", [])[:50])
    uf = d.get("user_field", "username")
    pf = d.get("pass_field", "password")
    try:
        return jsonify(run_backend("--brute-http", url, users, pwds, uf, pf, timeout=120))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/brute-ssh", methods=["POST"])
def brute_ssh():
    d = request.get_json() or {}
    host = d.get("host", "").strip()
    port = str(d.get("port", "22"))
    if not host:
        return jsonify({"error": "No host"}), 400
    user = get_current_user()
    audit(user["id"] if user else None, user["username"] if user else "anon", "BRUTE_SSH",
          target=host, ip=request.remote_addr)
    users = ",".join(d.get("users", [])[:5])
    pwds = ",".join(d.get("passwords", [])[:20])
    try:
        return jsonify(run_backend("--brute-ssh", host, port, users, pwds, timeout=120))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/discover")
def discover():
    subnet = request.args.get("subnet", "").strip()
    if not subnet:
        return jsonify({"error": "No subnet"}), 400
    if not re.match(r'^[0-9./]+$', subnet):
        return jsonify({"error": "Invalid subnet"}), 400
    try:
        return jsonify(run_backend("--discover", subnet, timeout=120))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history")
def history():
    user = get_current_user()
    uid = user["id"] if user else None
    return jsonify(get_history(int(request.args.get("limit", 20)), user_id=uid))

@app.route("/scan/<int:sid>")
def get_scan_route(sid):
    user = get_current_user()
    uid = user["id"] if user else None
    role = user["role"] if user else "user"
    d = get_scan_by_id(sid, user_id=None if role == "admin" else uid)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)

@app.route("/report", methods=["POST"])
def report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        return jsonify({"error": "reportlab not installed: pip3 install reportlab --break-system-packages"}), 500

    data = request.get_json() or {}
    target = data.get("target", "unknown")
    scan_time = data.get("scan_time", "")[:19].replace("T", " ")
    summary = data.get("summary", {})

    C_BG = colors.HexColor("#04040a"); C_DARK = colors.HexColor("#0d0d18")
    C_BORDER = colors.HexColor("#16162a"); C_MUTED = colors.HexColor("#5a5a8a")
    C_WHITE = colors.HexColor("#e8e8f0"); C_CYAN = colors.HexColor("#00e5ff")
    C_RED = colors.HexColor("#ff3366"); C_ORANGE = colors.HexColor("#ff6b35")
    C_YELLOW = colors.HexColor("#ffd60a"); C_GREEN = colors.HexColor("#00ff9d")
    C_PURPLE = colors.HexColor("#b06fff")

    def sty(name, **kw):
        d = dict(fontName="Helvetica", fontSize=9, textColor=C_WHITE, leading=14, spaceAfter=4, spaceBefore=2, leftIndent=0, alignment=TA_LEFT)
        d.update(kw)
        return ParagraphStyle(name, **d)

    S_T = sty("t", fontName="Helvetica-Bold", fontSize=26, textColor=C_CYAN, leading=32, spaceAfter=6)
    S_B = sty("b"); S_C = sty("c", alignment=TA_CENTER, textColor=C_MUTED, fontSize=8)

    def p(t, s=None): return Paragraph(str(t), s or S_B)
    def sp(h=6): return Spacer(1, h)
    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=7, spaceBefore=3)
    def tbl(data, cols, sx=[]):
        t = Table(data, colWidths=cols)
        base = [("FONTSIZE",(0,0),(-1,-1),8),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("TEXTCOLOR",(0,0),(-1,-1),C_WHITE),("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK,C_BG]),("GRID",(0,0),(-1,-1),0.3,C_BORDER),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),("LEFTPADDING",(0,0),(-1,-1),8)]
        t.setStyle(TableStyle(base + sx))
        return t

    W, H = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm, topMargin=14*mm, bottomMargin=14*mm)
    crit_c = summary.get("critical_cves", 0); high_c = summary.get("high_cves", 0)
    if crit_c > 0: risk = ("F", C_RED, "CRITICAL RISK")
    elif high_c > 0: risk = ("D", C_ORANGE, "HIGH RISK")
    elif summary.get("total_cves", 0) > 0: risk = ("C", C_YELLOW, "MEDIUM RISK")
    else: risk = ("A", C_GREEN, "LOW RISK")

    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG); canvas.rect(0,0,W,H,fill=1,stroke=0)
        canvas.setFillColor(C_RED); canvas.rect(0,H-3,W,3,fill=1,stroke=0)
        canvas.setFillColor(C_DARK); canvas.rect(0,0,W,13*mm,fill=1,stroke=0)
        canvas.setFont("Helvetica",7); canvas.setFillColor(C_MUTED)
        canvas.drawString(16*mm,4.5*mm,f"VulnScan Pro  |  {target}  |  {scan_time}  |  CONFIDENTIAL")
        canvas.drawRightString(W-16*mm,4.5*mm,f"Page {doc.page}")
        canvas.restoreState()

    story = [sp(36), p("VulnScan Pro", S_T)]
    story.append(p("SECURITY ASSESSMENT REPORT", sty("st2",fontName="Helvetica-Bold",fontSize=12,textColor=C_PURPLE,leading=18)))
    story += [sp(8), hr(), sp(8)]
    story.append(tbl([[k,v] for k,v in [("Target",target),("Scan Time",scan_time),("Report Date",datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),("Risk Level",risk[2])]],
                     [38*mm,115*mm],
                     [("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("TEXTCOLOR",(0,0),(0,-1),C_MUTED),("TEXTCOLOR",(1,3),(1,3),risk[1]),("FONTNAME",(1,3),(1,3),"Helvetica-Bold")]))
    story += [sp(18)]
    st = Table([[f"{summary.get('open_ports',0)}\nOPEN PORTS",f"{summary.get('total_cves',0)}\nTOTAL CVEs",f"{crit_c}\nCRITICAL",f"{high_c}\nHIGH",f"{summary.get('exploitable',0)}\nEXPLOITABLE"]],colWidths=[30*mm]*5)
    ss = TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("TOPPADDING",(0,0),(-1,-1),11),("BOTTOMPADDING",(0,0),(-1,-1),11),("FONTSIZE",(0,0),(-1,-1),8),("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("ROWBACKGROUNDS",(0,0),(-1,-1),[C_DARK]),("GRID",(0,0),(-1,-1),0.4,C_BORDER)])
    for i,c in enumerate([C_CYAN,C_YELLOW,C_RED,C_ORANGE,C_PURPLE]):ss.add("TEXTCOLOR",(i,0),(i,0),c)
    st.setStyle(ss); story += [st,sp(28)]
    story.append(p("CONFIDENTIAL — Authorized security assessment only",sty("disc",fontSize=8,textColor=C_MUTED,alignment=TA_CENTER)))
    story.append(PageBreak())
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    buf.seek(0)
    fname = f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]','_',target)}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(buf.read(), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.route("/dnsrecon", methods=["POST"])
def dnsrecon_route():
    import shutil, subprocess, json as _json, re as _re
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    scan_type = data.get("type", "std")
    ns = (data.get("ns") or "").strip()
    rec_filter = (data.get("filter") or "").strip()
    if not target:
        return jsonify({"error": "No target specified"})
    binary = shutil.which("dnsrecon")
    if not binary:
        return jsonify({"error": "dnsrecon is not installed. Run: sudo apt install dnsrecon"})
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [binary, "-d", target, "-t", scan_type, "-j", out_file]
    if ns: cmd += ["-n", ns]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        records = []
        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = _json.load(f)
                for item in (raw if isinstance(raw, list) else raw.get("records", [])):
                    if isinstance(item, dict):
                        rec = {"type": item.get("type","?"), "name": item.get("name",""), "address": item.get("address", item.get("data",""))}
                        if rec_filter and rec["type"] != rec_filter: continue
                        records.append(rec)
            except Exception: pass
        if not records:
            for line in proc.stdout.splitlines():
                m = _re.match(r'\s*\[\*\]\s*(\w+)\s+([\w\.\-]+)\s+([\d\.]+)', line)
                if m: records.append({"type": m.group(1), "name": m.group(2), "address": m.group(3)})
        os.unlink(out_file) if os.path.exists(out_file) else None
        return jsonify({"target": target, "records": records, "scan_type": scan_type})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "dnsrecon timed out"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/nikto", methods=["POST"])
def nikto_route():
    import shutil, subprocess, json as _json, re as _re
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    port = int(data.get("port") or 80)
    ssl_flag = data.get("ssl", "")
    tuning = data.get("tuning", "")
    if not target:
        return jsonify({"error": "No target specified"})
    binary = shutil.which("nikto")
    if not binary:
        return jsonify({"error": "Nikto is not installed. Run: sudo apt install nikto"})
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name
    cmd = [binary, "-h", target, "-p", str(port), "-Format", "json", "-o", out_file, "-nointeractive"]
    if ssl_flag == "-ssl": cmd += ["-ssl"]
    elif ssl_flag == "-nossl": cmd += ["-nossl"]
    if tuning: cmd += ["-Tuning", tuning]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        findings, server = [], ""
        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = _json.load(f)
                for host in (raw.get("host", []) if isinstance(raw, dict) else []):
                    server = host.get("banner", "")
                    for item in host.get("vulnerabilities", []):
                        findings.append({"id": item.get("id",""), "description": item.get("msg",""), "url": item.get("uri",""), "severity": "high" if item.get("OSVDB","0") != "0" else "info"})
            except Exception: pass
        if not findings:
            for line in proc.stdout.splitlines():
                m = _re.search(r'\+ (OSVDB-\d+|[\w-]+): (.+)', line)
                if m: findings.append({"id": m.group(1), "description": m.group(2), "severity": "high" if "OSVDB" in m.group(1) else "info"})
        os.unlink(out_file) if os.path.exists(out_file) else None
        return jsonify({"target": target, "port": port, "server": server, "findings": findings})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Nikto timed out after 10 minutes"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/wpscan", methods=["POST"])
def wpscan_route():
    import shutil, subprocess, json as _json
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    enum_flags = data.get("enum_flags", "p,u")
    token = (data.get("token") or "").strip()
    mode = data.get("mode", "mixed")
    if not target:
        return jsonify({"error": "No target specified"})
    binary = shutil.which("wpscan")
    if not binary:
        return jsonify({"error": "WPScan is not installed."})
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [binary, "--url", target, "--enumerate", enum_flags, "--detection-mode", mode, "--format", "json", "--output", out_file, "--no-banner"]
    if token: cmd += ["--api-token", token]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    raw = _json.load(f)
                wp_version = raw.get("version", {}).get("number", "unknown")
                users = list(raw.get("users", {}).keys())
                plugins = [{"name": name, "version": pdata.get("version", {}).get("number", "?"), "vulnerabilities": pdata.get("vulnerabilities", [])} for name, pdata in raw.get("plugins", {}).items()]
                vulns = [{"title": v.get("title",""), "type": v.get("type",""), "references": v.get("references",{})} for name, pdata in raw.get("plugins", {}).items() for v in pdata.get("vulnerabilities", [])]
                os.unlink(out_file) if os.path.exists(out_file) else None
                return jsonify({"target": target, "wp_version": wp_version, "users": users, "plugins": plugins, "vulnerabilities": vulns})
            except Exception as e:
                return jsonify({"error": f"Parse error: {e}"})
        return jsonify({"error": "WPScan produced no output."})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "WPScan timed out"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/lynis", methods=["POST"])
def lynis_route():
    import shutil, subprocess, re as _re
    data = request.get_json() or {}
    profile = data.get("profile", "system")
    compliance = (data.get("compliance") or "").strip()
    binary = shutil.which("lynis")
    if not binary:
        return jsonify({"error": "Lynis is not installed. Run: sudo apt install lynis"})
    cmd = [binary, "audit", "system", "--quiet", "--no-colors", "--noplugins"]
    if compliance: cmd += ["--compliance", compliance.lower()]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = proc.stdout + proc.stderr
        hardening_index = 0; warnings = []; suggestions = []
        for line in output.splitlines():
            m = _re.search(r'Hardening index\s*[:\|]\s*(\d+)', line, _re.IGNORECASE)
            if m: hardening_index = int(m.group(1))
            if "Warning" in line or "warning" in line:
                clean = _re.sub(r'\033\[[0-9;]*m','',line).strip()
                if len(clean)>10 and "=="not in clean: warnings.append(clean)
            elif "Suggestion" in line or "suggestion" in line:
                clean = _re.sub(r'\033\[[0-9;]*m','',line).strip()
                if len(clean)>10 and "=="not in clean: suggestions.append(clean)
        tests_m = _re.search(r'Tests performed\s*[:\|]\s*(\d+)', output, _re.IGNORECASE)
        return jsonify({"hardening_index": hardening_index, "warnings": list(set(warnings))[:50], "suggestions": list(set(suggestions))[:100], "tests_performed": tests_m.group(1) if tests_m else "?"})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Lynis timed out"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/legion", methods=["POST"])
def legion_route():
    import shutil, subprocess
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    intensity = data.get("intensity", "normal")
    modules = data.get("modules", ["nmap", "nikto"])
    if not target:
        return jsonify({"error": "No target specified"})
    results, open_ports, total_issues, modules_run = [], 0, 0, 0
    for mod in modules:
        binary = shutil.which(mod) or shutil.which(mod.lower())
        if not binary:
            results.append({"module": mod, "summary": f"{mod} not found", "findings": []})
            continue
        modules_run += 1; findings = []
        try:
            if mod == "nmap":
                speed = {"light":"-T2","normal":"-T3","aggressive":"-T4"}[intensity]
                proc = subprocess.run(["nmap",speed,"-sV","--open",target],capture_output=True,text=True,timeout=300)
                import re as _re
                for line in proc.stdout.splitlines():
                    m = _re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)',line)
                    if m: open_ports+=1; findings.append({"title":f"Port {m.group(1)} open","detail":f"{m.group(2)} {m.group(3)}".strip()})
            elif mod == "nikto":
                proc = subprocess.run(["nikto","-h",target,"-nointeractive"],capture_output=True,text=True,timeout=300)
                import re as _re
                for line in proc.stdout.splitlines():
                    if line.strip().startswith("+"): findings.append({"title":line.strip()[2:80],"detail":""}); total_issues+=1
            else:
                proc = subprocess.run([binary,target],capture_output=True,text=True,timeout=120)
                if proc.stdout.strip(): findings.append({"title":f"{mod} output","detail":proc.stdout[:500]})
        except subprocess.TimeoutExpired:
            findings.append({"title":f"{mod} timed out","detail":""})
        except Exception as e:
            findings.append({"title":f"{mod} error","detail":str(e)})
        results.append({"module":mod,"findings":findings,"summary":f"{len(findings)} findings"})
    return jsonify({"target":target,"open_ports":open_ports,"total_issues":total_issues,"modules_run":modules_run,"results":results})

@app.route("/harvester", methods=["POST"])
def harvester():
    import shutil, subprocess, json as _json, tempfile, re as _re
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    sources = (data.get("sources") or "google,bing,dnsdumpster,crtsh").strip()
    limit = int(data.get("limit") or 500)
    if not target:
        return jsonify({"error": "No target specified"})
    if not _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        return jsonify({"error": "Invalid domain format"})
    if not shutil.which("theHarvester") and not shutil.which("theharvester"):
        return jsonify({"error": "theHarvester is not installed."})
    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "harvest")
        cmd = [binary, "-d", target, "-l", str(limit), "-b", sources, "-f", out_file]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            raw_out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return jsonify({"error": "theHarvester timed out after 150s"})
        except Exception as e:
            return jsonify({"error": str(e)})
        emails, hosts, subdomains, ips = [], [], [], []
        json_path = out_file + ".json"
        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    jd = _json.load(f)
                emails = list(set(jd.get("emails", [])))
                hosts_raw = jd.get("hosts", [])
                for h in hosts_raw:
                    if isinstance(h, dict): hosts.append(h); (ips.append(h["ip"]) if h.get("ip") else None)
                    else: hosts.append({"host": h, "ip": ""})
                subdomains = list(set([h["host"] if isinstance(h,dict) else h for h in hosts_raw]))
                ips = list(set(ips + jd.get("ips", [])))
            except Exception: pass
        if not emails and not hosts:
            for line in raw_out.splitlines():
                line = line.strip()
                if "@" in line and "." in line and " " not in line: emails.append(line)
                elif _re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', line): subdomains.append(line)
                elif _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line): ips.append(line)
            emails = list(set(emails)); subdomains = list(set(subdomains)); ips = list(set(ips))
        return jsonify({"target":target,"sources":sources,"emails":emails[:500],"hosts":hosts[:500],"subdomains":subdomains[:500],"ips":ips[:500],"raw_lines":len(raw_out.splitlines())})

@app.route("/health")
def health():
    import shutil
    return jsonify({"status":"ok","version":"3.5","nmap":bool(shutil.which("nmap")),"dig":bool(shutil.which("dig")),"python":sys.version})

if __name__ == "__main__":
    print("[*] VulnScan Pro v3.5 starting")
    print("[*] Open: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
