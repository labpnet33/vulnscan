#!/usr/bin/env python3
import json, re, sys, os, subprocess, io
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("VULNSCAN_SECRET", "change-this-secret-key-in-production-2024")
app.permanent_session_lifetime = timedelta(days=7)

# FIX: Allow credentials + specific origins for CORS (was too permissive / incomplete)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py")

# Import database and auth
from database import save_scan, get_history, get_scan_by_id
from auth import register_auth_routes, get_current_user, audit

# Register all auth routes
register_auth_routes(app)

GRADE_COL = {"A+": "#00ff9d", "A": "#00e5ff", "B": "#ffd60a", "C": "#ff6b35", "D": "#ff6b35", "F": "#ff3366"}


def run_backend(*args, timeout=200):
    """
    FIX: No longer suppresses stderr — errors are now visible.
    Returns structured error with stdout + stderr for diagnosis.
    """
    cmd = [sys.executable, BACKEND] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Backend process timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": f"Python interpreter not found: {sys.executable}"}

    # FIX: Log stderr so errors are visible in server logs
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


# ══════════════════════════════════════════════
# HTML — Full UI with Auth
# ══════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Syne:wght@400;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;
  --t:#e8e8f0;--m:#5a5a8a;
  --cyan:#00e5ff;--green:#00ff9d;--red:#ff3366;--orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;
  --accent:var(--cyan);--grid-color:rgba(0,229,255,0.025);
}
/* ── THEMES ── */
body.theme-cyberpunk{--bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;--t:#e8e8f0;--m:#5a5a8a;--accent:#00e5ff;--grid-color:rgba(0,229,255,0.025);}
body.theme-midnight{--bg:#000510;--s1:#030920;--s2:#06112e;--b:#0a1a40;--b2:#0f2255;--t:#c8d8ff;--m:#3a5088;--cyan:#4d9fff;--purple:#a07fff;--accent:#4d9fff;--grid-color:rgba(77,159,255,0.03);}
body.theme-forest{--bg:#030a04;--s1:#060f07;--s2:#0a160a;--b:#111f12;--b2:#172818;--t:#d4f0d8;--m:#3a6b3e;--cyan:#39ff14;--green:#00ff9d;--purple:#9bff70;--accent:#39ff14;--grid-color:rgba(57,255,20,0.025);}
body.theme-blood{--bg:#0a0204;--s1:#110206;--s2:#180308;--b:#250510;--b2:#300718;--t:#f0d0d8;--m:#7a3040;--cyan:#ff4060;--red:#ff1030;--orange:#ff6040;--green:#ff9060;--purple:#ff60a0;--accent:#ff4060;--grid-color:rgba(255,64,96,0.025);}
body.theme-solar{--bg:#0c0800;--s1:#150f00;--s2:#1e1500;--b:#2e2000;--b2:#3d2c00;--t:#fff4c8;--m:#8a6820;--cyan:#ffd700;--yellow:#ffec40;--orange:#ff9500;--green:#d4ff40;--purple:#ffaa00;--accent:#ffd700;--grid-color:rgba(255,215,0,0.025);}
body.theme-arctic{--bg:#f4f8ff;--s1:#eaf0fb;--s2:#dde8f8;--b:#c8d8f0;--b2:#b0c4e8;--t:#1a2a40;--m:#6080a0;--cyan:#0066cc;--green:#00aa55;--red:#cc2244;--orange:#dd6600;--purple:#7733cc;--accent:#0066cc;--grid-color:rgba(0,102,204,0.04);}
body.theme-rose{--bg:#0a0408;--s1:#110609;--s2:#17080d;--b:#230d14;--b2:#2e121c;--t:#f8d0e0;--m:#7a4060;--cyan:#ff80b0;--red:#ff2060;--purple:#d060a0;--green:#ff90c0;--orange:#ff6080;--accent:#ff80b0;--grid-color:rgba(255,128,176,0.025);}
body.theme-ash{--bg:#0d0d0d;--s1:#111111;--s2:#161616;--b:#222222;--b2:#2a2a2a;--t:#e0e0e0;--m:#606060;--cyan:#aaaaaa;--green:#cccccc;--red:#888888;--orange:#999999;--purple:#bbbbbb;--accent:#ffffff;--grid-color:rgba(255,255,255,0.02);}
body.theme-toxic{--bg:#030802;--s1:#050f03;--s2:#071505;--b:#0c2008;--b2:#112b0c;--t:#c8ff90;--m:#3a7020;--cyan:#80ff00;--green:#40ff80;--red:#ffcc00;--orange:#ff8000;--purple:#c0ff40;--accent:#80ff00;--grid-color:rgba(128,255,0,0.025);}
body.theme-void{--bg:#000000;--s1:#050505;--s2:#080808;--b:#111111;--b2:#161616;--t:#ffffff;--m:#444444;--cyan:#ffffff;--green:#e0e0e0;--red:#ff4444;--orange:#ff8844;--purple:#cc88ff;--accent:#ffffff;--grid-color:rgba(255,255,255,0.015);}

html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--t);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden;transition:background 0.4s,color 0.3s}

/* ── Animated grid background ── */
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(var(--grid-color) 1px,transparent 1px),linear-gradient(90deg,var(--grid-color) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;animation:gridPulse 8s ease-in-out infinite}
@keyframes gridPulse{0%,100%{opacity:0.6}50%{opacity:1}}

/* ── Floating particles canvas ── */
#particles-canvas{position:fixed;inset:0;pointer-events:none;z-index:0;opacity:0.5}

/* ── Scan line overlay ── */
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);pointer-events:none;z-index:0;animation:scanlines 10s linear infinite}
@keyframes scanlines{0%{background-position:0 0}100%{background-position:0 40px}}

/* ── Page entrance animation ── */
.page.active{animation:pageIn 0.3s ease}
@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* ── Card hover glow ── */
.card{transition:border-color 0.2s,box-shadow 0.2s}
.card:hover{box-shadow:0 0 0 1px var(--accent),0 4px 24px rgba(0,0,0,0.4)}

/* ── Animated hero title ── */
@keyframes titleShimmer{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.home-hero h1{background-size:200% auto;animation:titleShimmer 4s ease infinite}

/* ── Glitch effect on brand ── */
.brand-name{position:relative}
.brand-name::before,.brand-name::after{content:attr(data-text);position:absolute;inset:0;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-name::before{animation:glitch1 6s infinite;clip-path:polygon(0 0,100% 0,100% 45%,0 45%)}
.brand-name::after{animation:glitch2 6s infinite;clip-path:polygon(0 55%,100% 55%,100% 100%,0 100%)}
@keyframes glitch1{0%,94%,100%{transform:none;opacity:0}95%{transform:translate(-2px,1px);opacity:0.7}96%{transform:translate(2px,-1px);opacity:0.5}97%{transform:none;opacity:0}}
@keyframes glitch2{0%,92%,100%{transform:none;opacity:0}93%{transform:translate(2px,2px);opacity:0.6}94%{transform:translate(-1px,0);opacity:0.4}95%{transform:none;opacity:0}}

/* ── Stat counter animation ── */
.home-stat-val{transition:color 0.3s}
.home-stat{transition:border-color 0.2s,transform 0.2s,box-shadow 0.2s}
.home-stat:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.4),0 0 0 1px var(--accent)}

/* ── Tool card animations ── */
.home-tool-card{transition:all 0.25s cubic-bezier(0.34,1.56,0.64,1)}
.home-tool-card:hover{transform:translateY(-4px) scale(1.01)}
.home-tool-icon{transition:transform 0.3s;display:inline-block}
.home-tool-card:hover .home-tool-icon{transform:scale(1.2) rotate(-5deg)}

/* ── Quick btn pulse ── */
.home-quick-btn{position:relative;overflow:hidden}
.home-quick-btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 40%,rgba(255,255,255,0.06) 50%,transparent 60%);transform:translateX(-100%);transition:transform 0.5s}
.home-quick-btn:hover::after{transform:translateX(100%)}

/* ── Progress bar shimmer ── */
#pb,[id$="-pb"]{position:relative;overflow:hidden}
#pb::after,[id$="-pb"]::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);animation:pbShimmer 1.5s ease infinite}
@keyframes pbShimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}

/* ── Navbar dropdown enhanced ── */
.nav-dropdown-menu{animation:ddFade 0.18s cubic-bezier(0.34,1.56,0.64,1)}

/* ── Button ripple ── */
.btn-p{position:relative;overflow:hidden}
.btn-p::after{content:'';position:absolute;inset:0;background:radial-gradient(circle at var(--x,50%) var(--y,50%),rgba(255,255,255,0.15) 0%,transparent 60%);opacity:0;transition:opacity 0.3s}
.btn-p:hover::after{opacity:1}

/* ── Terminal typewriter cursor ── */
.terminal-cursor{display:inline-block;width:8px;height:14px;background:var(--accent);animation:blink 1s step-end infinite;vertical-align:middle;margin-left:2px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}

/* ── Theme switcher UI ── */
.theme-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:10px}
.theme-swatch{border-radius:10px;overflow:hidden;cursor:pointer;border:2px solid transparent;transition:all 0.2s;position:relative}
.theme-swatch:hover{transform:scale(1.05);border-color:var(--accent)}
.theme-swatch.active{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent),0 0 16px rgba(0,0,0,0.4)}
.theme-swatch-preview{height:52px;display:flex;gap:3px;padding:6px}
.theme-swatch-bar{flex:1;border-radius:3px}
.theme-swatch-name{font-size:9px;font-family:'JetBrains Mono',monospace;letter-spacing:1px;padding:5px;text-align:center;background:rgba(0,0,0,0.3);color:#fff}
.theme-swatch.active .theme-swatch-name::before{content:'✓ '}

/* ── Pulse dot indicator ── */
.pulse-dot{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block;animation:pulseDot 2s ease infinite;box-shadow:0 0 0 0 var(--green)}
@keyframes pulseDot{0%{box-shadow:0 0 0 0 rgba(0,255,157,0.6)}70%{box-shadow:0 0 0 8px rgba(0,255,157,0)}100%{box-shadow:0 0 0 0 rgba(0,255,157,0)}}

/* ── Fade-in stagger for tool cards ── */
@keyframes cardIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.home-tool-card:nth-child(1){animation:cardIn 0.4s ease 0.05s both}
.home-tool-card:nth-child(2){animation:cardIn 0.4s ease 0.1s both}
.home-tool-card:nth-child(3){animation:cardIn 0.4s ease 0.15s both}
.home-tool-card:nth-child(4){animation:cardIn 0.4s ease 0.2s both}
.home-tool-card:nth-child(5){animation:cardIn 0.4s ease 0.25s both}
.home-tool-card:nth-child(6){animation:cardIn 0.4s ease 0.3s both}

/* ── Stat count-up animation indicator ── */
@keyframes numIn{from{opacity:0;transform:scale(0.7)}to{opacity:1;transform:scale(1)}}
.home-stat-val.loaded{animation:numIn 0.5s cubic-bezier(0.34,1.56,0.64,1)}

/* ── Header glow on scroll ── */
header{transition:box-shadow 0.3s}
header.scrolled{box-shadow:0 2px 30px rgba(0,0,0,0.6),0 0 60px rgba(0,0,0,0.2)}
}
header{position:sticky;top:0;z-index:100;background:rgba(4,4,10,0.92);backdrop-filter:blur(20px);border-bottom:1px solid var(--b);padding:0 24px;display:flex;align-items:center;justify-content:space-between;height:58px;flex-wrap:wrap;gap:8px}
.brand{display:flex;align-items:center;gap:10px}
.brand-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--red),var(--orange));border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 0 18px rgba(255,51,102,0.35)}
.brand-name{font-size:17px;font-weight:800;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-tag{font-size:8px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace}
nav{display:flex;gap:3px;flex-wrap:wrap;align-items:center}
.nb{padding:6px 13px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:1px;border-radius:6px;transition:all 0.2s;white-space:nowrap}
.nb:hover,.nb.active{background:var(--b);color:var(--cyan)}
.nav-dropdown{position:relative;display:inline-block}
.nav-dropdown:hover .nav-dropdown-menu{display:block;animation:ddFade 0.15s ease}
.nav-dropdown:hover .nav-dropdown-btn{background:var(--b);color:var(--cyan)}
.nav-dropdown:hover .nav-dropdown-btn .arrow{transform:rotate(180deg)}
@keyframes ddFade{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.nav-dropdown-btn{padding:6px 13px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:1px;border-radius:6px;transition:all 0.2s;white-space:nowrap;display:flex;align-items:center;gap:5px}
.nav-dropdown-btn:hover,.nav-dropdown-btn.active{background:var(--b);color:var(--cyan)}
.nav-dropdown-btn .arrow{font-size:8px;transition:transform 0.2s}
.nav-dropdown-menu{position:absolute;top:calc(100% + 2px);left:0;background:var(--s1);border:1px solid var(--b2);border-radius:10px;min-width:220px;z-index:100;padding:6px;display:none;box-shadow:0 8px 32px rgba(0,0,0,0.6)}
.nav-dropdown-section{font-size:9px;color:var(--m);letter-spacing:2px;font-family:'JetBrains Mono',monospace;padding:6px 10px 4px;margin-top:4px}
.nav-dropdown-section:first-child{margin-top:0}
.nav-dropdown-item{display:flex;align-items:center;gap:9px;padding:8px 12px;border:none;background:transparent;color:var(--t);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;border-radius:7px;width:100%;text-align:left;transition:all 0.2s}
.nav-dropdown-item:hover{background:var(--b);color:var(--cyan)}
.nav-dropdown-item.active{background:var(--b);color:var(--cyan)}
.nav-dropdown-item .item-icon{width:22px;text-align:center;font-size:13px}
.nav-dropdown-item .item-label{flex:1}
.nav-dropdown-item .item-badge{font-size:8px;background:var(--cyan);color:var(--bg);padding:2px 5px;border-radius:4px;font-weight:700}
.ver-badge{font-size:9px;font-family:'JetBrains Mono',monospace;background:rgba(0,229,255,0.08);color:var(--cyan);border:1px solid rgba(0,229,255,0.2);border-radius:4px;padding:2px 7px;letter-spacing:1px;cursor:default}
.brand-link{display:flex;align-items:center;gap:10px;cursor:pointer;text-decoration:none}
.home-hero{text-align:center;padding:48px 0 36px}
.home-hero h1{font-size:42px;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px;line-height:1.1}
.home-hero p{color:var(--m);font-size:14px;font-family:'JetBrains Mono',monospace;max-width:540px;margin:0 auto 28px}
.home-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:40px}
.home-stat{background:var(--s1);border:1px solid var(--b);border-radius:12px;padding:20px;text-align:center;transition:border-color 0.2s}
.home-stat:hover{border-color:var(--cyan)}
.home-stat-val{font-size:32px;font-weight:800;font-family:'JetBrains Mono',monospace;background:linear-gradient(135deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.home-stat-lbl{color:var(--m);font-size:10px;letter-spacing:2px;margin-top:4px;font-family:'JetBrains Mono',monospace}
.home-cat{margin-bottom:36px}
.home-cat-title{font-size:11px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-bottom:14px;font-weight:700;display:flex;align-items:center;gap:10px}
.home-cat-title::after{content:'';flex:1;height:1px;background:var(--b)}
.home-tools-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.home-tool-card{background:var(--s1);border:1px solid var(--b);border-radius:12px;padding:18px;cursor:pointer;transition:all 0.2s;position:relative;overflow:hidden}
.home-tool-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,var(--tool-c,var(--cyan)),transparent);opacity:0;transition:opacity 0.3s;pointer-events:none}
.home-tool-card:hover{border-color:var(--tool-c,var(--cyan));transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,0.4)}
.home-tool-card:hover::before{opacity:0.04}
.home-tool-icon{font-size:28px;margin-bottom:10px}
.home-tool-name{font-size:15px;font-weight:700;margin-bottom:4px;color:var(--t)}
.home-tool-desc{font-size:11px;color:var(--m);font-family:'JetBrains Mono',monospace;line-height:1.6}
.home-tool-tags{display:flex;gap:5px;margin-top:10px;flex-wrap:wrap}
.home-tool-tag{font-size:9px;font-family:'JetBrains Mono',monospace;padding:2px 7px;border-radius:3px;font-weight:700}
.home-quick{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:40px}
.home-quick-btn{padding:10px 20px;border:1px solid var(--b2);border-radius:8px;background:transparent;color:var(--t);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12px;transition:all 0.2s;display:flex;align-items:center;gap:7px}
.home-quick-btn:hover{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.05)}
.user-chip{display:flex;align-items:center;gap:8px;background:var(--s2);border:1px solid var(--b2);border-radius:20px;padding:4px 12px 4px 8px;cursor:pointer;transition:all 0.2s}
.user-chip:hover{border-color:var(--cyan)}
.user-avatar{width:24px;height:24px;border-radius:50%;background:linear-gradient(135deg,var(--cyan),var(--purple));display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--bg)}
.user-name{font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--t)}
.user-role{font-size:9px;color:var(--m);font-family:'JetBrains Mono',monospace}
.overlay{position:fixed;inset:0;background:rgba(4,4,10,0.95);z-index:200;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(10px)}
.auth-box{background:var(--s1);border:1px solid var(--b2);border-radius:16px;padding:36px;width:100%;max-width:420px;position:relative}
.auth-box h2{font-size:22px;font-weight:800;margin-bottom:4px;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.auth-box p{color:var(--m);font-size:12px;margin-bottom:24px;font-family:'JetBrains Mono',monospace}
.auth-tabs{display:flex;gap:0;margin-bottom:24px;background:var(--s2);border-radius:8px;padding:3px}
.auth-tab{flex:1;padding:8px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;border-radius:6px;transition:all 0.2s}
.auth-tab.active{background:var(--b2);color:var(--cyan)}
.fg{margin-bottom:14px}
.fg label{display:block;font-size:10px;color:var(--m);letter-spacing:2px;font-family:'JetBrains Mono',monospace;margin-bottom:5px}
.inp{width:100%;background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--t);padding:11px 14px;font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:border 0.2s}
.inp:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.07)}
.inp::placeholder{color:#252540}
.btn{padding:12px 22px;border:none;border-radius:9px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;letter-spacing:1px;transition:all 0.2s;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,var(--red),#b0102a);color:#fff;box-shadow:0 4px 18px rgba(255,51,102,0.28);width:100%}
.btn-p:hover{transform:translateY(-1px)}
.btn-p:disabled{background:var(--b);color:var(--m);cursor:not-allowed;transform:none;box-shadow:none}
.btn-g{background:transparent;color:var(--m);border:1px solid var(--b2);padding:12px 18px}
.btn-g:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-sm{padding:6px 12px;font-size:10px}
.btn-full{width:100%}
.auth-msg{padding:10px 14px;border-radius:7px;font-size:12px;font-family:'JetBrains Mono',monospace;margin-bottom:14px;display:none}
.auth-msg.ok{background:rgba(0,255,157,0.08);border:1px solid rgba(0,255,157,0.2);color:var(--green)}
.auth-msg.err{background:rgba(255,51,102,0.08);border:1px solid rgba(255,51,102,0.2);color:var(--red)}
.auth-link{background:none;border:none;color:var(--cyan);cursor:pointer;font-size:11px;font-family:'JetBrains Mono',monospace;text-decoration:underline;padding:0}
.container{max-width:1100px;margin:0 auto;padding:24px 16px;position:relative;z-index:1}
.page{display:none}.page.active{display:block}
.card{background:var(--s1);border:1px solid var(--b);border-radius:12px;padding:20px;margin-bottom:16px}
.ctitle{font-size:11px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-bottom:12px;font-weight:600}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
.hero{text-align:center;padding:32px 0 24px}
.hero h2{font-size:28px;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--purple),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.hero p{color:var(--m);font-size:13px;font-family:'JetBrains Mono',monospace}
.scan-inp{flex:1;min-width:200px;background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--cyan);padding:12px 16px;font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:border 0.2s}
.scan-inp:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,229,255,0.07)}
.scan-inp::placeholder{color:#252540}
.mods{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px;justify-content:center}
.mt{padding:5px 13px;border:1px solid var(--b2);border-radius:18px;cursor:pointer;font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--m);background:transparent;transition:all 0.2s}
.mt.on{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,0.07)}
#term{background:#020208;border:1px solid var(--b);border-radius:9px;padding:13px 15px;margin-bottom:16px;max-height:160px;overflow-y:auto;display:none;font-family:'JetBrains Mono',monospace;font-size:13px}
.tl{line-height:1.9;color:#4a4a7a}
.ti .p{color:var(--cyan)}.ts .p{color:var(--green)}.tw .p{color:var(--yellow)}.te .p{color:var(--red)}
#prog{height:2px;background:var(--b);border-radius:1px;margin-bottom:16px;display:none;overflow:hidden}
#pb{height:100%;width:0;background:linear-gradient(90deg,var(--red),var(--orange),var(--yellow));transition:width 0.3s}
#err{background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-size:13px;margin-bottom:16px;display:none;font-family:'JetBrains Mono',monospace}
#res{display:none}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}
.sc{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:14px;text-align:center}
.sv{font-size:28px;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}
.sl{color:var(--m);font-size:10px;letter-spacing:2px;margin-top:5px;font-family:'JetBrains Mono',monospace}
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--b);flex-wrap:wrap}
.tab{padding:9px 16px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.2s}
.tab:hover{color:var(--t)}.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tc{display:none}.tc.active{display:block}
.pc{border-radius:9px;background:rgba(255,255,255,0.015);margin-bottom:9px;overflow:hidden}
.ph{padding:13px 16px;cursor:pointer;display:flex;align-items:center;gap:12px;flex-wrap:wrap;user-select:none}
.pn{padding:6px 12px;border-radius:7px;font-family:'JetBrains Mono',monospace;font-weight:800;font-size:15px;min-width:66px;text-align:center}
.pi{flex:1;min-width:0}
.pname{font-weight:700;font-size:14px}
.psub{color:var(--m);font-size:12px;margin-top:2px;font-family:'JetBrains Mono',monospace}
.pm{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bdg{border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:1px;font-family:'JetBrains Mono',monospace;border:1px solid transparent}
.chev{color:var(--m);font-size:10px;transition:transform 0.25s;flex-shrink:0}
.pb2{padding:0 16px 16px;border-top:1px solid var(--b);display:none}
.pb2.open{display:block}
.st{color:var(--m);font-size:11px;letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin:14px 0 7px}
.ci{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px;margin-bottom:6px}
.ct{display:flex;align-items:center;gap:7px;margin-bottom:6px;flex-wrap:wrap}
.cid{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;text-decoration:none}
.cid:hover{text-decoration:underline}
.cdate{color:var(--m);font-size:10px;margin-left:auto;font-family:'JetBrains Mono',monospace}
.cdesc{color:#8e8e93;font-size:13px;line-height:1.7}
.ml{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.mi{display:flex;gap:9px;padding:5px 0;border-bottom:1px solid var(--b);font-size:13px;line-height:1.6;color:#c0c0d0}
.mi:last-child{border-bottom:none}
.ma{color:var(--green);font-family:'JetBrains Mono',monospace;flex-shrink:0}
.ssl-card{background:var(--s2);border-radius:9px;padding:16px;margin-bottom:11px;border:1px solid var(--b2)}
.gc2{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.ssl-hdr{display:flex;align-items:center;gap:16px;margin-bottom:12px}
.iss-item{display:flex;gap:9px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--b);font-size:13px}
.iss-item:last-child{border-bottom:none}
.dns-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:9px;margin-bottom:12px}
.dr{background:var(--s2);border:1px solid var(--b2);border-radius:7px;padding:11px}
.dtype{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--cyan);letter-spacing:2px;margin-bottom:5px}
.dval{font-size:12px;color:#8e8e93;line-height:1.7;font-family:'JetBrains Mono',monospace;word-break:break-all}
.sub-item{background:var(--s2);border:1px solid var(--b2);border-radius:5px;padding:7px 11px;font-family:'JetBrains Mono',monospace;font-size:12px;display:flex;justify-content:space-between;margin-bottom:4px}
.hdr-grade{font-size:48px;font-weight:900;font-family:'JetBrains Mono',monospace;line-height:1}
.hl{background:var(--s2);border-radius:7px;overflow:hidden;border:1px solid var(--b2)}
.hi{display:flex;justify-content:space-between;align-items:center;padding:7px 13px;border-bottom:1px solid var(--b);font-size:12px;font-family:'JetBrains Mono',monospace;flex-wrap:wrap;gap:6px}
.hi:last-child{border-bottom:none}
.hk{color:var(--m);min-width:180px;flex-shrink:0}.hv{color:var(--t);word-break:break-all;text-align:right;max-width:380px}
.hg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px}
.ht{background:var(--s2);border:1px solid var(--b2);border-radius:9px;padding:13px;cursor:pointer;transition:all 0.2s}
.ht:hover{border-color:var(--cyan)}
.hip{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:var(--cyan)}
.tbl{width:100%;border-collapse:collapse;font-size:13px;font-family:'JetBrains Mono',monospace}
.tbl th{color:var(--m);font-size:10px;letter-spacing:2px;padding:9px 10px;text-align:left;border-bottom:1px solid var(--b)}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--b);color:var(--t);vertical-align:middle;word-break:break-word}
.tbl tr:hover td{background:rgba(255,255,255,0.015)}
.lbtn{background:transparent;border:1px solid var(--b2);color:var(--cyan);padding:4px 9px;border-radius:4px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:10px}
.lbtn:hover{background:rgba(0,229,255,0.07)}
.lbtn.red{color:var(--red);border-color:rgba(255,51,102,0.3)}
.lbtn.red:hover{background:rgba(255,51,102,0.07)}
.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:9px;font-size:11px;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
.bl{color:var(--m);width:75px;text-align:right;flex-shrink:0;font-size:10px}
.bt{flex:1;background:var(--b);border-radius:2px;height:7px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width 1s ease}
.bv{color:var(--t);width:25px;flex-shrink:0}
.res-tbl{width:100%;border-collapse:collapse;font-size:12px;font-family:'JetBrains Mono',monospace;margin-top:8px}
.res-tbl th{color:var(--m);font-size:10px;letter-spacing:2px;padding:8px 10px;text-align:left;border-bottom:1px solid var(--b);background:var(--s2)}
.res-tbl td{padding:7px 10px;border-bottom:1px solid var(--b);vertical-align:middle;word-break:break-all}
.res-tbl tr:hover td{background:rgba(255,255,255,0.015)}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;border:1px solid transparent}
.bf-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
textarea.scan-inp{resize:vertical;min-height:80px;font-size:13px}
.sel{background:var(--s2);border:1px solid var(--b2);border-radius:9px;color:var(--t);padding:10px 12px;font-size:13px;font-family:'JetBrains Mono',monospace;outline:none;width:100%}
.sel:focus{border-color:var(--cyan)}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.admin-badge{background:rgba(255,214,10,0.1);color:var(--yellow);border:1px solid rgba(255,214,10,0.2);border-radius:4px;padding:2px 8px;font-size:10px;font-family:'JetBrains Mono',monospace}
.user-badge{background:rgba(0,229,255,0.08);color:var(--cyan);border:1px solid rgba(0,229,255,0.2);border-radius:4px;padding:2px 8px;font-size:10px;font-family:'JetBrains Mono',monospace}
.notice{background:rgba(255,214,10,0.06);border:1px solid rgba(255,214,10,0.2);border-radius:8px;padding:10px 14px;color:var(--yellow);font-size:12px;font-family:'JetBrains Mono',monospace;margin-bottom:14px}
.found-badge{background:rgba(0,255,157,0.1);color:var(--green);border:1px solid rgba(0,255,157,0.25);border-radius:5px;padding:3px 9px;font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace}
.spin{display:inline-block;width:11px;height:11px;border:2px solid var(--b2);border-top-color:var(--cyan);border-radius:50%;animation:sp 0.8s linear infinite;margin-right:7px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
@media(max-width:600px){.bf-grid{grid-template-columns:1fr}.hero h2{font-size:22px}header{height:auto;padding:10px 16px}}
</style>
</head>
<body>
<canvas id="particles-canvas"></canvas>

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
      <div class="fg"><label>USERNAME</label><input class="inp" id="r-user" type="text" placeholder="username (letters, numbers, _ -)"/></div>
      <div class="fg"><label>EMAIL</label><input class="inp" id="r-email" type="email" placeholder="you@example.com"/></div>
      <div class="fg"><label>PASSWORD</label><input class="inp" id="r-pass" type="password" placeholder="Min 8 chars, 1 uppercase, 1 number"/></div>
      <button class="btn btn-p" id="r-btn" onclick="doRegister()" style="margin-top:4px">CREATE ACCOUNT</button>
      <div style="text-align:center;margin-top:14px">
        <button class="auth-link" onclick="authTab('login')">Already have an account?</button>
      </div>
    </div>
    <div id="form-forgot" style="display:none">
      <div class="fg"><label>EMAIL ADDRESS</label><input class="inp" id="f-email" type="email" placeholder="you@example.com"/></div>
      <button class="btn btn-p" onclick="doForgot()" style="margin-top:4px">SEND RESET LINK</button>
      <div style="text-align:center;margin-top:14px">
        <button class="auth-link" onclick="authTab('login')">Back to login</button>
      </div>
    </div>
  </div>
</div>

<!-- ══ ABOUT MODAL ══ -->
<div id="about-modal" style="display:none;position:fixed;inset:0;background:rgba(4,4,10,0.92);z-index:300;align-items:center;justify-content:center;backdrop-filter:blur(12px)" onclick="if(event.target===this)closeAbout()">
  <div style="background:var(--s1);border:1px solid var(--b2);border-radius:18px;padding:40px;width:100%;max-width:560px;position:relative;margin:16px">
    <!-- Close button -->
    <button onclick="closeAbout()" style="position:absolute;top:16px;right:18px;background:transparent;border:none;color:var(--m);cursor:pointer;font-size:20px;line-height:1">&#10005;</button>

    <!-- Logo + Title -->
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:24px">
      <div style="width:48px;height:48px;background:linear-gradient(135deg,var(--red),var(--orange));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0;box-shadow:0 0 24px rgba(255,51,102,0.35)">&#9889;</div>
      <div>
        <div style="font-size:22px;font-weight:800;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent">VulnScan Pro</div>
        <div style="font-size:10px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-top:2px">OPEN SOURCE SECURITY PLATFORM</div>
      </div>
    </div>

    <!-- Divider -->
    <div style="height:1px;background:linear-gradient(90deg,var(--red),var(--purple),transparent);margin-bottom:22px"></div>

    <!-- Purpose -->
    <div style="margin-bottom:20px">
      <div style="font-size:10px;color:var(--m);letter-spacing:3px;font-family:'JetBrains Mono',monospace;margin-bottom:8px">PURPOSE</div>
      <p style="color:#c0c0d0;font-size:14px;line-height:1.8;margin:0">
        VulnScan Pro is a free, open-source vulnerability assessment platform designed for security professionals, penetration testers, and system administrators. It enables comprehensive scanning of networks, web servers, and infrastructure to identify security weaknesses before attackers do.
      </p>
    </div>

    <!-- Features grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:22px">
      <div style="background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px">
        <div style="color:var(--cyan);font-size:18px;margin-bottom:5px">&#128268;</div>
        <div style="font-size:12px;font-weight:700;color:var(--t);margin-bottom:3px">Port Scanner</div>
        <div style="font-size:11px;color:var(--m)">Nmap-powered with CVE intelligence</div>
      </div>
      <div style="background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px">
        <div style="color:var(--purple);font-size:18px;margin-bottom:5px">&#127760;</div>
        <div style="font-size:12px;font-weight:700;color:var(--t);margin-bottom:3px">Subdomain Finder</div>
        <div style="font-size:11px;color:var(--m)">crt.sh + HackerTarget + brute force</div>
      </div>
      <div style="background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px">
        <div style="color:var(--orange);font-size:18px;margin-bottom:5px">&#128193;</div>
        <div style="font-size:12px;font-weight:700;color:var(--t);margin-bottom:3px">Directory Buster</div>
        <div style="font-size:11px;color:var(--m)">Hidden path & file enumeration</div>
      </div>
      <div style="background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:12px">
        <div style="color:var(--green);font-size:18px;margin-bottom:5px">&#128274;</div>
        <div style="font-size:12px;font-weight:700;color:var(--t);margin-bottom:3px">SSL/TLS Analyser</div>
        <div style="font-size:11px;color:var(--m)">Certificate & cipher analysis</div>
      </div>
    </div>

    <!-- Divider -->
    <div style="height:1px;background:var(--b2);margin-bottom:20px"></div>

    <!-- Creator -->
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px">
      <div style="width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,var(--cyan),var(--purple));display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:var(--bg);flex-shrink:0">V</div>
      <div>
        <div style="font-size:14px;font-weight:700;color:var(--t)">Vijay Katariya</div>
        <div style="font-size:11px;color:var(--m);font-family:'JetBrains Mono',monospace;margin-top:2px">Creator &amp; Lead Developer</div>
        <div style="font-size:11px;color:var(--cyan);font-family:'JetBrains Mono',monospace;margin-top:1px">Motalund Organization</div>
      </div>
      <div style="margin-left:auto;text-align:right">
        <div style="background:rgba(0,255,157,0.08);border:1px solid rgba(0,255,157,0.2);border-radius:20px;padding:4px 12px;font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--green)">&#11044; OPEN SOURCE</div>
      </div>
    </div>

    <!-- Disclaimer -->
    <div style="background:rgba(255,214,10,0.05);border:1px solid rgba(255,214,10,0.15);border-radius:8px;padding:12px">
      <div style="font-size:11px;color:var(--yellow);font-family:'JetBrains Mono',monospace;line-height:1.7">
        &#9888; <strong>Legal Disclaimer:</strong> This tool is intended for authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.
      </div>
    </div>

    <!-- GitHub link -->
    <div style="text-align:center;margin-top:18px">
      <a href="https://github.com/labpnet33/vulnscan" target="_blank" style="display:inline-flex;align-items:center;gap:8px;background:var(--s2);border:1px solid var(--b2);border-radius:8px;padding:9px 18px;color:var(--t);text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:12px;transition:border-color 0.2s" onmouseover="this.style.borderColor='var(--cyan)'" onmouseout="this.style.borderColor='var(--b2)'">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        github.com/labpnet33/vulnscan
      </a>
    </div>
  </div>
</div>

<!-- ══ HEADER ══ -->
<header>
  <div class="brand brand-link" onclick="pg('home',null)" title="Go to Home">
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

    <!-- ── 01 Information Gathering ── -->
    <div class="nav-dropdown" id="dd-info">
      <button class="nav-dropdown-btn" id="dd-info-btn">
        &#128270; Info Gathering <span class="arrow">&#9660;</span>
      </button>
      <div class="nav-dropdown-menu" id="dd-info-menu">
        <div class="nav-dropdown-section">&#9632; NETWORK</div>
        <button class="nav-dropdown-item" id="dd-item-scan" onclick="pgFromDd('scan','info')">
          <span class="item-icon">&#128268;</span><span class="item-label">Network Scanner</span><span class="item-badge">nmap</span>
        </button>
        <button class="nav-dropdown-item" id="dd-item-dnsrecon" onclick="pgFromDd('dnsrecon','info')">
          <span class="item-icon">&#127760;</span><span class="item-label">DNSRecon</span><span class="item-badge">dns</span>
        </button>
        <button class="nav-dropdown-item" id="dd-item-disc" onclick="pgFromDd('disc','info')">
          <span class="item-icon">&#128225;</span><span class="item-label">Network Discovery</span><span class="item-badge">subnet</span>
        </button>
        <button class="nav-dropdown-item" id="dd-item-legion" onclick="pgFromDd('legion','info')">
          <span class="item-icon">&#9881;</span><span class="item-label">Legion</span><span class="item-badge">auto</span>
        </button>
        <div class="nav-dropdown-section">&#9632; OSINT</div>
        <button class="nav-dropdown-item" id="dd-item-harvester" onclick="pgFromDd('harvester','info')">
          <span class="item-icon">&#127919;</span><span class="item-label">theHarvester</span><span class="item-badge">recon</span>
        </button>
        <button class="nav-dropdown-item" id="dd-item-sub" onclick="pgFromDd('sub','info')">
          <span class="item-icon">&#127758;</span><span class="item-label">Subdomain Finder</span><span class="item-badge">dns</span>
        </button>
      </div>
    </div>

    <!-- ── 02 Web Application Testing ── -->
    <div class="nav-dropdown" id="dd-web">
      <button class="nav-dropdown-btn" id="dd-web-btn">
        &#127760; Web Testing <span class="arrow">&#9660;</span>
      </button>
      <div class="nav-dropdown-menu" id="dd-web-menu">
        <div class="nav-dropdown-section">&#9632; SCANNERS</div>
        <button class="nav-dropdown-item" id="dd-item-nikto" onclick="pgFromDd('nikto','web')">
          <span class="item-icon">&#128200;</span><span class="item-label">Nikto</span><span class="item-badge">web vuln</span>
        </button>
        <button class="nav-dropdown-item" id="dd-item-wpscan" onclick="pgFromDd('wpscan','web')">
          <span class="item-icon">&#128196;</span><span class="item-label">WPScan</span><span class="item-badge">wordpress</span>
        </button>
        <div class="nav-dropdown-section">&#9632; ENUMERATION</div>
        <button class="nav-dropdown-item" id="dd-item-dir" onclick="pgFromDd('dir','web')">
          <span class="item-icon">&#128193;</span><span class="item-label">Directory Buster</span><span class="item-badge">fuzzing</span>
        </button>
      </div>
    </div>

    <!-- ── 03 Password Attacks ── -->
    <div class="nav-dropdown" id="dd-pwd">
      <button class="nav-dropdown-btn" id="dd-pwd-btn">
        &#128272; Password Attacks <span class="arrow">&#9660;</span>
      </button>
      <div class="nav-dropdown-menu" id="dd-pwd-menu">
        <div class="nav-dropdown-section">&#9632; BRUTE FORCE</div>
        <button class="nav-dropdown-item" id="dd-item-brute" onclick="pgFromDd('brute','pwd')">
          <span class="item-icon">&#128272;</span><span class="item-label">Brute Force</span><span class="item-badge">http/ssh</span>
        </button>
      </div>
    </div>

    <!-- ── 04 System Auditing ── -->
    <div class="nav-dropdown" id="dd-audit">
      <button class="nav-dropdown-btn" id="dd-audit-btn">
        &#128203; System Auditing <span class="arrow">&#9660;</span>
      </button>
      <div class="nav-dropdown-menu" id="dd-audit-menu">
        <div class="nav-dropdown-section">&#9632; HOST SECURITY</div>
        <button class="nav-dropdown-item" id="dd-item-lynis" onclick="pgFromDd('lynis','audit')">
          <span class="item-icon">&#128203;</span><span class="item-label">Lynis</span><span class="item-badge">hardening</span>
        </button>
      </div>
    </div>

    <!-- ── Utilities ── -->
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
    <h1>VulnScan Pro</h1>
    <p>Professional security reconnaissance &amp; vulnerability assessment platform. Built for pentesters, sysadmins, and security researchers.</p>
    <div class="home-quick">
      <button class="home-quick-btn" onclick="pgFromDd('scan','info')">&#128268; Quick Network Scan</button>
      <button class="home-quick-btn" onclick="pgFromDd('harvester','info')">&#127919; OSINT Harvest</button>
      <button class="home-quick-btn" onclick="pg('sub',null)">&#127760; Subdomain Finder</button>
      <button class="home-quick-btn" onclick="pg('hist',null)">&#128196; View History</button>
    </div>
  </div>

  <!-- Live Stats -->
  <div class="home-stats" id="home-stats">
    <div class="home-stat"><div class="home-stat-val" id="hs-scans">—</div><div class="home-stat-lbl">TOTAL SCANS</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-cves" style="background:linear-gradient(135deg,var(--red),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">—</div><div class="home-stat-lbl">CVEs FOUND</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-ports" style="background:linear-gradient(135deg,var(--yellow),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">—</div><div class="home-stat-lbl">OPEN PORTS</div></div>
    <div class="home-stat"><div class="home-stat-val" id="hs-tools" style="background:linear-gradient(135deg,var(--green),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent">12</div><div class="home-stat-lbl">TOOLS AVAILABLE</div></div>
  </div>

  <!-- Category: Information Gathering -->
  <div class="home-cat">
    <div class="home-cat-title">&#128270; 01 — INFORMATION GATHERING</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--cyan)" onclick="pgFromDd('scan','info')">
        <div class="home-tool-icon">&#128268;</div>
        <div class="home-tool-name">Network Scanner</div>
        <div class="home-tool-desc">Deep port scanning with nmap, CVE lookups via NVD, SSL analysis, DNS records, and HTTP header auditing in a single run.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">nmap</span>
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">CVE</span>
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">SSL</span>
        </div>
      </div>
      <div class="home-tool-card" style="--tool-c:var(--cyan)" onclick="pgFromDd('dnsrecon','info')">
        <div class="home-tool-icon">&#127760;</div>
        <div class="home-tool-name">DNSRecon</div>
        <div class="home-tool-desc">Comprehensive DNS enumeration — zone transfers, record types (A, MX, NS, TXT, SRV), reverse lookups, and DNS cache snooping.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">DNS</span>
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">zone transfer</span>
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">records</span>
        </div>
      </div>
      <div class="home-tool-card" style="--tool-c:var(--yellow)" onclick="pgFromDd('disc','info')">
        <div class="home-tool-icon">&#128225;</div>
        <div class="home-tool-name">Network Discovery</div>
        <div class="home-tool-desc">Sweep subnets to discover live hosts, identify OS fingerprints, and map your network topology automatically.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">subnet</span>
          <span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">host discovery</span>
        </div>
      </div>
      <div cla
