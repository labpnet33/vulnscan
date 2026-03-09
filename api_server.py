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
:root{--bg:#04040a;--s1:#080810;--s2:#0d0d18;--b:#16162a;--b2:#1e1e35;--t:#e8e8f0;--m:#5a5a8a;
      --cyan:#00e5ff;--green:#00ff9d;--red:#ff3366;--orange:#ff6b35;--yellow:#ffd60a;--purple:#b06fff;}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--t);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,229,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.025) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
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
      <div class="brand-name">VulnScan Pro</div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
        <div class="brand-tag">SECURITY PLATFORM</div>
        <span class="ver-badge">v3.2</span>
      </div>
    </div>
  </div>
  <nav id="main-nav">
    <!-- ── Information Gathering Dropdown ── -->
    <div class="nav-dropdown" id="dd-info">
      <button class="nav-dropdown-btn" id="dd-info-btn">
        &#128270; Information Gathering <span class="arrow">&#9660;</span>
      </button>
      <div class="nav-dropdown-menu" id="dd-info-menu">
        <div class="nav-dropdown-section">&#9632; NETWORK</div>
        <button class="nav-dropdown-item" id="dd-item-scan" onclick="pgFromDd('scan','info')">
          <span class="item-icon">&#128268;</span>
          <span class="item-label">Network Scanner</span>
          <span class="item-badge">nmap</span>
        </button>
        <div class="nav-dropdown-section">&#9632; OSINT</div>
        <button class="nav-dropdown-item" id="dd-item-harvester" onclick="pgFromDd('harvester','info')">
          <span class="item-icon">&#127919;</span>
          <span class="item-label">theHarvester</span>
          <span class="item-badge">recon</span>
        </button>
      </div>
    </div>
    <!-- ── Regular Nav ── -->
    <button class="nb" onclick="pg('sub',this)">&#127760; Subdomains</button>
    <button class="nb" onclick="pg('dir',this)">&#128193; DirBust</button>
    <button class="nb" onclick="pg('brute',this)">&#128272; BruteForce</button>
    <button class="nb" onclick="pg('disc',this)">&#128225; Discover</button>
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
    <div class="home-stat"><div class="home-stat-val" id="hs-tools" style="background:linear-gradient(135deg,var(--green),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent">7</div><div class="home-stat-lbl">TOOLS AVAILABLE</div></div>
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
          <span class="home-tool-tag" style="background:rgba(0,229,255,0.1);color:var(--cyan)">DNS</span>
        </div>
      </div>
      <div class="home-tool-card" style="--tool-c:var(--purple)" onclick="pgFromDd('harvester','info')">
        <div class="home-tool-icon">&#127919;</div>
        <div class="home-tool-name">theHarvester</div>
        <div class="home-tool-desc">OSINT recon to harvest emails, subdomains, hosts, and IPs from public sources — Google, Bing, LinkedIn, crt.sh, and more.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">OSINT</span>
          <span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">emails</span>
          <span class="home-tool-tag" style="background:rgba(176,111,255,0.1);color:var(--purple)">subdomains</span>
        </div>
      </div>
      <div class="home-tool-card" style="--tool-c:var(--green)" onclick="pg('sub',null)">
        <div class="home-tool-icon">&#127760;</div>
        <div class="home-tool-name">Subdomain Finder</div>
        <div class="home-tool-desc">Enumerate subdomains via DNS brute-force and passive sources. Map the full attack surface of any domain.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">DNS</span>
          <span class="home-tool-tag" style="background:rgba(0,255,157,0.1);color:var(--green)">brute-force</span>
        </div>
      </div>
      <div class="home-tool-card" style="--tool-c:var(--yellow)" onclick="pg('disc',null)">
        <div class="home-tool-icon">&#128225;</div>
        <div class="home-tool-name">Network Discovery</div>
        <div class="home-tool-desc">Sweep subnets to discover live hosts, identify OS fingerprints, and map your network topology automatically.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">subnet</span>
          <span class="home-tool-tag" style="background:rgba(255,214,10,0.1);color:var(--yellow)">host discovery</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Category: Web Application Testing -->
  <div class="home-cat">
    <div class="home-cat-title">&#127760; 02 — WEB APPLICATION TESTING</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--orange)" onclick="pg('dir',null)">
        <div class="home-tool-icon">&#128193;</div>
        <div class="home-tool-name">Directory Buster</div>
        <div class="home-tool-desc">Brute-force hidden directories, admin panels, and sensitive files on web servers using wordlist-based enumeration.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">HTTP</span>
          <span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">fuzzing</span>
          <span class="home-tool-tag" style="background:rgba(255,107,53,0.1);color:var(--orange)">wordlist</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Category: Password Attacks -->
  <div class="home-cat">
    <div class="home-cat-title">&#128272; 03 — PASSWORD ATTACKS</div>
    <div class="home-tools-grid">
      <div class="home-tool-card" style="--tool-c:var(--red)" onclick="pg('brute',null)">
        <div class="home-tool-icon">&#128272;</div>
        <div class="home-tool-name">Brute Force</div>
        <div class="home-tool-desc">Credential testing against HTTP login forms and SSH services using custom or built-in wordlists.</div>
        <div class="home-tool-tags">
          <span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">HTTP</span>
          <span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">SSH</span>
          <span class="home-tool-tag" style="background:rgba(255,51,102,0.1);color:var(--red)">credentials</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Legal notice -->
  <div style="background:rgba(255,214,10,0.04);border:1px solid rgba(255,214,10,0.12);border-radius:10px;padding:14px 18px;margin-bottom:24px;display:flex;gap:12px;align-items:flex-start">
    <span style="font-size:16px">&#9888;</span>
    <div style="font-size:11px;color:var(--m);font-family:'JetBrains Mono',monospace;line-height:1.8">
      <strong style="color:var(--yellow)">Authorized Use Only.</strong> VulnScan Pro is designed exclusively for security testing on systems you own or have explicit written permission to assess. Unauthorized use is illegal and unethical. Always obtain proper authorization before scanning.
    </div>
  </div>
</div>

<!-- ═══ SCANNER ═══ -->
<div class="page" id="page-scan">
  <div class="hero">
    <h2>Vulnerability Intelligence</h2>
    <p>Port scan &middot; CVE lookup &middot; SSL analysis &middot; DNS recon &middot; Header audit</p>
    <div class="row">
      <input class="scan-inp" id="tgt" type="text" placeholder="IP address or hostname  e.g. 192.168.1.1" onkeydown="if(event.key==='Enter')doScan()"/>
      <button class="btn btn-p" id="sbtn" onclick="doScan()">SCAN</button>
    </div>
    <div class="mods">
      <button class="mt on" id="mod-ports" onclick="tmg('ports',this)">&#128268; Ports+CVE</button>
      <button class="mt on" id="mod-ssl" onclick="tmg('ssl',this)">&#128274; SSL/TLS</button>
      <button class="mt on" id="mod-dns" onclick="tmg('dns',this)">&#127758; DNS</button>
      <button class="mt on" id="mod-headers" onclick="tmg('headers',this)">&#128196; Headers</button>
    </div>
    <!-- FIX: Added scan timeout info notice -->
    <p style="color:var(--m);font-size:11px;margin-top:12px;font-family:'JetBrains Mono',monospace">&#9432; Scans may take 30–180 seconds. Please wait.</p>
  </div>
  <div id="prog"><div id="pb"></div></div>
  <div id="term"></div>
  <div id="err"></div>
  <div id="res"></div>
</div>

<!-- ═══ THE HARVESTER ═══ -->
<div class="page" id="page-harvester">
  <div class="card">
    <div class="ctitle">&#127919; theHarvester — OSINT Recon</div>
    <div class="notice">&#9888; Only perform reconnaissance on domains you own or have explicit written permission to test.</div>
    <div class="hero" style="padding:16px 0 8px">
      <p style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace;max-width:600px;margin:0 auto">
        theHarvester gathers emails, subdomains, hosts, employee names, open ports, and banners from public sources (Google, Bing, LinkedIn, DNS, and more).
      </p>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="fg">
        <label>TARGET DOMAIN</label>
        <input class="inp" id="hv-target" type="text" placeholder="e.g. example.com" />
      </div>
      <div class="fg">
        <label>DATA SOURCES</label>
        <select class="inp" id="hv-sources" multiple style="height:90px;padding:6px">
          <option value="google" selected>Google</option>
          <option value="bing" selected>Bing</option>
          <option value="linkedin">LinkedIn</option>
          <option value="dnsdumpster" selected>DNSDumpster</option>
          <option value="crtsh" selected>crt.sh</option>
          <option value="hackertarget">HackerTarget</option>
          <option value="baidu">Baidu</option>
          <option value="yahoo">Yahoo</option>
        </select>
        <div style="font-size:9px;color:var(--m);margin-top:3px;font-family:'JetBrains Mono',monospace">Hold Ctrl/Cmd to select multiple</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="fg">
        <label>RESULT LIMIT</label>
        <input class="inp" id="hv-limit" type="number" value="500" min="50" max="2000" />
      </div>
      <div class="fg">
        <label>DNS BRUTE-FORCE</label>
        <select class="inp" id="hv-dns">
          <option value="">Disabled</option>
          <option value="-f /tmp/hv_out -b all --dns-brute">Enable</option>
        </select>
      </div>
      <div class="fg">
        <label>OUTPUT FORMAT</label>
        <select class="inp" id="hv-fmt">
          <option value="xml">XML (full)</option>
          <option value="json">JSON</option>
        </select>
      </div>
    </div>
    <button class="btn btn-p" id="hv-btn" onclick="doHarvest()" style="width:auto;padding:10px 32px">&#127919; RUN HARVESTER</button>
    <p style="color:var(--m);font-size:11px;margin-top:12px;font-family:'JetBrains Mono',monospace">&#9432; Recon may take 30–120 seconds depending on sources selected.</p>
    <div id="hv-prog" style="display:none;margin-top:14px"><div style="height:3px;background:var(--b2);border-radius:2px"><div id="hv-pb" style="height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--purple));border-radius:2px;transition:width 0.4s"></div></div></div>
    <div id="hv-term" class="terminal" style="display:none;margin-top:14px"></div>
    <div id="hv-err" class="err-box" style="display:none;margin-top:10px"></div>
    <div id="hv-res" style="display:none;margin-top:16px"></div>
  </div>
</div>

<!-- ═══ SUBDOMAIN ═══ -->
<div class="page" id="page-sub">
  <div class="card">
    <div class="ctitle">SUBDOMAIN FINDER</div>
    <div class="notice">&#9888; Only enumerate domains you own or have written permission to test.</div>
    <div class="fg"><label>DOMAIN</label><input class="scan-inp" id="sub-domain" placeholder="example.com" type="text" style="width:100%"/></div>
    <div class="fg" style="margin-top:12px"><label>WORDLIST SIZE</label>
      <select class="sel" id="sub-size"><option value="small">Small (~30 words, faster)</option><option value="medium" selected>Medium (~80 words + crt.sh + HackerTarget)</option></select></div>
    <button class="btn btn-p btn-full" id="sub-btn" onclick="doSub()" style="margin-top:4px">FIND SUBDOMAINS</button>
  </div>
  <div id="sub-res"></div>
</div>

<!-- ═══ DIRBUSTER ═══ -->
<div class="page" id="page-dir">
  <div class="card">
    <div class="ctitle">DIRECTORY ENUMERATOR</div>
    <div class="notice">&#9888; Only scan web servers you own or have written permission to test.</div>
    <div class="fg"><label>TARGET URL</label><input class="scan-inp" id="dir-url" placeholder="http://192.168.1.1 or https://example.com" type="text" style="width:100%"/></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
      <div class="fg"><label>WORDLIST SIZE</label><select class="sel" id="dir-size"><option value="small" selected>Small (~60 paths)</option><option value="medium">Medium (~130 paths)</option></select></div>
      <div class="fg"><label>EXTENSIONS</label><input class="scan-inp" id="dir-ext" value="php,html,txt,bak,zip,json,xml" type="text" style="width:100%"/></div>
    </div>
    <button class="btn btn-p btn-full" id="dir-btn" onclick="doDir()">START ENUMERATION</button>
  </div>
  <div id="dir-res"></div>
</div>

<!-- ═══ BRUTE FORCE ═══ -->
<div class="page" id="page-brute">
  <div class="card">
    <div class="ctitle">LOGIN BRUTE FORCE TESTER</div>
    <div class="notice">&#9888; ONLY use on systems you own or have explicit written permission. Unauthorized use is illegal.</div>
    <div class="fg"><label>ATTACK TYPE</label><select class="sel" id="bf-type" onchange="bfTypeChange()"><option value="http">HTTP Form Login</option><option value="ssh">SSH Login</option></select></div>
    <div id="bf-http-fields">
      <div class="bf-grid">
        <div class="fg"><label>LOGIN URL</label><input class="scan-inp" id="bf-url" placeholder="http://192.168.1.1/login" type="text" style="width:100%"/></div>
        <div class="fg"><label>USERNAME FIELD</label><input class="scan-inp" id="bf-ufield" value="username" type="text" style="width:100%"/></div>
        <div class="fg"><label>PASSWORD FIELD</label><input class="scan-inp" id="bf-pfield" value="password" type="text" style="width:100%"/></div>
      </div>
    </div>
    <div id="bf-ssh-fields" style="display:none">
      <div class="bf-grid">
        <div class="fg"><label>HOST</label><input class="scan-inp" id="bf-ssh-host" placeholder="192.168.1.1" type="text" style="width:100%"/></div>
        <div class="fg"><label>PORT</label><input class="scan-inp" id="bf-ssh-port" value="22" type="text" style="width:100%"/></div>
      </div>
    </div>
    <div class="bf-grid" style="margin-top:12px">
      <div class="fg"><label>USERNAMES (one per line)</label><textarea class="scan-inp" id="bf-users" placeholder="admin&#10;root&#10;user"></textarea></div>
      <div class="fg"><label>PASSWORDS (one per line)</label><textarea class="scan-inp" id="bf-pwds" placeholder="admin&#10;password&#10;123456"></textarea></div>
    </div>
    <button class="btn btn-p btn-full" id="bf-btn" onclick="doBrute()">START BRUTE FORCE</button>
  </div>
  <div id="bf-res"></div>
</div>

<!-- ═══ DISCOVER ═══ -->
<div class="page" id="page-disc">
  <div class="card">
    <div class="ctitle">NETWORK DISCOVERY</div>
    <div class="row">
      <input class="scan-inp" id="subnet" placeholder="192.168.1.0/24" type="text" onkeydown="if(event.key==='Enter')doDisc()" style="flex:1"/>
      <button class="btn btn-p" id="disc-btn" onclick="doDisc()">DISCOVER</button>
    </div>
    <p style="color:var(--m);font-size:11px;margin-top:10px;font-family:'JetBrains Mono',monospace">&#9888; Only scan networks you own or have permission to scan</p>
  </div>
  <div id="disc-res"></div>
</div>

<!-- ═══ HISTORY ═══ -->
<div class="page" id="page-hist">
  <div class="card">
    <div class="ctitle">SCAN HISTORY</div>
    <div id="hist-content"><p style="color:var(--m);font-size:13px">Loading...</p></div>
  </div>
</div>

<!-- ═══ DASHBOARD ═══ -->
<div class="page" id="page-dash">
  <div class="card">
    <div class="ctitle">SECURITY DASHBOARD</div>
    <div id="dash-content"><p style="color:var(--m);font-size:13px">Run some scans to see statistics.</p></div>
  </div>
</div>

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
</div>

<!-- ═══ ADMIN ═══ -->
<div class="page" id="page-admin">
  <div class="tabs" id="admin-tabs">
    <button class="tab active" onclick="adminTab(event,'at-users')">&#128100; Users</button>
    <button class="tab" onclick="adminTab(event,'at-stats')">&#128202; Stats</button>
    <button class="tab" onclick="adminTab(event,'at-audit')">&#128196; Audit Log</button>
    <button class="tab" onclick="adminTab(event,'at-scans')">&#128269; All Scans</button>
  </div>
  <div class="tc active" id="at-users">
    <div class="card"><div class="ctitle">USER MANAGEMENT</div><div id="admin-users"><p style="color:var(--m)">Loading...</p></div></div>
  </div>
  <div class="tc" id="at-stats">
    <div class="card"><div class="ctitle">PLATFORM STATISTICS</div><div id="admin-stats"></div></div>
  </div>
  <div class="tc" id="at-audit">
    <div class="card"><div class="ctitle">AUDIT LOG</div><div id="admin-audit" style="overflow-x:auto"></div></div>
  </div>
  <div class="tc" id="at-scans">
    <div class="card"><div class="ctitle">ALL SCANS</div><div id="admin-scans" style="overflow-x:auto"></div></div>
  </div>
</div>

</div>

<script>
const SEV={CRITICAL:{c:"#ff3366",b:"rgba(255,51,102,0.12)",i:"&#9762;"},HIGH:{c:"#ff6b35",b:"rgba(255,107,53,0.12)",i:"&#9888;"},MEDIUM:{c:"#ffd60a",b:"rgba(255,214,10,0.1)",i:"&#9889;"},LOW:{c:"#00ff9d",b:"rgba(0,255,157,0.08)",i:"&#10003;"},UNKNOWN:{c:"#5a5a8a",b:"rgba(90,90,138,0.1)",i:"?"}};
const GC={"A+":"#00ff9d","A":"#00e5ff","B":"#ffd60a","C":"#ff6b35","D":"#ff6b35","F":"#ff3366"};
const mods={ports:true,ssl:true,dns:true,headers:true};
let busy=false,logEl=null,progT=null,progV=0,currentUser=null;

function authTab(t){
  document.querySelectorAll(".auth-tab").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll("[id^='form-']").forEach(e=>e.style.display="none");
  event.currentTarget.classList.add("active");
  document.getElementById("form-"+t).style.display="block";
  document.getElementById("auth-msg").style.display="none";
}
function authMsg(msg,type="err"){
  const el=document.getElementById("auth-msg");
  el.textContent=msg;el.className="auth-msg "+type;el.style.display="block";
}

async function doLogin(){
  const user=document.getElementById("l-user").value.trim();
  const pass=document.getElementById("l-pass").value;
  if(!user||!pass){authMsg("Enter username and password");return;}
  const btn=document.getElementById("l-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>LOGGING IN...';
  try{
    const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,password:pass})});
    const d=await r.json();
    if(d.success){
      authMsg("Welcome back, "+d.username+"!","ok");
      setTimeout(()=>{document.getElementById("auth-overlay").style.display="none";loadUser();},800);
    } else authMsg(d.error||"Login failed");
  }catch(e){authMsg("Connection error: "+e.message);}
  finally{btn.disabled=false;btn.innerHTML="LOGIN";}
}

async function doRegister(){
  const name=document.getElementById("r-name").value.trim();
  const user=document.getElementById("r-user").value.trim();
  const email=document.getElementById("r-email").value.trim();
  const pass=document.getElementById("r-pass").value;
  if(!user||!email||!pass){authMsg("All fields required");return;}
  const btn=document.getElementById("r-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>CREATING...';
  try{
    const r=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,email,password:pass,full_name:name})});
    const d=await r.json();
    if(d.success){
      authMsg(d.message,"ok");
      if(d.verified) setTimeout(()=>{authTab('login');},2000);
    } else authMsg(d.error||"Registration failed");
  }catch(e){authMsg("Error: "+e.message);}
  finally{btn.disabled=false;btn.innerHTML="CREATE ACCOUNT";}
}

async function doForgot(){
  const email=document.getElementById("f-email").value.trim();
  if(!email){authMsg("Enter your email");return;}
  try{
    const r=await fetch("/api/forgot-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email})});
    const d=await r.json();
    authMsg(d.message||d.error,(d.success?"ok":"err"));
  }catch(e){authMsg("Error: "+e.message);}
}

async function doLogout(){
  await fetch("/api/logout",{method:"POST"});
  currentUser=null;
  document.getElementById("auth-overlay").style.display="flex";
  document.getElementById("user-chip").style.display="none";
  document.getElementById("logout-btn").style.display="none";
  document.querySelectorAll(".admin-only").forEach(e=>e.style.display="none");
  document.getElementById("l-user").value="";
  document.getElementById("l-pass").value="";
  authTab("login");
}

async function loadUser(){
  try{
    const r=await fetch("/api/me");const d=await r.json();
    if(d.logged_in){
      currentUser=d;
      document.getElementById("auth-overlay").style.display="none";
      document.getElementById("user-chip").style.display="flex";
      document.getElementById("logout-btn").style.display="block";
      document.getElementById("user-avatar").textContent=d.username[0].toUpperCase();
      document.getElementById("user-name-disp").textContent=d.username;
      document.getElementById("user-role-disp").textContent=d.role==="admin"?"★ ADMIN":"USER";
      if(d.role==="admin") document.querySelectorAll(".admin-only").forEach(e=>e.style.display="block");
      loadProfileInfo(d);
      loadHomeStats();
    } else {
      document.getElementById("auth-overlay").style.display="flex";
    }
  }catch(e){document.getElementById("auth-overlay").style.display="flex";}
}

function loadProfileInfo(u){
  if(!u)return;
  document.getElementById("p-name").value=u.full_name||"";
  document.getElementById("profile-info").innerHTML=`
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-family:'JetBrains Mono',monospace;font-size:12px">
      <div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">USERNAME</div><div style="color:var(--cyan)">${u.username}</div></div>
      <div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">ROLE</div><div style="color:${u.role==='admin'?'var(--yellow)':'var(--t)'}">${u.role==='admin'?'★ ADMIN':'USER'}</div></div>
      <div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">EMAIL</div><div>${u.email}</div></div>
      <div style="background:var(--s2);border-radius:6px;padding:10px"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">LOGINS</div><div>${u.login_count||0}</div></div>
      <div style="background:var(--s2);border-radius:6px;padding:10px;grid-column:span 2"><div style="color:var(--m);font-size:9px;letter-spacing:2px;margin-bottom:4px">LAST LOGIN</div><div style="color:var(--m)">${u.last_login||'First login'}</div></div>
    </div>`;
}

async function saveProfile(){
  const name=document.getElementById("p-name").value.trim();
  try{
    const r=await fetch("/api/profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({full_name:name})});
    const d=await r.json();
    showPwdMsg(d.message||d.error,d.success?"ok":"err");
  }catch(e){showPwdMsg("Error: "+e.message,"err");}
}

async function changePassword(){
  const old=document.getElementById("cp-old").value;
  const n=document.getElementById("cp-new").value;
  const c=document.getElementById("cp-confirm").value;
  if(n!==c){showPwdMsg("New passwords do not match","err");return;}
  try{
    const r=await fetch("/api/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({old_password:old,new_password:n})});
    const d=await r.json();
    showPwdMsg(d.message||d.error,d.success?"ok":"err");
    if(d.success){document.getElementById("cp-old").value="";document.getElementById("cp-new").value="";document.getElementById("cp-confirm").value="";}
  }catch(e){showPwdMsg("Error: "+e.message,"err");}
}

function showPwdMsg(msg,type){const el=document.getElementById("pwd-msg");el.textContent=msg;el.className="auth-msg "+type;el.style.display="block";}

function pg(id,el){
  document.querySelectorAll(".page").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nb").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nav-dropdown-item").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nav-dropdown-btn").forEach(e=>e.classList.remove("active"));
  document.getElementById("page-"+id).classList.add("active");
  if(el)el.classList.add("active");
  if(id==="hist")loadHist();
  if(id==="dash")loadDash();
  if(id==="admin")loadAdmin();
  if(id==="home")loadHomeStats();
  if(id==="profile"&&currentUser)loadProfileInfo(currentUser);
}
function pgFromDd(id, ddId){
  document.querySelectorAll(".page").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nb").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nav-dropdown-item").forEach(e=>e.classList.remove("active"));
  document.querySelectorAll(".nav-dropdown-btn").forEach(e=>e.classList.remove("active"));
  document.getElementById("page-"+id).classList.add("active");
  const item=document.getElementById("dd-item-"+id);
  if(item)item.classList.add("active");
  const btn=document.getElementById("dd-"+ddId+"-btn");
  if(btn)btn.classList.add("active");
  if(id==="hist")loadHist();
  if(id==="dash")loadDash();
}
async function loadHomeStats(){
  try{
    const r=await fetch("/history");const d=await r.json();
    const scans=d.scans||[];
    let totalCves=0,totalPorts=0;
    scans.forEach(s=>{totalCves+=(s.total_cves||0);totalPorts+=(s.open_ports||0);});
    document.getElementById("hs-scans").textContent=scans.length;
    document.getElementById("hs-cves").textContent=totalCves;
    document.getElementById("hs-ports").textContent=totalPorts;
  }catch(e){["hs-scans","hs-cves","hs-ports"].forEach(id=>{const el=document.getElementById(id);if(el)el.textContent="0";});}
}

// ── theHarvester ──
let hvLogEl=null,hvProgT=null,hvProgV=0;
function hvLog(t,tp="i"){if(!hvLogEl)return;const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="tl t"+tp;d.innerHTML="<span class='p'>"+p+"</span> "+t;hvLogEl.appendChild(d);hvLogEl.scrollTop=hvLogEl.scrollHeight;}
function hvStartProg(){hvProgV=0;document.getElementById("hv-prog").style.display="block";document.getElementById("hv-pb").style.width="0%";hvProgT=setInterval(()=>{hvProgV=Math.min(hvProgV+(100-hvProgV)*0.035,90);document.getElementById("hv-pb").style.width=hvProgV+"%";},500);}
function hvEndProg(){clearInterval(hvProgT);document.getElementById("hv-pb").style.width="100%";setTimeout(()=>document.getElementById("hv-prog").style.display="none",400);}
async function doHarvest(){
  const target=document.getElementById("hv-target").value.trim();
  if(!target){alert("Please enter a target domain");return;}
  const srcEl=document.getElementById("hv-sources");
  const sources=Array.from(srcEl.selectedOptions).map(o=>o.value).join(",");
  const limit=document.getElementById("hv-limit").value||500;
  const btn=document.getElementById("hv-btn");
  btn.disabled=true;btn.textContent="Running...";
  hvLogEl=document.getElementById("hv-term");hvLogEl.innerHTML="";hvLogEl.style.display="block";
  document.getElementById("hv-err").style.display="none";
  document.getElementById("hv-res").style.display="none";
  hvStartProg();
  hvLog("Target: "+target);hvLog("Sources: "+sources);hvLog("Limit: "+limit);hvLog("Launching theHarvester...","w");
  try{
    const r=await fetchWithTimeout("/harvester",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target,sources,limit:parseInt(limit)})},180000);
    const d=await r.json();
    hvEndProg();
    if(d.error){document.getElementById("hv-err").textContent="Error: "+d.error;document.getElementById("hv-err").style.display="block";hvLog(d.error,"e");}
    else{hvLog("Done — "+( d.emails?.length||0)+" emails, "+(d.hosts?.length||0)+" hosts, "+(d.subdomains?.length||0)+" subdomains","s");renderHarvest(d);}
  }catch(e){hvEndProg();document.getElementById("hv-err").textContent="Error: "+e.message;document.getElementById("hv-err").style.display="block";hvLog(e.message,"e");}
  finally{btn.disabled=false;btn.textContent="🎯 RUN HARVESTER";}
}
function renderHarvest(d){
  const res=document.getElementById("hv-res");res.style.display="block";
  const emails=d.emails||[];const hosts=d.hosts||[];const subs=d.subdomains||[];const ips=d.ips||[];
  let html=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px">
    <div class="sc"><div class="sv" style="color:var(--cyan)">${emails.length}</div><div class="sl">EMAILS</div></div>
    <div class="sc"><div class="sv" style="color:var(--purple)">${hosts.length}</div><div class="sl">HOSTS</div></div>
    <div class="sc"><div class="sv" style="color:var(--green)">${subs.length}</div><div class="sl">SUBDOMAINS</div></div>
    <div class="sc"><div class="sv" style="color:var(--yellow)">${ips.length}</div><div class="sl">IPs FOUND</div></div>
  </div>`;
  if(emails.length){html+=`<div class="card" style="margin-bottom:12px"><div class="ctitle" style="font-size:11px">&#128231; EMAILS (${emails.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${emails.map(e=>`<span class="tag" style="background:rgba(0,229,255,0.08);color:var(--cyan);border-color:rgba(0,229,255,0.2)">${e}</span>`).join("")}</div></div>`;}
  if(subs.length){html+=`<div class="card" style="margin-bottom:12px"><div class="ctitle" style="font-size:11px">&#127760; SUBDOMAINS (${subs.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${subs.map(s=>`<span class="tag" style="background:rgba(176,111,255,0.08);color:var(--purple);border-color:rgba(176,111,255,0.2)">${s}</span>`).join("")}</div></div>`;}
  if(hosts.length){html+=`<div class="card" style="margin-bottom:12px"><div class="ctitle" style="font-size:11px">&#127968; HOSTS (${hosts.length})</div><div style="overflow-x:auto"><table class="res-tbl"><thead><tr><th>HOST</th><th>IP</th></tr></thead><tbody>${hosts.map(h=>`<tr><td>${h.host||h}</td><td>${h.ip||"—"}</td></tr>`).join("")}</tbody></table></div></div>`;}
  if(ips.length){html+=`<div class="card"><div class="ctitle" style="font-size:11px">&#128205; IP ADDRESSES (${ips.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${ips.map(ip=>`<span class="tag" style="background:rgba(57,255,20,0.08);color:var(--green);border-color:rgba(57,255,20,0.2)">${ip}</span>`).join("")}</div></div>`;}
  res.innerHTML=html;
}
function tmg(m,el){mods[m]=!mods[m];el.classList.toggle("on",mods[m]);}

function initLog(){logEl=document.getElementById("term");logEl.innerHTML="";logEl.style.display="block";}
function lg(t,tp="i"){if(!logEl)return;const p={i:"[*]",s:"[+]",w:"[!]",e:"[x]"}[tp]||"[*]";const d=document.createElement("div");d.className="tl t"+tp;d.innerHTML="<span class='p'>"+p+"</span> "+t;logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight;}
function clrUI(){["term","err","res"].forEach(id=>{const e=document.getElementById(id);if(e){e.innerHTML="";e.style.display="none";}});document.getElementById("prog").style.display="none";}
function showErr(msg){const e=document.getElementById("err");e.textContent="Error: "+msg;e.style.display="block";}
function startProg(){progV=0;document.getElementById("prog").style.display="block";document.getElementById("pb").style.width="0%";progT=setInterval(()=>{progV=Math.min(progV+(100-progV)*0.04,92);document.getElementById("pb").style.width=progV+"%";},400);}
function endProg(){clearInterval(progT);document.getElementById("pb").style.width="100%";setTimeout(()=>document.getElementById("prog").style.display="none",400);}

function bdg(lv,sm=false){const s=SEV[lv]||SEV.UNKNOWN;return`<span class="bdg${sm?" btn-sm":""}" style="background:${s.b};color:${s.c};border-color:${s.c}40">${s.i} ${lv}</span>`;}
function tag(t,c){return`<span class="tag" style="background:${c}15;color:${c};border-color:${c}30">${t}</span>`;}
function statusCol(s){return s===200?"var(--green)":s<400?"var(--yellow)":"var(--orange)";}

// FIX: Increased fetch timeout from default to 300s to allow long scans to complete
async function fetchWithTimeout(url, options={}, timeoutMs=300000){
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), timeoutMs);
  try {
    const r = await fetch(url, {...options, signal: controller.signal});
    clearTimeout(timer);
    return r;
  } catch(e) {
    clearTimeout(timer);
    if(e.name==='AbortError') throw new Error('Request timed out after '+Math.round(timeoutMs/1000)+'s. Try scanning fewer modules.');
    throw e;
  }
}

async function doScan(){
  const target=document.getElementById("tgt").value.trim();
  if(!target||busy)return;
  clrUI();busy=true;initLog();startProg();
  const btn=document.getElementById("sbtn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  const ml=Object.keys(mods).filter(m=>mods[m]).join(",");
  lg("Target: "+target);
  lg("Modules: "+ml);
  lg("Scanning — may take 60–180 seconds depending on open ports","w");
  try{
    // FIX: use fetchWithTimeout (300s) instead of plain fetch
    const r=await fetchWithTimeout("/scan?target="+encodeURIComponent(target)+"&modules="+encodeURIComponent(ml),{},300000);
    const d=await r.json();
    endProg();
    if(d.error){showErr(d.error);lg(d.error,"e");}
    else{lg("Done — "+(d.summary?.open_ports||0)+" ports, "+(d.summary?.total_cves||0)+" CVEs","s");renderScan(d);}
  }catch(e){endProg();showErr(e.message);}
  finally{busy=false;btn.disabled=false;btn.innerHTML="SCAN";}
}

function renderScan(data){
  const s=data.summary||{};
  const ports=(data.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
  let html=`<div class="sgrid">
    <div class="sc"><div class="sv" style="color:#00e5ff">${ports.length}</div><div class="sl">OPEN PORTS</div></div>
    <div class="sc"><div class="sv" style="color:#ff3366">${s.critical_cves||0}</div><div class="sl">CRITICAL</div></div>
    <div class="sc"><div class="sv" style="color:#ff6b35">${s.high_cves||0}</div><div class="sl">HIGH CVEs</div></div>
    <div class="sc"><div class="sv" style="color:#ffd60a">${s.total_cves||0}</div><div class="sl">TOTAL CVEs</div></div>
    <div class="sc"><div class="sv" style="color:#b06fff">${s.exploitable||0}</div><div class="sl">EXPLOITABLE</div></div>
  </div>`;
  html+=`<div class="tabs">
    <button class="tab active" onclick="swt(event,'tp')">&#128268; Ports</button>
    ${data.modules?.ssl?.length?'<button class="tab" onclick="swt(event,\'tssl\')">&#128274; SSL</button>':""}
    ${data.modules?.dns?'<button class="tab" onclick="swt(event,\'tdns\')">&#127758; DNS</button>':""}
    ${data.modules?.headers?'<button class="tab" onclick="swt(event,\'thdr\')">&#128196; Headers</button>':""}
    <button class="tab" onclick="exportPDF()">&#128196; PDF Report</button>
  </div>`;

  html+=`<div class="tc active" id="tp">`;
  const portsModule=data.modules?.ports;
  if(portsModule?.error){
    html+=`<div style="background:rgba(255,51,102,0.07);border:1px solid rgba(255,51,102,0.22);border-radius:9px;padding:13px 16px;color:var(--red);font-family:'JetBrains Mono',monospace;font-size:13px">
      &#9888; Port scan error: ${portsModule.error}<br><br>
      Make sure nmap is installed: <b>sudo apt-get install nmap dnsutils</b>
    </div>`;
  } else {
    (portsModule?.hosts||[]).forEach(host=>{
      html+=`<div style="display:flex;align-items:center;gap:9px;margin-bottom:12px;flex-wrap:wrap">
        <span style="color:var(--cyan);background:rgba(0,229,255,0.07);padding:3px 11px;border-radius:4px;border:1px solid rgba(0,229,255,0.18);font-family:'JetBrains Mono',monospace;font-size:12px">${host.ip||""}</span>
        ${host.hostnames?.[0]?`<span style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace">${host.hostnames[0]}</span>`:""}
        <span style="color:var(--green);font-size:12px">&#9679; ${host.status||"up"}</span>
        ${host.os?`<span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">OS: ${host.os}</span>`:""}
      </div>`;
      if(!host.ports||host.ports.length===0){
        html+=`<p style="color:var(--m);font-size:13px;font-family:'JetBrains Mono',monospace">No open ports found in range 1-10000.</p>`;
      }
      host.ports.forEach(port=>{
        const sv=SEV[port.risk_level]||SEV.UNKNOWN;
        const hx=port.cves?.some(c=>c.has_exploit);
        html+=`<div class="pc" style="border:1px solid ${sv.c}22;border-left:3px solid ${sv.c}">
          <div class="ph" onclick="tp2(this)">
            <div class="pn" style="background:${sv.b};color:${sv.c}">${port.port}</div>
            <div class="pi"><div class="pname">${port.product||port.service||"unknown"}${port.version?` <span style="color:var(--m);font-size:12px;font-weight:400">v${port.version}</span>`:""}</div>
            <div class="psub">${(port.protocol||"tcp").toUpperCase()} &middot; ${port.service||""}${port.extrainfo?" &middot; "+port.extrainfo:""}</div></div>
            <div class="pm">
              ${hx?'<span class="bdg" style="background:rgba(176,111,255,0.12);color:#b06fff;border-color:rgba(176,111,255,0.3);font-size:10px">&#9760; EXPLOIT</span>':""}
              ${bdg(port.risk_level)}
              ${port.risk_score?`<span style="color:${sv.c};font-weight:800;font-size:14px;font-family:'JetBrains Mono',monospace">${port.risk_score}</span>`:""}
              <span class="chev">&#9660;</span>
            </div>
          </div>
          <div class="pb2">
            ${port.cves?.length?`<div class="st">VULNERABILITIES (${port.cves.length})</div>${port.cves.map(c=>{const cs=SEV[c.severity]||SEV.UNKNOWN;return`<div class="ci"><div class="ct"><a class="cid" href="${c.references?.[0]||"https://nvd.nist.gov/vuln/detail/"+c.id}" target="_blank">${c.id}</a>${bdg(c.severity,true)}${c.score?`<span style="color:${cs.c};font-weight:700;font-size:11px;font-family:'JetBrains Mono',monospace">CVSS ${c.score}</span>`:""}${c.has_exploit?'<span class="bdg btn-sm" style="background:rgba(176,111,255,0.1);color:#b06fff;border-color:rgba(176,111,255,0.25)">&#9760; PUBLIC EXPLOIT</span>':""}<span class="cdate">${c.published||""}</span></div><div class="cdesc">${c.description||""}</div></div>`;}).join("")}`:""}
            ${port.mitigations?.length?`<div class="st">MITIGATIONS</div><div class="ml">${port.mitigations.map(m=>`<div class="mi"><span class="ma">&rsaquo;</span><span>${m}</span></div>`).join("")}</div>`:""}
          </div>
        </div>`;
      });
    });
    if(!portsModule?.hosts?.length){
      html+=`<p style="color:var(--m);font-size:13px;font-family:'JetBrains Mono',monospace">&#9888; No hosts found. Target may be offline or blocking scans.</p>`;
    }
  }
  html+=`</div>`;

  if(data.modules?.ssl?.length){
    html+=`<div class="tc" id="tssl">`;
    data.modules.ssl.forEach(s=>{
      const gc=GC[s.grade]||"#ff3366";const d=s.details||{};
      if(s.grade==="N/A"){
        html+=`<div class="ssl-card"><p style="color:var(--m);font-size:13px">SSL not available on ${s.host}:${s.port}</p></div>`;
        return;
      }
      html+=`<div class="ssl-card"><div class="ssl-hdr"><div class="gc2" style="background:${gc}15;color:${gc};border:2px solid ${gc}35">${s.grade}</div>
        <div><div style="font-weight:700;font-size:14px">${s.host}:${s.port}</div>
        <div style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace;margin-top:3px">${d.protocol||"?"} &middot; ${d.cipher||"?"} ${d.cipher_bits?"("+d.cipher_bits+" bit)":""}</div>
        ${d.days_until_expiry!=null?`<div style="color:${d.days_until_expiry<30?"var(--red)":"var(--green)"};font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3px">Expires: ${d.expires||""} (${d.days_until_expiry} days)</div>`:""}
        </div></div>
        ${s.issues?.filter(i=>i.severity!=="INFO").length?s.issues.filter(i=>i.severity!=="INFO").map(iss=>`<div class="iss-item">${bdg(iss.severity,true)}<span style="font-size:12px;color:#c0c0d0;margin-left:6px">${iss.msg}</span></div>`).join(""):"<p style='color:var(--green);font-size:12px'>&#10003; No SSL issues</p>"}
      </div>`;
    });
    html+=`</div>`;
  }

  if(data.modules?.dns){
    const dns=data.modules.dns;
    html+=`<div class="tc" id="tdns">
      <div class="dns-grid">${Object.entries(dns.records||{}).map(([t,v])=>`<div class="dr"><div class="dtype">${t}</div><div class="dval">${v.join("<br/>")}</div></div>`).join("")}</div>
      <div class="card" style="padding:12px;margin-bottom:12px">
        <div style="display:flex;gap:14px;flex-wrap:wrap">
          <span style="font-size:13px">${dns.has_spf?"✅":"❌"} SPF ${dns.has_spf?"configured":"MISSING"}</span>
          <span style="font-size:13px">${dns.has_dmarc?"✅":"❌"} DMARC ${dns.has_dmarc?"configured":"MISSING"}</span>
        </div>
      </div>
      ${dns.subdomains?.length?`<div class="st" style="margin-bottom:8px">SUBDOMAINS (${dns.subdomains.length})</div>${dns.subdomains.map(s=>`<div class="sub-item"><span>${s.subdomain}</span><span style="color:var(--m)">${s.ip}</span></div>`).join("")}`:""}
      ${dns.issues?.filter(i=>i.severity!=="INFO").length?`<div class="st" style="margin-top:12px;margin-bottom:8px">DNS ISSUES</div>${dns.issues.filter(i=>i.severity!=="INFO").map(i=>`<div class="iss-item">${bdg(i.severity,true)}<span style="margin-left:7px;font-size:12px">${i.msg}</span></div>`).join("")}`:""}
    </div>`;
  }

  if(data.modules?.headers){
    const hd=data.modules.headers;const gc=GC[hd.grade]||"#ff3366";
    html+=`<div class="tc" id="thdr">
      <div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;flex-wrap:wrap">
        <div class="hdr-grade" style="color:${gc}">${hd.grade}</div>
        <div><div style="font-size:14px;font-weight:600">${hd.url||""}</div>
          <div style="color:var(--m);font-size:12px;font-family:'JetBrains Mono',monospace;margin-top:3px">HTTP ${hd.status_code||""} &middot; Score ${hd.score||0}/100${hd.server?" &middot; "+hd.server:""}</div>
        </div>
      </div>
      ${hd.issues?.length?`<div class="st" style="margin-bottom:8px">ISSUES</div><div class="ml" style="margin-bottom:14px">${hd.issues.map(i=>`<div class="iss-item">${bdg(i.severity,true)}<span style="margin-left:7px;font-size:12px">${i.msg}</span></div>`).join("")}</div>`:""}
      <div class="st" style="margin-bottom:8px">RESPONSE HEADERS</div>
      <div class="hl">${Object.entries(hd.headers||{}).slice(0,25).map(([k,v])=>`<div class="hi"><span class="hk">${k}</span><span class="hv">${String(v).substring(0,100)}</span></div>`).join("")}</div>
    </div>`;
  }

  const r=document.getElementById("res");r.innerHTML=html;r.style.display="block";
  window._sd=data;
}

function tp2(hdr){const b=hdr.nextElementSibling;const c=hdr.querySelector(".chev");b.classList.toggle("open");c.style.transform=b.classList.contains("open")?"rotate(180deg)":"none";}
function swt(e,id){const p=document.getElementById("res");p.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));p.querySelectorAll(".tc").forEach(t=>t.classList.remove("active"));e.currentTarget.classList.add("active");const tc=document.getElementById(id);if(tc)tc.classList.add("active");}

async function doSub(){
  const domain=document.getElementById("sub-domain").value.trim();
  const size=document.getElementById("sub-size").value;
  if(!domain)return;
  const btn=document.getElementById("sub-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating subdomains for <b style="color:var(--cyan)">${domain}</b>...</p></div>`;
  try{
    const r=await fetchWithTimeout("/subdomains?domain="+encodeURIComponent(domain)+"&size="+size,{},120000);
    const d=await r.json();
    if(d.error){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    let html=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span class="found-badge">${d.total} SUBDOMAINS FOUND</span>
        <span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">Sources: ${(d.sources||[]).join(", ")}</span>
      </div>
      <div style="overflow-x:auto"><table class="res-tbl">
        <thead><tr><th>SUBDOMAIN</th><th>IP ADDRESS</th><th>SOURCE</th><th>ACTION</th></tr></thead><tbody>
        ${(d.subdomains||[]).map(s=>`<tr>
          <td style="color:var(--cyan)">${s.subdomain}</td>
          <td>${s.ip}</td>
          <td>${tag(s.source||"dns",s.source==="crt.sh"?"#b06fff":s.source==="hackertarget"?"#00e5ff":"#00ff9d")}</td>
          <td><button class="lbtn" onclick="scanFromSub('${s.subdomain}')">SCAN</button></td>
        </tr>`).join("")}
        </tbody>
      </table></div>
    </div>`;
    document.getElementById("sub-res").innerHTML=html;
  }catch(e){document.getElementById("sub-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="FIND SUBDOMAINS";}
}
function scanFromSub(d){document.getElementById("tgt").value=d;pg("scan",document.querySelector(".nb"));doScan();}

async function doDir(){
  const url=document.getElementById("dir-url").value.trim();
  const size=document.getElementById("dir-size").value;
  const ext=document.getElementById("dir-ext").value.trim();
  if(!url)return;
  const btn=document.getElementById("dir-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Enumerating directories on <b style="color:var(--cyan)">${url}</b>...</p></div>`;
  try{
    const r=await fetchWithTimeout("/dirbust?url="+encodeURIComponent(url)+"&size="+size+"&ext="+encodeURIComponent(ext),{},180000);
    const d=await r.json();
    if(d.error){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    let html=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span class="found-badge">${d.total} PATHS FOUND</span>
        <span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">${d.scanned} scanned &middot; ${d.errors} errors</span>
      </div>
      <div style="overflow-x:auto"><table class="res-tbl">
        <thead><tr><th>URL</th><th>STATUS</th><th>SIZE</th><th>SEVERITY</th><th>NOTE</th></tr></thead><tbody>
        ${(d.found||[]).map(f=>`<tr>
          <td><a href="${f.url}" target="_blank" style="color:var(--cyan);text-decoration:none;font-size:11px">${f.url}</a></td>
          <td style="color:${statusCol(f.status)};font-weight:700">${f.status}</td>
          <td style="color:var(--m)">${f.size||"?"}</td>
          <td>${bdg(f.severity,true)}</td>
          <td style="color:#8e8e93;font-size:11px">${f.note||""}</td>
        </tr>`).join("")}
        </tbody>
      </table></div>
    </div>`;
    document.getElementById("dir-res").innerHTML=html;
  }catch(e){document.getElementById("dir-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="START ENUMERATION";}
}

function bfTypeChange(){
  const t=document.getElementById("bf-type").value;
  document.getElementById("bf-http-fields").style.display=t==="http"?"block":"none";
  document.getElementById("bf-ssh-fields").style.display=t==="ssh"?"block":"none";
}
async function doBrute(){
  const type=document.getElementById("bf-type").value;
  const users=document.getElementById("bf-users").value.split("\n").map(s=>s.trim()).filter(Boolean);
  const pwds=document.getElementById("bf-pwds").value.split("\n").map(s=>s.trim()).filter(Boolean);
  if(!users.length||!pwds.length){alert("Enter at least one username and password");return;}
  const btn=document.getElementById("bf-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>ATTACKING...';
  document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--m);font-size:13px">Running — ${users.length} users × ${pwds.length} passwords...</p></div>`;
  try{
    let url="/brute-http",body={users,passwords:pwds};
    if(type==="http"){body.url=document.getElementById("bf-url").value.trim();body.user_field=document.getElementById("bf-ufield").value||"username";body.pass_field=document.getElementById("bf-pfield").value||"password";}
    else{url="/brute-ssh";body.host=document.getElementById("bf-ssh-host").value.trim();body.port=document.getElementById("bf-ssh-port").value||"22";}
    const r=await fetchWithTimeout(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)},120000);
    const d=await r.json();
    const found=d.found||[];
    document.getElementById("bf-res").innerHTML=`<div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <span class="found-badge">${found.length} CREDENTIALS FOUND</span>
        <span style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace">${d.attempts||0} attempts &middot; ${d.status||""}</span>
        ${d.note?`<span style="color:var(--yellow);font-size:11px">${d.note}</span>`:""}
      </div>
      ${found.length?`<table class="res-tbl"><thead><tr><th>USERNAME</th><th>PASSWORD</th><th>STATUS</th></tr></thead><tbody>
        ${found.map(f=>`<tr><td style="color:var(--cyan)">${f.username}</td><td style="color:var(--red);font-weight:700">${f.password}</td><td style="color:var(--green)">&#10003; SUCCESS</td></tr>`).join("")}
      </tbody></table>`:`<p style="color:var(--green);font-size:13px">&#10003; No valid credentials found.</p>`}
    </div>`;
  }catch(e){document.getElementById("bf-res").innerHTML=`<div class="card"><p style="color:var(--red)">Error: ${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="START BRUTE FORCE";}
}

async function doDisc(){
  const subnet=document.getElementById("subnet").value.trim();if(!subnet)return;
  const btn=document.getElementById("disc-btn");
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>SCANNING...';
  document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--m)">Scanning subnet...</p></div>`;
  try{
    const r=await fetchWithTimeout("/discover?subnet="+encodeURIComponent(subnet),{},120000);
    const d=await r.json();
    if(d.error){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${d.error}</p></div>`;return;}
    document.getElementById("disc-res").innerHTML=`<div class="card"><div class="ctitle">${d.total||0} HOSTS FOUND</div><div class="hg">
      ${(d.hosts||[]).map(h=>`<div class="ht" onclick="scanDisc('${h.ip}')">
        <div class="hip">${h.ip}</div>
        ${h.hostnames?.[0]?`<div style="color:var(--m);font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:3px">${h.hostnames[0]}</div>`:""}
        ${h.vendor?`<div style="color:#636366;font-size:10px;margin-top:2px">${h.vendor}</div>`:""}
        <div style="color:var(--m);font-size:10px;font-family:'JetBrains Mono',monospace;margin-top:7px">Click to scan &rsaquo;</div>
      </div>`).join("")}
    </div></div>`;
  }catch(e){document.getElementById("disc-res").innerHTML=`<div class="card"><p style="color:var(--red)">${e.message}</p></div>`;}
  finally{btn.disabled=false;btn.innerHTML="DISCOVER";}
}
function scanDisc(ip){document.getElementById("tgt").value=ip;pg("scan",document.querySelector(".nb"));doScan();}

async function loadHist(){
  try{
    const r=await fetch("/history");const d=await r.json();
    if(!d.length){document.getElementById("hist-content").innerHTML=`<p style="color:var(--m);font-size:13px">No scans yet.</p>`;return;}
    document.getElementById("hist-content").innerHTML=`<div style="overflow-x:auto"><table class="tbl">
      <thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>
      ${d.map(s=>`<tr>
        <td style="color:var(--m)">#${s.id}</td><td style="color:var(--cyan)">${s.target}</td>
        <td style="color:var(--m)">${(s.scan_time||"").replace("T"," ").substring(0,19)}</td>
        <td>${s.open_ports}</td><td>${s.total_cves}</td>
        <td style="color:${s.critical_cves>0?"var(--red)":"var(--green)"}">${s.critical_cves}</td>
        <td><button class="lbtn" onclick="loadScan(${s.id})">VIEW</button></td>
      </tr>`).join("")}
      </tbody></table></div>`;
  }catch(e){document.getElementById("hist-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}
}
async function loadScan(id){
  pg("scan",document.querySelector(".nb"));clrUI();
  try{const r=await fetch("/scan/"+id);const d=await r.json();document.getElementById("tgt").value=d.target||"";renderScan(d);initLog();lg("Loaded scan #"+id,"s");}
  catch(e){showErr(e.message);}
}

async function loadDash(){
  try{
    const r=await fetch("/history?limit=100");const d=await r.json();
    if(!d.length){document.getElementById("dash-content").innerHTML=`<p style="color:var(--m);font-size:13px">Run some scans first.</p>`;return;}
    const tc=d.reduce((a,s)=>a+s.total_cves,0),cr=d.reduce((a,s)=>a+s.critical_cves,0),tp=d.reduce((a,s)=>a+s.open_ports,0);
    const mx=Math.max(...d.map(s=>s.total_cves),1);
    document.getElementById("dash-content").innerHTML=`
      <div class="sgrid" style="margin-bottom:18px">
        <div class="sc"><div class="sv" style="color:var(--cyan)">${d.length}</div><div class="sl">SCANS</div></div>
        <div class="sc"><div class="sv" style="color:var(--yellow)">${tc}</div><div class="sl">TOTAL CVEs</div></div>
        <div class="sc"><div class="sv" style="color:var(--red)">${cr}</div><div class="sl">CRITICAL</div></div>
        <div class="sc"><div class="sv" style="color:var(--green)">${tp}</div><div class="sl">OPEN PORTS</div></div>
      </div>
      <div class="dash-grid">
        <div class="card"><div class="ctitle">TOP TARGETS BY CVEs</div>
          ${d.slice(0,6).map(s=>`<div class="bar-row"><span class="bl">${s.target.substring(0,12)}</span><div class="bt"><div class="bf" style="width:${s.total_cves/mx*100}%;background:linear-gradient(90deg,var(--red),var(--orange))"></div></div><span class="bv">${s.total_cves}</span></div>`).join("")}
        </div>
        <div class="card"><div class="ctitle">RECENT ACTIVITY</div>
          ${d.slice(0,8).map(s=>`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-size:12px;font-family:'JetBrains Mono',monospace"><span style="color:var(--cyan)">${s.target}</span><span style="color:${s.critical_cves>0?"var(--red)":"var(--m)"}">${s.critical_cves>0?"&#9762; "+s.critical_cves+" crit":s.total_cves+" CVEs"}</span></div>`).join("")}
        </div>
      </div>`;
  }catch(e){document.getElementById("dash-content").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}
}

function adminTab(e,id){
  document.querySelectorAll("#admin-tabs .tab").forEach(t=>t.classList.remove("active"));
  document.querySelectorAll("#page-admin .tc").forEach(t=>t.classList.remove("active"));
  e.currentTarget.classList.add("active");
  document.getElementById(id).classList.add("active");
  if(id==="at-users")loadAdminUsers();
  if(id==="at-stats")loadAdminStats();
  if(id==="at-audit")loadAdminAudit();
  if(id==="at-scans")loadAdminScans();
}
async function loadAdmin(){loadAdminUsers();loadAdminStats();}

async function loadAdminUsers(){
  try{
    const r=await fetch("/api/admin/users");const d=await r.json();
    document.getElementById("admin-users").innerHTML=`<div style="overflow-x:auto"><table class="tbl">
      <thead><tr><th>ID</th><th>USERNAME</th><th>EMAIL</th><th>ROLE</th><th>VERIFIED</th><th>ACTIVE</th><th>LOGINS</th><th>LAST LOGIN</th><th>ACTIONS</th></tr></thead><tbody>
      ${d.map(u=>`<tr>
        <td style="color:var(--m)">#${u.id}</td>
        <td style="color:var(--cyan)">${u.username}</td>
        <td style="color:var(--m);font-size:11px">${u.email}</td>
        <td>${u.role==="admin"?`<span class="admin-badge">★ ADMIN</span>`:`<span class="user-badge">USER</span>`}</td>
        <td style="color:${u.is_verified?"var(--green)":"var(--red)"}">${u.is_verified?"✅":"❌"}</td>
        <td style="color:${u.is_active?"var(--green)":"var(--red)"}">${u.is_active?"ON":"OFF"}</td>
        <td style="color:var(--m)">${u.login_count||0}</td>
        <td style="color:var(--m);font-size:11px">${(u.last_login||"never").substring(0,16)}</td>
        <td style="display:flex;gap:5px;flex-wrap:wrap">
          <button class="lbtn" onclick="toggleUser(${u.id})">${u.is_active?"DISABLE":"ENABLE"}</button>
          <button class="lbtn" onclick="setRole(${u.id},'${u.role==="admin"?"user":"admin"}')">${u.role==="admin"?"→USER":"→ADMIN"}</button>
          <button class="lbtn red" onclick="deleteUser(${u.id})">DEL</button>
        </td>
      </tr>`).join("")}
      </tbody></table></div>`;
  }catch(e){document.getElementById("admin-users").innerHTML=`<p style="color:var(--red)">${e.message}</p>`;}
}

async function toggleUser(id){await fetch(`/api/admin/users/${id}/toggle`,{method:"POST"});loadAdminUsers();}
async function setRole(id,role){await fetch(`/api/admin/users/${id}/role`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({role})});loadAdminUsers();}
async function deleteUser(id){if(!confirm("Delete this user? This cannot be undone."))return;await fetch(`/api/admin/users/${id}`,{method:"DELETE"});loadAdminUsers();}

async function loadAdminStats(){
  try{
    const r=await fetch("/api/admin/stats");const d=await r.json();
    document.getElementById("admin-stats").innerHTML=`<div class="sgrid">
      <div class="sc"><div class="sv" style="color:var(--cyan)">${d.total_users||0}</div><div class="sl">TOTAL USERS</div></div>
      <div class="sc"><div class="sv" style="color:var(--green)">${d.verified_users||0}</div><div class="sl">VERIFIED</div></div>
      <div class="sc"><div class="sv" style="color:var(--yellow)">${d.total_scans||0}</div><div class="sl">TOTAL SCANS</div></div>
      <div class="sc"><div class="sv" style="color:var(--orange)">${d.scans_today||0}</div><div class="sl">TODAY</div></div>
      <div class="sc"><div class="sv" style="color:var(--red)">${d.critical_cves||0}</div><div class="sl">CRITICAL CVEs</div></div>
      <div class="sc"><div class="sv" style="color:var(--purple)">${d.total_cves||0}</div><div class="sl">TOTAL CVEs</div></div>
    </div>`;
  }catch(e){}
}

async function loadAdminAudit(){
  try{
    const r=await fetch("/api/admin/audit?limit=200");const d=await r.json();
    document.getElementById("admin-audit").innerHTML=`<table class="tbl">
      <thead><tr><th>TIME</th><th>USER</th><th>ACTION</th><th>TARGET</th><th>IP</th><th>DETAILS</th></tr></thead><tbody>
      ${d.map(l=>`<tr>
        <td style="color:var(--m);font-size:11px">${(l.timestamp||"").substring(0,16)}</td>
        <td style="color:var(--cyan)">${l.username||"-"}</td>
        <td><span class="tag" style="background:rgba(0,229,255,0.07);color:var(--cyan);border-color:rgba(0,229,255,0.2)">${l.action||""}</span></td>
        <td style="color:var(--m);font-size:11px">${l.target||"-"}</td>
        <td style="color:var(--m);font-size:11px">${l.ip_address||"-"}</td>
        <td style="color:var(--m);font-size:11px">${l.details||""}</td>
      </tr>`).join("")}
      </tbody></table>`;
  }catch(e){}
}

async function loadAdminScans(){
  try{
    const r=await fetch("/api/admin/scans");const d=await r.json();
    document.getElementById("admin-scans").innerHTML=`<table class="tbl">
      <thead><tr><th>ID</th><th>TARGET</th><th>TIME</th><th>PORTS</th><th>CVEs</th><th>CRITICAL</th><th>ACTION</th></tr></thead><tbody>
      ${d.map(s=>`<tr>
        <td style="color:var(--m)">#${s.id}</td>
        <td style="color:var(--cyan)">${s.target}</td>
        <td style="color:var(--m);font-size:11px">${(s.scan_time||"").replace("T"," ").substring(0,19)}</td>
        <td>${s.open_ports}</td><td>${s.total_cves}</td>
        <td style="color:${s.critical_cves>0?"var(--red)":"var(--green)"}">${s.critical_cves}</td>
        <td><button class="lbtn" onclick="loadScan(${s.id})">VIEW</button></td>
      </tr>`).join("")}
      </tbody></table>`;
  }catch(e){}
}

async function exportPDF(){
  const data=window._sd;
  if(!data){alert("Run a scan first");return;}
  try{
    const r=await fetchWithTimeout("/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)},60000);
    if(!r.ok)throw new Error(await r.text());
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=`vulnscan-${data.target||"report"}-${new Date().toISOString().slice(0,10)}.pdf`;
    document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
  }catch(e){alert("PDF failed: "+e.message);}
}

const vt=new URLSearchParams(location.search).get("verify");
if(vt){
  fetch("/api/verify/"+vt).then(r=>r.json()).then(d=>{
    if(d.success){authMsg(d.message+" You can now login.","ok");authTab("login");}
    else authMsg(d.error||"Verification failed","err");
  });
}

// ── About Modal ────────────────────────────────
function showAbout(){
  const m=document.getElementById("about-modal");
  m.style.display="flex";
  setTimeout(()=>m.style.opacity="1",10);
}
function closeAbout(){
  document.getElementById("about-modal").style.display="none";
}
document.addEventListener("keydown",e=>{
  if(e.key==="Escape") closeAbout();
  if(e.key==="Enter"&&document.getElementById("l-pass")===document.activeElement)doLogin();
});
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
    # FIX: validate target more strictly to prevent injection
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
    modules = data.get("modules", {})
    hosts = modules.get("ports", {}).get("hosts", [])
    all_ports = [p for h in hosts for p in h.get("ports", [])]

    C_BG = colors.HexColor("#04040a"); C_DARK = colors.HexColor("#0d0d18")
    C_BORDER = colors.HexColor("#16162a"); C_MUTED = colors.HexColor("#5a5a8a")
    C_WHITE = colors.HexColor("#e8e8f0"); C_CYAN = colors.HexColor("#00e5ff")
    C_RED = colors.HexColor("#ff3366"); C_ORANGE = colors.HexColor("#ff6b35")
    C_YELLOW = colors.HexColor("#ffd60a"); C_GREEN = colors.HexColor("#00ff9d")
    C_PURPLE = colors.HexColor("#b06fff")
    SEV_C = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN, "UNKNOWN": C_MUTED}

    def sty(name, **kw):
        d = dict(fontName="Helvetica", fontSize=9, textColor=C_WHITE, leading=14, spaceAfter=4,
                 spaceBefore=2, leftIndent=0, alignment=TA_LEFT)
        d.update(kw)
        return ParagraphStyle(name, **d)

    S_T = sty("t", fontName="Helvetica-Bold", fontSize=26, textColor=C_CYAN, leading=32, spaceAfter=6)
    S_H1 = sty("h1", fontName="Helvetica-Bold", fontSize=15, textColor=C_CYAN, leading=20, spaceBefore=16, spaceAfter=8)
    S_H2 = sty("h2", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, leading=16, spaceBefore=10, spaceAfter=5)
    S_H3 = sty("h3", fontName="Helvetica-Bold", fontSize=9, textColor=C_MUTED, leading=13, spaceBefore=7, spaceAfter=4, leftIndent=8)
    S_B = sty("b"); S_C = sty("c", alignment=TA_CENTER, textColor=C_MUTED, fontSize=8)
    S_W = sty("w", fontName="Helvetica-Bold", textColor=C_RED)

    def p(t, s=None): return Paragraph(str(t), s or S_B)
    def sp(h=6): return Spacer(1, h)
    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=7, spaceBefore=3)
    def tbl(data, cols, sx=[]):
        t = Table(data, colWidths=cols)
        base = [("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_BG]),
                ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8)]
        t.setStyle(TableStyle(base + sx))
        return t

    W, H = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)

    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG); canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.setFillColor(C_RED); canvas.rect(0, H - 3, W, 3, fill=1, stroke=0)
        canvas.setFillColor(C_DARK); canvas.rect(0, 0, W, 13 * mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7); canvas.setFillColor(C_MUTED)
        canvas.drawString(16 * mm, 4.5 * mm, f"VulnScan Pro  |  {target}  |  {scan_time}  |  CONFIDENTIAL")
        canvas.drawRightString(W - 16 * mm, 4.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []
    crit_c = summary.get("critical_cves", 0); high_c = summary.get("high_cves", 0)
    if crit_c > 0: risk = ("F", C_RED, "CRITICAL RISK")
    elif high_c > 0: risk = ("D", C_ORANGE, "HIGH RISK")
    elif summary.get("total_cves", 0) > 0: risk = ("C", C_YELLOW, "MEDIUM RISK")
    else: risk = ("A", C_GREEN, "LOW RISK")

    story += [sp(36), p("VulnScan Pro", S_T)]
    story.append(p("SECURITY ASSESSMENT REPORT", sty("st2", fontName="Helvetica-Bold", fontSize=12, textColor=C_PURPLE, leading=18)))
    story += [sp(8), hr(), sp(8)]
    story.append(tbl([[k, v] for k, v in [("Target", target), ("Scan Time", scan_time),
                                           ("Report Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
                                           ("Risk Level", risk[2])]],
                     [38 * mm, 115 * mm],
                     [("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                      ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
                      ("TEXTCOLOR", (1, 3), (1, 3), risk[1]),
                      ("FONTNAME", (1, 3), (1, 3), "Helvetica-Bold")]))
    story += [sp(18)]
    st = Table([[f"{summary.get('open_ports', 0)}\nOPEN PORTS", f"{summary.get('total_cves', 0)}\nTOTAL CVEs",
                 f"{crit_c}\nCRITICAL", f"{high_c}\nHIGH", f"{summary.get('exploitable', 0)}\nEXPLOITABLE"]],
               colWidths=[30 * mm] * 5)
    ss = TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                     ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
                     ("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                     ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK]), ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER)])
    for i, c in enumerate([C_CYAN, C_YELLOW, C_RED, C_ORANGE, C_PURPLE]):
        ss.add("TEXTCOLOR", (i, 0), (i, 0), c)
    st.setStyle(ss); story += [st, sp(28)]
    story.append(p("CONFIDENTIAL — Authorized security assessment only",
                   sty("disc", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)))
    story.append(PageBreak())
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    buf.seek(0)
    fname = f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]', '_', target)}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.route("/harvester", methods=["POST"])
def harvester():
    import shutil, subprocess, json as _json, tempfile, re as _re
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    sources = (data.get("sources") or "google,bing,dnsdumpster,crtsh").strip()
    limit = int(data.get("limit") or 500)
    if not target:
        return jsonify({"error": "No target specified"})
    # Validate domain (basic)
    if not _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        return jsonify({"error": "Invalid domain format"})
    if not shutil.which("theHarvester") and not shutil.which("theharvester"):
        return jsonify({"error": "theHarvester is not installed. Run: sudo apt install theharvester  OR  pip3 install theHarvester"})
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
        # Parse JSON output if available
        emails, hosts, subdomains, ips = [], [], [], []
        json_path = out_file + ".json"
        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    jd = _json.load(f)
                emails = list(set(jd.get("emails", [])))
                hosts_raw = jd.get("hosts", [])
                for h in hosts_raw:
                    if isinstance(h, dict):
                        hosts.append(h)
                        if h.get("ip"): ips.append(h["ip"])
                    else:
                        hosts.append({"host": h, "ip": ""})
                subdomains = list(set(jd.get("hosts", []) if not hosts else
                                      [h["host"] if isinstance(h,dict) else h for h in hosts_raw]))
                ips = list(set(ips + jd.get("ips", [])))
            except Exception:
                pass
        # Fallback: parse stdout
        if not emails and not hosts:
            for line in raw_out.splitlines():
                line = line.strip()
                if "@" in line and "." in line and " " not in line:
                    emails.append(line)
                elif _re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', line):
                    subdomains.append(line)
                elif _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips.append(line)
            emails = list(set(emails))
            subdomains = list(set(subdomains))
            ips = list(set(ips))
        return jsonify({
            "target": target,
            "sources": sources,
            "emails": emails[:500],
            "hosts": hosts[:500],
            "subdomains": subdomains[:500],
            "ips": ips[:500],
            "raw_lines": len(raw_out.splitlines())
        })

@app.route("/health")
def health():
    # FIX: Also check if nmap and dig are available
    import shutil
    return jsonify({
        "status": "ok",
        "version": "3.2",
        "nmap": bool(shutil.which("nmap")),
        "dig": bool(shutil.which("dig")),
        "python": sys.version
    })

if __name__ == "__main__":
    print("[*] VulnScan Pro v3.2 starting")
    print("[*] Open: http://localhost:5000")
    print("[*] Health check: http://localhost:5000/health")
    app.run(host="0.0.0.0", port=5000, debug=False)
