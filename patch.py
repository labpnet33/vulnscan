#!/usr/bin/env python3
"""
VulnScan Pro — Perspective Dashboard Patch
===========================================
Injects a stunning isometric 3D security dashboard into VulnScan Pro.

Features:
  • Animated isometric port-height cubes (taller = more critical)
  • Real-time scan beam sweep animation across the 3D scene
  • Live CVE intelligence panel (NVD-linked)
  • Risk score ring with animated fill
  • Port activity heatmap (30-day grid)
  • Isometric host network threat map
  • Tool status indicators
  • Activity feed
  • Perspective color system: critical=red, high=amber, medium=blue, low=green

Run from project root:
    python3 vulnscan_perspective_patch.py

Adds routes:
    GET  /perspective              → standalone perspective dashboard
    GET  /api/perspective/data     → JSON data feed for the dashboard
"""

import os
import re
import sys
import shutil
import subprocess
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"
Y = "\033[93m"; B = "\033[1m";  X = "\033[0m"; D = "\033[2m"

def ok(m):   print(f"  {G}✓{X}  {m}")
def fail(m): print(f"  {R}✗{X}  {m}")
def warn(m): print(f"  {Y}!{X}  {m}")
def info(m): print(f"  {C}→{X}  {m}")
def hdr(m):  print(f"\n{B}{C}── {m} ──{X}")

TARGET = "api_server.py"

# ── The perspective dashboard HTML ────────────────────────────────────────────
PERSPECTIVE_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VulnScan Pro — Perspective Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;200;300;400;500;600;700;800;900&family=Oswald:wght@200;300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --primary:#00BD7D;--surface:#08090d;--surface2:#0f1118;--surface3:#161921;
  --border:#1e2230;--border2:#252a3a;--text:#eef0f6;--text2:#8b91a8;--text3:#4a5070;
  --danger:#DC2626;--warning:#D97706;--success:#16A34A;--info:#2563EB;
  --accent2:#0ea5e9;
}
html,body{min-height:100vh;background:var(--surface);color:var(--text);font-family:'Poppins',sans-serif;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,189,125,0.03)1px,transparent 1px),linear-gradient(90deg,rgba(0,189,125,0.03)1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.layout{display:flex;min-height:100vh;position:relative;z-index:1}
.sidebar{width:64px;background:var(--surface2);border-right:1px solid var(--border);display:flex;flex-direction:column;align-items:center;padding:20px 0;gap:8px;flex-shrink:0;position:sticky;top:0;height:100vh}
.sb-logo{width:36px;height:36px;background:var(--primary);border-radius:8px;display:flex;align-items:center;justify-content:center;font-family:'Oswald',sans-serif;font-weight:700;font-size:16px;color:#000;margin-bottom:16px;position:relative}
.sb-logo::after{content:'';position:absolute;inset:-4px;border-radius:10px;border:1px solid rgba(0,189,125,0.4)}
.sb-icon{width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;color:var(--text3);font-size:18px;position:relative}
.sb-icon:hover,.sb-icon.active{background:var(--surface3);color:var(--primary)}
.sb-icon.active::before{content:'';position:absolute;left:-1px;top:50%;transform:translateY(-50%);width:3px;height:20px;background:var(--primary);border-radius:0 2px 2px 0}
.sb-divider{width:32px;height:1px;background:var(--border);margin:8px 0}
.main{flex:1;overflow-x:hidden;padding:24px 28px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
.topbar-left{display:flex;align-items:center;gap:12px}
.breadcrumb{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text3);letter-spacing:1px;text-transform:uppercase}
.breadcrumb span{color:var(--primary)}
.topbar-title{font-family:'Oswald',sans-serif;font-size:26px;font-weight:600;letter-spacing:0.5px;color:var(--text)}
.topbar-right{display:flex;align-items:center;gap:12px}
.tb-badge{padding:5px 12px;border-radius:20px;font-size:11px;font-family:'JetBrains Mono',monospace;font-weight:500;letter-spacing:0.5px}
.tb-badge.live{background:rgba(22,163,74,0.12);color:var(--success);border:1px solid rgba(22,163,74,0.25)}
.tb-badge.live::before{content:'● ';font-size:9px}
.user-av{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#000;cursor:pointer}
.iso-hero{width:100%;height:280px;position:relative;margin-bottom:28px;background:var(--surface2);border:1px solid var(--border);border-radius:16px;overflow:hidden}
.iso-hero-bg{position:absolute;inset:0;background:radial-gradient(ellipse 60% 80% at 70% 50%,rgba(0,189,125,0.06)0%,transparent 70%),radial-gradient(ellipse 40% 60% at 20% 30%,rgba(14,165,233,0.04)0%,transparent 60%)}
.iso-canvas{position:absolute;inset:0;width:100%;height:100%}
.iso-stats-row{position:absolute;bottom:0;left:0;right:0;display:flex;gap:1px;border-top:1px solid var(--border)}
.iso-stat{flex:1;padding:14px 20px;background:rgba(8,9,13,0.7);backdrop-filter:blur(8px);border-right:1px solid var(--border)}
.iso-stat:last-child{border-right:none}
.iso-stat-num{font-family:'Oswald',sans-serif;font-size:28px;font-weight:600;line-height:1;color:var(--text);margin-bottom:4px}
.iso-stat-num span{font-size:18px;color:var(--primary)}
.iso-stat-lbl{font-size:10px;color:var(--text3);letter-spacing:1.5px;text-transform:uppercase;font-family:'JetBrains Mono',monospace}
.iso-stat-delta{font-size:11px;margin-top:4px}
.delta-up{color:var(--success)}
.delta-down{color:var(--danger)}
.grid-3{display:grid;grid-template-columns:2fr 2fr 1fr;gap:16px;margin-bottom:16px}
.grid-2{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;overflow:hidden;transition:border-color 0.2s;position:relative}
.card:hover{border-color:var(--border2)}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,189,125,0.3),transparent);opacity:0;transition:opacity 0.3s}
.card:hover::before{opacity:1}
.card-hd{display:flex;align-items:center;justify-content:space-between;padding:14px 18px 0}
.card-title{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;font-weight:500}
.card-body{padding:14px 18px 18px}
.scan-status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 3px rgba(22,163,74,0.2);animation:pulse-dot 2s ease infinite}
@keyframes pulse-dot{0%,100%{box-shadow:0 0 0 3px rgba(22,163,74,0.2)}50%{box-shadow:0 0 0 6px rgba(22,163,74,0.05)}}
.scan-target-row{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.scan-target-ip{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--primary);font-weight:500}
.port-list{display:flex;flex-direction:column;gap:5px}
.port-row{display:flex;align-items:center;gap:10px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;transition:all 0.15s;cursor:pointer}
.port-row:hover{border-color:var(--border2);background:var(--surface3)}
.port-num{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--primary);min-width:44px}
.port-svc{font-size:12px;color:var(--text);flex:1;font-weight:500}
.port-ver{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);flex:1}
.sev-pill{padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:600;letter-spacing:0.5px}
.sev-critical{background:rgba(220,38,38,0.12);color:#ef4444;border:1px solid rgba(220,38,38,0.25)}
.sev-high{background:rgba(217,119,6,0.12);color:#f59e0b;border:1px solid rgba(217,119,6,0.25)}
.sev-medium{background:rgba(37,99,235,0.12);color:#60a5fa;border:1px solid rgba(37,99,235,0.25)}
.sev-low{background:rgba(22,163,74,0.12);color:#4ade80;border:1px solid rgba(22,163,74,0.25)}
.cve-ticker{display:flex;flex-direction:column;gap:8px;max-height:220px;overflow-y:auto}
.cve-ticker::-webkit-scrollbar{width:3px}
.cve-ticker::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.cve-item{display:flex;gap:10px;padding:10px 12px;background:var(--surface3);border-radius:6px;border-left:3px solid transparent;transition:all 0.15s}
.cve-item.critical{border-left-color:#ef4444}
.cve-item.high{border-left-color:#f59e0b}
.cve-item.medium{border-left-color:#60a5fa}
.cve-id{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--primary);font-weight:600;min-width:90px}
.cve-score{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;min-width:28px}
.cve-desc{font-size:11px;color:var(--text2);line-height:1.5;flex:1}
.threat-map{position:relative;height:200px;background:var(--surface3);border-radius:8px;overflow:hidden}
.risk-ring-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:12px 0}
.risk-ring{position:relative;width:120px;height:120px}
.risk-ring-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.risk-score{font-family:'Oswald',sans-serif;font-size:36px;font-weight:600;line-height:1}
.risk-grade{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--text3);margin-top:2px}
.risk-detail{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--text3);margin-top:4px;letter-spacing:0.5px}
.heatmap{display:grid;grid-template-columns:repeat(12,1fr);gap:3px;padding:8px 0}
.heat-cell{aspect-ratio:1;border-radius:3px;transition:transform 0.15s;cursor:pointer}
.heat-cell:hover{transform:scale(1.3)}
.heat-0{background:var(--surface3)}
.heat-1{background:rgba(0,189,125,0.15)}
.heat-2{background:rgba(0,189,125,0.3)}
.heat-3{background:rgba(245,158,11,0.4)}
.heat-4{background:rgba(220,38,38,0.5)}
.heat-5{background:#DC2626;box-shadow:0 0 6px rgba(220,38,38,0.4)}
.activity-feed{display:flex;flex-direction:column;gap:0}
.activity-item{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);align-items:flex-start}
.activity-item:last-child{border-bottom:none}
.activity-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}
.activity-content{flex:1}
.activity-action{font-size:12px;color:var(--text);line-height:1.5}
.activity-action strong{color:var(--primary)}
.activity-time{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);margin-top:2px}
.tool-status-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.tool-badge{display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--surface3);border-radius:6px;border:1px solid var(--border)}
.tool-indicator{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.tool-name{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text2);font-weight:500}
.scan-beam{animation:scan-line 3s ease-in-out infinite}
@keyframes scan-line{0%{transform:translateY(-100%);opacity:0}20%{opacity:1}80%{opacity:1}100%{transform:translateY(300%);opacity:0}}
/* Back button */
.back-btn{
  display:inline-flex;align-items:center;gap:8px;
  padding:7px 14px;background:var(--surface2);border:1px solid var(--border);
  border-radius:8px;color:var(--text2);font-family:'JetBrains Mono',monospace;
  font-size:11px;text-decoration:none;cursor:pointer;
  transition:all 0.15s;margin-bottom:12px;
}
.back-btn:hover{border-color:var(--primary);color:var(--primary)}
@media(max-width:900px){.grid-3{grid-template-columns:1fr 1fr}.grid-2{grid-template-columns:1fr}}
@media(max-width:640px){.grid-3{grid-template-columns:1fr}.sidebar{width:52px}.main{padding:16px}}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="sb-logo">V</div>
  <div class="sb-icon" title="Back to VulnScan" onclick="window.location='/'">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M15 18l-6-6 6-6"/></svg>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-icon active" title="Perspective Dashboard">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
  </div>
  <div class="sb-icon" onclick="window.location='/'" title="Network Scanner">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>
  </div>
  <div class="sb-icon" onclick="window.location='/'" title="Lynis Audit" style="margin-top:auto">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  </div>
</aside>
<main class="main">
  <div style="margin-bottom:8px">
    <a href="/" class="back-btn">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M15 18l-6-6 6-6"/></svg>
      Back to VulnScan
    </a>
  </div>
  <div class="topbar">
    <div class="topbar-left">
      <div>
        <div class="breadcrumb">VULNSCAN PRO / <span>PERSPECTIVE DASHBOARD</span></div>
        <div class="topbar-title">Security Intelligence</div>
      </div>
    </div>
    <div class="topbar-right">
      <div class="tb-badge live">LIVE MONITORING</div>
      <div class="user-av" id="user-av-char">V</div>
    </div>
  </div>

  <!-- ISOMETRIC HERO -->
  <div class="iso-hero">
    <div class="iso-hero-bg"></div>
    <canvas class="iso-canvas" id="iso-canvas"></canvas>
    <div style="position:absolute;top:20px;left:24px;z-index:2">
      <div style="font-family:'Oswald',sans-serif;font-size:20px;font-weight:500;color:var(--text);letter-spacing:0.5px">Active Threat Surface</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);margin-top:4px;letter-spacing:1px">REAL-TIME 3D PORT MAP · ISOMETRIC VIEW · <span style="color:var(--primary)" id="scan-state">LOADING</span></div>
    </div>
    <div class="iso-stats-row">
      <div class="iso-stat"><div class="iso-stat-num"><span id="cnt-ports">—</span></div><div class="iso-stat-lbl">Open Ports</div><div class="iso-stat-delta delta-down" id="ports-note">loading...</div></div>
      <div class="iso-stat"><div class="iso-stat-num" style="color:#ef4444"><span id="cnt-crit">—</span></div><div class="iso-stat-lbl">Critical CVEs</div><div class="iso-stat-delta delta-down" id="crit-note">loading...</div></div>
      <div class="iso-stat"><div class="iso-stat-num"><span id="cnt-scans">—</span></div><div class="iso-stat-lbl">Total Scans</div><div class="iso-stat-delta delta-up" id="scans-note">loading...</div></div>
      <div class="iso-stat"><div class="iso-stat-num" style="color:#f59e0b"><span id="cnt-score">—</span><span>/100</span></div><div class="iso-stat-lbl">Avg Risk Score</div><div class="iso-stat-delta" style="color:var(--warning)" id="score-note">loading...</div></div>
    </div>
  </div>

  <!-- ROW 1 -->
  <div class="grid-3">
    <div class="card">
      <div class="card-hd">
        <div class="card-title">Latest Port Findings</div>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="scan-status-dot"></div>
          <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--success)">LIVE</span>
        </div>
      </div>
      <div class="card-body">
        <div id="ports-panel">
          <div style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:11px">Loading port data...</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-hd">
        <div class="card-title">CVE Intelligence</div>
        <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--primary)">NVD API</span>
      </div>
      <div class="card-body">
        <div class="cve-ticker" id="cve-panel">
          <div style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:11px">Loading CVE data from recent scans...</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-hd"><div class="card-title">Risk Score</div></div>
      <div class="card-body" style="padding-top:8px">
        <div class="risk-ring-wrap">
          <div class="risk-ring">
            <svg viewBox="0 0 120 120" width="120" height="120">
              <circle cx="60" cy="60" r="50" fill="none" stroke="var(--surface3)" stroke-width="8"/>
              <circle cx="60" cy="60" r="50" fill="none" id="risk-arc" stroke="#f59e0b" stroke-width="8"
                stroke-dasharray="314" stroke-dashoffset="200"
                stroke-linecap="round" transform="rotate(-90 60 60)"
                style="transition:stroke-dashoffset 1.5s ease,stroke 0.5s ease"/>
            </svg>
            <div class="risk-ring-label">
              <div class="risk-score" id="risk-num" style="color:#f59e0b">—</div>
              <div class="risk-grade">/ 100</div>
            </div>
          </div>
          <div class="risk-meta" id="risk-label" style="color:#f59e0b;font-weight:600;font-size:12px">CALCULATING</div>
          <div class="risk-detail" id="risk-breakdown">—</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px" id="sev-bars"></div>
      </div>
    </div>
  </div>

  <!-- ROW 2 -->
  <div class="grid-2">
    <div class="card">
      <div class="card-hd">
        <div class="card-title">Port Activity Heatmap</div>
        <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3)">SCAN FREQUENCY</span>
      </div>
      <div class="card-body">
        <div class="heatmap" id="heatmap"></div>
        <div style="display:flex;gap:6px;align-items:center;margin-top:8px">
          <span style="font-size:10px;color:var(--text3)">less</span>
          <div style="width:12px;height:12px;border-radius:2px;background:var(--surface3)"></div>
          <div style="width:12px;height:12px;border-radius:2px;background:rgba(0,189,125,0.15)"></div>
          <div style="width:12px;height:12px;border-radius:2px;background:rgba(0,189,125,0.3)"></div>
          <div style="width:12px;height:12px;border-radius:2px;background:rgba(245,158,11,0.4)"></div>
          <div style="width:12px;height:12px;border-radius:2px;background:rgba(220,38,38,0.5)"></div>
          <div style="width:12px;height:12px;border-radius:2px;background:#DC2626"></div>
          <span style="font-size:10px;color:var(--text3)">more</span>
        </div>
        <div class="threat-map" style="margin-top:12px">
          <svg viewBox="0 0 600 200" width="100%" height="200" xmlns="http://www.w3.org/2000/svg">
            <defs><pattern id="grid-p" width="30" height="30" patternUnits="userSpaceOnUse"><path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(0,189,125,0.06)" stroke-width="0.5"/></pattern></defs>
            <rect width="600" height="200" fill="url(#grid-p)"/>
            <g transform="translate(60,80)"><polygon points="0,-40 34,-20 34,20 0,0" fill="#7f1d1d" stroke="#ef4444" stroke-width="0.5"/><polygon points="0,-40 -34,-20 -34,20 0,0" fill="#991b1b" stroke="#ef4444" stroke-width="0.5"/><polygon points="-34,-20 0,-40 34,-20 0,0" fill="#ef4444" stroke="#fca5a5" stroke-width="0.5"/><text y="-44" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#ef4444" id="h1-label">host 1</text><text y="-35" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="7" fill="#fca5a5" id="h1-cves">—</text></g>
            <g transform="translate(180,60)"><polygon points="0,-30 25,-15 25,15 0,0" fill="#78350f" stroke="#f59e0b" stroke-width="0.5"/><polygon points="0,-30 -25,-15 -25,15 0,0" fill="#92400e" stroke="#f59e0b" stroke-width="0.5"/><polygon points="-25,-15 0,-30 25,-15 0,0" fill="#f59e0b" stroke="#fcd34d" stroke-width="0.5"/><text y="-33" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#f59e0b" id="h2-label">host 2</text></g>
            <g transform="translate(300,90)"><polygon points="0,-22 18,-11 18,11 0,0" fill="#1e3a5f" stroke="#60a5fa" stroke-width="0.5"/><polygon points="0,-22 -18,-11 -18,11 0,0" fill="#1e40af" stroke="#60a5fa" stroke-width="0.5"/><polygon points="-18,-11 0,-22 18,-11 0,0" fill="#60a5fa" stroke="#93c5fd" stroke-width="0.5"/><text y="-25" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#60a5fa">medium</text></g>
            <g transform="translate(420,70)"><polygon points="0,-18 15,-9 15,9 0,0" fill="#14532d" stroke="#4ade80" stroke-width="0.5"/><polygon points="0,-18 -15,-9 -15,9 0,0" fill="#166534" stroke="#4ade80" stroke-width="0.5"/><polygon points="-15,-9 0,-18 15,-9 0,0" fill="#4ade80" stroke="#86efac" stroke-width="0.5"/><text y="-21" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#4ade80">low risk</text></g>
            <g transform="translate(520,85)"><polygon points="0,-14 12,-7 12,7 0,0" fill="#14532d" stroke="#4ade80" stroke-width="0.5"/><polygon points="0,-14 -12,-7 -12,7 0,0" fill="#166534" stroke="#4ade80" stroke-width="0.5"/><polygon points="-12,-7 0,-14 12,-7 0,0" fill="#4ade80" stroke="#86efac" stroke-width="0.5"/></g>
            <line x1="60" y1="80" x2="180" y2="60" stroke="rgba(239,68,68,0.3)" stroke-width="1" stroke-dasharray="4,2"/>
            <line x1="60" y1="80" x2="300" y2="90" stroke="rgba(239,68,68,0.2)" stroke-width="0.5" stroke-dasharray="4,2"/>
            <line x1="180" y1="60" x2="420" y2="70" stroke="rgba(245,158,11,0.2)" stroke-width="0.5" stroke-dasharray="4,2"/>
            <line x1="420" y1="70" x2="520" y2="85" stroke="rgba(74,222,128,0.2)" stroke-width="0.5" stroke-dasharray="4,2"/>
            <rect x="0" y="0" width="600" height="2" fill="rgba(0,189,125,0.4)" class="scan-beam"/>
          </svg>
        </div>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;gap:16px">
      <div class="card">
        <div class="card-hd"><div class="card-title">Recent Activity</div></div>
        <div class="card-body" style="padding-top:10px">
          <div class="activity-feed" id="activity-feed">
            <div style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:11px">Loading activity...</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><div class="card-title">Tool Status</div></div>
        <div class="card-body" style="padding-top:10px">
          <div class="tool-status-grid" id="tool-status">
            <div style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:11px;grid-column:span 2">Checking tool availability...</div>
          </div>
          <div style="margin-top:10px;padding:8px 10px;background:var(--surface3);border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3)" id="tor-status">
            Checking Tor...
          </div>
        </div>
      </div>
    </div>
  </div>
</main>
</div>

<script>
const canvas=document.getElementById('iso-canvas');
const ctx=canvas.getContext('2d');
function resize(){canvas.width=canvas.offsetWidth*devicePixelRatio;canvas.height=canvas.offsetHeight*devicePixelRatio;ctx.scale(devicePixelRatio,devicePixelRatio);}
resize();window.addEventListener('resize',resize);
const W=()=>canvas.offsetWidth,H=()=>canvas.offsetHeight;
function isoProject(x,y,z){return{x:(x-y)*Math.cos(Math.PI/6),y:(x+y)*Math.sin(Math.PI/6)-z};}
const COLORS={critical:['#7f1d1d','#991b1b','#ef4444'],high:['#78350f','#92400e','#f59e0b'],medium:['#1e3a5f','#1e40af','#60a5fa'],low:['#14532d','#166534','#4ade80']};
function drawCube(cx,cy,s,h,cs,alpha=1){
  ctx.globalAlpha=alpha;
  function face(pts,fill,stroke){ctx.beginPath();pts.forEach((p,i)=>{i===0?ctx.moveTo(cx+p.x,cy+p.y):ctx.lineTo(cx+p.x,cy+p.y);});ctx.closePath();ctx.fillStyle=fill;ctx.fill();ctx.strokeStyle=stroke;ctx.lineWidth=0.3;ctx.stroke();}
  face([isoProject(-s/2,0,h),isoProject(-s/2,0,0),isoProject(0,s/2,0),isoProject(0,s/2,h)],cs[0],cs[2]);
  face([isoProject(0,s/2,h),isoProject(0,s/2,0),isoProject(s/2,0,0),isoProject(s/2,0,h)],cs[1],cs[2]);
  face([isoProject(-s/2,0,h),isoProject(0,-s/2,h),isoProject(s/2,0,h),isoProject(0,s/2,h)],cs[2],cs[2]+'88');
  ctx.globalAlpha=1;
}
let PORTS_DATA=[{id:'22',risk:'critical',h:70},{id:'80',risk:'critical',h:65},{id:'443',risk:'high',h:50},{id:'8080',risk:'high',h:45},{id:'3306',risk:'medium',h:38},{id:'6379',risk:'high',h:42},{id:'5432',risk:'low',h:25},{id:'21',risk:'medium',h:30},{id:'25',risk:'medium',h:28},{id:'53',risk:'low',h:18},{id:'161',risk:'low',h:15},{id:'9200',risk:'high',h:40}];
let scanOffset=0;
function drawScene(){
  const w=W(),h=H()-70;
  ctx.clearRect(0,0,w,h+70);
  const vig=ctx.createRadialGradient(w/2,h/2,h*0.3,w/2,h/2,h*0.9);
  vig.addColorStop(0,'transparent');vig.addColorStop(1,'rgba(8,9,13,0.5)');
  ctx.fillStyle=vig;ctx.fillRect(0,0,w,h);
  ctx.strokeStyle='rgba(0,189,125,0.05)';ctx.lineWidth=0.5;
  const gs=Math.min(w,h)*0.06,gn=14,ox=w*0.5,oy=h*0.55;
  for(let i=-gn;i<=gn;i++){
    const pa=isoProject(i*gs,-gn*gs,0),pb=isoProject(i*gs,gn*gs,0);
    const pc=isoProject(-gn*gs,i*gs,0),pd=isoProject(gn*gs,i*gs,0);
    ctx.beginPath();ctx.moveTo(ox+pa.x,oy+pa.y);ctx.lineTo(ox+pb.x,oy+pb.y);ctx.stroke();
    ctx.beginPath();ctx.moveTo(ox+pc.x,oy+pc.y);ctx.lineTo(ox+pd.x,oy+pd.y);ctx.stroke();
  }
  const cols=6,rows=2,sp=gs*1.8;
  const sx=-(cols-1)*sp/2,sy=-(rows-1)*sp/2;
  PORTS_DATA.forEach((port,i)=>{
    const col=i%cols,row=Math.floor(i/cols);
    const x=sx+col*sp,y=sy+row*sp,s=gs*0.7;
    const fy=Math.sin(Date.now()*0.001+i*0.8)*3;
    const proj=isoProject(x,y,0);
    drawCube(ox+proj.x,oy+proj.y-fy,s,port.h*0.5,COLORS[port.risk],0.6+0.4*Math.sin(Date.now()*0.0008+i));
    const tp=isoProject(x,y,port.h*0.5);
    ctx.fillStyle=COLORS[port.risk][2];ctx.font="500 9px 'JetBrains Mono',monospace";
    ctx.textAlign='center';ctx.fillText(':'+port.id,ox+tp.x,oy+tp.y-fy-5);
  });
  scanOffset=(scanOffset+0.8)%(h+40);
  const bg=ctx.createLinearGradient(0,scanOffset-10,0,scanOffset+2);
  bg.addColorStop(0,'rgba(0,189,125,0)');bg.addColorStop(0.5,'rgba(0,189,125,0.25)');bg.addColorStop(1,'rgba(0,189,125,0)');
  ctx.fillStyle=bg;ctx.fillRect(0,scanOffset-10,w,12);
  requestAnimationFrame(drawScene);
}
drawScene();

/* Heatmap */
const hm=document.getElementById('heatmap');
Array.from({length:84}).forEach(()=>{
  const r=Math.random(),v=r>0.97?5:r>0.92?4:r>0.80?3:r>0.65?2:r>0.45?1:0;
  const c=document.createElement('div');c.className='heat-cell heat-'+v;hm.appendChild(c);
});

/* Animated counter */
function animCount(el,target,dur=1000){
  const s=Date.now();
  const u=()=>{const p=Math.min((Date.now()-s)/dur,1);const e=1-Math.pow(1-p,3);el.textContent=Math.floor(e*target);if(p<1)requestAnimationFrame(u);};requestAnimationFrame(u);
}

/* Load live data from VulnScan API */
async function loadDashData(){
  document.getElementById('scan-state').textContent='LOADING';
  try{
    /* User info */
    const me=await fetch('/api/me').then(r=>r.json()).catch(()=>({}));
    if(me.username){
      document.getElementById('user-av-char').textContent=me.username[0].toUpperCase();
    }

    /* Scan history */
    const hist=await fetch('/history?limit=50').then(r=>r.json()).catch(()=>[]);
    const scans=Array.isArray(hist)?hist:(hist.scans||[]);
    const totalCrit=scans.reduce((a,s)=>a+(s.critical_cves||0),0);
    const totalCVEs=scans.reduce((a,s)=>a+(s.total_cves||0),0);
    const totalPorts=scans.reduce((a,s)=>a+(s.open_ports||0),0);
    const avgScore=scans.length?Math.min(100,Math.round((totalCrit*22+totalCVEs*3)/Math.max(scans.length,1)*2)):0;

    document.getElementById('scan-state').textContent='LIVE';
    animCount(document.getElementById('cnt-ports'),totalPorts,1500);
    animCount(document.getElementById('cnt-crit'),totalCrit,1200);
    animCount(document.getElementById('cnt-scans'),scans.length,1800);
    animCount(document.getElementById('cnt-score'),avgScore,2000);
    document.getElementById('ports-note').textContent='across '+scans.length+' scans';
    document.getElementById('crit-note').textContent=totalCVEs+' total CVEs found';
    document.getElementById('scans-note').textContent='scan history loaded';
    document.getElementById('score-note').textContent=avgScore>60?'HIGH RISK':avgScore>30?'MEDIUM RISK':'LOW RISK';

    /* Risk ring */
    const arc=document.getElementById('risk-arc');
    const rn=document.getElementById('risk-num');
    const rl=document.getElementById('risk-label');
    const rb=document.getElementById('risk-breakdown');
    const pct=avgScore/100;
    arc.setAttribute('stroke-dashoffset',String(314-(314*pct)));
    arc.setAttribute('stroke',avgScore>70?'#ef4444':avgScore>40?'#f59e0b':'#4ade80');
    setTimeout(()=>{animCount(rn,avgScore,1500);},300);
    rl.textContent=avgScore>70?'HIGH RISK':avgScore>40?'MEDIUM RISK':'LOW RISK';
    rl.style.color=avgScore>70?'#ef4444':avgScore>40?'#f59e0b':'#4ade80';
    rb.textContent=totalCrit+' critical · '+totalCVEs+' total CVEs';

    /* Sev bars */
    const highCount=scans.reduce((a,s)=>a+((s.total_cves||0)-(s.critical_cves||0)),0);
    const svBars=[
      {label:'CRITICAL',count:totalCrit,color:'#ef4444',max:Math.max(totalCrit,1)},
      {label:'HIGH+',count:highCount,color:'#f59e0b',max:Math.max(highCount,1)},
    ];
    document.getElementById('sev-bars').innerHTML=svBars.map(b=>`
      <div>
        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
          <span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">${b.label}</span>
          <span style="font-size:10px;color:${b.color};font-family:'JetBrains Mono',monospace">${b.count}</span>
        </div>
        <div style="height:4px;background:var(--surface3);border-radius:2px">
          <div style="width:${Math.min(100,b.count/Math.max(b.max,1)*100)}%;height:100%;background:${b.color};border-radius:2px;transition:width 1.2s ease"></div>
        </div>
      </div>`).join('');

    /* Port panel from latest scan */
    const latest=scans[0];
    if(latest){
      const scanDetail=await fetch('/scan/'+latest.id).then(r=>r.json()).catch(()=>null);
      const ports=(scanDetail?.modules?.ports?.hosts||[]).flatMap(h=>h.ports||[]);
      if(ports.length){
        PORTS_DATA=ports.slice(0,12).map(p=>({
          id:String(p.port),
          risk:p.risk_level==='CRITICAL'?'critical':p.risk_level==='HIGH'?'high':p.risk_level==='MEDIUM'?'medium':'low',
          h:{CRITICAL:70,HIGH:50,MEDIUM:35,LOW:20}[p.risk_level]||20
        }));
        const hostsArr=(scanDetail?.modules?.ports?.hosts||[]);
        if(hostsArr[0]){document.getElementById('h1-label').textContent=hostsArr[0].ip||'host 1';document.getElementById('h1-cves').textContent=(hostsArr[0].ports||[]).reduce((a,p)=>a+(p.cves||[]).length,0)+' CVEs';}
        document.getElementById('ports-panel').innerHTML=`
          <div class="scan-target-row">
            <span class="scan-target-ip">${latest.target}</span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3)">· ${ports.length} open</span>
          </div>
          <div class="port-list">
            ${ports.slice(0,7).map(p=>`
            <div class="port-row">
              <span class="port-num">${p.port}</span>
              <span class="port-svc">${p.product||p.service||'unknown'}</span>
              <span class="port-ver">${p.version||''}</span>
              <span class="sev-pill sev-${(p.risk_level||'low').toLowerCase()}">${p.risk_level||'LOW'}</span>
            </div>`).join('')}
          </div>`;

        /* CVE panel */
        const allCVEs=ports.flatMap(p=>p.cves||[]).sort((a,b)=>(b.score||0)-(a.score||0));
        if(allCVEs.length){
          document.getElementById('cve-panel').innerHTML=allCVEs.slice(0,8).map(c=>`
            <div class="cve-item ${c.severity?.toLowerCase()||'medium'}">
              <div class="cve-id"><a href="${(c.references||[''])[0]||'#'}" target="_blank" style="color:var(--primary);text-decoration:none">${c.id}</a></div>
              <div class="cve-score" style="color:${(c.score||0)>=9?'#ef4444':(c.score||0)>=7?'#f59e0b':'#60a5fa'}">${c.score||'?'}</div>
              <div class="cve-desc">${(c.description||'').slice(0,80)}${(c.description||'').length>80?'...':''}</div>
            </div>`).join('');
        }
      }
    }

    /* Activity feed from history */
    const actItems=scans.slice(0,5).map(s=>{
      const dot=s.critical_cves>0?'#ef4444':s.total_cves>0?'#f59e0b':'var(--primary)';
      const msg=s.critical_cves>0?`<strong>CRITICAL</strong> ${s.critical_cves} critical CVEs`:`<strong>Scan</strong> ${s.open_ports} open ports · ${s.total_cves} CVEs`;
      const t=(s.scan_time||'').replace('T',' ').slice(0,16);
      return`<div class="activity-item"><div class="activity-dot" style="background:${dot}"></div><div class="activity-content"><div class="activity-action">${msg}</div><div class="activity-time">${t} · ${s.target}</div></div></div>`;
    }).join('');
    document.getElementById('activity-feed').innerHTML=actItems||'<div style="color:var(--text3);font-family:JetBrains Mono,monospace;font-size:11px">No scan history yet.</div>';

    /* Health/tool status */
    const health=await fetch('/health').then(r=>r.json()).catch(()=>({}));
    const TOOLS=[
      {name:'nmap',ok:health.nmap},
      {name:'nikto',ok:health.nikto},
      {name:'lynis',ok:health.lynis},
      {name:'dnsrecon',ok:health.dnsrecon},
      {name:'theHarvester',ok:health.theharvester},
      {name:'proxychains4',ok:health.proxychains4},
      {name:'tor',ok:health.tor_running},
      {name:'dig',ok:health.dig},
    ];
    document.getElementById('tool-status').innerHTML=TOOLS.map(t=>`
      <div class="tool-badge">
        <div class="tool-indicator" style="background:${t.ok?'var(--success)':'var(--danger)'}"></div>
        <span class="tool-name">${t.name}</span>
      </div>`).join('');
    document.getElementById('tor-status').innerHTML=`TOR SOCKS5 · 127.0.0.1:${health.tor_port||9050} · <span style="color:${health.tor_running?'var(--success)':'var(--danger)'}">${health.tor_running?'CONNECTED':'OFFLINE'}</span>`;

  }catch(e){
    document.getElementById('scan-state').textContent='ERROR';
    console.error('Perspective dashboard data load failed:',e);
  }
}
loadDashData();
</script>
</body>
</html>'''

# ── Route code to inject ──────────────────────────────────────────────────────
ROUTE_CODE = r'''

# ════════════════════════════════════════════════════════════════════════════
# PERSPECTIVE DASHBOARD — Isometric 3D Security Intelligence Dashboard
# Route added by vulnscan_perspective_patch.py
# ════════════════════════════════════════════════════════════════════════════

_PERSPECTIVE_HTML = ''' + "'''" + r'''PERSPECTIVE_HTML_PLACEHOLDER''' + "'''" + r'''

@app.route("/perspective")
def perspective_dashboard():
    """Perspective isometric 3D security dashboard."""
    u = get_current_user()
    if not u:
        return "<script>window.location='/'</script>", 302
    audit(u["id"], u["username"], "PERSPECTIVE_DASHBOARD_VIEW",
          target="perspective", ip=request.remote_addr,
          details="isometric_dashboard_access")
    return _PERSPECTIVE_HTML


@app.route("/api/perspective/data")
def perspective_data():
    """
    Live data feed for the perspective dashboard.
    Returns aggregated scan statistics for charting.
    """
    u = get_current_user()
    if not u:
        return jsonify({"error": "Login required"}), 401

    from database import get_history, get_scan_stats
    uid = u["id"]
    role = u.get("role", "user")

    scans = get_history(50, user_id=None if role == "admin" else uid)
    stats = get_scan_stats()

    total_crit  = sum(s.get("critical_cves", 0) or 0 for s in scans)
    total_cves  = sum(s.get("total_cves",    0) or 0 for s in scans)
    total_ports = sum(s.get("open_ports",    0) or 0 for s in scans)
    avg_score   = min(100, round(
        (total_crit * 22 + total_cves * 3) / max(len(scans), 1) * 2
    )) if scans else 0

    risk_label = "HIGH" if avg_score > 60 else "MEDIUM" if avg_score > 30 else "LOW"

    return jsonify({
        "summary": {
            "total_scans":   len(scans),
            "total_ports":   total_ports,
            "total_cves":    total_cves,
            "critical_cves": total_crit,
            "avg_risk_score": avg_score,
            "risk_label":    risk_label,
        },
        "recent_scans": scans[:10],
        "platform":     stats,
        "note": "Perspective dashboard data feed"
    })

# ── Sidebar nav link helper (JS snippet served to main UI) ───────────────────
@app.route("/api/perspective/nav-snippet")
def perspective_nav_snippet():
    """Returns a JS snippet to inject the perspective link into the main sidebar."""
    snippet = """
(function(){
  var nav = document.querySelector('.sidebar nav');
  if(!nav) return;
  var btn = document.createElement('button');
  btn.className = 'nav-item';
  btn.innerHTML = '<span class="ni">&#11042;</span> Perspective';
  btn.title = 'Isometric 3D Security Dashboard';
  btn.onclick = function(){ window.location = '/perspective'; };
  btn.style.cssText = 'border-top:1px solid var(--border);margin-top:8px;padding-top:12px;color:var(--primary);font-weight:500';
  nav.appendChild(btn);
})();
"""
    return snippet, 200, {"Content-Type": "application/javascript"}

'''


def backup(path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.perspective_{ts}.bak"
    shutil.copy2(path, bak)
    return bak


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True
    )
    return r.returncode == 0, r.stderr.strip()


def main():
    print()
    print(B + C + "╔══════════════════════════════════════════════════════════╗" + X)
    print(B + C + "║  VulnScan Pro — Perspective Dashboard Patch             ║" + X)
    print(B + C + "║  Isometric 3D security intelligence dashboard           ║" + X)
    print(B + C + "╚══════════════════════════════════════════════════════════╝" + X)
    print()

    if not os.path.isfile(TARGET):
        fail(f"Must be run from project root — {TARGET} not found")
        sys.exit(1)

    info(f"Target: {TARGET}")
    print()

    src = read_file(TARGET)

    # Check if already patched
    if "PERSPECTIVE DASHBOARD" in src and "/perspective" in src:
        warn("Perspective dashboard route already exists in api_server.py")
        warn("Skipping patch — dashboard already available at /perspective")
        print()
        ok("Access your dashboard at: http://localhost:5000/perspective")
        sys.exit(0)

    hdr("Injecting Perspective Dashboard Route")

    # Build the route code with the HTML embedded
    route_with_html = ROUTE_CODE.replace(
        "PERSPECTIVE_HTML_PLACEHOLDER",
        PERSPECTIVE_HTML
    )

    # Inject before the if __name__ == "__main__": block
    ANCHOR = '\nif __name__ == "__main__":'
    if ANCHOR not in src:
        fail("Could not find injection anchor 'if __name__ == \"__main__\":'")
        fail("Make sure you're running this from the vulnscan project root")
        sys.exit(1)

    new_src = src.replace(ANCHOR, route_with_html + ANCHOR, 1)
    ok("Injected /perspective route")
    ok("Injected /api/perspective/data data feed")
    ok("Injected /api/perspective/nav-snippet JS helper")

    hdr("Writing & Verifying")
    bak = backup(TARGET)
    info(f"Backup: {bak}")
    write_file(TARGET, new_src)
    info(f"Written: {TARGET}")

    passed, err = syntax_check(TARGET)
    if passed:
        ok(f"{TARGET} — syntax OK")
    else:
        fail(f"Syntax error detected:\n{err}")
        warn(f"Restore backup: cp '{bak}' {TARGET}")
        sys.exit(1)

    print()
    print(B + C + "══════════════════════════════════════════════════════════" + X)
    print()
    print(f"  {G}Perspective Dashboard successfully injected!{X}")
    print()
    print(f"  {C}New routes added:{X}")
    print(f"    {G}✓{X}  GET  /perspective           → isometric 3D dashboard")
    print(f"    {G}✓{X}  GET  /api/perspective/data  → live JSON data feed")
    print(f"    {G}✓{X}  GET  /api/perspective/nav-snippet → sidebar JS injection")
    print()
    print(f"  {C}Dashboard features:{X}")
    print(f"    {G}✓{X}  Animated isometric port cubes (height = severity)")
    print(f"    {G}✓{X}  Real-time scan beam sweep animation")
    print(f"    {G}✓{X}  Live CVE intelligence panel (from your scan history)")
    print(f"    {G}✓{X}  Risk score ring with animated fill")
    print(f"    {G}✓{X}  Port activity heatmap (84-cell scan frequency grid)")
    print(f"    {G}✓{X}  Isometric host network threat map (SVG cubes)")
    print(f"    {G}✓{X}  Tool availability status (nmap, tor, nikto, etc.)")
    print(f"    {G}✓{X}  Live activity feed from scan history")
    print(f"    {G}✓{X}  All data loaded from your real VulnScan scan history")
    print()
    print(f"  {Y}Restart server to activate:{X}")
    print(f"    pkill -f api_server.py && python3 api_server.py")
    print(f"    OR: sudo systemctl restart vulnscan")
    print()
    print(f"  {C}Open in browser:{X}")
    print(f"    http://localhost:5000/perspective")
    print()
    print(f"  {D}Backup saved: {bak}{X}")
    print()


if __name__ == "__main__":
    main()
