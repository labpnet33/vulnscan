#!/usr/bin/env python3
"""
VulnScan Pro — PDF Report Theme Patch v2.0
Matches the PDF export theme to the website's dark cyberpunk aesthetic.
v2 fix: replaced invalid hexval() with a proper _hex() RGB helper.

Usage: python3 patch.py
Run from the project root directory.
"""
import os, shutil, subprocess, sys, re
from datetime import datetime

# ── Console colours ───────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def ok(m):    print(f"  {GREEN}✓{RESET} {m}")
def fail(m):  print(f"  {RED}✗{RESET} {m}")
def info(m):  print(f"  {CYAN}→{RESET} {m}")
def skip(m):  print(f"  {DIM}·{RESET} {m}")

results = {
    "changes_applied": 0,
    "changes_skipped": 0,
    "changes_failed":  0,
    "files_modified":  [],
    "restart_needed":  False,
}


def backup(path):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = f"{path}.{ts}.bak"
    shutil.copy2(path, dst)
    return dst


def apply_patches(path, patches):
    if not os.path.isfile(path):
        fail(f"File not found: {path}")
        results["changes_failed"] += len(patches)
        return 0

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    modified = content
    applied  = 0

    for desc, old, new in patches:
        if old in modified:
            modified = modified.replace(old, new, 1)
            ok(desc)
            applied += 1
            results["changes_applied"] += 1
        elif new in modified:
            skip(f"{desc}  (already applied)")
            results["changes_skipped"] += 1
        else:
            fail(f"{desc}")
            results["changes_failed"] += 1

    if applied:
        bak = backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(modified)
        info(f"Backed up → {os.path.basename(bak)}")
        if path not in results["files_modified"]:
            results["files_modified"].append(path)
        results["restart_needed"] = True

    return applied


# ══════════════════════════════════════════════════════════════════════════════
# The exact old /report route from api_server.py
# ══════════════════════════════════════════════════════════════════════════════
OLD_REPORT = r"""@app.route("/report", methods=["POST"])
def report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak)
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
    SEV_C = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW,
             "LOW": C_GREEN, "UNKNOWN": C_MUTED}

    def sty(name, **kw):
        d = dict(fontName="Helvetica", fontSize=9, textColor=C_WHITE, leading=14,
                 spaceAfter=4, spaceBefore=2, leftIndent=0, alignment=TA_LEFT)
        d.update(kw)
        return ParagraphStyle(name, **d)

    S_T  = sty("t",  fontName="Helvetica-Bold", fontSize=26, textColor=C_CYAN, leading=32, spaceAfter=6)
    S_H1 = sty("h1", fontName="Helvetica-Bold", fontSize=15, textColor=C_CYAN, leading=20, spaceBefore=16, spaceAfter=8)
    S_H2 = sty("h2", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, leading=16, spaceBefore=10, spaceAfter=5)
    S_H3 = sty("h3", fontName="Helvetica-Bold", fontSize=9,  textColor=C_MUTED, leading=13, spaceBefore=7, spaceAfter=4, leftIndent=8)
    S_B  = sty("b")
    S_C  = sty("c", alignment=TA_CENTER, textColor=C_MUTED, fontSize=8)
    S_W  = sty("w", fontName="Helvetica-Bold", textColor=C_RED)

    def p(t, s=None): return Paragraph(str(t), s or S_B)
    def sp(h=6): return Spacer(1, h)
    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=7, spaceBefore=3)

    def tbl(data, cols, sx=[]):
        t = Table(data, colWidths=cols)
        base = [
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ("TEXTCOLOR", (0,0), (-1,-1), C_WHITE),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8)
        ]
        t.setStyle(TableStyle(base + sx))
        return t

    W, H = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=16*mm, rightMargin=16*mm,
                            topMargin=14*mm, bottomMargin=14*mm)

    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG); canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.setFillColor(C_RED); canvas.rect(0, H-3, W, 3, fill=1, stroke=0)
        canvas.setFillColor(C_DARK); canvas.rect(0, 0, W, 13*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7); canvas.setFillColor(C_MUTED)
        canvas.drawString(16*mm, 4.5*mm,
                          f"VulnScan Pro  |  {target}  |  {scan_time}  |  CONFIDENTIAL  |  Via Tor")
        canvas.drawRightString(W-16*mm, 4.5*mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []
    crit_c = summary.get("critical_cves", 0)
    high_c = summary.get("high_cves", 0)
    if crit_c > 0:   risk = ("F", C_RED,    "CRITICAL RISK")
    elif high_c > 0: risk = ("D", C_ORANGE, "HIGH RISK")
    elif summary.get("total_cves", 0) > 0: risk = ("C", C_YELLOW, "MEDIUM RISK")
    else:            risk = ("A", C_GREEN,  "LOW RISK")

    story += [sp(36), p("VulnScan Pro", S_T)]
    story.append(p("SECURITY ASSESSMENT REPORT",
                   sty("st2", fontName="Helvetica-Bold", fontSize=12,
                       textColor=C_PURPLE, leading=18)))
    story += [sp(8), hr(), sp(8)]
    story.append(tbl(
        [[k, v] for k, v in [
            ("Target", target),
            ("Scan Time", scan_time),
            ("Report Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            ("Risk Level", risk[2]),
            ("Routing", f"Tor SOCKS5 ({TOR_SOCKS_HOST}:{TOR_SOCKS_PORT})")
        ]],
        [38*mm, 115*mm],
        [
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0,0), (0,-1), C_MUTED),
            ("TEXTCOLOR", (1,3), (1,3), risk[1]),
            ("FONTNAME",  (1,3), (1,3), "Helvetica-Bold"),
            ("TEXTCOLOR", (1,4), (1,4), C_CYAN),
        ]
    ))
    story += [sp(18)]
    st = Table([[
        f"{summary.get('open_ports', 0)}\nOPEN PORTS",
        f"{summary.get('total_cves', 0)}\nTOTAL CVEs",
        f"{crit_c}\nCRITICAL",
        f"{high_c}\nHIGH",
        f"{summary.get('exploitable', 0)}\nEXPLOITABLE"
    ]], colWidths=[30*mm]*5)
    ss = TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 11),
        ("BOTTOMPADDING", (0,0), (-1,-1), 11),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK]),
        ("GRID", (0,0), (-1,-1), 0.4, C_BORDER),
    ])
    for i, c in enumerate([C_CYAN, C_YELLOW, C_RED, C_ORANGE, C_PURPLE]):
        ss.add("TEXTCOLOR", (i,0), (i,0), c)
    st.setStyle(ss)
    story += [st, sp(28)]
    story.append(p("CONFIDENTIAL — Authorized security assessment only. Scanned anonymously via Tor.",
                   sty("disc", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)))
    story.append(PageBreak())
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    buf.seek(0)
    fname = (f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]', '_', target)}"
             f"-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf")
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})"""


# ══════════════════════════════════════════════════════════════════════════════
# New /report route — full cyberpunk theme, no hexval() calls
# ══════════════════════════════════════════════════════════════════════════════
NEW_REPORT = r"""@app.route("/report", methods=["POST"])
def report():
    # PDF report styled to match the VulnScan Pro website dark cyberpunk theme.
    # #04040a background, #00e5ff cyan, neon severity colours, Courier mono font.
    # Uses _hex() helper — no hexval() which does not exist in ReportLab.
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak,
                                        KeepTogether)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        return jsonify({"error": "reportlab not installed: pip3 install reportlab --break-system-packages"}), 500

    data      = request.get_json() or {}
    target    = data.get("target", "unknown")
    scan_time = data.get("scan_time", "")[:19].replace("T", " ")
    summary   = data.get("summary", {})
    modules   = data.get("modules", {})
    hosts     = modules.get("ports", {}).get("hosts", [])
    ssl_list  = modules.get("ssl", [])
    dns_data  = modules.get("dns", {})
    hdr_data  = modules.get("headers", {})

    # ── Palette — mirrors website CSS variables ───────────────────────────────
    C_BG      = colors.HexColor("#04040a")
    C_DARK    = colors.HexColor("#0d0d18")
    C_DARKER  = colors.HexColor("#111118")
    C_BORDER  = colors.HexColor("#1e1e2e")
    C_BORDER2 = colors.HexColor("#2a2a3a")
    C_MUTED   = colors.HexColor("#666688")
    C_BODY    = colors.HexColor("#aaaacc")
    C_WHITE   = colors.HexColor("#f0f0f0")
    C_CYAN    = colors.HexColor("#00e5ff")
    C_GREEN   = colors.HexColor("#00ff9d")
    C_YELLOW  = colors.HexColor("#ffd60a")
    C_ORANGE  = colors.HexColor("#ff6b35")
    C_RED     = colors.HexColor("#ff3366")
    C_PURPLE  = colors.HexColor("#b06fff")
    C_BLUE    = colors.HexColor("#5a9fe0")
    C_MATRIX  = colors.HexColor("#021a0a")

    SEV_MAP = {
        "CRITICAL": C_RED,   "HIGH": C_ORANGE,
        "MEDIUM":   C_YELLOW,"LOW":  C_GREEN,
        "INFO":     C_BLUE,  "UNKNOWN": C_MUTED,
    }

    # ── _hex: safe RGB→hex, works with any ReportLab Color ───────────────────
    def _hex(col):
        try:
            return "{:02X}{:02X}{:02X}".format(
                int(round(col.red   * 255)),
                int(round(col.green * 255)),
                int(round(col.blue  * 255)),
            )
        except Exception:
            return "AAAACC"

    # ── Style factory with simple dedup ──────────────────────────────────────
    _sc = {}
    def sty(name, **kw):
        k = name + repr(sorted(kw.items()))
        if k not in _sc:
            d = dict(fontName="Courier", fontSize=8, textColor=C_BODY,
                     leading=13, spaceAfter=3, spaceBefore=2,
                     leftIndent=0, alignment=TA_LEFT)
            d.update(kw)
            _sc[k] = ParagraphStyle(name + str(len(_sc)), **d)
        return _sc[k]

    S_TITLE = sty("title", fontName="Helvetica-Bold", fontSize=26,
                  textColor=C_CYAN, leading=32, spaceAfter=4, spaceBefore=0)
    S_H1    = sty("h1",   fontName="Helvetica-Bold", fontSize=13,
                  textColor=C_CYAN, leading=18, spaceBefore=16, spaceAfter=8)
    S_LABEL = sty("lbl",  fontName="Courier-Bold", fontSize=7,
                  textColor=C_MUTED, leading=11)
    S_BODY  = sty("body")
    S_MONO  = sty("mono", fontName="Courier", fontSize=8, textColor=C_BODY)
    S_SM    = sty("sm",   fontName="Courier", fontSize=7, textColor=C_MUTED)
    S_DISC  = sty("disc", fontName="Courier", fontSize=7, textColor=C_MUTED,
                  alignment=TA_CENTER, leading=11)

    def p(t, s=None):   return Paragraph(str(t), s or S_BODY)
    def sp(h=6):         return Spacer(1, h)
    def hr(col=None):
        return HRFlowable(width="100%", thickness=0.4,
                          color=col or C_BORDER, spaceAfter=5, spaceBefore=3)
    def col_txt(text, col):
        return f'<font color="#{_hex(col)}">{text}</font>'

    def tbl(rows, cols, extra=None, hdr=False):
        t = Table(rows, colWidths=cols, repeatRows=1 if hdr else 0)
        base = [
            ("FONTNAME",       (0,0),(-1,-1), "Courier"),
            ("FONTSIZE",       (0,0),(-1,-1), 7),
            ("TEXTCOLOR",      (0,0),(-1,-1), C_BODY),
            ("ROWBACKGROUNDS", (0,0),(-1,-1), [C_DARK, C_DARKER]),
            ("GRID",           (0,0),(-1,-1), 0.25, C_BORDER),
            ("TOPPADDING",     (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",  (0,0),(-1,-1), 5),
            ("LEFTPADDING",    (0,0),(-1,-1), 7),
            ("RIGHTPADDING",   (0,0),(-1,-1), 7),
            ("VALIGN",         (0,0),(-1,-1), "MIDDLE"),
        ]
        if hdr:
            base += [
                ("BACKGROUND",(0,0),(-1,0), C_BORDER2),
                ("FONTNAME",  (0,0),(-1,0), "Courier-Bold"),
                ("FONTSIZE",  (0,0),(-1,0), 7),
                ("TEXTCOLOR", (0,0),(-1,0), C_MUTED),
            ]
        t.setStyle(TableStyle(base + (extra or [])))
        return t

    W, H = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=12*mm,  bottomMargin=16*mm)

    def draw_page(canvas, doc):
        canvas.saveState()
        # Dark background
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Top accent: cyan left, purple right
        canvas.setFillColor(C_CYAN)
        canvas.rect(0, H-3, W*0.55, 3, fill=1, stroke=0)
        canvas.setFillColor(C_PURPLE)
        canvas.rect(W*0.55, H-3, W*0.45, 3, fill=1, stroke=0)
        # Matrix footer strip
        canvas.setFillColor(C_MATRIX)
        canvas.rect(0, 0, W, 13*mm, fill=1, stroke=0)
        canvas.setStrokeColor(C_GREEN)
        canvas.setLineWidth(0.5)
        canvas.line(0, 13*mm, W, 13*mm)
        # Footer text
        canvas.setFont("Courier", 6.5)
        canvas.setFillColor(C_GREEN)
        canvas.drawString(15*mm, 4.5*mm,
            f"VULNSCAN PRO  |  {target}  |  {scan_time}  |  CONFIDENTIAL")
        canvas.setFillColor(C_MUTED)
        canvas.drawRightString(W-15*mm, 4.5*mm, f"PAGE {doc.page}")
        # Watermark on pages > 1
        if doc.page > 1:
            canvas.saveState()
            canvas.setFont("Helvetica-Bold", 54)
            canvas.setFillColor(colors.HexColor("#0a0a14"))
            canvas.translate(W/2, H/2)
            canvas.rotate(38)
            canvas.drawCentredString(0, 0, "CONFIDENTIAL")
            canvas.restoreState()
        canvas.restoreState()

    # ── Risk posture ──────────────────────────────────────────────────────────
    crit_c  = summary.get("critical_cves", 0)
    high_c  = summary.get("high_cves",     0)
    expl_c  = summary.get("exploitable",   0)
    ports_c = summary.get("open_ports",    0)
    cvs_c   = summary.get("total_cves",    0)

    if crit_c > 0:    risk_label, risk_col = "CRITICAL RISK", C_RED
    elif high_c > 0:  risk_label, risk_col = "HIGH RISK",     C_ORANGE
    elif cvs_c > 0:   risk_label, risk_col = "MEDIUM RISK",   C_YELLOW
    else:             risk_label, risk_col = "LOW RISK",       C_GREEN

    story = []

    # ══════════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════════
    story += [sp(28)]
    story.append(p(col_txt("⚡ VulnScan Pro", C_CYAN), S_TITLE))
    story.append(p(col_txt("SECURITY ASSESSMENT REPORT", C_PURPLE),
                   sty("sub", fontName="Courier-Bold", fontSize=10,
                       textColor=C_PURPLE, leading=15)))
    story += [sp(8), hr(C_CYAN), sp(6)]

    story.append(tbl(
        [
            [p("TARGET",      S_LABEL), p(target,    S_MONO)],
            [p("SCAN TIME",   S_LABEL), p(scan_time, S_MONO)],
            [p("REPORT DATE", S_LABEL),
             p(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), S_MONO)],
            [p("RISK LEVEL",  S_LABEL),
             p(col_txt(risk_label, risk_col),
               sty("rl", fontName="Courier-Bold", fontSize=9, textColor=risk_col))],
            [p("ROUTING",     S_LABEL),
             p(f"Tor SOCKS5 ({TOR_SOCKS_HOST}:{TOR_SOCKS_PORT})", S_MONO)],
        ],
        [38*mm, 130*mm],
        extra=[
            ("FONTNAME",  (0,0),(0,-1), "Courier-Bold"),
            ("TEXTCOLOR", (0,0),(0,-1), C_MUTED),
        ]
    ))
    story += [sp(16)]

    # KPI grid — mirrors website .stats
    kpi_items = [
        (str(ports_c), "OPEN PORTS",  C_CYAN),
        (str(cvs_c),   "TOTAL CVEs",  C_YELLOW),
        (str(crit_c),  "CRITICAL",    C_RED),
        (str(high_c),  "HIGH",        C_ORANGE),
        (str(expl_c),  "EXPLOITABLE", C_PURPLE),
    ]
    kpi_cells = [[
        p(col_txt(val, col) +
          f'<br/><font color="#{_hex(C_MUTED)}">{lbl}</font>',
          sty(f"kpi{i}", fontName="Courier-Bold", fontSize=15,
              textColor=col, leading=19, alignment=TA_CENTER))
        for i, (val, lbl, col) in enumerate(kpi_items)
    ]]
    kpi_tbl = Table(kpi_cells, colWidths=[34*mm]*5)
    kpi_tbl.setStyle(TableStyle([
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 12),
        ("BOTTOMPADDING", (0,0),(-1,-1), 12),
        ("BACKGROUND",    (0,0),(-1,-1), C_DARK),
        ("GRID",          (0,0),(-1,-1), 0.3,  C_BORDER),
        ("BOX",           (0,0),(-1,-1), 0.6,  C_BORDER2),
    ]))
    story.append(kpi_tbl)
    story += [sp(14)]
    story.append(p(
        "CONFIDENTIAL — Authorized security assessment only. "
        "Scanned anonymously via Tor. Not for public distribution.",
        S_DISC))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PORT FINDINGS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(p(col_txt("01  PORT FINDINGS", C_CYAN), S_H1))
    story.append(hr(C_CYAN))

    for host in hosts:
        ip   = host.get("ip", "?")
        hns  = host.get("hostnames", [])
        os_  = host.get("os", "")
        chip = col_txt(ip, C_CYAN)
        if hns: chip += f'  <font color="#{_hex(C_MUTED)}">{hns[0]}</font>'
        if os_: chip += f'  <font color="#{_hex(C_MUTED)}">[{os_}]</font>'
        story.append(p(chip, sty("hchip", fontName="Courier-Bold", fontSize=8,
                                 textColor=C_WHITE, leading=12)))
        story.append(sp(5))

        ports = host.get("ports", [])
        if not ports:
            story.append(p("No open ports found.", S_SM))
            continue

        # Port summary table
        pr = [[p("PORT",S_LABEL),p("SVC",S_LABEL),p("PRODUCT",S_LABEL),
               p("VERSION",S_LABEL),p("RISK",S_LABEL),p("CVEs",S_LABEL)]]
        for port in ports:
            svc   = port.get("service","")
            prod  = port.get("product", svc) or svc
            ver   = port.get("version","")
            rl    = port.get("risk_level","UNKNOWN")
            score = port.get("risk_score","")
            ncves = len(port.get("cves",[]))
            rc    = SEV_MAP.get(rl, C_MUTED)
            pr.append([
                p(col_txt(str(port.get("port","")), C_CYAN),
                  sty("pn",fontName="Courier-Bold",fontSize=8,textColor=C_CYAN)),
                p(svc[:12], S_SM),
                p(prod[:22], S_MONO),
                p(ver[:16],  S_SM),
                p(col_txt(rl, rc),
                  sty("rc",fontName="Courier-Bold",fontSize=7,textColor=rc)),
                p(col_txt(str(ncves), C_RED) if ncves else "—",
                  sty("nc",fontName="Courier-Bold",fontSize=8,
                      textColor=C_RED if ncves else C_MUTED)),
            ])
        story.append(KeepTogether([
            tbl(pr, [14*mm,16*mm,36*mm,28*mm,28*mm,14*mm], hdr=True)
        ]))
        story.append(sp(8))

        # CVE detail per port
        for port in ports:
            cves = port.get("cves",[])
            if not cves:
                continue
            prod     = port.get("product", port.get("service","")) or ""
            port_num = port.get("port","")
            hdr_txt  = (col_txt(f"Port {port_num}", C_CYAN) +
                        f'  <font color="#{_hex(C_MUTED)}">'
                        f'{prod} — {len(cves)} CVE{"s" if len(cves)!=1 else ""}</font>')
            story.append(p(hdr_txt, sty("ph",fontName="Courier-Bold",fontSize=8,
                                        textColor=C_WHITE,leading=12,spaceBefore=8)))

            cr = [[p("CVE ID",S_LABEL),p("SEV",S_LABEL),
                   p("CVSS",S_LABEL),p("DATE",S_LABEL),p("DESCRIPTION",S_LABEL)]]
            for cve in cves:
                sev   = cve.get("severity","UNKNOWN")
                col   = SEV_MAP.get(sev, C_MUTED)
                score = cve.get("score","")
                refs  = cve.get("references",[])
                href  = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve.get('id','')}"
                desc  = (cve.get("description","") or "")[:85]
                if len(cve.get("description","") or "") > 85:
                    desc += "…"
                cid = (f'<link href="{href}">' +
                       col_txt(cve.get("id",""), C_CYAN) + "</link>")
                cr.append([
                    p(cid, sty("ci",fontName="Courier-Bold",fontSize=7,textColor=C_CYAN)),
                    p(col_txt(sev, col),
                      sty("cs",fontName="Courier-Bold",fontSize=7,textColor=col)),
                    p(str(score) if score else "—",
                      sty("csc",fontName="Courier-Bold",fontSize=7,textColor=col)),
                    p((cve.get("published","") or "")[:10], S_SM),
                    p(desc, S_SM),
                ])
            story.append(KeepTogether([
                tbl(cr, [28*mm,18*mm,12*mm,18*mm,60*mm], hdr=True)
            ]))

            mits = port.get("mitigations",[])
            if mits:
                story.append(sp(3))
                story.append(p("MITIGATIONS", S_LABEL))
                for m in mits[:6]:
                    story.append(p(
                        col_txt("›", C_GREEN) + f"  {m}",
                        sty("mi",fontName="Courier",fontSize=7,
                            textColor=C_BODY,leading=11,leftIndent=5)))
        story.append(sp(6))

    # ══════════════════════════════════════════════════════════════════════════
    # SSL / TLS
    # ══════════════════════════════════════════════════════════════════════════
    if ssl_list:
        story.append(PageBreak())
        story.append(p(col_txt("02  SSL / TLS ANALYSIS", C_CYAN), S_H1))
        story.append(hr(C_CYAN))
        GCOLS = {"A+":C_GREEN,"A":C_GREEN,"B":C_YELLOW,"C":C_ORANGE,"D":C_RED,"F":C_RED,"N/A":C_MUTED}
        for s in ssl_list:
            grade  = s.get("grade","N/A")
            gcol   = GCOLS.get(grade, C_MUTED)
            det    = s.get("details",{})
            issues = [i for i in s.get("issues",[]) if i.get("severity")!="INFO"]
            days   = det.get("days_until_expiry")
            exp_t  = (f'Expires: {det.get("expires","?")}  ({days} days)'
                      if det.get("expires") else "")
            exp_c  = C_RED if (days is not None and days < 30) else C_GREEN

            sr = Table([[
                p(col_txt(grade, gcol),
                  sty("sg",fontName="Helvetica-Bold",fontSize=26,
                      textColor=gcol,leading=30,alignment=TA_CENTER)),
                [
                    p(col_txt(f'{s.get("host","?")}:{s.get("port",443)}', C_WHITE),
                      sty("sh",fontName="Courier-Bold",fontSize=9,textColor=C_WHITE)),
                    p(f'{det.get("protocol","?")}  ·  {det.get("cipher","?")}  '
                      f'({det.get("cipher_bits","?")} bit)', S_SM),
                    p(col_txt(exp_t, exp_c),
                      sty("ex",fontName="Courier",fontSize=7,textColor=exp_c)) if exp_t else sp(1),
                ]
            ]], colWidths=[20*mm, None])
            sr.setStyle(TableStyle([
                ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1),8),
                ("BOTTOMPADDING", (0,0),(-1,-1),8),
                ("LEFTPADDING",   (0,0),(-1,-1),8),
                ("BACKGROUND",    (0,0),(-1,-1),C_DARK),
                ("BOX",           (0,0),(-1,-1),0.4,C_BORDER2),
            ]))
            story.append(sr)
            if issues:
                ir = [[p("SEVERITY",S_LABEL),p("ISSUE",S_LABEL)]]
                for iss in issues:
                    ic = SEV_MAP.get(iss.get("severity",""), C_MUTED)
                    ir.append([
                        p(col_txt(iss.get("severity",""), ic),
                          sty("is",fontName="Courier-Bold",fontSize=7,textColor=ic)),
                        p(iss.get("msg",""), S_SM),
                    ])
                story.append(tbl(ir, [24*mm,118*mm], hdr=True))
            story.append(sp(10))

    # ══════════════════════════════════════════════════════════════════════════
    # DNS
    # ══════════════════════════════════════════════════════════════════════════
    if dns_data and dns_data.get("records"):
        story.append(PageBreak())
        story.append(p(col_txt("03  DNS RECONNAISSANCE", C_CYAN), S_H1))
        story.append(hr(C_CYAN))
        for rtype, vals in (dns_data.get("records") or {}).items():
            if not vals: continue
            story.append(p(rtype, sty("rt",fontName="Courier-Bold",fontSize=8,
                                      textColor=C_MUTED,spaceBefore=5)))
            rr = [[p("VALUE",S_LABEL)]]
            for v in vals:
                rr.append([p(str(v)[:100], S_SM)])
            story.append(tbl(rr, [142*mm], hdr=True))

        story.append(sp(8))
        spf_ok   = dns_data.get("has_spf",   False)
        dmarc_ok = dns_data.get("has_dmarc", False)
        pos = [
            [p("CHECK",S_LABEL),p("STATUS",S_LABEL),p("NOTE",S_LABEL)],
            [p("SPF",  S_MONO),
             p(col_txt("CONFIGURED" if spf_ok else "MISSING",
                       C_GREEN if spf_ok else C_RED),
               sty("spf",fontName="Courier-Bold",fontSize=7,
                   textColor=C_GREEN if spf_ok else C_RED)),
             p("" if spf_ok else "Email spoofing risk", S_SM)],
            [p("DMARC",S_MONO),
             p(col_txt("CONFIGURED" if dmarc_ok else "MISSING",
                       C_GREEN if dmarc_ok else C_RED),
               sty("dmarc",fontName="Courier-Bold",fontSize=7,
                   textColor=C_GREEN if dmarc_ok else C_RED)),
             p("" if dmarc_ok else "Email spoofing risk", S_SM)],
        ]
        story.append(tbl(pos, [22*mm,30*mm,90*mm], hdr=True))

        subs = dns_data.get("subdomains",[])
        if subs:
            story.append(sp(8))
            story.append(p(f"SUBDOMAINS ({len(subs)})", S_LABEL))
            sr2 = [[p("SUBDOMAIN",S_LABEL),p("IP",S_LABEL)]]
            for s in subs[:30]:
                sr2.append([
                    p(col_txt(s.get("subdomain",""), C_CYAN),
                      sty("sd",fontName="Courier",fontSize=7,textColor=C_CYAN)),
                    p(s.get("ip",""), S_SM),
                ])
            story.append(tbl(sr2, [90*mm,52*mm], hdr=True))

    # ══════════════════════════════════════════════════════════════════════════
    # HTTP HEADERS
    # ══════════════════════════════════════════════════════════════════════════
    if hdr_data and hdr_data.get("headers"):
        story.append(PageBreak())
        story.append(p(col_txt("04  HTTP HEADER ANALYSIS", C_CYAN), S_H1))
        story.append(hr(C_CYAN))
        hgrade = hdr_data.get("grade","?")
        hscore = hdr_data.get("score",0)
        GCOLS2 = {"A+":C_GREEN,"A":C_GREEN,"B":C_YELLOW,"C":C_ORANGE,"D":C_RED,"F":C_RED}
        hgcol  = GCOLS2.get(hgrade, C_MUTED)

        gr = Table([[
            p(col_txt(hgrade, hgcol),
              sty("hg",fontName="Helvetica-Bold",fontSize=26,
                  textColor=hgcol,leading=30,alignment=TA_CENTER)),
            [
                p(col_txt(hdr_data.get("url",""), C_WHITE),
                  sty("hu",fontName="Courier-Bold",fontSize=8,textColor=C_WHITE)),
                p(f'HTTP {hdr_data.get("status_code","")}  ·  '
                  f'Score {hscore}/100  ·  {hdr_data.get("server","")}', S_SM),
            ]
        ]], colWidths=[20*mm, None])
        gr.setStyle(TableStyle([
            ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1),8),
            ("BOTTOMPADDING", (0,0),(-1,-1),8),
            ("LEFTPADDING",   (0,0),(-1,-1),8),
            ("BACKGROUND",    (0,0),(-1,-1),C_DARK),
            ("BOX",           (0,0),(-1,-1),0.4,C_BORDER2),
        ]))
        story.append(gr)
        story.append(sp(6))

        hiss = [i for i in hdr_data.get("issues",[]) if i.get("severity")!="INFO"]
        if hiss:
            story.append(p("SECURITY ISSUES", S_LABEL))
            hi = [[p("SEVERITY",S_LABEL),p("FINDING",S_LABEL)]]
            for iss in hiss:
                ic = SEV_MAP.get(iss.get("severity",""), C_MUTED)
                hi.append([
                    p(col_txt(iss.get("severity",""), ic),
                      sty("hi",fontName="Courier-Bold",fontSize=7,textColor=ic)),
                    p(iss.get("msg",""), S_SM),
                ])
            story.append(tbl(hi, [24*mm,118*mm], hdr=True))
            story.append(sp(6))

        story.append(p("RESPONSE HEADERS", S_LABEL))
        hr2 = [[p("HEADER",S_LABEL),p("VALUE",S_LABEL)]]
        for k, v in list((hdr_data.get("headers") or {}).items())[:25]:
            hr2.append([
                p(k[:32], sty("hk",fontName="Courier-Bold",fontSize=7,textColor=C_MUTED)),
                p(str(v)[:80], S_SM),
            ])
        story.append(tbl(hr2, [52*mm,90*mm], hdr=True))

    # ══════════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(p(col_txt("05  RECOMMENDATIONS", C_CYAN), S_H1))
    story.append(hr(C_CYAN))

    all_mits = []
    for h in hosts:
        for port in h.get("ports",[]):
            for m in port.get("mitigations",[]):
                if m not in all_mits:
                    all_mits.append(m)

    if all_mits:
        mr = [[p("#",S_LABEL),p("RECOMMENDATION",S_LABEL)]]
        for i, m in enumerate(all_mits[:40], 1):
            col = C_RED if "URGENT" in m else (C_ORANGE if "patch" in m.lower() else C_BODY)
            mr.append([
                p(str(i), sty("mn",fontName="Courier-Bold",fontSize=7,textColor=C_MUTED)),
                p(m, sty("mt",fontName="Courier",fontSize=7,textColor=col,leading=11)),
            ])
        story.append(tbl(mr, [10*mm,132*mm], hdr=True))
    else:
        story.append(p("No specific recommendations at this time.", S_SM))

    story += [sp(16)]
    story.append(p(
        "Generated by VulnScan Pro — open-source security assessment platform.  "
        "Results are informational only. Always verify before remediation.  "
        "Ensure written permission for all tested systems.",
        S_DISC))

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buf.seek(0)
    fname = (f"vulnscan-{re.sub(r'[^a-zA-Z0-9._-]', '_', target)}"
             f"-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf")
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})"""


# ── Patch registry ─────────────────────────────────────────────────────────────
PATCH_REGISTRY = [
    {
        "file": "api_server.py",
        "patches": [
            (
                "PDF /report: cyberpunk dark theme (v2 — fixed hexval bug)",
                OLD_REPORT,
                NEW_REPORT,
            ),
        ],
    },
]


def run_syntax_check(path):
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True
    )
    return r.returncode == 0, r.stderr.strip()


def main():
    print()
    print(BOLD + CYAN + "╔══════════════════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "║  VulnScan Pro — PDF Theme Patch v2.0             ║" + RESET)
    print(BOLD + CYAN + "║  Fix: hexval() → _hex()  |  500 error resolved   ║" + RESET)
    print(BOLD + CYAN + "╚══════════════════════════════════════════════════╝" + RESET)
    print()

    missing = [f for f in ["api_server.py","backend.py","auth.py"] if not os.path.isfile(f)]
    if missing:
        print(RED + BOLD + "  ERROR: Not in the vulnscan project root." + RESET)
        print(f"  Missing: {', '.join(missing)}")
        print("  Run: cd ~/vulnscan && python3 patch.py")
        sys.exit(1)

    info(f"Project root: {os.getcwd()}")
    print()

    for entry in PATCH_REGISTRY:
        path = entry["file"]
        print(BOLD + f"  File: {path}" + RESET)
        apply_patches(path, entry["patches"])
        print()

    syntax_ok = True
    if results["files_modified"]:
        print(BOLD + "  Syntax checks:" + RESET)
        for path in results["files_modified"]:
            flag, err = run_syntax_check(path)
            if flag:
                ok(f"{path} — syntax OK")
            else:
                fail(f"{path} — SYNTAX ERROR:")
                print(f"    {RED}{err}{RESET}")
                syntax_ok = False
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(BOLD + CYAN + "══════════════════════════════════════════════════" + RESET)
    print(BOLD + "  SUMMARY" + RESET)
    print(BOLD + CYAN + "══════════════════════════════════════════════════" + RESET)
    print(f"  Changes applied : {GREEN}{results['changes_applied']}{RESET}")
    print(f"  Already applied : {DIM}{results['changes_skipped']}{RESET}")
    print(f"  Failed          : {RED if results['changes_failed'] else DIM}{results['changes_failed']}{RESET}")
    print()

    if results["files_modified"]:
        print("  Files modified:")
        for f in results["files_modified"]:
            print(f"    {GREEN}✓{RESET}  {f}  {DIM}(backup: {f}.*.bak){RESET}")
        print()

    if not syntax_ok:
        print(f"  {RED}⚠  Syntax error — restore the .bak file before restarting{RESET}")
    elif results["restart_needed"]:
        print(f"  {YELLOW}Restart required:{RESET}")
        print(f"    {CYAN}python3 api_server.py{RESET}")
        print(f"  {DIM}or with systemd:{RESET}")
        print(f"    {CYAN}sudo systemctl restart vulnscan{RESET}")
    elif results["changes_applied"] == 0 and results["changes_skipped"] > 0:
        print(f"  {GREEN}Already up to date — no restart needed.{RESET}")
    else:
        print(f"  {YELLOW}Nothing changed (patch may already be applied or old code not found).{RESET}")

    if results["changes_applied"] > 0 and syntax_ok:
        print()
        print(f"  {GREEN}What changed:{RESET}")
        print(f"    {GREEN}✓{RESET} Root cause fixed: hexval() → _hex() helper (was causing 500)")
        print(f"    • Dark background: #04040a  (matches website body)")
        print(f"    • Top bar: cyan/purple gradient  (matches website header)")
        print(f"    • Footer: matrix-green strip with neon text")
        print(f"    • Fonts: Courier mono (matches --mono) + Helvetica headings")
        print(f"    • Neon severity: CRITICAL=#ff3366 HIGH=#ff6b35 MEDIUM=#ffd60a")
        print(f"    • Cover KPI grid matching website .stats cards")
        print(f"    • Full sections: ports·CVEs·mitigations·SSL·DNS·headers·recs")
        print(f"    • CONFIDENTIAL watermark on pages 2+")
        print(f"    • Website functionality unchanged — only /report patched")
    print()


if __name__ == "__main__":
    main()
