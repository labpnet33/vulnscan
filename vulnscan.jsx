import { useEffect, useMemo, useRef, useState } from "react";

const TOKENS = {
  color: {
    primary: "#00BD7D",
    secondary: "#00BD7D",
    success: "#16A34A",
    warning: "#D97706",
    danger: "#DC2626",
    surface: "rgba(255,255,255,0.18)",
    text: "#111827",
  },
  spacing: { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 },
};

const SEVERITY_CONFIG = {
  CRITICAL: { accent: "#DC2626", bg: "rgba(220,38,38,0.14)", label: "Critical" },
  HIGH: { accent: "#EA580C", bg: "rgba(234,88,12,0.14)", label: "High" },
  MEDIUM: { accent: "#D97706", bg: "rgba(217,119,6,0.14)", label: "Medium" },
  LOW: { accent: "#16A34A", bg: "rgba(22,163,74,0.14)", label: "Low" },
  UNKNOWN: { accent: "#6B7280", bg: "rgba(107,114,128,0.14)", label: "Unknown" },
};

const MOCK_SCAN_RESULT = {
  hosts: [
    {
      ip: "192.168.1.1",
      status: "up",
      hostnames: ["router.local"],
      ports: [
        {
          port: 22,
          protocol: "tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "7.4",
          extrainfo: "protocol 2.0",
          cpe: ["cpe:/a:openbsd:openssh:7.4"],
          risk_level: "HIGH",
          risk_score: 7.8,
          cves: [
            {
              id: "CVE-2023-38408",
              description:
                "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.",
              score: 9.8,
              severity: "CRITICAL",
              published: "2023-07-20",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
            },
          ],
          mitigations: [
            "Patch OpenSSH immediately.",
            "Upgrade OpenSSH to 9.3p2 or later.",
            "Disable root login.",
          ],
        },
        {
          port: 80,
          protocol: "tcp",
          service: "http",
          product: "Apache httpd",
          version: "2.4.51",
          risk_level: "CRITICAL",
          risk_score: 9.8,
          cves: [
            {
              id: "CVE-2021-41773",
              description: "Path traversal in Apache HTTP Server 2.4.49.",
              score: 9.8,
              severity: "CRITICAL",
              published: "2021-10-05",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
          ],
          mitigations: ["Upgrade Apache.", "Enable HTTPS.", "Harden headers."],
        },
      ],
    },
  ],
  scan_info: { elapsed: "12.34", summary: "Nmap done: 1 IP address (1 host up)" },
};

function SeverityBadge({ level }) {
  const config = SEVERITY_CONFIG[level] || SEVERITY_CONFIG.UNKNOWN;
  return (
    <span className="severity" style={{ color: config.accent, background: config.bg, borderColor: `${config.accent}66` }}>
      {config.label}
    </span>
  );
}

function PortCard({ port }) {
  const [open, setOpen] = useState(false);
  return (
    <article className="port-card">
      <button type="button" className="port-trigger" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <div>
          <h4>{port.port}/{port.protocol}</h4>
          <p>{port.product || port.service} {port.version ? `v${port.version}` : ""}</p>
        </div>
        <div className="port-right">
          <SeverityBadge level={port.risk_level} />
          <span className="cvss">CVSS {port.risk_score ?? "N/A"}</span>
        </div>
      </button>
      {open ? (
        <div className="port-body">
          <h5>Vulnerabilities</h5>
          {(port.cves || []).map((cve) => (
            <div key={cve.id} className="cve-item">
              <div className="cve-head">
                <a href={cve.references?.[0]} target="_blank" rel="noreferrer">{cve.id}</a>
                <SeverityBadge level={cve.severity} />
                <time>{cve.published}</time>
              </div>
              <p>{cve.description}</p>
            </div>
          ))}
          <h5>Mitigation</h5>
          <ul>
            {(port.mitigations || []).map((m, i) => <li key={`${port.port}-${i}`}>{m}</li>)}
          </ul>
        </div>
      ) : null}
    </article>
  );
}

function ScanResults({ results }) {
  if (!results?.hosts?.length) return null;
  const allPorts = results.hosts.flatMap((h) => h.ports || []);
  const stats = [
    ["Open Ports", allPorts.length],
    ["Critical", allPorts.filter((p) => p.risk_level === "CRITICAL").length],
    ["CVEs", allPorts.reduce((a, p) => a + (p.cves?.length || 0), 0)],
    ["Hosts", results.hosts.length],
  ];

  return (
    <section className="results" aria-live="polite">
      <div className="stat-row">
        {stats.map(([label, value]) => (
          <div key={label} className="stat">
            <strong>{value}</strong>
            <span>{label}</span>
          </div>
        ))}
      </div>
      {results.hosts.map((host) => (
        <div key={host.ip} className="host-card">
          <header>
            <h3>{host.ip}</h3>
            <p>{host.hostnames?.[0] || "No hostname"} · {host.status}</p>
          </header>
          {host.ports?.map((port) => <PortCard key={`${host.ip}-${port.port}`} port={port} />)}
        </div>
      ))}
      <p className="scan-note">{results.scan_info?.summary} · {results.scan_info?.elapsed}s</p>
    </section>
  );
}

export default function VulnScanner() {
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [logs, setLogs] = useState([]);
  const [demoMode, setDemoMode] = useState(false);
  const logRef = useRef(null);
  const canScan = useMemo(() => Boolean(target.trim()) && !scanning, [target, scanning]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const runDemoScan = () => {
    setDemoMode(true);
    setError(null);
    setScanning(true);
    setLogs([]);
    setResults(null);
    setTarget("192.168.1.1");
    const timeline = [
      ["Initializing scan canvas...", "info", 0],
      ["Collecting service metadata...", "info", 500],
      ["Matching CVEs against NVD...", "warn", 1200],
      ["Critical risk detected on port 80", "error", 2200],
      ["Mitigation plan prepared", "success", 3000],
    ];
    timeline.forEach(([text, type, delay]) => {
      setTimeout(() => setLogs((prev) => [...prev, { id: Date.now() + Math.random(), text, type }]), delay);
    });
    setTimeout(() => {
      setResults(MOCK_SCAN_RESULT);
      setScanning(false);
    }, 3600);
  };

  const runRealScan = async () => {
    if (!target.trim()) return;
    setDemoMode(false);
    setError(null);
    setResults(null);
    setScanning(true);
    setLogs([{ id: Date.now(), text: `Target queued: ${target}`, type: "info" }]);
    try {
      const resp = await fetch(`http://localhost:5000/scan?target=${encodeURIComponent(target)}`, {
        signal: AbortSignal.timeout(5000),
      });
      const data = await resp.json();
      if (data.error) setError(data.error);
      else setResults(data);
    } catch {
      setError("Local scanner backend is offline. Start api_server.py or run demo mode.");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="page">
      <div className="ambient-bg" />
      <div className="glass-shell">
        <aside className="side-nav">
          <p className="kicker">VULNSCAN VR</p>
          <h1>Spatial Security Console</h1>
          <div className="analyst-card">
            <div className="avatar" />
            <div>
              <strong>Security Analyst</strong>
              <span>Threat Monitoring</span>
            </div>
          </div>
          <nav>
            <button type="button">Overview</button>
            <button type="button">Live Scan</button>
            <button type="button">Risk Board</button>
            <button type="button">History</button>
          </nav>
        </aside>

        <section className="workspace">
          <header className="hero-art">
            <div className="art-frame" aria-hidden="true" />
          </header>

          <section className="control-strip">
            <label htmlFor="target">Target</label>
            <div className="controls">
              <input
                id="target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && canScan && runRealScan()}
                placeholder="192.168.1.1 or example.com"
              />
              <button type="button" className="primary" onClick={runRealScan} disabled={!canScan}>{scanning ? "Scanning..." : "Run Scan"}</button>
              <button type="button" className="ghost" onClick={runDemoScan} disabled={scanning}>Demo</button>
            </div>
            {demoMode ? <p className="demo-tag">Demo mode enabled</p> : null}
          </section>

          {logs.length > 0 ? (
            <section className="log-card" ref={logRef}>
              {logs.map((log) => <p key={log.id} className={`log-${log.type}`}>{log.text}</p>)}
            </section>
          ) : null}

          {error ? <section className="error">{error}</section> : null}

          <ScanResults results={results} />
        </section>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Oswald:wght@500;600&family=Poppins:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
        * { box-sizing: border-box; }
        body { margin: 0; }
        .page {
          min-height: 100vh;
          padding: 48px 24px;
          font-family: 'Poppins', sans-serif;
          color: #F9FAFB;
          position: relative;
          overflow: hidden;
          background: #9ca3af;
        }
        .ambient-bg {
          position: fixed;
          inset: 0;
          background:
            radial-gradient(circle at 20% 15%, rgba(255,255,255,.75) 0 20%, transparent 45%),
            radial-gradient(circle at 78% 84%, rgba(148,163,184,.48) 0 22%, transparent 45%),
            linear-gradient(135deg, #d1d5db, #9ca3af 48%, #e5e7eb);
          filter: blur(2px);
          transform: scale(1.06);
          z-index: 0;
        }
        .glass-shell {
          position: relative;
          z-index: 1;
          max-width: 1280px;
          margin: 0 auto;
          border-radius: 28px;
          background: rgba(255,255,255,.14);
          border: 1px solid rgba(255,255,255,.45);
          backdrop-filter: blur(24px) saturate(140%);
          box-shadow: 0 24px 60px rgba(15,23,42,.2);
          display: grid;
          grid-template-columns: 300px minmax(0, 1fr);
          overflow: hidden;
        }
        .side-nav {
          padding: 32px 20px;
          background: linear-gradient(180deg, rgba(31,41,55,.36), rgba(55,65,81,.18));
          border-right: 1px solid rgba(255,255,255,.22);
        }
        .kicker {
          margin: 0;
          font: 600 12px 'JetBrains Mono', monospace;
          letter-spacing: .12em;
          color: rgba(255,255,255,.86);
        }
        .side-nav h1 {
          margin: 12px 0 20px;
          font-family: 'Oswald', sans-serif;
          font-size: 30px;
          line-height: 1.1;
          letter-spacing: .02em;
        }
        .analyst-card {
          display: flex;
          align-items: center;
          gap: 12px;
          border: 1px solid rgba(255,255,255,.3);
          background: rgba(255,255,255,.2);
          border-radius: 14px;
          padding: 12px;
          margin-bottom: 16px;
        }
        .avatar {
          width: 40px;
          height: 40px;
          border-radius: 12px;
          background: linear-gradient(135deg, #60a5fa, #34d399);
          border: 1px solid rgba(255,255,255,.5);
        }
        .analyst-card strong { display: block; font-size: 14px; }
        .analyst-card span { font-size: 12px; color: rgba(255,255,255,.75); }
        nav { display: grid; gap: 8px; margin-top: 8px; }
        nav button {
          text-align: left;
          border: 1px solid transparent;
          color: rgba(255,255,255,.86);
          background: transparent;
          border-radius: 10px;
          padding: 10px 12px;
          cursor: pointer;
        }
        nav button:hover, nav button:focus-visible {
          background: rgba(255,255,255,.15);
          border-color: rgba(255,255,255,.3);
          outline: none;
        }
        .workspace { padding: 28px; }
        .hero-art {
          margin-bottom: 18px;
        }
        .art-frame {
          width: 100%;
          min-height: 260px;
          border-radius: 16px;
          border: 1px solid rgba(255,255,255,.38);
          background:
            radial-gradient(circle at center, rgba(0,189,125,.35), transparent 30%),
            repeating-linear-gradient(135deg, rgba(15,23,42,.24) 0 16px, rgba(255,255,255,.16) 16px 32px),
            linear-gradient(145deg, #dbeafe, #93c5fd 36%, #60a5fa 54%, #f8fafc);
          box-shadow: 0 16px 34px rgba(15,23,42,.22);
          transform: perspective(1200px) rotateY(-8deg) rotateX(2deg);
        }
        .control-strip {
          border: 1px solid rgba(255,255,255,.32);
          background: rgba(255,255,255,.16);
          border-radius: 16px;
          padding: 14px;
        }
        label {
          font: 600 12px 'JetBrains Mono', monospace;
          letter-spacing: .07em;
          display: block;
          margin-bottom: 8px;
          color: rgba(255,255,255,.88);
        }
        .controls { display: flex; gap: 8px; flex-wrap: wrap; }
        input {
          flex: 1;
          min-width: 220px;
          border: 1px solid rgba(255,255,255,.45);
          background: rgba(255,255,255,.2);
          color: #f9fafb;
          border-radius: 10px;
          padding: 11px 12px;
          font-size: 14px;
        }
        input::placeholder { color: rgba(249,250,251,.72); }
        input:focus-visible, button:focus-visible, .port-trigger:focus-visible {
          outline: 3px solid rgba(147,197,253,.95);
          outline-offset: 1px;
        }
        .primary, .ghost {
          border-radius: 10px;
          padding: 11px 14px;
          font-weight: 600;
          border: 1px solid transparent;
          cursor: pointer;
        }
        .primary { background: ${TOKENS.color.primary}; color: #052e16; }
        .ghost { background: rgba(255,255,255,.22); border-color: rgba(255,255,255,.4); color: #f9fafb; }
        button:disabled { opacity: .6; cursor: not-allowed; }
        .demo-tag { margin: 8px 0 0; color: #dcfce7; font-size: 12px; }
        .log-card, .error, .results {
          margin-top: 12px;
          border: 1px solid rgba(255,255,255,.3);
          background: rgba(17,24,39,.22);
          border-radius: 14px;
          padding: 12px;
          backdrop-filter: blur(8px);
        }
        .log-card { max-height: 140px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; }
        .log-card p { margin: 0 0 7px; font-size: 12px; }
        .log-info { color: #bae6fd; }
        .log-success { color: #86efac; }
        .log-warn { color: #fde68a; }
        .log-error, .error { color: #fecaca; }
        .stat-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
          gap: 8px;
          margin-bottom: 10px;
        }
        .stat {
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,.24);
          background: rgba(255,255,255,.14);
          text-align: center;
          padding: 8px;
        }
        .stat strong { display: block; font-size: 22px; }
        .stat span { font-size: 11px; color: rgba(255,255,255,.78); }
        .host-card {
          border: 1px solid rgba(255,255,255,.22);
          background: rgba(255,255,255,.1);
          border-radius: 12px;
          padding: 10px;
          margin-bottom: 10px;
        }
        .host-card h3 { margin: 0; font: 600 15px 'JetBrains Mono', monospace; }
        .host-card p { margin: 4px 0 8px; font-size: 12px; color: rgba(255,255,255,.78); }
        .port-card { border: 1px solid rgba(255,255,255,.18); border-radius: 10px; margin-bottom: 8px; overflow: hidden; }
        .port-trigger {
          width: 100%;
          border: 0;
          background: rgba(17,24,39,.24);
          color: #fff;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
          padding: 10px;
          cursor: pointer;
          text-align: left;
        }
        .port-trigger h4 { margin: 0; font-size: 14px; }
        .port-trigger p { margin: 3px 0 0; font-size: 12px; color: rgba(255,255,255,.72); }
        .port-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
        .severity, .cvss {
          border: 1px solid rgba(255,255,255,.28);
          border-radius: 999px;
          font-size: 11px;
          padding: 4px 8px;
          font-weight: 600;
        }
        .cvss { color: #e0f2fe; background: rgba(14,116,144,.28); }
        .port-body { background: rgba(255,255,255,.08); border-top: 1px solid rgba(255,255,255,.2); padding: 10px; }
        .port-body h5 { margin: 0 0 7px; font: 600 11px 'JetBrains Mono', monospace; letter-spacing: .06em; }
        .cve-item { border: 1px solid rgba(255,255,255,.2); border-radius: 8px; padding: 8px; margin-bottom: 7px; }
        .cve-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        .cve-head a { color: #86efac; font: 600 12px 'JetBrains Mono', monospace; }
        .cve-head time { margin-left: auto; font-size: 11px; color: rgba(255,255,255,.72); }
        .cve-item p { margin: 6px 0 0; font-size: 12px; color: rgba(255,255,255,.88); }
        ul { margin: 0; padding-left: 17px; }
        li { font-size: 12px; margin-bottom: 4px; color: rgba(255,255,255,.88); }
        .scan-note { margin: 0; text-align: center; font-size: 11px; color: rgba(255,255,255,.75); }

        @media (max-width: 980px) {
          .glass-shell { grid-template-columns: 1fr; }
          .side-nav { border-right: 0; border-bottom: 1px solid rgba(255,255,255,.22); }
        }
      `}</style>
    </div>
  );
}
