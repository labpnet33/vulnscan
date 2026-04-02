import { useEffect, useMemo, useRef, useState } from "react";

const TOKENS = {
  color: {
    primary: "#00BD7D",
    secondary: "#00BD7D",
    success: "#16A34A",
    warning: "#D97706",
    danger: "#DC2626",
    surface: "#FFFFFF",
    text: "#111827",
    neutral900: "#111827",
    neutral800: "#1F2937",
    neutral700: "#374151",
    neutral200: "#E5E7EB",
    neutral100: "#F3F4F6",
  },
  spacing: { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 },
  radius: { sm: 8, md: 12, lg: 16 },
};

const SEVERITY_CONFIG = {
  CRITICAL: { accent: "var(--danger)", bg: "#FEE2E2", label: "Critical" },
  HIGH: { accent: "#EA580C", bg: "#FFEDD5", label: "High" },
  MEDIUM: { accent: "var(--warning)", bg: "#FEF3C7", label: "Medium" },
  LOW: { accent: "var(--success)", bg: "#DCFCE7", label: "Low" },
  UNKNOWN: { accent: "#6B7280", bg: "#E5E7EB", label: "Unknown" },
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
            {
              id: "CVE-2023-28531",
              description:
                "ssh-add in OpenSSH before 9.3 applies destination constraints to smartcard keys even if they are not supported.",
              score: 7.8,
              severity: "HIGH",
              published: "2023-03-17",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-28531"],
            },
          ],
          mitigations: [
            "Urgent: patch OpenSSH immediately.",
            "Upgrade OpenSSH to version 9.3p2 or later.",
            "Disable root login (PermitRootLogin no).",
            "Use SSH key authentication instead of passwords.",
            "Restrict SSH access to specific IP ranges.",
          ],
        },
        {
          port: 80,
          protocol: "tcp",
          service: "http",
          product: "Apache httpd",
          version: "2.4.51",
          extrainfo: "",
          risk_level: "CRITICAL",
          risk_score: 9.8,
          cves: [
            {
              id: "CVE-2021-41773",
              description:
                "A flaw in path normalization in Apache HTTP Server 2.4.49 enables path traversal and file mapping outside configured directories.",
              score: 9.8,
              severity: "CRITICAL",
              published: "2021-10-05",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
          ],
          mitigations: [
            "Upgrade Apache to 2.4.52 or later.",
            "Enable HTTPS and redirect all HTTP traffic.",
            "Add security headers (CSP, X-Frame-Options).",
            "Disable directory listing.",
          ],
        },
        {
          port: 3306,
          protocol: "tcp",
          service: "mysql",
          product: "MySQL",
          version: "5.7.38",
          extrainfo: "MySQL Community Server",
          risk_level: "MEDIUM",
          risk_score: 5.5,
          cves: [
            {
              id: "CVE-2022-21417",
              description:
                "Vulnerability in Oracle MySQL Server allows high privileged attackers to cause server hang or crash.",
              score: 4.9,
              severity: "MEDIUM",
              published: "2022-04-19",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-21417"],
            },
          ],
          mitigations: [
            "Never expose MySQL directly to the internet.",
            "Bind MySQL to localhost only.",
            "Upgrade to MySQL 8.0 LTS.",
          ],
        },
      ],
    },
  ],
  scan_info: { elapsed: "12.34", summary: "Nmap done: 1 IP address (1 host up)" },
};

function SeverityBadge({ level }) {
  const config = SEVERITY_CONFIG[level] || SEVERITY_CONFIG.UNKNOWN;
  return (
    <span className="severity-badge" style={{ background: config.bg, color: config.accent }}>
      {config.label}
    </span>
  );
}

function ScorePill({ score }) {
  const config = score >= 9 ? SEVERITY_CONFIG.CRITICAL : score >= 7 ? SEVERITY_CONFIG.HIGH : score >= 4 ? SEVERITY_CONFIG.MEDIUM : SEVERITY_CONFIG.LOW;
  return (
    <span className="score-pill" style={{ borderColor: config.accent, color: config.accent }}>
      CVSS {score ?? "N/A"}
    </span>
  );
}

function PortCard({ port }) {
  const [open, setOpen] = useState(false);
  const config = SEVERITY_CONFIG[port.risk_level] || SEVERITY_CONFIG.UNKNOWN;

  return (
    <section className="port-card" style={{ borderColor: `${config.accent}50` }}>
      <button
        type="button"
        className="port-summary"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <div className="port-number" style={{ color: config.accent, background: config.bg }}>
          {port.port}
        </div>
        <div className="port-meta">
          <h4>
            {port.product || port.service} {port.version && <span>v{port.version}</span>}
          </h4>
          <p>
            {port.protocol.toUpperCase()} · {port.service}
            {port.extrainfo ? ` · ${port.extrainfo}` : ""}
          </p>
        </div>
        <div className="port-state">
          <ScorePill score={port.risk_score} />
          <SeverityBadge level={port.risk_level} />
        </div>
      </button>

      {open && (
        <div className="port-details">
          <div className="detail-block">
            <h5>Vulnerabilities ({port.cves?.length || 0})</h5>
            {port.cves?.map((cve) => (
              <article key={cve.id} className="cve-card">
                <div className="cve-top">
                  <a href={cve.references?.[0] || `https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer">
                    {cve.id}
                  </a>
                  <SeverityBadge level={cve.severity} />
                  <ScorePill score={cve.score} />
                  <time>{cve.published}</time>
                </div>
                <p>{cve.description}</p>
              </article>
            ))}
          </div>

          <div className="detail-block">
            <h5>Mitigation recommendations</h5>
            <ul>
              {port.mitigations?.map((item, idx) => (
                <li key={`${port.port}-mit-${idx}`}>{item}</li>
              ))}
            </ul>
          </div>

          {port.cpe?.length ? (
            <div className="cpe-list">
              {port.cpe.map((cpe, idx) => (
                <code key={`${cpe}-${idx}`}>{cpe}</code>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}

function ScanResults({ results }) {
  if (!results?.hosts?.length) return null;

  const allPorts = results.hosts.flatMap((host) => host.ports || []);
  const stats = [
    { label: "Open ports", value: allPorts.length },
    { label: "Critical", value: allPorts.filter((p) => p.risk_level === "CRITICAL").length },
    { label: "High", value: allPorts.filter((p) => p.risk_level === "HIGH").length },
    { label: "CVEs", value: allPorts.reduce((sum, p) => sum + (p.cves?.length || 0), 0) },
  ];

  return (
    <section className="results-layer" aria-live="polite">
      <div className="stats-grid">
        {stats.map((stat) => (
          <article key={stat.label} className="stat-card">
            <div>{stat.value}</div>
            <p>{stat.label}</p>
          </article>
        ))}
      </div>

      {results.hosts.map((host) => (
        <section key={host.ip} className="host-layer">
          <header>
            <h3>{host.ip}</h3>
            <p>{host.hostnames?.[0] || "No hostname"}</p>
            <span>{host.status === "up" ? "Host up" : "Host down"}</span>
          </header>
          {host.ports?.map((port) => (
            <PortCard key={`${host.ip}-${port.port}`} port={port} />
          ))}
        </section>
      ))}

      <footer className="scan-footer">
        {results.scan_info?.summary} · {results.scan_info?.elapsed}s
      </footer>
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

  const addLog = (text, type = "info", delay = 0) => {
    setTimeout(() => setLogs((prev) => [...prev, { id: Date.now() + Math.random(), text, type }]), delay);
  };

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const runDemoScan = () => {
    setDemoMode(true);
    setError(null);
    setResults(null);
    setLogs([]);
    setScanning(true);
    setTarget("192.168.1.1");

    [
      ["Initializing scanner pipeline...", "info", 0],
      ["Preparing layered host graph...", "info", 500],
      ["Collecting open services and CVEs...", "info", 1200],
      ["Critical exposure found on port 80.", "error", 2600],
      ["Mitigations generated.", "success", 4000],
      ["Scan complete.", "success", 4800],
    ].forEach(([text, type, delay]) => addLog(text, type, delay));

    setTimeout(() => {
      setResults(MOCK_SCAN_RESULT);
      setScanning(false);
    }, 5400);
  };

  const runRealScan = async () => {
    if (!target.trim()) return;
    setDemoMode(false);
    setError(null);
    setResults(null);
    setLogs([]);
    setScanning(true);

    addLog(`Target queued: ${target}`, "info", 0);
    addLog("Attempting local API bridge at localhost:5000", "info", 250);

    try {
      const resp = await fetch(`http://localhost:5000/scan?target=${encodeURIComponent(target)}`, {
        signal: AbortSignal.timeout(5000),
      });
      const data = await resp.json();
      if (data.error) {
        setError(data.error);
      } else {
        setResults(data);
        addLog("Scan complete.", "success", 100);
      }
    } catch {
      addLog("No local backend detected.", "warn", 800);
      setError("Local scanner backend is offline. Start api_server.py or run demo mode.");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="hero-layer">
        <div className="hero-content">
          <p>Perspective Security Workspace</p>
          <h1>VulnScan Depth Console</h1>
          <span>Isometric layers, strict hierarchy, and high-contrast remediation workflows.</span>
        </div>
      </header>

      <main className="main-grid">
        <section className="panel panel-elevated">
          <label htmlFor="target">Scan target</label>
          <div className="input-row">
            <input
              id="target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && canScan && runRealScan()}
              placeholder="IP, domain, or URL"
            />
            <button type="button" className="btn-primary" onClick={runRealScan} disabled={!canScan}>
              {scanning ? "Scanning..." : "Run Scan"}
            </button>
            <button type="button" className="btn-ghost" onClick={runDemoScan} disabled={scanning}>
              Demo Data
            </button>
          </div>
          {demoMode ? <p className="hint">Demo mode is active. Results are simulated.</p> : null}
        </section>

        {logs.length > 0 ? (
          <section className="panel terminal-panel" ref={logRef}>
            <h2>Activity stream</h2>
            {logs.map((log) => (
              <p key={log.id} className={`log-${log.type}`}>
                {log.text}
              </p>
            ))}
          </section>
        ) : null}

        {error ? <section className="panel error-panel">{error}</section> : null}

        <ScanResults results={results} />

        <section className="panel setup-panel">
          <h2>Setup</h2>
          <ol>
            <li>Install nmap: <code>sudo apt-get install nmap</code></li>
            <li>Run local scanner: <code>python3 backend.py &lt;target&gt;</code></li>
            <li>Run API mode: <code>python3 api_server.py</code></li>
          </ol>
        </section>
      </main>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Oswald:wght@500;600&family=Poppins:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
        :root {
          --primary: ${TOKENS.color.primary};
          --success: ${TOKENS.color.success};
          --warning: ${TOKENS.color.warning};
          --danger: ${TOKENS.color.danger};
          --surface: ${TOKENS.color.surface};
          --text: ${TOKENS.color.text};
          --neutral-900: ${TOKENS.color.neutral900};
          --neutral-800: ${TOKENS.color.neutral800};
          --neutral-700: ${TOKENS.color.neutral700};
          --neutral-200: ${TOKENS.color.neutral200};
          --neutral-100: ${TOKENS.color.neutral100};
        }
        * { box-sizing: border-box; }
        body { margin: 0; }
        .app-shell {
          min-height: 100vh;
          color: var(--text);
          font-family: 'Poppins', system-ui, sans-serif;
          background:
            radial-gradient(circle at 20% 0%, #d1fae5 0%, #f8fafc 34%, #f3f4f6 100%);
        }
        .hero-layer {
          padding: ${TOKENS.spacing.xxl}px;
          background: linear-gradient(132deg, #111827 8%, #1f2937 65%, #111827 100%);
          color: white;
          clip-path: polygon(0 0, 100% 0, 100% 84%, 0 100%);
        }
        .hero-content { max-width: 1100px; margin: 0 auto; }
        .hero-content p {
          margin: 0;
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          letter-spacing: .08em;
          color: #6ee7b7;
        }
        .hero-content h1 {
          margin: ${TOKENS.spacing.sm}px 0;
          font-family: 'Oswald', sans-serif;
          font-size: 32px;
          line-height: 1.1;
          letter-spacing: .02em;
        }
        .hero-content span { font-size: 16px; color: #d1d5db; }
        .main-grid {
          max-width: 1100px;
          margin: -18px auto 0;
          padding: 0 ${TOKENS.spacing.xl}px ${TOKENS.spacing.xxl}px;
          display: grid;
          gap: ${TOKENS.spacing.lg}px;
        }
        .panel {
          background: var(--surface);
          border: 1px solid var(--neutral-200);
          border-radius: ${TOKENS.radius.md}px;
          padding: ${TOKENS.spacing.lg}px;
          box-shadow: 0 6px 14px rgba(17,24,39,.06);
        }
        .panel-elevated {
          box-shadow: 0 10px 0 #d1d5db, 0 20px 24px rgba(17,24,39,.12);
          transform: perspective(1100px) rotateX(2deg);
        }
        label { display: block; font-size: 12px; font-weight: 600; margin-bottom: ${TOKENS.spacing.sm}px; }
        .input-row { display: flex; gap: ${TOKENS.spacing.sm}px; flex-wrap: wrap; }
        input {
          flex: 1;
          min-width: 220px;
          font-size: 14px;
          border: 1px solid var(--neutral-200);
          border-radius: ${TOKENS.radius.sm}px;
          padding: ${TOKENS.spacing.md}px;
          font-family: 'Poppins', sans-serif;
        }
        input:focus-visible, button:focus-visible, .port-summary:focus-visible {
          outline: 3px solid #93c5fd;
          outline-offset: 2px;
        }
        .btn-primary, .btn-ghost {
          border-radius: ${TOKENS.radius.sm}px;
          border: 1px solid transparent;
          padding: ${TOKENS.spacing.md}px ${TOKENS.spacing.lg}px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
        }
        .btn-primary { background: var(--primary); color: #052e16; }
        .btn-primary:hover:not(:disabled) { filter: brightness(0.94); }
        .btn-ghost { background: white; border-color: var(--neutral-200); color: var(--neutral-800); }
        .btn-ghost:hover:not(:disabled) { background: var(--neutral-100); }
        button:disabled { opacity: .55; cursor: not-allowed; }
        .hint { margin: ${TOKENS.spacing.sm}px 0 0; color: var(--neutral-700); font-size: 12px; }
        .terminal-panel h2, .setup-panel h2 { margin: 0 0 ${TOKENS.spacing.sm}px; font-size: 16px; }
        .terminal-panel { max-height: 260px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; }
        .terminal-panel p { margin: 0 0 8px; font-size: 12px; }
        .log-info { color: #1d4ed8; }
        .log-success { color: var(--success); }
        .log-warn { color: var(--warning); }
        .log-error { color: var(--danger); }
        .error-panel { color: var(--danger); border-color: #fecaca; background: #fef2f2; font-weight: 600; }
        .results-layer { display: grid; gap: ${TOKENS.spacing.lg}px; }
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
          gap: ${TOKENS.spacing.sm}px;
        }
        .stat-card {
          background: linear-gradient(160deg, white 0%, #f9fafb 70%);
          border: 1px solid #e5e7eb;
          border-radius: ${TOKENS.radius.sm}px;
          padding: ${TOKENS.spacing.md}px;
          text-align: center;
          transform: translateZ(0);
        }
        .stat-card div { font-size: 24px; font-weight: 700; }
        .stat-card p { margin: 4px 0 0; font-size: 12px; color: var(--neutral-700); }
        .host-layer > header { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; margin-bottom: 8px; }
        .host-layer h3 { margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 16px; }
        .host-layer p { margin: 0; font-size: 12px; color: var(--neutral-700); }
        .host-layer span { font-size: 12px; color: var(--success); font-weight: 600; }
        .port-card {
          border: 1px solid;
          border-radius: ${TOKENS.radius.md}px;
          background: white;
          margin-bottom: ${TOKENS.spacing.sm}px;
          overflow: hidden;
        }
        .port-summary {
          width: 100%;
          border: 0;
          background: transparent;
          padding: ${TOKENS.spacing.md}px;
          display: flex;
          align-items: center;
          gap: ${TOKENS.spacing.md}px;
          text-align: left;
          cursor: pointer;
        }
        .port-number {
          min-width: 62px;
          text-align: center;
          font: 600 20px 'Oswald', sans-serif;
          border-radius: ${TOKENS.radius.sm}px;
          padding: 6px 10px;
        }
        .port-meta { flex: 1; min-width: 170px; }
        .port-meta h4 { margin: 0; font-size: 16px; }
        .port-meta h4 span { font-size: 14px; color: var(--neutral-700); }
        .port-meta p { margin: 4px 0 0; font-size: 12px; color: var(--neutral-700); }
        .port-state { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .severity-badge, .score-pill {
          display: inline-flex;
          align-items: center;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 600;
          line-height: 1;
          padding: 6px 10px;
          white-space: nowrap;
        }
        .score-pill { border: 1px solid; background: white; }
        .port-details {
          border-top: 1px solid var(--neutral-200);
          padding: ${TOKENS.spacing.md}px;
          display: grid;
          gap: ${TOKENS.spacing.md}px;
        }
        .detail-block h5 { margin: 0 0 8px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
        .cve-card {
          border: 1px solid var(--neutral-200);
          border-radius: ${TOKENS.radius.sm}px;
          padding: 10px;
          margin-bottom: 8px;
          background: #fcfcfd;
        }
        .cve-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .cve-top a { color: #0369a1; font: 600 12px 'JetBrains Mono', monospace; text-decoration: none; }
        .cve-top time { margin-left: auto; font-size: 12px; color: var(--neutral-700); }
        .cve-card p { margin: 8px 0 0; font-size: 13px; color: var(--neutral-900); }
        ul { margin: 0; padding-left: 18px; }
        li { margin-bottom: 6px; font-size: 13px; }
        .cpe-list { display: flex; flex-wrap: wrap; gap: 6px; }
        .cpe-list code {
          font: 500 11px 'JetBrains Mono', monospace;
          background: var(--neutral-100);
          border: 1px solid var(--neutral-200);
          border-radius: 6px;
          padding: 4px 8px;
        }
        .scan-footer { text-align: center; font-size: 12px; color: var(--neutral-700); }
        .setup-panel code { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
        @media (max-width: 720px) {
          .hero-layer { padding: ${TOKENS.spacing.xl}px; }
          .hero-content h1 { font-size: 24px; }
          .main-grid { padding: 0 ${TOKENS.spacing.md}px ${TOKENS.spacing.xl}px; }
          .port-summary { align-items: flex-start; }
        }
      `}</style>
    </div>
  );
}
