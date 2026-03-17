import { useState, useEffect, useRef } from "react";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRITICAL", icon: "☢" },
  HIGH: { color: "#ff6b35", bg: "rgba(255,107,53,0.12)", label: "HIGH", icon: "⚠" },
  MEDIUM: { color: "#ffd60a", bg: "rgba(255,214,10,0.12)", label: "MEDIUM", icon: "⚡" },
  LOW: { color: "#30d158", bg: "rgba(48,209,88,0.12)", label: "LOW", icon: "✓" },
  UNKNOWN: { color: "#636366", bg: "rgba(99,99,102,0.12)", label: "UNKNOWN", icon: "?" },
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
              description: "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.",
              score: 9.8,
              severity: "CRITICAL",
              published: "2023-07-20",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
            },
            {
              id: "CVE-2023-28531",
              description: "ssh-add in OpenSSH before 9.3 applies destination constraints to smartcard keys even if they are not supported.",
              score: 7.8,
              severity: "HIGH",
              published: "2023-03-17",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-28531"],
            },
          ],
          mitigations: [
            "⚠️ URGENT: 2 critical/high CVEs found - patch immediately",
            "Upgrade OpenSSH to version 9.3p2 or later",
            "Disable root login (PermitRootLogin no)",
            "Use SSH key authentication instead of passwords",
            "Implement fail2ban to prevent brute-force attacks",
            "Restrict SSH access to specific IP ranges",
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
              description: "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories.",
              score: 9.8,
              severity: "CRITICAL",
              published: "2021-10-05",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
          ],
          mitigations: [
            "⚠️ URGENT: Immediately upgrade Apache to 2.4.52 or later",
            "Enable HTTPS and redirect all HTTP traffic to HTTPS",
            "Implement Content Security Policy (CSP) headers",
            "Add X-Frame-Options, X-Content-Type-Options headers",
            "Disable directory listing and server version disclosure",
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
              description: "Vulnerability in the MySQL Server product of Oracle MySQL. Easily exploitable vulnerability allows high privileged attacker to cause hang or crash.",
              score: 4.9,
              severity: "MEDIUM",
              published: "2022-04-19",
              references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-21417"],
            },
          ],
          mitigations: [
            "Never expose MySQL directly to the internet",
            "Bind MySQL to localhost (127.0.0.1) only",
            "Use strong passwords and principle of least privilege",
            "Upgrade to MySQL 8.0 LTS",
            "Enable MySQL audit logging",
          ],
        },
      ],
    },
  ],
  scan_info: { elapsed: "12.34", summary: "Nmap done: 1 IP address (1 host up)" },
};

function TerminalLine({ text, delay = 0, type = "info" }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);

  const colors = { info: "#00d4ff", success: "#30d158", warn: "#ffd60a", error: "#ff2d55" };
  const prefixes = { info: "[*]", success: "[+]", warn: "[!]", error: "[x]" };

  if (!visible) return null;
  return (
    <div style={{ fontFamily: "monospace", fontSize: 13, lineHeight: 1.6, color: "#a0a0a0" }}>
      <span style={{ color: colors[type] }}>{prefixes[type]} </span>
      {text}
    </div>
  );
}

function SeverityBadge({ level }) {
  const config = SEVERITY_CONFIG[level] || SEVERITY_CONFIG.UNKNOWN;
  return (
    <span style={{
      background: config.bg,
      color: config.color,
      border: `1px solid ${config.color}40`,
      borderRadius: 4,
      padding: "2px 8px",
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: 1,
      fontFamily: "monospace",
    }}>
      {config.icon} {config.label}
    </span>
  );
}

function ScoreRing({ score }) {
  if (!score) return <span style={{ color: "#636366", fontSize: 12 }}>N/A</span>;
  const config = score >= 9 ? SEVERITY_CONFIG.CRITICAL : score >= 7 ? SEVERITY_CONFIG.HIGH : score >= 4 ? SEVERITY_CONFIG.MEDIUM : SEVERITY_CONFIG.LOW;
  const pct = (score / 10) * 100;
  const r = 18, c = 2 * Math.PI * r;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <svg width={44} height={44} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={22} cy={22} r={r} fill="none" stroke="#1c1c1e" strokeWidth={4} />
        <circle cx={22} cy={22} r={r} fill="none" stroke={config.color} strokeWidth={4}
          strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1s ease" }} />
      </svg>
      <span style={{ color: config.color, fontWeight: 700, fontSize: 16, fontFamily: "monospace" }}>{score}</span>
    </div>
  );
}

function PortCard({ port }) {
  const [open, setOpen] = useState(false);
  const config = SEVERITY_CONFIG[port.risk_level] || SEVERITY_CONFIG.UNKNOWN;

  return (
    <div style={{
      border: `1px solid ${config.color}30`,
      borderLeft: `3px solid ${config.color}`,
      borderRadius: 8,
      background: "rgba(255,255,255,0.02)",
      marginBottom: 12,
      overflow: "hidden",
      transition: "all 0.2s",
    }}>
      <div onClick={() => setOpen(!open)} style={{
        padding: "14px 18px",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        gap: 16,
        flexWrap: "wrap",
      }}>
        <div style={{
          background: config.bg,
          color: config.color,
          padding: "6px 14px",
          borderRadius: 6,
          fontFamily: "monospace",
          fontWeight: 700,
          fontSize: 18,
          minWidth: 70,
          textAlign: "center",
        }}>
          {port.port}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ color: "#fff", fontWeight: 600, fontSize: 15 }}>
            {port.product || port.service} {port.version && <span style={{ color: "#636366", fontSize: 13 }}>v{port.version}</span>}
          </div>
          <div style={{ color: "#636366", fontSize: 12, marginTop: 2 }}>
            {port.protocol.toUpperCase()} · {port.service} {port.extrainfo && `· ${port.extrainfo}`}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <ScoreRing score={port.risk_score} />
          <SeverityBadge level={port.risk_level} />
          <span style={{ color: "#636366", fontSize: 18, transition: "transform 0.2s", transform: open ? "rotate(180deg)" : "none" }}>▼</span>
        </div>
      </div>

      {open && (
        <div style={{ padding: "0 18px 18px", borderTop: "1px solid #1c1c1e" }}>
          {/* CVEs */}
          {port.cves?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ color: "#636366", fontSize: 11, letterSpacing: 2, fontWeight: 700, marginBottom: 10, fontFamily: "monospace" }}>
                VULNERABILITIES ({port.cves.length})
              </div>
              {port.cves.map(cve => (
                <div key={cve.id} style={{
                  background: "#0a0a0c",
                  border: "1px solid #1c1c1e",
                  borderRadius: 6,
                  padding: 12,
                  marginBottom: 8,
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                    <a href={cve.references?.[0] || `https://nvd.nist.gov/vuln/detail/${cve.id}`}
                      target="_blank" rel="noopener noreferrer"
                      style={{ color: "#00d4ff", fontFamily: "monospace", fontWeight: 700, fontSize: 13, textDecoration: "none" }}>
                      {cve.id}
                    </a>
                    <SeverityBadge level={cve.severity} />
                    {cve.score && <span style={{ color: SEVERITY_CONFIG[cve.severity]?.color || "#fff", fontWeight: 700, fontSize: 13 }}>CVSS {cve.score}</span>}
                    <span style={{ color: "#636366", fontSize: 11, marginLeft: "auto" }}>{cve.published}</span>
                  </div>
                  <div style={{ color: "#8e8e93", fontSize: 12, lineHeight: 1.6 }}>{cve.description}</div>
                </div>
              ))}
            </div>
          )}

          {/* Mitigations */}
          {port.mitigations?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ color: "#636366", fontSize: 11, letterSpacing: 2, fontWeight: 700, marginBottom: 10, fontFamily: "monospace" }}>
                MITIGATION RECOMMENDATIONS
              </div>
              <div style={{ background: "#0a0a0c", border: "1px solid #1c1c1e", borderRadius: 6, padding: 12 }}>
                {port.mitigations.map((m, i) => (
                  <div key={i} style={{
                    display: "flex", gap: 10, padding: "6px 0",
                    borderBottom: i < port.mitigations.length - 1 ? "1px solid #1c1c1e" : "none",
                  }}>
                    <span style={{ color: "#30d158", fontFamily: "monospace", fontSize: 13, marginTop: 1 }}>›</span>
                    <span style={{ color: "#c7c7cc", fontSize: 13, lineHeight: 1.6 }}>{m}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CPE */}
          {port.cpe?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {port.cpe.map((c, i) => (
                <span key={i} style={{ background: "#1c1c1e", color: "#636366", borderRadius: 4, padding: "2px 8px", fontSize: 11, fontFamily: "monospace", marginRight: 6 }}>
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ScanResults({ results }) {
  if (!results || !results.hosts) return null;

  const allPorts = results.hosts.flatMap(h => h.ports || []);
  const critCount = allPorts.filter(p => p.risk_level === "CRITICAL").length;
  const highCount = allPorts.filter(p => p.risk_level === "HIGH").length;

  return (
    <div style={{ marginTop: 32 }}>
      {/* Summary bar */}
      <div style={{
        display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 24,
        padding: 18, background: "#0a0a0c", borderRadius: 10, border: "1px solid #1c1c1e",
      }}>
        {[
          { label: "Open Ports", value: allPorts.length, color: "#00d4ff" },
          { label: "Critical", value: critCount, color: "#ff2d55" },
          { label: "High", value: highCount, color: "#ff6b35" },
          { label: "Total CVEs", value: allPorts.reduce((a, p) => a + (p.cves?.length || 0), 0), color: "#ffd60a" },
        ].map(stat => (
          <div key={stat.label} style={{ flex: 1, minWidth: 100, textAlign: "center" }}>
            <div style={{ color: stat.color, fontSize: 28, fontWeight: 800, fontFamily: "monospace" }}>{stat.value}</div>
            <div style={{ color: "#636366", fontSize: 11, letterSpacing: 1 }}>{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Host results */}
      {results.hosts.map((host, i) => (
        <div key={i}>
          <div style={{
            display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap",
          }}>
            <span style={{ color: "#00d4ff", fontFamily: "monospace", fontSize: 13, background: "rgba(0,212,255,0.08)", padding: "4px 12px", borderRadius: 4, border: "1px solid rgba(0,212,255,0.2)" }}>
              {host.ip}
            </span>
            {host.hostnames?.[0] && <span style={{ color: "#636366", fontFamily: "monospace", fontSize: 12 }}>{host.hostnames[0]}</span>}
            <span style={{ color: "#30d158", fontSize: 12 }}>● {host.status}</span>
            {host.vendor && <span style={{ color: "#636366", fontSize: 12 }}>{host.vendor}</span>}
          </div>
          {host.ports?.map(port => <PortCard key={port.port} port={port} />)}
        </div>
      ))}

      {results.scan_info?.summary && (
        <div style={{ color: "#636366", fontSize: 11, fontFamily: "monospace", textAlign: "center", marginTop: 16 }}>
          {results.scan_info.summary} · {results.scan_info.elapsed}s
        </div>
      )}
    </div>
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

  const addLog = (text, type = "info", delay = 0) => {
    setTimeout(() => {
      setLogs(prev => [...prev, { text, type, id: Date.now() + Math.random() }]);
    }, delay);
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

    const demoLogs = [
      { text: "Initializing scanner engine...", type: "info", d: 0 },
      { text: `Starting nmap scan on: 192.168.1.1`, type: "info", d: 400 },
      { text: "Running SYN stealth scan (-sV -sC -T4)...", type: "info", d: 900 },
      { text: "Discovered open port 22/tcp on 192.168.1.1", type: "success", d: 1500 },
      { text: "Discovered open port 80/tcp on 192.168.1.1", type: "success", d: 2000 },
      { text: "Discovered open port 3306/tcp on 192.168.1.1", type: "warn", d: 2400 },
      { text: "Running version detection scripts...", type: "info", d: 2800 },
      { text: "Service detected: OpenSSH 7.4 on port 22", type: "info", d: 3200 },
      { text: "Service detected: Apache httpd 2.4.51 on port 80", type: "info", d: 3600 },
      { text: "Service detected: MySQL 5.7.38 on port 3306", type: "info", d: 4000 },
      { text: "Querying NVD database for CVEs...", type: "info", d: 4400 },
      { text: "Found 2 CVEs for OpenSSH 7.4 (max CVSS: 9.8 CRITICAL)", type: "error", d: 5000 },
      { text: "Found 1 CVE for Apache httpd 2.4.51 (CVSS: 9.8 CRITICAL)", type: "error", d: 5600 },
      { text: "Found 1 CVE for MySQL 5.7.38 (CVSS: 4.9 MEDIUM)", type: "warn", d: 6200 },
      { text: "Generating mitigation recommendations...", type: "info", d: 6800 },
      { text: "Scan complete. 3 open ports, 4 CVEs found.", type: "success", d: 7400 },
    ];

    demoLogs.forEach(({ text, type, d }) => addLog(text, type, d));

    setTimeout(() => {
      setResults(MOCK_SCAN_RESULT);
      setScanning(false);
    }, 8000);
  };

  const runRealScan = async () => {
    if (!target.trim()) return;
    setError(null);
    setResults(null);
    setLogs([]);
    setScanning(true);
    setDemoMode(false);

    addLog(`Target: ${target}`, "info", 0);
    addLog("This tool requires Python + nmap on your system.", "warn", 200);
    addLog("Run: python3 backend.py " + target, "info", 400);
    addLog("Copy the JSON output and paste below, or integrate with a local API server.", "info", 800);

    // Attempt to call a local backend if running
    try {
      const resp = await fetch(`http://localhost:5000/scan?target=${encodeURIComponent(target)}`, {
        signal: AbortSignal.timeout(5000),
      });
      const data = await resp.json();
      if (data.error) {
        setError(data.error);
      } else {
        setResults(data);
        addLog("Scan complete!", "success", 0);
      }
    } catch {
      addLog("Local backend not available (localhost:5000). Showing demo mode.", "warn", 1200);
      addLog("To run real scans, start the Flask API server included below.", "info", 1600);
      setTimeout(() => {
        setScanning(false);
        setError("Local scanner backend not running. Use demo mode or start the Flask server. See the Python files for setup instructions.");
      }, 2000);
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#050507",
      color: "#e5e5ea",
      fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
      padding: "0",
    }}>
      {/* Header */}
      <div style={{
        background: "linear-gradient(180deg, #0a0a0f 0%, #050507 100%)",
        borderBottom: "1px solid #1c1c1e",
        padding: "24px 32px",
      }}>
        <div style={{ maxWidth: 900, margin: "0 auto" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 6 }}>
            <div style={{
              width: 36, height: 36,
              background: "linear-gradient(135deg, #ff2d55, #ff6b35)",
              borderRadius: 8,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18, flexShrink: 0,
            }}>⚡</div>
            <div>
              <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, letterSpacing: -0.5, color: "#fff" }}>
                VulnScan
              </h1>
              <div style={{ color: "#636366", fontSize: 11, letterSpacing: 2, marginTop: 2 }}>
                PORT SCANNER + CVE INTELLIGENCE
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 24px" }}>
        {/* Input */}
        <div style={{
          background: "#0a0a0c",
          border: "1px solid #1c1c1e",
          borderRadius: 12,
          padding: 20,
          marginBottom: 24,
        }}>
          <div style={{ color: "#636366", fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>TARGET</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && runRealScan()}
              placeholder="Enter IP address or URL (e.g. 192.168.1.1)"
              style={{
                flex: 1, minWidth: 200,
                background: "#050507",
                border: "1px solid #2c2c2e",
                borderRadius: 8,
                color: "#00d4ff",
                padding: "10px 14px",
                fontSize: 14,
                fontFamily: "inherit",
                outline: "none",
              }}
            />
            <button onClick={runRealScan} disabled={scanning || !target.trim()} style={{
              background: scanning ? "#1c1c1e" : "linear-gradient(135deg, #ff2d55, #c02030)",
              color: "#fff",
              border: "none",
              borderRadius: 8,
              padding: "10px 20px",
              cursor: scanning || !target.trim() ? "not-allowed" : "pointer",
              fontFamily: "inherit",
              fontWeight: 700,
              fontSize: 13,
              letterSpacing: 1,
            }}>
              {scanning ? "SCANNING..." : "SCAN"}
            </button>
            <button onClick={runDemoScan} disabled={scanning} style={{
              background: "transparent",
              color: "#636366",
              border: "1px solid #2c2c2e",
              borderRadius: 8,
              padding: "10px 16px",
              cursor: scanning ? "not-allowed" : "pointer",
              fontFamily: "inherit",
              fontSize: 12,
              letterSpacing: 1,
            }}>
              DEMO
            </button>
          </div>
          {demoMode && (
            <div style={{ marginTop: 10, color: "#ffd60a", fontSize: 11, padding: "6px 10px", background: "rgba(255,214,10,0.06)", borderRadius: 4 }}>
              ⚡ Demo mode — showing sample scan results. For real scans, run the Python backend locally.
            </div>
          )}
        </div>

        {/* Terminal log */}
        {logs.length > 0 && (
          <div ref={logRef} style={{
            background: "#050507",
            border: "1px solid #1c1c1e",
            borderRadius: 10,
            padding: "14px 16px",
            marginBottom: 24,
            maxHeight: 180,
            overflowY: "auto",
          }}>
            {logs.map((log, i) => (
              <TerminalLine key={log.id} text={log.text} type={log.type} delay={0} />
            ))}
            {scanning && (
              <div style={{ color: "#00d4ff", fontFamily: "monospace", fontSize: 13, marginTop: 4 }}>
                <span style={{ animation: "blink 1s infinite" }}>▋</span>
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{
            background: "rgba(255,45,85,0.08)",
            border: "1px solid rgba(255,45,85,0.3)",
            borderRadius: 8,
            padding: 14,
            color: "#ff2d55",
            fontSize: 13,
            marginBottom: 24,
          }}>
            ☢ {error}
          </div>
        )}

        {/* Results */}
        <ScanResults results={results} />

        {/* Setup instructions */}
        <div style={{
          marginTop: 40,
          background: "#0a0a0c",
          border: "1px solid #1c1c1e",
          borderRadius: 10,
          padding: 20,
        }}>
          <div style={{ color: "#636366", fontSize: 11, letterSpacing: 2, marginBottom: 14 }}>SETUP INSTRUCTIONS</div>
          <div style={{ color: "#8e8e93", fontSize: 12, lineHeight: 2 }}>
            <div><span style={{ color: "#ffd60a" }}>1.</span> Install nmap: <code style={{ color: "#00d4ff" }}>sudo apt-get install nmap</code></div>
            <div><span style={{ color: "#ffd60a" }}>2.</span> Run direct scan: <code style={{ color: "#00d4ff" }}>python3 backend.py &lt;target-ip&gt;</code></div>
            <div><span style={{ color: "#ffd60a" }}>3.</span> Or start Flask API: <code style={{ color: "#00d4ff" }}>python3 api_server.py</code> then use this UI</div>
            <div><span style={{ color: "#ffd60a" }}>4.</span> CVE data sourced from <code style={{ color: "#00d4ff" }}>NVD (nvd.nist.gov)</code> — no API key required</div>
          </div>
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #050507; }
        ::-webkit-scrollbar-thumb { background: #2c2c2e; border-radius: 3px; }
        @keyframes blink { 0%,50% { opacity: 1 } 51%,100% { opacity: 0 } }
        input::placeholder { color: #3a3a3c; }
      `}</style>
    </div>
  );
}
