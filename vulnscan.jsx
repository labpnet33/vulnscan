import { Fragment, useEffect, useMemo, useRef, useState } from "react";

const TOKENS = {
  primary: "#00FF41",
  background: "#000000",
  surface: "#0A0A0A",
  text: "#E0E0E0",
  muted: "#333333",
  accent: "#FF003C",
  grid: "#111111",
};

const NODES = [
  { id: "NODE-001", ip: "10.12.4.17", x: 14, y: 22, status: "up", cpu: "41%", mem: "58%", os: "Ubuntu 24.04" },
  { id: "NODE-002", ip: "10.12.4.29", x: 38, y: 58, status: "up", cpu: "28%", mem: "47%", os: "Debian 12" },
  { id: "NODE-003", ip: "10.12.4.42", x: 66, y: 28, status: "up", cpu: "62%", mem: "74%", os: "Kali 2026.1" },
  { id: "NODE-004", ip: "10.12.4.63", x: 78, y: 66, status: "down", cpu: "--", mem: "--", os: "Unknown" },
];

const THREATS = [
  { id: "CVE-2025-20931", severity: "CRITICAL", cwe: "Command Injection in telemetry parser", endpoint: "/api/telemetry/upload" },
  { id: "CVE-2024-88411", severity: "HIGH", cwe: "Auth bypass via insecure JWT validation", endpoint: "/v1/session/refresh" },
  { id: "CVE-2023-44877", severity: "MEDIUM", cwe: "Stored XSS in admin console alerts", endpoint: "/admin/notifications" },
  { id: "CVE-2024-19003", severity: "LOW", cwe: "Verbose error leakage in diagnostics", endpoint: "/diag/ping" },
];

function NodeDetails({ node }) {
  if (!node) {
    return <p className="empty-detail">SELECT_NODE_FOR_HARDWARE_PROFILE</p>;
  }

  return (
    <div className="node-detail-card">
      <h3>{node.id}</h3>
      <p>{node.ip}</p>
      <ul>
        <li>OS: {node.os}</li>
        <li>CPU: {node.cpu}</li>
        <li>MEM: {node.mem}</li>
        <li>STATUS: {node.status.toUpperCase()}</li>
      </ul>
    </div>
  );
}

export default function VulnScanner() {
  const [screen, setScreen] = useState("nexus");
  const [selectedNodeId, setSelectedNodeId] = useState(NODES[0].id);
  const [target, setTarget] = useState("");
  const [includeNmap, setIncludeNmap] = useState(true);
  const [includeDirb, setIncludeDirb] = useState(true);
  const [includeNikto, setIncludeNikto] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [aborted, setAborted] = useState(false);
  const [terminalLines, setTerminalLines] = useState([]);
  const [flashAbort, setFlashAbort] = useState(false);
  const [dumped, setDumped] = useState(false);
  const [time, setTime] = useState(() => new Date());
  const logRef = useRef(null);

  const selectedNode = useMemo(() => NODES.find((node) => node.id === selectedNodeId), [selectedNodeId]);
  const severityStats = useMemo(
    () => ({
      CRITICAL: THREATS.filter((item) => item.severity === "CRITICAL").length,
      HIGH: THREATS.filter((item) => item.severity === "HIGH").length,
      MEDIUM: THREATS.filter((item) => item.severity === "MEDIUM").length,
      LOW: THREATS.filter((item) => item.severity === "LOW").length,
    }),
    [],
  );

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (screen !== "execution" || !executing || aborted) return undefined;
    const scripts = [
      "INITIALIZING_HANDSHAKE...",
      "RESOLVING_TARGET_SCOPE...",
      "NMAP_PAYLOAD_ATTACHED",
      "DIRB_DICTIONARY_LOADED",
      "NIKTO_SIGNATURES_LOADING",
      "VULN: Potential command injection at /api/telemetry/upload",
      "SUCCESS: Enumerated 48 services",
      "VULN: JWT verifier misconfiguration detected",
      "SCAN_COMPLETE -> SWITCH_TO_MATRIX",
    ];

    let index = 0;
    const stream = setInterval(() => {
      if (index >= scripts.length) {
        clearInterval(stream);
        setExecuting(false);
        return;
      }
      const line = scripts[index];
      setTerminalLines((prev) => [...prev, `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] ${line}`]);
      index += 1;
    }, 520);

    return () => clearInterval(stream);
  }, [screen, executing, aborted]);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const openTargetInjection = () => setScreen("target");

  const executeScan = () => {
    if (!target.trim()) return;
    setTerminalLines([
      `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] TARGET_ACCEPTED ${target}`,
      `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] PAYLOADS: ${includeNmap ? "NMAP " : ""}${includeDirb ? "DIRB " : ""}${includeNikto ? "NIKTO" : ""}`.trim(),
    ]);
    setAborted(false);
    setExecuting(true);
    setScreen("execution");
  };

  const abortScan = () => {
    setAborted(true);
    setExecuting(false);
    setFlashAbort(true);
    setTerminalLines((prev) => [...prev, `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] SIGINT RECEIVED. STREAM HALTED.`]);
    setTimeout(() => setFlashAbort(false), 50);
  };

  const dumpJson = () => {
    setDumped(true);
    const blob = new Blob([JSON.stringify(THREATS, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "threat-matrix.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="app-root">
      <div className="spatial-grid" aria-hidden="true" />
      {flashAbort ? <div className="abort-flash" /> : null}

      <header className="top-hud">
        <span>{time.toISOString().replace("T", " ").slice(0, 19)} UTC</span>
        <span>PROXY: ACTIVE</span>
        <button type="button" onClick={openTargetInjection}>[NEW_TARGET]</button>
      </header>

      {screen === "nexus" ? (
        <section className="nexus-screen">
          <div className="map-canvas">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="connection-layer" aria-hidden="true">
              <line x1="14" y1="22" x2="38" y2="58" />
              <line x1="38" y1="58" x2="66" y2="28" />
              <line x1="66" y1="28" x2="78" y2="66" />
            </svg>
            {NODES.map((node) => (
              <button
                key={node.id}
                type="button"
                className={`node-panel ${selectedNodeId === node.id ? "active" : ""} ${node.status === "down" ? "error" : ""}`}
                style={{ left: `${node.x}%`, top: `${node.y}%` }}
                onClick={() => setSelectedNodeId(node.id)}
              >
                <p>{node.ip}</p>
                <span className={`status-dot ${node.status}`} />
              </button>
            ))}
          </div>
          <aside className="node-info-float">
            <NodeDetails node={selectedNode} />
          </aside>
        </section>
      ) : null}

      {screen === "target" ? (
        <section className="target-injection" role="dialog" aria-label="Target Injection">
          <h2>TARGET_INJECTION</h2>
          <label htmlFor="target-ip">ENTER_TARGET_IP...</label>
          <input
            id="target-ip"
            value={target}
            placeholder="10.12.4.0/24"
            onChange={(e) => setTarget(e.target.value)}
            className={!target.trim() ? "" : "focus"}
          />

          <div className="toggle-list">
            <button type="button" className="toggle" onClick={() => setIncludeNmap((v) => !v)}>
              <span className={`check ${includeNmap ? "on" : ""}`} /> NMAP
            </button>
            <button type="button" className="toggle" onClick={() => setIncludeDirb((v) => !v)}>
              <span className={`check ${includeDirb ? "on" : ""}`} /> DIRB
            </button>
            <button type="button" className="toggle" onClick={() => setIncludeNikto((v) => !v)}>
              <span className={`check ${includeNikto ? "on" : ""}`} /> NIKTO
            </button>
          </div>

          <div className="action-row">
            <button type="button" onClick={() => setScreen("nexus")}>[CLOSE]</button>
            <button type="button" onClick={executeScan}>[EXECUTE]</button>
          </div>
        </section>
      ) : null}

      {screen === "execution" ? (
        <section className="execution-screen">
          <article className="live-feed" ref={logRef}>
            {terminalLines.length === 0 ? <p>INITIALIZING_HANDSHAKE...</p> : null}
            {terminalLines.map((line, idx) => (
              <p key={`${idx}-${line}`} className={line.includes("VULN") ? "critical" : line.includes("SUCCESS") ? "success" : ""}>{line}</p>
            ))}
          </article>
          <aside className="telemetry">
            <h3>CPU / MEM TELEMETRY</h3>
            <p>CPU [||||||    ] 60%</p>
            <p>MEM [|||||||   ] 73%</p>
            <p>NET [||||      ] 44%</p>
            <button type="button" onClick={() => setScreen("matrix")}>[VIEW_THREATS]</button>
          </aside>
          <button type="button" className="abort" onClick={abortScan}>[SIGINT / ABORT]</button>
        </section>
      ) : null}

      {screen === "matrix" ? (
        <section className="threat-matrix">
          <div className="severity-header">
            {Object.entries(severityStats).map(([label, count]) => (
              <div key={label}>
                <h3>{label}</h3>
                <strong>{count}</strong>
              </div>
            ))}
          </div>

          <div className="matrix-grid" role="table" aria-label="Threat Matrix">
            <div className="head">ID</div>
            <div className="head">SEVERITY</div>
            <div className="head">CWE_DESC</div>
            <div className="head">ENDPOINT</div>
            {THREATS.map((item) => (
              <Fragment key={item.id}>
                <div>{item.id}</div>
                <div>
                  <span className={`severity-tag ${item.severity.toLowerCase()}`}>{item.severity}</span>
                </div>
                <div>{item.cwe}</div>
                <div>{item.endpoint}</div>
              </Fragment>
            ))}
          </div>

          <button type="button" className="dump" onClick={dumpJson}>{dumped ? "[DUMP_COMPLETE]" : "[DUMP_JSON]"}</button>
        </section>
      ) : null}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

        * { box-sizing: border-box; }
        body { margin: 0; background: ${TOKENS.background}; }
        button, input { font-family: 'JetBrains Mono', monospace; }
        .app-root {
          min-height: 100vh;
          background: ${TOKENS.background};
          color: ${TOKENS.text};
          padding: 24px;
          font-family: 'JetBrains Mono', monospace;
          position: relative;
          overflow: hidden;
          cursor: crosshair;
        }
        .spatial-grid {
          position: absolute;
          inset: 0;
          background-image:
            linear-gradient(to right, ${TOKENS.grid} 1px, transparent 1px),
            linear-gradient(to bottom, ${TOKENS.grid} 1px, transparent 1px);
          background-size: 40px 40px;
          z-index: 0;
        }
        .abort-flash {
          position: fixed;
          inset: 0;
          background: white;
          z-index: 20;
          pointer-events: none;
        }
        .top-hud {
          position: relative;
          z-index: 2;
          width: 400px;
          margin: 0 auto;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.surface};
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
          display: grid;
          grid-template-columns: 1fr auto auto;
          gap: 16px;
          align-items: center;
          padding: 10px 14px;
          font-size: 12px;
          text-transform: uppercase;
        }
        .top-hud button {
          background: ${TOKENS.background};
          color: ${TOKENS.primary};
          border: 1px solid ${TOKENS.primary};
          height: 40px;
          width: 120px;
          text-transform: uppercase;
          font-weight: 700;
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
        }
        .top-hud button:hover {
          background: ${TOKENS.primary};
          color: ${TOKENS.background};
          box-shadow: 2px 2px 0 0 ${TOKENS.primary};
        }

        .nexus-screen { position: relative; z-index: 1; margin-top: 24px; min-height: calc(100vh - 140px); }
        .map-canvas {
          position: absolute;
          inset: 0 340px 0 0;
          border: 1px solid ${TOKENS.muted};
          background: rgba(10, 10, 10, 0.7);
          overflow: hidden;
        }
        .connection-layer {
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
        }
        .connection-layer line { stroke: ${TOKENS.muted}; stroke-width: 0.4; }
        .node-panel {
          position: absolute;
          width: 100px;
          height: 100px;
          margin-left: -50px;
          margin-top: -50px;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.surface};
          color: ${TOKENS.text};
          text-align: left;
          padding: 10px;
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
        }
        .node-panel.active { background: #101010; }
        .node-panel.error { border-color: ${TOKENS.accent}; box-shadow: 4px 4px 0 0 ${TOKENS.accent}; animation: glitch 0.3s infinite; }
        .node-panel p { font-size: 12px; margin: 0 0 8px; }
        .status-dot { width: 12px; height: 12px; display: inline-block; border: 1px solid ${TOKENS.muted}; }
        .status-dot.up { background: ${TOKENS.primary}; }
        .status-dot.down { background: ${TOKENS.accent}; }
        .node-info-float {
          position: absolute;
          right: 0;
          top: 0;
          width: 320px;
          border: 1px solid ${TOKENS.muted};
          background: ${TOKENS.surface};
          padding: 16px;
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
        }
        .node-detail-card h3 { margin: 0 0 8px; font-size: 18px; text-shadow: 0 0 8px ${TOKENS.primary}; }
        .node-detail-card p { margin: 0 0 10px; font-size: 12px; color: ${TOKENS.primary}; }
        .node-detail-card ul { margin: 0; padding-left: 16px; }
        .node-detail-card li { margin-bottom: 8px; font-size: 12px; text-transform: uppercase; }
        .empty-detail { font-size: 12px; color: ${TOKENS.muted}; }

        .target-injection {
          position: absolute;
          top: 24px;
          right: 24px;
          width: 400px;
          height: calc(100vh - 48px);
          border: 1px solid ${TOKENS.muted};
          background: ${TOKENS.surface};
          z-index: 5;
          padding: 18px;
          display: flex;
          flex-direction: column;
          gap: 14px;
        }
        .target-injection h2 { margin: 0; font-size: 24px; letter-spacing: -0.5px; text-transform: uppercase; }
        .target-injection label { font-size: 12px; text-transform: uppercase; }
        .target-injection input {
          width: 100%;
          height: 48px;
          border: 1px solid ${TOKENS.muted};
          background: ${TOKENS.background};
          color: ${TOKENS.primary};
          padding: 12px;
          font-size: 18px;
        }
        .target-injection input:focus,
        .target-injection input.focus {
          outline: none;
          border-color: ${TOKENS.primary};
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
        }
        .toggle-list { display: grid; gap: 12px; margin-top: 8px; }
        .toggle {
          background: transparent;
          color: ${TOKENS.text};
          border: 1px solid ${TOKENS.muted};
          text-align: left;
          padding: 8px;
          display: flex;
          align-items: center;
          gap: 8px;
          text-transform: uppercase;
        }
        .check { width: 24px; height: 24px; border: 1px solid ${TOKENS.primary}; display: inline-block; }
        .check.on { background: ${TOKENS.primary}; }
        .action-row { display: flex; justify-content: space-between; margin-top: auto; }
        .action-row button {
          width: 120px;
          height: 40px;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.background};
          color: ${TOKENS.primary};
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
          text-transform: uppercase;
          font-weight: 700;
        }

        .execution-screen { position: relative; z-index: 1; margin-top: 24px; min-height: calc(100vh - 140px); }
        .live-feed {
          width: 60vw;
          height: 70vh;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.surface};
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
          padding: 12px;
          overflow: auto;
          font-size: 14px;
          line-height: 1.2;
        }
        .live-feed p { margin: 0 0 8px; color: ${TOKENS.text}; }
        .live-feed .critical { color: ${TOKENS.accent}; text-shadow: 0 0 8px ${TOKENS.accent}; }
        .live-feed .success { color: ${TOKENS.primary}; text-shadow: 0 0 8px ${TOKENS.primary}; }
        .telemetry {
          position: absolute;
          right: 0;
          top: 0;
          width: 300px;
          border: 1px solid ${TOKENS.muted};
          background: ${TOKENS.surface};
          padding: 16px;
        }
        .telemetry h3 { margin: 0 0 12px; font-size: 14px; }
        .telemetry p { margin: 0 0 8px; font-size: 12px; }
        .telemetry button {
          margin-top: 8px;
          width: 100%;
          height: 40px;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.background};
          color: ${TOKENS.primary};
          text-transform: uppercase;
        }
        .abort {
          position: absolute;
          right: 0;
          bottom: 0;
          width: 200px;
          height: 60px;
          border: 1px solid ${TOKENS.accent};
          color: ${TOKENS.accent};
          background: ${TOKENS.background};
          box-shadow: 4px 4px 0 0 ${TOKENS.accent};
          font-weight: 700;
          text-transform: uppercase;
        }

        .threat-matrix {
          position: relative;
          z-index: 1;
          margin: 40px;
          border: 1px solid ${TOKENS.muted};
          background: ${TOKENS.surface};
          padding: 16px;
          min-height: calc(100vh - 180px);
        }
        .severity-header {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 12px;
          margin-bottom: 12px;
        }
        .severity-header div {
          border: 1px solid ${TOKENS.muted};
          padding: 10px;
        }
        .severity-header h3 { margin: 0; font-size: 12px; color: ${TOKENS.primary}; }
        .severity-header strong { font-size: 24px; }
        .matrix-grid {
          display: grid;
          grid-template-columns: 1.2fr 0.8fr 2fr 1.5fr;
          border: 1px solid ${TOKENS.muted};
        }
        .matrix-grid > div {
          min-height: 40px;
          border-bottom: 1px dashed ${TOKENS.muted};
          padding: 10px;
          display: flex;
          align-items: center;
          font-size: 12px;
        }
        .matrix-grid > div:hover { background: ${TOKENS.grid}; }
        .matrix-grid .head {
          font-weight: 700;
          text-transform: uppercase;
          color: ${TOKENS.primary};
          border-bottom: 1px solid ${TOKENS.primary};
        }
        .severity-tag {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 80px;
          height: 24px;
          font-weight: 700;
          color: ${TOKENS.background};
        }
        .severity-tag.critical { background: ${TOKENS.accent}; }
        .severity-tag.high { background: #ff6f00; }
        .severity-tag.medium { background: #ffca28; }
        .severity-tag.low { background: ${TOKENS.primary}; }
        .dump {
          position: absolute;
          right: 16px;
          bottom: 16px;
          width: 200px;
          height: 40px;
          border: 1px solid ${TOKENS.primary};
          background: ${TOKENS.background};
          color: ${TOKENS.primary};
          text-transform: uppercase;
          box-shadow: 4px 4px 0 0 ${TOKENS.primary};
          font-weight: 700;
        }

        @keyframes glitch {
          0% { transform: translate(0, 0); }
          50% { transform: translate(2px, -2px); }
          100% { transform: translate(-2px, 1px); }
        }

        @media (max-width: 1140px) {
          .top-hud { width: 100%; grid-template-columns: 1fr auto; }
          .top-hud span:nth-child(2) { display: none; }
          .map-canvas { inset: 0; }
          .node-info-float,
          .telemetry,
          .abort,
          .target-injection,
          .live-feed {
            position: static;
            width: 100%;
            margin-top: 12px;
            height: auto;
          }
          .execution-screen,
          .nexus-screen { min-height: auto; }
          .threat-matrix { margin: 20px 0; }
          .severity-header,
          .matrix-grid { grid-template-columns: 1fr; }
          .matrix-grid .head { border-top: 1px solid ${TOKENS.primary}; }
        }
      `}</style>
    </main>
  );
}
