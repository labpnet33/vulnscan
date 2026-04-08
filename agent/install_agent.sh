#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="${1:-}"
TOKEN="${2:-}"
API_BASE="${3:-http://161.118.189.254:5000}"

if [[ -z "$CLIENT_ID" ]]; then
  base_host="$(hostname -s 2>/dev/null || echo linux-client)"
  rand_part="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
  [[ -z "$rand_part" ]] && rand_part="$(date +%s)"
  CLIENT_ID="${base_host}-${rand_part}"
  echo "[*] Generated client id: $CLIENT_ID"
fi

AGENT_DIR="/opt/vulnscan-agent"
SERVICE_FILE="/etc/systemd/system/vulnscan-agent.service"
AGENT_SCRIPT="universal_agent.py"

echo "[*] Checking connection to $API_BASE ..."
curl -fsS "$API_BASE/health" >/dev/null
echo "[+] Server reachable."

sudo mkdir -p "$AGENT_DIR"

# Download the universal agent
curl -fsSL "$API_BASE/agent/$AGENT_SCRIPT" -o "/tmp/$AGENT_SCRIPT"
sudo cp "/tmp/$AGENT_SCRIPT" "$AGENT_DIR/$AGENT_SCRIPT"
sudo chmod +x "$AGENT_DIR/$AGENT_SCRIPT"

# Register and get token if not provided
if [[ -z "$TOKEN" ]]; then
  echo "[*] Registering with server..."
  reg_json="$(python3 - <<PY
import json, platform, socket, subprocess, urllib.request, shutil

def get_tools():
    tools = ["nmap","nikto","lynis","wpscan","dnsrecon","theHarvester",
             "sqlmap","nuclei","whatweb","ffuf","dirb","medusa","john",
             "hashcat","chkrootkit","rkhunter","wapiti","dalfox","hping3",
             "searchsploit","dig","curl"]
    return [t for t in tools if shutil.which(t) or shutil.which(t.lower())]

api_base = ${API_BASE@Q}
client_id = ${CLIENT_ID@Q}
payload = json.dumps({
    "client_id": client_id,
    "hostname": socket.gethostname(),
    "os_info": f"{platform.system()} {platform.release()}",
    "tools": get_tools(),
    "agent_version": "universal-2.0",
}).encode()
req = urllib.request.Request(
    f"{api_base.rstrip('/')}/api/agent/register",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as r:
    print(r.read().decode())
PY
)" || true

  if [[ -z "$reg_json" ]]; then
    echo "[x] Registration failed"
    exit 1
  fi
  TOKEN="$(printf '%s' "$reg_json" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("token","")).strip())')"
  if [[ -z "$TOKEN" ]]; then
    echo "[x] Token missing in response: $reg_json"
    exit 1
  fi
  echo "[+] Registered. Client ID: $CLIENT_ID"
fi

# Write systemd service
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=VulnScan Universal Remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/python3 $AGENT_DIR/$AGENT_SCRIPT \
  --api-base $API_BASE \
  --client-id $CLIENT_ID \
  --token $TOKEN \
  --interval 15

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-agent

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  VulnScan Universal Agent Installed!             ║"
echo "║                                                  ║"
echo "║  Client ID : '"$CLIENT_ID"'"
echo "║  Server    : '"$API_BASE"'"
echo "║                                                  ║"
echo "║  Go to the VulnScan dashboard → Remote Audit    ║"
echo "║  tab to run tools on this system.               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Status : sudo systemctl status vulnscan-agent"
echo "  Logs   : journalctl -u vulnscan-agent -f"
