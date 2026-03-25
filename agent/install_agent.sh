#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <client_id> [token] [api_base]"
  exit 1
fi

CLIENT_ID="$1"
TOKEN="${2:-}"
API_BASE="${3:-http://161.118.189.254:5000}"
AGENT_DIR="/opt/vulnscan-agent"
SERVICE_FILE="/etc/systemd/system/vulnscan-lynis-agent.service"

echo "[*] Checking connection to $API_BASE ..."
curl -fsS "$API_BASE/health" >/dev/null
echo "[+] Connection established."

sudo mkdir -p "$AGENT_DIR"
sudo cp "$(dirname "$0")/lynis_pull_agent.py" "$AGENT_DIR/lynis_pull_agent.py"
sudo chmod +x "$AGENT_DIR/lynis_pull_agent.py"

EXTRA=""
if [[ -n "$TOKEN" ]]; then
  EXTRA="--token $TOKEN"
fi

sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=VulnScan Lynis Pull Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=/usr/bin/python3 $AGENT_DIR/lynis_pull_agent.py --api-base $API_BASE --client-id $CLIENT_ID $EXTRA

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-lynis-agent
echo "[+] Agent service installed and started."
echo "[+] Check status: sudo systemctl status vulnscan-lynis-agent"
