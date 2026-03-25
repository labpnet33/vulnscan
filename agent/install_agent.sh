#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <api_base> <client_id> [token]"
  exit 1
fi

API_BASE="$1"
CLIENT_ID="$2"
TOKEN="${3:-}"
AGENT_DIR="/opt/vulnscan-agent"
SERVICE_FILE="/etc/systemd/system/vulnscan-lynis-agent.service"

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
