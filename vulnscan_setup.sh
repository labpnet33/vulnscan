#!/usr/bin/env bash
# ============================================================
#  VulnScan Pro — Full Dependency Installer & Health Checker
#  Supports: Ubuntu 20.04 / 22.04 / 24.04 (Debian-based)
#  Run as root or with sudo: sudo bash vulnscan_setup.sh
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
fail() { echo -e "  ${RED}✗${RESET}  $*"; FAILURES=$((FAILURES+1)); }
info() { echo -e "  ${CYAN}→${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${RESET}"; }

FAILURES=0
LOG_FILE="/tmp/vulnscan_setup_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ── Root check ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: This script must be run as root (sudo bash $0)${RESET}"
  exit 1
fi

echo -e "\n${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   VulnScan Pro — Setup & Health Check   ║"
echo "  ║         Dependency Installer v3.7        ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
info "Log file: $LOG_FILE"


# ════════════════════════════════════════════════════════════════
hdr "STEP 1 — System Update"
# ════════════════════════════════════════════════════════════════

info "Updating apt package lists..."
if apt-get update -qq; then
  ok "apt-get update"
else
  fail "apt-get update failed — check internet connection"
fi

info "Installing base utilities..."
apt-get install -y -qq \
  curl wget git unzip lsb-release gnupg ca-certificates \
  software-properties-common build-essential libssl-dev \
  net-tools dnsutils iproute2 procps \
  2>/dev/null && ok "Base utilities" || fail "Some base utilities failed to install"


# ════════════════════════════════════════════════════════════════
hdr "STEP 2 — Python 3 & pip"
# ════════════════════════════════════════════════════════════════

apt-get install -y -qq python3 python3-pip python3-venv 2>/dev/null \
  && ok "python3 $(python3 --version 2>&1 | awk '{print $2}')" \
  || fail "Python 3 install failed"

# Upgrade pip
python3 -m pip install --upgrade pip --break-system-packages -q 2>/dev/null \
  && ok "pip upgraded to $(pip3 --version | awk '{print $2}')" \
  || warn "pip upgrade failed (non-critical)"

# ── Python packages ───────────────────────────────────────────
hdr "STEP 3 — Python Packages"

PY_PKGS=(
  "flask"
  "flask-cors"
  "reportlab"
  "PySocks"
  "paramiko"
  "requests"
)

for pkg in "${PY_PKGS[@]}"; do
  if python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null; then
    installed_ver=$(python3 -m pip show "$pkg" 2>/dev/null | grep ^Version | awk '{print $2}')
    ok "$pkg $installed_ver"
  else
    fail "$pkg — install failed"
  fi
done


# ════════════════════════════════════════════════════════════════
hdr "STEP 4 — Core Security Tools (apt)"
# ════════════════════════════════════════════════════════════════

APT_TOOLS=(
  "nmap"
  "nikto"
  "dnsrecon"
  "lynis"
  "dnsutils"        # provides dig
  "proxychains4"
  "tor"
  "john"            # John the Ripper
  "theharvester"
  "dirb"
)

for tool in "${APT_TOOLS[@]}"; do
  info "Installing $tool..."
  if apt-get install -y -qq "$tool" 2>/dev/null; then
    ok "$tool installed"
  else
    warn "$tool — apt install failed (may not be in repos, see manual steps below)"
  fi
done


# ════════════════════════════════════════════════════════════════
hdr "STEP 5 — WPScan (Ruby gem)"
# ════════════════════════════════════════════════════════════════

if ! command -v ruby &>/dev/null; then
  info "Installing Ruby..."
  apt-get install -y -qq ruby ruby-dev 2>/dev/null && ok "ruby" || fail "ruby install failed"
fi

if command -v gem &>/dev/null; then
  info "Installing wpscan gem..."
  if gem install wpscan --no-document -q 2>/dev/null; then
    ok "wpscan $(wpscan --version 2>/dev/null | head -1)"
  else
    warn "wpscan gem install failed — try manually: gem install wpscan"
  fi
else
  fail "gem not found — wpscan cannot be installed"
fi


# ════════════════════════════════════════════════════════════════
hdr "STEP 6 — Tor Configuration"
# ════════════════════════════════════════════════════════════════

# Enable and start Tor
if systemctl enable tor 2>/dev/null && systemctl start tor 2>/dev/null; then
  sleep 3
  if systemctl is-active --quiet tor; then
    ok "Tor service running"
  else
    fail "Tor service failed to start — check: journalctl -u tor"
  fi
else
  warn "systemctl not available — starting tor manually"
  tor --RunAsDaemon 1 2>/dev/null && ok "Tor started as daemon" || fail "Tor failed to start"
fi

# Verify SOCKS5 port 9050 is listening
if ss -tlnp 2>/dev/null | grep -q ':9050'; then
  ok "Tor SOCKS5 listening on port 9050"
else
  warn "Port 9050 not detected — Tor may still be bootstrapping, wait 30s and retry"
fi


# ════════════════════════════════════════════════════════════════
hdr "STEP 7 — ProxyChains Configuration"
# ════════════════════════════════════════════════════════════════

PXCONF=""
for f in /etc/proxychains4.conf /etc/proxychains.conf; do
  [[ -f "$f" ]] && PXCONF="$f" && break
done

if [[ -n "$PXCONF" ]]; then
  info "Configuring proxychains: $PXCONF"
  # Backup original
  cp "$PXCONF" "${PXCONF}.bak.$(date +%Y%m%d)" 2>/dev/null || true
  # Ensure socks5 tor entry exists and dynamic_chain is set
  sed -i 's/^#dynamic_chain/dynamic_chain/' "$PXCONF"
  sed -i 's/^strict_chain/#strict_chain/'   "$PXCONF"
  # Remove existing socks5 9050 lines and re-add cleanly
  sed -i '/socks5.*127\.0\.0\.1.*9050/d' "$PXCONF"
  echo "socks5  127.0.0.1 9050" >> "$PXCONF"
  ok "proxychains configured → dynamic_chain + socks5 127.0.0.1:9050"
else
  warn "proxychains config file not found — may need manual setup"
fi


# ════════════════════════════════════════════════════════════════
hdr "STEP 8 — VulnScan Python Permissions & DB"
# ════════════════════════════════════════════════════════════════

# Detect vulnscan directory
VSDIR=""
for d in ~/vulnscan /opt/vulnscan /var/www/vulnscan; do
  [[ -f "$d/api_server.py" ]] && VSDIR="$d" && break
done

if [[ -n "$VSDIR" ]]; then
  ok "VulnScan directory: $VSDIR"
  chmod 755 "$VSDIR"
  chmod 644 "$VSDIR"/*.py 2>/dev/null || true
  # Ensure DB file is writable
  DB="$VSDIR/vulnscan.db"
  touch "$DB" 2>/dev/null && chmod 664 "$DB" && ok "Database file writable: $DB" \
    || warn "Could not set permissions on $DB"
  # Syntax-check the main files
  for pyfile in api_server.py backend.py auth.py database.py; do
    if python3 -m py_compile "$VSDIR/$pyfile" 2>/dev/null; then
      ok "$pyfile — syntax OK"
    else
      fail "$pyfile — syntax error! Run: python3 -m py_compile $VSDIR/$pyfile"
    fi
  done
else
  warn "VulnScan directory not found. Place your files in ~/vulnscan/ and re-run."
  info "Expected layout: api_server.py, backend.py, auth.py, database.py, mail_config.py"
fi


# ════════════════════════════════════════════════════════════════
hdr "STEP 9 — Health Check"
# ════════════════════════════════════════════════════════════════

echo ""
printf "  %-28s %s\n" "COMPONENT" "STATUS"
printf "  %-28s %s\n" "─────────────────────────" "──────────────"

check_cmd() {
  local label="$1"; local cmd="$2"
  if command -v "$cmd" &>/dev/null; then
    local ver
    ver=$(${cmd} --version 2>&1 | head -1 | tr -d '\n' | cut -c1-40) 2>/dev/null || ver="installed"
    printf "  ${GREEN}✓${RESET}  %-26s %s\n" "$label" "$ver"
  else
    printf "  ${RED}✗${RESET}  %-26s %s\n" "$label" "NOT FOUND"
    FAILURES=$((FAILURES+1))
  fi
}

check_py_pkg() {
  local pkg="$1"
  if python3 -c "import $pkg" 2>/dev/null; then
    local ver
    ver=$(python3 -m pip show "$pkg" 2>/dev/null | grep ^Version | awk '{print $2}')
    printf "  ${GREEN}✓${RESET}  %-26s %s\n" "py: $pkg" "$ver"
  else
    printf "  ${RED}✗${RESET}  %-26s %s\n" "py: $pkg" "NOT INSTALLED"
    FAILURES=$((FAILURES+1))
  fi
}

check_service() {
  local label="$1"; local svc="$2"; local port="$3"
  if ss -tlnp 2>/dev/null | grep -q ":${port}"; then
    printf "  ${GREEN}✓${RESET}  %-26s %s\n" "$label" "listening on :$port"
  else
    printf "  ${YELLOW}!${RESET}  %-26s %s\n" "$label" "not detected on :$port"
  fi
}

# System tools
check_cmd "python3"          python3
check_cmd "pip3"             pip3
check_cmd "nmap"             nmap
check_cmd "nikto"            nikto
check_cmd "dnsrecon"         dnsrecon
check_cmd "theHarvester"     theHarvester
check_cmd "lynis"            lynis
check_cmd "wpscan"           wpscan
check_cmd "john"             john
check_cmd "dig"              dig
check_cmd "proxychains4"     proxychains4
check_cmd "tor"              tor
check_cmd "git"              git

# Python packages
echo ""
check_py_pkg flask
check_py_pkg flask_cors
check_py_pkg reportlab
check_py_pkg socks
check_py_pkg paramiko

# Services
echo ""
check_service "Tor SOCKS5"   tor     9050

# Tor connectivity test
echo ""
info "Testing Tor connectivity..."
if python3 - <<'PYEOF' 2>/dev/null; then
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 9050), timeout=5)
    s.close()
    print("  Tor SOCKS5 reachable on 127.0.0.1:9050")
    sys.exit(0)
except Exception as e:
    print(f"  Tor not reachable: {e}")
    sys.exit(1)
PYEOF
  ok "Tor reachable on 127.0.0.1:9050"
else
  warn "Tor SOCKS5 not reachable — is Tor running? Try: systemctl start tor"
fi

# Proxychains curl-through-tor test (non-fatal)
info "Testing proxychains → Tor (may take 10-20s)..."
if timeout 30 proxychains4 -q curl -s --max-time 20 https://check.torproject.org/api/ip 2>/dev/null \
    | grep -q '"IsTor":true'; then
  ok "Proxychains → Tor working! IP is anonymized."
else
  warn "Proxychains/Tor test inconclusive (Tor may still be bootstrapping)"
fi


# ════════════════════════════════════════════════════════════════
hdr "STEP 10 — systemd Service (optional)"
# ════════════════════════════════════════════════════════════════

if [[ -n "$VSDIR" ]] && command -v systemctl &>/dev/null; then
  SERVICE_FILE="/etc/systemd/system/vulnscan.service"
  if [[ ! -f "$SERVICE_FILE" ]]; then
    info "Creating systemd service file..."
    PYTHON_BIN=$(command -v python3)
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=VulnScan Pro — Security Assessment Platform
After=network.target tor.service
Requires=tor.service

[Service]
Type=simple
User=root
WorkingDirectory=${VSDIR}
ExecStart=${PYTHON_BIN} ${VSDIR}/api_server.py
Restart=on-failure
RestartSec=5
Environment=VULNSCAN_SECRET=change-this-to-a-random-secret-in-production

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    ok "systemd service created: $SERVICE_FILE"
    info "Start with: systemctl start vulnscan"
    info "Enable on boot: systemctl enable vulnscan"
  else
    ok "systemd service already exists: $SERVICE_FILE"
  fi
fi


# ════════════════════════════════════════════════════════════════
hdr "SUMMARY"
# ════════════════════════════════════════════════════════════════

echo ""
if [[ $FAILURES -eq 0 ]]; then
  echo -e "  ${BOLD}${GREEN}All checks passed!${RESET} VulnScan Pro is ready."
  echo ""
  echo -e "  ${CYAN}Start the server:${RESET}"
  if command -v systemctl &>/dev/null && [[ -f /etc/systemd/system/vulnscan.service ]]; then
    echo -e "    systemctl start vulnscan && systemctl enable vulnscan"
  fi
  if [[ -n "$VSDIR" ]]; then
    echo -e "    cd ${VSDIR} && python3 api_server.py"
  fi
  echo -e "    Open: ${CYAN}http://localhost:5000${RESET}"
else
  echo -e "  ${YELLOW}${FAILURES} issue(s) found.${RESET} Review the output above."
  echo ""
  echo -e "  ${BOLD}Manual install tips:${RESET}"
  echo -e "  • wpscan:       gem install wpscan"
  echo -e "  • theHarvester: pip3 install theHarvester --break-system-packages"
  echo -e "  • dnsrecon:     pip3 install dnsrecon --break-system-packages"
  echo -e "  • paramiko:     pip3 install paramiko --break-system-packages"
  echo -e "  • PySocks:      pip3 install PySocks --break-system-packages"
  echo ""
  echo -e "  • Start Tor:    systemctl start tor"
  echo -e "  • Check Tor:    systemctl status tor"
fi

echo ""
echo -e "  ${CYAN}Full log saved:${RESET} $LOG_FILE"
echo ""
