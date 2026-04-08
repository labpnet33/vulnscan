#!/usr/bin/env bash
# ============================================================
#  VulnScan Pro — Watchdog & Auto-Healer
#  Keeps the website running, checks deps, auto-fixes issues
#  Usage: sudo bash vulnscan_watchdog.sh
#  Run in background: sudo nohup bash vulnscan_watchdog.sh &
# ============================================================

set -uo pipefail

# ── Config ────────────────────────────────────────────────────
SERVICE="vulnscan"
APP_DIR="/home/vijay/vulnscan"
APP_FILE="api_server.py"
PYTHON="/usr/bin/python3"
PORT=5000
CHECK_INTERVAL=10        # seconds between health checks
LOG_FILE="/var/log/vulnscan_watchdog.log"
MAX_LOG_SIZE=10485760    # 10MB — rotate after this
RESTART_LIMIT=5          # max restarts before cooldown
COOLDOWN_SECS=60         # cooldown period after too many restarts
HEALTH_URL="http://127.0.0.1:${PORT}/health"

# ── Python packages required ──────────────────────────────────
PY_PACKAGES=(
    "flask"
    "flask_cors"
    "dotenv:python-dotenv"
    "reportlab"
    "socks:PySocks"
    "paramiko"
    "supabase"
    "httpx"
    "gotrue"
    "postgrest"
)

# ── System packages required ──────────────────────────────────
SYS_PACKAGES=(
    "nmap"
    "tor"
    "proxychains4"
    "dnsutils"
    "curl"
)

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── State tracking ────────────────────────────────────────────
restart_count=0
last_restart_time=0
consecutive_failures=0

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[${ts}] [${level}] ${msg}"

    # Print to console with colour
    case "$level" in
        OK)    echo -e "${GREEN}${line}${RESET}" ;;
        WARN)  echo -e "${YELLOW}${line}${RESET}" ;;
        ERROR) echo -e "${RED}${line}${RESET}" ;;
        INFO)  echo -e "${CYAN}${line}${RESET}" ;;
        *)     echo "$line" ;;
    esac

    # Write to log file (plain, no colour codes)
    echo "$line" >> "$LOG_FILE" 2>/dev/null || true

    # Rotate log if too large
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if (( size > MAX_LOG_SIZE )); then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            log INFO "Log rotated — previous saved to ${LOG_FILE}.old"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────
# DEPENDENCY CHECKS
# ─────────────────────────────────────────────────────────────
check_python_packages() {
    local fixed=0
    for entry in "${PY_PACKAGES[@]}"; do
        # Format: "import_name:pip_name" or just "import_name"
        local import_name pip_name
        if [[ "$entry" == *":"* ]]; then
            import_name="${entry%%:*}"
            pip_name="${entry##*:}"
        else
            import_name="$entry"
            pip_name="$entry"
        fi

        if ! $PYTHON -c "import ${import_name}" 2>/dev/null; then
            log WARN "Missing Python package: ${pip_name} — installing..."
            if pip3 install "$pip_name" --break-system-packages -q 2>/dev/null; then
                log OK "Installed: ${pip_name}"
                fixed=1
            else
                log ERROR "Failed to install: ${pip_name}"
            fi
        fi
    done
    return $fixed
}

check_system_packages() {
    for pkg in "${SYS_PACKAGES[@]}"; do
        if ! command -v "$pkg" &>/dev/null && ! dpkg -l "$pkg" &>/dev/null 2>&1; then
            log WARN "Missing system package: ${pkg} — installing..."
            if apt-get install -y -qq "$pkg" 2>/dev/null; then
                log OK "Installed system package: ${pkg}"
            else
                log ERROR "Failed to install system package: ${pkg}"
            fi
        fi
    done
}

check_tor() {
    if ! ss -tlnp 2>/dev/null | grep -q ':9050'; then
        log WARN "Tor not listening on port 9050 — starting..."
        systemctl start tor 2>/dev/null || tor --RunAsDaemon 1 2>/dev/null || true
        sleep 5
        if ss -tlnp 2>/dev/null | grep -q ':9050'; then
            log OK "Tor started successfully"
        else
            log ERROR "Tor failed to start — scans will run without Tor anonymity"
        fi
    fi
}

check_apache() {
    if command -v apache2 &>/dev/null; then
        if ! systemctl is-active --quiet apache2; then
            log WARN "Apache2 not running — starting..."
            systemctl start apache2 2>/dev/null
            sleep 2
            if systemctl is-active --quiet apache2; then
                log OK "Apache2 restarted"
            else
                log ERROR "Apache2 failed to start"
            fi
        fi

        # Ensure proxy modules are enabled
        if ! apache2ctl -M 2>/dev/null | grep -q 'proxy_module'; then
            log WARN "Apache proxy module not enabled — enabling..."
            a2enmod proxy proxy_http 2>/dev/null && systemctl reload apache2 2>/dev/null
            log OK "Apache proxy modules enabled"
        fi
    fi
}

check_port_free() {
    # If port is in use by something OTHER than our app, kill it
    local pid
    pid=$(lsof -t -i ":${PORT}" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
        local proc
        proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        if [[ "$proc" != "python3" && "$proc" != "python" ]]; then
            log WARN "Port ${PORT} occupied by '${proc}' (PID ${pid}) — killing..."
            kill -9 "$pid" 2>/dev/null || true
            sleep 1
            log OK "Freed port ${PORT}"
        fi
    fi
}

check_dot_env() {
    local env_file="${APP_DIR}/.env"
    if [[ ! -f "$env_file" ]]; then
        log WARN ".env file missing — creating minimal placeholder..."
        cat > "$env_file" <<'EOF'
VULNSCAN_SECRET=change-this-secret-key-in-production-2024
SUPABASE_URL=https://qonplkgabhubntfhtthu.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUwMTc5MDMsImV4cCI6MjA5MDU5MzkwM30.oVFsJVBl4pD4Geq-Bj4X4m-HOe-wSctbfSPNaNq32ak
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTAxNzkwMywiZXhwIjoyMDkwNTkzOTAzfQ.xsT9_tzKyIJ20Yju6wOrQc3kAJ27xLXZhKQeqUKVbmA
VULNSCAN_APP_URL=http://161.118.189.254
VULNSCAN_SMTP_HOST=smtp.gmail.com
VULNSCAN_SMTP_PORT=587
VULNSCAN_SMTP_USER=labpnet33@gmail.com
VULNSCAN_SMTP_PASS=hkls wpey nvxi bgwh
EOF
        log OK ".env created"
    fi
}

# ─────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────
is_app_healthy() {
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 --connect-timeout 3 "$HEALTH_URL" 2>/dev/null || echo "000")
    [[ "$http_code" == "200" ]]
}

is_service_running() {
    systemctl is-active --quiet "$SERVICE" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────
# SERVICE MANAGEMENT
# ─────────────────────────────────────────────────────────────
restart_service() {
    local reason="$1"
    local now
    now=$(date +%s)

    # Cooldown check
    if (( restart_count >= RESTART_LIMIT )); then
        local elapsed=$(( now - last_restart_time ))
        if (( elapsed < COOLDOWN_SECS )); then
            local wait=$(( COOLDOWN_SECS - elapsed ))
            log WARN "Restart limit hit — cooling down for ${wait}s..."
            sleep "$wait"
            restart_count=0
        fi
    fi

    log WARN "Restarting ${SERVICE}: ${reason}"

    # Full dependency check before restarting
    check_python_packages
    check_dot_env

    systemctl daemon-reload 2>/dev/null || true
    systemctl restart "$SERVICE" 2>/dev/null

    last_restart_time=$(date +%s)
    (( restart_count++ )) || true

    sleep 5  # Give it time to boot

    if is_app_healthy; then
        log OK "Service restarted and healthy ✓"
        consecutive_failures=0
        restart_count=0
    else
        log ERROR "Service restarted but health check still failing"
        # Show last 10 lines of service log for diagnosis
        local recent_logs
        recent_logs=$(journalctl -u "$SERVICE" -n 10 --no-pager 2>/dev/null | tail -10)
        log ERROR "Recent logs:\n${recent_logs}"
        (( consecutive_failures++ )) || true
    fi
}

# ─────────────────────────────────────────────────────────────
# FULL SYSTEM CHECK (runs at startup + periodically)
# ─────────────────────────────────────────────────────────────
full_system_check() {
    log INFO "═══ Running full system check ═══"
    check_system_packages
    check_python_packages
    check_dot_env
    check_tor
    check_apache
    check_port_free
    log INFO "═══ Full system check complete ═══"
}

# ─────────────────────────────────────────────────────────────
# CONTINUOUS LOG MONITOR
# ─────────────────────────────────────────────────────────────
monitor_service_logs() {
    # Run journalctl follow in background, react to error patterns
    journalctl -u "$SERVICE" -f --no-pager 2>/dev/null | while IFS= read -r line; do
        # Echo every service log line to our watchdog log
        echo "[SERVICE] $line" >> "$LOG_FILE" 2>/dev/null || true

        # Detect crash patterns
        if echo "$line" | grep -qiE \
            'ModuleNotFoundError|ImportError|address already in use|Connection refused|FAILURE|Traceback|SystemExit|killed'; then
            log ERROR "Detected error pattern in service logs: ${line}"
        fi

        # Detect specific fixable issues
        if echo "$line" | grep -qi 'ModuleNotFoundError: No module named'; then
            local module
            module=$(echo "$line" | grep -oP "No module named '\K[^']+")
            log WARN "Auto-fixing missing module: ${module}"
            pip3 install "$module" --break-system-packages -q 2>/dev/null \
                && log OK "Installed missing module: ${module}" \
                || log ERROR "Could not auto-install: ${module}"
        fi
    done &
}

# ─────────────────────────────────────────────────────────────
# MAIN WATCHDOG LOOP
# ─────────────────────────────────────────────────────────────
main() {
    # Ensure log file exists and is writable
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/vulnscan_watchdog.log"
    chmod 644 "$LOG_FILE" 2>/dev/null || true

    echo ""
    log INFO "╔══════════════════════════════════════════╗"
    log INFO "║   VulnScan Pro — Watchdog Started        ║"
    log INFO "║   PID: $$   Interval: ${CHECK_INTERVAL}s              ║"
    log INFO "╚══════════════════════════════════════════╝"
    log INFO "Log: ${LOG_FILE}"
    log INFO "Health endpoint: ${HEALTH_URL}"
    echo ""

    # Initial full check
    full_system_check

    # Start background log monitor
    monitor_service_logs

    # Ensure service is enabled on boot
    systemctl enable "$SERVICE" 2>/dev/null || true

    # Start service if not running
    if ! is_service_running; then
        log WARN "Service not running at startup — starting..."
        systemctl start "$SERVICE" 2>/dev/null
        sleep 5
    fi

    local loop_count=0

    while true; do
        (( loop_count++ )) || true

        # ── Every 10s: health check ───────────────────────
        if ! is_service_running; then
            log ERROR "Service is DOWN — restarting..."
            restart_service "service not active"

        elif ! is_app_healthy; then
            log WARN "Service running but HTTP health check failed — restarting..."
            restart_service "health check failed on ${HEALTH_URL}"

        else
            # Reset failure counter on success
            if (( consecutive_failures > 0 )); then
                log OK "Service recovered after ${consecutive_failures} failures"
                consecutive_failures=0
            fi
            log INFO "✓ Service healthy | uptime check #${loop_count}"
        fi

        # ── Every 5 min: full dependency check ────────────
        if (( loop_count % 30 == 0 )); then
            log INFO "Running periodic full dependency check..."
            full_system_check
        fi

        # ── Every 1 min: check Tor + Apache ───────────────
        if (( loop_count % 6 == 0 )); then
            check_tor
            check_apache
        fi

        sleep "$CHECK_INTERVAL"
    done
}

# ─────────────────────────────────────────────────────────────
# TRAP signals for clean exit
# ─────────────────────────────────────────────────────────────
cleanup() {
    log INFO "Watchdog stopping (signal received)"
    # Kill background jobs
    jobs -p | xargs -r kill 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

# ─────────────────────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Run as root — sudo bash $0${RESET}"
    exit 1
fi

main
