#!/bin/bash
#
# YAKMESH Self-Contained Node - Stop Script
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/data/.pids"

echo ""
echo "[INFO] Stopping YAKMESH services..."

# Stop processes from PID file
if [ -f "$PID_FILE" ]; then
    while read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            echo "[OK] Stopped process $pid"
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

# Kill any remaining processes
pkill -f "php-cgi" 2>/dev/null && echo "[OK] PHP stopped" || true
pkill -f "yakmesh.*node" 2>/dev/null && echo "[OK] Node processes stopped" || true
pkill -f "caddy" 2>/dev/null && echo "[OK] Caddy stopped" || true

echo ""
echo "[OK] All services stopped"
echo ""
