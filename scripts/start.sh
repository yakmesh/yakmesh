#!/bin/bash
# Yakmesh Node Startup Script
# Handles process management, prevents orphan processes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$NODE_DIR/data/yakmesh.pid"
LOG_FILE="$NODE_DIR/data/yakmesh.log"

# Ensure data directory exists
mkdir -p "$NODE_DIR/data"

# Function to check if process is running
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Function to stop the node
stop_node() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        echo "🛑 Stopping Yakmesh Node (PID: $PID)..."
        kill "$PID" 2>/dev/null
        sleep 2
        # Force kill if still running
        if ps -p "$PID" > /dev/null 2>&1; then
            kill -9 "$PID" 2>/dev/null
        fi
        rm -f "$PID_FILE"
        echo "✓ Node stopped"
    else
        echo "Node is not running"
    fi
}

# Function to start the node
start_node() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        echo "⚠️  Node already running (PID: $PID)"
        echo "   Use: $0 restart"
        exit 1
    fi
    
    echo "🦬 Starting Yakmesh Node..."
    cd "$NODE_DIR"
    
    # Start node in background, redirect output to log
    nohup node server/index.js >> "$LOG_FILE" 2>&1 &
    PID=$!
    echo $PID > "$PID_FILE"
    
    # Wait a moment and check if it started
    sleep 3
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "✓ Node started (PID: $PID)"
        echo "  Log: $LOG_FILE"
        echo "  Use: $0 status  - Check status"
        echo "  Use: $0 logs    - View logs"
        echo "  Use: $0 stop    - Stop node"
    else
        echo "❌ Failed to start node"
        echo "   Check log: $LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
}

# Function to show status
show_status() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        echo "✓ Yakmesh Node is running (PID: $PID)"
        # Show last few lines of log
        if [ -f "$LOG_FILE" ]; then
            echo ""
            echo "Recent log:"
            tail -10 "$LOG_FILE"
        fi
    else
        echo "✗ Yakmesh Node is not running"
    fi
}

# Function to show logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -50 "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

# Function to follow logs
follow_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

# Main command handler
case "${1:-start}" in
    start)
        start_node
        ;;
    stop)
        stop_node
        ;;
    restart)
        stop_node
        sleep 1
        start_node
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    follow)
        follow_logs
        ;;
    *)
        echo "Yakmesh Node Manager"
        echo "Usage: $0 {start|stop|restart|status|logs|follow}"
        echo ""
        echo "  start   - Start the node in background"
        echo "  stop    - Stop the running node"
        echo "  restart - Stop and start the node"
        echo "  status  - Show node status"
        echo "  logs    - Show last 50 log lines"
        echo "  follow  - Follow log output (Ctrl+C to exit)"
        exit 1
        ;;
esac
