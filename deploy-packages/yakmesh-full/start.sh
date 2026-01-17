#!/bin/bash
#
# YAKMESH Self-Contained Node - Start Script
# Complete stack with bundled binaries (Node.js, Caddy, PHP)
# No external dependencies required.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ====================================="
echo "      YAKMESH SELF-CONTAINED"
echo "      Complete Stack - All Bundled"
echo "  ====================================="
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)  PLATFORM="linux" ;;
    Darwin*) PLATFORM="darwin" ;;
    *)       echo "[ERROR] Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64)  ARCH_NAME="x64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *)       echo "[ERROR] Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Paths to bundled binaries
NODE_BIN="$SCRIPT_DIR/bin/node/bin/node"
CADDY_BIN="$SCRIPT_DIR/bin/caddy"
PHP_BIN="$SCRIPT_DIR/bin/php/php-cgi"
PHP_INI="$SCRIPT_DIR/bin/php/php.ini"

# Check for bundled binaries
MISSING=()
[ ! -f "$NODE_BIN" ] && MISSING+=("Node.js (bin/node/bin/node)")
[ ! -f "$CADDY_BIN" ] && MISSING+=("Caddy (bin/caddy)")
[ ! -f "$PHP_BIN" ] && MISSING+=("PHP (bin/php/php-cgi)")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "[ERROR] Missing bundled binaries:"
    for item in "${MISSING[@]}"; do
        echo "  - $item"
    done
    echo ""
    echo "This is a self-contained package. Binaries should be included."
    echo "Please re-download the full package from yakmesh.dev"
    exit 1
fi

# Show versions
NODE_VERSION=$("$NODE_BIN" --version)
echo "[OK] Node.js $NODE_VERSION (bundled)"

PHP_VERSION=$("$PHP_BIN" -v 2>/dev/null | head -1 | grep -oP 'PHP \K[\d.]+')
echo "[OK] PHP $PHP_VERSION (bundled)"

CADDY_VERSION=$("$CADDY_BIN" version 2>/dev/null | head -1)
echo "[OK] Caddy $CADDY_VERSION (bundled)"

# Create directories
mkdir -p "$SCRIPT_DIR/htdocs"
mkdir -p "$SCRIPT_DIR/data/content"
mkdir -p "$SCRIPT_DIR/logs"

# Create default index.html if not exists
INDEX_PATH="$SCRIPT_DIR/htdocs/index.html"
if [ ! -f "$INDEX_PATH" ]; then
    cat > "$INDEX_PATH" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>YAKMESH Node</title>
    <style>
        body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; background: #f8f9fa; }
        h1 { color: #2d5016; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .online { background: #28a745; }
        .card { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <h1>🦬 YAKMESH Self-Contained Node</h1>
    <p>Your complete Yakmesh stack is running.</p>
    
    <div class="card">
        <h2>Services</h2>
        <p><span class="status online"></span><strong>Web Server:</strong> <a href="http://localhost:8080">http://localhost:8080</a></p>
        <p><span class="status online"></span><strong>Content API:</strong> <a href="http://localhost:3000/content">http://localhost:3000/content</a></p>
        <p><span class="status online"></span><strong>PHP:</strong> <a href="http://localhost:8080/info.php">http://localhost:8080/info.php</a></p>
        <p><span class="status online"></span><strong>Mesh P2P:</strong> <code>ws://localhost:9001</code></p>
    </div>
    
    <div class="card">
        <h2>Content API</h2>
        <ul>
            <li><code>GET /content</code> - List all content</li>
            <li><code>GET /content/:hash</code> - Get content by hash</li>
            <li><code>POST /content</code> - Store new content</li>
        </ul>
    </div>
    
    <div class="card">
        <h2>Bundled Software</h2>
        <ul>
            <li>Node.js 20 LTS</li>
            <li>PHP 8.3</li>
            <li>Caddy 2.8</li>
        </ul>
    </div>
    
    <p><a href="https://yakmesh.dev">yakmesh.dev</a> | <a href="https://github.com/yakmesh/yakmesh">GitHub</a></p>
</body>
</html>
EOF
fi

# Create PHP info file
PHP_INFO_PATH="$SCRIPT_DIR/htdocs/info.php"
if [ ! -f "$PHP_INFO_PATH" ]; then
    echo "<?php phpinfo();" > "$PHP_INFO_PATH"
fi

# Install node_modules using bundled Node if needed
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing Node.js dependencies..."
    export PATH="$(dirname "$NODE_BIN"):$PATH"
    "$NODE_BIN" "$(dirname "$NODE_BIN")/npm" install 2>&1 || true
fi

echo ""
echo "[INFO] Starting services..."
echo ""

# PID file
PID_FILE="$SCRIPT_DIR/data/.pids"

# Cleanup function
cleanup() {
    echo ""
    echo "[INFO] Shutting down..."
    
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    # Kill any orphan processes
    pkill -f "yakmesh.*node" 2>/dev/null || true
    pkill -f "php-cgi" 2>/dev/null || true
    pkill -f "caddy.*yakmesh" 2>/dev/null || true
    
    echo "[OK] All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start PHP FastCGI
"$PHP_BIN" -b 127.0.0.1:9000 -c "$PHP_INI" > "$SCRIPT_DIR/logs/php.log" 2>&1 &
PHP_PID=$!
echo "$PHP_PID" > "$PID_FILE"
echo "  ✓ PHP FastCGI started (PID: $PHP_PID)"

# Start Yakmesh node
export YAKMESH_CONFIG="$SCRIPT_DIR/config/yakmesh.config.js"
"$NODE_BIN" server/index.js > "$SCRIPT_DIR/logs/mesh.log" 2>&1 &
MESH_PID=$!
echo "$MESH_PID" >> "$PID_FILE"
echo "  ✓ Mesh Node started (PID: $MESH_PID)"

sleep 2

# Start Caddy
"$CADDY_BIN" run --config "$SCRIPT_DIR/config/Caddyfile" > "$SCRIPT_DIR/logs/caddy.log" 2>&1 &
CADDY_PID=$!
echo "$CADDY_PID" >> "$PID_FILE"
echo "  ✓ Caddy started (PID: $CADDY_PID)"

echo ""
echo "  ========================================"
echo "  All services running!"
echo "  ========================================"
echo ""
echo "  Web Server:    http://localhost:8080"
echo "  PHP Info:      http://localhost:8080/info.php"
echo "  Content API:   http://localhost:3000/content"
echo "  Mesh P2P:      ws://localhost:9001"
echo ""
echo "  Logs: $SCRIPT_DIR/logs/"
echo ""
echo "  Press Ctrl+C to stop all services"
echo ""

# Wait for processes
wait
