#!/bin/bash
#
# YAKMESH Minimal Node - Start Script
# Starts the Yakmesh mesh node, content API, and Caddy web server.
# Downloads Caddy on first run if not present.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ====================================="
echo "      YAKMESH MINIMAL NODE"
echo "      Mesh Network + Web Server"
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
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)       echo "[ERROR] Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js not found. Please install Node.js 18+ and add to PATH."
    exit 1
fi
NODE_VERSION=$(node --version)
echo "[OK] Node.js $NODE_VERSION"

# Check/Install dependencies
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing dependencies..."
    npm install
fi

# Check/Download Caddy
CADDY_BIN="$SCRIPT_DIR/bin/caddy"
if [ ! -f "$CADDY_BIN" ]; then
    echo "[INFO] Downloading Caddy web server..."
    
    mkdir -p "$SCRIPT_DIR/bin"
    
    CADDY_VERSION="2.8.4"
    CADDY_URL="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_${PLATFORM}_${ARCH}.tar.gz"
    
    curl -fsSL "$CADDY_URL" -o "$SCRIPT_DIR/bin/caddy.tar.gz"
    tar -xzf "$SCRIPT_DIR/bin/caddy.tar.gz" -C "$SCRIPT_DIR/bin"
    rm "$SCRIPT_DIR/bin/caddy.tar.gz"
    chmod +x "$CADDY_BIN"
    
    echo "[OK] Caddy installed"
fi

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
        body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #2d5016; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>🦬 YAKMESH Node Running</h1>
    <p>Your Yakmesh node is operational.</p>
    <h2>Endpoints</h2>
    <ul>
        <li><strong>Web Server:</strong> <a href="http://localhost:8080">http://localhost:8080</a></li>
        <li><strong>Content API:</strong> <a href="http://localhost:3000/content">http://localhost:3000/content</a></li>
        <li><strong>Mesh P2P:</strong> <code>ws://localhost:9001</code></li>
    </ul>
    <h2>Content API</h2>
    <ul>
        <li><code>GET /content</code> - List all content</li>
        <li><code>GET /content/:hash</code> - Get content by hash</li>
        <li><code>POST /content</code> - Store new content</li>
    </ul>
    <p><a href="https://yakmesh.dev">yakmesh.dev</a> | <a href="https://github.com/yakmesh/yakmesh">GitHub</a></p>
</body>
</html>
EOF
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
    pkill -f "caddy.*yakmesh" 2>/dev/null || true
    
    echo "[OK] All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start Yakmesh node
export YAKMESH_CONFIG="$SCRIPT_DIR/config/yakmesh.config.js"
node server/index.js > "$SCRIPT_DIR/logs/mesh.log" 2>&1 &
MESH_PID=$!
echo "$MESH_PID" > "$PID_FILE"

sleep 2

# Start Caddy
"$CADDY_BIN" run --config "$SCRIPT_DIR/config/Caddyfile" > "$SCRIPT_DIR/logs/caddy.log" 2>&1 &
CADDY_PID=$!
echo "$CADDY_PID" >> "$PID_FILE"

echo ""
echo "  ✓ Mesh Node:     ws://localhost:9001  (PID: $MESH_PID)"
echo "  ✓ Content API:   http://localhost:3000"
echo "  ✓ Web Server:    http://localhost:8080 (PID: $CADDY_PID)"
echo ""
echo "  Logs: $SCRIPT_DIR/logs/"
echo ""
echo "  Press Ctrl+C to stop all services"
echo ""

# Wait for processes
wait
