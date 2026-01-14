#!/bin/bash
# Yakmesh Full Stack Launcher

echo "===================================="
echo "   YAKMESH - Self-Hosting Stack"
echo "===================================="
echo ""

# Start web server
echo "[1/2] Starting Caddy web server..."
./bin/caddy run --config ./Caddyfile &
CADDY_PID=$!

# Start mesh node
echo "[2/2] Starting Yakmesh mesh node..."
node ./server/index.js &
MESH_PID=$!

echo ""
echo "Services running:"
echo "  Web:  http://localhost:8080"
echo "  Mesh: ws://localhost:9001"
echo "  Dashboard: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop"

trap "kill $CADDY_PID $MESH_PID 2>/dev/null; exit" INT TERM
wait