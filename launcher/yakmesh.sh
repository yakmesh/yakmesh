#!/bin/bash
# ============================================================================
# YAKMESH Launcher - Unix/Linux/macOS
# Opens dashboard in browser and starts the node
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ASCII Banner
echo -e "${GREEN}"
cat << 'EOF'

    YY   YY   AA   KK  KK MM   MM EEEE  SSSS HH   HH
     YY YY   AAAA  KK KK  MMM MMM EE   SS    HH   HH
      YYY   AA  AA KKKK   MM M MM EEE   SSS  HHHHHHH
      YY    AAAAAA KK KK  MM   MM EE      SS HH   HH
      YY    AA  AA KK  KK MM   MM EEEE SSSS  HH   HH

          Post-Quantum Secure P2P Mesh Network

EOF
echo -e "${NC}"

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js not found in PATH${NC}"
    echo -e "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_SCRIPT="$NODE_DIR/server/index.js"

if [ ! -f "$SERVER_SCRIPT" ]; then
    echo -e "${RED}[ERROR] server/index.js not found${NC}"
    echo -e "Expected at: $SERVER_SCRIPT"
    exit 1
fi

# Read port
HTTP_PORT="${YAKMESH_HTTP_PORT:-3789}"

echo -e "   ${CYAN}[*] Starting YAKMESH node...${NC}"
echo -e "   ${CYAN}[*] Dashboard: http://localhost:$HTTP_PORT/dashboard${NC}"
echo -e "   ${DIM}[*] Press Ctrl+C to stop${NC}"
echo ""

# Open dashboard after delay (background)
(
    sleep 3
    # Try different openers
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:$HTTP_PORT/dashboard" 2>/dev/null
    elif command -v open &> /dev/null; then
        open "http://localhost:$HTTP_PORT/dashboard"
    fi
) &

# Start node
cd "$NODE_DIR"
exec node server/index.js
