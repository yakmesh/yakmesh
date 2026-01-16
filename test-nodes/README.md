# Yakmesh 3-Node Test Suite

## Overview
This directory contains configs and scripts for comprehensive multi-node testing.

## Node Configuration

| Node | HTTP Port | WS Port | Purpose |
|------|-----------|---------|---------|
| Alpha | 3001 | 9001 | Local node (updated codebase) |
| Beta | 3002 | 9002 | Local node (updated codebase) |
| Gamma | 3000 | 9001 | LAN node @ WIN-LQH9ULSNBFU (old codebase) |

## Test Scenarios

### Test 1: Two Synced + One Old
- Alpha & Beta = same new codebase → should peer successfully
- Gamma = old codebase → should be REJECTED by Alpha/Beta

### Test 2: Three Different Codebases  
- Alpha = new codebase
- Beta = new codebase + minor modification → different hash
- Gamma = old codebase
- **Expected**: All three are isolated networks, NO peering

### Test 3: Stress/Race Conditions
- Rapid connect/disconnect cycles
- Simultaneous connection attempts
- Network partition simulation

## Running Tests

```powershell
# Start Alpha
node server/index.js --config test-nodes/config-alpha.js

# Start Beta (new terminal)
node server/index.js --config test-nodes/config-beta.js

# Run test suite
node test-nodes/test-three-nodes.mjs
```

## LAN Node (Gamma)
The remote node runs on WIN-LQH9ULSNBFU via Abyss X2 reverse proxy:
- HTTP: http://WIN-LQH9ULSNBFU:8000
- WS: ws://WIN-LQH9ULSNBFU:9001
