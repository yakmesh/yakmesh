# PeerQuanta ValidationOracle System

## Overview

The ValidationOracle system implements a "code is the oracle" approach to distributed consensus.
Instead of relying on voting or social trust, nodes prove they're running identical validation
code and therefore MUST arrive at the same conclusions about data validity.

## Core Principle

```
If two nodes:
  1. Can prove they run identical code (via code-proof protocol)
  2. Apply that code to the same data
  
Then they MUST get the same result.

Consensus is mathematical inevitability, not a vote.
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ValidationOracle System                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐   ┌──────────────────┐                    │
│  │ ValidationOracle │   │  ModuleSealer    │                    │
│  │                  │   │                  │                    │
│  │ - Self-hash      │   │ - Source hash    │                    │
│  │ - Validate()     │   │ - AST hash       │                    │
│  │ - CodeProof()    │   │ - Behavior hash  │                    │
│  │ - Deterministic  │   │ - Attestations   │                    │
│  └────────┬─────────┘   └──────────────────┘                    │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────┐   ┌──────────────────┐                    │
│  │ CodeProofProtocol│   │ ConsensusEngine  │                    │
│  │                  │   │                  │                    │
│  │ - Challenge/Resp │──▶│ - Content Store  │                    │
│  │ - Peer Verify    │   │ - Attestations   │                    │
│  │ - Trust Registry │   │ - Conflict Res   │                    │
│  └──────────────────┘   └──────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. ValidationOracle

The core validation module that:
- Computes its own hash on startup (self-verification)
- Provides pure, deterministic validation functions
- Can generate/verify code proofs

```javascript
import { getOracle } from './oracle/index.js';

const oracle = getOracle();

// Verify self-integrity
const integrity = oracle.verifySelfIntegrity();
console.log(integrity.valid); // true if code unchanged

// Validate content
const result = oracle.validateListing({
  title: 'Sell 100 QRL',
  price: 0.01,
  currency: 'BTC',
  user_id: 42,
  trade_type: 'sell'
});
```

### 2. CodeProofProtocol

Enables peers to prove they're running identical code:

```javascript
import { CodeProofProtocol } from './oracle/index.js';

const protocol = new CodeProofProtocol(nodeIdentity);

// Generate challenge for another peer
const challenge = protocol.generateChallenge(peerId);

// Respond to incoming challenge
const response = protocol.respondToChallenge(incomingChallenge);

// Verify peer's response
const verified = protocol.verifyResponse(peerResponse);
```

### 3. ConsensusEngine

Manages distributed consensus through deterministic validation:

```javascript
import { ConsensusEngine } from './oracle/index.js';

const engine = new ConsensusEngine(nodeIdentity, {
  minAttestations: 2,  // Require 2 nodes to agree
});

// Submit content
const result = engine.submitContent('listing', listingData);

// Content is now tracked, waiting for attestations from other nodes
// When minAttestations reached, consensus is achieved
```

### 4. ModuleSealer

Creates cryptographic seals for modules:

```javascript
import { ModuleSealer } from './oracle/index.js';

const sealer = new ModuleSealer();
const sealed = await sealer.sealModule('./my-module.js', '1.0.0');

// sealed.sealHash - unique hash binding source + behavior
// sealed.sourceHash - hash of source code
// sealed.behaviorFingerprint - hash of function signatures
```

## HTTP API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oracle/status` | GET | Oracle health and integrity check |
| `/oracle/submit` | POST | Submit content for validation |
| `/oracle/challenge` | POST | Challenge a peer |
| `/oracle/peers` | GET | List verified peers |
| `/oracle/consensus` | GET | Consensus statistics |
| `/oracle/resolve` | POST | Trigger conflict resolution |

### Example: Check Oracle Status

```bash
curl http://localhost:3000/oracle/status
```

Response:
```json
{
  "status": "healthy",
  "integrity": {
    "valid": true,
    "proof": {
      "selfHash": "6ecacbcfc6568834..."
    }
  },
  "validationMethods": ["listing", "qcoa", "user"],
  "consensusStats": {
    "contentValidated": 42,
    "consensusReached": 35
  }
}
```

### Example: Submit Content

```bash
curl -X POST http://localhost:3000/oracle/submit \
  -H "Content-Type: application/json" \
  -d '{
    "type": "listing",
    "content": {
      "title": "Sell 100 QRL",
      "price": 0.015,
      "currency": "BTC",
      "user_id": 42,
      "trade_type": "sell"
    }
  }'
```

## Trust Model

Traditional: "I trust Node X because humans vouched for it"

Oracle Model: "I trust Node X because:
1. It passed a code-proof challenge (runs same code as me)
2. Its validations MUST therefore match mine
3. Trust is mathematically derived, not socially assigned"

## Running Tests

```bash
node lantern-node/scripts/test-oracle.js
```

Expected output: 7/8 tests pass (QCoA fails without real signature - expected)

## Files

```
lantern-node/
├── oracle/
│   ├── index.js                 # Main entry point
│   ├── validation-oracle.js     # Core oracle (self-verifying)
│   ├── code-proof-protocol.js   # Peer verification
│   ├── consensus-engine.js      # Distributed consensus
│   └── module-sealer.js         # Cryptographic sealing
├── server/
│   └── index.js                 # LanternNode with Oracle integration
└── scripts/
    └── test-oracle.js           # Comprehensive test suite
```

## Security Properties

1. **Self-Verification**: Oracle hashes its own code, detects tampering
2. **Code Proof**: Peers prove they run identical code
3. **Deterministic**: Same input always produces same output
4. **Content-Addressed**: Data's hash IS its identity
5. **Conflict Resolution**: Deterministic rules, not voting
6. **Post-Quantum Signatures**: ML-DSA-65 (NIST Level 3)
