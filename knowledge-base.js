/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * YAKMESH Comprehensive Knowledge Base v3.3.0
 * 
 * This file contains ALL technical information about YAKMESH
 * for use by YakBot (Discord) and YakAI (Web Assistant).
 * 
 * Last Updated: 2026-02-12
 * 
 * @module knowledge-base
 */

export const YAKMESH_KNOWLEDGE_BASE = `
# YAKMESH v3.3.0 Complete Technical Reference

## Overview
YAKMESH (Yielding Atomic Kernel Modular Encryption Secured Hub) is a post-quantum secure P2P mesh network built for the 2026 threat landscape. It combines quantum-resistant cryptography with physics-based verification to create trustless distributed systems.

**Key Stats:**
- Version: 3.0.0
- Tests: 812+ (Oracle 98, Protocol 56, Multi-Node 18, Security 390+, BYOND 36)
- License: MIT
- Node.js 18+ required

---

## PROTOCOL STACK (Top to Bottom)

### 1. YAK:// Protocol
Custom URL scheme for mesh resources.
- \`yak://dashboard\` - Node dashboard
- \`yak://site\` - Hosted website
- \`yak://peers\` - Connected peers
- \`yak://content/<hash>\` - Content by SHA3-256 hash
- \`yak://settings\` - Node settings
- \`yak://<bookmark>\` - Custom pet names

### 2. GRANTH (ग्रन्थ) - Embedded Documentation
Guaranteed Read-only Authenticated Node Text Hardcode.
- SHA3-256 hash-verified documentation bundle
- ~767KB, 56 files bundled with npm package
- Offline-first access, tamper-proof
- Version: interact-contact-sulfide (current bundle hash)

### 3. KHATA (खाता) - Gossip Protocol
Epidemic-style message propagation.
- Message types: ATTESTATION, CHALLENGE, REVOCATION, GEO_PROOF, etc.
- Deduplication via message ID tracking
- Hop limit enforcement (default 6)
- Rumor spreading with TTL

### 4. ANNEX - Encrypted Channels
Autonomous Network Negotiated eXchange.
- ML-KEM-768 ephemeral key exchange (NIST FIPS 203)
- AES-256-GCM symmetric encryption
- Forward secrecy with TRIBHUJ key ratchet rotation
- Session expiry: 1hr timeout + 10K message limit, auto-rekey
- Replay protection: nonce dedup with 5-min window
- sharedSecret zeroed immediately after key derivation
- Transparent encryption on ALL peer-to-peer wire traffic
- Content-addressed storage integration

### 5. NAKPAK - Onion Routing
Nested Anonymous Kernel for Private Authenticated Komms.
- 3-hop onion routing by default
- ML-KEM-768 for each layer encryption
- Sphinx-style packet format
- Reply path support

### 6. SHERPA - Peer Discovery
Secure Hidden Endpoint Resolution Path Architecture.
- DHT-less beacon discovery via HTTP polling
- RTT measurement for geo-proofing (performance.now())
- Automatic landmark discovery
- Protocol version 1.1 (geo-enabled)

### 7. TRIBHUJ (त्रिभुज) - Trinary Rotating Keypairs (NEW in v3.0)
Fibonacci-style ML-DSA-65 key ratchet using balanced ternary principles.
- Two genesis keypairs generated once ("double overhead"), then infinite derivation
- Key Kn = ML-DSA-65.keygen(SHA3-256(epoch || pub(n-2) || secret(n-1)))
- Triangle state: {previous(-1), current(0), next(+1)} = balanced ternary
- Forward secrecy: previous secret keys zeroed on rotation
- 5-minute auto-rotation, 1-minute grace period for in-flight messages
- Chain limit 1000 before forced re-genesis
- Also provides balanced ternary math: Trit(-1,0,+1), TritArray, consensus logic

### 8. Gateway Attestation (NEW in v3.0)
Verify-once gossip signature optimization.
- First verifier creates attestation: SHA3-256(messageId + signer + gatewayId + timestamp)
- Attestation signed with TRIBHUJ ratchet (~0.01ms vs ~2-5ms full ML-DSA-65 verify)
- Downstream peers check attestation instead of re-verifying original signature
- 60s TTL, automatically attached to gossip messages

### 9. SSE Real-Time Push (NEW in v3.0)
Server-Sent Events for instant gossip delivery.
- GET /rumors/subscribe — real-time gossip stream
- Replaces 10s HTTP polling (avg 5s latency → near-instant)
- Topic filtering, 15s heartbeat, auto-cleanup
- MeshBridge connects via SSE-first with HTTP polling fallback
- No central bootstrap required

### 7. STUPA - State Consensus
Signal Transmission Unit for Peer Awareness.
- Priority-based broadcast messaging
- Emergency beacons with priority levels:
  - CRITICAL (1): Network-wide emergency
  - HIGH (2): Important updates
  - NORMAL (3): Regular broadcasts
  - LOW (4): Background sync

### 8. LAMA - Distributed Consensus
Locally Attested Multi-Agreement.
- Independent wisdom-based consensus
- No single point of authority
- Mathematical agreement through attestations
- 2/3 threshold for decisions

### 9. MANI - Time Synchronization
Metrological Anchoring for Network Integrity.
- Precision time source hierarchy:
  - ATOMIC (2.0x trust): Cesium/Rubidium clocks
  - GPS_PPS (1.5x): GPS with PPS signal
  - PTP (1.25x): Precision Time Protocol
  - NTP (1.0x): Network Time Protocol
  - UNKNOWN (0.25x): Unverified

### 10. MANTRA - Message Propagation
Message Amplification Network for Trust Relayed Announcements.
- Prayer wheel-style epidemic spreading
- Each node amplifies to connected peers
- TTL-based decay to prevent flooding

### 11. MANDALA - Topology Management
Mesh Architecture for Network Distribution & Layered Aggregation.
- Sacred geometry of interconnected nodes
- Cluster detection and management
- Load balancing across mesh
- Partition detection and healing

### 12. ECHO - Topology Discovery
Encrypted Coordinate Heuristic Oracle.
- Privacy-preserving network cartography
- 8-dimensional virtual coordinate space
- Encrypted timing probes (AES-256-GCM)
- RTT-based distance estimation
- Probe interval: 30 seconds

### 13. PULSE - Heartbeat System
Precision Universal Latency Sync Engine.
- Cryptographic heartbeat chains
- 1-second heartbeat interval
- Liveness detection (5 missed = dead)
- Leader election with term duration
- Partition detection via gap analysis

---

## IDENTITY & SECURITY LAYER (SURAKSHA सुरक्षा)

### NAMCHE Gateway - 7-Gate Verification
Network Authenticated Mesh Certificate Hub & Exchange.
Each node passes through 7 mathematical gates:

1. **CRYPTO** - ML-DSA-65 signature verification (NIST FIPS 204)
2. **TEMPORAL** - Challenge/response timing analysis
3. **BEHAVIORAL** - Pattern consistency over time
4. **HARDWARE** - AES-NI timing attestation (≤2 cycles/byte = real silicon)
5. **NETWORK** - Latency fingerprinting
6. **GEOGRAPHIC** - Speed-of-light location proof (199,861.639 km/s in fiber)
7. **SOCIAL** - Cross-node vouching from Guardians

Cross 5+ gates = cryptographically verified node.

### DOKO Identity
Distributed Ownership & Key Object.
- Self-sovereign identity certificates
- ML-DSA-65 public key as identity
- Certificate chains for delegation
- Emergency revocation certificates
- TLS binding (certificate fingerprints)

### KARMA Trust Tiers (Himalayan naming)
Kinetic Assessment of Reputation & Merit Accumulation.

| Tier | Nepali Name | Multiplier | Requirements |
|------|------------|------------|--------------|
| ORACLE | SARATHI (सारथी) | 2.0x | Atomic clock + AES-NI + 30 days |
| ANCHOR | SAMRAT (सम्राट) | 1.5x | GPS+PPS + AES-NI + 14 days |
| SENTINEL | SIPAHI (सिपाही) | 1.25x | PTP + AES-NI + 7 days |
| PARTICIPANT | PATHIK (पथिक) | 1.0x | NTP + AES-NI verified |
| OBSERVER | PARYATAK (पर्यटक) | 0.25x | New/unverified nodes |

### Hardware Attestation
AES-NI instruction timing proves real silicon vs VMs/emulators.
- Real hardware: ≤2 cycles/byte
- Emulators: 10-50x slower (detectable)
- 1000 AES operations for fingerprint
- 4KB data per operation (cache-friendly)

### Silicon Parity
"One Silicon = One Vote" anti-ASIC/farm defense.
- Weight = tierMax / coreCount
- 100-core rig = same weight as 1-core
- AES-NI fingerprint as unique silicon identity
- Prevents ASIC-style gaming

### Strike System
"Three Strikes — Then Math Speaks"
- Strike 1: Fresh start allowed, recorded (0.75x trust)
- Strike 2: 7-day probation, reduced trust (0.5x trust)
- Strike 3: Permanent network ban (0x trust)
- Hardware fingerprint tracks identity across fresh starts

### Sybil Detection
Graph analysis to detect fake identity clusters.
- Clustering coefficient analysis (>0.7 = suspicious)
- Edge cut ratio (<0.1 = insular cluster)
- Behavior correlation (uptime, activity patterns)
- Component analysis for cluster isolation

### Mesh Revocation
2/3 threshold attestation-based key revocation.
- No central CA required
- Post-quantum signed attestations (ML-DSA-65)
- Revocation certificates with threshold proof
- Gossip propagation via KHATA

### Phase Epochs
Time-based replay protection.
- 6-hour epoch duration
- Challenges include phase information
- Expired phases automatically rejected
- Prevents cross-epoch replay attacks

---

## TATTVA (तत्त्व) - Oracle System
Self-verifying validation, replacing "Oracle" naming.

### Code Proof Protocol
Nodes cryptographically prove they run identical code.
- Challenge-response verification
- SHA3-256 code hashing
- 30-second challenge timeout
- 5-minute re-verification interval
- Phase-modulated challenges (replay protection)

### Codebase Lock
Runtime file locking for source code protection.
- Windows: Creates sharing violations
- Unix: Removes write permissions
- Locks .js, .mjs, .cjs, .json, .ts files
- Excludes node_modules, .git, data, etc.

### Module Sealer
Prevents runtime module tampering.
- Freezes module exports
- Validates module signatures
- Detects hot-patching attempts

### Network Identity
Each network has unique identity from code hash.
- \`deriveNetworkName()\` - Human-readable network name
- \`deriveVerificationPhrase()\` - 4-word verification phrase
- Same code = same network (no configuration needed)

---

## PRAMAAN (प्रमाण) - Geographic Proof
Physics-based location verification.

### Speed-of-Light Physics
- Vacuum: 299,792.458 km/s
- Fiber (0.67c): 199,861.639 km/s

| RTT | Minimum Distance |
|-----|------------------|
| 1ms | ≥100 km |
| 5ms | ≥500 km |
| 10ms | ≥999 km |
| 50ms | ≥4,997 km |
| 100ms | ≥9,993 km |

### Exclusion Zones
"We prove where you CANNOT be, not where you ARE"
- Create zones from RTT measurements
- Network latency only adds delay
- Zones are always valid (can't exceed light speed)
- Triangulation from 3+ landmarks = ±50km precision

---

## CLI COMMANDS

### Basic Operations
\`\`\`bash
npx yakmesh init              # Initialize new node
npx yakmesh start             # Start node
npx yakmesh status            # Show node status
npx yakmesh peers             # List connected peers
npx yakmesh info              # Detailed node info
npx yakmesh join <endpoint>   # Connect to peer
\`\`\`

### YAK:// Protocol
\`\`\`bash
npx yakmesh protocol register            # Register yak:// with OS
npx yakmesh protocol unregister          # Unregister yak://
npx yakmesh protocol test <url>          # Test URL parsing
npx yakmesh protocol open <url>          # Open in browser
npx yakmesh protocol bookmark add <n> <t> # Add bookmark
npx yakmesh protocol bookmark list       # List bookmarks
npx yakmesh protocol bookmark remove <n> # Remove bookmark
\`\`\`

### Geographic Proof
\`\`\`bash
npx yakmesh geo status                   # Geo proof status
npx yakmesh geo landmarks                # List landmarks
npx yakmesh geo zones                    # List exclusion zones
npx yakmesh geo prove                    # Generate proof
npx yakmesh geo verify <nodeId>          # Verify another node
npx yakmesh geo add-landmark <name>      # Add landmark
npx yakmesh geo physics                  # Show physics constants
\`\`\`

### Documentation
\`\`\`bash
npx yakmesh docs info                    # Bundle information
npx yakmesh docs verify                  # Verify bundle integrity
npx yakmesh docs list                    # List all files
npx yakmesh docs serve                   # Start local docs server
\`\`\`

---

## API EXPORTS

\`\`\`javascript
import { 
  YakmeshNode,           // Main node class
  NAMCHE,                // 7-gate identity verification
  DOKO,                  // Distributed identity
  SHERPA,                // Peer discovery
  NAKPAK,                // Onion routing
  ANNEX,                 // Encrypted channels
  KHATA,                 // Gossip protocol
  GeographicProof,       // Location verification
  HardwareAttestation,   // AES-NI verification
  TrustTier,             // KARMA trust levels
  StrikeSystem,          // 3-strike system
  SybilDetection,        // Fake identity detection
  CodeProofProtocol,     // Code verification
  CodebaseLock,          // Runtime file locking
} from 'yakmesh';

// Network identity
import { 
  deriveNetworkName, 
  deriveVerificationPhrase 
} from 'yakmesh/oracle/network-identity.js';

// Embedded docs
import { 
  BUNDLE_HASH, 
  BUNDLE_VERSION, 
  getDocsFile,
  verifyFile,
  getBundleInfo,
} from 'yakmesh/embedded-docs/index.js';
\`\`\`

---

## INSTALLATION & QUICK START

\`\`\`bash
npm install yakmesh

# Initialize a new node
npx yakmesh init --name "My Node" --port 3000

# Start the node
npx yakmesh start
\`\`\`

\`\`\`javascript
import { YakmeshNode } from 'yakmesh';

const node = new YakmeshNode({
  node: { name: 'My Node', region: 'local' },
  network: { httpPort: 3000, wsPort: 9001 },
});

await node.start();
\`\`\`

---

## ADAPTERS

### BYOND Game Server Adapter
Integration for BYOND games (Space Station 13, etc.)
- Native BYOND wire protocol
- HTTP bridge for DreamDaemon
- Server discovery via mesh gossip
- World persistence to mesh storage
- DOKO identity for game servers

### PeerQuanta Marketplace Adapter
Bridges phpBB SQLite database with mesh network.
- DOKO Trader Identity for self-sovereign identities
- Trust-Based Escrow (variable by trust level)
- ANNEX Trade Chat (encrypted P2P messaging)
- Merchant Domain Verification via mesh
- Syncs: listings, QCoA certificates, reputation
- Tables: p2pq_listings, qcoa_certificates, p2pq_user_stats

### Website Adapter
Self-hosting static websites via mesh.
- Content-addressed storage (every file has SHA3-256 hash)
- Mesh replication across nodes
- .yak domain resolution (decentralized DNS via DOKO)
- Dashboard integration (built-in admin UI)
- DOKO identity binding for domain ownership
- MIME type handling for all common formats

---

## TEMPORAL MESH ENCODING (TME)

"Time IS the redundancy dimension"

TME encodes data across TIME rather than space:
- Atomic time synchronization (nanosecond precision)
- Configurable slice intervals
- SHA3-256 temporal hashing per slice
- TemporalSlice class with \`computeTemporalHash()\`
- Reconstruction within configurable time window

---

## REPLAY DEFENSE SYSTEM

### NonceRegistry
Prevents nonce reuse attacks.
- Cryptographic nonces (SHA3-256 + random)
- Configurable maximum nonce age
- Automatic pruning of expired nonces

### TimestampValidator
Ensures message freshness.
- Configurable maximum age and future drift
- Prevents replay of old messages
- Prevents clock manipulation attacks

### SequenceTracker
Per-sender sequence validation.
- Sliding window detection
- Detects out-of-order messages
- Prevents selective replay attacks
- Per-sender isolation

---

## RATE LIMITING

### ConnectionRateLimiter
Protects against flood attacks.
- Per-IP connection rate limiting
- Per-node message rate limiting
- Handshake rate limiting (expensive operations)
- Gossip flood protection
- Progressive ban system for violations

---

## SYBIL DEFENSE

### NAVR (Node Attestation Via Verification Requirements)
Proof-of-work challenge system.
- Configurable difficulty
- Time-bounded challenges
- SHA3-256 hash verification

### ReputationTracker
Behavioral trust scoring.
- Trust levels: trusted, normal, suspicious, banned
- NAVR solution = higher starting reputation
- Good behavior increases reputation
- Bad behavior decreases reputation

---

## GENESIS NETWORK

Code hash = Network identity. Same code → Same network.

\`\`\`javascript
// Philosophy: No authority, only mathematical truth
class GenesisNetwork {
  networkId = 'pq-' + hash.slice(0, 8);  // Human-readable
  isCompatible(peerHash);      // Check if same network
  registerPeer(peerId, hash);  // Track peer compatibility
  getCompatiblePeers();        // List same-network peers
  getIncompatiblePeers();      // List different networks
}
\`\`\`

---

## LAMA CONSENSUS ENGINE

"Many lamas, one truth" - Independent verification yields consensus.

### DharmicState
- PENDING: Received but not yet validated
- VALIDATED: Passed local validation
- CONSENSUS: Confirmed by multiple nodes
- REJECTED: Failed validation
- CONFLICT: Conflicting versions (auto-resolved)

### LamaConsensus Class
- Deterministic conflict resolution (no voting)
- Content-addressed storage (data IS identity)
- Automatic outlier rejection
- Cryptographic proof of consensus
- Network fingerprint for iO obfuscation

---

## REST API ENDPOINTS

### Core Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | Node health status |
| /node | GET | Node identity info |
| /peers | GET | Connected peers list |
| /dashboard | GET | Web dashboard UI |
| /docs | GET | Embedded documentation |
| /metrics | GET | Prometheus metrics |

### Network Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /connect | POST | Connect to peer |
| /data | POST | Submit data |
| /rumor | POST | Spread gossip |
| /gossip | GET | Gossip stats |
| /discovered | GET | Discovered peers |
| /replication | GET | Replication status |

### SHERPA Discovery
| Endpoint | Method | Description |
|----------|--------|-------------|
| /.well-known/yakmesh/beacon | GET | Beacon discovery |
| /sherpa/status | GET | Discovery status |
| /sherpa/candidates | GET | Peer candidates |

### Oracle Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /oracle/status | GET | Code proof status |
| /oracle/challenge | POST | Issue code challenge |
| /oracle/peers | GET | Verified peers |
| /oracle/submit | POST | Submit content |
| /oracle/consensus | GET | Consensus state |
| /oracle/resolve | POST | Resolve conflict |

### Network Identity (iO)
| Endpoint | Method | Description |
|----------|--------|-------------|
| /network/identity | GET | Network fingerprint |
| /network/handshake | GET | Handshake packet |
| /network/verify | POST | Verify peer |
| /network/status | GET | Network compatibility |
| /network/register-peer | POST | Register new peer |

### Time Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /time/status | GET | Time source status |
| /time/detect | GET | Detect time sources |
| /time/phase-config | GET | Phase configuration |
| /time/capabilities | GET | Timing capabilities |

### Security Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /security/status | GET | Security overview |
| /security/namche/gates | GET | Gate status |
| /security/namche/verify/:gate | POST | Verify specific gate |
| /security/doko/stats | GET | DOKO statistics |
| /security/doko/identities | GET | Known identities |
| /security/doko/verify | POST | Verify identity |

### Geographic Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /geo/status | GET | Geo proof status |
| /geo/landmarks | GET/POST | Manage landmarks |
| /geo/zones | GET | Exclusion zones |
| /geo/prove | POST | Generate proof |
| /geo/verify | POST | Verify proof |

---

## DEFAULT CONFIGURATION SCHEMA

\`\`\`javascript
const DEFAULT_CONFIG = {
  node: {
    name: 'Yakmesh Node',    // Human-readable name
    region: 'local',         // Geographic region
  },
  network: {
    httpPort: 3000,          // REST API port
    wsPort: 9001,            // WebSocket port
  },
  bootstrap: [],             // Initial peer endpoints
  database: {
    path: './data/yakmesh.db',  // SQLite path
    replication: {
      enabled: true,         // Enable mesh replication
      syncInterval: 5000,    // 5-second sync
    },
  },
};
\`\`\`

---

## HIMALAYAN NAMING CONVENTIONS
YAKMESH honors mountain peoples with Nepali/Tibetan naming:

| Protocol | Meaning |
|----------|---------|
| NAMCHE | Named after Namche Bazaar, Sherpa gateway |
| SHERPA | Mountain guides |
| KARMA | Buddhist concept of cause and effect |
| TATTVA | Sanskrit for "essence" or "truth" |
| GRANTH | Sanskrit for "text" or "scripture" |
| SURAKSHA | Hindi for "security" |
| PRAMAAN | Sanskrit for "proof" |
| DOKO | Nepali basket carried by porters |
| MANTRA | Sacred utterance |
| STUPA | Buddhist monument |
| LAMA | Tibetan teacher |
| MANI | Prayer wheels |
| MANDALA | Sacred geometric pattern |
| NAVR | Node Attestation Via Verification Requirements |
| TME | Temporal Mesh Encoding |

---

## LINKS
- Website: https://yakmesh.dev
- Documentation: https://yakmesh.dev/docs
- GitHub: https://github.com/yakmesh/yakmesh
- npm: https://npmjs.com/package/yakmesh
- Discord: https://discord.gg/8mSPfbJB8N
- Telegram: https://t.me/yakmesh
- Twitter/X: https://x.com/yakmesh_dev
- Patreon: https://patreon.com/yakmesh

## SUPPORT
- Community: Discord/Telegram (free)
- Pro Support: inquiry@peerquanta.com ($99/mo)
- Enterprise: inquiry@peerquanta.com (custom)

---

## CRYPTOGRAPHIC ALGORITHMS
- **Signatures**: ML-DSA-65 (NIST FIPS 204) - Post-quantum
- **Key Exchange**: ML-KEM-768 (NIST FIPS 203) - Post-quantum
- **Backup Signatures**: SLH-DSA - Hash-based (quantum-safe)
- **Hashing**: SHA3-256 (Keccak)
- **Symmetric**: XChaCha20-Poly1305
- **NIST Level**: 3 (128-bit post-quantum security)

---

## VERSION HISTORY
- v3.3.0: TRIBHUJ key ratchet, Gateway Attestation, SSE real-time push, ANNEX hardening, MeshBridge completion, comprehensive security audit (~90 findings addressed)
- v2.6.6: Philosophy page, Himalayan tribute, favicon fixes
- v2.6.5: Production Tailwind build, CDN removal
- v2.6.4: Win10 icon fix, sidebar toggle fix
- v2.6.0: GRANTH embedded docs, Himalayan naming, KARMA tiers
- v2.5.0: Geographic Exclusion (speed-of-light proofs)
- v2.4.0: Mathematical Trust (hardware attestation, silicon parity)
- v2.3.0: BYOND adapter, 598 tests
- v2.2.0: YAK:// Protocol, Remote Bookmarks, DOKO Revocation
`;

export default YAKMESH_KNOWLEDGE_BASE;

