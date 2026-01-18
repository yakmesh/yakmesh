# Changelog

All notable changes to YAKMESH will be documented in this file.

## [1.6.0] - 2026-01-17

### 🔐 NIST Level 5 (Paranoid Mode) & Cryptographic Unification

This release adds support for NIST Level 5 security and unifies all hash operations to SHA3-256.

#### New Features

##### NIST Level 5 Support
- Configurable security levels: Level 3 (default) or Level 5 (paranoid)
- **Level 5 Algorithms:**
  - ML-DSA-87 (Dilithium5) for signatures - 256-bit classical security
  - ML-KEM-1024 (Kyber1024) for key encapsulation - 256-bit classical security
- New `security/crypto-config.js` module for centralized crypto configuration
- Runtime switchable via `setSecurityLevel(SecurityLevel.LEVEL_5)`

##### Crypto Agility Documentation
- New `docs/CRYPTO-AGILITY.md` formalizes algorithm upgrade procedures
- Version negotiation protocol for future algorithm transitions
- Monitoring list for future algorithm candidates (X-Wing, SLH-DSA, etc.)

##### Post-Quantum Test Suite
- Comprehensive cryptographic tests in `oracle/tests/crypto.test.js`
- Tests for ML-DSA-65/87, ML-KEM-768/1024
- Performance benchmarks for Level 3 vs Level 5 overhead
- Run with `npm run test:crypto`

#### Changed

##### Unified SHA3-256 Hashing
All hash operations now use SHA3-256 for post-quantum consistency:
- `oracle/network-identity.js` - HKDF now uses SHA3-256
- `oracle/phase-epoch.js` - Phase derivation uses SHA3-256
- `gossip/protocol.js` - Bloom filters and message IDs use SHA3-256
- `mesh/temporal-encoder.js` - Temporal hashes use SHA3-256
- `mesh/phantom-routing.js` - Key derivation uses SHA3-256
- `mesh/annex.js` - Session key derivation uses SHA3-256
- `mesh/echo-ranging.js` - Probe key derivation uses SHA3-256

### Added
- `security/crypto-config.js` - Centralized crypto configuration module
- `docs/CRYPTO-AGILITY.md` - Algorithm upgrade path documentation
- `oracle/tests/crypto.test.js` - PQ cryptography test suite
- `npm run test:crypto` script for running crypto tests

### Technical Details
- SHA3-256 provides 128-bit post-quantum security (Grover resistance)
- All symmetric keys derived from PQ-safe shared secrets
- No vulnerable classical asymmetric crypto in codebase

---

## [1.5.1] - 2026-01-17

### 🔧 Maintenance Release
- Port fallback system for WebSocket and HTTP servers
- Process management script (`scripts/start.sh`)
- Discord webhook integration for releases
- Minor documentation updates

---

## [1.5.0] - 2026-01-17

### 🔧 Critical Fix: Network Identity Unification

This release fixes a fundamental issue where nodes running identical code were generating different node IDs, preventing them from recognizing each other as peers on the same network.

#### The Problem (v1.4.0 and earlier)
- Node IDs were derived from **random public key** entropy
- Each node got a unique ID regardless of codebase
- Nodes couldn't verify they were on the same network by comparing node IDs

#### The Solution (v1.5.0)
- Node IDs now composed of TWO parts:
  1. **Network Name** - Derived from codebase hash (SAME for all nodes on network)
  2. **Instance ID** - Derived from public key (UNIQUE per node)
- Format: `node-[network-name]-[instance-id]`
- Example: `node-qubit-lattice-prism-pq-a7x9`

#### Human Verification
- All nodes on the same network share the same **network name** and **verification phrase**
- Users can verbally verify: "Are you on qubit-lattice-prism?"
- If network names match = same code = can peer

### Changed
- `identity/node-key.js` - Node ID generation now uses codebase hash for network name
- `server/index.js` - Oracle initialized BEFORE identity (provides codebase hash)
- `node-key.json` now stores `networkName`, `verificationPhrase`, and `codebaseHash`
- Identity automatically regenerates if codebase changes

### Added
- `setCodebaseHash()` / `getCodebaseHash()` exports from identity module
- `getNetworkIdentity()` method on NodeIdentity class
- Codebase change detection - warns and regenerates identity on code updates

### Breaking Changes
- Existing `node-key.json` files will trigger identity regeneration
- Old node IDs are no longer compatible with v1.5.0 network naming

---

## [1.4.0] - 2026-01-16

### 🔐 Yakmesh Annex - Post-Quantum Encrypted P2P Channels

#### Annex: Autonomous Network Negotiated Encrypted eXchange
- ML-KEM-768 (Kyber) key encapsulation for quantum-resistant key exchange
- AES-256-GCM authenticated encryption for message confidentiality
- Perfect Forward Secrecy - session keys rotate every 5 minutes or 10,000 messages
- Replay protection via sequence numbers in AAD
- Three-message handshake: INIT → ACCEPT → CONFIRM

### Added
- `mesh/annex.js` - Complete Annex implementation (744 lines)
- AnnexEnvelope class for encrypted message wrapping
- AnnexSession class for per-peer session management
- Annex main class for channel orchestration
- Documentation at `website/docs/annex.html`
- Whitepaper section 3.4 for Yakmesh Annex

---

## [1.3.2] - 2026-01-17

### Added
- **Public Content Delivery API** - Content-addressed storage for decentralized website hosting
- `GET /content` - List available content with stats
- `GET /content/:hash` - Fetch content by hash with optional proof
- `POST /content` - Publish content with consensus verification
- Content gossip via mesh for cross-node synchronization
- Consensus proof system for verified content

### Fixed
- Gossip protocol method calls (use `spreadRumor()` instead of `broadcast()`)
- Direct messaging via mesh instead of non-existent gossip.sendTo()

### Community
- Added social links: Discord, Telegram, X (Twitter)
- Created Discord announcement template

---

## [1.3.1] - 2026-01-16

### Security
- Hardened peer handshake protocol validation
- Enhanced network fingerprint verification in HELLO/WELCOME exchange
- Added CodebaseLock module for runtime source integrity

### Added
- 3-node test infrastructure for protocol verification
- iO-style (indistinguishability obfuscation) network identity derivation
- Human-readable network names from codebase fingerprint

### Fixed
- Config path resolution for relative/absolute paths
- Test suite node ID prefix assertion

---

## [1.3.0] - 2026-01-15

### 🌟 Major New Systems - "A Beacon in the Darkness"

#### ECHO - Encrypted Coordinate Heuristic Oracle
- Privacy-preserving network topology discovery
- Virtual coordinate system for latency estimation
- Encrypted timing probes (AES-256-GCM)
- Route optimization through coordinate-based pathfinding

#### PULSE - Precision Universal Latency Sync Engine  
- Mesh heartbeat system with cryptographic proofs
- Node liveness detection (alive/suspect/dead states)
- Network partition detection with confidence scoring
- Raft-inspired leader election using heartbeat chains

#### PHANTOM - Post-quantum Hidden Anonymous Network Transmission
- **First-ever post-quantum onion routing implementation**
- ML-KEM-768 (Kyber) key encapsulation per layer
- Multi-layer encryption with temporal padding
- Decoy traffic injection (10% probability)
- Fixed packet sizing to prevent length analysis

#### BEACON - Broadcast Emergency Alert Channel Over Network
- Priority message propagation (ROUTINE → CRITICAL)
- Flood-based protocol with intelligent deduplication
- Proof-of-receipt for delivery confirmation
- TTL-based propagation control

### 📊 Test Coverage
- 68 tests total (18 TME + 24 Security + 26 Novel Systems)
- All tests passing

### 🔐 Security Improvements
- Enhanced cryptographic hashing (SHA3-256)
- Timing attack resistance in PHANTOM
- Improved rate limiting integration

### 🛡️ Code Proof Protocol Hardening
- **CRITICAL FIX**: HELLO message now includes `networkFingerprint`
- **CRITICAL FIX**: WELCOME handler validates fingerprint, rejects mismatches (code 1008)
- Added `CodebaseLock` module for runtime source file protection
- Fixed config loading for relative/absolute path handling
- Comprehensive 3-node test suite: 17/17 tests passing
  - Same-codebase peering verification
  - Cross-codebase rejection (bidirectional)
  - N-way fingerprint isolation matrix
  - Empty/partial fingerprint attack blocking
  - Flood attack resistance (20 simultaneous rejected)
  - Fingerprint spoofing prevention

---

## [1.2.0] - 2026-01-15

### Added
- **TME (Temporal Mesh Encoding)** - Novel packet resilience system
  - Encodes data across TIME, not space
  - Temporal slicing with cryptographic chaining
  - Predictive reconstruction from timing proofs
- TME FAQ documentation
- Whitepaper (docs/WHITEPAPER.md)

---

## [1.1.0] - 2026-01-14

### Added
- **NAVR** (Network Access Verification via Resources) - Sybil defense
- Replay attack protection (nonces, timestamps, sequences)
- Message validator with size limits and depth checks
- Rate limiter for DoS protection
- Subnet diversity tracking

---

## [1.0.3] - 2026-01-15

### Fixed
- verify() function in identity module
- Rate limiter initialization

---

## [1.0.0] - 2026-01-13

### Initial Release
- ML-DSA-65 post-quantum signatures
- SQLite-based distributed oracle
- WebSocket mesh networking
- Phase-based consensus timing
