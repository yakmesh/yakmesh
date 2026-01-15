# Changelog

All notable changes to YAKMESH will be documented in this file.

## [1.3.0] - 2026-01-15

### 🌟 Major New Systems - "A Beacon in the Darkness"

#### ECHO™ - Encrypted Coordinate Heuristic Oracle
- Privacy-preserving network topology discovery
- Virtual coordinate system for latency estimation
- Encrypted timing probes (AES-256-GCM)
- Route optimization through coordinate-based pathfinding

#### PULSE™ - Precision Universal Latency Sync Engine  
- Mesh heartbeat system with cryptographic proofs
- Node liveness detection (alive/suspect/dead states)
- Network partition detection with confidence scoring
- Raft-inspired leader election using heartbeat chains

#### PHANTOM™ - Post-quantum Hidden Anonymous Network Transmission
- **First-ever post-quantum onion routing implementation**
- ML-KEM-768 (Kyber) key encapsulation per layer
- Multi-layer encryption with temporal padding
- Decoy traffic injection (10% probability)
- Fixed packet sizing to prevent length analysis

#### BEACON™ - Broadcast Emergency Alert Channel Over Network
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

---

## [1.2.0] - 2026-01-15

### Added
- **TME™ (Temporal Mesh Encoding)** - Novel packet resilience system
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
