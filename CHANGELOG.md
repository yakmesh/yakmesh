# Changelog

All notable changes to YAKMESH will be documented in this file.

## [2.0.0] - 2026-01-18

### 🧭 NAMCHE Gateway & 📜 DOKO Identity — The "Sherpa Security Stack"

This major release introduces **mathematical trust** — replacing certificate authorities with cryptographic proof. The mesh now verifies identity through 7 independent gates, eliminating the need to trust any central authority.

> *"The Sherpa does not prove knowledge by certificate. The Sherpa proves knowledge by walking the path."*

---

#### 🧭 NAMCHE: Network Authenticated Mesh Certificate Hub & Exchange

A 7-gate verification gateway inspired by Nepal's Namche Bazaar — the last checkpoint before Everest.

##### The 7 Gates of Verification
| Gate | Name | Verification |
|------|------|-------------|
| 1 | Cryptographic Gate | Valid ML-DSA-65 signature |
| 2 | Format Gate | DOKO structure compliance |
| 3 | Temporal Gate | Not expired, within clock tolerance |
| 4 | Domain Gate | DNS TXT record verification |
| 5 | Mesh Gate | 3+ peer endorsements (KHATA protocol) |
| 6 | Behavioral Gate | Historical trust score ≥ threshold |
| 7 | Freshness Gate | Proof-of-liveliness within 5 minutes |

##### New Module: `security/namche-gateway.js`
- `NamcheGateway` - Main verification orchestrator
- `GateResult` - Individual gate pass/fail with evidence
- `VerificationReport` - Complete 7-gate assessment
- `TrustDecision` - Final ALLOW/DENY/CHALLENGE decision

##### Trust Levels
```javascript
TRUST_LEVELS = {
  UNTRUSTED: 0,    // Failed critical gates
  BRONZE: 1,       // Passed gates 1-3 only
  SILVER: 2,       // Passed gates 1-5
  GOLD: 3,         // Passed all 7 gates
  PLATINUM: 4      // Gold + extended history
}
```

---

#### 📜 DOKO: Distributed Ownership & Key Object

Self-sovereign identity documents verified by the mesh, not a CA.

##### New Module: `security/doko-identity.js`
- `DOKODocument` - The identity document structure
- `DOKOGenerator` - Create new DOKO documents
- `DOKOValidator` - Validate document structure and signatures
- `DOKOExtensions` - Optional capability declarations

##### DOKO Structure
```javascript
{
  version: "1.0",
  type: "node" | "user" | "service" | "device",
  nodeId: "cryptographic-hash",
  publicKey: "ML-DSA-65 public key",
  created: 1737225600000,
  expires: 1768761600000,
  claims: {
    domain: "example.com",
    name: "My Node"
  },
  extensions: {
    capabilities: ["annex", "nakpak", "sherpa"],
    tlsBinding: { ... }
  },
  endorsements: [...],
  signature: "self-signature"
}
```

---

#### 🔐 mTLS Phase 1: TLS Certificate Binding

Bind DOKO identity to X.509 certificates for TLS-level verification.

##### New Module: `security/tls-binding.js`
- `DOKOCertificateGenerator` - Create X.509 certs from DOKO
- `TLSVerifier` - Verify TLS connections against DOKO
- `TLSCapabilityAdvertiser` - Announce TLS capabilities to mesh

---

#### 🤝 Hybrid Trust Model

Multi-factor trust assessment combining cryptographic proof with behavioral history.

##### New Module: `security/hybrid-trust.js`
- `TrustEvidence` - Collect evidence from multiple sources
- `HybridTrustModel` - Calculate weighted trust scores
- `TrustBasedAccessControl` - Gate features by trust level

##### Trust Factors
| Factor | Weight | Source |
|--------|--------|--------|
| Cryptographic | 40% | NAMCHE gates 1-3 |
| Social | 25% | Mesh endorsements (KHATA) |
| Behavioral | 20% | Historical interactions |
| Temporal | 15% | Identity age, freshness |

---

#### 🌐 Domain Consensus Protocol

Mesh-verified domain ownership without centralized DNS authorities.

##### New Module: `security/domain-consensus.js`
- `DomainClaim` - Claim domain ownership
- `DomainConsensus` - Multi-peer verification
- `DNSVerifier` - Check DNS TXT records

---

#### 📊 Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| NAMCHE Gateway | 37 | ✅ Passing |
| Domain Consensus | 36 | ✅ Passing |
| TLS Binding | 26 | ✅ Passing |
| Hybrid Trust | 30 | ✅ Passing |
| **Total Security** | **129** | ✅ All Passing |

---

#### 🏔️ The Sherpa Protocol Family

| Protocol | Full Name | Purpose |
|----------|-----------|---------|
| **NAMCHE** | Network Authenticated Mesh Certificate Hub & Exchange | 7-gate verification |
| **DOKO** | Distributed Ownership & Key Object | Self-sovereign identity |
| **SHERPA** | Secure Hidden Endpoint Resolution Path Architecture | Peer discovery |
| **NAKPAK** | NAK Protocol for Anonymous Kommunication | Onion routing |
| **ANNEX** | Autonomous Network Negotiated eXchange | Encrypted P2P channels |
| **KHATA** | Kryptographic Handshake for Automated Trust Acceptance | Trust distribution |

---

#### Breaking Changes

- `identity.js` replaced by `doko-identity.js` (migration guide in docs)
- Trust verification now requires NAMCHE gateway for new connections
- Minimum Node.js version: 18.0.0

#### Migration Guide

```javascript
// Before (v1.x)
import { Identity } from 'yakmesh/oracle/identity';
const id = new Identity();

// After (v2.0)
import { DOKOGenerator } from 'yakmesh/security/doko-identity';
const doko = await DOKOGenerator.create({ type: 'node', claims: { name: 'My Node' } });
```

---

## [1.8.0] - 2026-01-18

### 🏔️ SHERPA: Decentralized Peer Discovery

This release implements SHERPA, a novel peer discovery mechanism that uses the public web as a decentralized DHT.

#### New Feature: SHERPA Discovery

##### The Innovation: "The Web IS the DHT"
- Each node exposes `/.well-known/yakmesh/beacon` with its peer list
- Discovery crawls known endpoints to find new peers
- No central authority - truly decentralized bootstrap
- Works with existing CDN infrastructure

##### New Module: `mesh/sherpa-discovery.js`
- `SherpaDiscovery` - Main discovery engine with peer crawling
- `BeaconMessage` - Signed beacon format for peer advertisement
- `PeerRegistry` - Scored peer management with decay
- `createBeaconMiddleware` - Express middleware for beacon endpoint

##### New Endpoints
- `GET /.well-known/yakmesh/beacon` - Advertise this node and known peers
- `GET /sherpa/status` - Discovery statistics
- `GET /sherpa/candidates` - Get connection candidates

##### Configuration
```javascript
// yakmesh.config.js
export default {
  sherpa: {
    enabled: true,
    selfEndpoint: 'https://mynode.example.com',
    wsEndpoint: 'wss://mynode.example.com:9001',
    seeds: ['https://peer1.example.com', 'https://peer2.example.com'],
  },
};
```

##### Beacon Response Format
```json
{
  "version": "1.0",
  "nodeId": "abc123...",
  "networkName": "mobius-rabi-junction",
  "timestamp": 1737225600000,
  "capabilities": { "wsPort": 9001, "supportsAnnex": true },
  "peers": [{ "nodeId": "...", "endpoint": "https://..." }],
  "publicKey": "...",
  "signature": "..."
}
```

---

## [1.7.1] - 2026-01-18

### 🦬 NAKPAK & SHERPA: Yak-Themed Protocol Naming

This release renames dark-themed protocols to yak-themed names for brand consistency.

#### Renamed Protocols

##### NAKPAK (formerly Phantom)
- **N**ested **A**nonymous **K**ernel for **P**rivate **A**uthenticated **K**omms
- Post-quantum onion routing with ML-KEM768 key encapsulation
- File renamed: `phantom-routing.js` → `nakpak-routing.js`
- Classes renamed: `PhantomRouter` → `NakpakRouter`, etc.
- Etymology: NAK (female yak) + PAK (package) = sounds like "knapsack" 🎒

##### SHERPA (new protocol slot)
- **S**ecure **H**idden **E**ndpoint **R**esolution **P**ath **A**rchitecture
- Peer discovery DHT via public web layer
- Guides nodes to find each other like Sherpas guide travelers

#### Protocol Stack Update
```text
1. HTTP API - Public content delivery
2. Annex - Encrypted P2P messaging
3. Gossip - Message propagation
4. Beacon - Emergency broadcast
5. Nakpak - Onion routing (NEW NAME)
6. Sherpa - Peer discovery (NEW)
7. Mesh - Core P2P network
```

---

### 🛡️ SLH-DSA Backup Signatures & Monitoring Dashboard

This release adds defense-in-depth with FIPS 205 hash-based backup signatures and a comprehensive monitoring dashboard.

#### New Features

##### SLH-DSA Backup Signatures (FIPS 205)
- **Dual Algorithm Support:** ML-DSA (lattice-based) + SLH-DSA (hash-based)
- **Level 3:** SLH-DSA-SHA2-192f (hash-based, different cryptographic assumptions)
- **Level 5:** SLH-DSA-SHA2-256f (hash-based, paranoid mode)
- New functions: `signBackup()`, `verifyBackup()`, `signDual()`, `verifyDual()`
- Generate dual keypairs with `generateDualSignatureKeyPairs()`
- Defense-in-depth: if lattice assumptions break, hash-based signatures still hold

##### Monitoring Dashboard
- Updated `/dashboard` with YAKMESH branding
- New `/metrics` endpoint aggregates all node status
- **Oracle Status:** Health, network identity, verified peers
- **Crypto Info:** Active algorithms, security level, NIST standards
- **Time Source:** Trust level, stratum, precision indicators
- **Uptime Tracking:** Human-readable uptime display

##### Dev.to Automation
- GitHub Actions now posts to Dev.to on major releases
- Automated article creation with version info
- Add `DEVTO_API_KEY` to GitHub secrets to enable

#### Technical Details

##### SLH-DSA Key/Signature Sizes
| Level | Public Key | Secret Key | Signature |
|-------|------------|------------|-----------|
| 3 (192f) | 48 bytes | 96 bytes | ~35 KB |
| 5 (256f) | 64 bytes | 128 bytes | ~50 KB |

##### Performance (SLH-DSA is slower than ML-DSA)
- Sign: ~100-160ms (vs 3ms for ML-DSA)
- Verify: ~5-9ms (vs 1ms for ML-DSA)
- Use dual signatures only for high-value operations

#### Added
- `signBackup()`, `verifyBackup()` - SLH-DSA standalone operations
- `signDual()`, `verifyDual()` - Dual signature operations
- `generateDualSignatureKeyPairs()` - Generate both ML-DSA and SLH-DSA keypairs
- `getBackupSignatureAlgorithm()`, `getBackupSignatureName()` - Config accessors
- `/metrics` endpoint for comprehensive node status
- Dashboard cards for Oracle, Crypto, Time Source
- Uptime tracking with human-readable formatting

#### Changed
- `getCryptoSummary()` now includes `backupSignatureAlgorithm` and FIPS 205 in standards
- Dashboard rebranded from "Lantern Mesh" to "YAKMESH"
- `discord-release.yml` now includes Dev.to posting job

---

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
- `mesh/nakpak-routing.js` - Key derivation uses SHA3-256 (formerly phantom-routing)
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
