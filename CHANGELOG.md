# Changelog

All notable changes to YAKMESH™ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-14

### Added
- **NAVR (Network Assimilation Validation Routine)**: Computational identity verification for new nodes
  - Replaces traditional "Proof of Work" terminology to avoid blockchain confusion
  - One-time puzzle solve during node registration (NOT mining)
  - Configurable difficulty for network defense scaling
- **Sybil Defense Module** (`mesh/sybil-defense.js`):
  - NAVR computational puzzle for identity creation
  - ReputationTracker for trust scoring (0.0 to 1.0 scale)
  - SubnetDiversity to prevent eclipse attacks (max 3 connections per /24 subnet)
- **Replay Defense Module** (`mesh/replay-defense.js`):
  - NonceRegistry with cryptographic 32-byte nonces (1hr expiry)
  - TimestampValidator (10-minute freshness window)
  - SequenceTracker for per-sender message ordering
  - ChallengeResponse for mutual node authentication
- **Message Validator Module** (`mesh/message-validator.js`):
  - Size limits per message type (1MB max, gossip 64KB, handshake 8KB)
  - Nesting depth protection (max 10 levels)
  - SafeJsonParser with prototype pollution protection
- Expanded test suite: 24 security tests covering all attack vectors

### Security
- Protection against Sybil attacks via NAVR + reputation + subnet diversity
- Protection against replay attacks via nonces + timestamps + sequences
- Protection against amplification attacks via message size limits
- Protection against eclipse attacks via subnet connection limits

## [1.0.3] - 2026-01-15

### Fixed
- **CRITICAL**: Fixed ML-DSA-65 signature verification parameter order (was: publicKey, message, signature → now: signature, message, publicKey)

### Added
- **Rate Limiter**: New `ConnectionRateLimiter` class for DoS protection
  - Connection flood protection (30 connections/minute per IP)
  - Handshake spam detection (100 handshakes/minute global)
  - Gossip message throttling (500 messages/minute)
  - Automatic cleanup of stale tracking data
- Comprehensive test suite (17 tests covering crypto, security, performance)
- Stress test suite (14 tests with edge cases)

### Security
- Integrated rate limiting into mesh/network.js WebSocket handling
- Protection against 51% / network isolation attacks via message throttling

## [1.0.2] - 2026-01-14

### Fixed
- Fixed README.md formatting for proper rendering on npm and GitHub

## [1.0.1] - 2026-01-14

### Fixed
- Removed Pro-only security module from public npm package
- Added `.npmignore` to exclude proprietary code

## [1.0.0] - 2026-01-14

### Added
- **Post-Quantum Cryptography**: ML-DSA-65 (NIST FIPS 204) signatures
- **Self-Verifying Oracle**: Deterministic validation without external trust
- **Mesh Networking**: P2P WebSocket communication with gossip protocol
- **Precision Timing**: Support for atomic clocks, GPS, PTP, NTP time sources
- **Plugin Architecture**: BaseAdapter for custom database integrations
- **Phase Modulation**: Time-based anti-replay protection
- **Network Identity**: Configurable salts for isolated network deployments
- **Code Proof Protocol**: Integrity verification for distributed code
- **Consensus Engine**: Distributed agreement on network state
- **CLI Tools**: `yakmesh init`, `yakmesh start`, `yakmesh status`
- **Dashboard**: Web-based node monitoring interface
- **Embedded Webserver**: Caddy integration for HTTPS/reverse proxy

### Security
- XChaCha20-Poly1305 encryption for message payloads
- Lattice-based cryptography resistant to quantum attacks
- Hardware timestamping support for timing attack mitigation

---

[1.0.3]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.3
[1.0.2]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.2
[1.0.1]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.1
[1.0.0]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.0

