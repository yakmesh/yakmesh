# Changelog

All notable changes to YAKMESH™ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.2]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.2
[1.0.1]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.1
[1.0.0]: https://github.com/yakmesh/yakmesh/releases/tag/v1.0.0
