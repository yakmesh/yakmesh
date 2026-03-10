# ROADMAP v3.3.0 — The Hardening Release

> Released 2026-03-10

## Overview

v3.3.0 is the **Hardening Release** — a comprehensive security and resilience audit across the entire yakmesh stack. Three new protocols, six ANNEX session fixes, 48 spec invariants, Worker thread offloading, and an AGPL license migration.

## New Protocols

### AGUWA — Adaptive Phase Coupling (Layer 16.5)

Kuramoto oscillator model for adaptive mesh synchronization. AGUWA couples MANI clocks using exponential-decay weighted phase differences, dynamically adjusting connection capacity based on network conditions.

- **Kuramoto coupling formula** with natural frequency derived from bootstrap/peer/gps/ntp sources
- **AGUWA score** weights: uptime (0.4), peerCount (0.2), maniSync (0.2), gossipLag (0.2)
- **PeerPhaseBuffer** — SharedArrayBuffer with 32-byte slots per peer
- **Dynamic capacity** — `maxPeers × networkMul × timeMul` adjusted in real-time
- **Worker thread offloading** — CPU-intensive coupling moved off main thread
- **GPS calibration** and order parameter calculation

### SAMUHA — Weighted Admission (Layer 17.5)

Ternary admission control replacing binary accept/reject:

- **Three verdicts**: ADMIT (+1), HOLD (0), REDIRECT (−1)
- **Priority formula**: `0.3×karma + 0.3×hw + 0.2×returning + 0.2×mani`
- **Utilization thresholds**: <0.8 admit all, 0.8–1.0 priority scoring, ≥1.0 redirect low-priority
- **REDIRECT eviction** — low-priority connected peers displaced by high-priority arrivals
- **Burst detection** — 30 connections/min IP rate limit
- **Concurrent handshake limit** — 50 max simultaneous

### SANGHA — Collective Attestation (Layer 23.5)

Component-level attestation with synapse mesh:

- **6 registered components**: CRYPTO, MESH, ORACLE, ACCEL, HTTP, IDENTITY
- **Synapse mesh**: N(N−1)/2 = 15 bidirectional channels
- **State machine**: HARMONIOUS (+1) → CONVERGING (0) → DISRUPTED (−1)
- **Attestation windows**: 100ms (CRYPTO) to 2000ms (HTTP) per component
- **FileGuardian**: SHA3-256 hash monitoring of machine-seed.json (CRITICAL), node-key.json (HIGH), yakmesh.db (NORMAL)
- **Memory canaries** — runtime data structure corruption detection

## ANNEX Session Hardening

Six bugs discovered and fixed in the ANNEX encrypted P2P session layer:

1. **Session ID entropy** — Increased from 16 to 32 bytes CSPRNG
2. **Replay window timing** — Monotonic clock checks close race condition
3. **GCM nonce rotation** — Rekey before 2³² invocations
4. **Handshake timeout** — Incomplete ML-KEM handshakes terminated after 10s
5. **Error message sanitization** — No internal state leakage to remote peers
6. **Sequence number overflow** — BigInt-backed counters prevent wraparound

## Spec Invariants

48 machine-verifiable spec invariants added across the codebase with `node:test` runner. Coverage includes ANNEX session lifecycle, TRIBHUJ ternary operations, SANGHA state transitions, and SAMUHA admission logic.

## Worker Thread Offloading

CPU-intensive operations moved to Worker threads to keep the main event loop responsive:

- AGUWA phase coupling calculations
- Batch ML-DSA-65 signature verification
- SHA3-256 bulk hashing operations

## License Migration

Migrated from MIT to **AGPL-3.0-or-later** — ensuring network-accessible derivatives share their source code.

## Migration Notes

- No breaking API changes
- No configuration changes required
- Existing nodes auto-upgrade via standard `npm update`
- New `GET /api/aguwa`, `GET /api/samuha`, `GET /api/sangha` endpoints available
- SANGHA state visible in `GET /health` response
