<div align="center">
  <img src="https://yakmesh.dev/assets/yakmesh-logo2.png" alt="YAKMESH" width="200">

  <h1>🏔️ YAKMESH™ v3.3.0 — The Hardening Release</h1>

  <p><strong>Yielding Atomic Kernel Modular Encryption Secured Hub</strong></p>

  <p>
    <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
    <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-24+-green.svg" alt="Node.js"></a>
    <a href="https://csrc.nist.gov/projects/post-quantum-cryptography"><img src="https://img.shields.io/badge/Crypto-Post--Quantum-blue.svg" alt="Post-Quantum"></a>
    <a href="https://www.npmjs.com/package/yakmesh"><img src="https://img.shields.io/npm/v/yakmesh.svg" alt="npm version"></a>
    <img src="https://img.shields.io/badge/version-3.3.0-purple.svg" alt="v3.3.0">
    <img src="https://img.shields.io/badge/Protocol_Layers-30-orange.svg" alt="30-Layer Stack">
  </p>
</div>

---

YAKMESH is a post-quantum secure P2P mesh network with a 30-layer protocol stack, heterogeneous GPU+NPU compute scheduling, and hardware-anchored precision timing. Built for the 2026 threat landscape with NIST FIPS 204/203 cryptography at every layer, YAKMESH provides a "sturdy" substrate for distributed systems that cannot afford to fail.

> **📚 Full documentation: [yakmesh.dev](https://yakmesh.dev)** | **[docs/](docs/)** for specifications

## Quick Start

```bash
npm install yakmesh
```

```javascript
import { YakmeshNode } from 'yakmesh';

const node = new YakmeshNode({
  node: { name: 'My Node' },
  network: { httpPort: 3000, wsPort: 9001 },
});

await node.start();
```

## Features

### Cryptography & Identity

- 🔒 **Post-Quantum Secure** — ML-DSA-65 (FIPS 204) signatures, ML-KEM-768 (FIPS 203) key encapsulation
- 🧬 **162-Trit Identity** — Ternary identity system with balanced-ternary encoding (YPC-27)
- 🔐 **ANNEX Channels** — ML-KEM-768 encrypted P2P sessions with forward secrecy (TRIBHUJ ratchet)
- 🧭 **NAMCHE Gateway** — 7-gate mathematical identity verification

### Networking & Discovery

- 🌐 **Mesh Networking** — P2P WebSocket mesh with epidemic gossip protocol
- 🏔️ **SHERPA Discovery** — Decentralized peer discovery with DNS beacon broadcast
- 📦 **NAKPAK Routing** — Efficient binary message routing with checksum verification
- 💬 **KOMM Stack** — Real-time communication layer (VANI messaging, GUMBA channels, KATHA sessions)

### Validation & Consensus

- 🔮 **TATTVA Oracle** — Self-verifying codebase validation; the code IS the network identity
- 📜 **DHARMA Consensus** — Multi-phase consensus engine with phase-epoch timing
- 👁️ **SAKSHI Witness** — Distributed witness protocol for transaction attestation
- 🌍 **Geographic Proof** — Speed-of-light exclusion zones for physical locality verification

### Compute & Acceleration

- ⚡ **GPU+NPU Acceleration** — Heterogeneous compute via ONNX Runtime (DirectML, CUDA, CPU fallback)
- 📊 **ComputeScheduler** — Priority-based task scheduling (CRITICAL → HIGH → NORMAL → LOW)
- 🧠 **SEVA Compute** — Distributed ML inference mesh across network peers

### Security & Monitoring

- 🛡️ **SANGHA Security** — Community-driven threat circulation and collective defense
- ⏱️ **Precision Timing** — GPS atomic clocks (MA-902), PTP, NTP with sub-millisecond sync
- 📡 **DARSHAN Telemetry** — Real-time network visibility and diagnostics
- 🏔️ **PRAHARI** — Mesh-consensus entropy engine with 5 pluggable sources and NPU-accelerated quality scoring
- ⚖️ **KARMA Rate Limiter** — Behavior-based reputation rate limiting with persistent trust scoring

### Mesh Hardening (v3.0)

- 🔗 **JHILKE Bootstrap** — Deterministic chirp key via HKDF(codeHash + buildNonce + sorted nodeIds), MITM-resistant
- 🧠 **PeerPhaseBuffer** — SharedArrayBuffer-backed peer state for zero-copy Worker thread handoff
- 🎯 **AGUWA Ternary Admission** — Weighted AFFIRM/ABSTAIN/DENY with priority scoring, REDIRECT eviction
- ⚙️ **Worker Thread Batch Kuramoto** — e-weighted phase coupling offloaded to Worker beyond capacity threshold
- 📐 **48 Spec Invariants** — 7-category structural verification (A–G) in the Validation Oracle
- 📊 **Dynamic Capacity** — `floor(64 × (log₂(threads+1) + log₂(totalTops+1)×0.5)) × networkMul × timeMul`

> See [yakmesh.dev](https://yakmesh.dev) for the complete 30-layer protocol documentation

## Architecture

```
yakmesh-node/
├── server/           # HTTP/WS server (~3,300 lines), all API routes
├── security/         # NAMCHE gateway, SANGHA, SAKSHI, trust models, geo-proof
├── oracle/           # TATTVA validation, consensus engine, code-proof, phase-epoch
├── identity/         # PQ key management, TRIBHUJ ratchet, 144T identity
├── mesh/             # SHERPA discovery, NAKPAK routing, ANNEX sessions, pulse-sync
├── gossip/           # Epidemic-style message propagation
├── protocol/         # STUPA, LAMA, MANI, KARMA, MANDALA protocol layers
├── utils/            # Hardware acceleration, ComputeScheduler (GPU+NPU)
├── cli/              # Command-line interface
├── dashboard/        # Web-based monitoring UI
├── database/         # SQLite persistence layer
├── content/          # Distributed content system
├── models/           # ONNX ML models for inference
├── embedded-docs/    # GRANTH documentation bundle (served at /docs)
├── adapters/         # Platform integration plugins (BYOND, etc.)
├── launcher/         # Process management and startup
├── webserver/        # Static web serving
├── yakbot/           # Bot integration
├── website/          # yakmesh.dev static site
├── deploy/           # Caddy/systemd deployment configs
├── deploy-packages/  # Package builder (yakbot, yakmesh basic/full)
├── reference/        # C++ reference implementations
├── docs/             # Protocol documentation site
└── tests/            # Integration tests (node:test runner)
```

## Network Identity

Each YAKMESH network has a unique identity derived from the **oracle's code hash** — the code IS the identity.

```javascript
import { deriveNetworkName, deriveVerificationPhrase } from 'yakmesh/oracle/network-identity.js';

// Same code = same network. Different code = different network.
// No configuration needed - the math handles network separation.
```

## API Reference

Full API documentation at [yakmesh.dev/docs/api](https://yakmesh.dev/docs/api)

### Core

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Node health status |
| `GET /node` | Node identity info |
| `GET /peers` | Connected peers |
| `GET /metrics` | Prometheus-compatible metrics |
| `GET /dashboard` | Web monitoring UI |

### Oracle & Consensus

| Endpoint | Description |
|----------|-------------|
| `GET /oracle/status` | Oracle integrity check |
| `GET /oracle/consensus` | Consensus state |
| `GET /oracle/peers` | Oracle peer list |
| `POST /oracle/challenge` | Challenge-response verification |
| `POST /oracle/submit` | Submit oracle data |

### Network & Mesh

| Endpoint | Description |
|----------|-------------|
| `GET /network/identity` | Network identity |
| `GET /network/status` | Network state |
| `GET /network/handshake` | Handshake data |
| `POST /connect` | Initiate peer connection |
| `POST /mesh/relay` | Relay message to peers |
| `GET /gossip` | Gossip state |
| `GET /discovered` | Discovered nodes |

### Protocol Subsystems

| Endpoint | Description |
|----------|-------------|
| `/komm/*` | KOMM real-time communication |
| `/darshan/*` | DARSHAN network telemetry |
| `GET /sherpa/status` | SHERPA peer discovery status |
| `GET /nakpak/status` | NAKPAK routing status |
| `GET /annex/status` | ANNEX encrypted channel status |
| `GET /sakshi/status` | SAKSHI witness protocol status |
| `GET /api/sangha` | SANGHA community security |
| `/content/*` | Content API |

### Timing & Compute

| Endpoint | Description |
|----------|-------------|
| `GET /time/status` | Time source detection |
| `GET /time/capabilities` | Timing hardware capabilities |
| `GET /api/time` | Full time data |
| `GET /accel` | Hardware acceleration status |
| `GET /accel/telemetry` | GPU/NPU telemetry |
| `GET /scheduler` | ComputeScheduler state |
| `GET /steadywatch` | Uptime monitoring |

### Security

| Endpoint | Description |
|----------|-------------|
| `GET /security/namche/gates` | Gateway verification status |

## License

Copyright © 2026 PeerQuanta. Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later).

YAKMESH™ is a registered trademark of PeerQuanta (Serial No. 99594620). See [TRADEMARK.md](TRADEMARK.md) for trademark usage policy.

---

<div align="center">
  <sub>Built with quantum principles. Secured by math. 30 layers deep.</sub>
  <br><br>
  <strong><a href="https://yakmesh.dev">yakmesh.dev</a></strong>
  <br><br>
  <p>
    <a href="https://discord.gg/8mSPfbJB8N">💬 Discord</a> •
    <a href="https://t.me/yakmesh">📱 Telegram</a> •
    <a href="https://x.com/yakmesh_dev">𝕏 Twitter</a> •
    <a href="https://patreon.com/yakmesh">❤️ Patreon</a>
  </p>
  <br>
  <sub>© 2026 YAKMESH™ Project. Sturdy & Secure.</sub>
  <br>
  <sub>YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).</sub>
</div>
