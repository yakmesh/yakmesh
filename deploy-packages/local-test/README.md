<div align="center">
  <img src="https://yakmesh.dev/assets/yakmesh-logo2.png" alt="YAKMESH" width="200">

  <h1>🏔️ YAKMESH™: Sturdy & Secure</h1>

  <p><strong>Yielding Atomic Kernel Modular Encryption Secured Hub</strong></p>

  <p>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-18+-green.svg" alt="Node.js"></a>
    <a href="https://csrc.nist.gov/projects/post-quantum-cryptography"><img src="https://img.shields.io/badge/Crypto-Post--Quantum-blue.svg" alt="Post-Quantum"></a>
    <a href="https://www.npmjs.com/package/yakmesh"><img src="https://img.shields.io/npm/v/yakmesh.svg" alt="npm version"></a>
  </p>
</div>

---

YAKMESH is a high-resiliency, decentralized networking layer designed for the 2026 threat landscape. Built with quantum-resistant cryptography at its core and anchored by PCIe atomic timing synchronization, YAKMESH provides a "sturdy" substrate for distributed systems that cannot afford to fail.

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

- 🔒 **Post-Quantum Secure** - ML-DSA-65 (NIST FIPS 204) signatures
- 🔮 **TATTVA Oracle** - Self-verifying validation without external trust
- 🌐 **Mesh Networking** - P2P WebSocket communication with gossip protocol
- ⏱️ **Precision Timing** - Support for atomic clocks, GPS, PTP, NTP
- 🧭 **NAMCHE Gateway** - 7-gate mathematical identity verification
- 🏔️ **SHERPA Discovery** - Decentralized peer discovery
- 🔐 **ANNEX Channels** - ML-KEM768 encrypted P2P with forward secrecy
- 🌍 **Geographic Proof** - Speed-of-light exclusion zones

> See [yakmesh.dev](https://yakmesh.dev) for complete feature documentation

## Architecture

```
yakmesh/
├── security/         # NAMCHE gateway, DOKO identity, trust models
├── oracle/           # TATTVA self-verifying validation engine
├── mesh/             # SHERPA, NAKPAK, ANNEX networking
├── gossip/           # Epidemic-style message propagation
├── protocol/         # STUPA, LAMA, MANI, KARMA, MANDALA
├── adapters/         # Platform integration plugins
├── embedded-docs/    # GRANTH documentation bundle
└── server/           # HTTP/WS server
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

| Endpoint | Description |
|----------|-------------|
| `/health` | Node health status |
| `/node` | Node identity info |
| `/peers` | Connected peers |
| `/oracle/status` | Oracle integrity check |
| `/network/identity` | Network identity |
| `/time/status` | Time source detection |
| `/security/namche/gates` | Gateway verification status |
| `/geo/status` | Geographic proof status |

## License

- **Community Edition**: MIT License (see [LICENSE](LICENSE))
- **Pro Edition**: Proprietary License

See [TRADEMARK.md](TRADEMARK.md) for trademark usage policy.

---

<div align="center">
  <sub>Built with quantum principles. Secured by math.</sub>
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

