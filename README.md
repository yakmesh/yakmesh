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

## Why YAKMESH?

In an era where traditional ECDSA is increasingly vulnerable and network jitter can desynchronize global state, YAKMESH offers a three-pillar solution:

🌿 **Yielding Resilience**: A self-healing mesh topology that adapts to node failure and adversarial interference without central authority.

⚛️ **Atomic Precision**: Integrated support for PCIe atomic clock hardware, enabling hardware timestamping with support for high-precision time sources for low-latency synchronization.

🔐 **Quantum Hardened**: Fully compatible with Project Zond and the QRL (Quantum Resistant Ledger) ecosystem, utilizing stateless lattice-based signatures (ML-DSA) from Genesis.

---

## The Y.A.K.M.E.S.H. Philosophy

| Letter | Principle | Description |
|--------|-----------|-------------|
| **Y** | **Yielding** | Not brittle; flexible enough to absorb network shocks |
| **A** | **Atomic** | Grounded in the absolute truth of physical time |
| **K** | **Kernel** | The essential, innermost part of the secure stack |
| **M** | **Modular** | Swap out encryption primitives or transport layers as tech evolves |
| **E** | **Encryption** | Privacy and integrity by default |
| **S** | **Secured** | Hardened against both classical and quantum vectors |
| **H** | **Hub** | A nexus for decentralized data and peer-to-peer logic |

---

## Features

- 🔒 **Post-Quantum Secure** - ML-DSA-65 (NIST FIPS 204) signatures
- 🔮 **Self-Verifying Oracle** - Deterministic validation without external trust
- 🌐 **Mesh Networking** - P2P WebSocket communication with gossip protocol
- ⏱️ **Precision Timing** - Support for atomic clocks, GPS, PTP, NTP
- 🔌 **Plugin Architecture** - Adapters for any database or API
- 🛡️ **Phase Modulation** - Time-based anti-replay protection
- 🌍 **Geographic Exclusion** - Speed-of-light physics prove where nodes CANNOT be

### v2.5 — The Complete Stack

**Identity & Trust:**
- 🧭 **NAMCHE Gateway** - 7-gate mathematical verification (no CA required)
- 📜 **DOKO Identity** - Self-sovereign identity documents verified by mesh
- 🏆 **Trust Tiers** - ORACLE/ANCHOR/SENTINEL/PARTICIPANT hierarchy
- 🔬 **Hardware Attestation** - AES-NI timing proves real silicon
- ⚖️ **Silicon Parity** - "One silicon = one vote" anti-farm defense
- ⚠️ **Strike System** - Three strikes with hardware fingerprint tracking

**Networking:**
- 🏔️ **SHERPA Discovery** - Decentralized peer discovery via public web beacons
- 🎒 **NAKPAK Routing** - Post-quantum onion routing for anonymity
- 🔐 **ANNEX Channels** - ML-KEM768 encrypted P2P with perfect forward secrecy
- 🔗 **YAK:// Protocol** - Mesh-native URL scheme with bookmarks

**Advanced:**
- 🌍 **Geographic Proof** - Speed-of-light exclusion zones
- 🕵️ **Sybil Detection** - Graph analysis for fake identity clusters
- 📡 **ECHO Ranging** - Privacy-preserving topology discovery
- 💓 **PULSE Heartbeat** - Liveness detection and partition recovery
- 🚨 **BEACON Alerts** - Priority emergency broadcast

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

## CLI

```bash
# Initialize a new node
npx yakmesh init

# Start the node
npx yakmesh start

# Check status
npx yakmesh status
```

## Documentation

Full documentation available at **[yakmesh.dev](https://yakmesh.dev)**

## Architecture

```
yakmesh/
├── security/         # NAMCHE gateway, DOKO identity, trust models
│   ├── namche-gateway.js    # 7-gate verification
│   ├── doko-identity.js     # Self-sovereign identity
│   ├── hybrid-trust.js      # Multi-factor trust scoring
│   ├── tls-binding.js       # mTLS certificate binding
│   ├── domain-consensus.js  # Mesh-verified domains
│   └── geo-proof.js         # Speed-of-light geographic exclusion
├── oracle/           # Self-verifying validation engine
├── mesh/             # WebSocket P2P networking
│   ├── sherpa-discovery.js  # Decentralized peer discovery
│   ├── nakpak-routing.js    # Onion routing
│   └── annex-channel.js     # Encrypted P2P channels
├── gossip/           # Epidemic-style message propagation
├── adapters/         # Platform integration plugins
├── webserver/        # Embedded Caddy web server
└── server/           # HTTP/WS server
```

## Network Identity

Each YAKMESH network has a unique identity derived from configurable salts:

```javascript
import { setIdentityConfig } from 'yakmesh/oracle/network-identity.js';

setIdentityConfig({
  networkPrefix: 'my',           // Network ID prefix
  identitySalt: 'my-app-v1',     // Unique network salt
});

// Different salt = different network (cannot interoperate)
```

## Time Source Trust Levels

| Level | Source | Tolerance | Oracle Capable |
|-------|--------|-----------|----------------|
| ATOMIC | PCIe atomic clock | ±100ms | ✅ Yes |
| GPS | GPS with PPS | ±500ms | ✅ Yes |
| PTP | IEEE 1588 (Meinberg) | ±500ms | ⚠️ Partial |
| NTP | Standard NTP | ±5000ms | ❌ No |

## Adapters

Create custom adapters by extending `BaseAdapter`:

```javascript
import { BaseAdapter } from 'yakmesh/adapters/base-adapter.js';

class MyAdapter extends BaseAdapter {
  async init() { /* Connect to your database */ }
  getSchema() { return { tables: ['users', 'orders'] }; }
  async fetchChanges(since) { /* Return changed records */ }
  async applyChange(table, record, op) { /* Write to database */ }
}
```

### Official Adapters

- `@yakmesh/adapter-peerquanta` - PeerQuanta phpBB marketplace

## v2.2.0 — YAK:// Protocol & Identity Recovery

### 🔗 YAK:// Protocol

Custom URL protocol for mesh-native addressing. Escape HTTP entirely!

```bash
# Built-in routes
yak://dashboard          # Node dashboard
yak://peers              # Connected peers
yak://content/<hash>     # Content by hash

# Personal bookmarks (pet names)
yakmesh bookmark add alice /site/alice-homepage
yak://alice              # Opens your bookmark
```

### 📚 Remote Bookmarks

Share bookmark lists between nodes via gossip protocol:

```javascript
import { getRemoteBookmarkSync } from 'yakmesh/protocol/yak-protocol';

const sync = getRemoteBookmarkSync({ nodeId: 'my-node' });

// Subscribe to another node's bookmarks
sync.subscribe('trusted-node-id');

// Publish your bookmarks to the mesh
sync.publish('my-bookmarks', ['project', 'docs', 'friends']);

// Resolve remote bookmarks
sync.resolveRemote('alice'); // Returns target from subscribed node
```

### 🔐 DOKO Revocation

Key compromise recovery with self-revocation and emergency "break-glass" certificates:

```javascript
import { DOKORevocation, REVOCATION_REASONS } from 'yakmesh/security/doko-identity';

const revocation = new DOKORevocation({ generator, nodeId });

// Normal self-revocation
const cert = revocation.revoke(dokoId, REVOCATION_REASONS.KEY_COMPROMISED, privateKey);

// Emergency revocation (primary key compromised, use backup)
const emergencyCert = revocation.createEmergencyCertificate(
  dokoId, 
  REVOCATION_REASONS.KEY_COMPROMISED, 
  backupPrivateKey
);

// Check revocation status
revocation.isRevoked(dokoId); // true
```

**Revocation Reasons:**
- `KEY_COMPROMISED` - Private key was exposed
- `DOKO_SUPERSEDED` - Replaced with new identity
- `IDENTITY_RETIRED` - No longer in use
- `LOST_ACCESS` - Cannot access keys
- `AFFILIATION_ENDED` - Organization membership ended

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Node health status |
| `/node` | GET | Node identity info |
| `/peers` | GET | Connected peers |
| `/oracle/status` | GET | Oracle integrity check |
| `/network/identity` | GET | Network identity (hash obfuscated) |
| `/time/status` | GET | Time source detection |
| `/time/capabilities` | GET | Time oracle eligibility |
| `/connect` | POST | Connect to a peer |
| `/bookmarks` | GET | List local bookmarks |
| `/bookmarks` | POST | Add a bookmark |
| `/bookmarks/:name` | DELETE | Remove a bookmark |
| `/bookmarks/remote` | GET | List remote bookmarks |
| `/bookmarks/remote/subscribe` | POST | Subscribe to node |
| `/bookmarks/remote/publish` | POST | Publish bookmark list |
| `/bookmarks/remote/status` | GET | Remote sync status |
| `/security/doko/stats` | GET | DOKO identity stats |
| `/security/namche/gates` | GET | Gateway verification status |
| `/geo/status` | GET | Geographic proof status |
| `/geo/landmarks` | GET/POST | List or add landmarks |
| `/geo/zones` | GET | List exclusion zones |
| `/geo/prove` | POST | Generate geographic proof |
| `/geo/verify` | POST | Verify another node's claims |

## Pro Features

YAKMESH Pro includes additional security features:

- 🔐 **WebSocket Authentication** - Challenge-response auth with signatures
- 🔒 **Message Encryption** - XChaCha20-Poly1305 encrypted messages
- 📋 **Peer Allowlist/Blocklist** - Access control for private networks
- 🛡️ **Connection Rate Limiting** - DDoS protection

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
