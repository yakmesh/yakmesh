# 🏔️ YAKMESH™ v1.8.0 — SHERPA Peer Discovery is Here!

## 🆕 What's New

### 🏔️ SHERPA - Decentralized Peer Discovery
**S**ecure **H**idden **E**ndpoint **R**esolution **P**ath **A**rchitecture

The web IS the DHT! SHERPA uses public web endpoints as a decentralized peer discovery mechanism.

✨ **Features:**
- No central bootstrap servers required
- Each node exposes `/.well-known/yakmesh/beacon`
- Works through CDNs, firewalls, and proxies (standard HTTPS)
- Cryptographically signed beacons (ML-DSA-65)
- Scored peer registry with automatic eviction
- Periodic re-crawl for network health

```javascript
// Configure SHERPA
export default {
  sherpa: {
    selfEndpoint: 'https://mynode.example.com',
    seedEndpoints: ['https://peerquanta.com'],
  }
};
```

### 🎒 NAKPAK - Post-Quantum Onion Routing
**N**ested **A**nonymous **K**ernel for **P**rivate **A**uthenticated **K**omms

Previously "Phantom" - now with a proper Himalayan name!
- ML-KEM768 key encapsulation at each hop
- 3+ relay anonymous routing
- Source and destination privacy

## 📊 Protocol Stack (v1.8.0)

```
Layer 1: HTTP API  🌐  Public content delivery
Layer 2: Annex     🔐  Encrypted P2P (ML-KEM768)
Layer 3: Gossip    📢  Message propagation
Layer 4: Beacon    🚨  Emergency broadcast
Layer 5: Nakpak    🎒  Onion routing
Layer 6: Sherpa    🏔️  Peer discovery
Layer 7: Mesh      🕸️  Core P2P network
```

## 📦 Install

```bash
npm install yakmesh@1.8.0
npx yakmesh init
npx yakmesh start
```

## 🔗 Links

- 📖 Docs: https://yakmesh.dev/docs/sherpa.html
- 🐙 GitHub: https://github.com/yakmesh/yakmesh
- 📦 npm: https://npmjs.com/package/yakmesh

---

*Sherpas guide travelers through hidden mountain paths, just like SHERPA guides nodes to discover each other.* 🏔️

#YAKMESH #PostQuantum #P2P #Decentralized #OpenSource
