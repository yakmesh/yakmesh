# 🦬 YAKMESH™ v1.4.0 — Annex Encrypted P2P + Trademark Cleanup!

Hey everyone! Fresh release just dropped:

## ✅ What's New

### 🔐 Yakmesh Annex - Encrypted Point-to-Point Messaging
**A**utonomous **N**etwork **N**egotiated **E**ncrypted e**X**change

Finally! Secure direct messaging between peers with:
- **ML-KEM768 (Kyber)** - Quantum-resistant key exchange
- **AES-256-GCM** - Authenticated symmetric encryption
- **Perfect Forward Secrecy** - Auto re-keys every 5 minutes
- **Replay Protection** - Sequence numbers + authenticated data

```javascript
// Send encrypted message to peer
await node.annex.send(peerId, { 
  type: 'private',
  data: 'Only you can read this!' 
});

// Receive encrypted messages
node.annex.onMessage(({ from, payload }) => {
  console.log(`Secret from ${from}:`, payload);
});
```

**Use cases:**
- 🔔 Beacon acknowledgments with encryption
- 📦 Authenticated content delivery
- 💬 Private peer-to-peer chat
- 🔑 App-specific secure payloads

### ⚖️ Trademark Cleanup
We did a legal sweep and removed ™ claims from protocol names that conflict with existing trademarks:
- Yakmesh Phantom (was PHANTOM)
- Yakmesh Beacon (was BEACON)
- Yakmesh Echo (was ECHO)
- Yakmesh Pulse (was PULSE)
- Yakmesh Annex (new!)

**YAKMESH™ remains our registered trademark** - we own the patent! 🎉

### 🐛 Bug Fixes
- Fixed gossip propagation for content distribution
- Messages now properly wrapped with type field for routing
- Multi-node content sync working reliably

## 📊 Protocol Stack

```
┌─────────────────────────────────────────┐
│ HTTP API        │ Public CDN layer      │
├─────────────────┼───────────────────────┤
│ Annex          │ ML-KEM768 + AES-256   │  ← NEW!
├─────────────────┼───────────────────────┤
│ Gossip         │ ML-DSA-65 signed      │
├─────────────────┼───────────────────────┤
│ Beacon         │ Flood + signed        │
├─────────────────┼───────────────────────┤
│ Phantom        │ Onion + multi-KEM     │
├─────────────────┼───────────────────────┤
│ Mesh           │ ML-DSA-65 + Code Proof│
└─────────────────┴───────────────────────┘
```

## 📦 Install

```bash
npm install yakmesh@1.4.0
```

## 🔗 Links
- 🌐 Website: https://yakmesh.dev
- 📖 GitHub: https://github.com/yakmesh/yakmesh
- 📦 npm: https://npmjs.com/package/yakmesh

---

**What's next?**
- Test Annex with multi-node encrypted messaging
- Deployment packages for easy self-hosting
- More protocol integrations

Questions? Drop them here! 🦬
