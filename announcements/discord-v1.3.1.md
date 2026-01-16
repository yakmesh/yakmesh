# 🦬 YAKMESH v1.3.1 — Public Content Delivery + Mesh Peering Confirmed!

Hey everyone! Big update today:

## ✅ What's New

### 🌐 Public Content Delivery API
We've added a complete **content-addressed storage system** with public delivery:

```
GET /content/:hash          → Fetch any content by its hash
GET /content/:hash/proof    → Get consensus proof for verification
POST /content/publish       → Store and gossip content to mesh
```

**Key features:**
- Content addressed by SHA3-256 hash (trustless verification)
- Consensus proofs for light client verification
- LRU caching for instant edge delivery
- Automatic mesh sync via gossip protocol

### 🔗 First Successful LAN Mesh Peering
Tested and confirmed: **two Yakmesh nodes successfully peered** with matching network fingerprints. The Code Proof Protocol verified both were running identical codebases before allowing the connection.

**Connection is as simple as:**
```powershell
POST http://localhost:3000/connect
{ "address": "ws://192.168.1.178:9001" }
```

### 📱 New Social Channels
We're now on:
- 💬 **Discord**: https://discord.gg/E62tAE2wGh
- 📱 **Telegram**: https://t.me/yakmesh  
- 𝕏 **Twitter**: https://x.com/yakmesh

## 📦 Install

```bash
npm install yakmesh@1.3.1
```

## 🔗 Links
- 🌐 Website: https://yakmesh.dev
- 📖 GitHub: https://github.com/yakmesh/yakmesh
- 📦 npm: https://npmjs.com/package/yakmesh

---

**What's next?**
- Multi-node cluster testing
- Production deployment
- Website/webapp hosting demos

Questions? Drop them here! 🦬
