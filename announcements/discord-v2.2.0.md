# 🏔️ YAKMESH™ v2.2.0 — YAK:// Protocol, Remote Bookmarks & DOKO Revocation!

## 🆕 What's New

This is a **mega release** combining v2.0.1, v2.1.0, and v2.2.0 features!

### 🔗 YAK:// Protocol - Escape HTTP Entirely!

Custom URL protocol for mesh-native addressing. No more `http://localhost:3000`!

```
yak://dashboard          → Node dashboard
yak://peers              → Connected peers
yak://content/<hash>     → Content by hash
yak://alice              → Your personal bookmark
```

✨ **Features:**
- Custom URL scheme registered with your OS
- Built-in routes for all node endpoints
- Content addressing via hash
- Personal bookmarks (pet names)

### 📚 Remote Bookmarks - Mesh Gossip Sync

Share bookmark lists between nodes automatically!

```javascript
// Subscribe to another node's bookmarks
sync.subscribe('trusted-node-id');

// Publish your bookmarks to the mesh
sync.publish('my-bookmarks');

// Resolve remote bookmarks
sync.resolveRemote('alice'); // From subscribed node
```

✨ **Features:**
- Gossip protocol sync
- Subscribe to trusted nodes
- Publish your bookmark lists
- Local always overrides remote
- Dashboard UI for management

### 🔐 DOKO Revocation - Key Compromise Recovery

Emergency revocation system for compromised identities.

```javascript
// Self-revoke if key is still accessible
const cert = revocation.revoke(dokoId, 'KEY_COMPROMISED', privateKey);

// Emergency "break-glass" certificate (if primary key lost)
const emergency = revocation.createEmergencyCertificate(dokoId, reason, backupKey);
```

**Revocation Reasons:**
- `KEY_COMPROMISED` - Private key leaked
- `DOKO_SUPERSEDED` - Replaced by new identity
- `IDENTITY_RETIRED` - Voluntary retirement
- `LOST_ACCESS` - Cannot access keys
- `AFFILIATION_ENDED` - Left organization

### ✅ 352 Tests Passing!

| Suite | Tests |
|-------|-------|
| Oracle | 98 |
| Protocol | 56 |
| Multi-Node | 18 |
| Security | 180 |
| **Total** | **352** |

### 📝 Also Included

- **SSL/TLS Binding** - Bind certificates to DOKO identities
- **Domain Transfers** - Secure ownership transfer workflow
- **TypeScript Definitions** - Full `.d.ts` types
- **Vitest Config** - Clean test output
- **npm Scripts** - `test:oracle`, `test:protocol`, `test:security`
- **Bug Fixes** - ML-DSA-65 argument order, beacon signatures

## 📦 Install

```bash
npm install yakmesh@2.2.0
```

## 🔗 Links

- **Docs**: https://yakmesh.dev
- **GitHub**: https://github.com/yakmesh/yakmesh
- **npm**: https://www.npmjs.com/package/yakmesh
- **Discord**: https://discord.gg/8mSPfbJB8N
- **Telegram**: https://t.me/yakmesh
- **Patreon**: https://patreon.com/yakmesh

---

*"The Yak carries your bookmarks across the mesh"* 🦬📚
