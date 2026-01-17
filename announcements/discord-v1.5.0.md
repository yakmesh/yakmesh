# Yakmesh v1.5.0 - Network Identity Unification

**🦬 Yakmesh v1.5.0 is here!**

This release introduces **Network Identity Unification** - a fundamental improvement to how nodes identify themselves and verify they're running the same code.

## 🔑 What's New

### Network Identity Unification
Node IDs now contain TWO components:
- **Network Name** - Derived from codebase hash (SAME for all nodes on network)
- **Instance ID** - Derived from public key (UNIQUE per node)

Format: `node-[network-name]-[instance-id]`
Example: `node-grid-carbide-reveal-pq-QHZx`

**Why this matters:**
✅ Nodes running identical code share the same network name
✅ Visual verification: same network name = same code = can trust peer
✅ Each node still has a unique instance identifier
✅ Human-readable verification phrases for extra confirmation

### Automatic Port Fallback
No more "port in use" crashes! If default ports (3000, 9001) are occupied, the node automatically finds the next available port.

### Process Management Script
New `scripts/start.sh` for proper background process management:
```bash
./scripts/start.sh start   # Start in background
./scripts/start.sh stop    # Clean shutdown  
./scripts/start.sh restart # Stop + start
./scripts/start.sh status  # Check if running
./scripts/start.sh logs    # View logs
```

## ⚠️ Breaking Change
Existing `node-key.json` files will trigger identity regeneration on first v1.5.0 startup. This is expected - the new format ensures network name derivation from codebase hash.

## 📦 Install/Upgrade
```bash
npm install yakmesh@1.5.0
```

---
🔗 https://yakmesh.dev | 💬 Discord: https://discord.gg/8mSPfbJB8N
