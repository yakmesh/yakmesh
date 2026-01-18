# 🔐 YAKMESH v1.6.0 - NIST Level 5 & Cryptographic Unification

**The paranoid mode has arrived.**

## What's New

### 🛡️ NIST Level 5 Support (Paranoid Mode)
Choose your security level:
- **Level 3** (default): ML-DSA-65/ML-KEM-768 - ~192-bit classical security  
- **Level 5** (paranoid): ML-DSA-87/ML-KEM-1024 - ~256-bit classical security

```javascript
import { setSecurityLevel, SecurityLevel } from 'yakmesh/security/crypto-config';
setSecurityLevel(SecurityLevel.LEVEL_5);  // Maximum security
```

### 🔄 SHA3-256 Everywhere
All hash operations now use SHA3-256 for post-quantum consistency:
- Bloom filter hashing in gossip protocol
- Temporal mesh encoding
- Phantom routing key derivation
- Annex session keys
- Echo ranging probes

**Why?** SHA3-256 provides 128-bit quantum security (Grover resistance) with its sponge construction.

### 📋 Crypto Agility Documentation
New `docs/CRYPTO-AGILITY.md` formalizes our algorithm upgrade path:
- When to upgrade (NIST recommendations, new attacks, standards updates)
- 90-day dual-algorithm transition periods
- Version negotiation between nodes

### ✅ 36-Test PQ Crypto Suite
Comprehensive validation of all cryptographic operations:
```bash
npm run test:crypto
```
Tests ML-DSA-65/87, ML-KEM-768/1024, SHA3-256, and full handshake simulations.

## Upgrade
```bash
npm install yakmesh@1.6.0
```

---

**No classical asymmetric crypto. Only post-quantum. Only math.**

🦬 https://yakmesh.dev | 📦 npm: yakmesh
