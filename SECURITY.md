# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously at YAKMESH™. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email**: security@yakmesh.dev

**Do NOT**:
- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before we've had a chance to address it

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days (depending on severity)

### Recognition

We appreciate responsible disclosure and will:
- Credit you in the security advisory (unless you prefer anonymity)
- Work with you to understand and resolve the issue
- Not take legal action for good-faith security research

## Security Features

YAKMESH implements multiple layers of security:

- **Post-Quantum Cryptography**: ML-DSA-65 signatures (NIST FIPS 204)
- **Authenticated Encryption**: XChaCha20-Poly1305
- **Replay Protection**: Phase-epoch based message validation
- **Code Integrity**: Self-verifying oracle with module sealing

---

## 🔒 Protected Architectural Elements

> **WARNING**: The following architectural decisions are FOUNDATIONAL.
> They MUST NOT be changed without explicit cryptographic review.

### NodeID Generation (CRITICAL)

**Location**: `identity/node-key.js`

The NodeID is a **two-part composite**:

```
node-[networkName]-[instanceId]
```

| Component | Derived From | Purpose |
|-----------|--------------|---------|
| `networkName` | Codebase hash via iO | Proves nodes run identical code |
| `instanceId` | Public key hash via iO | Unique per node instance |

**Security Properties**:
1. **Codebase Integrity** - Network name proves nodes run identical code
2. **Instance Uniqueness** - Instance ID is deterministically tied to keypair
3. **Human Verifiability** - Word-based names can be verified verbally
4. **Network Segmentation** - Different code versions form separate networks

**Rejected Simplifications**:

| Proposal | Status | Reason |
|----------|--------|--------|
| `NodeID = SHA3-256(publicKey)` | ❌ REJECTED | Removes codebase verification |
| `NodeID = base64(publicKey)` | ❌ REJECTED | Same as above, plus loses readability |
| `NodeID = UUID` | ❌ REJECTED | Breaks deterministic derivation |
| Remove codebase hash | ❌ REJECTED | Destroys network segmentation |

### iO Oracle Integration (CRITICAL)

**Location**: `oracle/`

The indistinguishability obfuscation (iO) oracle provides:
- Deterministic codebase hashing
- Network identity derivation  
- Phase modulation for replay protection

**DO NOT**:
- Bypass the oracle for "faster" identity generation
- Cache identities without oracle verification
- Accept identities that don't match expected network name

### Security Anti-Pattern Examples

```javascript
// ❌ WRONG: Simplified NodeID (NEVER DO THIS)
const nodeId = sha3_256(publicKey);

// ✅ CORRECT: Full iO-based derivation
const nodeId = generateNodeId(publicKey, codebaseHash);
```

---

## 📋 Security Review Checklist

Before merging any identity/crypto changes:

- [ ] Does it maintain the two-part NodeID structure?
- [ ] Does it preserve codebase hash in identity derivation?
- [ ] Does it use ML-DSA-65 (not classical crypto)?
- [ ] Does it verify signatures before trusting data?
- [ ] Does it respect the iO oracle's role?

---

## 🕒 Security Incident Log

| Date | Description | Resolution |
|------|-------------|------------|
| 2026-01-18 | NAMCHE spec draft proposed `NodeID = SHA3-256(publicKey)` | Rejected. Spec corrected to document actual two-part design. Security warnings added to codebase. |

---

## Known Limitations

- NTP time sources are not suitable for oracle operations (use GPS/PTP/Atomic)
- Community edition does not include WebSocket authentication (see Pro)

---

YAKMESH™ is a trademark of PeerQuanta (USPTO Serial No. 99594620)
