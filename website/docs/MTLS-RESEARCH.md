# mTLS Research: Node-to-Node Authentication for YAKMESH

**Date**: 2026-01-18  
**Status**: Research Document  
**Related**: NAMCHE Specification, Domain Consensus

---

## Executive Summary

This document explores how mutual TLS (mTLS) can enhance YAKMESH's node-to-node authentication, complementing the existing ML-DSA-65 signature-based authentication with transport-level security.

**Key Findings:**
1. mTLS without central CA is achievable using self-signed certificates bound to node identity
2. Post-quantum TLS 1.3 with ML-KEM is emerging as a standard
3. YAKMESH's existing DOKO certificates can serve as the trust anchor
4. Hybrid approach recommended: ML-DSA-65 signatures + mTLS for defense-in-depth

---

## 1. The Challenge

### Current State
YAKMESH nodes currently authenticate at the **application layer**:
- Messages are signed with ML-DSA-65 (post-quantum)
- Signatures are verified by receiving nodes
- Transport (WebSocket) may or may not use TLS

### The Gap
Without transport-layer authentication:
- Network observers can see connection metadata
- Man-in-the-middle attacks require active signature forging (hard but not impossible)
- No forward secrecy for message content

### Goal
Add **mutual TLS** where both client and server present certificates, providing:
- Transport encryption (confidentiality)
- Endpoint authentication (both sides verified)
- Forward secrecy (ephemeral keys)
- Post-quantum security (when using ML-KEM)

---

## 2. mTLS Without Central CA

### The Traditional Problem
Standard mTLS requires a Certificate Authority (CA) that both parties trust.
In a decentralized network, there is no central CA.

### Solution: Self-Certifying Identities

YAKMESH already has the primitives:
1. **Node Identity** = ML-DSA-65 keypair
2. **DOKO Certificate** = Self-signed identity document
3. **KHATA Protocol** = Certificate distribution

We can create TLS certificates that:
- Are self-signed by the node's ML-DSA-65 key
- Bind the TLS certificate to the DOKO
- Are verified against known DOKOs, not a CA

### Certificate Chain

```
┌─────────────────────────────────────────┐
│  DOKO (Distributed Ownership Key Object)│
│  - Signed by node's ML-DSA-65 key       │
│  - Contains nodeId, publicKey           │
│  - Verified via NAMCHE 7-gate check     │
└─────────────────────────────────────────┘
                    │
                    │ binds to
                    ▼
┌─────────────────────────────────────────┐
│  TLS Certificate                        │
│  - X.509 format for compatibility       │
│  - Subject: nodeId                      │
│  - Public Key: derived from DOKO        │
│  - Signed by: node's private key        │
│  - Extension: DOKO hash reference       │
└─────────────────────────────────────────┘
```

### Verification Process

When Node A connects to Node B:

1. **TLS Handshake** - Certificates exchanged
2. **Extract nodeId** - From certificate subject
3. **Lookup DOKO** - Via KHATA protocol or local cache
4. **Verify Binding** - Certificate pubkey matches DOKO pubkey
5. **NAMCHE Verify** - Run 7-gate verification on DOKO
6. **Accept/Reject** - Based on verification result

---

## 3. Post-Quantum TLS

### Current Options

| Option | Algorithm | Status | Notes |
|--------|-----------|--------|-------|
| **Hybrid TLS 1.3** | X25519 + ML-KEM-768 | Draft IETF | Best near-term option |
| **Pure ML-KEM** | ML-KEM-768/1024 | Draft IETF | Future standard |
| **ML-DSA in TLS** | ML-DSA-65/87 | Experimental | For signatures |

### ML-KEM Integration

ML-KEM (formerly Kyber) provides post-quantum key encapsulation:

```
TLS 1.3 Handshake with Hybrid Key Exchange:

Client                                    Server
  │                                         │
  │──── ClientHello ───────────────────────▶│
  │     + key_share: X25519 + ML-KEM-768    │
  │                                         │
  │◀─── ServerHello ────────────────────────│
  │     + key_share: X25519 + ML-KEM-768    │
  │                                         │
  │     [Encrypted with hybrid shared key]  │
  │◀─── Certificate (ML-DSA-65 signed) ─────│
  │◀─── CertificateVerify ──────────────────│
  │◀─── Finished ───────────────────────────│
  │                                         │
  │──── Certificate (ML-DSA-65 signed) ────▶│
  │──── CertificateVerify ─────────────────▶│
  │──── Finished ──────────────────────────▶│
  │                                         │
  │     [Application Data, fully encrypted] │
```

### Node.js Support

As of 2026, Node.js support for post-quantum TLS is emerging:

```javascript
// Future API (when available)
const tls = require('tls');

const options = {
  // Hybrid key exchange
  cipherSuites: ['TLS_AES_256_GCM_SHA384'],
  groups: ['x25519_mlkem768', 'x25519'],  // Hybrid, fallback to classical
  
  // ML-DSA certificate
  cert: loadMLDSACertificate(),
  key: loadMLDSAPrivateKey(),
  
  // Custom verification
  requestCert: true,
  rejectUnauthorized: false,  // We verify manually
  checkServerIdentity: verifyDoko,
};
```

---

## 4. Integration with NAMCHE

### Enhanced DOKO with TLS Binding

```javascript
{
  // ... existing DOKO fields ...
  
  // TLS binding (optional)
  "tls": {
    // X.509 certificate fingerprint
    "certFingerprint": "sha256:AB:CD:EF:...",
    
    // Certificate validity
    "certIssuedAt": 1737200000000,
    "certExpiresAt": 1768736000000,
    
    // Supported TLS features
    "supports": {
      "tls13": true,
      "mlkem": true,
      "hybridKeyExchange": true,
    }
  }
}
```

### Verification Flow

```javascript
async function verifyTLSConnection(peerCert, peerDoko) {
  // 1. Verify DOKO via NAMCHE gateway
  const dokoResult = await namcheGateway.verify(peerDoko);
  if (!dokoResult.valid) {
    throw new Error(`DOKO verification failed: ${dokoResult.reason}`);
  }
  
  // 2. Verify TLS certificate binds to DOKO
  const certPubKey = extractPublicKey(peerCert);
  const dokoPubKey = peerDoko.publicKey;
  
  if (certPubKey !== dokoPubKey) {
    throw new Error('TLS certificate does not match DOKO public key');
  }
  
  // 3. Verify certificate fingerprint if specified in DOKO
  if (peerDoko.tls?.certFingerprint) {
    const actualFingerprint = computeCertFingerprint(peerCert);
    if (actualFingerprint !== peerDoko.tls.certFingerprint) {
      throw new Error('Certificate fingerprint mismatch');
    }
  }
  
  // 4. Check certificate validity
  const now = Date.now();
  if (peerCert.validFrom > now || peerCert.validTo < now) {
    throw new Error('Certificate expired or not yet valid');
  }
  
  return { verified: true, nodeId: peerDoko.nodeId };
}
```

---

## 5. Certificate Pinning Strategy

### Recommended Approach

For YAKMESH, we recommend **DOKO-based pinning**:

```javascript
class DokoPinning {
  constructor() {
    this.pinnedDokos = new Map();  // nodeId -> DOKO
  }
  
  pin(doko) {
    // Only pin after NAMCHE verification
    this.pinnedDokos.set(doko.nodeId, {
      publicKey: doko.publicKey,
      dokoHash: computeDokoHash(doko),
      pinnedAt: Date.now(),
    });
  }
  
  verify(nodeId, presentedCert) {
    const pinned = this.pinnedDokos.get(nodeId);
    if (!pinned) {
      // No pin = first contact, verify via NAMCHE
      return { pinned: false };
    }
    
    // Check certificate matches pinned public key
    const certPubKey = extractPublicKey(presentedCert);
    if (certPubKey !== pinned.publicKey) {
      throw new Error('Certificate does not match pinned identity');
    }
    
    return { pinned: true, since: pinned.pinnedAt };
  }
}
```

### Key Rotation

When a node rotates keys:

1. Old DOKO is revoked via KHATA
2. New DOKO is announced
3. Peers update their pins via KHATA messages
4. Grace period allows both old and new to be accepted

---

## 6. Implementation Phases

### Phase 1: Optional TLS (Current Compatible)
- Nodes can optionally use TLS for transport
- No mTLS requirement
- SHERPA beacon advertises TLS capability

### Phase 2: TLS with DOKO Binding
- TLS certificates bound to DOKOs
- mTLS between consenting nodes
- Classical crypto (X25519, Ed25519 fallback)

### Phase 3: Hybrid Post-Quantum TLS
- ML-KEM for key exchange
- ML-DSA for signatures
- Fallback to classical for compatibility

### Phase 4: Pure Post-Quantum
- ML-KEM mandatory
- ML-DSA mandatory
- Classical algorithms deprecated

---

## 7. Security Considerations

### Advantages of mTLS + DOKO

| Property | mTLS Alone | DOKO Alone | mTLS + DOKO |
|----------|------------|------------|-------------|
| Transport encryption | ✅ | ❌ | ✅ |
| Forward secrecy | ✅ | ❌ | ✅ |
| Post-quantum signatures | ❌ | ✅ | ✅ |
| Post-quantum key exchange | ⚠️ | ❌ | ✅ |
| Decentralized trust | ❌ | ✅ | ✅ |
| Message-level auth | ❌ | ✅ | ✅ |

### Attack Mitigation

| Attack | mTLS Protection | DOKO Protection |
|--------|-----------------|-----------------|
| Passive eavesdropping | ✅ Encrypted | - |
| Active MITM | ✅ Cert verification | ✅ Signature verification |
| Replay attacks | ⚠️ Connection only | ✅ Message timestamps |
| Identity spoofing | ✅ Cert pinning | ✅ NodeID derivation |
| Key compromise | ⚠️ Single point | ✅ Revocation via KHATA |

---

## 8. Recommendations

### Short Term (Now)
1. Add TLS capability advertisement to SHERPA beacons
2. Support optional TLS for WebSocket connections
3. Document certificate generation for node operators

### Medium Term (6 months)
1. Implement DOKO-to-X.509 certificate binding
2. Add mTLS verification in mesh connections
3. Integrate with NAMCHE gateway

### Long Term (12+ months)
1. Adopt hybrid ML-KEM key exchange when Node.js supports it
2. Phase out classical-only connections
3. Full post-quantum mTLS

---

## 9. References

1. **IETF TLS 1.3 ML-KEM**: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
2. **OWASP Pinning Guide**: https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html
3. **Themis Decentralized mTLS**: https://www.cs.ox.ac.uk/files/14894/3538969.3538983.pdf
4. **NIST FIPS 203 (ML-KEM)**: https://csrc.nist.gov/pubs/fips/203/final
5. **NIST FIPS 204 (ML-DSA)**: https://csrc.nist.gov/pubs/fips/204/final

---

## 10. Conclusion

mTLS integration with YAKMESH's existing DOKO/NAMCHE system provides defense-in-depth:

- **DOKO** proves identity mathematically
- **mTLS** protects the transport layer
- **Together** they provide comprehensive security

The decentralized nature of YAKMESH eliminates the central CA problem - DOKOs verified through NAMCHE become the trust anchor for TLS certificate verification.

Post-quantum TLS (ML-KEM + ML-DSA) is the clear path forward, and YAKMESH's existing post-quantum signature infrastructure positions it well for this transition.

---

*"The SHERPA guides, the DOKO certifies, and the encrypted tunnel protects the journey."*
