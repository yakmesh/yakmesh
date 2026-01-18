# Cryptographic Agility in Yakmesh

This document formalizes Yakmesh's approach to cryptographic agility—the ability to transition between cryptographic algorithms as standards evolve and new threats emerge.

## Current Cryptographic Stack

| Purpose | Algorithm | Standard | Security Level |
|---------|-----------|----------|----------------|
| **Digital Signatures** | ML-DSA-65/87 | FIPS 204 | NIST Level 3/5 |
| **Key Encapsulation** | ML-KEM-768/1024 | FIPS 203 | NIST Level 3/5 |
| **Symmetric Encryption** | AES-256-GCM | FIPS 197 | 256-bit |
| **Hash Functions** | SHA3-256 | FIPS 202 | 256-bit |
| **Key Derivation** | HKDF-SHA3-256 | RFC 5869 | 256-bit |

## Security Level Selection

Yakmesh supports two NIST security levels:

### Level 3 (Default)
- **Signature**: ML-DSA-65 (Dilithium3)
- **KEM**: ML-KEM-768 (Kyber768)
- **Classical Security**: ~192 bits
- **Quantum Security**: ~128 bits
- **Use Case**: Standard operations, good performance

### Level 5 (Paranoid Mode)
- **Signature**: ML-DSA-87 (Dilithium5)
- **KEM**: ML-KEM-1024 (Kyber1024)
- **Classical Security**: ~256 bits
- **Quantum Security**: ~192 bits
- **Use Case**: High-security environments, long-term secrets

## Configuration

Set security level in `yakmesh.config.js`:

```javascript
export default {
  security: {
    level: 5,  // 3 = default, 5 = paranoid
  },
  // ... other config
};
```

Or programmatically:

```javascript
import { setSecurityLevel, SecurityLevel } from 'yakmesh/security/crypto-config';
setSecurityLevel(SecurityLevel.LEVEL_5);
```

## Algorithm Upgrade Path

### When to Upgrade

1. **NIST Recommendations Change**: If NIST deprecates an algorithm
2. **New Attacks Published**: If cryptanalysis weakens security margins
3. **Performance Improvements**: When newer algorithms offer better performance
4. **Standard Updates**: When FIPS standards are revised

### Upgrade Procedure

1. **Announce Deprecation** (T-90 days)
   - Publish security advisory
   - Update documentation
   - Begin dual-algorithm support period

2. **Dual Support Period** (90 days)
   - Accept both old and new algorithms
   - Log deprecation warnings for old algorithm usage
   - Allow nodes to upgrade at their own pace

3. **Cutover** (T+0)
   - Stop accepting old algorithms for new connections
   - Existing sessions continue until natural expiry
   - All new handshakes require new algorithm

4. **Cleanup** (T+30)
   - Remove old algorithm code
   - Update minimum version requirements

### Version Negotiation

During handshake, nodes exchange supported algorithms:

```json
{
  "supportedAlgorithms": {
    "signature": ["ML-DSA-87", "ML-DSA-65"],
    "kem": ["ML-KEM-1024", "ML-KEM-768"]
  },
  "preferredLevel": 5
}
```

Nodes select the highest mutually-supported level.

## Future Algorithm Candidates

### Monitoring List

| Algorithm | Type | Status | Notes |
|-----------|------|--------|-------|
| **X-Wing** | Hybrid KEM | Draft | ML-KEM + X25519 hybrid |
| **SLH-DSA** | Signature | FIPS 205 | Hash-based, different assumptions |
| **HQC** | KEM | Round 4 | Code-based alternative to ML-KEM |
| **BIKE** | KEM | Round 4 | Code-based alternative |

### Hybrid Approach (Future)

When NIST finalizes hybrid standards, Yakmesh will support:

```
SharedSecret = KDF(ML-KEM-SharedSecret || X25519-SharedSecret)
```

This provides defense-in-depth: both PQ and classical algorithms must be broken.

## Hash Function Strategy

### Current: SHA3-256 Everywhere

Yakmesh uses SHA3-256 (Keccak) for all hashing:
- Content addressing
- Oracle validation  
- Key derivation context
- Bloom filter hashing

### Rationale

1. **SHA3 is Grover-resistant**: 256-bit hash provides 128-bit quantum security
2. **Different construction**: SHA3 uses sponge construction vs SHA2's Merkle-Damgård
3. **No length-extension**: SHA3 is immune to length-extension attacks
4. **Future-proof**: Native 256-bit output without truncation

## Backward Compatibility

### Node Identity Continuity

When upgrading algorithms:
- Node IDs remain stable (derived from codebase hash)
- Public keys are regenerated with new algorithm
- Key rotation is transparent to peers

### Message Format

Crypto parameters are included in message headers:

```json
{
  "cryptoVersion": "1.6.0",
  "signatureAlgo": "ML-DSA-65",
  "kemAlgo": "ML-KEM-768",
  "hashAlgo": "SHA3-256"
}
```

Receivers validate algorithm support before processing.

## Security Considerations

### Key Storage

- Private keys are stored locally in `data/node-key.json`
- Keys are never transmitted over the network
- Consider HSM integration for enterprise deployments

### Algorithm Downgrades

- Yakmesh REJECTS algorithm downgrade attempts
- If peer offers only deprecated algorithms, connection fails
- Log all downgrade attempts for security monitoring

### Side-Channel Resistance

The `@noble/post-quantum` library includes:
- Constant-time implementations
- Memory-hard operations where applicable
- No branching on secret data

## Audit Trail

All cryptographic changes are logged:

| Version | Date | Change | Rationale |
|---------|------|--------|-----------|
| 1.0.0 | 2025-12 | Initial ML-DSA-65/ML-KEM-768 | FIPS 203/204 released |
| 1.4.0 | 2026-01 | Added ANNEX (ML-KEM-768) | P2P encryption |
| 1.6.0 | 2026-01 | Added Level 5 option | Paranoid mode |

## References

- [NIST FIPS 203](https://csrc.nist.gov/publications/detail/fips/203/final) - ML-KEM
- [NIST FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final) - ML-DSA
- [NIST FIPS 205](https://csrc.nist.gov/publications/detail/fips/205/final) - SLH-DSA
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) - Implementation

---

*Last Updated: 2026-01-17*  
*Document Version: 1.0*
