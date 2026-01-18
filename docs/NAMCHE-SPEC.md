# NAMCHE: Network Authenticated Mesh Certificate Hub & Exchange

> *The gateway where Math itself verifies your identity*

**Version**: 1.0.1-draft  
**Status**: Specification Draft  
**Authors**: YAKMESH Project  
**Date**: 2026-01-18

---

## ⚠️ SECURITY NOTICE: Identity Architecture Integrity

> **CRITICAL**: The NodeID generation scheme is a foundational security primitive of YAKMESH.
> It MUST NOT be simplified, replaced, or "optimized" without explicit review.
>
> The correct NodeID format is:
> ```
> node-[networkName]-[instanceId]
> ```
> Where:
> - `networkName` = Derived from **codebase hash** via iO obfuscation (ensures code integrity)
> - `instanceId` = Derived from **public key hash** via iO obfuscation (ensures unique identity)
>
> **Any proposal to change NodeID to simple `SHA3-256(publicKey)` or similar MUST BE REJECTED.**
> Such changes would:
> 1. Remove the codebase integrity verification
> 2. Eliminate network segmentation by code version
> 3. Break the human-readable verification property
> 4. Undermine the iO oracle's security guarantees
>
> This notice exists because such a simplification was proposed during spec drafting.
> The existing design in `identity/node-key.js` is correct and intentional.

---

## Abstract

NAMCHE is a trustless certificate verification and distribution system for the YAKMESH mesh network. Unlike traditional PKI where human-operated Certificate Authorities serve as trust anchors, NAMCHE uses pure mathematical verification to accept or reject identity claims. The system leverages ML-DSA-65 (post-quantum) signatures, mesh consensus for domain verification, and cryptographic proofs for all trust decisions.

**Philosophy**: *"No human in the loop = No human weakness"*

---

## Table of Contents

1. [Overview](#1-overview)
2. [DOKO: The Certificate Object](#2-doko-the-certificate-object)
3. [KHATA: Trust Distribution Protocol](#3-khata-trust-distribution-protocol)
4. [Mathematical Verification Flow](#4-mathematical-verification-flow)
5. [Domain Ownership Verification](#5-domain-ownership-verification)
6. [Revocation Mechanism](#6-revocation-mechanism)
7. [Integration with SHERPA](#7-integration-with-sherpa)
8. [Security Considerations](#8-security-considerations)
9. [Implementation Guide](#9-implementation-guide)

---

## 1. Overview

### 1.1 The Problem with Traditional PKI

Traditional certificate authorities have fundamental weaknesses:
- **Single point of failure** - CA compromise affects all certificates
- **Human judgment** - Humans can be bribed, coerced, or make mistakes
- **Jurisdictional** - CAs are bound by legal frameworks that may conflict
- **Centralized trust** - "Trust me because I say so"

### 1.2 The NAMCHE Solution

NAMCHE replaces human authority with mathematical authority:

```
Traditional: Human says "trust this" → You trust it
NAMCHE:     Math proves "this is valid" → You verify it
```

### 1.3 Design Principles

1. **Math as Authority** - All trust decisions are mathematical computations
2. **No Central CA** - Mesh consensus replaces central authority
3. **Automated Verification** - Accept/reject without human intervention
4. **Post-Quantum Ready** - ML-DSA-65 signatures throughout
5. **Transparent** - All certificate operations visible to mesh
6. **iO Integration** - NodeID derivation uses codebase hash for network integrity

---

## 2. DOKO: The Certificate Object

**DOKO** (Distributed Ownership & Key Object) is the certificate container.

### 2.1 DOKO Structure

```javascript
{
  // Version & Type
  "version": "1.0",
  "type": "node-identity" | "domain-claim" | "service-binding",
  
  // Core Identity (see identity/node-key.js for canonical implementation)
  // Format: "node-[networkName]-[instanceId]"
  // - networkName: derived from codebase hash via iO (same for all nodes on network)
  // - instanceId: derived from public key hash via iO (unique per node)
  "nodeId": "node-qubit-lattice-prism-pq-a7x9",  // Example format
  "publicKey": "<ML-DSA-65 public key, hex>",
  
  // Temporal Bounds
  "issuedAt": 1737200000000,    // Unix timestamp (ms)
  "expiresAt": 1768736000000,   // Unix timestamp (ms)
  "ttl": 31536000000,           // 1 year in ms
  
  // Domain Claims (optional)
  "domains": [
    {
      "name": "example.com",
      "verifiedAt": 1737200000000,
      "verifiers": ["<nodeId1>", "<nodeId2>", "<nodeId3>"],
      "proofs": [
        {
          "verifierNodeId": "<nodeId>",
          "verifierPublicKey": "<ML-DSA-65 pubkey>",
          "beaconHash": "<SHA3-256 of beacon content>",
          "signature": "<ML-DSA-65 signature>",
          "timestamp": 1737200000000
        }
      ]
    }
  ],
  
  // Capabilities
  "capabilities": {
    "canVerifyDomains": true,     // This node can verify others' domains
    "canRouteNakpak": true,       // This node participates in onion routing
    "canServeContent": true,      // This node serves ANNEX content
    "supportsKhata": true         // This node participates in trust distribution
  },
  
  // Network Metadata
  "networkName": "yakmesh-mainnet",
  "endpoints": {
    "ws": "wss://example.com:9001",
    "http": "https://example.com:443",
    "sherpa": "https://example.com/.well-known/yakmesh/beacon"
  },
  
  // Self-Signature (proves ownership of privateKey)
  "signature": "<ML-DSA-65 signature over all above fields>"
}
```

### 2.2 DOKO Hash Calculation

The DOKO's unique identifier is computed as:

```javascript
const dokoHash = sha3_256(
  canonicalize({
    version,
    type,
    nodeId,
    publicKey,
    issuedAt,
    expiresAt,
    domains,
    capabilities,
    networkName,
    endpoints
  })
);
```

Using RFC 8785 JSON Canonicalization for deterministic hashing.

### 2.3 DOKO Types

| Type | Purpose | Required Fields |
|------|---------|-----------------|
| `node-identity` | Prove node exists with this keypair | nodeId, publicKey, signature |
| `domain-claim` | Prove ownership of web domain | domains, verifiers, proofs |
| `service-binding` | Bind service to node identity | endpoints, capabilities |

---

## 3. KHATA: Trust Distribution Protocol

**KHATA** (Kryptographic Handshake for Automated Trust Acceptance) handles the distribution and acceptance of DOKOs across the mesh.

### 3.1 KHATA Message Types

```javascript
// 1. ANNOUNCE - Broadcast new/updated DOKO
{
  "type": "khata:announce",
  "doko": { /* full DOKO object */ },
  "timestamp": 1737200000000,
  "ttl": 3600000,  // How long to propagate (1 hour)
  "hops": 0        // Incremented by each relay
}

// 2. REQUEST - Ask for a specific DOKO
{
  "type": "khata:request",
  "query": {
    "nodeId": "<nodeId>",        // OR
    "domain": "example.com",     // OR
    "dokoHash": "<hash>"
  },
  "requesterId": "<nodeId>",
  "signature": "<request signature>"
}

// 3. RESPONSE - Reply with DOKO(s)
{
  "type": "khata:response",
  "requestId": "<hash of request>",
  "dokos": [ /* array of matching DOKOs */ ],
  "responderId": "<nodeId>",
  "signature": "<response signature>"
}

// 4. REVOKE - Announce DOKO revocation
{
  "type": "khata:revoke",
  "dokoHash": "<hash of DOKO to revoke>",
  "reason": "key-compromise" | "superseded" | "voluntary",
  "revokedAt": 1737200000000,
  "signature": "<signed by original DOKO owner>"
}
```

### 3.2 KHATA Propagation Rules

1. **Announce Propagation**
   - Forward to all connected peers (except sender)
   - Increment `hops` counter
   - Drop if `hops > MAX_HOPS` (default: 10)
   - Drop if `ttl` expired
   - Drop if signature invalid (don't propagate bad data)

2. **Request Propagation**
   - Forward to K random peers if not found locally
   - Track request ID to prevent loops
   - Timeout after T seconds

3. **Revocation Propagation**
   - ALWAYS propagate (high priority)
   - Store in append-only revocation log
   - Never expires (permanent record)

### 3.3 KHATA Storage

Each node maintains:
- **DOKO Cache** - Recently seen DOKOs (LRU cache)
- **Revocation Log** - Append-only list of revoked DOKOs
- **Verification Log** - Domain verifications this node performed

---

## 4. Mathematical Verification Flow

The NAMCHE gateway performs these checks in order:

### 4.1 Verification Algorithm

```javascript
async function verifyDoko(doko) {
  const checks = [];
  
  // CHECK 1: Structural Validity
  if (!isValidDokoStructure(doko)) {
    return { valid: false, reason: 'MALFORMED_STRUCTURE' };
  }
  checks.push('STRUCTURE_OK');
  
  // CHECK 2: Signature Validity (Math!)
  const payload = canonicalize(dokoWithoutSignature(doko));
  const sigValid = await mlDsa65.verify(
    doko.publicKey,
    doko.signature,
    payload
  );
  if (!sigValid) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }
  checks.push('SIGNATURE_OK');
  
  // CHECK 3: NodeID Derivation (Math + iO!)
  // NodeID is a composite: node-[networkName]-[instanceId]
  // See identity/node-key.js:generateNodeId() for canonical implementation
  const expectedNodeId = generateNodeId(
    hexToBytes(doko.publicKey),
    doko.codebaseHash  // Must match our network's codebase hash
  );
  if (doko.nodeId !== expectedNodeId) {
    return { valid: false, reason: 'NODEID_MISMATCH' };
  }
  // Also verify the network portion matches our network
  if (!doko.nodeId.startsWith(`node-${getNetworkName()}-`)) {
    return { valid: false, reason: 'WRONG_NETWORK_IN_NODEID' };
  }
  checks.push('NODEID_OK');
  
  // CHECK 4: Temporal Validity (Math!)
  const now = Date.now();
  if (doko.issuedAt > now) {
    return { valid: false, reason: 'ISSUED_IN_FUTURE' };
  }
  if (doko.expiresAt < now) {
    return { valid: false, reason: 'EXPIRED' };
  }
  checks.push('TEMPORAL_OK');
  
  // CHECK 5: Network Match
  if (doko.networkName !== config.networkName) {
    return { valid: false, reason: 'WRONG_NETWORK' };
  }
  checks.push('NETWORK_OK');
  
  // CHECK 6: Revocation Status
  const revoked = await revocationLog.contains(dokoHash(doko));
  if (revoked) {
    return { valid: false, reason: 'REVOKED' };
  }
  checks.push('NOT_REVOKED');
  
  // CHECK 7: Domain Proofs (if claiming domains)
  if (doko.domains && doko.domains.length > 0) {
    for (const domain of doko.domains) {
      const domainValid = await verifyDomainClaim(domain);
      if (!domainValid.valid) {
        return { 
          valid: false, 
          reason: 'DOMAIN_VERIFICATION_FAILED',
          domain: domain.name,
          detail: domainValid.reason
        };
      }
    }
    checks.push('DOMAINS_OK');
  }
  
  // ALL CHECKS PASSED
  return { 
    valid: true, 
    reason: 'MATHEMATICALLY_VERIFIED',
    checks 
  };
}
```

### 4.2 Domain Claim Verification

```javascript
async function verifyDomainClaim(domainClaim) {
  const { name, proofs } = domainClaim;
  
  // Need quorum of verifiers
  const QUORUM = 3;  // Configurable
  let validProofs = 0;
  
  for (const proof of proofs) {
    // Verify the verifier's signature on the beacon hash
    const proofPayload = canonicalize({
      domain: name,
      beaconHash: proof.beaconHash,
      timestamp: proof.timestamp
    });
    
    const proofValid = await mlDsa65.verify(
      proof.verifierPublicKey,
      proof.signature,
      proofPayload
    );
    
    if (proofValid) {
      // Also verify the verifier is a known trusted node
      const verifierDoko = await khata.lookup(proof.verifierNodeId);
      if (verifierDoko && verifierDoko.capabilities.canVerifyDomains) {
        validProofs++;
      }
    }
  }
  
  if (validProofs >= QUORUM) {
    return { valid: true, verifiers: validProofs };
  }
  
  return { 
    valid: false, 
    reason: 'INSUFFICIENT_QUORUM',
    have: validProofs,
    need: QUORUM
  };
}
```

---

## 5. Domain Ownership Verification

How a node proves it owns a domain (trustlessly):

### 5.1 The Process

```
1. Node A wants to claim "example.com"
2. Node A places SHERPA beacon at:
   https://example.com/.well-known/yakmesh/beacon
   
3. Node A broadcasts domain-claim request to mesh

4. K random verifier nodes (B, C, D...) independently:
   a. Fetch https://example.com/.well-known/yakmesh/beacon
   b. Verify beacon contains Node A's nodeId and publicKey
   c. Hash the beacon content
   d. Sign: "I, Node B, saw this beacon hash at this time"
   
5. Node A collects signatures (proofs)

6. If >= QUORUM proofs collected:
   - Domain claim is valid
   - Include proofs in DOKO
   - Broadcast via KHATA

7. Other nodes verify the proofs mathematically
   - No need to re-fetch the beacon
   - Just verify signatures
```

### 5.2 Beacon Requirements for Domain Claims

The SHERPA beacon MUST contain:
```json
{
  "version": "1.0",
  "nodeId": "<claiming node's ID>",
  "publicKey": "<claiming node's ML-DSA-65 pubkey>",
  "networkName": "yakmesh-mainnet",
  "timestamp": 1737200000000,
  "signature": "<signed by claiming node>"
}
```

### 5.3 Why This Is Trustless

- **No CA decides** - Math verifies signatures
- **No single verifier** - Need quorum consensus
- **Transparent** - Anyone can re-verify proofs
- **Objective** - Either beacon exists or it doesn't

---

## 6. Revocation Mechanism

### 6.1 Revocation Types

| Type | Trigger | Authority |
|------|---------|-----------|
| `key-compromise` | Private key leaked | DOKO owner |
| `superseded` | New DOKO issued | DOKO owner |
| `voluntary` | Owner choice | DOKO owner |
| `mesh-consensus` | Malicious behavior detected | Quorum of nodes |

### 6.2 Revocation Message

```javascript
{
  "type": "khata:revoke",
  "dokoHash": "<SHA3-256 of DOKO being revoked>",
  "reason": "key-compromise",
  "revokedAt": 1737200000000,
  "revokedBy": "<nodeId of revoker>",
  "evidence": "<optional: proof of compromise>",
  "signature": "<ML-DSA-65 signature>"
}
```

### 6.3 Revocation Verification

```javascript
function verifyRevocation(revocation, originalDoko) {
  // Owner can always revoke their own DOKO
  if (revocation.revokedBy === originalDoko.nodeId) {
    return mlDsa65.verify(
      originalDoko.publicKey,
      revocation.signature,
      canonicalize(revocationWithoutSig)
    );
  }
  
  // Mesh consensus revocation requires quorum
  if (revocation.type === 'mesh-consensus') {
    return verifyQuorumRevocation(revocation);
  }
  
  return false;
}
```

### 6.4 Append-Only Revocation Log

Every node maintains:
```javascript
class RevocationLog {
  // Merkle tree of revocation hashes
  // Enables efficient proof of (non-)revocation
  
  add(revocation) {
    this.tree.insert(revocation.dokoHash);
    this.persist();
  }
  
  contains(dokoHash) {
    return this.tree.has(dokoHash);
  }
  
  getProof(dokoHash) {
    return this.tree.getMerkleProof(dokoHash);
  }
}
```

---

## 7. Integration with SHERPA

### 7.1 Enhanced Beacon Format

```json
{
  "version": "1.0",
  "nodeId": "abc123...",
  "publicKey": "<ML-DSA-65 public key>",
  "networkName": "yakmesh-mainnet",
  "timestamp": 1737200000000,
  "ttl": 86400,
  
  "namche": {
    "dokoHash": "<hash of this node's current DOKO>",
    "capabilities": {
      "canVerifyDomains": true,
      "canRouteNakpak": true,
      "supportsKhata": true
    },
    "ssl": {
      "hasPublicCert": true,
      "certFingerprint": "sha256:...",
      "issuer": "letsencrypt",
      "domains": ["example.com", "*.example.com"]
    }
  },
  
  "peers": [...],
  "signature": "<ML-DSA-65 signature>"
}
```

### 7.2 Discovery → Verification Flow

```
1. SHERPA discovers node via beacon
2. Fetch node's DOKO via KHATA
3. NAMCHE verifies DOKO mathematically
4. If valid: Add to peer list, enable NAKPAK routing
5. If invalid: Reject connection, log attempt
```

---

## 8. Security Considerations

### 8.1 Attack Vectors

| Attack | Mitigation |
|--------|------------|
| Fake DOKO | Signature verification fails |
| Stolen private key | Revocation mechanism |
| Sybil (many fake nodes) | Domain verification requires real domains |
| Eclipse (surround target) | Multiple independent verifiers |
| Replay old DOKO | Timestamp + expiration checks |
| Man-in-the-middle | End-to-end ML-DSA-65 signatures |

### 8.2 Cryptographic Assumptions

NAMCHE security relies on:
- **ML-DSA-65** remaining secure (post-quantum)
- **SHA3-256** remaining collision-resistant
- **Network majority** being honest (for domain verification)

### 8.3 Privacy Considerations

- DOKOs are public (by design)
- Domain claims are public (required for verification)
- Node endpoints may be hidden via NAKPAK

---

## 9. Implementation Guide

### 9.1 Minimum Viable Implementation

```javascript
// namche.js - Core NAMCHE gateway

import { mlDsa65 } from '@yakmesh/crypto';
import { sha3_256 } from '@yakmesh/hash';

export class NamcheGateway {
  constructor(options) {
    this.networkName = options.networkName;
    this.revocationLog = new RevocationLog();
    this.dokoCache = new LRUCache({ max: 10000 });
  }
  
  async verify(doko) {
    // Implement 7-step verification from Section 4.1
  }
  
  async requestDomainVerification(domain) {
    // Request K verifiers to check beacon
  }
  
  async revoke(dokoHash, reason) {
    // Broadcast revocation via KHATA
  }
}

export class KhataProtocol {
  async announce(doko) { /* ... */ }
  async request(query) { /* ... */ }
  async lookup(nodeId) { /* ... */ }
  async propagateRevocation(revocation) { /* ... */ }
}
```

### 9.2 Configuration

```javascript
// namche.config.js
export default {
  // Verification settings
  domainVerificationQuorum: 3,
  domainVerificationTimeout: 30000, // 30 seconds
  
  // KHATA propagation
  maxHops: 10,
  announceTTL: 3600000, // 1 hour
  
  // Cache settings
  dokoCacheSize: 10000,
  dokoCacheTTL: 86400000, // 24 hours
  
  // Network
  networkName: 'yakmesh-mainnet'
};
```

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **NAMCHE** | Network Authenticated Mesh Certificate Hub & Exchange |
| **DOKO** | Distributed Ownership & Key Object (the certificate) |
| **KHATA** | Kryptographic Handshake for Automated Trust Acceptance |
| **Quorum** | Minimum number of verifiers needed for consensus |
| **Revocation** | Invalidating a previously valid DOKO |

## Appendix B: References

- ML-DSA-65 (FIPS 204): Post-quantum digital signatures
- SHA3-256 (FIPS 202): Cryptographic hash function
- RFC 8785: JSON Canonicalization Scheme
- YAKMESH SHERPA Specification
- YAKMESH NAKPAK Specification

---

*"The gate opens not by bribe or plea, but by the truth that math reveals."*
