# PeerQuanta + Yakmesh Integration Design Document

**Version**: 1.0.0  
**Date**: January 18, 2026  
**Status**: Draft  
**Authors**: PeerQuanta Team

---

## Executive Summary

This document outlines the integration strategy between **PeerQuanta** (P2P cryptocurrency marketplace) and **Yakmesh** (post-quantum secure mesh network). The integration creates a privacy-first, decentralized ecosystem where users can trade, communicate, and verify transactions without central authority.

---

## 1. YETI - Yakmesh Encrypted Trustless Index

### 1.1 Overview

**Y**akmesh **E**ncrypted **T**rustless **I**ndex - A private DNS-like system for the mesh.

```
Traditional:  example.com → DNS → 93.184.216.34 → HTTP Server
YETI:         merchant.yak → YETI → NodeID:abc123 → Mesh Node → Content
```

### 1.2 How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         YETI Resolution                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User types: "alice-crypto.yak"                                │
│                    │                                            │
│                    ▼                                            │
│   ┌─────────────────────────────────────┐                       │
│   │    Local YETI Cache                 │                       │
│   │    (Recently resolved names)        │                       │
│   └─────────────────────────────────────┘                       │
│                    │ Miss                                       │
│                    ▼                                            │
│   ┌─────────────────────────────────────┐                       │
│   │    SHERPA Discovery                 │                       │
│   │    Query known peers for name       │                       │
│   └─────────────────────────────────────┘                       │
│                    │                                            │
│                    ▼                                            │
│   ┌─────────────────────────────────────┐                       │
│   │    Gossip Propagation               │                       │
│   │    Flood query to mesh network      │                       │
│   └─────────────────────────────────────┘                       │
│                    │                                            │
│                    ▼                                            │
│   ┌─────────────────────────────────────┐                       │
│   │    Response: NodeID + PublicKey     │                       │
│   │    Signed by name owner             │                       │
│   └─────────────────────────────────────┘                       │
│                    │                                            │
│                    ▼                                            │
│   Connect via Annex (encrypted) or Nakpak (anonymous)           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Name Registration

Names are registered by signing a claim with your node's private key:

```javascript
// YETI Name Record
{
  name: "alice-crypto",
  tld: "yak",
  nodeId: "abc123...",
  publicKey: "ML-DSA-65 public key",
  registered: 1737200000000,
  expires: 1768736000000,  // 1 year
  signature: "signed by owner's key",
  
  // Optional metadata
  meta: {
    description: "Alice's Crypto Shop",
    avatar: "ipfs://...",
    services: ["marketplace", "escrow"]
  }
}
```

### 1.4 Conflict Resolution

- First-come-first-served with timestamp proof
- Name claims propagate through Gossip
- Mesh consensus determines valid owner
- Disputes resolved by earliest signed claim

### 1.5 TLD Structure

| TLD | Purpose |
|-----|---------|
| `.yak` | General mesh names |
| `.pq` | PeerQuanta marketplace |
| `.anon` | Nakpak-only (anonymous) |
| `.test` | Development/testing |

---

## 2. Mesh-Backed PeerQuanta Tools

### 2.1 Digital Notary → Mesh Attestation

**Current**: Client-side timestamp with SHA-3 hash  
**Enhanced**: Distributed attestation across mesh nodes

```
┌─────────────────────────────────────────────────────────────────┐
│                    Mesh-Backed Notarization                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Document → SHA3-256 Hash → Notary Request                     │
│                                   │                             │
│                                   ▼                             │
│   ┌─────────────────────────────────────┐                       │
│   │         Gossip Broadcast            │                       │
│   │   "I attest hash X at time T"       │                       │
│   └─────────────────────────────────────┘                       │
│              │         │         │                              │
│              ▼         ▼         ▼                              │
│         ┌───────┐ ┌───────┐ ┌───────┐                           │
│         │Node A │ │Node B │ │Node C │                           │
│         │ Signs │ │ Signs │ │ Signs │                           │
│         └───────┘ └───────┘ └───────┘                           │
│              │         │         │                              │
│              └─────────┼─────────┘                              │
│                        ▼                                        │
│   ┌─────────────────────────────────────┐                       │
│   │       Attestation Certificate       │                       │
│   │   Hash + Time + N node signatures   │                       │
│   │   "3 of 5 nodes attested"           │                       │
│   └─────────────────────────────────────┘                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation File**: `mesh/notary-attestation.js`

### 2.2 Secure Notes → Mesh-Synced Vault

**Current**: Password-encrypted notes stored locally  
**Enhanced**: Encrypted notes synced across user's nodes

```javascript
// Secure Note with Mesh Sync
{
  id: "note-uuid",
  encryptedContent: "XChaCha20-Poly1305 ciphertext",
  owner: "nodeId",
  syncNodes: ["node1", "node2"],  // User's other devices
  version: 3,
  lastModified: 1737200000000,
  
  // Sync via Annex (encrypted P2P)
  // Only owner's nodes can decrypt
}
```

### 2.3 Covert Art → Mesh Steganography

**Current**: Hide data in images client-side  
**Enhanced**: Transmit covert images through Nakpak onion routes

```
┌─────────────────────────────────────────────────────────────────┐
│                    Covert Art via Nakpak                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Image + Hidden Message                                        │
│           │                                                     │
│           ▼                                                     │
│   ┌─────────────────────────────────────┐                       │
│   │    Steganographic Encoding          │                       │
│   │    (LSB, DCT, or ML-based)          │                       │
│   └─────────────────────────────────────┘                       │
│           │                                                     │
│           ▼                                                     │
│   ┌─────────────────────────────────────┐                       │
│   │    Nakpak Onion Routing             │                       │
│   │    Source → Relay1 → Relay2 → Dest  │                       │
│   └─────────────────────────────────────┘                       │
│           │                                                     │
│           ▼                                                     │
│   Recipient extracts hidden message                             │
│   (No observer knows source or content)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.4 QCoA → Mesh Identity Attestation

**Current**: Quantum Certificate of Authenticity for digital assets  
**Enhanced**: Cross-mesh verified merchant/user identity badges

```javascript
// QCoA Mesh Badge
{
  type: "merchant",
  name: "alice-crypto.yak",
  publicKey: "...",
  reputation: {
    trades: 150,
    rating: 4.9,
    disputes: 0,
  },
  attestations: [
    { nodeId: "node1", signature: "..." },
    { nodeId: "node2", signature: "..." },
  ],
  
  // Badge verified by multiple mesh nodes
  // Cannot be faked without controlling majority
}
```

### 2.5 Encrypted Wagers → Mesh Escrow

**Current**: Commitment-reveal protocol for wagers  
**Enhanced**: Mesh-enforced escrow with dispute resolution

```
┌─────────────────────────────────────────────────────────────────┐
│                    Mesh Escrow Protocol                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Phase 1: COMMITMENT                                           │
│   ┌─────────┐              ┌─────────┐                          │
│   │  Alice  │  Commit A    │  Bob    │  Commit B                │
│   └─────────┘──────────────└─────────┘                          │
│                    │                                            │
│                    ▼                                            │
│   ┌─────────────────────────────────────┐                       │
│   │         Mesh Escrow Nodes           │                       │
│   │   Store commitments + stake         │                       │
│   └─────────────────────────────────────┘                       │
│                                                                 │
│   Phase 2: REVEAL                                               │
│   Alice reveals → Bob reveals → Outcome determined              │
│                                                                 │
│   Phase 3: SETTLEMENT                                           │
│   If dispute: Mesh consensus arbitrates                         │
│   If clean: Automatic payout                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. SHERPA Integration with PeerQuanta

### 3.1 PeerQuanta as SHERPA Seed

The peerquanta.com website will expose a beacon endpoint:

```
https://peerquanta.com/.well-known/yakmesh/beacon
```

This provides a stable, trusted entry point to the yakmesh network.

### 3.2 Beacon Response

```json
{
  "version": "1.0",
  "nodeId": "peerquanta-primary",
  "networkName": "yakmesh-mainnet",
  "timestamp": 1737200000000,
  "ttl": 3600,
  "capabilities": {
    "wsPort": 9001,
    "httpPort": 443,
    "supportsAnnex": true,
    "supportsNakpak": true,
    "supportsGossip": true,
    "supportsYETI": true
  },
  "peers": [
    { "nodeId": "node1", "endpoint": "https://node1.yakmesh.dev" },
    { "nodeId": "node2", "endpoint": "https://node2.yakmesh.dev" }
  ],
  "publicKey": "...",
  "signature": "..."
}
```

### 3.3 Implementation Steps

1. **Static Beacon** (v1): JSON file served by Caddy/nginx
2. **Dynamic Beacon** (v2): Yakmesh node generates live peer list
3. **Signed Beacon** (v3): Cryptographic proof of authenticity

---

## 4. Protocol Stack (Updated)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Yakmesh Protocol Stack v1.9                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Layer 0: YETI      🏔️  Encrypted Trustless Index (DNS)        │
│   Layer 1: HTTP API  🌐  Public content delivery                │
│   Layer 2: Annex     🔐  Encrypted P2P (ML-KEM768)              │
│   Layer 3: Gossip    📢  Message propagation                    │
│   Layer 4: Beacon    🚨  Emergency broadcast                    │
│   Layer 5: Nakpak    🎒  Onion routing                          │
│   Layer 6: Sherpa    🏔️  Peer discovery                         │
│   Layer 7: Mesh      🕸️  Core P2P network                       │
│                                                                 │
│   Extensions:                                                   │
│   - Notary Attestation (mesh-backed timestamps)                 │
│   - Escrow Protocol (commitment-based trades)                   │
│   - Identity Badges (QCoA verification)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Implementation Roadmap

### Phase 1: Foundation (Current - v1.8.x)
- [x] SHERPA peer discovery
- [x] NAKPAK onion routing
- [ ] Beacon endpoint on peerquanta.com
- [ ] Website updates for v1.8.0
- [ ] SHERPA tests

### Phase 2: YETI DNS (v1.9.0)
- [ ] YETI name registration
- [ ] Gossip-based name resolution
- [ ] `.yak` TLD support
- [ ] Browser extension for `.yak` domains

### Phase 3: Tool Integration (v2.0.0)
- [ ] Mesh-backed Digital Notary
- [ ] Synced Secure Notes
- [ ] QCoA mesh badges
- [ ] Nakpak Covert Art transmission

### Phase 4: Marketplace (v2.1.0)
- [ ] Mesh escrow protocol
- [ ] Anonymous trading via Nakpak
- [ ] Reputation propagation
- [ ] Dispute resolution consensus

---

## 6. Security Considerations

### 6.1 YETI Name Squatting
- Require proof-of-stake or proof-of-work for registration
- Implement name challenges for trademark disputes
- Rate limit new registrations per node

### 6.2 Sybil Attacks on Consensus
- Require code proof for participation
- Weight votes by node age and reputation
- Implement subnet diversity checks

### 6.3 Eclipse Attacks on SHERPA
- Maintain diverse peer set across subnets
- Verify beacon signatures
- Cross-check peer lists from multiple sources

### 6.4 Timing Attacks on Nakpak
- Add random delays in onion routing
- Use constant-time operations
- Pad messages to fixed sizes

---

## 7. Open Questions

1. **YETI Governance**: Who resolves `.yak` disputes?
2. **Fee Structure**: Should name registration cost tokens?
3. **Interoperability**: Can YETI work with ENS/Handshake?
4. **Mobile Support**: How do mobile apps resolve `.yak` names?

---

## 8. References

- [Yakmesh Whitepaper](https://yakmesh.dev/whitepaper)
- [SHERPA Implementation](../mesh/sherpa-discovery.js)
- [NAKPAK Implementation](../mesh/nakpak-routing.js)
- [PeerQuanta Tools](https://peerquanta.com/tools)

---

*Document Version History*
| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-18 | Initial draft |

---

**YAKMESH™** is a trademark of PeerQuanta (USPTO Serial No. 99594620)
