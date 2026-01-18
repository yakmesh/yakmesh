---
title: Building a Post-Quantum P2P Network with a Self-Verifying Oracle
published: true
tags: p2p, cryptography, nodejs, distributedsystems
cover_image: https://yakmesh.dev/assets/yakmesh-logo.png
---

## The Problem with Trust

Every distributed system has the same fundamental question: *who do you trust?*

Blockchains trust consensus mechanisms. Federated systems trust server operators. Certificate authorities trust... themselves?

I wanted to explore a different model: **what if the code itself was the authority?**

## Introducing Yakmesh

Yakmesh is a P2P network where your identity is derived from the hash of your validation code. Same code = same network. It is deterministic, reproducible, and requires no external trust.

### The Self-Verifying Oracle

The core concept is simple:

1. Hash your validation oracle code
2. Derive a network identity from that hash (using HKDF)
3. Everyone running the same code gets the same identity
4. Change the code = different network

```javascript
import { deriveNetworkIdentity } from '@yakmesh/core';

const identity = await deriveNetworkIdentity();
// Returns: { networkName: "Alpine-Falcon-7x", trustLevel: "oracle" }
```

The trust level is cryptographic proof that you are running unmodified code.

### Post-Quantum Security

With quantum computers on the horizon, we use ML-DSA-65 (NIST FIPS 204) - a lattice-based signature scheme that is resistant to both classical and quantum attacks.

### Phase Modulation

To prevent replay attacks, every message includes a phase fingerprint - a time-based component derived from:

- Current epoch (configurable window, default 30s)
- Network identity
- Content hash

Old phases are rejected automatically.

### Precision Timing

For applications requiring high accuracy, Yakmesh auto-detects:

- Atomic clocks - Sub-microsecond accuracy
- GPS receivers - ~100ns with good signal
- PTP hardware - Meinberg PTP270PEX, etc.
- NTP - Fallback for most users

## Use Cases

- Decentralized marketplaces - No central authority
- Multi-node databases - Sync without conflict
- IoT networks - Lightweight P2P communication
- Audit systems - Tamper-evident logging

## Current Status

Yakmesh is in **private beta**. We are looking for early adopters who want to build on a post-quantum foundation.

Learn more: [yakmesh.dev](https://yakmesh.dev/)

---

*I would love to hear your thoughts on the code as authority model. Is this approach viable for production systems?*



