# Reddit Launch Posts

## r/programming

**Title:** I built a P2P network where the code itself is the source of truth (no blockchain)

**Body:**

After getting frustrated with the complexity of consensus mechanisms, I started exploring a simpler question: what if we removed trust entirely by making the validation code itself the identity?

Yakmesh is the result. Here's the core idea:

1. Hash your validation oracle code (SHA-256)
2. Derive network identity using HKDF
3. Everyone with identical code = same network
4. Modify the code = you're on a different network

It's like a network that automatically forks when rules change.

**Post-quantum ready:** Using ML-DSA-65 (NIST FIPS 204) signatures because RSA/ECC won't survive quantum computers.

**Phase modulation:** Time-based fingerprints prevent replay attacks. Supports atomic clocks, GPS, PTP hardware down to nanosecond precision.

Currently in private beta: https://yakmesh.dev/

Would love technical feedback, especially on edge cases I haven't considered.

---

## r/node

**Title:** Show r/node: Post-quantum mesh networking library with self-verifying oracle

**Body:**

Been working on this for a while – a P2P mesh network library that uses lattice-based cryptography (quantum-resistant) and derives network identity from code hashes.

Stack:
- Node.js 18+
- WebSockets for mesh communication
- @noble/post-quantum for ML-DSA-65 signatures
- sql.js for embedded database

Key features:
- Gossip protocol for message propagation
- Plugin architecture (BaseAdapter class for custom integrations)
- REST + WebSocket APIs
- Precision timing (NTP/GPS/PTP auto-detection)

The "oracle" concept: your network identity is derived from a hash of your validation code. Same code = same network. No external validators needed.

Private beta: https://yakmesh.dev/

Source will be available under BSL (Business Source License) – free for non-commercial use.

---

## r/cryptography

**Title:** Implementing ML-DSA-65 for a mesh network – seeking feedback on approach

**Body:**

I'm building a P2P mesh network (Yakmesh) and chose ML-DSA-65 for signatures. Looking for feedback from the crypto community.

**Why ML-DSA-65:**
- NIST standardized (FIPS 204)
- Lattice-based, quantum-resistant
- Reasonable signature sizes for network traffic

**Identity derivation:**
- Hash validation code with SHA-256
- Use HKDF to derive network fingerprint
- 3-word human-readable names from 256-word wordlist

**Phase epochs:**
- Time-divided into 30-second windows
- Each phase has unique fingerprint
- Prevents replay of old messages

**Questions:**
1. Is HKDF appropriate for this use case, or should I consider alternatives?
2. Any concerns with using code hash as identity seed?
3. Recommendations for the wordlist entropy (currently 256 words, 3-word names = ~24 bits)?

More details: https://yakmesh.dev/docs/

---

## r/selfhosted

**Title:** Yakmesh: Self-hosted P2P sync for databases without blockchain complexity

**Body:**

If you've ever wanted to sync data between self-hosted instances without relying on a central server or setting up blockchain infrastructure, this might interest you.

Yakmesh is a P2P mesh network that:
- Syncs via WebSocket gossip protocol
- Uses post-quantum cryptography (ML-DSA-65)
- Requires no central coordinator
- Works with any database via adapter plugins

**Self-hosting friendly:**
- Single binary (coming soon) or npm package
- No external dependencies
- Configurable peer discovery
- REST API for monitoring

Use case example: Sync your phpBB forum database across multiple servers with automatic conflict resolution.

Private beta (looking for self-hosters to test): https://yakmesh.dev/

Free tier: Up to 3 nodes, community support
Pro tier: Unlimited nodes, encryption, priority support



