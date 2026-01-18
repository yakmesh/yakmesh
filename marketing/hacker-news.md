# Hacker News Submission

**Title:** Show HN: Yakmesh – Post-quantum P2P network with self-verifying oracle

**URL:** https://yakmesh.dev/

**Text (if self-post):**

I've been building Yakmesh, a distributed mesh network that uses post-quantum cryptography (ML-DSA-65, NIST FIPS 204) and a "self-verifying oracle" – the idea being that the code itself is the source of truth, with no external dependencies for validation.

Key features:
- Post-quantum signatures using ML-DSA-65 (lattice-based, quantum-resistant)
- Deterministic validation – hash your code, derive your network identity
- Phase modulation for temporal anti-replay protection  
- Precision timing support (atomic clocks, GPS, PTP hardware like Meinberg PTP270PEX)
- Plugin architecture for integrating any database/API

The oracle concept: instead of trusting external validators, the network identity is derived from a hash of the validation code itself. Same code = same identity = same trust network. Change the code, and you're on a different network.

Currently in private beta – looking for feedback on the architecture and early adopters.

Tech stack: Node.js, WebSockets, @noble/post-quantum

Would love to hear thoughts from the HN community on the approach, especially around the "code as authority" model.



