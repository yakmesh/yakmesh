🏔️ *YAKMESH v3.5.4 — The Fortress Release, finally _actually_ fortified*

Honest version of events: the package has been quietly broken since earlier this year, and nobody told me directly. I found out by auditing it myself. This release is the apology and the fix in one.

*What was wrong (and is now fixed):*
• *Verification gaps* — attestation claims weren't bound to signer identities (sybil inflation), revocation certificates counted duplicate attesters and let the attacker declare the network size, hardware attestation trusted self-reported timing
• *Alert fatigue* — vegati was crying `elevated` every 60s on quiet meshes. Root cause: it was fed a cumulative counter as a "rate" with no variance floor. Fixed properly — steady traffic is silent, real bursts still trip
• *Wire bloat* — redundant stacked signatures on every frame. Now one per layer: heartbeat traffic ~67KB → ~15–22KB
• *Dependency sprawl* — down to 8 runtime packages. `npm audit --omit=dev`: *zero vulnerabilities*
• *Packaging drift* — shipped builds could carry files that drift the codebase hash (the "incompatible network" bug class). Packaging is now manifest-exact and self-verifying — that failure is build-time impossible

*Live-verified:* two-node PQ mesh, Linux↔Windows — JHILKE chirp → ANNEX → ML-KEM handshake → gossip → GPS-disciplined time sync → claim attestation, all green.

`npm install yakmesh` · https://github.com/yakmesh/yakmesh · tag `v3.5.4`

Post-quantum from genesis. ML-DSA identity, ML-KEM transport, hardware-bound attestation. Built different. 🦬
