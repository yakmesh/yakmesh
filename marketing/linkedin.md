# LinkedIn Post

**Post:**

🚀 Excited to announce Yakmesh – a new approach to distributed systems.

After months of development, I'm launching a P2P mesh network built on post-quantum cryptography.

**The core innovation:** Instead of trusting external validators or consensus mechanisms, network identity is derived from the validation code itself. Same code = same network. It's deterministic and requires no external trust.

**Why post-quantum?**
Quantum computers will eventually break RSA and ECC. We're using ML-DSA-65 (NIST FIPS 204) – lattice-based signatures that resist both classical and quantum attacks. Future-proofing infrastructure matters.

**Key features:**
• Post-quantum ML-DSA-65 signatures
• Self-verifying oracle (code IS the authority)
• Precision timing (atomic clock/GPS/PTP support)
• Plugin architecture for any database integration
• P2P mesh with gossip protocol

**Use cases:**
• Decentralized marketplaces
• Multi-node database synchronization
• IoT mesh networks
• Tamper-evident audit systems

Currently in private beta – looking for early adopters in fintech, healthcare, and enterprise sectors where data integrity and quantum-readiness matter.

Learn more: https://yakmesh.dev/

#DistributedSystems #PostQuantumCryptography #P2P #Innovation #Cybersecurity

---

**Comment to add:**

For technical folks: The "self-verifying oracle" works by hashing the validation code and using HKDF to derive network identity. This creates a trustless system where protocol changes automatically fork the network. No governance debates needed – just different code, different network.

Happy to answer questions in the comments.



