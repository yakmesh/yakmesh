# 🏔️ YAKMESH v3.0.0 — The Mega Release

**Every module wired. Every path hardened. Every proof verifiable.**

Post-quantum secure mesh networking for the 2026 threat landscape.

## ⚡ What's New

### 🧠 ACCEL — Hardware Acceleration Engine

Heterogeneous compute routing across CPU-SIMD, GPU (WebGPU), and NPU (ONNX Runtime).

- AES-NI, VAES, AVX-512, GFNI detection via timing attestation
- 3 ONNX ML models ship with every node:
  - `entropy-sentinel` — quantum entropy quality scoring
  - `sakshi-anomaly` — behavioral anomaly detection
  - `karma-trust` — trust level prediction

### 🛡️ PRAHARI — Mesh-Consensus Entropy Engine

Locally-sourced, pluggable entropy harvested from the mesh itself:

- 5 sources: RDRAND/RDSEED, GPS jitter, interrupt timing, mesh packet arrival, OS CSPRNG
- SHA3-256 sponge mixing pool with domain-separated expansion
- NPU-accelerated EntropySentinel quality scoring
- More peers = better entropy — the opposite of centralized systems

### 📡 Full Protocol Stack — Live & Serving

Every protocol module wired, routed, and operational:

- **KOMM** — KATHA chat, VANI voice/video, YURT rooms, GUMBA access control
- **DARSHAN** — View-not-copy content streaming
- **NAKPAK** — Onion routing with ML-KEM circuits
- **SHERPA** — HTTP relay bridge for NAT/CGNAT traversal

### ⚖️ Voting Consensus → Math Proof

Voting is gone. Content validity now determined by cryptographic proof:

- **A** (Authenticity): ML-DSA-65 publisher signature
- **C** (Correctness): SHA3-256 hash integrity
- One proof = proven. No quorum needed.

### 🔒 Security Audit — 30 Findings Fixed

- 2 CRITICALs, 6 HIGHs, 22 others — all resolved
- 140 new security-focused tests
- ML-DSA-65 verified on ALL incoming mesh messages

### 📚 48 Themed Documentation Pages

Each docs page features unique silhouette backgrounds, themed particle animations, and complete protocol coverage at <https://yakmesh.dev/docs>

## 📊 Stats

| Metric | Value |
|--------|-------|
| Total Tests | **1,535 (0 failures)** |
| Source Files | 179+ protected |
| ONNX Models | 3 (22,829 bytes) |
| Server Module | 3,202 lines |
| Doc Pages | 48 themed |

## 🔗 Links

- 🌐 Website: <https://yakmesh.dev>
- 📚 Docs: <https://yakmesh.dev/docs>
- 📦 npm: <https://npmjs.com/package/yakmesh>
- 🐙 GitHub: <https://github.com/yakmesh/yakmesh>
- 💬 Discord: <https://discord.gg/8mSPfbJB8N>
- 📱 Telegram: <https://t.me/yakmesh>

```bash
npm install yakmesh
```

---
*MIT Licensed • Post-quantum since 2024 • Sturdy & Secure 🦬*
