# Changelog

All notable changes to YAKMESH will be documented in this file.

## [Unreleased]

## [3.4.0] - 2026-05-28

### 📡 Public Entropy Beacon API

*Theme: "The mesh breathes entropy. Anyone can watch."*

External builders can now consume PRAHARI commit-reveal consensus entropy as a public REST API — signed, chained, and verifiable without trusting the operator.

**New Endpoints** (`server/index.js`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/public/latest` | GET | Latest signed pulse (round, randomness, timestamp, signature, previous_signature) |
| `/public/:round` | GET | Retrieve any historical pulse by round number (O(1) Map lookup) |
| `/public` | GET | Paginated pulse history (`?limit=&offset=`) |
| `/info` | GET | Beacon metadata: `public_key`, `period`, `threshold`, `next_expected`, `node_id` |
| `/public/verify` | POST | Client-side verification helper: submits pulse JSON, returns `valid: true/false` |

**Security properties**:
- **Open CORS** — `Access-Control-Allow-Origin: *` on all `/public/*` and `/info` routes
- **Generous rate limits** — 300 req/min per IP (remote), loopback exempt
- **ML-DSA-65 signed pulses** — Every pulse is signed by the node's identity key; clients verify against `public_key` from `/info`
- **Hash chain** — Each pulse carries `previous_signature`, linking rounds into an auditable sequence
- **Bounded history** — `pulseHistory` Map retains last 1,000 pulses; old rounds pruned automatically

**Implementation** (`security/prahari-mesh.js`):
- `CommitRevealEntropy` now stores every combined round as a signed `Pulse` object
- New methods: `getLatestPulse()`, `getPulse(round)`, `getPulseHistory(limit, offset)`, `getGenesisInfo()`
- Constructor accepts `signFn` and `publicKey` for pulse signing
- `wireCommitReveal` passes `this.identity.sign` and `this.identity.publicKey` from `server/index.js`
- Fixed `next_expected` drift in `getGenesisInfo()` (now uses aligned `nextPhaseTime`)
- Fixed pulse object mutation leak in `getPulseHistory()` (deep clone before return)
- Fixed missing `public_key` and `node_id` fields in pulse objects

### 🔍 Client Verification

**Scripts** (`scripts/verify-beacon.mjs`, `scripts/verify_beacon.py`):
- Node.js and Python client verification scripts exercising all public endpoints
- Signature verification, chain-link validation, freshness checks
- Server-side `/public/verify` cross-check
- `npm run verify:beacon` — one-command verification

### 📝 Documentation & Deploy

- **`website/docs/prahari.html`** — Full Public Entropy Beacon API documentation with pulse format, endpoints, client verification checklist, and edge cases (first boot, genesis pulse, clock skew)
- **`scripts/sync-docs.mjs`** — Unified docs sync workflow: `npm run sync:docs` updates nav, mirrors to `yakmesh-node/docs/`, and rebuilds bundle + public
- **`scripts/deploy-hostinger.cjs`** — Rewritten with correct two-way sync (`website/docs/` is source of truth), 6-stage pipeline (nav → mirror → bundle → public → SEO → sitemap/robots)
- **`scripts/deploy-hostinger-ssh.ps1`** — Atomic tar+SCP deploy to Hostinger shared hosting

---

## [3.3.0] - 2026-02-28

### 🏔️ ARCH-RESONANCE: 8-Phase Mesh Hardening + License Migration + Repo Cleanup

*Theme: "Every connection is an interview. Every peer earns its slot. The mesh breathes."*

Comprehensive mesh hardening across 8 phases, AGPLv3 license migration with trademark protections,
and repository cleanup removing 80+ unnecessary files.

---

#### Phase 0: Bug Fixes (JHILKE, HELLO/WELCOME, _send fallback)

- **JHILKE deterministic ordering** — Chirp key derived from `HKDF(codeHash + buildNonce + sorted(nodeId1, nodeId2))`, guaranteeing both sides compute the same key
- **targetNodeId in connect/connectToPeer** — Prevents MITM by verifying expected peer identity
- **_send() fallback** — Graceful plaintext fallback when ANNEX channel not yet established
- **HELLO handler JHILKE ordering** — Consistent key derivation regardless of which side initiates

#### Phase 0.5: 48 Spec Invariant Vectors

- **7 categories (A–G)** — Crypto, Mesh, Security, Protocol, Identity, Oracle, Mesh Hardening
- **G39–G48** — REDIRECT message type, admissionVerdict, PeerPhaseBuffer, Worker, KARMA persistence, destroy(), SharedArrayBuffer dispatch, REDIRECT handler

#### Phase 1+2+6: PeerPhaseBuffer (SharedArrayBuffer)

- **Zero-copy peer state** — SharedArrayBuffer with 32 bytes/slot (theta, stability, timeTrust, karma, hardware, lastArrival, flags)
- **Dynamic capacity** — `floor(64 × (log₂(threads+1) + log₂(totalTops+1)×0.5)) × networkMul × timeMul`
- **Overflow buffer** — Graceful handling when SAB capacity exhausted
- **Micro-precision** — MICRO = 1,000,000 for sub-float integer packing

#### Phase 3: Weighted Ternary Admission

- **AFFIRM/ABSTAIN/DENY** — Ternary admission verdict with weighted priority scoring
- **KARMA persistence** — `saveToDisk()`/`loadFromDisk()` with 30s debounce, auto-restore on startup
- **REDIRECT eviction** — Lowest-priority peer evicted with suggested alternative peers
- **Network wiring** — HELLO handler integrates admission verdict, mesh passes KARMA model

#### Phase 4: AGUWA Integration

- **PeerPhaseState → buffer delegation** — Getter/setter pairs delegate to Atomics when buffer available
- **initBuffer(hwTelemetry)** — Creates PeerPhaseBuffer + Worker, wires capacity from hardware telemetry
- **Server integration** — `aguwa.initBuffer({ threads, totalTops })` after `aguwa.init()`

#### Phase 5: Worker Thread Batch Kuramoto

- **aguwa-worker.js** — Worker thread computes mean phase + e-weighted Kuramoto delta via Atomics
- **Batch dispatch** — When `peers.size > threshold && !workerInFlight`, posts SharedArrayBuffer + config to Worker
- **Threshold** — `max(100, maxPeers × 0.4)` — only offloads when worth the overhead
- **destroy()** — Clean Worker termination on shutdown

---

#### 🔐 License Migration: MIT → AGPLv3

- **201 source files** — AGPLv3 header prepended to all .js files (excluding yakmesh.config.js and *.min.js)
- **LICENSE file** — Full GNU AGPL-3.0 text with YAKMESH™ trademark preamble (Serial No. 99594620)
- **package.json** — `"license": "AGPL-3.0-or-later"`

#### 🧹 Repository Cleanup

- **Removed 80+ files** — Ad-hoc test scripts, backup files, deprecated oracle, marketing/announcements
- **Root cleanup** — 14 test-*.mjs scripts, 4 test output .txt files, verify-*.js, audit-*.js
- **Directories removed** — test-nodes/, marketing/, announcements/, security/_legacy/
- **Backup files removed** — prahari.v2.bak.js, steadywatch-ternary.v2.test.bak.js
- **Deprecated code removed** — validation-oracle.js (replaced by validation-oracle-hardened.js)
- **.gitignore hardened** — Comprehensive patterns prevent re-committing junk

---

## [3.2.0] - 2026-02-25

### 🔐 SANGHA Security + 3-Node Mesh Live + YakApp Discord Features

*Theme: "Unity is security. Components protecting components. Every peer short-named, every message ephemeral."*

Three major streams: (1) SANGHA collective security architecture with novel approaches;
(2) first successful 3-node mesh deployment with SHERPA auto-discovery;
(3) YakApp gains Discord-like features including DARSHAN-powered ephemeral streaming.

---

#### 🛡️ SANGHA — Unified Component Attestation (`security/sangha.js`, 570 lines)

**Novel security philosophy**: Traditional process isolation SEPARATES components — each stands alone.
SANGHA UNIFIES components — they protect each other through continuous mutual attestation.

**Core Mechanisms**:

- **SYNAPSE** — Cryptographic communication channels between components (signed + GPS-timestamped)
- **ANTIBODY** — Circulating verification routines patrol every 5s, collect state attestations
- **TEMPORAL BINDING** — Operations bound to GPS time windows (100ms→2000ms per component type)
- **COLLECTIVE RESPONSE** — All components react to any detected anomaly

**10 Components, 45 Synapses**: crypto, oracle, mesh, http, identity, fs, memory, sign, rate, config

---

#### 🔒 Security Hardening Suite (6 new modules)

| Module | File | Lines | Novel Approach |
|--------|------|-------|----------------|
| FS Hardening | `security/fs-hardening.js` | ~510 | Files as SANGHA participants |
| Memory Safety | `security/memory-safety.js` | ~530 | Circulating canaries (heap/closure/native) |
| Temporal Signing | `security/temporal-signing.js` | ~470 | GPS-bound, auto-expiring signatures |
| KARMA Rate Limiter | `security/karma-rate-limiter.js` | ~600 | Trust-adaptive throughput (10→200 req/min) |
| Secure Config | `security/secure-config.js` | ~480 | Oracle-attested config hash |
| Sandboxing Guide | `docs/sandboxing.md` | ~400 | Linux/macOS container docs |

**Security Profiles**: PARANOID, HARDENED, STANDARD, DEVELOPMENT — with appropriate defaults.

---

#### 🌐 3-Node Mesh Live — First Successful Deployment

**Milestone**: All 3 yakmesh nodes connected on same network via SHERPA automatic discovery.

**Networks** (oracle hash changes = new network name):

- `cipher-nitrogen-decompose (pq-3FZd)` — 98 JS files (2026-02-22)
- `countable-csidh-sphaleron (pq-HWXp)` — 99 JS files (2026-02-23)
- `discrete-fullerene-nitride (pq-vE4V)` — current (2026-02-24)

**Bug Fixes (6 critical)**:

1. **ANNEX KEM rekey race** — `deterministicRekey()` with deterministic shared key derivation
2. **ANNEX random sessionId** — sha3-256 of sorted peer IDs replaces random bytes
3. **ANNEX bootstrap→KEM gap** — `_transitionKey` bridge holds old key 5s during handoff
4. **JHILKE tick mismatch** — `_sharedTick()` using wall-clock `Math.floor(Date.now() / 1000)`
5. **JHILKE rekey coordination** — `deriveRekeyKey()` + `_executeSwitch()` rewrite
6. **SHERPA PHP bridge port** — sed 3000→3080 in beacon.php/relay.php

**peerTag() Helper** — Clean short tags in logs (`tc4H`, `mR7B`, `426u` instead of 60-char IDs).
Implemented across 8 files, ~60 truncation sites.

---

#### 💬 YakApp — Discord-Like Features

**ChatPanel.jsx** expanded to ~3200 lines with 8 new Discord-inspired features:

| Feature | Protocol | Description |
|---------|----------|-------------|
| Direct Messages | KATHA | Private 1:1 conversations |
| User Presence | DARSHAN | Online/away/DND status via mesh |
| File/Media Sharing | ANNEX | Encrypted uploads with progress |
| Message Search | Local | Full-text search across history |
| Desktop Notifications | Browser API | Permission-gated alerts |
| Channel Management | GUMBA | Create/edit/delete channels |
| Invite Links | YAK:// | `yak://invite/{code}` deep links |
| Ephemeral Streams | DARSHAN | Real-time disappearing chat |

**Ephemeral Streaming (DARSHAN)**: Host broadcasts, viewers see content without downloading.
Messages auto-expire with TTL countdown UI. Purple-themed ephemeral styling.

**InviteModal**: Create/copy/delete invite links with expiry (1h/24h/7d/never) and max uses.

**SUDDHI Content Moderation** (`lib/suddhi.js`, ~350 lines):
Multi-layer validation for public room names/descriptions. Never censors messages — only
prevents harmful room ADVERTISING. Bloom filter for privacy-preserving pattern detection.

---

#### 🔧 Infrastructure Improvements

**Bootstrap System Refactored**:

- Changed from aggressive 30s retry loop to seed-only mechanism
- DirectWS connections have priority
- Bootstrap only activates when `peers.size === 0`
- Added `peer:disconnected` handler for recovery

**Advertised Endpoints**: Nodes announce listening address in HELLO/WELCOME.
`_getAdvertisedEndpoint()` detects best local IP. Enables reconnection after restart.

**144T Routing Security**: 256-bit post-quantum routing (Grover-resistant).
3^144 ≈ 10^68 address space. Now displayed in dashboard POST-QUANTUM card.

---

#### 🐛 Protocol URL Fix

**CRITICAL**: Fixed incorrect protocol URLs across yakapp:

- `yakmesh://` → `yak://` (ChatPanel, QRGenerator, QRScanner)
- `yakmesh.io` → `yakmesh.dev` (SettingsPanel)

The correct protocol scheme is `yak://` — documented at <https://yakmesh.dev/docs/yak-protocol.html>

---

#### 📊 Stats

| Metric | Value |
|--------|-------|
| Security modules added | 6 |
| SANGHA components | 10 |
| SANGHA synapses | 45 |
| ANNEX bugs fixed | 3 |
| JHILKE bugs fixed | 2 |
| peerTag() sites updated | ~60 |
| ChatPanel features added | 8 |
| ChatPanel lines | ~3200 |
| Protocol URL fixes | 4 files |

---

## [3.1.0] - 2026-02-21

### 🎨 Docs 3.0 Polish + Phase 6 Realm AI — Zero External Dependencies

*Theme: "Every font local, every icon inline, every faction alive."*

Two streams of work: (1) the docs site achieves true zero-dependency operation — no Google Fonts,
no external requests, system font stacks only; (2) the C2C realm system grows a full AI layer
with NPU-driven faction brains, adaptive difficulty, and player-facing AI profiles.

---

#### 📄 Docs 3.0 Polish Series

**Google Fonts Removal** — 48 HTML files purged of all `fonts.googleapis.com` references.
System font stacks (`system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif`) replace
all external font loads. Zero render-blocking requests from the docs site.

**SVG Icon Sprite System (Phase 2)** — `docs/assets/icons.svg` expanded to 69 symbols
covering every protocol, application, and reference category. 3,215+ icon references
across all docs pages. Inline `<svg><use href="#icon-..."/></svg>` pattern — no image
requests, instant rendering, accessible via `aria-hidden`.

**Heading Hierarchy Audit** — All 48 docs pages verified: one `<h1>` per page, consistent
`<h2>`/`<h3>` nesting. 48 h1s, 430 h2s, 335 h3s total.

**Performance Pass** — Async CSS loading via `media="print" onload` pattern (45 files),
`<noscript>` fallbacks, `will-change` hints for animations, skip-link accessibility on
every page. No external blocking resources remain.

**Content Expansion** — `docs/c2c.html` expanded from 513 words / 0 code blocks to
1,226 lines with full "Building Your Own Realm" developer guide and "AI Profiles"
documentation section (three-tier table, personality shape, API endpoints, usage examples).

**Tooling** — `update-docs-nav.cjs` (398 lines, 5 phases: sprite injection, emoji→SVG
hero icons, sidebar sync, journey navigation cards). `deploy-hostinger.cjs` (230 lines,
4-stage pipeline: mirror, canonical injection, OG URLs, sitemap generation).

---

#### 🤖 C2C Phase 6 — Realm & AI (Miles 22–29)

Eight milestones completing the realm system's AI backbone. All documented in
[DESIGN.md](c2c/DESIGN.md) as Phase 6.

**Mile 22 — Realm System Core**: `realms.js` (429 lines). Realm CRUD, memberships,
story arc schema, manifest loader. Obsidian Scion reference realm with 6 story arcs,
5 factions, 2 tech trees, 6 unit types. 4 game modes (sandbox/coop-pve/pvp/campaign).

**Mile 23 — NPC Factions & Narrative Voice**: `realm_factions` table with alignment,
personality, and capabilities JSON. `narrative.js` per-realm vocabulary and NPC dialogue
templates. 7 narrative event types in `realm_narrative_log`.

**Mile 24 — Realm Combat**: `realm-combat.js` (831 lines). 6 faction unit types in
900-range IDs (Aethian Warrior → Power Tower Relay). Stats/rapidfire injected into
existing OGame combat engine. Player-vs-garrison and faction-raid-interception paths.

**Mile 25 — Realm Progression**: `realm-progression.js` (227 lines). 7-tier rank system
(Recruit 0 XP → Fleet Lord 150,000 XP). Atomic XP grants with rank-up detection.
Paginated leaderboard and individual progression stats.

**Mile 26 — Realm Research**: `realm-research.js` (364 lines). Manifest-defined tech
trees (`dark_energy`, `aethian_salvage`) gated by story arc completion. 6 concrete
`TECH_EFFECTS`: hull bonus, spy bonus, attack bonus, shield bonus, fleet diversity
bonus, repair speed.

**Mile 27 — Realm Tick Engine**: `realm-tick.js` (619 lines). Arc trigger evaluator
(6 trigger types), faction economy simulation (mines/expansion/towers/warriors),
staggered processing across realms, integrated into 30s main game tick.

**Mile 28 — NPU Faction Brain + Diplomacy + Adaptive Threats**:

- `faction-brain.js` — ONNX model (12→20→14→6 MLP), 6-action scoring (scout/expand/
  tower/raid/obliterator/wait), personality-weighted, mood-aware narrative generation
- `faction_reputation` + `faction_diplomacy_log` tables — 7 diplomatic status tiers
  (nemesis → allied), atomic reputation adjustments, combat targeting influenced by rep
- `adaptive-threats.js` — ONNX model (14→20→14→4 MLP), difficulty/category/timing/cost
  scaling from player response history. Threat history table for learning.

**Mile 29 — AI Profiles**: `ai-profiles.js` (294 lines). Three-tier system:

- **Preset** — 5 profiles shipped with Obsidian Scion manifest (Berserker, Turtle,
  Diplomat, Expansionist, Balanced)
- **Custom** — player-created via slider UI, max 20 per realm
- **NPU-Generated** — text description → personality vector via SEVA inference
- 7 REST API endpoints + `POST /generate` for NPU text→personality conversion
- `applyProfile()` copies personality + dialogue tags onto a realm faction

---

#### 📊 Stats

| Metric | Value |
|--------|-------|
| Docs pages updated | 48 |
| SVG icon symbols | 69 |
| Google Fonts references removed | 192 lines across 48 files |
| C2C game modules added | 5 (realm-combat, realm-progression, realm-research, realm-tick, ai-profiles) |
| C2C schema tables added | 10 (realms, realm_memberships, realm_story_arcs, realm_factions, realm_faction_planets, realm_narrative_log, realm_research, faction_reputation, faction_diplomacy_log, threat_response_history, ai_profiles) |
| ONNX models added | 2 (faction-brain, adaptive-threat) |
| AI Profile presets | 5 |
| REST API endpoints added | 15+ |
| DESIGN.md milestones documented | 8 (Miles 22–29) |

---

## [3.0.0] - 2026-02-20

### 🏔️ The Mega Release — Every Module Wired, Every Path Hardened

*Theme: "The mesh stands on math. Every protocol alive, every path encrypted, every proof verifiable."*

This is the culmination release. Every protocol module that existed as standalone code is now wired into
a running server. Every security gap identified by audit has been closed. Voting consensus is gone —
replaced by mathematical proof. The ternary backbone runs through every subsystem. Hardware acceleration
routes crypto to the fastest silicon available. And STEADYWATCH delivers real 256-bit quantum entropy
from IBM ibm_marrakesh quantum hardware.

---

#### ⚡ ACCEL — Adaptive Compute & Crypto Engine Layer (`utils/accel.js`, 962 lines)

**New module.** Heterogeneous hardware acceleration that routes cryptographic operations to the
fastest available silicon:

- **CPU-SIMD**: AES-NI, VAES, AVX-512, GFNI detection via timing attestation
- **GPU**: WebGPU compute shader dispatch for batch operations
- **NPU**: ONNX Runtime integration (DirectML, CoreML, CUDA, TensorRT providers)
- Capability probing on startup — no false claims, no assumptions
- `accel.route(operation)` returns optimal backend for each crypto/ML task
- `_probeOnnxRuntime()` — locates and loads `onnxruntime-node` for ML inference
- Wired into **all 12 subsystem files**: security, oracle, mesh, adapters

#### 🧠 ONNX Machine Learning Pipeline

**3 security models** trained and shipping with every node:

| Model | Input → Output | Purpose |
|-------|----------------|---------|
| `entropy-sentinel.onnx` | 32 → 1 | STEADYWATCH entropy quality scoring |
| `sakshi-anomaly.onnx` | 12 → 4 | SAKSHI behavioral anomaly detection |
| `karma-trust.onnx` | 14 → 4 | KARMA trust level prediction |

- **Training pipeline**: `train_models.py` — numpy + ONNX pattern (no PyTorch/TF dependency)
- **Runtime**: `onnxruntime-node` with DirectML (NPU/GPU) and CPU fallback
- **Model manifest**: `models/manifest.json` — versioned, hash-verified
- Total: 22,829 bytes, 24,200 training samples
- NPU inference paths wired into SAKSHI `assessNode()` and KARMA `predictTrustLevel()`

#### 🛡️ STEADYWATCH Ternary-144 Integration (`security/steadywatch.js`, 1,129 lines)

**Quantum-hardware-validated entropy** from IBM ibm_marrakesh (156-qubit Heron r2):

- **SST satellite families**: 48/48/48 (A/B/C) from Hurwitz quaternion coordinates
- **6-trit balanced ternary** satellite addresses (729 addressable slots)
- **Fibonacci 24-cycle** family-aware seed selection (`selectByFibonacciCycle`)
- **Ternary seed quality**: `_checkBiasTernary()` returns `Trit` verdict (+1/0/-1)
- **EntropySentinel** NPU-accelerated quality monitor — `score()` returns numeric + ternary verdict
- **Batch consensus**: `batchQualityConsensus(seeds)` — TritArray aggregate quality
- Seed lookup by trit address: `getSeedByTritAddress(tritAddr)`
- **Result**: Real 256-bit quantum entropy for ANNEX ML-KEM-768 keygen

*Every Yakmesh node provisioned with a quantum-hardware-derived entropy seed,
validated by actual measurement on physical qubits.*

$$\text{Satellites} = 24 \times (p + 1), \quad p=5 \Rightarrow 144 \text{ unique seeds}$$

#### 🔌 Full Protocol Wiring — Zero Orphaned Modules

Every previously-standalone protocol module is now initialized, routed, and serving:

- **KOMM stack** (`server/komm-api.js`, 662 lines) — full HTTP+WS API:
  - KATHA rich chat (reactions, typing, threads, read receipts)
  - VANI voice/video signaling (WebRTC via mesh)
  - YURT room discovery and management
  - GUMBA cryptographic access control (proof-based, E2E over ANNEX)
  - WebSocket at `/komm/ws` — JSON protocol `{ type, data, ts }`
- **DARSHAN** (`server/darshan-api.js`, 343 lines) — content streaming API
  - View-not-copy delivery with attestation
- **NAKPAK** — onion routing initialized with ML-KEM circuits
- **SAKSHI** → **KARMA** pipeline — velocity alerts drive trust accumulation:
  - CRITICAL alerts → negative karma
  - WARNING alerts → neutral beacon sighting
  - Mesh peer connections → positive karma accumulation

#### 🔗 SHERPA HTTP Relay Bridge

**Firewall traversal** for nodes behind NAT/CGNAT:

- `_initRelay()` — HTTP relay bridge alongside WebSocket
- SHERPA auto-connect with explicit beacon endpoints
- PHP bridge compatibility (`/mesh/relay` base endpoint)
- Gossip wired through relay transport
- **PQ-signed relay**: ML-DSA-65 signatures on all relay operations
- Relay client expiry and health visibility
- Caddy WSS template for TLS-terminated WebSocket

#### 🔐 ANNEX Hardening

- Single Annex instance per peer pair + deterministic initiator selection
- Infinite recursion fix in `_send()` (self-encrypting loop eliminated)
- Key derivation fixed with proper replay nonce management
- **PFS-safe rekey** — forward-looking pending key (no gap during ratchet)
- ANNEX relay bridge with `sendTo()` fallback for relay-only peers
- E2E delivery wired into GUMBA `getMessages()` — **zero TODOs remaining**

#### 🔺 TRIBHUJ Deep Integration

- **TRIBHUJ key ratchet** (`identity/tribhuj-ratchet.js`, 506 lines) — Fibonacci-style ternary key rotation
- Gateway attestation with TRIBHUJ proofs
- SSE (Server-Sent Events) for real-time state push
- Tighter drift tolerance in time synchronization
- Ternary + SST backbone wired across: KARMA, DOKO, revocation, strike, sybil, ANNEX

#### ⚖️ A+C Hybrid Integrity — Voting Consensus Removed

**Content validity determined by math, not votes:**

- **A** (Authenticity): Publisher ML-DSA-65 signature over content hash
- **C** (Correctness): SHA3-256 hash integrity verification
- Any node independently verifies both — one proof = proven

**Removed:**

- `ConsensusProof` class (validators, quorum, `hasQuorum`, `addValidator`)
- `content_vote` and `content_validate` gossip handlers
- `quorumSize` config, PENDING/REJECTED `ContentStatus` values
- `/:hash/proof` API endpoint, `X-Consensus-Proof` header

**Added:**

- `ContentStatus`: LOCAL → ANNOUNCED → VERIFIED (no PENDING/REJECTED)
- `publish()` signs content hash with ML-DSA-65, status → ANNOUNCED
- `content_response` verifies hash + publisher signature → VERIFIED
- `/:hash/integrity` API endpoint (hash + publisher sig + status)
- `X-Publisher-Signature`, `X-Published-By`, `X-Verified` response headers
- 8 new integrity verification tests replace 11 voting tests

*Ethos: Voting consensus is inherently flawed (51% attacks).
The math checks out — that's the only consensus needed.*

#### 🔒 Deep Security Audit — 30 Findings Fixed

**Two rounds of comprehensive security hardening:**

1. **2 CRITICALs** — fixed: missing auth bypass, unsigned replication
2. **6 HIGHs** — fixed: unsigned gossip rumors, unverified content votes,
   unsigned replication changes, unauthenticated KOMM/DARSHAN APIs (`requirePeerAuth` wired)
3. **27 findings** from deep review — all resolved
4. **140 new security-focused tests** added
5. Ethos audit: no external dependencies introduced, no centralization
6. ML-DSA-65 signatures verified on **all** incoming mesh messages
7. Comprehensive hardening: SQL injection, auth, encryption across all paths

#### 📊 Complete Statistics

| Metric | Value |
|--------|-------|
| Vitest tests | 1,323 passing |
| Oracle tests | 212 passing |
| **Total tests** | **1,535 (0 failures)** |
| New security tests | 140 |
| Test files | 29 vitest + oracle suites |
| Source files (protected) | 179+ |
| ONNX models | 3 (22,829 bytes) |
| Server module | 3,202 lines |
| SAKSHI module | 1,966 lines |
| STEADYWATCH module | 1,129 lines |
| ACCEL module | 962 lines |

---

## [2.9.0] - 2026-02-10

### 📡 Communication Stack Complete + DHARMA Content Moderation

*Theme: "The full voice of the mesh — from chat to streaming, moderated by behavior, not identity."*

This release completes the 3.0 communication stack (Layers 9–13), adds behavior-based content moderation,
and introduces the adapter framework for extensible chat.

#### 🗣️ Communication Protocol Stack (Layers 9–13)

Five new protocol layers, all documented and tested:

| Layer | Protocol | Purpose | Module |
|-------|----------|---------|--------|
| 9 | GUMBA | Cryptographic access control (proof-based) | `mesh/gumba.js` |
| 10 | YURT | Decentralized room discovery | `mesh/yurt.js` |
| 11 | KATHA | Rich chat (reactions, typing, threads) | `mesh/katha.js` |
| 12 | VANI | Voice/video calls (WebRTC via mesh) | `mesh/vani.js` |
| 13 | DARSHAN | View-not-copy content streaming | `mesh/darshan.js` |

#### 🛡️ DHARMA — Behavior-Based Content Moderation (`security/dharma-moderation.js`, 517 lines)

**धर्म (Sanskrit: "righteous conduct")** — Content moderation that blocks actions, not identities:

- ✅ Violence incitement — blocked
- ✅ Terrorism promotion — blocked
- ✅ Exploitation — blocked
- ❌ NO religious discrimination
- ❌ NO identity-based filtering

Same rules for everyone. That's the law.

#### 🔌 Adapter Framework

Extensible chat plugin system with security built-in:

- **`ContentAdapter`** — serve content over the P2P mesh
- **`ChatModAdapter`** — add `/slash` commands to KATHA
- Capability declaration required for all adapters
- Response signing for verification
- Rate limiting by default
- **MLV Bible Adapter** — example implementation included

#### 🛡️ Active Defense Systems

- **VEGATI** velocity detection — behavioral velocity monitoring across dimensions
- **ZIMMEDARI** attestation accountability — revocation with lineage tracking
- Trust-proportional rate limits — higher trust = higher throughput
- STUPA revocation broadcasts — mesh-wide revocation propagation

#### 🔬 Security Audit

16 modules analyzed against three principles: SECURITY (crypto, zero-trust), OPPORTUNITY (no gatekeeping), ETHOS (no external dependencies).

**Result: 96.7% compliant** — 14 fully compliant, 2 acceptable by design, 0 violations.

#### 📚 Documentation

- GUMBA, YURT, KATHA, VANI, DARSHAN — all documented with full HTML pages
- Protocol stack table dynamically generated from `nav-order.json`
- Silhouette illustrations for all communication protocols
- 87 doc files synced with sidebar navigation
- Adapters guide with ContentAdapter and ChatModAdapter examples
- Security + Opportunity + Ethos audit report published
- v2.9.0 release announcements for X, Discord, Telegram

#### 📊 Packaging

- 212 tests passing (0 regressions)
- 105 documentation files (2.59 MB bundle)
- 179 protected source files

---

## [2.8.3] - 2026-02-19

### 📡 MA-902 SNMP Integration — Hardware GPS Telemetry for MANI

*Theme: "The celestial stones speak through silicon."*

#### 🛰️ New Module: `oracle/ma902-snmp.js` (662 lines)

- **MA902Monitor** class — SNMP v2c monitor for MA-902/S-C1 GPS Gigabit Time Server
- Queries enterprise OID `1.3.6.1.4.1.26381` (Chongqing Miaoan Technology)
- 12 proprietary OIDs mapped: GPS time, sub-seconds, lock status, reference source,
  constellation bitmask, satellites (visible/used/tracking), alarm, quality, offset
- Lazy-loads `net-snmp` — nodes without MA-902 hardware are unaffected
- Configurable poll interval (default 10s), auto-reconnect on connection loss
- Event-driven: `telemetry`, `lockLost`, `lockAcquired`, `alarm`, `trustChanged`,
  `satelliteDegradation`, `connectionLost`, `connectionRestored`
- **Trust assessment engine** translates satellite telemetry → MANI trust levels:
  - Excellent (≥8 sats, confidence 1.0), Good (≥5, 0.625+), Marginal (≥3, 0.375+)
  - Clock delta sanity check (GPS leap second aware, rejects >120s drift)
  - Alarm and lock status validation

#### 🔗 ManiTimeDetector Integration

- `ManiTimeDetector` now accepts `ma902: { host, pollInterval }` config option
- GPS detection enriched with live SNMP data: satellite counts, constellation info,
  lock status, timing quality — all from hardware, not just NTP inference
- NTP source cross-referenced: detects when w32tm/chrony source IP matches MA-902
- `getStatus()` includes full MA-902 monitor status in API responses
- MA-902 events forwarded through detector: `ma902:telemetry`, `ma902:lockLost`, etc.
- Trust level auto-re-evaluates on MA-902 state changes (lock loss triggers re-detect)
- **Result: Trust level upgraded from NTP → GPS** when MA-902 is reachable

#### 📊 Verified Live Results

```
Trust Level: GPS (was NTP)
Phase Tolerance: ±500ms (was ±5000ms — 10x tighter)
Primary Source: gps (MA-902/S-C1)
Satellites: 6 used / 8 tracking / 10 visible
Constellations: GPS + BeiDou
Lock: YES | Alarm: NONE | Clock Delta: 0s
MA-902 Backed NTP: YES (w32tm source = 192.168.1.30)
High Precision Time: TRUE
```

#### 📦 Packaging

- `net-snmp` added as **optionalDependency** (not required for non-MA-902 nodes)
- Export path: `yakmesh/oracle/ma902-snmp`
- 212/212 tests passing (0 regressions)

---

## [2.8.2] - 2026-02-05

### 📦 Documentation Release: TRIBHUJ Ternary Systems

*Theme: "The math testifies in place of the node."*

#### 📚 Documentation

- **TRIBHUJ** - Balanced ternary mathematics system (`{-1, 0, +1}`) with 684-line implementation
- **YPC-27** - 27-trit quantum-hard checksums (SIS hardness proof)
- **SAKSHI** - Observational capability system reference (no permissions, only observations)
- **Protocol Stack** - Updated to 20 layers with new modules
- **Cross-linking** - YPC-27 integration callouts in STUPA, NAKPAK, SHERPA docs
- **Version badges** - All pages updated to v2.8.2

#### 🔐 Security

- **khata-trust-integration.js** - ML-DSA-65 signature verification for silicon challenge responses

#### 📦 Packaging

- **Self-hosted docs** - website/ folder now bundled in npm package
- **embedded-docs/serve.js** - Updated path resolution for bundled docs
- **81 documentation files** - HTML, CSS, assets included for offline serving

#### 🔺 TRIBHUJ Acronym Update

- Changed from "Jugaad" to "Junction" for better international adoption
- Full: "Ternary Radix Implementation — Balanced Harmonic Universal Junction"

---

## [2.8.1] - 2026-02-05

### 👁️ SAKSHI Observational Capability System + VIVAAD Disagreement Analysis

*Theme: "The math testifies in place of the node."*

#### 🧘 Philosophy Shift

This release formalizes YAKMESH's rejection of voting-based consensus in favor of **mathematical agreement**:

- **No permissions, only observations** - Nodes are witnesses, not gatekeepers
- **No voting, only math** - Disagreement → recompute, not majority rule
- **No denial systems** - Every node can attempt any action; math decides success
- **Assume good faith** - 95% of disagreements are hardware/timing, not malicious

#### 🔬 SAKSHI Module (`security/sakshi.js`)

**साक्षी (Sanskrit: "witness")** - Observational capability system:

- `CAPABILITY_LEVEL` - 6 descriptive levels (not permission tiers)
- `NodeWitness` class - No `hasPermission()` method by design
- `fuseTimeAttestations()` - Sensor fusion by precision (physics, not politics)
- `checkMathematicalAgreement()` - Returns `RECOMPUTE_AND_VERIFY` on disagreement
- `rankByReliability()` - Sorting for optimization, not gatekeeping

#### ⚖️ VIVAAD Disagreement Analysis

**विवाद (Sanskrit: "dispute")** - Understanding WHY disagreements happen:

| Category | Est. % | Examples |
|----------|--------|----------|
| Hardware | ~70% | CPU timeout, FP variance, no AES-NI |
| Timing | ~15% | Clock drift, epoch boundary, race condition |
| Network | ~10% | Incomplete data, message ordering |
| Byzantine | ~5% | Deliberate wrong, sybil, compromised |

**New exports:**

- `DISAGREEMENT_CAUSE` - 16 categorized causes
- `REMEDIATION` - 11 remediation actions (no permanent bans)
- `analyzeDisagreement()` - Diagnose likely cause
- `createRemediationPlan()` - Create action plan
- `trackDisagreementPattern()` - Observe patterns over time

#### 🗑️ VARNA Removed

**VARNA** (`security/varna.js`) has been **deleted** as anti-yakmesh ethos:

- `VARNA_PERMISSIONS` gated actions by tier (denial system = attack vector)
- `verifyWeightedVotes()` was voting (politics, not math)
- `VARNA_WEIGHT` gave higher tiers more power (PoW/PoS replication)

**Migration:** Use `SAKSHI` for all capability/observation needs.

#### 🌉 SETU Trust-Tier Bridge

**सेतु (Sanskrit: "bridge")** - Migration path from voting to observation:

- `witnessFromTrustProfile()` - Convert TrustProfile → NodeWitness
- `trustProfileFromWitness()` - Backward compatibility layer
- `checkRevocationAgreement()` - Replaces WeightedRevocationCalculator
- `aggregateAttestations()` - Replaces calculateEffectiveCount()
- `assessComputationTrust()` - Trust based on math, not node tier

**Key difference from old trust-tier patterns:**

| Old (trust-tier) | New (SAKSHI+SETU) |
|------------------|-------------------|
| `getWeight()` → voting power | `qualityScore` → data fusion |
| `calculateEffectiveCount()` | `aggregateAttestations()` |
| `WeightedRevocationCalculator` | `checkRevocationAgreement()` |
| Majority vote wins | Mathematical agreement required |

#### 📊 Test Coverage

- 174 tests passing
- SAKSHI tests include philosophy validation (no permission methods exist)
- SETU bridge tests verify no weighted voting

---

## [2.8.0] - 2026-02-04

### 🔺 TRIBHUJ Balanced Ternary Mathematics

*Theme: "The triangle stands stable on three points."*

#### Core Ternary System (`oracle/tribhuj.js`)

**त्रिभुज (Sanskrit: "triangle")** - Native balanced ternary for YAKMESH:

- `Trit` class - Single balanced ternary digit (-1, 0, +1)
- `TritArray` class - Multi-trit values with arithmetic
- Ternary logic: AND (min), OR (max), consensus
- Path balance calculation for link quality
- Weighted consensus computation

#### TATTVA Ternary ValidationResult

**तत्त्व (Sanskrit: "essence")** - Three-state validation:

- `VALID` (+1), `INVALID` (-1), `PENDING` (0)
- Ternary logic operations: AND, OR, CONSENSUS
- Backward compatible: `result.valid` still works
- Disagreement → PENDING (not forced resolution)

#### LAMA Ternary Consensus

**Retrofitted consensus voting:**

- `ConsensusVote.accept()`, `.reject()`, `.abstain()`
- `computeTernaryConsensus()` with confidence calculation
- Close votes return NEUTRAL (undecided), not forced majority

---

## [2.7.1] - 2026-02-04

### 🔐 YPC-27 Quantum-Hard Packet Checksums

*Theme: "Your packets now carry quantum-resistant armor."*

#### 🎯 Core Integration

- **YPC-27 Checksum Module** (`oracle/ypc27.js`)
  - 27-trit polynomial in ring Z[x]/(x^27-1) mod 3
  - Forging requires solving the Short Integer Solution (SIS) problem
  - 3^27 = 7.6 trillion possible checksum states
  - Single bit flip → all 27 coefficients affected (avalanche)
  - **7 tests** via verification script

- **Packet Checksum Integration** (`oracle/packet-checksum.js`)
  - Domain-separated checksums (prevents cross-protocol attacks)
  - Wire format: `YPC27:v1:<base64-trits>`
  - `wrapWithChecksum()` / `unwrapWithChecksum()` helpers
  - Factory functions: `createStupaChecksum()`, `createNakpakChecksum()`, etc.
  - **14 tests** via verification script

#### 📦 Protocol Integrations

**STUPA Broadcast** (`mesh/beacon-broadcast.js`)

- `StupaMessage` now includes `ypc27` field
- `_computeYpc27()` and `verifyYpc27()` methods
- `isValid(verifyQuantum)` for optional quantum verification
- Checksum verified on `deserialize()` for incoming messages

**NAKPAK Routing** (`mesh/nakpak-routing.js`)

- `NakpakPacket` now includes `ypc27` field
- Checksum computed during `padToFixedSize()` finalization
- `verifyYpc27()` for packet integrity verification
- Checksum verified on `deserialize()` with error on mismatch

**KHATA Protocol** (`security/khata-protocol.js`)

- All message types (ANNOUNCE, REQUEST, RESPONSE, REVOKE) now include checksums
- `_wrapWithYpc27()` and `_verifyYpc27()` helper methods
- Checksum failures logged with stats tracking
- Backward compatible: messages without checksum still accepted

#### 🔒 Security Properties

- **Domain Separation**: Same data produces different checksums for different protocols
- **Deterministic JSON**: Key order doesn't affect checksum (sorted serialization)
- **Quantum Resistance**: Based on lattice problem, resistant to Shor's algorithm
- **Attack Detection**: Invalid checksum logged as potential quantum attack or corruption

---

## [2.7.0] - 2026-02-04

### 🔺 Balanced Ternary Mathematics — Three States of Truth

*Theme: "Binary thinks in absolutes. Ternary embraces the unknown."*

#### 🎯 Core Principles

- **Three-State Logic** - Accept/Reject/Abstain replaces True/False
- **Self-Inverting Negation** - No 2's complement overhead
- **NTRU-Native** - Balanced ternary is the native math for post-quantum crypto
- **Optimal Radix** - Closest integer to e ≈ 2.718 for information density

#### ✅ New Modules

**TRIBHUJ Foundation** (`oracle/tribhuj.js`)

- त्रिभुज (Triangle) — balanced ternary primitives
- `Trit` class: immutable single trit {-1, 0, +1}
- `TritArray` class: arrays with decimal conversion
- `TritState` semantic aliases (VALID/INVALID/PENDING, etc.)
- Kleene 3-valued logic: AND (min), OR (max)
- `weightedConsensus()`: vote aggregation with weights
- `calculatePathBalance()`: path metric calculation
- **36 tests**

**TRISULA Routing** (`mesh/trisula-tree.js`)

- त्रिशूल (Trident) — Ternary Search Tree for peer routing
- `TrisulaTST`: O(k) insert/search where k = key length
- `TrisulaPeerRouter`: XOR-distance peer lookup
- Prefix search for DHT-style routing
- Natural 3-way branching: LEFT/MIDDLE/RIGHT
- **33 tests**

#### 🔄 Retrofits

**TATTVA Validation** (`oracle/validation-oracle-hardened.js`)

- `ValidationResult` now uses ternary state internally
- New methods: `isValid`, `isInvalid`, `isPending`
- New operations: `and()`, `or()`, `consensus()`
- Backwards compatible: `result.valid` still works (deprecated)
- **22 tests**

**LAMA Consensus** (`oracle/consensus-engine.js`)

- New `ConsensusVote` class: ACCEPT/REJECT/ABSTAIN with weights
- `computeTernaryConsensus()`: threshold-based aggregation
- Prevents consensus "flapping" with ABSTAIN votes
- **16 tests**

**KHATA/SHERPA Link Quality** (`mesh/sherpa-discovery.js`)

- New `LinkQuality` class for bidirectional link health
- Outbound/inbound quality as balanced ternary
- `isSymmetric`/`isAsymmetric` detection
- `pathBalance` for routing decisions
- **17 tests**

#### 📊 Balanced Ternary Reference

| Decimal | Balanced Ternary | Representation |
|---------|------------------|----------------|
| -4 | T T 1 | (-1×9) + (-1×3) + (1×1) |
| -3 | T 0 0 | (-1×9) + (0×3) + (0×1) |
| -2 | T 1 | (-1×3) + (1×1) |
| -1 | T | (-1×1) |
| 0 | 0 | (0×1) |
| 1 | 1 | (1×1) |
| 2 | 1 T | (1×3) + (-1×1) |
| 3 | 1 0 | (1×3) + (0×1) |
| 4 | 1 1 | (1×3) + (1×1) |

#### 🔮 Future: NTRU Integration

This release lays the foundation for NTRU post-quantum cryptography:

- NTRU uses ternary polynomials with coefficients in {-1, 0, +1}
- `TritArray` can directly represent NTRU polynomial coefficients
- Self-inverting negation simplifies NTRU arithmetic

---

## [2.6.7] - 2026-02-03

### 📚 Zero External Dependencies

- Quick Reference documentation page
- Local Prism.js bundle (no CDN)
- YAK icon fixes
- **Zero external runtime dependencies**

---

## [2.6.6] - 2026-02-02

### 🏔️ Philosophy & Heritage

- Philosophy documentation page
- Himalayan tribute section
- Favicon fixes across all pages
- Docs bundle sync

---

## [2.6.5] - 2026-02-01

### 🎨 Production CSS

- Production Tailwind CSS build
- Remove CDN dependency for styles
- Fully self-contained documentation

---

## [2.6.4] - 2026-01-31

### 🔧 UI Fixes

- YAK icon fix for Windows 10
- Sidebar toggle fix
- Protocol stack documentation complete
- Docs bundle rebuild

---

## [2.6.3] - 2026-01-30

### 🔧 Bug Fixes

- YAK icon rendering fix
- Sidebar toggle behavior fix
- Protocol stack visualization complete

---

## [2.6.2] - 2026-01-29

### 📝 Documentation

- Documentation fixes
- Network placeholder pages

---

## [2.6.1] - 2026-01-28

### 🎨 Visual Fixes

- KARMA/MANDALA silhouette fixes
- DOKO mobile responsiveness
- Navigation improvements

---

## [2.6.0] - 2026-01-27

### 📖 GRANTH Embedded Documentation Bundle

*Theme: "The code carries its own scripture."*

- **GRANTH** (`embedded-docs/`) - Hash-verified documentation bundle
- Himalayan naming convention formalized
- KARMA trust tier documentation
- Unified announcements (Discord + Telegram)
- Network identity clarification (code hash, not salts)

---

## [2.5.0] - 2026-01-20

### 🌍 Geographic Exclusion — Physics Don't Lie

*Theme: "Speed of light is the ultimate validator. We prove where you CANNOT be."*

#### 🎯 Core Principles

- **Unforgeable Distance** - Speed of light provides cryptographic lower bound on distance
- **Exclusion Zones** - Prove where nodes CANNOT be, not precise location
- **No GPS Required** - RTT + physics = provable geography
- **Network Overhead is Safe** - Latency only inflates RTT, making zones always valid

#### ✅ Implemented Features

**Geographic Proof Core** (`security/geo-proof.js`)

- Speed-of-light distance calculation (fiber = 0.67c)
- LandmarkRegistry for known geographic reference points
- RTTMeasurement with jitter handling and averaging
- ExclusionZone creation from RTT measurements
- GeographicProof with confidence scoring
- GeoProofService for full lifecycle management
- **59 tests**

**KHATA Gossip Integration** (`security/khata-trust-integration.js`)

- 6 new message types for geo-proof gossip:
  - GEO_PROOF_ANNOUNCE, GEO_PROOF_REQUEST, GEO_PROOF_RESPONSE
  - LANDMARK_ANNOUNCE, LANDMARK_REQUEST, LANDMARK_VERIFY
- Geo-proof announcement and request handling
- Landmark discovery via gossip
- **14 new tests** (36 total)

**CLI Commands** (`cli/index.js`)

- `yakmesh geo status` - Show geographic proof status
- `yakmesh geo landmarks` - List known landmarks
- `yakmesh geo zones` - List exclusion zones
- `yakmesh geo prove` - Generate geographic proof
- `yakmesh geo verify <nodeId>` - Verify another node
- `yakmesh geo add-landmark <name>` - Add landmark manually
- `yakmesh geo physics` - Show speed-of-light constants

**Server API Endpoints** (`server/index.js`)

- `GET /geo/status` - Geographic proof status and physics constants
- `GET /geo/landmarks` - List registered landmarks
- `POST /geo/landmarks` - Add a landmark
- `GET /geo/zones` - List exclusion zones
- `POST /geo/prove` - Generate geographic proof
- `POST /geo/verify` - Verify another node's claims

**SHERPA Beacon Integration** (`mesh/sherpa-discovery.js`)

- RTT measurement during beacon fetch (performance.now())
- Geographic coordinates in BeaconMessage (lat, lon, name, accuracyKm, timeTier)
- Automatic landmark discovery from geo-enabled beacons
- RTT sample averaging with configurable window
- Protocol version bumped to 1.1 for geo support
- New SherpaDiscovery methods:
  - `setGeoCoordinates()` - Configure this node as landmark
  - `setGeoProofService()` - Connect to GeoProofService
  - `getGeoLandmarks()` - List discovered landmarks
  - `getRttMeasurements()` - Get RTT data for proof generation
- **31 tests**

#### ⚡ Speed-of-Light Physics

| RTT | Minimum Distance |
|-----|------------------|
| 1 ms | ≥100 km |
| 5 ms | ≥500 km |
| 10 ms | ≥999 km |
| 50 ms | ≥4,997 km |
| 100 ms | ≥9,993 km |
| 200 ms | ≥19,986 km |

**Formula:** `minDistance = (RTT / 2) × fiberSpeed`

- Vacuum speed: 299,792.458 km/s
- Fiber speed (0.67c): 199,861.639 km/s

#### 📊 Test Summary

| Module | Tests | Status |
|--------|-------|--------|
| Geo Proof Core | 59 | ✅ |
| KHATA Geo Integration | 14 | ✅ |
| SHERPA Geo Integration | 31 | ✅ |
| **v2.5 Total** | **104** | ✅ |

#### 🔮 Implementation Notes

- Dashboard visualization skipped (privacy concern - CLI provides same data)
- SHERPA beacons now serve as geographic landmarks automatically
- RTT measured using high-resolution `performance.now()` timing

---

## [2.4.0] - 2026-01-19 (Internal)

### 🤝 Mathematical Trust — No Simulation

*Theme: "You can't fake physics. Atomic time and real silicon are your credentials."*

> **Note**: This version was developed internally and released as part of v2.5.0.

#### 🎯 Core Principles

- **No Simulation** - Must prove real AES-NI hardware through timing analysis
- **Atomic Precision** - Highest trust requires physical time sources
- **Mathematical Consensus** - Revocation through signature counting, not voting

#### ✅ Implemented Features

**Mesh-Consensus Revocation** (`security/mesh-revocation.js`)

- 2/3 threshold attestation-based revocation
- Post-quantum signed attestations (ML-DSA-65)
- Revocation certificates with threshold proof
- **41 tests**

**Hardware Attestation** (`security/hardware-attestation.js`)

- AES-NI timing verification to prove real silicon
- Challenge-response protocol for peer verification
- Bot farms and VMs fail timing checks
- **5 tests**

**Trust Tier System** (`security/trust-tier.js`)

- ORACLE (2.0x): Atomic clock + AES-NI + 30 days
- ANCHOR (1.5x): GPS+PPS + AES-NI + 14 days  
- SENTINEL (1.25x): PTP + AES-NI + 7 days
- PARTICIPANT (1.0x): NTP + AES-NI
- OBSERVER (0.25x): Unverified
- **35 tests**

**Silicon Parity** (`security/silicon-parity.js`)

- "One Silicon = One Vote" anti-ASIC/farm defense
- Weight division: `tierMax / coreCount`
- 100-core rig = same weight as 1-core
- AES-NI fingerprint as unique silicon identity
- **36 tests**

**Sybil Graph Analysis** (`security/sybil-graph.js`)

- Clustering coefficient detection (>0.7 = suspicious)
- Edge cut ratio analysis (<0.1 = insular cluster)
- Component analysis for cluster isolation
- Behavior correlation (uptime, activity patterns)
- **44 tests**

**KHATA Trust Integration** (`security/khata-trust-integration.js`)

- Gossip layer for trust messages over KHATA protocol
- 8 new message types for attestation/challenge routing
- Deduplication and hop limit enforcement
- Trust synchronization between peers
- **22 tests**

**Strike System** (`security/strike-system.js`)

- "Three Strikes — Then Math Speaks"
- Hardware fingerprint tracks identity across fresh starts
- Strike 1: Fresh start allowed, recorded
- Strike 2: 7-day probation, reduced trust (0.5x)
- Strike 3: Permanent network ban
- Revocation bridge for automated strike issuance
- **31 tests**

#### 📊 Test Summary

| Module | Tests | Status |
|--------|-------|--------|
| Mesh Revocation | 41 | ✅ |
| Hardware Attestation | 5 | ✅ |
| Trust Tiers | 35 | ✅ |
| Silicon Parity | 36 | ✅ |
| Sybil Graph | 44 | ✅ |
| KHATA Integration | 22 | ✅ |
| Strike System | 31 | ✅ |
| **v2.4 Total** | **214** | ✅ |

**Project Total**: 598 + 214 = **812 tests**

See [ROADMAP-2.4.0.md](docs/ROADMAP-2.4.0.md) for full details.

---

## [2.3.0] - 2026-01-20

### 🧪 Testing Expansion, BYOND Adapter & Bug Fixes

This release expands test coverage from 352 to 598 tests with comprehensive mesh module testing and adds the BYOND game server adapter.

#### 📊 Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| **Oracle** | 98 | ✅ All passing |
| **Protocol** | 56 | ✅ All passing |
| **Multi-Node** | 18 | ✅ All passing |
| **BYOND Adapter** | 36 | ✅ All passing |
| **Security (Vitest)** | 390 | ✅ All passing (55 skipped) |
| **Total** | **598** | **543 passing, 55 skipped** |

#### 🎮 BYOND Game Server Adapter

New adapter for integrating BYOND games (Space Station 13, Pondera, etc.) with Yakmesh:

- **Topic Protocol** - Native BYOND wire protocol implementation
- **HTTP Bridge** - REST API for DreamDaemon communication
- **Server Discovery** - Find BYOND servers via mesh gossip
- **World Persistence** - Save/load world data to mesh storage
- **DOKO Integration** - Cryptographic identity for game servers
- **DMAPI Library** - Drop-in DM code for game developers

**Files:**

- `adapters/adapter-byond/index.js` - Main adapter
- `adapters/adapter-byond/topic-client.js` - Wire protocol
- `adapters/adapter-byond/http-bridge.js` - HTTP server
- `adapters/adapter-byond/security.js` - DOKO verification
- `adapters/adapter-byond/dmapi/` - DM library

#### ✅ New Test Files

- `mesh/tests/nakpak-routing.test.js` - 52 tests for NAKPAK onion routing
- `mesh/tests/sherpa-discovery.test.js` - 57 tests for SHERPA peer discovery
- `mesh/tests/annex.test.js` - 64 tests for ANNEX encrypted channels
- `security/tests/khata-protocol.test.js` - 38 tests for KHATA trust protocol
- `security/tests/mesh-auth.test.js` - 54 tests for WebSocket authentication
- `adapters/adapter-byond/tests/*.test.js` - 36 tests for BYOND integration

#### 🐛 Bug Fixes

- **Fixed ML-KEM768 cipherText capitalization** - `ml_kem768.encapsulate()` returns `{cipherText}` with capital T, not `{ciphertext}`. Fixed in `nakpak-routing.js` and `annex.js`
- **Fixed mesh-auth.js import** - Changed `@noble/hashes/sha3` to `@noble/hashes/sha3.js` for proper ESM resolution
- **Fixed oracle path normalization** - Consistent cross-platform path handling

#### 🤖 YakBot Updates

- Updated to v2.3.0 with current features
- Enhanced AI context with NAMCHE/DOKO, adapters, 598 tests
- New FAQ entry for security features
- Added YakBot deployment package to build system

#### 📝 Notes

Some tests are skipped pending full key exchange implementation or complex async mocking requirements. These represent edge cases that work correctly in production but need specialized test infrastructure.

## [2.2.0] - 2026-01-18

### ✨ YAK:// Protocol v2.2.0 - Remote Bookmarks, DOKO Revocation & Comprehensive Testing

**This release includes all features from v2.0.1, v2.1.0, and v2.2.0 (combined release).**

#### 📋 Complete v2.2.0 Feature Summary

| Category | Features Added |
|----------|----------------|
| **YAK:// Protocol** | Custom URL scheme, builtin routes, content addressing |
| **Local Bookmarks** | Pet names, CLI commands, REST API, dashboard UI |
| **Remote Bookmarks** | Mesh gossip sync, subscribe/publish, priority resolution |
| **DOKO Revocation** | Self-revocation, emergency certificates, reason codes |
| **SSL/TLS Binding** | Certificate fingerprints, domain binding, verification |
| **Domain Transfers** | Request/authorize workflow, completion proofs |
| **TypeScript** | Full `.d.ts` type definitions |
| **Testing** | 352 tests (Oracle 98, Protocol 56, Multi-Node 18, Security 180) |
| **Developer Experience** | Vitest config, npm scripts, expanded README |
| **Bug Fixes** | ML-DSA-65 argument order, beacon signature verification |

This release adds mesh-synchronized bookmark sharing, key compromise recovery, and brings test coverage to 352 tests across all modules.

#### 🌐 Remote Bookmarks (Mesh Sync)

Share bookmark lists between nodes via gossip protocol. Subscribe to trusted nodes and receive their bookmarks automatically.

**New Class: `RemoteBookmarkSync`**

- **Publish**: Share your bookmarks to the mesh (`yakmesh bookmark share <list-name>`)
- **Subscribe**: Follow other nodes' bookmark lists (`yakmesh bookmark subscribe <node-id>`)
- **Sync**: Automatic sync via gossip protocol
- **Priority**: Local bookmarks always override remote ones

**Dashboard UI:**

- New "Remote Bookmarks" panel with subscription management
- Subscribe/Unsubscribe buttons
- Publish your bookmarks to mesh
- View remote bookmarks from subscribed nodes

**REST API:**

- `GET /bookmarks/remote/status` - Sync status and stats
- `GET /bookmarks/remote` - List remote bookmarks
- `POST /bookmarks/remote/subscribe` - Subscribe to a node
- `POST /bookmarks/remote/unsubscribe` - Unsubscribe from a node
- `POST /bookmarks/remote/publish` - Publish your bookmarks

#### 🔑 DOKO Revocation (Key Compromise Recovery)

Emergency revocation system for compromised DOKO identities.

**New Class: `DOKORevocation`**

- **Self-revocation**: Sign revocation with your own key (if available)
- **Emergency revocation**: Pre-generated "break-glass" certificates
- **Verification**: Validate revocation certificates with ML-DSA
- **Broadcast**: Share revocations via gossip to prevent trust in compromised DOKOs

**Revocation Reasons:**

- `KEY_COMPROMISED` - Private key leaked or stolen
- `DOKO_SUPERSEDED` - Replaced by new DOKO
- `IDENTITY_RETIRED` - Voluntary retirement
- `LOST_ACCESS` - Lost access to private key
- `AFFILIATION_ENDED` - Left organization

**Usage:**

```javascript
// Generate emergency cert when creating DOKO (store offline!)
const emergencyCert = DOKORevocation.generateEmergencyCertificate(doko, privateKey);

// Self-revoke if key is compromised but still accessible
const revocation = DOKORevocation.createSelfRevocation(doko, privateKey, 'key_compromised');

// Activate emergency revocation if key is lost
DOKORevocation.activateEmergencyRevocation(emergencyCert);

// Check if a DOKO is revoked
const status = DOKORevocation.isRevoked(dokoId);
```

#### ✅ Comprehensive Test Coverage

**352 tests across all modules:**

| Suite | Framework | Tests |
|-------|-----------|-------|
| Oracle | Node.js test runner | 98 |
| Protocol | Node.js test runner | 56 |
| Multi-Node | Node.js test runner | 18 |
| Security | Vitest | 180 |
| **Total** | | **352** |

**New Test Files:**

- `protocol/tests/yak-protocol.test.js` - 56 tests for URL parsing, bookmarks, DOKO integration
- `tests/multi-node.test.js` - 18 tests for cross-node sync with mock network

#### 🎨 Dashboard Improvements

- **Bookmarks Panel**: Add, list, remove local bookmarks
- **Remote Bookmarks Panel**: Subscribe, publish, view mesh-synced bookmarks
- **Version**: Updated to v2.2.0

---

## [2.1.0] - 2026-01-18

### ✨ YAK:// Protocol v2.1.0 - Bookmarks, SSL Binding & Domain Transfers

This release completes Phase 2 of the YAK:// protocol implementation with local bookmarks, SSL/TLS certificate binding, and secure domain transfer workflows.

#### 🔖 Local Bookmarks (Phase 2)

Personal "pet names" for YAK:// addresses. No global registry needed - bookmarks are local to your node.

**Features:**

- **BookmarkManager**: Manages local bookmarks stored in `data/bookmarks.json`
- **URL Resolution**: Bookmarks are resolved after builtins, before content hashes
- **CLI Commands**: Full bookmark management via CLI
  - `yakmesh protocol bookmark add <name> <target>` - Add bookmark
  - `yakmesh protocol bookmark list` - List all bookmarks
  - `yakmesh protocol bookmark get <name>` - Get bookmark details
  - `yakmesh protocol bookmark rm <name>` - Remove bookmark
- **REST API**: `/bookmarks` endpoints for programmatic access
  - `GET /bookmarks` - List all bookmarks
  - `GET /bookmarks/:name` - Get specific bookmark
  - `POST /bookmarks` - Add bookmark
  - `DELETE /bookmarks/:name` - Remove bookmark

**Usage:**

```bash
# Add a bookmark
yakmesh protocol bookmark add docs yak://site/docs

# Use the bookmark
yakmesh protocol open yak://docs

# Test resolution
yakmesh protocol test yak://docs
# → http://localhost:3000/site/docs
```

#### 🔐 SSL/TLS Certificate Binding

Bind SSL certificates to DOKO identities for enhanced domain verification.

**New Class: `DOKOCertBinding`**

- `computeFingerprint(cert)` - SHA-256 fingerprint from PEM or DER certificate
- `createBinding(options)` - Create SSL binding for a domain
- `addBinding(doko, binding)` - Add binding to DOKO extensions
- `verifyBinding(binding, cert)` - Verify certificate matches binding
- `getBindingForDomain(doko, domain)` - Get binding for specific domain
- `validateBindings(doko)` - Validate all bindings (expiration, etc.)

**Cryptographic Chain:**

```
Domain → SSL Certificate → DOKO Identity → Mesh Verification
```

**19 tests** covering fingerprint computation, binding management, and verification.

#### 🔄 Domain Transfer Workflow

Secure ownership transfer of domains and DOKO-bound assets.

**New Class: `DOKOTransfer`**

- `createRequest(options)` - Create transfer request with expiration
- `authorize(request, signature, nodeId)` - Owner authorizes transfer
- `reject(request, reason)` - Owner rejects transfer
- `cancel(request)` - Requester cancels pending transfer
- `verifyAuthorization(transfer, publicKey)` - Verify owner signature
- `complete(transfer, toNodeId)` - Complete transfer with proof
- `createProof(completedTransfer)` - Generate mesh-verifiable proof

**Transfer Flow:**

```
New Owner → Request → Current Owner → Authorize → 
Mesh Verifies → Complete → Ownership Updated
```

**Transfer States:** `pending`, `authorized`, `completed`, `rejected`, `expired`, `cancelled`

**Transfer Types:** `domain`, `website`, `asset`

**19 tests** covering request creation, state transitions, completion, and proof validation.

#### 📊 Test Results

| Test Suite | Tests | Status |
|------------|-------|--------|
| Oracle Tests | 98 | ✅ Pass |
| Security Tests | 152 | ✅ Pass |
| DOKO Identity | 60 | ✅ Pass |
| **Total** | **310** | ✅ All Pass |

#### 🔧 Other Changes

- Updated protocol version to 2.1.0
- Fixed regex in DOKO ID format test (mixed case shortId)
- Improved BookmarkManager normalization (simple `/` prefix)

---

## [2.0.1] - 2026-01-18

### 🔧 Security Patch & Export Completeness

This patch release fixes critical ML-DSA-65 argument order bugs discovered during post-release audit.

#### 🐛 Bug Fixes

##### ML-DSA-65 Argument Order (CRITICAL)

Fixed incorrect argument order in two files where the noble-post-quantum API was used incorrectly:

- **`oracle/module-sealer.js`**: Fixed `sign()` and `verify()` argument order
  - `sign(secretKey, message)` → `sign(message, secretKey)` ✅
  - `verify(publicKey, message, signature)` → `verify(signature, message, publicKey)` ✅

- **`mesh/nakpak-routing.js`**: Fixed `sign()` and `verify()` argument order
  - Same corrections as above

**Impact**: Module attestations and NakPak routing signatures were failing validation.

##### JSON Serialization in DOKO Identity

Fixed `getSignableBytes()` to properly serialize nested objects using recursive key sorting.

#### ✨ New Exports

Added missing module exports to `package.json`:

| Export Path | Module |
|-------------|--------|
| `./security/khata-protocol` | KHATA peer endorsement protocol |
| `./security/mesh-auth` | Mesh authentication |
| `./identity/node-key` | Node key management |
| `./mesh/annex` | ANNEX encrypted P2P channels |
| `./mesh/temporal-encoder` | Temporal encoding utilities |

#### 📋 Release Process

Added `RELEASE_CHECKLIST.md` with pre-release verification steps including:

- Cryptographic API argument order verification
- Export file existence checks
- Documentation accuracy review

---

## [2.0.0] - 2026-01-18

### 🧭 NAMCHE Gateway & 📜 DOKO Identity — The "Sherpa Security Stack"

This major release introduces **mathematical trust** — replacing certificate authorities with cryptographic proof. The mesh now verifies identity through 7 independent gates, eliminating the need to trust any central authority.

> *"The Sherpa does not prove knowledge by certificate. The Sherpa proves knowledge by walking the path."*

---

#### 🧭 NAMCHE: Network Authenticated Mesh Certificate Hub & Exchange

A 7-gate verification gateway inspired by Nepal's Namche Bazaar — the last checkpoint before Everest.

##### The 7 Gates of Verification

| Gate | Name | Verification |
|------|------|-------------|
| 1 | Cryptographic Gate | Valid ML-DSA-65 signature |
| 2 | Format Gate | DOKO structure compliance |
| 3 | Temporal Gate | Not expired, within clock tolerance |
| 4 | Domain Gate | DNS TXT record verification |
| 5 | Mesh Gate | 3+ peer endorsements (KHATA protocol) |
| 6 | Behavioral Gate | Historical trust score ≥ threshold |
| 7 | Freshness Gate | Proof-of-liveliness within 5 minutes |

##### New Module: `security/namche-gateway.js`

- `NamcheGateway` - Main verification orchestrator
- `GateResult` - Individual gate pass/fail with evidence
- `VerificationReport` - Complete 7-gate assessment
- `TrustDecision` - Final ALLOW/DENY/CHALLENGE decision

##### Trust Levels

```javascript
TRUST_LEVELS = {
  UNTRUSTED: 0,    // Failed critical gates
  BRONZE: 1,       // Passed gates 1-3 only
  SILVER: 2,       // Passed gates 1-5
  GOLD: 3,         // Passed all 7 gates
  PLATINUM: 4      // Gold + extended history
}
```

---

#### 📜 DOKO: Distributed Ownership & Key Object

Self-sovereign identity documents verified by the mesh, not a CA.

##### New Module: `security/doko-identity.js`

- `DOKODocument` - The identity document structure
- `DOKOGenerator` - Create new DOKO documents
- `DOKOValidator` - Validate document structure and signatures
- `DOKOExtensions` - Optional capability declarations

##### DOKO Structure

```javascript
{
  version: "1.0",
  type: "node" | "user" | "service" | "device",
  nodeId: "cryptographic-hash",
  publicKey: "ML-DSA-65 public key",
  created: 1737225600000,
  expires: 1768761600000,
  claims: {
    domain: "example.com",
    name: "My Node"
  },
  extensions: {
    capabilities: ["annex", "nakpak", "sherpa"],
    tlsBinding: { ... }
  },
  endorsements: [...],
  signature: "self-signature"
}
```

---

#### 🔐 mTLS Phase 1: TLS Certificate Binding

Bind DOKO identity to X.509 certificates for TLS-level verification.

##### New Module: `security/tls-binding.js`

- `DOKOCertificateGenerator` - Create X.509 certs from DOKO
- `TLSVerifier` - Verify TLS connections against DOKO
- `TLSCapabilityAdvertiser` - Announce TLS capabilities to mesh

---

#### 🤝 Hybrid Trust Model

Multi-factor trust assessment combining cryptographic proof with behavioral history.

##### New Module: `security/hybrid-trust.js`

- `TrustEvidence` - Collect evidence from multiple sources
- `HybridTrustModel` - Calculate weighted trust scores
- `TrustBasedAccessControl` - Gate features by trust level

##### Trust Factors

| Factor | Weight | Source |
|--------|--------|--------|
| Cryptographic | 40% | NAMCHE gates 1-3 |
| Social | 25% | Mesh endorsements (KHATA) |
| Behavioral | 20% | Historical interactions |
| Temporal | 15% | Identity age, freshness |

---

#### 🌐 Domain Consensus Protocol

Mesh-verified domain ownership without centralized DNS authorities.

##### New Module: `security/domain-consensus.js`

- `DomainClaim` - Claim domain ownership
- `DomainConsensus` - Multi-peer verification
- `DNSVerifier` - Check DNS TXT records

---

#### 📊 Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| NAMCHE Gateway | 37 | ✅ Passing |
| Domain Consensus | 36 | ✅ Passing |
| TLS Binding | 26 | ✅ Passing |
| Hybrid Trust | 30 | ✅ Passing |
| **Total Security** | **129** | ✅ All Passing |

---

#### 🏔️ The Sherpa Protocol Family

| Protocol | Full Name | Purpose |
|----------|-----------|---------|
| **NAMCHE** | Network Authenticated Mesh Certificate Hub & Exchange | 7-gate verification |
| **DOKO** | Distributed Ownership & Key Object | Self-sovereign identity |
| **SHERPA** | Secure Hidden Endpoint Resolution Path Architecture | Peer discovery |
| **NAKPAK** | NAK Protocol for Anonymous Kommunication | Onion routing |
| **ANNEX** | Autonomous Network Negotiated eXchange | Encrypted P2P channels |
| **KHATA** | Kryptographic Handshake for Automated Trust Acceptance | Trust distribution |

---

#### Breaking Changes

- `identity.js` replaced by `doko-identity.js` (migration guide in docs)
- Trust verification now requires NAMCHE gateway for new connections
- Minimum Node.js version: 18.0.0

#### Migration Guide

```javascript
// Before (v1.x)
import { Identity } from 'yakmesh/oracle/identity';
const id = new Identity();

// After (v2.0)
import { DOKOGenerator } from 'yakmesh/security/doko-identity';
const doko = await DOKOGenerator.create({ type: 'node', claims: { name: 'My Node' } });
```

---

## [1.8.0] - 2026-01-18

### 🏔️ SHERPA: Decentralized Peer Discovery

This release implements SHERPA, a novel peer discovery mechanism that uses the public web as a decentralized DHT.

#### New Feature: SHERPA Discovery

##### The Innovation: "The Web IS the DHT"

- Each node exposes `/.well-known/yakmesh/beacon` with its peer list
- Discovery crawls known endpoints to find new peers
- No central authority - truly decentralized bootstrap
- Works with existing CDN infrastructure

##### New Module: `mesh/sherpa-discovery.js`

- `SherpaDiscovery` - Main discovery engine with peer crawling
- `BeaconMessage` - Signed beacon format for peer advertisement
- `PeerRegistry` - Scored peer management with decay
- `createBeaconMiddleware` - Express middleware for beacon endpoint

##### New Endpoints

- `GET /.well-known/yakmesh/beacon` - Advertise this node and known peers
- `GET /sherpa/status` - Discovery statistics
- `GET /sherpa/candidates` - Get connection candidates

##### Configuration

```javascript
// yakmesh.config.js
export default {
  sherpa: {
    enabled: true,
    selfEndpoint: 'https://mynode.example.com',
    wsEndpoint: 'wss://mynode.example.com:9001',
    seeds: ['https://peer1.example.com', 'https://peer2.example.com'],
  },
};
```

##### Beacon Response Format

```json
{
  "version": "1.0",
  "nodeId": "abc123...",
  "networkName": "mobius-rabi-junction",
  "timestamp": 1737225600000,
  "capabilities": { "wsPort": 9001, "supportsAnnex": true },
  "peers": [{ "nodeId": "...", "endpoint": "https://..." }],
  "publicKey": "...",
  "signature": "..."
}
```

---

## [1.7.1] - 2026-01-18

### 🦬 NAKPAK & SHERPA: Yak-Themed Protocol Naming

This release renames dark-themed protocols to yak-themed names for brand consistency.

#### Renamed Protocols

##### NAKPAK (formerly Phantom)

- **N**ested **A**nonymous **K**ernel for **P**rivate **A**uthenticated **K**omms
- Post-quantum onion routing with ML-KEM768 key encapsulation
- File renamed: `phantom-routing.js` → `nakpak-routing.js`
- Classes renamed: `PhantomRouter` → `NakpakRouter`, etc.
- Etymology: NAK (female yak) + PAK (package) = sounds like "knapsack" 🎒

##### SHERPA (new protocol slot)

- **S**ecure **H**idden **E**ndpoint **R**esolution **P**ath **A**rchitecture
- Peer discovery DHT via public web layer
- Guides nodes to find each other like Sherpas guide travelers

#### Protocol Stack Update

```text
1. HTTP API - Public content delivery
2. Annex - Encrypted P2P messaging
3. Gossip - Message propagation
4. Beacon - Emergency broadcast
5. Nakpak - Onion routing (NEW NAME)
6. Sherpa - Peer discovery (NEW)
7. Mesh - Core P2P network
```

---

### 🛡️ SLH-DSA Backup Signatures & Monitoring Dashboard

This release adds defense-in-depth with FIPS 205 hash-based backup signatures and a comprehensive monitoring dashboard.

#### New Features

##### SLH-DSA Backup Signatures (FIPS 205)

- **Dual Algorithm Support:** ML-DSA (lattice-based) + SLH-DSA (hash-based)
- **Level 3:** SLH-DSA-SHA2-192f (hash-based, different cryptographic assumptions)
- **Level 5:** SLH-DSA-SHA2-256f (hash-based, paranoid mode)
- New functions: `signBackup()`, `verifyBackup()`, `signDual()`, `verifyDual()`
- Generate dual keypairs with `generateDualSignatureKeyPairs()`
- Defense-in-depth: if lattice assumptions break, hash-based signatures still hold

##### Monitoring Dashboard

- Updated `/dashboard` with YAKMESH branding
- New `/metrics` endpoint aggregates all node status
- **Oracle Status:** Health, network identity, verified peers
- **Crypto Info:** Active algorithms, security level, NIST standards
- **Time Source:** Trust level, stratum, precision indicators
- **Uptime Tracking:** Human-readable uptime display

##### Dev.to Automation

- GitHub Actions now posts to Dev.to on major releases
- Automated article creation with version info
- Add `DEVTO_API_KEY` to GitHub secrets to enable

#### Technical Details

##### SLH-DSA Key/Signature Sizes

| Level | Public Key | Secret Key | Signature |
|-------|------------|------------|-----------|
| 3 (192f) | 48 bytes | 96 bytes | ~35 KB |
| 5 (256f) | 64 bytes | 128 bytes | ~50 KB |

##### Performance (SLH-DSA is slower than ML-DSA)

- Sign: ~100-160ms (vs 3ms for ML-DSA)
- Verify: ~5-9ms (vs 1ms for ML-DSA)
- Use dual signatures only for high-value operations

#### Added

- `signBackup()`, `verifyBackup()` - SLH-DSA standalone operations
- `signDual()`, `verifyDual()` - Dual signature operations
- `generateDualSignatureKeyPairs()` - Generate both ML-DSA and SLH-DSA keypairs
- `getBackupSignatureAlgorithm()`, `getBackupSignatureName()` - Config accessors
- `/metrics` endpoint for comprehensive node status
- Dashboard cards for Oracle, Crypto, Time Source
- Uptime tracking with human-readable formatting

#### Changed

- `getCryptoSummary()` now includes `backupSignatureAlgorithm` and FIPS 205 in standards
- Dashboard rebranded from "Lantern Mesh" to "YAKMESH"
- `discord-release.yml` now includes Dev.to posting job

---

## [1.6.0] - 2026-01-17

### 🔐 NIST Level 5 (Paranoid Mode) & Cryptographic Unification

This release adds support for NIST Level 5 security and unifies all hash operations to SHA3-256.

#### New Features

##### NIST Level 5 Support

- Configurable security levels: Level 3 (default) or Level 5 (paranoid)
- **Level 5 Algorithms:**
  - ML-DSA-87 (Dilithium5) for signatures - 256-bit classical security
  - ML-KEM-1024 (Kyber1024) for key encapsulation - 256-bit classical security
- New `security/crypto-config.js` module for centralized crypto configuration
- Runtime switchable via `setSecurityLevel(SecurityLevel.LEVEL_5)`

##### Crypto Agility Documentation

- New `docs/CRYPTO-AGILITY.md` formalizes algorithm upgrade procedures
- Version negotiation protocol for future algorithm transitions
- Monitoring list for future algorithm candidates (X-Wing, SLH-DSA, etc.)

##### Post-Quantum Test Suite

- Comprehensive cryptographic tests in `oracle/tests/crypto.test.js`
- Tests for ML-DSA-65/87, ML-KEM-768/1024
- Performance benchmarks for Level 3 vs Level 5 overhead
- Run with `npm run test:crypto`

#### Changed

##### Unified SHA3-256 Hashing

All hash operations now use SHA3-256 for post-quantum consistency:

- `oracle/network-identity.js` - HKDF now uses SHA3-256
- `oracle/phase-epoch.js` - Phase derivation uses SHA3-256
- `gossip/protocol.js` - Bloom filters and message IDs use SHA3-256
- `mesh/temporal-encoder.js` - Temporal hashes use SHA3-256
- `mesh/nakpak-routing.js` - Key derivation uses SHA3-256 (formerly phantom-routing)
- `mesh/annex.js` - Session key derivation uses SHA3-256
- `mesh/echo-ranging.js` - Probe key derivation uses SHA3-256

### Added

- `security/crypto-config.js` - Centralized crypto configuration module
- `docs/CRYPTO-AGILITY.md` - Algorithm upgrade path documentation
- `oracle/tests/crypto.test.js` - PQ cryptography test suite
- `npm run test:crypto` script for running crypto tests

### Technical Details

- SHA3-256 provides 128-bit post-quantum security (Grover resistance)
- All symmetric keys derived from PQ-safe shared secrets
- No vulnerable classical asymmetric crypto in codebase

---

## [1.5.1] - 2026-01-17

### 🔧 Maintenance Release

- Port fallback system for WebSocket and HTTP servers
- Process management script (`scripts/start.sh`)
- Discord webhook integration for releases
- Minor documentation updates

---

## [1.5.0] - 2026-01-17

### 🔧 Critical Fix: Network Identity Unification

This release fixes a fundamental issue where nodes running identical code were generating different node IDs, preventing them from recognizing each other as peers on the same network.

#### The Problem (v1.4.0 and earlier)

- Node IDs were derived from **random public key** entropy
- Each node got a unique ID regardless of codebase
- Nodes couldn't verify they were on the same network by comparing node IDs

#### The Solution (v1.5.0)

- Node IDs now composed of TWO parts:
  1. **Network Name** - Derived from codebase hash (SAME for all nodes on network)
  2. **Instance ID** - Derived from public key (UNIQUE per node)
- Format: `node-[network-name]-[instance-id]`
- Example: `node-qubit-lattice-prism-pq-a7x9`

#### Human Verification

- All nodes on the same network share the same **network name** and **verification phrase**
- Users can verbally verify: "Are you on qubit-lattice-prism?"
- If network names match = same code = can peer

### Changed

- `identity/node-key.js` - Node ID generation now uses codebase hash for network name
- `server/index.js` - Oracle initialized BEFORE identity (provides codebase hash)
- `node-key.json` now stores `networkName`, `verificationPhrase`, and `codebaseHash`
- Identity automatically regenerates if codebase changes

### Added

- `setCodebaseHash()` / `getCodebaseHash()` exports from identity module
- `getNetworkIdentity()` method on NodeIdentity class
- Codebase change detection - warns and regenerates identity on code updates

### Breaking Changes

- Existing `node-key.json` files will trigger identity regeneration
- Old node IDs are no longer compatible with v1.5.0 network naming

---

## [1.4.0] - 2026-01-16

### 🔐 Yakmesh Annex - Post-Quantum Encrypted P2P Channels

#### Annex: Autonomous Network Negotiated Encrypted eXchange

- ML-KEM-768 (Kyber) key encapsulation for quantum-resistant key exchange
- AES-256-GCM authenticated encryption for message confidentiality
- Perfect Forward Secrecy - session keys rotate every 5 minutes or 10,000 messages
- Replay protection via sequence numbers in AAD
- Three-message handshake: INIT → ACCEPT → CONFIRM

### Added

- `mesh/annex.js` - Complete Annex implementation (744 lines)
- AnnexEnvelope class for encrypted message wrapping
- AnnexSession class for per-peer session management
- Annex main class for channel orchestration
- Documentation at `website/docs/annex.html`
- Whitepaper section 3.4 for Yakmesh Annex

---

## [1.3.2] - 2026-01-17

### Added

- **Public Content Delivery API** - Content-addressed storage for decentralized website hosting
- `GET /content` - List available content with stats
- `GET /content/:hash` - Fetch content by hash with optional proof
- `POST /content` - Publish content with consensus verification
- Content gossip via mesh for cross-node synchronization
- Consensus proof system for verified content

### Fixed

- Gossip protocol method calls (use `spreadRumor()` instead of `broadcast()`)
- Direct messaging via mesh instead of non-existent gossip.sendTo()

### Community

- Added social links: Discord, Telegram, X (Twitter)
- Created Discord announcement template

---

## [1.3.1] - 2026-01-16

### Security

- Hardened peer handshake protocol validation
- Enhanced network fingerprint verification in HELLO/WELCOME exchange
- Added CodebaseLock module for runtime source integrity

### Added

- 3-node test infrastructure for protocol verification
- iO-style (indistinguishability obfuscation) network identity derivation
- Human-readable network names from codebase fingerprint

### Fixed

- Config path resolution for relative/absolute paths
- Test suite node ID prefix assertion

---

## [1.3.0] - 2026-01-15

### 🌟 Major New Systems - "A Beacon in the Darkness"

#### ECHO - Encrypted Coordinate Heuristic Oracle

- Privacy-preserving network topology discovery
- Virtual coordinate system for latency estimation
- Encrypted timing probes (AES-256-GCM)
- Route optimization through coordinate-based pathfinding

#### PULSE - Precision Universal Latency Sync Engine  

- Mesh heartbeat system with cryptographic proofs
- Node liveness detection (alive/suspect/dead states)
- Network partition detection with confidence scoring
- Raft-inspired leader election using heartbeat chains

#### PHANTOM - Post-quantum Hidden Anonymous Network Transmission

- **First-ever post-quantum onion routing implementation**
- ML-KEM-768 (Kyber) key encapsulation per layer
- Multi-layer encryption with temporal padding
- Decoy traffic injection (10% probability)
- Fixed packet sizing to prevent length analysis

#### BEACON - Broadcast Emergency Alert Channel Over Network

- Priority message propagation (ROUTINE → CRITICAL)
- Flood-based protocol with intelligent deduplication
- Proof-of-receipt for delivery confirmation
- TTL-based propagation control

### 📊 Test Coverage

- 68 tests total (18 TME + 24 Security + 26 Novel Systems)
- All tests passing

### 🔐 Security Improvements

- Enhanced cryptographic hashing (SHA3-256)
- Timing attack resistance in PHANTOM
- Improved rate limiting integration

### 🛡️ Code Proof Protocol Hardening

- **CRITICAL FIX**: HELLO message now includes `networkFingerprint`
- **CRITICAL FIX**: WELCOME handler validates fingerprint, rejects mismatches (code 1008)
- Added `CodebaseLock` module for runtime source file protection
- Fixed config loading for relative/absolute path handling
- Comprehensive 3-node test suite: 17/17 tests passing
  - Same-codebase peering verification
  - Cross-codebase rejection (bidirectional)
  - N-way fingerprint isolation matrix
  - Empty/partial fingerprint attack blocking
  - Flood attack resistance (20 simultaneous rejected)
  - Fingerprint spoofing prevention

---

## [1.2.0] - 2026-01-15

### Added

- **TME (Temporal Mesh Encoding)** - Novel packet resilience system
  - Encodes data across TIME, not space
  - Temporal slicing with cryptographic chaining
  - Predictive reconstruction from timing proofs
- TME FAQ documentation
- Whitepaper (docs/WHITEPAPER.md)

---

## [1.1.0] - 2026-01-14

### Added

- **NAVR** (Network Access Verification via Resources) - Sybil defense
- Replay attack protection (nonces, timestamps, sequences)
- Message validator with size limits and depth checks
- Rate limiter for DoS protection
- Subnet diversity tracking

---

## [1.0.3] - 2026-01-15

### Fixed

- verify() function in identity module
- Rate limiter initialization

---

## [1.0.0] - 2026-01-13

### Initial Release

- ML-DSA-65 post-quantum signatures
- SQLite-based distributed oracle
- WebSocket mesh networking
- Phase-based consensus timing
