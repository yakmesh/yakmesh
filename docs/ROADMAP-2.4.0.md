# YAKMESH v2.4.0 Roadmap

## Theme: "Mathematical Trust — No Simulation"

**Target Release**: February 2026

This release unifies YAKMESH's core principles into an unbreakable trust system:
- **Real hardware** (AES-NI verified)
- **Precision time** (Atomic/GPS/PTP)
- **Mathematical consensus** (2/3 threshold)

**"You can't fake physics. Atomic time and real silicon are your credentials."**

---

## 🎯 Core Principles

### No Simulation
- Must prove **real AES-NI hardware** through timing analysis
- VMs, emulators, and bot farms fail timing verification
- **Economic barrier**: Real servers cost real money

### Atomic Precision  
- Highest trust requires **physical time sources**
- Atomic clocks, GPS+PPS, or PTP (IEEE 1588)
- **Can't fake physics**: Time sources are verifiable

### Mathematical Consensus
- Revocation through **signature counting**, not voting
- 2/3 threshold = Byzantine fault tolerance
- **No human decisions**: Math is final

---

## 🏔️ Trust Tiers

| Tier | Hardware | Time Source | Weight | Description |
|------|----------|-------------|--------|-------------|
| **ORACLE** | AES-NI ✅ | Atomic Clock | 2.0x | Network truth anchors |
| **ANCHOR** | AES-NI ✅ | GPS + PPS | 1.5x | Regional anchors |
| **SENTINEL** | AES-NI ✅ | PTP (IEEE 1588) | 1.25x | Time-verified nodes |
| **PARTICIPANT** | AES-NI ✅ | NTP only | 1.0x | Standard nodes |
| **OBSERVER** | Unverified | Any | 0.25x | Minimal trust |

### Network Topology

```
                    ┌─────────────┐
                    │   ORACLE    │ Atomic + AES-NI
                    │   (2.0x)    │ Source of truth
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
      ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
      │  ANCHOR   │  │  ANCHOR   │  │  ANCHOR   │
      │  (1.5x)   │  │  (1.5x)   │  │  (1.5x)   │
      └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
            │              │              │
       ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
       │SENTINEL │    │SENTINEL │    │SENTINEL │
       │ (1.25x) │    │ (1.25x) │    │ (1.25x) │
       └────┬────┘    └────┬────┘    └────┬────┘
            │              │              │
    ┌───────┴───────┬──────┴──────┬───────┴───────┐
    │ PARTICIPANT   │ PARTICIPANT │ PARTICIPANT   │
    │   (1.0x)      │   (1.0x)    │   (1.0x)      │
    └───────────────┴─────────────┴───────────────┘
```

---

## ✅ Implemented Features

### 1. Mesh-Consensus Revocation

**File**: `security/mesh-revocation.js`  
**Tests**: 41 passing

When 2/3 of nodes attest bad behavior, revocation is a mathematical fact.

```javascript
import { MeshRevocation, REVOCATION_REASONS } from 'yakmesh/security/mesh-revocation';

// Create attestation when you observe bad behavior
const attestation = revocation.createAttestation(
  badDokoId,
  REVOCATION_REASONS.DOUBLE_SIGN
);

// Check revocation (pure math)
const status = revocation.isRevoked(someDokoId);
// { revoked: true/false, effectiveCount, threshold, confidence }
```

### 2. Hardware Attestation

**File**: `security/hardware-attestation.js`  
**Tests**: 5 passing

Proves real AES-NI silicon through timing analysis.

```javascript
import { HardwareAttestation } from 'yakmesh/security/hardware-attestation';

// Create local attestation
const attestation = await HardwareAttestation.createLocal();
// { hasAESNI: true/false, throughputMBps, timing... }

// Challenge another node
const challenge = HardwareAttestation.createChallenge();
const response = await HardwareAttestation.respondToChallenge(challenge, privateKey, dokoId);
const verification = HardwareAttestation.verifyResponse(response, challenge, publicKey);
```

### 3. Trust Tier System

**File**: `security/trust-tier.js`  
**Tests**: 35 passing

Combines hardware + time source into trust levels.

```javascript
import { TrustTierRegistry, TRUST_TIER } from 'yakmesh/security/trust-tier';

const registry = new TrustTierRegistry({
  getTimeSource: (dokoId) => timeOracle.getSource(dokoId),
  getHardwareAttestation: (dokoId) => hwStore.get(dokoId),
  getNetworkAge: (dokoId) => sherpa.getAge(dokoId),
  getEndorsementCount: (dokoId) => dokoStore.getEndorsements(dokoId).length,
});

// Get trust tier
const tier = await registry.getTier(dokoId);  // 'oracle', 'anchor', etc.
const weight = await registry.getWeight(dokoId);  // 2.0, 1.5, 1.25, 1.0, 0.25
```

### 4. Weighted Revocation

**Integrated with Trust Tiers**

ORACLE nodes have 2x weight in revocation consensus:

```javascript
import { WeightedRevocationCalculator } from 'yakmesh/security/trust-tier';

const calculator = new WeightedRevocationCalculator(registry);

// 2 ORACLEs (4.0) + 6 PARTICIPANTs (6.0) = 10.0 effective
// vs. threshold of 9.33 (2/3 of 14.0 effective network size)
const result = await calculator.isRevoked(attestations);
```

---

## 📊 Implementation Status

| Component | File | Tests | Status |
|-----------|------|-------|--------|
| Mesh Revocation | `mesh-revocation.js` | 41 | ✅ Complete |
| Hardware Attestation | `hardware-attestation.js` | 5 | ✅ Complete |
| **Extended HW Detection** | `hardware-attestation.js` | 29 | ✅ v2.4.1 |
| Trust Tiers | `trust-tier.js` | 35 | ✅ Complete |
| Silicon Parity | `silicon-parity.js` | 36 | ✅ Complete |
| Sybil Graph Analysis | `sybil-graph.js` | 44 | ✅ Complete |
| KHATA Trust Integration | `khata-trust-integration.js` | 22 | ✅ Complete |
| Strike System | `strike-system.js` | 31 | ✅ Complete |
| Weighted Calculator | (in trust-tier.js) | (included) | ✅ Complete |
| **Total v2.4 Tests** | | **243** | |

**Project Test Count**: 598 + 243 = **841 tests**

---

## 🛡️ Security Properties

### Sybil Attack Defense

| Layer | Defense | Cost to Attack |
|-------|---------|----------------|
| SHERPA Presence | Must run real nodes | Infrastructure |
| AES-NI Timing | Must have real hardware | Real servers |
| Time Source | Must have precision time | Atomic/GPS hardware |
| Network Age | Must wait 7-30 days | Time |
| Endorsements | Must build reputation | Social proof |

### Bot Farm Economics

To revoke an innocent node in a 100-node network:

```
Required: 67 effective weight (2/3 of ~100)
With PARTICIPANTs only: 67 real servers
With ORACLEs (2.0x): 34 atomic clock nodes (!)
```

**Bot farms become economically infeasible.**

### Byzantine Fault Tolerance

- Tolerates up to 1/3 malicious nodes
- Attestations are post-quantum signed (ML-DSA-65)
- Threshold is 2/3 of **weighted** network

---

## 🛡️ Sybil Defense Layers

The v2.4 security model uses **layered defenses** to make Sybil attacks economically infeasible:

```
┌─────────────────────────────────────────────────────────────┐
│                    SYBIL DEFENSE STACK                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 0: Crypto Acceleration Detection (v2.4.1)            │
│           → AES-NI (128-bit): Baseline detection            │
│           → VAES (256/512-bit): Enhanced fingerprinting     │
│           → GFNI: Universal Galois Field acceleration       │
│           → PQC-Ready: NTT + SHA-3 for post-quantum         │
│                                                             │
│  Layer 1: Silicon Parity (v2.4)                             │
│           → AES timing fingerprint = unique CPU identity    │
│           → Weight division: tierMax / coreCount            │
│           → 100 cores on 1 rig = same weight as 1 core     │
│                                                             │
│  Layer 2: Graph Analysis (v2.4)                             │
│           → Attestation clustering detection                │
│           → Sybil clusters have coefficient > 0.7           │
│           → Honest networks have sparse, random graphs      │
│                                                             │
│  Layer 3: Behavioral Correlation (v2.4)                     │
│           → Uptime correlation analysis                     │
│           → Attestation pattern correlation                 │
│           → Synchronized activity = suspicious              │
│                                                             │
│  Layer 4: SHERPA Clock Correlation (existing)               │
│           → Clock drift patterns reveal physical proximity  │
│           → Same-room nodes have correlated drift           │
│                                                             │
│  Layer 5: Geographic Proof via SHERPA (v2.5)                │
│           → Hardware timestamps enable RTT measurement      │
│           → Nanosecond precision = ~2-20km resolution       │
│           → Trilateration from global PTP/GPS landmarks     │
│           → Physics can't be spoofed: speed of light!       │
│                                                             │
│  Layer 6: Economic Friction (future)                        │
│           → Registration queue (time cost)                  │
│           → Stake requirements (financial cost)             │
│           → Makes mass registration expensive               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Crypto Acceleration Tiers (v2.4.1)

```javascript
// Extended hardware detection beyond AES-NI
CRYPTO_ACCELERATION_TIER = {
  NONE: 0,      // Software only - no acceleration
  AES_NI: 1,    // 128-bit AES-NI (baseline)
  VAES_256: 2,  // VAES 256-bit (AVX2) - 2x throughput
  VAES_512: 3,  // VAES 512-bit (AVX-512) - 4x throughput
  GFNI: 4,      // Galois Field - universal crypto
  PQC_READY: 5, // NTT + SHA-3 accelerators
};

// Detection via timing heuristics:
// - Throughput > 2000 MB/s → likely VAES-256
// - Throughput > 4000 MB/s → likely VAES-512
// - CPU model string parsing for GFNI/PQC
```

| CPU | Era | Typical Tier |
|-----|-----|--------------|
| Intel 10th Gen | 2019 | AES-NI |
| Intel 11th Gen+ | 2020+ | VAES-512 + GFNI |
| AMD Zen 3 | 2020 | VAES-256 + GFNI |
| AMD Zen 4+ | 2022+ | VAES-512 + GFNI |
| Apple M1+ | 2020+ | ~VAES-256 (equivalent) |

### Silicon Parity: "One Silicon = One Vote"

```javascript
// Weight division formula:
effectiveWeight = tierMaxWeight / max(1, detectedCores)

// Examples for PARTICIPANT tier (max 1.0x):
// 1 core   → 1.0 / 1   = 1.0x    ✅ Full weight
// 4 cores  → 1.0 / 4   = 0.25x   (per core, 1.0x total)
// 100 cores → 1.0 / 100 = 0.01x   (per core, 1.0x total)

// Attack economics:
// 100-core rig cost: ~$50,000
// Benefit vs 1-core: $0 (identical total weight)
// ROI: Negative (electricity + hardware for nothing)
```

### Graph Analysis: Cluster Detection

```javascript
// Honest network: Sparse, random attestation patterns
// Sybil cluster: Dense, everyone-attests-everyone pattern

// Detection metrics:
// - Clustering coefficient > 0.7 = suspicious
// - Low edge cut to outside = insular cluster  
// - Eigenvalue gap reveals hidden structure

// Dr. Sybil's 1000 nodes:
// - All attest each other → clustering ~0.95
// - Few edges to honest nodes → edge cut ~0.05
// - Result: ENTIRE CLUSTER FLAGGED 🚨
```

### Geographic Proof via SHERPA Hardware Timestamps

```javascript
// SHERPA already has hardware timestamping (PTP/GPS)
// We can measure RTT to landmarks with nanosecond precision!

// Physics:
// Light in fiber: ~5μs per km
// Hardware timestamp precision: 10-100ns
// Resolution: ~2-20km (city-level!)

// Trust Tier → Geographic Resolution:
// ORACLE (Atomic):   ~1km  (lab-grade)
// ANCHOR (GPS+PPS):  ~5km  (city-level)
// SENTINEL (PTP):    ~20km (metro-level)
// PARTICIPANT (NTP): ~2000km (not useful)

// Dr. Sybil's 1000 "distributed" nodes:
// All triangulate to same datacenter → BUSTED
```

---

## 🔧 Tier Requirements

### ORACLE (2.0x weight)
- ✅ AES-NI hardware (verified by timing)
- ✅ Atomic clock time source
- ✅ 30+ days network age
- ✅ 3+ endorsements from established nodes

### ANCHOR (1.5x weight)
- ✅ AES-NI hardware
- ✅ GPS + PPS time source
- ✅ 14+ days network age
- ✅ 2+ endorsements

### SENTINEL (1.25x weight)
- ✅ AES-NI hardware
- ✅ PTP (IEEE 1588) time source
- ✅ 7+ days network age
- ✅ 1+ endorsement

### PARTICIPANT (1.0x weight)
- ✅ AES-NI hardware
- ⚪ NTP time source (any)
- ✅ 1+ day network age
- ⚪ No endorsement required

### OBSERVER (0.25x weight)
- ❌ No hardware verification
- ⚪ Any time source
- ⚪ No age requirement
- ⚪ No endorsement required

---

## 🚀 Remaining Work

### Silicon Parity (Anti-Farm)

- [ ] Implement `security/silicon-parity.js`
- [ ] AES timing fingerprint collection (1000-op histogram)
- [ ] Bitslice sampling for epoch verification (~1ms)
- [ ] Full fingerprint refresh every 8 epochs (~10ms)
- [ ] Weight division: `tierMax / coreCount`
- [ ] VM detection via timing jitter analysis
- [ ] Platform UUID + fingerprint commitment binding

### Graph Analysis (Sybil Detection)

- [ ] Implement `security/sybil-graph.js`
- [ ] Build attestation graph from KHATA messages
- [ ] Clustering coefficient calculation
- [ ] Edge cut analysis (insular clusters)
- [ ] Eigenvalue gap detection
- [ ] Automatic flagging when coefficient > 0.7

### KHATA Integration

- [ ] Add `MESH_REVOCATION_MESSAGES` to KHATA protocol
- [ ] Attestation gossip via existing mesh
- [ ] Hardware challenge-response via KHATA

### Strike System (Graduated Consequences)

- [ ] Track revocation lineage
- [ ] Strike 1: Fresh start allowed
- [ ] Strike 2: 7-day probation, reduced weight
- [ ] Strike 3: Permanent ban from linked lineage

### Integration Testing

- [ ] Multi-node weighted revocation tests
- [ ] Hardware attestation challenge-response tests
- [ ] Cross-tier consensus scenarios
- [ ] Silicon parity weight division tests
- [ ] Graph analysis cluster detection tests

---

## 📝 API Reference

### MeshRevocation
```javascript
createAttestation(dokoId, reason, evidence?)  // Create signed attestation
addAttestation(attestation)                   // Add from gossip
isRevoked(dokoId)                            // Check status (math)
createRevocationCertificate(dokoId)          // Generate proof
MeshRevocation.verifyCertificate(cert, resolver)  // Verify proof
```

### HardwareAttestation
```javascript
HardwareAttestation.createLocal()            // Attest local hardware
HardwareAttestation.createChallenge()        // Challenge remote node
HardwareAttestation.respondToChallenge(...)  // Respond to challenge
HardwareAttestation.verifyResponse(...)      // Verify response
```

### TrustTierRegistry
```javascript
getProfile(dokoId)                           // Get full trust profile
getTier(dokoId)                              // Get tier name
getWeight(dokoId)                            // Get attestation weight
calculateEffectiveCount(attestations)         // Weighted count
getEffectiveNetworkSize()                    // Weighted network size
```

---

*Created: 2026-01-20*  
*Philosophy: You can't fake physics*
