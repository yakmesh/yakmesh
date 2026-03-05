# STEADYWATCH Integration in Yakmesh

> How a post-quantum P2P mesh network uses quantum-hardware-validated satellite seeds to fortify ML-KEM-768 key exchange.

---

## 1. What Yakmesh Is

**Yakmesh** is a post-quantum secure peer-to-peer mesh network with heterogeneous GPU+NPU compute scheduling. Every cryptographic primitive in the system is post-quantum: ML-DSA-65 for signatures, ML-KEM-768 for key encapsulation, SHA3-256/512 for hashing. There is no RSA, no ECDSA, no classical key exchange anywhere in the stack.

The node runs on Node.js v24 ESM and is designed for hardware with acceleration capabilities — in our reference deployment: an AMD Ryzen 7 8700F (AVX-512, VAES, SHA-NI, GFNI, XDNA NPU at 16 TOPS) paired with an NVIDIA RTX 3060 12GB (101 TOPS INT8), yielding 117 TOPS of combined inference throughput.

STEADYWATCH provides the entropy foundation that makes the entire post-quantum key exchange trustworthy.

---

## 2. Why STEADYWATCH

The weakest link in any key exchange is the entropy source. ML-KEM-768 key generation requires 64 bytes of high-quality seed material. If that seed is predictable — weak VM CSPRNG, compromised `/dev/urandom`, hardware RNG backdoor — the post-quantum key pair is worthless regardless of the lattice math protecting it.

STEADYWATCH solves this with a **two-source extractor** pattern:

$$\text{hybridSeed} = \text{SHA3}(\text{satelliteSeed} \| \text{EXPAND}) \oplus \text{CSPRNG}(64)$$

Even if one entropy source is fully compromised (weak CSPRNG *or* faulty quantum hardware), the other source ensures the hybrid seed retains at least 256 bits of entropy. This is a provable security property of XOR-based extractors when at least one source has sufficient min-entropy.

---

## 3. Seed Constellation Architecture

### 3.1 Hurwitz Quaternion Satellite Seeds

STEADYWATCH generates 256-bit satellite seeds from Hurwitz quaternion phase rotations on IBM Quantum hardware (ibm_marrakesh, 156-qubit Heron r2). The satellite count follows the formula:

$$N = 24(p + 1)$$

For prime $p = 5$, this gives **144 satellites** — each representing a unique quantum measurement outcome encoded as a 32-byte seed.

| Prime | Satellites | Status |
|-------|-----------|--------|
| $p = 5$ | 144 | ✅ Validated (Feb 2026) |
| $p = 13$ | 336 | 🔜 Future batch |
| $p = 17$ | 432 | 🔜 Future batch |

### 3.2 Synergy Sequence Theory (SST) Family Grouping

Each satellite index is classified by its digital root into three SST families:

| Family | Digital Roots | Polarity | Count (p=5) |
|--------|--------------|----------|-------------|
| **A** | 1, 4, 7 | Physical Negative (descending) | 48 |
| **B** | 2, 5, 8 | Physical Positive (ascending) | 48 |
| **C** | 3, 6, 9 | Governing Source (singularity) | 48 |

The constellation itself: $\text{DR}(144) = 9 \rightarrow \text{Family C}$ — a governing singularity that divides evenly across all three polarities. This isn't a coincidence; it falls directly out of the Hurwitz prime construction.

### 3.3 Balanced Ternary Satellite Addressing

Each satellite is assigned a **6-trit balanced ternary address** using the TRIBHUJ ternary system (Yakmesh's implementation of balanced ternary logic):

$$144_{10} = 1\bar{1}\bar{1}100_{bt}$$

Written in our notation: `1TT100` (where `T` represents $-1$).

The address space capacity is $3^5 = 243 > 144$, so 6 trits provide a compact, collision-free addressing scheme. Satellites can be looked up by trit address via a reverse index — enabling ternary trie routing as an alternative to array indexing.

### 3.4 Fibonacci 24-Cycle Seed Selection

Rather than simple round-robin rotation, seed selection follows a **Fibonacci digital root 24-cycle**:

```
Position:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 ...
Fib Root:  1  1  2  3  5  8  4  3  7  1  8  9  8  8  7  6 ...
Family:    A  A  B  C  B  B  A  C  A  A  B  C  B  B  A  C ...
```

At each hybrid seed generation, the Fibonacci cycle position advances, determining which SST family pool to draw from. The selection round-robins *within* the chosen family group, ensuring all 48 satellites in each family get used before repeating.

At cycle positions 12 and 24 ($\text{fibRoot} = 9$), the selection hits Family C — the singularity marker — providing a natural checkpoint in the rotation.

---

## 4. Integration Points

### 4.1 ANNEX Key Exchange (ML-KEM-768)

ANNEX is Yakmesh's encrypted session protocol, built on ML-KEM-768. When establishing a session between two peers, each side generates a KEM key pair:

```javascript
// mesh/annex.js — ServerAnnexSession.generateKeyPair()
const seed = steadywatchStore.initialized
  ? getHybridSeed()             // Quantum + CSPRNG hybrid
  : randomBytes(64);            // Pure CSPRNG fallback

this.kemKeyPair = await mlKem768Keygen(seed);
```

The `getHybridSeed()` call triggers the full pipeline:

1. Advance Fibonacci 24-cycle position
2. Determine SST family for this position
3. Select satellite from matching family group
4. Expand 32-byte seed to 64 bytes via SHA3-256 domain separation:
   - `SHA3-256(seed || "EXPAND-0")` → bytes 0–31
   - `SHA3-256(seed || "EXPAND-1")` → bytes 32–63
5. XOR with 64 bytes of OS CSPRNG
6. Return 64-byte hybrid seed

This makes every ANNEX session key pair rooted in quantum-validated entropy.

### 4.2 Entropy Sentinel (NPU-Accelerated Quality Monitor)

The Entropy Sentinel continuously monitors seed quality using a small ONNX model (`entropy-sentinel.onnx`) that detects patterns indicating weak randomness:

- Low bit-entropy (information density per byte)
- Repeating patterns (autocorrelation)
- Byte frequency bias (chi-square deviation)
- Sequential runs

**Hardware acceleration**: The model preferentially runs on the AMD XDNA NPU via DirectML. This is a 16 TOPS dedicated inference accelerator — always warm, low latency, doesn't compete with the GPU for display or LLM workloads.

If no ONNX model is available, the Sentinel falls back to a software implementation that computes bit-entropy, chi-square, run-length, and autocorrelation statistics:

$$\text{score} = 0.4 \cdot H_{\text{norm}} + 0.25 \cdot \chi^2_{\text{norm}} + 0.15 \cdot R_{\text{norm}} + 0.2 \cdot A_{\text{norm}}$$

The score maps to a **TRIBHUJ ternary verdict**:

| Score Range | Verdict | Meaning |
|-------------|---------|---------|
| ≥ 0.85 | POSITIVE (+1) | Excellent entropy |
| ≥ 0.50 | NEUTRAL (0) | Acceptable entropy |
| < 0.50 | NEGATIVE (−1) | Poor entropy — reject |

### 4.3 ComputeScheduler Integration

As of v3.0, STEADYWATCH's Entropy Sentinel runs through Yakmesh's heterogeneous **ComputeScheduler** — a priority-based GPU/NPU/CPU work router with bounded queues, circuit breakers, and work gifting:

```javascript
// server/index.js — scheduled entropy check
_scheduledEntropyCheck(data) {
  return accel.scheduler.submit({
    type:      'entropy-sentinel',
    priority:  Priority.CRITICAL,        // Never dropped, preempts lower work
    affinity:  Affinity.NPU_PREFERRED,   // Route to AMD XDNA NPU
    timeoutMs: 2000,
    executors: { npu: executor, gpu: executor, cpu: executor },
  });
}
```

**Priority: CRITICAL** — entropy degradation is a security emergency. The scheduler guarantees CRITICAL tasks are never dropped, even under heavy load. They preempt LOW and NORMAL work via the work gifting mechanism (idle devices pull lower-priority tasks from congested queues).

A periodic timer runs every 30 seconds, generating 256 fresh random bytes and scoring them through the Sentinel. If the score drops below 0.6, a warning fires — alerting operators that the entropy source may be degrading *before* it impacts ANNEX keygen.

### 4.4 Batch Quality Consensus

When seeds are loaded, each one receives a ternary quality verdict (`_checkBiasTernary`). The `batchQualityConsensus()` method aggregates all verdicts using `TritArray.majority()`:

- **POSITIVE majority**: High-quality quantum entropy across the constellation
- **NEUTRAL majority**: Mixed quality (acceptable but not ideal)
- **NEGATIVE majority**: Triggers a warning — seeds may be compromised

This consensus is exposed via the `/steadywatch` API endpoint and the `/health` status page.

---

## 5. Boot Sequence

STEADYWATCH initializes early in the boot sequence — step 0c, before identity, mesh, or any network subsystem:

```
[0a] ACCEL hardware probe (SHA3, AVX-512, GPU, NPU detection)
[0b] ONNX model loading (entropy-sentinel.onnx, sakshi-anomaly.onnx, karma-trust.onnx)
[0c] STEADYWATCH initialization ← here
  │  ├─ Load/generate 144 satellite seeds
  │  ├─ Build SST family groups (A:48, B:48, C:48)
  │  ├─ Assign 6-trit balanced ternary addresses
  │  └─ Initialize Entropy Sentinel (NPU model or CPU fallback)
[1]  Oracle system (codebase hash for network identity)
[2]  Node identity (ML-DSA-65 keypair, network name)
[3]  Mesh network (P2P WebSocket connections)
[4]  ANNEX encrypted sessions ← uses getHybridSeed() from here on
[5]  SAKSHI + KARMA + KOMM + SHERPA subsystems
[5k] Scheduled workloads start (entropy-sentinel every 30s, peer-assessment every 60s)
```

Typical boot output:

```
🛰️  Initializing STEADYWATCH (quantum entropy)...
SST family groups: A=48 B=48 C=48
Trit addresses assigned: 144 satellites in 6-trit space
Ternary-144: DR(144)=9 → Family C → TRIT 0 | constellation address: 1TT100
✓ STEADYWATCH: 144 satellite seeds loaded (Sentinel: NPU)
```

---

## 6. API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Includes `steadywatch` section with full status |
| `/steadywatch` | GET | Dedicated STEADYWATCH status and telemetry |
| `/scheduler` | GET | ComputeScheduler stats (shows entropy-sentinel task throughput) |

### Example `/steadywatch` Response

```json
{
  "initialized": true,
  "prime": 5,
  "seedCount": 144,
  "nodeAssignment": -1,
  "rotationIndex": 0,
  "metadata": {
    "prime": 5,
    "backend": "simulation",
    "validated": "2026-02-21",
    "seedCount": 144
  },
  "telemetry": {
    "seedsLoaded": 144,
    "hybridSeeds": 0,
    "rotations": 0,
    "sentinelChecks": 4,
    "sentinelPasses": 4,
    "sentinelFails": 0,
    "familySelections": { "A": 0, "B": 0, "C": 0 },
    "fibonacciCyclePosition": 0
  },
  "ternary": {
    "familyGroups": { "A": 48, "B": 48, "C": 48 },
    "constellationDR": 9,
    "constellationFamily": "C",
    "constellationAddress": "1TT100"
  },
  "sentinel": {
    "modelLoaded": true,
    "provider": "dml"
  }
}
```

---

## 7. File Map

| File | Lines | Purpose |
|------|-------|---------|
| `security/steadywatch.js` | ~1130 | Core module: SteadywatchSeedStore, EntropySentinel, all exports |
| `mesh/annex.js` | ~879 | ANNEX ML-KEM-768 — calls `getHybridSeed()` for keygen |
| `server/index.js` | ~3535 | Boot integration, scheduled entropy checks via ComputeScheduler |
| `utils/accel.js` | ~2257 | ACCEL hardware layer, InferenceEngine (NPU/GPU), ComputeScheduler |
| `oracle/tribhuj.js` | — | Balanced ternary: Trit, TritArray, consensus operations |
| `oracle/sst.js` | — | Synergy Sequence Theory: digital root, families, Fibonacci cycle |
| `models/entropy-sentinel.onnx` | — | ONNX model for NPU-accelerated entropy scoring |
| `data/steadywatch-seeds-p5.json` | — | 144 satellite seeds (generated or IBM Quantum validated) |

---

## 8. Security Properties

1. **Two-source extraction**: Hybrid seed is XOR of quantum seed and CSPRNG. Compromising one source alone cannot predict the output.

2. **Continuous monitoring**: Entropy Sentinel scores every 30 seconds via ComputeScheduler at CRITICAL priority. Degradation is detected and warned before it reaches keygen.

3. **Ternary consensus**: Batch quality verdict across all 144 seeds uses balanced ternary majority vote. A NEGATIVE majority signals potential compromise of the entire seed batch.

4. **Domain separation**: Seed expansion uses SHA3-256 with explicit domain tags (`EXPAND-0`, `EXPAND-1`), preventing related-key attacks between the two halves of the 64-byte output.

5. **Transparent fallback**: If STEADYWATCH is not initialized (no seed file, no quantum hardware), ANNEX silently falls back to pure OS CSPRNG. The system never hard-fails.

6. **NPU isolation**: The Entropy Sentinel model runs on dedicated NPU silicon (XDNA, 16 TOPS), never competing with GPU workloads (display rendering, LLM inference). This ensures entropy checks have consistent, low-latency execution.

---

## 9. Telemetry & Observability

The STEADYWATCH subsystem tracks comprehensive telemetry, accessible via API and logged at runtime:

- **seedsLoaded** / **hybridSeeds** / **rotations** — seed usage patterns
- **sentinelChecks** / **sentinelPasses** / **sentinelFails** — entropy quality trend
- **familySelections** {A, B, C} — SST family distribution balance
- **fibonacciCyclePosition** — current position in the 24-cycle
- **ternaryQualityVerdicts** {positive, neutral, negative} — per-seed quality breakdown
- **tritAddressLookups** / **batchConsensusRuns** — ternary subsystem activity

The ComputeScheduler separately tracks `entropy-sentinel` task throughput: submitted, completed, rejected, timed-out, execution latency, and which device (NPU/GPU/CPU) handled each check.

---

## 10. Future Work

- **IBM Quantum validated seeds**: Replace simulation seeds with real ibm_marrakesh measurements for $p = 5$ (144 satellites)
- **Larger constellations**: $p = 13$ (336) and $p = 17$ (432) for higher-node-count deployments
- **DOKO ceremony integration**: Assign specific satellite indices to nodes during identity provisioning
- **Cross-node seed diversity attestation**: Peers verify they're drawing from different constellation regions
- **ML routing model**: Train the ComputeScheduler's ONNX model to predict optimal device routing for entropy-sentinel tasks based on historical latency and load patterns

---

*This document describes the STEADYWATCH integration in Yakmesh v3.0. The implementation lives in [`security/steadywatch.js`](../security/steadywatch.js) (1,130 lines). For the interactive documentation, see the [Prahari page](prahari.html) on the Yakmesh website.*
