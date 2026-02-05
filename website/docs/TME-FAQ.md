# TME Technical FAQ

## Frequently Asked Questions about Temporal Matrix Encoding

---

### Q1: How is YAKMESH TME different from Walrus/Red Stuff?

**Short Answer:** Walrus encodes data across **space** (multiple storage nodes). YAKMESH TME encodes data across **time** (multiple temporal slices).

**Detailed Answer:**

| Aspect | Walrus (Red Stuff) | YAKMESH (TME) |
|--------|-------------------|---------------|
| **Encoding Dimension** | 2D spatial grid | 1D temporal chain |
| **Purpose** | Long-term storage | Real-time transmission |
| **Recovery Trigger** | Node failure/churn | Packet loss/interference |
| **Sync Requirement** | Asynchronous (tolerates drift) | Atomic (nanosecond precision) |
| **Data Lifetime** | Epochs (days/weeks) | Milliseconds |
| **Recovery Latency** | Full download from quorum | Zero (parity from adjacent slices) |

Walrus treats the network like a **Hard Drive** — data lives across spatial nodes.
YAKMESH treats the network like a **Synthesizer** — data flows across temporal intervals.

---

### Q2: Why can't I just use Reed-Solomon or other erasure codes?

Traditional erasure coding (Reed-Solomon, LDPC, etc.) was designed for:
- Storage systems with slow failure detection
- Known, static topology
- Time-insensitive recovery

TME is designed for:
- Real-time networks where retransmission kills latency
- Dynamic mesh topology with unknown paths
- Time-critical recovery (sub-millisecond)

**The Key Difference:** Erasure codes don't leverage timing. TME uses the **atomic clock synchronization** as a recovery mechanism itself.

---

### Q3: What is "Cryptographic Time Binding"?

Each temporal slice contains a `temporalHash` computed from:

```javascript
temporalHash = SHA256(
  data +           // The actual payload
  timestamp +      // Nanosecond-precision BigInt
  sequenceNumber + // Position in stream
  streamId +       // Unique stream identifier  
  prevTemporalHash + // Hash of previous slice
  meshPosition     // [x, y, z] topology coordinates
)
```

This creates an **immutable temporal chain**:
- If any slice is tampered with, the chain breaks
- Missing slices can be verified via `prevTemporalHash` in the next slice
- Timing proofs from neighbors can attest to a slice's existence

---

### Q4: What are "Timing Proofs"?

When a packet is lost, instead of requesting retransmission, the receiver asks mesh neighbors:

> "Did you see Slice N with hash X at time T?"

If multiple independent nodes agree (consensus), the receiver:
1. Knows the slice existed and wasn't fabricated
2. Can request the specific slice from a trusted neighbor
3. Can verify the slice's integrity via its temporal hash

This is faster than round-trip retransmission and provides Byzantine fault tolerance.

---

### Q5: Why does TME require atomic clock synchronization?

Without atomic sync, temporal encoding is impossible:

| Timing | Problem for TME |
|--------|-----------------|
| NTP (~10ms jitter) | Can't distinguish "late packet" from "wrong slice" |
| PTP (~100ns) | Borderline — works for coarse slicing |
| Atomic (~1ns) | Optimal — unambiguous slice identification |

With traditional timing, if a packet arrives 5ms late, is it:
- Slice N arriving late?
- Slice N+1 arriving early?
- A replay attack?

With atomic sync, all nodes share **Universal Mesh Time**. A packet's slice membership is deterministic based on its timestamp.

---

### Q6: Can TME be used without post-quantum cryptography?

Yes, but you lose quantum resistance. The components are separable:

| Component | Can Use Without PQ? |
|-----------|---------------------|
| Temporal slicing | ✅ Yes |
| Cryptographic chaining | ✅ Yes (use SHA-256) |
| Timing proofs | ✅ Yes |
| Packet signing | ⚠️ Yes, but vulnerable to HNDL |

YAKMESH uses ML-DSA-65 (FIPS 204) for signatures. If you swap in ECDSA, TME still works — but an adversary with a quantum computer could forge signatures in the future.

---

### Q7: What's the overhead of TME?

**Per-Slice Overhead:**
- Timestamp: 8 bytes (BigInt)
- Sequence number: 4 bytes
- Stream ID: 32 bytes (first slice only, then 0)
- Prev temporal hash: 32 bytes
- Temporal hash: 32 bytes
- Mesh position: 12 bytes (3x float32)

**Total:** ~88 bytes per slice (excluding payload)

For a 1KB slice size, that's ~8.5% overhead.
For a 4KB slice size, that's ~2.1% overhead.

**Computational Overhead:**
- 1 SHA-256 hash per slice (fast)
- BigInt timestamp handling (minimal)

---

### Q8: How does TME handle out-of-order delivery?

TME is **designed** for out-of-order delivery:

1. Each slice has a `sequenceNumber`
2. The receiver buffers slices by sequence
3. Missing sequences are detected immediately
4. Chain verification happens after buffering

```
Received: [0] [3] [1] [2]
Buffer:   [0] [_] [_] [_]  → [0] [_] [_] [3]  → [0] [1] [_] [3]  → [0] [1] [2] [3]
Chain verification: hash(0) → hash(1) → hash(2) → hash(3) ✓
```

---

### Q9: What percentage of slices must arrive for reconstruction?

Default threshold: **60%** (configurable via `TME_CONFIG.minSlicesForReconstruction`)

With 60% of slices:
- Chain gaps are detectable
- Timing proofs can verify missing slices existed
- Neighbors can supply specific missing slices

Below 60%:
- Too many gaps for reliable chain verification
- Reconstruction degrades to traditional request/retry

---

### Q10: Is TME patented?

TME (Temporal Matrix Encoding) is a **proprietary technology** of the YAKMESH project.

It is **not** covered by the Walrus/Red Stuff patents because:
1. Different encoding dimension (time vs. space)
2. Different recovery mechanism (timing proofs vs. quorum download)
3. Different hardware requirements (atomic sync vs. asynchronous)

YAKMESH™ itself has USPTO Serial No. 99594620.

---

### Q11: Can I use TME in my project?

TME is available in the `yakmesh` npm package under MIT license:

```bash
npm install yakmesh
```

```javascript
import { TemporalMeshEncoder } from 'yakmesh/mesh/temporal-encoder.js';

const encoder = new TemporalMeshEncoder();
const { streamId, slices, metadata } = encoder.encode('Hello TME!');
```

---

### Q12: What's the relationship between TME and the Yielding Atomic Kernel?

The **Yielding Atomic Kernel (YAK)** is the core system that provides:
- Atomic clock synchronization
- Post-quantum cryptography (ML-DSA-65)
- Byzantine fault tolerance

**TME** is a protocol that runs on top of YAK, exploiting its unique capabilities:
- Uses atomic timing for temporal slicing
- Uses PQ signatures for slice authentication
- Uses reputation systems for timing proof validation

TME without YAK is like HTTPS without TLS — technically possible, but missing the security guarantees.

---

## Still have questions?

- **GitHub:** https://github.com/yakmesh/yakmesh
- **Website:** https://yakmesh.dev
- **npm:** https://www.npmjs.com/package/yakmesh

---

*Powered by TME — The world's first temporal-erasure protocol for atomically-synced mesh networks.*
