# Synergy Sequence Theory (SST) Integration for YAKMESH

**Version:** 2.9.0-spec  
**Date:** 2026-02-07  
**Author:** YAKMESH Research Team  
**Inspired by:** Wesley Long's Synergy Sequence Theory

---

## Executive Summary

Synergy Sequence Theory (SST) provides a mathematical framework centered on the numbers 3, 6, and 9 that aligns remarkably well with YAKMESH's balanced ternary architecture. This document proposes four integration paths:

1. **Digital Root Trit Encoding** - Map any number to SST family groups, then to balanced ternary
2. **YPC-27 Cycle Enhancement** - Use SST's 24-digit Fibonacci cycle for checksum rotation
3. **KARMA Trust Geometry** - Model reputation flow using the 30-60-90 Synergy Triangle
4. **PRAMAAN Hexagonal Tessellation** - Geographic proof zones based on hexagonal lattices

---

## 1. Digital Root Trit Encoding

### SST Foundation

SST identifies three "Family Number Groups" based on digital roots:

| Family | Members | SST Polarity | Proposed Trit |
|--------|---------|--------------|---------------|
| Family A | 1, 4, 7 | Physical (−) | **-1** (NEGATIVE) |
| Family B | 2, 5, 8 | Physical (+) | **+1** (POSITIVE) |
| Family C | 3, 6, 9 | Governing/Source | **0** (NEUTRAL) |

The 3-6-9 family acts as the "singularity" in SST - a governing force that doesn't oscillate like the physical families.

### Implementation: `oracle/sst.js`

```javascript
/**
 * SST - Synergy Sequence Theory Integration
 * 
 * Maps any number to its SST family group, then to balanced ternary.
 * Based on Wesley Long's Synergy Sequence Theory.
 * 
 * @module oracle/sst
 */

import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from './tribhuj.js';

// =============================================================================
// DIGITAL ROOT & FAMILY MAPPING
// =============================================================================

/**
 * Calculate the digital root of a number (sum digits until single digit).
 * @param {number | bigint} n - Any integer
 * @returns {number} - A value 1-9
 */
export function digitalRoot(n) {
  if (n === 0) return 9; // Special case: 9 → 9, multiples of 9 → 9
  const abs = n < 0 ? -n : n;
  const root = abs % 9;
  return root === 0 ? 9 : root;
}

/**
 * Family identifiers based on SST.
 */
export const SSTFamily = {
  A: 'A', // 1, 4, 7 - Physical Negative
  B: 'B', // 2, 5, 8 - Physical Positive  
  C: 'C', // 3, 6, 9 - Governing/Source
};

/**
 * Get the SST family for a digital root.
 * @param {number} root - Digital root 1-9
 * @returns {'A' | 'B' | 'C'}
 */
export function getFamily(root) {
  if ([1, 4, 7].includes(root)) return SSTFamily.A;
  if ([2, 5, 8].includes(root)) return SSTFamily.B;
  return SSTFamily.C; // 3, 6, 9
}

/**
 * Map any number to a Trit via its SST family.
 * 
 * Family A (1,4,7) → -1 (NEGATIVE) - Physical descending
 * Family B (2,5,8) → +1 (POSITIVE) - Physical ascending
 * Family C (3,6,9) →  0 (NEUTRAL)  - Governing singularity
 * 
 * @param {number | bigint} n 
 * @returns {Trit}
 */
export function toFamilyTrit(n) {
  const root = digitalRoot(n);
  const family = getFamily(root);
  
  switch (family) {
    case SSTFamily.A: return new Trit(NEGATIVE);
    case SSTFamily.B: return new Trit(POSITIVE);
    case SSTFamily.C: return new Trit(NEUTRAL);
  }
}

/**
 * Convert a byte array to family trits.
 * Each byte maps to its SST family trit.
 * @param {Uint8Array} bytes 
 * @returns {Int8Array} - Array of trit values
 */
export function bytesToFamilyTrits(bytes) {
  const trits = new Int8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    trits[i] = toFamilyTrit(bytes[i]).value;
  }
  return trits;
}

// =============================================================================
// FIBONACCI DIGITAL ROOT SEQUENCES
// =============================================================================

/**
 * The 24-digit repeating Fibonacci digital root sequence.
 * This is the fundamental SST cycle.
 */
export const FIBONACCI_CYCLE_24 = Object.freeze([
  1, 1, 2, 3, 5, 8, 4, 3, 7, 1, 8, 9,
  8, 8, 7, 6, 4, 1, 5, 6, 2, 8, 1, 9
]);

/**
 * Get the digital root Fibonacci number at position n.
 * Cycles every 24 positions.
 * @param {number} n - Position (0-indexed)
 * @returns {number} - Digital root 1-9
 */
export function fibonacciRoot(n) {
  return FIBONACCI_CYCLE_24[n % 24];
}

/**
 * Get the family trit for Fibonacci position n.
 * @param {number} n 
 * @returns {Trit}
 */
export function fibonacciFamilyTrit(n) {
  return toFamilyTrit(fibonacciRoot(n));
}

// =============================================================================
// SYNERGY MATRIX PATTERNS
// =============================================================================

/**
 * Generate the Synergy Matrix - 9 Fibonacci-style sequences.
 * Each row starts with its digit (1-9) repeated, then follows Fib-addition.
 * All values reduced to digital roots.
 * @param {number} length - How many columns
 * @returns {number[][]} - 9 rows of digital roots
 */
export function generateSynergyMatrix(length = 24) {
  const matrix = [];
  
  for (let seed = 1; seed <= 9; seed++) {
    const row = [seed, seed]; // Start with seed, seed
    
    for (let i = 2; i < length; i++) {
      const sum = row[i - 1] + row[i - 2];
      row.push(digitalRoot(sum));
    }
    
    matrix.push(row);
  }
  
  return matrix;
}

/**
 * Get the family pattern for a Synergy Matrix row.
 * @param {number[]} row - Digital root sequence
 * @returns {Int8Array} - Trit pattern
 */
export function rowToFamilyPattern(row) {
  const trits = new Int8Array(row.length);
  for (let i = 0; i < row.length; i++) {
    trits[i] = toFamilyTrit(row[i]).value;
  }
  return trits;
}
```

### Use Cases

1. **Node ID Classification** - Quickly categorize nodes into three groups based on ID digital root
2. **Channel Assignment** - Divide communication into 3 channels based on SST family
3. **Shard Distribution** - Natural 3-way data partitioning

---

## 2. YPC-27 Cycle Enhancement

### Current State

YPC-27 uses a fixed 27-trit seed polynomial. The checksum rotates through this seed during computation.

### SST Enhancement: 24-Cycle Rotation

SST reveals that Fibonacci digital roots repeat every 24 positions. We can use this to create a **dynamic seed rotation schedule**:

```javascript
// In oracle/ypc27.js

import { FIBONACCI_CYCLE_24, getFamily, SSTFamily } from './sst.js';

/**
 * YPC-27 with SST-based seed rotation.
 * 
 * The seed polynomial rotates based on the 24-cycle:
 * - Family A (1,4,7): Rotate seed LEFT (negative direction)
 * - Family B (2,5,8): Rotate seed RIGHT (positive direction)
 * - Family C (3,6,9): No rotation (singularity/stable)
 */
export class YPC27_SST extends YPC27Checksum {
  #cyclePosition = 0;
  #baseSeed;

  constructor(seed = DEFAULT_SEED) {
    super(seed);
    this.#baseSeed = Array.from(seed);
  }

  /**
   * Get rotated seed based on current cycle position.
   */
  #getRotatedSeed() {
    const fibRoot = FIBONACCI_CYCLE_24[this.#cyclePosition % 24];
    const family = getFamily(fibRoot);
    
    // Rotation amount based on the actual Fibonacci root (1-9)
    const rotateAmount = fibRoot % 27;
    
    switch (family) {
      case SSTFamily.A:
        return this.#rotateLeft(rotateAmount);
      case SSTFamily.B:
        return this.#rotateRight(rotateAmount);
      case SSTFamily.C:
        return this.#baseSeed; // Singularity - no rotation
    }
  }

  #rotateLeft(n) {
    const arr = [...this.#baseSeed];
    return [...arr.slice(n), ...arr.slice(0, n)];
  }

  #rotateRight(n) {
    const arr = [...this.#baseSeed];
    return [...arr.slice(-n), ...arr.slice(0, -n)];
  }

  /**
   * Override update to advance cycle position.
   */
  update(data) {
    // Use rotated seed for this chunk
    const rotatedSeed = new Poly27(this.#getRotatedSeed());
    // ... update logic with rotated seed
    this.#cyclePosition++;
  }
}
```

### Benefits

1. **Increased Entropy** - Seed rotation prevents pattern analysis attacks
2. **Self-Synchronizing** - The 24-cycle is deterministic, all nodes compute same rotation
3. **Mathematical Elegance** - Leverages natural Fibonacci periodicity

### The 27-24 Relationship

```
27 = 3³      (YPC-27 polynomial degree)
24 = 3 × 8  (SST Fibonacci cycle)

LCM(27, 24) = 216 = 6³

The full hypercycle repeats every 216 chunks!
```

---

## 3. KARMA Trust Geometry

### SST Synergy Triangle

SST proposes the 30-60-90 triangle as the fundamental geometric unit, superior to Phi-based spirals for describing natural growth.

```
        90°
        /|
       / |
      /  | (height = 9)
     /   |
    /60° |
   /_____|
  30°     (base = 3)
  
  Ratios: 1 : √3 : 2  (normalized to 3 : 5.196 : 6)
```

### Application to KARMA Trust Levels

Current KARMA has trust tiers. We can reorganize using SST geometry:

```javascript
/**
 * KARMA Trust Geometry based on SST Synergy Triangle.
 * 
 * The 30-60-90 triangle defines trust flow patterns:
 * 
 * - 30° (shallow): Light trust, many connections
 * - 60° (balanced): Moderate trust, balanced connections
 * - 90° (deep): High trust, few but strong connections
 */

export const TrustAngles = {
  SHALLOW: 30,  // Fast, wide, low commitment
  BALANCED: 60, // Medium speed, medium width
  DEEP: 90,     // Slow, narrow, high commitment
};

/**
 * Calculate trust decay based on SST triangle.
 * 
 * Shallow (30°) trust decays quickly: halfLife = 24 hours
 * Balanced (60°) trust decays moderately: halfLife = 7 days  
 * Deep (90°) trust decays slowly: halfLife = 90 days
 * 
 * These map to the 3-6-9 pattern:
 *   30 → 3 → Family C (base)
 *   60 → 6 → Family C (medium)
 *   90 → 9 → Family C (apex)
 */
export function trustHalfLife(angle) {
  const HOUR = 3600 * 1000;
  const DAY = 24 * HOUR;
  
  switch (angle) {
    case TrustAngles.SHALLOW:
      return 1 * DAY;      // 24 hours (digital root = 6 → Family C)
    case TrustAngles.BALANCED:
      return 7 * DAY;      // 168 hours (1+6+8 = 15 → 6 → Family C)
    case TrustAngles.DEEP:
      return 90 * DAY;     // 2160 hours (2+1+6+0 = 9 → Family C)
    default:
      return 7 * DAY;
  }
}

/**
 * Trust propagation based on Synergy Triangle ratios.
 * 
 * When trust flows from node A to B:
 * - Direct connection: 100% of A's endorsement
 * - One hop away: 57.7% (1/√3, the 30-60-90 ratio)
 * - Two hops away: 33.3% (1/3)
 * - Three hops away: 19.2% (1/√27)
 */
export const TRUST_PROPAGATION = {
  DIRECT: 1.0,
  ONE_HOP: 0.577,  // 1 / √3
  TWO_HOPS: 0.333, // 1 / 3
  THREE_HOPS: 0.192, // 1 / √27
};

/**
 * Apply SST trust propagation.
 * @param {number} baseTrust - Original trust score (0-1)
 * @param {number} hops - Distance from source
 * @returns {number} - Propagated trust score
 */
export function propagateTrust(baseTrust, hops) {
  switch (hops) {
    case 0: return baseTrust * TRUST_PROPAGATION.DIRECT;
    case 1: return baseTrust * TRUST_PROPAGATION.ONE_HOP;
    case 2: return baseTrust * TRUST_PROPAGATION.TWO_HOPS;
    case 3: return baseTrust * TRUST_PROPAGATION.THREE_HOPS;
    default: 
      // Beyond 3 hops: 1 / √(3^n) = 3^(-n/2)
      return baseTrust * Math.pow(3, -hops / 2);
  }
}
```

### Trust Triangle Visualization

```
                    HIGH TRUST (apex)
                         /\
                        /  \
                       / 9  \     90° zone: Validators, longtime members
                      /______\
                     /   6    \   60° zone: Regular participants
                    /__________\
                   /      3      \ 30° zone: New nodes, observers
                  /______________\
                       LOT TRUST (base)
```

---

## 4. PRAMAAN Hexagonal Tessellation

### SST Natural Geometry

SST argues that hexagons are nature's "easiest path" - seen in beehives, Saturn's polar storm, and bubble formations. The 30-60-90 triangle tiles naturally into hexagonal patterns.

### Hexagonal Geographic Zones

Instead of circular exclusion zones, use hexagonal tessellation:

```javascript
/**
 * PRAMAAN Hexagonal Tessellation
 * 
 * Geographic proof zones as hexagonal cells.
 * Each cell is defined by:
 * - Center landmark coordinates
 * - Radius in km (minimum exclusion distance)
 * - 6 neighbor cells (hexagonal adjacency)
 */

// Hexagonal grid constants based on SST
export const HEX_CONSTANTS = {
  // The 30-60-90 ratios scaled to standard hex cell
  INNER_RADIUS: 1,        // Apothem (center to edge midpoint)
  OUTER_RADIUS: 1.1547,   // 2/√3 (center to vertex)
  EDGE_LENGTH: 1.1547,    // Same as outer radius
  
  // SST-inspired cell sizes (km)
  CELL_SIZES: {
    MICRO: 9,     // 9 km - City district
    SMALL: 27,    // 27 km - Metro area (3³)
    MEDIUM: 81,   // 81 km - Regional (3⁴)
    LARGE: 243,   // 243 km - National (3⁵)
    MEGA: 729,    // 729 km - Continental (3⁶)
  }
};

/**
 * Axial coordinates for hexagonal grid (cube coordinates simplified).
 * Uses the "pointy-top" orientation aligned with 30-60-90 triangles.
 */
export class HexCoord {
  constructor(q, r) {
    this.q = q; // Column
    this.r = r; // Row
  }

  /** Get the 6 neighbor cells */
  neighbors() {
    return [
      new HexCoord(this.q + 1, this.r),     // E
      new HexCoord(this.q + 1, this.r - 1), // NE
      new HexCoord(this.q, this.r - 1),     // NW
      new HexCoord(this.q - 1, this.r),     // W
      new HexCoord(this.q - 1, this.r + 1), // SW
      new HexCoord(this.q, this.r + 1),     // SE
    ];
  }

  /** Distance to another hex cell */
  distanceTo(other) {
    const s1 = -this.q - this.r;
    const s2 = -other.q - other.r;
    return Math.max(
      Math.abs(this.q - other.q),
      Math.abs(this.r - other.r),
      Math.abs(s1 - s2)
    );
  }

  /** Convert to lat/lon given cell size and reference point */
  toLatLon(cellSizeKm, refLat, refLon) {
    const EARTH_RADIUS_KM = 6371;
    
    // Hex to cartesian (pointy-top)
    const x = cellSizeKm * (Math.sqrt(3) * this.q + Math.sqrt(3) / 2 * this.r);
    const y = cellSizeKm * (3 / 2 * this.r);
    
    // To lat/lon offset
    const latOffset = (y / EARTH_RADIUS_KM) * (180 / Math.PI);
    const lonOffset = (x / (EARTH_RADIUS_KM * Math.cos(refLat * Math.PI / 180))) * (180 / Math.PI);
    
    return {
      lat: refLat + latOffset,
      lon: refLon + lonOffset
    };
  }

  /** Get hex cell from lat/lon */
  static fromLatLon(lat, lon, cellSizeKm, refLat, refLon) {
    const EARTH_RADIUS_KM = 6371;
    
    // Lat/lon to cartesian offset
    const y = (lat - refLat) * (Math.PI / 180) * EARTH_RADIUS_KM;
    const x = (lon - refLon) * (Math.PI / 180) * EARTH_RADIUS_KM * Math.cos(refLat * Math.PI / 180);
    
    // Cartesian to hex (pointy-top, inverse)
    const q = (Math.sqrt(3) / 3 * x - 1 / 3 * y) / cellSizeKm;
    const r = (2 / 3 * y) / cellSizeKm;
    
    // Round to nearest hex
    return HexCoord.round(q, r);
  }

  /** Round fractional hex coordinates to nearest integer hex */
  static round(q, r) {
    const s = -q - r;
    
    let rq = Math.round(q);
    let rr = Math.round(r);
    let rs = Math.round(s);
    
    const qDiff = Math.abs(rq - q);
    const rDiff = Math.abs(rr - r);
    const sDiff = Math.abs(rs - s);
    
    if (qDiff > rDiff && qDiff > sDiff) {
      rq = -rr - rs;
    } else if (rDiff > sDiff) {
      rr = -rq - rs;
    }
    
    return new HexCoord(rq, rr);
  }
}

/**
 * Geographic proof using hexagonal zones.
 * 
 * A node proves it's NOT in a hex cell by having RTT too low
 * to be at that distance from the landmark.
 */
export function proveHexExclusion(landmarkHex, nodeRtt, cellSizeKm) {
  const FIBER_SPEED_KM_PER_MS = 199.861;
  
  // Minimum distance from RTT
  const minDistanceKm = (nodeRtt / 2) * FIBER_SPEED_KM_PER_MS;
  
  // Number of hex cells that can be excluded
  const cellsExcluded = Math.floor(minDistanceKm / cellSizeKm);
  
  // Generate ring of excluded cells
  const excludedCells = [];
  for (let ring = 0; ring <= cellsExcluded; ring++) {
    excludedCells.push(...hexRing(landmarkHex, ring));
  }
  
  return {
    minDistanceKm,
    cellsExcluded: cellsExcluded + 1, // +1 for center cell
    excludedHexes: excludedCells
  };
}

/**
 * Get all hex cells in a ring around a center.
 * Ring 0 = just the center, Ring 1 = 6 cells, Ring 2 = 12 cells, etc.
 */
function hexRing(center, radius) {
  if (radius === 0) return [center];
  
  const results = [];
  let hex = new HexCoord(center.q + radius, center.r - radius);
  
  // 6 directions, radius steps each
  const directions = [
    [0, 1], [-1, 1], [-1, 0], [0, -1], [1, -1], [1, 0]
  ];
  
  for (const [dq, dr] of directions) {
    for (let i = 0; i < radius; i++) {
      results.push(hex);
      hex = new HexCoord(hex.q + dq, hex.r + dr);
    }
  }
  
  return results;
}
```

### Hexagonal Network Topology

The MANDALA mesh topology can also use hexagonal structure:

```
     Node─────Node
    /    ╲   /    ╲
Node      Node      Node
    ╲    /   ╲    /
     Node─────Node
    /    ╲   /    ╲
Node      Node      Node
    ╲    /   ╲    /
     Node─────Node
```

Each node has exactly **6 preferred peers**, matching the hexagonal geometry.

---

## 5. Implementation Roadmap

### Phase 1: Foundation (v2.9.0)
- [ ] Create `oracle/sst.js` with digital root and family mapping
- [ ] Add SST utility functions to TRIBHUJ
- [ ] Unit tests for all SST primitives

### Phase 2: YPC-27 Enhancement (v2.9.1)
- [ ] Implement YPC-27-SST with 24-cycle rotation
- [ ] Benchmark performance vs. static seed
- [ ] Document the 216-hypercycle relationship

### Phase 3: KARMA Geometry (v2.10.0)
- [ ] Implement trust propagation with √3 ratios
- [ ] Add trust angle classification
- [ ] Create trust triangle visualization

### Phase 4: PRAMAAN Hexagons (v2.11.0)
- [ ] Implement HexCoord class
- [ ] Add hexagonal zone exclusion to geo-proof
- [ ] Create hexagonal MANDALA topology option

---

## 6. Mathematical Foundations

### Why 27?

```
27 = 3³

In SST terms:
- 3 is the base of the Synergy Triangle (30° angle)
- 3³ represents three levels of triangular nesting
- 27 trits can express 7.6 trillion unique states (3^27)

In YAKMESH:
- YPC-27 checksum degree
- 27 trits = ~42.7 bits (vs 40-bit CRC)
- Maps to NTRU lattice parameter n=27
```

### Why 24?

```
24 = 3 × 8 = 3 × 2³

In SST terms:
- Fibonacci digital roots repeat every 24 positions
- 24 = 2 full cycles of the 3-6-9 governing pattern
- The "heartbeat" of SST mathematics

In YAKMESH:
- Potential epoch length for seed rotation
- 24 hours = 1 day (natural time unit)
- 24 × 27 = 648 trits full hypercycle
```

### The 3-6-9 Pattern in YAKMESH

| Concept | Value | Digital Root | Family |
|---------|-------|--------------|--------|
| Trit values | -1, 0, +1 | 8, 9, 1 | B, C, A |
| YPC degree | 27 | 9 | C (Governing) |
| Fibonacci cycle | 24 | 6 | C (Governing) |
| LCM(27,24) | 216 | 9 | C (Governing) |
| 216 ÷ 27 | 8 | 8 | B (Physical+) |
| 216 ÷ 24 | 9 | 9 | C (Governing) |

The governing 3-6-9 family appears consistently in YAKMESH's core constants!

---

## 7. Conclusion

SST provides a compelling mathematical framework that validates and extends YAKMESH's ternary architecture. The proposed integrations:

1. **Unify** existing systems under a coherent mathematical philosophy
2. **Enhance** security through dynamic rotation schedules
3. **Optimize** trust propagation using natural geometric ratios
4. **Enable** geographic proofs with efficient hexagonal tessellation

The philosophical connection is striking: YAKMESH chose balanced ternary for practical reasons (radix economy, NTRU compatibility), but SST suggests this aligns with fundamental patterns in nature and mathematics.

---

## References

1. Long, Wesley. "Synergy Sequence Theory Explained" (2024)
2. Hayes, Brian. "Third Base" American Scientist (2001)
3. YAKMESH TRIBHUJ Specification v2.8.2
4. YAKMESH YPC-27 Specification v2.8.2
5. Tesla, Nikola. "If you knew the magnificence of 3, 6, and 9..." (attributed)

---

*"The universe is built on ternary logic: positive, negative, and neutral. SST reveals why."*
