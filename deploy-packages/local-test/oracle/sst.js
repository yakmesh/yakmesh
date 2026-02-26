/**
 * SST - Synergy Sequence Theory Integration for YAKMESH
 * 
 * Based on Wesley Long's Synergy Sequence Theory, this module provides:
 * - Digital root calculation
 * - SST family classification (1,4,7 / 2,5,8 / 3,6,9)
 * - Fibonacci 24-cycle sequences
 * - Synergy Matrix generation
 * 
 * The theory proposes that the numbers 3, 6, and 9 are "keys to the universe"
 * and that all numbers belong to one of three family groups that determine
 * their fundamental polarity.
 * 
 * Integration Points:
 * - TRIBHUJ: Family → Trit mapping
 * - YPC-27: 24-cycle seed rotation
 * - KARMA: Synergy Triangle trust geometry
 * - PRAMAAN: Hexagonal tessellation
 * 
 * @module oracle/sst
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 * @see docs/SST-INTEGRATION.md
 */

import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from './tribhuj.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * SST Family identifiers.
 * 
 * Family A (1,4,7): Physical Negative - descending energy
 * Family B (2,5,8): Physical Positive - ascending energy
 * Family C (3,6,9): Governing/Source - the singularity
 */
export const SSTFamily = Object.freeze({
  A: 'A', // 1, 4, 7 - Physical Negative
  B: 'B', // 2, 5, 8 - Physical Positive  
  C: 'C', // 3, 6, 9 - Governing/Source
});

/**
 * The 24-digit repeating Fibonacci digital root sequence.
 * This is the fundamental SST cycle discovered by reducing
 * the infinite Fibonacci sequence to digital roots.
 * 
 * Pattern emerges: positions 12 and 24 are both 9 (singularity markers)
 */
export const FIBONACCI_CYCLE_24 = Object.freeze([
  1, 1, 2, 3, 5, 8, 4, 3, 7, 1, 8, 9,  // First half
  8, 8, 7, 6, 4, 1, 5, 6, 2, 8, 1, 9   // Second half (mirror-ish)
]);

/**
 * Family to Trit mapping.
 * 
 * This is the core SST-TRIBHUJ bridge:
 * - Family A represents the negative/descending polarity
 * - Family B represents the positive/ascending polarity
 * - Family C represents the neutral/governing singularity
 */
export const FAMILY_TO_TRIT = Object.freeze({
  [SSTFamily.A]: NEGATIVE, // -1
  [SSTFamily.B]: POSITIVE, // +1
  [SSTFamily.C]: NEUTRAL,  //  0
});

/**
 * Synergy Triangle angles (degrees).
 * These form the fundamental 30-60-90 right triangle.
 */
export const SynergyAngles = Object.freeze({
  BASE: 30,     // Shallow, wide
  MIDDLE: 60,   // Balanced
  APEX: 90,     // Deep, narrow
});

/**
 * Trust propagation ratios based on Synergy Triangle geometry.
 * Derived from the 30-60-90 triangle: sides are in ratio 1 : √3 : 2
 */
export const TRUST_PROPAGATION = Object.freeze({
  DIRECT: 1.0,                    // Self
  ONE_HOP: 1 / Math.sqrt(3),      // ≈ 0.577
  TWO_HOPS: 1 / 3,                // ≈ 0.333
  THREE_HOPS: 1 / Math.sqrt(27),  // ≈ 0.192
});

/**
 * Hexagonal cell sizes (km) based on powers of 3.
 * These provide natural scaling for geographic zones.
 */
export const HEX_CELL_SIZES = Object.freeze({
  MICRO: 9,     // 3² km - City district
  SMALL: 27,    // 3³ km - Metro area
  MEDIUM: 81,   // 3⁴ km - Regional
  LARGE: 243,   // 3⁵ km - National
  MEGA: 729,    // 3⁶ km - Continental
});

// =============================================================================
// DIGITAL ROOT FUNCTIONS
// =============================================================================

/**
 * Calculate the digital root of a number.
 * 
 * Sum digits repeatedly until a single digit (1-9) remains.
 * This is equivalent to (n - 1) % 9 + 1 for positive n.
 * 
 * Examples:
 *   digitalRoot(27) = 9 (2 + 7 = 9)
 *   digitalRoot(123) = 6 (1 + 2 + 3 = 6)
 *   digitalRoot(999) = 9
 *   digitalRoot(0) = 9 (special case: 0 → 9 in SST)
 * 
 * @param {number | bigint} n - Any integer
 * @returns {number} - A value 1-9
 */
export function digitalRoot(n) {
  // Handle BigInt
  if (typeof n === 'bigint') {
    if (n === 0n) return 9;
    const abs = n < 0n ? -n : n;
    const root = Number(abs % 9n);
    return root === 0 ? 9 : root;
  }
  
  // Handle regular numbers
  if (n === 0) return 9;
  const abs = Math.abs(Math.floor(n));
  const root = abs % 9;
  return root === 0 ? 9 : root;
}

/**
 * Get the SST family for a digital root (1-9).
 * 
 * @param {number} root - Digital root value 1-9
 * @returns {'A' | 'B' | 'C'}
 */
export function getFamily(root) {
  if (root === 1 || root === 4 || root === 7) return SSTFamily.A;
  if (root === 2 || root === 5 || root === 8) return SSTFamily.B;
  return SSTFamily.C; // 3, 6, 9
}

/**
 * Get the SST family for any number.
 * Calculates digital root, then returns family.
 * 
 * @param {number | bigint} n - Any integer
 * @returns {'A' | 'B' | 'C'}
 */
export function getFamilyOf(n) {
  return getFamily(digitalRoot(n));
}

/**
 * Map any number to a Trit via its SST family.
 * 
 * This is the core SST-TRIBHUJ mapping:
 *   Family A (1,4,7) → -1 (NEGATIVE) - Physical descending
 *   Family B (2,5,8) → +1 (POSITIVE) - Physical ascending
 *   Family C (3,6,9) →  0 (NEUTRAL)  - Governing singularity
 * 
 * @param {number | bigint} n 
 * @returns {Trit}
 */
export function toFamilyTrit(n) {
  const family = getFamilyOf(n);
  return new Trit(FAMILY_TO_TRIT[family]);
}

/**
 * Convert a byte array to family trits.
 * Each byte maps to its SST family trit.
 * 
 * @param {Uint8Array} bytes 
 * @returns {Int8Array} - Array of trit values (-1, 0, +1)
 */
export function bytesToFamilyTrits(bytes) {
  const trits = new Int8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    trits[i] = toFamilyTrit(bytes[i]).value;
  }
  return trits;
}

/**
 * Get family statistics for a byte array.
 * 
 * @param {Uint8Array} bytes 
 * @returns {{ a: number, b: number, c: number, dominant: 'A' | 'B' | 'C' }}
 */
export function analyzeBytesFamilies(bytes) {
  let a = 0, b = 0, c = 0;
  
  for (const byte of bytes) {
    const family = getFamilyOf(byte);
    if (family === SSTFamily.A) a++;
    else if (family === SSTFamily.B) b++;
    else c++;
  }
  
  const max = Math.max(a, b, c);
  const dominant = max === a ? SSTFamily.A : max === b ? SSTFamily.B : SSTFamily.C;
  
  return { a, b, c, dominant };
}

// =============================================================================
// FIBONACCI CYCLE FUNCTIONS
// =============================================================================

/**
 * Get the digital root Fibonacci number at position n.
 * Uses the 24-position cycle.
 * 
 * @param {number} n - Position (0-indexed)
 * @returns {number} - Digital root 1-9
 */
export function fibonacciRoot(n) {
  const pos = ((n % 24) + 24) % 24; // Handle negative indices
  return FIBONACCI_CYCLE_24[pos];
}

/**
 * Get the SST family for Fibonacci position n.
 * 
 * @param {number} n 
 * @returns {'A' | 'B' | 'C'}
 */
export function fibonacciFamily(n) {
  return getFamily(fibonacciRoot(n));
}

/**
 * Get the family trit for Fibonacci position n.
 * 
 * @param {number} n 
 * @returns {Trit}
 */
export function fibonacciFamilyTrit(n) {
  return toFamilyTrit(fibonacciRoot(n));
}

/**
 * Analyze the 24-cycle for family distribution.
 * 
 * @returns {{ a: number[], b: number[], c: number[] }}
 */
export function analyzeFibonacciCycle() {
  const a = [], b = [], c = [];
  
  for (let i = 0; i < 24; i++) {
    const family = fibonacciFamily(i);
    if (family === SSTFamily.A) a.push(i);
    else if (family === SSTFamily.B) b.push(i);
    else c.push(i);
  }
  
  return { a, b, c };
}

// =============================================================================
// SYNERGY MATRIX FUNCTIONS
// =============================================================================

/**
 * Generate a Fibonacci-style sequence starting with a specific seed.
 * Each term is the digital root of the sum of the previous two.
 * 
 * @param {number} seed - Starting digit 1-9
 * @param {number} length - How many terms
 * @returns {number[]}
 */
export function generateFibonacciSequence(seed, length = 24) {
  if (seed < 1 || seed > 9) throw new Error('Seed must be 1-9');
  
  const sequence = [seed, seed]; // Start with seed, seed
  
  for (let i = 2; i < length; i++) {
    const sum = sequence[i - 1] + sequence[i - 2];
    sequence.push(digitalRoot(sum));
  }
  
  return sequence;
}

/**
 * Generate the full Synergy Matrix - 9 Fibonacci-style sequences.
 * Each row starts with digit 1-9 repeated, then follows Fibonacci addition.
 * All values reduced to digital roots.
 * 
 * @param {number} length - How many columns
 * @returns {number[][]} - 9 rows of digital roots
 */
export function generateSynergyMatrix(length = 24) {
  const matrix = [];
  
  for (let seed = 1; seed <= 9; seed++) {
    matrix.push(generateFibonacciSequence(seed, length));
  }
  
  return matrix;
}

/**
 * Get the family pattern for a Synergy Matrix row.
 * 
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

/**
 * Convert entire Synergy Matrix to trit patterns.
 * 
 * @param {number[][]} matrix 
 * @returns {Int8Array[]}
 */
export function matrixToTritPatterns(matrix) {
  return matrix.map(row => rowToFamilyPattern(row));
}

// =============================================================================
// TRUST GEOMETRY FUNCTIONS
// =============================================================================

/**
 * Calculate trust propagation based on hop distance.
 * Uses the Synergy Triangle ratios (1/√3 decay).
 * 
 * @param {number} baseTrust - Original trust score (0-1)
 * @param {number} hops - Number of hops from source
 * @returns {number} - Propagated trust score
 */
export function propagateTrust(baseTrust, hops) {
  if (hops < 0) throw new Error('Hops cannot be negative');
  if (hops === 0) return baseTrust * TRUST_PROPAGATION.DIRECT;
  if (hops === 1) return baseTrust * TRUST_PROPAGATION.ONE_HOP;
  if (hops === 2) return baseTrust * TRUST_PROPAGATION.TWO_HOPS;
  if (hops === 3) return baseTrust * TRUST_PROPAGATION.THREE_HOPS;
  
  // Beyond 3 hops: general formula 1/√(3^hops) = 3^(-hops/2)
  return baseTrust * Math.pow(3, -hops / 2);
}

/**
 * Get trust decay half-life based on trust angle.
 * 
 * Shallow (30°): Fast decay, low commitment
 * Balanced (60°): Medium decay
 * Deep (90°): Slow decay, high commitment
 * 
 * @param {number} angle - 30, 60, or 90
 * @returns {number} - Half-life in milliseconds
 */
export function trustHalfLife(angle) {
  const HOUR = 3600 * 1000;
  const DAY = 24 * HOUR;
  
  switch (angle) {
    case SynergyAngles.BASE:   return 1 * DAY;   // 24 hours
    case SynergyAngles.MIDDLE: return 7 * DAY;   // 1 week
    case SynergyAngles.APEX:   return 90 * DAY;  // ~3 months
    default: return 7 * DAY;
  }
}

/**
 * Calculate decayed trust based on time elapsed and angle.
 * 
 * @param {number} initialTrust - Starting trust (0-1)
 * @param {number} elapsedMs - Time since trust was established
 * @param {number} angle - Trust angle (30, 60, or 90)
 * @returns {number} - Current trust level
 */
export function decayTrust(initialTrust, elapsedMs, angle = SynergyAngles.MIDDLE) {
  const halfLife = trustHalfLife(angle);
  const decayFactor = Math.pow(0.5, elapsedMs / halfLife);
  return initialTrust * decayFactor;
}

// =============================================================================
// HEXAGONAL GEOMETRY (PRAMAAN INTEGRATION)
// =============================================================================

/**
 * Axial coordinates for hexagonal grid.
 * Uses "pointy-top" orientation aligned with 30-60-90 triangles.
 */
export class HexCoord {
  /**
   * @param {number} q - Column coordinate
   * @param {number} r - Row coordinate
   */
  constructor(q, r) {
    this.q = q;
    this.r = r;
  }

  /** Get the implicit s coordinate (q + r + s = 0) */
  get s() {
    return -this.q - this.r;
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

  /** Distance to another hex cell (in cells) */
  distanceTo(other) {
    return Math.max(
      Math.abs(this.q - other.q),
      Math.abs(this.r - other.r),
      Math.abs(this.s - other.s)
    );
  }

  /** Check equality */
  equals(other) {
    return this.q === other.q && this.r === other.r;
  }

  /** String representation */
  toString() {
    return `Hex(${this.q}, ${this.r})`;
  }

  /**
   * Round fractional hex coordinates to nearest integer hex.
   * @param {number} q - Fractional q
   * @param {number} r - Fractional r
   * @returns {HexCoord}
   */
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

  /** Origin cell */
  static origin() {
    return new HexCoord(0, 0);
  }
}

/**
 * Get all hex cells in a ring around a center.
 * Ring 0 = just the center, Ring 1 = 6 cells, Ring 2 = 12 cells, etc.
 * 
 * @param {HexCoord} center 
 * @param {number} radius 
 * @returns {HexCoord[]}
 */
export function hexRing(center, radius) {
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

/**
 * Get all hex cells in a filled hexagon (disk) around a center.
 * 
 * @param {HexCoord} center 
 * @param {number} radius 
 * @returns {HexCoord[]}
 */
export function hexDisk(center, radius) {
  const results = [];
  for (let r = 0; r <= radius; r++) {
    results.push(...hexRing(center, r));
  }
  return results;
}

/**
 * Calculate number of cells in a hex disk of given radius.
 * Formula: 3*r*(r+1) + 1
 * 
 * @param {number} radius 
 * @returns {number}
 */
export function hexDiskSize(radius) {
  return 3 * radius * (radius + 1) + 1;
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Constants
  SSTFamily,
  FIBONACCI_CYCLE_24,
  FAMILY_TO_TRIT,
  SynergyAngles,
  TRUST_PROPAGATION,
  HEX_CELL_SIZES,
  
  // Digital Root
  digitalRoot,
  getFamily,
  getFamilyOf,
  toFamilyTrit,
  bytesToFamilyTrits,
  analyzeBytesFamilies,
  
  // Fibonacci Cycle
  fibonacciRoot,
  fibonacciFamily,
  fibonacciFamilyTrit,
  analyzeFibonacciCycle,
  
  // Synergy Matrix
  generateFibonacciSequence,
  generateSynergyMatrix,
  rowToFamilyPattern,
  matrixToTritPatterns,
  
  // Trust Geometry
  propagateTrust,
  trustHalfLife,
  decayTrust,
  
  // Hexagonal Geometry
  HexCoord,
  hexRing,
  hexDisk,
  hexDiskSize,
};
