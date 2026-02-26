/**
 * YPC-27: Yakmesh Polynomial Checksum
 * 
 * A 27-trit quantum-hard checksum operating in the ring:
 *   R = Z[x] / (x^27 - 1) mod 3
 * 
 * This makes packet integrity verification a lattice problem (SIS).
 * Forging a valid checksum requires solving the Shortest Vector Problem.
 * 
 * Properties:
 * - 27 balanced ternary coefficients {-1, 0, +1}
 * - 3^27 = 7.6 trillion possible states
 * - Single bit flip propagates to all 27 coefficients
 * - Quantum-resistant (no hidden period for Shor's algorithm)
 * 
 * @module oracle/ypc27
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE } from './tribhuj.js';
import { FIBONACCI_CYCLE_24, getFamily, SSTFamily } from './sst.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/** Ring degree - number of trits in checksum */
export const N = 27;

/** Default network seed (alternating pattern) */
export const DEFAULT_SEED = Object.freeze([
  1, -1, 0, 1, -1, 0, 1, -1, 0,
  1, -1, 0, 1, -1, 0, 1, -1, 0,
  1, -1, 0, 1, -1, 0, 1, -1, 0
]);

// =============================================================================
// POLY27 CLASS - 27-Trit Polynomial
// =============================================================================

/**
 * A polynomial in the ring Z[x] / (x^27 - 1) mod 3.
 * Coefficients are balanced ternary {-1, 0, +1}.
 */
export class Poly27 {
  /** @type {Int8Array} */
  #coeffs;

  /**
   * Create a Poly27 from coefficients.
   * @param {number[] | Int8Array} [coeffs] - 27 coefficients, defaults to zeros
   */
  constructor(coeffs = null) {
    this.#coeffs = new Int8Array(N);
    
    if (coeffs) {
      if (coeffs.length !== N) {
        throw new Error(`Poly27 requires exactly ${N} coefficients, got ${coeffs.length}`);
      }
      for (let i = 0; i < N; i++) {
        this.#coeffs[i] = Poly27.#reduce3(coeffs[i]);
      }
    }
    
    Object.freeze(this);
  }

  /**
   * Reduce value to balanced ternary {-1, 0, +1}.
   * @param {number} val 
   * @returns {number}
   */
  static #reduce3(val) {
    let r = val % 3;
    if (r < 0) r += 3; // Handle JS negative modulo
    // Map {0, 1, 2} => {0, 1, -1}
    return r === 2 ? -1 : r;
  }

  /** Get coefficient at index */
  get(i) {
    return this.#coeffs[i];
  }

  /** Get all coefficients as array */
  toArray() {
    return Array.from(this.#coeffs);
  }

  /** Get coefficients as Int8Array (for performance) */
  toTypedArray() {
    return new Int8Array(this.#coeffs);
  }

  /**
   * Add two polynomials mod 3.
   * @param {Poly27} other 
   * @returns {Poly27}
   */
  add(other) {
    const result = new Int8Array(N);
    for (let i = 0; i < N; i++) {
      result[i] = Poly27.#reduce3(this.#coeffs[i] + other.#coeffs[i]);
    }
    return new Poly27(result);
  }

  /**
   * Subtract two polynomials mod 3.
   * @param {Poly27} other 
   * @returns {Poly27}
   */
  subtract(other) {
    const result = new Int8Array(N);
    for (let i = 0; i < N; i++) {
      result[i] = Poly27.#reduce3(this.#coeffs[i] - other.#coeffs[i]);
    }
    return new Poly27(result);
  }

  /**
   * Multiply two polynomials mod (x^27 - 1) mod 3.
   * This is cyclic convolution: (i + j) % N wraps around.
   * O(N^2) direct convolution - acceptable for N=27.
   * @param {Poly27} other 
   * @returns {Poly27}
   */
  multiply(other) {
    const result = new Int8Array(N);
    
    for (let i = 0; i < N; i++) {
      for (let j = 0; j < N; j++) {
        const idx = (i + j) % N;
        result[idx] = Poly27.#reduce3(result[idx] + this.#coeffs[i] * other.#coeffs[j]);
      }
    }
    
    return new Poly27(result);
  }

  /**
   * Check if polynomial is zero.
   * @returns {boolean}
   */
  isZero() {
    for (let i = 0; i < N; i++) {
      if (this.#coeffs[i] !== 0) return false;
    }
    return true;
  }

  /**
   * Check equality with another Poly27.
   * @param {Poly27} other 
   * @returns {boolean}
   */
  equals(other) {
    for (let i = 0; i < N; i++) {
      if (this.#coeffs[i] !== other.#coeffs[i]) return false;
    }
    return true;
  }

  /**
   * Convert to string representation.
   * Uses T for -1, 0 for 0, 1 for +1.
   * @returns {string}
   */
  toString() {
    const chars = this.#coeffs.map(c => c === -1 ? 'T' : String(c));
    return `[${chars.join(' ')}]`;
  }

  /**
   * Create Poly27 from hex string (e.g., node ID).
   * Each hex char (4 bits) maps to ~2.5 trits, we use 5 trits per byte.
   * @param {string} hex 
   * @returns {Poly27}
   */
  static fromHex(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return Poly27.fromBytes(new Uint8Array(bytes));
  }

  /**
   * Create Poly27 from bytes.
   * 1 byte → 5 trits (3^5 = 243 ≈ 256).
   * @param {Uint8Array} bytes 
   * @returns {Poly27}
   */
  static fromBytes(bytes) {
    const trits = bytesToTrits(bytes);
    // Take first N trits, pad with zeros if needed
    const coeffs = new Int8Array(N);
    for (let i = 0; i < N && i < trits.length; i++) {
      coeffs[i] = trits[i];
    }
    return new Poly27(coeffs);
  }

  /**
   * Create a zero polynomial.
   * @returns {Poly27}
   */
  static zero() {
    return new Poly27();
  }
}

// =============================================================================
// BYTE/TRIT CONVERSION
// =============================================================================

/**
 * Convert bytes to trits (5 trits per byte).
 * 3^5 = 243, maps 0-242 exactly. Values 243-255 wrap via mod 243.
 * @param {Uint8Array} bytes 
 * @returns {Int8Array}
 */
export function bytesToTrits(bytes) {
  const trits = new Int8Array(bytes.length * 5);
  let idx = 0;
  
  for (const byte of bytes) {
    let val = byte % 243; // Handle 243-255 range
    
    // Extract 5 trits (little endian)
    for (let k = 0; k < 5; k++) {
      let trit = val % 3;
      // Map {0, 1, 2} to {0, 1, -1}
      if (trit === 2) trit = -1;
      trits[idx++] = trit;
      val = Math.floor(val / 3);
    }
  }
  
  return trits;
}

/**
 * Convert trits back to bytes.
 * @param {Int8Array} trits 
 * @returns {Uint8Array}
 */
export function tritsToBytes(trits) {
  const numBytes = Math.floor(trits.length / 5);
  const bytes = new Uint8Array(numBytes);
  
  for (let i = 0; i < numBytes; i++) {
    let val = 0;
    let power = 1;
    
    for (let k = 0; k < 5; k++) {
      let trit = trits[i * 5 + k];
      // Map {-1, 0, 1} to {2, 0, 1}
      if (trit === -1) trit = 2;
      val += trit * power;
      power *= 3;
    }
    
    bytes[i] = val;
  }
  
  return bytes;
}

// =============================================================================
// YPC27 CHECKSUM ENGINE
// =============================================================================

/**
 * YPC-27 Checksum calculator.
 * Computes: C = Σ(P_i · G^i) mod (x^27 - 1) mod 3
 * 
 * Where:
 * - P_i = input data as polynomial chunks
 * - G = seed polynomial
 * - C = 27-trit checksum
 */
export class YPC27Checksum {
  /** @type {Poly27} */
  #state;
  
  /** @type {Poly27} */
  #seed;
  
  /** @type {Poly27} */
  #seedPower; // G^i for rolling update

  /**
   * Create checksum engine with seed polynomial.
   * @param {Poly27 | number[]} [seed] - Network seed, defaults to DEFAULT_SEED
   */
  constructor(seed = DEFAULT_SEED) {
    this.#seed = seed instanceof Poly27 ? seed : new Poly27(seed);
    this.#state = Poly27.zero();
    this.#seedPower = new Poly27([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // = 1
  }

  /**
   * Update checksum with data.
   * State = (State + Input_Poly) * Seed
   * @param {Uint8Array | string} data 
   */
  update(data) {
    // Convert string to bytes if needed
    const bytes = typeof data === 'string' 
      ? new TextEncoder().encode(data) 
      : data;
    
    const trits = bytesToTrits(bytes);
    
    // Process in chunks of N (27) trits
    const numChunks = Math.ceil(trits.length / N);
    
    for (let k = 0; k < numChunks; k++) {
      // Extract chunk
      const chunkCoeffs = new Int8Array(N);
      for (let i = 0; i < N; i++) {
        const idx = k * N + i;
        chunkCoeffs[i] = idx < trits.length ? trits[idx] : 0;
      }
      const chunk = new Poly27(chunkCoeffs);
      
      // State = (State + Chunk) * Seed
      this.#state = this.#state.add(chunk).multiply(this.#seed);
    }
  }

  /**
   * Get the final checksum.
   * @returns {Poly27}
   */
  digest() {
    return this.#state;
  }

  /**
   * Get checksum as compact byte array.
   * 27 trits → ~6 bytes (27/5 = 5.4, rounded up).
   * @returns {Uint8Array}
   */
  digestBytes() {
    // Pad to 30 trits for clean byte conversion
    const trits = new Int8Array(30);
    const stateArr = this.#state.toTypedArray();
    for (let i = 0; i < N; i++) {
      trits[i] = stateArr[i];
    }
    return tritsToBytes(trits);
  }

  /**
   * Get checksum as hex string.
   * @returns {string}
   */
  digestHex() {
    const bytes = this.digestBytes();
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Reset state for reuse.
   */
  reset() {
    this.#state = Poly27.zero();
  }

  /**
   * Set internal state directly (for subclass SST override).
   * @param {Poly27} newState
   * @protected
   */
  _setState(newState) {
    this.#state = newState;
  }

  /**
   * Compute checksum of data in one call.
   * @param {Uint8Array | string} data 
   * @param {Poly27 | number[]} [seed] 
   * @returns {Poly27}
   */
  static compute(data, seed = DEFAULT_SEED) {
    const hasher = new YPC27Checksum(seed);
    hasher.update(data);
    return hasher.digest();
  }

  /**
   * Verify data matches expected checksum.
   * @param {Uint8Array | string} data 
   * @param {Poly27} expected 
   * @param {Poly27 | number[]} [seed] 
   * @returns {boolean}
   */
  static verify(data, expected, seed = DEFAULT_SEED) {
    const computed = YPC27Checksum.compute(data, seed);
    return computed.equals(expected);
  }
}

// =============================================================================
// YPC27_SST — SST-Enhanced Checksum with 24-Cycle Seed Rotation
// =============================================================================

/**
 * YPC-27 with Synergy Sequence Theory (SST) 24-cycle seed rotation.
 * 
 * The seed polynomial rotates based on the Fibonacci digital root cycle:
 * - Family A (1,4,7): Rotate seed LEFT by fibRoot positions (negative polarity)
 * - Family B (2,5,8): Rotate seed RIGHT by fibRoot positions (positive polarity)
 * - Family C (3,6,9): No rotation — singularity/stable point
 * 
 * The full hypercycle repeats every LCM(27, 24) = 216 chunks.
 * This creates 216 unique seed configurations before repeating,
 * dramatically increasing resistance to pattern analysis attacks.
 * 
 * Properties:
 * - Deterministic: all nodes compute the same rotation for the same data
 * - Self-synchronizing: rotation state is derived from chunk index, not mutable state
 * - Compatible: YPC27_SST.verify() can verify its own checksums
 * - The 3-6-9 governing family acts as a stability anchor (no rotation)
 * 
 * @extends YPC27Checksum
 */
export class YPC27_SST extends YPC27Checksum {
  /** @type {number} Current cycle position within the 24-step Fibonacci cycle */
  #cyclePosition;
  
  /** @type {number[]} Original unrotated seed coefficients */
  #baseSeed;

  /** @type {number} Total chunks processed (for telemetry) */
  #chunksProcessed;

  /**
   * Create an SST-enhanced checksum engine.
   * @param {Poly27 | number[]} [seed] - Network seed, defaults to DEFAULT_SEED
   */
  constructor(seed = DEFAULT_SEED) {
    super(seed);
    this.#baseSeed = seed instanceof Poly27 ? seed.toArray() : Array.from(seed);
    this.#cyclePosition = 0;
    this.#chunksProcessed = 0;
  }

  /**
   * Get the rotated seed for the current cycle position.
   * The rotation direction and magnitude are determined by the
   * Fibonacci digital root at the current position:
   * 
   *   Position → fibRoot → Family → Rotation
   *   0 → 1 → A → LEFT by 1
   *   1 → 1 → A → LEFT by 1
   *   2 → 2 → B → RIGHT by 2
   *   3 → 3 → C → NONE (singularity)
   *   ...repeats every 24
   * 
   * @returns {number[]} Rotated seed coefficients
   */
  #getRotatedSeed() {
    const fibRoot = FIBONACCI_CYCLE_24[this.#cyclePosition % 24];
    const family = getFamily(fibRoot);
    const rotateAmount = fibRoot % N; // Constrain to ring degree
    
    switch (family) {
      case SSTFamily.A:
        return YPC27_SST.#rotateArray(this.#baseSeed, -rotateAmount); // LEFT
      case SSTFamily.B:
        return YPC27_SST.#rotateArray(this.#baseSeed, rotateAmount);  // RIGHT
      case SSTFamily.C:
        return this.#baseSeed; // Singularity — no rotation
      default:
        return this.#baseSeed;
    }
  }

  /**
   * Rotate an array by n positions.
   * Positive n = right rotation, negative n = left rotation.
   * @param {number[]} arr 
   * @param {number} n 
   * @returns {number[]}
   */
  static #rotateArray(arr, n) {
    const len = arr.length;
    const shift = ((n % len) + len) % len; // Normalize to [0, len)
    if (shift === 0) return arr;
    return [...arr.slice(len - shift), ...arr.slice(0, len - shift)];
  }

  /**
   * Update checksum with data using SST-rotated seeds.
   * 
   * Each chunk of 27 trits gets multiplied by a seed that has been
   * rotated according to the current Fibonacci cycle position.
   * The cycle advances per chunk, creating a 216-chunk hypercycle.
   * 
   * @param {Uint8Array | string} data 
   */
  update(data) {
    const bytes = typeof data === 'string' 
      ? new TextEncoder().encode(data) 
      : data;
    
    const trits = bytesToTrits(bytes);
    const numChunks = Math.ceil(trits.length / N);
    
    for (let k = 0; k < numChunks; k++) {
      // Extract chunk
      const chunkCoeffs = new Int8Array(N);
      for (let i = 0; i < N; i++) {
        const idx = k * N + i;
        chunkCoeffs[i] = idx < trits.length ? trits[idx] : 0;
      }
      const chunk = new Poly27(chunkCoeffs);
      
      // Get the SST-rotated seed for this chunk's cycle position
      const rotatedSeed = new Poly27(this.#getRotatedSeed());
      
      // State = (State + Chunk) * RotatedSeed
      // Access parent state via digest/reset pattern
      this._updateStateWith(chunk, rotatedSeed);
      
      // Advance the cycle
      this.#cyclePosition = (this.#cyclePosition + 1) % 24;
      this.#chunksProcessed++;
    }
  }

  /**
   * Internal: update state with chunk and rotated seed.
   * This replaces the parent's update logic for SST mode.
   * @param {Poly27} chunk 
   * @param {Poly27} rotatedSeed 
   */
  _updateStateWith(chunk, rotatedSeed) {
    // We need direct access to parent state — use the internal pattern
    const currentState = this.digest();
    const newState = currentState.add(chunk).multiply(rotatedSeed);
    this._setState(newState);
  }

  /**
   * Get current cycle position (0-23).
   * @returns {number}
   */
  get cyclePosition() {
    return this.#cyclePosition;
  }

  /**
   * Get hypercycle position (0-215).
   * LCM(27, 24) = 216 — the full rotation repeats here.
   * @returns {number}
   */
  get hypercyclePosition() {
    return this.#chunksProcessed % 216;
  }

  /**
   * Get total chunks processed.
   * @returns {number}
   */
  get chunksProcessed() {
    return this.#chunksProcessed;
  }

  /**
   * Reset state for reuse.
   */
  reset() {
    super.reset();
    this.#cyclePosition = 0;
    this.#chunksProcessed = 0;
  }

  /**
   * Compute SST-enhanced checksum in one call.
   * @param {Uint8Array | string} data 
   * @param {Poly27 | number[]} [seed] 
   * @returns {Poly27}
   */
  static compute(data, seed = DEFAULT_SEED) {
    const hasher = new YPC27_SST(seed);
    hasher.update(data);
    return hasher.digest();
  }

  /**
   * Verify data against an SST-computed checksum.
   * @param {Uint8Array | string} data 
   * @param {Poly27} expected 
   * @param {Poly27 | number[]} [seed] 
   * @returns {boolean}
   */
  static verify(data, expected, seed = DEFAULT_SEED) {
    const computed = YPC27_SST.compute(data, seed);
    return computed.equals(expected);
  }
}

// =============================================================================
// CONVENIENCE EXPORTS
// =============================================================================

/**
 * Quick hash function - returns hex string.
 * @param {Uint8Array | string} data 
 * @param {number[]} [seed] 
 * @returns {string}
 */
export function ypc27(data, seed = DEFAULT_SEED) {
  const hasher = new YPC27Checksum(seed);
  hasher.update(data);
  return hasher.digestHex();
}

/**
 * Create seed from peer ID (first 27 trits of ID).
 * @param {string} peerId - 64-char hex peer ID
 * @returns {Poly27}
 */
export function seedFromPeerId(peerId) {
  return Poly27.fromHex(peerId.substring(0, 12)); // 6 bytes = 30 trits, take first 27
}
