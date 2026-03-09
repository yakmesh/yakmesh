/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * TRIBHUJ - Balanced Ternary Mathematics for YAKMESH
 * 
 * त्रिभुज (Tribhuj) = Triangle, three-pointed
 * 
 * Implements balanced ternary logic using the set {-1, 0, +1}:
 *   -1 (NEGATIVE): False, Invalid, Reject, Reverse
 *    0 (NEUTRAL):  Unknown, Pending, Abstain, Bidirectional
 *   +1 (POSITIVE): True, Valid, Accept, Forward
 * 
 * Why balanced ternary for mesh networks?
 * 1. Natural representation for 3-state consensus (Accept/Reject/Pending)
 * 2. Self-inverting negation (no 2's complement overhead)
 * 3. Optimal radix economy (closest integer to e ≈ 2.718)
 * 4. Native to NTRU post-quantum cryptography polynomials
 * 5. Perfect for link quality metrics (Forward/Reverse/Bidirectional)
 * 
 * @module oracle/tribhuj
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** Negative trit value: False, Invalid, Reject */
export const NEGATIVE = -1;

/** Neutral trit value: Unknown, Pending, Abstain */
export const NEUTRAL = 0;

/** Positive trit value: True, Valid, Accept */
export const POSITIVE = 1;

/** Semantic aliases for different contexts */
export const TritState = {
  // Boolean logic
  FALSE: NEGATIVE,
  UNKNOWN: NEUTRAL,
  TRUE: POSITIVE,
  
  // Validation
  INVALID: NEGATIVE,
  PENDING: NEUTRAL,
  VALID: POSITIVE,
  
  // Consensus voting
  REJECT: NEGATIVE,
  ABSTAIN: NEUTRAL,
  ACCEPT: POSITIVE,
  
  // Link direction
  REVERSE: NEGATIVE,
  BIDIRECTIONAL: NEUTRAL,
  FORWARD: POSITIVE,
  
  // Trust
  DISTRUST: NEGATIVE,
  UNVERIFIED: NEUTRAL,
  TRUST: POSITIVE,
};

/** Character representations for balanced ternary */
export const TritChars = {
  NEGATIVE: 'T',  // T for "minus" (Soviet convention)
  NEUTRAL: '0',
  POSITIVE: '1',
};

// =============================================================================
// TRIT CLASS - Single Ternary Digit
// =============================================================================

/**
 * A single balanced ternary digit (trit).
 * Immutable value object with arithmetic and logic operations.
 */
export class Trit {
  /** @type {-1 | 0 | 1} */
  #value;

  /**
   * Create a new Trit.
   * @param {number | string | Trit} value - The trit value
   */
  constructor(value = 0) {
    if (value instanceof Trit) {
      this.#value = value.#value;
    } else if (typeof value === 'string') {
      this.#value = Trit.#parseChar(value);
    } else {
      this.#value = Trit.#clamp(value);
    }
    Object.freeze(this);
  }

  /** Get the numeric value (-1, 0, or 1) */
  get value() { return this.#value; }

  /** Check if negative */
  get isNegative() { return this.#value === NEGATIVE; }

  /** Check if neutral */
  get isNeutral() { return this.#value === NEUTRAL; }

  /** Check if positive */
  get isPositive() { return this.#value === POSITIVE; }

  // ---------------------------------------------------------------------------
  // Arithmetic Operations
  // ---------------------------------------------------------------------------

  /**
   * Negate this trit (self-inverting: -(-1)=1, -(0)=0, -(1)=-1)
   * @returns {Trit}
   */
  negate() {
    return new Trit(-this.#value);
  }

  /**
   * Add another trit (with carry).
   * @param {Trit | number} other
   * @returns {{ result: Trit, carry: Trit }}
   */
  add(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    const sum = this.#value + otherVal;
    
    if (sum > 1) {
      return { result: new Trit(sum - 3), carry: new Trit(POSITIVE) };
    } else if (sum < -1) {
      return { result: new Trit(sum + 3), carry: new Trit(NEGATIVE) };
    } else {
      return { result: new Trit(sum), carry: new Trit(NEUTRAL) };
    }
  }

  /**
   * Multiply by another trit.
   * @param {Trit | number} other
   * @returns {Trit}
   */
  multiply(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    return new Trit(this.#value * otherVal);
  }

  // ---------------------------------------------------------------------------
  // Ternary Logic Operations (Kleene/Priest 3-valued logic)
  // ---------------------------------------------------------------------------

  /**
   * Logical NOT (same as negate for balanced ternary)
   * @returns {Trit}
   */
  not() {
    return this.negate();
  }

  /**
   * Logical AND (minimum)
   * Truth table:
   *   AND | -1 |  0 | +1
   *   ----+----+----+----
   *   -1  | -1 | -1 | -1
   *    0  | -1 |  0 |  0
   *   +1  | -1 |  0 | +1
   * 
   * @param {Trit | number} other
   * @returns {Trit}
   */
  and(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    return new Trit(Math.min(this.#value, otherVal));
  }

  /**
   * Logical OR (maximum)
   * @param {Trit | number} other
   * @returns {Trit}
   */
  or(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    return new Trit(Math.max(this.#value, otherVal));
  }

  /**
   * Consensus operation (returns NEUTRAL if disagreement)
   * Useful for distributed voting where disagreement = undecided.
   * @param {Trit | number} other
   * @returns {Trit}
   */
  consensus(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    if (this.#value === otherVal) {
      return new Trit(this.#value);
    }
    return new Trit(NEUTRAL);
  }

  // ---------------------------------------------------------------------------
  // Comparison
  // ---------------------------------------------------------------------------

  /**
   * Compare to another trit.
   * @param {Trit | number} other
   * @returns {Trit} NEGATIVE if less, NEUTRAL if equal, POSITIVE if greater
   */
  compare(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    if (this.#value < otherVal) return new Trit(NEGATIVE);
    if (this.#value > otherVal) return new Trit(POSITIVE);
    return new Trit(NEUTRAL);
  }

  /**
   * Check equality.
   * @param {Trit | number} other
   * @returns {boolean}
   */
  equals(other) {
    const otherVal = other instanceof Trit ? other.#value : Trit.#clamp(other);
    return this.#value === otherVal;
  }

  // ---------------------------------------------------------------------------
  // Conversion
  // ---------------------------------------------------------------------------

  /** Convert to string character (T, 0, 1) */
  toChar() {
    if (this.#value === NEGATIVE) return TritChars.NEGATIVE;
    if (this.#value === POSITIVE) return TritChars.POSITIVE;
    return TritChars.NEUTRAL;
  }

  /** Convert to string */
  toString() {
    return this.toChar();
  }

  /** Convert to JSON-serializable value */
  toJSON() {
    return this.#value;
  }

  /** Get semantic name based on context */
  toName(context = 'boolean') {
    const names = {
      boolean: ['FALSE', 'UNKNOWN', 'TRUE'],
      validation: ['INVALID', 'PENDING', 'VALID'],
      consensus: ['REJECT', 'ABSTAIN', 'ACCEPT'],
      link: ['REVERSE', 'BIDIRECTIONAL', 'FORWARD'],
      trust: ['DISTRUST', 'UNVERIFIED', 'TRUST'],
    };
    const contextNames = names[context] || names.boolean;
    return contextNames[this.#value + 1];
  }

  // ---------------------------------------------------------------------------
  // Static Helpers
  // ---------------------------------------------------------------------------

  /** Clamp a number to valid trit range */
  static #clamp(n) {
    if (n <= -1) return NEGATIVE;
    if (n >= 1) return POSITIVE;
    return NEUTRAL;
  }

  /** Parse a character to trit value */
  static #parseChar(c) {
    const char = c.toUpperCase().trim();
    if (char === 'T' || char === '-' || char === 'N' || char === '-1') return NEGATIVE;
    if (char === '1' || char === '+' || char === 'P' || char === '+1') return POSITIVE;
    return NEUTRAL;
  }

  /** Create from various inputs */
  static from(value) {
    return new Trit(value);
  }

  /** Create NEGATIVE trit */
  static negative() { return new Trit(NEGATIVE); }

  /** Create NEUTRAL trit */
  static neutral() { return new Trit(NEUTRAL); }

  /** Create POSITIVE trit */
  static positive() { return new Trit(POSITIVE); }
}

// =============================================================================
// TRITARRAY CLASS - Multi-Trit Values
// =============================================================================

/**
 * An array of trits representing a balanced ternary number.
 * Most significant trit first (big-endian).
 */
export class TritArray {
  /** @type {Trit[]} */
  #trits;

  /**
   * Create a TritArray.
   * @param {number | string | Trit[] | TritArray} value
   * @param {number} [length] - Fixed length (pads with zeros if needed)
   */
  constructor(value, length) {
    if (value instanceof TritArray) {
      this.#trits = [...value.#trits];
    } else if (Array.isArray(value)) {
      this.#trits = value.map(v => new Trit(v));
    } else if (typeof value === 'string') {
      this.#trits = TritArray.#parseString(value);
    } else if (typeof value === 'number') {
      this.#trits = TritArray.#fromDecimal(value);
    } else {
      this.#trits = [new Trit(NEUTRAL)];
    }

    // Pad or trim to fixed length if specified
    if (length !== undefined) {
      while (this.#trits.length < length) {
        this.#trits.unshift(new Trit(NEUTRAL));
      }
      if (this.#trits.length > length) {
        this.#trits = this.#trits.slice(-length);
      }
    }

    Object.freeze(this.#trits);
    Object.freeze(this);
  }

  /** Get the trit array (copy) */
  get trits() { return [...this.#trits]; }

  /** Get the length */
  get length() { return this.#trits.length; }

  /** Get trit at index (0 = most significant) */
  at(index) {
    return this.#trits[index] ?? new Trit(NEUTRAL);
  }

  // ---------------------------------------------------------------------------
  // Arithmetic
  // ---------------------------------------------------------------------------

  /**
   * Negate the entire array.
   * @returns {TritArray}
   */
  negate() {
    return new TritArray(this.#trits.map(t => t.negate()));
  }

  /**
   * Add another TritArray.
   * @param {TritArray | number} other
   * @returns {TritArray}
   */
  add(other) {
    const otherArr = other instanceof TritArray ? other : new TritArray(other);
    const maxLen = Math.max(this.#trits.length, otherArr.length);
    
    // Pad both to same length
    const a = new TritArray(this, maxLen);
    const b = new TritArray(otherArr, maxLen);
    
    const result = [];
    let carry = new Trit(NEUTRAL);
    
    // Add from least significant (right) to most significant (left)
    for (let i = maxLen - 1; i >= 0; i--) {
      const { result: sum1, carry: carry1 } = a.at(i).add(b.at(i));
      const { result: sum2, carry: carry2 } = sum1.add(carry);
      result.unshift(sum2);
      
      // Combine carries
      const { result: totalCarry } = carry1.add(carry2);
      carry = totalCarry;
    }
    
    // Handle final carry
    if (!carry.isNeutral) {
      result.unshift(carry);
    }
    
    return new TritArray(result);
  }

  /**
   * Multiply by a single trit (scalar).
   * @param {Trit | number} scalar
   * @returns {TritArray}
   */
  multiplyTrit(scalar) {
    const t = scalar instanceof Trit ? scalar : new Trit(scalar);
    return new TritArray(this.#trits.map(trit => trit.multiply(t)));
  }

  // ---------------------------------------------------------------------------
  // Logic Operations (element-wise)
  // ---------------------------------------------------------------------------

  /**
   * Element-wise AND.
   * @param {TritArray} other
   * @returns {TritArray}
   */
  and(other) {
    const otherArr = other instanceof TritArray ? other : new TritArray(other);
    const maxLen = Math.max(this.#trits.length, otherArr.length);
    const a = new TritArray(this, maxLen);
    const b = new TritArray(otherArr, maxLen);
    
    return new TritArray(a.#trits.map((t, i) => t.and(b.at(i))));
  }

  /**
   * Element-wise OR.
   * @param {TritArray} other
   * @returns {TritArray}
   */
  or(other) {
    const otherArr = other instanceof TritArray ? other : new TritArray(other);
    const maxLen = Math.max(this.#trits.length, otherArr.length);
    const a = new TritArray(this, maxLen);
    const b = new TritArray(otherArr, maxLen);
    
    return new TritArray(a.#trits.map((t, i) => t.or(b.at(i))));
  }

  // ---------------------------------------------------------------------------
  // Aggregate Operations
  // ---------------------------------------------------------------------------

  /**
   * Sum all trits (useful for path balance calculation).
   * @returns {number} Sum of all trit values
   */
  sum() {
    return this.#trits.reduce((acc, t) => acc + t.value, 0);
  }

  /**
   * Check if perfectly balanced (sum = 0).
   * @returns {boolean}
   */
  isBalanced() {
    return this.sum() === 0;
  }

  /**
   * Count trits by value.
   * @returns {{ negative: number, neutral: number, positive: number }}
   */
  count() {
    return this.#trits.reduce((acc, t) => {
      if (t.isNegative) acc.negative++;
      else if (t.isPositive) acc.positive++;
      else acc.neutral++;
      return acc;
    }, { negative: 0, neutral: 0, positive: 0 });
  }

  /**
   * Consensus: returns the majority trit, or NEUTRAL if no majority.
   * @returns {Trit}
   */
  majority() {
    const { negative, neutral, positive } = this.count();
    const max = Math.max(negative, neutral, positive);
    
    // Check for tie
    const atMax = [negative, neutral, positive].filter(n => n === max).length;
    if (atMax > 1) return new Trit(NEUTRAL);
    
    if (positive === max) return new Trit(POSITIVE);
    if (negative === max) return new Trit(NEGATIVE);
    return new Trit(NEUTRAL);
  }

  // ---------------------------------------------------------------------------
  // Conversion
  // ---------------------------------------------------------------------------

  /**
   * Convert to decimal integer.
   * @returns {number}
   */
  toDecimal() {
    let result = 0;
    for (let i = 0; i < this.#trits.length; i++) {
      const power = this.#trits.length - 1 - i;
      result += this.#trits[i].value * Math.pow(3, power);
    }
    return result;
  }

  /**
   * Convert to string (e.g., "1T0" for decimal 6).
   * @returns {string}
   */
  toString() {
    return this.#trits.map(t => t.toChar()).join('');
  }

  /** Convert to JSON-serializable array */
  toJSON() {
    return this.#trits.map(t => t.value);
  }

  // ---------------------------------------------------------------------------
  // Static Helpers
  // ---------------------------------------------------------------------------

  /** Parse string to trit array */
  static #parseString(s) {
    return s.split('').map(c => new Trit(c));
  }

  /** Convert decimal to balanced ternary */
  static #fromDecimal(n) {
    if (n === 0) return [new Trit(NEUTRAL)];
    
    const trits = [];
    let value = Math.abs(n);
    const isNegative = n < 0;
    
    while (value > 0) {
      let remainder = value % 3;
      value = Math.floor(value / 3);
      
      if (remainder === 2) {
        remainder = -1;
        value += 1;
      }
      
      trits.unshift(new Trit(remainder));
    }
    
    return isNegative 
      ? trits.map(t => t.negate()) 
      : trits;
  }

  /** Create from decimal */
  static fromDecimal(n, length) {
    return new TritArray(n, length);
  }

  /** Create from string */
  static fromString(s, length) {
    return new TritArray(s, length);
  }

  /** Create zeros of specified length */
  static zeros(length) {
    return new TritArray(new Array(length).fill(NEUTRAL));
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Convert a hex string to TritArray.
 * Useful for converting node IDs to ternary for routing.
 * @param {string} hex - Hexadecimal string
 * @returns {TritArray}
 */
export function hexToTrits(hex) {
  const decimal = parseInt(hex, 16);
  return new TritArray(decimal);
}

/**
 * Compare two hex strings using ternary comparison.
 * @param {string} a - First hex string
 * @param {string} b - Second hex string
 * @returns {Trit} NEGATIVE if a < b, NEUTRAL if equal, POSITIVE if a > b
 */
export function hexCompare(a, b) {
  if (a < b) return new Trit(NEGATIVE);
  if (a > b) return new Trit(POSITIVE);
  return new Trit(NEUTRAL);
}

/**
 * Calculate path balance from an array of link qualities.
 * A balanced path (sum = 0) indicates good bidirectional connectivity.
 * @param {(Trit | number)[]} linkQualities
 * @returns {{ balance: number, isBalanced: boolean, quality: Trit }}
 */
export function calculatePathBalance(linkQualities) {
  const arr = new TritArray(linkQualities.map(q => q instanceof Trit ? q.value : q));
  const balance = arr.sum();
  const isBalanced = balance === 0;
  
  // Quality assessment
  let quality;
  if (isBalanced) {
    quality = new Trit(POSITIVE); // Perfect bidirectional
  } else if (Math.abs(balance) <= Math.ceil(arr.length / 3)) {
    quality = new Trit(NEUTRAL); // Slightly asymmetric
  } else {
    quality = new Trit(NEGATIVE); // Heavily asymmetric
  }
  
  return { balance, isBalanced, quality };
}

// =============================================================================
// NOTE: weightedConsensus was REMOVED (2026-02-05)
// YAKMESH validation is deterministic, not democratic.
// If nodes compute different results, the answer is RECOMPUTE_AND_VERIFY.
// See security/sakshi.js for proper consensus via checkMathematicalAgreement().
// =============================================================================
// EXPORTS SUMMARY
// =============================================================================

export default {
  // Constants
  NEGATIVE,
  NEUTRAL,
  POSITIVE,
  TritState,
  TritChars,
  
  // Classes
  Trit,
  TritArray,
  
  // Utilities
  hexToTrits,
  hexCompare,
  calculatePathBalance,
};
