/**
 * YPC-27 Polynomial Checksum Tests
 * 
 * @module oracle/tests/ypc27.test
 */

import { describe, it, expect } from 'vitest';
import {
  Poly27,
  YPC27Checksum,
  ypc27,
  bytesToTrits,
  tritsToBytes,
  seedFromPeerId,
  N,
  DEFAULT_SEED
} from '../ypc27.js';

describe('Poly27', () => {
  describe('constructor', () => {
    it('creates zero polynomial by default', () => {
      const p = new Poly27();
      for (let i = 0; i < N; i++) {
        expect(p.get(i)).toBe(0);
      }
    });

    it('creates polynomial from array', () => {
      const coeffs = [1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0];
      const p = new Poly27(coeffs);
      expect(p.get(0)).toBe(1);
      expect(p.get(1)).toBe(-1);
      expect(p.get(2)).toBe(0);
    });

    it('reduces coefficients to balanced ternary', () => {
      const coeffs = [2, 3, 4, -2, -3, -4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      const p = new Poly27(coeffs);
      // 2 % 3 = 2 → -1
      expect(p.get(0)).toBe(-1);
      // 3 % 3 = 0 → 0
      expect(p.get(1)).toBe(0);
      // 4 % 3 = 1 → 1
      expect(p.get(2)).toBe(1);
    });

    it('throws if wrong length', () => {
      expect(() => new Poly27([1, 2, 3])).toThrow();
    });
  });

  describe('arithmetic', () => {
    it('adds two polynomials mod 3', () => {
      const a = new Poly27([1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const b = new Poly27([1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const c = a.add(b);
      // 1 + 1 = 2 → -1 (mod 3)
      expect(c.get(0)).toBe(-1);
      // 0 + 1 = 1
      expect(c.get(1)).toBe(1);
      // -1 + 1 = 0
      expect(c.get(2)).toBe(0);
    });

    it('subtracts two polynomials mod 3', () => {
      const a = new Poly27([1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const b = new Poly27([1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const c = a.subtract(b);
      // 1 - 1 = 0
      expect(c.get(0)).toBe(0);
      // 0 - 1 = -1
      expect(c.get(1)).toBe(-1);
      // -1 - 1 = -2 → 1 (mod 3)
      expect(c.get(2)).toBe(1);
    });

    it('multiplies with cyclic convolution', () => {
      // Simple test: x * x = x^2
      const x = new Poly27([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const x2 = x.multiply(x);
      expect(x2.get(2)).toBe(1);
      expect(x2.get(0)).toBe(0);
      expect(x2.get(1)).toBe(0);
    });

    it('wraps around at x^27 (cyclic)', () => {
      // x^26 * x = x^27 = x^0 = 1 (in ring x^27 - 1)
      const x26 = new Poly27([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
      const x = new Poly27([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const result = x26.multiply(x);
      // x^27 wraps to index 0
      expect(result.get(0)).toBe(1);
    });
  });

  describe('equality', () => {
    it('equals returns true for identical polynomials', () => {
      const a = new Poly27(DEFAULT_SEED);
      const b = new Poly27(DEFAULT_SEED);
      expect(a.equals(b)).toBe(true);
    });

    it('equals returns false for different polynomials', () => {
      const a = new Poly27(DEFAULT_SEED);
      const b = Poly27.zero();
      expect(a.equals(b)).toBe(false);
    });

    it('isZero detects zero polynomial', () => {
      expect(Poly27.zero().isZero()).toBe(true);
      expect(new Poly27(DEFAULT_SEED).isZero()).toBe(false);
    });
  });

  describe('conversion', () => {
    it('toString produces readable output', () => {
      const p = new Poly27([1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0]);
      const str = p.toString();
      expect(str).toContain('1');
      expect(str).toContain('T');
      expect(str).toContain('0');
    });

    it('fromBytes creates polynomial from bytes', () => {
      const bytes = new Uint8Array([0, 1, 2, 3, 4, 5]);
      const p = Poly27.fromBytes(bytes);
      expect(p).toBeInstanceOf(Poly27);
    });

    it('fromHex creates polynomial from hex string', () => {
      const p = Poly27.fromHex('abcdef');
      expect(p).toBeInstanceOf(Poly27);
    });
  });
});

describe('bytesToTrits / tritsToBytes', () => {
  it('converts bytes to 5 trits each', () => {
    const bytes = new Uint8Array([0]);
    const trits = bytesToTrits(bytes);
    expect(trits.length).toBe(5);
    // 0 → [0, 0, 0, 0, 0]
    expect(Array.from(trits)).toEqual([0, 0, 0, 0, 0]);
  });

  it('converts byte 1 correctly', () => {
    const bytes = new Uint8Array([1]);
    const trits = bytesToTrits(bytes);
    // 1 in base 3 = [1, 0, 0, 0, 0]
    expect(trits[0]).toBe(1);
  });

  it('converts byte 2 to balanced ternary', () => {
    const bytes = new Uint8Array([2]);
    const trits = bytesToTrits(bytes);
    // 2 → -1 in balanced ternary
    expect(trits[0]).toBe(-1);
  });

  it('round-trips bytes through trits', () => {
    const original = new Uint8Array([0, 42, 100, 200, 242]);
    const trits = bytesToTrits(original);
    const recovered = tritsToBytes(trits);
    expect(Array.from(recovered)).toEqual(Array.from(original));
  });

  it('handles values > 242 via mod 243', () => {
    const bytes = new Uint8Array([243, 255]);
    const trits = bytesToTrits(bytes);
    const recovered = tritsToBytes(trits);
    // 243 % 243 = 0, 255 % 243 = 12
    expect(recovered[0]).toBe(0);
    expect(recovered[1]).toBe(12);
  });
});

describe('YPC27Checksum', () => {
  describe('basic usage', () => {
    it('computes checksum for string', () => {
      const hasher = new YPC27Checksum();
      hasher.update('Hello World');
      const digest = hasher.digest();
      expect(digest).toBeInstanceOf(Poly27);
      expect(digest.isZero()).toBe(false);
    });

    it('computes checksum for bytes', () => {
      const hasher = new YPC27Checksum();
      hasher.update(new Uint8Array([1, 2, 3, 4, 5]));
      const digest = hasher.digest();
      expect(digest.isZero()).toBe(false);
    });

    it('returns hex digest', () => {
      const hasher = new YPC27Checksum();
      hasher.update('test');
      const hex = hasher.digestHex();
      expect(typeof hex).toBe('string');
      expect(hex.length).toBe(12); // 6 bytes = 12 hex chars
    });
  });

  describe('determinism', () => {
    it('same input produces same output', () => {
      const h1 = new YPC27Checksum();
      h1.update('deterministic');
      const d1 = h1.digest();

      const h2 = new YPC27Checksum();
      h2.update('deterministic');
      const d2 = h2.digest();

      expect(d1.equals(d2)).toBe(true);
    });

    it('different input produces different output', () => {
      const h1 = new YPC27Checksum();
      h1.update('message1');
      const d1 = h1.digest();

      const h2 = new YPC27Checksum();
      h2.update('message2');
      const d2 = h2.digest();

      expect(d1.equals(d2)).toBe(false);
    });

    it('order matters (not commutative)', () => {
      const h1 = new YPC27Checksum();
      h1.update('AB');
      const d1 = h1.digest();

      const h2 = new YPC27Checksum();
      h2.update('BA');
      const d2 = h2.digest();

      expect(d1.equals(d2)).toBe(false);
    });
  });

  describe('seed sensitivity', () => {
    it('different seeds produce different checksums', () => {
      const seed1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      const seed2 = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

      const h1 = new YPC27Checksum(seed1);
      h1.update('test');
      
      const h2 = new YPC27Checksum(seed2);
      h2.update('test');

      expect(h1.digest().equals(h2.digest())).toBe(false);
    });
  });

  describe('static methods', () => {
    it('compute() returns checksum in one call', () => {
      const digest = YPC27Checksum.compute('quick test');
      expect(digest).toBeInstanceOf(Poly27);
    });

    it('verify() confirms matching data', () => {
      const data = 'verify me';
      const expected = YPC27Checksum.compute(data);
      expect(YPC27Checksum.verify(data, expected)).toBe(true);
    });

    it('verify() rejects mismatched data', () => {
      const expected = YPC27Checksum.compute('original');
      expect(YPC27Checksum.verify('tampered', expected)).toBe(false);
    });
  });

  describe('reset', () => {
    it('reset allows reuse', () => {
      const hasher = new YPC27Checksum();
      hasher.update('first');
      const d1 = hasher.digestHex();
      
      hasher.reset();
      hasher.update('second');
      const d2 = hasher.digestHex();

      expect(d1).not.toBe(d2);

      // Verify second run is deterministic
      hasher.reset();
      hasher.update('second');
      expect(hasher.digestHex()).toBe(d2);
    });
  });
});

describe('ypc27 convenience function', () => {
  it('returns hex string', () => {
    const hex = ypc27('quick hash');
    expect(typeof hex).toBe('string');
    expect(hex.length).toBe(12);
  });

  it('works with bytes', () => {
    const hex = ypc27(new Uint8Array([1, 2, 3]));
    expect(typeof hex).toBe('string');
  });
});

describe('seedFromPeerId', () => {
  it('creates Poly27 from peer ID', () => {
    const peerId = 'a'.repeat(64);
    const seed = seedFromPeerId(peerId);
    expect(seed).toBeInstanceOf(Poly27);
  });

  it('different peer IDs produce different seeds', () => {
    const seed1 = seedFromPeerId('a'.repeat(64));
    const seed2 = seedFromPeerId('b'.repeat(64));
    expect(seed1.equals(seed2)).toBe(false);
  });
});

describe('quantum-hard properties', () => {
  it('single bit change affects multiple output coefficients', () => {
    const data1 = new Uint8Array([0, 0, 0, 0, 0]);
    const data2 = new Uint8Array([1, 0, 0, 0, 0]); // Only first byte differs

    const d1 = YPC27Checksum.compute(data1);
    const d2 = YPC27Checksum.compute(data2);

    // Count differing coefficients
    let diffCount = 0;
    for (let i = 0; i < N; i++) {
      if (d1.get(i) !== d2.get(i)) diffCount++;
    }

    // Should affect many coefficients (avalanche effect)
    expect(diffCount).toBeGreaterThan(10);
  });
});
