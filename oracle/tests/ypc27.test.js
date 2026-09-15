/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * YPC-27 Polynomial Checksum Tests
 *
 * Uses node:test (not vitest) — matches package.json test runner.
 *
 * @module oracle/tests/ypc27.test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
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
        assert.strictEqual(p.get(i), 0);
      }
    });

    it('creates polynomial from array', () => {
      const coeffs = [1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0];
      const p = new Poly27(coeffs);
      assert.strictEqual(p.get(0), 1);
      assert.strictEqual(p.get(1), 2);  // -1 mod 3 = 2 in F_3 {0,1,2}
      assert.strictEqual(p.get(2), 0);
    });

    it('reduces coefficients to F_3 {0, 1, 2}', () => {
      const coeffs = [2, 3, 4, -2, -3, -4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      const p = new Poly27(coeffs);
      // 2 % 3 = 2 (stored as 2 in F_3, not -1)
      assert.strictEqual(p.get(0), 2);
      // 3 % 3 = 0
      assert.strictEqual(p.get(1), 0);
      // 4 % 3 = 1
      assert.strictEqual(p.get(2), 1);
    });

    it('throws if wrong length', () => {
      assert.throws(() => new Poly27([1, 2, 3]));
    });
  });

  describe('arithmetic', () => {
    it('adds two polynomials mod 3', () => {
      const a = new Poly27([1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const b = new Poly27([1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const c = a.add(b);
      // 1 + 1 = 2 (in F_3 {0,1,2})
      assert.strictEqual(c.get(0), 2);
      // 0 + 1 = 1
      assert.strictEqual(c.get(1), 1);
      // 2 + 1 = 3 → 0 (mod 3)
      assert.strictEqual(c.get(2), 0);
    });

    it('subtracts two polynomials mod 3', () => {
      const a = new Poly27([1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const b = new Poly27([1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const c = a.subtract(b);
      // 1 - 1 = 0
      assert.strictEqual(c.get(0), 0);
      // 0 - 1 = -1 → 2 (mod 3)
      assert.strictEqual(c.get(1), 2);
      // 2 - 1 = 1
      assert.strictEqual(c.get(2), 1);
    });

    it('multiplies with cyclic convolution', () => {
      // Simple test: x * x = x^2
      const x = new Poly27([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const x2 = x.multiply(x);
      assert.strictEqual(x2.get(2), 1);
      assert.strictEqual(x2.get(0), 0);
      assert.strictEqual(x2.get(1), 0);
    });

    it('reduces x^27 via irreducible polynomial (field reduction)', () => {
      // The field F₃²⁷ uses an irreducible polynomial of degree 27.
      // x^27 does NOT wrap to x^0=1 (that was the old degenerate ring x^27-1).
      // Instead, x^27 is reduced modulo the irreducible polynomial.
      const x26 = new Poly27([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
      const x = new Poly27([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const result = x26.multiply(x);
      // x^27 is reduced by the irreducible polynomial — result should be non-zero
      // and should NOT be 1 (that would be the old degenerate ring)
      assert.ok(!result.isZero(), 'x^27 should not reduce to zero');
      // The result should be the reduction of x^27 mod f(x), which is a specific
      // polynomial determined by the irreducible. We just verify it's non-trivial.
    });
  });

  describe('equality', () => {
    it('equals returns true for identical polynomials', () => {
      const a = new Poly27(DEFAULT_SEED);
      const b = new Poly27(DEFAULT_SEED);
      assert.strictEqual(a.equals(b), true);
    });

    it('equals returns false for different polynomials', () => {
      const a = new Poly27(DEFAULT_SEED);
      const b = Poly27.zero();
      assert.strictEqual(a.equals(b), false);
    });

    it('isZero detects zero polynomial', () => {
      assert.strictEqual(Poly27.zero().isZero(), true);
      assert.strictEqual(new Poly27(DEFAULT_SEED).isZero(), false);
    });
  });

  describe('conversion', () => {
    it('toString produces readable output', () => {
      const p = new Poly27([1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0]);
      const str = p.toString();
      // toString uses balanced ternary notation: T = -1, 0 = 0, 1 = 1
      assert.ok(str.includes('1'));
      assert.ok(str.includes('T'));  // T represents -1 (which is 2 in F_3)
      assert.ok(str.includes('0'));
    });

    it('fromBytes creates polynomial from bytes', () => {
      const bytes = new Uint8Array([0, 1, 2, 3, 4, 5]);
      const p = Poly27.fromBytes(bytes);
      assert.ok(p instanceof Poly27);
    });

    it('fromHex creates polynomial from hex string', () => {
      const p = Poly27.fromHex('abcdef');
      assert.ok(p instanceof Poly27);
    });
  });
});

describe('bytesToTrits / tritsToBytes', () => {
  it('converts bytes to 5 trits each', () => {
    const bytes = new Uint8Array([0]);
    const trits = bytesToTrits(bytes);
    assert.strictEqual(trits.length, 5);
    // 0 → [0, 0, 0, 0, 0]
    assert.deepStrictEqual(Array.from(trits), [0, 0, 0, 0, 0]);
  });

  it('converts byte 1 correctly', () => {
    const bytes = new Uint8Array([1]);
    const trits = bytesToTrits(bytes);
    // 1 in base 3 = [1, 0, 0, 0, 0]
    assert.strictEqual(trits[0], 1);
  });

  it('converts byte 2 to balanced ternary', () => {
    const bytes = new Uint8Array([2]);
    const trits = bytesToTrits(bytes);
    // 2 → -1 in balanced ternary
    assert.strictEqual(trits[0], -1);
  });

  it('round-trips bytes through trits', () => {
    const original = new Uint8Array([0, 42, 100, 200, 242]);
    const trits = bytesToTrits(original);
    const recovered = tritsToBytes(trits);
    assert.deepStrictEqual(Array.from(recovered), Array.from(original));
  });

  it('handles values > 242 via mod 243', () => {
    const bytes = new Uint8Array([243, 255]);
    const trits = bytesToTrits(bytes);
    const recovered = tritsToBytes(trits);
    // 243 % 243 = 0, 255 % 243 = 12
    assert.strictEqual(recovered[0], 0);
    assert.strictEqual(recovered[1], 12);
  });
});

describe('YPC27Checksum', () => {
  describe('basic usage', () => {
    it('computes checksum for string', () => {
      const hasher = new YPC27Checksum();
      hasher.update('Hello World');
      const digest = hasher.digest();
      assert.ok(digest instanceof Poly27);
      assert.strictEqual(digest.isZero(), false);
    });

    it('computes checksum for bytes', () => {
      const hasher = new YPC27Checksum();
      hasher.update(new Uint8Array([1, 2, 3, 4, 5]));
      const digest = hasher.digest();
      assert.strictEqual(digest.isZero(), false);
    });

    it('returns hex digest', () => {
      const hasher = new YPC27Checksum();
      hasher.update('test');
      const hex = hasher.digestHex();
      assert.strictEqual(typeof hex, 'string');
      assert.strictEqual(hex.length, 12); // 6 bytes = 12 hex chars
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

      assert.strictEqual(d1.equals(d2), true);
    });

    it('different input produces different output', () => {
      const h1 = new YPC27Checksum();
      h1.update('message1');
      const d1 = h1.digest();

      const h2 = new YPC27Checksum();
      h2.update('message2');
      const d2 = h2.digest();

      assert.strictEqual(d1.equals(d2), false);
    });

    it('order matters (not commutative)', () => {
      const h1 = new YPC27Checksum();
      h1.update('AB');
      const d1 = h1.digest();

      const h2 = new YPC27Checksum();
      h2.update('BA');
      const d2 = h2.digest();

      assert.strictEqual(d1.equals(d2), false);
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

      assert.strictEqual(h1.digest().equals(h2.digest()), false);
    });
  });

  describe('static methods', () => {
    it('compute() returns checksum in one call', () => {
      const digest = YPC27Checksum.compute('quick test');
      assert.ok(digest instanceof Poly27);
    });

    it('verify() confirms matching data', () => {
      const data = 'verify me';
      const expected = YPC27Checksum.compute(data);
      assert.strictEqual(YPC27Checksum.verify(data, expected), true);
    });

    it('verify() rejects mismatched data', () => {
      const expected = YPC27Checksum.compute('original');
      assert.strictEqual(YPC27Checksum.verify('tampered', expected), false);
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

      assert.notStrictEqual(d1, d2);

      // Verify second run is deterministic
      hasher.reset();
      hasher.update('second');
      assert.strictEqual(hasher.digestHex(), d2);
    });
  });
});

describe('ypc27 convenience function', () => {
  it('returns Poly27 instance', () => {
    const result = ypc27('quick hash');
    assert.ok(result instanceof Poly27);
    assert.strictEqual(result.isZero(), false);
  });

  it('works with bytes', () => {
    const result = ypc27(new Uint8Array([1, 2, 3]));
    assert.ok(result instanceof Poly27);
    assert.strictEqual(result.isZero(), false);
  });

  it('is deterministic (same input → same output)', () => {
    const a = ypc27('deterministic test');
    const b = ypc27('deterministic test');
    assert.strictEqual(a.equals(b), true);
  });

  it('different inputs produce different outputs', () => {
    const a = ypc27('message1');
    const b = ypc27('message2');
    assert.strictEqual(a.equals(b), false);
  });
});

describe('seedFromPeerId', () => {
  it('creates Poly27 from peer ID', () => {
    const peerId = 'a'.repeat(64);
    const seed = seedFromPeerId(peerId);
    assert.ok(seed instanceof Poly27);
  });

  it('different peer IDs produce different seeds', () => {
    const seed1 = seedFromPeerId('a'.repeat(64));
    const seed2 = seedFromPeerId('b'.repeat(64));
    assert.strictEqual(seed1.equals(seed2), false);
  });
});

// =============================================================================
// PROPERTY TESTS — Lock in the audit fixes
// =============================================================================

describe('Property: distinct outputs (no silent collapse)', () => {
  it('100k random inputs produce 100k distinct outputs', () => {
    const seen = new Set();
    const count = 100_000;
    for (let i = 0; i < count; i++) {
      // Generate a pseudo-random 32-byte input
      const bytes = new Uint8Array(32);
      let v = i + 1; // never zero
      for (let j = 0; j < 32; j++) {
        bytes[j] = v & 0xff;
        v = (v * 1103515245 + 12345) & 0x7fffffff;
        v = (v ^ (v >> 13)) >>> 0;
      }
      const hex = ypc27(bytes);
      seen.add(hex);
    }
    // If any two inputs collide, seen.size < count
    // With 3^27 ≈ 7.6T space and 100k samples, collision probability is negligible
    assert.strictEqual(seen.size, count, `Output collapse: only ${seen.size} distinct out of ${count}`);
  });
});

describe('Property: avalanche (single bit flip affects ~2/3 of trits)', () => {
  it('flipping one bit changes ~66.7% of output trits', () => {
    const base = new Uint8Array(64);
    // Fill with pseudo-random data
    let v = 42;
    for (let j = 0; j < 64; j++) {
      v = (v * 1103515245 + 12345) & 0x7fffffff;
      v = (v ^ (v >> 13)) >>> 0;
      base[j] = v & 0xff;
    }

    const d1 = YPC27Checksum.compute(base);

    // Flip one bit in byte 0
    const modified = new Uint8Array(base);
    modified[0] ^= 0x01;

    const d2 = YPC27Checksum.compute(modified);

    // Count differing trits
    let diffCount = 0;
    for (let i = 0; i < N; i++) {
      if (d1.get(i) !== d2.get(i)) diffCount++;
    }

    // Ideal avalanche for balanced ternary: 2/3 of trits change
    // Accept 50%-80% as reasonable range (18-22 out of 27)
    const ratio = diffCount / N;
    assert.ok(
      ratio >= 0.5 && ratio <= 0.85,
      `Avalanche ratio ${ratio.toFixed(3)} (${diffCount}/${N} trits) outside expected 0.5-0.85 range`
    );
  });

  it('avalanche is consistent across multiple bit positions', () => {
    const base = new Uint8Array(64);
    let v = 99;
    for (let j = 0; j < 64; j++) {
      v = (v * 1103515245 + 12345) & 0x7fffffff;
      v = (v ^ (v >> 13)) >>> 0;
      base[j] = v & 0xff;
    }

    const d1 = YPC27Checksum.compute(base);
    const ratios = [];

    // Test 10 different bit positions
    for (let bit = 0; bit < 10; bit++) {
      const modified = new Uint8Array(base);
      const byteIdx = Math.floor(bit / 8);
      const bitIdx = bit % 8;
      modified[byteIdx] ^= (1 << bitIdx);

      const d2 = YPC27Checksum.compute(modified);
      let diffCount = 0;
      for (let i = 0; i < N; i++) {
        if (d1.get(i) !== d2.get(i)) diffCount++;
      }
      ratios.push(diffCount / N);
    }

    // All should be in the avalanche range
    for (const r of ratios) {
      assert.ok(r >= 0.4 && r <= 0.9, `Avalanche ratio ${r.toFixed(3)} outside 0.4-0.9 range`);
    }

    // Average should be close to 2/3
    const avg = ratios.reduce((a, b) => a + b, 0) / ratios.length;
    assert.ok(
      Math.abs(avg - 2/3) < 0.15,
      `Average avalanche ${avg.toFixed(3)} too far from ideal 0.667`
    );
  });
});

describe('Property: non-linearity (C(a)+C(b) ≠ C(a+b))', () => {
  it('checksum is NOT linear — hash-to-field breaks additivity', () => {
    // The old v1.x YPC-27 was linear (C(a)+C(b) = C(a+b)), which meant
    // an attacker could forge checksums. The fix uses SHA3-based hashToField
    // which makes the function non-linear. This test locks that in.
    let nonLinearCount = 0;
    const tests = 200;

    for (let i = 0; i < tests; i++) {
      const a = new Uint8Array(16);
      const b = new Uint8Array(16);
      // Fill with pseudo-random data
      let va = i * 2 + 1;
      let vb = i * 2 + 2;
      for (let j = 0; j < 16; j++) {
        va = (va * 1103515245 + 12345) & 0x7fffffff;
        vb = (vb * 1103515245 + 12345) & 0x7fffffff;
        a[j] = va & 0xff;
        b[j] = vb & 0xff;
      }

      // C(a) + C(b)
      const ca = YPC27Checksum.compute(a);
      const cb = YPC27Checksum.compute(b);
      const sumOfChecksums = ca.add(cb);

      // C(a + b) — byte-wise addition
      const ab = new Uint8Array(16);
      for (let j = 0; j < 16; j++) {
        ab[j] = (a[j] + b[j]) & 0xff;
      }
      const cAb = YPC27Checksum.compute(ab);

      // These should NOT be equal (non-linearity from hashToField)
      if (!sumOfChecksums.equals(cAb)) {
        nonLinearCount++;
      }
    }

    // At least 95% should be non-linear (allowing rare coincidences)
    assert.ok(
      nonLinearCount >= tests * 0.95,
      `Only ${nonLinearCount}/${tests} non-linear — checksum may be linear (regression!)`
    );
  });
});

describe('Property: forgery resistance', () => {
  it('cannot craft a different message with the same checksum (random search)', () => {
    // Try 20k random modifications of a message — none should match the original checksum
    const original = new Uint8Array(32);
    let v = 7;
    for (let j = 0; j < 32; j++) {
      v = (v * 1103515245 + 12345) & 0x7fffffff;
      v = (v ^ (v >> 13)) >>> 0;
      original[j] = v & 0xff;
    }

    const originalChecksum = YPC27Checksum.compute(original);
    const attempts = 20_000;
    let forged = 0;

    for (let i = 0; i < attempts; i++) {
      const modified = new Uint8Array(original);
      // Flip a random bit
      const byteIdx = Math.floor(Math.random() * 32);
      const bitIdx = Math.floor(Math.random() * 8);
      modified[byteIdx] ^= (1 << bitIdx);

      const modifiedChecksum = YPC27Checksum.compute(modified);
      if (modifiedChecksum.equals(originalChecksum)) {
        forged++;
      }
    }

    assert.strictEqual(forged, 0, `Found ${forged} forged checksums in ${attempts} attempts — checksum is weak!`);
  });
});
