/**
 * SST - Synergy Sequence Theory Tests
 * 
 * Tests for the SST module based on Wesley Long's theory.
 * Uses Node.js test runner (node:test).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

import {
  digitalRoot,
  getFamily,
  getFamilyOf,
  toFamilyTrit,
  SSTFamily,
  FIBONACCI_CYCLE_24,
  fibonacciRoot,
  fibonacciFamily,
  generateSynergyMatrix,
  propagateTrust,
  TRUST_PROPAGATION,
  HexCoord,
  hexRing,
  hexDisk,
  hexDiskSize,
} from '../sst.js';
import { POSITIVE, NEUTRAL, NEGATIVE } from '../tribhuj.js';

// =============================================================================
// Demo output for visual confirmation
// =============================================================================

console.log('✨ SST - Synergy Sequence Theory Integration for YAKMESH\n');
console.log('='.repeat(60));

console.log('\n📊 SST Family Groups (Wesley Long):');
console.log('   Family A: 1, 4, 7 → NEGATIVE (Physical Descending)');
console.log('   Family B: 2, 5, 8 → POSITIVE (Physical Ascending)');
console.log('   Family C: 3, 6, 9 → NEUTRAL (Governing Singularity)');

console.log('\n🔢 Digital Root Examples:');
console.log(`   digitalRoot(27) = ${digitalRoot(27)} → Family ${getFamilyOf(27)}`);
console.log(`   digitalRoot(123) = ${digitalRoot(123)} → Family ${getFamilyOf(123)}`);
console.log(`   digitalRoot(999) = ${digitalRoot(999)} → Family ${getFamilyOf(999)}`);

console.log('\n📈 Fibonacci 24-Cycle:');
console.log(`   ${FIBONACCI_CYCLE_24.slice(0, 12).join(', ')}`);
console.log(`   ${FIBONACCI_CYCLE_24.slice(12).join(', ')}`);

console.log('\n🔺 SST-YAKMESH Key Constants:');
console.log(`   YPC-27 degree: 27 → root ${digitalRoot(27)} → Family ${getFamilyOf(27)}`);
console.log(`   Fib cycle: 24 → root ${digitalRoot(24)} → Family ${getFamilyOf(24)}`);
console.log(`   LCM(27,24): 216 → root ${digitalRoot(216)} → Family ${getFamilyOf(216)}`);

console.log('\n' + '='.repeat(60) + '\n');

// =============================================================================
// Tests
// =============================================================================

describe('SST Digital Root', () => {
  it('calculates digital roots correctly', () => {
    assert.strictEqual(digitalRoot(1), 1);
    assert.strictEqual(digitalRoot(9), 9);
    assert.strictEqual(digitalRoot(10), 1);  // 1+0
    assert.strictEqual(digitalRoot(27), 9);  // 2+7
    assert.strictEqual(digitalRoot(123), 6); // 1+2+3
    assert.strictEqual(digitalRoot(999), 9);
  });

  it('handles zero as 9 (SST convention)', () => {
    assert.strictEqual(digitalRoot(0), 9);
  });

  it('handles negative numbers', () => {
    assert.strictEqual(digitalRoot(-27), 9);
    assert.strictEqual(digitalRoot(-123), 6);
  });

  it('handles BigInt', () => {
    assert.strictEqual(digitalRoot(123456789012345678901234567890n), 9);
  });
});

describe('SST Family Classification', () => {
  it('classifies Family A (1,4,7) correctly', () => {
    assert.strictEqual(getFamily(1), SSTFamily.A);
    assert.strictEqual(getFamily(4), SSTFamily.A);
    assert.strictEqual(getFamily(7), SSTFamily.A);
  });

  it('classifies Family B (2,5,8) correctly', () => {
    assert.strictEqual(getFamily(2), SSTFamily.B);
    assert.strictEqual(getFamily(5), SSTFamily.B);
    assert.strictEqual(getFamily(8), SSTFamily.B);
  });

  it('classifies Family C (3,6,9) correctly', () => {
    assert.strictEqual(getFamily(3), SSTFamily.C);
    assert.strictEqual(getFamily(6), SSTFamily.C);
    assert.strictEqual(getFamily(9), SSTFamily.C);
  });

  it('maps numbers to families via digital root', () => {
    assert.strictEqual(getFamilyOf(10), SSTFamily.A); // 10 → 1 → A
    assert.strictEqual(getFamilyOf(11), SSTFamily.B); // 11 → 2 → B
    assert.strictEqual(getFamilyOf(12), SSTFamily.C); // 12 → 3 → C
    assert.strictEqual(getFamilyOf(27), SSTFamily.C); // 27 → 9 → C
  });
});

describe('SST to Trit Mapping', () => {
  it('maps Family A to NEGATIVE', () => {
    assert.strictEqual(toFamilyTrit(1).value, NEGATIVE);
    assert.strictEqual(toFamilyTrit(4).value, NEGATIVE);
    assert.strictEqual(toFamilyTrit(7).value, NEGATIVE);
    assert.strictEqual(toFamilyTrit(10).value, NEGATIVE); // 10 → 1
  });

  it('maps Family B to POSITIVE', () => {
    assert.strictEqual(toFamilyTrit(2).value, POSITIVE);
    assert.strictEqual(toFamilyTrit(5).value, POSITIVE);
    assert.strictEqual(toFamilyTrit(8).value, POSITIVE);
  });

  it('maps Family C to NEUTRAL', () => {
    assert.strictEqual(toFamilyTrit(3).value, NEUTRAL);
    assert.strictEqual(toFamilyTrit(6).value, NEUTRAL);
    assert.strictEqual(toFamilyTrit(9).value, NEUTRAL);
    assert.strictEqual(toFamilyTrit(27).value, NEUTRAL); // 27 → 9 → C
  });
});

describe('Fibonacci 24-Cycle', () => {
  it('has exactly 24 elements', () => {
    assert.strictEqual(FIBONACCI_CYCLE_24.length, 24);
  });

  it('starts correctly', () => {
    assert.strictEqual(FIBONACCI_CYCLE_24[0], 1);
    assert.strictEqual(FIBONACCI_CYCLE_24[1], 1);
    assert.strictEqual(FIBONACCI_CYCLE_24[2], 2);
    assert.strictEqual(FIBONACCI_CYCLE_24[3], 3);
    assert.strictEqual(FIBONACCI_CYCLE_24[4], 5);
  });

  it('has 9 at positions 11 and 23 (singularity markers)', () => {
    assert.strictEqual(FIBONACCI_CYCLE_24[11], 9);
    assert.strictEqual(FIBONACCI_CYCLE_24[23], 9);
  });

  it('correctly references cycle positions', () => {
    assert.strictEqual(fibonacciRoot(0), 1);
    assert.strictEqual(fibonacciRoot(24), 1); // Wraps
    assert.strictEqual(fibonacciRoot(48), 1); // Wraps again
    assert.strictEqual(fibonacciRoot(-1), 9); // Negative wraps to position 23
  });

  it('correctly maps to families', () => {
    assert.strictEqual(fibonacciFamily(0), SSTFamily.A);  // 1 → A
    assert.strictEqual(fibonacciFamily(4), SSTFamily.B);  // 5 → B
    assert.strictEqual(fibonacciFamily(11), SSTFamily.C); // 9 → C
  });
});

describe('Synergy Matrix', () => {
  it('generates 9 rows', () => {
    const matrix = generateSynergyMatrix(24);
    assert.strictEqual(matrix.length, 9);
  });

  it('starts each row with its seed', () => {
    const matrix = generateSynergyMatrix(24);
    for (let i = 0; i < 9; i++) {
      assert.strictEqual(matrix[i][0], i + 1);
      assert.strictEqual(matrix[i][1], i + 1);
    }
  });

  it('generates standard Fibonacci on row 1', () => {
    const matrix = generateSynergyMatrix(12);
    // Row 0 is seed 1: 1, 1, 2, 3, 5, 8, 4, 3, 7, 1, 8, 9
    assert.deepStrictEqual(matrix[0], [1, 1, 2, 3, 5, 8, 4, 3, 7, 1, 8, 9]);
  });

  it('all values are 1-9', () => {
    const matrix = generateSynergyMatrix(100);
    for (const row of matrix) {
      for (const val of row) {
        assert.ok(val >= 1 && val <= 9, `Value ${val} out of range`);
      }
    }
  });
});

describe('Trust Propagation', () => {
  it('returns full trust for direct connection', () => {
    assert.strictEqual(propagateTrust(1.0, 0), 1.0);
    assert.strictEqual(propagateTrust(0.8, 0), 0.8);
  });

  it('uses √3 ratio for one hop', () => {
    const result = propagateTrust(1.0, 1);
    const expected = TRUST_PROPAGATION.ONE_HOP;
    assert.ok(Math.abs(result - expected) < 0.00001, `Expected ${expected}, got ${result}`);
  });

  it('uses 1/3 ratio for two hops', () => {
    const result = propagateTrust(1.0, 2);
    const expected = TRUST_PROPAGATION.TWO_HOPS;
    assert.ok(Math.abs(result - expected) < 0.00001, `Expected ${expected}, got ${result}`);
  });

  it('decays geometrically beyond 3 hops', () => {
    const hop3 = propagateTrust(1.0, 3);
    const hop4 = propagateTrust(1.0, 4);
    const hop5 = propagateTrust(1.0, 5);
    assert.ok(hop4 < hop3, 'Hop 4 should be less than hop 3');
    assert.ok(hop5 < hop4, 'Hop 5 should be less than hop 4');
  });

  it('scales with base trust', () => {
    const result = propagateTrust(0.5, 1);
    const expected = 0.5 * TRUST_PROPAGATION.ONE_HOP;
    assert.ok(Math.abs(result - expected) < 0.00001, `Expected ${expected}, got ${result}`);
  });
});

describe('Hexagonal Geometry', () => {
  describe('HexCoord', () => {
    it('creates coordinates', () => {
      const hex = new HexCoord(3, 4);
      assert.strictEqual(hex.q, 3);
      assert.strictEqual(hex.r, 4);
      assert.strictEqual(hex.s, -7); // q + r + s = 0
    });

    it('calculates neighbors', () => {
      const hex = new HexCoord(0, 0);
      const neighbors = hex.neighbors();
      assert.strictEqual(neighbors.length, 6);
    });

    it('calculates distance', () => {
      const a = new HexCoord(0, 0);
      const b = new HexCoord(3, 0);
      assert.strictEqual(a.distanceTo(b), 3);
    });

    it('rounds fractional coordinates', () => {
      const hex = HexCoord.round(1.2, 0.9);
      assert.ok(Number.isInteger(hex.q), 'q should be integer');
      assert.ok(Number.isInteger(hex.r), 'r should be integer');
    });
  });

  describe('hexRing', () => {
    it('returns center for radius 0', () => {
      const center = new HexCoord(0, 0);
      const ring = hexRing(center, 0);
      assert.strictEqual(ring.length, 1);
      assert.ok(ring[0].equals(center), 'Should contain center');
    });

    it('returns 6 cells for radius 1', () => {
      const center = new HexCoord(0, 0);
      const ring = hexRing(center, 1);
      assert.strictEqual(ring.length, 6);
    });

    it('returns 12 cells for radius 2', () => {
      const center = new HexCoord(0, 0);
      const ring = hexRing(center, 2);
      assert.strictEqual(ring.length, 12);
    });

    it('returns 6*r cells for any radius r', () => {
      for (let r = 1; r <= 5; r++) {
        const ring = hexRing(new HexCoord(0, 0), r);
        assert.strictEqual(ring.length, 6 * r, `Ring ${r} should have ${6 * r} cells`);
      }
    });
  });

  describe('hexDisk', () => {
    it('returns 1 cell for radius 0', () => {
      const disk = hexDisk(new HexCoord(0, 0), 0);
      assert.strictEqual(disk.length, 1);
    });

    it('returns 7 cells for radius 1', () => {
      const disk = hexDisk(new HexCoord(0, 0), 1);
      assert.strictEqual(disk.length, 7);
    });

    it('matches hexDiskSize formula', () => {
      for (let r = 0; r <= 5; r++) {
        const disk = hexDisk(new HexCoord(0, 0), r);
        assert.strictEqual(disk.length, hexDiskSize(r), `Disk ${r} size mismatch`);
      }
    });
  });

  describe('hexDiskSize', () => {
    it('uses correct formula: 3*r*(r+1) + 1', () => {
      assert.strictEqual(hexDiskSize(0), 1);
      assert.strictEqual(hexDiskSize(1), 7);
      assert.strictEqual(hexDiskSize(2), 19);
      assert.strictEqual(hexDiskSize(3), 37);
    });
  });
});

describe('SST-YAKMESH Integration Points', () => {
  it('YPC-27: 27 has digital root 9 (Governing)', () => {
    assert.strictEqual(digitalRoot(27), 9);
    assert.strictEqual(getFamilyOf(27), SSTFamily.C);
  });

  it('Fibonacci cycle length 24 has root 6 (Governing)', () => {
    assert.strictEqual(digitalRoot(24), 6);
    assert.strictEqual(getFamilyOf(24), SSTFamily.C);
  });

  it('LCM(27,24) = 216 has root 9 (Governing)', () => {
    assert.strictEqual(digitalRoot(216), 9);
    assert.strictEqual(getFamilyOf(216), SSTFamily.C);
  });

  it('All key YAKMESH constants fall in Family C (Governing)', () => {
    const constants = [27, 24, 216, 3, 6, 9, 27 * 8];
    for (const c of constants) {
      assert.strictEqual(getFamilyOf(c), SSTFamily.C, `Constant ${c} should be Family C`);
    }
  });
});

console.log('\n✅ SST Tests Complete\n');

