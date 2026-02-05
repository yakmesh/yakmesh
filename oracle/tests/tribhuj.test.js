/**
 * TRIBHUJ Test Suite
 * Tests for balanced ternary mathematics module
 * 
 * @module oracle/tests/tribhuj.test
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

import {
  NEGATIVE, NEUTRAL, POSITIVE,
  TritState,
  Trit,
  TritArray,
  hexToTrits,
  hexCompare,
  calculatePathBalance,
} from '../tribhuj.js';

// =============================================================================
// Demo output for visual confirmation
// =============================================================================

console.log('🔺 TRIBHUJ - Balanced Ternary Mathematics for YAKMESH\n');
console.log('='.repeat(60));

// Basic trit demo
console.log('\n📐 Trit Values:');
console.log(`   NEGATIVE: ${NEGATIVE} (${TritState.INVALID}/${TritState.REJECT}/${TritState.DISTRUST})`);
console.log(`   NEUTRAL:  ${NEUTRAL} (${TritState.PENDING}/${TritState.ABSTAIN}/${TritState.UNVERIFIED})`);
console.log(`   POSITIVE: ${POSITIVE} (${TritState.VALID}/${TritState.ACCEPT}/${TritState.TRUST})`);

// Arithmetic demo
console.log('\n🧮 Trit Arithmetic:');
const t1 = new Trit(1);
const t2 = new Trit(-1);
console.log(`   ${t1} + ${t2} = ${t1.add(t2).result}`);
console.log(`   ${t1} × ${t2} = ${t1.multiply(t2)}`);
console.log(`   -${t1} = ${t1.negate()}`);
console.log(`   -${t2} = ${t2.negate()} (self-inverting!)`);

// Logic demo
console.log('\n🔀 Ternary Logic (Kleene 3-valued):');
console.log(`   TRUE AND UNKNOWN = ${new Trit(1).and(0).toName()}`);
console.log(`   TRUE OR UNKNOWN = ${new Trit(1).or(0).toName()}`);
console.log(`   NOT UNKNOWN = ${new Trit(0).not().toName()}`);

// Consensus demo
console.log('\n🗳️ Consensus Operation:');
console.log(`   ACCEPT ⊕ ACCEPT = ${new Trit(1).consensus(1).toName('consensus')}`);
console.log(`   ACCEPT ⊕ REJECT = ${new Trit(1).consensus(-1).toName('consensus')} (disagreement!)`);
console.log(`   REJECT ⊕ REJECT = ${new Trit(-1).consensus(-1).toName('consensus')}`);

// TritArray demo
console.log('\n📊 TritArray (multi-trit values):');
const decimal42 = new TritArray(42);
console.log(`   42 in balanced ternary: ${decimal42} (verify: ${decimal42.toDecimal()})`);
const negDecimal = new TritArray(-13);
console.log(`   -13 in balanced ternary: ${negDecimal} (verify: ${negDecimal.toDecimal()})`);

// Path balance demo
console.log('\n🔗 Path Balance (link quality):');
const path1 = [POSITIVE, POSITIVE, NEGATIVE, NEGATIVE]; // Two forward, two reverse
const balance1 = calculatePathBalance(path1);
console.log(`   Path [+1,+1,-1,-1]: balance=${balance1.balance}, balanced=${balance1.isBalanced}`);

const path2 = [POSITIVE, POSITIVE, POSITIVE]; // All forward
const balance2 = calculatePathBalance(path2);
console.log(`   Path [+1,+1,+1]: balance=${balance2.balance}, balanced=${balance2.isBalanced}`);

// NOTE: weightedConsensus was REMOVED - YAKMESH validation is deterministic
console.log('\n⚠️  weightedConsensus REMOVED - validation is deterministic, not democratic');
console.log('   See security/sakshi.js for proper consensus via checkMathematicalAgreement()');

console.log('\n' + '='.repeat(60));
console.log('✅ Running test suite...\n');

// =============================================================================
// Actual Tests
// =============================================================================

describe('TRIBHUJ - Balanced Ternary Mathematics', () => {
  
  describe('Constants', () => {
    it('should define correct trit values', () => {
      assert.strictEqual(NEGATIVE, -1);
      assert.strictEqual(NEUTRAL, 0);
      assert.strictEqual(POSITIVE, 1);
    });

    it('should define semantic aliases', () => {
      assert.strictEqual(TritState.FALSE, NEGATIVE);
      assert.strictEqual(TritState.UNKNOWN, NEUTRAL);
      assert.strictEqual(TritState.TRUE, POSITIVE);
      assert.strictEqual(TritState.INVALID, NEGATIVE);
      assert.strictEqual(TritState.PENDING, NEUTRAL);
      assert.strictEqual(TritState.VALID, POSITIVE);
    });
  });

  describe('Trit Class', () => {
    
    describe('Construction', () => {
      it('should create from number', () => {
        assert.strictEqual(new Trit(-1).value, NEGATIVE);
        assert.strictEqual(new Trit(0).value, NEUTRAL);
        assert.strictEqual(new Trit(1).value, POSITIVE);
      });

      it('should clamp out-of-range values', () => {
        assert.strictEqual(new Trit(-5).value, NEGATIVE);
        assert.strictEqual(new Trit(0.3).value, NEUTRAL);
        assert.strictEqual(new Trit(99).value, POSITIVE);
      });

      it('should parse string characters', () => {
        assert.strictEqual(new Trit('T').value, NEGATIVE);
        assert.strictEqual(new Trit('0').value, NEUTRAL);
        assert.strictEqual(new Trit('1').value, POSITIVE);
        assert.strictEqual(new Trit('-').value, NEGATIVE);
        assert.strictEqual(new Trit('+').value, POSITIVE);
      });

      it('should copy from another Trit', () => {
        const t1 = new Trit(POSITIVE);
        const t2 = new Trit(t1);
        assert.strictEqual(t2.value, POSITIVE);
      });
    });

    describe('Properties', () => {
      it('should report isNegative correctly', () => {
        assert.strictEqual(new Trit(-1).isNegative, true);
        assert.strictEqual(new Trit(0).isNegative, false);
        assert.strictEqual(new Trit(1).isNegative, false);
      });

      it('should report isNeutral correctly', () => {
        assert.strictEqual(new Trit(-1).isNeutral, false);
        assert.strictEqual(new Trit(0).isNeutral, true);
        assert.strictEqual(new Trit(1).isNeutral, false);
      });

      it('should report isPositive correctly', () => {
        assert.strictEqual(new Trit(-1).isPositive, false);
        assert.strictEqual(new Trit(0).isPositive, false);
        assert.strictEqual(new Trit(1).isPositive, true);
      });
    });

    describe('Arithmetic', () => {
      it('should negate correctly (self-inverting)', () => {
        assert.strictEqual(new Trit(-1).negate().value, POSITIVE);
        assert.strictEqual(new Trit(0).negate().value, NEUTRAL);
        assert.strictEqual(new Trit(1).negate().value, NEGATIVE);
      });

      it('should add without carry', () => {
        const { result, carry } = new Trit(0).add(1);
        assert.strictEqual(result.value, POSITIVE);
        assert.strictEqual(carry.value, NEUTRAL);
      });

      it('should add with positive carry (1 + 1 = T in next place + carry)', () => {
        const { result, carry } = new Trit(1).add(1);
        assert.strictEqual(result.value, NEGATIVE); // 2 - 3 = -1
        assert.strictEqual(carry.value, POSITIVE);  // Carry 1
        // In balanced ternary: 1 + 1 = 1T (carry=1, result=-1), which is 3 - 1 = 2 ✓
      });

      it('should add with negative carry (-1 + -1)', () => {
        const { result, carry } = new Trit(-1).add(-1);
        assert.strictEqual(result.value, POSITIVE); // -2 + 3 = 1
        assert.strictEqual(carry.value, NEGATIVE);  // Carry -1
      });

      it('should multiply correctly', () => {
        assert.strictEqual(new Trit(1).multiply(1).value, POSITIVE);
        assert.strictEqual(new Trit(1).multiply(-1).value, NEGATIVE);
        assert.strictEqual(new Trit(-1).multiply(-1).value, POSITIVE);
        assert.strictEqual(new Trit(0).multiply(1).value, NEUTRAL);
      });
    });

    describe('Logic Operations', () => {
      it('should AND correctly (minimum)', () => {
        assert.strictEqual(new Trit(1).and(1).value, POSITIVE);
        assert.strictEqual(new Trit(1).and(0).value, NEUTRAL);
        assert.strictEqual(new Trit(1).and(-1).value, NEGATIVE);
        assert.strictEqual(new Trit(0).and(-1).value, NEGATIVE);
      });

      it('should OR correctly (maximum)', () => {
        assert.strictEqual(new Trit(-1).or(-1).value, NEGATIVE);
        assert.strictEqual(new Trit(-1).or(0).value, NEUTRAL);
        assert.strictEqual(new Trit(-1).or(1).value, POSITIVE);
        assert.strictEqual(new Trit(0).or(1).value, POSITIVE);
      });

      it('should compute consensus correctly', () => {
        // Agreement
        assert.strictEqual(new Trit(1).consensus(1).value, POSITIVE);
        assert.strictEqual(new Trit(-1).consensus(-1).value, NEGATIVE);
        assert.strictEqual(new Trit(0).consensus(0).value, NEUTRAL);
        // Disagreement
        assert.strictEqual(new Trit(1).consensus(-1).value, NEUTRAL);
        assert.strictEqual(new Trit(1).consensus(0).value, NEUTRAL);
      });
    });

    describe('Comparison', () => {
      it('should compare correctly', () => {
        assert.strictEqual(new Trit(-1).compare(1).value, NEGATIVE);
        assert.strictEqual(new Trit(1).compare(-1).value, POSITIVE);
        assert.strictEqual(new Trit(0).compare(0).value, NEUTRAL);
      });

      it('should check equality', () => {
        assert.strictEqual(new Trit(1).equals(1), true);
        assert.strictEqual(new Trit(1).equals(0), false);
      });
    });

    describe('Conversion', () => {
      it('should convert to character', () => {
        assert.strictEqual(new Trit(-1).toChar(), 'T');
        assert.strictEqual(new Trit(0).toChar(), '0');
        assert.strictEqual(new Trit(1).toChar(), '1');
      });

      it('should convert to semantic name', () => {
        assert.strictEqual(new Trit(-1).toName('validation'), 'INVALID');
        assert.strictEqual(new Trit(0).toName('consensus'), 'ABSTAIN');
        assert.strictEqual(new Trit(1).toName('trust'), 'TRUST');
      });
    });
  });

  describe('TritArray Class', () => {
    
    describe('Construction', () => {
      it('should create from decimal', () => {
        assert.strictEqual(new TritArray(0).toDecimal(), 0);
        assert.strictEqual(new TritArray(1).toDecimal(), 1);
        assert.strictEqual(new TritArray(42).toDecimal(), 42);
        assert.strictEqual(new TritArray(-13).toDecimal(), -13);
      });

      it('should create from string', () => {
        assert.strictEqual(new TritArray('1T0').toDecimal(), 6); // 9 - 3 + 0 = 6
        assert.strictEqual(new TritArray('111').toDecimal(), 13); // 9 + 3 + 1 = 13
      });

      it('should pad to fixed length', () => {
        const arr = new TritArray(1, 5);
        assert.strictEqual(arr.length, 5);
        assert.strictEqual(arr.toString(), '00001');
      });
    });

    describe('Arithmetic', () => {
      it('should negate correctly', () => {
        const arr = new TritArray(42);
        assert.strictEqual(arr.negate().toDecimal(), -42);
      });

      it('should add correctly', () => {
        const a = new TritArray(10);
        const b = new TritArray(5);
        assert.strictEqual(a.add(b).toDecimal(), 15);
      });

      it('should handle negative addition', () => {
        const a = new TritArray(10);
        const b = new TritArray(-3);
        assert.strictEqual(a.add(b).toDecimal(), 7);
      });
    });

    describe('Aggregate Operations', () => {
      it('should sum trits', () => {
        const arr = new TritArray([1, 1, -1, -1, 0]);
        assert.strictEqual(arr.sum(), 0);
      });

      it('should detect balanced arrays', () => {
        assert.strictEqual(new TritArray([1, -1]).isBalanced(), true);
        assert.strictEqual(new TritArray([1, 1, -1]).isBalanced(), false);
      });

      it('should count trits', () => {
        const arr = new TritArray([1, 1, 0, -1, 0, 0]);
        const counts = arr.count();
        assert.strictEqual(counts.positive, 2);
        assert.strictEqual(counts.neutral, 3);
        assert.strictEqual(counts.negative, 1);
      });

      it('should find majority', () => {
        assert.strictEqual(new TritArray([1, 1, -1]).majority().value, POSITIVE);
        assert.strictEqual(new TritArray([-1, -1, 1]).majority().value, NEGATIVE);
        assert.strictEqual(new TritArray([1, 0, -1]).majority().value, NEUTRAL); // Tie
      });
    });
  });

  describe('Utility Functions', () => {
    
    describe('hexCompare', () => {
      it('should compare hex strings', () => {
        assert.strictEqual(hexCompare('abc', 'def').value, NEGATIVE);
        assert.strictEqual(hexCompare('fff', 'aaa').value, POSITIVE);
        assert.strictEqual(hexCompare('abc', 'abc').value, NEUTRAL);
      });
    });

    describe('calculatePathBalance', () => {
      it('should calculate balanced path', () => {
        const result = calculatePathBalance([1, -1, 1, -1]);
        assert.strictEqual(result.balance, 0);
        assert.strictEqual(result.isBalanced, true);
        assert.strictEqual(result.quality.value, POSITIVE);
      });

      it('should detect asymmetric path', () => {
        const result = calculatePathBalance([1, 1, 1]);
        assert.strictEqual(result.balance, 3);
        assert.strictEqual(result.isBalanced, false);
        assert.strictEqual(result.quality.value, NEGATIVE);
      });
    });

    // NOTE: weightedConsensus tests removed - function deprecated
    // YAKMESH validation is deterministic, not democratic
  });

});

console.log('\n✅ TRIBHUJ module ready for YAKMESH integration');
console.log('🔺 "The triangle stands stable on three points"\n');
