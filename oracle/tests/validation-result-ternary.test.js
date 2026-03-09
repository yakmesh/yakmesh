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
 * Tests for Ternary ValidationResult (TATTVA retrofit)
 * 
 * Verifies that ValidationResult now uses 3-valued logic:
 *   VALID   (+1) = Definitively valid
 *   INVALID (-1) = Definitively invalid
 *   PENDING  (0) = Awaiting consensus
 * 
 * @module oracle/tests/validation-result-ternary.test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ValidationResult } from '../validation-oracle-hardened.js';
import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from '../tribhuj.js';

// =============================================================================
// Visual Demo
// =============================================================================

console.log('\n🔺 TATTVA Ternary Retrofit - ValidationResult');
console.log('─'.repeat(50));

const valid = ValidationResult.success({ hash: 'abc123' });
const invalid = ValidationResult.failure('SIGNATURE_INVALID');
const pending = ValidationResult.pending('AWAITING_CONSENSUS');

console.log('📊 Three States:');
console.log(`   ✓ SUCCESS: state=${valid.state.value}, isValid=${valid.isValid}`);
console.log(`   ✗ FAILURE: state=${invalid.state.value}, isInvalid=${invalid.isInvalid}`);
console.log(`   ◌ PENDING: state=${pending.state.value}, isPending=${pending.isPending}`);

console.log('\n🧮 Ternary Logic Operations:');
console.log(`   VALID ∧ PENDING = ${valid.and(pending).state.value} (${valid.and(pending).toString()})`);
console.log(`   VALID ∨ PENDING = ${valid.or(pending).state.value} (VALID if any valid)`);
console.log(`   VALID ⊕ INVALID = ${valid.consensus(invalid).state.value} (disagreement → PENDING)`);

console.log('\n🔙 Backwards Compatibility:');
console.log(`   valid.valid = ${valid.valid} (deprecated but works)`);
console.log(`   invalid.valid = ${invalid.valid} (false for INVALID)`);

console.log('\n📦 JSON Serialization:');
console.log(`   ${JSON.stringify(pending.toJSON()).slice(0, 80)}...`);

console.log('\n' + '─'.repeat(50) + '\n');

// =============================================================================
// Tests
// =============================================================================

describe('TATTVA Ternary ValidationResult', () => {

  describe('Static Constructors', () => {
    it('success() creates VALID state', () => {
      const result = ValidationResult.success({ data: 'test' });
      assert.equal(result.state.value, POSITIVE);
      assert.equal(result.isValid, true);
      assert.equal(result.isInvalid, false);
      assert.equal(result.isPending, false);
    });

    it('failure() creates INVALID state', () => {
      const result = ValidationResult.failure('TEST_ERROR');
      assert.equal(result.state.value, NEGATIVE);
      assert.equal(result.isValid, false);
      assert.equal(result.isInvalid, true);
      assert.equal(result.isPending, false);
      assert.equal(result.reason, 'TEST_ERROR');
    });

    it('pending() creates PENDING state', () => {
      const result = ValidationResult.pending('WAITING');
      assert.equal(result.state.value, NEUTRAL);
      assert.equal(result.isValid, false);
      assert.equal(result.isInvalid, false);
      assert.equal(result.isPending, true);
      assert.equal(result.reason, 'WAITING');
    });

    it('pending() has default reason', () => {
      const result = ValidationResult.pending();
      assert.equal(result.reason, 'AWAITING_CONSENSUS');
    });
  });

  describe('Backwards Compatibility', () => {
    it('valid getter returns true for success', () => {
      const result = ValidationResult.success();
      assert.equal(result.valid, true);
    });

    it('valid getter returns false for failure', () => {
      const result = ValidationResult.failure('ERR');
      assert.equal(result.valid, false);
    });

    it('valid getter returns false for pending', () => {
      const result = ValidationResult.pending();
      assert.equal(result.valid, false);
    });

    it('accepts boolean in constructor (true → VALID)', () => {
      const result = new ValidationResult(true);
      assert.equal(result.isValid, true);
    });

    it('accepts boolean in constructor (false → INVALID)', () => {
      const result = new ValidationResult(false);
      assert.equal(result.isInvalid, true);
    });
  });

  describe('Ternary Logic', () => {
    const valid = ValidationResult.success();
    const invalid = ValidationResult.failure('ERR');
    const pending = ValidationResult.pending();

    it('AND: VALID ∧ VALID = VALID', () => {
      assert.equal(valid.and(valid).isValid, true);
    });

    it('AND: VALID ∧ INVALID = INVALID', () => {
      assert.equal(valid.and(invalid).isInvalid, true);
    });

    it('AND: VALID ∧ PENDING = PENDING', () => {
      assert.equal(valid.and(pending).isPending, true);
    });

    it('AND: PENDING ∧ PENDING = PENDING', () => {
      assert.equal(pending.and(pending).isPending, true);
    });

    it('OR: VALID ∨ INVALID = VALID', () => {
      assert.equal(valid.or(invalid).isValid, true);
    });

    it('OR: INVALID ∨ INVALID = INVALID', () => {
      assert.equal(invalid.or(invalid).isInvalid, true);
    });

    it('OR: PENDING ∨ PENDING = PENDING', () => {
      assert.equal(pending.or(pending).isPending, true);
    });

    it('OR: INVALID ∨ PENDING = PENDING', () => {
      assert.equal(invalid.or(pending).isPending, true);
    });

    it('CONSENSUS: same states agree', () => {
      assert.equal(valid.consensus(valid).isValid, true);
      assert.equal(invalid.consensus(invalid).isInvalid, true);
    });

    it('CONSENSUS: different states → PENDING', () => {
      assert.equal(valid.consensus(invalid).isPending, true);
      assert.equal(valid.consensus(pending).isPending, true);
    });
  });

  describe('Serialization', () => {
    it('toJSON includes ternary state info', () => {
      const result = ValidationResult.pending('TEST');
      const json = result.toJSON();
      
      assert.equal(json.state, 0);
      assert.equal(json.isValid, false);
      assert.equal(json.isInvalid, false);
      assert.equal(json.isPending, true);
      assert.equal(json.valid, false); // Backwards compat
    });

    it('toString shows state name', () => {
      assert.ok(ValidationResult.success().toString().includes('VALID'));
      assert.ok(ValidationResult.failure('X').toString().includes('INVALID'));
      assert.ok(ValidationResult.pending().toString().includes('PENDING'));
    });
  });

  describe('Immutability', () => {
    it('instance is frozen', () => {
      const result = ValidationResult.success();
      assert.throws(() => {
        result.newProp = 'test';
      });
    });
  });
});

console.log('✅ TATTVA ternary retrofit tests complete!\n');
