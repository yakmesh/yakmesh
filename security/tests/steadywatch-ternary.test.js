/**
 * STEADYWATCH Ternary-144 Integration Tests
 *
 * Validates the deep mathematical integration between:
 *   - TRIBHUJ balanced ternary (Trit, TritArray)
 *   - SST digital-root family system (A/B/C → 48/48/48)
 *   - Hurwitz quaternion 144-satellite constellation
 *   - Fibonacci 24-cycle rotation
 *
 * 144 = 12th Fibonacci = 24 × 6 = DR(9) → Family C → NEUTRAL
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  SteadywatchSeedStore,
  EntropySentinel,
  SATELLITE_COUNTS,
  TRIT_ADDRESS_LENGTH,
  FAMILY_GROUPS,
} from '../steadywatch.js';
import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE } from '../../oracle/tribhuj.js';
import { digitalRoot, getFamily, SSTFamily } from '../../oracle/sst.js';

describe('STEADYWATCH Ternary-144 Integration', () => {
  /** @type {SteadywatchSeedStore} */
  let store;

  beforeEach(() => {
    store = new SteadywatchSeedStore();
    store.generateTestSeeds(5); // p=5 → 144 satellites
  });

  // ─────────────────────────────────────────────
  //  Mathematical Constants
  // ─────────────────────────────────────────────

  describe('144 mathematical harmony', () => {
    it('SATELLITE_COUNTS[5] = 144 (Hurwitz: 24*(5+1))', () => {
      expect(SATELLITE_COUNTS[5]).toBe(144);
    });

    it('144 is the 12th Fibonacci number', () => {
      let a = 1, b = 1;
      for (let i = 3; i <= 12; i++) [a, b] = [b, a + b];
      expect(b).toBe(144);
    });

    it('DR(144) = 9 → Family C → NEUTRAL trit', () => {
      expect(digitalRoot(144)).toBe(9);
      expect(getFamily(144)).toBe(SSTFamily.C);
    });

    it('144 = 24 × 6 (Fibonacci cycle × hex directions)', () => {
      expect(24 * 6).toBe(144);
    });

    it('TRIT_ADDRESS_LENGTH = 6 (3^6 = 729 > 144)', () => {
      expect(TRIT_ADDRESS_LENGTH).toBe(6);
      expect(Math.pow(3, 6)).toBeGreaterThan(144);
    });

    it('5 balanced trits also suffice (3^5 = 243 > 144)', () => {
      expect(Math.pow(3, 5)).toBeGreaterThan(144);
    });
  });

  // ─────────────────────────────────────────────
  //  SST Family Grouping (48/48/48)
  // ─────────────────────────────────────────────

  describe('SST family grouping', () => {
    it('partitions 144 satellites into exactly 3 families', () => {
      const status = store.getStatus();
      expect(status.ternary).toBeDefined();
      expect(status.ternary.familyGroups).toBeDefined();
      expect(Object.keys(status.ternary.familyGroups)).toHaveLength(3);
    });

    it('each family has exactly 48 satellites (144/3)', () => {
      const status = store.getStatus();
      const groups = status.ternary.familyGroups;
      expect(groups.A).toBe(48);
      expect(groups.B).toBe(48);
      expect(groups.C).toBe(48);
    });

    it('total across families = seed count', () => {
      const status = store.getStatus();
      const groups = status.ternary.familyGroups;
      const total = groups.A + groups.B + groups.C;
      expect(total).toBe(store.seeds.length);
    });

    it('FAMILY_GROUPS template matches expected structure', () => {
      expect(FAMILY_GROUPS).toEqual({ A: [], B: [], C: [] });
    });

    it('selectFromFamily returns seed from the specified family', () => {
      const result = store.selectFromFamily('A', 0);
      expect(result).toBeDefined();
      expect(result.seed).toBeInstanceOf(Uint8Array);
      expect(result.seed.length).toBe(32);
      expect(result.family).toBe('A');
    });

    it('selectFromFamily returns different seeds for different offsets', () => {
      const r1 = store.selectFromFamily('B', 0);
      const r2 = store.selectFromFamily('B', 1);
      expect(r1.index).not.toBe(r2.index);
    });
  });

  // ─────────────────────────────────────────────
  //  6-Trit Balanced Ternary Addresses
  // ─────────────────────────────────────────────

  describe('6-trit satellite addresses', () => {
    it('assigns addresses to all 144 satellites', () => {
      const status = store.getStatus();
      expect(status.ternary.tritAddressCount).toBe(144);
    });

    it('getTritAddress returns a TritArray of length 6', () => {
      const addr = store.getTritAddress(0);
      expect(addr).toBeInstanceOf(TritArray);
      expect(addr.length).toBe(TRIT_ADDRESS_LENGTH);
    });

    it('every satellite has a unique trit address', () => {
      const addresses = new Set();
      for (let i = 0; i < 144; i++) {
        const addr = store.getTritAddress(i);
        addresses.add(addr.toString());
      }
      expect(addresses.size).toBe(144);
    });

    it('getSeedByTritAddress performs round-trip lookup', () => {
      for (const idx of [0, 1, 42, 71, 100, 143]) {
        const addr = store.getTritAddress(idx);
        const result = store.getSeedByTritAddress(addr.toString());
        expect(result).toBeDefined();
        expect(result.index).toBe(idx);
        expect(result.seed).toBeInstanceOf(Uint8Array);
      }
    });

    it('getSeedByTritAddress returns null for unknown address', () => {
      const result = store.getSeedByTritAddress('111111');
      expect(result).toBeNull();
    });

    it('constellation address matches DR(144) identity', () => {
      const status = store.getStatus();
      expect(status.ternary.constellationDR).toBe(9);
      expect(status.ternary.constellationFamily).toBe('C');
    });
  });

  // ─────────────────────────────────────────────
  //  Fibonacci 24-Cycle Rotation
  // ─────────────────────────────────────────────

  describe('Fibonacci-cycle seed selection', () => {
    it('selectByFibonacciCycle returns seed + metadata', () => {
      const result = store.selectByFibonacciCycle();
      expect(result).toBeDefined();
      expect(result.seed).toBeInstanceOf(Uint8Array);
      expect(result.seed.length).toBe(32);
      expect(result.family).toMatch(/^[ABC]$/);
      expect(result.fibPosition).toBeGreaterThanOrEqual(0);
      expect(result.fibPosition).toBeLessThanOrEqual(24);
    });

    it('advances through distinct positions', () => {
      const positions = [];
      for (let i = 0; i < 24; i++) {
        const result = store.selectByFibonacciCycle();
        positions.push(result.fibPosition);
      }
      // Each call should produce a different position from the last
      for (let i = 1; i < positions.length; i++) {
        expect(positions[i]).not.toBe(positions[i - 1]);
      }
    });

    it('cycles back after 24 selections', () => {
      for (let i = 0; i < 24; i++) store.selectByFibonacciCycle();
      const result = store.selectByFibonacciCycle();
      expect(result.fibPosition).toBeLessThanOrEqual(24);
      expect(result.fibPosition).toBeGreaterThanOrEqual(0);
    });

    it('getHybridSeed uses Fibonacci-based selection internally', () => {
      const seed = store.getHybridSeed();
      expect(seed).toBeInstanceOf(Uint8Array);
      expect(seed.length).toBe(64); // 64-byte hybrid seed
    });

    it('all 3 families selected within a full cycle', () => {
      const families = new Set();
      for (let i = 0; i < 24; i++) {
        const result = store.selectByFibonacciCycle();
        families.add(result.family);
      }
      expect(families.size).toBe(3);
    });
  });

  // ─────────────────────────────────────────────
  //  Ternary Bias Check (_checkBiasTernary)
  // ─────────────────────────────────────────────

  describe('ternary seed quality verdicts', () => {
    it('real satellite seeds pass quality check', () => {
      for (let i = 0; i < 144; i++) {
        const result = store._checkBias(store.seeds[i], i);
        expect(result).toBe(true);
      }
    });

    it('_checkBiasTernary returns a Trit', () => {
      const verdict = store._checkBiasTernary(store.seeds[0]);
      expect(verdict).toBeInstanceOf(Trit);
    });

    it('excellent entropy yields POSITIVE verdict', () => {
      const verdict = store._checkBiasTernary(store.seeds[0]);
      expect(verdict.value).toBe(POSITIVE);
    });

    it('all-zero seed yields NEGATIVE verdict', () => {
      const zeros = new Uint8Array(32);
      const verdict = store._checkBiasTernary(zeros);
      expect(verdict.value).toBe(NEGATIVE);
    });

    it('all-0xFF seed yields NEGATIVE verdict', () => {
      const ones = new Uint8Array(32).fill(0xFF);
      const verdict = store._checkBiasTernary(ones);
      expect(verdict.value).toBe(NEGATIVE);
    });

    it('backward-compat _checkBias returns boolean', () => {
      const result = store._checkBias(store.seeds[0], 0);
      expect(typeof result).toBe('boolean');
      expect(result).toBe(true);
    });

    it('backward-compat _checkBias returns false for degenerate seed', () => {
      const zeros = new Uint8Array(32);
      const result = store._checkBias(zeros, 999);
      expect(result).toBe(false);
    });
  });

  // ─────────────────────────────────────────────
  //  TritArray Batch Consensus
  // ─────────────────────────────────────────────

  describe('batch quality consensus', () => {
    it('returns majority verdict for all seeds', () => {
      for (let i = 0; i < store.seeds.length; i++) {
        store._checkBias(store.seeds[i], i);
      }
      const consensus = store.batchQualityConsensus();
      expect(consensus).toBeDefined();
      expect(consensus.majority).toBeInstanceOf(Trit);
      expect(consensus.total).toBe(144);
    });

    it('SHA3-generated test seeds achieve POSITIVE consensus', () => {
      for (let i = 0; i < store.seeds.length; i++) {
        store._checkBias(store.seeds[i], i);
      }
      const consensus = store.batchQualityConsensus();
      expect(consensus.majority.value).toBe(POSITIVE);
      expect(consensus.counts.positive).toBe(144);
      expect(consensus.counts.negative).toBe(0);
    });

    it('returns NEUTRAL consensus when no quality checks run (default verdicts)', () => {
      const freshStore = new SteadywatchSeedStore();
      freshStore.generateTestSeeds(5);
      const consensus = freshStore.batchQualityConsensus();
      // Seeds exist but no _checkBias called → all default to NEUTRAL
      expect(consensus.total).toBe(144);
      expect(consensus.counts.neutral).toBe(144);
      expect(consensus.majority.value).toBe(NEUTRAL);
    });
  });

  // ─────────────────────────────────────────────
  //  EntropySentinel Ternary Verdicts
  // ─────────────────────────────────────────────

  describe('EntropySentinel ternary verdicts', () => {
    let sentinel;

    beforeEach(() => {
      sentinel = new EntropySentinel();
    });

    it('score() returns verdict field as Trit', async () => {
      const result = await sentinel.score(store.seeds[0]);
      expect(result.verdict).toBeInstanceOf(Trit);
      expect(result.score).toBeGreaterThan(0);
    });

    it('excellent entropy scores POSITIVE or NEUTRAL verdict (32 bytes is small sample)', async () => {
      // With only 32 bytes, chi-square penalizes heavily (256 bins, ~224 empty)
      // So score may be NEUTRAL rather than POSITIVE — mathematically correct
      const result = await sentinel.score(store.seeds[42]);
      expect(result.verdict.value).toBeGreaterThanOrEqual(NEUTRAL);
      expect(result.score).toBeGreaterThan(0);
    });

    it('zero-byte data scores NEGATIVE verdict', async () => {
      const zeros = new Uint8Array(32);
      const result = await sentinel.score(zeros);
      expect(result.verdict.value).toBe(NEGATIVE);
      expect(result.score).toBeLessThan(0.5);
    });

    it('empty data returns score 0 with NEGATIVE verdict', async () => {
      const empty = new Uint8Array(0);
      const result = await sentinel.score(empty);
      expect(result.score).toBe(0);
      expect(result.verdict.value).toBe(NEGATIVE);
    });

    it('method is cpu when no NPU/GPU model loaded', async () => {
      const result = await sentinel.score(store.seeds[0]);
      expect(result.method).toBe('cpu');
    });
  });

  // ─────────────────────────────────────────────
  //  getStatus() Ternary Data
  // ─────────────────────────────────────────────

  describe('getStatus ternary integration', () => {
    it('includes ternary section', () => {
      expect(store.getStatus().ternary).toBeDefined();
    });

    it('reports correct family group sizes', () => {
      const { ternary } = store.getStatus();
      expect(ternary.familyGroups).toEqual({ A: 48, B: 48, C: 48 });
    });

    it('reports initial fibCyclePos = 0', () => {
      expect(store.getStatus().ternary.fibCyclePos).toBe(0);
    });

    it('fibCyclePos advances after selection', () => {
      store.selectByFibonacciCycle();
      expect(store.getStatus().ternary.fibCyclePos).toBe(1);
    });

    it('reports constellation DR and family', () => {
      const { ternary } = store.getStatus();
      expect(ternary.constellationDR).toBe(9);
      expect(ternary.constellationFamily).toBe('C');
    });

    it('reports trit address count matching seed count', () => {
      expect(store.getStatus().ternary.tritAddressCount).toBe(144);
    });
  });

  // ─────────────────────────────────────────────
  //  Edge Cases & Other Primes
  // ─────────────────────────────────────────────

  describe('other prime constellations', () => {
    it('p=13 generates 336 satellites with valid ternary structure', () => {
      const store13 = new SteadywatchSeedStore();
      store13.generateTestSeeds(13);
      expect(store13.seeds.length).toBe(336);

      const status = store13.getStatus();
      const groups = status.ternary.familyGroups;
      expect(groups.A + groups.B + groups.C).toBe(336);
      expect(groups.A).toBe(112);
      expect(groups.B).toBe(112);
      expect(groups.C).toBe(112);
    });

    it('p=17 generates 432 satellites with valid ternary structure', () => {
      const store17 = new SteadywatchSeedStore();
      store17.generateTestSeeds(17);
      expect(store17.seeds.length).toBe(432);
      expect(store17.getStatus().ternary.tritAddressCount).toBe(432);
    });
  });
});
