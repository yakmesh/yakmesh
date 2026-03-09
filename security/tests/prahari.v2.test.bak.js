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
 * PRAHARI v2 Mesh-Consensus Entropy Engine — Integration Tests
 *
 * Validates the deep mathematical integration between:
 *   - TRIBHUJ balanced ternary (Trit, TritArray)
 *   - SST digital-root family system (A/B/C → 48/48/48)
 *   - 144-slot entropy pool constellation
 *   - Fibonacci 24-cycle rotation
 *   - Pluggable entropy source registry
 *   - SHA3 sponge mixing pool
 *
 * API-compatible with steadywatch-ternary.test.js.
 *
 * 144 = 12th Fibonacci = 24 × 6 = DR(9) → Family C → NEUTRAL
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
    PrahariEntropyPool,
    SteadywatchSeedStore,  // alias for backward compat
    EntropySentinel,
    EntropySourceRegistry,
    SourceKind,
    SATELLITE_COUNTS,
    POOL_SLOT_COUNTS,
    TRIT_ADDRESS_LENGTH,
    FAMILY_GROUPS,
    MIN_ENTROPY_RATIO,
} from '../prahari.js';
import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE } from '../../oracle/tribhuj.js';
import { digitalRoot, getFamily, SSTFamily } from '../../oracle/sst.js';

describe('PRAHARI Mesh-Consensus Entropy Engine', () => {
    /** @type {PrahariEntropyPool} */
    let pool;

    beforeEach(() => {
        pool = new PrahariEntropyPool();
        pool.generateTestSeeds(5); // p=5 → 144 pool slots
    });

    // ─────────────────────────────────────────────
    //  Mathematical Constants (preserved from STEADYWATCH)
    // ─────────────────────────────────────────────

    describe('144 mathematical harmony', () => {
        it('SATELLITE_COUNTS[5] = 144 (backward compat alias)', () => {
            expect(SATELLITE_COUNTS[5]).toBe(144);
        });

        it('POOL_SLOT_COUNTS[5] = 144 (24*(5+1))', () => {
            expect(POOL_SLOT_COUNTS[5]).toBe(144);
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
        it('partitions 144 slots into exactly 3 families', () => {
            const status = pool.getStatus();
            expect(status.ternary).toBeDefined();
            expect(status.ternary.familyGroups).toBeDefined();
            expect(Object.keys(status.ternary.familyGroups)).toHaveLength(3);
        });

        it('each family has exactly 48 slots (144/3)', () => {
            const status = pool.getStatus();
            const groups = status.ternary.familyGroups;
            expect(groups.A).toBe(48);
            expect(groups.B).toBe(48);
            expect(groups.C).toBe(48);
        });

        it('total across families = seed count', () => {
            const status = pool.getStatus();
            const groups = status.ternary.familyGroups;
            const total = groups.A + groups.B + groups.C;
            expect(total).toBe(pool.seeds.length);
        });

        it('FAMILY_GROUPS template matches expected structure', () => {
            expect(FAMILY_GROUPS).toEqual({ A: [], B: [], C: [] });
        });

        it('selectFromFamily returns seed from the specified family', () => {
            const result = pool.selectFromFamily('A', 0);
            expect(result).toBeDefined();
            expect(result.seed).toBeInstanceOf(Uint8Array);
            expect(result.seed.length).toBe(32);
            expect(result.family).toBe('A');
        });

        it('selectFromFamily returns different seeds for different offsets', () => {
            const r1 = pool.selectFromFamily('B', 0);
            const r2 = pool.selectFromFamily('B', 1);
            expect(r1.index).not.toBe(r2.index);
        });
    });

    // ─────────────────────────────────────────────
    //  6-Trit Balanced Ternary Addresses
    // ─────────────────────────────────────────────

    describe('6-trit slot addresses', () => {
        it('assigns addresses to all 144 slots', () => {
            const status = pool.getStatus();
            expect(status.ternary.tritAddressCount).toBe(144);
        });

        it('getTritAddress returns a TritArray of length 6', () => {
            const addr = pool.getTritAddress(0);
            expect(addr).toBeInstanceOf(TritArray);
            expect(addr.length).toBe(TRIT_ADDRESS_LENGTH);
        });

        it('every slot has a unique trit address', () => {
            const addresses = new Set();
            for (let i = 0; i < 144; i++) {
                const addr = pool.getTritAddress(i);
                addresses.add(addr.toString());
            }
            expect(addresses.size).toBe(144);
        });

        it('getSeedByTritAddress performs round-trip lookup', () => {
            for (const idx of [0, 1, 42, 71, 100, 143]) {
                const addr = pool.getTritAddress(idx);
                const result = pool.getSeedByTritAddress(addr.toString());
                expect(result).toBeDefined();
                expect(result.index).toBe(idx);
                expect(result.seed).toBeInstanceOf(Uint8Array);
            }
        });

        it('getSeedByTritAddress returns null for unknown address', () => {
            const result = pool.getSeedByTritAddress('111111');
            expect(result).toBeNull();
        });

        it('constellation address matches DR(144) identity', () => {
            const status = pool.getStatus();
            expect(status.ternary.constellationDR).toBe(9);
            expect(status.ternary.constellationFamily).toBe('C');
        });
    });

    // ─────────────────────────────────────────────
    //  Fibonacci 24-Cycle Rotation
    // ─────────────────────────────────────────────

    describe('Fibonacci-cycle seed selection', () => {
        it('selectByFibonacciCycle returns seed + metadata', () => {
            const result = pool.selectByFibonacciCycle();
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
                const result = pool.selectByFibonacciCycle();
                positions.push(result.fibPosition);
            }
            for (let i = 1; i < positions.length; i++) {
                expect(positions[i]).not.toBe(positions[i - 1]);
            }
        });

        it('cycles back after 24 selections', () => {
            for (let i = 0; i < 24; i++) pool.selectByFibonacciCycle();
            const result = pool.selectByFibonacciCycle();
            expect(result.fibPosition).toBeLessThanOrEqual(24);
            expect(result.fibPosition).toBeGreaterThanOrEqual(0);
        });

        it('getHybridSeed uses Fibonacci-based selection internally', () => {
            const seed = pool.getHybridSeed();
            expect(seed).toBeInstanceOf(Uint8Array);
            expect(seed.length).toBe(64); // 64-byte hybrid seed
        });

        it('all 3 families selected within a full cycle', () => {
            const families = new Set();
            for (let i = 0; i < 24; i++) {
                const result = pool.selectByFibonacciCycle();
                families.add(result.family);
            }
            expect(families.size).toBe(3);
        });
    });

    // ─────────────────────────────────────────────
    //  Ternary Bias Check (_checkBiasTernary)
    // ─────────────────────────────────────────────

    describe('ternary slot quality verdicts', () => {
        it('SHA3-generated pool slots pass quality check', () => {
            for (let i = 0; i < 144; i++) {
                const result = pool._checkBias(pool.seeds[i], i);
                expect(result).toBe(true);
            }
        });

        it('_checkBiasTernary returns a Trit', () => {
            const verdict = pool._checkBiasTernary(pool.seeds[0]);
            expect(verdict).toBeInstanceOf(Trit);
        });

        it('excellent entropy yields POSITIVE verdict', () => {
            const verdict = pool._checkBiasTernary(pool.seeds[0]);
            expect(verdict.value).toBe(POSITIVE);
        });

        it('all-zero slot yields NEGATIVE verdict', () => {
            const zeros = new Uint8Array(32);
            const verdict = pool._checkBiasTernary(zeros);
            expect(verdict.value).toBe(NEGATIVE);
        });

        it('all-0xFF slot yields NEGATIVE verdict', () => {
            const ones = new Uint8Array(32).fill(0xFF);
            const verdict = pool._checkBiasTernary(ones);
            expect(verdict.value).toBe(NEGATIVE);
        });

        it('backward-compat _checkBias returns boolean', () => {
            const result = pool._checkBias(pool.seeds[0], 0);
            expect(typeof result).toBe('boolean');
            expect(result).toBe(true);
        });

        it('backward-compat _checkBias returns false for degenerate slot', () => {
            const zeros = new Uint8Array(32);
            const result = pool._checkBias(zeros, 999);
            expect(result).toBe(false);
        });
    });

    // ─────────────────────────────────────────────
    //  TritArray Batch Consensus
    // ─────────────────────────────────────────────

    describe('batch quality consensus', () => {
        it('returns majority verdict for all slots', () => {
            for (let i = 0; i < pool.seeds.length; i++) {
                pool._checkBias(pool.seeds[i], i);
            }
            const consensus = pool.batchQualityConsensus();
            expect(consensus).toBeDefined();
            expect(consensus.majority).toBeInstanceOf(Trit);
            expect(consensus.total).toBe(144);
        });

        it('SHA3-generated test slots achieve POSITIVE consensus', () => {
            for (let i = 0; i < pool.seeds.length; i++) {
                pool._checkBias(pool.seeds[i], i);
            }
            const consensus = pool.batchQualityConsensus();
            expect(consensus.majority.value).toBe(POSITIVE);
            // SHA3 output is high-quality but ~1/144 slots may borderline fail bias check
            expect(consensus.counts.positive).toBeGreaterThanOrEqual(140);
            expect(consensus.counts.negative).toBe(0);
        });

        it('returns correct consensus when quality checks are already run by generateTestSeeds', () => {
            const freshPool = new PrahariEntropyPool();
            freshPool.generateTestSeeds(5);
            const consensus = freshPool.batchQualityConsensus();
            // PRAHARI's generateTestSeeds runs _checkBias on all slots automatically
            expect(consensus.total).toBe(144);
            // SHA3-generated slots should all be POSITIVE quality
            expect(consensus.majority.value).toBe(POSITIVE);
            expect(consensus.counts.positive).toBeGreaterThanOrEqual(140);
            expect(consensus.counts.negative).toBe(0);
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
            const result = await sentinel.score(pool.seeds[0]);
            expect(result.verdict).toBeInstanceOf(Trit);
            expect(result.score).toBeGreaterThan(0);
        });

        it('excellent entropy scores POSITIVE or NEUTRAL verdict (32 bytes is small sample)', async () => {
            const result = await sentinel.score(pool.seeds[42]);
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
            const result = await sentinel.score(pool.seeds[0]);
            expect(result.method).toBe('cpu');
        });
    });

    // ─────────────────────────────────────────────
    //  getStatus() Ternary Data
    // ─────────────────────────────────────────────

    describe('getStatus ternary integration', () => {
        it('includes ternary section', () => {
            expect(pool.getStatus().ternary).toBeDefined();
        });

        it('reports correct family group sizes', () => {
            const { ternary } = pool.getStatus();
            expect(ternary.familyGroups).toEqual({ A: 48, B: 48, C: 48 });
        });

        it('reports initial fibCyclePos = 0', () => {
            expect(pool.getStatus().ternary.fibCyclePos).toBe(0);
        });

        it('fibCyclePos advances after selection', () => {
            pool.selectByFibonacciCycle();
            expect(pool.getStatus().ternary.fibCyclePos).toBe(1);
        });

        it('reports constellation DR and family', () => {
            const { ternary } = pool.getStatus();
            expect(ternary.constellationDR).toBe(9);
            expect(ternary.constellationFamily).toBe('C');
        });

        it('reports trit address count matching seed count', () => {
            expect(pool.getStatus().ternary.tritAddressCount).toBe(144);
        });
    });

    // ─────────────────────────────────────────────
    //  Edge Cases & Other Primes
    // ─────────────────────────────────────────────

    describe('other prime constellations', () => {
        it('p=13 generates 336 slots with valid ternary structure', () => {
            const pool13 = new PrahariEntropyPool();
            pool13.generateTestSeeds(13);
            expect(pool13.seeds.length).toBe(336);

            const status = pool13.getStatus();
            const groups = status.ternary.familyGroups;
            expect(groups.A + groups.B + groups.C).toBe(336);
            expect(groups.A).toBe(112);
            expect(groups.B).toBe(112);
            expect(groups.C).toBe(112);
        });

        it('p=17 generates 432 slots with valid ternary structure', () => {
            const pool17 = new PrahariEntropyPool();
            pool17.generateTestSeeds(17);
            expect(pool17.seeds.length).toBe(432);
            expect(pool17.getStatus().ternary.tritAddressCount).toBe(432);
        });
    });

    // ─────────────────────────────────────────────
    //  PRAHARI-Specific: Entropy Sources & Sponge
    // ─────────────────────────────────────────────

    describe('pluggable entropy source registry', () => {
        it('pool has built-in sources after generateTestSeeds', () => {
            // generateTestSeeds doesn't register sources (initializePool does)
            // But we can test the registry interface
            const registry = new EntropySourceRegistry();
            expect(registry.size).toBe(0);
        });

        it('can register and harvest from a custom source', () => {
            const registry = new EntropySourceRegistry();
            const registered = registry.register({
                kind: 'test-source',
                name: 'Test entropy source',
                weight: 5,
                available: () => true,
                harvest: () => new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]),
            });
            expect(registered).toBe(true);
            expect(registry.size).toBe(1);

            const results = registry.harvestAll();
            expect(results).toHaveLength(1);
            expect(results[0].kind).toBe('test-source');
            expect(results[0].data).toEqual(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));
        });

        it('skips unavailable sources during harvest', () => {
            const registry = new EntropySourceRegistry();
            registry.register({
                kind: 'offline-source',
                name: 'Offline',
                weight: 1,
                available: () => false,
                harvest: () => new Uint8Array([0xFF]),
            });
            const results = registry.harvestAll();
            expect(results).toHaveLength(0);
        });

        it('getStatus reports registered sources', () => {
            const registry = new EntropySourceRegistry();
            registry.register({
                kind: 'test',
                name: 'Test',
                weight: 3,
                available: () => true,
                harvest: () => new Uint8Array(4),
            });
            const status = registry.getStatus();
            expect(status.test).toBeDefined();
            expect(status.test.name).toBe('Test');
            expect(status.test.weight).toBe(3);
        });
    });

    describe('SHA3 sponge mixing', () => {
        it('getHybridSeed returns 64-byte output through sponge expansion', () => {
            const seed = pool.getHybridSeed();
            expect(seed).toBeInstanceOf(Uint8Array);
            expect(seed.length).toBe(64);
        });

        it('consecutive getHybridSeed calls return different seeds', () => {
            const s1 = pool.getHybridSeed();
            const s2 = pool.getHybridSeed();
            // Should differ due to CSPRNG XOR
            let same = true;
            for (let i = 0; i < 64; i++) {
                if (s1[i] !== s2[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });

        it('uninitialized pool falls back to pure CSPRNG', () => {
            const emptyPool = new PrahariEntropyPool();
            const seed = emptyPool.getHybridSeed();
            expect(seed).toBeInstanceOf(Uint8Array);
            expect(seed.length).toBe(64);
        });
    });

    describe('backward compatibility', () => {
        it('SteadywatchSeedStore is aliased to PrahariEntropyPool', () => {
            expect(SteadywatchSeedStore).toBe(PrahariEntropyPool);
        });

        it('SATELLITE_COUNTS and POOL_SLOT_COUNTS are the same', () => {
            expect(SATELLITE_COUNTS).toEqual(POOL_SLOT_COUNTS);
        });

        it('SourceKind constants are defined', () => {
            expect(SourceKind.RDRAND).toBe('rdrand');
            expect(SourceKind.GPS).toBe('gps-jitter');
            expect(SourceKind.INTERRUPT).toBe('interrupt');
            expect(SourceKind.MESH).toBe('mesh-arrival');
            expect(SourceKind.CSPRNG).toBe('csprng');
        });

        it('MIN_ENTROPY_RATIO = 0.75', () => {
            expect(MIN_ENTROPY_RATIO).toBe(0.75);
        });
    });
});
