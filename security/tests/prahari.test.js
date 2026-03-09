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
 * PRAHARI v3 — Pure Sponge Entropy Engine Tests
 *
 * Validates:
 *   - SHA3-256 sponge operations (_absorb, _squeeze)
 *   - Hybrid seed generation (squeeze ⊕ CSPRNG)
 *   - Pluggable entropy source registry
 *   - Reseed cycle mechanics
 *   - EntropySentinel ternary verdicts
 *   - Backward compatibility aliases
 *
 * 162T address space: 162 × log₂(3) ≈ 256.8 bits
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
    PrahariSpongeEngine,
    PrahariEntropyPool,    // backward compat alias
    SteadywatchSeedStore,  // backward compat alias
    EntropySentinel,
    EntropySourceRegistry,
    SourceKind,
    MIN_ENTROPY_RATIO,
} from '../prahari.js';
import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from '../../oracle/tribhuj.js';

describe('PRAHARI v3 — Pure Sponge Entropy Engine', () => {
    /** @type {PrahariSpongeEngine} */
    let engine;

    beforeEach(() => {
        engine = new PrahariSpongeEngine();
    });

    afterEach(() => {
        engine.stopReseed();
    });

    // ─────────────────────────────────────────────
    //  Constructor & Initial State
    // ─────────────────────────────────────────────

    describe('constructor', () => {
        it('creates uninitialized engine', () => {
            expect(engine.initialized).toBe(false);
        });

        it('has a 64-byte sponge state from construction', () => {
            expect(engine._spongeState).toBeInstanceOf(Uint8Array);
            expect(engine._spongeState.length).toBe(64);
        });

        it('starts with absorbCount = 0', () => {
            expect(engine._absorbCount).toBe(0);
        });

        it('has empty entropy source registry', () => {
            expect(engine.sources).toBeInstanceOf(EntropySourceRegistry);
            expect(engine.sources.size).toBe(0);
        });

        it('backward compat: seeds returns empty array', () => {
            expect(engine.seeds).toEqual([]);
        });

        it('backward compat: nodeAssignment returns -1', () => {
            expect(engine.nodeAssignment).toBe(-1);
        });
    });

    // ─────────────────────────────────────────────
    //  Sponge Operations
    // ─────────────────────────────────────────────

    describe('sponge _absorb', () => {
        it('advances absorbCount on each absorb', () => {
            const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
            engine._absorb(data);
            expect(engine._absorbCount).toBe(1);
            engine._absorb(data);
            expect(engine._absorbCount).toBe(2);
        });

        it('changes sponge state after absorb', () => {
            const stateBefore = new Uint8Array(engine._spongeState);
            engine._absorb(new Uint8Array([0x42]));
            let same = true;
            for (let i = 0; i < 64; i++) {
                if (engine._spongeState[i] !== stateBefore[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });

        it('maintains 64-byte state after absorb', () => {
            engine._absorb(new Uint8Array(256).fill(0xAA));
            expect(engine._spongeState.length).toBe(64);
        });

        it('different inputs produce different states', () => {
            const e1 = new PrahariSpongeEngine();
            const e2 = new PrahariSpongeEngine();
            // Force same initial state
            e2._spongeState = new Uint8Array(e1._spongeState);
            e2._absorbCount = e1._absorbCount;

            e1._absorb(new Uint8Array([0x01]));
            e2._absorb(new Uint8Array([0x02]));

            let same = true;
            for (let i = 0; i < 64; i++) {
                if (e1._spongeState[i] !== e2._spongeState[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });
    });

    describe('sponge _squeeze', () => {
        it('returns requested number of bytes', () => {
            const out32 = engine._squeeze(32, 'TEST');
            expect(out32.length).toBe(32);

            const out64 = engine._squeeze(64, 'TEST');
            expect(out64.length).toBe(64);

            const out128 = engine._squeeze(128, 'TEST');
            expect(out128.length).toBe(128);
        });

        it('same label produces same output (deterministic)', () => {
            const a = engine._squeeze(32, 'SAME');
            const b = engine._squeeze(32, 'SAME');
            let same = true;
            for (let i = 0; i < 32; i++) {
                if (a[i] !== b[i]) { same = false; break; }
            }
            expect(same).toBe(true);
        });

        it('different labels produce different output', () => {
            const a = engine._squeeze(32, 'LABEL-A');
            const b = engine._squeeze(32, 'LABEL-B');
            let same = true;
            for (let i = 0; i < 32; i++) {
                if (a[i] !== b[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });

        it('absorb changes subsequent squeeze output', () => {
            const before = engine._squeeze(32, 'CHECK');
            engine._absorb(new Uint8Array([0xFF]));
            const after = engine._squeeze(32, 'CHECK');

            let same = true;
            for (let i = 0; i < 32; i++) {
                if (before[i] !== after[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });

        it('does not mutate sponge state', () => {
            engine._absorb(new Uint8Array([0x42]));
            const stateBefore = new Uint8Array(engine._spongeState);
            engine._squeeze(64, 'TEST');
            let same = true;
            for (let i = 0; i < 64; i++) {
                if (engine._spongeState[i] !== stateBefore[i]) { same = false; break; }
            }
            expect(same).toBe(true);
        });
    });

    // ─────────────────────────────────────────────
    //  Initialization
    // ─────────────────────────────────────────────

    describe('initialize', () => {
        it('sets initialized to true', () => {
            engine.initialize();
            expect(engine.initialized).toBe(true);
        });

        it('registers built-in entropy sources', () => {
            engine.initialize();
            expect(engine.sources.size).toBeGreaterThanOrEqual(2);
        });

        it('advances absorb count during initialization', () => {
            engine.initialize();
            expect(engine._absorbCount).toBeGreaterThan(0);
        });

        it('returns true on success', () => {
            const result = engine.initialize();
            expect(result).toBe(true);
        });
    });

    // ─────────────────────────────────────────────
    //  Hybrid Seed Generation
    // ─────────────────────────────────────────────

    describe('getHybridSeed', () => {
        it('returns 64-byte seed', () => {
            engine.initialize();
            const seed = engine.getHybridSeed();
            expect(seed).toBeInstanceOf(Uint8Array);
            expect(seed.length).toBe(64);
        });

        it('consecutive calls return different seeds (CSPRNG XOR)', () => {
            engine.initialize();
            const s1 = engine.getHybridSeed();
            const s2 = engine.getHybridSeed();
            let same = true;
            for (let i = 0; i < 64; i++) {
                if (s1[i] !== s2[i]) { same = false; break; }
            }
            expect(same).toBe(false);
        });

        it('uninitialized engine falls back to pure CSPRNG', () => {
            const seed = engine.getHybridSeed();
            expect(seed).toBeInstanceOf(Uint8Array);
            expect(seed.length).toBe(64);
        });

        it('output has good byte diversity', () => {
            engine.initialize();
            const seed = engine.getHybridSeed();
            const unique = new Set(seed);
            // 64 random bytes should have decent diversity
            expect(unique.size).toBeGreaterThan(20);
        });
    });

    // ─────────────────────────────────────────────
    //  Reseed
    // ─────────────────────────────────────────────

    describe('reseed', () => {
        it('does nothing when not initialized', () => {
            const countBefore = engine._absorbCount;
            engine.reseed();
            expect(engine._absorbCount).toBe(countBefore);
        });

        it('advances absorb count when initialized', () => {
            engine.initialize();
            const countBefore = engine._absorbCount;
            engine.reseed();
            expect(engine._absorbCount).toBeGreaterThan(countBefore);
        });

        it('stopReseed clears timer', () => {
            engine.initialize();
            expect(engine._reseedTimer).not.toBeNull();
            engine.stopReseed();
            expect(engine._reseedTimer).toBeNull();
        });
    });

    // ─────────────────────────────────────────────
    //  getStatus
    // ─────────────────────────────────────────────

    describe('getStatus', () => {
        it('reports version 3', () => {
            const status = engine.getStatus();
            expect(status.version).toBe(3);
        });

        it('reports initialized state', () => {
            expect(engine.getStatus().initialized).toBe(false);
            engine.initialize();
            expect(engine.getStatus().initialized).toBe(true);
        });

        it('reports absorbCount', () => {
            engine.initialize();
            expect(engine.getStatus().absorbCount).toBeGreaterThan(0);
        });

        it('reports spongeHealthy when absorbCount > 0', () => {
            engine.initialize();
            expect(engine.getStatus().spongeHealthy).toBe(true);
        });

        it('includes telemetry', () => {
            engine.initialize();
            const status = engine.getStatus();
            expect(status.telemetry).toBeDefined();
        });

        it('includes source status', () => {
            engine.initialize();
            const status = engine.getStatus();
            expect(status.sources).toBeDefined();
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
            const data = new Uint8Array(64);
            crypto.getRandomValues?.(data) || data.fill(0x42);
            // Use randomBytes for node
            const { randomBytes } = await import('node:crypto');
            const testData = randomBytes(64);
            const result = await sentinel.score(testData);
            expect(result.verdict).toBeInstanceOf(Trit);
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
            const { randomBytes } = await import('node:crypto');
            const result = await sentinel.score(randomBytes(64));
            expect(result.method).toBe('cpu');
        });
    });

    // ─────────────────────────────────────────────
    //  Entropy Source Registry
    // ─────────────────────────────────────────────

    describe('pluggable entropy source registry', () => {
        it('starts empty', () => {
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

    // ─────────────────────────────────────────────
    //  Backward Compatibility
    // ─────────────────────────────────────────────

    describe('backward compatibility', () => {
        it('PrahariEntropyPool is aliased to PrahariSpongeEngine', () => {
            expect(PrahariEntropyPool).toBe(PrahariSpongeEngine);
        });

        it('SteadywatchSeedStore is aliased to PrahariSpongeEngine', () => {
            expect(SteadywatchSeedStore).toBe(PrahariSpongeEngine);
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
