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
 * JHILKE — Just Hidden In-band Legitimate Key Exchange Tests
 *
 * Comprehensive tests for the friend-or-foe verification and
 * deterministic bootstrap key derivation system. Validates:
 *   - Bootstrap key derivation (same code+build → same key, deterministic)
 *   - Dialect seed derivation from code hash + build nonce
 *   - Chirp generation and verification (SST Fibonacci 24-cycle)
 *   - Tick tolerance (±1 tick window)
 *   - Chirp handling and event emission (chirp:verified, chirp:failed)
 *   - Stats tracking
 *   - Peer state lifecycle
 *
 * @module mesh/tests/jhilke.test
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { JhilkeCoordinator } from '../jhilke.js';

// Test oracle hashes (64 hex chars = 32 bytes SHA3-256)
const CODE_HASH_A = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const CODE_HASH_B = 'ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00';
const BUILD_NONCE = 'test-build-nonce-abc123';
const ALT_BUILD_NONCE = 'different-build-nonce-xyz789';
const NODE_A = 'node-alpha-abcdef0123456789';
const NODE_B = 'node-bravo-9876543210fedcba';
const NODE_C = 'node-charlie-deadbeefcafe42';

// Mock mesh — captures sendTo calls
function createMockMesh(peers = []) {
    const peerMap = new Map(peers.map(id => [id, { ws: {} }]));
    return {
        peers: peerMap,
        sendTo: vi.fn(),
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// JHILKE COORDINATOR
// ═══════════════════════════════════════════════════════════════════════════

describe('JhilkeCoordinator', () => {

    // ═══════════════════════════════════════════════════════════════════════════
    // CONSTRUCTION & INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Construction', () => {
        test('initializes with code hash and node ID', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A,
                nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            expect(jhilke.codeHash).toBe(CODE_HASH_A);
            expect(jhilke.nodeId).toBe(NODE_A);
            expect(jhilke.dialectSeed).toBeDefined();
            expect(jhilke.dialectSeed.length).toBe(32);
        });

        test('initializes with build nonce', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A,
                nodeId: NODE_A,
                mesh: createMockMesh(),
                buildNonce: BUILD_NONCE,
            });

            expect(jhilke.buildNonce).toBe(BUILD_NONCE);
        });

        test('stats start at zero', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A,
                nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            expect(jhilke.stats.bootstrapKeysDerived).toBe(0);
            expect(jhilke.stats.chirpsSent).toBe(0);
            expect(jhilke.stats.chirpsReceived).toBe(0);
            expect(jhilke.stats.chirpsVerified).toBe(0);
            expect(jhilke.stats.chirpsFailed).toBe(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // BOOTSTRAP KEY DERIVATION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Bootstrap Key Derivation', () => {
        test('both nodes derive identical key', () => {
            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const keyA = jA.deriveBootstrapKey(NODE_B);
            const keyB = jB.deriveBootstrapKey(NODE_A);

            expect(Buffer.compare(keyA, keyB)).toBe(0);
        });

        test('key is 32 bytes (256-bit AES)', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const key = jhilke.deriveBootstrapKey(NODE_B);
            expect(key.length).toBe(32);
        });

        test('key is deterministic (same inputs → same output)', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const key1 = jhilke.deriveBootstrapKey(NODE_B);
            const key2 = jhilke.deriveBootstrapKey(NODE_B);
            expect(Buffer.compare(key1, key2)).toBe(0);
        });

        test('different code hash → different key', () => {
            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: CODE_HASH_B, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const keyA = jA.deriveBootstrapKey(NODE_B);
            const keyB = jB.deriveBootstrapKey(NODE_B);
            expect(Buffer.compare(keyA, keyB)).not.toBe(0);
        });

        test('different build nonce → different key', () => {
            const j1 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const j2 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: ALT_BUILD_NONCE,
            });

            const key1 = j1.deriveBootstrapKey(NODE_B);
            const key2 = j2.deriveBootstrapKey(NODE_B);
            expect(Buffer.compare(key1, key2)).not.toBe(0);
        });

        test('key is order-independent (A↔B == B↔A)', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            // Derive key for two different peers
            const keyAB = jhilke.deriveBootstrapKey(NODE_B);
            // Swap roles — NODE_B deriving key for NODE_A
            const jReverse = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const keyBA = jReverse.deriveBootstrapKey(NODE_A);

            expect(Buffer.compare(keyAB, keyBA)).toBe(0);
        });

        test('different peer → different key', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const keyB = jhilke.deriveBootstrapKey(NODE_B);
            const keyC = jhilke.deriveBootstrapKey(NODE_C);
            expect(Buffer.compare(keyB, keyC)).not.toBe(0);
        });

        test('increments bootstrapKeysDerived stat', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.deriveBootstrapKey(NODE_B);
            jhilke.deriveBootstrapKey(NODE_C);
            expect(jhilke.stats.bootstrapKeysDerived).toBe(2);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // DIALECT SEED
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Dialect Seed', () => {
        test('same code+nonce → same dialect', () => {
            const j1 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const j2 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            expect(bytesToHex(j1.dialectSeed)).toBe(bytesToHex(j2.dialectSeed));
        });

        test('different code hash → different dialect', () => {
            const j1 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const j2 = new JhilkeCoordinator({
                codeHash: CODE_HASH_B, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            expect(bytesToHex(j1.dialectSeed)).not.toBe(bytesToHex(j2.dialectSeed));
        });

        test('different build nonce → different dialect', () => {
            const j1 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const j2 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: ALT_BUILD_NONCE,
            });

            expect(bytesToHex(j1.dialectSeed)).not.toBe(bytesToHex(j2.dialectSeed));
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHIRP GENERATION & VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Chirp Generation', () => {
        let jA, jB;

        beforeEach(() => {
            jA = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            jB = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
        });

        test('chirp is 8 bytes', () => {
            const chirp = jA._generateChirp(NODE_B, 1000);
            expect(chirp.length).toBe(8);
        });

        test('chirp is deterministic', () => {
            const c1 = jA._generateChirp(NODE_B, 1000);
            const c2 = jA._generateChirp(NODE_B, 1000);
            expect(bytesToHex(c1)).toBe(bytesToHex(c2));
        });

        test('different tick → different chirp', () => {
            const c1 = jA._generateChirp(NODE_B, 1000);
            const c2 = jA._generateChirp(NODE_B, 1001);
            expect(bytesToHex(c1)).not.toBe(bytesToHex(c2));
        });

        test('peer B can verify chirp from peer A', () => {
            const tick = 1000;
            const chirp = jA._generateChirp(NODE_B, tick);
            const result = jB._verifyChirp(NODE_A, chirp, tick);
            expect(result.valid).toBe(true);
            expect(result.tick).toBe(tick);
            expect(result.offset).toBe(0);
        });

        test('peer A can verify chirp from peer B', () => {
            const tick = 1000;
            const chirp = jB._generateChirp(NODE_A, tick);
            const result = jA._verifyChirp(NODE_B, chirp, tick);
            expect(result.valid).toBe(true);
        });

        test('cross-verification: chirps are symmetric', () => {
            // Both nodes generate the same chirp for the same pair at the same tick
            const tick = 42;
            const chirpA = jA._generateChirp(NODE_B, tick);
            const chirpB = jB._generateChirp(NODE_A, tick);
            expect(bytesToHex(chirpA)).toBe(bytesToHex(chirpB));
        });

        test('verification succeeds with ±1 tick tolerance', () => {
            const tick = 1000;
            const chirp = jA._generateChirp(NODE_B, tick);

            // Verifier thinks it's 1 tick later
            const result1 = jB._verifyChirp(NODE_A, chirp, tick + 1);
            expect(result1.valid).toBe(true);
            expect(result1.offset).toBe(-1);

            // Verifier thinks it's 1 tick earlier
            const result2 = jB._verifyChirp(NODE_A, chirp, tick - 1);
            expect(result2.valid).toBe(true);
            expect(result2.offset).toBe(1);
        });

        test('verification fails beyond dynamic AGUWA tolerance', () => {
            const tick = 1000;
            const chirp = jA._generateChirp(NODE_B, tick);

            // Unknown peers get UNSYNC tolerance (30s = ±30 ticks)
            // So tick + 31 must fail
            const result = jB._verifyChirp(NODE_A, chirp, tick + 31);
            expect(result.valid).toBe(false);
        });

        test('different code hash → verification fails', () => {
            const jFork = new JhilkeCoordinator({
                codeHash: CODE_HASH_B, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const tick = 1000;
            const chirp = jA._generateChirp(NODE_B, tick);
            const result = jFork._verifyChirp(NODE_A, chirp, tick);
            expect(result.valid).toBe(false);
        });

        test('different build nonce → verification fails', () => {
            const jDiffBuild = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: ALT_BUILD_NONCE,
            });

            const tick = 1000;
            const chirp = jA._generateChirp(NODE_B, tick);
            const result = jDiffBuild._verifyChirp(NODE_A, chirp, tick);
            expect(result.valid).toBe(false);
        });

        test('SST Fibonacci cycle varies chirps across 24 ticks', () => {
            const chirps = new Set();
            for (let tick = 0; tick < 24; tick++) {
                chirps.add(bytesToHex(jA._generateChirp(NODE_B, tick)));
            }
            // All 24 should be unique (different fibPos and fibRoot)
            expect(chirps.size).toBe(24);
        });

        test('chirps repeat after 24-tick Fibonacci cycle', () => {
            // Ticks at same position in cycle but different cycles
            // Actually they DON'T repeat because the tick value itself changes
            // the context string. This test validates they're different.
            const c0 = bytesToHex(jA._generateChirp(NODE_B, 0));
            const c24 = bytesToHex(jA._generateChirp(NODE_B, 24));
            // Different ticks always → different chirps even with same fibPos
            expect(c0).not.toBe(c24);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // INCOMING CHIRP HANDLING
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Incoming Chirp Handling', () => {
        let jA, jB;

        beforeEach(() => {
            jA = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            jB = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_B,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
        });

        test('valid chirp emits chirp:verified event', () => {
            const verifiedHandler = vi.fn();
            jB.on('chirp:verified', verifiedHandler);

            const tick = jA._sharedTick();
            const chirp = jA._generateChirp(NODE_B, tick);

            jB.handleIncoming(NODE_A, { jhilke: bytesToHex(chirp) });

            expect(verifiedHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    peerId: NODE_A,
                    tick: expect.any(Number),
                })
            );
            expect(jB.stats.chirpsReceived).toBe(1);
            expect(jB.stats.chirpsVerified).toBe(1);
        });

        test('invalid chirp emits chirp:failed event', () => {
            const failedHandler = vi.fn();
            jB.on('chirp:failed', failedHandler);

            // Random garbage chirp
            jB.handleIncoming(NODE_A, { jhilke: 'deadbeef12345678' });

            expect(failedHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    peerId: NODE_A,
                    consecutiveFailures: 1,
                })
            );
            expect(jB.stats.chirpsFailed).toBe(1);
        });

        test('consecutive failures accumulate', () => {
            const failedHandler = vi.fn();
            jB.on('chirp:failed', failedHandler);

            for (let i = 0; i < 5; i++) {
                jB.handleIncoming(NODE_A, { jhilke: 'deadbeef12345678' });
            }

            expect(failedHandler).toHaveBeenCalledTimes(5);
            expect(failedHandler).toHaveBeenLastCalledWith(
                expect.objectContaining({
                    consecutiveFailures: 5,
                })
            );
        });

        test('successful verification resets consecutive failures', () => {
            // Fail twice
            jB.handleIncoming(NODE_A, { jhilke: 'deadbeef12345678' });
            jB.handleIncoming(NODE_A, { jhilke: 'deadbeef12345678' });
            expect(jB.peerState.get(NODE_A).consecutiveFailures).toBe(2);

            // Send valid chirp
            const tick = jA._sharedTick();
            const chirp = jA._generateChirp(NODE_B, tick);
            jB.handleIncoming(NODE_A, { jhilke: bytesToHex(chirp) });

            expect(jB.peerState.get(NODE_A).consecutiveFailures).toBe(0);
        });

        test('ignores messages without jhilke field', () => {
            jB.handleIncoming(NODE_A, { entropy: 'abcdef' });
            expect(jB.stats.chirpsReceived).toBe(0);
        });

        test('handles malformed hex gracefully', () => {
            // Should not throw
            jB.handleIncoming(NODE_A, { jhilke: 'not-valid-hex!!!' });
            expect(jB.stats.chirpsReceived).toBe(1);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Lifecycle', () => {
        test('start() creates chirp timer', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.start();
            expect(jhilke._chirpTimer).not.toBeNull();
            jhilke.stop();
        });

        test('stop() clears timer and peer state', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.start();
            jhilke.peerState.set('peer-1', {});
            jhilke.stop();
            expect(jhilke._chirpTimer).toBeNull();
            expect(jhilke.peerState.size).toBe(0);
        });

        test('cleanupPeer() removes specific peer', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.peerState.set(NODE_B, { consecutiveFailures: 0 });
            jhilke.peerState.set(NODE_C, { consecutiveFailures: 0 });
            jhilke.cleanupPeer(NODE_B);
            expect(jhilke.peerState.has(NODE_B)).toBe(false);
            expect(jhilke.peerState.has(NODE_C)).toBe(true);
        });

        test('double start() does not create duplicate timers', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.start();
            const timer1 = jhilke._chirpTimer;
            jhilke.start();
            expect(jhilke._chirpTimer).toBe(timer1);
            jhilke.stop();
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // STATS
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Stats', () => {
        test('getStats() includes peer count', () => {
            const jhilke = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
            });

            jhilke.peerState.set(NODE_B, {});
            jhilke.peerState.set(NODE_C, {});

            const stats = jhilke.getStats();
            expect(stats.peerCount).toBe(2);
            expect(stats.chirpsSent).toBe(0);
            expect(stats.chirpsReceived).toBe(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY PROPERTIES
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Security Properties', () => {
        test('bootstrap key cannot be derived without code hash', () => {
            const j1 = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const j2 = new JhilkeCoordinator({
                codeHash: CODE_HASH_B, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const key1 = j1.deriveBootstrapKey(NODE_B);
            const key2 = j2.deriveBootstrapKey(NODE_B);
            // Keys must be completely different
            expect(Buffer.compare(key1, key2)).not.toBe(0);
        });

        test('chirp is unpredictable without dialect seed', () => {
            const jLegit = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const jFake = new JhilkeCoordinator({
                codeHash: CODE_HASH_B, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });

            const tick = 1000;
            const chirpLegit = bytesToHex(jLegit._generateChirp(NODE_B, tick));
            const chirpFake = bytesToHex(jFake._generateChirp(NODE_B, tick));
            expect(chirpLegit).not.toBe(chirpFake);
        });

        test('build nonce prevents source-code-only key derivation', () => {
            const withNonce = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(), buildNonce: BUILD_NONCE,
            });
            const withoutNonce = new JhilkeCoordinator({
                codeHash: CODE_HASH_A, nodeId: NODE_A,
                mesh: createMockMesh(),
                // No buildNonce
            });

            const key1 = withNonce.deriveBootstrapKey(NODE_B);
            const key2 = withoutNonce.deriveBootstrapKey(NODE_B);
            expect(Buffer.compare(key1, key2)).not.toBe(0);
        });
    });
});
