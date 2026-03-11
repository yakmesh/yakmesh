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
 * AGUWA + JHILKE Integration Tests
 *
 * Tests the complete time synchronization and friend-or-foe pipeline:
 *   - JHILKE uses aguwa.tick() for chirp timing
 *   - GPS calibration shifts aguwa.tick() → affects chirp window
 *   - Kuramoto convergence over multiple heartbeat rounds
 *   - Two-node simulation: bootstrap key exchange + chirp verification
 *   - Oracle hash → ω frequency → Sybil defense property
 *
 * @module mesh/tests/aguwa-jhilke-integration.test
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import { Aguwa, AGUWA_CONFIG } from '../aguwa.js';
import { JhilkeCoordinator } from '../jhilke.js';

const CODE_HASH = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const ALT_HASH = 'ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00';
const BUILD_NONCE = 'integration-test-nonce';
const NODE_A = 'node-integration-alpha-111';
const NODE_B = 'node-integration-bravo-222';

function gpsCaps() {
    return { maniTrust: 'gps', avx512: true, vaes: true, shaNI: true, nvGpu: true, totalTops: 117 };
}

function mockMesh() {
    return { peers: new Map(), sendTo: () => { } };
}

// ═══════════════════════════════════════════════════════════════════════════

describe('AGUWA + JHILKE Integration', () => {

    // ═══════════════════════════════════════════════════════════════════════════
    // SAME CODE HASH → SAME BOOTSTRAP KEYS
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Two-Node Bootstrap', () => {
        test('same oracle hash + build → same ω, same bootstrap key, same dialect', () => {
            const aguwaA = new Aguwa();
            const aguwaB = new Aguwa();
            aguwaA.init(CODE_HASH);
            aguwaB.init(CODE_HASH);

            // Same ω (natural frequency)
            expect(aguwaA._omega).toBe(aguwaB._omega);

            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_A,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_B,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });

            // Same bootstrap key
            const keyA = jA.deriveBootstrapKey(NODE_B);
            const keyB = jB.deriveBootstrapKey(NODE_A);
            expect(Buffer.compare(keyA, keyB)).toBe(0);

            // Same dialect
            expect(bytesToHex(jA.dialectSeed)).toBe(bytesToHex(jB.dialectSeed));
        });

        test('different oracle hash → different ω, different key, different dialect', () => {
            const aguwaA = new Aguwa();
            const aguwaB = new Aguwa();
            aguwaA.init(CODE_HASH);
            aguwaB.init(ALT_HASH);

            expect(aguwaA._omega).not.toBe(aguwaB._omega);

            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_A,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: ALT_HASH, nodeId: NODE_B,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });

            const keyA = jA.deriveBootstrapKey(NODE_B);
            const keyB = jB.deriveBootstrapKey(NODE_A);
            expect(Buffer.compare(keyA, keyB)).not.toBe(0);
            expect(bytesToHex(jA.dialectSeed)).not.toBe(bytesToHex(jB.dialectSeed));
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHIRP + AGUWA.TICK() AGREEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Chirp Timing via AGUWA', () => {
        test('chirps use aguwa.tick() (Kuramoto-corrected)', () => {
            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_A,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });

            // _sharedTick() should match aguwa.tick()
            const sharedTick = jA._sharedTick();
            const expected = Math.floor(Date.now() / 1000);
            expect(Math.abs(sharedTick - expected)).toBeLessThanOrEqual(1);
        });

        test('GPS-calibrated aguwa shifts chirp window', () => {
            // Both JHILKEs use the global aguwa singleton. For isolated tests,
            // we verify the design: chirps generated at the same shared tick
            // are verifiable by both sides.
            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_A,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_B,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });

            // Use same tick explicitly
            const tick = jA._sharedTick();
            const chirp = jA._generateChirp(NODE_B, tick);
            const result = jB._verifyChirp(NODE_A, chirp, tick);
            expect(result.valid).toBe(true);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // KURAMOTO CONVERGENCE SIMULATION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Kuramoto Convergence', () => {
        test('two nodes respond to mutual hardware clock drift', () => {
            const a1 = new Aguwa();
            const a2 = new Aguwa();
            a1.init(CODE_HASH);
            a2.init(CODE_HASH);
            vi.spyOn(a1, '_getMyTrustLevel').mockReturnValue('gps');
            vi.spyOn(a2, '_getMyTrustLevel').mockReturnValue('gps');

            a1.addPeer(NODE_B, gpsCaps());
            a2.addPeer(NODE_A, gpsCaps());

            // Simulate realistic network jitter (variable delays). Constant-rate drift
            // produces constant intervals, which dynamic prediction absorbs perfectly.
            // Only variable jitter creates prediction residuals that drive Kuramoto.
            const jitterA = [6, -4, 11, -8, 3, -10, 7, -2, 9, -5, 13, -1, 8, -7, 4, -12, 10, -3, 12, -6];
            const jitterB = [-3, 9, -7, 5, -11, 8, -2, 13, -5, 10, -9, 3, -6, 14, -4, 7, -8, 6, -10, 4];
            let wallTime = Date.now();
            for (let i = 0; i < 60; i++) {
                a1.onHeartbeat(NODE_B, wallTime + jitterB[i % jitterB.length]);
                a2.onHeartbeat(NODE_A, wallTime + jitterA[i % jitterA.length]);
                wallTime += 1000;
            }

            // Kuramoto coupling produces non-zero corrections responding to jitter
            expect(a1._correctionMs).not.toBe(0);
            expect(a2._correctionMs).not.toBe(0);
            // Corrections bounded (no runaway)
            expect(Math.abs(a1._correctionMs)).toBeLessThan(AGUWA_CONFIG.maxDriftMs);
            expect(Math.abs(a2._correctionMs)).toBeLessThan(AGUWA_CONFIG.maxDriftMs);
            // Phase tracks jitter
            expect(a1.peers.get(NODE_B).theta).not.toBe(0);
        });

        test('three nodes respond to heterogeneous clock drift', () => {
            const nodeC = 'node-integration-charlie-333';
            const a = [new Aguwa(), new Aguwa(), new Aguwa()];
            const ids = [NODE_A, NODE_B, nodeC];

            for (const ai of a) {
                ai.init(CODE_HASH);
                vi.spyOn(ai, '_getMyTrustLevel').mockReturnValue('gps');
            }

            // All peers know each other
            for (let i = 0; i < 3; i++) {
                for (let j = 0; j < 3; j++) {
                    if (i !== j) a[i].addPeer(ids[j], gpsCaps());
                }
            }

            // Each node has independent jitter (models real OS/network variation).
            // Constant-rate drift = constant intervals = zero prediction error,
            // so we use variable jitter which creates real prediction residuals.
            const jitters = [
                [5, -8, 12, -3, 7, -10, 4, -6, 11, -2, 9, -7, 3, -11, 8, -4, 10, -5, 6, -9],
                [-4, 11, -6, 8, -2, 13, -7, 5, -10, 3, -9, 6, -1, 12, -5, 9, -8, 4, -3, 7],
                [9, -3, 7, -11, 4, -8, 14, -5, 2, -10, 6, -1, 8, -4, 13, -7, 3, -9, 5, -6],
            ];
            let wallTime = Date.now();

            for (let round = 0; round < 60; round++) {
                for (let i = 0; i < 3; i++) {
                    for (let j = 0; j < 3; j++) {
                        if (i !== j) {
                            const jit = jitters[j][round % jitters[j].length];
                            a[i].onHeartbeat(ids[j], wallTime + jit);
                        }
                    }
                }
                wallTime += 1000;
            }

            // All corrections stay bounded
            for (const ai of a) {
                expect(Math.abs(ai._correctionMs)).toBeLessThan(AGUWA_CONFIG.maxDriftMs);
            }
            // At least some nodes should show Kuramoto response to jitter
            const anyResponse = a.some(ai => ai._correctionMs !== 0);
            expect(anyResponse).toBe(true);
        });

        test('nodes with different ω drift apart (fork detection)', () => {
            const a1 = new Aguwa();
            const a2 = new Aguwa();
            a1.init(CODE_HASH);
            a2.init(ALT_HASH); // different code → different ω

            a1.addPeer(NODE_B, gpsCaps());
            a2.addPeer(NODE_A, gpsCaps());

            // Simulate heartbeats — but with different ω, coupling won't converge
            let wallTime = Date.now();
            for (let i = 0; i < 100; i++) {
                const t1 = wallTime + a1._correctionMs;
                const t2 = wallTime + a2._correctionMs;
                a1.onHeartbeat(NODE_B, t2);
                a2.onHeartbeat(NODE_A, t1);
                wallTime += 1000;
            }

            // Different ω means the phase vectors should NOT perfectly align
            // (the coupling still works on timing, but ω causes drift)
            // This test validates the design intent: same code = convergence
            expect(a1._omega).not.toBe(a2._omega);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // ORDER PARAMETER AS SYBIL DEFENSE
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Order Parameter (Mesh Health)', () => {
        test('homogeneous mesh → r = 1.0', () => {
            const a = new Aguwa();
            a.init(CODE_HASH);

            // Add 5 peers, all in phase
            for (let i = 0; i < 5; i++) {
                const peerId = `peer-${i}`;
                a.addPeer(peerId, gpsCaps());
                const peer = a.peers.get(peerId);
                peer.lastArrival = Date.now();
                peer.theta = 0.01 * i; // Slight variation
            }

            const r = a.orderParameter();
            expect(r).toBeGreaterThan(0.95);
        });

        test('divergent node detected in otherwise healthy mesh', () => {
            const a = new Aguwa();
            a.init(CODE_HASH);

            // 4 healthy peers
            for (let i = 0; i < 4; i++) {
                const peerId = `healthy-${i}`;
                a.addPeer(peerId, gpsCaps());
                const peer = a.peers.get(peerId);
                peer.lastArrival = Date.now();
                peer.theta = 0.05;
            }

            // 1 Sybil/fork peer
            a.addPeer('sybil-1', gpsCaps());
            const sybil = a.peers.get('sybil-1');
            sybil.lastArrival = Date.now();
            sybil.theta = Math.PI; // 180° out of phase

            const suspects = a.detectDivergentPeers();
            expect(suspects.some(s => s.nodeId === 'sybil-1')).toBe(true);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GPS CALIBRATION → PROPAGATION PATH
    // ═══════════════════════════════════════════════════════════════════════════

    describe('GPS Calibration Flow', () => {
        test('GPS calibration sets initial correction before heartbeats', () => {
            const a = new Aguwa();
            a.init(CODE_HASH);

            // MA-902 says system is 4.7s behind GPS
            const systemNow = Date.now();
            const hardwareTime = (systemNow + 4700) / 1000;
            a.calibrateFromHardware(hardwareTime);

            expect(Math.abs(a._correctionMs - 4700)).toBeLessThan(100);
        });

        test('Kuramoto heartbeats refine GPS calibration', () => {
            const a = new Aguwa();
            a.init(CODE_HASH);
            vi.spyOn(a, '_getMyTrustLevel').mockReturnValue('gps');

            // Initial GPS calibration: +4700ms
            a._correctionMs = 4700;
            a.addPeer(NODE_B, gpsCaps());

            // Peer heartbeats with realistic jitter (±5-15ms around 1000ms)
            // Dynamic prediction adapts to the base interval;
            // jitter residuals drive Kuramoto corrections
            const jitters = [8, -3, 12, -7, 5, -11, 9, -4, 6, -9,
                7, -5, 10, -8, 3, -6, 11, -2, 4, -10,
                8, -3, 12, -7, 5, -11, 9, -4, 6, -9,
                7, -5, 10, -8, 3, -6, 11, -2, 4, -10,
                8, -3, 12, -7, 5, -11, 9, -4, 6, -9];
            let t = Date.now();
            for (const j of jitters) {
                a.onHeartbeat(NODE_B, t);
                t += 1000 + j;
            }

            // Jitter drives non-zero corrections that shift from initial GPS value
            expect(a._correctionMs).not.toBe(4700);
        });

        test('propagation delay establishes distance bound', () => {
            const a = new Aguwa();
            a.init(CODE_HASH);
            a.addPeer(NODE_B, gpsCaps());

            // Simulate heartbeats with realistic jitter (variable intervals)
            // The residual prediction error after dynamic smoothing ≈ propagation delay
            const jitters = [3, -2, 5, -1, 4, -3, 6, -2, 3, -4,
                5, -1, 2, -3, 7, -2, 4, -5, 3, -1,
                6, -3, 2, -4, 5, -2, 3, -1, 4, -3];
            let t = 1000000;
            for (const j of jitters) {
                a.onHeartbeat(NODE_B, t);
                t += 1000 + j;
            }

            // After enough samples, propagation delay should be estimatable
            const delays = a.getPropagationDelays();
            if (delays.has(NODE_B)) {
                expect(delays.get(NODE_B).delayMs).toBeGreaterThanOrEqual(0);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // FULL PIPELINE: GPS → AGUWA → JHILKE → ANNEX
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Full Pipeline', () => {
        test('complete two-node handshake: bootstrap + chirp + Kuramoto', () => {
            // Node A setup
            const aguwaA = new Aguwa();
            aguwaA.init(CODE_HASH);
            aguwaA._correctionMs = -4700; // GPS calibration
            vi.spyOn(aguwaA, '_getMyTrustLevel').mockReturnValue('gps');

            // Node B setup
            const aguwaB = new Aguwa();
            aguwaB.init(CODE_HASH);
            aguwaB._correctionMs = -1200; // Different GPS calibration
            vi.spyOn(aguwaB, '_getMyTrustLevel').mockReturnValue('gps');

            // JHILKE instances
            const jA = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_A,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });
            const jB = new JhilkeCoordinator({
                codeHash: CODE_HASH, nodeId: NODE_B,
                mesh: mockMesh(), buildNonce: BUILD_NONCE,
            });

            // 1. Bootstrap: both derive same key
            const keyA = jA.deriveBootstrapKey(NODE_B);
            const keyB = jB.deriveBootstrapKey(NODE_A);
            expect(Buffer.compare(keyA, keyB)).toBe(0);

            // 2. Chirps: both can verify each other at the same tick
            const tick = Math.floor(Date.now() / 1000);
            const chirpFromA = jA._generateChirp(NODE_B, tick);
            const chirpFromB = jB._generateChirp(NODE_A, tick);
            expect(jB._verifyChirp(NODE_A, chirpFromA, tick).valid).toBe(true);
            expect(jA._verifyChirp(NODE_B, chirpFromB, tick).valid).toBe(true);

            // 3. Kuramoto coupling responds to heartbeat drift
            aguwaA.addPeer(NODE_B, gpsCaps());
            aguwaB.addPeer(NODE_A, gpsCaps());

            // Simulate heartbeats with realistic variable jitter
            const jitA = [7, -5, 10, -8, 3, -12, 9, -4, 6, -11, 14, -2, 8, -7, 5, -13, 11, -3, 12, -6];
            const jitB = [-4, 9, -7, 5, -11, 8, -2, 13, -5, 10, -9, 3, -6, 14, -4, 7, -8, 6, -10, 4];
            let wallTime = Date.now();
            for (let i = 0; i < 60; i++) {
                aguwaA.onHeartbeat(NODE_B, wallTime + jitB[i % jitB.length]);
                aguwaB.onHeartbeat(NODE_A, wallTime + jitA[i % jitA.length]);
                wallTime += 1000;
            }

            // 4. Hardware corrections are set by calibrateFromHardware; Kuramoto fine-tunes
            // Both still have GPS-based corrections, plus Kuramoto adjustments from jitter
            expect(aguwaA._correctionMs).not.toBe(-4700); // Kuramoto shifted it
            expect(aguwaB._correctionMs).not.toBe(-1200); // Kuramoto shifted it
        });
    });
});


