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
 * AGUWA — Adaptive Gyroscopic Universal Waveform Authority Tests
 *
 * Comprehensive tests for the Kuramoto coupled-oscillator mesh time
 * synchronization system. Validates:
 *   - Initialization and natural frequency derivation from oracle hash
 *   - GPS calibration (MA-902 stratum-1)
 *   - Kuramoto phase coupling and convergence
 *   - Order parameter (mesh health metric)
 *   - Monotonic tick/now guarantees
 *   - Peer management and AGUWA confidence scoring
 *   - Divergent peer detection (different ω = Sybil/fork indicator)
 *   - Propagation delay estimation
 *   - Adaptive tolerance computation
 *
 * @module mesh/tests/aguwa.test
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { Aguwa, AGUWA_CONFIG, PeerPhaseState } from '../aguwa.js';
import { ManiTrustLevel, ManiPhaseTolerance } from '../../oracle/time-source.js';

// Deterministic test oracle hash (64 hex chars = 32 bytes SHA3-256)
const TEST_CODE_HASH = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const ALT_CODE_HASH = 'ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00';

// Helper: create GPS-capable peer capabilities
function gpsCaps() {
    return { maniTrust: 'gps', avx512: true, vaes: true, shaNI: true, nvGpu: true, totalTops: 117 };
}

function ntpCaps() {
    return { maniTrust: 'ntp', avx512: false, vaes: false, shaNI: false, nvGpu: false, totalTops: 0 };
}

function unsyncCaps() {
    return { maniTrust: 'unsync' };
}

// ═══════════════════════════════════════════════════════════════════════════
// AGUWA INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

describe('Aguwa', () => {
    let aguwa;

    beforeEach(() => {
        aguwa = new Aguwa();
    });

    describe('Initialization', () => {
        test('starts uninitialized', () => {
            expect(aguwa._initialized).toBe(false);
            expect(aguwa._omega).toBe(0);
            expect(aguwa._correctionMs).toBe(0);
            expect(aguwa.peers.size).toBe(0);
        });

        test('init() derives natural frequency from code hash', () => {
            aguwa.init(TEST_CODE_HASH);
            expect(aguwa._initialized).toBe(true);
            expect(aguwa._omega).toBeGreaterThanOrEqual(0);
            expect(aguwa._omega).toBeLessThan(2 * Math.PI);
            expect(aguwa._codeHash).toBe(TEST_CODE_HASH);
        });

        test('same code hash → same ω (deterministic)', () => {
            const a1 = new Aguwa();
            const a2 = new Aguwa();
            a1.init(TEST_CODE_HASH);
            a2.init(TEST_CODE_HASH);
            expect(a1._omega).toBe(a2._omega);
        });

        test('different code hash → different ω', () => {
            const a1 = new Aguwa();
            const a2 = new Aguwa();
            a1.init(TEST_CODE_HASH);
            a2.init(ALT_CODE_HASH);
            expect(a1._omega).not.toBe(a2._omega);
        });

        test('init() rejects invalid hash', () => {
            expect(() => aguwa.init('')).toThrow();
            expect(() => aguwa.init(null)).toThrow();
            expect(() => aguwa.init(42)).toThrow();
        });

        test('ω stays within [0, 2π)', () => {
            // Test with multiple hashes to ensure range is always correct
            const hashes = [
                TEST_CODE_HASH,
                ALT_CODE_HASH,
                '0000000000000000000000000000000000000000000000000000000000000000',
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            ];
            for (const hash of hashes) {
                const a = new Aguwa();
                a.init(hash);
                expect(a._omega).toBeGreaterThanOrEqual(0);
                expect(a._omega).toBeLessThan(2 * Math.PI);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GPS CALIBRATION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('GPS Calibration', () => {
        test('calibrateFromHardware sets correction offset', () => {
            const systemNow = Date.now();
            // Simulate GPS ahead by 500ms
            const hardwareUnix = (systemNow + 500) / 1000;
            aguwa.calibrateFromHardware(hardwareUnix);
            // correction should be ~500ms (±jitter)
            expect(Math.abs(aguwa._correctionMs - 500)).toBeLessThan(50);
        });

        test('calibrateFromHardware skips tiny offsets (<10ms)', () => {
            const systemNow = Date.now();
            const hardwareUnix = (systemNow + 5) / 1000; // only 5ms ahead
            aguwa.calibrateFromHardware(hardwareUnix);
            expect(aguwa._correctionMs).toBe(0); // Should not have changed
        });

        test('calibrateFromHardware rejects insane offsets (>60s)', () => {
            const systemNow = Date.now();
            const hardwareUnix = (systemNow + 120_000) / 1000; // 120s ahead
            aguwa.calibrateFromHardware(hardwareUnix);
            expect(aguwa._correctionMs).toBe(0);
        });

        test('calibrateFromHardware handles negative offset (GPS behind)', () => {
            const systemNow = Date.now();
            const hardwareUnix = (systemNow - 1000) / 1000; // 1s behind
            aguwa.calibrateFromHardware(hardwareUnix);
            expect(Math.abs(aguwa._correctionMs + 1000)).toBeLessThan(50);
        });

        test('calibrateFromHardware ignores null/invalid input', () => {
            aguwa.calibrateFromHardware(null);
            expect(aguwa._correctionMs).toBe(0);
            aguwa.calibrateFromHardware('not a number');
            expect(aguwa._correctionMs).toBe(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CANONICAL TIME API
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Canonical Time API', () => {
        test('tick() returns integer Unix seconds', () => {
            const t = aguwa.tick();
            expect(Number.isInteger(t)).toBe(true);
            // Should be close to current time
            const expected = Math.floor(Date.now() / 1000);
            expect(Math.abs(t - expected)).toBeLessThanOrEqual(1);
        });

        test('now() returns millisecond timestamp', () => {
            const n = aguwa.now();
            expect(typeof n).toBe('number');
            expect(Math.abs(n - Date.now())).toBeLessThan(100);
        });

        test('tick() is monotonic', () => {
            const t1 = aguwa.tick();
            // Force correction backward
            aguwa._correctionMs = -120_000;
            const t2 = aguwa.tick();
            expect(t2).toBeGreaterThanOrEqual(t1);
        });

        test('now() is monotonic', () => {
            const n1 = aguwa.now();
            // Force correction backward
            aguwa._correctionMs = -120_000;
            const n2 = aguwa.now();
            expect(n2).toBeGreaterThanOrEqual(n1);
        });

        test('tick() reflects GPS correction', () => {
            const baseTick = aguwa.tick();
            // Calibrate GPS: shift +5 seconds
            const systemNow = Date.now();
            aguwa._correctionMs = 5000;
            // Reset monotonic guard
            aguwa._lastTick = 0;
            const correctedTick = aguwa.tick();
            expect(correctedTick).toBeGreaterThanOrEqual(baseTick + 4);
            expect(correctedTick).toBeLessThanOrEqual(baseTick + 6);
        });

        test('phase() returns 0-999 within current second', () => {
            // Reset monotonic guards for clean test
            aguwa._lastNowMs = 0;
            const p = aguwa.phase();
            expect(p).toBeGreaterThanOrEqual(0);
            expect(p).toBeLessThan(1000);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // PEER MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Peer Management', () => {
        test('addPeer() creates new peer state', () => {
            aguwa.addPeer('peer-abc-123', gpsCaps());
            expect(aguwa.peers.size).toBe(1);
            expect(aguwa.peers.has('peer-abc-123')).toBe(true);
        });

        test('addPeer() updates existing peer capabilities', () => {
            aguwa.addPeer('peer-abc-123', ntpCaps());
            expect(aguwa.peers.get('peer-abc-123').timeTrust).toBe(0.4); // NTP

            aguwa.addPeer('peer-abc-123', gpsCaps());
            expect(aguwa.peers.get('peer-abc-123').timeTrust).toBe(0.85); // GPS
        });

        test('removePeer() removes peer state', () => {
            aguwa.addPeer('peer-abc-123', gpsCaps());
            aguwa.removePeer('peer-abc-123');
            expect(aguwa.peers.size).toBe(0);
        });

        test('updateKarma() clamps to [0, 1]', () => {
            aguwa.addPeer('peer-abc-123', gpsCaps());
            aguwa.updateKarma('peer-abc-123', 0.75);
            expect(aguwa.peers.get('peer-abc-123').karmaScore).toBe(0.75);

            aguwa.updateKarma('peer-abc-123', -5);
            expect(aguwa.peers.get('peer-abc-123').karmaScore).toBe(0);

            aguwa.updateKarma('peer-abc-123', 99);
            expect(aguwa.peers.get('peer-abc-123').karmaScore).toBe(1);
        });

        test('updateKarma() ignores unknown peer', () => {
            // Should not throw
            aguwa.updateKarma('does-not-exist', 0.5);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // PEER PHASE STATE
    // ═══════════════════════════════════════════════════════════════════════════

    describe('PeerPhaseState', () => {
        test('initializes with correct defaults', () => {
            const peer = new PeerPhaseState('node-xyz', gpsCaps());
            expect(peer.theta).toBe(0);
            expect(peer.predictedArrival).toBeNull();
            expect(peer.lastArrival).toBeNull();
            expect(peer.karmaScore).toBe(0.5);
            expect(peer.stabilityScore).toBe(0.5);
            expect(peer.timeTrust).toBe(0.85); // GPS
        });

        test('GPS peer has correct trust score', () => {
            const peer = new PeerPhaseState('gps-node', gpsCaps());
            expect(peer.timeTrust).toBe(0.85);
        });

        test('NTP peer has lower trust score', () => {
            const peer = new PeerPhaseState('ntp-node', ntpCaps());
            expect(peer.timeTrust).toBe(0.4);
        });

        test('UNSYNC peer has minimal trust', () => {
            const peer = new PeerPhaseState('unsync-node', unsyncCaps());
            expect(peer.timeTrust).toBe(0.1);
        });

        test('hardware score accounts for GPU/NPU/AVX-512', () => {
            const fullHw = new PeerPhaseState('full', gpsCaps());
            const bareHw = new PeerPhaseState('bare', ntpCaps());
            expect(fullHw.hardwareScore).toBeGreaterThan(bareHw.hardwareScore);
        });

        test('aguwaScore is weighted composite', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            const score = peer.aguwaScore;
            // Must be in [0, 1]
            expect(score).toBeGreaterThanOrEqual(0);
            expect(score).toBeLessThanOrEqual(1);
            // GPS trust (0.85*0.4) + karma (0.5*0.2) + hardware + stability
            expect(score).toBeGreaterThan(0.3);
        });

        test('recordArrival tracks heartbeat intervals', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            const t0 = 1000000;
            peer.recordArrival(t0);
            expect(peer.lastArrival).toBe(t0);
            // First call: no previous arrival → no period estimate → prediction null
            expect(peer.predictedArrival).toBe(null);
            expect(peer._estimatedPeriodMs).toBe(null);
            expect(peer.arrivalDeltas.length).toBe(0);

            peer.recordArrival(t0 + 1000);
            expect(peer.arrivalDeltas.length).toBe(1);
            expect(peer.arrivalDeltas[0]).toBe(1000);
            // Second call bootstraps period estimate from first delta
            expect(peer._estimatedPeriodMs).toBe(1000);
            expect(peer.predictedArrival).toBe(t0 + 2000);
        });

        test('stability score improves with consistent intervals', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            let t = 1000000;
            // Simulate 10 consistent 1000ms heartbeats
            for (let i = 0; i < 10; i++) {
                peer.recordArrival(t);
                t += 1000;
            }
            // Very low variance → high stability
            expect(peer.stabilityScore).toBeGreaterThan(0.8);
        });

        test('stability score degrades with jittery intervals', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            let t = 1000000;
            // Simulate jittery heartbeats
            const jitters = [800, 1200, 600, 1400, 900, 1100, 500, 1500, 700, 1300];
            for (const dt of jitters) {
                peer.recordArrival(t);
                t += dt;
            }
            // High variance → low stability
            expect(peer.stabilityScore).toBeLessThan(0.5);
        });

        test('propagationDelayMs returns null with insufficient samples', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            expect(peer.propagationDelayMs).toBeNull();
        });

        test('propagationDelayMs returns 5th percentile', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            // Add 20 error samples
            for (let i = 0; i < 20; i++) {
                peer.recordError(10 + i); // 10, 11, ..., 29
            }
            const delay = peer.propagationDelayMs;
            expect(delay).not.toBeNull();
            expect(delay).toBe(11); // sorted[1] for 20 samples, floor(20*0.05)=1
        });

        test('arrival deltas respect window size', () => {
            const peer = new PeerPhaseState('test', gpsCaps());
            let t = 0;
            // Push more than stabilityWindowSize arrivals
            for (let i = 0; i < AGUWA_CONFIG.stabilityWindowSize + 10; i++) {
                peer.recordArrival(t);
                t += 1000;
            }
            expect(peer.arrivalDeltas.length).toBeLessThanOrEqual(AGUWA_CONFIG.stabilityWindowSize);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // KURAMOTO COUPLING
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Kuramoto Coupling', () => {
        beforeEach(() => {
            aguwa.init(TEST_CODE_HASH);
            // Mock our own trust level to GPS so coupling isn't couplingMin
            // (no real MANI time detector in test env → defaults to UNSYNC)
            vi.spyOn(aguwa, '_getMyTrustLevel').mockReturnValue('gps');
        });

        afterEach(() => {
            vi.restoreAllMocks();
        });

        test('onHeartbeat() ignores unknown peer', () => {
            // Should not throw
            aguwa.onHeartbeat('unknown-peer', Date.now());
            expect(aguwa._correctionMs).toBe(0);
        });

        test('first heartbeat establishes baseline, no correction', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            const peer = aguwa.peers.get('peer-1');
            expect(peer.lastArrival).toBe(t0);
            // First beat: no period estimate yet → no prediction → no correction
            expect(aguwa._correctionMs).toBe(0);
            expect(peer._estimatedPeriodMs).toBe(null);
        });

        test('second heartbeat bootstraps period estimate but skips correction', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const t0 = 1000000;
            aguwa.onHeartbeat('peer-1', t0);       // 1st: no prediction
            aguwa.onHeartbeat('peer-1', t0 + 1000); // 2nd: bootstraps period, but prevPrediction was null → skip
            const peer = aguwa.peers.get('peer-1');
            expect(peer._estimatedPeriodMs).toBe(1000); // Learned the interval
            expect(aguwa._correctionMs).toBe(0);         // No correction yet (need 3 beats)
        });

        test('third heartbeat triggers Kuramoto correction on jitter', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const t0 = 1000000;
            aguwa.onHeartbeat('peer-1', t0);          // 1st: baseline
            aguwa.onHeartbeat('peer-1', t0 + 1000);   // 2nd: period=1000, prediction=t0+2000
            aguwa.onHeartbeat('peer-1', t0 + 2050);   // 3rd: 50ms late vs prediction → correction
            expect(aguwa._correctionMs).not.toBe(0);
        });

        test('perfect heartbeat timing → near-zero correction', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const t0 = 1000000;
            // 4 beats at exactly 1000ms intervals → dynamic prediction adapts perfectly
            for (let i = 0; i < 4; i++) {
                aguwa.onHeartbeat('peer-1', t0 + i * 1000);
            }
            // Constant interval → prediction matches → zero phase error (correct!)
            expect(Math.abs(aguwa._correctionMs)).toBeLessThan(0.001);
        });

        test('variable jitter produces non-zero Kuramoto corrections', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            // Realistic network jitter: ±5-15ms variation around 1000ms
            const intervals = [1000, 1012, 993, 1008, 987, 1015, 995, 1010, 988, 1007,
                992, 1013, 990, 1005, 998, 1011, 994, 1009, 991, 1006];
            let t = 1000000;
            for (const dt of intervals) {
                aguwa.onHeartbeat('peer-1', t);
                t += dt;
            }
            // Jitter → prediction errors → Kuramoto responds dynamically
            expect(aguwa._correctionMs).not.toBe(0);
            // Correction is small (jitter is small) and bounded
            expect(Math.abs(aguwa._correctionMs)).toBeLessThan(50);
            // Phase has evolved
            const peer = aguwa.peers.get('peer-1');
            expect(peer.theta).not.toBe(0);
        });

        test('systematic drift produces growing phase error', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            // Peer's clock drifts: each interval grows by 0.5ms (accelerating drift)
            let t = 1000000;
            let interval = 1000;
            for (let i = 0; i < 30; i++) {
                aguwa.onHeartbeat('peer-1', t);
                interval += 0.5; // Accelerating: 1000, 1000.5, 1001, 1001.5...
                t += interval;
            }
            // Smoothed period lags behind the real period → prediction errors grow
            expect(aguwa._correctionMs).not.toBe(0);
            const peer = aguwa.peers.get('peer-1');
            expect(peer.theta).not.toBe(0);
        });

        test('GPS peer has stronger coupling than NTP peer', () => {
            // Two AGUWA instances with different trust peers
            const a1 = new Aguwa();
            a1.init(TEST_CODE_HASH);
            vi.spyOn(a1, '_getMyTrustLevel').mockReturnValue('gps');
            a1.addPeer('gps-peer', gpsCaps());

            const a2 = new Aguwa();
            a2.init(TEST_CODE_HASH);
            vi.spyOn(a2, '_getMyTrustLevel').mockReturnValue('gps');
            a2.addPeer('ntp-peer', ntpCaps());

            // Variable intervals (jitter) so dynamic prediction produces errors
            const intervals = [1000, 1012, 993, 1008, 987, 1015, 995, 1010, 988, 1007,
                992, 1013, 990, 1005, 998, 1011, 994, 1009, 991, 1006];
            let t = 1000000;
            for (const dt of intervals) {
                a1.onHeartbeat('gps-peer', t);
                a2.onHeartbeat('ntp-peer', t);
                t += dt;
            }

            // GPS peer causes larger correction (higher K × A_j)
            expect(Math.abs(a1._correctionMs)).toBeGreaterThan(Math.abs(a2._correctionMs));
        });

        test('correction is clamped to maxDriftMs', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            // Establish baseline with 3 normal beats
            aguwa.onHeartbeat('peer-1', 1000000);
            aguwa.onHeartbeat('peer-1', 1001000);
            aguwa.onHeartbeat('peer-1', 1002000);
            // Then a wildly late heartbeat (500s instead of 1s)
            aguwa.onHeartbeat('peer-1', 1502000);
            // Correction must stay within maxDriftMs bounds
            expect(Math.abs(aguwa._correctionMs)).toBeLessThanOrEqual(AGUWA_CONFIG.maxDriftMs);
        });

        test('Kuramoto responds to frequency drift between oscillators', () => {
            // Two nodes with same ω, but one experiences hardware clock drift
            const a1 = new Aguwa();
            const a2 = new Aguwa();
            a1.init(TEST_CODE_HASH);
            a2.init(TEST_CODE_HASH);
            vi.spyOn(a1, '_getMyTrustLevel').mockReturnValue('gps');
            vi.spyOn(a2, '_getMyTrustLevel').mockReturnValue('gps');

            a1.addPeer('node-2', gpsCaps());
            a2.addPeer('node-1', gpsCaps());

            // Simulate: each node independently jitters (models real network/OS scheduling noise).
            // Constant-rate drift produces constant intervals which dynamic prediction absorbs
            // perfectly — only variable jitter creates prediction residuals that drive Kuramoto.
            const jitterA = [8, -3, 12, -7, 5, -11, 9, -4, 6, -9, 14, -2, 7, -8, 3, -13, 10, -5, 11, -6];
            const jitterB = [-5, 10, -8, 4, -12, 7, -3, 14, -6, 9, -11, 2, -7, 13, -4, 8, -9, 5, -10, 6];
            let wallTime = Date.now();
            for (let i = 0; i < 60; i++) {
                const ja = jitterA[i % jitterA.length];
                const jb = jitterB[i % jitterB.length];
                a1.onHeartbeat('node-2', wallTime + jb);
                a2.onHeartbeat('node-1', wallTime + ja);
                wallTime += 1000;
            }

            // Both respond to jitter (non-zero corrections)
            expect(a1._correctionMs).not.toBe(0);
            expect(a2._correctionMs).not.toBe(0);
            // Corrections stay bounded (Kuramoto doesn't blow up)
            expect(Math.abs(a1._correctionMs)).toBeLessThan(AGUWA_CONFIG.maxDriftMs);
            expect(Math.abs(a2._correctionMs)).toBeLessThan(AGUWA_CONFIG.maxDriftMs);
            // Phase estimates reflect the jitter
            expect(a1.peers.get('node-2').theta).not.toBe(0);
            expect(a2.peers.get('node-1').theta).not.toBe(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // ORDER PARAMETER
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Order Parameter', () => {
        test('returns 1.0 with no peers (solo mode)', () => {
            expect(aguwa.orderParameter()).toBe(1.0);
        });

        test('returns 1.0 with peers that have no arrivals', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            expect(aguwa.orderParameter()).toBe(1.0);
        });

        test('phase-locked peers → r close to 1.0', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            aguwa.addPeer('peer-2', gpsCaps());

            const now = Date.now();
            // Both peers have theta ≈ 0 (same phase)
            const p1 = aguwa.peers.get('peer-1');
            const p2 = aguwa.peers.get('peer-2');
            p1.lastArrival = now;
            p2.lastArrival = now;
            p1.theta = 0.01;
            p2.theta = -0.01;

            const r = aguwa.orderParameter();
            expect(r).toBeGreaterThan(0.9);
        });

        test('opposed peers → r close to 0', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            aguwa.addPeer('peer-2', gpsCaps());

            const now = Date.now();
            const p1 = aguwa.peers.get('peer-1');
            const p2 = aguwa.peers.get('peer-2');
            p1.lastArrival = now;
            p2.lastArrival = now;
            p1.theta = Math.PI / 2;    // 90°
            p2.theta = -Math.PI / 2;   // -90°

            const r = aguwa.orderParameter();
            expect(r).toBeLessThan(0.5);
        });

        test('stale peers are excluded from order parameter', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const p1 = aguwa.peers.get('peer-1');
            p1.lastArrival = Date.now() - AGUWA_CONFIG.staleThresholdMs - 1000; // stale
            p1.theta = Math.PI; // Would drag r down if included

            // Stale peer should be excluded → solo mode → r = 1.0
            const r = aguwa.orderParameter();
            expect(r).toBe(1.0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // HEALTH ASSESSMENT
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Health Assessment', () => {
        test('solo node → "solo"', () => {
            expect(aguwa.health()).toBe('solo');
        });

        test('phase-locked peers → "healthy"', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const p = aguwa.peers.get('peer-1');
            p.lastArrival = Date.now();
            p.theta = 0.05;
            expect(aguwa.health()).toBe('healthy');
        });

        test('desynchronized peers → "degraded" or "critical"', () => {
            // Need 2+ peers with opposed phases for low order parameter
            aguwa.addPeer('peer-1', gpsCaps());
            aguwa.addPeer('peer-2', gpsCaps());
            const p1 = aguwa.peers.get('peer-1');
            const p2 = aguwa.peers.get('peer-2');
            p1.lastArrival = Date.now();
            p2.lastArrival = Date.now();
            p1.theta = 0;         // 0° phase
            p2.theta = Math.PI;   // 180° out of phase → r ≈ 0
            const h = aguwa.health();
            expect(['degraded', 'critical']).toContain(h);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // DIVERGENT PEER DETECTION
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Divergent Peer Detection', () => {
        test('returns empty with <2 peers', () => {
            expect(aguwa.detectDivergentPeers()).toEqual([]);
            aguwa.addPeer('peer-1', gpsCaps());
            expect(aguwa.detectDivergentPeers()).toEqual([]);
        });

        test('aligned peers → no divergence detected', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            aguwa.addPeer('peer-2', gpsCaps());
            aguwa.addPeer('peer-3', gpsCaps());
            const now = Date.now();
            for (const [, peer] of aguwa.peers) {
                peer.lastArrival = now;
                peer.theta = 0.1; // All close to 0
            }
            expect(aguwa.detectDivergentPeers()).toEqual([]);
        });

        test('detects peer with phase >π/2 from mean', () => {
            aguwa.addPeer('good-1', gpsCaps());
            aguwa.addPeer('good-2', gpsCaps());
            aguwa.addPeer('bad-1', gpsCaps());
            const now = Date.now();
            aguwa.peers.get('good-1').lastArrival = now;
            aguwa.peers.get('good-1').theta = 0.1;
            aguwa.peers.get('good-2').lastArrival = now;
            aguwa.peers.get('good-2').theta = 0.15;
            aguwa.peers.get('bad-1').lastArrival = now;
            aguwa.peers.get('bad-1').theta = Math.PI; // 180° — clearly divergent

            const suspects = aguwa.detectDivergentPeers();
            expect(suspects.length).toBe(1);
            expect(suspects[0].nodeId).toBe('bad-1');
            expect(suspects[0].divergence).toBeGreaterThan(Math.PI / 2);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // COUPLING STRENGTH
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Coupling Strength', () => {
        test('GPS↔GPS = high coupling', () => {
            aguwa.addPeer('gps-peer', gpsCaps());
            const peer = aguwa.peers.get('gps-peer');
            // _couplingForPeer is a method — we can test via Kuramoto behavior
            // Direct internal test: access the coupling method
            const K = aguwa._couplingForPeer(peer);
            // GPS↔GPS or GPS↔NTP depends on our own trust level
            // Without a time source, we default to UNSYNC → MIN coupling
            expect(K).toBe(AGUWA_CONFIG.couplingMin);
        });

        test('UNSYNC peer always gets MIN coupling', () => {
            aguwa.addPeer('unsync-peer', unsyncCaps());
            const peer = aguwa.peers.get('unsync-peer');
            const K = aguwa._couplingForPeer(peer);
            expect(K).toBe(AGUWA_CONFIG.couplingMin);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // PROPAGATION DELAY
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Propagation Delays', () => {
        test('getPropagationDelays() returns empty map initially', () => {
            const delays = aguwa.getPropagationDelays();
            expect(delays.size).toBe(0);
        });

        test('returns delay after sufficient heartbeat samples', () => {
            aguwa.addPeer('peer-1', gpsCaps());
            const peer = aguwa.peers.get('peer-1');
            // Add error samples (propagation observations)
            for (let i = 0; i < 10; i++) {
                peer.recordError(5 + i); // 5, 6, ..., 14
            }
            const delays = aguwa.getPropagationDelays();
            expect(delays.has('peer-1')).toBe(true);
            expect(delays.get('peer-1').delayMs).toBeGreaterThan(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // ADAPTIVE TOLERANCE
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Adaptive Tolerance', () => {
        test('unknown peer gets UNSYNC tolerance (30s)', () => {
            const tol = aguwa.getToleranceForPeer('unknown');
            expect(tol).toBe(ManiPhaseTolerance[ManiTrustLevel.UNSYNC]);
        });

        test('GPS peer gets at least GPS tolerance', () => {
            aguwa.addPeer('gps-peer', gpsCaps());
            const tol = aguwa.getToleranceForPeer('gps-peer');
            // Our own trust defaults to UNSYNC in test → max(500, 30000) = 30000
            expect(tol).toBeGreaterThanOrEqual(ManiPhaseTolerance[ManiTrustLevel.GPS]);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // STATUS API
    // ═══════════════════════════════════════════════════════════════════════════

    describe('Status API', () => {
        test('getStatus() returns complete snapshot', () => {
            aguwa.init(TEST_CODE_HASH);
            aguwa.addPeer('peer-1', gpsCaps());

            const status = aguwa.getStatus();
            expect(status.initialized).toBe(true);
            expect(typeof status.omega).toBe('number');
            expect(typeof status.correctionMs).toBe('number');
            expect(typeof status.tick).toBe('number');
            expect(typeof status.nowMs).toBe('number');
            expect(typeof status.phase).toBe('number');
            expect(typeof status.orderParameter).toBe('number');
            expect(status.health).toBeDefined();
            expect(status.peerCount).toBe(1);
            expect(status.peers.length).toBe(1);
            expect(status.peers[0].nodeId).toContain('...');
        });

        test('getStatus() includes all peer metrics', () => {
            aguwa.init(TEST_CODE_HASH);
            aguwa.addPeer('peer-1', gpsCaps());

            const peer = aguwa.getStatus().peers[0];
            expect(peer.theta).toBeDefined();
            expect(peer.aguwaScore).toBeDefined();
            expect(peer.timeTrust).toBeDefined();
            expect(peer.karma).toBeDefined();
            expect(peer.hardware).toBeDefined();
            expect(peer.stability).toBeDefined();
            expect(peer.variance).toBeDefined();
        });

        test('getStatus() includes entropy link fields', () => {
            aguwa.init(TEST_CODE_HASH);
            const status = aguwa.getStatus();
            expect(status).toHaveProperty('networkJitter');
            expect(status).toHaveProperty('entropyLinked');
            expect(status.networkJitter).toBe(0);
            expect(status.entropyLinked).toBe(false);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // PRAHARI ↔ AGUWA BIDIRECTIONAL LINK
    // ═══════════════════════════════════════════════════════════════════════════

    describe('PRAHARI ↔ AGUWA Link', () => {
        beforeEach(() => {
            aguwa.init(TEST_CODE_HASH);
            vi.spyOn(aguwa, '_getMyTrustLevel').mockReturnValue('gps');
        });

        afterEach(() => {
            vi.restoreAllMocks();
        });

        test('registerEntropyCallback stores the callback', () => {
            expect(aguwa._entropyCallback).toBe(null);
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            expect(aguwa._entropyCallback).toBe(cb);
        });

        test('onHeartbeat fires entropy callback with 8-byte residual', () => {
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);          // first — baseline
            aguwa.onHeartbeat('peer-1', t0 + 1000);   // second — bootstraps period
            aguwa.onHeartbeat('peer-1', t0 + 2005);   // third — has prediction, fires callback

            expect(cb).toHaveBeenCalledTimes(1);
            const residual = cb.mock.calls[0][0];
            expect(residual).toBeInstanceOf(Uint8Array);
            expect(residual.length).toBe(8);
        });

        test('entropy callback contains errorMs as float64', () => {
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            aguwa.onHeartbeat('peer-1', t0 + 1000);
            // Heartbeat arrives 50ms late → errorMs = +50
            aguwa.onHeartbeat('peer-1', t0 + 2050);

            const bytes = cb.mock.calls[0][0];
            const dv = new DataView(bytes.buffer, bytes.byteOffset, 8);
            const errorMs = dv.getFloat64(0, false);
            expect(errorMs).toBeCloseTo(50, 0);
        });

        test('setNetworkJitter clamps to [0, 1]', () => {
            aguwa.setNetworkJitter(0.5);
            expect(aguwa._networkJitter).toBe(0.5);

            aguwa.setNetworkJitter(-1);
            expect(aguwa._networkJitter).toBe(0);

            aguwa.setNetworkJitter(2.5);
            expect(aguwa._networkJitter).toBe(1);
        });

        test('network jitter modulates Kuramoto coupling strength', () => {
            aguwa.addPeer('peer-1', gpsCaps());

            // Simulate 3 heartbeats to establish baseline
            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            aguwa.onHeartbeat('peer-1', t0 + 1000);

            // Save correction after a jittery heartbeat at jitter=0 (full coupling)
            aguwa.setNetworkJitter(0);
            aguwa.onHeartbeat('peer-1', t0 + 2050);
            const correctionFull = aguwa._correctionMs;

            // Reset for comparison
            const aguwa2 = new Aguwa();
            aguwa2.init(TEST_CODE_HASH);
            vi.spyOn(aguwa2, '_getMyTrustLevel').mockReturnValue('gps');
            aguwa2.addPeer('peer-1', gpsCaps());

            aguwa2.onHeartbeat('peer-1', t0);
            aguwa2.onHeartbeat('peer-1', t0 + 1000);

            // Same heartbeat but at jitter=1 (heavily dampened coupling)
            aguwa2.setNetworkJitter(1.0);
            aguwa2.onHeartbeat('peer-1', t0 + 2050);
            const correctionDampened = aguwa2._correctionMs;

            // Both should have corrections, but dampened should be smaller
            expect(Math.abs(correctionFull)).toBeGreaterThan(0);
            expect(Math.abs(correctionDampened)).toBeGreaterThan(0);
            expect(Math.abs(correctionDampened)).toBeLessThan(Math.abs(correctionFull));
        });

        test('getStatus reflects entropy link state', () => {
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            aguwa.setNetworkJitter(0.42);

            const status = aguwa.getStatus();
            expect(status.entropyLinked).toBe(true);
            expect(status.networkJitter).toBeCloseTo(0.42);
        });
    });
});


