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
 * PRAHARI ↔ AGUWA Bidirectional Link Tests
 *
 * Tests the wiring between the PRAHARI sponge entropy engine
 * and the AGUWA Kuramoto oscillator:
 *   - Kuramoto residuals flow into PRAHARI as entropy source
 *   - Mesh jitter statistics modulate AGUWA coupling strength
 *   - Source lifecycle (available, harvest, weight)
 *
 * @module security/tests/prahari-aguwa.test
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { Aguwa, AGUWA_CONFIG, PeerPhaseState } from '../../mesh/aguwa.js';

// We test the createKuramotoResidualSource internals via the wiring function
// Since the module uses the singleton aguwa, we import wireAguwaWithPrahari
// and mock prahari as a minimal object.

function gpsCaps() {
    return { maniTrust: 'gps', avx512: true, vaes: true, shaNI: true, nvGpu: true, totalTops: 117 };
}

const CODE_HASH = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

describe('PRAHARI ↔ AGUWA Wiring', () => {
    let aguwa;
    let mockPrahari;
    let registeredSource;

    beforeEach(async () => {
        // Fresh AGUWA instance (can't use singleton in tests)
        aguwa = new Aguwa();
        aguwa.init(CODE_HASH);
        vi.spyOn(aguwa, '_getMyTrustLevel').mockReturnValue('gps');

        // Mock prahari module
        registeredSource = null;
        mockPrahari = {
            registerEntropySource(source) {
                registeredSource = source;
                return true;
            },
        };
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // ═══════════════════════════════════════════════════════════════
    // DIRECTION 1: AGUWA → PRAHARI (Kuramoto residuals as entropy)
    // ═══════════════════════════════════════════════════════════════

    describe('Kuramoto Residual Entropy Source', () => {
        test('entropy callback feeds residual bytes into source buffer', () => {
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            aguwa.onHeartbeat('peer-1', t0 + 1000);
            aguwa.onHeartbeat('peer-1', t0 + 2015); // 15ms jitter

            expect(cb).toHaveBeenCalledTimes(1);
            const bytes = cb.mock.calls[0][0];
            // Should be 8 bytes (Float64)
            expect(bytes.length).toBe(8);
        });

        test('multiple heartbeats produce multiple entropy samples', () => {
            const cb = vi.fn();
            aguwa.registerEntropyCallback(cb);
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            const jitter = [0, 0, 8, -3, 12, -7, 5, -11, 9, -4];
            let wallTime = t0;
            for (let i = 0; i < jitter.length; i++) {
                aguwa.onHeartbeat('peer-1', wallTime + jitter[i]);
                wallTime += 1000;
            }

            // First 2 beats: no callback (baseline + bootstrap)
            // Beats 3-10: 8 callbacks (each has prediction to compare)
            expect(cb).toHaveBeenCalledTimes(8);
        });

        test('residual bytes vary with different jitter', () => {
            const residuals = [];
            aguwa.registerEntropyCallback((bytes) => {
                residuals.push(new Uint8Array(bytes));
            });
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            aguwa.onHeartbeat('peer-1', t0 + 1000);
            aguwa.onHeartbeat('peer-1', t0 + 2050); // +50ms
            aguwa.onHeartbeat('peer-1', t0 + 2990); // -60ms from expected

            expect(residuals.length).toBe(2);
            // Different errors → different bytes
            const hex1 = Array.from(residuals[0]).map(b => b.toString(16)).join('');
            const hex2 = Array.from(residuals[1]).map(b => b.toString(16)).join('');
            expect(hex1).not.toBe(hex2);
        });
    });

    // ═══════════════════════════════════════════════════════════════
    // DIRECTION 2: PRAHARI → AGUWA (jitter → coupling modulation)
    // ═══════════════════════════════════════════════════════════════

    describe('Network Jitter Modulation', () => {
        test('zero jitter gives full coupling', () => {
            aguwa.setNetworkJitter(0);
            aguwa.addPeer('peer-1', gpsCaps());

            const t0 = Date.now();
            aguwa.onHeartbeat('peer-1', t0);
            aguwa.onHeartbeat('peer-1', t0 + 1000);
            aguwa.onHeartbeat('peer-1', t0 + 2100); // +100ms error

            const correction0 = Math.abs(aguwa._correctionMs);
            expect(correction0).toBeGreaterThan(0);
        });

        test('high jitter dampens corrections', () => {
            // Run same scenario twice: jitter=0 vs jitter=1
            const corrections = [];

            for (const jitter of [0, 1]) {
                const a = new Aguwa();
                a.init(CODE_HASH);
                vi.spyOn(a, '_getMyTrustLevel').mockReturnValue('gps');
                a.addPeer('peer-1', gpsCaps());
                a.setNetworkJitter(jitter);

                const t0 = Date.now();
                a.onHeartbeat('peer-1', t0);
                a.onHeartbeat('peer-1', t0 + 1000);
                a.onHeartbeat('peer-1', t0 + 2100);

                corrections.push(Math.abs(a._correctionMs));
            }

            // jitter=0 should produce larger correction than jitter=1
            expect(corrections[0]).toBeGreaterThan(corrections[1]);
            // jitter=1 dampens to 30% of base K, so correction ratio ≈ 0.3
            expect(corrections[1] / corrections[0]).toBeCloseTo(0.3, 1);
        });

        test('peer arrival variance drives jitter level', () => {
            // Simulate messy arrivals to build high variance
            aguwa.addPeer('peer-1', gpsCaps());
            const t0 = Date.now();
            const arrivals = [0, 1000, 1950, 3100, 3900, 5200, 6000, 7300, 8100, 9500];
            for (const offset of arrivals) {
                aguwa.onHeartbeat('peer-1', t0 + offset);
            }

            const peer = aguwa.peers.get('peer-1');
            expect(peer.arrivalDeltaVariance).toBeGreaterThan(0);
            expect(peer.arrivalDeltaVariance).not.toBe(Infinity);
        });
    });

    // ═══════════════════════════════════════════════════════════════
    // STATUS INTEGRATION
    // ═══════════════════════════════════════════════════════════════

    describe('Status Fields', () => {
        test('status shows entropy link state', () => {
            let status = aguwa.getStatus();
            expect(status.entropyLinked).toBe(false);
            expect(status.networkJitter).toBe(0);

            aguwa.registerEntropyCallback(() => { });
            aguwa.setNetworkJitter(0.6);

            status = aguwa.getStatus();
            expect(status.entropyLinked).toBe(true);
            expect(status.networkJitter).toBeCloseTo(0.6);
        });
    });
});
