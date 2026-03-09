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
 * GPS Jitter Entropy Source for PRAHARI
 * 
 * Harvests entropy from MA-902 GPS time server timing residuals.
 * The sub-second field from SNMP polls contains genuine hardware noise:
 * - GPS receiver clock jitter (oscillator phase noise)
 * - SNMP round-trip timing variation (network + protocol jitter)
 * - Satellite constellation geometry changes (multipath, atmospheric)
 * 
 * This source registers itself with PRAHARI's EntropySourceRegistry
 * when the MANI time source becomes available (lazy registration).
 * 
 * @module security/sources/gps-jitter
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { createLogger } from '../../utils/logger.js';

const log = createLogger('security:prahari:gps-jitter');

/** Circular buffer size for timing samples */
const SAMPLE_BUFFER_SIZE = 64;

/**
 * Create a GPS jitter entropy source from an MA-902 monitor instance.
 * 
 * The source collects timing residuals from SNMP telemetry events and
 * stores them in a circular buffer. On harvest, the buffer contents
 * are returned as raw entropy bytes.
 * 
 * Entropy quality depends on:
 * - MA-902 poll interval (default 10s) — slower = more independent samples
 * - GPS lock status — locked = higher quality (genuine satellite jitter)
 * - Satellite count — more satellites = more multipath noise
 * 
 * @param {import('../../oracle/ma902-snmp.js').MA902Monitor} ma902Monitor
 * @returns {import('../prahari.js').EntropySource}
 */
export function createGPSJitterSource(ma902Monitor) {
    /** Circular buffer of timing residual bytes */
    const sampleBuffer = new Uint8Array(SAMPLE_BUFFER_SIZE);
    let writePos = 0;
    let samplesCollected = 0;
    let lastSubSeconds = null;
    let lastPollTimestamp = null;

    // Listen for telemetry events from the MA-902 monitor
    if (ma902Monitor && typeof ma902Monitor.on === 'function') {
        ma902Monitor.on('telemetry', (telemetry) => {
            if (!telemetry) return;

            const now = process.hrtime.bigint();

            // Extract sub-second field — contains GPS clock phase noise
            if (telemetry.subSeconds !== null && telemetry.subSeconds !== undefined) {
                const subSec = typeof telemetry.subSeconds === 'number' ? telemetry.subSeconds : 0;

                // Delta from last sub-second value — the jitter itself
                if (lastSubSeconds !== null) {
                    const delta = Math.abs(subSec - lastSubSeconds);
                    // Extract lowest 2 bytes of delta (most entropic)
                    sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = delta & 0xFF;
                    writePos++;
                    sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = (delta >> 8) & 0xFF;
                    writePos++;
                    samplesCollected += 2;
                }
                lastSubSeconds = subSec;
            }

            // SNMP round-trip timing delta — contains network + processing jitter
            if (lastPollTimestamp !== null) {
                const rtDelta = Number(now - lastPollTimestamp);
                // Extract lowest 2 bytes of nanosecond delta
                sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = rtDelta & 0xFF;
                writePos++;
                sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = (rtDelta >> 8) & 0xFF;
                writePos++;
                samplesCollected += 2;
            }
            lastPollTimestamp = now;

            // GPS time vs system time delta LSBs — genuine clock skew noise
            if (telemetry.clockDeltaSeconds !== null && telemetry.clockDeltaSeconds !== undefined) {
                const clockDelta = Math.round(telemetry.clockDeltaSeconds * 1_000_000); // microseconds
                sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = clockDelta & 0xFF;
                writePos++;
                sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = (clockDelta >> 8) & 0xFF;
                writePos++;
                samplesCollected += 2;
            }

            // Satellite count changes contribute small amounts of entropy
            if (telemetry.satellites) {
                const satByte = (telemetry.satellites.used || 0) ^ (telemetry.satellites.visible || 0);
                sampleBuffer[writePos % SAMPLE_BUFFER_SIZE] = satByte & 0xFF;
                writePos++;
                samplesCollected++;
            }
        });

        log.info('GPS jitter entropy source attached to MA-902 monitor');
    }

    return {
        kind: 'gps-jitter',
        name: 'MA-902 GPS timing jitter (SNMP)',
        weight: 7, // High weight — genuine hardware noise

        available() {
            return ma902Monitor?.available === true && samplesCollected > 0;
        },

        harvest() {
            if (samplesCollected === 0) return null;

            // Return current buffer contents (up to what we've collected)
            const len = Math.min(samplesCollected, SAMPLE_BUFFER_SIZE);
            const out = new Uint8Array(len);

            // Read from circular buffer, starting from oldest
            const readStart = samplesCollected > SAMPLE_BUFFER_SIZE
                ? writePos % SAMPLE_BUFFER_SIZE
                : 0;

            for (let i = 0; i < len; i++) {
                out[i] = sampleBuffer[(readStart + i) % SAMPLE_BUFFER_SIZE];
            }

            return out;
        },
    };
}

/**
 * Register GPS jitter source with PRAHARI when a time source detector is available.
 * Called by server/index.js after _initTimeSource() completes.
 * 
 * @param {import('./prahari.js')} prahari — PRAHARI module
 * @param {import('../../oracle/time-source.js').ManiTimeDetector} timeDetector
 */
export function registerGPSJitterWithPrahari(prahari, timeDetector) {
    if (!timeDetector) {
        log.debug('No time source detector — GPS jitter entropy not available');
        return;
    }

    // Check if MA-902 monitor is accessible
    const ma902 = timeDetector.ma902Monitor || timeDetector._ma902 || null;
    if (!ma902) {
        log.debug('No MA-902 monitor in time detector — GPS jitter entropy not available');
        return;
    }

    const source = createGPSJitterSource(ma902);
    prahari.registerEntropySource(source);
    log.info('GPS jitter entropy source registered with PRAHARI');
}

export default { createGPSJitterSource, registerGPSJitterWithPrahari };
