/**
 * PRAHARI ↔ AGUWA Bidirectional Entropy-Timing Link
 *
 * Connects the PRAHARI sponge entropy engine to the AGUWA Kuramoto clock:
 *
 *   Direction 1 (AGUWA → PRAHARI):
 *     Kuramoto prediction residuals (errorMs) fed into sponge as entropy.
 *     The LSBs of timing prediction errors contain genuine network jitter
 *     that is unpredictable even to an adversary controlling one endpoint.
 *     New source kind: 'kuramoto-residual' (weight: 6).
 *
 *   Direction 2 (PRAHARI → AGUWA):
 *     Mesh arrival jitter variance → AGUWA network jitter level.
 *     Modulates Kuramoto coupling strength adaptively:
 *       High jitter → conservative coupling (don't overreact to noise)
 *       Low jitter  → tight coupling (trust the observations)
 *
 * Wiring: Call wireAguwaWithPrahari() once from server/index.js
 *         after both PRAHARI and AGUWA are initialized.
 *
 * @module security/prahari-aguwa
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createLogger } from '../utils/logger.js';
import { aguwa } from '../mesh/aguwa.js';

const log = createLogger('security:prahari:aguwa');

/** Circular buffer for Kuramoto residuals (entropy source for PRAHARI) */
const RESIDUAL_BUFFER_SIZE = 64;

/** Minimum residual samples before the source is "available" */
const MIN_RESIDUAL_SAMPLES = 4;

/** How often to update AGUWA's network jitter from mesh stats (ms) */
const JITTER_UPDATE_INTERVAL = 10_000;

/**
 * Create a Kuramoto residual entropy source for PRAHARI.
 *
 * Collects the raw float64 bytes of each prediction error (errorMs)
 * from AGUWA's onHeartbeat(). The lowest bytes carry genuine network
 * timing noise — OS scheduling jitter, NIC interrupt latency, routing
 * variance — that no single party can predict.
 *
 * @returns {{ source: object, feedResidual: (bytes: Uint8Array) => void }}
 */
function createKuramotoResidualSource() {
    const buffer = new Uint8Array(RESIDUAL_BUFFER_SIZE);
    let writePos = 0;
    let samplesCollected = 0;

    /**
     * Called by AGUWA after each Kuramoto update with the raw
     * float64 encoding of errorMs (8 bytes per heartbeat).
     */
    function feedResidual(bytes) {
        for (let i = 0; i < bytes.length; i++) {
            buffer[writePos % RESIDUAL_BUFFER_SIZE] = bytes[i];
            writePos++;
        }
        samplesCollected += bytes.length;
    }

    const source = {
        kind: 'kuramoto-residual',
        name: 'Kuramoto prediction residuals (network timing jitter)',
        weight: 6,

        available() {
            return samplesCollected >= MIN_RESIDUAL_SAMPLES;
        },

        harvest() {
            if (samplesCollected < MIN_RESIDUAL_SAMPLES) return null;
            const len = Math.min(samplesCollected, RESIDUAL_BUFFER_SIZE);
            const out = new Uint8Array(len);
            const readStart = samplesCollected > RESIDUAL_BUFFER_SIZE
                ? writePos % RESIDUAL_BUFFER_SIZE
                : 0;
            for (let i = 0; i < len; i++) {
                out[i] = buffer[(readStart + i) % RESIDUAL_BUFFER_SIZE];
            }
            return out;
        },
    };

    return { source, feedResidual };
}

/**
 * Compute network jitter level from mesh arrival source statistics.
 *
 * Reads the variance of AGUWA peer arrival deltas across all active peers.
 * Maps aggregate variance to a [0, 1] jitter level via sigmoid.
 *
 * Variance    → Jitter    → Coupling effect
 * 0           → 0.0       → Full coupling (network perfectly stable)
 * 500         → ~0.09     → Slightly conservative
 * 5000        → ~0.50     → Moderate dampening
 * 50000       → ~0.91     → Very conservative
 * ∞           → 1.0       → Minimum coupling (30% of base K)
 *
 * @returns {number} jitterLevel ∈ [0, 1]
 */
function computeNetworkJitter() {
    let totalVariance = 0;
    let count = 0;

    for (const peer of aguwa.peers.values()) {
        if (peer.arrivalDeltaVariance !== Infinity && peer.arrivalDeltas.length >= 3) {
            totalVariance += peer.arrivalDeltaVariance;
            count++;
        }
    }

    if (count === 0) return 0; // No data → assume stable
    const avgVariance = totalVariance / count;

    // Sigmoid: variance 0 → 0, variance 5000 → 0.5, variance ∞ → 1
    return avgVariance / (avgVariance + 5000);
}

/**
 * Wire the bidirectional PRAHARI ↔ AGUWA link.
 *
 * Call once from server/index.js after PRAHARI init + AGUWA init + mesh online:
 *
 *   import { wireAguwaWithPrahari } from './security/prahari-aguwa.js';
 *   wireAguwaWithPrahari(prahari);
 *
 * @param {Object} prahari — PRAHARI module (has registerEntropySource)
 * @returns {{ source: object, stopJitterFeed: () => void }}
 */
export function wireAguwaWithPrahari(prahari) {
    // ── Direction 1: AGUWA → PRAHARI (residuals as entropy) ──
    const { source, feedResidual } = createKuramotoResidualSource();
    prahari.registerEntropySource(source);
    aguwa.registerEntropyCallback(feedResidual);

    log.info('AGUWA → PRAHARI: Kuramoto residuals registered as entropy source (weight=6)');

    // ── Direction 2: PRAHARI → AGUWA (mesh jitter → coupling modulation) ──
    const jitterTimer = setInterval(() => {
        const jitter = computeNetworkJitter();
        aguwa.setNetworkJitter(jitter);
    }, JITTER_UPDATE_INTERVAL);

    if (jitterTimer.unref) jitterTimer.unref();

    log.info('PRAHARI → AGUWA: Network jitter feed started (every 10s)');

    return {
        source,
        stopJitterFeed() {
            clearInterval(jitterTimer);
        },
    };
}
