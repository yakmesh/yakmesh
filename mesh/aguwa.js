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
 * AGUWA — Adaptive Gyroscopic Universal Waveform Authority
 * अगुवा (aguwa) — "the one who goes first"
 *
 * Canonical time source for the yakmesh mesh. Every module that needs time
 * calls aguwa.now() or aguwa.tick() instead of Date.now() / Math.floor(Date.now()/1000).
 *
 * Physics: Kuramoto coupled oscillator model.
 * Each peer j has phase θ_j and coupling weight A_j (AGUWA confidence score).
 * GPS/Atomic-equipped nodes naturally become passive pacemakers — no election,
 * no announcement, just physics.
 *
 *   dθ_i/dt = ω_i + (K/N) Σ A_j sin(θ_j − θ_i)
 *
 * The "4th signal" is heartbeat arrival precision — zero additional bytes on
 * the wire. Every 1-second heartbeat IS a Kuramoto observation.
 *
 * Order parameter r = (1/N) |Σ e^{iθ_j}| measures mesh phase coherence.
 * r → 1: healthy, phase-locked. r → 0: split codebase or Byzantine nodes.
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  INTEGRATION CONTRACT — DO NOT LEAVE UNWIRED
 * ═══════════════════════════════════════════════════════════════════════════════
 * This module is USELESS without three critical wirings in server/index.js:
 *
 *  1. aguwa.init(oracle.selfHash)     — Derives Kuramoto ω from codebase hash
 *  2. aguwa.calibrateFromGPS(gpsUnix) — Seeds _correctionMs from MA-902 GPS
 *  3. aguwa.onHeartbeat(origin, now)  — Called from _handleTimeHeartbeat
 *
 * Without ALL THREE, aguwa.now() === Date.now() and commit-reveal WILL fail.
 * Learned the hard way: 2026-03-08. Verify integration, don't just write code.
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * @module mesh/aguwa
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 as _sha3 } from '@noble/hashes/sha3.js';
import { utf8ToBytes, hexToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';
import { ManiTrustLevel, ManiPhaseTolerance, getManiTimeDetector } from '../oracle/time-source.js';
import { PeerPhaseBuffer } from './peer-phase-buffer.js';
import { Worker } from 'worker_threads';

const log = createLogger('AGUWA');

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const AGUWA_CONFIG = {
    // Kuramoto coupling strength by trust-pair category
    couplingHigh: 0.25,   // Both GPS/Atomic  — tight phase-lock
    couplingMid: 0.10,   // GPS ↔ NTP        — moderate
    couplingLow: 0.04,   // Both NTP         — gentle nudge
    couplingMin: 0.01,   // UNSYNC involved  — very loose

    // AGUWA score weights  (Σ = 1.0)
    weightTimeTrust: 0.4,
    weightKarma: 0.2,
    weightHardware: 0.2,
    weightStability: 0.2,

    // Stability tracking
    stabilityWindowSize: 30,   // Last N heartbeats for variance
    maxDriftMs: 60_000,      // Clamp correction to ±60s max
    staleThresholdMs: 10_000,  // Peer considered stale after 10s silence

    // Order parameter thresholds
    orderHealthy: 0.9,
    orderWarn: 0.5,
    orderCritical: 0.2,

    // Frequency derivation salt/info for HKDF
    frequencySalt: 'aguwa:omega:v1',
    frequencyInfo: 'yakmesh:kuramoto:natural-frequency',
};

// ─────────────────────────────────────────────────────────────────────────────
// Trust-level numeric mapping for AGUWA score
// ─────────────────────────────────────────────────────────────────────────────

const TRUST_SCORES = {
    [ManiTrustLevel.QUANTUM]: 1.0,
    [ManiTrustLevel.ATOMIC]: 0.95,
    [ManiTrustLevel.GPS]: 0.85,
    [ManiTrustLevel.PTP]: 0.75,
    [ManiTrustLevel.NTP]: 0.4,
    [ManiTrustLevel.UNSYNC]: 0.1,
};

// ─────────────────────────────────────────────────────────────────────────────
// Per-Peer Kuramoto State
// ─────────────────────────────────────────────────────────────────────────────

class PeerPhaseState {
    /**
     * @param {string} nodeId
     * @param {Object} capabilities
     * @param {PeerPhaseBuffer|null} buffer  — SharedArrayBuffer-backed store (Phase 4)
     * @param {number} slotIndex             — slot in buffer (-1 if no buffer)
     */
    constructor(nodeId, capabilities, buffer = null, slotIndex = -1) {
        this.nodeId = nodeId;
        this.capabilities = capabilities;

        // SharedArrayBuffer delegation (Phase 4)
        // When buffer is set, theta/stabilityScore/timeTrust/karmaScore/
        // hardwareScore/lastArrival are backed by Atomics in the SAB.
        // When null, plain JS properties (_theta etc.) are used instead.
        this._buffer = buffer;
        this._slotIndex = slotIndex;

        // Local fallbacks (used when no buffer)
        this._theta = 0;
        this._stabilityScore = 0.5;
        this._timeTrust = 0;
        this._karmaScore = 0.5;
        this._hardwareScore = 0;
        this._lastArrival = null;

        // Initialize via setters (writes to buffer if available)
        this.theta = 0;
        this.predictedArrival = null;
        this.timeTrust = this._scoreTrust(capabilities);
        this.karmaScore = 0.5;
        this.hardwareScore = this._scoreHardware(capabilities);
        this.stabilityScore = 0.5;
        this.lastArrival = null;

        // Non-hot-path state — always plain JS (not in SAB)
        this.arrivalDeltas = [];
        this.arrivalDeltaVariance = Infinity;
        this._estimatedPeriodMs = null;
        this.minErrorMs = Infinity;
        this.recentErrors = [];
    }

    // ── Buffer-delegated property accessors ──
    // Hot-path fields go through Atomics when buffer exists.

    get theta() {
        if (this._buffer) return this._buffer.getTheta(this._slotIndex);
        return this._theta;
    }
    set theta(val) {
        if (this._buffer) { this._buffer.setTheta(this._slotIndex, val); return; }
        this._theta = val;
    }

    get stabilityScore() {
        if (this._buffer) return this._buffer.getStabilityScore(this._slotIndex);
        return this._stabilityScore;
    }
    set stabilityScore(val) {
        if (this._buffer) { this._buffer.setStabilityScore(this._slotIndex, val); return; }
        this._stabilityScore = val;
    }

    get timeTrust() {
        if (this._buffer) return this._buffer.getTimeTrust(this._slotIndex);
        return this._timeTrust;
    }
    set timeTrust(val) {
        if (this._buffer) { this._buffer.setTimeTrust(this._slotIndex, val); return; }
        this._timeTrust = val;
    }

    get karmaScore() {
        if (this._buffer) return this._buffer.getKarmaScore(this._slotIndex);
        return this._karmaScore;
    }
    set karmaScore(val) {
        if (this._buffer) { this._buffer.setKarmaScore(this._slotIndex, val); return; }
        this._karmaScore = val;
    }

    get hardwareScore() {
        if (this._buffer) return this._buffer.getHardwareScore(this._slotIndex);
        return this._hardwareScore;
    }
    set hardwareScore(val) {
        if (this._buffer) { this._buffer.setHardwareScore(this._slotIndex, val); return; }
        this._hardwareScore = val;
    }

    get lastArrival() {
        if (this._buffer && this._buffer.getLastArrival(this._slotIndex) > 0) {
            return this._buffer.getLastArrival(this._slotIndex);
        }
        return this._lastArrival;
    }
    set lastArrival(val) {
        if (this._buffer && val !== null) {
            this._buffer.setLastArrival(this._slotIndex, val);
        }
        this._lastArrival = val;
    }

    /** Numeric trust from MANI level (0–1) */
    _scoreTrust(caps) {
        if (!caps) return TRUST_SCORES[ManiTrustLevel.UNSYNC];
        const trust = caps.maniTrust || ManiTrustLevel.UNSYNC;
        return TRUST_SCORES[trust] ?? TRUST_SCORES[ManiTrustLevel.UNSYNC];
    }

    /** Hardware score from capabilities (0–1) */
    _scoreHardware(caps) {
        if (!caps) return 0.1;
        let score = 0.1; // baseline
        if (caps.avx512) score += 0.15;
        if (caps.vaes) score += 0.10;
        if (caps.shaNI) score += 0.10;
        if (caps.gfni) score += 0.05;
        if (caps.nvGpu) score += 0.25;
        if (caps.amdNpu) score += 0.15;
        // TOPS contribution (clamped sigmoid)
        if (caps.totalTops > 0) {
            score += 0.2 * Math.min(1, caps.totalTops / 200);
        }
        return Math.min(1, score);
    }

    /** Composite AGUWA confidence: A_j = w_t*T + w_k*K + w_h*H + w_s*S */
    get aguwaScore() {
        return (
            AGUWA_CONFIG.weightTimeTrust * this.timeTrust +
            AGUWA_CONFIG.weightKarma * this.karmaScore +
            AGUWA_CONFIG.weightHardware * this.hardwareScore +
            AGUWA_CONFIG.weightStability * this.stabilityScore
        );
    }

    /** Record a heartbeat arrival and update stability */
    recordArrival(arrivalMs) {
        if (this.lastArrival !== null) {
            const delta = arrivalMs - this.lastArrival;
            this.arrivalDeltas.push(delta);
            if (this.arrivalDeltas.length > AGUWA_CONFIG.stabilityWindowSize) {
                this.arrivalDeltas.shift();
            }
            this._updateVariance();

            // Dynamic period estimation: bootstrap from first delta,
            // then exponential smoothing (α=0.1) to adapt to environment.
            // This replaces the static `+ 1000` that only worked for
            // integer-second heartbeat intervals by coincidence.
            if (this._estimatedPeriodMs === null) {
                this._estimatedPeriodMs = delta; // First observation bootstraps
            } else {
                this._estimatedPeriodMs = 0.9 * this._estimatedPeriodMs + 0.1 * delta;
            }
        }
        this.lastArrival = arrivalMs;

        // Dynamic prediction: use observed period (null if only 1 heartbeat)
        this.predictedArrival = this._estimatedPeriodMs !== null
            ? arrivalMs + this._estimatedPeriodMs
            : null;
    }

    /** Compute variance of arrival deltas → stability score */
    _updateVariance() {
        const n = this.arrivalDeltas.length;
        if (n < 3) return; // Need minimum samples
        const mean = this.arrivalDeltas.reduce((a, b) => a + b, 0) / n;
        const variance = this.arrivalDeltas.reduce((s, d) => s + (d - mean) ** 2, 0) / n;
        this.arrivalDeltaVariance = variance;
        // Low variance = high stability (sigmoid mapping)
        // Variance 0 → score 1.0, variance 10000 (100ms std) → score ~0.27
        this.stabilityScore = 1 / (1 + variance / 5000);
    }

    /** Record propagation delay sample (absolute error ms) */
    recordError(absErrorMs) {
        if (absErrorMs < this.minErrorMs) this.minErrorMs = absErrorMs;
        this.recentErrors.push(absErrorMs);
        if (this.recentErrors.length > AGUWA_CONFIG.stabilityWindowSize) {
            this.recentErrors.shift();
        }
    }

    /**
     * Estimated one-way propagation delay (ms).
     * Uses the 5th percentile of |errorMs| — the minimum residual
     * after Kuramoto drift correction. Physical distance bound.
     * @returns {number|null} ms, or null if insufficient samples
     */
    get propagationDelayMs() {
        if (this.recentErrors.length < 5) return null;
        const sorted = [...this.recentErrors].sort((a, b) => a - b);
        // 5th percentile to filter noise
        const idx = Math.max(0, Math.floor(sorted.length * 0.05));
        return sorted[idx];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AGUWA Core
// ─────────────────────────────────────────────────────────────────────────────

class Aguwa {
    constructor() {
        /** @type {Map<string, PeerPhaseState>} Per-peer Kuramoto tracking */
        this.peers = new Map();

        // Our own Kuramoto phase offset (ms correction to add to wall clock)
        this._correctionMs = 0;

        // Monotonic guarantee — never return a value lower than previous
        this._lastNowMs = 0;
        this._lastTick = 0;

        // Natural frequency ω_i — derived from oracle hash
        this._omega = 0; // radians per second

        // Oracle hash (hex string) — set via init()
        this._codeHash = null;

        // Initialized flag
        this._initialized = false;

        // ── PRAHARI ↔ AGUWA bidirectional link ──
        // Callback: receives (residualBytes: Uint8Array) after each Kuramoto update
        // Used by PRAHARI to absorb Kuramoto residuals as sponge entropy
        this._entropyCallback = null;

        // Network jitter level from PRAHARI mesh arrival source.
        // Modulates Kuramoto coupling: high jitter → conservative, low → tight.
        // Range [0, 1] where 0 = perfectly stable, 1 = maximally noisy.
        this._networkJitter = 0;

        /** @type {PeerPhaseBuffer|null} SharedArrayBuffer-backed peer state (Phase 4) */
        this._buffer = null;

        // ── Worker thread offloading (Phase 5) ──
        /** @type {Worker|null} Persistent worker for batch Kuramoto updates */
        this._worker = null;
        /** True while worker is processing a batch — main thread skips theta writes */
        this._workerInFlight = false;
        /** Peer count threshold to offload to Worker (set in initBuffer) */
        this._workerThreshold = Infinity;
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Initialization
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Initialize AGUWA with the oracle codebase hash.
     * Derives the natural frequency ω from the hash via HKDF.
     * Same hash → same ω → guaranteed phase-lock.
     *
     * @param {string} codeHash - Hex-encoded oracle selfHash
     */
    init(codeHash) {
        if (!codeHash || typeof codeHash !== 'string') {
            throw new Error('AGUWA requires oracle codeHash (hex string)');
        }
        this._codeHash = codeHash;

        // Derive natural frequency from codebase hash via HKDF
        // Output: 8 bytes → float64 in [0, 2π) radians/sec
        const hashBytes = hexToBytes(codeHash);
        const salt = utf8ToBytes(AGUWA_CONFIG.frequencySalt);
        const info = utf8ToBytes(AGUWA_CONFIG.frequencyInfo);
        const derived = hkdf(_sha3, hashBytes, salt, info, 8);
        // Convert 8 bytes to a value in [0, 2π)
        const dv = new DataView(derived.buffer, derived.byteOffset, 8);
        const raw = dv.getBigUint64(0, false); // big-endian
        this._omega = Number(raw % BigInt(628318)) / 100000; // [0, 2π)

        this._initialized = true;
        log.info(`AGUWA initialized | ω = ${this._omega.toFixed(6)} rad/s | hash = ${codeHash.slice(0, 16)}...`);
    }

    /**
     * Initialize the SharedArrayBuffer-backed PeerPhaseBuffer.
     * Must be called after accel.probe() returns HW telemetry.
     *
     * @param {{ threads?: number, totalTops?: number }} hwTelemetry
     */
    initBuffer(hwTelemetry) {
        if (this._buffer) return; // Already initialized
        this._buffer = new PeerPhaseBuffer(hwTelemetry);

        // Spawn persistent Worker for batch Kuramoto updates
        this._workerThreshold = Math.max(100, Math.floor(this._buffer.maxPeers * 0.4));
        this._worker = new Worker(new URL('./aguwa-worker.js', import.meta.url));
        this._worker.on('message', (result) => {
            // Apply aggregate correction from batch update
            this._correctionMs += result.totalDeltaMs * 0.1; // 10% smoothing (matches inline)
            this._workerInFlight = false;
        });
        this._worker.on('error', (err) => {
            log.warn('AGUWA Worker error', { error: err.message });
            this._workerInFlight = false; // Unblock, fall back to inline
        });

        log.info('PeerPhaseBuffer attached', {
            maxPeers: this._buffer.maxPeers,
            totalSlots: this._buffer.totalSlots,
            workerThreshold: this._workerThreshold,
        });
    }

    /** @returns {PeerPhaseBuffer|null} */
    getBuffer() { return this._buffer; }

    /**
     * Calibrate AGUWA from a GPS time source.
     * Sets _correctionMs so that aguwa.now() ≈ GPS Unix ms.
     * Should be called once at startup when MA-902 telemetry is available.
     *
     * @param {number} gpsTimeUnix - GPS time in Unix seconds from MA-902
     */
    calibrateFromGPS(gpsTimeUnix) {
        if (!gpsTimeUnix || typeof gpsTimeUnix !== 'number') return;
        const gpsMs = gpsTimeUnix * 1000;
        const systemMs = Date.now();
        const deltaMs = gpsMs - systemMs;

        // Only apply if the delta is meaningful (>10ms) and not insane (>60s)
        if (Math.abs(deltaMs) < 10) {
            log.debug('AGUWA GPS calibration: system clock already within 10ms of GPS');
            return;
        }
        if (Math.abs(deltaMs) > 60_000) {
            log.warn(`AGUWA GPS calibration: delta ${deltaMs}ms too large (>60s), skipping — check system clock`);
            return;
        }

        this._correctionMs = deltaMs;
        log.info(`AGUWA GPS calibrated | offset = ${deltaMs > 0 ? '+' : ''}${deltaMs.toFixed(1)}ms`);
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Public API — Canonical Time
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Returns Kuramoto-corrected Unix-second tick.
     * Drop-in replacement for Math.floor(Date.now() / 1000).
     * Monotonic: never returns value lower than previous call.
     * @returns {number} Unix seconds (integer)
     */
    tick() {
        const t = Math.floor(this._correctedNow() / 1000);
        if (t < this._lastTick) return this._lastTick;
        this._lastTick = t;
        return t;
    }

    /**
     * Returns Kuramoto-corrected millisecond timestamp.
     * Drop-in replacement for Date.now().
     * Monotonic: never returns value lower than previous call.
     * @returns {number} Unix milliseconds
     */
    now() {
        const t = this._correctedNow();
        if (t < this._lastNowMs) return this._lastNowMs;
        this._lastNowMs = t;
        return t;
    }

    /**
     * Current Kuramoto phase offset (0–999ms within the current tick).
     * @returns {number} Milliseconds within current second
     */
    phase() {
        const n = this.now();
        return n - Math.floor(n / 1000) * 1000;
    }

    /**
     * Kuramoto order parameter r ∈ [0, 1].
     * r → 1: all peers phase-locked (healthy).
     * r → 0: desynchronized / incompatible code / Sybil.
     * Returns 1.0 when solo (no peers to compare).
     * @returns {number}
     */
    orderParameter() {
        if (this.peers.size === 0) return 1.0;

        let sumCos = 0;
        let sumSin = 0;
        let count = 0;
        const nowMs = Date.now(); // raw wall clock for staleness check

        for (const peer of this.peers.values()) {
            if (peer.lastArrival === null) continue;
            if (nowMs - peer.lastArrival > AGUWA_CONFIG.staleThresholdMs) continue;
            sumCos += Math.cos(peer.theta);
            sumSin += Math.sin(peer.theta);
            count++;
        }

        if (count === 0) return 1.0;
        return Math.sqrt(sumCos ** 2 + sumSin ** 2) / count;
    }

    /**
     * Human-readable health assessment from order parameter.
     * @returns {'healthy'|'degraded'|'critical'|'solo'}
     */
    health() {
        const r = this.orderParameter();
        if (this.peers.size === 0) return 'solo';
        if (r >= AGUWA_CONFIG.orderHealthy) return 'healthy';
        if (r >= AGUWA_CONFIG.orderCritical) return 'degraded';
        return 'critical';
    }

    // ───────────────────────────────────────────────────────────────────────────
    // PRAHARI ↔ AGUWA Bidirectional Link
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Register callback that receives Kuramoto prediction residuals as entropy.
     * PRAHARI calls this to siphon timing jitter into the sponge.
     *
     * @param {(residualBytes: Uint8Array) => void} fn
     */
    registerEntropyCallback(fn) {
        if (typeof fn === 'function') this._entropyCallback = fn;
    }

    /**
     * Update network jitter level from PRAHARI mesh arrival statistics.
     * Modulates Kuramoto coupling strength: high jitter → conservative coupling,
     * low jitter → tighter coupling (more trust in observations).
     *
     * @param {number} jitterLevel — normalized [0, 1]
     */
    setNetworkJitter(jitterLevel) {
        this._networkJitter = Math.max(0, Math.min(1, jitterLevel));
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Peer Management
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Register or update a peer's capabilities.
     * Called when a HELLO/WELCOME arrives with capabilities payload.
     * @param {string} nodeId
     * @param {Object} capabilities
     */
    addPeer(nodeId, capabilities) {
        if (!this.peers.has(nodeId)) {
            let slotIndex = -1;
            if (this._buffer) {
                slotIndex = this._buffer.allocateSlot(nodeId);
                if (slotIndex === -1) {
                    log.warn('PeerPhaseBuffer full — peer added without buffer slot', { peer: nodeId.slice(0, 8) });
                }
            }
            const state = new PeerPhaseState(
                nodeId, capabilities,
                slotIndex !== -1 ? this._buffer : null,
                slotIndex,
            );
            this.peers.set(nodeId, state);
            log.debug(`Peer added`, { peer: nodeId.slice(0, 8), aguwa: state.aguwaScore.toFixed(3), bufferSlot: slotIndex });
        } else {
            // Update capabilities if peer reconnects
            const state = this.peers.get(nodeId);
            state.capabilities = capabilities;
            state.timeTrust = state._scoreTrust(capabilities);
            state.hardwareScore = state._scoreHardware(capabilities);
        }
    }

    /**
     * Remove a peer (disconnected, evicted).
     * @param {string} nodeId
     */
    removePeer(nodeId) {
        this.peers.delete(nodeId);
        if (this._buffer) this._buffer.freeSlot(nodeId);
    }

    /**
     * Update a peer's KARMA score (0–1).
     * Called by the KARMA rate limiter / reputation system.
     * @param {string} nodeId
     * @param {number} karma Normalized 0–1
     */
    updateKarma(nodeId, karma) {
        const peer = this.peers.get(nodeId);
        if (peer) peer.karmaScore = Math.max(0, Math.min(1, karma));
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Weighted Ternary Admission (Phase 3)
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Compute admission verdict for an incoming peer.
     *
     * Uses HELLO payload (capabilities, persistentId) + persisted KARMA
     * to produce a ternary admission decision:
     *   AFFIRM (+1) — peerCount < 80% maxPeers
     *   ABSTAIN (0) — peerCount ∈ [80%, 100%)
     *   DENY   (-1) — peerCount ≥ maxPeers
     *
     * @param {Object} params
     * @param {Object} params.capabilities — from HELLO payload
     * @param {string} [params.persistentId] — for KARMA lookup
     * @param {Object} [params.karmaModel] — KarmaTrustModel instance
     * @returns {{ verdict: number, priority: number, lowestPeer: string|null }}
     */
    admissionVerdict({ capabilities, persistentId, karmaModel } = {}) {
        const maxPeers = this._buffer ? this._buffer.maxPeers : 128;
        const count = this.peers.size;
        const util = count / maxPeers;

        // Compute admission priority score for this incoming peer
        const priority = this._admissionPriority({ capabilities, persistentId, karmaModel });

        let verdict;
        if (util < 0.8) {
            verdict = 1;  // AFFIRM
        } else if (util < 1.0) {
            verdict = 0;  // ABSTAIN
        } else {
            verdict = -1; // DENY
        }

        // On DENY, find lowest-priority connected peer for potential eviction
        let lowestPeer = null;
        if (verdict === -1) {
            let lowestScore = Infinity;
            for (const [peerId, state] of this.peers) {
                const score = state.aguwaScore;
                if (score < lowestScore) {
                    lowestScore = score;
                    lowestPeer = peerId;
                }
            }
            // If incoming > lowest connected → evict lowest
            if (lowestPeer && priority > lowestScore) {
                verdict = 1; // Upgrade to AFFIRM (evict lowest)
            }
        }

        return { verdict, priority, lowestPeer, maxPeers, utilization: util };
    }

    /**
     * Compute admission priority score from HELLO payload + KARMA.
     * admissionPriority = 0.3×karmaWeight + 0.3×hardwareWeight + 0.2×returningBonus + 0.2×maniTrust
     * @private
     */
    _admissionPriority({ capabilities, persistentId, karmaModel } = {}) {
        // KARMA weight: lookup persistentId → trust level
        let karmaWeight = 0;
        let returningBonus = 0;
        if (karmaModel && persistentId) {
            const { level } = karmaModel.getTrustLevel(persistentId);
            karmaWeight = [0, 0.25, 0.5, 1.0][level] ?? 0;
            returningBonus = level > 0 ? 1.0 : 0; // Known node returning
        }

        // Hardware weight: log-scale TOPS
        const tops = capabilities?.totalTops || 0;
        const hardwareWeight = tops > 0 ? Math.min(1, Math.log2(tops + 1) / 7) : 0.1;

        // MANI trust weight
        const maniTrust = capabilities?.maniTrust || 'UNSYNC';
        const maniWeights = { QUANTUM: 1.0, ATOMIC: 0.95, GPS: 0.85, PTP: 0.75, NTP: 0.4, UNSYNC: 0.1 };
        const maniWeight = maniWeights[maniTrust] ?? 0.1;

        return 0.3 * karmaWeight + 0.3 * hardwareWeight + 0.2 * returningBonus + 0.2 * maniWeight;
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Kuramoto Update — THE 4th Signal
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Process a heartbeat arrival from peer j.
     * This IS the Kuramoto coupling — zero extra bytes.
     *
     * Called by pulse-sync on every received heartbeat:
     *   aguwa.onHeartbeat(nodeId, receivedAtMs)
     *
     * @param {string} nodeId   Sending peer's node ID
     * @param {number} arrivalMs  Local wall-clock time heartbeat was received (Date.now())
     */
    onHeartbeat(nodeId, arrivalMs) {
        const peer = this.peers.get(nodeId);
        if (!peer) return; // Unknown peer — skip

        // Capture prediction BEFORE recordArrival() overwrites it
        const previousPrediction = peer.predictedArrival;
        peer.recordArrival(arrivalMs);

        if (previousPrediction === null) return; // First heartbeat — no prediction to compare

        // Phase error: actual arrival vs predicted (using saved prediction)
        const errorMs = arrivalMs - previousPrediction;

        // Map error to phase using the OBSERVED period (not hardcoded 1000ms).
        // One heartbeat period = 2π radians. Dynamic scaling adapts to any
        // heartbeat interval (1s tests, 30s production, arbitrary future values).
        const period = peer._estimatedPeriodMs || 1000; // fallback during bootstrap
        const phaseError = (errorMs / period) * 2 * Math.PI;

        // Update peer's phase estimate
        peer.theta += phaseError;
        // Normalize to [-π, π]
        peer.theta = ((peer.theta + Math.PI) % (2 * Math.PI)) - Math.PI;
        if (peer.theta < -Math.PI) peer.theta += 2 * Math.PI;

        // Determine coupling strength based on trust pair
        const K = this._couplingForPeer(peer);

        // Modulate coupling by network jitter from PRAHARI mesh source.
        // High jitter → scale down (be conservative about corrections).
        // jitter=0 → full K, jitter=1 → K * 0.3 (never zero — always some coupling).
        const jitterScale = 1 - 0.7 * this._networkJitter;
        const effectiveK = K * jitterScale;

        // Kuramoto update with e-weighted coupling decay:
        //   Δcorrection = K · A_j · e^{-|θ|} · sin(θ)
        // e^{-|θ|} creates non-linear gravitational pull:
        //   - Near resonance (θ≈0): e^0 = 1, full coupling strength
        //   - Distant peers (|θ|≫0): coupling decays exponentially
        // This dampens outlier influence and accelerates convergence
        // at the mixed-radix optimal economy of e ≈ 2.718.
        const A_j = peer.aguwaScore;
        const delta = effectiveK * A_j * Math.exp(-Math.abs(peer.theta)) * Math.sin(peer.theta);

        // Convert radians back to ms (2π = one heartbeat period)
        const deltaMs = (delta / (2 * Math.PI)) * period;

        // Clamp to prevent runaway correction
        const clampedMs = Math.max(-AGUWA_CONFIG.maxDriftMs,
            Math.min(AGUWA_CONFIG.maxDriftMs, deltaMs));

        // Apply correction (exponential smoothing — don't jump)
        this._correctionMs += clampedMs * 0.1; // 10% per observation

        // Track propagation delay: absolute error after correction
        peer.recordError(Math.abs(errorMs));

        // ── Feed Kuramoto residual to PRAHARI sponge as entropy ──
        // The prediction error LSBs contain genuine network jitter that is
        // unpredictable even to an adversary controlling one endpoint.
        if (this._entropyCallback) {
            const buf = new Uint8Array(8);
            const dv = new DataView(buf.buffer);
            dv.setFloat64(0, errorMs, false);
            this._entropyCallback(buf);
        }

        if (Math.abs(clampedMs) > 50) {
            log.debug(`Kuramoto correction`, {
                peer: nodeId.slice(0, 8),
                errorMs: errorMs.toFixed(1), A_j: A_j.toFixed(3),
                K: K.toFixed(3),
                deltaMs: clampedMs.toFixed(1),
                totalCorrection: this._correctionMs.toFixed(1),
            });
        }

        // Event-driven capacity recalculation (rate-limited to 2s in buffer)
        if (this._buffer) {
            this._buffer.recalculateCapacity(this._networkJitter, this.orderParameter());
        }

        // ── Worker batch dispatch (Phase 5) ──
        // When peer count exceeds threshold, offload theta computation to Worker.
        // Worker reads/writes theta via Atomics on the SharedArrayBuffer — zero copy.
        if (this._worker && this._buffer && this.peers.size > this._workerThreshold && !this._workerInFlight) {
            const activeSlots = [...this._buffer.activeSlots()];
            if (activeSlots.length > 0) {
                this._workerInFlight = true;
                this._worker.postMessage({
                    sharedBuffer: this._buffer.getSharedBuffer(),
                    overflowBuffer: this._buffer.getOverflowBuffer(),
                    primarySlots: this._buffer.primarySlotCount,
                    activeSlots,
                    omega: this._omega,
                    couplingConfig: {
                        high: AGUWA_CONFIG.couplingHigh,
                        mid: AGUWA_CONFIG.couplingMid,
                        low: AGUWA_CONFIG.couplingLow,
                        min: AGUWA_CONFIG.couplingMin,
                    },
                    weights: {
                        timeTrust: AGUWA_CONFIG.weightTimeTrust,
                        karma: AGUWA_CONFIG.weightKarma,
                        hardware: AGUWA_CONFIG.weightHardware,
                        stability: AGUWA_CONFIG.weightStability,
                    },
                    defaultCoupling: AGUWA_CONFIG.couplingMid, // conservative batch coupling
                });
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Adaptive Tolerance
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Get the appropriate timestamp tolerance for a peer pair.
     * Used by CommitReveal and other validators.
     * @param {string} peerNodeId
     * @returns {number} Tolerance in milliseconds
     */
    getToleranceForPeer(peerNodeId) {
        const peer = this.peers.get(peerNodeId);
        if (!peer) return ManiPhaseTolerance[ManiTrustLevel.UNSYNC]; // 30s default

        const myTrust = this._getMyTrustLevel();
        const peerTrust = peer.capabilities?.maniTrust || ManiTrustLevel.UNSYNC;

        // Use the LESS precise of the two sides
        const myTol = ManiPhaseTolerance[myTrust] ?? ManiPhaseTolerance[ManiTrustLevel.UNSYNC];
        const peerTol = ManiPhaseTolerance[peerTrust] ?? ManiPhaseTolerance[ManiTrustLevel.UNSYNC];
        return Math.max(myTol, peerTol);
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Status / Debugging
    // ───────────────────────────────────────────────────────────────────────────

    /**
     * Full status snapshot for API / debugging.
     * @returns {Object}
     */
    getStatus() {
        const r = this.orderParameter();
        const peerStates = [];
        for (const [id, peer] of this.peers) {
            peerStates.push({
                nodeId: id.slice(0, 8) + '...',
                theta: peer.theta.toFixed(4),
                aguwaScore: peer.aguwaScore.toFixed(3),
                timeTrust: peer.timeTrust.toFixed(2),
                karma: peer.karmaScore.toFixed(2),
                hardware: peer.hardwareScore.toFixed(2),
                stability: peer.stabilityScore.toFixed(2),
                variance: peer.arrivalDeltaVariance === Infinity
                    ? 'Infinity' : peer.arrivalDeltaVariance.toFixed(1),
                propagationDelayMs: peer.propagationDelayMs,
            });
        }

        return {
            initialized: this._initialized,
            omega: this._omega,
            correctionMs: this._correctionMs,
            tick: this.tick(),
            nowMs: this.now(),
            phase: this.phase(),
            orderParameter: r,
            health: this.health(),
            peerCount: this.peers.size,
            networkJitter: this._networkJitter,
            entropyLinked: this._entropyCallback !== null,
            buffer: this._buffer ? {
                peerCount: this._buffer.peerCount,
                maxPeers: this._buffer.maxPeers,
                totalSlots: this._buffer.totalSlots,
                utilization: +this._buffer.utilization.toFixed(3),
                hasOverflow: this._buffer.hasOverflow,
            } : null,
            peers: peerStates,
        };
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Internal
    // ───────────────────────────────────────────────────────────────────────────

    /** Raw corrected timestamp (not yet clamped for monotonicity) */
    _correctedNow() {
        return Date.now() + this._correctionMs;
    }

    /**
     * Get propagation delay estimates for all peers with sufficient data.
     * Used by GeoProofService to create distance bounds from heartbeat timing.
     * @returns {Map<string, {delayMs: number, trustLevel: string}>}
     */
    getPropagationDelays() {
        const delays = new Map();
        for (const [nodeId, peer] of this.peers) {
            const delay = peer.propagationDelayMs;
            if (delay !== null) {
                delays.set(nodeId, {
                    delayMs: delay,
                    trustLevel: peer.capabilities?.maniTrust || ManiTrustLevel.UNSYNC,
                    aguwaScore: peer.aguwaScore,
                });
            }
        }
        return delays;
    }

    /**
     * Compute the optimal ACT epoch buffer from observed propagation delays.
     * Uses the 95th percentile of all peer delays to estimate worst-case
     * propagation time, then converts to epochs (minimum 2).
     *
     * @returns {number} Recommended epoch buffer N (minimum 2)
     */
    getACTEpochBuffer() {
        const delays = this.getPropagationDelays();
        if (delays.size === 0) return 2; // No data → conservative default

        const allDelays = [];
        for (const { delayMs } of delays.values()) {
            allDelays.push(delayMs);
        }

        // 95th percentile of propagation delays
        allDelays.sort((a, b) => a - b);
        const p95Idx = Math.min(allDelays.length - 1, Math.floor(allDelays.length * 0.95));
        const worstCaseMs = allDelays[p95Idx];

        // Convert to epoch count: how many epochs does it take for a rumor to reach
        // the farthest peer with high confidence? Include 3x safety margin.
        // Import epochHours lazily to avoid circular deps
        const epochMs = 6 * 60 * 60 * 1000; // default 6h epoch
        const rumorsNeeded = Math.ceil((worstCaseMs * 3) / epochMs);

        return Math.max(2, rumorsNeeded + 1);
    }

    /** Get our own MANI trust level */
    _getMyTrustLevel() {
        try {
            const detector = getManiTimeDetector();
            return detector.getTrustLevel();
        } catch {
            return ManiTrustLevel.UNSYNC;
        }
    }

    /** Coupling strength K based on our trust vs peer's trust */
    _couplingForPeer(peer) {
        const myTrust = this._getMyTrustLevel();
        const peerTrust = peer.capabilities?.maniTrust || ManiTrustLevel.UNSYNC;

        const HIGH_TRUST = new Set([ManiTrustLevel.QUANTUM, ManiTrustLevel.ATOMIC, ManiTrustLevel.GPS, ManiTrustLevel.PTP]);
        const myHigh = HIGH_TRUST.has(myTrust);
        const peerHigh = HIGH_TRUST.has(peerTrust);

        if (myTrust === ManiTrustLevel.UNSYNC || peerTrust === ManiTrustLevel.UNSYNC) {
            return AGUWA_CONFIG.couplingMin;
        }
        if (myHigh && peerHigh) return AGUWA_CONFIG.couplingHigh;
        if (myHigh || peerHigh) return AGUWA_CONFIG.couplingMid;
        return AGUWA_CONFIG.couplingLow;
    }

    /**
     * Detect peers whose phase diverges persistently from the group.
     * Different oracle hash → different ω → phase drifts despite coupling.
     * Returns list of suspect nodeIds with divergence metrics.
     *
     * @returns {Array<{nodeId: string, theta: number, divergence: number, stability: number}>}
     */
    detectDivergentPeers() {
        if (this.peers.size < 2) return [];

        // Compute mean phase vector
        const nowMs = Date.now();
        let sumCos = 0, sumSin = 0, count = 0;
        const active = [];

        for (const [id, peer] of this.peers) {
            if (peer.lastArrival === null) continue;
            if (nowMs - peer.lastArrival > AGUWA_CONFIG.staleThresholdMs) continue;
            sumCos += Math.cos(peer.theta);
            sumSin += Math.sin(peer.theta);
            count++;
            active.push({ id, peer });
        }

        if (count < 2) return [];

        const meanTheta = Math.atan2(sumSin / count, sumCos / count);
        const suspects = [];

        for (const { id, peer } of active) {
            // Angular distance from mean phase [0, π]
            let delta = Math.abs(peer.theta - meanTheta);
            if (delta > Math.PI) delta = 2 * Math.PI - delta;

            // Divergent if: far from mean AND has high variance (not converging)
            // Threshold: >π/2 radians from mean (90°) = clearly different frequency
            if (delta > Math.PI / 2) {
                suspects.push({
                    nodeId: id,
                    theta: +peer.theta.toFixed(4),
                    divergence: +delta.toFixed(4),
                    stability: +peer.stabilityScore.toFixed(3),
                });
            }
        }

        return suspects;
    }

    /**
     * Shut down Worker thread and release resources.
     * Safe to call multiple times.
     */
    destroy() {
        if (this._worker) {
            this._worker.terminate();
            this._worker = null;
            this._workerInFlight = false;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton
// ─────────────────────────────────────────────────────────────────────────────

let _instance = null;

/**
 * Get the global AGUWA instance (lazy singleton).
 * Call aguwa.init(codeHash) once at startup.
 * @returns {Aguwa}
 */
export function getAguwa() {
    if (!_instance) _instance = new Aguwa();
    return _instance;
}

// Convenience — import { aguwa } from './aguwa.js'
export const aguwa = getAguwa();

export { AGUWA_CONFIG, PeerPhaseState, Aguwa };
export default aguwa;
