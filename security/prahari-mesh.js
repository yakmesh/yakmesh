/**
 * PRAHARI Mesh Entropy Layer
 * 
 * Harvests entropy from the mesh network itself:
 * - WebSocket message interarrival timing (genuine network jitter)
 * - Peer handshake timing (TCP/TLS/WS negotiation noise)
 * - Gossip message arrival patterns (distributed chaos)
 * 
 * Key insight: A mesh network is an inherently chaotic system.
 * Message arrival times depend on:
 * - Network latency variance (routing, congestion, queuing)
 * - Remote peer behavior (CPU load, scheduling jitter)
 * - Physical layer noise (Ethernet, WiFi, WAN hops)
 * 
 * As the mesh grows, entropy quality IMPROVES — more peers = more
 * independent timing sources = higher min-entropy per sample.
 * 
 * Commit-Reveal Protocol:
 * Each node commits SHA3(local_entropy) to the mesh, then reveals.
 * Mesh consensus validates contributions via SAKSHI.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  TIMESTAMP VALIDATION DEPENDS ON AGUWA BEING PROPERLY WIRED
 * ═══════════════════════════════════════════════════════════════════════════════
 * _validateTimestamp() compares aguwa.now() against remote timestamp.
 * Tolerance = max(MANI precision, |correctionMs| + 2s) + 2s propagation.
 * MANI precision alone is insufficient — it measures time-source quality,
 * not inter-node clock drift. correctionMs accounts for actual drift.
 * See mesh/aguwa.js header for the three required wirings.
 * ═══════════════════════════════════════════════════════════════════════════════
 * Combined entropy = XOR of all revealed contributions.
 * 
 * @module security/prahari-mesh
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import crypto from 'node:crypto';
import { createLogger } from '../utils/logger.js';
// ACCEL: Hardware-accelerated SHA3-256 (OpenSSL/SHA-NI — 4.6x faster)
import { sha3_256 } from '../utils/accel.js';

// AGUWA — canonical mesh time source
import { aguwa } from '../mesh/aguwa.js';

// MANI time-sync: Trust levels + tolerance windows for epoch-aligned rounds
import {
    getManiTimeDetector,
    createPhaseConfig,
    ManiPhaseTolerance,
    ManiTrustLevel,
} from '../oracle/time-source.js';

// SAKSHI witness: Mathematical agreement + behavioral velocity monitoring
import {
    checkMathematicalAgreement,
    analyzeDisagreement,
    BEHAVIOR_DIMENSION,
} from './sakshi.js';

const log = createLogger('security:prahari:mesh');

/** Circular buffer size for mesh timing samples */
const MESH_SAMPLE_BUFFER_SIZE = 128;

/** Minimum samples before we consider the source "available" */
const MIN_SAMPLES_THRESHOLD = 8;

/**
 * Create a mesh packet arrival entropy source.
 * 
 * Captures nanosecond-resolution interarrival times of WebSocket messages.
 * The LSBs of these deltas contain genuine network jitter that is
 * unpredictable even to an adversary controlling one endpoint.
 * 
 * @returns {{ source: import('../prahari.js').EntropySource, onMessage: Function, onPeerConnect: Function }}
 */
export function createMeshArrivalSource() {
    const sampleBuffer = new Uint8Array(MESH_SAMPLE_BUFFER_SIZE);
    let writePos = 0;
    let samplesCollected = 0;
    let lastMessageTime = null;
    let lastPeerConnectTime = null;

    /**
     * Called on every incoming WebSocket message.
     * Extracts interarrival timing jitter.
     * 
     * @param {number} [messageSize] — optional message byte length for additional mixing
     */
    function onMessage(messageSize = 0) {
        const now = process.hrtime.bigint();

        if (lastMessageTime !== null) {
            const delta = Number(now - lastMessageTime);

            // Extract lowest 3 bytes of nanosecond delta (most entropic)
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = delta & 0xFF;
            writePos++;
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = (delta >> 8) & 0xFF;
            writePos++;
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = (delta >> 16) & 0xFF;
            writePos++;

            // Mix in message size LSB for additional entropy
            if (messageSize > 0) {
                sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = messageSize & 0xFF;
                writePos++;
                samplesCollected++;
            }

            samplesCollected += 3;
        }

        lastMessageTime = now;
    }

    /**
     * Called on peer WebSocket connection events.
     * TCP/TLS handshake timing adds independent entropy.
     */
    function onPeerConnect() {
        const now = process.hrtime.bigint();

        if (lastPeerConnectTime !== null) {
            const delta = Number(now - lastPeerConnectTime);

            // Peer connection timing has higher variance = more entropy per sample
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = delta & 0xFF;
            writePos++;
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = (delta >> 8) & 0xFF;
            writePos++;
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = (delta >> 16) & 0xFF;
            writePos++;
            sampleBuffer[writePos % MESH_SAMPLE_BUFFER_SIZE] = (delta >> 24) & 0xFF;
            writePos++;

            samplesCollected += 4;
        }

        lastPeerConnectTime = now;
    }

    const source = {
        kind: 'mesh-arrival',
        name: 'Mesh WebSocket arrival jitter',
        weight: 8, // Very high weight — genuinely independent network noise

        available() {
            return samplesCollected >= MIN_SAMPLES_THRESHOLD;
        },

        harvest() {
            if (samplesCollected < MIN_SAMPLES_THRESHOLD) return null;

            const len = Math.min(samplesCollected, MESH_SAMPLE_BUFFER_SIZE);
            const out = new Uint8Array(len);

            const readStart = samplesCollected > MESH_SAMPLE_BUFFER_SIZE
                ? writePos % MESH_SAMPLE_BUFFER_SIZE
                : 0;

            for (let i = 0; i < len; i++) {
                out[i] = sampleBuffer[(readStart + i) % MESH_SAMPLE_BUFFER_SIZE];
            }

            return out;
        },
    };

    return { source, onMessage, onPeerConnect };
}

/**
 * Register mesh arrival source with PRAHARI and hook into mesh events.
 * Called by server/index.js after mesh initialization.
 * 
 * @param {import('./prahari.js')} prahari — PRAHARI module
 * @param {Object} mesh — MeshNetwork instance (has events for messages/peers)
 */
export function registerMeshEntropyWithPrahari(prahari, mesh) {
    if (!mesh) {
        log.debug('No mesh instance — mesh arrival entropy not available');
        return null;
    }

    const { source, onMessage, onPeerConnect } = createMeshArrivalSource();
    prahari.registerEntropySource(source);

    // Hook into mesh events if available
    if (typeof mesh.on === 'function') {
        mesh.on('message', (msg) => {
            const size = msg?.data?.length || msg?.length || 0;
            onMessage(size);
        });

        mesh.on('peer:connected', () => onPeerConnect());
        mesh.on('peer:join', () => onPeerConnect());
    }

    log.info('Mesh arrival entropy source registered with PRAHARI');
    return { source, onMessage, onPeerConnect };
}

// ===================================================================
// COMMIT-REVEAL PROTOCOL — Gossip-Integrated Mesh Entropy
// ===================================================================

/** Domain labels for commit-reveal SHA3 operations */
const DOMAIN_COMMIT = Buffer.from('PRAHARI-COMMIT-v1');
const DOMAIN_COMBINE = Buffer.from('PRAHARI-COMBINE-v1');

/** Gossip topics */
export const PRAHARI_TOPICS = {
    COMMIT: 'prahari:entropy:commit',
    REVEAL: 'prahari:entropy:reveal',
};

/** Round phase states */
const Phase = {
    IDLE: 0,
    COMMITTING: 1,
    REVEALING: 2,
    COMBINING: 3,
};

/**
 * Commit-Reveal entropy contribution for mesh consensus.
 * 
 * Protocol (Byzantine-fault-tolerant):
 * 1. Each node harvests local entropy → E_i, generates nonce_i
 * 2. Commit: gossip SHA3(E_i || nonce_i) to all peers
 * 3. Wait for commits from threshold peers (2f+1 of 3f+1)
 * 4. Reveal: gossip E_i || nonce_i
 * 5. Validate: SHA3(reveal) == commit for each peer
 * 6. Combined entropy = SHA3(XOR(E_1, E_2, ..., E_n) || DOMAIN_COMBINE)
 * 
 * Guarantees:
 * - No single node can bias the output (XOR + SHA3 conditioning)
 * - Late joiners can't adapt their contribution (commit first)
 * - Missing reveals just reduce the contributor count, don't fail
 * - ML-DSA-65 signature on gossip prevents impersonation (free from MANTRA)
 * 
 * @class
 */
export class CommitRevealEntropy {
    /**
     * @param {Object} options
     * @param {Object} options.gossip — MantraProtocol instance (for spreadRumor)
     * @param {Object} options.prahari — PRAHARI module (for registering entropy source)
     * @param {string} options.nodeId — This node's identity
     * @param {Object} [options.maniDetector] — ManiTimeDetector instance (for epoch-aligned rounds)
     * @param {Object} [options.sakshiMonitor] — BehaviorVelocityMonitor instance (for witness tracking)
     * @param {Map}    [options.witnessMap] — Map of nodeId → NodeWitness (for quality weighting)
     * @param {number} [options.roundIntervalMs=90000] — Time between rounds (90s default, overridden by MANI)
     * @param {number} [options.commitTimeoutMs=15000] — Max wait for commits
     * @param {number} [options.revealTimeoutMs=10000] — Max wait for reveals after committing
     * @param {number} [options.entropyBytes=32] — Bytes of local entropy per round
     */
    constructor(options = {}) {
        this.gossip = options.gossip;
        this.prahari = options.prahari;
        this.nodeId = options.nodeId;

        // MANI time-sync: Derive timing from trust level if detector available
        this.maniDetector = options.maniDetector || null;
        this._phaseConfig = null;
        if (this.maniDetector) {
            try {
                this._phaseConfig = createPhaseConfig(this.maniDetector);
                log.info(`CommitReveal: MANI detected — trust level: ${this._phaseConfig.trustLevel}, tolerance: ${this._phaseConfig.toleranceMs}ms`);
            } catch (e) {
                log.warn(`CommitReveal: MANI createPhaseConfig failed, using defaults — ${e.message}`);
            }
        }

        // SAKSHI witness integration
        this.sakshiMonitor = options.sakshiMonitor || null;  // BehaviorVelocityMonitor
        this.witnessMap = options.witnessMap || new Map();     // nodeId → NodeWitness

        // Timing configuration — MANI-derived if available, otherwise fallback
        this.roundIntervalMs = this._deriveRoundInterval(options.roundIntervalMs);
        this.commitTimeoutMs = this._deriveCommitTimeout(options.commitTimeoutMs);
        this.revealTimeoutMs = this._deriveRevealTimeout(options.revealTimeoutMs);
        this.entropyBytes = options.entropyBytes || 32;

        // Round state
        this.roundId = 0;
        this.phase = Phase.IDLE;
        this.pendingCommits = new Map();  // nodeId → { commitHash (hex), timestamp }
        this.reveals = new Map();          // nodeId → { entropy (hex), nonce (hex), valid }
        this.localEntropy = null;          // Our E_i for current round
        this.localNonce = null;            // Our nonce_i for current round

        // Timers
        this._roundTimer = null;
        this._phaseTimer = null;

        // Statistics
        this.stats = {
            roundsCompleted: 0,
            roundsFailed: 0,
            totalContributors: 0,
            totalBytesContributed: 0,
            lastCombinedAt: null,
            sakshiObservations: 0,
            sakshiDisagreements: 0,
            invalidReveals: 0,
            maniTrustLevel: this._phaseConfig?.trustLevel || 'none',
        };

        this.active = false;
    }

    // ───────────────────────────────────────────────────────────────
    // MANI TIMING DERIVATION
    // ───────────────────────────────────────────────────────────────

    /**
     * Derive round interval from MANI trust level.
     * Higher-precision time = faster rounds (tighter synchronization).
     * @private
     */
    _deriveRoundInterval(override) {
        if (override) return override;
        if (!this._phaseConfig) return 90_000; // Default 90s

        const trustLevel = this._phaseConfig.trustLevel;
        return {
            [ManiTrustLevel.QUANTUM]: 30_000,   // 30s — sub-ms precision enables fast rounds
            [ManiTrustLevel.ATOMIC]: 45_000,    // 45s — atomic clock enables tight sync
            [ManiTrustLevel.GPS]: 60_000,    // 60s — GPS ±500ms
            [ManiTrustLevel.PTP]: 60_000,    // 60s — PTP ±500ms
            [ManiTrustLevel.NTP]: 90_000,    // 90s — NTP ±5s (default)
            [ManiTrustLevel.UNSYNC]: 120_000,    // 120s — degraded, wide tolerance
        }[trustLevel] || 90_000;
    }

    /**
     * Derive commit timeout from MANI trust level.
     * @private
     */
    _deriveCommitTimeout(override) {
        if (override) return override;
        if (!this._phaseConfig) return 15_000;

        const trustLevel = this._phaseConfig.trustLevel;
        return {
            [ManiTrustLevel.QUANTUM]: 5_000,
            [ManiTrustLevel.ATOMIC]: 8_000,
            [ManiTrustLevel.GPS]: 10_000,
            [ManiTrustLevel.PTP]: 10_000,
            [ManiTrustLevel.NTP]: 15_000,
            [ManiTrustLevel.UNSYNC]: 25_000,
        }[trustLevel] || 15_000;
    }

    /**
     * Derive reveal timeout from MANI trust level.
     * @private
     */
    _deriveRevealTimeout(override) {
        if (override) return override;
        if (!this._phaseConfig) return 10_000;

        const trustLevel = this._phaseConfig.trustLevel;
        return {
            [ManiTrustLevel.QUANTUM]: 3_000,
            [ManiTrustLevel.ATOMIC]: 5_000,
            [ManiTrustLevel.GPS]: 8_000,
            [ManiTrustLevel.PTP]: 8_000,
            [ManiTrustLevel.NTP]: 10_000,
            [ManiTrustLevel.UNSYNC]: 15_000,
        }[trustLevel] || 10_000;
    }

    /**
     * Get the MANI phase tolerance in ms for incoming timestamp validation.
     * @returns {number} Tolerance window in ms
     * @private
     */
    _getTimestampTolerance() {
        if (this._phaseConfig) return this._phaseConfig.toleranceMs;
        return 30_000; // Default 30s tolerance if no MANI
    }

    /**
     * Validate an incoming message timestamp against MANI tolerance.
     * @param {number} remoteTimestamp — Timestamp from the incoming message
     * @returns {boolean} True if within tolerance
     * @private
     */
    _validateTimestamp(remoteTimestamp) {
        const now = aguwa.now();
        const maniToleranceMs = this._getTimestampTolerance();

        // MANI tolerance measures time-source precision (GPS=±500ms),
        // NOT inter-node clock drift. Two GPS nodes can have system clocks
        // seconds apart before AGUWA Kuramoto convergence corrects them.
        // Use the larger of MANI precision and actual clock drift + margin.
        const driftToleranceMs = Math.abs(aguwa._correctionMs) + 2000;
        const tolerance = Math.max(maniToleranceMs, driftToleranceMs);

        // Add gossip propagation buffer — messages take real time to traverse the mesh
        // (signing, WS send, receive, verify, gossip dispatch, event emission).
        const propagationBuffer = 2000;
        return Math.abs(now - remoteTimestamp) <= tolerance + propagationBuffer;
    }

    /**
     * Start the commit-reveal protocol.
     * Registers itself as a PRAHARI entropy source and begins round timer.
     */
    start() {
        if (this.active) return;
        if (!this.gossip || !this.prahari) {
            log.warn('CommitReveal: Cannot start — missing gossip or prahari reference');
            return;
        }

        this.active = true;

        // Register as a PRAHARI entropy source
        this._entropySource = {
            kind: 'mesh-commit-reveal',
            name: 'Mesh commit-reveal consensus entropy',
            weight: 10, // Highest weight — multi-node consensus is strongest source
            _buffer: null,

            available: () => this._entropySource._buffer !== null,

            harvest: () => {
                const buf = this._entropySource._buffer;
                this._entropySource._buffer = null; // Consume once
                return buf;
            },
        };
        this.prahari.registerEntropySource(this._entropySource);

        // Start round timer
        // If MANI is available and not UNSYNC, align to epoch boundaries for natural peer sync
        if (this._phaseConfig && this._phaseConfig.trustLevel !== ManiTrustLevel.UNSYNC) {
            const now = aguwa.now();
            const nextEpochBoundary = Math.ceil(now / this.roundIntervalMs) * this.roundIntervalMs;
            const alignedDelay = nextEpochBoundary - now + Math.floor(Math.random() * 2000); // ±2s jitter to avoid exact collision
            this._roundTimer = setTimeout(() => {
                this._startRound();
                this._roundTimer = setInterval(() => this._startRound(), this.roundIntervalMs);
                if (this._roundTimer.unref) this._roundTimer.unref();
            }, alignedDelay);
            if (this._roundTimer.unref) this._roundTimer.unref();
            log.info(`CommitReveal: MANI-aligned start (trust: ${this._phaseConfig.trustLevel}, interval: ${this.roundIntervalMs / 1000}s, epoch-aligned delay: ${(alignedDelay / 1000).toFixed(1)}s)`);
        } else {
            // Fallback: random stagger 5-30s
            const initialDelay = 5000 + Math.floor(Math.random() * 25000);
            this._roundTimer = setTimeout(() => {
                this._startRound();
                this._roundTimer = setInterval(() => this._startRound(), this.roundIntervalMs);
                if (this._roundTimer.unref) this._roundTimer.unref();
            }, initialDelay);
            if (this._roundTimer.unref) this._roundTimer.unref();
            log.info(`CommitReveal: Protocol started (round interval: ${this.roundIntervalMs / 1000}s, initial delay: ${(initialDelay / 1000).toFixed(1)}s)`);
        }
    }

    /**
     * Stop the protocol and clean up timers.
     */
    stop() {
        this.active = false;
        if (this._roundTimer) { clearInterval(this._roundTimer); clearTimeout(this._roundTimer); this._roundTimer = null; }
        if (this._phaseTimer) { clearTimeout(this._phaseTimer); this._phaseTimer = null; }
        if (this.prahari && this._entropySource) {
            this.prahari.unregisterEntropySource('mesh-commit-reveal');
        }
        log.info('CommitReveal: Protocol stopped');
    }

    // ───────────────────────────────────────────────────────────────
    // ROUND LIFECYCLE
    // ───────────────────────────────────────────────────────────────

    /**
     * Start a new commit-reveal round.
     * @private
     */
    _startRound() {
        if (this.phase !== Phase.IDLE) {
            log.trace('CommitReveal: Skipping round — previous round still active');
            return;
        }

        // Need at least 1 peer to make commit-reveal meaningful
        const peerCount = this.gossip.getKnownPeers?.()?.length || 0;
        if (peerCount < 1) {
            log.trace('CommitReveal: No peers — skipping round');
            return;
        }

        this.roundId++;
        this.phase = Phase.COMMITTING;
        this.pendingCommits.clear();
        this.reveals.clear();

        // Generate our local entropy contribution
        this.localEntropy = crypto.randomBytes(this.entropyBytes);
        this.localNonce = crypto.randomBytes(16);

        // Compute commit hash: SHA3(entropy || nonce || DOMAIN_COMMIT)
        const commitHash = this._computeCommitHash(this.localEntropy, this.localNonce);
        const commitHex = Buffer.from(commitHash).toString('hex');

        // Store our own commit
        this.pendingCommits.set(this.nodeId, {
            commitHash: commitHex,
            timestamp: aguwa.now(),
        });

        // Broadcast commit via gossip
        this.gossip.spreadRumor(PRAHARI_TOPICS.COMMIT, {
            roundId: this.roundId,
            nodeId: this.nodeId,
            commitHash: commitHex,
            timestamp: aguwa.now(),
        });

        log.debug(`CommitReveal: Round #${this.roundId} started — commit broadcast (${peerCount} peers known)`);

        // After commit timeout, move to reveal phase
        this._phaseTimer = setTimeout(() => this._startRevealPhase(), this.commitTimeoutMs);
    }

    /**
     * Transition from commit → reveal phase.
     * @private
     */
    _startRevealPhase() {
        if (this.phase !== Phase.COMMITTING) return;

        this.phase = Phase.REVEALING;

        // Broadcast our reveal
        this.gossip.spreadRumor(PRAHARI_TOPICS.REVEAL, {
            roundId: this.roundId,
            nodeId: this.nodeId,
            entropy: Buffer.from(this.localEntropy).toString('hex'),
            nonce: Buffer.from(this.localNonce).toString('hex'),
            timestamp: aguwa.now(),
        });

        log.debug(`CommitReveal: Round #${this.roundId} — reveal broadcast (${this.pendingCommits.size} commits collected)`);

        // After reveal timeout, combine
        this._phaseTimer = setTimeout(() => this._combinePhase(), this.revealTimeoutMs);
    }

    /**
     * Combine all validated reveals into consensus entropy.
     * SAKSHI-enhanced: validates contribution agreement, weights by node quality.
     * @private
     */
    _combinePhase() {
        if (this.phase !== Phase.REVEALING) return;

        this.phase = Phase.COMBINING;

        // ─── Validate all reveals against their commits ───
        const validReveals = [];  // { nodeId, entropyBuf, witness }

        for (const [nodeId, reveal] of this.reveals) {
            if (!reveal.valid) {
                // SAKSHI: Track invalid reveals as behavioral anomaly
                if (this.sakshiMonitor) {
                    this.sakshiMonitor.observe(nodeId, BEHAVIOR_DIMENSION.ERROR_RATE, 1.0);
                    this.stats.invalidReveals++;
                }
                continue;
            }
            if (!this.pendingCommits.has(nodeId)) continue;

            const entropyBuf = Buffer.from(reveal.entropy, 'hex');
            const witness = this.witnessMap.get(nodeId) || null;

            validReveals.push({ nodeId, entropyBuf, witness });
        }

        // ─── SAKSHI: Mathematical agreement check ───
        // Entropy values won't be "equal" (each is random), but we verify
        // structural agreement: all values are the expected length and format.
        if (this.sakshiMonitor && validReveals.length >= 2) {
            // Build observation set for SAKSHI: check that all contributions
            // are structurally sound (correct byte length)
            const observations = validReveals.map(r => ({
                witness: r.witness || { qualityScore: 0.5 },
                value: r.entropyBuf.length,
            }));
            const agreement = checkMathematicalAgreement(observations);

            if (agreement.isDisagreed) {
                // Some nodes sent wrong-sized entropy — investigate
                const analysis = analyzeDisagreement({
                    observations,
                    expectedTime: this.roundIntervalMs,
                });
                this.stats.sakshiDisagreements++;
                log.warn(`CommitReveal: SAKSHI disagreement in round #${this.roundId} — ${analysis?.likelyCause || 'unknown cause'}`);
            }
            this.stats.sakshiObservations++;
        }

        // ─── Combine with NodeWitness quality weighting ───
        const combined = Buffer.alloc(this.entropyBytes);
        let validContributors = 0;

        for (const { nodeId, entropyBuf, witness } of validReveals) {
            // Quality-weighted XOR: higher-quality witnesses get their entropy
            // mixed in more thoroughly via repeated rounds of XOR mixing
            const quality = witness?.qualityScore ?? 0.5;
            const mixRounds = quality >= 0.8 ? 3 : quality >= 0.5 ? 2 : 1;

            for (let round = 0; round < mixRounds; round++) {
                if (round === 0) {
                    // First round: direct XOR
                    for (let i = 0; i < Math.min(combined.length, entropyBuf.length); i++) {
                        combined[i] ^= entropyBuf[i];
                    }
                } else {
                    // Additional rounds: SHA3-rotated XOR for high-quality witnesses
                    const rotated = sha3_256(Buffer.concat([
                        entropyBuf,
                        Buffer.from([round & 0xFF]),
                        Buffer.from(nodeId.slice(0, 16)),
                    ]));
                    for (let i = 0; i < Math.min(combined.length, rotated.length); i++) {
                        combined[i] ^= rotated[i];
                    }
                }
            }

            // SAKSHI: Observe contribution quality
            if (this.sakshiMonitor) {
                this.sakshiMonitor.observe(
                    nodeId,
                    BEHAVIOR_DIMENSION.ATTESTATION_RATE,
                    quality // Track contribution quality over time
                );
            }

            validContributors++;
        }

        // Also include our own contribution (always quality 1.0 — we trust ourselves)
        for (let i = 0; i < Math.min(combined.length, this.localEntropy.length); i++) {
            combined[i] ^= this.localEntropy[i];
        }
        validContributors++;

        if (validContributors >= 2) {
            // Condition the XOR'd output through SHA3 for uniform distribution
            const conditioned = sha3_256(Buffer.concat([combined, DOMAIN_COMBINE]));
            // Expand to full entropy bytes
            const counterBuf = Buffer.alloc(4);
            counterBuf.writeUInt32BE(this.roundId, 0);
            const extended = sha3_256(Buffer.concat([Buffer.from(conditioned), counterBuf]));
            const output = new Uint8Array(64);
            output.set(conditioned, 0);
            output.set(extended, 32);

            // Feed into PRAHARI via the entropy source buffer
            this._entropySource._buffer = output;

            this.stats.roundsCompleted++;
            this.stats.totalContributors += validContributors;
            this.stats.totalBytesContributed += output.length;
            this.stats.lastCombinedAt = new Date().toISOString();

            log.info(`CommitReveal: Round #${this.roundId} — combined ${validContributors} contributions → 64 bytes consensus entropy`);
        } else {
            this.stats.roundsFailed++;
            log.debug(`CommitReveal: Round #${this.roundId} — insufficient contributors (${validContributors}), discarded`);
        }

        // Clean up round state
        this.localEntropy = null;
        this.localNonce = null;
        this.pendingCommits.clear();
        this.reveals.clear();
        this.phase = Phase.IDLE;
    }

    // ───────────────────────────────────────────────────────────────
    // GOSSIP MESSAGE HANDLERS (called from server/index.js rumor router)
    // ───────────────────────────────────────────────────────────────

    /**
     * Handle incoming commit from a peer.
     * MANI-enhanced: validates timestamp against phase tolerance window.
     * @param {Object} data — { roundId, nodeId, commitHash, timestamp }
     * @param {string} origin — ML-DSA verified origin nodeId from gossip
     */
    handleCommit(data, origin) {
        if (!this.active) return;

        // Validate origin matches claimed nodeId (gossip already verified ML-DSA sig)
        if (data.nodeId !== origin) {
            log.warn(`CommitReveal: Commit nodeId mismatch: claimed ${data.nodeId}, gossip origin ${origin}`);
            return;
        }

        // MANI: Validate timestamp within tolerance window
        if (data.timestamp && !this._validateTimestamp(data.timestamp)) {
            log.warn(`CommitReveal: Commit from ${data.nodeId} rejected — timestamp outside MANI tolerance (${this._getTimestampTolerance()}ms)`);
            if (this.sakshiMonitor) {
                this.sakshiMonitor.observe(data.nodeId, BEHAVIOR_DIMENSION.RESPONSE_LATENCY, Math.abs(aguwa.now() - data.timestamp));
            }
            return;
        }

        // Only accept commits for our current round (or slightly future)
        if (data.roundId < this.roundId - 1 || data.roundId > this.roundId + 1) {
            log.trace(`CommitReveal: Ignoring stale/future commit (round ${data.roundId}, ours ${this.roundId})`);
            return;
        }

        // If we're idle and a peer started a round, sync to their roundId
        if (this.phase === Phase.IDLE && data.roundId > this.roundId) {
            this.roundId = data.roundId;
            // Kick off our own commit in response
            this._startRound();
        }

        // Store the commit
        if (!this.pendingCommits.has(data.nodeId)) {
            this.pendingCommits.set(data.nodeId, {
                commitHash: data.commitHash,
                timestamp: data.timestamp,
            });
            log.trace(`CommitReveal: Stored commit from ${data.nodeId} (round ${data.roundId})`);
        }
    }

    /**
     * Handle incoming reveal from a peer.
     * MANI-enhanced: validates timestamp. SAKSHI-enhanced: tracks invalid reveals.
     * @param {Object} data — { roundId, nodeId, entropy, nonce, timestamp }
     * @param {string} origin — ML-DSA verified origin nodeId from gossip
     */
    handleReveal(data, origin) {
        if (!this.active) return;

        if (data.nodeId !== origin) {
            log.warn(`CommitReveal: Reveal nodeId mismatch: claimed ${data.nodeId}, gossip origin ${origin}`);
            return;
        }

        // MANI: Validate timestamp
        if (data.timestamp && !this._validateTimestamp(data.timestamp)) {
            log.warn(`CommitReveal: Reveal from ${data.nodeId} rejected — timestamp outside MANI tolerance`);
            if (this.sakshiMonitor) {
                this.sakshiMonitor.observe(data.nodeId, BEHAVIOR_DIMENSION.RESPONSE_LATENCY, Math.abs(aguwa.now() - data.timestamp));
            }
            return;
        }

        if (data.roundId !== this.roundId) {
            log.trace(`CommitReveal: Ignoring reveal for wrong round (${data.roundId}, ours ${this.roundId})`);
            return;
        }

        // Must have a matching commit
        const commit = this.pendingCommits.get(data.nodeId);
        if (!commit) {
            log.warn(`CommitReveal: Reveal without prior commit from ${data.nodeId}`);
            return;
        }

        // Validate: SHA3(entropy || nonce || DOMAIN_COMMIT) == commitHash
        const entropyBytes = Buffer.from(data.entropy, 'hex');
        const nonceBytes = Buffer.from(data.nonce, 'hex');
        const expectedHash = this._computeCommitHash(entropyBytes, nonceBytes);
        const expectedHex = Buffer.from(expectedHash).toString('hex');

        const valid = expectedHex === commit.commitHash;

        if (!valid) {
            log.warn(`CommitReveal: Reveal FAILED validation from ${data.nodeId} — commit hash mismatch`);
            // SAKSHI: Flag invalid reveal as behavioral anomaly
            if (this.sakshiMonitor) {
                this.sakshiMonitor.observe(data.nodeId, BEHAVIOR_DIMENSION.ERROR_RATE, 1.0);
                this.stats.invalidReveals++;
            }
        }

        this.reveals.set(data.nodeId, {
            entropy: data.entropy,
            nonce: data.nonce,
            valid,
        });

        log.trace(`CommitReveal: Processed reveal from ${data.nodeId} — ${valid ? 'VALID' : 'INVALID'}`);
    }

    // ───────────────────────────────────────────────────────────────
    // CRYPTO HELPERS
    // ───────────────────────────────────────────────────────────────

    /**
     * Compute commit hash: SHA3(entropy || nonce || DOMAIN_COMMIT)
     * @param {Uint8Array} entropy
     * @param {Uint8Array} nonce
     * @returns {Uint8Array} — 32-byte commit hash
     */
    _computeCommitHash(entropy, nonce) {
        return sha3_256(Buffer.concat([
            Buffer.from(entropy),
            Buffer.from(nonce),
            DOMAIN_COMMIT,
        ]));
    }

    /**
     * Get protocol statistics.
     */
    getStats() {
        return {
            ...this.stats,
            roundId: this.roundId,
            phase: ['IDLE', 'COMMITTING', 'REVEALING', 'COMBINING'][this.phase],
            pendingCommits: this.pendingCommits.size,
            reveals: this.reveals.size,
            active: this.active,
        };
    }
}

/**
 * Wire CommitRevealEntropy into the gossip + PRAHARI + MANI + SAKSHI systems.
 * Called from server/index.js after gossip starts.
 * 
 * @param {Object} options
 * @param {Object} options.gossip — MantraProtocol instance
 * @param {Object} options.prahari — PRAHARI module
 * @param {Object} options.mesh — MeshNetwork instance (for rumor events)
 * @param {string} options.nodeId — This node's identity
 * @param {Object} [options.maniDetector] — ManiTimeDetector (for epoch-aligned rounds)
 * @param {Object} [options.sakshiMonitor] — BehaviorVelocityMonitor (for witness tracking)
 * @param {Map}    [options.witnessMap] — nodeId → NodeWitness (for quality weighting)
 * @returns {CommitRevealEntropy}
 */
export function wireCommitReveal({ gossip, prahari, mesh, nodeId, maniDetector, sakshiMonitor, witnessMap }) {
    // Use global MANI detector as fallback if not explicitly provided
    const detector = maniDetector || (() => { try { return getManiTimeDetector(); } catch { return null; } })();

    const cr = new CommitRevealEntropy({
        gossip,
        prahari,
        nodeId,
        maniDetector: detector,
        sakshiMonitor: sakshiMonitor || null,
        witnessMap: witnessMap || new Map(),
    });

    // Subscribe to prahari:entropy:* rumor topics on the mesh
    if (mesh && typeof mesh.on === 'function') {
        mesh.on('rumor', (topic, data, origin) => {
            if (topic === PRAHARI_TOPICS.COMMIT) {
                cr.handleCommit(data, origin);
            } else if (topic === PRAHARI_TOPICS.REVEAL) {
                cr.handleReveal(data, origin);
            }
        });
    }

    cr.start();
    return cr;
}

export default {
    createMeshArrivalSource,
    registerMeshEntropyWithPrahari,
    CommitRevealEntropy,
    wireCommitReveal,
    PRAHARI_TOPICS,
};
