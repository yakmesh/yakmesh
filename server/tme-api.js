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
 * TME API — Temporal Mesh Encoding HTTP + Gossip Integration
 * 
 * Wires the TemporalMeshEncoder into the yakmesh mesh network so that
 * messages can be encoded across TIME — temporal slices propagate via
 * MANTRA gossip, and receivers reconstruct from slices + timing proofs.
 * 
 * TIMING STACK INTEGRATION:
 *   TME's entire value proposition is "time IS the redundancy dimension."
 *   Without precise time, temporal hashes are worthless. This module binds
 *   TME to the MANI time source detector + mesh time heartbeat reference
 *   so that every slice timestamp is GPS/atomic-quality, not sloppy Date.now().
 * 
 *   Priority order:
 *     1. Local GPS/atomic (TimeSourceDetector with MA-902 or PTP)
 *     2. Mesh grandmaster time (best peer heartbeat, offset-corrected)
 *     3. System clock (Date.now — last resort, worst tolerance)
 * 
 * Gossip topics:
 *   tme:metadata    — Stream metadata announcement (totalSlices, sliceSize, etc.)
 *   tme:slice       — Individual temporal slice data
 *   tme:timing-proof — Timing proof from a mesh neighbor
 * 
 * HTTP endpoints (mounted at /tme):
 *   POST /tme/encode          — Encode a message into temporal slices and gossip them
 *   POST /tme/decode/:streamId — Attempt to decode/reconstruct a stream
 *   GET  /tme/stream/:streamId — Stream reception status
 *   GET  /tme/stats            — TME subsystem statistics
 * 
 * @module server/tme-api
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Router } from 'express';
import { createLogger } from '../utils/logger.js';
import { TemporalMeshEncoder, TME_CONFIG } from '../mesh/temporal-encoder.js';
import { ManiPhaseTolerance } from '../oracle/time-source.js';

const log = createLogger('server:tme');

// ─── Timing tolerance mapping ───────────────────────────────────────────────
// Map MANI trust levels → TME timingToleranceNs.
// Tighter time source = tighter slice tolerance = better reconstruction.
const TRUST_TO_TOLERANCE_NS = {
    quantum: 100_000,        // 0.1 ms — sub-nanosecond source
    atomic: 1_000_000,      // 1 ms   — PCIe CSAC / Rubidium
    gps: 5_000_000,      // 5 ms   — GPS+PPS (default in TME_CONFIG)
    ptp: 5_000_000,      // 5 ms   — IEEE 1588 PTP
    ntp: 50_000_000,     // 50 ms  — standard NTP
    unsync: 500_000_000,    // 500 ms — degraded, no reliable source
};

/**
 * Get the best available timestamp in nanoseconds.
 *
 * @param {Object|null} timeSource - MANI TimeSourceDetector
 * @param {Function|null} getMeshTimeRef - Returns mesh grandmaster reference
 * @returns {{ timestampNs: bigint, source: string, trustLevel: string }}
 */
function getPreciseTimeNs(timeSource, getMeshTimeRef) {
    // 1. Try local GPS / atomic / PTP
    if (timeSource) {
        const status = timeSource.getStatus();
        const trustLevel = status.trustLevel || 'unsync';

        if (trustLevel !== 'unsync') {
            // MA-902 provides a GPS time ISO string when locked
            if (status.ma902?.gpsTime) {
                const gpsMs = new Date(status.ma902.gpsTime).getTime();
                if (gpsMs > 0) {
                    return {
                        timestampNs: BigInt(gpsMs) * 1_000_000n,
                        source: 'gps:ma902',
                        trustLevel,
                    };
                }
            }

            // Apply offset correction: correctedTime = Date.now() + offset_ns / 1e6
            const offsetNs = status.sources?.ptp?.offset ??
                status.sources?.ntp?.offset ?? 0;
            if (offsetNs !== 0) {
                const correctedMs = Date.now() + (offsetNs / 1_000_000);
                return {
                    timestampNs: BigInt(Math.round(correctedMs)) * 1_000_000n,
                    source: `local:${trustLevel}`,
                    trustLevel,
                };
            }

            // High-precision source detected but no explicit offset — trust local clock
            return {
                timestampNs: BigInt(Date.now()) * 1_000_000n,
                source: `local:${trustLevel}`,
                trustLevel,
            };
        }
    }

    // 2. Try mesh grandmaster reference (time:heartbeat from best peer)
    const meshRef = getMeshTimeRef?.();
    if (meshRef && meshRef.lock && meshRef.receivedAt) {
        // Estimate current mesh time:
        // meshRef.timestamp was the peer's clock when it sent the heartbeat
        // meshRef.receivedAt was our local clock when we received it
        // Elapsed since receipt: Date.now() - meshRef.receivedAt
        const elapsed = Date.now() - meshRef.receivedAt;
        const estimatedNow = meshRef.timestamp + elapsed;
        return {
            timestampNs: BigInt(Math.round(estimatedNow)) * 1_000_000n,
            source: `mesh:${meshRef.trustLevel || 'gps'}`,
            trustLevel: meshRef.trustLevel || 'gps',
        };
    }

    // 3. Fallback: plain system clock
    return {
        timestampNs: BigInt(Date.now()) * 1_000_000n,
        source: 'system',
        trustLevel: 'unsync',
    };
}

/**
 * Create the TME API router.
 * 
 * @param {Object} params
 * @param {Object} params.gossip - GossipProtocol instance
 * @param {Object} params.identity - NodeIdentity instance
 * @param {Object|null} params.timeSource - MANI TimeSourceDetector instance
 * @param {Function|null} params.getMeshTimeRef - () => meshTimeReference object
 * @param {Function} params.writeLimiter - Express rate limiter for writes
 * @param {Function|null} [params.tmeTransportGetter] - () => TmeTransportController (lazy, may be null initially)
 * @returns {{ router: Router, encoder: TemporalMeshEncoder }}
 */
export function createTmeAPI({ gossip, identity, timeSource, getMeshTimeRef, writeLimiter, tmeTransportGetter }) {
    const router = Router();
    const nodeId = identity.identity.nodeId;

    // Initialize the encoder with our node identity
    const encoder = new TemporalMeshEncoder({
        nodeId,
        meshPosition: [0, 0, 0], // Updated if mesh provides position
    });

    // ── Apply initial timing tolerance ──────────────────────────────────────
    const initialTime = getPreciseTimeNs(timeSource, getMeshTimeRef);
    TME_CONFIG.timingToleranceNs = TRUST_TO_TOLERANCE_NS[initialTime.trustLevel]
        ?? TME_CONFIG.timingToleranceNs;

    log.info('TME encoder initialized', {
        nodeId: nodeId.slice(0, 12),
        timeSource: initialTime.source,
        trustLevel: initialTime.trustLevel,
        toleranceNs: TME_CONFIG.timingToleranceNs,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /tme/encode — Encode a message and gossip the slices
    // Body: { message: string, sliceSize?: number }
    // ═══════════════════════════════════════════════════════════════════════════
    router.post('/encode', writeLimiter, (req, res) => {
        // Localhost-only — encoding is a local operation
        // SECURITY: Use raw socket address, NOT req.ip which trusts X-Forwarded-For
        const remoteIp = req.socket?.remoteAddress || '';
        const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
        if (!isLocal) {
            return res.status(403).json({ ok: false, error: 'TME encode is localhost-only' });
        }

        const { message, sliceSize } = req.body;
        if (!message) {
            return res.status(400).json({ ok: false, error: 'message required' });
        }

        try {
            // Get precise timestamp from timing stack
            const timeInfo = getPreciseTimeNs(timeSource, getMeshTimeRef);

            // Update tolerance dynamically based on current trust level
            TME_CONFIG.timingToleranceNs = TRUST_TO_TOLERANCE_NS[timeInfo.trustLevel]
                ?? TME_CONFIG.timingToleranceNs;

            const result = encoder.encode(message, {
                sliceSize: sliceSize || 1024,
                baseTimestamp: timeInfo.timestampNs,
            });

            // Gossip the stream metadata first
            gossip.spreadRumor('tme:metadata', {
                streamId: result.streamId,
                metadata: {
                    ...result.metadata,
                    timeSource: timeInfo.source,
                    trustLevel: timeInfo.trustLevel,
                },
                origin: nodeId,
            });

            // Gossip each slice
            for (const slice of result.slices) {
                gossip.spreadRumor('tme:slice', {
                    streamId: result.streamId,
                    slice,
                    origin: nodeId,
                });
            }

            log.info('TME encoded and gossiped', {
                streamId: result.streamId,
                slices: result.slices.length,
                size: message.length,
                timeSource: timeInfo.source,
                trustLevel: timeInfo.trustLevel,
            });

            // Also dispatch via dedicated wire protocol if available (Step 25)
            // Wire protocol sends slices directly to peers with path diversity,
            // complementing the gossip broadcast for faster targeted delivery.
            let wireDispatched = 0;
            if (typeof tmeTransportGetter === 'function') {
                const transport = tmeTransportGetter();
                if (transport) {
                    const wireResult = transport.dispatchSlices(result);
                    wireDispatched = wireResult?.dispatched || 0;
                }
            }

            res.json({
                ok: true,
                streamId: result.streamId,
                totalSlices: result.metadata.totalSlices,
                sliceSize: result.metadata.sliceSize,
                wireDispatched,
                timing: {
                    source: timeInfo.source,
                    trustLevel: timeInfo.trustLevel,
                    toleranceNs: TME_CONFIG.timingToleranceNs,
                },
            });
        } catch (err) {
            log.error('TME encode failed', { error: err.message });
            res.status(500).json({ ok: false, error: err.message });
        }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /tme/decode/:streamId — Attempt to reconstruct a received stream
    // ═══════════════════════════════════════════════════════════════════════════
    router.post('/decode/:streamId', (req, res) => {
        // SECURITY: Use raw socket address, NOT req.ip which trusts X-Forwarded-For
        const remoteIp = req.socket?.remoteAddress || '';
        const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
        if (!isLocal) {
            return res.status(403).json({ ok: false, error: 'TME decode is localhost-only' });
        }

        try {
            const result = encoder.decode(req.params.streamId);
            if (result.success) {
                res.json({
                    ok: true,
                    message: result.data.toString('utf-8'),
                    sliceCount: result.sliceCount,
                    streamId: result.streamId,
                });
            } else {
                res.json({
                    ok: false,
                    error: result.error,
                    received: result.received,
                    required: result.required,
                    total: result.total,
                    completionPercent: result.completionPercent,
                    reconstructed: result.reconstructed,
                    unrecoverable: result.unrecoverable,
                });
            }
        } catch (err) {
            log.error('TME decode failed', { error: err.message });
            res.status(500).json({ ok: false, error: err.message });
        }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /tme/stream/:streamId — Check reception status of a stream
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/stream/:streamId', (req, res) => {
        const status = encoder.getStreamStatus(req.params.streamId);
        if (!status) {
            return res.status(404).json({ ok: false, error: 'Stream not found' });
        }
        res.json({ ok: true, ...status });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /tme/stats — TME subsystem statistics + timing quality
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/stats', (_req, res) => {
        const timeInfo = getPreciseTimeNs(timeSource, getMeshTimeRef);
        res.json({
            ok: true,
            stats: encoder.getStats(),
            outboundStreams: encoder.outboundStreams.size,
            inboundStreams: encoder.inboundStreams.size,
            timing: {
                source: timeInfo.source,
                trustLevel: timeInfo.trustLevel,
                toleranceNs: TME_CONFIG.timingToleranceNs,
                phaseToleranceMs: ManiPhaseTolerance[timeInfo.trustLevel] ?? null,
                sliceIntervalNs: TME_CONFIG.defaultSliceIntervalNs,
            },
        });
    });

    return { router, encoder };
}

/**
 * Wire TME gossip handlers into the mesh rumor listener.
 * 
 * When tme:metadata arrives, initialize a receive stream.
 * When tme:slice arrives, feed it into the encoder.
 * When tme:timing-proof arrives, register the proof for reconstruction.
 * 
 * @param {Object} params
 * @param {Object} params.mesh - MeshNetwork instance  
 * @param {TemporalMeshEncoder} params.encoder - The TME encoder instance
 * @param {string} params.nodeId - This node's ID (to skip own messages)
 */
export function wireTmeGossip({ mesh, encoder, nodeId }) {
    mesh.on('rumor', (topic, data, origin) => {
        // Skip our own gossip
        if (data.origin === nodeId) return;

        if (topic === 'tme:metadata') {
            const { streamId, metadata } = data;
            if (!streamId || !metadata) return;

            try {
                encoder.initReceive({ streamId, ...metadata });
                log.debug('TME stream registered', {
                    streamId: streamId.slice(0, 12),
                    from: origin?.slice(0, 12),
                    slices: metadata.totalSlices,
                    peerTimeSource: metadata.timeSource || 'unknown',
                });
            } catch (err) {
                log.warn('TME metadata error', { error: err.message });
            }
        }

        if (topic === 'tme:slice') {
            const { slice } = data;
            if (!slice) return;

            try {
                const result = encoder.receiveSlice(slice);
                if (result.accepted) {
                    log.debug('TME slice accepted', {
                        stream: slice.streamId?.slice(0, 12),
                        seq: slice.sequenceNumber,
                        completion: `${result.completionPercent.toFixed(0)}%`,
                    });

                    // If stream is complete, log it
                    if (result.streamComplete) {
                        log.info('TME stream fully received', {
                            stream: slice.streamId?.slice(0, 12),
                        });
                    }
                }
            } catch (err) {
                log.warn('TME slice error', { error: err.message });
            }
        }

        if (topic === 'tme:timing-proof') {
            const { streamId, sequenceNumber, proof } = data;
            if (!streamId || sequenceNumber == null || !proof) return;

            try {
                encoder.addTimingProof(streamId, sequenceNumber, proof);
                log.debug('TME timing proof registered', {
                    stream: streamId.slice(0, 12),
                    seq: sequenceNumber,
                });
            } catch (err) {
                log.warn('TME timing proof error', { error: err.message });
            }
        }
    });

    log.info('TME gossip handler wired');
}
