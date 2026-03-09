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
 * Yakmesh TME Transport — Bridge between temporal-encoder.js and mesh wire protocol
 *
 * While TME slices can travel via gossip rumors (tme:metadata, tme:slice,
 * tme:timing-proof), this module adds dedicated MandalaMessageTypes so slices
 * can be dispatched directly to specific peers for:
 *   - Multi-path slice dispatch (different slices → different peers for diversity)
 *   - Point-to-point timing proof requests
 *   - On-demand stream reconstruction from the most responsive peer
 *
 * The gossip layer remains the default broadcast path; this transport adds
 * targeted, low-latency delivery as an overlay.
 *
 * @module mesh/tme-transport
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { MandalaMessageTypes } from './network.js';
import { createHash } from 'crypto';

/**
 * Create a structured logger stub if none provided.
 * @param {string} name
 */
function fallbackLogger(name) {
  const noop = () => {};
  return { info: noop, debug: noop, warn: noop, error: noop };
}

/**
 * TME Transport configuration
 */
const TME_TRANSPORT_CONFIG = {
  /** Max peers to dispatch a single slice to (path diversity) */
  maxSliceTargets: 3,
  /** Timeout (ms) for proof requests before falling back */
  proofRequestTimeoutMs: 5000,
  /** Max concurrent reconstruction requests per stream */
  maxReconstructionConcurrency: 2,
};

/**
 * Wire TME transport handlers into the mesh network.
 *
 * Registers handlers for:
 *   TME_SLICE           — receive a temporal slice from a peer
 *   TME_PROOF_REQUEST   — peer asks us for a timing proof
 *   TME_PROOF_RESPONSE  — we receive a timing proof from a peer
 *   TME_RECONSTRUCT     — peer asks us to send all slices for a stream
 *
 * Returns a controller object with methods to send slices, request proofs, etc.
 *
 * @param {Object} params
 * @param {import('./network.js').MandalaNetwork} params.mesh
 * @param {import('./temporal-encoder.js').TemporalMeshEncoder} params.encoder
 * @param {string} params.nodeId
 * @param {Object} [params.log]
 * @returns {TmeTransportController}
 */
export function wireTmeTransport({ mesh, encoder, nodeId, log: externalLog }) {
  const log = externalLog || fallbackLogger('tme-transport');

  // ─── Pending proof requests (requestId → { resolve, timer }) ───────────
  const pendingProofs = new Map();

  // ─────────────────────────────────────────────────────────────────────────
  // INBOUND HANDLERS
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * TME_SLICE — A peer sends us a temporal slice directly.
   */
  mesh.on(MandalaMessageTypes.TME_SLICE, (msg, _ws, senderNodeId) => {
    if (senderNodeId === nodeId) return; // skip own
    const { slice, metadata } = msg;
    if (!slice) return;

    try {
      // If we haven't seen this stream yet, init it from metadata
      if (metadata && !encoder.inboundStreams?.has(slice.streamId)) {
        encoder.initReceive({ streamId: slice.streamId, ...metadata });
        log.debug('TME transport: init stream from direct slice', {
          stream: slice.streamId?.slice(0, 12),
          from: senderNodeId?.slice(0, 12),
        });
      }

      const result = encoder.receiveSlice(slice);
      if (result.accepted) {
        log.debug('TME transport: slice accepted (direct)', {
          stream: slice.streamId?.slice(0, 12),
          seq: slice.sequenceNumber,
          completion: `${result.completionPercent?.toFixed(0)}%`,
        });
        if (result.streamComplete) {
          log.info('TME transport: stream complete (direct)', {
            stream: slice.streamId?.slice(0, 12),
          });
        }
      }
    } catch (err) {
      log.warn('TME transport: slice error', { error: err.message });
    }
  });

  /**
   * TME_PROOF_REQUEST — A peer wants a timing proof for a specific slice.
   * If we have the slice, compute and send back a proof.
   */
  mesh.on(MandalaMessageTypes.TME_PROOF_REQUEST, (msg, _ws, senderNodeId) => {
    if (senderNodeId === nodeId) return;
    const { streamId, sequenceNumber, requestId } = msg;
    if (!streamId || sequenceNumber == null || !requestId) return;

    try {
      // Look up the slice in our outbound or inbound streams
      const stream =
        encoder.outboundStreams?.get(streamId) ||
        encoder.inboundStreams?.get(streamId);

      if (!stream) {
        // We don't have this stream — respond with empty proof
        mesh.sendTo(senderNodeId, {
          type: MandalaMessageTypes.TME_PROOF_RESPONSE,
          requestId,
          streamId,
          sequenceNumber,
          proof: null,
          reason: 'stream_not_found',
        });
        return;
      }

      const slice = stream.slices?.get(sequenceNumber);
      if (!slice) {
        mesh.sendTo(senderNodeId, {
          type: MandalaMessageTypes.TME_PROOF_RESPONSE,
          requestId,
          streamId,
          sequenceNumber,
          proof: null,
          reason: 'slice_not_found',
        });
        return;
      }

      // Build timing proof: hash of slice temporal hash + our nodeId + timestamp
      const proofHash = createHash('sha3-256');
      proofHash.update(slice.temporalHash || Buffer.alloc(32));
      proofHash.update(nodeId);
      const ts = BigInt(Date.now()) * 1_000_000n; // ms → ns approximation
      const tsBuf = Buffer.alloc(8);
      tsBuf.writeBigUInt64BE(ts);
      proofHash.update(tsBuf);

      const proof = {
        nodeId,
        timestamp: ts.toString(),
        hash: proofHash.digest('base64'),
        sequenceNumber,
      };

      mesh.sendTo(senderNodeId, {
        type: MandalaMessageTypes.TME_PROOF_RESPONSE,
        requestId,
        streamId,
        sequenceNumber,
        proof,
      });

      log.debug('TME transport: proof sent', {
        stream: streamId.slice(0, 12),
        seq: sequenceNumber,
        to: senderNodeId.slice(0, 12),
      });
    } catch (err) {
      log.warn('TME transport: proof request error', { error: err.message });
    }
  });

  /**
   * TME_PROOF_RESPONSE — We receive a timing proof we requested.
   */
  mesh.on(MandalaMessageTypes.TME_PROOF_RESPONSE, (msg, _ws, senderNodeId) => {
    if (senderNodeId === nodeId) return;
    const { requestId, streamId, sequenceNumber, proof } = msg;
    if (!requestId) return;

    const pending = pendingProofs.get(requestId);
    if (!pending) {
      log.debug('TME transport: proof response for unknown request', { requestId });
      return;
    }

    clearTimeout(pending.timer);
    pendingProofs.delete(requestId);

    if (proof) {
      try {
        encoder.addTimingProof(streamId, sequenceNumber, proof);
        log.debug('TME transport: proof registered', {
          stream: streamId?.slice(0, 12),
          seq: sequenceNumber,
          from: senderNodeId?.slice(0, 12),
        });
      } catch (err) {
        log.warn('TME transport: proof register error', { error: err.message });
      }
    }

    pending.resolve(proof);
  });

  /**
   * TME_RECONSTRUCT — A peer asks us to send all slices for a stream.
   */
  mesh.on(MandalaMessageTypes.TME_RECONSTRUCT, (msg, _ws, senderNodeId) => {
    if (senderNodeId === nodeId) return;
    const { streamId } = msg;
    if (!streamId) return;

    const stream =
      encoder.outboundStreams?.get(streamId) ||
      encoder.inboundStreams?.get(streamId);

    if (!stream || !stream.slices) {
      log.debug('TME transport: reconstruct request for unknown stream', {
        stream: streamId?.slice(0, 12),
        from: senderNodeId?.slice(0, 12),
      });
      return;
    }

    // Send metadata first
    mesh.sendTo(senderNodeId, {
      type: MandalaMessageTypes.TME_SLICE,
      metadata: {
        totalSlices: stream.totalSlices,
        sliceSize: stream.sliceSize,
        sliceIntervalNs: stream.sliceIntervalNs,
        baseTimestamp: stream.baseTimestamp?.toString(),
      },
      slice: null,
    });

    // Send all slices we have
    let sent = 0;
    for (const [_seq, slice] of stream.slices) {
      mesh.sendTo(senderNodeId, {
        type: MandalaMessageTypes.TME_SLICE,
        slice: slice.serialize(),
      });
      sent++;
    }

    log.info('TME transport: sent reconstruction data', {
      stream: streamId.slice(0, 12),
      slices: sent,
      to: senderNodeId.slice(0, 12),
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // OUTBOUND API (returned controller)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Dispatch slices from an encoded stream to peers with path diversity.
   * Each slice is sent to up to `maxSliceTargets` different peers so that
   * no single peer receives the entire stream.
   *
   * @param {Object} encoded - Output of encoder.encode()
   * @param {string} encoded.streamId
   * @param {Array}  encoded.slices - Serialized slices
   * @param {Object} encoded.metadata
   */
  function dispatchSlices(encoded) {
    const peers = mesh.getPeers();
    if (peers.length === 0) {
      log.debug('TME transport: no peers for slice dispatch');
      return { dispatched: 0 };
    }

    const { streamId, slices, metadata } = encoded;

    // Broadcast metadata to all peers so everyone can set up the stream
    for (const peer of peers) {
      mesh.sendTo(peer.nodeId, {
        type: MandalaMessageTypes.TME_SLICE,
        metadata,
        slice: null,
      });
    }

    // Dispatch slices with round-robin path diversity
    let dispatched = 0;
    for (let i = 0; i < slices.length; i++) {
      const targets = Math.min(TME_TRANSPORT_CONFIG.maxSliceTargets, peers.length);
      for (let t = 0; t < targets; t++) {
        const peerIdx = (i + t) % peers.length;
        mesh.sendTo(peers[peerIdx].nodeId, {
          type: MandalaMessageTypes.TME_SLICE,
          slice: slices[i],
        });
      }
      dispatched++;
    }

    log.info('TME transport: dispatched stream', {
      stream: streamId.slice(0, 12),
      slices: slices.length,
      peers: peers.length,
      targets: Math.min(TME_TRANSPORT_CONFIG.maxSliceTargets, peers.length),
    });

    return { dispatched, streamId };
  }

  /**
   * Request a timing proof from a specific peer for a stream/slice.
   * Returns a Promise that resolves with the proof or null on timeout.
   *
   * @param {string} targetNodeId
   * @param {string} streamId
   * @param {number} sequenceNumber
   * @returns {Promise<Object|null>}
   */
  function requestProof(targetNodeId, streamId, sequenceNumber) {
    const requestId = `${nodeId}-${streamId.slice(0, 8)}-${sequenceNumber}-${Date.now()}`;

    return new Promise(resolve => {
      const timer = setTimeout(() => {
        pendingProofs.delete(requestId);
        log.debug('TME transport: proof request timed out', {
          stream: streamId.slice(0, 12),
          seq: sequenceNumber,
          peer: targetNodeId.slice(0, 12),
        });
        resolve(null);
      }, TME_TRANSPORT_CONFIG.proofRequestTimeoutMs);

      pendingProofs.set(requestId, { resolve, timer });

      mesh.sendTo(targetNodeId, {
        type: MandalaMessageTypes.TME_PROOF_REQUEST,
        streamId,
        sequenceNumber,
        requestId,
      });
    });
  }

  /**
   * Request reconstruction of a stream from a peer.
   * The peer will send all slices they have via TME_SLICE messages.
   *
   * @param {string} targetNodeId
   * @param {string} streamId
   */
  function requestReconstruction(targetNodeId, streamId) {
    mesh.sendTo(targetNodeId, {
      type: MandalaMessageTypes.TME_RECONSTRUCT,
      streamId,
    });

    log.info('TME transport: reconstruction requested', {
      stream: streamId.slice(0, 12),
      from: targetNodeId.slice(0, 12),
    });
  }

  /**
   * Request timing proofs for all missing slices in a stream from multiple peers.
   * Uses round-robin across available peers for load distribution.
   *
   * @param {string} streamId
   * @returns {Promise<{proofs: number, missing: number}>}
   */
  async function requestMissingProofs(streamId) {
    const status = encoder.getStreamStatus(streamId);
    if (!status || status.missing.length === 0) {
      return { proofs: 0, missing: 0 };
    }

    const peers = mesh.getPeers();
    if (peers.length === 0) return { proofs: 0, missing: status.missing.length };

    let proofsReceived = 0;
    const promises = status.missing.map((seq, i) => {
      const peer = peers[i % peers.length];
      return requestProof(peer.nodeId, streamId, seq).then(proof => {
        if (proof) proofsReceived++;
      });
    });

    await Promise.allSettled(promises);
    return { proofs: proofsReceived, missing: status.missing.length };
  }

  log.info('TME transport wired (dedicated wire protocol)', {
    maxSliceTargets: TME_TRANSPORT_CONFIG.maxSliceTargets,
    proofTimeoutMs: TME_TRANSPORT_CONFIG.proofRequestTimeoutMs,
  });

  return {
    dispatchSlices,
    requestProof,
    requestReconstruction,
    requestMissingProofs,
    config: TME_TRANSPORT_CONFIG,
  };
}

export { TME_TRANSPORT_CONFIG };
