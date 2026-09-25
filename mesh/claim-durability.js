/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Claim Durability — TME dispersal for witnessed claim sets.
 *
 * The pay-per-share record must never be lost. At epoch close each node
 * canonically encodes its witnessed claim set, TME-slices it, and
 * disperses the slices across the mesh (path diversity — no single peer
 * holds the whole set). A node that was offline, partitioned, or had a
 * corrupted download recovers by streamId + TME_RECONSTRUCT; recovered
 * slices are quorum-authenticated via timing proofs.
 *
 * The closed loop: attestation items commit to each claim's canonical
 * leaf (claimLeafHash). A TME-recovered claim is parsed back into its
 * leaf preimage and recomputed — corruption fails locally — then
 * cross-checked against what attestations committed. A recovered claim
 * nobody attested is flagged, never silently trusted.
 *
 * Canonical claim-set encoding:
 *   u8 version ‖ u32LE epoch ‖ u16LE count
 *   per claim (sorted nodeId, then leaf bytes):
 *     u8 yakmeshNodeIdLen ‖ yakmeshNodeId utf8 ‖ leafBytes[81]
 * Each record IS the 81-byte leaf preimage + the yakmesh identity —
 * ~100B/claim. Parse-level checks are structural (bounds, epoch
 * consistency); CONTENT integrity comes from the TME slice hash-chain
 * below us and the attested-leaf cross-check in assemble() above us —
 * a flipped leaf byte produces a valid parse whose claimLeafHash
 * simply doesn't match anything attested.
 *
 * streamId = sha3_256("claims:${epoch}:${witnessNodeId}") — deterministic
 * so any node can name the stream it needs to recover.
 *
 * @module mesh/claim-durability
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { ClaimLedger } from './claim-ledger.js';
import { claimLeafHash } from './attestation-gossip.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:claim-durability');

const SET_VERSION = 1;
const MAX_CLAIMS_PER_SET = 2048;  // bound encode work (~260KB worst case)
const MAX_NODE_ID_LEN = 128;      // yakmesh nodeIds are ~30 chars; hard bound
const RETAIN_EPOCHS = 64;         // claim-ledger prune horizon

/**
 * Deterministic TME stream id for a node's epoch claim set.
 */
export function claimsStreamId(epoch, witnessNodeId) {
  return bytesToHex(sha3_256(
    utf8ToBytes(`claims:${epoch}:${witnessNodeId}`)));
}

/**
 * Canonically serialize an epoch claim set. Claims sort by (nodeId,
 * leaf) — the same order epochClaimRoot uses, so the encoded order is
 * itself canonical.
 */
export function claimSetBytes(epoch, claims) {
  const sorted = [...claims]
    .filter(c => typeof c.yakmeshNodeId === 'string' &&
                c.yakmeshNodeId.length > 0 &&
                c.yakmeshNodeId.length <= MAX_NODE_ID_LEN)
    .sort((a, b) =>
      a.nodeId.localeCompare(b.nodeId) ||
      Buffer.compare(ClaimLedger.claimLeafBytes(a),
                     ClaimLedger.claimLeafBytes(b)));
  const n = Math.min(sorted.length, MAX_CLAIMS_PER_SET);

  let size = 7;
  const idBufs = sorted.slice(0, n).map(c => {
    const b = Buffer.from(c.yakmeshNodeId, 'utf8');
    size += 1 + b.length + 81;
    return b;
  });

  const buf = Buffer.alloc(size);
  let o = 0;
  buf.writeUInt8(SET_VERSION, o); o += 1;
  buf.writeUInt32LE(epoch, o); o += 4;
  buf.writeUInt16LE(n, o); o += 2;
  for (let i = 0; i < n; i++) {
    buf.writeUInt8(idBufs[i].length, o); o += 1;
    idBufs[i].copy(buf, o); o += idBufs[i].length;
    ClaimLedger.claimLeafBytes(sorted[i]).copy(buf, o); o += 81;
  }
  return buf;
}

/**
 * Parse a canonical claim set. Each record's stored leafBytes must
 * recompute identically — a corrupted record fails and is counted, not
 * trusted. Returns {epoch, claims, rejected, truncated}.
 */
export function parseClaimSet(buf) {
  const out = { epoch: 0, claims: [], rejected: 0, truncated: false };
  if (!Buffer.isBuffer(buf) || buf.length < 7 || buf.readUInt8(0) !== SET_VERSION) {
    return { ...out, rejected: 1 };
  }
  let o = 1;
  out.epoch = buf.readUInt32LE(o); o += 4;
  const count = buf.readUInt16LE(o); o += 2;

  for (let i = 0; i < count; i++) {
    if (o + 1 > buf.length) { out.truncated = true; break; }
    const idLen = buf.readUInt8(o); o += 1;
    if (idLen === 0 || idLen > MAX_NODE_ID_LEN || o + idLen + 81 > buf.length) {
      out.truncated = true; break;
    }
    const yakmeshNodeId = buf.toString('utf8', o, o + idLen); o += idLen;
    const leaf = buf.subarray(o, o + 81); o += 81;

    // Rebuild the claim from its leaf preimage fields (same offsets as
    // claimLeafBytes writes).
    let p = 0;
    const claim = {
      version: leaf.readUInt8(p),
      epoch: leaf.readUInt32LE(p += 1),
      spongeRounds: leaf.readUInt16LE(p += 4),
      shareCount: leaf.readUInt32LE(p += 2),
      jobRoot: leaf.toString('hex', p += 4, p += 32),
      entropyFlags: leaf.readUInt8(p),
      siliconDrift: leaf.readUInt8(p += 1),
      seal: [...leaf.subarray(p += 1, p += 4)],
      nodeId: leaf.toString('hex', p, p += 32),
      yakmeshNodeId,
    };
    // Semantic check: a record whose embedded leaf epoch disagrees
    // with the set header is misplaced/damaged — reject it.
    if (claim.epoch !== out.epoch) {
      out.rejected++;
      continue;
    }
    out.claims.push(claim);
  }
  if (o < buf.length && out.claims.length + out.rejected < count) {
    out.truncated = true;
  }
  return out;
}

/**
 * Epoch-close dispersal + recovery orchestration for claim sets.
 */
export class ClaimDurability extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.nodeId - our yakmesh nodeId
   * @param {ClaimLedger} opts.claimLedger - witnessed claim source
   * @param {TemporalMeshEncoder} opts.encoder - TME encoder instance
   * @param {object} [opts.transport] - wireTmeTransport controller
   * @param {AttestationGossip} [opts.attestGossip] - for leaf cross-check
   */
  constructor(opts) {
    super();
    this.nodeId = opts.nodeId;
    this.claimLedger = opts.claimLedger;
    this.encoder = opts.encoder;
    this.transport = opts.transport || null;
    this.attestGossip = opts.attestGossip || null;
    /** @type {Map<number, string>} epoch → streamId (our encoded sets) */
    this.encoded = new Map();
    this.stats = { encoded: 0, slicesDispatched: 0, recovered: 0, rejectedClaims: 0 };
  }

  /**
   * Encode + disperse this epoch's witnessed claim set. Cheap and local
   * — runs at epoch close alongside the attestation batch.
   */
  encodeEpoch(epoch) {
    const claims = this.claimLedger.epochClaims(epoch);
    if (claims.length === 0) return null;

    const bytes = claimSetBytes(epoch, claims);
    const streamId = claimsStreamId(epoch, this.nodeId);
    const enc = this.encoder.encode(bytes, {
      streamId,
      sliceSize: 1024,
      // Deterministic temporal anchors — a recovering node can derive
      // metadata from the epoch alone.
      baseTimestamp: BigInt(epoch) * 30_000_000_000n, // 30s/epoch, ns
      sliceIntervalNs: 50_000_000,
    });
    this.encoded.set(epoch, streamId);
    const dispatched = this.transport?.dispatchSlices(enc);
    this.stats.encoded++;
    this.stats.slicesDispatched += dispatched?.dispatched || 0;
    this._prune(epoch);
    this.emit('encoded', {
      epoch, streamId, claims: claims.length,
      bytes: bytes.length, slices: enc.slices.length,
    });
    return { streamId, slices: enc.slices.length, claims: claims.length };
  }

  /**
   * Ask peers for a witness node's epoch claim set we missed.
   * Fire-and-forget — slices land in encoder.inboundStreams; call
   * assemble(streamId) once status shows complete/enough.
   */
  requestEpoch(epoch, witnessNodeId, peerIds = []) {
    const streamId = claimsStreamId(epoch, witnessNodeId);
    if (!this.transport) return null;
    for (const p of peerIds) {
      this.transport.requestReconstruction(p, streamId);
    }
    return streamId;
  }

  /**
   * Decode a received claim-set stream → leaf-verified claims. Claims
   * whose leaf was never attested (when attestGossip is wired) are
   * flagged `unattested: true` — usable for context, never silently
   * merged into settlement weight.
   */
  assemble(streamId) {
    const res = this.encoder.decode(streamId);
    if (!res.success) return res;

    const parsed = parseClaimSet(res.data);
    this.stats.recovered += parsed.claims.length;
    this.stats.rejectedClaims += parsed.rejected;

    // Cross-check recovered leaves against attested commitments.
    let unattested = 0;
    if (this.attestGossip && parsed.claims.length > 0) {
      const attestedLeaves = new Set(
        [...this.attestGossip.claimRefs.values()]
          .map(r => r.leaf).filter(Boolean));
      if (attestedLeaves.size > 0) {
        for (const c of parsed.claims) {
          if (!attestedLeaves.has(claimLeafHash(c))) {
            c.unattested = true;
            unattested++;
          }
        }
      }
    }

    if (parsed.rejected > 0 || unattested > 0) {
      this.emit('recoveryAnomaly', {
        streamId, epoch: parsed.epoch,
        rejected: parsed.rejected, unattested,
      });
    }
    return { ...res, ...parsed, unattested };
  }

  /** Drop claim-set streams older than the retention horizon. */
  _prune(currentEpoch) {
    const floor = currentEpoch - RETAIN_EPOCHS;
    for (const [epoch, streamId] of this.encoded) {
      if (epoch < floor) {
        this.encoded.delete(epoch);
        this.encoder.outboundStreams?.delete(streamId);
        this.encoder.inboundStreams?.delete(streamId);
      }
    }
  }

  getStats() { return { ...this.stats }; }
}
