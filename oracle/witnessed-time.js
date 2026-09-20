/**
 * WITNESSED time — the cardless tier. A node without a stratum-1 clock
 * borrows one transitively: it collects signed time pulses from
 * stratum-1 mesh members, verifies each signature and attester binding,
 * and derives a median offset with a measured consistency bound.
 *
 * Design (yakcoin ARCHITECTURE "witnessed time"):
 *   1. Time pulses — stratum-1 members broadcast signed
 *      (time, stratum, nodeId) at MANI epoch boundaries
 *   2. Error bound — measured, not assumed. The consistency bound is
 *      half the inter-attester spread of offset estimates; an RTT/2
 *      refinement is pending per-peer latency instrumentation.
 *   3. k-of-m quorum — median of k signed pulses from DISTINCT
 *      attesters; outliers rejected. A lying stratum-1 node's offset
 *      diverges from the quorum and is excluded.
 *   4. MANI level WITNESSED — between NTP and GPS in trust: stratum 2
 *      numerically (one hop from the source) but elevated above NTP
 *      because the bound is witnessed evidence, not configuration.
 *
 * Honest limits: a pulse's stratum is self-reported (signed but
 * self-claimed) — the quorum-median is what makes a lie expensive:
 * one attester can't move the median, and sustained disagreement shows
 * up as bound inflation, which gates eligibility.
 *
 * @module oracle/witnessed-time
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { verifySignature, generateNodeId } from '../identity/node-key.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:witnessed-time');

/** Minimum distinct attesters before WITNESSED eligibility (k-of-m). */
export const WITNESS_QUORUM_K = 3;
/** Epoch window a pulse is counted in — 30 s, the MANI epoch. */
const EPOCH_MS = 30_000;
/** Hard eligibility ceiling on the measured bound — beyond this the
 *  quorum is too disagreeable to mean anything (≈PTP-class ceiling). */
const MAX_BOUND_MS = 500;
/** Pulses kept per epoch per attester — first-seen wins. */
const PULSE_VERSION = 1;

/**
 * The canonical payload a stratum-1 node signs — same fields the
 * receiver re-hashes. Versioned so the format can evolve.
 */
export function pulsePreimage({ nodeId, epoch, timestamp, stratum }) {
  return `mani-pulse:${PULSE_VERSION}:${nodeId}:${epoch}:${timestamp}:${stratum}`;
}

export class WitnessedTime {
  /**
   * @param {object} opts
   * @param {string} opts.nodeId - our nodeId (self-pulses ignored)
   * @param {function} [opts.now] - ms clock (default Date.now)
   */
  constructor(opts) {
    this.nodeId = opts.nodeId;
    this.now = opts.now || (() => Date.now());

    /** epoch → Map<attesterNodeId, {offsetMs, stratum, receivedAt}> */
    this.pulses = new Map();
    this.stats = { received: 0, badSig: 0, badBinding: 0, lowStratum: 0, self: 0 };
  }

  /**
   * Observe an incoming time:heartbeat rumor. Unsigned or non-stratum-1
   * pulses are ignored — WITNESSED evidence must be signed AND claim a
   * real clock; both checks are structural.
   * @param {object} data - the rumor payload
   * @returns {boolean} accepted into the quorum set
   */
  observePulse(data) {
    if (!data || !data.nodeId) return false;
    if (data.nodeId === this.nodeId) { this.stats.self++; return false; }

    // Only stratum ≤ 1 sources may serve witnessed time (signed claim,
    // still self-reported — quorum-median bounds the lie's effect).
    const stratum = data.stratum ?? 16;
    if (stratum > 1) { this.stats.lowStratum++; return false; }

    // Signature over the canonical pulse fields.
    if (!data.pubKey || !data.pulseSig) { this.stats.badSig++; return false; }
    const epoch = Math.floor(data.timestamp / EPOCH_MS);
    const pre = pulsePreimage({ nodeId: data.nodeId, epoch,
      timestamp: data.timestamp, stratum });
    try {
      if (!verifySignature(pre, data.pulseSig, data.pubKey)) {
        this.stats.badSig++;
        log.warn('time pulse bad signature', { from: data.nodeId.slice(0, 16) });
        return false;
      }
      // Attester binding — nodeId must derive from the signing key,
      // same anti-Sybil rule as HELLO and claim:attest.
      if (generateNodeId(hexToBytes(data.pubKey)) !== data.nodeId) {
        this.stats.badBinding++;
        return false;
      }
    } catch {
      this.stats.badSig++;
      return false;
    }

    // Offset estimate: remote pulse time minus our local receive time.
    // Positive = remote clock ahead of us.
    const receivedAt = this.now();
    const offsetMs = data.timestamp - receivedAt;

    let epochMap = this.pulses.get(epoch);
    if (!epochMap) {
      epochMap = new Map();
      this.pulses.set(epoch, epochMap);
      this._prune();
    }
    // First pulse per attester per epoch wins — an attester can't
    // improve its position by re-sending.
    if (!epochMap.has(data.nodeId)) {
      epochMap.set(data.nodeId, { offsetMs, stratum, receivedAt });
      this.stats.received++;
    }
    return true;
  }

  /**
   * The witnessed-time estimate for an epoch (default: current).
   * @returns {{eligible:boolean, attesters:number, offsetMs:?number,
   *           boundMs:?number}} — offset is the median attester
   *   offset; bound is half the inter-quartile-free spread
   *   ((max−min)/2 over retained attesters after outlier rejection).
   */
  witnessedState(epoch = Math.floor(this.now() / EPOCH_MS)) {
    const epochMap = this.pulses.get(epoch);
    if (!epochMap || epochMap.size < WITNESS_QUORUM_K) {
      return { eligible: false, attesters: epochMap?.size || 0,
               offsetMs: null, boundMs: null };
    }
    const offsets = [...epochMap.values()].map(p => p.offsetMs).sort((a, b) => a - b);
    const median = offsets[Math.floor(offsets.length / 2)];
    // Outlier rejection: drop attesters >MAX_BOUND_MS from the median —
    // a lying/faulty clock shows up as a divergent offset.
    const inliers = offsets.filter(o => Math.abs(o - median) <= MAX_BOUND_MS);
    if (inliers.length < WITNESS_QUORUM_K) {
      return { eligible: false, attesters: inliers.length,
               offsetMs: median, boundMs: null };
    }
    const bound = (inliers[inliers.length - 1] - inliers[0]) / 2;
    const med = inliers[Math.floor(inliers.length / 2)];
    return {
      eligible: bound <= MAX_BOUND_MS,
      attesters: inliers.length,
      offsetMs: med,
      boundMs: bound,
    };
  }

  _prune() {
    while (this.pulses.size > 8) {
      const oldest = Math.min(...this.pulses.keys());
      this.pulses.delete(oldest);
    }
  }
}
