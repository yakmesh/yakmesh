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
 * Envelope Controller — dynamic conformance scrutiny.
 *
 * Moves the timing tolerance (capability-bands TOLERANCE) and the
 * challenge sampling weight per peer, driven ONLY by locally witnessed
 * metrics: conformance samples the challenger measured on its own
 * clock, refusals, and epoch seal-verification health. No self-reported
 * signal ever enters — a peer cannot tell us their envelope, only
 * behave into it.
 *
 * Anti-gaming rules (by construction, not policy):
 *
 *  1. DETECTION-ONLY. The envelope controls how hard we look, never
 *     what a peer earns. Reward math (caps × KARMA curve) is
 *     consensus-fixed upstream — no envelope position raises a payout.
 *     The worst a manipulator achieves is tighter scrutiny on itself.
 *  2. FUSE MODEL — asymmetric response. Violations tighten fast
 *     (two strikes → strict). Loosening requires sustained clean
 *     history (~27 clean samples from neutral). Staying loose IS
 *     staying honest — the exploit path is the desired behavior.
 *  3. FIXED BOUNDS. strict/normal/relaxed are constant windows; the
 *     controller interpolates between them, never invents thresholds.
 *  4. HYSTERESIS. Level changes need a margin past the threshold —
 *     no oscillation at boundaries.
 *  5. PER-PEER. A peer's envelope is driven by MY measurements of that
 *     peer alone — attackers cannot move a victim's scrutiny. A global
 *     floor (epoch seal-health) can tighten everyone but never loosen
 *     anyone below their own level.
 *
 * @module mesh/envelope-controller
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createLogger } from '../utils/logger.js';
import { TOLERANCE } from './capability-bands.js';

const log = createLogger('mesh:envelope');

/** Fixed tolerance windows — the controller never exceeds these. */
export const LEVELS = {
  strict:  { lo: 0.75, hi: 1.25 },  // suspicion — narrow window
  normal:  { lo: 0.5,  hi: 2.0 },   // the static TOLERANCE baseline
  relaxed: { lo: 0.4,  hi: 3.0 },   // sustained clean history
};

// Fuse-model asymmetry: tightening is ~10× faster than loosening.
const TIGHTEN_STEP = 0.5;   // per violation — two strikes → strict
const REFUSE_STEP = 0.25;   // refusals count, softer (could be load)
const LOOSEN_STEP = 0.05;   // per clean sample — slow burn back

// Level thresholds with hysteresis margin.
const STRICT_ENTER = 0.34, STRICT_EXIT = 0.29;
const RELAXED_ENTER = -0.67, RELAXED_EXIT = -0.62;

// Challenge sampling weights per level — suspicious peers get
// spot-audited more, relaxed peers less. Never zero: a relaxed peer
// who degrades must still be caught by the fuse.
const CHALLENGE_WEIGHT = { strict: 3, normal: 1, relaxed: 0.5 };

export class EnvelopeController {
  constructor() {
    /** @type {Map<string, {score:number, level:string}>} */
    this.peers = new Map();
    this.global = { score: 0, level: 'normal' };
  }

  _peer(peerId) {
    let p = this.peers.get(peerId);
    if (!p) { p = { score: 0, level: 'normal' }; this.peers.set(peerId, p); }
    return p;
  }

  /**
   * Level transition with hysteresis — must cross the ENTER threshold
   * to move up/down, and hold past EXIT to come back.
   */
  static _resolveLevel(state) {
    const s = state.score;
    if (state.level !== 'strict' && s >= STRICT_ENTER) return 'strict';
    if (state.level === 'strict' && s < STRICT_EXIT) return 'normal';
    if (state.level !== 'relaxed' && s <= RELAXED_ENTER) return 'relaxed';
    if (state.level === 'relaxed' && s > RELAXED_EXIT) return 'normal';
    return state.level;
  }

  /**
   * Feed one challenger-measured outcome.
   * @param {string} peerId
   * @param {object} sample - {band, refused?, failed?, timeout?}
   *   'ok'→clean · 'fast'/'slow'→violation · refused/failed/timeout→
   *   violation · 'unclassified'/other→neutral (no verdict = no move)
   */
  observe(peerId, sample) {
    const p = this._peer(peerId);
    if (sample.failed || sample.timeout ||
        sample.band === 'fast' || sample.band === 'slow') {
      p.score = Math.min(1, p.score + TIGHTEN_STEP);
    } else if (sample.refused) {
      p.score = Math.min(1, p.score + REFUSE_STEP);
    } else if (sample.band === 'ok') {
      p.score = Math.max(-1, p.score - LOOSEN_STEP);
    } else {
      return; // neutral — unclassified results move nothing
    }
    const next = EnvelopeController._resolveLevel(p);
    if (next !== p.level) {
      log.info('envelope level change', { peerId, from: p.level, to: next, score: p.score });
      p.level = next;
    }
  }

  /**
   * Feed epoch seal-health — the GLOBAL floor. Invalid seals tighten
   * everyone's scrutiny (a claim-forgery wave is a mesh event), but a
   * clean epoch loosens the floor only — never a peer directly.
   * @param {number} valid - claims passing seal verification
   * @param {number} invalid - claims failing
   */
  observeEpochHealth(valid, invalid) {
    const g = this.global;
    if (invalid > 0) {
      // Fraction-weighted: one bad claim in a big epoch is noise,
      // a flood is a fire. Still asymmetric — tightens fast.
      g.score = Math.min(1, g.score + TIGHTEN_STEP * (invalid / Math.max(1, valid + invalid) + 0.5));
    } else if (valid > 0) {
      // Floored at 0 — the global floor is TIGHTENING-ONLY. A clean
      // mesh never reduces anyone's scrutiny (that would be the
      // collective-manipulation vector); it just relaxes the floor.
      g.score = Math.max(0, g.score - LOOSEN_STEP);
    }
    g.level = EnvelopeController._resolveLevel(g);
  }

  /** Effective level for a peer — global strict overrides all. */
  levelFor(peerId) {
    const pl = this._peer(peerId).level;
    return this.global.level === 'strict' ? 'strict' : pl;
  }

  /**
   * Tolerance window for a peer — same shape as capability-bands
   * TOLERANCE ({lo,hi}), bounded to the fixed LEVELS.
   */
  toleranceFor(peerId) {
    return LEVELS[this.levelFor(peerId)];
  }

  /**
   * Sampling weight for challenge scheduling — higher suspicion, more
   * spot-audits. Feed into a weighted random pick over peer ids.
   */
  challengeWeight(peerId) {
    return CHALLENGE_WEIGHT[this.levelFor(peerId)];
  }

  /**
   * Weighted-random challenge target. Suspicion biases selection —
   * the peers we distrust get measured most.
   * @param {string[]} peerIds
   * @returns {string|null}
   */
  pickTarget(peerIds) {
    if (!peerIds.length) return null;
    const ws = peerIds.map(id => this.challengeWeight(id));
    const total = ws.reduce((a, b) => a + b, 0);
    let r = Math.random() * total;
    for (let i = 0; i < peerIds.length; i++) {
      r -= ws[i];
      if (r <= 0) return peerIds[i];
    }
    return peerIds[peerIds.length - 1];
  }

  /** Static TOLERANCE for callers that want the old constant. */
  static get BASELINE() { return TOLERANCE; }
}
