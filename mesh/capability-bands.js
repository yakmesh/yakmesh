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
 * Capability Bands — measured-capability classification.
 *
 * Classes describe what hardware CAN DO, never what it IS — no "RTX
 * 9999 120GB" strings, only measured rates. A node self-benchmarks at
 * startup, declares its band in every echo:result, and peers verify
 * conformance against that declaration with their own clock.
 *
 * PEACH semantics (two-sided):
 *   measured < band floor → 'fast' — stronger than declared; the
 *     declaration is stale or sandbagging (reward follows the band,
 *     so sandbagging costs the node rate anyway).
 *   measured > band ceiling → 'slow' — weaker than declared; the
 *     classic lie, a VM, or a loaded machine. Ambiguous, log-only.
 *
 * Tolerances are deliberately wide (×0.5 / ×2.0) — per the MAD lesson,
 * honest loaded systems must never fall out of band; envelopes catch
 * order-of-magnitude lies, not scheduling noise. The band table is the
 * ONLY governed surface here.
 *
 * v1 work types: sha3chain (pure JS sequential chain — measures the
 * interpreter) and mkc-sha3batch (bridge-dispatched MKC batch — MKC is
 * bit-accurate across CPU/GPU/NPU so the timing delta is silicon, not
 * software). The pq-bridge is an integrated companion service; when it
 * is unreachable the mkc band is simply undeclared (degraded, legible).
 *
 * @module mesh/capability-bands
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { workSha3Chain, mkcBatchMessages } from './echo-challenge.js';

/**
 * Band tables — ns-per-unit windows per work type, ordered fast→slow.
 * Unit = chain round for sha3chain, message for mkc-sha3batch.
 * The only governed surface: calibration constants, not policy.
 *
 * mkc-sha3batch windows include the localhost bridge round-trip (the
 * honest cost of the silicon path). Calibrated on Hawk Point XDNA:
 * ~340µs/msg marginal at count 256, ~476µs/msg at count 16 — the
 * dispatch floor inflates small counts, biasing toward slower bands,
 * which is the conservative direction.
 */
export const BANDS = {
  sha3chain: {
    auric:   [80,    800],
    silver:  [800,   3000],
    copper:  [3000,  12000],
    ferrous: [12000, 120000],
  },
  'mkc-sha3batch': {
    auric:   [10_000,  100_000],
    silver:  [100_000, 250_000],
    copper:  [250_000, 600_000],
    ferrous: [600_000, 3_000_000],
  },
};

export const BAND_NAMES = ['auric', 'silver', 'copper', 'ferrous'];

// Conformance tolerance — wide on purpose (load is not a lie).
export const TOLERANCE = { lo: 0.5, hi: 2.0 };

/** Work-unit count for a work spec. */
function unitsOf(work) {
  return work.type === 'sha3chain' ? work.rounds : work.count;
}

/**
 * Classify a measured ns/unit into a band name for a work type.
 * Boundaries: fastest band whose ceiling the rate fits.
 */
export function bandFor(nsPerUnit, workType = 'sha3chain') {
  const table = BANDS[workType];
  if (!table) return 'ferrous';
  for (const name of BAND_NAMES) {
    if (nsPerUnit < table[name][1]) return name;
  }
  return 'ferrous';
}

/**
 * Timing envelope for a declared band × work spec. `declared` may be
 * a band map ({sha3chain:'copper','mkc-sha3batch':'silver'}) or a
 * legacy string (read as the sha3chain band). `tolerance` overrides
 * TOLERANCE (envelope-controller levels — bounded {lo,hi} only).
 * Returns {minNs, maxNs, band} or null for unknown band/work.
 */
export function envelopeFor(work, declared, tolerance = TOLERANCE) {
  if (!work || !BANDS[work.type]) return null;
  const bandName = typeof declared === 'string' ? declared : declared?.[work.type];
  const win = bandName && BANDS[work.type][bandName];
  if (!win) return null;
  const units = BigInt(unitsOf(work) | 0);
  return {
    minNs: BigInt(Math.floor(win[0] * tolerance.lo)) * units,
    maxNs: BigInt(Math.ceil(win[1] * tolerance.hi)) * units,
    band: bandName,
  };
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

/**
 * Self-benchmark: measure sha3chain in JS plus mkc-sha3batch through
 * the pq-bridge when reachable, classify each into a declared band.
 * Deterministic seeds — the number is about silicon, not luck.
 *
 * @param {number} [rounds=2048] sha3chain rounds per sample
 * @param {number} [samples=3]
 * @param {string} [responderId]
 * @param {object} [mkcMod] - utils/mkc surface (injectable for tests)
 * @returns {Promise<{bands:Object, measured:Object}>} bands maps
 *   work type → band name; absent mkc entry = bridge unreachable.
 */
export async function benchmark(rounds = 2048, samples = 3,
                                responderId = 'benchmark', mkcMod = null) {
  const nonce = 'be'.repeat(32);
  const measured = {};
  const bands = {};

  let rates = [];
  for (let s = 0; s < samples; s++) {
    const t0 = process.hrtime.bigint();
    workSha3Chain(nonce, responderId, rounds);
    rates.push(Number(process.hrtime.bigint() - t0) / rounds);
  }
  measured.sha3chain = { nsPerUnit: median(rates), samples: rates };
  bands.sha3chain = bandFor(measured.sha3chain.nsPerUnit, 'sha3chain');

  const mkc = mkcMod || await import('../utils/mkc.js').catch(() => null);
  if (mkc && await mkc.isAvailable().catch(() => false)) {
    // A live bridge can still refuse a surface (older build, missing
    // endpoint, kernel not resident) — a probe that throws degrades the
    // band, it must never take the node down.
    try {
      const count = 64;
      rates = [];
      let device = null;
      for (let s = 0; s < samples; s++) {
        const msgs = mkcBatchMessages(nonce, responderId, count);
        const t0 = process.hrtime.bigint();
        const r = await mkc.sha3_256Batch(msgs);
        rates.push(Number(process.hrtime.bigint() - t0) / count);
        device = r.device;
      }
      measured['mkc-sha3batch'] = { nsPerUnit: median(rates), samples: rates, device };
      bands['mkc-sha3batch'] = bandFor(measured['mkc-sha3batch'].nsPerUnit, 'mkc-sha3batch');
    } catch (e) {
      measured['mkc-sha3batch'] = { unavailable: true, error: e.message };
    }
  }

  return { bands, measured };
}
