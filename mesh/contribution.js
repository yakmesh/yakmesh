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
 * Contribution Reporter — produces meshState.contribution for heartbeats.
 *
 * Fetches the node's yakcoin identity + epoch seal from the YakOS
 * pq-bridge (localhost:9995) — the canonical AVOTH implementation.
 * Fields PRAHARI/the mesh pool don't feed yet are honest zeros;
 * if the bridge is unreachable the field is omitted entirely —
 * an unattested heartbeat, never a fake claim.
 *
 * Wire schema: yakcoin/docs/WIRE-FORMAT.md §3 ContributionSummary.
 *
 * @module mesh/contribution
 */

const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE || 'http://127.0.0.1:9995';
const FETCH_TIMEOUT_MS = 1500;

/** Cached seal for the current epoch — bridge call is ~1ms, epochs are 30s. */
let cached = { epoch: -1, payload: null };

async function getJson(path) {
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`bridge ${path}: ${res.status}`);
  return res.json();
}

/**
 * Current MANI-aligned epoch (30s — matches yakcoind EPOCH_SECS and
 * pq-bridge's default).
 */
export function currentEpoch(nowMs = Date.now()) {
  return Math.floor(nowMs / 1000 / 30);
}

/**
 * Produce the meshState.contribution payload, or null when the node is
 * unattested (no pq-bridge). Safe to call every heartbeat — results are
 * cached per epoch so the seal stays constant within it.
 *
 * @returns {Promise<object|null>} ContributionSummary-shaped object
 */
export async function contributionMeshState() {
  const epoch = currentEpoch();
  if (cached.epoch === epoch) return cached.payload;

  try {
    const { node_id, seal } = await getJson(`/yakcoin/seal?epoch=${epoch}`);
    const payload = {
      version: 1,
      epoch,
      nodeId: node_id,
      seal,                    // 4 quats — wormhole seal at AVOTH pos 191
      spongeRounds: 0,         // PRAHARI feed not wired — honest zero
      shareCount: 0,           // mesh pool not live — honest zero
      jobRoot: '0'.repeat(64), // no completed work orders yet
      entropyFlags: 0,         // set by MANI trust once detector reports in
    };
    cached = { epoch, payload };
    return payload;
  } catch {
    cached = { epoch, payload: null };
    return null;
  }
}

/**
 * Merge into an outgoing heartbeat's meshState. Omits the field entirely
 * when unattested — an absent claim is honest, a fabricated one is not.
 */
export async function withContribution(meshState = {}) {
  const contribution = await contributionMeshState();
  return contribution ? { ...meshState, contribution } : meshState;
}
