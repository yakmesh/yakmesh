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
const NPU_PROOF_URL = process.env.YAKOS_NPU_PROOF || 'http://127.0.0.1:9997';
const FETCH_TIMEOUT_MS = 1500;

/** Cached seal for the current epoch — bridge call is ~1ms, epochs are 30s. */
let cached = { epoch: -1, payload: null };

/**
 * Time-trust provider — wired by the server at startup. Must return
 * true when MANI tier ≥ PTP (can_attest_time, entropyFlags bit0).
 * Unwired → bit0 stays 0: unattested time is reported, never claimed.
 */
let timeTrustProvider = null;

export function setTimeTrustProvider(fn) {
  timeTrustProvider = typeof fn === 'function' ? fn : null;
}

/**
 * NPU execution-proof provider — wired by the server at startup when a
 * silicon-capable prover exists (rust-embed /npu/proof). Called once per
 * epoch with the epoch number; must return the proof object or null.
 * Unwired/failure → the claim simply omits npuProof: honest absence,
 * never a fabricated attestation.
 */
let proofProvider = null;

export function setProofProvider(fn) {
  proofProvider = typeof fn === 'function' ? fn : null;
}

/**
 * Build an execution-proof provider for rust-embed's /npu/proof
 * (:9997). Runs a nonce-seeded GEMM on real silicon — the returned
 * digest only exists if the kernel actually dispatched. The nonce is
 * bound to the epoch so a proof can't be replayed into a later claim.
 * Returns null when the service or NPU is absent.
 */
export function createNpuProofProvider({ url = NPU_PROOF_URL, n = 8, timeoutMs = 5000 } = {}) {
  return async (epoch) => {
    const res = await fetch(`${url}/npu/proof?n=${n}&nonce=yakmesh-e${epoch}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    const p = await res.json();
    if (p?.status !== 'ok' || !p.digests?.output) return null;
    return {
      nonce: p.nonce,
      device: p.device?.pci || null,
      kernel: p.kernel || null,
      n: p.n_dispatches,
      consistent: p.digests.consistent_across_dispatches === true,
      digests: { input: p.digests.input, output: p.digests.output },
      timingNs: {
        p50: p.timing?.per_dispatch_ns?.p50,
        p95: p.timing?.per_dispatch_ns?.p95,
        mean: p.timing?.per_dispatch_ns?.mean,
        min: p.timing?.per_dispatch_ns?.min,
        max: p.timing?.per_dispatch_ns?.max,
        wall: p.timing?.wall_ns,
      },
    };
  };
}

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
export async function contributionMeshState(nowMs) {
  const epoch = currentEpoch(nowMs);
  if (cached.epoch === epoch) return cached.payload;

  try {
    const { node_id, seal, real_silicon, silicon_drift } =
      await getJson(`/yakcoin/seal?epoch=${epoch}`);
    const canAttestTime = timeTrustProvider ? !!timeTrustProvider() : false;
    // Execution proof is fetched once per epoch — the provider binds the
    // nonce to this epoch so the digest can't be replayed across epochs.
    const npuProof = proofProvider ? await proofProvider(epoch).catch(() => null) : null;
    const payload = {
      version: 1,
      epoch,
      nodeId: node_id,
      seal,                    // 4 quats — wormhole seal at AVOTH pos 191
      spongeRounds: 0,         // PRAHARI feed not wired — honest zero
      shareCount: 0,           // mesh pool not live — honest zero
      jobRoot: '0'.repeat(64), // no completed work orders yet
      entropyFlags: (canAttestTime ? 1 : 0) | (real_silicon ? 2 : 0),
      siliconDrift: Number.isInteger(silicon_drift) ? silicon_drift : 0,
      ...(npuProof ? { npuProof } : {}),
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
