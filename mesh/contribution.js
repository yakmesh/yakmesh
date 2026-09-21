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

import { readFileSync } from 'fs';
import { join } from 'path';

const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE || 'http://127.0.0.1:9995';
const NPU_PROOF_URL = process.env.YAKOS_NPU_PROOF || 'http://127.0.0.1:9997';
const FETCH_TIMEOUT_MS = 1500;

/**
 * yakcoind handoff: when the Rust daemon runs it publishes the epoch's
 * self-verified claim to this path once per epoch. We adopt only its
 * work fields (spongeRounds/shareCount/jobRoot) — identity stays
 * bridge-derived, and a file whose nodeId or seal doesn't match ours
 * is ignored (a foreign claim under our heartbeat is worse than none).
 */
const YAKCOIND_CLAIM = join(process.env.XDG_RUNTIME_DIR || '/tmp',
  'yakmesh', 'yakcoind-claim.json');

function yakcoindWorkFields(epoch, nodeId, seal) {
  try {
    const c = JSON.parse(readFileSync(YAKCOIND_CLAIM, 'utf8'));
    if (c.epoch !== epoch || c.nodeId !== nodeId) return null;
    if (!Array.isArray(c.seal) || c.seal.length !== 4 ||
        c.seal.some((q, i) => q !== seal[i])) return null;
    const work = {
      spongeRounds: Number.isInteger(c.spongeRounds) ? c.spongeRounds : 0,
      shareCount: Number.isInteger(c.shareCount) ? c.shareCount : 0,
      jobRoot: typeof c.jobRoot === 'string' && /^[0-9a-f]{64}$/.test(c.jobRoot)
        ? c.jobRoot : '0'.repeat(64),
    };
    // Relay the coinbase-format attestation bundle only when its
    // embedded nodeId (canonical bytes 1..33) matches ours — a bundle
    // for foreign hardware must not ride our claim.
    if (typeof c.attestationBundle === 'string') {
      try {
        const raw = Buffer.from(c.attestationBundle, 'base64');
        if (raw.length > 33 &&
            raw.subarray(1, 33).toString('hex') === nodeId) {
          work.attestationBundle = c.attestationBundle;
        }
      } catch { /* malformed b64 — drop the field, keep the work */ }
    }
    return work;
  } catch {
    return null; // no daemon, stale file, or unreadable — self-generate
  }
}

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
 * Generic hardware-proof provider — wired alongside (or instead of)
 * the NPU proof provider. Use createHwProofProvider({device}) for any
 * triad executor: 'cpu' | 'gpu' | 'npu'. A node proves the silicon it
 * actually has; multiple providers can be chained by the caller.
 */
let hwProofProvider = null;

export function setHwProofProvider(fn) {
  hwProofProvider = typeof fn === 'function' ? fn : null;
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

/**
 * Generic hardware execution-proof provider — pq-bridge /hw/proof
 * (:9995) covers all three triad executors with the same evidence
 * contract as /npu/proof: N dispatches of a nonce-seeded AVOTH hash on
 * real silicon. `device` selects the executor: 'cpu' | 'gpu' | 'npu'.
 * The returned proof carries a capability block (CPU feature flags,
 * GPU name+VRAM, NPU kernel/tiles) so the claim says WHAT ran, not
 * just THAT something ran. Returns null when unavailable.
 */
export function createHwProofProvider({ device = 'cpu', url = BRIDGE_URL, n = 8, timeoutMs = 30000 } = {}) {
  return async (epoch) => {
    const res = await fetch(`${url}/hw/proof?device=${device}&nonce=yakmesh-e${epoch}&n=${n}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    const p = await res.json();
    if (p?.status !== 'ok' || !p.digests?.output) return null;
    return {
      nonce: p.nonce,
      device: p.device?.pci || p.device?.name || p.device?.class || device,
      deviceClass: p.device?.class || device,
      kernel: p.kernel || null,
      n: p.n_dispatches,
      consistent: p.digests.consistent_across_dispatches === true,
      capability: p.capability || null,
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

/** Bridge signing key — fetched once, the keystore identity doesn't rotate. */
let bridgeSigningKey = null;

/**
 * The pq-bridge emits base64 key/signature material; the mesh's canonical
 * encoding is hex. Hex-looking input is already canonical — base64's
 * alphabet is a superset, so hex must be tested first.
 */
function toCanonicalHex(value) {
  if (typeof value !== 'string' || /^[0-9a-fA-F]+$/.test(value)) return value;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value) ? Buffer.from(value, 'base64').toString('hex') : value;
}

async function getBridgeSigningKey() {
  if (!bridgeSigningKey) {
    const { signing_key } = await getJson('/public-keys');
    bridgeSigningKey = { keyId: signing_key.key_id, publicKey: toCanonicalHex(signing_key.public_key) };
  }
  return bridgeSigningKey;
}

/**
 * Canonical serialization of an execution-proof claim — the exact bytes
 * the ML-DSA-65 signature covers. Pipe-separated (device IDs contain
 * colons, so the YAKMESH: referral convention can't be reused). A verifier
 * must reconstruct this string from the proof fields and compare before
 * verifying — the signature binds the fields, not the string alone.
 */
export function npuProofClaim(epoch, nodeId, p) {
  const t = p.timingNs || {};
  return [
    'YAKMESH|NPU-PROOF|v1', epoch, nodeId,
    p.device ?? '', p.kernel ?? '', p.nonce ?? '',
    p.n ?? '', p.consistent ? 1 : 0,
    p.digests?.input ?? '', p.digests?.output ?? '',
    t.p50 ?? '', t.p95 ?? '', t.mean ?? '', t.min ?? '', t.max ?? '', t.wall ?? '',
  ].join('|');
}

/**
 * Turn an execution proof into a signed attestation: canonical claim →
 * pq-bridge /sign (yakos-keystore ML-DSA-65). The FNV digests stay
 * checksum-grade evidence — the signature is what binds them to this
 * node's hardware identity. Throws on bridge failure; callers decide
 * whether an unsigned proof still rides.
 */
async function signNpuProof(epoch, nodeId, proof) {
  const claim = npuProofClaim(epoch, nodeId, proof);
  const key = await getBridgeSigningKey();
  const res = await fetch(`${BRIDGE_URL}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: claim }),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`bridge /sign: ${res.status}`);
  const { signature, algorithm } = await res.json();
  return { claim, algorithm, keyId: key.keyId, publicKey: key.publicKey, signature: toCanonicalHex(signature) };
}

/**
 * Canonical serialization of a generic hardware-proof claim — same
 * field discipline as npuProofClaim plus deviceClass (which executor
 * proved itself) and a capability digest. YAKMESH|HW-PROOF|v1.
 */
export function hwProofClaim(epoch, nodeId, p) {
  const t = p.timingNs || {};
  return [
    'YAKMESH|HW-PROOF|v1', epoch, nodeId,
    p.deviceClass ?? '', p.device ?? '', p.kernel ?? '', p.nonce ?? '',
    p.n ?? '', p.consistent ? 1 : 0,
    JSON.stringify(p.capability ?? null),
    p.digests?.input ?? '', p.digests?.output ?? '',
    t.p50 ?? '', t.p95 ?? '', t.mean ?? '', t.min ?? '', t.max ?? '', t.wall ?? '',
  ].join('|');
}

/** Sign a hardware-proof claim via the keystore — same flow as signNpuProof. */
async function signHwProof(epoch, nodeId, proof) {
  const claim = hwProofClaim(epoch, nodeId, proof);
  const key = await getBridgeSigningKey();
  const res = await fetch(`${BRIDGE_URL}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: claim }),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`bridge /sign: ${res.status}`);
  const { signature, algorithm } = await res.json();
  return { claim, algorithm, keyId: key.keyId, publicKey: key.publicKey, signature: toCanonicalHex(signature) };
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
    if (npuProof) {
      // Attestation failure omits the signature only — the unsigned proof
      // is still real execution evidence, just unattributed.
      const attestation = await signNpuProof(epoch, node_id, npuProof).catch(() => null);
      if (attestation) npuProof.attestation = attestation;
    }
    const hwProof = hwProofProvider ? await hwProofProvider(epoch).catch(() => null) : null;
    if (hwProof) {
      const attestation = await signHwProof(epoch, node_id, hwProof).catch(() => null);
      if (attestation) hwProof.attestation = attestation;
    }
    // Adopt yakcoind's work fields when its claim is present and its
    // identity+seal provably match ours — zeros stay honest otherwise.
    const work = yakcoindWorkFields(epoch, node_id, seal);
    const payload = {
      version: 1,
      epoch,
      nodeId: node_id,
      seal,                    // 4 quats — wormhole seal at AVOTH pos 191
      spongeRounds: work?.spongeRounds ?? 0, // PRAHARI feed not wired — honest zero
      shareCount: work?.shareCount ?? 0,     // mesh pool not live — honest zero
      jobRoot: work?.jobRoot ?? '0'.repeat(64), // no completed work orders yet
      entropyFlags: (canAttestTime ? 1 : 0) | (real_silicon ? 2 : 0),
      siliconDrift: Number.isInteger(silicon_drift) ? silicon_drift : 0,
      ...(work ? { yakcoind: true } : {}),
      ...(work?.attestationBundle
          ? { attestationBundle: work.attestationBundle } : {}),
      ...(npuProof ? { npuProof } : {}),
      ...(hwProof ? { hwProof } : {}),
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
