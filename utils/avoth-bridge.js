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
 * AVOTH Bridge Client — shared access to the YakOS pq-bridge AVOTH API.
 *
 * The pq-bridge (localhost:9995) runs the canonical AVOTH implementation
 * across the compute triad (CPU / CUDA GPU / XDNA NPU — bit-identical
 * results on all three). This client is the ONLY path yakmesh-node uses
 * for AVOTH operations — the math is never reimplemented in JS.
 *
 * Honest-availability contract: every method throws or returns null when
 * the bridge is unreachable. Callers MUST surface "unavailable" rather
 * than pretend an AVOTH operation happened (rule 9 — no fake success).
 *
 * @module utils/avoth-bridge
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createHash } from 'crypto';
import { createLogger } from './logger.js';

const log = createLogger('avoth:bridge');

const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE || 'http://127.0.0.1:9995';
const PROBE_TTL_MS = 15_000;      // re-probe availability at most every 15s
const REQ_TIMEOUT_MS = 5_000;

// MANI-aligned epoch (30s) — matches yakcoind EPOCH_SECS, claim-ledger's
// currentEpoch(), and the pq-bridge's own epoch derivation.
export const EPOCH_SECS = 30;
export function currentEpoch(nowMs = Date.now()) {
  return Math.floor(nowMs / 1000 / EPOCH_SECS);
}

let _avail = { at: 0, ok: false };

/**
 * Is the pq-bridge AVOTH API reachable? Cached for PROBE_TTL_MS so
 * hot paths (chirps, seals) don't hammer a dead service.
 */
export async function isAvailable(force = false) {
  if (!force && Date.now() - _avail.at < PROBE_TTL_MS) return _avail.ok;
  try {
    const r = await fetch(`${BRIDGE_URL}/health`, { signal: AbortSignal.timeout(2000) });
    _avail = { at: Date.now(), ok: r.ok };
  } catch {
    _avail = { at: Date.now(), ok: false };
  }
  return _avail.ok;
}

// Self-prime the cache at module load — first callers see real state.
isAvailable(true).catch(() => { });

/**
 * Synchronous read of the cached probe — for hot paths that must not
 * await (replication log inserts, chirp ticks). May be stale by up to
 * PROBE_TTL_MS; async callers should use isAvailable() for authority.
 */
export function lastKnownAvailable() {
  return _avail.ok;
}

async function getJson(path, timeoutMs = REQ_TIMEOUT_MS) {
  const r = await fetch(`${BRIDGE_URL}${path}`, { signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error(`bridge ${path} -> ${r.status}`);
  return r.json();
}

async function postJson(path, body, timeoutMs = REQ_TIMEOUT_MS) {
  const r = await fetch(`${BRIDGE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (r.status === 409) {
    const err = new Error(`bridge ${path} -> 409 conflict`);
    err.conflict = true;
    err.status = 409;
    throw err;
  }
  if (!r.ok) throw new Error(`bridge ${path} -> ${r.status}`);
  return r.json();
}

// ── Seals ────────────────────────────────────────────────────────────

/**
 * Derive a deterministic 4-quat wormhole seal (each quat 0..3) from a
 * context string. 4 quats = 8 bits = one byte of the SHA-256 of the
 * context — public tamper evidence, not a secret.
 * @param {string|Buffer} context - e.g. `${nodeId}:${epoch}` or a streamId
 * @returns {[number,number,number,number]}
 */
export function sealFromContext(context) {
  const b = createHash('sha256').update(context).digest()[0];
  return [(b >> 6) & 3, (b >> 4) & 3, (b >> 2) & 3, b & 3];
}

// ── Hashing ──────────────────────────────────────────────────────────

/**
 * AVOTH hash (fractal v4, canonical construction — byte-identical with
 * the GPU implementation).
 * @param {Buffer|string} data
 * @returns {Promise<{hash:string, bits:number, version:string, families:string[]}>}
 */
export async function hash(data) {
  const b64 = Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(String(data)).toString('base64');
  return postJson('/avoth/hash', { data: b64 });
}

/**
 * Batch AVOTH hash through the triad, optionally sealed per message.
 * @param {(Buffer|string)[]} messages
 * @param {{device?:'gpu'|'npu'|'cpu', seals?:number[][]}} [opts]
 *   seals: one [q,q,q,q] (0..3) per message — wormhole-sealed hashing.
 * @returns {Promise<object>} triad BatchHashResult
 */
export async function batchHash(messages, opts = {}) {
  const body = {
    messages: messages.map(m =>
      (Buffer.isBuffer(m) ? m : Buffer.from(String(m))).toString('base64')),
  };
  if (opts.device) body.device = opts.device;
  if (opts.seals) body.seals = opts.seals;
  return postJson('/avoth/batch-hash', body, 30_000);
}

/**
 * Convenience: sealed hash of a single message.
 * @param {Buffer|string} data
 * @param {[number,number,number,number]} seal
 */
export async function hashSealed(data, seal) {
  const res = await batchHash([data], { seals: [seal] });
  return res?.digests?.[0] ?? null;
}

// ── Hourglass (epoch-flip OTS) ───────────────────────────────────────

/**
 * Hourglass-sign a message — at most one signature per epoch.
 * Throws err.conflict=true (HTTP 409) if this epoch was already signed.
 * @param {Buffer|string} message
 * @returns {Promise<{epoch:number, rotation:number, revealed:string[], size:number, signature:string}>}
 */
export async function hourglassSign(message) {
  const b64 = (Buffer.isBuffer(message) ? message : Buffer.from(String(message))).toString('base64');
  return postJson('/avoth/sign', { message: b64 });
}

/**
 * Verify a JSON-encoded FractalSignature. Old epochs verify via archived
 * commitments (sig.epoch lookup), so recent-epoch sigs survive flips.
 * @param {Buffer|string} message
 * @param {string} signatureJson - JSON-encoded FractalSignature
 * @param {Object} [commitments] - Signer's full epoch commitment set
 *   ({epoch, commitments: {"index:level": hex}}) as returned by /avoth/sign.
 *   Required to verify signatures from a FOREIGN hourglass — each node's
 *   glass is uniquely seeded, so local archives can't verify remote sigs.
 *   Must be the complete set; partial sets are rejected by the bridge.
 * @returns {Promise<{valid:boolean, epoch:number, external?:boolean}>}
 */
export async function hourglassVerify(message, signatureJson, commitments = null) {
  const b64 = (Buffer.isBuffer(message) ? message : Buffer.from(String(message))).toString('base64');
  const body = { message: b64, signature: signatureJson };
  if (commitments) body.commitments = commitments;
  return postJson('/avoth/verify', body);
}

/** Flip the hourglass — rotate epoch keys through the neck. */
export async function flip() {
  return postJson('/avoth/flip', {});
}

// ── State / observability ────────────────────────────────────────────

export const getState = () => getJson('/avoth/state');
export const getFractalState = () => getJson('/avoth/fractal/state');
export const selfcheck = () => getJson('/avoth/selfcheck');
export const cryptanalysis = () => getJson('/avoth/cryptanalysis');
export const triadStats = () => getJson('/avoth/triad-stats');
export const defenseState = () => getJson('/avoth/defense-state');
export const yakcoinSeal = (epoch) => getJson(`/yakcoin/seal?epoch=${epoch}`);
export const hwProof = () => getJson('/hw/proof');

/**
 * Compact capability summary for mesh advertisements — honest values
 * only; returns null when the bridge is down.
 */
export async function capabilitySummary() {
  if (!(await isAvailable())) return null;
  try {
    const [state, stats] = await Promise.all([getState(), triadStats()]);
    return {
      avoth: true,
      version: 'v4',
      epoch: state?.epoch ?? null,
      gpu: !!stats?.gpu_available,
      npu: !!stats?.npu_available,
      triad: stats ?? null,
    };
  } catch (e) {
    log.warn('capability summary failed', { error: e.message });
    return null;
  }
}

export default {
  EPOCH_SECS, currentEpoch, isAvailable, lastKnownAvailable,
  sealFromContext, hash, batchHash, hashSealed,
  hourglassSign, hourglassVerify, flip,
  getState, getFractalState, selfcheck, cryptanalysis, triadStats,
  defenseState, yakcoinSeal, hwProof, capabilitySummary,
};
