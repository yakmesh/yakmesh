// ═══════════════════════════════════════════════════════════════════════════════
// YAKMESH — mesh/work-receipt.js
// WORK RECEIPT — issuer-signed job attestation (the game/service claim interface)
// ═══════════════════════════════════════════════════════════════════════════════
//
// PEACH issuer path: a game authority (or any service) attests that a
// worker produced a result. Issuers ATTEST — they never mint. The
// receipt travels inside the worker's own epoch claim, committed via
// jobRoot = AVOTH-256(concat(canonical receipt encodings)), so the
// claim itself rides the normal witnessed path and the receipt cannot
// be transplanted: it binds the worker's nodeId, epoch, AND wormhole
// seal — the same seal the claim commits.
//
// Hash convention (ratified): AVOTH commits identity-bound objects;
// SHA3-256 folds bulk structure (Merkle leaves). issuerNode follows
// the Hash256 convention: sha3_256(issuerPubkey).
//
// Wire receipt:
//   { version, jobId, issuerNode, issuerPubkey, workerNode, epoch,
//     workClass, resultHash, feePaid, seal[4], issuerSig }
//
// Canonical signed encoding (issuerSig excluded):
//   version u8 ‖ jobId[32] ‖ issuerNode[32] ‖ workerNode[32] ‖
//   epoch u32LE ‖ workClass u8 ‖ resultHash[32] ‖ feePaid u64LE ‖ seal[4] ‖
//   issuerPidLen u8 ‖ issuerPersistentId[len]
//   — 146-byte fixed head + variable persistentId tail (~70B "yak-…").
// issuerNode = sha3_256(issuerPubkey) proves THIS key signed; the
// persistentId is the cross-build authority anchor — pubkeys rotate
// per build (seed+oracle+codebase derivation), persistentId does not.
// Verifiers check the DOKO binds pid → pubkey.
//
// Rust-side type: yakcoin-core/src/claims.rs WorkReceipt — wire-align
// its serializer when the coinbase path consumes receipts.
// ═══════════════════════════════════════════════════════════════════════════════

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { signMessage, verifySignature } from '../identity/node-key.js';
import { avothHash } from '../utils/dna-spiral.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:work-receipt');

export const RECEIPT_VERSION = 1;
export const MAX_RECEIPTS_PER_CLAIM = 8;
export const CANONICAL_BYTES = 146;
// Wire bound: canonical 146 + ML-DSA-65 sig (2420) + pubkey (1312) as
// hex — a receipt object exceeding this is malformed, not big.
export const MAX_RECEIPT_JSON_BYTES = 16 * 1024;

const HEX64 = /^[0-9a-f]{64}$/;
// 162T persistent machine id: "yak-" + ternary {T,0,1} groups.
const PID_RE = /^yak-[T01:]{10,90}$/;
export const MAX_PID_LEN = 96;

function isQuatSeal(seal) {
  return Array.isArray(seal) && seal.length === 4
    && seal.every(q => Number.isInteger(q) && q >= 0 && q <= 3);
}

/**
 * Payload shape — the signed fields only. Used by encodeReceipt, which
 * runs BEFORE the signature exists (it produces the signing payload),
 * so it cannot check issuerSig.
 */
function payloadShapeError(r) {
  if (!r || typeof r !== 'object') return 'not-object';
  if (r.version !== RECEIPT_VERSION) return 'bad-version';
  if (!HEX64.test(r.jobId || '')) return 'bad-jobId';
  if (!HEX64.test(r.issuerNode || '')) return 'bad-issuerNode';
  if (!HEX64.test(r.workerNode || '')) return 'bad-workerNode';
  if (!Number.isInteger(r.epoch) || r.epoch <= 0) return 'bad-epoch';
  if (!Number.isInteger(r.workClass) || r.workClass < 1 || r.workClass > 5) return 'bad-workClass';
  if (!HEX64.test(r.resultHash || '')) return 'bad-resultHash';
  if (!Number.isSafeInteger(r.feePaid) || r.feePaid < 0) return 'bad-feePaid';
  if (!isQuatSeal(r.seal)) return 'bad-seal';
  if (typeof r.issuerPersistentId !== 'string'
      || r.issuerPersistentId.length > MAX_PID_LEN
      || !PID_RE.test(r.issuerPersistentId)) return 'bad-issuerPersistentId';
  return null;
}

/**
 * Structural check — full wire shape, no crypto. Returns a reason
 * string or null when the shape is clean.
 */
export function receiptShapeError(r) {
  return payloadShapeError(r)
    || (typeof r.issuerPubkey !== 'string' || r.issuerPubkey.length < 32 ? 'bad-issuerPubkey'
      : typeof r.issuerSig !== 'string' || r.issuerSig.length < 32 ? 'bad-issuerSig'
        : null);
}

/**
 * Canonical 146-byte encoding — the signed payload and the AVOTH
 * commitment preimage. issuerSig is excluded (it can't sign itself);
 * issuerPubkey is excluded from the signed bytes but bound through
 * issuerNode = sha3_256(issuerPubkey), verified at check time.
 */
export function encodeReceipt(r) {
  if (payloadShapeError(r)) return null;
  const pid = Buffer.from(r.issuerPersistentId, 'utf8');
  const buf = Buffer.alloc(CANONICAL_BYTES + 1 + pid.length);
  let o = 0;
  buf.writeUInt8(r.version, o); o += 1;
  Buffer.from(r.jobId, 'hex').copy(buf, o); o += 32;
  Buffer.from(r.issuerNode, 'hex').copy(buf, o); o += 32;
  Buffer.from(r.workerNode, 'hex').copy(buf, o); o += 32;
  buf.writeUInt32LE(r.epoch, o); o += 4;
  buf.writeUInt8(r.workClass, o); o += 1;
  Buffer.from(r.resultHash, 'hex').copy(buf, o); o += 32;
  buf.writeBigUInt64LE(BigInt(r.feePaid), o); o += 8;
  buf.set(r.seal, o); o += 4;
  buf.writeUInt8(pid.length, o); o += 1;
  pid.copy(buf, o);
  return buf;
}

/**
 * jobRoot commitment for a claim carrying receipts:
 * AVOTH-256 over the concatenated canonical encodings, in array order.
 * The wire field is 32 bytes, so the commitment folds to the leading
 * 32 bytes of the 64-byte AVOTH digest. Returns null when AVOTH is
 * unavailable — callers must NOT fall back to another hash silently;
 * an uncommitted claim is honest, a mis-committed one is fraud-shaped.
 */
export function receiptsCommitment(receipts) {
  if (!Array.isArray(receipts) || receipts.length === 0
      || receipts.length > MAX_RECEIPTS_PER_CLAIM) return null;
  const parts = receipts.map(encodeReceipt);
  if (parts.some(p => !p)) return null;
  const digest = avothHash(Buffer.concat(parts));
  return digest ? digest.subarray(0, 32).toString('hex') : null;
}

/**
 * Issue a receipt — the authority side. `issuer` is an identity with
 * {publicKey, secretKey, persistentId} — the persistentId (162T
 * "yak-…" machine id) is the cross-build authority anchor and goes
 * INSIDE the signed payload. issuerNode derives as
 * sha3_256(publicKey) — the Hash256 node-address convention.
 */
export function signReceipt(fields, issuer) {
  if (!issuer?.publicKey || !issuer?.secretKey || !issuer?.persistentId) return null;
  let pubBytes;
  try { pubBytes = Buffer.from(issuer.publicKey, 'hex'); } catch { return null; }
  const r = {
    version: RECEIPT_VERSION,
    jobId: fields.jobId,
    issuerNode: bytesToHex(sha3_256(pubBytes)),
    issuerPubkey: issuer.publicKey,
    issuerPersistentId: issuer.persistentId,
    workerNode: fields.workerNode,
    epoch: fields.epoch,
    workClass: fields.workClass,
    resultHash: fields.resultHash,
    feePaid: fields.feePaid ?? 0,
    seal: fields.workerSeal,
  };
  const canonical = encodeReceipt(r);
  if (!canonical) return null;
  r.issuerSig = signMessage(canonical, issuer.secretKey);
  return r;
}

/**
 * Verify a receipt — TRIBHUJ-style ternary verdict:
 *   'reject'  — malformed, bad signature, or binding violation
 *               (worker/epoch/seal mismatch = transplant attempt)
 *   'observe' — signature and bindings valid, but issuer authority
 *               unverified (no DOKO registry, or issuer not a
 *               Service-typed DOKO)
 *   'accept'  — valid signature AND issuer is a Service DOKO
 *
 * ctx: { expectedWorkerNode?, expectedEpoch?, expectedSeal?, dokoRegistry? }
 */
export function verifyReceipt(r, ctx = {}) {
  const shapeErr = receiptShapeError(r);
  if (shapeErr) return { verdict: 'reject', reason: shapeErr };

  // issuerPubkey → issuerNode binding: the declared node identity must
  // hash to the signing key, else the receipt names a phantom issuer.
  let pubBytes;
  try { pubBytes = Buffer.from(r.issuerPubkey, 'hex'); } catch { pubBytes = null; }
  if (!pubBytes || bytesToHex(sha3_256(pubBytes)) !== r.issuerNode) {
    return { verdict: 'reject', reason: 'issuer-key-mismatch' };
  }

  const canonical = encodeReceipt(r);
  if (!canonical || !verifySignature(canonical, r.issuerSig, r.issuerPubkey)) {
    return { verdict: 'reject', reason: 'bad-signature' };
  }

  if (ctx.expectedWorkerNode && r.workerNode !== ctx.expectedWorkerNode) {
    return { verdict: 'reject', reason: 'worker-mismatch' };
  }
  if (ctx.expectedEpoch && r.epoch !== ctx.expectedEpoch) {
    return { verdict: 'reject', reason: 'epoch-mismatch' };
  }
  if (ctx.expectedSeal
      && (!isQuatSeal(ctx.expectedSeal)
          || r.seal.some((q, i) => q !== ctx.expectedSeal[i]))) {
    return { verdict: 'reject', reason: 'seal-mismatch' };
  }

  // Authority check — DOKO Service registration keyed on the
  // persistentId (the cross-build anchor), with the presented pubkey
  // required to match the DOKO's current key. A rotated key on the
  // same machine keeps authority via an updated DOKO; a stolen
  // persistentId fails because the pubkey won't match. Absence is the
  // honest middle state: the receipt is real, the issuer's standing
  // is not yet witnessed. Bond-gating lands with the bond build.
  const registry = ctx.dokoRegistry;
  if (registry && typeof registry.getByPersistentId === 'function') {
    const doko = registry.getByPersistentId(r.issuerPersistentId)
      || (typeof registry.getByPublicKey === 'function'
        ? registry.getByPublicKey(r.issuerPubkey) : null);
    if (doko && doko.type === 'service' && !doko.revoked
        && doko.publicKey === r.issuerPubkey
        && doko.extensions?.persistentId === r.issuerPersistentId) {
      return { verdict: 'accept', reason: 'service-doko' };
    }
    return { verdict: 'observe', reason: doko ? 'doko-binding-mismatch' : 'issuer-unknown' };
  }
  return { verdict: 'observe', reason: 'no-doko-registry' };
}

/**
 * Verify a claim's receipt set: jobRoot must equal the AVOTH
 * commitment of ALL receipts, and every receipt must bind to the
 * claim's worker/epoch/seal. Returns { verdict, receipts: [per-] }.
 * 'reject' on ANY binding/crypto failure — the commitment is over the
 * whole set, so one bad artifact breaks it entirely.
 */
export function verifyClaimReceipts(claim, ctx = {}) {
  const receipts = claim.receipts;
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return { verdict: 'reject', reason: 'no-receipts' };
  }
  if (receipts.length > MAX_RECEIPTS_PER_CLAIM) {
    return { verdict: 'reject', reason: 'too-many-receipts' };
  }
  const commitment = receiptsCommitment(receipts);
  if (!commitment) return { verdict: 'reject', reason: 'commitment-unavailable' };
  if (commitment !== claim.jobRoot) {
    return { verdict: 'reject', reason: 'commitment-mismatch' };
  }
  const per = receipts.map(r => verifyReceipt(r, {
    expectedWorkerNode: claim.nodeId,
    expectedEpoch: claim.epoch,
    expectedSeal: claim.seal,
    dokoRegistry: ctx.dokoRegistry,
  }));
  if (per.some(p => p.verdict === 'reject')) {
    return { verdict: 'reject', reason: 'receipt-invalid', receipts: per };
  }
  return {
    verdict: per.every(p => p.verdict === 'accept') ? 'accept' : 'observe',
    receipts: per,
  };
}

export default {
  RECEIPT_VERSION, MAX_RECEIPTS_PER_CLAIM, MAX_RECEIPT_JSON_BYTES,
  receiptShapeError, encodeReceipt, receiptsCommitment,
  signReceipt, verifyReceipt, verifyClaimReceipts,
};
