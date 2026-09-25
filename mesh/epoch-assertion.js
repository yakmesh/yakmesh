// ═══════════════════════════════════════════════════════════════════════════════
// YAKMESH — mesh/epoch-assertion.js
// EPOCH ASSERTION — canonical signed claim/witness artifacts (slashable objects)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The signature covers canonical BYTES — not JSON — so consensus can
// parse and compare assertions directly. Byte-identical to
// yakcoin-core claims::EpochAssertion::canonical_bytes:
//
//   "YAKMESH-EASSERT-V1"[18] ‖ node_id[32] ‖ epoch u32LE ‖
//   claim_ref[32] ‖ value[32]
//
// Self-assertion (claimer):  claim_ref = sha3("YAKMESH-CLAIMREF" ‖
//   node ‖ epochLE), value = sha3(own 81-byte claim leaf).
// Witness assertion (attester): claim_ref = the witnessed claim's
//   key, value = the witnessed leaf hash.
//
// Two assertions with same (node_id, epoch, claim_ref) and different
// value = provable equivocation. A self-assertion whose leaf fails
// seal recomputation = provable fraud. Both feed EvidenceTx.
// ═══════════════════════════════════════════════════════════════════════════════

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifySignature } from '../identity/node-key.js';

// NOTE: callers supply leaf bytes (ClaimLedger.claimLeafBytes) — this
// module deliberately does not import claim-ledger (it would cycle
// through contribution.js).

export const EASSERT_DOMAIN = 'YAKMESH-EASSERT-V1';
const CLAIMREF_DOMAIN = 'YAKMESH-CLAIMREF';
export const ASSERTION_BYTES = 18 + 32 + 4 + 32 + 32; // 118

const HEX64 = /^[0-9a-f]{64}$/;
const ENC = new TextEncoder();

/**
 * The claim_ref a self-assertion commits — must equal
 * yakcoin-consensus `self_claim_ref`: sha3(CLAIMREF ‖ node ‖ epochLE).
 */
export function selfClaimRef(nodeId, epoch) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(epoch);
  return bytesToHex(sha3_256(concatBytes(
    ENC.encode(CLAIMREF_DOMAIN), hexToBytes(nodeId), buf)));
}

/** Canonical 118-byte assertion preimage — the signing payload. */
export function assertionBytes({ nodeId, epoch, claimRef, value }) {
  if (!HEX64.test(nodeId || '') || !HEX64.test(claimRef || '')
      || !HEX64.test(value || '') || !Number.isInteger(epoch)) return null;
  const buf = Buffer.alloc(ASSERTION_BYTES);
  let o = 0;
  buf.write(EASSERT_DOMAIN, o, 'utf8'); o += 18;
  Buffer.from(nodeId, 'hex').copy(buf, o); o += 32;
  buf.writeUInt32LE(epoch, o); o += 4;
  Buffer.from(claimRef, 'hex').copy(buf, o); o += 32;
  Buffer.from(value, 'hex').copy(buf, o);
  return buf;
}

/**
 * Sign an assertion — `sign` may be sync or async (bytes → hex sig).
 * MUST be the keystore signer (bridge /sign): the canonical node_id
 * derives from the keystore key, so a gossip-key signature produces
 * assertions no evidence can bind.
 */
export async function signAssertion(fields, sign, pubkey = null) {
  const bytes = assertionBytes(fields);
  if (!bytes) return null;
  const sig = await sign(bytes);
  // pubkey rides the wire UNSIGNED (outside the canonical preimage —
  // matches Rust's EpochAssertion); the evidence supplies it to the
  // fp→identity derive for binding. Here it lets receivers verify
  // the signature immediately.
  return sig ? { ...fields, sig, ...(pubkey ? { pubkey } : {}) } : null;
}

/** Self-assertion for our own claim — value commits the leaf bytes. */
export function selfAssertClaim(claim, leafBytes, sign, pubkey = null) {
  return signAssertion({
    nodeId: claim.nodeId,
    epoch: claim.epoch,
    claimRef: selfClaimRef(claim.nodeId, claim.epoch),
    value: bytesToHex(sha3_256(leafBytes)),
  }, sign, pubkey);
}

/** Witness assertion for a foreign claim — value = its leaf hash. */
export function witnessAssertClaim(claim, leafBytes, ourCanonicalNodeId, sign, pubkey = null) {
  return signAssertion({
    nodeId: ourCanonicalNodeId,
    epoch: claim.epoch,
    claimRef: selfClaimRef(claim.nodeId, claim.epoch),
    value: bytesToHex(sha3_256(leafBytes)),
  }, sign, pubkey);
}

/** Verify an assertion's signature against a presented pubkey. */
export function verifyAssertion(a, pubkey) {
  const bytes = assertionBytes(a);
  if (!bytes || typeof a?.sig !== 'string') return false;
  return verifySignature(bytes, a.sig, pubkey);
}

/**
 * Build EvidenceTx payloads (yakcoind assembles inputs/outputs — it
 * owns the UTXO view; we produce the proof object).
 *   fp = subject's hardware fingerprint (binds pubkey→canonical id).
 */
export function buildEquivocationEvidence({ hwFingerprint, pubkey, assertA, assertB }) {
  return {
    kind: 'equivocation', hwFingerprint, pubkey, assertA, assertB,
  };
}

export function buildBadSealEvidence({ hwFingerprint, pubkey, assertion, leafBytes }) {
  return {
    kind: 'badSeal', hwFingerprint, pubkey, assertion,
    leafPreimage: bytesToHex(leafBytes),
  };
}

// ─── Judgment evidence — bonded-witness quorum ───────────────────────

export const JVERDICT_DOMAIN = 'YAKMESH-JVERDICT';
/** v1 verdict bytes — only 'mismatch' is seizure-class. */
export const VERDICT_MISMATCH = 1;
/** Bonded witnesses needed to convict — mirrors domain-consensus 3-of-5. */
export const JUDGMENT_QUORUM = 3;

/**
 * The verdict value all witnesses must assert — canonical both
 * sides: sha3(JVERDICT ‖ claim_ref ‖ verdict_byte). Every witness
 * signing the same value on the same claim_ref IS the quorum.
 */
export function judgmentVerdictHash(claimRef, verdictByte) {
  if (!HEX64.test(claimRef || '') || !Number.isInteger(verdictByte)) return null;
  return bytesToHex(sha3_256(concatBytes(
    ENC.encode(JVERDICT_DOMAIN), hexToBytes(claimRef),
    new Uint8Array([verdictByte]))));
}

/**
 * A witness judgment assertion — the SAME EpochAssertion artifact:
 * (witness_identity, claim_epoch, claim_ref, verdict_hash).
 */
export function judgmentAssertion({ witnessNodeId, epoch, claimRef, verdictByte }, sign, pubkey = null) {
  const value = judgmentVerdictHash(claimRef, verdictByte);
  if (!value) return null;
  return signAssertion({
    nodeId: witnessNodeId, epoch, claimRef, value,
  }, sign, pubkey);
}

/**
 * Judgment evidence — ≥3 distinct bonded witnesses asserting the same
 * verdict_hash on the same claim_ref. Consensus rederives every
 * identity (subject AND witnesses) from fp‖pubkey; the claim_ref
 * binding proves the subject, never a supplied label.
 * witnesses: [{hwFingerprint, pubkey, assertion}]
 */
export function buildJudgmentEvidence({
  subjectHwFingerprint, subjectPubkey, claimEpoch, claimRef,
  verdictHash, witnesses,
}) {
  return {
    kind: 'judgment', subjectHwFingerprint, subjectPubkey,
    claimEpoch, claimRef, verdictHash, witnesses,
  };
}

// ─── Serde bridge — yakcoind reads these files as `Evidence` ─────────
// Rust-serde JSON: externally-tagged variant, snake_case fields,
// Hash256/bytes as number arrays. This is the wire contract — keep it
// byte-exact with yakcoin-core::claims::Evidence.

const hexArr = (h) => [...hexToBytes(h)];

function assertionSerde(a) {
  return {
    node_id: hexArr(a.nodeId), epoch: a.epoch,
    claim_ref: hexArr(a.claimRef), value: hexArr(a.value),
    sig: hexArr(a.sig),
  };
}

/** Convert a JS evidence payload to the Rust-serde JSON object. */
export function evidenceToSerdeJson(ev) {
  switch (ev.kind) {
    case 'equivocation':
      return { Equivocation: {
        hw_fingerprint: hexArr(ev.hwFingerprint),
        pubkey: hexArr(ev.pubkey),
        assert_a: assertionSerde(ev.assertA),
        assert_b: assertionSerde(ev.assertB),
      } };
    case 'badSeal':
      return { BadSeal: {
        hw_fingerprint: hexArr(ev.hwFingerprint),
        pubkey: hexArr(ev.pubkey),
        assertion: assertionSerde(ev.assertion),
        leaf_preimage: hexArr(ev.leafPreimage),
      } };
    case 'judgment':
      return { Judgment: {
        subject_hw_fingerprint: hexArr(ev.subjectHwFingerprint),
        subject_pubkey: hexArr(ev.subjectPubkey),
        claim_epoch: ev.claimEpoch,
        claim_ref: hexArr(ev.claimRef),
        verdict_hash: hexArr(ev.verdictHash),
        witnesses: ev.witnesses.map(w => ({
          hw_fingerprint: hexArr(w.hwFingerprint),
          pubkey: hexArr(w.pubkey),
          assertion: assertionSerde(w.assertion),
        })),
      } };
    default:
      return null;
  }
}
