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
 * Attestation Gossip — the k-of-m layer that turns local witnessing
 * into network consensus on who contributed.
 *
 * Attestations are SIGNED WITNESS STATEMENTS, not claim re-broadcasts:
 * "I, attester A, witnessed claim {epoch, yakmeshNodeId → yakcoinNodeId,
 * seal}". A claim's k-count is the number of DISTINCT attester nodeIds —
 * counted from received attestations, never read from the claim itself
 * (a claimant inflating their own k is the first attack anyone tries).
 *
 * Cadence: at epoch close (30s boundary) each node attests the claims it
 * witnessed in the just-closed epoch. Attestations for epoch E are
 * accepted through E+1 (grace), frozen at E+2 — matches claim-ledger's
 * bounded-epoch model.
 *
 * Fork evidence rides the same rumor: an attester reporting a forked
 * identity produces quorum-visible slashing evidence.
 *
 * @module mesh/attestation-gossip
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { verifySignature, generateNodeId } from '../identity/node-key.js';
import { createLogger } from '../utils/logger.js';
import { ClaimLedger } from './claim-ledger.js';
import { signAssertion, selfClaimRef, verifyAssertion } from './epoch-assertion.js';
import { DOKODocument } from '../security/doko-identity.js';

const log = createLogger('mesh:attestation-gossip');

const ATTEST_VERSION = 1;
const GRACE_EPOCHS = 2;        // attestations for E accepted while now ≤ E+2
const MAX_EPOCHS = 64;         // matches claim-ledger prune horizon
const MAX_BATCH_ITEMS = 512;   // bound per-batch processing work
const MAX_EVIDENCE_ITEMS = 16; // matches the sender-side cap
const MAX_REPORTED_EVIDENCE = 512; // ring bound — evidence is a record, not a leak

/**
 * Canonical claim leaf — SHA3-256 over the 81-byte canonical claim
 * encoding (claim-ledger.claimLeafBytes). The wormhole seal binds only
 * (nodeId, epoch) — shareCount/jobRoot/spongeRounds are uncommitted, so
 * without the leaf a claimant could equivocate on work quantities across
 * witness subsets and attestations would merge invisibly. Two witnesses
 * reporting different leaves for one claimKey is provable equivocation.
 */
export function claimLeafHash(c) {
  return bytesToHex(sha3_256(ClaimLedger.claimLeafBytes(c)));
}

/**
 * Canonical claim key — every attester derives the same key for the
 * same witnessed claim. (epoch, yakmeshNodeId) is canonical because
 * claim-ledger is first-claim-wins per node per epoch.
 */
export function claimKey(epoch, yakmeshNodeId) {
  return bytesToHex(sha3_256(utf8ToBytes(`${epoch}:${yakmeshNodeId}`)));
}

/** Per-batch bound on keystore-signed canon assertions — each is a
 *  bridge /sign round-trip; items beyond the cap still ride the
 *  batch-level JSON signature (unchanged semantics). */
export const MAX_CANON_ITEMS = 32;

/** What one attester signed over — the full attested tuple. */
function attestationPreimage(a) {
  return `attest:${a.epoch}:${a.yakmeshNodeId}:${a.claimNodeId}:${a.seal.join(',')}`;
}

/**
 * deviceClass → settlement ClaimClass (Rust enum names, verbatim).
 * Only VERIFIED device labels reach this map — claimed-/forged-/
 * unproven collapse to Generic. An undifferentiated 'gpu'/'cpu'
 * (hwProof.deviceClass can't tell CUDA from WebGPU, SHA from VAES)
 * takes the floor cap of that tier — honest, conservative, never
 * inflated.
 */
function settlementClass(deviceClass) {
  switch (deviceClass) {
    case 'npu': return 'NpuXdna1';
    case 'gpu': return 'GpuWebgpu';
    case 'cpu': return 'CpuSha';
    default: return 'Generic';
  }
}

/**
 * Claim record → wire proof_state. 'invalid' carries no reason across
 * the boundary (the reason is JS-side evidence; settlement only needs
 * the exclusion). Device labels inside attested/unsigned use the Rust
 * DeviceClass names.
 */
function settlementProofState(c) {
  const v = c.proofVerification || {};
  const bad = ['forged', 'malformed'];
  if (bad.includes(v.npu) || bad.includes(v.hw)) return 'invalid';
  if (v.npu === 'verified') return { attested: 'Npu' };
  if (v.hw === 'verified') {
    const d = c.hwProof?.deviceClass;
    return { attested: d === 'gpu' ? 'Gpu' : d === 'npu' ? 'Npu' : d === 'cpu' ? 'Cpu' : 'Unknown' };
  }
  if (c.npuProof) return { unsigned: 'Npu' };
  if (c.hwProof) {
    const d = c.hwProof.deviceClass;
    return { unsigned: d === 'gpu' ? 'Gpu' : d === 'npu' ? 'Npu' : d === 'cpu' ? 'Cpu' : 'Unknown' };
  }
  return null;
}

export class AttestationGossip extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.nodeId - our yakmesh nodeId
   * @param {string} opts.publicKey - our ML-DSA-65 pubkey hex
   * @param {function} opts.sign - (data:string) => sigHex
   * @param {ClaimLedger} opts.claimLedger - witness source
   */
  constructor(opts) {
    super();
    this.nodeId = opts.nodeId;
    this.publicKey = opts.publicKey;
    this.sign = opts.sign;
    this.claimLedger = opts.claimLedger;

    /** @type {Map<number, Map<string, Set<string>>>} epoch → claimKey → attesterIds */
    this.attestations = new Map();
    /** @type {Map<string, object>} claimKey → {seal, claimNodeId} first-seen */
    this.claimRefs = new Map();
    /** Fork/binding evidence received from attestations */
    this.reportedEvidence = [];
    /** Foreign canon assertions: claimKey → attester → {leaf, canon}.
     *  Two canonically-signed different values for one claimRef from
     *  one attester = provable equivocation (EvidenceTx material). */
    this.foreignAssertions = new Map();
    this.canonicalNodeId = opts.canonicalNodeId || null; // () → hex
    this.canonSign = opts.canonSign || null;             // async keystore signer
    this.canonPubkey = opts.canonPubkey || null;         // () → keystore pubkey hex
    this.canonHwFp = opts.canonHwFp || null;             // () → keystore hw fp hex
    // Claims carry their own personhood proof (pidBind triple) — the
    // persistent key binds pid→nodeId→epoch, and pid re-derives from
    // the pubkey via wormhole-sealed AVOTH. No table lookup needed.
    this.stats = { sent: 0, received: 0, dupes: 0, badSigs: 0, conflicts: 0 };
  }

  /**
   * Build our attestation batch for a just-closed epoch.
   * One signature covers the batch + any fork evidence we hold.
   */
  async buildBatch(epoch) {
    const claims = this.claimLedger.epochClaims(epoch);
    if (claims.length === 0 && this.claimLedger.forks.length === 0) return null;

    // Only attest VERIFIED claims — a witness must not vouch for
    // unsigned or forged beats (v3.5.3 signed-heartbeat fix). Claims
    // that FAILED the AVOTH seal recompute (sealVerified === false, set
    // by claimLedger.verifyEpochSeals at epoch close) are excluded too —
    // seal failure is emitted separately as sealFailure evidence.
    // sealVerified === undefined (bridge unreachable) still attests:
    // verification defers to settlement, never fabricated.
    const base = claims.filter(c =>
      c.verified === 'verified' && c.sealVerified !== false).map(c => ({
      epoch,
      yakmeshNodeId: c.yakmeshNodeId,
      claimNodeId: c.nodeId,
      seal: c.seal,
      leaf: claimLeafHash(c),
    }));
    // Canon assertions — keystore-signed canonical artifacts per item
    // (slashable evidence objects). Bounded by MAX_CANON_ITEMS; the
    // batch signature still covers every item either way.
    const canonId = this.canonicalNodeId?.();
    const canonFp = this.canonHwFp?.();
    const items = [];
    for (const item of base) {
      if (this.canonSign && canonId && items.length < MAX_CANON_ITEMS) {
        // hwFingerprint rides UNSIGNED like pubkey — settlement binds
        // it by re-deriving node_id = AVOTH(fp‖pk), so a forged fp is
        // self-refuting; a missing fp leaves the proof hardware-weak.
        const canon = await signAssertion({
          nodeId: canonId, epoch: item.epoch,
          claimRef: selfClaimRef(item.claimNodeId, item.epoch),
          value: item.leaf,
          ...(canonFp ? { hwFingerprint: canonFp } : {}),
        }, this.canonSign, this.canonPubkey?.());
        if (canon) item.canon = canon; // absent when bridge is down
      }
      items.push(item);
    }
    const forks = this.claimLedger.forks.slice(-16).map(f => ({
      nodeId: f.nodeId, sequence: f.sequence, hashA: f.hashA, hashB: f.hashB,
    }));
    const conflicts = this.claimLedger.bindingConflicts.slice(-16);

    const batch = {
      v: ATTEST_VERSION,
      attester: this.nodeId,
      pubKey: this.publicKey,
      epoch,
      items,
      evidence: { forks, conflicts },
      sig: null,
    };
    batch.sig = this.sign(JSON.stringify({ ...batch, sig: undefined }));
    return batch;
  }

  /**
   * Process a received claim:attest batch.
   * @returns {{accepted:number, rejected:number}}
   */
  receive(batch, origin) {
    if (!batch || batch.v !== ATTEST_VERSION || !batch.attester) return { accepted: 0, rejected: 0 };
    if (batch.attester === this.nodeId) return { accepted: 0, rejected: 0 }; // ours

    // Grace window: attestations for E only valid while now ≤ E+2
    const now = Math.floor(Date.now() / 30000);
    if (!Number.isInteger(batch.epoch) || batch.epoch > now || batch.epoch < now - GRACE_EPOCHS) {
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    // Verify batch signature over the signed payload
    const { sig, ...signed } = batch;
    if (!batch.pubKey || !verifySignature(JSON.stringify(signed), sig, batch.pubKey)) {
      this.stats.badSigs++;
      log.warn('attestation batch bad signature', { from: batch.attester });
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    // IDENTITY BINDING: batch.attester must derive from batch.pubKey.
    // Otherwise a sybil can mint arbitrary attester nodeIds, each signing
    // a self-consistent batch with its own key, inflating k-of-m counts
    // with identities that don't exist. Same binding as HELLO handshake.
    try {
      if (generateNodeId(hexToBytes(batch.pubKey)) !== batch.attester) {
        this.stats.badSigs++;
        log.warn('attestation batch attester not bound to pubkey', { from: batch.attester });
        return { accepted: 0, rejected: batch.items?.length || 0 };
      }
    } catch {
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    let accepted = 0;
    const skips = { shape: 0, canon: 0, canonNodeId: 0, sealConflict: 0, nodeIdConflict: 0, leafConflict: 0, refConflict: 0, dupe: 0 };
    let epochMap = this.attestations.get(batch.epoch);
    if (!epochMap) {
      epochMap = new Map();
      this.attestations.set(batch.epoch, epochMap);
      this._prune();
    }

    // Our own witnessed claims are ground truth for this epoch: a foreign
    // attestation contradicting what WE saw is conflict evidence, never a
    // reference. First-seen-wins applies only to claims we did not witness
    // — closes the seal-poisoning DoS where an early malicious attestation
    // suppresses an honest claim's count by planting a wrong seal.
    const ours = new Map();
    for (const c of this.claimLedger.epochClaims(batch.epoch)) {
      ours.set(claimKey(c.epoch, c.yakmeshNodeId), c);
    }

    const items = Array.isArray(batch.items) ? batch.items.slice(0, MAX_BATCH_ITEMS) : [];

    for (const item of items) {
      // Item scope: every item must belong to the batch's own epoch —
      // the grace check covers batch.epoch only, so an item carrying a
      // different epoch would inject stale/future attestations past it.
      if (item.epoch !== batch.epoch ||
          typeof item.yakmeshNodeId !== 'string' ||
          typeof item.claimNodeId !== 'string' || !/^[0-9a-f]{64}$/.test(item.claimNodeId) ||
          !Array.isArray(item.seal) || item.seal.length !== 4 ||
          item.seal.some(q => !Number.isInteger(q) || q < 0 || q > 3)) {
        skips.shape++; continue;
      }

      const key = claimKey(item.epoch, item.yakmeshNodeId);
      const seen = ours.get(key);
      const sealStr = item.seal.join(',');

      // Canon assertion handling — keystore-signed artifacts. Verify
      // the signature against the declared pubkey; cross-check
      // canon.nodeId against the attester's own witnessed claim when
      // we hold one. Two different values for the same claimRef from
      // the same attester = provable equivocation (evidence material).
      if (item.canon) {
        const canonOk = verifyAssertion(item.canon, item.canon.pubkey)
          && item.canon.claimRef === selfClaimRef(item.claimNodeId, item.epoch)
          && item.canon.value === item.leaf;
        if (!canonOk) { this.stats.badSigs++; skips.canon++; continue; }
        const witClaim = this.claimLedger?.epochs?.get(item.epoch)?.get(batch.attester);
        if (witClaim && item.canon.nodeId !== witClaim.nodeId) { skips.canonNodeId++; continue; }
        let entry = this.foreignAssertions.get(key);
        if (!entry) {
          entry = { epoch: item.epoch, byAttester: new Map() };
          this.foreignAssertions.set(key, entry);
        }
        const prev = entry.byAttester.get(batch.attester);
        if (prev && prev.canon.value !== item.canon.value) {
          this.emit('attesterEquivocation', {
            attester: batch.attester, claimKey: key,
            keystorePubkey: item.canon.pubkey,
            assertA: prev.canon, assertB: item.canon,
          });
        }
        entry.byAttester.set(batch.attester, { leaf: item.leaf, canon: item.canon });
      }

      if (seen) {
        if (seen.seal.join(',') !== sealStr) {
          this.stats.conflicts++;
          skips.sealConflict++;
          this.emit('sealConflict', {
            claimKey: key, attester: batch.attester,
            sealA: seen.seal.join(','), sealB: sealStr,
          });
          continue;
        }
        // Binding mirror: the attester vouches a different yakcoin
        // nodeId for a yakmesh identity we witnessed — same class of
        // conflict claim-ledger emits as bindingConflict.
        if (seen.nodeId !== item.claimNodeId) {
          this.stats.conflicts++;
          skips.nodeIdConflict++;
          this.emit('sealConflict', {
            claimKey: key, attester: batch.attester,
            sealA: `nodeId:${seen.nodeId.slice(0, 16)}`,
            sealB: `nodeId:${item.claimNodeId.slice(0, 16)}`,
          });
          continue;
        }
        // Leaf binding: same identity+seal but a different canonical
        // claim leaf = the claimant equivocated on work quantities
        // across witness subsets. Provable misconduct — evidence, not
        // attestable weight.
        if (item.leaf && item.leaf !== claimLeafHash(seen)) {
          this.stats.conflicts++;
          skips.leafConflict++;
          this.emit('claimEquivocation', {
            claimKey: key, attester: batch.attester,
            yakmeshNodeId: item.yakmeshNodeId,
            leafA: claimLeafHash(seen), leafB: item.leaf,
          });
          continue;
        }
      }

      // Seal consistency: two attesters reporting different seals for the
      // same claim = conflict evidence (like binding conflicts)
      const ref = this.claimRefs.get(key);
      if (ref && ref.seal !== sealStr) {
        this.stats.conflicts++;
        skips.refConflict++;
        this.emit('sealConflict', {
          claimKey: key,
          attester: batch.attester,
          sealA: ref.seal, sealB: sealStr,
        });
        continue; // conflicting attestations don't count
      }
      if (!ref) this.claimRefs.set(key, {
        epoch: item.epoch, seal: sealStr,
        claimNodeId: item.claimNodeId, yakmeshNodeId: item.yakmeshNodeId,
        leaf: typeof item.leaf === 'string' ? item.leaf : null,
      });

      let attesters = epochMap.get(key);
      if (!attesters) {
        attesters = new Set();
        epochMap.set(key, attesters);
      }
      if (attesters.has(batch.attester)) {
        this.stats.dupes++;
        skips.dupe++;
        continue; // same attester, same claim — count once
      }
      attesters.add(batch.attester);
      accepted++;
      this.stats.received++;
    }

    // Fork/binding evidence rides along — quorum-visible slashing material
    for (const f of (batch.evidence?.forks || []).slice(0, MAX_EVIDENCE_ITEMS)) {
      this.reportedEvidence.push({ kind: 'fork', reporter: batch.attester, ...f });
    }
    for (const c of (batch.evidence?.conflicts || []).slice(0, MAX_EVIDENCE_ITEMS)) {
      this.reportedEvidence.push({ kind: 'bindingConflict', reporter: batch.attester, ...c });
    }
    if (this.reportedEvidence.length > MAX_REPORTED_EVIDENCE) {
      this.reportedEvidence.splice(0, this.reportedEvidence.length - MAX_REPORTED_EVIDENCE);
    }

    if (accepted > 0) this.emit('attestations', { epoch: batch.epoch, from: batch.attester, accepted });
    log.debug('claim attestation batch processed', {
      from: batch.attester, epoch: batch.epoch, accepted,
      items: batch.items?.length || 0, skips,
    });
    return { accepted, rejected: (batch.items?.length || 0) - accepted };
  }

  /**
   * The attested set for settlement — claims with their distinct-attester
   * counts. This is what becomes EpochClaim.attestations.
   */
  attestedSet(epoch) {
    const epochMap = this.attestations.get(epoch);
    if (!epochMap) return [];
    const set = [];
    for (const [key, attesters] of epochMap) {
      const ref = this.claimRefs.get(key);
      const claim = this.claimLedger.epochClaims(epoch)
        .find(c => claimKey(c.epoch, c.yakmeshNodeId) === key);
      // Hardware-distinct attestation count. canon.nodeId is the
      // attester's keystore identity — signature-verified at receive —
      // so N gossip identities on one machine collapse to one vote,
      // and an attester on the claimant's own hardware is excluded
      // entirely (self-attestation). Gossip-only attesters (no canon
      // material) carry no hardware proof and do not buy quorum.
      const selfId = ref?.claimNodeId ?? claim?.nodeId;
      const hwIds = new Set();
      const byAttester = this.foreignAssertions.get(key)?.byAttester;
      for (const a of attesters) {
        const canonId = byAttester?.get(a)?.canon?.nodeId;
        if (canonId && canonId !== selfId) hwIds.add(canonId);
      }
      set.push({
        claimKey: key,
        yakmeshNodeId: claim?.yakmeshNodeId ?? ref?.yakmeshNodeId,
        claimNodeId: ref?.claimNodeId,
        seal: ref?.seal?.split(',').map(Number),
        shares: claim?.shareCount || 0,
        attestations: hwIds.size,
        rawAttestations: attesters.size,
        attesterIds: [...hwIds].sort(),
        witnessed: claim != null, // did WE see this claim, or only hear it attested?
      });
    }
    return set;
  }

  /**
   * Settlement input producer — the EpochClaim-shaped objects the
   * yakcoin side consumes. Every field is derived from witnessed data:
   *
   *   node_id      — the claim's yakcoin identity
   *   seal         — the witnessed wormhole seal (verified at settlement)
   *   class        — mapped from deviceClass, which is itself built from
   *                  VERIFIED proofs only. An undifferentiated 'gpu' or
   *                  'cpu' takes the floor of that tier; claimed-/forged-/
   *                  unproven all collapse to Generic — self-reported
   *                  labels never buy a better cap.
   *   karma_age    — consecutive witnessed epochs (claim-ledger
   *                  presenceStreak). A node with fork or binding-conflict
   *                  evidence is contested: its age reports 0 = floor
   *                  weight. Evidence stays attached; KARMA is the burn.
   *   shares       — witnessed work weight (ACCEPTED receipts, else
   *                  leaf-committed shareCount). Settlement does NOT
   *                  trust this field: it recounts from `receipts`
   *                  (verified signatures bound to the claim), or pins
   *                  to the leaf's shareCount when receipts are absent.
   *                  Emitted for the audit record.
   *   attestations — distinct HARDWARE attester count (canon nodeIds,
   *                  signature-verified) — gossip identities on shared
   *                  keystore collapse to one vote; the claimant's own
   *                  hardware is excluded
   *   attester_ids — the sorted canon nodeIds backing that count, so
   *                  the settlement consumer can recompute quorum and
   *                  audit exactly which machines witnessed the claim
   *   hw_fingerprint + pubkey — the claimant's hardware binding,
   *                  decoded from its witnessed attestation bundle
   *                  (fp@33..65, pk@69..pkLen). Settlement re-derives
   *                  node_id = AVOTH(fp‖pk) — the fp is PROVEN, so
   *                  same-silicon self-attestation is provably excluded.
   *   leaf         — the 81-byte canonical claim leaf (hex) — the
   *                  object every attester proof commits to; settlement
   *                  binds it (node_id @49..81, epoch @1..5, seal @45..49)
   *                  before any proof can count.
   *   attester_proofs — the signed canon assertions themselves
   *                  ({hw_fingerprint, pubkey, node_id, epoch,
   *                  claim_ref, value, sig} — hex). When present they
   *                  are the ONLY quorum source on the Rust side: each
   *                  signature verifies in-process, attesters dedupe by
   *                  fingerprint. Proofs without a fingerprint could
   *                  never prove hardware distinctness — not emitted.
   *   receipts     — the claim's issuer receipts (snake_case wire),
   *                  each carrying issuer_doko_hash so the consumer
   *                  rebuilds the exact signed preimage. shares on the
   *                  Rust side = verified-receipt count, or the
   *                  leaf-committed shareCount when absent.
   *   proof_state  — 'invalid' on any forged/malformed inner attestation,
   *                  {attested|unsigned:<device>} on verified/unsigned
   *                  proofs, null when the claim carried no proof.
   *
   * Only claims WE witnessed enter the set — attested-but-unwitnessed
   * entries in attestedSet are context, never settlement weight.
   */
  settlementInputs(epoch) {
    const byKey = new Map(this.attestedSet(epoch)
      .map(a => [a.claimKey, a]));
    const ledger = this.claimLedger;
    const contested = (id) =>
      ledger.bindingConflicts?.some(c => c.yakmeshNodeId === id) ||
      ledger.forksFor?.(id)?.length > 0;

    return ledger.epochClaims(epoch).map(c => {
      const key = claimKey(c.epoch, c.yakmeshNodeId);
      const att = byKey.get(key);
      // Issuer receipts are verified at observe; when a claim carries
      // them the accepted count is the witnessed share weight. A claim
      // whose receipts only reach 'observe' (issuer authority unknown)
      // earns zero — attestable work requires an attested issuer.
      let shares = c.shareCount;
      if (Array.isArray(c.receipts) && c.receipts.length > 0) {
        const acc = c.receiptVerification?.receipts
          ?.filter(r => r.verdict === 'accept').length ?? 0;
        shares = acc;
      }
      // Claimant hardware binding — decoded from its witnessed
      // attestation bundle (version‖nodeId‖hwFp‖pkLen u32LE‖pk‖…).
      // fp@33..65, pkLen@65..69, pk@69.. — settlement re-derives
      // node_id = AVOTH(fp‖pk), so the declared fp is PROVEN, not
      // self-asserted: same-silicon exclusion can't be lied about.
      // Absent bundle → absent fields → proofs can't count (no
      // verifiable claimant binding).
      let claimantFp = null;
      let claimantPk = null;
      if (typeof c.attestationBundle === 'string') {
        try {
          const raw = Buffer.from(c.attestationBundle, 'base64');
          if (raw.length >= 69) {
            const pkLen = raw.readUInt32LE(65);
            if (raw.length >= 69 + pkLen && pkLen > 0) {
              claimantFp = raw.subarray(33, 65).toString('hex');
              claimantPk = raw.subarray(69, 69 + pkLen).toString('hex');
            }
          }
        } catch { /* malformed bundle → no binding */ }
      }
      // The signed witness evidence itself — every canon assertion a
      // foreign attester made about this claim. Only fp-carrying
      // proofs can establish hardware distinctness on the consumer
      // side; fp-less canon still counted toward attester_ids above
      // (identity dedupe) but is omitted here.
      const attester_proofs = [];
      const byAttester = this.foreignAssertions.get(key)?.byAttester;
      if (byAttester) {
        for (const { canon } of byAttester.values()) {
          if (!canon?.hwFingerprint || !canon?.pubkey) continue;
          attester_proofs.push({
            hw_fingerprint: canon.hwFingerprint,
            pubkey: canon.pubkey,
            node_id: canon.nodeId,
            epoch: canon.epoch,
            claim_ref: canon.claimRef,
            value: canon.value,
            sig: canon.sig,
          });
        }
      }
      // The receipt set — carried so settlement verifies shares rather
      // than trusting our accept-count. issuer_doko_hash is the DOKO's
      // committed content hash (getContentHash) — inside the signed
      // bytes, so the consumer can rebuild the exact preimage.
      const receipts = [];
      if (Array.isArray(c.receipts)) {
        for (const r of c.receipts.slice(0, 128)) {
          let issuer_doko_hash = null;
          if (r.issuerDoko) {
            try {
              issuer_doko_hash = DOKODocument
                .fromJSON(r.issuerDoko).getContentHash();
            } catch { /* malformed doc → hash absent, sig still verifiable */ }
          }
          receipts.push({
            version: r.version, job_id: r.jobId,
            issuer_node: r.issuerNode, issuer_pubkey: r.issuerPubkey,
            worker_node: r.workerNode, epoch: r.epoch,
            work_class: r.workClass, result_hash: r.resultHash,
            fee_paid: r.feePaid ?? 0, seal: r.seal,
            issuer_persistent_id: r.issuerPersistentId || '',
            ...(issuer_doko_hash ? { issuer_doko_hash } : {}),
            issuer_sig: r.issuerSig,
          });
        }
      }
      return {
        node_id: c.nodeId,
        // The account this claim credits — self-contained personhood
        // proof verified at observe: pid = 324T wormhole-sealed AVOTH
        // digest of the persistent pubkey + persistent-key signature
        // binding pid→nodeId→epoch. node_id is this epoch's spend key;
        // the pid is the personhood (seed-derived, survives rotation).
        ...(c.pidBind ? {
          persistent_id: c.pidBind.persistentId,
          persistent_pubkey: c.pidBind.persistentPubkey,
          persistent_sig: c.pidBind.persistentSig,
        } : {}),
        seal: c.seal,
        epoch: c.epoch,
        shares,
        class: settlementClass(c.deviceClass),
        karma_age: contested(c.yakmeshNodeId) ? 0 : ledger.presenceStreak(c.yakmeshNodeId, epoch),
        attestations: att?.attestations || 0,
        ...(claimantFp ? { hw_fingerprint: claimantFp } : {}),
        ...(claimantPk ? { pubkey: claimantPk } : {}),
        leaf: bytesToHex(ClaimLedger.claimLeafBytes(c)),
        attester_proofs,
        ...(receipts.length ? { receipts } : {}),
        // The claim's own proofs — settlement verifies them in-process;
        // class/proof_state below are audit metadata, not authority.
        ...(c.npuProof ? { npu_proof: c.npuProof } : {}),
        ...(c.hwProof ? { hw_proof: c.hwProof } : {}),
        attester_ids: att?.attesterIds || [],
        proof_state: settlementProofState(c),
      };
    });
  }

  _prune() {
    while (this.attestations.size > MAX_EPOCHS) {
      const oldest = Math.min(...this.attestations.keys());
      this.attestations.delete(oldest);
    }
    // claimRefs carries the same epoch horizon — refs for pruned epochs
    // are dead weight. (Was unbounded before; ref.epoch enables this.)
    if (this.attestations.size === 0) {
      this.claimRefs.clear();
      this.foreignAssertions.clear();
      return;
    }
    const floor = Math.min(...this.attestations.keys());
    for (const [key, ref] of this.claimRefs) {
      if (ref.epoch < floor) this.claimRefs.delete(key);
    }
    for (const [key, entry] of this.foreignAssertions) {
      if (entry.epoch < floor) this.foreignAssertions.delete(key);
    }
  }
}
