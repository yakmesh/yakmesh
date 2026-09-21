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
 * Claim Ledger — the witness side of yakcoin contribution transport.
 *
 * Observes received pulse:heartbeat rumors, extracts meshState.contribution,
 * and accumulates the per-epoch witnessed claim set that settlement
 * consumes. Also detects chain forks and identity-binding conflicts:
 *
 * - CHAIN FORK: same (nodeId, sequence), different hash → the node is
 *   emitting divergent histories = cloned identity or rewritten chain.
 *   Cryptographic evidence, not suspicion.
 * - BINDING CONFLICT: same yakmesh nodeId claiming a different yakcoin
 *   nodeId → identity layer mismatch (machine-seed cloned onto another
 *   box, or keystore rebound — either way, witnessed).
 *
 * This is a LOCAL witness record. True k-of-m quorum emerges when nodes
 * gossip their ledger attestations — that aggregation is the settlement
 * layer's job, not this module's.
 *
 * @module mesh/claim-ledger
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { createLogger } from '../utils/logger.js';
import { verifySignature } from '../identity/node-key.js';
import { npuProofClaim, hwProofClaim } from './contribution.js';

const log = createLogger('mesh:claim-ledger');

const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE || 'http://127.0.0.1:9995';
const VERIFY_TIMEOUT_MS = 30000;

/**
 * Structural check on a contribution claim — shape only. The wormhole
 * seal's cryptographic validity is verified at settlement (AVOTH
 * recompute); here we only confirm it is well-formed.
 */
function validContributionShape(c) {
  return c
    && c.version === 1
    && Number.isInteger(c.epoch) && c.epoch > 0
    && typeof c.nodeId === 'string' && /^[0-9a-f]{64}$/.test(c.nodeId)
    && Array.isArray(c.seal) && c.seal.length === 4
    && c.seal.every(q => Number.isInteger(q) && q >= 0 && q <= 3)
    && Number.isInteger(c.spongeRounds) && c.spongeRounds >= 0
    && Number.isInteger(c.shareCount) && c.shareCount >= 0
    && typeof c.jobRoot === 'string' && /^[0-9a-f]{64}$/.test(c.jobRoot)
    && Number.isInteger(c.entropyFlags);
}

export class ClaimLedger extends EventEmitter {
  constructor(options = {}) {
    super();
    this.nodeId = options.nodeId;            // our yakmesh nodeId (skip self)
    this.maxEpochs = options.maxEpochs || 64;

    /** @type {Map<string, Map<string, object>>} epoch → nodeId → claim */
    this.epochs = new Map();

    /** @type {Map<string, Map<number, string>>} nodeId → seq → hash */
    this.seenSeq = new Map();

    /** @type {Map<string, string>} yakmesh nodeId → yakcoin nodeId */
    this.bindings = new Map();

    this.forks = [];        // recorded fork evidence
    this.bindingConflicts = [];
  }

  /**
   * Observe a received heartbeat. Call for every pulse:heartbeat rumor.
   * @param {object} hb - serialized heartbeat (post-deserialize)
   */
  /**
   * Observe a received heartbeat. `opts.verified` — 'verified' (ML-DSA
   * signature checks out), 'unsigned' (legacy), or 'forged' (bad sig).
   * Unverified claims are recorded as evidence but NEVER attested.
   */
  observe(hb, opts = {}) {
    if (!hb || !hb.nodeId || hb.nodeId === this.nodeId) return;

    this._checkFork(hb);

    const c = hb.meshState?.contribution;
    if (!c) return; // unattested heartbeat — nothing to record

    if (!validContributionShape(c)) {
      log.warn('malformed contribution claim', { from: hb.nodeId });
      this.emit('malformed', { nodeId: hb.nodeId, claim: c });
      return;
    }

    this._checkBinding(hb.nodeId, c.nodeId);

    // Record into the epoch bucket (first claim per node per epoch wins —
    // a node can't upgrade its claim mid-epoch; conflicts are evidence)
    let bucket = this.epochs.get(c.epoch);
    if (!bucket) {
      bucket = new Map();
      this.epochs.set(c.epoch, bucket);
      this._prune();
    }
    if (!bucket.has(hb.nodeId)) {
      // Inner attestations: npuProof/hwProof carry a keystore ML-DSA-65
      // signature over the canonical claim string (contribution.js) —
      // separate from the heartbeat signature, which only covers the
      // heartbeat hash. Recompute the claim from the witnessed proof
      // fields and verify; a bad signature or rebound fields are forgery
      // evidence, never attestable weight.
      const proofVerification = this._verifyInnerProofs(c, hb.nodeId);
      bucket.set(hb.nodeId, {
        ...c,
        yakmeshNodeId: hb.nodeId,
        firstSeenSeq: hb.sequence,
        witnessedAt: hb.timestamp,
        verified: opts.verified || 'unsigned',
        proofVerification,
        deviceClass: ClaimLedger._classifyDevice(c, proofVerification),
      });
      this.emit('claim', bucket.get(hb.nodeId));
    }
  }

  /**
   * Verify the inner keystore attestations on npuProof/hwProof. Per-proof
   * verdict: 'verified' | 'forged' | 'malformed' | 'unsigned'. Only
   * present proofs get a key. Forgery/malformation is emitted as
   * 'proofForgery' evidence — the raw proof stays on the claim record.
   */
  _verifyInnerProofs(c, yakmeshNodeId) {
    const out = {};
    if (c.npuProof) out.npu = this._verifyProofAttestation('npu', c);
    if (c.hwProof) out.hw = this._verifyProofAttestation('hw', c);
    for (const [kind, verdict] of Object.entries(out)) {
      if (verdict === 'forged' || verdict === 'malformed') {
        const evidence = { nodeId: yakmeshNodeId, epoch: c.epoch, kind, verdict, at: Date.now() };
        log.error('CLAIM forged inner attestation', evidence);
        this.emit('proofForgery', evidence);
      }
    }
    return out;
  }

  _verifyProofAttestation(kind, c) {
    const proof = kind === 'npu' ? c.npuProof : c.hwProof;
    const claimFn = kind === 'npu' ? npuProofClaim : hwProofClaim;
    const att = proof?.attestation;
    if (!att) return 'unsigned';
    if (typeof att.claim !== 'string' || typeof att.signature !== 'string' || typeof att.publicKey !== 'string') {
      return 'malformed';
    }
    // Field binding: the signed claim must be the canonical form of the
    // proof fields exactly as witnessed — a mismatch means fields were
    // altered after signing or the attestation belongs to other data.
    if (att.claim !== claimFn(c.epoch, c.nodeId, proof)) return 'forged';
    return verifySignature(att.claim, att.signature, att.publicKey) ? 'verified' : 'forged';
  }

  /**
   * Honest executor classification — derived from VERIFIED proofs only.
   * An unverified proof is recorded as claimed-* evidence; a failed one
   * as forged-*; no proofs at all is 'unproven'. The producer's own
   * labels are never trusted on their own.
   */
  static _classifyDevice(c, verdicts) {
    const bad = (v) => v === 'forged' || v === 'malformed';
    if (verdicts.npu === 'verified') return 'npu';
    if (verdicts.hw === 'verified') return c.hwProof?.deviceClass || 'hw';
    if (c.npuProof) return bad(verdicts.npu) ? 'forged-npu' : 'claimed-npu';
    if (c.hwProof) {
      const cls = c.hwProof.deviceClass || 'hw';
      return bad(verdicts.hw) ? `forged-${cls}` : `claimed-${cls}`;
    }
    return 'unproven';
  }

  /**
   * Fork detection: a second heartbeat for (nodeId, sequence) with a
   * different hash is proof of divergent chain emission.
   */
  _checkFork(hb) {
    let seqs = this.seenSeq.get(hb.nodeId);
    if (!seqs) {
      seqs = new Map();
      this.seenSeq.set(hb.nodeId, seqs);
    }
    const seenHash = seqs.get(hb.sequence);
    if (seenHash && seenHash !== hb.hash) {
      const evidence = {
        nodeId: hb.nodeId,
        sequence: hb.sequence,
        hashA: seenHash,
        hashB: hb.hash,
        at: Date.now(),
      };
      this.forks.push(evidence);
      log.warn('⛓️ CHAIN FORK — cloned identity or rewritten history', evidence);
      this.emit('fork', evidence);
      return;
    }
    if (!seenHash) seqs.set(hb.sequence, hb.hash);
    // bound memory per node
    if (seqs.size > 600) {
      const oldest = Math.min(...seqs.keys());
      seqs.delete(oldest);
    }
  }

  /**
   * yakmesh nodeId ↔ yakcoin nodeId binding — first claim wins.
   */
  _checkBinding(yakmeshNodeId, yakcoinNodeId) {
    const bound = this.bindings.get(yakmeshNodeId);
    if (bound && bound !== yakcoinNodeId) {
      const conflict = { yakmeshNodeId, boundA: bound, boundB: yakcoinNodeId, at: Date.now() };
      this.bindingConflicts.push(conflict);
      log.warn('BINDING CONFLICT — node claims different yakcoin identity', conflict);
      this.emit('bindingConflict', conflict);
      return;
    }
    if (!bound) this.bindings.set(yakmeshNodeId, yakcoinNodeId);
  }

  /** All witnessed claims for an epoch → what settlement consumes. */
  epochClaims(epoch) {
    return [...(this.epochs.get(epoch)?.values() || [])];
  }

  /**
   * Cryptographic seal verification for an epoch's witnessed claims —
   * upgrades the shape check to a real AVOTH recompute via the pq-bridge
   * (/yakcoin/verify-claims, triad-dispatched: GPU bulk, NPU dot matrix,
   * or CPU floor). One POST verifies the whole epoch.
   *
   * Verdicts are written back onto the witnessed claim records
   * (`sealVerified: true|false`) and failing claims are emitted as
   * 'sealFailure' evidence — a forged or transplanted seal is provable
   * misconduct, not a shape error. Returns null when the bridge is
   * unreachable (witnessing continues; verification defers to settlement).
   */
  async verifyEpochSeals(epoch) {
    const bucket = this.epochs.get(epoch);
    if (!bucket || bucket.size === 0) return null;

    const entries = [...bucket.values()];
    const claims = entries.map(c => ({
      node_id: c.nodeId,
      epoch: c.epoch,
      seal: c.seal,
    }));

    let res;
    try {
      res = await fetch(`${BRIDGE_URL}/yakcoin/verify-claims`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claims }),
        signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
      });
    } catch (e) {
      log.warn('seal verification unreachable', { epoch, error: e.message });
      return null;
    }
    if (!res.ok) {
      log.warn('seal verification rejected', { epoch, status: res.status });
      return null;
    }
    const body = await res.json();

    entries.forEach((claim, i) => {
      // Verdict shape: legacy `true|false` or the signed-claim object
      // `{seal_valid, sig_valid, valid}` — sealVerified tracks the seal
      // layer specifically (these claims carry no signature, so
      // sig_valid is null and valid === seal_valid).
      const v = body.verdicts?.[i];
      claim.sealVerified = v === true || v?.seal_valid === true;
      if (!claim.sealVerified) {
        const evidence = {
          yakmeshNodeId: claim.yakmeshNodeId,
          nodeId: claim.nodeId,
          epoch: claim.epoch,
          seal: claim.seal,
          at: Date.now(),
        };
        log.warn('SEAL FAILURE — forged or transplanted claim seal', evidence);
        this.emit('sealFailure', evidence);
      }
    });

    return {
      epoch,
      total: body.total,
      valid: body.valid,
      invalid: body.invalid,
      device: body.device,
      elapsedMs: body.elapsed_ms,
    };
  }

  /** Fork evidence for a node — empty = clean record. */
  forksFor(nodeId) {
    return this.forks.filter(f => f.nodeId === nodeId);
  }

  /**
   * Canonical 81-byte claim encoding — the Merkle leaf preimage.
   * Commits to the wire-format claim fields only; npuProof/hwProof are
   * auxiliary evidence attachments, not part of the canonical claim, and
   * witness metadata (firstSeenSeq/witnessedAt/verified) is local, so
   * every honest witness derives the SAME leaf for the same claim.
   *
   *   version u8 ‖ epoch u32LE ‖ spongeRounds u16LE ‖ shareCount u32LE ‖
   *   jobRoot[32] ‖ entropyFlags u8 ‖ siliconDrift u8 ‖ seal[4] ‖ nodeId[32]
   */
  static claimLeafBytes(c) {
    const buf = Buffer.alloc(81);
    let o = 0;
    buf.writeUInt8(c.version, o); o += 1;
    buf.writeUInt32LE(c.epoch, o); o += 4;
    buf.writeUInt16LE(c.spongeRounds, o); o += 2;
    buf.writeUInt32LE(c.shareCount, o); o += 4;
    Buffer.from(c.jobRoot, 'hex').copy(buf, o); o += 32;
    buf.writeUInt8(c.entropyFlags, o); o += 1;
    buf.writeUInt8(c.siliconDrift || 0, o); o += 1;
    buf.set(c.seal, o); o += 4;
    Buffer.from(c.nodeId, 'hex').copy(buf, o);
    return buf;
  }

  /**
   * Binary Merkle root over an epoch's witnessed claim set:
   * leaf = SHA3-256(canonical claim), sorted by (nodeId, leaf bytes),
   * internal = SHA3-256(left ‖ right), odd node promoted un-hashed.
   * Returns null for an empty/absent epoch — no attestation of nothing.
   */
  epochClaimRoot(epoch) {
    const bucket = this.epochs.get(epoch);
    if (!bucket || bucket.size === 0) return null;

    const leaves = [...bucket.values()]
      .map(c => ({ nodeId: c.nodeId, leaf: Buffer.from(sha3_256(ClaimLedger.claimLeafBytes(c))) }))
      .sort((a, b) => a.nodeId.localeCompare(b.nodeId) || Buffer.compare(a.leaf, b.leaf))
      .map(e => e.leaf);

    let level = leaves;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(i + 1 < level.length
          ? Buffer.from(sha3_256(Buffer.concat([level[i], level[i + 1]])))
          : level[i]); // odd promoted
      }
      level = next;
    }
    return { root: level[0].toString('hex'), claims: leaves.length, epoch };
  }

  /**
   * Ask the pq-bridge to hourglass-sign this epoch's claim-set root.
   * The bridge signs at most once per MANI epoch — a 409 means the epoch
   * was already attested under a DIFFERENT root, which is evidence:
   * either our witnessed set diverges from the first attester's, or
   * someone attested a root they cannot substantiate. Emitted as
   * 'attestationConflict', never silently resolved.
   */
  async attestEpoch(epoch) {
    const r = this.epochClaimRoot(epoch);
    if (!r) return null;

    let res;
    try {
      res = await fetch(`${BRIDGE_URL}/yakcoin/epoch-attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim_root: r.root }),
        signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
      });
    } catch (e) {
      log.warn('epoch attestation unreachable', { epoch, error: e.message });
      return null;
    }

    if (res.status === 409) {
      const evidence = { epoch, ourRoot: r.root, claims: r.claims, at: Date.now() };
      log.warn('ATTESTATION CONFLICT — epoch already signed under a different root', evidence);
      this.emit('attestationConflict', evidence);
      return { conflict: true, epoch, ourRoot: r.root };
    }
    if (!res.ok) {
      log.warn('epoch attestation rejected', { epoch, status: res.status });
      return null;
    }
    const body = await res.json();
    return { epoch, claimRoot: r.root, claims: r.claims, ...body };
  }

  _prune() {
    while (this.epochs.size > this.maxEpochs) {
      const oldest = Math.min(...this.epochs.keys());
      this.epochs.delete(oldest);
    }
  }
}
