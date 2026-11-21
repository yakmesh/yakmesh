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
 * Audit Duty — assigned spot-recompute of witnessed claims.
 *
 * The "Job-result laziness" row of the PEACH attack table: audit-duty
 * is ASSIGNED, never volunteered — a verifier who only audits what it
 * chooses audits nothing inconvenient.
 *
 * Assignment draw: sha3_256(AUDIT-DRAW ‖ epochRoot ‖ claimRef ‖ k)
 * over the epoch's witnessed claim-set Merkle root — deterministic
 * across any node holding the same witnessed set, unbiasable because
 * the inputs are committed before assignment matters. (PRAHARI's local
 * sponge is NOT usable here: each node absorbs different entropy —
 * consensus-determinism requires hashing committed data.)
 *
 * Protocol (reveal-or-withhold):
 *   auditor → claimer   audit:request {epoch, claimRef}
 *   claimer → auditor   audit:reveal  {spec, result}   (jobStore lookup)
 *   auditor             recompute(spec) → sha3(result) vs claim.jobRoot
 *   auditor → gossip    audit:verdict {match|mismatch|withheld}
 *
 * Verdicts: 'mismatch' = provable result fraud (emitted as evidence);
 * 'withheld' = non-reveal within the window — the claimer's silence is
 * itself attestable. 'match' is paid labor — audits feed the
 * ServiceAudit class at settlement.
 *
 * `recompute` and `jobStore` are injected — the mesh's job pipeline
 * is not live yet; the plumbing (draw, reveal, verdict, evidence) is
 * real and tested against deterministic fakes.
 *
 * @module mesh/audit-duty
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hexToBytes, utf8ToBytes, concatBytes, bytesToHex } from '@noble/hashes/utils.js';
import { generateNodeId, verifySignature } from '../identity/node-key.js';
import { jobClassOf, RECOMPUTE_CLASSES } from './claim-ledger.js';
import { judgmentAssertion, selfClaimRef, VERDICT_MISMATCH } from './epoch-assertion.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:audit-duty');

const AUDIT_VERSION = 1;

const CONFIG = {
  sampleRate: 0.05,        // fraction of witnessed claims audited
  auditorsPerClaim: 1,     // meta-verification depth-1 (bounded at 2 per spec)
  revealTimeoutMs: 15000,  // non-reveal window → 'withheld'
  maxPending: 64,          // outbound audit bound
};

const DRAW_DOMAIN = 'YAKMESH-AUDIT-DRAW-V1';
const SEL_DOMAIN = 'YAKMESH-AUDIT-SELECT-V1';

// Inbound reveal bounds — a giant spec is a compute-DoS on the auditor.
const MAX_SPEC_BYTES = 256 * 1024;   // 256 KiB job spec
const MAX_RESULT_HEX = 2 * 1024 * 1024; // 1 MiB result as hex

/** Canonical signature payload — same convention as echo/attestation. */
function signedPayload(obj) {
  return JSON.stringify({ ...obj, sig: undefined });
}

function verifyBound(msg) {
  if (typeof msg.pubKey !== 'string' || typeof msg.sig !== 'string' ||
      typeof msg.from !== 'string') return false;
  try {
    if (generateNodeId(hexToBytes(msg.pubKey)) !== msg.from) return false;
    return verifySignature(signedPayload(msg), msg.sig, msg.pubKey);
  } catch {
    return false;
  }
}

function drawBytes(domain, epochRoot, claimRef, k = 0) {
  return Buffer.from(sha3_256(concatBytes(
    utf8ToBytes(domain), hexToBytes(epochRoot),
    utf8ToBytes(String(claimRef)), new Uint8Array([k]),
  )));
}

export class AuditDuty extends EventEmitter {
  /**
   * @param {Object} params
   * @param {string} params.nodeId
   * @param {string} params.publicKey
   * @param {function} params.sign - (payload:string) => sigHex
   * @param {function} params.send - (peerId, msg) => void
   * @param {Object} [params.verifiers] - kind → {recompute, commit?}:
   *   recompute(spec, claimerId) => Promise<Buffer> — the job re-run;
   *   commit(resultBytes) => jobRoot hex (default sha3_256). Jobs are
   *   identity-bound, so recompute receives the CLAIMER's id — never
   *   audit with our own (that manufactures false work-fraud).
   *   `recompute` alone wires a fallback executor for any kind.
   * @param {Object} [params.jobStore] - claimer side: get(claimRef) => {spec,result}|null
   * @param {Object} [params.config]
   */
  constructor({ nodeId, publicKey, sign, send, recompute = null, verifiers = null, jobStore = null, config = {},
                canonicalNodeId = null, canonSign = null, canonPubkey = null }) {
    super();
    this.nodeId = nodeId;
    this.publicKey = publicKey;
    this.sign = sign;
    this.send = send;
    // Keystore-signed judgment assertions — the slashable form of a
    // 'mismatch' verdict. A mesh-key sig is transport; canon is
    // consensus evidence (bonded-witness quorum → Judgment EvidenceTx).
    this.canonicalNodeId = canonicalNodeId; // () → hex
    this.canonSign = canonSign;             // async keystore signer
    this.canonPubkey = canonPubkey;         // () → keystore pubkey hex
    /** @type {Map<string, {recompute:Function, commit:Function}>} */
    this.verifiers = new Map(Object.entries(verifiers || {}));
    if (recompute) this.verifiers.set('*', { recompute, commit: null });
    this.jobStore = jobStore;
    this.cfg = { ...CONFIG, ...config };
    /** @type {Map<string, object>} auditId → pending audit */
    this.pending = new Map();
    /** Witnessed verdicts — ours AND gossiped foreign ones.
     *  epoch → claimRef → auditorId → verdict record (deduped). */
    this.verdictLog = new Map();
    this.stats = { requested: 0, served: 0, verdicts: 0, mismatches: 0, withheld: 0, aborted: 0 };
  }

  _signEmit(obj) {
    obj.sig = this.sign(signedPayload(obj));
    return obj;
  }

  /** The assignment-draw primitive — exposed for verification/tests. */
  drawBytes(epochRoot, claimRef, k = 0, domain = DRAW_DOMAIN) {
    return drawBytes(domain, epochRoot, claimRef, k);
  }

  /**
   * Deterministic audit plan over a witnessed claim set.
   * @param {string} epochRoot - witnessed claim-set Merkle root (hex)
   * @param {number} epoch
   * @param {Array} claims - witnessed claims ({nodeId, epoch})
   * @param {string[]} eligible - auditor candidate nodeIds
   * @returns {Array<{claimRef, claimerId, auditorId}>}
   */
  plan(epochRoot, epoch, claims, eligible) {
    const out = [];
    for (const c of claims) {
      // Job-class routing — only recompute-verifiable classes enter
      // this plan. Fuzzy needs similarity consensus, storage needs
      // challenge-response, duties are witnessed records — different
      // protocols, different samplers.
      if (!RECOMPUTE_CLASSES.has(jobClassOf(c))) continue;
      // Receipt claims are self-verifying: the artifacts rode the
      // claim and were signature/binding-checked at observe time.
      // There is no spec to reveal — auditing them would manufacture
      // 'withheld' verdicts against honest claimers.
      if (Array.isArray(c.receipts) && c.receipts.length > 0) continue;
      const claimRef = `${c.nodeId}:${c.epoch}`;
      // Deterministic sampling — same witnessed set → same selection.
      const sel = drawBytes(SEL_DOMAIN, epochRoot, claimRef);
      const selU64 = sel.readBigUInt64BE(0);
      if (Number(selU64) / Number(1n << 64n) >= this.cfg.sampleRate) continue;

      // eligible may be an array (uniform pool) or a function of the
      // claim (capability-aware pool — e.g. SEVA capability ads).
      const base = typeof eligible === 'function' ? eligible(c) : eligible;
      const pool = base.filter(id => id !== (c.yakmeshNodeId || c.nodeId));
      for (let k = 0; k < this.cfg.auditorsPerClaim && pool.length; k++) {
        const d = drawBytes(DRAW_DOMAIN, epochRoot, claimRef, k);
        const auditorId = pool[Number(d.readBigUInt64BE(0) % BigInt(pool.length))];
        out.push({
          claimRef, claimerId: c.yakmeshNodeId || c.nodeId,
          auditorId, epoch, jobRoot: c.jobRoot || null,
        });
      }
    }
    return out;
  }

  /** My assigned audits from a plan — assigned, not volunteered. */
  myAssignments(epochRoot, epoch, claims, eligible) {
    return this.plan(epochRoot, epoch, claims, eligible)
      .filter(a => a.auditorId === this.nodeId);
  }

  /**
   * Issue my assigned audits — send audit:request to each claimer.
   * Pending entries expire into 'withheld' verdicts on timeout.
   * Dormant when no recompute executor is wired — issuing audits we
   * cannot complete would manufacture 'withheld' noise, so the sleep
   * state lives here, not in the caller.
   */
  issueAudits(epochRoot, epoch, claims, eligible) {
    if (this.verifiers.size === 0) return []; // dormant: nothing we can audit
    const mine = this.myAssignments(epochRoot, epoch, claims, eligible);
    const issued = [];
    for (const a of mine) {
      if (this.pending.size >= this.cfg.maxPending) break;
      const id = bytesToHex(drawBytes(DRAW_DOMAIN, epochRoot, a.claimRef, 255)).slice(0, 32);
      const req = this._signEmit({
        type: 'audit:request', v: AUDIT_VERSION,
        id, epoch, claimRef: a.claimRef, epochRoot,
        from: this.nodeId, pubKey: this.publicKey,
      });
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this._verdict(a.claimRef, a.claimerId, 'withheld',
          { reason: 'non-reveal', epoch: a.epoch });
      }, this.cfg.revealTimeoutMs);
      if (timer.unref) timer.unref();
      this.pending.set(id, { ...a, id, timer });
      this.send(a.claimerId, req);
      this.stats.requested++;
      issued.push(req);
    }
    return issued;
  }

  /**
   * Claimer side — audit:request → reveal job spec + result, or refuse.
   * Non-reveal is itself attestable; 'no-job' is the honest refuse.
   */
  handleRequest(msg) {
    if (!msg || msg.v !== AUDIT_VERSION || !verifyBound(msg)) return;
    if (this.pending.size >= this.cfg.maxPending) return;
    const job = this.jobStore?.get(msg.claimRef);
    const res = this._signEmit({
      type: 'audit:reveal', v: AUDIT_VERSION,
      id: msg.id, epoch: msg.epoch, claimRef: msg.claimRef,
      spec: job ? job.spec : null,
      result: job ? job.result : null,
      reason: job ? undefined : 'no-job',
      from: this.nodeId, pubKey: this.publicKey,
    });
    this.send(msg.from, res);
    if (job) this.stats.served++;
  }

  /**
   * Auditor side — audit:reveal → recompute → verdict. A 'withheld'
   * reveal (spec/result null) is recorded as non-reveal.
   */
  async handleReveal(msg) {
    if (!msg || msg.v !== AUDIT_VERSION || !verifyBound(msg)) return;
    const pending = this.pending.get(msg.id);
    if (!pending || msg.from !== pending.claimerId) return;
    clearTimeout(pending.timer);
    this.pending.delete(msg.id);
    const at = { epoch: pending.epoch };

    if (msg.spec == null || msg.result == null) {
      return this._verdict(msg.claimRef, msg.from, 'withheld',
        { reason: msg.reason || 'empty-reveal', ...at });
    }
    // Inbound bounds — an unbounded spec is a compute-DoS on us.
    const specBytes = Buffer.byteLength(JSON.stringify(msg.spec));
    if (specBytes > MAX_SPEC_BYTES || msg.result.length > MAX_RESULT_HEX) {
      return this._verdict(msg.claimRef, msg.from, 'withheld', { reason: 'oversize-reveal', ...at });
    }

    // Verifier registry — kind-specific executor, '*' fallback.
    const kind = msg.spec?.kind;
    const v = this.verifiers.get(kind) || this.verifiers.get('*');
    if (!v) {
      // WE can't run this job class — auditor-side incapability is NOT
      // claimer misconduct. 'aborted', not 'withheld'.
      return this._verdict(msg.claimRef, msg.from, 'aborted',
        { reason: 'no-verifier', kind: kind ?? 'none', ...at });
    }
    const commit = v.commit || ((b) => bytesToHex(sha3_256(b)));

    let got;
    try {
      // Jobs are identity-bound — recompute against the CLAIMER's id.
      got = Buffer.from(await v.recompute(msg.spec, msg.from));
    } catch (e) {
      // Auditor-side failure (executor error) is not claimer misconduct.
      log.warn('audit recompute failed', { claimRef: msg.claimRef, error: e.message });
      return this._verdict(msg.claimRef, msg.from, 'aborted', { reason: 'recompute-error', ...at });
    }
    const revealed = Buffer.from(msg.result, 'hex');
    // Check 1 — work fraud: recomputing the spec doesn't produce the
    // revealed result (the claimer didn't do the work, or did it wrong).
    if (!got.equals(revealed)) {
      return this._verdict(msg.claimRef, msg.from, 'mismatch',
        { reason: 'work-fraud', recomputed: bytesToHex(got), revealed: msg.result, ...at });
    }
    // Check 2 — commitment fraud: the revealed result isn't what the
    // claim's jobRoot committed to (bait-and-switch at reveal time).
    if (pending.jobRoot && commit(revealed) !== pending.jobRoot) {
      return this._verdict(msg.claimRef, msg.from, 'mismatch',
        { reason: 'commit-mismatch', jobRoot: pending.jobRoot, committed: commit(revealed), ...at });
    }
    this._verdict(msg.claimRef, msg.from, 'match', { jobRoot: pending.jobRoot, ...at });
  }

  /** Sign + emit a verdict; mismatches/withholds are evidence. */
  async _verdict(claimRef, claimerId, verdict, detail = {}) {
    this.stats.verdicts++;
    if (verdict === 'mismatch') this.stats.mismatches++;
    if (verdict === 'withheld') this.stats.withheld++;
    if (verdict === 'aborted') this.stats.aborted++;
    const v = this._signEmit({
      type: 'audit:verdict', v: AUDIT_VERSION,
      claimRef, claimerId, verdict, ...detail,
      at: Date.now(), from: this.nodeId, pubKey: this.publicKey,
    });
    // Slashable judgment: a 'mismatch' verdict gets a keystore-signed
    // canon assertion committing the verdict_hash — quorum of bonded
    // witnesses asserting the same value = Judgment EvidenceTx.
    // Bridge down → no canon field, honest absence.
    if (verdict === 'mismatch' && this.canonSign && detail.epoch) {
      const canonId = this.canonicalNodeId?.();
      const claimerNode = claimRef.split(':')[0];
      if (canonId && /^[0-9a-f]{64}$/.test(claimerNode)) {
        const canon = await judgmentAssertion({
          witnessNodeId: canonId, epoch: detail.epoch,
          claimRef: selfClaimRef(claimerNode, detail.epoch),
          verdictByte: VERDICT_MISMATCH,
        }, this.canonSign, this.canonPubkey?.());
        if (canon) v.canon = canon;
      }
    }
    this._logVerdict(v);
    log[verdict === 'match' ? 'debug' : 'warn']('audit verdict', {
      claimRef, claimer: claimerId?.slice(0, 16), verdict,
    });
    this.emit('verdict', v);
    if (verdict === 'mismatch') this.emit('resultFraud', v);
    if (verdict === 'withheld') this.emit('auditWithheld', v);
    if (verdict === 'aborted') this.emit('auditAborted', v);
    return v;
  }

  _logVerdict(v) {
    let epochMap = this.verdictLog.get(v.epoch);
    if (!epochMap) { epochMap = new Map(); this.verdictLog.set(v.epoch, epochMap); }
    let claimMap = epochMap.get(v.claimRef);
    if (!claimMap) { claimMap = new Map(); epochMap.set(v.claimRef, claimMap); }
    claimMap.set(v.from, v);
  }

  /**
   * Record a gossiped foreign verdict — verified + deduped so the
   * same auditor can't double-count labor. Conflicting verdicts on
   * the same claimRef are evidence, surfaced not resolved.
   */
  recordVerdict(v) {
    if (!v || v.v !== AUDIT_VERSION || v.type !== 'audit:verdict' ||
        typeof v.claimRef !== 'string' || !v.epoch ||
        !verifyBound(v)) return false;
    const existing = this.verdictLog.get(v.epoch)?.get(v.claimRef)?.get(v.from);
    if (existing) {
      if (existing.verdict !== v.verdict) {
        this.emit('verdictConflict', { claimRef: v.claimRef, auditor: v.from,
          first: existing.verdict, second: v.verdict });
      }
      return false; // dedupe — first verdict stands
    }
    this._logVerdict(v);
    this.emit('foreignVerdict', v);
    return true;
  }

  /**
   * Witnessed audit labor for an epoch — grouped by auditor for
   * ServiceAudit-class settlement inputs. Counts are distinct signed
   * verdicts observed, never self-reported fields.
   */
  auditLabor(epoch) {
    const epochMap = this.verdictLog.get(epoch);
    if (!epochMap) return [];
    const byAuditor = new Map();
    for (const claimMap of epochMap.values()) {
      for (const v of claimMap.values()) {
        let a = byAuditor.get(v.from);
        if (!a) { a = { auditorId: v.from, verdicts: 0, matches: 0, mismatches: 0 }; byAuditor.set(v.from, a); }
        a.verdicts++;
        if (v.verdict === 'match') a.matches++;
        if (v.verdict === 'mismatch') a.mismatches++;
      }
    }
    return [...byAuditor.values()];
  }
}
