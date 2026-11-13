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
 * Job Store — the claimer side of the payable-job pipeline.
 *
 * Producers (zonegen, drop rolls, transforms — see
 * CONFIDENTIAL/C2C-YAKCOIN-JOBS.md) deposit completed job material:
 *   { job_id, spec: {kind, ...input}, result: <hex>, executor, wall_ms }
 *
 * Deposits queue in `pending`. At claim-build time the contribution
 * layer calls commitFor(nodeId, epoch), which drains up to
 * maxJobsPerCommit into a committed batch:
 *
 *   spec   = { kind: 'job-batch', jobs: [spec, ...] }   (deposit order)
 *   result = concat(resultBytes)                          (hex)
 *   jobRoot = sha3_256(resultBytes)  — exactly the audit-duty default
 *            commit, so a revealed batch verifies end-to-end.
 *
 * The batch is keyed claimRef = `${nodeId}:${epoch}` — the same ref
 * audit-duty requests reveals for. get(claimRef) returns ONLY
 * committed material: pending jobs are uncommitted and must never
 * leak into a reveal (a reveal of uncommitted work can't match the
 * claim's jobRoot and would manufacture commit-mismatch evidence).
 *
 * Receipt claims take precedence in an epoch (they ride the claim
 * inline and are audit-exempt); when receipts commit, the provider
 * isn't called and pending jobs simply wait for a receipt-free epoch.
 *
 * Bounds mirror audit-duty's inbound limits so anything committable
 * is also revealable:
 *   spec JSON ≤ 256 KiB, result ≤ 1 MiB bytes, batch totals the same.
 *
 * @module mesh/job-store
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { JOB_CLASS } from './claim-ledger.js';

// Mirror of audit-duty's inbound bounds — a batch that can't be
// revealed must not be committable.
const MAX_SPEC_BYTES = 256 * 1024;
const MAX_RESULT_BYTES = 1024 * 1024; // audit bound is 2 MiB of hex

const JOB_ID_RE = /^[\w:.-]{1,128}$/;

export class JobStore {
  /**
   * @param {Object} [opts]
   * @param {number} [opts.maxPending] - pending-job cap (DoS bound)
   * @param {number} [opts.maxJobsPerCommit] - batch size per epoch claim
   * @param {number} [opts.maxCommittedEpochs] - reveal retention window
   */
  constructor(opts = {}) {
    this.maxPending = opts.maxPending ?? 256;
    this.maxJobsPerCommit = opts.maxJobsPerCommit ?? 64;
    this.maxCommittedEpochs = opts.maxCommittedEpochs ?? 64;
    /** @type {Array<{jobId:string, spec:Object, resultHex:string, executor:string, wallMs:number}>} */
    this.pending = [];
    /** @type {Map<string, {spec:Object, result:string, jobRoot:string, epoch:number}>} claimRef → batch */
    this.committed = new Map();
    this._pendingIds = new Set();
  }

  /**
   * Queue completed job material for the next committing claim.
   * Idempotent on job_id — producer retries don't double-commit.
   * @returns {{ok:true, jobId:string}|{error:string}}
   */
  deposit(job) {
    const b = job || {};
    const jobId = typeof b.job_id === 'string' ? b.job_id
      : typeof b.jobId === 'string' ? b.jobId : null;
    if (!jobId || !JOB_ID_RE.test(jobId)) {
      return { error: 'job_id required (<=128 chars, [\\w:.-])' };
    }
    if (this._pendingIds.has(jobId)) return { ok: true, jobId }; // retry — already queued
    if (typeof b.result !== 'string' || !/^[0-9a-f]+$/.test(b.result) || b.result.length % 2) {
      return { error: 'result must be even-length lowercase hex' };
    }
    if (b.result.length / 2 > MAX_RESULT_BYTES) {
      return { error: `result exceeds ${MAX_RESULT_BYTES} bytes — can never be revealed` };
    }
    if (typeof b.spec !== 'object' || b.spec === null || Array.isArray(b.spec)) {
      return { error: 'spec must be a JSON object' };
    }
    if (typeof b.spec.kind !== 'string' || !b.spec.kind) {
      return { error: 'spec.kind required — routes the audit verifier' };
    }
    if (Buffer.byteLength(JSON.stringify(b.spec)) > MAX_SPEC_BYTES) {
      return { error: `spec exceeds ${MAX_SPEC_BYTES} bytes — can never be revealed` };
    }
    if (this.pending.length >= this.maxPending) {
      return { error: 'pending queue full — wait for a claim to drain it' };
    }
    this.pending.push({
      jobId,
      spec: b.spec,
      resultHex: b.result,
      executor: typeof b.executor === 'string' ? b.executor : 'unknown',
      wallMs: Number.isInteger(b.wall_ms) ? b.wall_ms
        : Number.isInteger(b.wallMs) ? b.wallMs : 0,
      depositedAt: Date.now(),
    });
    this._pendingIds.add(jobId);
    return { ok: true, jobId };
  }

  /**
   * Drain pending deposits into an epoch-committed batch. Called by
   * contribution's jobProvider exactly once per claim build — the
   * batch it returns IS the material the claim's jobRoot commits to.
   * @returns {{jobRoot:string, jobClass:number}|null}
   */
  commitFor(nodeId, epoch) {
    if (!this.pending.length) return null;
    const jobs = [];
    let specBytes = 32;      // {kind:'job-batch',jobs:[...]} framing
    let resultBytes = 0;
    for (const j of this.pending) {
      const s = Buffer.byteLength(JSON.stringify(j.spec));
      const r = j.resultHex.length / 2;
      if (jobs.length >= this.maxJobsPerCommit
          || specBytes + s > MAX_SPEC_BYTES
          || resultBytes + r > MAX_RESULT_BYTES) break;
      specBytes += s; resultBytes += r;
      jobs.push(j);
    }
    if (!jobs.length) return null; // first pending job somehow unfittable
    this.pending.splice(0, jobs.length);
    for (const j of jobs) this._pendingIds.delete(j.jobId);

    const spec = { kind: 'job-batch', jobs: jobs.map(j => j.spec) };
    const result = Buffer.concat(jobs.map(j => Buffer.from(j.resultHex, 'hex')));
    const jobRoot = bytesToHex(sha3_256(result));
    const claimRef = `${nodeId}:${epoch}`;
    this.committed.set(claimRef, {
      spec, result: result.toString('hex'), jobRoot, epoch,
      jobIds: jobs.map(j => j.jobId),
      committedAt: Date.now(),
    });
    this._prune(epoch);
    return { jobRoot, jobClass: JOB_CLASS.DETERMINISTIC, count: jobs.length };
  }

  /**
   * Audit-duty reveal lookup — committed material ONLY. Pending jobs
   * are uncommitted; revealing them manufactures commit-mismatch.
   * @returns {{spec:Object, result:string}|null}
   */
  get(claimRef) {
    const c = this.committed.get(claimRef);
    return c ? { spec: c.spec, result: c.result } : null;
  }

  /** Reveal retention — keep recent epochs, drop settled history. */
  _prune(currentEpoch) {
    for (const [ref, c] of this.committed) {
      if (c.epoch < currentEpoch - this.maxCommittedEpochs
          || this.committed.size > this.maxCommittedEpochs) {
        this.committed.delete(ref);
      } else break; // Map is insertion-ordered — oldest first
    }
  }
}
