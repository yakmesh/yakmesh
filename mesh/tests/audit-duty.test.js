/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Audit-duty tests — deterministic assignment draws, reveal-or-withhold
 * protocol, two-check verdicts (work-fraud + commit-mismatch), and the
 * assigned-not-volunteered property.
 *
 * @module mesh/tests/audit-duty.test
 */

import { describe, test, expect } from 'vitest';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { AuditDuty } from '../audit-duty.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import {
  selfClaimRef, judgmentVerdictHash, VERDICT_MISMATCH, verifyAssertion,
} from '../epoch-assertion.js';

setCodebaseHash('a'.repeat(64));

const mkIdentity = (fill) => {
  const kp = generateKeyPair(new Uint8Array(32).fill(fill));
  return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
};

const AUDITOR = mkIdentity(10);
const CLAIMER = mkIdentity(20);
const OTHER = mkIdentity(30);

const EPOCH_ROOT = 'ef'.repeat(32);

// A deterministic fake job: result = sha3(spec). The claim's jobRoot
// commits to that result via the default commit (sha3_256).
const spec = { kind: 'fake', seed: 'aa'.repeat(32) };
const RESULT = sha3_256(hexToBytes(spec.seed));
const JOB_ROOT = bytesToHex(sha3_256(RESULT));

const mkClaim = (nodeId, epoch = 5) => ({ nodeId, epoch, jobRoot: JOB_ROOT });

function mkDuty(id, over = {}) {
  const sent = [];
  const d = new AuditDuty({
    nodeId: id.nodeId, publicKey: id.kp.publicKey,
    sign: (p) => signMessage(p, id.kp.secretKey),
    send: (peerId, msg) => sent.push({ peerId, msg }),
    recompute: 'recompute' in over ? over.recompute
      : over.verifiers ? null
      : async (s) => sha3_256(hexToBytes(s.seed)),
    verifiers: over.verifiers ?? null,
    jobStore: over.jobStore ?? null,
    config: { sampleRate: 1, ...over.config }, // sample everything in tests
    ...over.duty,
  });
  return { d, sent };
}

describe('AuditDuty — assignment draw', () => {
  test('deterministic: same inputs → same plan on any node', () => {
    const claims = [mkClaim(CLAIMER.nodeId), mkClaim(OTHER.nodeId)];
    const eligible = [AUDITOR.nodeId, CLAIMER.nodeId, OTHER.nodeId];
    const { d: d1 } = mkDuty(AUDITOR);
    const { d: d2 } = mkDuty(OTHER);
    expect(d1.plan(EPOCH_ROOT, 5, claims, eligible))
      .toEqual(d2.plan(EPOCH_ROOT, 5, claims, eligible));
  });

  test('assigned not volunteered: claimer never audits itself', () => {
    const claims = [mkClaim(CLAIMER.nodeId)];
    const { d } = mkDuty(CLAIMER);
    const plan = d.plan(EPOCH_ROOT, 5, claims, [AUDITOR.nodeId, CLAIMER.nodeId]);
    expect(plan.every(a => a.auditorId !== CLAIMER.nodeId)).toBe(true);
    expect(plan.every(a => a.auditorId === AUDITOR.nodeId)).toBe(true);
  });

  test('different epoch roots → different draws (unbiasable per epoch)', () => {
    // Assert on the draw primitive directly — a 2-member pool would
    // collide ~50% of the time if we compared picked auditors.
    const { d } = mkDuty(AUDITOR);
    const claimRef = `${CLAIMER.nodeId}:5`;
    const a = d.drawBytes(EPOCH_ROOT, claimRef, 0);
    const b = d.drawBytes('ff'.repeat(32), claimRef, 0);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    // Same inputs → identical bytes (consensus-determinism).
    expect(bytesToHex(d.drawBytes(EPOCH_ROOT, claimRef, 0))).toBe(bytesToHex(a));
  });
});

describe('AuditDuty — reveal protocol', () => {
  test('full round-trip: request → reveal → match verdict', async () => {
    const { d: auditor, sent: auditorSent } = mkDuty(AUDITOR);
    const { d: claimer, sent: claimerSent } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec, result: bytesToHex(RESULT) }) },
    });
    auditor.send = (peerId, msg) => claimer.handleRequest(msg);
    claimer.send = (peerId, msg) => auditor.handleReveal(msg);

    let verdict = null;
    auditor.on('verdict', (v) => { verdict = v; });

    const claims = [mkClaim(CLAIMER.nodeId)];
    auditor.issueAudits(EPOCH_ROOT, 5, claims, [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));

    expect(verdict.verdict).toBe('match');
    expect(verdict.claimerId).toBe(CLAIMER.nodeId);
    expect(claimer.stats.served).toBe(1);
    expect(auditorSent.length + claimerSent.length).toBe(0); // sends rerouted
  });

  test('mismatch: recompute disagrees with revealed result → resultFraud evidence', async () => {
    const { d: auditor } = mkDuty(AUDITOR, {
      recompute: async () => sha3_256(hexToBytes('11'.repeat(32))), // wrong answer
    });
    const { d: claimer } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec, result: bytesToHex(RESULT) }) },
    });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);

    let fraud = null;
    auditor.on('resultFraud', (v) => { fraud = v; });
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));

    expect(fraud).not.toBeNull();
    expect(fraud.verdict).toBe('mismatch');
    expect(fraud.reason).toBe('work-fraud');
    expect(auditor.stats.mismatches).toBe(1);
  });

  test('commit-mismatch: honest work but jobRoot lies → fraud evidence', async () => {
    const { d: auditor } = mkDuty(AUDITOR);
    const { d: claimer } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec, result: bytesToHex(RESULT) }) },
    });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);

    let fraud = null;
    auditor.on('resultFraud', (v) => { fraud = v; });
    // jobRoot commits to a DIFFERENT result than the reveal carries.
    auditor.issueAudits(EPOCH_ROOT, 5,
      [{ nodeId: CLAIMER.nodeId, epoch: 5, jobRoot: '00'.repeat(32) }],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));

    expect(fraud.verdict).toBe('mismatch');
    expect(fraud.reason).toBe('commit-mismatch');
  });

  test('withheld: claimer has no job → empty reveal → withheld verdict', async () => {
    const { d: auditor } = mkDuty(AUDITOR);
    const { d: claimer } = mkDuty(CLAIMER, { jobStore: { get: () => null } });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);

    let withheld = null;
    auditor.on('auditWithheld', (v) => { withheld = v; });
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));

    expect(withheld.verdict).toBe('withheld');
    expect(withheld.reason).toBe('no-job');
  });

  test('non-reveal within the window → withheld on timeout', async () => {
    const { d: auditor } = mkDuty(AUDITOR, {
      config: { sampleRate: 1, revealTimeoutMs: 20 },
    });
    auditor.send = () => {}; // claimer never responds

    let withheld = null;
    auditor.on('auditWithheld', (v) => { withheld = v; });
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setTimeout(r, 50));

    expect(withheld.verdict).toBe('withheld');
    expect(withheld.reason).toBe('non-reveal');
  });

  test('identity-bound: recompute receives the CLAIMER id, never ours', async () => {
    let boundTo = null;
    const { d: auditor } = mkDuty(AUDITOR, {
      verifiers: { fake: { recompute: async (s, claimerId) => {
        boundTo = claimerId;
        return sha3_256(hexToBytes(s.seed));
      } } },
    });
    const { d: claimer } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec, result: bytesToHex(RESULT) }) },
    });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));
    expect(boundTo).toBe(CLAIMER.nodeId);
  });

  test('unknown kind → aborted (auditor-side), NOT withheld against claimer', async () => {
    const { d: auditor } = mkDuty(AUDITOR, {
      // Registry nonempty (issueAudits stays awake) but lacks the kind.
      verifiers: { other: { recompute: async () => Buffer.alloc(0) } },
    });
    const { d: claimer } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec: { kind: 'npu-inference' }, result: 'ff'.repeat(32) }) },
    });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);

    let aborted = null, withheld = null;
    auditor.on('auditAborted', (v) => { aborted = v; });
    auditor.on('auditWithheld', (v) => { withheld = v; });
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));

    expect(aborted?.reason).toBe('no-verifier');
    expect(withheld).toBeNull();
  });

  test('oversize reveal → withheld (bounded inbound work)', async () => {
    const { d: auditor } = mkDuty(AUDITOR);
    const { d: claimer } = mkDuty(CLAIMER, {
      jobStore: { get: () => ({ spec: { kind: 'fake', pad: 'x'.repeat(300 * 1024) }, result: bytesToHex(RESULT) }) },
    });
    auditor.send = (p, m) => claimer.handleRequest(m);
    claimer.send = (p, m) => auditor.handleReveal(m);

    let withheld = null;
    auditor.on('auditWithheld', (v) => { withheld = v; });
    auditor.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    await new Promise(r => setImmediate(r));
    expect(withheld?.reason).toBe('oversize-reveal');
  });

  test('dormant: no recompute executor → issueAudits sleeps, returns []', () => {
    const { d: sleeper } = mkDuty(AUDITOR, { recompute: null });
    const issued = sleeper.issueAudits(EPOCH_ROOT, 5, [mkClaim(CLAIMER.nodeId)],
      [AUDITOR.nodeId, CLAIMER.nodeId]);
    expect(issued).toEqual([]);
    expect(sleeper.pending.size).toBe(0);
  });

  test('job-class routing: fuzzy/storage/duty claims skip the recompute plan', () => {
    const { d } = mkDuty(AUDITOR);
    const eligible = [AUDITOR.nodeId, OTHER.nodeId];
    const cls = (tag) => ({ nodeId: CLAIMER.nodeId, epoch: 5,
      jobRoot: JOB_ROOT, entropyFlags: tag << 2 });
    // Fuzzy(3)/Audit(4)/Storage(5) are NOT recompute-verifiable.
    expect(d.plan(EPOCH_ROOT, 5, [cls(3), cls(4), cls(5)], eligible)).toEqual([]);
    // Unspecified(0)/Avoth(1)/Deterministic(2) are.
    expect(d.plan(EPOCH_ROOT, 5, [cls(0), cls(1), cls(2)], eligible).length).toBe(3);
  });

  test('verdicts: foreign verdicts record, dedupe, conflict → evidence', async () => {
    const { d: auditor } = mkDuty(AUDITOR);
    const { d: foreign } = mkDuty(OTHER);
    // A signed foreign verdict (constructed by the foreign node).
    const v = await foreign._verdict('claimref:5', CLAIMER.nodeId, 'match', { epoch: 5 });
    expect(auditor.recordVerdict(v)).toBe(true);
    expect(auditor.recordVerdict(v)).toBe(false); // dedupe
    expect(auditor.auditLabor(5)).toEqual([
      { auditorId: OTHER.nodeId, verdicts: 1, matches: 1, mismatches: 0 },
    ]);
    // A conflicting verdict from the same auditor → evidence.
    let conflict = null;
    auditor.on('verdictConflict', (e) => { conflict = e; });
    const v2 = await foreign._verdict('claimref:5', CLAIMER.nodeId, 'mismatch', { epoch: 5 });
    auditor.recordVerdict(v2);
    expect(conflict).not.toBeNull();
    expect(conflict.first).toBe('match');
  });

  test('mismatch verdict carries a keystore-signed canon judgment', async () => {
    const canonKp = generateKeyPair(new Uint8Array(32).fill(99));
    const CANON_ID = 'cc'.repeat(32);
    const claimerNode = 'ab'.repeat(32);
    const { d } = mkDuty(AUDITOR, { duty: {
      canonicalNodeId: () => CANON_ID,
      canonSign: async (b) => signMessage(b, canonKp.secretKey),
      canonPubkey: () => canonKp.publicKey,
    }});
    const v = await d._verdict(`${claimerNode}:5`, 'claimer-yak', 'mismatch', { epoch: 5 });
    expect(v.canon).toBeTruthy();
    expect(v.canon.nodeId).toBe(CANON_ID);
    expect(v.canon.claimRef).toBe(selfClaimRef(claimerNode, 5));
    expect(v.canon.value).toBe(judgmentVerdictHash(v.canon.claimRef, VERDICT_MISMATCH));
    expect(verifyAssertion(v.canon, canonKp.publicKey)).toBe(true);
    // Non-mismatch verdicts carry no canon — not seizure-class.
    const m = await d._verdict(`${claimerNode}:5`, 'claimer-yak', 'match', { epoch: 5 });
    expect(m.canon).toBeUndefined();
    // Bridge down → honest absence, verdict still valid.
    const { d: down } = mkDuty(AUDITOR, { duty: {
      canonicalNodeId: () => CANON_ID, canonSign: async () => null,
    }});
    const w = await down._verdict(`${claimerNode}:5`, 'claimer-yak', 'mismatch', { epoch: 5 });
    expect(w.canon).toBeUndefined();
    expect(w.verdict).toBe('mismatch');
  });

  test('unsigned/forged requests and reveals are ignored', async () => {
    const { d: auditor } = mkDuty(AUDITOR);
    const { d: claimer, sent } = mkDuty(CLAIMER);
    claimer.handleRequest({ v: 1, id: 'x', epoch: 5, claimRef: 'c', from: 'fake' });
    expect(sent.length).toBe(0);
    await auditor.handleReveal({ v: 1, id: 'x', claimRef: 'c', from: 'fake' });
    expect(auditor.stats.verdicts).toBe(0);
  });
});
