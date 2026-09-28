/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Work-receipt tests — the issuer interface: sign/verify, ternary
 * verdicts, transplant-proof binding (worker+epoch+seal), AVOTH
 * commitment into jobRoot, claim-ledger integration, and audit-plan
 * exclusion (receipt claims are self-verifying).
 *
 * @module mesh/tests/work-receipt.test
 */

import { describe, test, expect } from 'vitest';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import {
  signReceipt, verifyReceipt, verifyClaimReceipts,
  receiptsCommitment, encodeReceipt,
} from '../work-receipt.js';
import { ClaimLedger, JOB_CLASS } from '../claim-ledger.js';
import { AuditDuty } from '../audit-duty.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';

setCodebaseHash('a'.repeat(64));

const mkIdentity = (fill) => {
  const kp = generateKeyPair(new Uint8Array(32).fill(fill));
  return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
};

const ISSUER = mkIdentity(40);
const WORKER = mkIdentity(50);

const WORKER_NODE = 'ab'.repeat(32);   // worker's canonical claim nodeId
const SEAL = [0, 1, 2, 3];
const JOB_ID = 'cd'.repeat(32);
const RESULT_HASH = 'ef'.repeat(32);

// Well-formed 324T service pid: six 54-trit tiers (6×9 colon groups),
// dot-separated — 'yaks-' + 359 chars.
const TIER = 'TT00TTT00:TTT00TTT0:0TTT00TTT:TT00TTT00:TTT00TTT0:0TTT00TTT';
const ISSUER_PID = 'yaks-' + Array(6).fill(TIER).join('.');

const serviceRegistry = {
  getByPersistentId: (pid) => pid === ISSUER_PID
    ? {
      type: 'service', dokoId: 'doko-issuer',
      publicKey: ISSUER.kp.publicKey,
      extensions: { persistentId: ISSUER_PID },
    } : null,
  getByPublicKey: (pk) => pk === ISSUER.kp.publicKey
    ? {
      type: 'service', dokoId: 'doko-issuer',
      publicKey: ISSUER.kp.publicKey,
      extensions: { persistentId: ISSUER_PID },
    } : null,
};
const userRegistry = {
  getByPersistentId: () => null,
  getByPublicKey: (pk) => pk === ISSUER.kp.publicKey
    ? { type: 'user', dokoId: 'doko-user', publicKey: ISSUER.kp.publicKey } : null,
};

function issue(over = {}) {
  return signReceipt({
    jobId: JOB_ID,
    workerNode: WORKER_NODE,
    workerSeal: SEAL,
    epoch: 7,
    workClass: 3,
    resultHash: RESULT_HASH,
    feePaid: 500,
    ...over,
  }, {
    publicKey: ISSUER.kp.publicKey,
    secretKey: ISSUER.kp.secretKey,
    persistentId: ISSUER_PID,
  });
}

describe('work-receipt sign/verify', () => {
  test('issued receipt verifies — observe without a DOKO registry', () => {
    const r = issue();
    expect(r).toBeTruthy();
    expect(r.issuerNode).toBe(bytesToHex(sha3_256(hexToBytes(ISSUER.kp.publicKey))));
    const v = verifyReceipt(r, {
      expectedWorkerNode: WORKER_NODE, expectedEpoch: 7, expectedSeal: SEAL,
    });
    expect(v.verdict).toBe('observe');
    expect(v.reason).toBe('no-doko-registry');
  });

  test('service-typed DOKO issuer → accept', () => {
    const v = verifyReceipt(issue(), { dokoRegistry: serviceRegistry });
    expect(v.verdict).toBe('accept');
  });

  test('non-service DOKO issuer → observe', () => {
    const v = verifyReceipt(issue(), { dokoRegistry: userRegistry });
    expect(v.verdict).toBe('observe');
    expect(v.reason).toBe('doko-binding-mismatch');
  });

  test('stolen persistentId → observe, never accept (pubkey mismatch)', () => {
    // Attacker claims the real issuer's persistentId but signs with
    // their own key. The DOKO binds pid→pubkey — binding fails.
    const thief = issue();
    thief.issuerPubkey = WORKER.kp.publicKey;
    thief.issuerNode = bytesToHex(sha3_256(hexToBytes(WORKER.kp.publicKey)));
    thief.issuerSig = signMessage(encodeReceipt(thief), WORKER.kp.secretKey);
    const v = verifyReceipt(thief, { dokoRegistry: serviceRegistry });
    expect(v.verdict).toBe('observe');
    expect(v.reason).toBe('doko-binding-mismatch');
  });

  test('key rotation keeps authority only when DOKO reflects the new key', () => {
    // Issuer upgraded — new pubkey, same persistentId. Old DOKO →
    // observe (not punished, not accepted); updated DOKO → accept.
    const rotated = issue();
    rotated.issuerPubkey = WORKER.kp.publicKey;
    rotated.issuerNode = bytesToHex(sha3_256(hexToBytes(WORKER.kp.publicKey)));
    rotated.issuerSig = signMessage(encodeReceipt(rotated), WORKER.kp.secretKey);
    expect(verifyReceipt(rotated, { dokoRegistry: serviceRegistry }).verdict)
      .toBe('observe');
    const rotatedRegistry = {
      getByPersistentId: (pid) => pid === ISSUER_PID
        ? {
          type: 'service', dokoId: 'doko-issuer',
          publicKey: WORKER.kp.publicKey,   // DOKO updated for new key
          extensions: { persistentId: ISSUER_PID },
        } : null,
      getByPublicKey: () => null,
    };
    expect(verifyReceipt(rotated, { dokoRegistry: rotatedRegistry }).verdict)
      .toBe('accept');
  });

  test('tampered resultHash → reject bad-signature', () => {
    const r = issue();
    r.resultHash = 'aa'.repeat(32);
    expect(verifyReceipt(r).verdict).toBe('reject');
    expect(verifyReceipt(r).reason).toBe('bad-signature');
  });

  test('swapped issuer pubkey → reject issuer-key-mismatch', () => {
    const r = issue();
    r.issuerPubkey = WORKER.kp.publicKey;
    const v = verifyReceipt(r);
    expect(v.verdict).toBe('reject');
    expect(v.reason).toBe('issuer-key-mismatch');
  });

  test('worker/epoch/seal binding violations → reject (transplant-proof)', () => {
    const r = issue();
    expect(verifyReceipt(r, { expectedWorkerNode: 'ff'.repeat(32) }))
      .toMatchObject({ verdict: 'reject', reason: 'worker-mismatch' });
    expect(verifyReceipt(r, { expectedEpoch: 8 }))
      .toMatchObject({ verdict: 'reject', reason: 'epoch-mismatch' });
    expect(verifyReceipt(r, { expectedSeal: [3, 2, 1, 0] }))
      .toMatchObject({ verdict: 'reject', reason: 'seal-mismatch' });
  });
});

describe('receipt commitment', () => {
  test('deterministic, order-sensitive, bounded', () => {
    const a = issue(), b = issue({ jobId: '11'.repeat(32) });
    expect(receiptsCommitment([a])).toBe(receiptsCommitment([a]));
    expect(receiptsCommitment([a, b])).not.toBe(receiptsCommitment([b, a]));
    expect(receiptsCommitment([])).toBeNull();
    expect(receiptsCommitment(Array(9).fill(a))).toBeNull();
    // 146-byte fixed head + u16 len + persistentId tail
    expect(encodeReceipt(a)).toHaveLength(146 + 2 + ISSUER_PID.length);
  });
});

describe('claim-ledger integration', () => {
  const mkClaimWithReceipts = (receipts) => ({
    version: 1, epoch: 7,
    nodeId: WORKER_NODE,
    seal: SEAL,
    spongeRounds: 0, shareCount: 0,
    jobRoot: receiptsCommitment(receipts),
    entropyFlags: (3 << 2),
    receipts,
  });
  const feed = (ledger, claim) => ledger.observe({
    nodeId: 'node-test-worker', sequence: 1,
    hash: 'h1', timestamp: Date.now(),
    meshState: { contribution: claim },
  }, { verified: 'verified' });

  test('receipt claim enters the witnessed set with verdict attached', () => {
    const ledger = new ClaimLedger({ nodeId: 'us', dokoRegistry: serviceRegistry });
    feed(ledger, mkClaimWithReceipts([issue()]));
    const claims = ledger.epochClaims(7);
    expect(claims).toHaveLength(1);
    expect(claims[0].receiptVerification.verdict).toBe('accept');
  });

  test('commitment-mismatch → claim rejected + receiptForgery evidence', () => {
    const ledger = new ClaimLedger({ nodeId: 'us' });
    const events = [];
    ledger.on('receiptForgery', (e) => events.push(e));
    const claim = mkClaimWithReceipts([issue()]);
    claim.jobRoot = '00'.repeat(32); // commitment no longer matches
    feed(ledger, claim);
    expect(ledger.epochClaims(7)).toHaveLength(0);
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe('commitment-mismatch');
  });

  test('receipt bound to a different worker → claim rejected', () => {
    const ledger = new ClaimLedger({ nodeId: 'us' });
    const r = issue({ workerNode: 'ff'.repeat(32) });
    const claim = mkClaimWithReceipts([r]);
    feed(ledger, claim);
    expect(ledger.epochClaims(7)).toHaveLength(0);
  });
});

describe('audit-plan exclusion', () => {
  test('receipt claims skip the recompute plan (self-verifying)', () => {
    const d = new AuditDuty({
      nodeId: 'auditor-1', publicKey: ISSUER.kp.publicKey,
      sign: (p) => signMessage(p, ISSUER.kp.secretKey),
      send: () => {}, recompute: () => Buffer.alloc(32),
      config: { sampleRate: 1 },
    });
    const receiptClaim = {
      nodeId: WORKER_NODE, yakmeshNodeId: 'claimer-peer', epoch: 7,
      jobRoot: receiptsCommitment([issue()]),
      entropyFlags: (JOB_CLASS.DETERMINISTIC << 2),
      receipts: [issue()],
    };
    const plainClaim = {
      nodeId: 'ee'.repeat(32), yakmeshNodeId: 'other-peer', epoch: 7,
      jobRoot: 'dd'.repeat(32),
      entropyFlags: (JOB_CLASS.DETERMINISTIC << 2),
    };
    const plan = d.plan('aa'.repeat(32), 7,
      [receiptClaim, plainClaim], ['auditor-1']);
    expect(plan.every(a => a.claimerId !== 'claimer-peer')).toBe(true);
    expect(plan.some(a => a.claimerId === 'other-peer')).toBe(true);
  });
});
