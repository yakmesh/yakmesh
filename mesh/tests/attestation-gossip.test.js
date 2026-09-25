/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * AttestationGossip seal-gating tests — the epoch-close batch must
 * exclude claims whose wormhole seal FAILED the AVOTH recompute
 * (sealVerified === false) while still attesting claims the bridge
 * never checked (sealVerified === undefined — verification deferred
 * to settlement, never fabricated).
 *
 * @module mesh/tests/attestation-gossip.test
 */

import { describe, test, expect } from 'vitest';
import { AttestationGossip, claimLeafHash } from '../attestation-gossip.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes } from '@noble/hashes/utils.js';

function ledgerWith(claims) {
  return {
    epochClaims: () => claims,
    forks: [],
    bindingConflicts: [],
  };
}

const gossip = (claims) => new AttestationGossip({
  nodeId: 'us',
  publicKey: 'pk',
  sign: () => 'sig',
  claimLedger: ledgerWith(claims),
});

const claim = (over = {}) => ({
  version: 1, epoch: 5, yakmeshNodeId: 'peer1', nodeId: 'ab'.repeat(32),
  seal: [0, 1, 2, 3], spongeRounds: 0, shareCount: 0,
  jobRoot: '0'.repeat(64), entropyFlags: 0, siliconDrift: 0,
  verified: 'verified', ...over,
});

describe('AttestationGossip seal gating', () => {
  test('attests verified claims with unchecked seals', async () => {
    const batch = await gossip([claim()]).buildBatch(5);
    expect(batch.items).toHaveLength(1);
  });

  test('excludes claims that failed the AVOTH seal recompute', async () => {
    const batch = await gossip([
      claim({ yakmeshNodeId: 'good' }),
      claim({ yakmeshNodeId: 'forged', sealVerified: false }),
    ]).buildBatch(5);
    expect(batch.items).toHaveLength(1);
    expect(batch.items[0].yakmeshNodeId).toBe('good');
  });

  test('excludes unsigned beats regardless of seal state', async () => {
    const batch = await gossip([
      claim({ verified: 'unsigned' }),
    ]).buildBatch(5);
    expect(batch.items).toHaveLength(0);
  });

  test('attestation items carry the canonical claim leaf', async () => {
    const c = claim();
    const batch = await gossip([c]).buildBatch(5);
    expect(batch.items[0].leaf).toBe(claimLeafHash(c));
  });
});

// ─── receive() — signed batch verification, dedupe, scope, conflicts ───

describe('AttestationGossip receive path', () => {
  setCodebaseHash('a'.repeat(64));

  const NOW = () => Math.floor(Date.now() / 30000);
  const mkAttester = (fill) => {
    const kp = generateKeyPair(new Uint8Array(32).fill(fill));
    return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
  };
  const A = mkAttester(1);
  const B = mkAttester(2);

  const item = (epoch, yakmeshNodeId, over = {}) => ({
    epoch, yakmeshNodeId,
    claimNodeId: 'ab'.repeat(32), seal: [0, 1, 2, 3], ...over,
  });

  function signedBatch(att, epoch, items, evidence = { forks: [], conflicts: [] }) {
    const batch = {
      v: 1, attester: att.nodeId, pubKey: att.kp.publicKey,
      epoch, items, evidence,
    };
    batch.sig = signMessage(
      JSON.stringify({ ...batch, sig: undefined }), att.kp.secretKey);
    return batch;
  }

  test('counts distinct attesters per claim', () => {
    const g = gossip([]);
    const it = item(NOW(), 'peer1');
    expect(g.receive(signedBatch(A, NOW(), [it]), null).accepted).toBe(1);
    expect(g.receive(signedBatch(B, NOW(), [it]), null).accepted).toBe(1);
    const set = g.attestedSet(NOW());
    expect(set).toHaveLength(1);
    expect(set[0].attestations).toBe(2);
    expect(set[0].witnessed).toBe(false); // attested, not locally witnessed
  });

  test('same attester counted once per claim', () => {
    const g = gossip([]);
    const batch = signedBatch(A, NOW(), [item(NOW(), 'peer1')]);
    expect(g.receive(batch, null).accepted).toBe(1);
    expect(g.receive(batch, null).accepted).toBe(0);
    expect(g.attestedSet(NOW())[0].attestations).toBe(1);
  });

  test('rejects bad signatures', () => {
    const g = gossip([]);
    const batch = signedBatch(A, NOW(), [item(NOW(), 'peer1')]);
    batch.sig = 'aa'.repeat(3309);
    expect(g.receive(batch, null).accepted).toBe(0);
    expect(g.stats.badSigs).toBe(1);
  });

  test('rejects attester nodeIds not bound to the signing pubkey', () => {
    const g = gossip([]);
    const batch = signedBatch(A, NOW(), [item(NOW(), 'peer1')]);
    batch.attester = 'node-fake-sybil';
    batch.sig = signMessage(
      JSON.stringify({ ...batch, sig: undefined }), A.kp.secretKey);
    expect(g.receive(batch, null).accepted).toBe(0);
    expect(g.stats.badSigs).toBe(1);
  });

  test('drops stale and future batches at the grace window', () => {
    const g = gossip([]);
    expect(g.receive(signedBatch(A, NOW() - 3, [item(NOW() - 3, 'p1')]), null).accepted).toBe(0);
    expect(g.receive(signedBatch(A, NOW() + 1, [item(NOW() + 1, 'p1')]), null).accepted).toBe(0);
  });

  test('items cannot escape the batch epoch (grace bypass closed)', () => {
    const g = gossip([]);
    // Batch epoch passes grace; the item claims a stale epoch.
    const res = g.receive(signedBatch(A, NOW(), [item(NOW() - 10, 'peer1')]), null);
    expect(res.accepted).toBe(0);
    expect(g.attestedSet(NOW())).toHaveLength(0);
    expect(g.attestedSet(NOW() - 10)).toHaveLength(0);
  });

  test('malformed items are skipped, not thrown', () => {
    const g = gossip([]);
    const bad = item(NOW(), 'peer1', { seal: 'not-an-array' });
    expect(() => g.receive(signedBatch(A, NOW(), [bad]), null)).not.toThrow();
    expect(g.attestedSet(NOW())).toHaveLength(0);
  });

  test('foreign seal cannot poison a claim WE witnessed', () => {
    const e = NOW();
    const ourClaim = claim({ epoch: e, yakmeshNodeId: 'victim', seal: [0, 1, 2, 3] });
    const g = gossip([ourClaim]);
    let conflict = null;
    g.on('sealConflict', (ev) => { conflict = ev; });

    const res = g.receive(signedBatch(A, e, [item(e, 'victim', { seal: [3, 2, 1, 0] })]), null);
    expect(res.accepted).toBe(0);
    expect(conflict).not.toBeNull();

    // Honest attester with the real seal still counts.
    const good = g.receive(signedBatch(B, e, [
      item(e, 'victim', { leaf: claimLeafHash(ourClaim) }),
    ]), null);
    expect(good.accepted).toBe(1);
    expect(g.attestedSet(e)[0].attestations).toBe(1);
    expect(g.attestedSet(e)[0].witnessed).toBe(true);
  });

  test('divergent leaf on a witnessed claim is equivocation evidence', () => {
    const e = NOW();
    const ourClaim = claim({ epoch: e, yakmeshNodeId: 'peer1', shareCount: 100 });
    const g = gossip([ourClaim]);
    let ev = null;
    g.on('claimEquivocation', (x) => { ev = x; });

    // Attester reports same seal but the leaf of a DIFFERENT claim
    // (shareCount 0) — the claimant showed different content to
    // different witnesses under one seal.
    const fakeLeaf = claimLeafHash(claim({ epoch: e, yakmeshNodeId: 'peer1', shareCount: 0 }));
    const res = g.receive(signedBatch(A, e, [
      item(e, 'peer1', { leaf: fakeLeaf }),
    ]), null);
    expect(res.accepted).toBe(0);
    expect(ev).not.toBeNull();
    expect(ev.leafB).toBe(fakeLeaf);
  });

  test('first-seen seal wins only for claims we never witnessed', () => {
    const g = gossip([]); // empty ledger — we saw nothing
    const e = NOW();
    g.receive(signedBatch(A, e, [item(e, 'peer1', { seal: [3, 3, 3, 3] })]), null);
    const res = g.receive(signedBatch(B, e, [item(e, 'peer1', { seal: [0, 0, 0, 0] })]), null);
    expect(res.accepted).toBe(0); // conflicts with first-seen seal
    expect(g.stats.conflicts).toBe(1);
  });
});
