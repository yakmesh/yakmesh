/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Settlement input producer tests — the EpochClaim-shaped set must
 * carry only witnessed-derived fields: attester counts from gossip,
 * class from verified proofs, karma_age from consecutive attested
 * presence (zeroed on contested identity).
 *
 * @module mesh/tests/settlement-inputs.test
 */

import { describe, test, expect } from 'vitest';
import { AttestationGossip, claimLeafHash } from '../attestation-gossip.js';
import { ClaimLedger } from '../claim-ledger.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes } from '@noble/hashes/utils.js';

setCodebaseHash('a'.repeat(64));

const NOW = () => Math.floor(Date.now() / 30000);
const mkAttester = (fill) => {
  const kp = generateKeyPair(new Uint8Array(32).fill(fill));
  return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
};
const A = mkAttester(1);
const B = mkAttester(2);
const C = mkAttester(3);

function signedBatch(att, epoch, items) {
  const batch = {
    v: 1, attester: att.nodeId, pubKey: att.kp.publicKey,
    epoch, items, evidence: { forks: [], conflicts: [] },
  };
  batch.sig = signMessage(
    JSON.stringify({ ...batch, sig: undefined }), att.kp.secretKey);
  return batch;
}

const item = (epoch, yakmeshNodeId, over = {}) => ({
  epoch, yakmeshNodeId,
  claimNodeId: 'ab'.repeat(32), seal: [0, 1, 2, 3], ...over,
});

const claim = (over = {}) => ({
  version: 1, epoch: NOW(), yakmeshNodeId: 'peer1', nodeId: 'ab'.repeat(32),
  seal: [0, 1, 2, 3], spongeRounds: 0, shareCount: 42,
  jobRoot: '0'.repeat(64), entropyFlags: 0, siliconDrift: 0,
  verified: 'verified', deviceClass: 'unproven', proofVerification: {},
  ...over,
});

function ledgerWith(claims, over = {}) {
  return {
    epochClaims: (e) => claims.filter(c => c.epoch === e),
    bindingConflicts: [],
    forksFor: () => [],
    presenceStreak: (id, e) => over.streaks?.[`${id}:${e}`] ?? 0,
  };
}

const gossip = (ledger) => new AttestationGossip({
  nodeId: 'us', publicKey: 'pk', sign: () => 'sig', claimLedger: ledger,
});

// ─── presenceStreak (real ClaimLedger) ──────────────────────────────

describe('ClaimLedger.presenceStreak', () => {
  const hb = (epoch, nodeId = 'peer1') => ({
    nodeId, sequence: epoch * 100, hash: `${epoch}x`,
    timestamp: epoch * 30000,
    meshState: { contribution: {
      version: 1, epoch, nodeId: 'ab'.repeat(32), seal: [0, 1, 2, 3],
      spongeRounds: 0, shareCount: 5, jobRoot: '0'.repeat(64),
      entropyFlags: 0, siliconDrift: 0,
    } },
  });

  test('counts consecutive witnessed epochs back from the epoch', () => {
    const l = new ClaimLedger({ nodeId: 'us' });
    l.observe(hb(8)); l.observe(hb(9)); l.observe(hb(10));
    expect(l.presenceStreak('peer1', 10)).toBe(3);
    expect(l.presenceStreak('peer1', 9)).toBe(2);
  });

  test('a gap in attested presence breaks the streak', () => {
    const l = new ClaimLedger({ nodeId: 'us' });
    l.observe(hb(7)); l.observe(hb(9)); l.observe(hb(10));
    expect(l.presenceStreak('peer1', 10)).toBe(2); // 8 missing
    expect(l.presenceStreak('peer1', 8)).toBe(0);  // 8 itself absent
  });

  test('absent node and absent epoch → 0', () => {
    const l = new ClaimLedger({ nodeId: 'us' });
    l.observe(hb(10));
    expect(l.presenceStreak('nobody', 10)).toBe(0);
    expect(l.presenceStreak('peer1', 99)).toBe(0);
  });
});

// ─── settlementInputs ───────────────────────────────────────────────

describe('AttestationGossip.settlementInputs', () => {
  test('assembles witnessed claims with attester counts', () => {
    const e = NOW();
    const c = claim({ epoch: e });
    const g = gossip(ledgerWith([c], { streaks: { [`peer1:${e}`]: 7 } }));
    const it = item(e, 'peer1', { leaf: claimLeafHash(c) });
    g.receive(signedBatch(A, e, [it]), null);
    g.receive(signedBatch(B, e, [it]), null);
    g.receive(signedBatch(C, e, [it]), null);

    const [in0] = g.settlementInputs(e);
    expect(in0.node_id).toBe(c.nodeId);
    expect(in0.seal).toEqual([0, 1, 2, 3]);
    expect(in0.shares).toBe(42);
    expect(in0.attestations).toBe(3);
    expect(in0.karma_age).toBe(7);
    expect(in0.proof_state).toBeNull();
    expect(in0.class).toBe('Generic');
  });

  test('unattested witnessed claims still enter with attestations 0', () => {
    const e = NOW();
    const g = gossip(ledgerWith([claim({ epoch: e })]));
    const [in0] = g.settlementInputs(e);
    expect(in0.attestations).toBe(0); // Rust quorum gate excludes it
  });

  test('class maps from VERIFIED device labels only', () => {
    const e = NOW();
    const g = gossip(ledgerWith([
      claim({ epoch: e, yakmeshNodeId: 'a', deviceClass: 'npu' }),
      claim({ epoch: e, yakmeshNodeId: 'b', deviceClass: 'gpu' }),
      claim({ epoch: e, yakmeshNodeId: 'c', deviceClass: 'cpu' }),
      claim({ epoch: e, yakmeshNodeId: 'd', deviceClass: 'claimed-npu' }),
      claim({ epoch: e, yakmeshNodeId: 'e', deviceClass: 'forged-gpu' }),
      claim({ epoch: e, yakmeshNodeId: 'f', deviceClass: 'unproven' }),
    ]));
    const inputs = g.settlementInputs(e);
    expect(inputs[0].class).toBe('NpuXdna1');
    expect(inputs[1].class).toBe('GpuWebgpu'); // undiff gpu → floor GPU cap
    expect(inputs[2].class).toBe('CpuSha');    // undiff cpu → floor CPU cap
    expect(inputs[3].class).toBe('Generic');
    expect(inputs[4].class).toBe('Generic');
    expect(inputs[5].class).toBe('Generic');
  });

  test('contested identity (fork / binding conflict) → karma_age 0', () => {
    const e = NOW();
    const ledger = ledgerWith([claim({ epoch: e })], {
      streaks: { [`peer1:${e}`]: 50 },
    });
    ledger.bindingConflicts = [{ yakmeshNodeId: 'peer1', boundA: 'x', boundB: 'y' }];
    const [in0] = gossip(ledger).settlementInputs(e);
    expect(in0.karma_age).toBe(0);

    const ledger2 = ledgerWith([claim({ epoch: e })], {
      streaks: { [`peer1:${e}`]: 50 },
    });
    ledger2.forksFor = () => [{ nodeId: 'peer1' }];
    const [in1] = gossip(ledger2).settlementInputs(e);
    expect(in1.karma_age).toBe(0);
  });

  test('proof_state: forged inner attestation → invalid', () => {
    const e = NOW();
    const g = gossip(ledgerWith([
      claim({ epoch: e, proofVerification: { npu: 'forged' } }),
    ]));
    expect(g.settlementInputs(e)[0].proof_state).toBe('invalid');
  });

  test('proof_state: verified proofs → attested with device', () => {
    const e = NOW();
    const g = gossip(ledgerWith([
      claim({ epoch: e, yakmeshNodeId: 'a',
        proofVerification: { npu: 'verified' }, npuProof: {} }),
      claim({ epoch: e, yakmeshNodeId: 'b',
        proofVerification: { hw: 'verified' },
        hwProof: { deviceClass: 'gpu' } }),
      claim({ epoch: e, yakmeshNodeId: 'c',
        proofVerification: { hw: 'unsigned' },
        hwProof: { deviceClass: 'cpu' } }),
    ]));
    const inputs = g.settlementInputs(e);
    expect(inputs[0].proof_state).toEqual({ attested: 'Npu' });
    expect(inputs[1].proof_state).toEqual({ attested: 'Gpu' });
    expect(inputs[2].proof_state).toEqual({ unsigned: 'Cpu' });
  });

  test('attested-but-unwitnessed claims never enter the input set', () => {
    const e = NOW();
    const g = gossip(ledgerWith([])); // we witnessed nothing
    g.receive(signedBatch(A, e, [item(e, 'ghost')]), null);
    g.receive(signedBatch(B, e, [item(e, 'ghost')]), null);
    g.receive(signedBatch(C, e, [item(e, 'ghost')]), null);
    expect(g.attestedSet(e)).toHaveLength(1); // quorum met…
    expect(g.settlementInputs(e)).toHaveLength(0); // …but no claim body
  });
});
