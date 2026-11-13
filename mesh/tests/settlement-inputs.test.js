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
import { signAssertion, selfClaimRef } from '../epoch-assertion.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  persistentKeyPair, persistentIdFromPublicKey, pidBindString,
} from '../../identity/machine-seed.js';

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

// A canon assertion as buildBatch emits it — keystore-signed over the
// canonical assertion bytes, node_id re-derivable from fp‖pk in the
// same shape the Rust side verifies (AVOTH(fp‖pk)).
const canonIdOf = (fpFill, kp) => bytesToHex(sha3_256(
  Buffer.concat([Buffer.alloc(32, fpFill), hexToBytes(kp.publicKey)])));
async function canonItem(att, epoch, yakmeshNodeId, leafHex,
    { fpFill = att.kp.secretKey[0], claimNodeId = 'ab'.repeat(32) } = {}) {
  const nodeId = canonIdOf(fpFill, att.kp);
  const canon = await signAssertion({
    nodeId, epoch,
    claimRef: selfClaimRef(claimNodeId, epoch),
    value: leafHex,
    hwFingerprint: Buffer.alloc(32, fpFill).toString('hex'),
  }, (b) => signMessage(b, att.kp.secretKey), att.kp.publicKey);
  return item(epoch, yakmeshNodeId, { leaf: leafHex, canon });
}

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

// ─── persistentId = the account (PEACH §14) ─────────────────────────

describe('settlementInputs persistent_id', () => {
  test('claim-carried pidBind triple rides the input; absent → omitted', () => {
    const e = NOW();
    const g = gossip(ledgerWith([
      claim({ epoch: e, yakmeshNodeId: 'peerA',
        pidBind: { persistentId: 'yak-aaa', persistentPubkey: 'pka',
          persistentSig: 'siga' } }),
      claim({ epoch: e, yakmeshNodeId: 'peerB' }),
    ]));
    const inputs = g.settlementInputs(e);
    expect(inputs[0].persistent_id).toBe('yak-aaa');
    expect(inputs[0].persistent_pubkey).toBe('pka');
    expect(inputs[0].persistent_sig).toBe('siga');
    expect(inputs[1].persistent_id).toBeUndefined();
    expect(inputs[1].persistent_pubkey).toBeUndefined();
  });

  test('pid binding verifies through observe; forged triples stripped', () => {
    const e = NOW();
    const nodeId = 'ab'.repeat(32);
    const kp = persistentKeyPair(new Uint8Array(32).fill(9));
    const pid = persistentIdFromPublicKey(kp.publicKey);
    expect(pid).toMatch(/^yak-/);
    expect(pid.length).toBe(363); // full 324T — ~256-bit PQ preimage
    const sigFor = (ep) => bytesToHex(ml_dsa65.sign(
      new TextEncoder().encode(pidBindString(pid, nodeId, ep)),
      kp.secretKey));
    const hbFor = (pidBind) => ({
      nodeId: 'peer9', sequence: 1, hash: 'h', timestamp: Date.now(),
      meshState: { contribution: {
        version: 1, epoch: e, nodeId, seal: [0, 1, 2, 3],
        spongeRounds: 0, shareCount: 5, jobRoot: '0'.repeat(64),
        entropyFlags: 0, siliconDrift: 0, pidBind,
      } },
    });
    const pidBind = {
      persistentId: pid, persistentPubkey: bytesToHex(kp.publicKey),
      persistentSig: sigFor(e),
    };
    const l = new ClaimLedger({ nodeId: 'us' });
    l.observe(hbFor(pidBind));
    expect(l.epochClaims(e)[0].pidBind?.persistentId).toBe(pid);

    // A binding signed for another epoch is forgery-shaped — stripped.
    const l2 = new ClaimLedger({ nodeId: 'us' });
    let forged = null;
    l2.on('pidForgery', (ev) => { forged = ev; });
    l2.observe(hbFor({ ...pidBind, persistentSig: sigFor(e + 1) }));
    expect(l2.epochClaims(e)[0].pidBind).toBeUndefined();
    expect(forged).toBeTruthy();

    // And a well-formed pid that isn't THIS pubkey's sealed digest
    // fails — a real 324T pid borrowed from another identity.
    const l3 = new ClaimLedger({ nodeId: 'us' });
    const alien = persistentIdFromPublicKey(
      persistentKeyPair(new Uint8Array(32).fill(8)).publicKey);
    l3.observe(hbFor({ ...pidBind, persistentId: alien }));
    expect(l3.epochClaims(e)[0].pidBind).toBeUndefined();
  });
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
  test('assembles witnessed claims with attester counts', async () => {
    const e = NOW();
    const c = claim({ epoch: e });
    const g = gossip(ledgerWith([c], { streaks: { [`peer1:${e}`]: 7 } }));
    const leaf = claimLeafHash(c);
    // Canon-carrying items — distinct hardware identities, real sigs.
    g.receive(signedBatch(A, e, [await canonItem(A, e, 'peer1', leaf)]), null);
    g.receive(signedBatch(B, e, [await canonItem(B, e, 'peer1', leaf)]), null);
    g.receive(signedBatch(C, e, [await canonItem(C, e, 'peer1', leaf)]), null);

    const [in0] = g.settlementInputs(e);
    expect(in0.node_id).toBe(c.nodeId);
    expect(in0.seal).toEqual([0, 1, 2, 3]);
    expect(in0.shares).toBe(42);
    expect(in0.attestations).toBe(3);
    expect(in0.karma_age).toBe(7);
    expect(in0.proof_state).toBeNull();
    expect(in0.class).toBe('Generic');
    // Proof material rides the drop for Rust-side verification.
    expect(in0.leaf).toBe(
      bytesToHex(ClaimLedger.claimLeafBytes(c)));
    expect(in0.attester_proofs).toHaveLength(3);
    expect(in0.attester_proofs[0].hw_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(in0.attester_proofs[0].claim_ref).toBe(
      selfClaimRef(c.nodeId, e));
  });

  test('batch attesterPidBind materializes per-proof; malformed dropped', async () => {
    const e = NOW();
    const c = claim({ epoch: e });
    const g = gossip(ledgerWith([c]));
    const leaf = claimLeafHash(c);
    // The triple must be inside the batch BEFORE the signature.
    const bA = {
      v: 1, attester: A.nodeId, pubKey: A.kp.publicKey, epoch: e,
      items: [await canonItem(A, e, 'peer1', leaf)],
      evidence: { forks: [], conflicts: [] },
      attesterPidBind: {
        persistentId: 'yak-' + 'T01:'.repeat(5) + 'T01',
        persistentPubkey: 'aa'.repeat(64),
        persistentSig: 'bb'.repeat(64),
      },
    };
    bA.sig = signMessage(
      JSON.stringify({ ...bA, sig: undefined }), A.kp.secretKey);
    // B's batch carries a malformed triple — pubkey missing.
    const bB = {
      v: 1, attester: B.nodeId, pubKey: B.kp.publicKey, epoch: e,
      items: [await canonItem(B, e, 'peer1', leaf)],
      evidence: { forks: [], conflicts: [] },
      attesterPidBind: { persistentId: 'yak-' + 'T01:'.repeat(5) + 'T01' },
    };
    bB.sig = signMessage(
      JSON.stringify({ ...bB, sig: undefined }), B.kp.secretKey);
    g.receive(bA, null);
    g.receive(bB, null);

    const [in0] = g.settlementInputs(e);
    expect(in0.attester_proofs).toHaveLength(2);
    const pa = in0.attester_proofs.find(p => p.persistent_id);
    const pb = in0.attester_proofs.find(p => !p.persistent_id);
    expect(pa.persistent_pubkey).toBe('aa'.repeat(64));
    expect(pa.persistent_sig).toBe('bb'.repeat(64));
    expect(pb.persistent_pubkey).toBeUndefined();
    expect(pb.persistent_sig).toBeUndefined();
  });

  test('canon-less gossip attestations buy no quorum', async () => {
    const e = NOW();
    const c = claim({ epoch: e });
    const g = gossip(ledgerWith([c]));
    const it = item(e, 'peer1', { leaf: claimLeafHash(c) });
    g.receive(signedBatch(A, e, [it]), null);
    g.receive(signedBatch(B, e, [it]), null);
    g.receive(signedBatch(C, e, [it]), null);
    const [in0] = g.settlementInputs(e);
    // No keystore-bound proof → no quorum weight, however many gossip
    // identities attested. This is the dedupe guarantee.
    expect(in0.attestations).toBe(0);
    expect(in0.attester_proofs).toHaveLength(0);
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

  test('raw execution proofs ride the drop for in-process verification', () => {
    const e = NOW();
    const npuProof = { nonce: 'yakmesh-e1', consistent: true,
      digests: { input: 'aa', output: 'bb' },
      timingNs: { p50: 1 }, attestation: { claim: 'x' } };
    const hwProof = { deviceClass: 'gpu', nonce: 'yakmesh-e1',
      consistent: true, digests: { input: 'cc', output: 'dd' },
      timingNs: {} };
    const g = gossip(ledgerWith([
      claim({ epoch: e, yakmeshNodeId: 'a', npuProof }),
      claim({ epoch: e, yakmeshNodeId: 'b', hwProof }),
      claim({ epoch: e, yakmeshNodeId: 'c' }),
    ]));
    const inputs = g.settlementInputs(e);
    expect(inputs[0].npu_proof).toEqual(npuProof);
    expect(inputs[1].hw_proof).toEqual(hwProof);
    expect(inputs[2].npu_proof).toBeUndefined();
    expect(inputs[2].hw_proof).toBeUndefined();
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
