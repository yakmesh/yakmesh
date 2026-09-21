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
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Contribution Reporter tests — entropyFlags bit0 (can_attest_time,
 * MANI tier ≥ PTP) and bit1 (real_silicon) plus siliconDrift
 * forwarding from the pq-bridge seal response. Honest-zeros contract:
 * no provider → bit0 stays 0; no bridge → no claim at all.
 *
 * @module mesh/tests/contribution.test
 */

import { describe, test, expect, vi, afterEach } from 'vitest';
import {
  contributionMeshState,
  withContribution,
  setTimeTrustProvider,
  setProofProvider,
  currentEpoch,
  npuProofClaim,
} from '../contribution.js';
import { generateKeyPair, signMessage, verifySignature } from '../../identity/node-key.js';

const SEAL_OK = {
  node_id: 'a'.repeat(64),
  seal: [0, 1, 2, 3],
  real_silicon: true,
  silicon_drift: 6,
  epoch_ok: true,
  cores: 16,
  weight_1to1: 0.125,
};

// Real ML-DSA-65 sizes — the pq-bridge emits base64 (pubkey 1952B, sig 3309B)
const KEYS_OK = {
  signing_key: { key_id: 'k'.repeat(32), public_key: Buffer.alloc(1952, 7).toString('base64'), algorithm: 'ML-DSA-65' },
};

const SIGN_OK = { signature: Buffer.alloc(3309, 9).toString('base64'), algorithm: 'ML-DSA-65', key_id: 'k'.repeat(32) };

function stubBridge(body = SEAL_OK, { signFails = false } = {}) {
  return vi.fn(async (url) => {
    if (String(url).includes('/public-keys')) {
      return { ok: true, json: async () => KEYS_OK };
    }
    if (String(url).includes('/sign')) {
      return signFails
        ? { ok: false, status: 500, json: async () => ({}) }
        : { ok: true, json: async () => SIGN_OK };
    }
    return { ok: true, json: async () => body };
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setTimeTrustProvider(null);
  setProofProvider(null);
});

describe('contributionMeshState', () => {
  test('entropyFlags = 3 when time attestable and real silicon', async () => {
    vi.stubGlobal('fetch', stubBridge());
    setTimeTrustProvider(() => true);
    const c = await contributionMeshState(1_000_000_000_000);
    expect(c.entropyFlags).toBe(3);
    expect(c.siliconDrift).toBe(6);
  });

  test('bit0 stays 0 when MANI tier < PTP', async () => {
    vi.stubGlobal('fetch', stubBridge());
    setTimeTrustProvider(() => false);
    const c = await contributionMeshState(1_000_030_000_000);
    expect(c.entropyFlags).toBe(2); // real_silicon only
  });

  test('unwired provider → bit0 0 (unattested time, never claimed)', async () => {
    vi.stubGlobal('fetch', stubBridge());
    const c = await contributionMeshState(1_000_060_000_000);
    expect(c.entropyFlags).toBe(2);
  });

  test('silicon_drift forwarded, epoch/shape per wire spec', async () => {
    vi.stubGlobal('fetch', stubBridge());
    const c = await contributionMeshState(1_000_090_000_000);
    expect(c.version).toBe(1);
    expect(c.epoch).toBe(currentEpoch(1_000_090_000_000));
    expect(c.seal).toEqual([0, 1, 2, 3]);
    expect(c.spongeRounds).toBe(0);
    expect(c.shareCount).toBe(0);
    expect(c.jobRoot).toBe('0'.repeat(64));
  });

  test('bridge down → null payload, field omitted by withContribution', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('ECONNREFUSED'); }));
    const c = await contributionMeshState(1_000_120_000_000);
    expect(c).toBeNull();
    const merged = await withContribution({ foo: 1 });
    expect(merged.contribution).toBeUndefined();
    expect(merged.foo).toBe(1);
  });

  test('per-epoch cache — no refetch inside the same epoch', async () => {
    const spy = stubBridge();
    vi.stubGlobal('fetch', spy);
    const t = 1_000_150_000_000;
    await contributionMeshState(t);
    await contributionMeshState(t + 500);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test('npuProof carried when provider returns an execution proof', async () => {
    vi.stubGlobal('fetch', stubBridge());
    const proof = {
      nonce: 'yakmesh-e333',
      device: '1022:1502',
      consistent: true,
      digests: { input: 'aa', output: 'bb' },
      timingNs: { p50: 145000 },
    };
    setProofProvider(async () => proof);
    const c = await contributionMeshState(1_000_180_000_000);
    expect(c.npuProof).toMatchObject(proof);
    expect(c.npuProof.attestation).toMatchObject({
      algorithm: 'ML-DSA-65',
      signature: Buffer.alloc(3309, 9).toString('hex'),
      publicKey: Buffer.alloc(1952, 7).toString('hex'),
    });
    expect(c.npuProof.attestation.claim).toContain('YAKMESH|NPU-PROOF|v1|');
  });

  test('sign failure → unsigned proof still rides, attestation omitted', async () => {
    vi.stubGlobal('fetch', stubBridge(SEAL_OK, { signFails: true }));
    const proof = {
      nonce: 'yakmesh-eX', device: '1022:1502', consistent: true,
      digests: { input: 'aa', output: 'bb' }, timingNs: { p50: 1 },
    };
    setProofProvider(async () => proof);
    const c = await contributionMeshState(1_000_270_000_000);
    expect(c.npuProof).toMatchObject(proof);
    expect(c.npuProof.attestation).toBeUndefined();
  });

  test('verifySignature — pq-bridge base64 signature/key decode + hex path', () => {
    const kp = generateKeyPair();
    const claim = 'YAKMESH|NPU-PROOF|v1|42|node1|d|k|n|8|1|i|o|1|2|3|4|5|6';
    const sigB64 = Buffer.from(signMessage(claim, kp.secretKey), 'hex').toString('base64');
    const pkB64 = Buffer.from(kp.publicKey, 'hex').toString('base64');
    // base64 (bridge form) and hex (canonical form) both verify
    expect(verifySignature(claim, sigB64, pkB64)).toBe(true);
    expect(verifySignature(claim, signMessage(claim, kp.secretKey), kp.publicKey)).toBe(true);
    // tampered claim and non-encoded garbage still reject
    expect(verifySignature(claim + 'x', sigB64, pkB64)).toBe(false);
    expect(verifySignature(claim, 'not-a-signature!!', pkB64)).toBe(false);
  });

  test('npuProofClaim — canonical serialization is deterministic and complete', () => {
    const p = {
      nonce: 'n1', device: '1022:1502', kernel: 'k', n: 8, consistent: true,
      digests: { input: 'i', output: 'o' },
      timingNs: { p50: 1, p95: 2, mean: 3, min: 4, max: 5, wall: 6 },
    };
    const claim = npuProofClaim(42, 'node1', p);
    expect(claim).toBe('YAKMESH|NPU-PROOF|v1|42|node1|1022:1502|k|n1|8|1|i|o|1|2|3|4|5|6');
    expect(npuProofClaim(42, 'node1', p)).toBe(claim);
    expect(npuProofClaim(43, 'node1', p)).not.toBe(claim); // epoch-bound
  });

  test('proof provider throws → claim still emitted without npuProof', async () => {
    vi.stubGlobal('fetch', stubBridge());
    setProofProvider(async () => { throw new Error('no NPU'); });
    const c = await contributionMeshState(1_000_210_000_000);
    expect(c).not.toBeNull();
    expect(c.npuProof).toBeUndefined();
    expect(c.seal).toEqual([0, 1, 2, 3]);
  });

  test('unwired provider → npuProof omitted entirely', async () => {
    vi.stubGlobal('fetch', stubBridge());
    const c = await contributionMeshState(1_000_240_000_000);
    expect(c.npuProof).toBeUndefined();
  });
});
