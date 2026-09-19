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
  currentEpoch,
} from '../contribution.js';

const SEAL_OK = {
  node_id: 'a'.repeat(64),
  seal: [0, 1, 2, 3],
  real_silicon: true,
  silicon_drift: 6,
  epoch_ok: true,
  cores: 16,
  weight_1to1: 0.125,
};

function stubBridge(body = SEAL_OK) {
  return vi.fn(async () => ({ ok: true, json: async () => body }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  setTimeTrustProvider(null);
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
});
