/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * ClaimLedger epoch-root tests — the MKC KECCAK/KECU64 batch path must
 * produce bit-identical Merkle roots to the local noble fallback, and
 * `device` must report which path actually computed the result.
 *
 * The bridge-availability probe is mocked so both paths are exercised
 * deterministically. With the probe on and a live pq-bridge the MKC
 * batch path runs for real (bit-exact by contract); with no bridge it
 * races down and falls back — the root must be identical either way.
 *
 * @module mesh/tests/claim-ledger.test
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';
import { sha3_256 } from '@noble/hashes/sha3.js';

vi.mock('../../utils/avoth-bridge.js', () => ({ isAvailable: vi.fn() }));

import { isAvailable } from '../../utils/avoth-bridge.js';
import { ClaimLedger } from '../claim-ledger.js';

const hex64 = (n) => n.toString(16).padStart(2, '0').repeat(64).slice(0, 64);

const contribution = (id, epoch, over = {}) => ({
  version: 1, epoch,
  nodeId: hex64(id),           // yakcoin nodeId (canonical leaf field)
  seal: [id % 4, (id + 1) % 4, (id + 2) % 4, (id + 3) % 4],
  spongeRounds: 24,
  shareCount: 7 + id,
  jobRoot: hex64(id * 7919),
  entropyFlags: 1,
  ...over,
});

function feed(ledger, ids, epoch) {
  ids.forEach((id, i) => ledger.observe({
    nodeId: hex64(1000 + id),  // yakmesh nodeId (bucket key)
    sequence: i, hash: `h${id}-${epoch}`, timestamp: Date.now(),
    meshState: { contribution: contribution(id, epoch) },
  }, { verified: 'verified' }));
}

/** Pure-noble reference implementation of the spec. */
function referenceRoot(ledger, epoch) {
  const claims = ledger.epochClaims(epoch);
  let level = claims
    .map(c => ({ nodeId: c.nodeId, leaf: Buffer.from(sha3_256(ClaimLedger.claimLeafBytes(c))) }))
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId) || Buffer.compare(a.leaf, b.leaf))
    .map(e => e.leaf);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length
        ? Buffer.from(sha3_256(Buffer.concat([level[i], level[i + 1]])))
        : level[i]);
    }
    level = next;
  }
  return level[0].toString('hex');
}

describe('ClaimLedger epochClaimRoot', () => {
  beforeEach(() => isAvailable.mockReset());

  test('returns null for an empty epoch', async () => {
    isAvailable.mockResolvedValue(false);
    const ledger = new ClaimLedger({ nodeId: 'us' });
    expect(await ledger.epochClaimRoot(99)).toBeNull();
  });

  test.each([[1], [2], [3], [4], [5], [7], [16]])(
    'local path: %i claim(s) match the reference root',
    async (n) => {
      isAvailable.mockResolvedValue(false);
      const ledger = new ClaimLedger({ nodeId: 'us' });
      feed(ledger, Array.from({ length: n }, (_, i) => i + 1), 5);
      const r = await ledger.epochClaimRoot(5);
      expect(r.root).toBe(referenceRoot(ledger, 5));
      expect(r.claims).toBe(n);
      expect(r.device).toBe('cpu-local');
    });

  test('bridge path: identical root when the probe is up', async () => {
    isAvailable.mockResolvedValue(true);
    const ledger = new ClaimLedger({ nodeId: 'us' });
    feed(ledger, [1, 2, 3, 4, 5, 6, 7], 5);
    const r = await ledger.epochClaimRoot(5);
    // MKC KECCAK is bit-exact vs noble; a dead bridge races to the same
    // local fallback — the root is the invariant either way.
    expect(r.root).toBe(referenceRoot(ledger, 5));
    expect(['npu', 'cpu', 'gpu', 'cpu-local']).toContain(r.device);
  });

  test('bridge racing down mid-call falls back without changing the root', async () => {
    isAvailable
      .mockResolvedValueOnce(true)   // leaf level: bridge attempted
      .mockResolvedValue(false);     // tree levels: probe goes cold
    const ledger = new ClaimLedger({ nodeId: 'us' });
    feed(ledger, [1, 2, 3], 5);
    const r = await ledger.epochClaimRoot(5);
    expect(r.root).toBe(referenceRoot(ledger, 5));
    expect(r.claims).toBe(3);
  });
});
