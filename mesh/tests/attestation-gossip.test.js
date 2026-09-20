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
import { AttestationGossip } from '../attestation-gossip.js';

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
  epoch: 5, yakmeshNodeId: 'peer1', nodeId: 'n'.repeat(64),
  seal: [0, 1, 2, 3], verified: 'verified', ...over,
});

describe('AttestationGossip seal gating', () => {
  test('attests verified claims with unchecked seals', () => {
    const batch = gossip([claim()]).buildBatch(5);
    expect(batch.items).toHaveLength(1);
  });

  test('excludes claims that failed the AVOTH seal recompute', () => {
    const batch = gossip([
      claim({ yakmeshNodeId: 'good' }),
      claim({ yakmeshNodeId: 'forged', sealVerified: false }),
    ]).buildBatch(5);
    expect(batch.items).toHaveLength(1);
    expect(batch.items[0].yakmeshNodeId).toBe('good');
  });

  test('excludes unsigned beats regardless of seal state', () => {
    const batch = gossip([
      claim({ verified: 'unsigned' }),
    ]).buildBatch(5);
    expect(batch.items).toHaveLength(0);
  });
});
