/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * dna-spiral wasm tests — native wormhole-seal verification must be
 * bit-exact with the native Rust build (golden vectors generated from
 * yakcoin_crypto::seal::derive on x86_64), and verifyEpochSeals must
 * mark verdicts locally without the bridge.
 *
 * @module mesh/tests/dna-spiral.test
 */

import { describe, test, expect, vi } from 'vitest';

vi.mock('../../utils/avoth-bridge.js', () => ({ isAvailable: vi.fn() }));
import { isAvailable } from '../../utils/avoth-bridge.js';

import { sealDerive, verifyEpochSeal, avothHash, isAvailable as wasmUp }
  from '../../utils/dna-spiral.js';
import { ClaimLedger } from '../claim-ledger.js';

const NODE = 'ab'.repeat(32);
const JOB0 = '0'.repeat(64);
const JOBCD = 'cd'.repeat(32);

describe('dna-spiral wasm', () => {
  test('loads', () => {
    expect(wasmUp()).toBe(true);
  });

  // Golden vectors — yakcoin_crypto::seal::derive on x86_64:
  //   derive(node=ab*32, job=0*32, epoch) → seal
  test.each([
    [0, [0, 3, 0, 0]],
    [1, [0, 3, 3, 3]],
    [7, [0, 2, 0, 0]],
    [42, [2, 1, 0, 1]],
    [100_000, [1, 0, 0, 1]],
  ])('seal_derive epoch %i → %j (native-exact)', (epoch, want) => {
    expect(sealDerive(NODE, JOB0, epoch)).toEqual(want);
  });

  test('nonzero jobId binds into the seal', () => {
    expect(sealDerive(NODE, JOBCD, 42)).toEqual([2, 3, 3, 1]);
  });

  test('verifyEpochSeal accepts the derived seal, rejects transplants', () => {
    const seal = sealDerive(NODE, JOB0, 42);
    expect(verifyEpochSeal(NODE, 42, seal)).toBe(true);
    // Seal from a different epoch — transplanted claim fails.
    expect(verifyEpochSeal(NODE, 42, sealDerive(NODE, JOB0, 41))).toBe(false);
    // Seal from a different node — identity transplant fails.
    expect(verifyEpochSeal('cd'.repeat(32), 42, seal)).toBe(false);
  });

  test('avothHash returns 64 bytes, deterministic', () => {
    const a = avothHash(Buffer.from('hello'));
    const b = avothHash(Buffer.from('hello'));
    expect(a).toHaveLength(64);
    expect(a.equals(b)).toBe(true);
  });
});

describe('ClaimLedger.verifyEpochSeals — native path', () => {
  const hb = (epoch, yakId, seal) => ({
    nodeId: yakId, sequence: 1, hash: `h-${yakId}`, timestamp: Date.now(),
    meshState: { contribution: {
      version: 1, epoch, nodeId: NODE, seal,
      spongeRounds: 0, shareCount: 5, jobRoot: '0'.repeat(64),
      entropyFlags: 0, siliconDrift: 0,
    } },
  });

  test('verifies seals in-process — no bridge, no deferral', async () => {
    isAvailable.mockResolvedValue(false); // bridge DOWN — native must not care
    const ledger = new ClaimLedger({ nodeId: 'us' });
    const good = sealDerive(NODE, JOB0, 9);
    const bad = [3, 3, 3, 3];
    ledger.observe(hb(9, 'good', good));
    ledger.observe(hb(9, 'bad', bad));

    let failed = null;
    ledger.on('sealFailure', (ev) => { failed = ev; });
    const r = await ledger.verifyEpochSeals(9);

    expect(r.device).toBe('wasm-local');
    expect(r.valid).toBe(1);
    expect(r.invalid).toBe(1);
    const claims = ledger.epochClaims(9);
    expect(claims.find(c => c.yakmeshNodeId === 'good').sealVerified).toBe(true);
    expect(claims.find(c => c.yakmeshNodeId === 'bad').sealVerified).toBe(false);
    expect(failed.yakmeshNodeId).toBe('bad');
  });
});
