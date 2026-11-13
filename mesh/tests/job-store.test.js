/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Job-store tests — the payable-job pipeline's claimer side:
 * deposit → pending, commitFor → epoch-bound batch (jobRoot =
 * sha3_256 of concatenated results, audit-duty's default commit),
 * reveal serves committed material only.
 *
 * @module mesh/tests/job-store.test
 */

import { describe, test, expect } from 'vitest';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { JobStore } from '../job-store.js';
import { JOB_CLASS } from '../claim-ledger.js';

const NODE = 'a'.repeat(64);
const EPOCH = 59728360;

function job(id, kind, specExtra, resultBytes) {
  return {
    job_id: id,
    spec: { kind, ...specExtra },
    result: Buffer.from(resultBytes).toString('hex'),
    executor: 'cpu',
    wall_ms: 42,
  };
}

describe('JobStore — deposit', () => {
  test('accepts well-formed jobs, queues them pending', () => {
    const s = new JobStore();
    const r = s.deposit(job('z-1', 'zonegen', { seed: 'x' }, [1, 2, 3]));
    expect(r).toEqual({ ok: true, jobId: 'z-1' });
    expect(s.pending).toHaveLength(1);
  });

  test('dedupes job_id — producer retry is idempotent', () => {
    const s = new JobStore();
    s.deposit(job('z-1', 'zonegen', { seed: 'x' }, [1]));
    const r = s.deposit(job('z-1', 'zonegen', { seed: 'x' }, [1]));
    expect(r.ok).toBe(true);
    expect(s.pending).toHaveLength(1);
  });

  test('rejects malformed deposits', () => {
    const s = new JobStore();
    expect(s.deposit({}).error).toMatch(/job_id/);
    expect(s.deposit(job('x', 'zonegen', {}, [])).error)
      .toMatch(/hex/); // zero-byte results aren't jobs
    expect(s.deposit({ job_id: 'x', spec: { kind: 'k' }, result: 'zz' }).error)
      .toMatch(/hex/);
    expect(s.deposit({ job_id: 'x', spec: ['not-object'], result: 'aa' }).error)
      .toMatch(/spec/);
    expect(s.deposit({ job_id: 'x', spec: { nokind: 1 }, result: 'aa' }).error)
      .toMatch(/kind/);
  });

  test('rejects jobs that can never be revealed (bounds)', () => {
    const s = new JobStore();
    const big = { job_id: 'big', spec: { kind: 'k', pad: 'x'.repeat(300 * 1024) }, result: 'aa' };
    expect(s.deposit(big).error).toMatch(/spec/);
    const bigRes = { job_id: 'bigr', spec: { kind: 'k' }, result: 'aa'.repeat(1024 * 1024 + 1) };
    expect(s.deposit(bigRes).error).toMatch(/result/);
  });
});

describe('JobStore — commitFor', () => {
  test('returns null with empty pending', () => {
    expect(new JobStore().commitFor(NODE, EPOCH)).toBeNull();
  });

  test('commits batch: jobRoot = sha3_256(concat results), DETERMINISTIC', () => {
    const s = new JobStore();
    s.deposit(job('a', 'zonegen', { seed: 's1' }, [0x01, 0x02]));
    s.deposit(job('b', 'zonegen', { seed: 's2' }, [0x03]));
    const c = s.commitFor(NODE, EPOCH);
    expect(c.jobClass).toBe(JOB_CLASS.DETERMINISTIC);
    expect(c.count).toBe(2);
    expect(c.jobRoot).toBe(bytesToHex(sha3_256(Buffer.from([1, 2, 3]))));
    expect(s.pending).toHaveLength(0);
  });

  test('committed batch is revealable at claimRef nodeId:epoch', () => {
    const s = new JobStore();
    s.deposit(job('a', 'zonegen', { seed: 's1' }, [9]));
    s.commitFor(NODE, EPOCH);
    const rev = s.get(`${NODE}:${EPOCH}`);
    expect(rev.spec.kind).toBe('job-batch');
    expect(rev.spec.jobs).toHaveLength(1);
    expect(rev.spec.jobs[0].kind).toBe('zonegen');
    expect(rev.result).toBe('09');
  });

  test('pending material is never revealable', () => {
    const s = new JobStore();
    s.deposit(job('a', 'zonegen', { seed: 's1' }, [9]));
    expect(s.get(`${NODE}:${EPOCH}`)).toBeNull();
    expect(s.get(`${NODE}:999`)).toBeNull();
  });

  test('respects maxJobsPerCommit — remainder stays pending', () => {
    const s = new JobStore({ maxJobsPerCommit: 2 });
    s.deposit(job('a', 'k', {}, [1]));
    s.deposit(job('b', 'k', {}, [2]));
    s.deposit(job('c', 'k', {}, [3]));
    const c1 = s.commitFor(NODE, EPOCH);
    expect(c1.count).toBe(2);
    expect(s.pending).toHaveLength(1);
    const c2 = s.commitFor(NODE, EPOCH + 1);
    expect(c2.count).toBe(1);
    expect(c2.jobRoot).toBe(bytesToHex(sha3_256(Buffer.from([3]))));
  });
});

describe('JobStore — audit round-trip', () => {
  test('revealed batch recomputes to the same bytes → commit matches', () => {
    const s = new JobStore();
    const spec = { kind: 'mkc-sha3batch', nonce: 'ab'.repeat(16), count: 4 };
    // simulate the producer's deterministic result
    const fakeResult = sha3_256(Buffer.from('worked'));
    s.deposit({ job_id: 'w1', spec, result: Buffer.from(fakeResult).toString('hex') });
    const c = s.commitFor(NODE, EPOCH);
    const rev = s.get(`${NODE}:${EPOCH}`);
    // audit: commit(revealed) === jobRoot
    const revealed = Buffer.from(rev.result, 'hex');
    expect(bytesToHex(sha3_256(revealed))).toBe(c.jobRoot);
    expect(rev.spec.jobs[0]).toEqual(spec);
  });
});
