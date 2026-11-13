#!/usr/bin/env node
/*
 * job-feeder — deposit deterministic mkc-sha3batch jobs into the
 * local node's claim pipeline. One deposit per epoch by default.
 *
 * The job is identity-bound: result = expectedResult(spec, OUR
 * canonical nodeId), so the epoch claim's jobRoot commits work only
 * this hardware could have produced — and any peer can recompute it
 * to audit (sha3chain-family recomputes in plain JS, no binary).
 *
 *   node scripts/job-feeder.js                 # one job per epoch
 *   node scripts/job-feeder.js --once          # single deposit, exit
 *   node scripts/job-feeder.js --jobs 3        # 3 jobs per epoch
 *   node scripts/job-feeder.js --node :3080 --count 64
 *
 * Requires the job pipeline (mesh/job-store.js + /api/jobs/deposit).
 */

import { expectedResult } from '../mesh/echo-challenge.js';
import { randomBytes } from 'crypto';

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};
const NODE = opt('node', 'http://127.0.0.1:3080');
const COUNT = parseInt(opt('count', '64'), 10);
const JOBS = parseInt(opt('jobs', '1'), 10);
const ONCE = args.includes('--once');
const EPOCH_MS = 30_000;

async function canonicalNodeId() {
  const r = await fetch(`${NODE}/node`, { signal: AbortSignal.timeout(5000) });
  const d = await r.json();
  if (!d.canonicalNodeId) throw new Error('node reports no canonicalNodeId — claim layer not up?');
  return d.canonicalNodeId;
}

async function depositOnce(me) {
  const nonce = randomBytes(16).toString('hex');
  const spec = { kind: 'mkc-sha3batch', nonce, count: COUNT };
  const result = expectedResult(
    { type: 'mkc-sha3batch', count: COUNT }, nonce, me);
  const r = await fetch(`${NODE}/api/jobs/deposit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      job_id: `mkc-${nonce}`,
      class: 2, spec, result,
      executor: 'cpu', wall_ms: 0,
    }),
    signal: AbortSignal.timeout(5000),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`deposit ${r.status}: ${JSON.stringify(d).slice(0, 200)}`);
  return d;
}

function msToNextEpoch() {
  return EPOCH_MS - (Date.now() % EPOCH_MS) + 500; // just past the boundary
}

const me = await canonicalNodeId();
console.log(`[job-feeder] canonical node ${me.slice(0, 24)}… — ${JOBS} job(s)/epoch, count=${COUNT}`);

if (ONCE) {
  const d = await depositOnce(me);
  console.log('[job-feeder] deposited:', JSON.stringify(d));
  process.exit(0);
}

for (;;) {
  await new Promise(r => setTimeout(r, msToNextEpoch()));
  const epoch = Math.floor(Date.now() / EPOCH_MS);
  try {
    for (let i = 0; i < JOBS; i++) {
      const d = await depositOnce(me);
      console.log(`[job-feeder] epoch ${epoch} deposit ${i + 1}/${JOBS}: pending=${d.pending}`);
    }
  } catch (e) {
    console.warn(`[job-feeder] epoch ${epoch}: ${e.message}`);
  }
}
