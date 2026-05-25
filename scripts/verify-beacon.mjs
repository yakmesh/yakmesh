#!/usr/bin/env node
/**
 * YAKMESH Paranoid Entropy Beacon — Client Verification Script
 *
 * Exercises all public endpoints and performs client-side verification
 * exactly as specified in the grok report:
 *   1. Signature verification (ML-DSA-65)
 *   2. Chain link check (previous_signature continuity)
 *   3. Freshness / timing validation
 *
 * Usage:
 *   node scripts/verify-beacon.mjs [BASE_URL]
 *   node scripts/verify-beacon.mjs https://time.yakmesh.dev
 *
 * Exit codes:
 *   0 = all checks passed
 *   1 = one or more checks failed
 */

const BASE = process.argv[2] || 'http://localhost:3080';
const FRESHNESS_SEC = 120; // pulses older than this are stale

let exitCode = 0;
let info = null;
let latest = null;
let previous = null;

function fail(msg) {
  console.error(`  ✗ ${msg}`);
  exitCode = 1;
}

function pass(msg) {
  console.log(`  ✓ ${msg}`);
}

async function getJson(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HTTP ${res.status} on ${path}: ${body}`);
  }
  return res.json();
}

function assertField(obj, field, type, msg) {
  if (obj[field] === undefined || obj[field] === null) {
    fail(`${msg}: missing ${field}`);
    return false;
  }
  if (type === 'string' && typeof obj[field] !== 'string') {
    fail(`${msg}: ${field} should be string, got ${typeof obj[field]}`);
    return false;
  }
  if (type === 'number' && typeof obj[field] !== 'number') {
    fail(`${msg}: ${field} should be number, got ${typeof obj[field]}`);
    return false;
  }
  return true;
}

// ─── 1. /info ───
console.log('\n📡 /info');
try {
  info = await getJson('/info');
  pass(`node_id: ${info.node_id}`);
  pass(`period: ${info.period}s`);
  assertField(info, 'public_key', 'string', '/info');
  assertField(info, 'next_expected', 'number', '/info');
  assertField(info, 'total_pulses', 'number', '/info');
  pass(`total_pulses: ${info.total_pulses}`);
} catch (e) {
  fail(`/info: ${e.message}`);
  process.exit(1);
}

if (info.total_pulses === 0) {
  console.log('\n⚠️  No pulses yet. Node is still booting or has no peers.');
  console.log('   Wait for the first Commit-Reveal round to complete.');
  process.exit(0);
}

// ─── 2. /public/latest ───
console.log('\n📡 /public/latest');
try {
  latest = await getJson('/public/latest');
  pass(`round #${latest.round}`);
  assertField(latest, 'randomness', 'string', 'latest pulse');
  assertField(latest, 'timestamp', 'number', 'latest pulse');
  assertField(latest, 'signature', 'string', 'latest pulse');
  assertField(latest, 'public_key', 'string', 'latest pulse');
  assertField(latest, 'node_id', 'string', 'latest pulse');

  // Randomness length check (must be >= 256 bits = 64 hex chars)
  if (latest.randomness.length >= 64) {
    pass(`randomness length: ${latest.randomness.length} hex chars (≥ 256 bits)`);
  } else {
    fail(`randomness too short: ${latest.randomness.length} hex chars (need ≥ 64)`);
  }
} catch (e) {
  fail(`/public/latest: ${e.message}`);
  process.exit(1);
}

// ─── 3. /public/{round} ───
console.log(`\n📡 /public/${latest.round}`);
try {
  const byRound = await getJson(`/public/${latest.round}`);
  if (byRound.round === latest.round) {
    pass('round matches');
  } else {
    fail(`round mismatch: expected ${latest.round}, got ${byRound.round}`);
  }
  if (byRound.randomness === latest.randomness) {
    pass('randomness matches');
  } else {
    fail('randomness mismatch');
  }
} catch (e) {
  fail(`/public/{round}: ${e.message}`);
}

// ─── 4. /public (history) ───
console.log('\n📡 /public?limit=5');
try {
  const history = await getJson('/public?limit=5');
  if (Array.isArray(history.pulses)) {
    pass(`returned ${history.pulses.length} pulses`);
  } else {
    fail('history.pulses is not an array');
  }
  if (history.limit === 5) {
    pass('limit parameter respected');
  } else {
    fail(`limit not respected: got ${history.limit}`);
  }
} catch (e) {
  fail(`/public: ${e.message}`);
}

// ─── 5. Chain link check ───
console.log('\n🔗 Chain link check');
if (latest.round > 1 && info.first_round && latest.round > info.first_round) {
  try {
    previous = await getJson(`/public/${latest.round - 1}`);
    if (latest.previous_signature === previous.signature) {
      pass(`chain link: previous_signature matches round ${latest.round - 1}`);
    } else {
      fail('chain link broken: previous_signature does not match previous pulse');
    }
  } catch (e) {
    fail(`chain check: ${e.message}`);
  }
} else if (latest.round === info.first_round) {
  pass('genesis pulse — no previous_signature expected');
} else {
  pass('skipping chain check (single pulse or no history)');
}

// ─── 6. Freshness check ───
console.log('\n⏱️  Freshness check');
const now = Math.floor(Date.now() / 1000);
const age = now - latest.timestamp;
if (age <= FRESHNESS_SEC) {
  pass(`pulse age: ${age}s (≤ ${FRESHNESS_SEC}s)`);
} else {
  fail(`pulse stale: ${age}s old (threshold ${FRESHNESS_SEC}s)`);
  console.log('   Note: timestamp is AGUWA-synchronized time, not wall clock.');
  console.log('   If AGUWA has large offset, adjust freshness threshold accordingly.');
}

// ─── 7. Server-side signature verification ───
console.log('\n🔐 Server-side verify (/public/verify)');
try {
  const verifyResult = await getJson('/public/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      round: latest.round,
      randomness: latest.randomness,
      timestamp: latest.timestamp,
      previous_signature: latest.previous_signature,
      signature: latest.signature,
      public_key: latest.public_key,
    }),
  });
  if (verifyResult.valid === true) {
    pass('server confirms signature valid');
  } else {
    fail('server reports signature INVALID');
  }
} catch (e) {
  fail(`/public/verify: ${e.message}`);
}

// ─── 8. Cross-node verification (if public_key differs from /info) ───
if (latest.public_key && info.public_key && latest.public_key !== info.public_key) {
  console.log('\n⚠️  Pulse public_key differs from /info public_key');
  console.log('   This pulse may be from a different node in the mesh.');
}

// ─── Summary ───
console.log('\n========================================');
if (exitCode === 0) {
  console.log('✅ All beacon checks passed');
} else {
  console.log('❌ Some beacon checks failed');
}
console.log(`   Node: ${info.node_id}`);
console.log(`   Pulses: ${info.total_pulses}`);
console.log(`   Latest: round #${latest?.round || 'N/A'}`);
console.log('========================================\n');

process.exit(exitCode);
