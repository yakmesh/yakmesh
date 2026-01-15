/**
 * YAKMESH Real Node Timing Test Suite
 * 
 * This test runs on an ACTUAL node to measure real-world timing capabilities.
 * Results should be used for patent documentation.
 * 
 * Run with: node test-real-timing.mjs
 */

import { TimeSourceDetector, TimeTrustLevel, PhaseTolerance } from './oracle/time-source.js';

console.log(`
╔══════════════════════════════════════════════════════════════════╗
║     YAKMESH REAL-WORLD TIMING MEASUREMENT SUITE                  ║
║     For Patent Validation - January 2026                         ║
╚══════════════════════════════════════════════════════════════════╝
`);

// ===== TEST 1: Local Timer Resolution =====
console.log('━━━ TEST 1: Local Timer Resolution ━━━');
console.log('Measuring actual resolution of Node.js timing APIs...\n');

// Test process.hrtime.bigint()
const hrSamples = [];
for (let i = 0; i < 10000; i++) {
  const t1 = process.hrtime.bigint();
  const t2 = process.hrtime.bigint();
  if (t2 > t1) hrSamples.push(Number(t2 - t1));
}
hrSamples.sort((a, b) => a - b);

console.log('process.hrtime.bigint() results:');
console.log(`  Minimum delta: ${hrSamples[0]} ns`);
console.log(`  Median delta:  ${hrSamples[Math.floor(hrSamples.length / 2)]} ns`);
console.log(`  95th percentile: ${hrSamples[Math.floor(hrSamples.length * 0.95)]} ns`);
console.log(`  Maximum delta: ${hrSamples[hrSamples.length - 1]} ns`);

// Test performance.now()
const perfSamples = [];
for (let i = 0; i < 10000; i++) {
  const t1 = performance.now();
  const t2 = performance.now();
  if (t2 > t1) perfSamples.push((t2 - t1) * 1_000_000); // Convert to ns
}
perfSamples.sort((a, b) => a - b);

console.log('\nperformance.now() results:');
console.log(`  Minimum delta: ${perfSamples[0].toFixed(0)} ns`);
console.log(`  Median delta:  ${perfSamples[Math.floor(perfSamples.length / 2)].toFixed(0)} ns`);

// ===== TEST 2: Time Source Detection =====
console.log('\n━━━ TEST 2: Time Source Detection ━━━');
console.log('Detecting available time sources on this system...\n');

const detector = new TimeSourceDetector();
const detection = await detector.detect();

console.log('Detection results:');
console.log(`  Trust Level: ${detection.trustLevel}`);
console.log(`  Primary Source: ${detection.primarySource || 'None'}`);
console.log(`  NTP Available: ${detection.sources.ntp.available}`);
console.log(`  PTP Available: ${detection.sources.ptp?.available || false}`);
console.log(`  GPS Available: ${detection.sources.gps?.available || false}`);
console.log(`  Atomic Available: ${detection.sources.atomic?.available || false}`);

// ===== TEST 3: Phase Tolerance Settings =====
console.log('\n━━━ TEST 3: Current Tolerance Configuration ━━━');
console.log('These are the actual tolerances used in the codebase:\n');

console.log('Trust Level Tolerances:');
for (const [level, tolerance] of Object.entries(PhaseTolerance)) {
  console.log(`  ${level}: ±${tolerance}ms`);
}

// ===== TEST 4: Clock Drift Measurement =====
console.log('\n━━━ TEST 4: Local Clock Stability (60-second test) ━━━');
console.log('Measuring clock stability over time...\n');

const driftSamples = [];
const startTime = process.hrtime.bigint();
const intervalMs = 100;
const testDurationMs = 5000; // 5 seconds for quick test

for (let elapsed = 0; elapsed < testDurationMs; elapsed += intervalMs) {
  const expectedNs = BigInt(elapsed * 1_000_000);
  const actualNs = process.hrtime.bigint() - startTime;
  const driftNs = Number(actualNs - expectedNs);
  driftSamples.push(driftNs);
  
  // Busy wait for interval
  const waitUntil = startTime + BigInt((elapsed + intervalMs) * 1_000_000);
  while (process.hrtime.bigint() < waitUntil) {
    // busy wait
  }
}

const avgDrift = driftSamples.reduce((a, b) => a + b, 0) / driftSamples.length;
const maxDrift = Math.max(...driftSamples.map(Math.abs));

console.log('Clock stability results (5-second test):');
console.log(`  Average drift from expected: ${(avgDrift / 1000).toFixed(2)} μs`);
console.log(`  Maximum drift from expected: ${(maxDrift / 1000).toFixed(2)} μs`);
console.log(`  Maximum drift in ms: ${(maxDrift / 1_000_000).toFixed(3)} ms`);

// ===== TEST 5: NTP Offset Query =====
console.log('\n━━━ TEST 5: NTP Synchronization Status ━━━');
console.log('Querying system NTP status...\n');

import { execSync } from 'child_process';

try {
  if (process.platform === 'win32') {
    const result = execSync('w32tm /query /status', { encoding: 'utf8', timeout: 5000 });
    console.log('Windows Time Service Status:');
    const lines = result.split('\n').filter(l => l.includes('Offset') || l.includes('Source') || l.includes('Stratum'));
    lines.forEach(l => console.log(`  ${l.trim()}`));
  } else {
    const result = execSync('chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || timedatectl show-timesync 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    console.log('NTP Status:');
    console.log(result.split('\n').slice(0, 10).map(l => `  ${l}`).join('\n'));
  }
} catch (e) {
  console.log('  Unable to query NTP status:', e.message);
}

// ===== SUMMARY =====
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                         TEST SUMMARY                              ║
╚══════════════════════════════════════════════════════════════════╝

FACTUAL CLAIMS SUPPORTED BY THIS TEST:

✓ Local timer resolution: ~${hrSamples[0]}ns (process.hrtime.bigint)
✓ Detected trust level: ${detection.trustLevel}
✓ Configured tolerances: ±${PhaseTolerance[detection.trustLevel]}ms for ${detection.trustLevel}
✓ Maximum local clock drift (5s): ${(maxDrift / 1_000_000).toFixed(3)}ms

CLAIMS THAT CANNOT BE MADE WITHOUT ADDITIONAL HARDWARE:

✗ "Nanosecond network synchronization" - requires atomic hardware + PTP
✗ "Sub-nanosecond alignment" - physically impossible without specialized hardware
✗ "1ns precision" - local measurement only, not network sync

RECOMMENDED LANGUAGE FOR PATENT/MARKETING:

"YAKMESH implements configurable timing tolerances from ±100ms (atomic)
to ±5000ms (NTP), with a software architecture designed to leverage
high-precision time sources when available."
`);

console.log('Test complete. Save these results for patent documentation.\n');
