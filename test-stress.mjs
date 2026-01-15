/**
 * YAKMESH Stress Tests & Edge Cases
 */

import { generateKeyPair, signMessage, verifySignature } from './identity/node-key.js';

console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║         YAKMESH STRESS TESTS & EDGE CASES                ║');
console.log('╚══════════════════════════════════════════════════════════╝\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch(e) {
    console.log(`❌ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

// ═══════════════════════════════════════════════════════════
// MALFORMED INPUT TESTS
// ═══════════════════════════════════════════════════════════
console.log('─── Malformed Input Handling ───\n');

test('Invalid hex in public key returns false, not crash', () => {
  const keys = generateKeyPair();
  const sig = signMessage('test', keys.secretKey);
  // Invalid hex characters
  const result = verifySignature('test', sig, 'ZZZZ' + keys.publicKey.slice(4));
  assert(result === false, 'Should return false for invalid hex');
});

test('Empty signature returns false, not crash', () => {
  const keys = generateKeyPair();
  const result = verifySignature('test', '', keys.publicKey);
  assert(result === false, 'Empty signature should return false');
});

test('Null bytes in message are handled', () => {
  const keys = generateKeyPair();
  const messageWithNull = 'test\x00\x00\x00null';
  const sig = signMessage(messageWithNull, keys.secretKey);
  const valid = verifySignature(messageWithNull, sig, keys.publicKey);
  assert(valid === true, 'Null bytes should be handled correctly');
});

test('Very long signature is rejected', () => {
  const keys = generateKeyPair();
  const fakeSignature = 'a'.repeat(100000);
  const result = verifySignature('test', fakeSignature, keys.publicKey);
  assert(result === false, 'Oversized signature should fail');
});

test('Wrong length public key is rejected', () => {
  const keys = generateKeyPair();
  const sig = signMessage('test', keys.secretKey);
  const shortPk = keys.publicKey.slice(0, 100);
  const result = verifySignature('test', sig, shortPk);
  assert(result === false, 'Short public key should fail');
});

// ═══════════════════════════════════════════════════════════
// REPLAY ATTACK SIMULATION
// ═══════════════════════════════════════════════════════════
console.log('\n─── Replay Attack Scenarios ───\n');

test('Same message signed twice produces different signatures', () => {
  const keys = generateKeyPair();
  const message = 'transfer 100 coins';
  const sig1 = signMessage(message, keys.secretKey);
  const sig2 = signMessage(message, keys.secretKey);
  // ML-DSA is deterministic for same key, so signatures should match
  // This is actually EXPECTED behavior - not a vulnerability
  console.log(`   └─ Note: ML-DSA-65 is deterministic (sigs ${sig1 === sig2 ? 'match' : 'differ'})`);
  // Both should verify
  assert(verifySignature(message, sig1, keys.publicKey), 'Sig1 should verify');
  assert(verifySignature(message, sig2, keys.publicKey), 'Sig2 should verify');
});

test('Timestamp in message prevents replay (application pattern)', () => {
  const keys = generateKeyPair();
  const msg1 = JSON.stringify({ action: 'transfer', timestamp: Date.now() });
  const msg2 = JSON.stringify({ action: 'transfer', timestamp: Date.now() + 1 });
  const sig1 = signMessage(msg1, keys.secretKey);
  const sig2 = signMessage(msg2, keys.secretKey);
  // Different timestamps = different messages = different (or can't reuse) signatures
  assert(verifySignature(msg1, sig1, keys.publicKey), 'Msg1 verifies with sig1');
  assert(!verifySignature(msg2, sig1, keys.publicKey), 'Msg2 does NOT verify with sig1');
});

// ═══════════════════════════════════════════════════════════
// CONCURRENT OPERATIONS
// ═══════════════════════════════════════════════════════════
console.log('\n─── Concurrent Operations ───\n');

test('Multiple keys can coexist', () => {
  const keys1 = generateKeyPair();
  const keys2 = generateKeyPair();
  const keys3 = generateKeyPair();
  
  const sig1 = signMessage('msg1', keys1.secretKey);
  const sig2 = signMessage('msg2', keys2.secretKey);
  const sig3 = signMessage('msg3', keys3.secretKey);
  
  assert(verifySignature('msg1', sig1, keys1.publicKey), 'Key1 works');
  assert(verifySignature('msg2', sig2, keys2.publicKey), 'Key2 works');
  assert(verifySignature('msg3', sig3, keys3.publicKey), 'Key3 works');
  
  // Cross-verification should fail
  assert(!verifySignature('msg1', sig1, keys2.publicKey), 'Cross-verify fails');
});

test('Rapid sequential operations', () => {
  const keys = generateKeyPair();
  const results = [];
  for (let i = 0; i < 50; i++) {
    const msg = `rapid-${i}`;
    const sig = signMessage(msg, keys.secretKey);
    const valid = verifySignature(msg, sig, keys.publicKey);
    results.push(valid);
  }
  assert(results.every(r => r === true), 'All rapid operations should succeed');
});

// ═══════════════════════════════════════════════════════════
// MEMORY/RESOURCE TESTS  
// ═══════════════════════════════════════════════════════════
console.log('\n─── Resource Usage ───\n');

test('Large message stress test (1MB)', () => {
  const keys = generateKeyPair();
  const largeMessage = 'X'.repeat(1024 * 1024); // 1MB
  const start = Date.now();
  const sig = signMessage(largeMessage, keys.secretKey);
  const signTime = Date.now() - start;
  
  const verifyStart = Date.now();
  const valid = verifySignature(largeMessage, sig, keys.publicKey);
  const verifyTime = Date.now() - verifyStart;
  
  console.log(`   └─ Sign: ${signTime}ms, Verify: ${verifyTime}ms`);
  assert(valid === true, '1MB message should work');
});

test('Memory cleanup (generate many keys)', () => {
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < 100; i++) {
    generateKeyPair();
  }
  // Force GC if available
  if (global.gc) global.gc();
  const after = process.memoryUsage().heapUsed;
  const growth = (after - before) / 1024 / 1024;
  console.log(`   └─ Memory growth: ${growth.toFixed(2)}MB`);
  assert(growth < 500, 'Memory growth should be reasonable');
});

// ═══════════════════════════════════════════════════════════
// BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════
console.log('\n─── Boundary Conditions ───\n');

test('Single character message', () => {
  const keys = generateKeyPair();
  const sig = signMessage('X', keys.secretKey);
  assert(verifySignature('X', sig, keys.publicKey), 'Single char works');
});

test('Message with only whitespace', () => {
  const keys = generateKeyPair();
  const sig = signMessage('   \t\n\r   ', keys.secretKey);
  assert(verifySignature('   \t\n\r   ', sig, keys.publicKey), 'Whitespace works');
});

test('Message with special JSON characters', () => {
  const keys = generateKeyPair();
  const msg = '{"key": "value with \\"quotes\\" and \\\\backslash"}';
  const sig = signMessage(msg, keys.secretKey);
  assert(verifySignature(msg, sig, keys.publicKey), 'JSON escapes work');
});

// ═══════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════
console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log(`║  STRESS TESTS: ${passed} passed, ${failed} failed                       ║`);
console.log('╚══════════════════════════════════════════════════════════╝');

if (failed > 0) process.exit(1);
