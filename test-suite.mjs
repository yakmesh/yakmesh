/**
 * YAKMESH Comprehensive Test Suite
 */

import { generateKeyPair, signMessage, verifySignature, generateNodeId, NodeIdentity } from './identity/node-key.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';

console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║         YAKMESH COMPREHENSIVE TEST SUITE                 ║');
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
// IDENTITY & CRYPTOGRAPHY TESTS
// ═══════════════════════════════════════════════════════════
console.log('─── Identity & Cryptography ───\n');

test('Key generation produces correct lengths', () => {
  const keys = generateKeyPair();
  assert(keys.publicKey.length === 3904, 'Public key should be 3904 hex chars (1952 bytes)');
  assert(keys.secretKey.length === 8064, 'Secret key should be 8064 hex chars (4032 bytes)');
  assert(keys.algorithm === 'ML-DSA-65', 'Algorithm should be ML-DSA-65');
  assert(keys.nistLevel === 3, 'NIST level should be 3');
});

test('Node ID generation is deterministic', () => {
  const keys = generateKeyPair();
  const pk = hexToBytes(keys.publicKey);
  const id1 = generateNodeId(pk);
  const id2 = generateNodeId(pk);
  assert(id1 === id2, 'Same public key should produce same node ID');
  assert(id1.startsWith('node-'), 'Node ID should start with node-');
});

test('Different keys produce different node IDs', () => {
  const keys1 = generateKeyPair();
  const keys2 = generateKeyPair();
  const id1 = generateNodeId(hexToBytes(keys1.publicKey));
  const id2 = generateNodeId(hexToBytes(keys2.publicKey));
  assert(id1 !== id2, 'Different keys should produce different IDs');
});

test('Message signing produces valid signature', () => {
  const keys = generateKeyPair();
  const message = 'Hello YAKMESH!';
  const signature = signMessage(message, keys.secretKey);
  assert(signature.length > 0, 'Signature should not be empty');
  assert(typeof signature === 'string', 'Signature should be hex string');
});

test('Signature verification succeeds for valid signature', () => {
  const keys = generateKeyPair();
  const message = 'Test message for verification';
  const signature = signMessage(message, keys.secretKey);
  const valid = verifySignature(message, signature, keys.publicKey);
  assert(valid === true, 'Valid signature should verify');
});

test('Signature verification fails for tampered message', () => {
  const keys = generateKeyPair();
  const signature = signMessage('original', keys.secretKey);
  const valid = verifySignature('tampered', signature, keys.publicKey);
  assert(valid === false, 'Tampered message should fail verification');
});

test('Signature verification fails for wrong public key', () => {
  const keys1 = generateKeyPair();
  const keys2 = generateKeyPair();
  const signature = signMessage('message', keys1.secretKey);
  const valid = verifySignature('message', signature, keys2.publicKey);
  assert(valid === false, 'Wrong public key should fail verification');
});

test('Empty message can be signed and verified', () => {
  const keys = generateKeyPair();
  const signature = signMessage('', keys.secretKey);
  const valid = verifySignature('', signature, keys.publicKey);
  assert(valid === true, 'Empty message should work');
});

test('Long message can be signed and verified', () => {
  const keys = generateKeyPair();
  const longMessage = 'A'.repeat(10000);
  const signature = signMessage(longMessage, keys.secretKey);
  const valid = verifySignature(longMessage, signature, keys.publicKey);
  assert(valid === true, 'Long message should work');
});

test('Unicode message can be signed and verified', () => {
  const keys = generateKeyPair();
  const unicodeMessage = '🏔️ YAKMESH 你好 مرحبا שלום';
  const signature = signMessage(unicodeMessage, keys.secretKey);
  const valid = verifySignature(unicodeMessage, signature, keys.publicKey);
  assert(valid === true, 'Unicode message should work');
});

test('Binary data can be signed (as Uint8Array)', () => {
  const keys = generateKeyPair();
  const binaryData = new Uint8Array([0x00, 0xFF, 0x42, 0x13, 0x37]);
  const signature = signMessage(binaryData, keys.secretKey);
  const valid = verifySignature(binaryData, signature, keys.publicKey);
  assert(valid === true, 'Binary data should work');
});

// ═══════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════
console.log('\n─── Security Tests ───\n');

test('Truncated signature fails verification', () => {
  const keys = generateKeyPair();
  const signature = signMessage('test', keys.secretKey);
  const truncated = signature.slice(0, signature.length - 100);
  const valid = verifySignature('test', truncated, keys.publicKey);
  assert(valid === false, 'Truncated signature should fail');
});

test('Modified signature fails verification', () => {
  const keys = generateKeyPair();
  const signature = signMessage('test', keys.secretKey);
  // Flip some bits in the middle
  const modified = signature.slice(0, 100) + 'ff'.repeat(50) + signature.slice(200);
  const valid = verifySignature('test', modified, keys.publicKey);
  assert(valid === false, 'Modified signature should fail');
});

test('Signature from one message cannot verify another', () => {
  const keys = generateKeyPair();
  const sig1 = signMessage('message1', keys.secretKey);
  const valid = verifySignature('message2', sig1, keys.publicKey);
  assert(valid === false, 'Cross-message signature should fail');
});

// ═══════════════════════════════════════════════════════════
// PERFORMANCE TESTS
// ═══════════════════════════════════════════════════════════
console.log('\n─── Performance Tests ───\n');

test('Key generation performance (10 iterations)', () => {
  const start = Date.now();
  for (let i = 0; i < 10; i++) {
    generateKeyPair();
  }
  const elapsed = Date.now() - start;
  console.log(`   └─ ${elapsed}ms total, ${(elapsed/10).toFixed(1)}ms per keygen`);
  assert(elapsed < 10000, 'Key generation should complete in reasonable time');
});

test('Signing performance (100 iterations)', () => {
  const keys = generateKeyPair();
  const start = Date.now();
  for (let i = 0; i < 100; i++) {
    signMessage(`Message ${i}`, keys.secretKey);
  }
  const elapsed = Date.now() - start;
  console.log(`   └─ ${elapsed}ms total, ${(elapsed/100).toFixed(2)}ms per sign`);
  assert(elapsed < 30000, 'Signing should complete in reasonable time');
});

test('Verification performance (100 iterations)', () => {
  const keys = generateKeyPair();
  const sig = signMessage('test', keys.secretKey);
  const start = Date.now();
  for (let i = 0; i < 100; i++) {
    verifySignature('test', sig, keys.publicKey);
  }
  const elapsed = Date.now() - start;
  console.log(`   └─ ${elapsed}ms total, ${(elapsed/100).toFixed(2)}ms per verify`);
  assert(elapsed < 30000, 'Verification should complete in reasonable time');
});

// ═══════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════
console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log(`║  RESULTS: ${passed} passed, ${failed} failed                           ║`);
console.log('╚══════════════════════════════════════════════════════════╝');

if (failed > 0) {
  process.exit(1);
}
