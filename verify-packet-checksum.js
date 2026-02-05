#!/usr/bin/env node
/**
 * YPC-27 Packet Checksum Integration Tests
 * 
 * Verifies that YPC-27 checksums work correctly with all YAKMESH protocols.
 * Run with: node verify-packet-checksum.js
 */

import {
  PROTOCOL_DOMAIN,
  CHECKSUM_PREFIX,
  checksumToWire,
  checksumFromWire,
  PacketChecksum,
  createStupaChecksum,
  createNakpakChecksum,
  createKhataChecksum,
  createMantraChecksum,
  wrapWithChecksum,
  unwrapWithChecksum,
} from './oracle/packet-checksum.js';

console.log('🔐 YPC-27 Packet Checksum Integration Tests\n');
console.log('='.repeat(50));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`❌ ${name}`);
    console.log(`   Error: ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// =============================================================================
// Test 1: Protocol domain tags exist
// =============================================================================
test('Protocol domains defined', () => {
  assert(PROTOCOL_DOMAIN.STUPA === 'YAKMESH.STUPA.v1', 'STUPA domain');
  assert(PROTOCOL_DOMAIN.NAKPAK === 'YAKMESH.NAKPAK.v1', 'NAKPAK domain');
  assert(PROTOCOL_DOMAIN.KHATA === 'YAKMESH.KHATA.v1', 'KHATA domain');
  assert(PROTOCOL_DOMAIN.MANTRA === 'YAKMESH.MANTRA.v1', 'MANTRA domain');
});

// =============================================================================
// Test 2: Wire format serialization
// =============================================================================
test('Wire format round-trip', () => {
  const engine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA);
  const checksum = engine.compute('test data');
  
  const wire = checksumToWire(checksum);
  assert(wire.startsWith(CHECKSUM_PREFIX), 'Has prefix');
  assert(wire.length > CHECKSUM_PREFIX.length, 'Has data');
  
  const restored = checksumFromWire(wire);
  assert(checksum.equals(restored), 'Round-trip preserves checksum');
});

// =============================================================================
// Test 3: Domain separation
// =============================================================================
test('Domain separation (different protocols = different checksums)', () => {
  const data = { message: 'test', timestamp: 12345 };
  
  const stupaEngine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA);
  const nakpakEngine = new PacketChecksum(PROTOCOL_DOMAIN.NAKPAK);
  
  const stupaChecksum = stupaEngine.compute(data);
  const nakpakChecksum = nakpakEngine.compute(data);
  
  // Same data, different domains = different checksums
  assert(!stupaChecksum.equals(nakpakChecksum), 'Checksums should differ');
});

// =============================================================================
// Test 4: Deterministic checksums
// =============================================================================
test('Deterministic (same data = same checksum)', () => {
  const engine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA);
  const data = { b: 2, a: 1 };
  
  const checksum1 = engine.compute(data);
  const checksum2 = engine.compute(data);
  
  assert(checksum1.equals(checksum2), 'Same data produces same checksum');
});

// =============================================================================
// Test 5: Key order independence (deterministic JSON)
// =============================================================================
test('Key order independence', () => {
  const engine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA);
  
  const data1 = { z: 3, a: 1, m: 2 };
  const data2 = { a: 1, m: 2, z: 3 };
  
  const checksum1 = engine.compute(data1);
  const checksum2 = engine.compute(data2);
  
  assert(checksum1.equals(checksum2), 'Key order should not affect checksum');
});

// =============================================================================
// Test 6: Tampering detection
// =============================================================================
test('Tampering detection', () => {
  const engine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA);
  const original = { value: 100 };
  const tampered = { value: 101 };
  
  const checksum = engine.compute(original);
  
  assert(engine.verify(original, checksum), 'Original verifies');
  assert(!engine.verify(tampered, checksum), 'Tampered should fail');
});

// =============================================================================
// Test 7: Convenience factory functions
// =============================================================================
test('Factory functions create valid engines', () => {
  const stupa = createStupaChecksum('node-123');
  const nakpak = createNakpakChecksum('node-123');
  const khata = createKhataChecksum('node-123');
  const mantra = createMantraChecksum('node-123');
  
  assert(stupa.domain === PROTOCOL_DOMAIN.STUPA, 'STUPA engine');
  assert(nakpak.domain === PROTOCOL_DOMAIN.NAKPAK, 'NAKPAK engine');
  assert(khata.domain === PROTOCOL_DOMAIN.KHATA, 'KHATA engine');
  assert(mantra.domain === PROTOCOL_DOMAIN.MANTRA, 'MANTRA engine');
});

// =============================================================================
// Test 8: wrapWithChecksum / unwrapWithChecksum
// =============================================================================
test('Wrap/unwrap message with checksum', () => {
  const original = {
    type: 'TEST',
    payload: { data: 'hello' },
    timestamp: Date.now(),
  };
  
  const wrapped = wrapWithChecksum(original, PROTOCOL_DOMAIN.STUPA);
  
  assert(wrapped.ypc27, 'Has ypc27 field');
  assert(wrapped.ypc27.startsWith(CHECKSUM_PREFIX), 'Correct prefix');
  
  const { message, valid, error } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.STUPA);
  
  assert(valid, `Should be valid: ${error}`);
  assert(message.type === 'TEST', 'Message preserved');
  assert(!message.ypc27, 'ypc27 stripped from message');
});

// =============================================================================
// Test 9: Cross-protocol attack prevention
// =============================================================================
test('Cross-protocol attack prevention', () => {
  const message = {
    type: 'HELLO',
    nodeId: 'attacker',
  };
  
  // Wrap as STUPA
  const wrapped = wrapWithChecksum(message, PROTOCOL_DOMAIN.STUPA);
  
  // Try to verify as KHATA (should fail)
  const { valid: validAsKhata } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.KHATA);
  assert(!validAsKhata, 'Cross-protocol should fail');
  
  // Verify as STUPA (should pass)
  const { valid: validAsStupa } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.STUPA);
  assert(validAsStupa, 'Correct protocol should pass');
});

// =============================================================================
// Test 10: Missing checksum detection
// =============================================================================
test('Missing checksum detection', () => {
  const message = { type: 'TEST' };
  
  const { valid, error } = unwrapWithChecksum(message, PROTOCOL_DOMAIN.STUPA);
  
  assert(!valid, 'Should detect missing checksum');
  assert(error.includes('Missing'), 'Error mentions missing');
});

// =============================================================================
// Test 11: Invalid checksum format detection
// =============================================================================
test('Invalid checksum format detection', () => {
  const message = { type: 'TEST', ypc27: 'invalid-format' };
  
  const { valid, error } = unwrapWithChecksum(message, PROTOCOL_DOMAIN.STUPA);
  
  assert(!valid, 'Should detect invalid format');
  assert(error.includes('prefix'), 'Error mentions prefix');
});

// =============================================================================
// Test 12: Simulated STUPA message
// =============================================================================
test('Realistic STUPA message', () => {
  const stupaMessage = {
    id: 'abc123',
    originNodeId: 'yak-node-1',
    payload: { alert: 'Network partition detected' },
    priority: 4,  // CRITICAL
    ttl: 10,
    timestamp: Date.now(),
    hopPath: ['yak-node-1'],
  };
  
  const wrapped = wrapWithChecksum(stupaMessage, PROTOCOL_DOMAIN.STUPA, 'yak-node-1');
  const { valid } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.STUPA, 'yak-node-1');
  
  assert(valid, 'STUPA message validates');
});

// =============================================================================
// Test 13: Simulated NAKPAK packet
// =============================================================================
test('Realistic NAKPAK packet', () => {
  const nakpakPacket = {
    id: 'onion-456',
    circuitId: 'circuit-789',
    layers: [
      { nonce: 'abc', data: 'encrypted1', tag: 'tag1' },
      { nonce: 'def', data: 'encrypted2', tag: 'tag2' },
    ],
    timestamp: Date.now(),
  };
  
  const wrapped = wrapWithChecksum(nakpakPacket, PROTOCOL_DOMAIN.NAKPAK);
  const { valid } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.NAKPAK);
  
  assert(valid, 'NAKPAK packet validates');
});

// =============================================================================
// Test 14: Simulated KHATA message
// =============================================================================
test('Realistic KHATA message', () => {
  const khataMessage = {
    type: 'khata:announce',
    doko: {
      nodeId: 'yak-elder-1',
      publicKey: 'ed25519:abcd...',
      capabilities: ['verify', 'relay'],
    },
    timestamp: Date.now(),
    ttl: 3600000,
    hops: 0,
  };
  
  const wrapped = wrapWithChecksum(khataMessage, PROTOCOL_DOMAIN.KHATA);
  const { valid } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.KHATA);
  
  assert(valid, 'KHATA message validates');
});

// =============================================================================
// Summary
// =============================================================================
console.log('\n' + '='.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\n❌ Some tests failed');
  process.exit(1);
} else {
  console.log('\n✅ All tests passed - YPC-27 packet integration ready');
  process.exit(0);
}
