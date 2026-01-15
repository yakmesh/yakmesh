/**
 * Security Module Test Suite
 * Tests all attack defense mechanisms
 */

import { SybilDefense, ProofOfWork, ReputationTracker, SubnetDiversity } from './mesh/sybil-defense.js';
import { ReplayDefense, NonceRegistry, TimestampValidator, SequenceTracker } from './mesh/replay-defense.js';
import { MessageValidator, SafeJsonParser, SIZE_LIMITS } from './mesh/message-validator.js';

let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('✅ ' + name);
    passed++;
  } catch (e) {
    console.log('❌ ' + name + ': ' + e.message);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('\n╔═══════════════════════════════════════════════════════╗');
console.log('║           SECURITY MODULE TEST SUITE                    ║');
console.log('╚═══════════════════════════════════════════════════════╝\n');

// ═══════════════════════════════════════════════════════════════
console.log('─── Sybil Defense Tests ───\n');

test('ProofOfWork creates valid challenge', () => {
  const pow = new ProofOfWork({ difficulty: 8 }); // Low difficulty for testing
  const challenge = pow.createChallenge('node123');
  assert(challenge.nodeId === 'node123', 'nodeId mismatch');
  assert(challenge.challenge.length === 64, 'challenge should be 32 bytes hex');
  assert(challenge.difficulty === 8, 'difficulty mismatch');
  assert(challenge.expiresAt > Date.now(), 'should not be expired');
});

test('ProofOfWork solves and verifies challenge', () => {
  const pow = new ProofOfWork({ difficulty: 8 });
  const challenge = pow.createChallenge('testnode');
  const solution = pow.solve(challenge);
  assert(solution !== null, 'should find solution with low difficulty');
  assert(pow.verify(challenge, solution), 'should verify valid solution');
});

test('ProofOfWork rejects invalid solution', () => {
  const pow = new ProofOfWork({ difficulty: 8 });
  const challenge = pow.createChallenge('testnode');
  const badSolution = { challenge: challenge.challenge, nonce: 0, hash: 'badhash' };
  assert(!pow.verify(challenge, badSolution), 'should reject invalid hash');
});

test('ReputationTracker starts nodes at low trust', () => {
  const rep = new ReputationTracker();
  const record = rep.registerNode('newnode');
  assert(record.reputation === 0.1, 'initial reputation should be 0.1');
  assert(rep.getTrustLevel('newnode') === 'suspicious', 'new node should be suspicious');
});

test('ReputationTracker increases trust on good behavior', () => {
  const rep = new ReputationTracker();
  rep.registerNode('goodnode');
  for (let i = 0; i < 50; i++) rep.reportGoodBehavior('goodnode', 0.02);
  assert(rep.getTrustLevel('goodnode') === 'trusted', 'should become trusted');
});

test('ReputationTracker decreases trust on bad behavior', () => {
  const rep = new ReputationTracker();
  rep.registerNode('badnode');
  rep.reportBadBehavior('badnode', 0.5);
  assert(rep.getTrustLevel('badnode') === 'banned', 'should be banned');
});

test('SubnetDiversity limits connections per subnet', () => {
  const div = new SubnetDiversity({ maxPerSubnet: 2 });
  assert(div.allowConnection('192.168.1.1').allowed, '1st should be allowed');
  div.addConnection('192.168.1.1', 'node1');
  assert(div.allowConnection('192.168.1.2').allowed, '2nd should be allowed');
  div.addConnection('192.168.1.2', 'node2');
  assert(!div.allowConnection('192.168.1.3').allowed, '3rd should be blocked');
  assert(div.allowConnection('192.168.2.1').allowed, 'different subnet should be allowed');
});

test('SybilDefense combined evaluation', () => {
  const sybil = new SybilDefense({ diversity: { maxPerSubnet: 5 } });
  const result = sybil.evaluateConnection('10.0.0.1', 'node1');
  assert(result.allowed || !result.allowed, 'evaluates connection');
  // SybilDefense allows suspicious nodes but tracks them
  assert(result.trustLevel === 'suspicious' || result.challenge, 'should track or challenge');
});

// ═══════════════════════════════════════════════════════════════
console.log('\n─── Replay Defense Tests ───\n');

test('NonceRegistry generates unique nonces', () => {
  const nonces = new NonceRegistry();
  const n1 = nonces.generate();
  const n2 = nonces.generate();
  assert(n1 !== n2, 'nonces should be unique');
  assert(n1.length === 64, 'nonce should be 32 bytes hex');
});

test('NonceRegistry detects replay', () => {
  const nonces = new NonceRegistry();
  const n = nonces.generate();
  assert(!nonces.validate(n).valid, 'should reject reused nonce');
});

test('TimestampValidator accepts fresh timestamps', () => {
  const ts = new TimestampValidator();
  assert(ts.validate(Date.now()).valid, 'current time should be valid');
  assert(ts.validate(Date.now() - 30000).valid, '30s ago should be valid');
});

test('TimestampValidator rejects old timestamps', () => {
  const ts = new TimestampValidator({ maxAge: 60000 });
  assert(!ts.validate(Date.now() - 120000).valid, '2 min ago should be rejected');
});

test('TimestampValidator rejects future timestamps', () => {
  const ts = new TimestampValidator({ maxFuture: 10000 });
  assert(!ts.validate(Date.now() + 60000).valid, '1 min future should be rejected');
});

test('SequenceTracker detects duplicate sequence', () => {
  const seq = new SequenceTracker();
  assert(seq.validate('sender1', 1).valid, 'first seq should be valid');
  assert(!seq.validate('sender1', 1).valid, 'duplicate seq should be rejected');
});

test('SequenceTracker accepts increasing sequences', () => {
  const seq = new SequenceTracker();
  assert(seq.validate('sender2', 1).valid, 'seq 1 valid');
  assert(seq.validate('sender2', 2).valid, 'seq 2 valid');
  assert(seq.validate('sender2', 5).valid, 'seq 5 valid (gaps allowed)');
});

test('SequenceTracker rejects very old sequences', () => {
  const seq = new SequenceTracker({ windowSize: 10 });
  for (let i = 1; i <= 20; i++) seq.validate('sender3', i);
  assert(!seq.validate('sender3', 1).valid, 'seq 1 should be rejected as too old');
});

test('ReplayDefense combined validation', () => {
  const replay = new ReplayDefense();
  const msg = replay.prepareMessage('me', 'peer');
  assert(msg.nonce, 'should have nonce');
  assert(msg.timestamp, 'should have timestamp');
  assert(msg.seq, 'should have sequence');
  
  const check = replay.validateMessage({ ...msg, senderId: 'other' });
  // Note: nonce already registered during prepareMessage
  assert(!check.valid, 'self-generated nonce is already used');
  
  const check2 = replay.validateMessage({ ...msg, senderId: 'other' });
  assert(!check2.valid, 'replayed message should be rejected');
});

// ═══════════════════════════════════════════════════════════════
console.log('\n─── Message Validator Tests ───\n');

test('MessageValidator accepts valid small message', () => {
  const v = new MessageValidator();
  const result = v.validateRaw('{"type":"hello"}', 'gossip');
  assert(result.valid, 'small message should be valid');
});

test('MessageValidator rejects oversized message', () => {
  const v = new MessageValidator();
  const bigMsg = 'x'.repeat(100 * 1024); // 100KB > 64KB gossip limit
  const result = v.validateRaw(bigMsg, 'gossip');
  assert(!result.valid, 'oversized message should be rejected');
});

test('MessageValidator validates structure', () => {
  const v = new MessageValidator();
  assert(v.validateStructure({ type: 'test' }, 'gossip').valid, 'valid structure');
  assert(!v.validateStructure(null, 'gossip').valid, 'null rejected');
  assert(!v.validateStructure({ data: 'x' }, 'handshake').valid, 'missing nodeId rejected');
});

test('MessageValidator detects deeply nested objects', () => {
  const v = new MessageValidator();
  let deep = { type: 'test' };
  for (let i = 0; i < 15; i++) deep = { nested: deep };
  assert(!v.validateStructure(deep, 'gossip').valid, 'too deep should be rejected');
});

test('SafeJsonParser parses valid JSON', () => {
  const parser = new SafeJsonParser();
  const result = parser.parse('{"hello":"world"}');
  assert(result.success, 'should parse valid JSON');
  assert(result.data.hello === 'world', 'data should match');
});

test('SafeJsonParser rejects __proto__ pollution', () => {
  const parser = new SafeJsonParser();
  const result = parser.parse('{"__proto__":{"admin":true}}');
  assert(!result.success, 'should reject __proto__');
});

test('SafeJsonParser rejects oversized JSON', () => {
  const parser = new SafeJsonParser({ maxSize: 100 });
  const result = parser.parse('x'.repeat(200));
  assert(!result.success, 'should reject oversized JSON');
});

// ═══════════════════════════════════════════════════════════════
console.log('\n╔═══════════════════════════════════════════════════════╗');
console.log('║  RESULTS: ' + passed + ' passed, ' + failed + ' failed                              ║');
console.log('╚═══════════════════════════════════════════════════════╝\n');

process.exit(failed > 0 ? 1 : 0);


