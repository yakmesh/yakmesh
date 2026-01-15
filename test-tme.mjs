/**
 * YAKMESH™ Temporal Mesh Encoding (TME) Test Suite
 */

import assert from 'assert';
import {
  TME_CONFIG,
  TemporalSlice,
  TemporalStream,
  TemporalReconstructor,
  TemporalMeshEncoder,
} from './mesh/temporal-encoder.js';

// Test utilities
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('✅ ' + name);
    passed++;
  } catch (err) {
    console.log('❌ ' + name + ': ' + err.message);
    failed++;
  }
}

function section(name) {
  console.log('\n─── ' + name + ' ───\n');
}

console.log('╔══════════════════════════════════════════════════════╗');
console.log('║           TME (TEMPORAL MESH ENCODING) TEST SUITE   ║');
console.log('╚══════════════════════════════════════════════════════╝');

// =============================================================================
section('TemporalSlice Tests');
// =============================================================================

test('TemporalSlice creates with valid temporal hash', () => {
  const slice = new TemporalSlice({
    data: Buffer.from('Hello TME'),
    timestamp: BigInt(Date.now() * 1_000_000),
    sequenceNumber: 0,
    streamId: 'test-stream-123',
    meshPosition: [1.0, 2.0, 3.0],
  });
  
  assert(slice.temporalHash.length === 32, 'Temporal hash should be 32 bytes');
  assert(slice.verify(), 'Slice should verify');
});

test('TemporalSlice serializes and deserializes correctly', () => {
  const original = new TemporalSlice({
    data: Buffer.from('Test data for serialization'),
    timestamp: BigInt(1234567890000000000n),
    sequenceNumber: 5,
    streamId: 'serialize-test',
    meshPosition: [10.5, 20.5, 30.5],
  });
  
  const serialized = original.serialize();
  const deserialized = TemporalSlice.deserialize(serialized);
  
  assert(deserialized.data.equals(original.data), 'Data should match');
  assert(deserialized.timestamp === original.timestamp, 'Timestamp should match');
  assert(deserialized.sequenceNumber === original.sequenceNumber, 'Sequence should match');
  assert(deserialized.streamId === original.streamId, 'StreamId should match');
  assert(deserialized.temporalHash.equals(original.temporalHash), 'Temporal hash should match');
});

test('TemporalSlice rejects tampered data', () => {
  const slice = new TemporalSlice({
    data: Buffer.from('Original data'),
    timestamp: BigInt(Date.now() * 1_000_000),
    sequenceNumber: 0,
    streamId: 'tamper-test',
  });
  
  const serialized = slice.serialize();
  serialized.data = Buffer.from('Tampered data').toString('base64');
  
  try {
    TemporalSlice.deserialize(serialized);
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err.message.includes('mismatch'), 'Should detect tampering');
  }
});

test('TemporalSlice chains with prevTemporalHash', () => {
  const slice1 = new TemporalSlice({
    data: Buffer.from('First slice'),
    timestamp: BigInt(1000000000n),
    sequenceNumber: 0,
    streamId: 'chain-test',
  });
  
  const slice2 = new TemporalSlice({
    data: Buffer.from('Second slice'),
    timestamp: BigInt(1050000000n),
    sequenceNumber: 1,
    streamId: 'chain-test',
    prevTemporalHash: slice1.temporalHash,
  });
  
  assert(!slice2.prevTemporalHash.equals(Buffer.alloc(32)), 'Should have prev hash');
  assert(slice2.prevTemporalHash.equals(slice1.temporalHash), 'Prev hash should match slice1');
});

// =============================================================================
section('TemporalStream Tests');
// =============================================================================

test('TemporalStream encodes message into slices', () => {
  const stream = new TemporalStream({ sliceSize: 10 });
  const message = 'Hello, this is a test message for TME encoding!';
  const slices = stream.encode(message);
  
  assert(slices.length === Math.ceil(message.length / 10), 'Should create correct number of slices');
  assert(stream.totalSlices === slices.length, 'totalSlices should match');
  assert(stream.isComplete, 'Stream should be marked complete');
});

test('TemporalStream maintains temporal chain integrity', () => {
  const stream = new TemporalStream({ sliceSize: 5 });
  const slices = stream.encode('1234567890ABCDEF');
  
  for (let i = 1; i < slices.length; i++) {
    const prev = slices[i - 1];
    const curr = slices[i];
    assert(curr.prevTemporalHash.equals(prev.temporalHash), 'Chain should be linked at slice ' + i);
  }
});

test('TemporalStream rejects message exceeding max slices', () => {
  const stream = new TemporalStream({ sliceSize: 1 });
  const hugeMessage = 'x'.repeat(TME_CONFIG.maxSlicesPerStream + 1);
  
  try {
    stream.encode(hugeMessage);
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err.message.includes('too large'), 'Should reject oversized message');
  }
});

test('TemporalStream addSlice validates slice integrity', () => {
  const stream = new TemporalStream({ sliceSize: 10 });
  const slices = stream.encode('Test message');
  
  // Create a new stream to receive
  const receiverStream = new TemporalStream({
    streamId: stream.streamId,
    sliceSize: 10,
  });
  receiverStream.totalSlices = stream.totalSlices;
  
  // Should accept valid slice
  const added = receiverStream.addSlice(slices[0]);
  assert(added, 'Should accept valid slice');
  
  // Should reject slice from different stream
  const wrongSlice = new TemporalSlice({
    data: Buffer.from('Wrong'),
    timestamp: BigInt(Date.now() * 1_000_000),
    sequenceNumber: 1,
    streamId: 'wrong-stream',
  });
  const rejected = receiverStream.addSlice(wrongSlice);
  assert(!rejected, 'Should reject slice from wrong stream');
});

test('TemporalStream tracks completion percentage', () => {
  const stream = new TemporalStream({ sliceSize: 5 });
  const slices = stream.encode('12345678901234567890'); // 20 chars = 4 slices
  
  const receiverStream = new TemporalStream({
    streamId: stream.streamId,
    sliceSize: 5,
  });
  receiverStream.totalSlices = 4;
  
  assert(receiverStream.getCompletionPercent() === 0, 'Should start at 0%');
  
  receiverStream.addSlice(slices[0]);
  assert(receiverStream.getCompletionPercent() === 25, 'Should be 25% after 1 slice');
  
  receiverStream.addSlice(slices[1]);
  assert(receiverStream.getCompletionPercent() === 50, 'Should be 50% after 2 slices');
});

test('TemporalStream detects missing slices', () => {
  const stream = new TemporalStream({ sliceSize: 5 });
  const slices = stream.encode('12345678901234567890');
  
  const receiverStream = new TemporalStream({
    streamId: stream.streamId,
    sliceSize: 5,
  });
  receiverStream.totalSlices = 4;
  
  receiverStream.addSlice(slices[0]);
  receiverStream.addSlice(slices[3]); // Skip 1 and 2
  
  const missing = receiverStream.getMissingSlices();
  assert(missing.length === 2, 'Should have 2 missing slices');
  assert(missing.includes(1), 'Should be missing slice 1');
  assert(missing.includes(2), 'Should be missing slice 2');
});

// =============================================================================
section('TemporalReconstructor Tests');
// =============================================================================

test('TemporalReconstructor assembles complete stream', () => {
  const stream = new TemporalStream({ sliceSize: 10 });
  const message = 'Hello TME World!';
  const slices = stream.encode(message);
  
  const reconstructor = new TemporalReconstructor();
  reconstructor.registerStream(stream);
  
  const result = reconstructor.reconstruct(stream.streamId);
  assert(result.success, 'Should reconstruct successfully');
  assert(result.data.toString() === message, 'Data should match original');
});

test('TemporalReconstructor reports insufficient slices', () => {
  const stream = new TemporalStream({ sliceSize: 5 });
  stream.encode('12345678901234567890'); // 4 slices
  
  // Create receiver with only 1 slice (25% < 60% threshold)
  const receiverStream = new TemporalStream({
    streamId: stream.streamId,
    sliceSize: 5,
  });
  receiverStream.totalSlices = 4;
  receiverStream.slices.set(0, stream.slices.get(0));
  
  const reconstructor = new TemporalReconstructor();
  reconstructor.registerStream(receiverStream);
  
  const result = reconstructor.reconstruct(receiverStream.streamId);
  assert(!result.success, 'Should fail with insufficient slices');
  assert(result.error.includes('Insufficient'), 'Should report insufficient');
});

test('TemporalReconstructor verifies missing slice via timing proofs', () => {
  const reconstructor = new TemporalReconstructor();
  const streamId = 'proof-test';
  
  reconstructor.timingProofs.set(streamId, new Map());
  
  // Add 3 timing proofs that agree on the hash
  const consensusHash = '0'.repeat(64);
  reconstructor.addTimingProof(streamId, 5, {
    nodeId: 'node-a',
    timestamp: Date.now() * 1_000_000,
    temporalHash: consensusHash,
    signature: 'sig-a',
  });
  reconstructor.addTimingProof(streamId, 5, {
    nodeId: 'node-b',
    timestamp: Date.now() * 1_000_000,
    temporalHash: consensusHash,
    signature: 'sig-b',
  });
  reconstructor.addTimingProof(streamId, 5, {
    nodeId: 'node-c',
    timestamp: Date.now() * 1_000_000,
    temporalHash: 'f'.repeat(64), // Dissenting
    signature: 'sig-c',
  });
  
  const verification = reconstructor.verifyMissingSlice(streamId, 5);
  assert(verification !== null, 'Should have verification');
  assert(verification.verified, 'Should be verified');
  assert(verification.consensusHash === consensusHash, 'Should have consensus hash');
  assert(verification.proofCount === 2, 'Should have 2 agreeing proofs');
});

// =============================================================================
section('TemporalMeshEncoder Tests (End-to-End)');
// =============================================================================

test('TemporalMeshEncoder full encode/decode cycle', () => {
  const sender = new TemporalMeshEncoder({ meshPosition: [1, 2, 3] });
  const receiver = new TemporalMeshEncoder({ meshPosition: [4, 5, 6] });
  
  const message = 'This is a complete TME transmission test!';
  const encoded = sender.encode(message, { sliceSize: 10 });
  
  // Receiver initializes stream
  receiver.initReceive({
    streamId: encoded.streamId,
    ...encoded.metadata,
  });
  
  // Receive all slices
  for (const slice of encoded.slices) {
    receiver.receiveSlice(slice);
  }
  
  // Decode
  const decoded = receiver.decode(encoded.streamId);
  assert(decoded.success, 'Should decode successfully');
  assert(decoded.data.toString() === message, 'Message should match');
});

test('TemporalMeshEncoder tracks statistics', () => {
  const encoder = new TemporalMeshEncoder();
  
  encoder.encode('Message 1', { sliceSize: 5 });
  encoder.encode('Message 2', { sliceSize: 5 });
  
  const stats = encoder.getStats();
  assert(stats.slicesSent > 0, 'Should track slices sent');
});

test('TemporalMeshEncoder handles partial reception', () => {
  const sender = new TemporalMeshEncoder();
  const receiver = new TemporalMeshEncoder();
  
  const message = '12345678901234567890'; // 20 chars
  const encoded = sender.encode(message, { sliceSize: 5 }); // 4 slices
  
  receiver.initReceive({
    streamId: encoded.streamId,
    ...encoded.metadata,
  });
  
  // Only receive slices 0 and 3 (skip 1 and 2)
  receiver.receiveSlice(encoded.slices[0]);
  receiver.receiveSlice(encoded.slices[3]);
  
  const status = receiver.getStreamStatus(encoded.streamId);
  assert(status.receivedSlices === 2, 'Should have 2 slices');
  assert(status.completionPercent === 50, 'Should be 50% complete');
  assert(status.missing.length === 2, 'Should have 2 missing');
});

test('TemporalMeshEncoder rejects unknown stream slice', () => {
  const receiver = new TemporalMeshEncoder();
  
  const fakeSlice = new TemporalSlice({
    data: Buffer.from('Fake'),
    timestamp: BigInt(Date.now() * 1_000_000),
    sequenceNumber: 0,
    streamId: 'unknown-stream',
  });
  
  const result = receiver.receiveSlice(fakeSlice.serialize());
  assert(!result.accepted, 'Should reject unknown stream');
  assert(result.error === 'Unknown stream', 'Should report unknown stream');
});

test('TemporalMeshEncoder detects stream completion', () => {
  const sender = new TemporalMeshEncoder();
  const receiver = new TemporalMeshEncoder();
  
  const encoded = sender.encode('Short', { sliceSize: 10 }); // 1 slice
  
  receiver.initReceive({
    streamId: encoded.streamId,
    ...encoded.metadata,
  });
  
  const result = receiver.receiveSlice(encoded.slices[0]);
  assert(result.streamComplete, 'Should detect completion');
  assert(result.completionPercent === 100, 'Should be 100%');
});

// =============================================================================
// Summary
// =============================================================================

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║  RESULTS: ' + passed + ' passed, ' + failed + ' failed                              ║');
console.log('╚══════════════════════════════════════════════════════╝');

process.exit(failed > 0 ? 1 : 0);
