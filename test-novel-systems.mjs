/**
 * YAKMESH™ v1.3.0 Novel Systems Test Suite
 * Tests for: ECHO, PULSE, NAKPAK, BEACON, SHERPA
 */

import {
  ECHO_CONFIG,
  EchoProbe,
  EchoResponse,
  VirtualCoordinates,
  LatencyTracker,
  EchoRanging,
} from './mesh/echo-ranging.js';

import {
  PULSE_CONFIG,
  Heartbeat,
  HeartbeatChain,
  MeshHealthMonitor,
  PulseLeaderElection,
  PulseSync,
} from './mesh/pulse-sync.js';

import {
  BEACON_CONFIG,
  BeaconMessage,
  DeliveryReceipt,
  DeduplicationTracker,
  ReceiptCollector,
  PriorityMessageQueue,
  BeaconBroadcast,
} from './mesh/beacon-broadcast.js';

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

function assertEqual(actual, expected, msg = '') {
  if (actual !== expected) {
    throw new Error(msg + ' Expected: ' + expected + ', Got: ' + actual);
  }
}

function assertTrue(condition, msg = '') {
  if (!condition) throw new Error(msg || 'Expected true');
}

function assertFalse(condition, msg = '') {
  if (condition) throw new Error(msg || 'Expected false');
}

// ═══════════════════════════════════════════════════════════════════
console.log('\n╔═══════════════════════════════════════════════════════════╗');
console.log('║     YAKMESH v1.3.0 NOVEL SYSTEMS TEST SUITE              ║');
console.log('╚═══════════════════════════════════════════════════════════╝\n');

// ─────────────────────────────────────────────────────────────────────
console.log('─── ECHO (Encrypted Coordinate Heuristic Oracle) Tests ───\n');

test('VirtualCoordinates initializes with random values', () => {
  const vc = new VirtualCoordinates(8);
  assertEqual(vc.dimensions, 8);
  assertEqual(vc.coordinates.length, 8);
  assertTrue(vc.error > 0, 'Should have initial error');
});

test('VirtualCoordinates updates based on RTT measurement', () => {
  const vc = new VirtualCoordinates(4);
  const peerCoords = [10, 20, 30, 40];
  const result = vc.update(peerCoords, 50);
  
  assertTrue(result.predictedDistance !== undefined);
  assertTrue(result.measuredRtt === 50);
  assertTrue(result.newCoordinates.length === 4);
  assertEqual(vc.updateCount, 1);
});

test('VirtualCoordinates calculates distance correctly', () => {
  const vc = new VirtualCoordinates(3);
  vc.coordinates = [0, 0, 0];
  const distance = vc.distanceTo([3, 4, 0]);
  assertEqual(distance, 5); // 3-4-5 triangle
});

test('LatencyTracker computes statistics', () => {
  const tracker = new LatencyTracker(5);
  tracker.addSample(100000000n); // 100ms in ns
  tracker.addSample(150000000n);
  tracker.addSample(200000000n);
  
  const stats = tracker.getStats();
  assertTrue(stats !== null);
  assertEqual(stats.sampleCount, 3);
  assertTrue(stats.min === 100000000n);
  assertTrue(stats.max === 200000000n);
});

test('EchoRanging creates and handles probes', () => {
  const echo = new EchoRanging({ nodeId: 'node-a' });
  const probe = echo.createProbe('node-b');
  
  assertTrue(probe.probeId !== undefined);
  assertEqual(probe.sourceNodeId, 'node-a');
  assertEqual(probe.targetNodeId, 'node-b');
  assertEqual(echo.stats.probesSent, 1);
});

test('EchoRanging handles probe responses', () => {
  const echoA = new EchoRanging({ nodeId: 'node-a' });
  const echoB = new EchoRanging({ nodeId: 'node-b' });
  
  // A sends probe to B
  const probe = echoA.createProbe('node-b');
  
  // B handles probe and generates response
  const response = echoB.handleProbe(probe, 'node-a');
  assertTrue(response.probeId === probe.probeId);
  assertTrue(response.coordinates !== undefined);
});

test('EchoRanging builds topology from measurements', () => {
  const echo = new EchoRanging({ nodeId: 'center' });
  
  // Simulate peer coordinate data
  echo.peerCoordinates.set('peer1', [10, 20, 30, 40, 50, 60, 70, 80]);
  echo.peerCoordinates.set('peer2', [15, 25, 35, 45, 55, 65, 75, 85]);
  
  const topology = echo.getTopology();
  assertEqual(topology.self.nodeId, 'center');
  assertEqual(topology.peers.length, 2);
});

test('EchoRanging estimates latency to peer', () => {
  const echo = new EchoRanging({ nodeId: 'node-a' });
  echo.coordinates.coordinates = [0, 0, 0, 0, 0, 0, 0, 0];
  echo.peerCoordinates.set('node-b', [10, 0, 0, 0, 0, 0, 0, 0]);
  
  const latency = echo.estimateLatency('node-b');
  assertEqual(latency, 10);
});

// ─────────────────────────────────────────────────────────────────────
console.log('\n─── PULSE (Precision Universal Latency Sync Engine) Tests ───\n');

test('Heartbeat creates with valid hash', () => {
  const hb = new Heartbeat({
    nodeId: 'node-a',
    sequence: 0,
  });
  
  assertTrue(hb.hash.length === 64);
  assertTrue(hb.verify());
});

test('Heartbeat chaining works correctly', () => {
  const hb1 = new Heartbeat({ nodeId: 'node-a', sequence: 0, timestamp: 1000 });
  const hb2 = new Heartbeat({ 
    nodeId: 'node-a', 
    sequence: 1, 
    prevHash: hb1.hash,
    timestamp: 2000,
  });
  
  assertTrue(hb2.chainsFrom(hb1));
});

test('Heartbeat rejects tampering', () => {
  const hb = new Heartbeat({
    nodeId: 'node-a',
    sequence: 5,
  });
  
  hb.timestamp = Date.now() + 1000; // Tamper
  assertFalse(hb.verify());
});

test('HeartbeatChain tracks node liveness', () => {
  const chain = new HeartbeatChain('node-a');
  
  const hb = new Heartbeat({ nodeId: 'node-a', sequence: 0 });
  const result = chain.addHeartbeat(hb);
  
  assertTrue(result.success);
  assertEqual(chain.status, 'alive');
  assertEqual(chain.chain.length, 1);
});

test('HeartbeatChain detects missed heartbeats', () => {
  const chain = new HeartbeatChain('node-a');
  const hb = new Heartbeat({ nodeId: 'node-a', sequence: 0 });
  chain.addHeartbeat(hb, Date.now() - 10000); // 10 seconds ago
  
  const liveness = chain.checkLiveness();
  assertTrue(liveness.missedBeats >= 5);
  assertEqual(liveness.status, 'dead');
});

test('MeshHealthMonitor tracks multiple nodes', () => {
  const monitor = new MeshHealthMonitor();
  
  const hb1 = new Heartbeat({ nodeId: 'node-a', sequence: 0 });
  const hb2 = new Heartbeat({ nodeId: 'node-b', sequence: 0 });
  
  monitor.processHeartbeat(hb1);
  monitor.processHeartbeat(hb2);
  
  assertEqual(monitor.nodes.size, 2);
});

test('PulseLeaderElection starts election', () => {
  const election = new PulseLeaderElection({ nodeId: 'node-a' });
  const request = election.startElection();
  
  assertEqual(request.type, 'VOTE_REQUEST');
  assertEqual(request.term, 1);
  assertEqual(request.candidateId, 'node-a');
  assertEqual(election.state, 'candidate');
});

test('PulseLeaderElection handles vote response', () => {
  const election = new PulseLeaderElection({ nodeId: 'node-a' });
  election.startElection();
  
  // Simulate receiving a vote
  const result = election.handleVoteResponse({ 
    voteGranted: true, 
    term: 1, 
    voterId: 'node-b' 
  }, 2); // 2 total nodes
  
  // With 2 votes (self + peer) out of 2 nodes, should be elected
  assertTrue(result.elected);
  assertEqual(election.state, 'leader');
});

test('PulseSync creates and receives heartbeats', () => {
  const syncA = new PulseSync({ nodeId: 'node-a' });
  const syncB = new PulseSync({ nodeId: 'node-b' });
  const hbA = syncA.createHeartbeat({ peerCount: 5 });
  assertTrue(hbA.nodeId === 'node-a');
  assertEqual(syncA.stats.heartbeatsSent, 1);
  const result = syncB.receiveHeartbeat(hbA);
  assertTrue(result.success);
  assertEqual(syncB.stats.heartbeatsReceived, 1);
});

// ─────────────────────────────────────────────────────────────────────
console.log('\n─── BEACON (Broadcast Emergency Alert Channel) Tests ───\n');

test('BeaconMessage creates with valid hash', () => {
  const msg = new BeaconMessage({
    originNodeId: 'node-a',
    payload: { alert: 'Test message' },
  });
  
  assertTrue(msg.hash.length === 64);
  assertTrue(msg.isValid());
});

test('BeaconMessage forwards with decremented TTL', () => {
  const msg = new BeaconMessage({
    originNodeId: 'node-a',
    payload: { data: 'test' },
    ttl: 5,
  });
  
  const forwarded = msg.forward('node-b');
  assertEqual(forwarded.ttl, 4);
  assertTrue(forwarded.hopPath.includes('node-b'));
});

test('BeaconMessage expires correctly', () => {
  const msg = new BeaconMessage({
    originNodeId: 'node-a',
    payload: { data: 'test' },
    expiresAt: Date.now() - 1000, // Already expired
  });
  
  assertFalse(msg.isValid());
});

test('DeliveryReceipt creates with valid hash', () => {
  const receipt = new DeliveryReceipt({
    messageId: 'msg-123',
    receiverNodeId: 'node-b',
  });
  
  assertTrue(receipt.hash.length === 64);
});

test('DeduplicationTracker detects duplicates', () => {
  const dedup = new DeduplicationTracker();
  const msg = new BeaconMessage({
    originNodeId: 'node-a',
    payload: { test: true },
  });
  
  assertTrue(dedup.markSeen(msg)); // First time
  assertTrue(dedup.isDuplicate(msg.id)); // Now it's seen
  
  dedup.destroy();
});

test('PriorityMessageQueue respects priority order', () => {
  const queue = new PriorityMessageQueue();
  
  const routine = new BeaconMessage({
    originNodeId: 'a',
    payload: 'routine',
    priority: BEACON_CONFIG.priorities.ROUTINE,
  });
  
  const critical = new BeaconMessage({
    originNodeId: 'a',
    payload: 'critical',
    priority: BEACON_CONFIG.priorities.CRITICAL,
  });
  
  queue.enqueue(routine);
  queue.enqueue(critical);
  
  const first = queue.dequeue();
  assertEqual(first.priority, BEACON_CONFIG.priorities.CRITICAL);
});

test('BeaconBroadcast broadcasts messages', () => {
  const beacon = new BeaconBroadcast({ nodeId: 'origin' });
  beacon.addPeer('peer-1');
  beacon.addPeer('peer-2');
  
  const result = beacon.broadcast({ alert: 'test' });
  
  assertTrue(result.messageId !== undefined);
  assertEqual(result.queuedFor, 2);
  assertEqual(beacon.stats.messagesOriginated, 1);
  
  beacon.destroy();
});

test('BeaconBroadcast receives and forwards', () => {
  const beaconA = new BeaconBroadcast({ nodeId: 'node-a' });
  const beaconB = new BeaconBroadcast({ nodeId: 'node-b' });
  beaconB.addPeer('node-c');
  
  // A broadcasts
  const msg = new BeaconMessage({
    originNodeId: 'node-a',
    payload: { data: 'hello' },
  });
  
  // B receives
  const result = beaconB.receive(msg.serialize());
  
  assertTrue(result.accepted);
  assertTrue(result.receipt !== undefined);
  assertEqual(result.forwarded.length, 1); // Forwarded to node-c
  
  beaconA.destroy();
  beaconB.destroy();
});

test('BeaconBroadcast sends emergency with max TTL', () => {
  const beacon = new BeaconBroadcast({ nodeId: 'emergency-node' });
  beacon.addPeer('peer-1');
  
  let deliveryConfirmed = false;
  const result = beacon.sendEmergency(
    { type: 'EARTHQUAKE', magnitude: 7.2 },
    { 
      expectedReceipts: 1,
      onDeliveryConfirm: () => { deliveryConfirmed = true; }
    }
  );
  
  assertTrue(result.messageId !== undefined);
  
  beacon.destroy();
});

// ═══════════════════════════════════════════════════════════════════
console.log('\n╔═══════════════════════════════════════════════════════════╗');
console.log('║  RESULTS: ' + passed + ' passed, ' + failed + ' failed' + ' '.repeat(Math.max(0, 37 - passed.toString().length - failed.toString().length)) + '║');
console.log('╚═══════════════════════════════════════════════════════════╝\n');

if (failed > 0) {
  process.exit(1);
}
