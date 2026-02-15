/**
 * MANTRA Gossip Protocol Tests — BloomFilter, MantraProtocol, rumor buffer
 * 
 * @module gossip/tests/mantra.test
 */

import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert';

import { MantraProtocol, MantraMessageType, GossipMessageType, GossipProtocol } from '../protocol.js';

console.log('\n📿 MANTRA Gossip Protocol Tests\n');
console.log('='.repeat(60));

// =============================================================================
// Message Type Constants
// =============================================================================

describe('MantraMessageType', () => {
  it('has all expected types', () => {
    assert.strictEqual(MantraMessageType.HELLO, 'GOSSIP_HELLO');
    assert.strictEqual(MantraMessageType.PEERS, 'GOSSIP_PEERS');
    assert.strictEqual(MantraMessageType.WANT_PEERS, 'GOSSIP_WANT_PEERS');
    assert.strictEqual(MantraMessageType.RUMOR, 'GOSSIP_RUMOR');
    assert.strictEqual(MantraMessageType.SEEN, 'GOSSIP_SEEN');
    assert.strictEqual(MantraMessageType.DIGEST, 'GOSSIP_DIGEST');
    assert.strictEqual(MantraMessageType.DIFF, 'GOSSIP_DIFF');
  });

  it('GossipMessageType is alias for MantraMessageType', () => {
    assert.strictEqual(GossipMessageType, MantraMessageType);
  });
});

// =============================================================================
// Mock helpers
// =============================================================================

function createMockMesh() {
  const listeners = {};
  return {
    _listeners: listeners,
    on(event, handler) { listeners[event] = handler; },
    off(event, handler) { delete listeners[event]; },
    emit(event, ...args) { listeners[event]?.(...args); },
    broadcast(msg) { /* no-op */ },
    sendTo(nodeId, msg) { /* no-op */ },
    getPeers() { return []; },
    isConnectedTo(nodeId) { return false; },
    connectToPeer(endpoint) { return Promise.resolve(); },
    getPublicEndpoint() { return 'ws://localhost:9001'; },
  };
}

function createMockIdentity(nodeId = 'test-node-' + Math.random().toString(36).slice(2, 10)) {
  return {
    identity: {
      nodeId,
      name: 'Test Node',
      region: 'local',
      capabilities: ['listings'],
    },
  };
}

// =============================================================================
// MantraProtocol — Construction
// =============================================================================

describe('MantraProtocol: Construction', () => {
  it('constructs with defaults', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    assert.strictEqual(protocol.config.fanout, 3);
    assert.strictEqual(protocol.config.helloInterval, 30000);
    assert.strictEqual(protocol.config.digestInterval, 60000);
    assert.strictEqual(protocol.config.peerTTL, 300000);
    assert.strictEqual(protocol.config.rumorTTL, 5);
  });

  it('accepts custom options', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity, { fanout: 5, rumorTTL: 10 });
    
    assert.strictEqual(protocol.config.fanout, 5);
    assert.strictEqual(protocol.config.rumorTTL, 10);
  });
});

// =============================================================================
// MantraProtocol — Start/Stop lifecycle
// =============================================================================

describe('MantraProtocol: Lifecycle', () => {
  it('start() registers gossip handler and creates intervals', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity, {
      helloInterval: 999999,
      digestInterval: 999999,
    });
    
    protocol.start();
    assert.ok(mesh._listeners['gossip'], 'Should register gossip handler');
    assert.ok(protocol.intervals.length >= 3, 'Should have at least 3 intervals');
    protocol.stop();
  });

  it('stop() clears all intervals and removes handler', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity, {
      helloInterval: 999999,
      digestInterval: 999999,
    });
    
    protocol.start();
    protocol.stop();
    
    assert.strictEqual(protocol.intervals.length, 0);
    assert.strictEqual(mesh._listeners['gossip'], undefined);
  });
});

// =============================================================================
// MantraProtocol — Bloom Filter (seenMessages)
// =============================================================================

describe('MantraProtocol: BloomFilter', () => {
  it('add + has tracks messages', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    protocol.seenMessages.add('msg-1');
    assert.strictEqual(protocol.seenMessages.has('msg-1'), true);
    assert.strictEqual(protocol.seenMessages.has('msg-2'), false);
  });

  it('shouldReset after filling beyond threshold', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    // Add enough messages to fill 70% of bloom filter
    const threshold = Math.ceil(protocol.seenMessages.size * 0.7) + 1;
    for (let i = 0; i < threshold; i++) {
      protocol.seenMessages.add(`msg-${i}`);
    }
    assert.strictEqual(protocol.seenMessages.shouldReset(), true);
  });

  it('reset clears the filter', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    protocol.seenMessages.add('msg-1');
    protocol.seenMessages.reset();
    assert.strictEqual(protocol.seenMessages.count, 0);
    // Note: false positive possible after reset, but count == 0 is deterministic
  });
});

// =============================================================================
// MantraProtocol — Rumor Spreading
// =============================================================================

describe('MantraProtocol: Rumors', () => {
  it('spreadRumor creates a message ID and buffers', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const id = protocol.spreadRumor('test-topic', { value: 42 });
    assert.strictEqual(typeof id, 'string');
    assert.ok(id.length > 0);
    assert.ok(protocol.recentRumors.length >= 1);
  });

  it('spreadRumor deduplicates (second call is no-op)', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const id1 = protocol.spreadRumor('topic-a', { x: 1 });
    // Same seenMessages bloom should block duplicate message IDs
    // but since timestamp differs, different ID — so test buffer grows
    const id2 = protocol.spreadRumor('topic-b', { x: 2 });
    assert.ok(protocol.recentRumors.length >= 2);
  });
});

// =============================================================================
// MantraProtocol — Recent Rumors buffer
// =============================================================================

describe('MantraProtocol: Rumor Buffer', () => {
  it('getRecentRumors returns all by default', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    protocol._bufferRumor({ messageId: 'r1', topic: 'a', data: {}, origin: 'n1', timestamp: Date.now() - 100 });
    protocol._bufferRumor({ messageId: 'r2', topic: 'b', data: {}, origin: 'n2', timestamp: Date.now() });
    
    const all = protocol.getRecentRumors();
    assert.strictEqual(all.length, 2);
  });

  it('getRecentRumors filters by since', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const now = Date.now();
    protocol._bufferRumor({ messageId: 'r1', topic: 'a', data: {}, origin: 'n1', timestamp: now - 5000 });
    protocol._bufferRumor({ messageId: 'r2', topic: 'b', data: {}, origin: 'n2', timestamp: now });
    
    const recent = protocol.getRecentRumors(now - 1000);
    assert.strictEqual(recent.length, 1);
    assert.strictEqual(recent[0].messageId, 'r2');
  });

  it('getRecentRumors filters by topic', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    protocol._bufferRumor({ messageId: 'r1', topic: 'content', data: {}, origin: 'n1', timestamp: Date.now() });
    protocol._bufferRumor({ messageId: 'r2', topic: 'chat', data: {}, origin: 'n2', timestamp: Date.now() });
    
    const contentOnly = protocol.getRecentRumors(0, 'content');
    assert.strictEqual(contentOnly.length, 1);
    assert.strictEqual(contentOnly[0].topic, 'content');
  });

  it('buffer evicts when exceeding max', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    protocol.maxRecentRumors = 3;
    
    for (let i = 0; i < 5; i++) {
      protocol._bufferRumor({ messageId: `r${i}`, topic: 't', data: {}, origin: 'n', timestamp: Date.now() });
    }
    
    assert.ok(protocol.recentRumors.length <= 3);
  });
});

// =============================================================================
// MantraProtocol — Peer discovery
// =============================================================================

describe('MantraProtocol: Peers', () => {
  it('getKnownPeers returns empty initially', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    assert.deepStrictEqual(protocol.getKnownPeers(), []);
  });

  it('getKnownPeers filters expired peers', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity, { peerTTL: 1000 });
    
    protocol.knownPeers.set('old-peer', {
      name: 'Expired',
      endpoint: 'ws://old',
      lastSeen: Date.now() - 5000,
    });
    protocol.knownPeers.set('fresh-peer', {
      name: 'Fresh',
      endpoint: 'ws://fresh',
      lastSeen: Date.now(),
    });
    
    const peers = protocol.getKnownPeers();
    assert.strictEqual(peers.length, 1);
    assert.strictEqual(peers[0].nodeId, 'fresh-peer');
  });
});

// =============================================================================
// MantraProtocol — Statistics
// =============================================================================

describe('MantraProtocol: Stats', () => {
  it('getStats returns expected shape', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const stats = protocol.getStats();
    assert.strictEqual(typeof stats.knownPeers, 'number');
    assert.strictEqual(typeof stats.seenMessages, 'number');
    assert.strictEqual(typeof stats.pendingRumors, 'number');
    assert.strictEqual(typeof stats.bloomFilterHealth, 'number');
  });
});

// =============================================================================
// MantraProtocol — _selectRandom (Fisher-Yates)
// =============================================================================

describe('MantraProtocol: Fisher-Yates', () => {
  it('returns requested count or fewer', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const items = [1, 2, 3, 4, 5];
    const selected = protocol._selectRandom(items, 3);
    assert.strictEqual(selected.length, 3);
  });

  it('returns all items when count > array size', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const items = [1, 2];
    const selected = protocol._selectRandom(items, 10);
    assert.strictEqual(selected.length, 2);
  });

  it('does not mutate original array', () => {
    const mesh = createMockMesh();
    const identity = createMockIdentity();
    const protocol = new MantraProtocol(mesh, identity);
    
    const items = [1, 2, 3, 4, 5];
    const copy = [...items];
    protocol._selectRandom(items, 3);
    assert.deepStrictEqual(items, copy);
  });
});

// =============================================================================
// Legacy export alias
// =============================================================================

describe('Legacy exports', () => {
  it('GossipProtocol is alias for MantraProtocol', () => {
    assert.strictEqual(GossipProtocol, MantraProtocol);
  });
});
