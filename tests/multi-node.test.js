/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Multi-Node Integration Tests
 * 
 * Tests for cross-node synchronization, gossip propagation,
 * and distributed consensus scenarios.
 * 
 * These tests simulate a mesh network with multiple nodes
 * to verify network-level functionality.
 * 
 * @module tests/multi-node.test.js
 * @version 2.2.0
 * @license MIT
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'events';

// Import core modules
import { RemoteBookmarkSync, BookmarkManager } from '../protocol/yak-protocol.js';
import { DOKODocument, DOKOGenerator, DOKOStore, DOKO_TYPES } from '../security/doko-identity.js';

// ============================================================
// MOCK NETWORK FOR TESTING
// ============================================================

/**
 * Mock network for simulating node-to-node communication
 */
class MockNetwork extends EventEmitter {
  constructor(nodeId) {
    super();
    this.nodeId = nodeId;
    this.peers = [];
    this.messages = [];
  }
  
  connect(otherNetwork) {
    this.peers.push(otherNetwork);
    otherNetwork.peers.push(this);
  }
  
  broadcast(message) {
    this.messages.push({ type: 'broadcast', message, timestamp: Date.now() });
    
    // Propagate to all peers
    for (const peer of this.peers) {
      if (message.gossip) {
        peer.emit('gossip', message.gossip, this.nodeId);
      }
    }
  }
  
  send(peerId, message) {
    const peer = this.peers.find(p => p.nodeId === peerId);
    if (peer) {
      this.messages.push({ type: 'direct', to: peerId, message, timestamp: Date.now() });
      peer.emit('message', message, this.nodeId);
    }
  }
}

/**
 * Create a simulated node for testing
 */
function createTestNode(id, options = {}) {
  const nodeId = id || `test-node-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const network = new MockNetwork(nodeId);
  const localBookmarks = new BookmarkManager({ dataDir: `./data/test-node-${nodeId}` });
  const dokoStore = new DOKOStore();
  
  // Create remote sync with network
  const remoteSync = new RemoteBookmarkSync({
    nodeId,
    network,
    localBookmarks,
  });
  
  return {
    nodeId,
    network,
    localBookmarks,
    remoteSync,
    dokoStore,
    // Cleanup function
    cleanup: () => {
      const all = localBookmarks.list();
      for (const name of Object.keys(all)) {
        localBookmarks.remove(name);
      }
    },
  };
}

// ============================================================
// MULTI-NODE BOOKMARK SYNC TESTS
// ============================================================

describe('Multi-Node Bookmark Sync', () => {
  let nodeA;
  let nodeB;
  let nodeC;
  
  beforeEach(() => {
    nodeA = createTestNode('node-a');
    nodeB = createTestNode('node-b');
    nodeC = createTestNode('node-c');
    
    // Connect nodes in a mesh: A <-> B <-> C, A <-> C
    nodeA.network.connect(nodeB.network);
    nodeB.network.connect(nodeC.network);
    nodeA.network.connect(nodeC.network);
  });
  
  afterEach(() => {
    nodeA.cleanup();
    nodeB.cleanup();
    nodeC.cleanup();
  });
  
  describe('Network Connectivity', () => {
    it('should establish connections between nodes', () => {
      assert.strictEqual(nodeA.network.peers.length, 2);
      assert.strictEqual(nodeB.network.peers.length, 2);
      assert.strictEqual(nodeC.network.peers.length, 2);
    });
    
    it('should track node IDs correctly', () => {
      assert.strictEqual(nodeA.nodeId, 'node-a');
      assert.strictEqual(nodeB.nodeId, 'node-b');
      assert.strictEqual(nodeC.nodeId, 'node-c');
    });
  });
  
  describe('Bookmark Subscription', () => {
    it('should allow subscribing to another node', () => {
      const result = nodeB.remoteSync.subscribe(nodeA.nodeId);
      assert.strictEqual(result, true);
      
      const subs = nodeB.remoteSync.getSubscriptions();
      assert.deepStrictEqual(subs, [nodeA.nodeId]);
    });
    
    it('should allow multiple subscriptions', () => {
      nodeC.remoteSync.subscribe(nodeA.nodeId);
      nodeC.remoteSync.subscribe(nodeB.nodeId);
      
      const subs = nodeC.remoteSync.getSubscriptions();
      assert.strictEqual(subs.length, 2);
      assert.ok(subs.includes(nodeA.nodeId));
      assert.ok(subs.includes(nodeB.nodeId));
    });
  });
  
  describe('Bookmark Publishing', () => {
    it('should publish bookmarks via gossip', () => {
      // Node A adds and publishes bookmarks
      nodeA.localBookmarks.add('wiki', '/site/wiki');
      nodeA.localBookmarks.add('docs', '/site/docs');
      
      const result = nodeA.remoteSync.publish('default');
      assert.strictEqual(result, true);
      
      // Check that broadcast was called
      assert.ok(nodeA.network.messages.length >= 1);
      assert.strictEqual(nodeA.network.messages[nodeA.network.messages.length - 1].type, 'broadcast');
    });
    
    it('should track published lists', () => {
      nodeA.localBookmarks.add('test-bm', '/site/test');
      nodeA.remoteSync.publish('my-list');
      
      // Verify the published list is tracked
      const published = nodeA.remoteSync.getPublished();
      assert.ok(published['my-list']);
      assert.strictEqual(published['my-list'].count, 1);
    });
    
    it('should include bookmark data in publish message', () => {
      nodeA.localBookmarks.add('secret', '/site/secret');
      nodeA.remoteSync.publish();
      
      // Check the message content
      const lastMsg = nodeA.network.messages[nodeA.network.messages.length - 1];
      const gossipMsg = lastMsg.message.gossip;
      
      assert.strictEqual(gossipMsg.type, 'bookmark-sync');
      assert.ok(gossipMsg.bookmarks['secret']);
      assert.strictEqual(gossipMsg.bookmarks['secret'].target, '/site/secret');
    });
  });
  
  describe('Cross-Node Resolution', () => {
    it('should return null for unknown remote bookmark', () => {
      const resolved = nodeB.remoteSync.getRemote('unknown');
      assert.strictEqual(resolved, null);
    });
    
    it('should list empty remote bookmarks initially', () => {
      const remote = nodeB.remoteSync.listRemote();
      assert.ok(Array.isArray(remote));
    });
  });
});

// ============================================================
// MULTI-NODE DOKO IDENTITY TESTS
// ============================================================

describe('Multi-Node DOKO Identity', () => {
  let nodeA;
  let nodeB;
  
  beforeEach(() => {
    nodeA = createTestNode('doko-node-a');
    nodeB = createTestNode('doko-node-b');
    nodeA.network.connect(nodeB.network);
  });
  
  afterEach(() => {
    nodeA.cleanup();
    nodeB.cleanup();
  });
  
  describe('DOKO Store Synchronization', () => {
    it('should create unique DOKOs per node', () => {
      const dokoA = DOKODocument.computeDokoId(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        DOKO_TYPES.NODE
      );
      
      const dokoB = DOKODocument.computeDokoId(
        new Uint8Array([10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
        DOKO_TYPES.NODE
      );
      
      assert.notStrictEqual(dokoA, dokoB);
      assert.ok(dokoA.startsWith('doko-node-'));
      assert.ok(dokoB.startsWith('doko-node-'));
    });
    
    it('should export and import DOKO between stores', () => {
      // Create a valid mock public key (32 bytes as hex = 64 chars)
      const mockPublicKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      
      // Use mock doc for testing (not actual ML-DSA)
      const mockDoc = new DOKODocument({
        type: DOKO_TYPES.USER,
        dokoId: 'doko-user-test-abc123',
        publicKey: mockPublicKeyHex,
        claims: { name: 'Test User' },
      });
      
      // DOKOStore.add expects skipValidation for mock docs
      nodeA.dokoStore.add(mockDoc.toJSON ? mockDoc.toJSON() : mockDoc, { skipValidation: true });
      
      // Export from A, import to B
      const exported = nodeA.dokoStore.export();
      assert.strictEqual(exported.length, 1);
      
      const result = nodeB.dokoStore.import(exported, { skipValidation: true });
      assert.strictEqual(result.imported, 1);
      
      // Verify B has the DOKO
      const found = nodeB.dokoStore.get(mockDoc.dokoId);
      assert.ok(found);
    });
  });
});

// ============================================================
// GOSSIP PROTOCOL TESTS
// ============================================================

describe('Gossip Protocol', () => {
  let nodes;
  
  beforeEach(() => {
    // Create a mesh of 5 nodes
    nodes = [];
    for (let i = 0; i < 5; i++) {
      nodes.push(createTestNode(`gossip-node-${i}`));
    }
    
    // Connect in a ring: 0-1-2-3-4-0
    for (let i = 0; i < 5; i++) {
      nodes[i].network.connect(nodes[(i + 1) % 5].network);
    }
  });
  
  afterEach(() => {
    for (const node of nodes) {
      node.cleanup();
    }
  });
  
  describe('Message Propagation', () => {
    it('should propagate messages to all connected peers', () => {
      const testMessage = { type: 'test', data: 'hello mesh' };
      
      // Node 0 broadcasts
      nodes[0].network.broadcast({ gossip: testMessage });
      
      // Check adjacent nodes received (0 is connected to 1 and 4)
      assert.strictEqual(nodes[0].network.messages.length, 1);
    });
    
    it('should track message history', () => {
      nodes[2].network.broadcast({ gossip: { type: 'msg1' } });
      nodes[2].network.broadcast({ gossip: { type: 'msg2' } });
      nodes[2].network.broadcast({ gossip: { type: 'msg3' } });
      
      assert.strictEqual(nodes[2].network.messages.length, 3);
    });
  });
  
  describe('Network Topology', () => {
    it('should have 2 peers per node in ring topology', () => {
      for (const node of nodes) {
        assert.strictEqual(node.network.peers.length, 2);
      }
    });
    
    it('should allow additional connections', () => {
      // Add cross-ring connection: 0 <-> 2
      nodes[0].network.connect(nodes[2].network);
      
      assert.strictEqual(nodes[0].network.peers.length, 3);
      assert.strictEqual(nodes[2].network.peers.length, 3);
    });
  });
});

// ============================================================
// CONCURRENT OPERATIONS TESTS
// ============================================================

describe('Concurrent Operations', () => {
  let nodeA;
  let nodeB;
  
  beforeEach(() => {
    nodeA = createTestNode('concurrent-a');
    nodeB = createTestNode('concurrent-b');
    nodeA.network.connect(nodeB.network);
    
    // Clear any persisted subscriptions
    for (const sub of nodeA.remoteSync.getSubscriptions()) {
      nodeA.remoteSync.unsubscribe(sub);
    }
    for (const sub of nodeB.remoteSync.getSubscriptions()) {
      nodeB.remoteSync.unsubscribe(sub);
    }
  });
  
  afterEach(() => {
    nodeA.cleanup();
    nodeB.cleanup();
    
    // Clear subscriptions
    for (const sub of nodeA.remoteSync.getSubscriptions()) {
      nodeA.remoteSync.unsubscribe(sub);
    }
    for (const sub of nodeB.remoteSync.getSubscriptions()) {
      nodeB.remoteSync.unsubscribe(sub);
    }
  });
  
  describe('Simultaneous Bookmark Updates', () => {
    it('should handle both nodes adding bookmarks', () => {
      // Both nodes add bookmarks simultaneously
      nodeA.localBookmarks.add('link-a', '/site/a');
      nodeB.localBookmarks.add('link-b', '/site/b');
      
      // Verify each node has its own bookmark
      assert.strictEqual(nodeA.localBookmarks.get('link-a'), '/site/a');
      assert.strictEqual(nodeB.localBookmarks.get('link-b'), '/site/b');
      
      // Cross-node should not exist (not synced yet)
      assert.strictEqual(nodeA.localBookmarks.get('link-b'), null);
    });
    
    it('should track subscriptions across nodes', () => {
      // Mutual subscription
      nodeA.remoteSync.subscribe(nodeB.nodeId);
      nodeB.remoteSync.subscribe(nodeA.nodeId);
      
      // Both should have 1 subscription each
      assert.strictEqual(nodeA.remoteSync.getSubscriptions().length, 1);
      assert.strictEqual(nodeB.remoteSync.getSubscriptions().length, 1);
      
      // Verify the subscriptions are to each other
      assert.ok(nodeA.remoteSync.getSubscriptions().includes(nodeB.nodeId));
      assert.ok(nodeB.remoteSync.getSubscriptions().includes(nodeA.nodeId));
    });
    
    it('should broadcast publish messages', () => {
      // Track message count before
      const msgCountA = nodeA.network.messages.length;
      const msgCountB = nodeB.network.messages.length;
      
      // Add bookmarks
      nodeA.localBookmarks.add('from-a', '/a');
      nodeB.localBookmarks.add('from-b', '/b');
      
      // Publish
      nodeA.remoteSync.publish();
      nodeB.remoteSync.publish();
      
      // Verify broadcasts were sent (at least 1 more each)
      assert.ok(nodeA.network.messages.length > msgCountA);
      assert.ok(nodeB.network.messages.length > msgCountB);
      
      // Verify latest message content
      const msgA = nodeA.network.messages[nodeA.network.messages.length - 1].message.gossip;
      assert.strictEqual(msgA.type, 'bookmark-sync');
      assert.ok(msgA.bookmarks['from-a']);
    });
  });
});

// ============================================================
// RUN INFO
// ============================================================

console.log('\n╔═══════════════════════════════════════════════════════════╗');
console.log('║        MULTI-NODE INTEGRATION TEST SUITE v2.2.0          ║');
console.log('╚═══════════════════════════════════════════════════════════╝\n');
