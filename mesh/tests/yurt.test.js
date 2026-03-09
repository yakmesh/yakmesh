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
 * YURT Protocol Tests
 * 
 * Tests for YAK Unified Room Tags - room discovery and direct access
 */

import { describe, it, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from 'crypto';

import {
  YurtEntry,
  YurtLink,
  YurtDirectory,
  YurtGossip,
  YurtHub,
  YURT_CONFIG,
} from '../yurt.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function generateKeyPair() {
  const seed = randomBytes(32);
  return ml_dsa65.keygen(seed);
}

function createTestEntry(overrides = {}) {
  return new YurtEntry({
    bundleId: overrides.bundleId || `bundle-${randomBytes(8).toString('hex')}`,
    hostNodeId: overrides.hostNodeId || `node-${randomBytes(8).toString('hex')}`,
    hostEndpoint: overrides.hostEndpoint || 'testnode.example.com:8787',
    name: overrides.name || 'Test Room',
    description: overrides.description || 'A test room for testing',
    visibility: overrides.visibility || YURT_CONFIG.visibility.PUBLIC,
    tags: overrides.tags || ['test', 'example'],
    ...overrides,
  });
}

function createMockMesh() {
  const listeners = new Map();
  const peers = [];
  const sentMessages = [];
  
  return {
    on(event, handler) {
      if (!listeners.has(event)) {
        listeners.set(event, []);
      }
      listeners.get(event).push(handler);
    },
    emit(event, data) {
      const handlers = listeners.get(event) || [];
      for (const handler of handlers) {
        handler(data);
      }
    },
    send(peerId, message) {
      sentMessages.push({ peerId, message });
    },
    getPeers() {
      return peers;
    },
    addPeer(id) {
      peers.push({ id });
    },
    getSentMessages() {
      return sentMessages;
    },
    clearSentMessages() {
      sentMessages.length = 0;
    },
  };
}

function createMockIdentity() {
  const keyPair = generateKeyPair();
  return {
    identity: {
      nodeId: `node-${randomBytes(8).toString('hex')}`,
      dokoId: `doko-${randomBytes(8).toString('hex')}`,
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// YURT ENTRY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('YurtEntry', () => {
  describe('constructor', () => {
    it('creates entry with required fields', () => {
      const entry = new YurtEntry({
        bundleId: 'test-bundle',
        hostNodeId: 'test-node',
        hostEndpoint: 'test.example.com:8787',
      });
      
      assert.strictEqual(entry.bundleId, 'test-bundle');
      assert.strictEqual(entry.hostNodeId, 'test-node');
      assert.strictEqual(entry.hostEndpoint, 'test.example.com:8787');
      assert.ok(entry.entryId);
    });
    
    it('sets default values', () => {
      const entry = createTestEntry();
      
      assert.strictEqual(entry.visibility, YURT_CONFIG.visibility.PUBLIC);
      assert.ok(entry.createdAt > 0);
      assert.ok(entry.updatedAt > 0);
      assert.ok(entry.lastSeen > 0);
    });
    
    it('computes deterministic entry ID', () => {
      const entry1 = new YurtEntry({
        bundleId: 'same-bundle',
        hostNodeId: 'same-node',
        hostEndpoint: 'test.com:8787',
      });
      
      const entry2 = new YurtEntry({
        bundleId: 'same-bundle',
        hostNodeId: 'same-node',
        hostEndpoint: 'different.com:9999',
      });
      
      assert.strictEqual(entry1.entryId, entry2.entryId);
    });
  });
  
  describe('validation', () => {
    it('validates required fields', () => {
      const entry = new YurtEntry({});
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.includes('bundleId required'));
      assert.ok(result.errors.includes('hostNodeId required'));
      assert.ok(result.errors.includes('hostEndpoint required'));
    });
    
    it('validates name length', () => {
      const entry = createTestEntry({ name: 'x'.repeat(100) });
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('name exceeds')));
    });
    
    it('validates description length', () => {
      const entry = createTestEntry({ description: 'x'.repeat(300) });
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('description exceeds')));
    });
    
    it('validates tag count', () => {
      const entry = createTestEntry({ 
        tags: Array.from({ length: 15 }, (_, i) => `tag${i}`),
      });
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('too many tags')));
    });
    
    it('validates tag length', () => {
      const entry = createTestEntry({ 
        tags: ['x'.repeat(30)],
      });
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('tag') && e.includes('exceeds')));
    });
    
    it('validates visibility', () => {
      const entry = createTestEntry({ visibility: 'invalid' });
      const result = entry.validate();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('invalid visibility')));
    });
    
    it('passes valid entry', () => {
      const entry = createTestEntry();
      const result = entry.validate();
      
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.errors.length, 0);
    });
  });
  
  describe('signing and verification', () => {
    it('signs entry with secret key', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      
      entry.sign(keyPair.secretKey);
      
      assert.ok(entry.signature);
      assert.strictEqual(typeof entry.signature, 'string');
    });
    
    it('verifies valid signature', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      
      entry.sign(keyPair.secretKey);
      const valid = entry.verify(keyPair.publicKey);
      
      assert.strictEqual(valid, true);
    });
    
    it('rejects invalid signature (wrong key)', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const entry = createTestEntry();
      
      entry.sign(keyPair1.secretKey);
      const valid = entry.verify(keyPair2.publicKey);
      
      assert.strictEqual(valid, false);
    });
    
    it('rejects tampered entry', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      
      entry.sign(keyPair.secretKey);
      entry.name = 'Tampered Name';
      
      const valid = entry.verify(keyPair.publicKey);
      assert.strictEqual(valid, false);
    });
    
    it('returns false for unsigned entry', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      
      const valid = entry.verify(keyPair.publicKey);
      assert.strictEqual(valid, false);
    });
  });
  
  describe('expiration', () => {
    it('detects expired entry', () => {
      const entry = createTestEntry();
      entry.lastSeen = Date.now() - YURT_CONFIG.maxEntryAge - 1000;
      
      assert.strictEqual(entry.isExpired(), true);
    });
    
    it('returns false for fresh entry', () => {
      const entry = createTestEntry();
      
      assert.strictEqual(entry.isExpired(), false);
    });
  });
  
  describe('URI generation', () => {
    it('generates yak:// URI', () => {
      const entry = new YurtEntry({
        bundleId: 'my-room',
        hostNodeId: 'node1',
        hostEndpoint: 'example.com:8787',
      });
      
      const uri = entry.toUri();
      
      assert.ok(uri.startsWith('yak://'));
      assert.ok(uri.includes('example.com'));
      assert.ok(uri.includes('my-room'));
    });
    
    it('generates invite URI with attestation', () => {
      const entry = createTestEntry({ hostEndpoint: 'example.com:8787' });
      const attestation = { token: 'abc123' };
      
      const uri = entry.toInviteUri(attestation);
      
      assert.ok(uri.includes('invite='));
    });
  });
  
  describe('serialization', () => {
    it('exports to JSON', () => {
      const entry = createTestEntry();
      const json = entry.toJSON();
      
      assert.strictEqual(json.bundleId, entry.bundleId);
      assert.strictEqual(json.name, entry.name);
      assert.ok(json.entryId);
    });
    
    it('imports from JSON', () => {
      const original = createTestEntry();
      const json = original.toJSON();
      
      const restored = YurtEntry.fromJSON(json);
      
      assert.strictEqual(restored.bundleId, original.bundleId);
      assert.strictEqual(restored.name, original.name);
      assert.strictEqual(restored.entryId, original.entryId);
    });
    
    it('preserves signature through serialization', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      entry.sign(keyPair.secretKey);
      
      const restored = YurtEntry.fromJSON(entry.toJSON());
      
      assert.strictEqual(restored.verify(keyPair.publicKey), true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// YURT LINK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('YurtLink', () => {
  describe('parse', () => {
    it('parses basic yak:// URI', () => {
      const result = YurtLink.parse('yak://example.com/my-bundle');
      
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.scheme, 'yak');
      assert.strictEqual(result.host, 'example.com');
      assert.strictEqual(result.bundleId, 'my-bundle');
      assert.strictEqual(result.port, YURT_CONFIG.defaultPort);
    });
    
    it('parses URI with explicit port', () => {
      const result = YurtLink.parse('yak://example.com:9999/test-room');
      
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.port, 9999);
      assert.strictEqual(result.bundleId, 'test-room');
    });
    
    it('parses URI with invite parameter', () => {
      const invite = { token: 'abc123', expiry: 12345 };
      const encoded = encodeURIComponent(JSON.stringify(invite));
      const uri = `yak://example.com/room?invite=${encoded}`;
      
      const result = YurtLink.parse(uri);
      
      assert.strictEqual(result.valid, true);
      assert.deepStrictEqual(result.invite, invite);
    });
    
    it('handles invalid URI gracefully', () => {
      const result = YurtLink.parse('not a uri');
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.error);
    });
    
    it('constructs endpoint from host:port', () => {
      const result = YurtLink.parse('yak://qrl.example.com:8787/qrl-official');
      
      assert.strictEqual(result.endpoint, 'qrl.example.com:8787');
    });
  });
  
  describe('create', () => {
    it('creates basic URI', () => {
      const uri = YurtLink.create('example.com', 'my-room');
      
      assert.strictEqual(uri, 'yak://example.com/my-room');
    });
    
    it('creates URI with custom port', () => {
      const uri = YurtLink.create('example.com', 'my-room', { port: 9999 });
      
      assert.strictEqual(uri, 'yak://example.com:9999/my-room');
    });
    
    it('creates invite URI', () => {
      const uri = YurtLink.create('example.com', 'room', {
        invite: { token: 'xyz' },
      });
      
      assert.ok(uri.includes('invite='));
      const parsed = YurtLink.parse(uri);
      assert.deepStrictEqual(parsed.invite, { token: 'xyz' });
    });
  });
  
  describe('isValid', () => {
    it('returns true for valid URI', () => {
      assert.strictEqual(YurtLink.isValid('yak://example.com/room'), true);
    });
    
    it('returns false for non-yak scheme', () => {
      assert.strictEqual(YurtLink.isValid('https://example.com/room'), false);
    });
    
    it('returns false for invalid input', () => {
      assert.strictEqual(YurtLink.isValid(null), false);
      assert.strictEqual(YurtLink.isValid(''), false);
      assert.strictEqual(YurtLink.isValid(123), false);
    });
  });
  
  describe('toHttpsGateway', () => {
    it('converts to HTTPS gateway URL', () => {
      const uri = 'yak://node.example.com:8787/my-room';
      const https = YurtLink.toHttpsGateway(uri);
      
      assert.ok(https.startsWith('https://yak.to/join/'));
      assert.ok(https.includes('node.example.com:8787'));
      assert.ok(https.includes('my-room'));
    });
    
    it('uses custom gateway URL', () => {
      const uri = 'yak://node.example.com/room';
      const https = YurtLink.toHttpsGateway(uri, 'https://custom.gateway');
      
      assert.ok(https.startsWith('https://custom.gateway/join/'));
    });
    
    it('returns null for invalid URI', () => {
      assert.strictEqual(YurtLink.toHttpsGateway('invalid'), null);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// YURT DIRECTORY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('YurtDirectory', () => {
  let directory;
  
  beforeEach(() => {
    directory = new YurtDirectory();
  });
  
  describe('add', () => {
    it('adds valid entry', () => {
      const entry = createTestEntry();
      const result = directory.add(entry, false);
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.entryId, entry.entryId);
    });
    
    it('rejects invalid entry', () => {
      const entry = new YurtEntry({}); // Missing required fields
      const result = directory.add(entry, false);
      
      assert.strictEqual(result.success, false);
      assert.ok(result.errors.length > 0);
    });
    
    it('updates existing entry', () => {
      const entry1 = createTestEntry({ bundleId: 'same', hostNodeId: 'node' });
      const entry2 = createTestEntry({ bundleId: 'same', hostNodeId: 'node', name: 'Updated' });
      
      directory.add(entry1, false);
      directory.add(entry2, false);
      
      const stored = directory.get(entry1.entryId);
      assert.strictEqual(stored.name, 'Updated');
      assert.strictEqual(directory.entries.size, 1);
    });
    
    it('verifies signature when required', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const entry = createTestEntry();
      entry.sign(keyPair1.secretKey);
      
      // Lookup returns wrong key
      const result = directory.add(entry, true, () => keyPair2.publicKey);
      
      assert.strictEqual(result.success, false);
      assert.ok(result.errors.some(e => e.includes('signature')));
    });
    
    it('accepts valid signature', () => {
      const keyPair = generateKeyPair();
      const entry = createTestEntry();
      entry.sign(keyPair.secretKey);
      
      const result = directory.add(entry, true, () => keyPair.publicKey);
      
      assert.strictEqual(result.success, true);
    });
  });
  
  describe('remove', () => {
    it('removes existing entry', () => {
      const entry = createTestEntry();
      directory.add(entry, false);
      
      const removed = directory.remove(entry.entryId);
      
      assert.strictEqual(removed, true);
      assert.strictEqual(directory.get(entry.entryId), null);
    });
    
    it('returns false for non-existent entry', () => {
      assert.strictEqual(directory.remove('non-existent'), false);
    });
  });
  
  describe('get and getByBundle', () => {
    it('retrieves entry by ID', () => {
      const entry = createTestEntry();
      directory.add(entry, false);
      
      const result = directory.get(entry.entryId);
      
      assert.strictEqual(result.bundleId, entry.bundleId);
    });
    
    it('retrieves entry by bundle ID', () => {
      const entry = createTestEntry({ bundleId: 'unique-bundle' });
      directory.add(entry, false);
      
      const result = directory.getByBundle('unique-bundle');
      
      assert.strictEqual(result.name, entry.name);
    });
    
    it('returns null for missing entry', () => {
      assert.strictEqual(directory.get('missing'), null);
      assert.strictEqual(directory.getByBundle('missing'), null);
    });
  });
  
  describe('search', () => {
    beforeEach(() => {
      directory.add(createTestEntry({ 
        name: 'QRL Official',
        description: 'Official QRL community',
        tags: ['qrl', 'crypto', 'official'],
        visibility: YURT_CONFIG.visibility.PUBLIC,
      }), false);
      
      directory.add(createTestEntry({ 
        name: 'Yakmesh Dev',
        description: 'Developer discussion',
        tags: ['dev', 'coding'],
        visibility: YURT_CONFIG.visibility.PUBLIC,
      }), false);
      
      directory.add(createTestEntry({ 
        name: 'Private Room',
        description: 'Secret club',
        visibility: YURT_CONFIG.visibility.INVITE_ONLY,
      }), false);
    });
    
    it('searches by text query', () => {
      const results = directory.search({ query: 'QRL' });
      
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].name, 'QRL Official');
    });
    
    it('searches in description', () => {
      const results = directory.search({ query: 'community' });
      
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].name, 'QRL Official');
    });
    
    it('searches by tags', () => {
      const results = directory.search({ tags: ['dev'] });
      
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].name, 'Yakmesh Dev');
    });
    
    it('filters by visibility', () => {
      const results = directory.search({ visibility: YURT_CONFIG.visibility.INVITE_ONLY });
      
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].name, 'Private Room');
    });
    
    it('applies limit', () => {
      const results = directory.search({ limit: 1 });
      
      assert.strictEqual(results.length, 1);
    });
    
    it('returns all matching entries', () => {
      const results = directory.search({ query: '' });
      
      assert.strictEqual(results.length, 3);
    });
  });
  
  describe('listPublic', () => {
    it('returns only public entries', () => {
      directory.add(createTestEntry({ 
        visibility: YURT_CONFIG.visibility.PUBLIC,
        name: 'Public',
      }), false);
      directory.add(createTestEntry({ 
        visibility: YURT_CONFIG.visibility.INVITE_ONLY,
        name: 'Private',
      }), false);
      
      const results = directory.listPublic();
      
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].name, 'Public');
    });
  });
  
  describe('own listings', () => {
    it('tracks own listings', () => {
      const entry = createTestEntry();
      directory.add(entry, false);
      directory.markAsOwn(entry.entryId);
      
      const own = directory.getOwnListings();
      
      assert.strictEqual(own.length, 1);
      assert.strictEqual(own[0].entryId, entry.entryId);
    });
  });
  
  describe('cleanup', () => {
    it('removes expired entries', () => {
      const fresh = createTestEntry({ name: 'Fresh' });
      const expired = createTestEntry({ name: 'Expired' });
      expired.lastSeen = Date.now() - YURT_CONFIG.maxEntryAge - 1000;
      
      directory.add(fresh, false);
      directory.add(expired, false);
      
      const cleaned = directory.cleanup();
      
      assert.strictEqual(cleaned, 1);
      assert.strictEqual(directory.entries.size, 1);
    });
    
    it('preserves own listings even if expired', () => {
      const entry = createTestEntry();
      entry.lastSeen = Date.now() - YURT_CONFIG.maxEntryAge - 1000;
      
      directory.add(entry, false);
      directory.markAsOwn(entry.entryId);
      
      const cleaned = directory.cleanup();
      
      assert.strictEqual(cleaned, 0);
      assert.strictEqual(directory.entries.size, 1);
    });
  });
  
  describe('indexes', () => {
    it('indexes by host', () => {
      directory.add(createTestEntry({ hostNodeId: 'host1', name: 'Room1' }), false);
      directory.add(createTestEntry({ hostNodeId: 'host1', name: 'Room2' }), false);
      directory.add(createTestEntry({ hostNodeId: 'host2', name: 'Room3' }), false);
      
      const byHost1 = directory.getByHost('host1');
      
      assert.strictEqual(byHost1.length, 2);
    });
    
    it('indexes by tag', () => {
      directory.add(createTestEntry({ tags: ['qrl', 'crypto'] }), false);
      directory.add(createTestEntry({ tags: ['qrl'] }), false);
      directory.add(createTestEntry({ tags: ['eth'] }), false);
      
      const byQrl = directory.getByTag('qrl');
      
      assert.strictEqual(byQrl.length, 2);
    });
  });
  
  describe('persistence', () => {
    it('exports and imports', () => {
      const entry1 = createTestEntry({ name: 'Room 1' });
      const entry2 = createTestEntry({ name: 'Room 2' });
      
      directory.add(entry1, false);
      directory.add(entry2, false);
      directory.markAsOwn(entry1.entryId);
      
      const exported = directory.export();
      
      const newDirectory = new YurtDirectory();
      newDirectory.import(exported);
      
      assert.strictEqual(newDirectory.entries.size, 2);
      assert.strictEqual(newDirectory.ownListings.size, 1);
    });
  });
  
  describe('stats', () => {
    it('tracks statistics', () => {
      const entry = createTestEntry();
      directory.add(entry, false);
      directory.remove(entry.entryId);
      
      const stats = directory.getStats();
      
      assert.strictEqual(stats.entriesAdded, 1);
      assert.strictEqual(stats.entriesRemoved, 1);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// YURT GOSSIP TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('YurtGossip', () => {
  let identity;
  let directory;
  let mesh;
  let gossip;
  
  beforeEach(() => {
    identity = createMockIdentity();
    directory = new YurtDirectory();
    mesh = createMockMesh();
    gossip = new YurtGossip(identity, directory, mesh);
  });
  
  afterEach(() => {
    gossip.stop();
  });
  
  describe('announce', () => {
    it('announces room to network', () => {
      const entry = createTestEntry({
        hostNodeId: identity.identity.nodeId,
      });
      
      mesh.addPeer('peer1');
      const result = gossip.announce(entry);
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(directory.ownListings.has(entry.entryId), true);
    });
    
    it('signs entry with node identity', () => {
      const entry = createTestEntry({
        hostNodeId: identity.identity.nodeId,
      });
      
      gossip.announce(entry);
      
      assert.ok(entry.signature);
      assert.strictEqual(entry.verify(identity.identity.publicKey), true);
    });
    
    it('broadcasts to peers', () => {
      const entry = createTestEntry({
        hostNodeId: identity.identity.nodeId,
      });
      
      mesh.addPeer('peer1');
      mesh.addPeer('peer2');
      gossip.announce(entry);
      
      const sent = mesh.getSentMessages();
      assert.strictEqual(sent.length, 2);
      assert.strictEqual(sent[0].message.type, YURT_CONFIG.messageTypes.ANNOUNCE);
    });
  });
  
  describe('withdraw', () => {
    it('withdraws own listing', () => {
      const entry = createTestEntry({
        hostNodeId: identity.identity.nodeId,
      });
      
      gossip.announce(entry);
      mesh.clearSentMessages();
      
      const result = gossip.withdraw(entry.bundleId);
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(directory.getByBundle(entry.bundleId), null);
    });
    
    it('rejects withdrawing others listings', () => {
      const entry = createTestEntry({
        hostNodeId: 'other-node',
      });
      directory.add(entry, false);
      
      const result = gossip.withdraw(entry.bundleId);
      
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.error, 'NOT_OWN_LISTING');
    });
  });
  
  describe('query', () => {
    it('broadcasts query to network', () => {
      mesh.addPeer('peer1');
      
      const queryId = gossip.query({ query: 'qrl' });
      
      assert.ok(queryId);
      const sent = mesh.getSentMessages();
      assert.strictEqual(sent[0].message.type, YURT_CONFIG.messageTypes.QUERY);
    });
  });
  
  describe('stats', () => {
    it('tracks gossip statistics', () => {
      const stats = gossip.getStats();
      
      assert.strictEqual(stats.gossipsSent, 0);
      assert.strictEqual(stats.gossipsReceived, 0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

describe('Integration Scenarios', () => {
  describe('QRL Official Room Flow', () => {
    it('creates and discovers QRL room', async () => {
      // QRL sets up their node
      const qrlIdentity = createMockIdentity();
      const qrlDirectory = new YurtDirectory();
      
      // Create the official room entry
      const qrlRoom = new YurtEntry({
        bundleId: 'qrl-official',
        hostNodeId: qrlIdentity.identity.nodeId,
        hostEndpoint: 'qrl-node.theqrl.org:8787',
        name: 'QRL Official',
        description: 'Official Quantum Resistant Ledger community chat',
        visibility: YURT_CONFIG.visibility.PUBLIC,
        tags: ['qrl', 'crypto', 'quantum', 'official'],
        memberCount: 500,
      });
      
      // Sign and add to directory
      qrlRoom.sign(qrlIdentity.identity.secretKey);
      qrlDirectory.add(qrlRoom, false);
      qrlDirectory.markAsOwn(qrlRoom.entryId);
      
      // Generate direct link for website
      const joinLink = qrlRoom.toUri();
      assert.strictEqual(joinLink, 'yak://qrl-node.theqrl.org:8787/qrl-official');
      
      // User clicks link from website
      const parsed = YurtLink.parse(joinLink);
      assert.strictEqual(parsed.valid, true);
      assert.strictEqual(parsed.bundleId, 'qrl-official');
      assert.strictEqual(parsed.host, 'qrl-node.theqrl.org');
      
      // User's client can now connect directly
      // (GUMBA proof exchange would happen here)
    });
    
    it('discovers room via gossip', async () => {
      // Two nodes
      const node1Identity = createMockIdentity();
      const node2Identity = createMockIdentity();
      
      const node1Dir = new YurtDirectory();
      const node2Dir = new YurtDirectory();
      
      // Node 1 hosts the room
      const entry = new YurtEntry({
        bundleId: 'test-room',
        hostNodeId: node1Identity.identity.nodeId,
        hostEndpoint: 'node1.example.com:8787',
        name: 'Test Room',
        visibility: YURT_CONFIG.visibility.PUBLIC,
        tags: ['test'],
      });
      entry.sign(node1Identity.identity.secretKey);
      node1Dir.add(entry, false);
      node1Dir.markAsOwn(entry.entryId);
      
      // Simulate gossip - Node1 sends entry to Node2
      const gossipPayload = entry.toJSON();
      
      // Node2 receives and verifies
      const receivedEntry = YurtEntry.fromJSON(gossipPayload);
      const verification = receivedEntry.verify(node1Identity.identity.publicKey);
      assert.strictEqual(verification, true);
      
      // Node2 adds to their directory
      node2Dir.add(receivedEntry, false);
      
      // Node2 can now find it
      const found = node2Dir.search({ query: 'Test Room' });
      assert.strictEqual(found.length, 1);
      assert.strictEqual(found[0].hostEndpoint, 'node1.example.com:8787');
    });
  });
  
  describe('Invite Flow', () => {
    it('creates and parses invite links', () => {
      const entry = createTestEntry({
        hostEndpoint: 'private.example.com:8787',
        visibility: YURT_CONFIG.visibility.INVITE_ONLY,
      });
      
      // Create attestation (would come from GUMBA)
      const attestation = {
        type: 'attestation',
        bundleId: entry.bundleId,
        grantorDokoId: 'grantor-doko-id',
        granteeDokoId: 'new-member-doko-id',
        grantedRole: 'member',
        expiry: Date.now() + 24 * 60 * 60 * 1000,
        signature: 'base64-signature-here',
      };
      
      const inviteUri = entry.toInviteUri(attestation);
      
      // Share invite link
      assert.ok(inviteUri.includes('invite='));
      
      // New member clicks link
      const parsed = YurtLink.parse(inviteUri);
      assert.strictEqual(parsed.valid, true);
      assert.ok(parsed.invite);
      assert.strictEqual(parsed.invite.type, 'attestation');
      assert.strictEqual(parsed.invite.grantedRole, 'member');
    });
  });
  
  describe('Browser Fallback', () => {
    it('provides HTTPS gateway fallback', () => {
      const yakUri = 'yak://mesh.example.com:8787/room-id';
      const httpsUrl = YurtLink.toHttpsGateway(yakUri);
      
      // For browsers without yak:// handler
      assert.ok(httpsUrl.startsWith('https://yak.to/join/'));
      assert.ok(httpsUrl.includes('mesh.example.com'));
      
      // Gateway would redirect to install app or provide web interface
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// RUN TESTS
// ═══════════════════════════════════════════════════════════════════════════════

console.log('YURT Protocol Tests');
console.log('═'.repeat(60));
