/**
 * Tests for TRISULA - Ternary Search Tree
 * 
 * @module mesh/tests/trisula-tree.test
 */

import { describe, it, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import { TrisulaTST, TrisulaPeerRouter } from '../trisula-tree.js';
import { Trit, NEGATIVE, NEUTRAL, POSITIVE } from '../../oracle/tribhuj.js';

// =============================================================================
// Visual Demo
// =============================================================================

console.log('\n🔱 TRISULA - Ternary Search Tree for YAKMESH\n');
console.log('─'.repeat(50));

// Demo basic TST operations
const demo = new TrisulaTST();
const nodeIds = [
  'a1b2c3d4e5f6',
  'a1b2c3d4aaaa',
  'a1b2ffff0000',
  'deadbeef1234',
  'cafebabe5678',
];

console.log('📍 Inserting node IDs:');
nodeIds.forEach((id, i) => {
  demo.insert(id, { name: `Peer ${i + 1}` });
  console.log(`   ${id} → Peer ${i + 1}`);
});

console.log(`\n📊 Tree stats: ${JSON.stringify(demo.stats())}`);

console.log('\n🔍 Prefix search for "a1b2":');
const prefixResults = demo.prefixSearch('a1b2');
prefixResults.forEach(r => console.log(`   ${r.key} → ${r.value.name}`));

console.log('\n🎯 Finding nearest to "a1b2c3d5":');
const nearest = demo.nearest('a1b2c3d5');
console.log(`   ${nearest.key} (comparison: ${nearest.comparison.toString()})`);

console.log('\n─'.repeat(50));

// Demo routing table
console.log('\n🌐 TrisulaPeerRouter Demo:');
const router = new TrisulaPeerRouter();

router.addPeer('a'.repeat(64), { endpoint: 'wss://node-a:8080', lastSeen: Date.now(), latency: 50, linkQuality: new Trit(POSITIVE) });
router.addPeer('b'.repeat(64), { endpoint: 'wss://node-b:8080', lastSeen: Date.now(), latency: 120, linkQuality: new Trit(NEUTRAL) });
router.addPeer('c'.repeat(64), { endpoint: 'wss://node-c:8080', lastSeen: Date.now(), latency: 30, linkQuality: new Trit(POSITIVE) });

console.log(`   Peer count: ${router.size}`);
console.log(`   Best route to 'aaaa...': ${router.findBestRoute('a'.repeat(64))?.endpoint}`);

const target = 'ab'.padEnd(64, '0');
console.log(`   Closest 2 peers to ${target.slice(0, 8)}...:`);
router.findClosestPeers(target, 2).forEach(p => {
  console.log(`      ${p.nodeId.slice(0, 8)}... - ${p.endpoint}`);
});

console.log('\n' + '─'.repeat(50) + '\n');

// =============================================================================
// Tests
// =============================================================================

describe('TRISULA - Ternary Search Tree', () => {

  describe('TrisulaTST Basic Operations', () => {
    let tst;

    beforeEach(() => {
      tst = new TrisulaTST();
    });

    it('should start empty', () => {
      assert.equal(tst.size, 0);
      assert.equal(tst.isEmpty, true);
    });

    it('should insert and search keys', () => {
      tst.insert('hello', 42);
      tst.insert('help', 99);
      
      assert.equal(tst.search('hello'), 42);
      assert.equal(tst.search('help'), 99);
      assert.equal(tst.size, 2);
    });

    it('should return null for missing keys', () => {
      tst.insert('hello', 42);
      assert.equal(tst.search('helloworld'), null);
      assert.equal(tst.search('hell'), null);
      assert.equal(tst.search('xyz'), null);
    });

    it('should update existing keys', () => {
      tst.insert('key', 'value1');
      assert.equal(tst.search('key'), 'value1');
      
      tst.insert('key', 'value2');
      assert.equal(tst.search('key'), 'value2');
      assert.equal(tst.size, 1); // Size unchanged
    });

    it('should check key existence with has()', () => {
      tst.insert('exists', true);
      assert.equal(tst.has('exists'), true);
      assert.equal(tst.has('missing'), false);
    });

    it('should delete keys', () => {
      tst.insert('delete-me', 123);
      assert.equal(tst.has('delete-me'), true);
      
      const deleted = tst.delete('delete-me');
      assert.equal(deleted, true);
      assert.equal(tst.has('delete-me'), false);
      assert.equal(tst.search('delete-me'), null);
    });

    it('should return false when deleting non-existent key', () => {
      assert.equal(tst.delete('ghost'), false);
    });

    it('should throw on empty key', () => {
      assert.throws(() => tst.insert('', 'value'), /Key cannot be empty/);
    });

    it('should support chained inserts', () => {
      const result = tst
        .insert('a', 1)
        .insert('b', 2)
        .insert('c', 3);
      
      assert.equal(result, tst);
      assert.equal(tst.size, 3);
    });
  });

  describe('TrisulaTST Prefix Operations', () => {
    let tst;

    beforeEach(() => {
      tst = new TrisulaTST();
      tst.insert('test', 1);
      tst.insert('testing', 2);
      tst.insert('tester', 3);
      tst.insert('team', 4);
      tst.insert('tea', 5);
      tst.insert('other', 6);
    });

    it('should find all keys with prefix', () => {
      const results = tst.prefixSearch('test');
      const keys = results.map(r => r.key).sort();
      
      assert.deepEqual(keys, ['test', 'tester', 'testing']);
    });

    it('should find keys with short prefix', () => {
      const results = tst.prefixSearch('te');
      assert.equal(results.length, 5); // test, testing, tester, team, tea
    });

    it('should return empty for non-matching prefix', () => {
      const results = tst.prefixSearch('xyz');
      assert.equal(results.length, 0);
    });

    it('should return all keys for empty prefix', () => {
      const results = tst.prefixSearch('');
      assert.equal(results.length, 6);
    });

    it('should find longest prefix of string', () => {
      const result = tst.longestPrefixOf('testing123');
      assert.equal(result.key, 'testing');
      assert.equal(result.value, 2);
    });

    it('should find shorter longest prefix', () => {
      const result = tst.longestPrefixOf('teapot');
      assert.equal(result.key, 'tea');
    });

    it('should return null for no matching prefix', () => {
      const result = tst.longestPrefixOf('xyz');
      assert.equal(result, null);
    });
  });

  describe('TrisulaTST Nearest Neighbor', () => {
    let tst;

    beforeEach(() => {
      tst = new TrisulaTST();
      tst.insert('apple', 1);
      tst.insert('banana', 2);
      tst.insert('cherry', 3);
    });

    it('should return exact match with NEUTRAL comparison', () => {
      const result = tst.nearest('banana');
      assert.equal(result.key, 'banana');
      assert.equal(result.comparison.value, NEUTRAL);
    });

    it('should find nearest when key not found', () => {
      const result = tst.nearest('blueberry');
      assert.ok(result !== null);
      assert.ok(result.key === 'banana' || result.key === 'cherry');
    });

    it('should indicate comparison direction', () => {
      const result = tst.nearest('aaa'); // Before 'apple'
      assert.ok(result !== null);
      assert.equal(result.key, 'apple');
      assert.equal(result.comparison.value, NEGATIVE); // 'aaa' < 'apple'
    });

    it('should return null for empty tree', () => {
      const empty = new TrisulaTST();
      assert.equal(empty.nearest('anything'), null);
    });
  });

  describe('TrisulaTST Iteration', () => {
    let tst;

    beforeEach(() => {
      tst = new TrisulaTST();
      tst.insert('c', 3);
      tst.insert('a', 1);
      tst.insert('b', 2);
    });

    it('should return sorted keys', () => {
      const keys = tst.keys();
      assert.deepEqual(keys, ['a', 'b', 'c']);
    });

    it('should return all values', () => {
      const values = tst.values();
      assert.equal(values.length, 3);
      assert.ok(values.includes(1));
      assert.ok(values.includes(2));
      assert.ok(values.includes(3));
    });

    it('should return sorted entries', () => {
      const entries = tst.entries();
      assert.deepEqual(entries, [
        { key: 'a', value: 1 },
        { key: 'b', value: 2 },
        { key: 'c', value: 3 },
      ]);
    });

    it('should be iterable', () => {
      const collected = [];
      for (const entry of tst) {
        collected.push(entry);
      }
      assert.equal(collected.length, 3);
    });
  });

  describe('TrisulaTST Utility', () => {
    it('should clear the tree', () => {
      const tst = new TrisulaTST();
      tst.insert('a', 1).insert('b', 2);
      
      tst.clear();
      
      assert.equal(tst.size, 0);
      assert.equal(tst.isEmpty, true);
    });

    it('should report stats', () => {
      const tst = new TrisulaTST();
      tst.insert('abc', 1);
      tst.insert('abd', 2);
      tst.insert('xyz', 3);
      
      const stats = tst.stats();
      
      assert.equal(stats.size, 3);
      assert.ok(stats.nodeCount > 0);
      assert.ok(stats.maxDepth > 0);
    });
  });

  describe('TrisulaPeerRouter', () => {
    let router;

    beforeEach(() => {
      router = new TrisulaPeerRouter();
    });

    it('should add and get peers', () => {
      const nodeId = 'a'.repeat(64);
      router.addPeer(nodeId, {
        endpoint: 'wss://test:8080',
        lastSeen: 1000,
        latency: 50,
        linkQuality: new Trit(POSITIVE),
      });

      const peer = router.getPeer(nodeId);
      assert.equal(peer.endpoint, 'wss://test:8080');
      assert.equal(peer.latency, 50);
    });

    it('should remove peers', () => {
      const nodeId = 'b'.repeat(64);
      router.addPeer(nodeId, { endpoint: 'ws://x', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      
      router.removePeer(nodeId);
      
      assert.equal(router.hasPeer(nodeId), false);
    });

    it('should find by prefix', () => {
      router.addPeer('aaaa' + '0'.repeat(60), { endpoint: 'a1', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      router.addPeer('aaab' + '0'.repeat(60), { endpoint: 'a2', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      router.addPeer('bbbb' + '0'.repeat(60), { endpoint: 'b1', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });

      const found = router.findByPrefix('aaa');
      assert.equal(found.length, 2);
    });

    it('should find closest peers using XOR distance', () => {
      router.addPeer('a'.repeat(64), { endpoint: 'a', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      router.addPeer('b'.repeat(64), { endpoint: 'b', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      router.addPeer('c'.repeat(64), { endpoint: 'c', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });

      const closest = router.findClosestPeers('a'.repeat(64), 2);
      assert.equal(closest.length, 2);
      // The first should be exact match
      assert.equal(closest[0].nodeId, 'a'.repeat(64));
    });

    it('should get all peers', () => {
      router.addPeer('a'.repeat(64), { endpoint: 'a', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      router.addPeer('b'.repeat(64), { endpoint: 'b', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });

      const all = router.allPeers();
      assert.equal(all.length, 2);
    });

    it('should report stats', () => {
      router.addPeer('test'.padEnd(64, '0'), { endpoint: 'x', lastSeen: 0, latency: 0, linkQuality: new Trit(NEUTRAL) });
      
      const stats = router.stats();
      assert.equal(stats.peerCount, 1);
      assert.ok(stats.nodeCount > 0);
    });
  });

  describe('TrisulaTST with Hex Node IDs', () => {
    it('should handle 64-char hex node IDs efficiently', () => {
      const tst = new TrisulaTST();
      const ids = [];
      
      // Generate 100 random-ish node IDs
      for (let i = 0; i < 100; i++) {
        const id = i.toString(16).padStart(64, '0');
        ids.push(id);
        tst.insert(id, { index: i });
      }

      // All should be findable
      for (const id of ids) {
        assert.ok(tst.has(id), `Should find ${id}`);
      }

      // Prefix search should work
      const prefixed = tst.prefixSearch('00000000000000000000000000000000000000000000000000000000000000');
      assert.ok(prefixed.length > 0);
    });
  });
});

console.log('\n✅ All TRISULA tests complete!\n');
