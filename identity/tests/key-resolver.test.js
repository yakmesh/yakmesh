/**
 * Tests for KeyResolver — unified public key resolution
 * 
 * @module identity/tests/key-resolver.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { KeyResolver, KEY_SOURCE } from '../key-resolver.js';

describe('KeyResolver', () => {

  describe('Self resolution', () => {
    it('resolves own nodeId', () => {
      const resolver = new KeyResolver({
        identity: {
          identity: {
            nodeId: 'node-abc-123',
            dokoId: 'doko-abc-123',
            publicKey: 'deadbeef',
          },
        },
      });

      assert.strictEqual(resolver.resolve('node-abc-123'), 'deadbeef');
    });

    it('resolves own dokoId', () => {
      const resolver = new KeyResolver({
        identity: {
          identity: {
            nodeId: 'node-abc-123',
            dokoId: 'doko-abc-123',
            publicKey: 'deadbeef',
          },
        },
      });

      assert.strictEqual(resolver.resolve('doko-abc-123'), 'deadbeef');
    });

    it('returns null for unknown id with no sources', () => {
      const resolver = new KeyResolver();
      assert.strictEqual(resolver.resolve('unknown-node'), null);
    });

    it('returns null for null/undefined', () => {
      const resolver = new KeyResolver();
      assert.strictEqual(resolver.resolve(null), null);
      assert.strictEqual(resolver.resolve(undefined), null);
    });
  });

  describe('Registry', () => {
    it('registers and resolves a key', () => {
      const resolver = new KeyResolver();
      resolver.register('node-peer-1', 'aabbcc', KEY_SOURCE.REGISTERED);

      assert.strictEqual(resolver.resolve('node-peer-1'), 'aabbcc');
    });

    it('register overwrites existing entry', () => {
      const resolver = new KeyResolver();
      resolver.register('node-1', 'old-key');
      resolver.register('node-1', 'new-key');

      assert.strictEqual(resolver.resolve('node-1'), 'new-key');
    });

    it('evicts oldest when at capacity', () => {
      const resolver = new KeyResolver({ cacheSize: 3 });
      resolver.register('a', 'key-a');
      resolver.register('b', 'key-b');
      resolver.register('c', 'key-c');
      // Cache full — registering 'd' should evict 'a'
      resolver.register('d', 'key-d');

      assert.strictEqual(resolver.resolve('a'), null);
      assert.strictEqual(resolver.resolve('d'), 'key-d');
    });

    it('ignores null/undefined registration', () => {
      const resolver = new KeyResolver();
      resolver.register(null, 'key');
      resolver.register('id', null);
      assert.strictEqual(resolver.registry.size, 0);
    });
  });

  describe('NamcheGateway resolution', () => {
    it('resolves from DOKO cache via lookupByNodeId', () => {
      const mockNamche = {
        lookupByNodeId: (id) => id === 'node-x' ? { publicKey: 'doko-key-x' } : null,
        lookupByHash: () => null,
      };

      const resolver = new KeyResolver();
      resolver.attachNamche(mockNamche);

      assert.strictEqual(resolver.resolve('node-x'), 'doko-key-x');
    });

    it('resolves from DOKO cache via lookupByHash', () => {
      const mockNamche = {
        lookupByNodeId: () => null,
        lookupByHash: (hash) => hash === 'doko-hash' ? { publicKey: 'hash-key' } : null,
      };

      const resolver = new KeyResolver();
      resolver.attachNamche(mockNamche);

      assert.strictEqual(resolver.resolve('doko-hash'), 'hash-key');
    });

    it('caches DOKO result in registry for fast future lookup', () => {
      let lookupCount = 0;
      const mockNamche = {
        lookupByNodeId: (id) => {
          lookupCount++;
          return id === 'node-y' ? { publicKey: 'cached-key' } : null;
        },
        lookupByHash: () => null,
      };

      const resolver = new KeyResolver();
      resolver.attachNamche(mockNamche);

      resolver.resolve('node-y');
      resolver.resolve('node-y'); // Second call should hit registry
      assert.strictEqual(lookupCount, 1); // Only one DOKO lookup
    });
  });

  describe('Network peer resolution', () => {
    it('resolves from peer map', () => {
      const mockNetwork = {
        peers: new Map([
          ['node-peer', { identity: { publicKey: 'peer-key' } }],
        ]),
      };

      const resolver = new KeyResolver();
      resolver.attachNetwork(mockNetwork);

      assert.strictEqual(resolver.resolve('node-peer'), 'peer-key');
    });

    it('resolves from relay peer keys', () => {
      const mockNetwork = {
        peers: new Map(),
        _relayPeerKeys: new Map([
          ['relay-node', 'relay-key'],
        ]),
      };

      const resolver = new KeyResolver();
      resolver.attachNetwork(mockNetwork);

      assert.strictEqual(resolver.resolve('relay-node'), 'relay-key');
    });
  });

  describe('SHERPA resolution', () => {
    it('resolves from SHERPA registry', () => {
      const mockSherpa = {
        registry: new Map([
          ['sherpa-node', { publicKey: 'sherpa-key' }],
        ]),
      };

      const resolver = new KeyResolver();
      resolver.attachSherpa(mockSherpa);

      assert.strictEqual(resolver.resolve('sherpa-node'), 'sherpa-key');
    });
  });

  describe('Resolution cascade', () => {
    it('self takes priority over registry', () => {
      const resolver = new KeyResolver({
        identity: { identity: { nodeId: 'me', publicKey: 'self-key' } },
      });
      resolver.register('me', 'reg-key');

      assert.strictEqual(resolver.resolve('me'), 'self-key');
    });

    it('registry takes priority over DOKO', () => {
      const resolver = new KeyResolver();
      resolver.register('node-z', 'reg-key');
      resolver.attachNamche({
        lookupByNodeId: () => ({ publicKey: 'doko-key' }),
        lookupByHash: () => null,
      });

      assert.strictEqual(resolver.resolve('node-z'), 'reg-key');
    });
  });

  describe('resolveWithMeta', () => {
    it('returns source metadata for self', () => {
      const resolver = new KeyResolver({
        identity: { identity: { nodeId: 'me', publicKey: 'pk' } },
      });

      const meta = resolver.resolveWithMeta('me');
      assert.strictEqual(meta.source, KEY_SOURCE.SELF);
      assert.strictEqual(meta.publicKey, 'pk');
    });

    it('returns source metadata for registered key', () => {
      const resolver = new KeyResolver();
      resolver.register('x', 'key-x', KEY_SOURCE.PEER);

      const meta = resolver.resolveWithMeta('x');
      assert.strictEqual(meta.source, KEY_SOURCE.PEER);
      assert.strictEqual(meta.publicKey, 'key-x');
    });

    it('returns null for unknown', () => {
      const resolver = new KeyResolver();
      assert.strictEqual(resolver.resolveWithMeta('nope'), null);
    });
  });

  describe('has()', () => {
    it('returns true for known keys', () => {
      const resolver = new KeyResolver();
      resolver.register('known', 'key');
      assert.strictEqual(resolver.has('known'), true);
    });

    it('returns false for unknown keys', () => {
      const resolver = new KeyResolver();
      assert.strictEqual(resolver.has('unknown'), false);
    });
  });

  describe('Statistics', () => {
    it('tracks resolution sources', () => {
      const resolver = new KeyResolver({
        identity: { identity: { nodeId: 'me', publicKey: 'pk' } },
      });
      resolver.register('other', 'ok');

      resolver.resolve('me');
      resolver.resolve('other');
      resolver.resolve('missing');

      const stats = resolver.getStats();
      assert.strictEqual(stats.resolvedSelf, 1);
      assert.strictEqual(stats.resolvedRegistry, 1);
      assert.strictEqual(stats.misses, 1);
    });

    it('reports attachment status', () => {
      const resolver = new KeyResolver();
      const stats = resolver.getStats();
      assert.strictEqual(stats.hasNamche, false);
      assert.strictEqual(stats.hasNetwork, false);
      assert.strictEqual(stats.hasSherpa, false);

      resolver.attachNamche({});
      const stats2 = resolver.getStats();
      assert.strictEqual(stats2.hasNamche, true);
    });
  });
});
