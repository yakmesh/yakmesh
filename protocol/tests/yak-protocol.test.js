/**
 * YAK:// Protocol Integration Tests
 * Tests for: Bookmarks, URL Resolution, Protocol Configuration
 * 
 * NOTE: DOKOCertBinding and DOKOTransfer are tested extensively in
 * security/tests/doko-identity.test.js (60 tests). This file focuses
 * on protocol-specific integration.
 * 
 * @module protocol/tests/yak-protocol.test.js
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';

import YakProtocolHandler, {
  BookmarkManager,
  getBookmarkManager,
  RemoteBookmarkSync,
  getRemoteBookmarkSync,
  parseYakUrl,
  httpToYak,
  yakToHttp,
  PROTOCOL,
  BUILTIN_ROUTES,
} from '../yak-protocol.js';

import {
  DOKOCertBinding,
  DOKOTransfer,
} from '../../security/doko-identity.js';

// ============================================================
// BOOKMARK MANAGER TESTS
// ============================================================

describe('BookmarkManager', () => {
  let bookmarkManager;
  
  beforeEach(() => {
    // Create isolated instance for testing
    bookmarkManager = new BookmarkManager({ dataDir: './data/test-bookmarks' });
  });
  
  afterEach(() => {
    // Clean up test bookmarks
    const all = bookmarkManager.list();
    for (const name of Object.keys(all)) {
      bookmarkManager.remove(name);
    }
  });
  
  describe('Basic Operations', () => {
    it('should add a bookmark', () => {
      const result = bookmarkManager.add('testsite', '/site/test');
      assert.strictEqual(result, true);
      assert.strictEqual(bookmarkManager.has('testsite'), true);
    });
    
    it('should normalize bookmark names to lowercase', () => {
      bookmarkManager.add('TestSite', '/site/test');
      assert.strictEqual(bookmarkManager.has('testsite'), true);
      assert.strictEqual(bookmarkManager.has('TESTSITE'), true);
    });
    
    it('should get bookmark target', () => {
      // Use a non-builtin name (docs is a builtin route)
      bookmarkManager.add('mydocs', '/site/docs');
      const target = bookmarkManager.get('mydocs');
      assert.strictEqual(target, '/site/docs');
    });
    
    it('should remove a bookmark', () => {
      bookmarkManager.add('temp', '/temp');
      bookmarkManager.remove('temp');
      assert.strictEqual(bookmarkManager.has('temp'), false);
    });
    
    it('should list all bookmarks', () => {
      bookmarkManager.add('one', '/one');
      bookmarkManager.add('two', '/two');
      const list = bookmarkManager.list();
      assert.strictEqual(Object.keys(list).length, 2);
    });
    
    it('should reject builtins as bookmark names', () => {
      const result = bookmarkManager.add('dashboard', '/custom');
      assert.strictEqual(result, false);
    });
  });
  
  describe('Path Normalization', () => {
    it('should normalize paths without leading slash', () => {
      bookmarkManager.add('test', 'site/test');
      assert.strictEqual(bookmarkManager.get('test'), '/site/test');
    });
    
    it('should preserve paths with leading slash', () => {
      bookmarkManager.add('test', '/already/slashed');
      assert.strictEqual(bookmarkManager.get('test'), '/already/slashed');
    });
    
    it('should handle site/ prefix correctly', () => {
      bookmarkManager.add('mysite', 'site');
      assert.strictEqual(bookmarkManager.get('mysite'), '/site');
    });
    
    it('should handle content/ prefix correctly', () => {
      bookmarkManager.add('file', 'content/abc123');
      assert.strictEqual(bookmarkManager.get('file'), '/content/abc123');
    });
  });
});

// ============================================================
// URL RESOLUTION TESTS
// ============================================================

describe('YAK:// URL Parsing', () => {
  describe('Builtin Routes', () => {
    it('should resolve yak://dashboard to builtin', () => {
      const result = parseYakUrl('yak://dashboard');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'dashboard');
    });
    
    it('should resolve yak://metrics to builtin', () => {
      const result = parseYakUrl('yak://metrics');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'metrics');
    });
    
    it('should resolve yak://site to builtin', () => {
      const result = parseYakUrl('yak://site');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'site');
    });
    
    it('should handle subpaths in builtins', () => {
      const result = parseYakUrl('yak://site/docs/api');
      assert.strictEqual(result.type, 'builtin');
      assert.ok(result.path.includes('/docs/api'));
    });
  });
  
  describe('Content Hash Resolution', () => {
    it('should resolve SHA3-256 content hashes', () => {
      const hash = 'a'.repeat(64);
      const result = parseYakUrl(`yak://${hash}`);
      assert.strictEqual(result.type, 'content');
      assert.strictEqual(result.hash, hash);
    });
    
    it('should handle content subpaths', () => {
      const hash = 'b'.repeat(64);
      const result = parseYakUrl(`yak://${hash}/index.html`);
      assert.strictEqual(result.type, 'content');
      assert.ok(result.path.includes('/index.html'));
    });
    
    it('should reject invalid hashes', () => {
      const result = parseYakUrl('yak://notahash123');
      assert.strictEqual(result.type, 'unknown');
    });
    
    it('should reject short hashes', () => {
      const shortHash = 'a'.repeat(32);
      const result = parseYakUrl(`yak://${shortHash}`);
      assert.strictEqual(result.type, 'unknown');
    });
  });
  
  describe('iO Name Resolution', () => {
    it('should resolve valid 3-word iO names', () => {
      // Valid iO name from QUANTUM_WORDLIST
      const result = parseYakUrl('yak://qubit-lattice-prism');
      assert.strictEqual(result.type, 'io-content');
      assert.strictEqual(result.ioName, 'qubit-lattice-prism');
    });
    
    it('should handle iO name subpaths', () => {
      const result = parseYakUrl('yak://photon-cipher-node/vacation-photos');
      assert.strictEqual(result.type, 'io-content');
      assert.strictEqual(result.ioName, 'photon-cipher-node');
      assert.ok(result.path.includes('/vacation-photos'));
    });
    
    it('should reject invalid iO names (wrong word count)', () => {
      const result = parseYakUrl('yak://qubit-lattice');  // Only 2 words
      assert.strictEqual(result.type, 'unknown');
    });
    
    it('should reject invalid iO names (not in wordlist)', () => {
      const result = parseYakUrl('yak://apple-banana-cherry');  // Not quantum words
      assert.strictEqual(result.type, 'unknown');
    });
    
    it('should be case-insensitive for iO names', () => {
      const result = parseYakUrl('yak://QUBIT-LATTICE-PRISM');
      assert.strictEqual(result.type, 'io-content');
      assert.strictEqual(result.ioName, 'qubit-lattice-prism');
    });
  });
  
  describe('HTTP to YAK Conversion', () => {
    it('should convert HTTP site URLs to yak://', () => {
      const result = httpToYak('http://localhost:3000/site/example');
      assert.strictEqual(result, 'yak://site/example');
    });
    
    it('should convert HTTP dashboard URL to yak://', () => {
      const result = httpToYak('http://localhost:3000/dashboard');
      assert.strictEqual(result, 'yak://dashboard');
    });
    
    it('should handle URLs with query strings', () => {
      const result = httpToYak('http://localhost:3000/site/page?tab=1');
      assert.ok(result.startsWith('yak://site/'));
    });
  });
  
  describe('YAK to HTTP Conversion', () => {
    it('should convert yak://site to HTTP', () => {
      const result = yakToHttp('yak://site/example', 3000);
      assert.strictEqual(result, 'http://localhost:3000/site//example');
    });
    
    it('should convert yak://dashboard to HTTP', () => {
      const result = yakToHttp('yak://dashboard', 3000);
      assert.strictEqual(result, 'http://localhost:3000/dashboard');
    });
  });
  
  describe('Empty and Edge Cases', () => {
    it('should handle empty yak:// URL', () => {
      const result = parseYakUrl('yak://');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'dashboard');
    });
    
    it('should handle y:// shorthand', () => {
      const result = parseYakUrl('y://dashboard');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'dashboard');
    });
    
    it('should handle case insensitive routes', () => {
      const result = parseYakUrl('yak://DASHBOARD');
      assert.strictEqual(result.type, 'builtin');
      assert.strictEqual(result.route, 'dashboard');
    });
  });
});

// ============================================================
// REMOTE BOOKMARK SYNC TESTS (v2.2.0)
// ============================================================

describe('RemoteBookmarkSync', () => {
  let remoteSync;
  let localBookmarks;
  
  beforeEach(() => {
    // Create isolated instances for testing
    localBookmarks = new BookmarkManager({ dataDir: './data/test-remote' });
    remoteSync = new RemoteBookmarkSync({
      nodeId: 'test-node-' + Date.now(),
      localBookmarks,
      dataDir: './data/test-remote',  // Use separate dir to avoid polluting main data
    });
  });
  
  afterEach(() => {
    // Clean up test bookmarks
    const all = localBookmarks.list();
    for (const name of Object.keys(all)) {
      localBookmarks.remove(name);
    }
    // Clear subscriptions
    for (const nodeId of remoteSync.getSubscriptions()) {
      remoteSync.unsubscribe(nodeId);
    }
  });
  
  describe('Initialization', () => {
    it('should initialize with empty subscriptions', () => {
      // Note: publishedLists may have persisted state from previous runs
      assert.strictEqual(remoteSync.subscriptions.size, 0);
      assert.strictEqual(remoteSync.remoteBookmarks.size, 0);
    });
    
    it('should have correct message type', () => {
      assert.strictEqual(remoteSync.MESSAGE_TYPE, 'bookmark-sync');
    });
    
    it('should link to local bookmark manager', () => {
      assert.strictEqual(remoteSync.localBookmarks, localBookmarks);
    });
  });
  
  describe('Subscriptions', () => {
    it('should subscribe to a node', () => {
      const result = remoteSync.subscribe('node-abc123');
      assert.strictEqual(result, true);
      assert.ok(remoteSync.subscriptions.has('node-abc123'));
    });
    
    it('should not subscribe to self', () => {
      const result = remoteSync.subscribe(remoteSync.nodeId);
      assert.strictEqual(result, false);
    });
    
    it('should unsubscribe from a node', () => {
      remoteSync.subscribe('node-xyz789');
      assert.ok(remoteSync.subscriptions.has('node-xyz789'));
      
      const result = remoteSync.unsubscribe('node-xyz789');
      assert.strictEqual(result, true);
      assert.strictEqual(remoteSync.subscriptions.has('node-xyz789'), false);
    });
    
    it('should return false when unsubscribing from non-subscribed node', () => {
      const result = remoteSync.unsubscribe('non-existent-node');
      assert.strictEqual(result, false);
    });
    
    it('should list subscriptions', () => {
      remoteSync.subscribe('node-1');
      remoteSync.subscribe('node-2');
      
      const subs = remoteSync.getSubscriptions();
      assert.deepStrictEqual(subs.sort(), ['node-1', 'node-2'].sort());
    });
  });
  
  describe('Remote Bookmark Lookup', () => {
    it('should return null for non-existent remote bookmark', () => {
      const result = remoteSync.getRemote('nonexistent');
      assert.strictEqual(result, null);
    });
    
    it('should list remote bookmarks (empty initially)', () => {
      const list = remoteSync.listRemote();
      assert.deepStrictEqual(list, []);
    });
  });
  
  describe('Publishing', () => {
    it('should track published lists locally', () => {
      // Add some local bookmarks first
      localBookmarks.add('docs', '/site/docs');
      localBookmarks.add('api', '/api/v1');
      
      // Can't actually broadcast without network, but we can track intention
      remoteSync.publishedLists['default'] = {
        bookmarks: localBookmarks.list(),
        publishedAt: Date.now(),
        count: 2,
      };
      remoteSync._save();
      
      const published = remoteSync.getPublished();
      assert.ok(published['default']);
      assert.strictEqual(published['default'].count, 2);
    });
  });
  
  describe('Status', () => {
    it('should report status correctly', () => {
      remoteSync.subscribe('node-test');
      
      const status = remoteSync.getStatus();
      assert.strictEqual(status.subscriptions, 1);
      assert.strictEqual(status.remoteBookmarks, 0);
      assert.strictEqual(status.totalRemoteItems, 0);
    });
  });
});

describe('getRemoteBookmarkSync', () => {
  it('should be a function', () => {
    assert.strictEqual(typeof getRemoteBookmarkSync, 'function');
  });
  
  it('should return RemoteBookmarkSync instance', () => {
    const sync = getRemoteBookmarkSync();
    assert.ok(sync);
    assert.ok(sync.subscriptions !== undefined);
    assert.ok(sync.remoteBookmarks !== undefined);
  });
});

// ============================================================
// DOKO CLASSES EXISTENCE TESTS (Integration Check)
// Classes are tested in detail in security/tests/doko-identity.test.js
// ============================================================

describe('DOKO Classes Integration', () => {
  describe('DOKOCertBinding', () => {
    it('should export computeFingerprint static method', () => {
      assert.strictEqual(typeof DOKOCertBinding.computeFingerprint, 'function');
    });
    
    it('should export createBinding static method', () => {
      assert.strictEqual(typeof DOKOCertBinding.createBinding, 'function');
    });
    
    it('should export verifyBinding static method', () => {
      assert.strictEqual(typeof DOKOCertBinding.verifyBinding, 'function');
    });
    
    it('should export addBinding static method', () => {
      assert.strictEqual(typeof DOKOCertBinding.addBinding, 'function');
    });
  });
  
  describe('DOKOTransfer', () => {
    it('should export createRequest static method', () => {
      assert.strictEqual(typeof DOKOTransfer.createRequest, 'function');
    });
    
    it('should export authorize static method', () => {
      assert.strictEqual(typeof DOKOTransfer.authorize, 'function');
    });
    
    it('should export complete static method', () => {
      assert.strictEqual(typeof DOKOTransfer.complete, 'function');
    });
    
    it('should export reject static method', () => {
      assert.strictEqual(typeof DOKOTransfer.reject, 'function');
    });
    
    it('should export cancel static method', () => {
      assert.strictEqual(typeof DOKOTransfer.cancel, 'function');
    });
    
    it('should export STATES constant', () => {
      assert.ok(DOKOTransfer.STATES);
      assert.ok(DOKOTransfer.STATES.PENDING);
      assert.ok(DOKOTransfer.STATES.AUTHORIZED);
      assert.ok(DOKOTransfer.STATES.COMPLETED);
    });
    
    it('should export TYPES constant', () => {
      assert.ok(DOKOTransfer.TYPES);
      assert.ok(DOKOTransfer.TYPES.DOMAIN);
      assert.ok(DOKOTransfer.TYPES.WEBSITE);
      assert.ok(DOKOTransfer.TYPES.ASSET);
    });
  });
});

// ============================================================
// PROTOCOL CONFIGURATION TESTS
// ============================================================

describe('Protocol Configuration', () => {
  it('should export correct protocol config', () => {
    assert.ok(PROTOCOL);
    assert.strictEqual(PROTOCOL.scheme, 'yak');
    assert.ok(PROTOCOL.name.includes('Yakmesh'));
  });
  
  it('should define builtin routes', () => {
    assert.ok(BUILTIN_ROUTES);
    assert.ok(BUILTIN_ROUTES.dashboard);
    assert.ok(BUILTIN_ROUTES.content);
    assert.ok(BUILTIN_ROUTES.site);
  });
  
  it('should have all expected builtin routes', () => {
    const expectedRoutes = ['dashboard', 'site', 'content', 'node', 'peers', 'metrics', 'health', 'gossip'];
    for (const route of expectedRoutes) {
      assert.ok(BUILTIN_ROUTES[route], `Missing builtin route: ${route}`);
    }
  });
  
  it('should have YakProtocolHandler class', () => {
    assert.ok(YakProtocolHandler);
    assert.strictEqual(typeof YakProtocolHandler, 'function');
  });
  
  it('should have getBookmarkManager function', () => {
    assert.ok(getBookmarkManager);
    assert.strictEqual(typeof getBookmarkManager, 'function');
    const manager = getBookmarkManager();
    assert.ok(manager);
  });
});

// ============================================================
// RUN TESTS
// ============================================================

console.log('\n╔═══════════════════════════════════════════════════════════╗');
console.log('║     YAK:// PROTOCOL INTEGRATION TEST SUITE v2.2.0        ║');
console.log('╚═══════════════════════════════════════════════════════════╝\n');
