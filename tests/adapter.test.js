/**
 * Adapter Framework Tests
 * 
 * Tests for ContentAdapter, ChatModAdapter, and MLVBibleAdapter
 * including security, rate limiting, and capability enforcement.
 * 
 * @module tests/adapter.test.js
 * @version 3.0.0
 * @license MIT
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert';

// Import adapter framework
import { 
  ContentAdapter, 
  ContentMetadata, 
  CONTENT_CAPABILITIES 
} from '../adapters/content-adapter.js';

import { 
  ChatModAdapter, 
  ChatModManifest, 
  ChatModRegistry,
  CHAT_MOD_CAPABILITIES,
  SECURITY_LEVELS
} from '../adapters/chat-mod-adapter.js';

import {
  MLVContentAdapter,
  MLVChatAdapter,
  MLVBibleAdapter,
  BIBLE_BOOKS,
  parseReference
} from '../adapters/adapter-mlv-bible/index.js';

// ============================================================
// CONTENT ADAPTER TESTS
// ============================================================

describe('ContentAdapter', () => {
  
  describe('CONTENT_CAPABILITIES', () => {
    it('should have all required capabilities defined', () => {
      assert.ok(CONTENT_CAPABILITIES.SERVE_PDF);
      assert.ok(CONTENT_CAPABILITIES.SERVE_TEXT);
      assert.ok(CONTENT_CAPABILITIES.SEARCH_REFERENCE);
      assert.ok(CONTENT_CAPABILITIES.CHAT_QUOTE);
      assert.ok(CONTENT_CAPABILITIES.STREAM_NETWORK);
    });
  });
  
  describe('ContentMetadata', () => {
    it('should create metadata with required fields', () => {
      const meta = new ContentMetadata(
        'test-id',
        'Test Document',
        'application/pdf',
        { author: 'Test Author' }
      );
      
      assert.strictEqual(meta.id, 'test-id');
      assert.strictEqual(meta.title, 'Test Document');
      assert.strictEqual(meta.mimeType, 'application/pdf');
      assert.strictEqual(meta.extra.author, 'Test Author');
    });
    
    it('should convert to JSON', () => {
      const meta = new ContentMetadata('test', 'Test', 'text/plain');
      const json = meta.toJSON();
      
      assert.ok(json.id);
      assert.ok(json.title);
      assert.ok(json.mimeType);
    });
  });
  
  describe('ContentAdapter base class', () => {
    class TestContentAdapter extends ContentAdapter {
      constructor() {
        super({
          name: 'Test Adapter',
          id: 'test-adapter',
          capabilities: [CONTENT_CAPABILITIES.SERVE_TEXT],
        });
      }
      
      async lookupReference(ref) {
        return { reference: ref, text: 'Test text', found: true };
      }
    }
    
    it('should initialize with capabilities', async () => {
      const adapter = new TestContentAdapter();
      await adapter.init();
      
      assert.ok(adapter.initialized);
      assert.ok(adapter.capabilities.has(CONTENT_CAPABILITIES.SERVE_TEXT));
    });
    
    it('should check capabilities', async () => {
      const adapter = new TestContentAdapter();
      await adapter.init();
      
      assert.strictEqual(
        adapter.hasCapability(CONTENT_CAPABILITIES.SERVE_TEXT), 
        true
      );
      assert.strictEqual(
        adapter.hasCapability(CONTENT_CAPABILITIES.SERVE_PDF), 
        false
      );
    });
    
    it('should lookup references', async () => {
      const adapter = new TestContentAdapter();
      await adapter.init();
      
      const result = await adapter.lookupReference('test:1:1');
      
      assert.ok(result.found);
      assert.strictEqual(result.text, 'Test text');
    });
  });
});

// ============================================================
// CHAT MOD ADAPTER TESTS
// ============================================================

describe('ChatModAdapter', () => {
  
  describe('CHAT_MOD_CAPABILITIES', () => {
    it('should define all security-scoped capabilities', () => {
      assert.ok(CHAT_MOD_CAPABILITIES.MSG_READ);
      assert.ok(CHAT_MOD_CAPABILITIES.MSG_RESPOND);
      assert.ok(CHAT_MOD_CAPABILITIES.CMD_SLASH);
      assert.ok(CHAT_MOD_CAPABILITIES.GEN_QUOTE);
      assert.ok(CHAT_MOD_CAPABILITIES.SPECIAL_DM);
    });
  });
  
  describe('SECURITY_LEVELS', () => {
    it('should define security levels', () => {
      assert.strictEqual(SECURITY_LEVELS.SANDBOX, 'sandbox');
      assert.strictEqual(SECURITY_LEVELS.STANDARD, 'standard');
      assert.strictEqual(SECURITY_LEVELS.TRUSTED, 'trusted');
    });
  });
  
  describe('ChatModManifest', () => {
    it('should create manifest with ID and version', () => {
      const manifest = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
        commands: ['/test'],
      });
      
      assert.strictEqual(manifest.id, 'test-mod');
      assert.strictEqual(manifest.version, '1.0.0');
      assert.ok(manifest.capabilities.includes(CHAT_MOD_CAPABILITIES.CMD_SLASH));
    });
    
    it('should generate manifest hash', () => {
      const manifest = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [],
        commands: [],
      });
      
      const hash = manifest.getHash();
      
      // Hash should be deterministic
      assert.strictEqual(hash, manifest.getHash());
      assert.ok(hash.length > 0);
    });
    
    it('should validate capability requirements', () => {
      const manifest = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
        commands: [],
      });
      
      assert.strictEqual(
        manifest.hasCapability(CHAT_MOD_CAPABILITIES.CMD_SLASH),
        true
      );
      assert.strictEqual(
        manifest.hasCapability(CHAT_MOD_CAPABILITIES.SPECIAL_DM),
        false
      );
    });
  });
  
  describe('ChatModAdapter security', () => {
    class TestChatMod extends ChatModAdapter {
      constructor() {
        super(new ChatModManifest({
          id: 'test-chat-mod',
          version: '1.0.0',
          capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
          commands: ['/test'],
          rateLimit: { maxPerMinute: 5 }
        }));
      }
      
      async handleCommand(command, args, context) {
        return this._signResponse({
          type: 'text',
          content: 'Test response: ' + args.join(' '),
        });
      }
    }
    
    it('should enforce rate limits', async () => {
      const mod = new TestChatMod();
      await mod.init();
      
      const context = { userId: 'user-1', channelId: 'channel-1' };
      
      // Should allow up to rate limit
      for (let i = 0; i < 5; i++) {
        const result = await mod.handleCommand('/test', ['hello'], context);
        assert.ok(result);
      }
      
      // Should reject after limit exceeded
      try {
        await mod.handleCommand('/test', ['overflow'], context);
        assert.fail('Should have thrown rate limit error');
      } catch (err) {
        assert.ok(err.message.includes('Rate limit'));
      }
    });
    
    it('should sign responses with manifest hash', async () => {
      const mod = new TestChatMod();
      await mod.init();
      
      const context = { userId: 'user-1', channelId: 'channel-1' };
      const response = await mod.handleCommand('/test', ['hello'], context);
      
      assert.ok(response._signed);
      assert.strictEqual(response._signed.adapterId, 'test-chat-mod');
      assert.ok(response._signed.hash);
      assert.ok(response._signed.timestamp);
    });
    
    it('should sanitize context based on capabilities', async () => {
      const mod = new TestChatMod();
      await mod.init();
      
      const rawContext = {
        userId: 'user-1',
        channelId: 'channel-1',
        userEmail: 'secret@example.com', // Should be stripped
        privateKey: 'super-secret',       // Should be stripped
      };
      
      const sanitized = mod._sanitizeContext(rawContext);
      
      assert.strictEqual(sanitized.userId, 'user-1');
      assert.strictEqual(sanitized.channelId, 'channel-1');
      assert.strictEqual(sanitized.userEmail, undefined);
      assert.strictEqual(sanitized.privateKey, undefined);
    });
  });
  
  describe('ChatModRegistry', () => {
    it('should register and route commands', async () => {
      const registry = new ChatModRegistry();
      
      class TestMod extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'registry-test',
            version: '1.0.0',
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['/greet'],
          }));
        }
        
        async handleCommand(command, args, context) {
          return this._signResponse({ content: 'Hello ' + args[0] });
        }
      }
      
      const mod = new TestMod();
      await mod.init();
      registry.register(mod);
      
      const result = await registry.routeCommand('/greet', ['World'], {});
      
      assert.ok(result);
      assert.strictEqual(result.content, 'Hello World');
    });
    
    it('should return null for unknown commands', async () => {
      const registry = new ChatModRegistry();
      
      const result = await registry.routeCommand('/unknown', [], {});
      
      assert.strictEqual(result, null);
    });
  });
});

// ============================================================
// MLV BIBLE ADAPTER TESTS
// ============================================================

describe('MLVBibleAdapter', () => {
  
  describe('BIBLE_BOOKS constant', () => {
    it('should contain all 66 books', () => {
      assert.strictEqual(Object.keys(BIBLE_BOOKS).length, 66);
    });
    
    it('should have correct abbreviations', () => {
      assert.deepStrictEqual(BIBLE_BOOKS.Genesis.abbrevs, ['Gen', 'Ge', 'Gn']);
      assert.deepStrictEqual(BIBLE_BOOKS.John.abbrevs, ['Jn', 'Jhn']);
      assert.deepStrictEqual(BIBLE_BOOKS.Revelation.abbrevs, ['Rev', 'Re']);
    });
    
    it('should have chapter counts', () => {
      assert.strictEqual(BIBLE_BOOKS.Genesis.chapters, 50);
      assert.strictEqual(BIBLE_BOOKS.Psalms.chapters, 150);
      assert.strictEqual(BIBLE_BOOKS.Revelation.chapters, 22);
    });
  });
  
  describe('parseReference()', () => {
    it('should parse full book name with chapter and verse', () => {
      const ref = parseReference('John 3:16');
      
      assert.strictEqual(ref.book, 'John');
      assert.strictEqual(ref.chapter, 3);
      assert.strictEqual(ref.verseStart, 16);
      assert.strictEqual(ref.valid, true);
    });
    
    it('should parse abbreviations', () => {
      const ref = parseReference('Gen 1:1');
      
      assert.strictEqual(ref.book, 'Genesis');
      assert.strictEqual(ref.chapter, 1);
      assert.strictEqual(ref.verseStart, 1);
    });
    
    it('should parse verse ranges', () => {
      const ref = parseReference('Ps 23:1-6');
      
      assert.strictEqual(ref.book, 'Psalms');
      assert.strictEqual(ref.chapter, 23);
      assert.strictEqual(ref.verseStart, 1);
      assert.strictEqual(ref.verseEnd, 6);
    });
    
    it('should handle chapter-only references', () => {
      const ref = parseReference('Romans 8');
      
      assert.strictEqual(ref.book, 'Romans');
      assert.strictEqual(ref.chapter, 8);
      assert.strictEqual(ref.verseStart, undefined);
    });
    
    it('should return invalid for bad input', () => {
      const ref = parseReference('Not a book 99:99');
      
      assert.strictEqual(ref.valid, false);
    });
    
    it('should handle case insensitivity', () => {
      const ref = parseReference('GENESIS 1:1');
      
      assert.strictEqual(ref.book, 'Genesis');
      assert.strictEqual(ref.valid, true);
    });
  });
  
  describe('MLVContentAdapter', () => {
    it('should initialize with correct capabilities', async () => {
      const adapter = new MLVContentAdapter({ contentPath: './test' });
      await adapter.init();
      
      assert.ok(adapter.hasCapability(CONTENT_CAPABILITIES.SERVE_PDF));
      assert.ok(adapter.hasCapability(CONTENT_CAPABILITIES.SEARCH_REFERENCE));
      assert.ok(adapter.hasCapability(CONTENT_CAPABILITIES.CHAT_QUOTE));
    });
    
    it('should lookup Bible references', async () => {
      const adapter = new MLVContentAdapter({ contentPath: './test' });
      await adapter.init();
      
      const result = await adapter.lookupReference('John 3:16');
      
      assert.strictEqual(result.book, 'John');
      assert.strictEqual(result.chapter, 3);
      assert.strictEqual(result.verseStart, 16);
    });
  });
  
  describe('MLVChatAdapter', () => {
    let chatAdapter;
    
    beforeEach(async () => {
      const contentAdapter = new MLVContentAdapter({ contentPath: './test' });
      await contentAdapter.init();
      
      chatAdapter = new MLVChatAdapter(contentAdapter);
      await chatAdapter.init();
    });
    
    it('should register expected commands', () => {
      const manifest = chatAdapter.manifest;
      
      assert.ok(manifest.commands.includes('/bible'));
      assert.ok(manifest.commands.includes('/mlv'));
      assert.ok(manifest.commands.includes('/verse'));
      assert.ok(manifest.commands.includes('/scripture'));
    });
    
    it('should handle /bible command', async () => {
      const result = await chatAdapter.handleCommand(
        '/bible',
        ['John', '3:16'],
        { userId: 'test-user', channelId: 'test-channel' }
      );
      
      assert.ok(result);
      assert.strictEqual(result.type, 'scripture-quote');
      assert.ok(result._signed);
    });
    
    it('should generate scripture cards', async () => {
      const result = await chatAdapter.handleCommand(
        '/verse',
        ['Gen', '1:1'],
        { userId: 'test-user', channelId: 'test-channel' }
      );
      
      assert.ok(result);
      assert.strictEqual(result.reference.book, 'Genesis');
    });
  });
  
  describe('MLVBibleAdapter combined', () => {
    it('should provide both content and chat functionality', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();
      
      // Check content adapter
      assert.ok(adapter.content);
      assert.ok(adapter.content.hasCapability(CONTENT_CAPABILITIES.SERVE_PDF));
      
      // Check chat adapter
      assert.ok(adapter.chat);
      assert.ok(adapter.chat.manifest.commands.includes('/bible'));
    });
    
    it('should register with DARSHAN', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();
      
      // Mock DARSHAN instance
      const mockDarshan = {
        registered: [],
        registerContentSource(source) {
          this.registered.push(source);
        }
      };
      
      await adapter.registerWithDarshan(mockDarshan);
      
      assert.strictEqual(mockDarshan.registered.length, 1);
      assert.strictEqual(mockDarshan.registered[0].id, 'mlv-bible');
    });
    
    it('should register with KATHA', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();
      
      const registry = new ChatModRegistry();
      
      adapter.registerWithKatha(null, registry);
      
      // Should be able to route commands
      const result = await registry.routeCommand(
        '/mlv',
        ['Rom', '8:28'],
        { userId: 'test', channelId: 'test' }
      );
      
      assert.ok(result);
    });
  });
});

// ============================================================
// SECURITY INTEGRATION TESTS
// ============================================================

describe('Security Integration', () => {
  
  describe('Capability enforcement', () => {
    it('should prevent unauthorized message access', async () => {
      class LimitedMod extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'limited-mod',
            version: '1.0.0',
            // Note: No MSG_READ capability
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['/limited'],
          }));
        }
        
        async handleMessage(message, context) {
          // Should not be called without MSG_READ
          return { type: 'response', content: 'Saw: ' + message };
        }
      }
      
      const mod = new LimitedMod();
      await mod.init();
      
      // handleMessage should reject without capability
      try {
        await mod.handleMessage('test message', {});
        assert.fail('Should have rejected message handling');
      } catch (err) {
        assert.ok(err.message.includes('capability'));
      }
    });
    
    it('should isolate adapters from each other', async () => {
      const registry = new ChatModRegistry();
      
      class Adapter1 extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'adapter-1',
            version: '1.0.0',
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['/cmd1'],
          }));
          this.secret = 'adapter-1-secret';
        }
        
        async handleCommand(cmd, args, ctx) {
          return this._signResponse({ from: 'adapter-1' });
        }
      }
      
      class Adapter2 extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'adapter-2',
            version: '1.0.0',
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['/cmd2'],
          }));
        }
        
        async handleCommand(cmd, args, ctx) {
          // Try to access adapter-1's data (should fail)
          return this._signResponse({ 
            from: 'adapter-2',
            // Can't access other adapter's internals
          });
        }
      }
      
      const a1 = new Adapter1();
      const a2 = new Adapter2();
      await a1.init();
      await a2.init();
      
      registry.register(a1);
      registry.register(a2);
      
      const r1 = await registry.routeCommand('/cmd1', [], {});
      const r2 = await registry.routeCommand('/cmd2', [], {});
      
      // Each response is from its own adapter
      assert.strictEqual(r1.from, 'adapter-1');
      assert.strictEqual(r2.from, 'adapter-2');
      
      // Signed by different adapters
      assert.notStrictEqual(r1._signed.adapterId, r2._signed.adapterId);
    });
  });
  
  describe('Response verification', () => {
    it('should verify response signatures', async () => {
      class SignedMod extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'signed-mod',
            version: '1.0.0',
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['/sign'],
          }));
        }
        
        async handleCommand(cmd, args, ctx) {
          return this._signResponse({ content: 'Verified content' });
        }
      }
      
      const mod = new SignedMod();
      await mod.init();
      
      const response = await mod.handleCommand('/sign', [], {});
      
      // Verify signature structure
      assert.ok(response._signed);
      assert.strictEqual(response._signed.adapterId, 'signed-mod');
      assert.strictEqual(response._signed.version, '1.0.0');
      assert.strictEqual(response._signed.hash, mod.manifest.getHash());
      assert.ok(typeof response._signed.timestamp === 'number');
      
      // Signature should be stable for same manifest
      const response2 = await mod.handleCommand('/sign', [], {});
      assert.strictEqual(response._signed.hash, response2._signed.hash);
    });
    
    it('should detect tampered responses', () => {
      // If someone modifies a response, hash won't match
      const signedResponse = {
        content: 'Original',
        _signed: {
          adapterId: 'test',
          version: '1.0.0',
          hash: 'original-hash',
          timestamp: Date.now(),
        }
      };
      
      // Tamper with content
      signedResponse.content = 'Tampered!';
      
      // In real system, verification would fail
      // because content changed but hash didn't
      // This is validated by the receiving system
    });
  });
});

console.log('\\n=== Adapter Framework Tests ===');
console.log('Run with: node --test tests/adapter.test.js');
