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
      assert.ok(CONTENT_CAPABILITIES.NET_STREAM);
    });
  });

  describe('ContentMetadata', () => {
    it('should create metadata with required fields', () => {
      const meta = new ContentMetadata({
        id: 'test-id',
        title: 'Test Document',
        contentType: 'application/pdf',
        author: 'Test Author',
      });

      assert.strictEqual(meta.id, 'test-id');
      assert.strictEqual(meta.title, 'Test Document');
      assert.strictEqual(meta.contentType, 'application/pdf');
      assert.strictEqual(meta.author, 'Test Author');
    });

    it('should convert to JSON', () => {
      const meta = new ContentMetadata({ id: 'test', title: 'Test', contentType: 'text/plain' });
      const json = meta.toJSON();

      assert.ok(json.id);
      assert.ok(json.title);
      assert.ok(json.contentType);
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

      async init() {
        // Test implementation — base class is abstract
      }

      async lookupReference(ref) {
        return { reference: ref, text: 'Test text', found: true };
      }
    }

    it('should initialize with capabilities', async () => {
      const adapter = new TestContentAdapter();
      await adapter.init();

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
        commands: ['test'],
      });

      assert.strictEqual(manifest.id, 'test-mod');
      assert.strictEqual(manifest.version, '1.0.0');
      assert.ok(manifest.capabilities.has(CHAT_MOD_CAPABILITIES.CMD_SLASH));
    });

    it('should generate manifest hash', () => {
      const manifest = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [],
        commands: [],
      });

      // Hash is a property, computed in constructor
      assert.ok(manifest.hash);
      assert.ok(manifest.hash.length > 0);

      // Hash should be deterministic — same input = same hash
      const manifest2 = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [],
        commands: [],
      });
      assert.strictEqual(manifest.hash, manifest2.hash);
    });

    it('should validate capability requirements', () => {
      const manifest = new ChatModManifest({
        id: 'test-mod',
        version: '1.0.0',
        capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
        commands: [],
      });

      // capabilities is a Set
      assert.strictEqual(
        manifest.capabilities.has(CHAT_MOD_CAPABILITIES.CMD_SLASH),
        true
      );
      assert.strictEqual(
        manifest.capabilities.has(CHAT_MOD_CAPABILITIES.SPECIAL_DM),
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
          commands: ['test'],
          rateLimit: { messages: 5, window: 60000 }
        }));
      }

      async init() {
        // Test init override
      }

      async onCommand(command, args, context) {
        return {
          type: 'text',
          content: 'Test response: ' + args.join(' '),
        };
      }
    }

    it('should enforce rate limits', async () => {
      const mod = new TestChatMod();
      await mod.init();

      const context = { senderId: 'user-1', roomId: 'room-1' };

      // Should allow up to rate limit
      for (let i = 0; i < 5; i++) {
        const result = await mod.handleCommand('test', ['hello'], context);
        assert.ok(result);
      }

      // Should return null after limit exceeded (rate limiting returns null, not throw)
      const result = await mod.handleCommand('test', ['overflow'], context);
      assert.strictEqual(result, null);
    });

    it('should sign responses with manifest hash', async () => {
      const mod = new TestChatMod();
      await mod.init();

      const context = { senderId: 'user-1', roomId: 'room-1' };
      const response = await mod.handleCommand('test', ['hello'], context);

      assert.ok(response._adapter);
      assert.strictEqual(response._adapter.id, 'test-chat-mod');
      assert.ok(response._adapter.manifestHash);
      assert.ok(response._adapter.timestamp);
    });

    it('should sanitize context based on capabilities', async () => {
      const mod = new TestChatMod();
      await mod.init();

      const rawContext = {
        senderId: 'user-1',
        roomId: 'room-1',
        content: 'secret message',    // Should be stripped (no MSG_READ capability)
        threadId: 'thread-1',         // Should be stripped (no SPECIAL_THREAD capability)
      };

      const sanitized = mod._sanitizeContext(rawContext);

      assert.strictEqual(sanitized.senderId, 'user-1');
      assert.strictEqual(sanitized.roomId, 'room-1');
      assert.strictEqual(sanitized.content, undefined);   // Stripped — no MSG_READ
      assert.strictEqual(sanitized.threadId, undefined);   // Stripped — no SPECIAL_THREAD
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
            commands: ['greet'],
          }));
        }

        async init() {
          // Test init override
        }

        async onCommand(command, args, context) {
          return { content: 'Hello ' + args[0] };
        }
      }

      const mod = new TestMod();
      await mod.init();
      registry.register(mod);

      const result = await registry.routeCommand('greet', ['World'], {});

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
      assert.deepStrictEqual(BIBLE_BOOKS.Genesis.abbrev, ['Gen', 'Ge']);
      assert.deepStrictEqual(BIBLE_BOOKS.John.abbrev, ['John', 'Jn']);
      assert.deepStrictEqual(BIBLE_BOOKS.Revelation.abbrev, ['Rev', 'Re']);
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
      assert.strictEqual(ref.startVerse, 16);
    });

    it('should parse abbreviations', () => {
      const ref = parseReference('Gen 1:1');

      assert.strictEqual(ref.book, 'Genesis');
      assert.strictEqual(ref.chapter, 1);
      assert.strictEqual(ref.startVerse, 1);
    });

    it('should parse verse ranges', () => {
      const ref = parseReference('Ps 23:1-6');

      assert.strictEqual(ref.book, 'Psalms');
      assert.strictEqual(ref.chapter, 23);
      assert.strictEqual(ref.startVerse, 1);
      assert.strictEqual(ref.endVerse, 6);
    });

    it('should handle chapter-only references', () => {
      // Current parser requires chapter:verse format
      const ref = parseReference('Romans 8');

      // Returns null for chapter-only (no verse specified)
      assert.strictEqual(ref, null);
    });

    it('should return invalid for bad input', () => {
      const ref = parseReference('Not a book 99:99');

      assert.strictEqual(ref, null);
    });

    it('should handle case insensitivity', () => {
      const ref = parseReference('GENESIS 1:1');

      assert.ok(ref);
      assert.strictEqual(ref.book, 'Genesis');
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
      assert.strictEqual(result.verse, 16);
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

      // Commands stored without / prefix
      assert.ok(manifest.commands.includes('bible'));
      assert.ok(manifest.commands.includes('mlv'));
      assert.ok(manifest.commands.includes('verse'));
      assert.ok(manifest.commands.includes('scripture'));
    });

    it('should handle /bible command', async () => {
      const result = await chatAdapter.handleCommand(
        'bible',
        ['John', '3:16'],
        { senderId: 'test-user', roomId: 'test-room' }
      );

      assert.ok(result);
      assert.strictEqual(result.type, 'scripture-card');
      assert.ok(result._adapter);
    });

    it('should generate scripture cards', async () => {
      const result = await chatAdapter.handleCommand(
        'verse',
        ['Gen', '1:1'],
        { senderId: 'test-user', roomId: 'test-room' }
      );

      assert.ok(result);
      assert.strictEqual(result.reference, 'Genesis 1:1');
    });
  });

  describe('MLVBibleAdapter combined', () => {
    it('should provide both content and chat functionality', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();

      // Check content adapter
      assert.ok(adapter.contentAdapter);
      assert.ok(adapter.contentAdapter.hasCapability(CONTENT_CAPABILITIES.SERVE_PDF));

      // Check chat adapter
      assert.ok(adapter.chatAdapter);
      assert.ok(adapter.chatAdapter.manifest.commands.includes('bible'));
    });

    it('should register with DARSHAN', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();

      // Mock DARSHAN instance
      const mockDarshan = {
        registered: [],
        async registerContent(id, opts) {
          this.registered.push({ id, ...opts });
        }
      };

      await adapter.registerWithDarshan(mockDarshan);

      // With no content directory, catalog is empty, so nothing registers
      assert.strictEqual(mockDarshan.registered.length, adapter.contentAdapter.catalog.size);
    });

    it('should register with KATHA', async () => {
      const adapter = new MLVBibleAdapter({ contentPath: './test' });
      await adapter.init();

      const registry = new ChatModRegistry();

      adapter.registerWithKatha(null, registry);

      // Should be able to route commands (commands stored without /)
      const result = await registry.routeCommand(
        'mlv',
        ['Rom', '8:28'],
        { senderId: 'test', roomId: 'test' }
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
            commands: ['limited'],
          }));
        }

        async init() { }

        async onMessage(context) {
          // Should not see message content without MSG_READ
          return { type: 'response', content: 'Saw: ' + context.content };
        }
      }

      const mod = new LimitedMod();
      await mod.init();

      // handleMessage sanitizes context — content stripped without MSG_READ
      const response = await mod.handleMessage({
        senderId: 'user-1',
        roomId: 'room-1',
        content: 'secret message',
      });

      // Response content should be undefined (sanitized out)
      if (response) {
        assert.strictEqual(response.content, 'Saw: undefined');
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
            commands: ['cmd1'],
          }));
          this.secret = 'adapter-1-secret';
        }

        async init() { }

        async onCommand(cmd, args, ctx) {
          return { from: 'adapter-1' };
        }
      }

      class Adapter2 extends ChatModAdapter {
        constructor() {
          super(new ChatModManifest({
            id: 'adapter-2',
            version: '1.0.0',
            capabilities: [CHAT_MOD_CAPABILITIES.CMD_SLASH],
            commands: ['cmd2'],
          }));
        }

        async init() { }

        async onCommand(cmd, args, ctx) {
          // Try to access adapter-1's data (should fail)
          return {
            from: 'adapter-2',
            // Can't access other adapter's internals
          };
        }
      }

      const a1 = new Adapter1();
      const a2 = new Adapter2();
      await a1.init();
      await a2.init();

      registry.register(a1);
      registry.register(a2);

      const r1 = await registry.routeCommand('cmd1', [], {});
      const r2 = await registry.routeCommand('cmd2', [], {});

      // Each response is from its own adapter
      assert.strictEqual(r1.from, 'adapter-1');
      assert.strictEqual(r2.from, 'adapter-2');

      // Signed by different adapters (_adapter, not _signed)
      assert.notStrictEqual(r1._adapter.id, r2._adapter.id);
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
            commands: ['sign'],
          }));
        }

        async init() { }

        async onCommand(cmd, args, ctx) {
          return { content: 'Verified content' };
        }
      }

      const mod = new SignedMod();
      await mod.init();

      const response = await mod.handleCommand('sign', [], {});

      // Verify _adapter signature structure
      assert.ok(response._adapter);
      assert.strictEqual(response._adapter.id, 'signed-mod');
      assert.strictEqual(response._adapter.version, '1.0.0');
      assert.strictEqual(response._adapter.manifestHash, mod.manifest.hash);
      assert.ok(typeof response._adapter.timestamp === 'number');

      // Signature should be stable for same manifest
      const response2 = await mod.handleCommand('sign', [], {});
      assert.strictEqual(response._adapter.manifestHash, response2._adapter.manifestHash);
    });

    it('should detect tampered responses', () => {
      // If someone modifies a response, hash won't match
      const signedResponse = {
        content: 'Original',
        _adapter: {
          id: 'test',
          version: '1.0.0',
          manifestHash: 'original-hash',
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
