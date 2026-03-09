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
 * Server Module Tests — KOMM API, DARSHAN API, route factories
 * 
 * Tests the Express route factory functions with mocked protocol hubs.
 * Does NOT start an actual HTTP server.
 * 
 * @module server/tests/server.test
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert';

import { createKommAPI, wireKommGossip } from '../komm-api.js';
import { createDarshanAPI, wireDarshanGossip } from '../darshan-api.js';

console.log('\n🖥️  Server Module Tests (KOMM API + DARSHAN API)\n');
console.log('='.repeat(60));

// =============================================================================
// Mock helpers
// =============================================================================

function noopMiddleware(req, res, next) { next(); }

function createMockKathaHub() {
  return {
    channels: new Map([
      ['ch-1', { messages: [{ id: 'm1' }], getTypingUsers: () => [] }],
    ]),
    getMessages(channelId, since, limit) { return []; },
    sendMessage(channelId, message) { return { id: 'msg-new', ...message }; },
    startTyping(channelId, userId) {},
    stopTyping(channelId, userId) {},
    getStats() { return { channels: 1 }; },
  };
}

function createMockVaniHub() {
  return {
    calls: new Map(),
    activeCallId: null,
    initiateCall(peerId, mediaType) { return { callId: 'call-1' }; },
    sendSignal(callId, signal) {},
    endCall(callId) {},
    getStats() { return { calls: 0 }; },
  };
}

function createMockYurtHub() {
  return {
    directory: {
      entries: new Map([
        ['room-1', { roomId: 'room-1', name: 'Test Room', toJSON() { return this; } }],
      ]),
      ownEntries: new Map(),
    },
    publishRoom(info) { return { roomId: 'room-pub' }; },
    searchRooms(query) { return []; },
    getStats() { return { rooms: 1 }; },
  };
}

function createMockGumbaHub() {
  return {
    bundles: new Map(),
    sessions: new Map(),
    stats: { operations: 0 },
    createSession(opts) { return { sessionId: 'sess-1' }; },
    getStats() { return this.stats; },
  };
}

function createMockIdentity(nodeId = 'server-test-node') {
  return {
    identity: { nodeId },
  };
}

function createMockGossip() {
  return {
    spreadRumor(topic, data) {},
    on(event, handler) { return this; },
    off(event, handler) { return this; },
    removeListener(event, handler) { return this; },
  };
}

function createMockDarshanGateway() {
  return {
    contents: new Map([
      ['content-1', {
        contentId: 'content-1',
        contentType: 'TEXT',
        getPublicMetadata() { return { contentId: 'content-1', title: 'Test' }; },
      }],
    ]),
    streams: new Map(),
    exclusions: new Set(),
    stats: { views: 10 },
    registerContent(opts) { return { contentId: 'new-1' }; },
    requestStream(contentId, viewerId) { return { streamId: 'stream-1' }; },
  };
}

// =============================================================================
// createKommAPI
// =============================================================================

describe('createKommAPI', () => {
  let router;

  before(() => {
    router = createKommAPI({
      kathaHub: createMockKathaHub(),
      vaniHub: createMockVaniHub(),
      yurtHub: createMockYurtHub(),
      gumbaHub: createMockGumbaHub(),
      gossip: createMockGossip(),
      identity: createMockIdentity(),
      writeLimiter: noopMiddleware,
      requirePeerAuth: noopMiddleware,
    });
  });

  it('returns an Express router', () => {
    assert.ok(router, 'Router should exist');
    // Express routers have .stack
    assert.ok(Array.isArray(router.stack), 'Should be an Express router with stack');
  });

  it('has KOMM status route', () => {
    const routes = router.stack.filter(l => l.route);
    const statusRoute = routes.find(l => l.route.path === '/status');
    assert.ok(statusRoute, 'Should have /status route');
  });

  it('has KATHA channel routes', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    assert.ok(paths.includes('/katha/channels'), 'Should have /katha/channels');
  });

  it('has VANI call routes', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    const hasVani = paths.some(p => p.includes('/vani'));
    assert.ok(hasVani, 'Should have VANI routes');
  });

  it('has YURT room routes', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    const hasYurt = paths.some(p => p.includes('/yurt'));
    assert.ok(hasYurt, 'Should have YURT routes');
  });

  it('has GUMBA access control routes', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    const hasGumba = paths.some(p => p.includes('/gumba'));
    assert.ok(hasGumba, 'Should have GUMBA routes');
  });

  // =========================================================================
  // HIGH 7.1 Regression: requirePeerAuth wired into write routes
  // =========================================================================

  it('KOMM write routes have auth middleware (HIGH 7.1)', () => {
    // All POST/DELETE routes should have at least 2 middleware layers
    // (writeLimiter/requirePeerAuth + handler, or requirePeerAuth + handler)
    const writeRoutes = router.stack
      .filter(l => l.route)
      .filter(l => {
        const methods = l.route.methods;
        return methods.post || methods.delete;
      });

    for (const layer of writeRoutes) {
      const handlerCount = layer.route.stack.length;
      // At minimum: requirePeerAuth + handler = 2; write routes have writeLimiter too = 3
      assert.ok(
        handlerCount >= 2,
        `${layer.route.path} should have auth middleware (has ${handlerCount} handler(s))`
      );
    }
  });
});

// =============================================================================
// createDarshanAPI
// =============================================================================

describe('createDarshanAPI', () => {
  let router;

  before(() => {
    router = createDarshanAPI({
      darshanGateway: createMockDarshanGateway(),
      gossip: createMockGossip(),
      identity: createMockIdentity(),
      writeLimiter: noopMiddleware,
      requirePeerAuth: noopMiddleware,
    });
  });

  it('returns an Express router', () => {
    assert.ok(router);
    assert.ok(Array.isArray(router.stack));
  });

  it('has DARSHAN status route', () => {
    const routes = router.stack.filter(l => l.route);
    const statusRoute = routes.find(l => l.route.path === '/status');
    assert.ok(statusRoute, 'Should have /status route');
  });

  it('has content listing route', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    assert.ok(paths.includes('/content'), 'Should have /content listing');
  });

  it('has content detail route', () => {
    const paths = router.stack.filter(l => l.route).map(l => l.route.path);
    assert.ok(paths.includes('/content/:contentId'), 'Should have /content/:contentId');
  });

  // =========================================================================
  // HIGH 8.2 Regression: requirePeerAuth wired into DARSHAN write routes
  // =========================================================================

  it('DARSHAN write routes have auth middleware (HIGH 8.2)', () => {
    const writeRoutes = router.stack
      .filter(l => l.route)
      .filter(l => {
        const methods = l.route.methods;
        return methods.post || methods.delete;
      });

    for (const layer of writeRoutes) {
      const handlerCount = layer.route.stack.length;
      assert.ok(
        handlerCount >= 2,
        `${layer.route.path} should have auth middleware (has ${handlerCount} handler(s))`
      );
    }
  });
});

// =============================================================================
// wireKommGossip
// =============================================================================

describe('wireKommGossip', () => {
  it('is a function', () => {
    assert.strictEqual(typeof wireKommGossip, 'function');
  });

  it('does not throw with valid arguments', () => {
    assert.doesNotThrow(() => {
      wireKommGossip(
        createMockGossip(),   // mesh (positional)
        createMockKathaHub(),
        createMockVaniHub(),
        createMockYurtHub(),
        createMockGumbaHub(),
      );
    });
  });
});

// =============================================================================
// wireDarshanGossip
// =============================================================================

describe('wireDarshanGossip', () => {
  it('is a function', () => {
    assert.strictEqual(typeof wireDarshanGossip, 'function');
  });

  it('does not throw with valid arguments', () => {
    assert.doesNotThrow(() => {
      wireDarshanGossip(
        createMockGossip(),          // mesh (positional)
        createMockDarshanGateway(),
      );
    });
  });
});
