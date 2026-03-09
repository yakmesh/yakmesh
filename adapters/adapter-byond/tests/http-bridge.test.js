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
 * HTTP Bridge Tests
 * 
 * Tests for the BYOND HTTP bridge that connects DreamDaemon to Yakmesh.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';

import { BYONDHttpBridge, createHttpBridge } from '../http-bridge.js';
import BYONDAdapter, { BYONDServer, SERVER_STATUS } from '../index.js';

// ═══════════════════════════════════════════════════════════════════════════════
// MOCK ADAPTER
// ═══════════════════════════════════════════════════════════════════════════════

function createMockAdapter() {
  const localServers = new Map();
  const remoteServers = new Map();
  
  return {
    isInitialized: true,
    localServers,
    remoteServers,
    stats: {
      serversRegistered: 0,
      serversDiscovered: 0,
      topicsSent: 0,
    },
    security: null, // No security for basic tests
    
    getServers(filter = {}) {
      const servers = [...localServers.values(), ...remoteServers.values()];
      return servers.filter(s => {
        if (filter.gameId && s.gameId !== filter.gameId) return false;
        if (filter.status && s.status !== filter.status) return false;
        return true;
      });
    },
    
    async registerServer(config) {
      const server = new BYONDServer({
        ...config,
        meshNodeId: 'mock-node',
      });
      server.status = SERVER_STATUS.ONLINE;
      localServers.set(server.id, server);
      return server;
    },
    
    async sendTopic(serverId, topic) {
      return { type: 'string', value: `mock-response:${topic}` };
    },
    
    async saveWorld(serverId, data, metadata) {
      return { cid: `cid-${Date.now()}`, hash: 'mock-hash' };
    },
    
    async loadWorld(cid) {
      return Buffer.from(`world-data-for-${cid}`);
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP BRIDGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYONDHttpBridge', () => {
  describe('Construction', () => {
    it('should create bridge with defaults', () => {
      const adapter = createMockAdapter();
      const bridge = new BYONDHttpBridge(adapter);
      
      assert.strictEqual(bridge.port, 8080);
      assert.strictEqual(bridge.host, '127.0.0.1');
      assert.strictEqual(bridge.apiKey, null);
    });

    it('should create bridge with custom options', () => {
      const adapter = createMockAdapter();
      const bridge = new BYONDHttpBridge(adapter, {
        port: 9000,
        host: '0.0.0.0',
        apiKey: 'secret123',
      });
      
      assert.strictEqual(bridge.port, 9000);
      assert.strictEqual(bridge.host, '0.0.0.0');
      assert.strictEqual(bridge.apiKey, 'secret123');
    });
  });

  describe('Server Lifecycle', () => {
    it('should start and stop', async () => {
      const adapter = createMockAdapter();
      const bridge = new BYONDHttpBridge(adapter, { port: 0 }); // port 0 = random
      
      await bridge.start();
      assert.ok(bridge.server);
      assert.ok(bridge.stats.startTime);
      
      await bridge.stop();
      // Server should be closed
    });
  });
});

describe('HTTP Bridge Request Handling', () => {
  let adapter;
  let bridge;
  let baseUrl;

  before(async () => {
    adapter = createMockAdapter();
    bridge = new BYONDHttpBridge(adapter, { port: 0 });
    await bridge.start();
    
    const address = bridge.server.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    await bridge.stop();
  });

  it('should respond to GET /status', async () => {
    const response = await fetch(`${baseUrl}/status`);
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.strictEqual(data.status, 'online');
    assert.ok(data.adapter);
    assert.ok(data.bridge);
  });

  it('should respond to GET /servers', async () => {
    const response = await fetch(`${baseUrl}/servers`);
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.ok(Array.isArray(data.servers));
    assert.strictEqual(typeof data.count, 'number');
  });

  it('should register a server via POST /register', async () => {
    const response = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gameId: 'test-game',
        host: 'localhost',
        port: 6666,
        name: 'Test Server',
      }),
    });
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.strictEqual(data.success, true);
    assert.ok(data.serverId);
    assert.strictEqual(data.server.gameId, 'test-game');
  });

  it('should reject registration with missing fields', async () => {
    const response = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gameId: 'test-game',
        // missing host and port
      }),
    });
    const data = await response.json();
    
    assert.strictEqual(response.status, 400);
    assert.ok(data.error);
  });

  it('should filter servers by gameId', async () => {
    // Register another server
    await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gameId: 'other-game',
        host: 'localhost',
        port: 7777,
        name: 'Other Server',
      }),
    });

    const response = await fetch(`${baseUrl}/servers?gameId=test-game`);
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.ok(data.servers.every(s => s.gameId === 'test-game'));
  });

  it('should send Topic via POST /topic/:serverId', async () => {
    // First register a server
    const regResponse = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gameId: 'topic-test',
        host: 'localhost',
        port: 8888,
      }),
    });
    const regData = await regResponse.json();
    const serverId = regData.serverId;

    // Now send a topic
    const response = await fetch(`${baseUrl}/topic/${serverId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ topic: 'status' }),
    });
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.strictEqual(data.success, true);
    assert.ok(data.response);
  });

  it('should save world via POST /world/save', async () => {
    // Register a server first
    const regResponse = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gameId: 'save-test',
        host: 'localhost',
        port: 9999,
      }),
    });
    const regData = await regResponse.json();

    const response = await fetch(`${baseUrl}/world/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serverId: regData.serverId,
        data: Buffer.from('world-data').toString('base64'),
        encoding: 'base64',
      }),
    });
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.strictEqual(data.success, true);
    assert.ok(data.cid);
  });

  it('should load world via GET /world/load/:cid', async () => {
    const response = await fetch(`${baseUrl}/world/load/test-cid`);
    const data = await response.json();
    
    assert.strictEqual(response.status, 200);
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.encoding, 'base64');
    assert.ok(data.data);
  });

  it('should return 404 for unknown endpoints', async () => {
    const response = await fetch(`${baseUrl}/unknown/endpoint`);
    const data = await response.json();
    
    assert.strictEqual(response.status, 404);
    assert.ok(data.error);
  });

  it('should handle CORS preflight', async () => {
    const response = await fetch(`${baseUrl}/status`, {
      method: 'OPTIONS',
    });
    
    assert.strictEqual(response.status, 204);
    assert.ok(response.headers.get('access-control-allow-origin'));
  });
});

describe('HTTP Bridge API Key Authentication', () => {
  it('should reject requests without API key when configured', async () => {
    // Small delay to ensure previous test suite's server is fully closed
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const adapter = createMockAdapter();
    const bridge = new BYONDHttpBridge(adapter, { 
      port: 8085, // Use fixed port different from default
      apiKey: 'secret-key',
    });
    
    await bridge.start();
    const testUrl = `http://127.0.0.1:8085`;

    try {
      // Request without key should fail
      const response = await fetch(`${testUrl}/servers`);
      assert.strictEqual(response.status, 401);

      // Request with key should succeed
      const authResponse = await fetch(`${testUrl}/servers`, {
        headers: { 'X-API-Key': 'secret-key' },
      });
      assert.strictEqual(authResponse.status, 200);

      // Status endpoint should work without key
      const statusResponse = await fetch(`${testUrl}/status`);
      assert.strictEqual(statusResponse.status, 200);
    } finally {
      await bridge.stop();
    }
  });
});

console.log('✓ HTTP Bridge tests loaded');
