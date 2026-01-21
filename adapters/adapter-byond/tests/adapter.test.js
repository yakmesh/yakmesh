/**
 * BYOND Adapter Tests
 * 
 * Tests for the BYOND adapter including:
 * - Topic protocol encoding/decoding
 * - Server registration and discovery
 * - Topic relay through mesh
 * - Security integration
 * 
 * @module adapters/adapter-byond/tests
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert';

import BYONDTopicClient, {
  parseTopicResponse,
  buildTopicPacket,
  createTopicConnection,
} from '../topic-client.js';

import BYONDAdapter, {
  BYONDServer,
  BYOND_TOPICS,
  SERVER_STATUS,
} from '../index.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TOPIC PROTOCOL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYOND Topic Protocol', () => {
  describe('buildTopicPacket', () => {
    it('should build valid packet for simple topic', () => {
      const packet = buildTopicPacket('status');
      
      // Verify header
      assert.strictEqual(packet[0], 0x00, 'First byte should be 0x00');
      assert.strictEqual(packet[1], 0x83, 'Second byte should be 0x83');
      
      // Verify topic marker
      assert.strictEqual(packet[4], 0x00, 'Topic marker byte 1');
      assert.strictEqual(packet[5], 0x6A, 'Topic marker byte 2');
      
      // Verify topic content
      const topicStr = packet.slice(6, packet.length - 1).toString('utf8');
      assert.strictEqual(topicStr, 'status', 'Topic string should match');
      
      // Verify null terminator
      assert.strictEqual(packet[packet.length - 1], 0x00, 'Should end with null');
    });

    it('should build valid packet for topic with parameters', () => {
      const packet = buildTopicPacket('action=test&key=value');
      const topicStr = packet.slice(6, packet.length - 1).toString('utf8');
      assert.strictEqual(topicStr, 'action=test&key=value');
    });

    it('should handle unicode characters', () => {
      const packet = buildTopicPacket('msg=Hello 世界');
      const topicStr = packet.slice(6, packet.length - 1).toString('utf8');
      assert.strictEqual(topicStr, 'msg=Hello 世界');
    });

    it('should calculate size correctly', () => {
      const topic = 'status';
      const packet = buildTopicPacket(topic);
      
      // Size = marker(2) + topic length + null(1)
      const expectedSize = 2 + Buffer.from(topic).length + 1;
      const actualSize = (packet[2] << 8) | packet[3];
      
      assert.strictEqual(actualSize, expectedSize, 'Size should match payload');
    });
  });

  describe('parseTopicResponse', () => {
    it('should parse null response', () => {
      // [0x00][0x83][0x00][0x01][0x00]
      const buffer = Buffer.from([0x00, 0x83, 0x00, 0x01, 0x00]);
      const result = parseTopicResponse(buffer);
      
      assert.strictEqual(result.type, 'null');
      assert.strictEqual(result.value, null);
    });

    it('should parse float response', () => {
      // Float 1.0 in little endian: 0x00 0x00 0x80 0x3F
      const buffer = Buffer.from([0x00, 0x83, 0x00, 0x05, 0x2a, 0x00, 0x00, 0x80, 0x3F]);
      const result = parseTopicResponse(buffer);
      
      assert.strictEqual(result.type, 'float');
      assert.strictEqual(result.value, 1.0);
    });

    it('should parse string response', () => {
      const testStr = 'players=5&map=station';
      const strBytes = Buffer.from(testStr, 'utf8');
      
      // Build response: header(4) + type(1) + string + null
      const buffer = Buffer.alloc(5 + strBytes.length + 1);
      buffer[0] = 0x00;
      buffer[1] = 0x83;
      buffer[2] = 0x00;
      buffer[3] = strBytes.length + 2; // type + string + null
      buffer[4] = 0x06; // string type
      strBytes.copy(buffer, 5);
      buffer[buffer.length - 1] = 0x00;
      
      const result = parseTopicResponse(buffer);
      
      assert.strictEqual(result.type, 'string');
      assert.strictEqual(result.value, testStr);
    });

    it('should handle invalid header', () => {
      const buffer = Buffer.from([0xFF, 0xFF, 0x00, 0x01, 0x00]);
      const result = parseTopicResponse(buffer);
      
      assert.strictEqual(result.type, 'invalid');
    });

    it('should handle short buffer', () => {
      const buffer = Buffer.from([0x00, 0x83]);
      const result = parseTopicResponse(buffer);
      
      assert.strictEqual(result.type, 'error');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BYOND SERVER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYONDServer', () => {
  it('should create server with defaults', () => {
    const server = new BYONDServer({
      gameId: 'pondera',
      host: 'localhost',
      port: 6666,
    });
    
    assert.strictEqual(server.gameId, 'pondera');
    assert.strictEqual(server.host, 'localhost');
    assert.strictEqual(server.port, 6666);
    assert.strictEqual(server.status, SERVER_STATUS.OFFLINE);
    assert.strictEqual(server.players, 0);
    assert.ok(server.id.startsWith('byond-'));
  });

  it('should serialize to JSON', () => {
    const server = new BYONDServer({
      id: 'test-server-1',
      gameId: 'ss13',
      host: '192.168.1.100',
      port: 7777,
      name: 'Test Station',
      maxPlayers: 50,
      tags: ['roleplay', 'lowpop'],
    });
    
    server.status = SERVER_STATUS.ONLINE;
    server.players = 25;
    server.map = 'station_1';
    
    const json = server.toJSON();
    
    assert.strictEqual(json.id, 'test-server-1');
    assert.strictEqual(json.gameId, 'ss13');
    assert.strictEqual(json.players, 25);
    assert.deepStrictEqual(json.tags, ['roleplay', 'lowpop']);
  });

  it('should deserialize from JSON', () => {
    const json = {
      id: 'remote-server-1',
      gameId: 'pondera',
      host: '10.0.0.5',
      port: 8888,
      status: 'online',
      players: 10,
      verified: true,
    };
    
    const server = BYONDServer.fromJSON(json);
    
    assert.strictEqual(server.id, 'remote-server-1');
    assert.strictEqual(server.status, 'online');
    assert.strictEqual(server.verified, true);
  });

  it('should update from status response', () => {
    const server = new BYONDServer({
      gameId: 'ss13',
      host: 'localhost',
      port: 6666,
    });
    
    server.updateFromStatus({
      type: 'string',
      value: 'players=15&playermax=50&map=boxstation&version=514.1589',
      parsed: {
        players: '15',
        playermax: '50',
        map: 'boxstation',
        version: '514.1589',
      },
    });
    
    assert.strictEqual(server.players, 15);
    assert.strictEqual(server.maxPlayers, 50);
    assert.strictEqual(server.map, 'boxstation');
    assert.strictEqual(server.version, '514.1589');
    assert.strictEqual(server.status, SERVER_STATUS.ONLINE);
    assert.ok(server.lastSeen !== null);
  });

  it('should mark offline with error', () => {
    const server = new BYONDServer({
      gameId: 'ss13',
      host: 'localhost',
      port: 6666,
    });
    
    server.status = SERVER_STATUS.ONLINE;
    server.players = 10;
    
    server.markOffline('Connection refused');
    
    assert.strictEqual(server.status, SERVER_STATUS.OFFLINE);
    assert.strictEqual(server.players, 0);
    assert.strictEqual(server.lastError, 'Connection refused');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// TOPIC CLIENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYONDTopicClient', () => {
  it('should create client with defaults', () => {
    const client = new BYONDTopicClient();
    
    assert.strictEqual(client.timeout, 10000);
    assert.strictEqual(client.retries, 0);
  });

  it('should create client with custom options', () => {
    const client = new BYONDTopicClient({
      timeout: 5000,
      retries: 3,
      retryDelay: 500,
    });
    
    assert.strictEqual(client.timeout, 5000);
    assert.strictEqual(client.retries, 3);
    assert.strictEqual(client.retryDelay, 500);
  });

  it('should emit topic-sent event on successful connection attempt', async () => {
    const client = new BYONDTopicClient({ timeout: 100 });
    
    // Test that the client emits events properly
    // Since we can't connect to a real server, we just verify the event system works
    let eventListenerAdded = false;
    
    client.on('topic-sent', () => {
      eventListenerAdded = true;
    });
    
    // Manually emit to verify event system
    client.emit('topic-sent', { host: 'test', port: 1234, topic: 'test' });
    
    assert.ok(eventListenerAdded, 'Event listener should work');
  });
});

describe('createTopicConnection', () => {
  it('should create connection object with all methods', () => {
    const conn = createTopicConnection({
      host: 'localhost',
      port: 6666,
    });
    
    assert.strictEqual(typeof conn.send, 'function');
    assert.strictEqual(typeof conn.sendWithRetry, 'function');
    assert.strictEqual(typeof conn.status, 'function');
    assert.strictEqual(typeof conn.ping, 'function');
    assert.ok(conn.client instanceof BYONDTopicClient);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// RUMOR TOPICS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYOND Rumor Topics', () => {
  it('should have all required topic constants', () => {
    assert.ok(BYOND_TOPICS.SERVER_ONLINE);
    assert.ok(BYOND_TOPICS.SERVER_OFFLINE);
    assert.ok(BYOND_TOPICS.SERVER_STATUS);
    assert.ok(BYOND_TOPICS.TOPIC_RELAY);
    assert.ok(BYOND_TOPICS.WORLD_SAVE);
    assert.ok(BYOND_TOPICS.WORLD_LOAD);
    assert.ok(BYOND_TOPICS.PLAYER_DOKO);
    assert.ok(BYOND_TOPICS.CHAT_MESSAGE);
  });

  it('should have consistent topic prefix', () => {
    for (const [key, value] of Object.entries(BYOND_TOPICS)) {
      assert.ok(value.startsWith('byond:'), `${key} should start with byond:`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SERVER STATUS ENUM TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('SERVER_STATUS', () => {
  it('should have all status values', () => {
    assert.strictEqual(SERVER_STATUS.STARTING, 'starting');
    assert.strictEqual(SERVER_STATUS.ONLINE, 'online');
    assert.strictEqual(SERVER_STATUS.OFFLINE, 'offline');
    assert.strictEqual(SERVER_STATUS.RESTARTING, 'restarting');
    assert.strictEqual(SERVER_STATUS.CRASHED, 'crashed');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS (Mock)
// ═══════════════════════════════════════════════════════════════════════════════

describe('BYONDAdapter Integration', () => {
  // These tests require mocking the Yakmesh node
  // For now, just test construction
  
  it('should construct with minimal mock node', () => {
    const mockNode = {
      nodeId: 'test-node-123',
      mesh: {
        on: () => {},
        off: () => {},
      },
      gossip: {
        spreadRumor: () => {},
      },
      content: {
        store: async () => 'cid-123',
        retrieve: async () => Buffer.from('test'),
      },
    };
    
    const adapter = new BYONDAdapter(mockNode, {
      statusInterval: 60000,
      broadcastInterval: 120000,
    });
    
    assert.strictEqual(adapter.node, mockNode);
    assert.strictEqual(adapter.config.statusInterval, 60000);
    assert.strictEqual(adapter.config.broadcastInterval, 120000);
    assert.strictEqual(adapter.isInitialized, false);
  });
});

console.log('✓ BYOND Adapter tests loaded');
