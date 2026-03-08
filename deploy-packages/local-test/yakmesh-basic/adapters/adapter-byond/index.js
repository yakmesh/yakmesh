/**
 * Yakmesh BYOND Adapter
 * 
 * Bridges BYOND game servers (DreamDaemon) with the Yakmesh mesh network.
 * Enables game servers like SS13 and Pondera to benefit from:
 * - Server discovery via SHERPA beacons
 * - Player count/status broadcasting via gossip
 * - World persistence via content store
 * - P2P server-to-server communication through mesh
 * - Trust-based access control (DOKO identities)
 * 
 * @module adapters/adapter-byond
 * @version 1.0.0
 * @author AERProductions
 */

import { EventEmitter } from 'events';
import { createServer as createTCPServer } from 'net';
import BYONDTopicClient, { 
  createTopicConnection,
  parseTopicResponse,
  buildTopicPacket 
} from './topic-client.js';
import { getOracle, contentHash } from '../../oracle/index.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

// Rumor topics for mesh communication
export const BYOND_TOPICS = {
  SERVER_ONLINE: 'byond:server:online',
  SERVER_OFFLINE: 'byond:server:offline',
  SERVER_STATUS: 'byond:server:status',
  TOPIC_RELAY: 'byond:topic:relay',
  WORLD_SAVE: 'byond:world:save',
  WORLD_LOAD: 'byond:world:load',
  PLAYER_DOKO: 'byond:doko:player',
  CHAT_MESSAGE: 'byond:chat:message',
};

// Server status values
export const SERVER_STATUS = {
  STARTING: 'starting',
  ONLINE: 'online',
  OFFLINE: 'offline',
  RESTARTING: 'restarting',
  CRASHED: 'crashed',
};

// Default configuration
const DEFAULT_CONFIG = {
  // How often to poll registered servers for status (ms)
  statusInterval: 30000,
  
  // How often to broadcast our server list to mesh (ms)
  broadcastInterval: 60000,
  
  // Topic relay listener port (0 = disabled)
  relayPort: 0,
  
  // Enable world persistence
  enablePersistence: true,
  
  // Enable player DOKO identities
  enablePlayerDoko: true,
};

// ═══════════════════════════════════════════════════════════════════════════════
// BYOND SERVER REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Represents a registered BYOND server
 */
export class BYONDServer {
  constructor(config) {
    this.id = config.id || `byond-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    this.gameId = config.gameId;  // e.g., "pondera", "ss13", "citadel"
    this.host = config.host;
    this.port = config.port;
    this.name = config.name || config.gameId;
    this.description = config.description || '';
    this.version = config.version || '1.0.0';
    this.maxPlayers = config.maxPlayers || 0;
    this.tags = config.tags || [];
    this.metadata = config.metadata || {};
    
    // Runtime state
    this.status = SERVER_STATUS.OFFLINE;
    this.players = 0;
    this.playerList = [];
    this.map = '';
    this.round = '';
    this.lastSeen = null;
    this.lastError = null;
    
    // Mesh state
    this.meshNodeId = null;  // Which Yakmesh node hosts this server
    this.verified = false;   // Whether server identity is verified
  }

  /**
   * Update server status from a Topic response
   */
  updateFromStatus(statusData) {
    this.lastSeen = Date.now();
    this.status = SERVER_STATUS.ONLINE;
    
    if (statusData.parsed) {
      this.players = parseInt(statusData.parsed.players) || 0;
      this.maxPlayers = parseInt(statusData.parsed.playermax) || this.maxPlayers;
      this.map = statusData.parsed.map || '';
      this.round = statusData.parsed.round_id || statusData.parsed.round || '';
      this.version = statusData.parsed.version || this.version;
      
      // Game-specific fields
      if (statusData.parsed.mode) {
        this.metadata.mode = statusData.parsed.mode;
      }
      if (statusData.parsed.hub) {
        this.metadata.hub = statusData.parsed.hub;
      }
    }
  }

  /**
   * Mark server as offline
   */
  markOffline(error = null) {
    this.status = SERVER_STATUS.OFFLINE;
    this.players = 0;
    this.lastError = error;
  }

  /**
   * Serialize for mesh transmission
   */
  toJSON() {
    return {
      id: this.id,
      gameId: this.gameId,
      host: this.host,
      port: this.port,
      name: this.name,
      description: this.description,
      version: this.version,
      maxPlayers: this.maxPlayers,
      tags: this.tags,
      metadata: this.metadata,
      status: this.status,
      players: this.players,
      map: this.map,
      round: this.round,
      lastSeen: this.lastSeen,
      meshNodeId: this.meshNodeId,
      verified: this.verified,
    };
  }

  /**
   * Create from JSON
   */
  static fromJSON(json) {
    const server = new BYONDServer(json);
    server.status = json.status || SERVER_STATUS.OFFLINE;
    server.players = json.players || 0;
    server.map = json.map || '';
    server.round = json.round || '';
    server.lastSeen = json.lastSeen || null;
    server.meshNodeId = json.meshNodeId || null;
    server.verified = json.verified || false;
    return server;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BYOND ADAPTER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * BYOND Adapter for Yakmesh
 * 
 * Manages BYOND game server registration, discovery, and mesh integration.
 */
export class BYONDAdapter extends EventEmitter {
  constructor(yakmeshNode, config = {}) {
    super();
    
    this.node = yakmeshNode;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.oracle = null;
    
    // Server registry
    this.localServers = new Map();   // Servers we host: id -> BYONDServer
    this.remoteServers = new Map();  // Servers from mesh: id -> BYONDServer
    
    // Topic client for querying servers
    this.topicClient = new BYONDTopicClient({
      timeout: 5000,
      retries: 1,
    });
    
    // Topic relay server (optional)
    this.relayServer = null;
    
    // Intervals
    this.statusInterval = null;
    this.broadcastInterval = null;
    
    // Statistics
    this.stats = {
      serversRegistered: 0,
      serversDiscovered: 0,
      topicsSent: 0,
      topicsRelayed: 0,
      worldsSaved: 0,
      worldsLoaded: 0,
    };

    this.isInitialized = false;
  }

  /**
   * Initialize the adapter
   */
  async init() {
    console.log('🎮 Initializing BYOND Adapter...');
    
    // Get ValidationOracle
    this.oracle = getOracle();
    console.log(`  ✓ ValidationOracle attached: ${this.oracle.selfHash.slice(0, 16)}...`);
    
    // Register mesh event handlers
    this._registerMeshHandlers();
    
    // Start Topic relay server if configured
    if (this.config.relayPort > 0) {
      await this._startRelayServer();
    }
    
    // Start status polling
    this._startStatusPolling();
    
    // Start broadcasting
    this._startBroadcasting();
    
    this.isInitialized = true;
    console.log('  ✓ BYOND Adapter initialized');
    
    return this;
  }

  /**
   * Stop the adapter
   */
  async stop() {
    // Stop intervals
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }
    if (this.broadcastInterval) {
      clearInterval(this.broadcastInterval);
      this.broadcastInterval = null;
    }
    
    // Stop relay server
    if (this.relayServer) {
      await new Promise(resolve => this.relayServer.close(resolve));
      this.relayServer = null;
    }
    
    // Mark all local servers offline
    for (const server of this.localServers.values()) {
      await this._broadcastServerOffline(server);
    }
    
    this.isInitialized = false;
    console.log('  ✓ BYOND Adapter stopped');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVER REGISTRATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Register a local BYOND server
   * @param {Object} config - Server configuration
   * @returns {BYONDServer} Registered server
   */
  async registerServer(config) {
    const server = new BYONDServer({
      ...config,
      meshNodeId: this.node.nodeId,
    });
    
    // Verify server is reachable
    const isOnline = await this.topicClient.ping(server.host, server.port);
    if (isOnline) {
      server.status = SERVER_STATUS.ONLINE;
      server.lastSeen = Date.now();
      
      // Get initial status
      try {
        const status = await this.topicClient.queryStatus(server.host, server.port);
        server.updateFromStatus(status);
      } catch (err) {
        console.warn(`  ⚠ Could not get initial status for ${server.name}: ${err.message}`);
      }
    }
    
    this.localServers.set(server.id, server);
    this.stats.serversRegistered++;
    
    console.log(`  ✓ Registered BYOND server: ${server.name} (${server.host}:${server.port})`);
    
    // Broadcast to mesh
    await this._broadcastServerOnline(server);
    
    this.emit('server-registered', server);
    return server;
  }

  /**
   * Unregister a local BYOND server
   * @param {string} serverId - Server ID
   */
  async unregisterServer(serverId) {
    const server = this.localServers.get(serverId);
    if (!server) {
      return false;
    }
    
    this.localServers.delete(serverId);
    
    // Broadcast offline
    await this._broadcastServerOffline(server);
    
    this.emit('server-unregistered', server);
    return true;
  }

  /**
   * Get all known servers (local + remote)
   * @param {Object} filter - Optional filter
   * @returns {BYONDServer[]} Matching servers
   */
  getServers(filter = {}) {
    const servers = [
      ...this.localServers.values(),
      ...this.remoteServers.values(),
    ];
    
    return servers.filter(server => {
      if (filter.gameId && server.gameId !== filter.gameId) return false;
      if (filter.status && server.status !== filter.status) return false;
      if (filter.tag && !server.tags.includes(filter.tag)) return false;
      return true;
    });
  }

  /**
   * Find servers by game ID
   * @param {string} gameId - Game identifier (e.g., "pondera", "ss13")
   * @returns {BYONDServer[]} Matching servers
   */
  findByGame(gameId) {
    return this.getServers({ gameId, status: SERVER_STATUS.ONLINE });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TOPIC BRIDGE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Send a Topic request to a server
   * @param {string} serverId - Target server ID
   * @param {string} topic - Topic string
   * @returns {Promise<Object>} Response
   */
  async sendTopic(serverId, topic) {
    const server = this.localServers.get(serverId) || this.remoteServers.get(serverId);
    if (!server) {
      throw new Error(`Server not found: ${serverId}`);
    }
    
    // If local server, send directly
    if (this.localServers.has(serverId)) {
      const response = await this.topicClient.sendTopic({
        host: server.host,
        port: server.port,
        topic,
      });
      this.stats.topicsSent++;
      return response;
    }
    
    // If remote server, relay through mesh
    return this._relayTopic(server, topic);
  }

  /**
   * Relay a Topic through the mesh to a remote server
   */
  async _relayTopic(server, topic) {
    return new Promise((resolve, reject) => {
      const requestId = `topic-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const timeout = setTimeout(() => {
        reject(new Error('Topic relay timeout'));
      }, 15000);
      
      // Listen for response
      const handler = (responseTopic, data) => {
        if (responseTopic === BYOND_TOPICS.TOPIC_RELAY && 
            data.requestId === requestId && 
            data.type === 'response') {
          clearTimeout(timeout);
          this.node.mesh.off('rumor', handler);
          resolve(data.response);
        }
      };
      
      this.node.mesh.on('rumor', handler);
      
      // Send relay request
      this.node.gossip.spreadRumor(BYOND_TOPICS.TOPIC_RELAY, {
        type: 'request',
        requestId,
        serverId: server.id,
        topic,
        sourceNodeId: this.node.nodeId,
      });
      
      this.stats.topicsRelayed++;
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // WORLD PERSISTENCE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save a world state to the mesh
   * @param {string} serverId - Server ID
   * @param {Buffer|string} worldData - Serialized world data
   * @param {Object} metadata - Save metadata
   */
  async saveWorld(serverId, worldData, metadata = {}) {
    if (!this.config.enablePersistence) {
      throw new Error('World persistence is disabled');
    }
    
    const server = this.localServers.get(serverId);
    if (!server) {
      throw new Error(`Local server not found: ${serverId}`);
    }
    
    // Generate content hash
    const dataBuffer = Buffer.isBuffer(worldData) ? worldData : Buffer.from(worldData);
    const hash = contentHash(dataBuffer);
    
    // Store in content store
    const cid = await this.node.content.store(dataBuffer, {
      type: 'byond-world',
      serverId,
      gameId: server.gameId,
      timestamp: Date.now(),
      ...metadata,
    });
    
    // Broadcast save event
    this.node.gossip.spreadRumor(BYOND_TOPICS.WORLD_SAVE, {
      serverId,
      gameId: server.gameId,
      cid,
      hash,
      size: dataBuffer.length,
      timestamp: Date.now(),
      metadata,
    });
    
    this.stats.worldsSaved++;
    this.emit('world-saved', { serverId, cid, hash });
    
    return { cid, hash };
  }

  /**
   * Load a world state from the mesh
   * @param {string} cid - Content ID
   * @returns {Promise<Buffer>} World data
   */
  async loadWorld(cid) {
    if (!this.config.enablePersistence) {
      throw new Error('World persistence is disabled');
    }
    
    const data = await this.node.content.retrieve(cid);
    this.stats.worldsLoaded++;
    this.emit('world-loaded', { cid });
    
    return data;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL: MESH HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  _registerMeshHandlers() {
    this.node.mesh.on('rumor', (topic, data, origin) => {
      if (!topic.startsWith('byond:')) return;
      
      switch (topic) {
        case BYOND_TOPICS.SERVER_ONLINE:
          this._handleServerOnline(data, origin);
          break;
        case BYOND_TOPICS.SERVER_OFFLINE:
          this._handleServerOffline(data, origin);
          break;
        case BYOND_TOPICS.SERVER_STATUS:
          this._handleServerStatus(data, origin);
          break;
        case BYOND_TOPICS.TOPIC_RELAY:
          this._handleTopicRelay(data, origin);
          break;
      }
    });
  }

  _handleServerOnline(data, origin) {
    if (data.meshNodeId === this.node.nodeId) return;  // Ignore our own
    
    const server = BYONDServer.fromJSON(data);
    this.remoteServers.set(server.id, server);
    this.stats.serversDiscovered++;
    
    this.emit('server-discovered', server);
    console.log(`  📡 Discovered BYOND server: ${server.name} via ${origin.slice(0, 8)}...`);
  }

  _handleServerOffline(data, origin) {
    const server = this.remoteServers.get(data.serverId);
    if (server) {
      server.markOffline();
      this.emit('server-offline', server);
    }
  }

  _handleServerStatus(data, origin) {
    const server = this.remoteServers.get(data.serverId);
    if (server) {
      server.players = data.players;
      server.map = data.map;
      server.status = data.status;
      server.lastSeen = Date.now();
      this.emit('server-status', server);
    }
  }

  async _handleTopicRelay(data, origin) {
    // Only handle requests for our servers
    if (data.type !== 'request') return;
    
    const server = this.localServers.get(data.serverId);
    if (!server) return;
    
    try {
      const response = await this.topicClient.sendTopic({
        host: server.host,
        port: server.port,
        topic: data.topic,
      });
      
      // Send response back through mesh
      this.node.gossip.spreadRumor(BYOND_TOPICS.TOPIC_RELAY, {
        type: 'response',
        requestId: data.requestId,
        serverId: server.id,
        response,
        targetNodeId: data.sourceNodeId,
      });
    } catch (err) {
      // Send error response
      this.node.gossip.spreadRumor(BYOND_TOPICS.TOPIC_RELAY, {
        type: 'response',
        requestId: data.requestId,
        serverId: server.id,
        response: { type: 'error', value: err.message },
        targetNodeId: data.sourceNodeId,
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL: BROADCASTING
  // ═══════════════════════════════════════════════════════════════════════════

  async _broadcastServerOnline(server) {
    this.node.gossip.spreadRumor(BYOND_TOPICS.SERVER_ONLINE, server.toJSON());
  }

  async _broadcastServerOffline(server) {
    this.node.gossip.spreadRumor(BYOND_TOPICS.SERVER_OFFLINE, {
      serverId: server.id,
      gameId: server.gameId,
    });
  }

  _startStatusPolling() {
    this.statusInterval = setInterval(async () => {
      for (const server of this.localServers.values()) {
        try {
          const status = await this.topicClient.queryStatus(server.host, server.port);
          server.updateFromStatus(status);
        } catch (err) {
          server.markOffline(err.message);
        }
      }
    }, this.config.statusInterval);
  }

  _startBroadcasting() {
    this.broadcastInterval = setInterval(() => {
      for (const server of this.localServers.values()) {
        if (server.status === SERVER_STATUS.ONLINE) {
          this.node.gossip.spreadRumor(BYOND_TOPICS.SERVER_STATUS, {
            serverId: server.id,
            gameId: server.gameId,
            status: server.status,
            players: server.players,
            maxPlayers: server.maxPlayers,
            map: server.map,
            round: server.round,
          });
        }
      }
    }, this.config.broadcastInterval);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL: TOPIC RELAY SERVER
  // ═══════════════════════════════════════════════════════════════════════════

  async _startRelayServer() {
    return new Promise((resolve, reject) => {
      this.relayServer = createTCPServer((socket) => {
        let buffer = Buffer.alloc(0);
        
        socket.on('data', async (chunk) => {
          buffer = Buffer.concat([buffer, chunk]);
          
          // Check for complete BYOND packet
          if (buffer.length >= 4) {
            const size = (buffer[2] << 8) | buffer[3];
            if (buffer.length >= 4 + size) {
              const response = parseTopicResponse(buffer);
              
              // Forward to mesh if it's a relay request
              if (response.type === 'string' && response.value.startsWith('yakmesh:')) {
                // Parse relay command
                const cmd = response.value.slice(8);
                const [action, ...args] = cmd.split(':');
                
                if (action === 'relay') {
                  // Format: yakmesh:relay:serverId:topic
                  const [serverId, topic] = args;
                  try {
                    const result = await this.sendTopic(serverId, topic);
                    socket.write(buildTopicPacket(JSON.stringify(result)));
                  } catch (err) {
                    socket.write(buildTopicPacket(`error:${err.message}`));
                  }
                }
              }
              
              buffer = buffer.slice(4 + size);
            }
          }
        });
        
        socket.on('error', () => {});
      });
      
      this.relayServer.listen(this.config.relayPort, () => {
        console.log(`  ✓ Topic relay server listening on port ${this.config.relayPort}`);
        resolve();
      });
      
      this.relayServer.on('error', reject);
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export default BYONDAdapter;
export { BYONDTopicClient, createTopicConnection };
