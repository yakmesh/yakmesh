/**
 * BYOND HTTP Bridge
 * 
 * HTTP server that allows BYOND games (via world.Export) to communicate
 * with the Yakmesh BYOND adapter. This bridges the gap between BYOND's
 * HTTP capabilities and the Yakmesh mesh network.
 * 
 * Endpoints:
 * - GET  /status          - Bridge status and stats
 * - GET  /servers         - List discovered servers
 * - GET  /servers/:id     - Get specific server info
 * - POST /register        - Register a server
 * - POST /topic/:serverId - Send Topic to a server
 * - POST /world/save      - Save world state
 * - GET  /world/load/:cid - Load world state
 * - GET  /doko/:ckey      - Get player DOKO
 * - POST /doko/create     - Create player DOKO
 * - POST /doko/verify     - Verify player signature
 * 
 * @module adapters/adapter-byond/http-bridge
 * @version 1.0.0
 */

import { createServer } from 'http';
import { URL } from 'url';
import { EventEmitter } from 'events';

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP BRIDGE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * HTTP Bridge for BYOND ↔ Yakmesh communication
 */
export class BYONDHttpBridge extends EventEmitter {
  constructor(adapter, options = {}) {
    super();
    
    this.adapter = adapter;
    this.port = options.port || 8080;
    this.host = options.host || '127.0.0.1';
    this.apiKey = options.apiKey || null; // Optional API key for security
    
    this.server = null;
    this.stats = {
      requestsTotal: 0,
      requestsByEndpoint: {},
      errors: 0,
      startTime: null,
    };
  }

  /**
   * Start the HTTP bridge
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => this._handleRequest(req, res));
      
      this.server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          reject(new Error(`Port ${this.port} is already in use`));
        } else {
          reject(err);
        }
      });

      this.server.listen(this.port, this.host, () => {
        this.stats.startTime = Date.now();
        console.log(`  ✓ BYOND HTTP Bridge listening on http://${this.host}:${this.port}`);
        resolve();
      });
    });
  }

  /**
   * Stop the HTTP bridge
   */
  async stop() {
    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => {
          console.log('  ✓ BYOND HTTP Bridge stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Main request handler
   */
  async _handleRequest(req, res) {
    this.stats.requestsTotal++;
    
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method;

    // Track endpoint stats
    const endpoint = `${method} ${path.split('/').slice(0, 3).join('/')}`;
    this.stats.requestsByEndpoint[endpoint] = (this.stats.requestsByEndpoint[endpoint] || 0) + 1;

    // CORS headers for browser-based tools
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // API key check (if configured)
    if (this.apiKey && req.headers['x-api-key'] !== this.apiKey) {
      // Allow status endpoint without key
      if (path !== '/status') {
        return this._sendError(res, 401, 'Invalid or missing API key');
      }
    }

    try {
      // Parse body for POST requests
      let body = null;
      if (method === 'POST') {
        body = await this._parseBody(req);
      }

      // Route request
      const result = await this._route(method, path, url.searchParams, body);
      this._sendJson(res, 200, result);

    } catch (err) {
      this.stats.errors++;
      this._sendError(res, err.statusCode || 500, err.message);
    }
  }

  /**
   * Route request to handler
   */
  async _route(method, path, params, body) {
    // GET /status
    if (method === 'GET' && path === '/status') {
      return this._handleStatus();
    }

    // GET /servers
    if (method === 'GET' && path === '/servers') {
      return this._handleListServers(params);
    }

    // GET /servers/:id
    if (method === 'GET' && path.startsWith('/servers/')) {
      const serverId = path.split('/')[2];
      return this._handleGetServer(serverId);
    }

    // POST /register
    if (method === 'POST' && path === '/register') {
      return this._handleRegister(body);
    }

    // POST /topic/:serverId
    if (method === 'POST' && path.startsWith('/topic/')) {
      const serverId = path.split('/')[2];
      return this._handleTopic(serverId, body);
    }

    // POST /world/save
    if (method === 'POST' && path === '/world/save') {
      return this._handleWorldSave(body);
    }

    // GET /world/load/:cid
    if (method === 'GET' && path.startsWith('/world/load/')) {
      const cid = path.split('/')[3];
      return this._handleWorldLoad(cid);
    }

    // GET /doko/:ckey
    if (method === 'GET' && path.startsWith('/doko/')) {
      const ckey = path.split('/')[2];
      return this._handleGetDoko(ckey);
    }

    // POST /doko/create
    if (method === 'POST' && path === '/doko/create') {
      return this._handleCreateDoko(body);
    }

    // POST /doko/verify
    if (method === 'POST' && path === '/doko/verify') {
      return this._handleVerifyDoko(body);
    }

    // 404
    const err = new Error(`Not found: ${method} ${path}`);
    err.statusCode = 404;
    throw err;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  _handleStatus() {
    return {
      status: 'online',
      uptime: Date.now() - this.stats.startTime,
      adapter: {
        initialized: this.adapter.isInitialized,
        localServers: this.adapter.localServers.size,
        remoteServers: this.adapter.remoteServers.size,
        stats: this.adapter.stats,
      },
      bridge: {
        requestsTotal: this.stats.requestsTotal,
        errors: this.stats.errors,
      },
    };
  }

  _handleListServers(params) {
    const filter = {};
    if (params.get('gameId')) filter.gameId = params.get('gameId');
    if (params.get('status')) filter.status = params.get('status');
    if (params.get('tag')) filter.tag = params.get('tag');

    const servers = this.adapter.getServers(filter);
    return {
      count: servers.length,
      servers: servers.map(s => s.toJSON()),
    };
  }

  _handleGetServer(serverId) {
    const server = this.adapter.localServers.get(serverId) ||
                   this.adapter.remoteServers.get(serverId);
    
    if (!server) {
      const err = new Error(`Server not found: ${serverId}`);
      err.statusCode = 404;
      throw err;
    }

    return server.toJSON();
  }

  async _handleRegister(body) {
    if (!body || !body.gameId || !body.host || !body.port) {
      const err = new Error('Missing required fields: gameId, host, port');
      err.statusCode = 400;
      throw err;
    }

    const server = await this.adapter.registerServer({
      gameId: body.gameId,
      host: body.host,
      port: body.port,
      name: body.name,
      description: body.description,
      version: body.version,
      maxPlayers: body.maxPlayers,
      tags: body.tags,
      metadata: body.metadata,
    });

    return {
      success: true,
      serverId: server.id,
      server: server.toJSON(),
    };
  }

  async _handleTopic(serverId, body) {
    if (!body || !body.topic) {
      const err = new Error('Missing required field: topic');
      err.statusCode = 400;
      throw err;
    }

    const response = await this.adapter.sendTopic(serverId, body.topic);
    return {
      success: true,
      response,
    };
  }

  async _handleWorldSave(body) {
    if (!body || !body.serverId || !body.data) {
      const err = new Error('Missing required fields: serverId, data');
      err.statusCode = 400;
      throw err;
    }

    // Data can be base64 encoded or raw string
    let worldData = body.data;
    if (body.encoding === 'base64') {
      worldData = Buffer.from(body.data, 'base64');
    }

    const result = await this.adapter.saveWorld(
      body.serverId,
      worldData,
      body.metadata || {}
    );

    return {
      success: true,
      cid: result.cid,
      hash: result.hash,
    };
  }

  async _handleWorldLoad(cid) {
    const data = await this.adapter.loadWorld(cid);
    return {
      success: true,
      data: data.toString('base64'),
      encoding: 'base64',
      size: data.length,
    };
  }

  _handleGetDoko(ckey) {
    if (!this.adapter.security) {
      const err = new Error('Security module not initialized');
      err.statusCode = 503;
      throw err;
    }

    const doko = this.adapter.security.getPlayerDoko(ckey);
    if (!doko) {
      return { exists: false, ckey };
    }

    return {
      exists: true,
      ckey,
      dokoId: doko.dokoId,
      claims: doko.claims,
      created: doko.created,
    };
  }

  _handleCreateDoko(body) {
    if (!body || !body.ckey) {
      const err = new Error('Missing required field: ckey');
      err.statusCode = 400;
      throw err;
    }

    if (!this.adapter.security) {
      const err = new Error('Security module not initialized');
      err.statusCode = 503;
      throw err;
    }

    const result = this.adapter.security.createPlayerDoko(body.ckey, {
      claims: body.claims || {},
    });

    if (!result.success) {
      const err = new Error(result.error);
      err.statusCode = 409;
      throw err;
    }

    return {
      success: true,
      dokoId: result.dokoId,
      // IMPORTANT: Secret key returned only on creation
      secretKey: result.secretKey,
    };
  }

  _handleVerifyDoko(body) {
    if (!body || !body.ckey || !body.challenge || !body.signature) {
      const err = new Error('Missing required fields: ckey, challenge, signature');
      err.statusCode = 400;
      throw err;
    }

    if (!this.adapter.security) {
      const err = new Error('Security module not initialized');
      err.statusCode = 503;
      throw err;
    }

    const result = this.adapter.security.players.verifyPlayerSignature(
      body.ckey,
      body.challenge,
      body.signature
    );

    return {
      valid: result.valid,
      dokoId: result.dokoId,
      error: result.error,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  async _parseBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => { data += chunk; });
      req.on('end', () => {
        if (!data) {
          resolve(null);
          return;
        }
        
        try {
          // Try JSON first
          resolve(JSON.parse(data));
        } catch {
          // Try URL-encoded (BYOND's default)
          const params = new URLSearchParams(data);
          const obj = {};
          for (const [key, value] of params) {
            obj[key] = value;
          }
          resolve(obj);
        }
      });
      req.on('error', reject);
    });
  }

  _sendJson(res, code, data) {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  _sendError(res, code, message) {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message, code }));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create and start an HTTP bridge for a BYOND adapter
 * @param {BYONDAdapter} adapter - The BYOND adapter
 * @param {Object} options - Bridge options
 * @returns {Promise<BYONDHttpBridge>} Started bridge
 */
export async function createHttpBridge(adapter, options = {}) {
  const bridge = new BYONDHttpBridge(adapter, options);
  await bridge.start();
  return bridge;
}

export default BYONDHttpBridge;
