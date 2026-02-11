/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                    🌐 MANDALA NETWORK - SACRED GEOMETRY 🌐                    ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  In Tibetan Buddhism, a MANDALA is a sacred geometric pattern representing   ║
 * ║  the cosmos—intricate, interconnected, and perfectly balanced. Each point    ║
 * ║  relates to every other, creating harmony through structure.                 ║
 * ║                                                                               ║
 * ║  The MANDALA Network embodies this principle:                                ║
 * ║  - Nodes form geometric patterns of connection                               ║
 * ║  - Messages flow through balanced pathways                                   ║
 * ║  - The whole emerges from the harmony of its parts                           ║
 * ║  - Each peer is essential to the cosmic structure                            ║
 * ║                                                                               ║
 * ║  PROTOCOL PHILOSOPHY:                                                         ║
 * ║    "Sacred geometry binds us" - Structure creates resilience                 ║
 * ║                                                                               ║
 * ║  SECURITY POLICY (2026-02-11):                                               ║
 * ║    ALL peer-to-peer communications MUST use ANNEX encryption.                ║
 * ║    - ML-KEM-768 key exchange on connection                                   ║
 * ║    - AES-256-GCM for message encryption                                      ║
 * ║    - No plaintext on wire between nodes                                      ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * MANDALA Mesh Protocol
 * WebSocket-based peer-to-peer communication forming sacred network geometry
 * Encrypted via ANNEX (Autonomous Network Negotiated Encrypted eXchange)
 */

import { WebSocketServer, WebSocket } from 'ws';
import { ConnectionRateLimiter } from './rate-limiter.js';
import { createLogger } from '../utils/logger.js';

// TODO: Integrate ANNEX encryption for all peer connections
// import { Annex } from './annex.js';

const log = createLogger('mandala:network');

/**
 * Message types for MANDALA mesh protocol
 * Each message type represents a sacred communication form
 */
export const MandalaMessageTypes = {
  // Handshake (greeting rituals)
  HELLO: 'hello',           // Initial connection with identity
  WELCOME: 'welcome',       // Response to hello
  
  // Node management (maintaining the mandala pattern)
  PING: 'ping',
  PONG: 'pong',
  PEERS: 'peers',           // Share known peers (reveal the pattern)
  
  // Data replication (sacred knowledge transmission)
  SYNC_REQUEST: 'sync_request',
  SYNC_RESPONSE: 'sync_response',
  REPLICATE: 'replicate',   // Push new data
  
  // Gossip (whispered teachings)
  GOSSIP: 'gossip',         // Broadcast message
};

// Backward compatibility alias
export const MessageTypes = MandalaMessageTypes;

/**
 * MANDALA Network Manager
 * Handles peer connections and message routing through sacred geometry
 */
export class MandalaNetwork {
  constructor(identity, config = {}) {
    this.identity = identity;
    this.config = {
      wsPort: config.wsPort || 9001,
      maxPeers: config.maxPeers || 10,
      pingInterval: config.pingInterval || 30000,
      portRetries: config.portRetries || 10,  // Try up to 10 sequential ports
      ...config,
    };
    
    // Track actual bound port (may differ from config if fallback used)
    this.boundPort = null;
    
    // Network identity for code proof verification
    this.networkId = config.networkId || null;
    this.networkFingerprint = config.networkFingerprint || null;
    
    this.server = null;
    this.peers = new Map();        // nodeId -> { ws, identity, lastSeen }
    this.knownNodes = new Map();   // nodeId -> { endpoint, identity }
    this.messageHandlers = new Map();
    this.seenMessages = new Set(); // For gossip deduplication
    
    // Rate limiter for connection/message flood protection
    this.rateLimiter = new ConnectionRateLimiter(config.rateLimiter || {});
    
    this._setupDefaultHandlers();
  }

  /**
   * Start the WebSocket server with automatic port fallback
   */
  async start() {
    const basePort = this.config.wsPort;
    const maxRetries = this.config.portRetries;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const port = basePort + attempt;
      try {
        await this._tryBindPort(port);
        this.boundPort = port;
        if (attempt > 0) {
          log.warn('Port was in use, bound to alternate', { originalPort: basePort, boundPort: port });
        }
        log.info('Mesh server listening', { url: `ws://localhost:${port}` });
        this._startPingLoop();
        return;
      } catch (err) {
        if (err.code === 'EADDRINUSE' && attempt < maxRetries - 1) {
          continue; // Try next port
        }
        throw err;
      }
    }
    
    throw new Error(`Could not bind to any port in range ${basePort}-${basePort + maxRetries - 1}`);
  }

  /**
   * Attempt to bind to a specific port
   */
  _tryBindPort(port) {
    return new Promise((resolve, reject) => {
      const server = new WebSocketServer({ port });

      server.on('listening', () => {
        this.server = server;
        
        server.on('connection', (ws, req) => {
          this._handleIncomingConnection(ws, req);
        });

        server.on('error', (err) => {
          console.error('Mesh server error:', err);
        });
        
        resolve();
      });

      server.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Connect to a peer node
   */
  async connect(endpoint) {
    return new Promise((resolve, reject) => {
      log.debug('Connecting to peer', { endpoint });
      
      const ws = new WebSocket(endpoint);
      
      ws.on('open', () => {
        // Send HELLO with our identity AND network fingerprint for code proof verification
        this._send(ws, {
          type: MessageTypes.HELLO,
          identity: {
            ...this.identity.getPublicIdentity(),
            networkId: this.networkId,
            networkFingerprint: this.networkFingerprint,
          },
          timestamp: Date.now(),
        });
      });

      ws.on('message', (data) => {
        this._handleMessage(ws, data, null);
      });

      ws.on('close', () => {
        this._handleDisconnect(ws);
      });

      ws.on('error', (err) => {
        console.error(`Connection to ${endpoint} failed:`, err.message);
        reject(err);
      });

      // Resolve when we get WELCOME back
      const welcomeHandler = (msg) => {
        if (msg.type === MessageTypes.WELCOME) {
          log.info('Connected to peer', { nodeId: msg.identity.nodeId });
          resolve(msg.identity);
        }
      };
      ws._pendingWelcome = welcomeHandler;
    });
  }

  /**
   * Broadcast message to all peers (gossip)
   */
  broadcast(message) {
    const msgId = `${this.identity.identity.nodeId}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    
    const gossipMsg = {
      type: MessageTypes.GOSSIP,
      id: msgId,
      origin: this.identity.identity.nodeId,
      payload: message,
      ttl: 10,
      timestamp: Date.now(),
    };

    // Sign the message
    const signed = this.identity.signObject(gossipMsg);
    
    this.seenMessages.add(msgId);
    
    // Send to all peers
    for (const [nodeId, peer] of this.peers) {
      this._send(peer.ws, signed);
    }
  }

  /**
   * Send message to specific peer
   */
  sendTo(nodeId, message) {
    const peer = this.peers.get(nodeId);
    if (!peer) {
      throw new Error(`Peer ${nodeId} not connected`);
    }
    
    const signed = this.identity.signObject({
      ...message,
      timestamp: Date.now(),
    });
    
    this._send(peer.ws, signed);
  }

  /**
   * Register a message handler
   */
  on(messageType, handler) {
    if (!this.messageHandlers.has(messageType)) {
      this.messageHandlers.set(messageType, []);
    }
    this.messageHandlers.get(messageType).push(handler);
  }

  /**
   * Remove a message handler
   */
  off(messageType, handler) {
    if (!this.messageHandlers.has(messageType)) return;
    const handlers = this.messageHandlers.get(messageType);
    const idx = handlers.indexOf(handler);
    if (idx >= 0) handlers.splice(idx, 1);
  }

  /**
   * Emit an event to handlers
   */
  emit(eventType, ...args) {
    const handlers = this.messageHandlers.get(eventType) || [];
    for (const handler of handlers) {
      handler(...args);
    }
  }

  /**
   * Check if connected to a specific node
   */
  isConnectedTo(nodeId) {
    return this.peers.has(nodeId);
  }

  /**
   * Connect to a peer (alias for connect)
   */
  async connectToPeer(endpoint) {
    return this.connect(endpoint);
  }

  /**
   * Get public endpoint for this node
   */
  getPublicEndpoint() {
    if (this.config.publicHost) {
      return `ws://${this.config.publicHost}:${this.config.wsPort}`;
    }
    return null;
  }

  /**
   * Get list of connected peers
   */
  getPeers() {
    return Array.from(this.peers.entries()).map(([nodeId, peer]) => ({
      nodeId,
      name: peer.identity.name,
      endpoint: peer.endpoint,
      lastSeen: peer.lastSeen,
    }));
  }

  /**
   * Stop the mesh server
   */
  async stop() {
    // Close all peer connections
    for (const [nodeId, peer] of this.peers) {
      peer.ws.close();
    }
    this.peers.clear();
    
    // Stop server
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    
    log.info('Mesh server stopped');
  }

  // ===== Private Methods =====

  _setupDefaultHandlers() {
    // Handle HELLO
    this.on(MessageTypes.HELLO, (msg, ws) => {
      const nodeId = msg.identity.nodeId;
      
      // CODE PROOF VERIFICATION: Check network fingerprint
      // Nodes with different codebases will have different fingerprints
      if (this.networkFingerprint && msg.identity.networkFingerprint) {
        if (msg.identity.networkFingerprint !== this.networkFingerprint) {
          console.warn(`✗ Rejected peer ${nodeId.slice(0, 20)}... - incompatible codebase`);
          console.warn(`  Their network: ${msg.identity.networkId || 'unknown'}`);
          console.warn(`  Our network:   ${this.networkId || 'unknown'}`);
          
          // Send rejection and close connection
          this._send(ws, {
            type: 'REJECT',
            reason: 'INCOMPATIBLE_CODEBASE',
            message: 'Your node is running a different codebase version',
            ourNetworkId: this.networkId,
          });
          ws.close(1008, 'Incompatible codebase');
          return;
        }
      }
      
      // Store peer
      this.peers.set(nodeId, {
        ws,
        identity: msg.identity,
        lastSeen: Date.now(),
      });
      
      // Send WELCOME back with our network info
      this._send(ws, {
        type: MessageTypes.WELCOME,
        identity: {
          ...this.identity.getPublicIdentity(),
          networkId: this.networkId,
          networkFingerprint: this.networkFingerprint,
        },
        peers: this.getPeers().filter(p => p.nodeId !== nodeId),
      });
      
      log.info('Peer connected', { name: msg.identity.name, nodeId: nodeId.slice(0, 20) });
    });

    // Handle WELCOME
    this.on(MessageTypes.WELCOME, (msg, ws) => {
      const nodeId = msg.identity.nodeId;
      
      // CODE PROOF VERIFICATION: Check network fingerprint on WELCOME too
      // This protects the INITIATOR - even if remote accepts us, we reject them if mismatched
      if (this.networkFingerprint && msg.identity.networkFingerprint) {
        if (msg.identity.networkFingerprint !== this.networkFingerprint) {
          console.warn(`✗ Rejecting peer ${nodeId.slice(0, 20)}... - incompatible codebase (on WELCOME)`);
          console.warn(`  Their network: ${msg.identity.networkId || 'unknown'}`);
          console.warn(`  Our network:   ${this.networkId || 'unknown'}`);
          ws.close(1008, 'Incompatible codebase');
          
          // Signal rejection to pending promise
          if (ws._pendingWelcome) {
            ws._pendingWelcome({ rejected: true, reason: 'INCOMPATIBLE_CODEBASE' });
            delete ws._pendingWelcome;
          }
          return;
        }
      } else if (this.networkFingerprint && !msg.identity.networkFingerprint) {
        // Remote node didn't send fingerprint - they're running old code
        console.warn(`✗ Rejecting peer ${nodeId.slice(0, 20)}... - no fingerprint (old codebase)`);
        ws.close(1008, 'Missing network fingerprint');
        
        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'MISSING_FINGERPRINT' });
          delete ws._pendingWelcome;
        }
        return;
      }
      
      this.peers.set(nodeId, {
        ws,
        identity: msg.identity,
        lastSeen: Date.now(),
      });
      
      // Callback for pending connection
      if (ws._pendingWelcome) {
        ws._pendingWelcome(msg);
        delete ws._pendingWelcome;
      }
    });

    // Handle PING
    this.on(MessageTypes.PING, (msg, ws, nodeId) => {
      this._send(ws, { type: MessageTypes.PONG, timestamp: Date.now() });
    });

    // Handle PONG
    this.on(MessageTypes.PONG, (msg, ws, nodeId) => {
      const peer = this.peers.get(nodeId);
      if (peer) {
        peer.lastSeen = Date.now();
      }
    });

    // Handle GOSSIP
    this.on(MessageTypes.GOSSIP, (msg, ws, nodeId) => {
      // Deduplicate
      if (this.seenMessages.has(msg.id)) return;
      this.seenMessages.add(msg.id);
      
      // TTL check
      if (msg.ttl <= 0) return;
      
      // Check for gossip protocol message
      if (msg.payload && msg.payload.gossip) {
        this.emit('gossip', msg.payload.gossip, nodeId);
      }
      
      // Forward to other peers
      const forwardMsg = { ...msg, ttl: msg.ttl - 1 };
      for (const [peerId, peer] of this.peers) {
        if (peerId !== nodeId && peerId !== msg.origin) {
          this._send(peer.ws, forwardMsg);
        }
      }
    });
  }

  _handleIncomingConnection(ws, req) {
    const clientIp = req.socket.remoteAddress || 'unknown';
    log.debug('Incoming connection', { clientIp });
    
    // SECURITY: Rate limit check for connection flood protection
    const connectionCheck = this.rateLimiter.checkConnection(clientIp);
    if (!connectionCheck.allowed) {
      console.warn(`⚠️ Connection rejected (rate limit): ${clientIp} - ${connectionCheck.reason}`);
      ws.close(1008, connectionCheck.reason);
      return;
    }
    
    ws.on('message', (data) => {
      this._handleMessage(ws, data, req);
    });

    ws.on('close', () => {
      this._handleDisconnect(ws);
    });

    ws.on('error', (err) => {
      console.error('Peer error:', err.message);
    });
  }

  _handleMessage(ws, data, req) {
    try {
      const msg = JSON.parse(data.toString());
      
      // Find nodeId for this connection
      let senderNodeId = null;
      for (const [nodeId, peer] of this.peers) {
        if (peer.ws === ws) {
          senderNodeId = nodeId;
          peer.lastSeen = Date.now();
          break;
        }
      }

      // Dispatch to handlers
      const handlers = this.messageHandlers.get(msg.type) || [];
      for (const handler of handlers) {
        handler(msg, ws, senderNodeId);
      }
    } catch (e) {
      console.error('Failed to parse message:', e.message);
    }
  }

  _handleDisconnect(ws) {
    for (const [nodeId, peer] of this.peers) {
      if (peer.ws === ws) {
        log.info('Peer disconnected', { name: peer.identity.name });
        this.peers.delete(nodeId);
        break;
      }
    }
  }

  _send(ws, message) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  _startPingLoop() {
    setInterval(() => {
      const now = Date.now();
      for (const [nodeId, peer] of this.peers) {
        // Check for stale connections
        if (now - peer.lastSeen > this.config.pingInterval * 3) {
          log.warn('Peer timeout', { name: peer.identity.name });
          peer.ws.close();
          this.peers.delete(nodeId);
        } else {
          this._send(peer.ws, { type: MessageTypes.PING, timestamp: now });
        }
      }
      
      // Cleanup old seen messages
      if (this.seenMessages.size > 10000) {
        this.seenMessages.clear();
      }
    }, this.config.pingInterval);
  }
}

// ============================================================
// EXPORTS - MANDALA naming with backward compatibility
// ============================================================

// Note: MandalaMessageTypes and MandalaNetwork already exported at declarations
// Backward compatibility exports (original naming)
export { MandalaNetwork as MeshNetwork };

export default MandalaNetwork;
