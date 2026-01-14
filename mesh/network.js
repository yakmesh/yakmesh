/**
 * Lantern Mesh Protocol
 * WebSocket-based peer-to-peer communication
 */

import { WebSocketServer, WebSocket } from 'ws';

/**
 * Message types for mesh protocol
 */
export const MessageTypes = {
  // Handshake
  HELLO: 'hello',           // Initial connection with identity
  WELCOME: 'welcome',       // Response to hello
  
  // Node management
  PING: 'ping',
  PONG: 'pong',
  PEERS: 'peers',           // Share known peers
  
  // Data replication
  SYNC_REQUEST: 'sync_request',
  SYNC_RESPONSE: 'sync_response',
  REPLICATE: 'replicate',   // Push new data
  
  // Gossip
  GOSSIP: 'gossip',         // Broadcast message
};

/**
 * Mesh Network Manager
 * Handles peer connections and message routing
 */
export class MeshNetwork {
  constructor(identity, config = {}) {
    this.identity = identity;
    this.config = {
      wsPort: config.wsPort || 9001,
      maxPeers: config.maxPeers || 10,
      pingInterval: config.pingInterval || 30000,
      ...config,
    };
    
    this.server = null;
    this.peers = new Map();        // nodeId -> { ws, identity, lastSeen }
    this.knownNodes = new Map();   // nodeId -> { endpoint, identity }
    this.messageHandlers = new Map();
    this.seenMessages = new Set(); // For gossip deduplication
    
    this._setupDefaultHandlers();
  }

  /**
   * Start the WebSocket server
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = new WebSocketServer({ 
        port: this.config.wsPort,
      });

      this.server.on('listening', () => {
        console.log(`✓ Mesh server listening on ws://localhost:${this.config.wsPort}`);
        resolve();
      });

      this.server.on('connection', (ws, req) => {
        this._handleIncomingConnection(ws, req);
      });

      this.server.on('error', (err) => {
        console.error('Mesh server error:', err);
        reject(err);
      });

      // Start ping interval
      this._startPingLoop();
    });
  }

  /**
   * Connect to a peer node
   */
  async connect(endpoint) {
    return new Promise((resolve, reject) => {
      console.log(`→ Connecting to ${endpoint}...`);
      
      const ws = new WebSocket(endpoint);
      
      ws.on('open', () => {
        // Send HELLO with our identity
        this._send(ws, {
          type: MessageTypes.HELLO,
          identity: this.identity.getPublicIdentity(),
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
          console.log(`✓ Connected to ${msg.identity.nodeId}`);
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
    
    console.log('✓ Mesh server stopped');
  }

  // ===== Private Methods =====

  _setupDefaultHandlers() {
    // Handle HELLO
    this.on(MessageTypes.HELLO, (msg, ws) => {
      const nodeId = msg.identity.nodeId;
      
      // Store peer
      this.peers.set(nodeId, {
        ws,
        identity: msg.identity,
        lastSeen: Date.now(),
      });
      
      // Send WELCOME back
      this._send(ws, {
        type: MessageTypes.WELCOME,
        identity: this.identity.getPublicIdentity(),
        peers: this.getPeers().filter(p => p.nodeId !== nodeId),
      });
      
      console.log(`✓ Peer connected: ${msg.identity.name} (${nodeId.slice(0, 20)}...)`);
    });

    // Handle WELCOME
    this.on(MessageTypes.WELCOME, (msg, ws) => {
      const nodeId = msg.identity.nodeId;
      
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
    console.log(`← Incoming connection from ${req.socket.remoteAddress}`);
    
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
        console.log(`✗ Peer disconnected: ${peer.identity.name}`);
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
          console.log(`✗ Peer timeout: ${peer.identity.name}`);
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

export default MeshNetwork;
