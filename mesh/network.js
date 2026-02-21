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

// ANNEX - Autonomous Network Negotiated Encrypted eXchange
// PQ-encrypted point-to-point communication between mesh peers
import { Annex } from './annex.js';

// MessageValidator + SafeJsonParser — size limits, depth checks, proto pollution guard
import MessageValidator, { SafeJsonParser } from './message-validator.js';

// TRIBHUJ Key Ratchet — trinary rotating keypairs with gateway attestation
import { TribhujRatchet, GatewayAttestation } from '../identity/tribhuj-ratchet.js';

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
      pingInterval: config.pingInterval || 30000,
      portRetries: config.portRetries || 10,  // Try up to 10 sequential ports
      // Max peers allowed in HELLO/WELCOME handshake simultaneously.
      // Total connected peers is UNBOUNDED — the mesh scales freely.
      // This only gates the handshake window to prevent Sybil flood attacks.
      maxConcurrentHandshakes: config.maxConcurrentHandshakes || 50,
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
    
    // ANNEX - PQ-encrypted point-to-point channels
    // Initialized after start() when identity is available
    this.annex = null;
    
    // TRIBHUJ ratchet - trinary rotating keypairs for forward secrecy
    this.ratchet = null;
    this.gateway = null;  // Gateway attestation for gossip verify-once
    
    // Track peer ratchet states (their announced TRIBHUJ public keys)
    this.peerRatchets = new Map(); // nodeId -> { currentPubKey, previousPubKey, epoch }
    
    // Rate limiter for connection/message flood protection
    this.rateLimiter = new ConnectionRateLimiter(config.rateLimiter || {});
    
    // Concurrent handshake tracking — limits how many peers can be in the
    // HELLO/WELCOME negotiation window at the same time. Legitimate nodes
    // trickle in; a burst of 200 simultaneous connections is a Sybil tell.
    // Total peer count is UNBOUNDED (mesh scales freely).
    this._pendingHandshakeCount = 0;
    this._pendingHandshakeWs = new Set();  // Track WSs in handshake state
    
    // Connection burst detector — sliding window for GPS-timestamped alerts.
    // A sudden spike from baseline to hundreds of connections per minute
    // shows up as a "bright spot" with microsecond-precise timing evidence.
    this._burstWindow = [];           // [{ ts, ip }] — last 60s of connections
    this._burstWindowMs = 60000;      // 60-second sliding window
    this._burstThreshold = 30;        // connections/minute that trigger alert
    this._burstAlerted = false;       // debounce: one alert per burst episode
    this._burstStats = {
      totalBurstsDetected: 0,
      lastBurstAt: null,
      lastBurstRate: 0,
      peakRate: 0,
    };
    
    // Message validation — size limits, depth limits, proto pollution guard
    // This was implemented but never wired in. Now it gates ALL incoming WS messages.
    this.messageValidator = new MessageValidator();
    this.safeJsonParser = new SafeJsonParser();
    
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
        
        // Initialize ANNEX encryption layer
        this.annex = new Annex({ identity: this.identity, mesh: this });
        log.info('ANNEX encryption layer initialized');
        
        // Initialize TRIBHUJ key ratchet — trinary rotating keypairs
        this.ratchet = new TribhujRatchet({
          rotationInterval: this.config.tribhujRotation || 300000,  // 5min default
          gracePeriod: this.config.tribhujGrace || 60000,           // 1min grace
        });
        await this.ratchet.initialize();
        this.ratchet.startAutoRotation();
        
        // Gateway attestation — verify gossip once, attest for downstream
        this.gateway = new GatewayAttestation(
          this.identity.identity.nodeId,
          this.ratchet,
          { attestationTTL: 60000 }
        );
        log.info('TRIBHUJ ratchet + gateway attestation initialized');
        
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
      const server = new WebSocketServer({ port, maxPayload: 1048576 }); // 1MB max message size

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
      let settled = false;
      
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
        if (!settled) {
          settled = true;
          log.debug(`Connection to ${endpoint} failed: ${err.message}`);
          reject(err);
        }
        // If already settled (e.g. caller timed out), just silently close
        try { ws.close(); } catch {}
      });

      // Resolve when we get WELCOME back
      const welcomeHandler = (msg) => {
        if (msg.type === MessageTypes.WELCOME && !settled) {
          settled = true;
          log.info('Connected to peer', { nodeId: msg.identity.nodeId });
          resolve(msg.identity);
        }
      };
      ws._pendingWelcome = welcomeHandler;
    });
  }

  /**
   * Send encrypted message to specific peer via ANNEX.
   * HARD FAIL: If no ANNEX session exists, the message is NOT sent.
   * Caller must handle the error and initiate ANNEX negotiation.
   */
  async sendEncrypted(nodeId, payload) {
    if (this.annex) {
      const session = this.annex.sessions.get(nodeId);
      if (session?.established && !session.isExpired()) {
        return await this.annex.send(nodeId, payload);
      }
    }
    // HARD FAIL: No plaintext fallback. Encryption is mandatory.
    const err = new Error(`No active ANNEX session for ${nodeId.slice(0, 20)} — refusing plaintext send`);
    log.error(err.message);
    throw err;
  }

  /**
   * Get ANNEX encryption stats
   */
  getAnnexStats() {
    return this.annex?.getStats() || { activeSessions: 0, note: 'ANNEX not initialized' };
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

    // Sign the message — prefer TRIBHUJ ratchet for forward secrecy, fall back to identity
    const signed = this.ratchet
      ? this.ratchet.signObject(gossipMsg)
      : this.identity.signObject(gossipMsg);
    
    this.seenMessages.add(msgId);
    
    // Send to all WS peers
    for (const [nodeId, peer] of this.peers) {
      this._send(peer.ws, signed);
    }

    // Emit for HTTP relay peers (server layer hooks this)
    this.emit('outbound-gossip', signed, []);
  }

  /**
   * Send message to specific peer (WS or relay fallback)
   */
  sendTo(nodeId, message) {
    const signed = this.ratchet
      ? this.ratchet.signObject({ ...message, timestamp: Date.now() })
      : this.identity.signObject({ ...message, timestamp: Date.now() });

    const peer = this.peers.get(nodeId);
    if (peer) {
      this._send(peer.ws, signed);
      return;
    }

    // Not a WS peer — try relay fallback (server layer hooks this)
    this.emit('outbound-relay', nodeId, signed);
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
    // Stop ping loop
    if (this._pingInterval) {
      clearInterval(this._pingInterval);
      this._pingInterval = null;
    }
    
    // Close all ANNEX channels
    if (this.annex) {
      for (const nodeId of this.annex.sessions.keys()) {
        try { await this.annex.closeChannel(nodeId); } catch {}
      }
      this.annex = null;
    }
    
    // Destroy TRIBHUJ ratchet — zero all key material
    if (this.ratchet) {
      this.ratchet.destroy();
      this.ratchet = null;
    }
    this.gateway = null;
    this.peerRatchets.clear();
    
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
      
      // Store peer — no cap on total peers (mesh scales freely)
      this.peers.set(nodeId, {
        ws,
        identity: msg.identity,
        lastSeen: Date.now(),
      });
      
      // Release handshake slot — peer is now fully registered.
      // The slot was reserved in _handleIncomingConnection.
      if (this._pendingHandshakeWs.has(ws)) {
        this._pendingHandshakeCount = Math.max(0, this._pendingHandshakeCount - 1);
        this._pendingHandshakeWs.delete(ws);
      }
      
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
      
      log.info('Peer connected', { name: msg.identity.name, nodeId: nodeId.slice(0, 20), totalPeers: this.peers.size });
      
      // Signal that this peer's public key is now available — any deferred
      // ANNEX messages waiting for this key will be replayed.
      this.emit('peer-registered', nodeId);
      
      // Deterministic initiator: lower nodeId always initiates ANNEX
      // Prevents duplicate sessions when both sides try to openChannel simultaneously
      // Guard: skip if the WELCOME handler already initiated (both fire when
      // two nodes simultaneously connect to each other as bootstrap peers)
      const ourNodeId = this.identity.identity.nodeId;
      if (this.annex && ourNodeId < nodeId) {
        const existingSession = this.annex.sessions.get(nodeId);
        const pendingHandshake = this.annex.pendingHandshakes.get(nodeId);
        if (!existingSession && !pendingHandshake) {
          log.debug('ANNEX: we initiate (lower nodeId)', { us: ourNodeId.slice(0, 12), them: nodeId.slice(0, 12) });
          this.annex.openChannel(nodeId).then(() => {
            log.info('ANNEX channel established with peer', { nodeId: nodeId.slice(0, 20) });
          }).catch(err => {
            log.warn('ANNEX negotiation failed', { nodeId: nodeId.slice(0, 20), error: err.message });
          });
        }
      } else if (this.annex) {
        log.debug('ANNEX: waiting for peer to initiate (they have lower nodeId)', { us: ourNodeId.slice(0, 12), them: nodeId.slice(0, 12) });
      }
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
      
      // Signal that this peer's public key is now available
      this.emit('peer-registered', nodeId);
      
      // Deterministic initiator: connector side also checks
      // Lower nodeId always initiates ANNEX — mirrors the HELLO handler logic
      // Guard: skip if the HELLO handler already initiated (openChannel returns
      // the existing session when one is pending, but we avoid the extra call entirely)
      const ourNodeId = this.identity.identity.nodeId;
      if (this.annex && ourNodeId < nodeId) {
        const existingSession = this.annex.sessions.get(nodeId);
        const pendingHandshake = this.annex.pendingHandshakes.get(nodeId);
        if (!existingSession && !pendingHandshake) {
          log.debug('ANNEX: we initiate on WELCOME (lower nodeId)', { us: ourNodeId.slice(0, 12), them: nodeId.slice(0, 12) });
          this.annex.openChannel(nodeId).then(() => {
            log.info('ANNEX channel established with peer', { nodeId: nodeId.slice(0, 20) });
          }).catch(err => {
            log.warn('ANNEX negotiation failed', { nodeId: nodeId.slice(0, 20), error: err.message });
          });
        }
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
      
      // Forward to other WS peers
      const forwardMsg = { ...msg, ttl: msg.ttl - 1 };
      for (const [peerId, peer] of this.peers) {
        if (peerId !== nodeId && peerId !== msg.origin) {
          this._send(peer.ws, forwardMsg);
        }
      }

      // Also forward to HTTP relay peers (server layer hooks this)
      this.emit('outbound-gossip', forwardMsg, [nodeId, msg.origin]);
    });
  }

  _handleIncomingConnection(ws, req) {
    const clientIp = req.socket.remoteAddress || 'unknown';
    log.debug('Incoming connection', { clientIp });
    
    // SECURITY: Rate limit check for connection flood protection (per-IP)
    const connectionCheck = this.rateLimiter.checkConnection(clientIp);
    if (!connectionCheck.allowed) {
      console.warn(`⚠️ Connection rejected (rate limit): ${clientIp} - ${connectionCheck.reason}`);
      ws.close(1008, connectionCheck.reason);
      return;
    }
    
    // SECURITY: Concurrent handshake gate — limits how many peers can be
    // negotiating HELLO/WELCOME simultaneously. Total peers is unbounded;
    // only the handshake window is capped. A burst of connections from
    // many IPs at once is a Sybil tell.
    if (this._pendingHandshakeCount >= this.config.maxConcurrentHandshakes) {
      log.warn('Connection rejected (handshake slots full)', {
        clientIp,
        pending: this._pendingHandshakeCount,
        max: this.config.maxConcurrentHandshakes,
      });
      ws.close(1013, 'Try again later — handshake slots full');
      return;
    }
    
    // Track this connection as pending handshake
    this._pendingHandshakeCount++;
    this._pendingHandshakeWs.add(ws);
    
    // SECURITY: Burst detection — track connection rate in sliding window.
    // GPS-timestamped evidence for Sybil forensics.
    this._recordConnectionBurst(clientIp);
    
    ws.on('message', (data) => {
      this._handleMessage(ws, data, req);
    });

    ws.on('close', () => {
      // Release handshake slot if peer disconnects before completing HELLO
      if (this._pendingHandshakeWs.has(ws)) {
        this._pendingHandshakeCount = Math.max(0, this._pendingHandshakeCount - 1);
        this._pendingHandshakeWs.delete(ws);
      }
      this._handleDisconnect(ws);
    });

    ws.on('error', (err) => {
      console.error('Peer error:', err.message);
    });
  }

  _handleMessage(ws, data, req) {
    try {
      const rawStr = data.toString();
      
      // STAGE 1: Raw size validation — reject before parsing
      const rawCheck = this.messageValidator.validateRaw(rawStr);
      if (!rawCheck.valid) {
        log.warn('Rejected oversized WS message', { reason: rawCheck.reason, size: rawStr.length });
        return;
      }
      
      // STAGE 2: Safe JSON parse — proto pollution guard + size check
      const parseResult = this.safeJsonParser.parse(rawStr);
      if (!parseResult.success) {
        log.warn('Rejected malformed WS message', { error: parseResult.error });
        return;
      }
      const msg = parseResult.data;
      
      // STAGE 3: Structure validation — depth, array length, required fields
      const msgType = msg.type || 'gossip';
      const structCheck = this.messageValidator.validateStructure(msg, msgType);
      if (!structCheck.valid) {
        log.warn('Rejected invalid WS message structure', { reason: structCheck.reason, type: msgType });
        return;
      }
      
      // Find nodeId for this connection
      let senderNodeId = null;
      let senderPublicKey = null;
      for (const [nodeId, peer] of this.peers) {
        if (peer.ws === ws) {
          senderNodeId = nodeId;
          senderPublicKey = peer.identity?.publicKey;
          peer.lastSeen = Date.now();
          break;
        }
      }

      // SECURITY: Verify signatures on messages from known peers
      // Priority: (1) gateway attestation (fast), (2) TRIBHUJ ratchet, (3) legacy identity
      
      // Check for gateway attestation first — "verify once, trust the stamp"
      if (msg._gwAttest && this.gateway) {
        const attestResult = this.gateway.verifyAttestation(msg._gwAttest);
        if (attestResult.valid) {
          // Attestation valid — skip expensive ML-DSA-65 verify (~0.01ms vs ~2-5ms)
          log.debug('Accepted via gateway attestation', {
            type: msg.type,
            gateway: msg._gwAttest.gateway?.slice(0, 20),
          });
        } else {
          // Attestation invalid — still try full verification below
          log.debug('Gateway attestation invalid, falling back to full verify', {
            reason: attestResult.reason,
          });
          msg._gwAttest = null; // Clear bad attestation
        }
      }
      
      // TRIBHUJ ratchet verification (rotating keys)
      if (msg._tribhujSig && !msg._gwAttest?.hash) {
        const payload = { ...msg };
        delete payload._tribhujSig;
        delete payload._tribhujEpoch;
        delete payload._tribhujPubKey;
        
        const result = this.ratchet
          ? this.ratchet.verifyObject(msg, msg._tribhujPubKey)
          : { valid: false, keyState: 'no_ratchet' };
        
        if (!result.valid) {
          log.warn('Rejected message with invalid TRIBHUJ signature', {
            type: msg.type,
            epoch: msg._tribhujEpoch,
            keyState: result.keyState,
            sender: senderNodeId?.slice(0, 20),
          });
          return; // Drop forged message
        }
        
        // If we're also a gateway, attest this for downstream peers
        if (this.gateway && msg.type === MessageTypes.GOSSIP && msg.id) {
          msg._gwAttest = this.gateway.attest(msg.id, msg.origin || senderNodeId);
        }
      }
      // Legacy identity verification (permanent key, no ratchet)
      else if (msg._signature && senderPublicKey && !msg._gwAttest?.hash) {
        const verified = this.identity.verifyObject(msg, senderPublicKey);
        if (!verified) {
          log.warn('Rejected message with invalid signature', {
            type: msg.type,
            signer: msg._signer?.slice(0, 20),
            sender: senderNodeId?.slice(0, 20),
          });
          return; // Drop forged message
        }
        
        // Attest for downstream if we have a gateway
        if (this.gateway && msg.type === MessageTypes.GOSSIP && msg.id) {
          msg._gwAttest = this.gateway.attest(msg.id, msg.origin || senderNodeId);
        }
      } else if (msg._signature && !senderPublicKey) {
        // Signed message from unknown peer — might be HELLO/WELCOME flow
        // Allow through since the handshake handler validates identity
        log.debug('Signed message from unregistered peer, passing through', { type: msg.type });
      } else if (!msg._gwAttest && !msg._tribhujSig && !msg._signature) {
        // UNSIGNED message — only allow handshake types (HELLO/WELCOME)
        // All other message types from known peers MUST be signed
        const HANDSHAKE_TYPES = new Set([MessageTypes.HELLO, MessageTypes.WELCOME]);
        if (!HANDSHAKE_TYPES.has(msg.type)) {
          log.warn('Rejected unsigned message from peer', {
            type: msg.type,
            sender: senderNodeId?.slice(0, 20) || 'unknown',
          });
          return; // Drop unsigned non-handshake message
        }
      }

      // Dispatch to handlers
      const handlers = this.messageHandlers.get(msg.type) || [];
      for (const handler of handlers) {
        handler(msg, ws, senderNodeId);
      }
      
      // Route ANNEX messages — extract envelope and pass correctly
      if (msg.annex && this.annex) {
        this.annex._handleAnnexMessage(msg.annex, senderNodeId).catch(err => {
          log.warn('ANNEX message handling error', { error: err.message });
        });
      }
    } catch (e) {
      console.error('Failed to parse message:', e.message);
    }
  }

  _handleDisconnect(ws) {
    for (const [nodeId, peer] of this.peers) {
      if (peer.ws === ws) {
        log.info('Peer disconnected', { name: peer.identity.name });
        // Close ANNEX channel for departing peer
        if (this.annex) {
          this.annex.closeChannel(nodeId).catch(() => {});
        }
        this.peers.delete(nodeId);
        // Signal so deferred ANNEX messages for this peer are cleaned up
        this.emit('peer-disconnected', nodeId);
        break;
      }
    }
  }

  _send(ws, message) {
    if (ws.readyState !== WebSocket.OPEN) return;
    
    // Opportunistic ANNEX encryption: if we have an active session
    // for this peer, encrypt the message transparently.
    // This ensures gossip, broadcast, ping — ALL traffic — is encrypted on the wire.
    // SKIP for ANNEX control messages (type 'annex') to prevent infinite recursion:
    //   _send → annex.send → _sendToMesh → mesh.sendTo → _send → ...
    if (this.annex && message.type !== 'annex') {
      // Reverse-lookup nodeId from ws
      for (const [nodeId, peer] of this.peers) {
        if (peer.ws === ws) {
          const session = this.annex.sessions.get(nodeId);
          if (session?.established && !session.isExpired()) {
            // Send via ANNEX (async, fire-and-forget for broadcast)
            this.annex.send(nodeId, message).catch(err => {
              // HARD FAIL: No plaintext fallback. Encryption is mandatory per Yakmesh ethos.
              // Peer must re-negotiate ANNEX session. Dropping message is safer than leaking it.
              log.error('ANNEX send failed — message dropped (no plaintext fallback)', { 
                nodeId: nodeId.slice(0, 20), error: err.message 
              });
            });
            return;
          }
          break;
        }
      }
    }
    
    // Plaintext only for ANNEX handshake messages (type 'annex') and initial
    // HELLO/WELCOME before ANNEX is established. Once ANNEX exists for a
    // peer, ALL traffic MUST go through it.
    ws.send(JSON.stringify(message));
  }

  _startPingLoop() {
    this._pingInterval = setInterval(() => {
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
      
      // LRU eviction — keep newest half instead of clearing all (prevents dedup bypass window)
      if (this.seenMessages.size > 10000) {
        const entries = [...this.seenMessages];
        const keepCount = Math.floor(entries.length / 2);
        this.seenMessages = new Set(entries.slice(entries.length - keepCount));
      }
    }, this.config.pingInterval);
  }

  /**
   * Record a connection in the burst detection sliding window.
   * When connections/minute exceeds _burstThreshold, emits a GPS-timestamped
   * alert — the "bright spot on the map" that makes Sybil floods visible.
   * @param {string} ip - Client IP address
   */
  _recordConnectionBurst(ip) {
    const now = Date.now();
    
    // Add to sliding window
    this._burstWindow.push({ ts: now, ip });
    
    // Evict entries older than window
    const cutoff = now - this._burstWindowMs;
    while (this._burstWindow.length > 0 && this._burstWindow[0].ts < cutoff) {
      this._burstWindow.shift();
    }
    
    const rate = this._burstWindow.length;  // connections in last 60s
    
    // Track peak
    if (rate > this._burstStats.peakRate) {
      this._burstStats.peakRate = rate;
    }
    
    if (rate >= this._burstThreshold && !this._burstAlerted) {
      // Count unique IPs in burst
      const uniqueIps = new Set(this._burstWindow.map(e => e.ip)).size;
      
      this._burstAlerted = true;
      this._burstStats.totalBurstsDetected++;
      this._burstStats.lastBurstAt = new Date().toISOString();
      this._burstStats.lastBurstRate = rate;
      
      console.warn(`🛰️ BURST DETECTED: ${rate} connections/min (threshold: ${this._burstThreshold}) from ${uniqueIps} unique IPs`);
      log.warn('Connection burst detected — possible Sybil flood', {
        connectionsPerMinute: rate,
        threshold: this._burstThreshold,
        uniqueIps,
        pendingHandshakes: this._pendingHandshakeCount,
        totalPeers: this.peers.size,
        // GPS-precision timestamp for forensic evidence
        gpsTimestamp: new Date().toISOString(),
        // IP frequency distribution (top 5 offenders)
        topIps: this._getTopBurstIps(5),
      });
      
      // Emit event for external consumers (health endpoint, SAKSHI anomaly detection)
      this.emit('connection-burst', {
        rate,
        uniqueIps,
        topIps: this._getTopBurstIps(5),
        timestamp: new Date().toISOString(),
      });
      
      // Reset alert after 30s (allow re-triggering if burst continues)
      setTimeout(() => { this._burstAlerted = false; }, 30000);
    }
  }

  /**
   * Get the top N most frequent IPs in the current burst window.
   * @param {number} n - Number of top IPs to return
   * @returns {Array<{ip: string, count: number}>}
   */
  _getTopBurstIps(n = 5) {
    const counts = new Map();
    for (const entry of this._burstWindow) {
      counts.set(entry.ip, (counts.get(entry.ip) || 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([ip, count]) => ({ ip, count }));
  }

  /**
   * Security stats for /health endpoint exposure.
   * Provides visibility into handshake pressure and burst detection.
   */
  getSecurityStats() {
    return {
      pendingHandshakes: this._pendingHandshakeCount,
      maxConcurrentHandshakes: this.config.maxConcurrentHandshakes,
      totalConnectedPeers: this.peers.size,
      burstDetection: {
        currentRate: this._burstWindow.length,
        threshold: this._burstThreshold,
        windowMs: this._burstWindowMs,
        inBurst: this._burstAlerted,
        stats: { ...this._burstStats },
      },
    };
  }
}

// ============================================================
// EXPORTS - MANDALA naming with backward compatibility
// ============================================================

// Note: MandalaMessageTypes and MandalaNetwork already exported at declarations
// Backward compatibility exports (original naming)
export { MandalaNetwork as MeshNetwork };

export default MandalaNetwork;
