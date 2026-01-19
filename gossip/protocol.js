/**
 * Gossip Protocol for Lantern Mesh Network
 * 
 * Implements epidemic-style message propagation with:
 * - Peer discovery via HELLO/PEERS exchange
 * - Anti-entropy synchronization
 * - Rumor mongering for fast propagation
 * - Bloom filters for efficient seen-message tracking
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('gossip:protocol');

// Message types for gossip protocol
export const GossipMessageType = {
  // Peer discovery
  HELLO: 'GOSSIP_HELLO',           // Announce self to network
  PEERS: 'GOSSIP_PEERS',           // Share known peers
  WANT_PEERS: 'GOSSIP_WANT_PEERS', // Request peer list
  
  // Rumor mongering
  RUMOR: 'GOSSIP_RUMOR',           // New data to propagate
  SEEN: 'GOSSIP_SEEN',             // Acknowledge receipt
  
  // Anti-entropy
  DIGEST: 'GOSSIP_DIGEST',         // Summary of known data
  DIFF: 'GOSSIP_DIFF',             // Missing data request
};

/**
 * Simple Bloom Filter for tracking seen messages
 */
class BloomFilter {
  constructor(size = 10000, hashCount = 3) {
    this.size = size;
    this.hashCount = hashCount;
    this.bits = new Uint8Array(Math.ceil(size / 8));
    this.count = 0;
  }

  _hash(value, seed) {
    const data = `${seed}:${value}`;
    const hash = sha3_256(new TextEncoder().encode(data));
    return new DataView(hash.buffer).getUint32(0, true) % this.size;
  }

  add(value) {
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this._hash(value, i);
      const bytePos = Math.floor(pos / 8);
      const bitPos = pos % 8;
      this.bits[bytePos] |= (1 << bitPos);
    }
    this.count++;
  }

  has(value) {
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this._hash(value, i);
      const bytePos = Math.floor(pos / 8);
      const bitPos = pos % 8;
      if (!(this.bits[bytePos] & (1 << bitPos))) {
        return false;
      }
    }
    return true;
  }

  // Reset when filter gets too full (false positive rate increases)
  shouldReset() {
    return this.count > this.size * 0.5;
  }

  reset() {
    this.bits.fill(0);
    this.count = 0;
  }
}

/**
 * Gossip Protocol Manager
 */
export class GossipProtocol {
  constructor(mesh, identity, options = {}) {
    this.mesh = mesh;
    this.identity = identity;
    
    // Configuration
    this.config = {
      fanout: options.fanout || 3,              // Peers to gossip to
      helloInterval: options.helloInterval || 30000,    // 30s
      digestInterval: options.digestInterval || 60000,  // 60s
      peerTTL: options.peerTTL || 300000,       // 5 min peer expiry
      maxPeersToShare: options.maxPeersToShare || 10,
      rumorTTL: options.rumorTTL || 5,          // Max hops
      ...options,
    };

    // State
    this.knownPeers = new Map();  // nodeId -> { info, lastSeen, endpoint }
    this.seenMessages = new BloomFilter();
    this.pendingRumors = new Map();  // messageId -> { rumor, attempts, targets }
    
    // Intervals
    this.intervals = [];
    
    // Bind handlers
    this._handleGossipMessage = this._handleGossipMessage.bind(this);
  }

  /**
   * Start the gossip protocol
   */
  start() {
    log.info('Gossip protocol started');
    
    // Register message handler with mesh
    this.mesh.on('gossip', this._handleGossipMessage);

    // Periodic HELLO broadcast
    this.intervals.push(
      setInterval(() => this._broadcastHello(), this.config.helloInterval)
    );

    // Periodic anti-entropy
    this.intervals.push(
      setInterval(() => this._runAntiEntropy(), this.config.digestInterval)
    );

    // Peer expiry check
    this.intervals.push(
      setInterval(() => this._expirePeers(), 60000)
    );

    // Initial hello
    setTimeout(() => this._broadcastHello(), 1000);
  }

  /**
   * Stop the gossip protocol
   */
  stop() {
    this.intervals.forEach(clearInterval);
    this.intervals = [];
    this.mesh.off('gossip', this._handleGossipMessage);
    log.info('Gossip protocol stopped');
  }

  /**
   * Broadcast a rumor to the network
   */
  spreadRumor(topic, data) {
    const messageId = this._generateMessageId(topic, data);
    
    if (this.seenMessages.has(messageId)) {
      return; // Already seen
    }

    const rumor = {
      type: GossipMessageType.RUMOR,
      messageId,
      topic,
      data,
      origin: this.identity.identity.nodeId,
      ttl: this.config.rumorTTL,
      timestamp: Date.now(),
    };

    this.seenMessages.add(messageId);
    this._propagateRumor(rumor);
    
    return messageId;
  }

  /**
   * Get known peers (for peer discovery)
   */
  getKnownPeers() {
    const now = Date.now();
    const peers = [];
    
    for (const [nodeId, info] of this.knownPeers) {
      if (now - info.lastSeen < this.config.peerTTL) {
        peers.push({
          nodeId,
          name: info.name,
          endpoint: info.endpoint,
          region: info.region,
          lastSeen: info.lastSeen,
        });
      }
    }
    
    return peers;
  }

  /**
   * Handle incoming gossip messages
   */
  _handleGossipMessage(message, fromNodeId) {
    switch (message.type) {
      case GossipMessageType.HELLO:
        this._handleHello(message, fromNodeId);
        break;
      case GossipMessageType.PEERS:
        this._handlePeers(message);
        break;
      case GossipMessageType.WANT_PEERS:
        this._handleWantPeers(fromNodeId);
        break;
      case GossipMessageType.RUMOR:
        this._handleRumor(message, fromNodeId);
        break;
      case GossipMessageType.SEEN:
        this._handleSeen(message, fromNodeId);
        break;
      case GossipMessageType.DIGEST:
        this._handleDigest(message, fromNodeId);
        break;
      case GossipMessageType.DIFF:
        this._handleDiff(message, fromNodeId);
        break;
    }
  }

  /**
   * Broadcast HELLO to all connected peers
   */
  _broadcastHello() {
    const hello = {
      type: GossipMessageType.HELLO,
      nodeId: this.identity.identity.nodeId,
      name: this.identity.identity.name,
      region: this.identity.identity.region,
      capabilities: this.identity.identity.capabilities,
      endpoint: this.mesh.getPublicEndpoint?.() || null,
      timestamp: Date.now(),
    };

    this.mesh.broadcast({ gossip: hello });
    
    // Also request peers
    this.mesh.broadcast({ 
      gossip: { type: GossipMessageType.WANT_PEERS } 
    });
  }

  /**
   * Handle HELLO from a peer
   */
  _handleHello(message, fromNodeId) {
    this.knownPeers.set(message.nodeId, {
      name: message.name,
      region: message.region,
      capabilities: message.capabilities,
      endpoint: message.endpoint,
      lastSeen: Date.now(),
    });

    log.info('Discovered peer', { name: message.name, nodeId: message.nodeId.slice(0, 16) });

    // Respond with our peer list
    this._sendPeerList(fromNodeId);
  }

  /**
   * Handle WANT_PEERS request
   */
  _handleWantPeers(fromNodeId) {
    this._sendPeerList(fromNodeId);
  }

  /**
   * Send peer list to a specific node
   */
  _sendPeerList(toNodeId) {
    const peers = this.getKnownPeers()
      .filter(p => p.nodeId !== toNodeId)
      .slice(0, this.config.maxPeersToShare);

    if (peers.length > 0) {
      this.mesh.sendTo(toNodeId, {
        gossip: {
          type: GossipMessageType.PEERS,
          peers,
        }
      });
    }
  }

  /**
   * Handle PEERS message
   */
  _handlePeers(message) {
    for (const peer of message.peers) {
      if (peer.nodeId === this.identity.identity.nodeId) continue;
      
      if (!this.knownPeers.has(peer.nodeId)) {
        this.knownPeers.set(peer.nodeId, {
          name: peer.name,
          region: peer.region,
          endpoint: peer.endpoint,
          lastSeen: peer.lastSeen,
        });
        
        // Try to connect if we have an endpoint
        if (peer.endpoint && !this.mesh.isConnectedTo(peer.nodeId)) {
          log.debug('Attempting connection to discovered peer', { name: peer.name });
          this.mesh.connectToPeer(peer.endpoint).catch(() => {
            // Connection failed, that's ok
          });
        }
      }
    }
  }

  /**
   * Handle incoming rumor
   */
  _handleRumor(rumor, fromNodeId) {
    const { messageId, ttl } = rumor;

    // Already seen?
    if (this.seenMessages.has(messageId)) {
      // Send SEEN to stop rumor mongering
      this.mesh.sendTo(fromNodeId, {
        gossip: { type: GossipMessageType.SEEN, messageId }
      });
      return;
    }

    // Mark as seen
    this.seenMessages.add(messageId);
    
    // Check bloom filter health
    if (this.seenMessages.shouldReset()) {
      this.seenMessages.reset();
    }

    // Emit event for application layer
    this.mesh.emit('rumor', rumor.topic, rumor.data, rumor.origin);

    log.debug('Received rumor', { topic: rumor.topic, origin: rumor.origin.slice(0, 16) });

    // Propagate if TTL allows
    if (ttl > 1) {
      const forwardRumor = { ...rumor, ttl: ttl - 1 };
      this._propagateRumor(forwardRumor, fromNodeId);
    }
  }

  /**
   * Handle SEEN acknowledgment
   */
  _handleSeen(message, fromNodeId) {
    const pending = this.pendingRumors.get(message.messageId);
    if (pending) {
      pending.targets.delete(fromNodeId);
      if (pending.targets.size === 0) {
        this.pendingRumors.delete(message.messageId);
      }
    }
  }

  /**
   * Propagate a rumor using fanout
   */
  _propagateRumor(rumor, excludeNodeId = null) {
    const peers = this.mesh.getPeers()
      .filter(p => p.nodeId !== excludeNodeId && p.nodeId !== rumor.origin);

    if (peers.length === 0) {
      log.warn('No peers to propagate rumor to');
      return;
    }

    // Select random subset based on fanout
    const targets = this._selectRandom(peers, this.config.fanout);
    log.debug('Propagating rumor', { targetCount: targets.length, targets: targets.map(t => t.nodeId.slice(0, 12)) });

    for (const target of targets) {
      // Use broadcast format so the mesh routes it correctly
      this.mesh.sendTo(target.nodeId, {
        type: 'gossip',  // This ensures the mesh routes it to gossip handlers
        payload: { gossip: rumor },
        id: rumor.messageId,
        origin: rumor.origin,
        ttl: rumor.ttl,
      });
    }

    // Track for rumor mongering
    this.pendingRumors.set(rumor.messageId, {
      rumor,
      attempts: 1,
      targets: new Set(targets.map(t => t.nodeId)),
    });
  }

  /**
   * Run anti-entropy synchronization
   */
  _runAntiEntropy() {
    // This would typically sync with replication engine
    // For now, just exchange peer lists
    const peers = this.mesh.getPeers();
    if (peers.length === 0) return;

    // Pick a random peer for anti-entropy
    const target = peers[Math.floor(Math.random() * peers.length)];
    
    this.mesh.sendTo(target.nodeId, {
      gossip: { type: GossipMessageType.WANT_PEERS }
    });
  }

  /**
   * Handle DIGEST for anti-entropy
   */
  _handleDigest(message, fromNodeId) {
    // Would compare digests and request missing data
    // Integration point with replication engine
  }

  /**
   * Handle DIFF request
   */
  _handleDiff(message, fromNodeId) {
    // Would send missing data
    // Integration point with replication engine
  }

  /**
   * Expire old peers
   */
  _expirePeers() {
    const now = Date.now();
    for (const [nodeId, info] of this.knownPeers) {
      if (now - info.lastSeen > this.config.peerTTL) {
        this.knownPeers.delete(nodeId);
        log.info('Peer expired', { name: info.name });
      }
    }
  }

  /**
   * Generate deterministic message ID
   */
  _generateMessageId(topic, data) {
    const payload = JSON.stringify({ topic, data, origin: this.identity.identity.nodeId, ts: Date.now() });
    return bytesToHex(sha3_256(new TextEncoder().encode(payload))).slice(0, 32);
  }

  /**
   * Select random items from array
   */
  _selectRandom(array, count) {
    const shuffled = [...array].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(count, array.length));
  }

  /**
   * Get gossip statistics
   */
  getStats() {
    return {
      knownPeers: this.knownPeers.size,
      seenMessages: this.seenMessages.count,
      pendingRumors: this.pendingRumors.size,
      bloomFilterHealth: this.seenMessages.count / this.seenMessages.size,
    };
  }
}

export default GossipProtocol;
