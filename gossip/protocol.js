/**
 * MANTRA - Message Amplification Network for Trust Relayed Announcements
 * 
 * "Like prayer wheels spreading mantras across the mountains,
 *  messages flow through the mesh, carrying truth to all who listen."
 * 
 * Implements epidemic-style message propagation with:
 * - Peer discovery via HELLO/PEERS exchange
 * - Anti-entropy synchronization (KARMA balance)
 * - Rumor mongering for fast propagation (MANTRA spreading)
 * - Bloom filters for efficient seen-message tracking
 * 
 * Part of the Himalayan Protocol Family:
 * - NAMCHE: Gateway verification
 * - DOKO: Identity certificates
 * - SHERPA: Peer discovery
 * - NAKPAK: Onion routing
 * - ANNEX: P2P channels
 * - KHATA: Trust distribution
 * - MANTRA: Message propagation (this module)
 * 
 * @module gossip/mantra-protocol
 * @version 2.6.0
 */

import { EventEmitter } from 'node:events';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

// 144T ternary addressing for message IDs (eliminates hex "666" patterns)
import { TritAddress } from '../oracle/ternary-routing.js';

// ACCEL: Hardware-accelerated SHA3-256 (OpenSSL/SHA-NI — 4.6x faster)
import { sha3_256 } from '../utils/accel.js';

// AGUWA — canonical mesh time source
import { aguwa } from '../mesh/aguwa.js';

const log = createLogger('mantra:protocol');

/** Extract unique peer suffix from nodeId (e.g. 'node-net-name-pq-kEEU' → 'kEEU') */
const peerTag = (id) => id?.split('-pq-').pop() || id?.slice?.(-8) || String(id);

// Message types for MANTRA protocol
// (Maintains GOSSIP_ prefix for backward compatibility with existing mesh messages)
export const MantraMessageType = {
  // Peer discovery (SHERPA integration)
  HELLO: 'GOSSIP_HELLO',           // Announce self to network (prayer wheel spin)
  PEERS: 'GOSSIP_PEERS',           // Share known peers (community)
  WANT_PEERS: 'GOSSIP_WANT_PEERS', // Request peer list (seeking guidance)

  // Rumor mongering (MANTRA spreading)
  RUMOR: 'GOSSIP_RUMOR',           // New data to propagate (mantra to spread)
  SEEN: 'GOSSIP_SEEN',             // Acknowledge receipt (mantra received)

  // Anti-entropy (KARMA balance)
  DIGEST: 'GOSSIP_DIGEST',         // Summary of known data (karma digest)
  DIFF: 'GOSSIP_DIFF',             // Missing data request (karma balance)
};

// Legacy export for backward compatibility
export const GossipMessageType = MantraMessageType;

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
  // 70% fill keeps FP rate manageable; 50% was too aggressive (wasted capacity)
  shouldReset() {
    return this.count > this.size * 0.7;
  }

  reset() {
    this.bits.fill(0);
    this.count = 0;
  }
}

/**
 * MANTRA Protocol Manager
 * 
 * Spreads messages through the mesh like mantras carried by prayer wheels.
 * Each spin (propagation) brings the message closer to enlightenment (full network coverage).
 */
export class MantraProtocol extends EventEmitter {
  constructor(mesh, identity, options = {}) {
    super();
    this.mesh = mesh;
    this.identity = identity;

    // Relay info callback — lets gossip ask the node about active relay endpoints
    // Returns { relayEndpoints: ['https://...'], relayNodeIds: Set } or null
    this._getRelayInfo = options.getRelayInfo || null;
    // Relay connect callback — lets gossip tell the node to register with a relay
    // Signature: (relayEndpoint, nodeId) => Promise<void>
    this._connectRelay = options.connectRelay || null;

    // Configuration
    this.config = {
      fanout: options.fanout || 3,              // Peers to spread mantra to
      helloInterval: options.helloInterval || 30000,    // 30s (prayer wheel spin)
      digestInterval: options.digestInterval || 60000,  // 60s (karma check)
      peerTTL: options.peerTTL || 300000,       // 5 min peer expiry
      maxPeersToShare: options.maxPeersToShare || 10,
      rumorTTL: options.rumorTTL || 5,          // Max hops (wheel spins)
      ...options,
    };

    // State
    this.knownPeers = new Map();  // nodeId -> { info, lastSeen, endpoint }
    this.seenMessages = new BloomFilter();
    this.pendingRumors = new Map();  // messageId -> { rumor, attempts, targets }

    // Recent rumors buffer (for HTTP polling by MeshBridge)
    this.recentRumors = [];           // { topic, data, origin, timestamp, messageId }
    this.maxRecentRumors = 500;       // Keep last 500 rumors
    this.rumorRetentionMs = 300000;   // 5 min retention

    // Intervals
    this.intervals = [];

    // Bind handlers
    this._handleGossipMessage = this._handleGossipMessage.bind(this);
  }

  /**
   * Start the MANTRA protocol (begin spinning the prayer wheel)
   */
  start() {
    log.info('MANTRA protocol started - prayer wheel spinning');

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
    this._helloTimer = setTimeout(() => this._broadcastHello(), 1000);
  }

  /**
   * Stop the MANTRA protocol (prayer wheel rests)
   */
  stop() {
    this.intervals.forEach(clearInterval);
    this.intervals = [];
    clearTimeout(this._helloTimer);
    this.mesh.off('gossip', this._handleGossipMessage);
    log.info('MANTRA protocol stopped - prayer wheel at rest');
  }

  /**
   * Spread a mantra (rumor) to the network
   * Like spinning a prayer wheel, the message propagates outward
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
      originTTL: this.config.rumorTTL,
      timestamp: aguwa.now(),
    };

    // Sign the rumor (ML-DSA-65) — excludes TTL since it decrements during propagation
    const sigPayload = JSON.stringify({
      messageId: rumor.messageId,
      topic: rumor.topic,
      data: rumor.data,
      origin: rumor.origin,
      originTTL: rumor.originTTL,
      timestamp: rumor.timestamp,
    });
    rumor.signature = this.identity.sign(sigPayload);

    this.seenMessages.add(messageId);
    this._bufferRumor(rumor);
    this._propagateRumor(rumor);

    // Also emit for HTTP relay bridge — locally-generated rumors must reach
    // relay peers (nodes connected via HTTP polling, not WebSocket).
    // _propagateRumor only sends to mesh.getPeers() (WS peers), so relay-only
    // nodes (e.g. behind firewalls) would never propagate their own rumors
    // without this. The server layer's outbound-gossip handler queues the
    // message in the relay outbox for delivery on the next poll cycle.
    this._emitForRelayBridge(rumor);

    return messageId;
  }

  /**
   * Emit a rumor as an outbound-gossip event for the HTTP relay bridge.
   * This ensures locally-generated rumors reach relay peers (nodes connected
   * via HTTP polling rather than direct WebSocket). Without this, nodes that
   * only have relay connections would generate rumors that never leave the node.
   */
  _emitForRelayBridge(rumor) {
    const meshMsg = {
      type: 'gossip',
      payload: { gossip: rumor },
      id: rumor.messageId,
      origin: rumor.origin,
      ttl: rumor.ttl,
    };
    // Exclude our own nodeId — we're the origin, no need to relay back to self
    this.mesh.emit('outbound-gossip', meshMsg, [rumor.origin]);
  }

  /**
   * Get known peers (for peer discovery)
   */
  getKnownPeers() {
    const now = aguwa.now();
    const peers = [];

    for (const [nodeId, info] of this.knownPeers) {
      if (now - info.lastSeen < this.config.peerTTL) {
        peers.push({
          nodeId,
          name: info.name,
          endpoint: info.endpoint,
          relayEndpoints: info.relayEndpoints || [],
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
      publicKey: this.identity.identity.publicKey,  // ML-DSA-65 public key for signature verification
      timestamp: aguwa.now(),
    };

    // Include relay endpoints we're registered with so peers can discover relay paths
    // This is how relay knowledge propagates organically through the mesh
    if (this._getRelayInfo) {
      try {
        const relayInfo = this._getRelayInfo();
        if (relayInfo?.relayEndpoints?.length > 0) {
          hello.relayEndpoints = relayInfo.relayEndpoints;
        }
      } catch { /* relay info unavailable — that's ok */ }
    }

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
    const isNewPeer = !this.knownPeers.has(message.nodeId);

    this.knownPeers.set(message.nodeId, {
      name: message.name,
      region: message.region,
      capabilities: message.capabilities,
      endpoint: message.endpoint,
      relayEndpoints: message.relayEndpoints || [],
      publicKey: message.publicKey || null,  // Store for gossip signature verification
      lastSeen: aguwa.now(),
    });

    // Store public key in mesh._relayPeerKeys for signature verification
    // This allows relay-discovered peers to verify each other's gossip signatures
    if (message.publicKey && message.nodeId && this.mesh?._relayPeerKeys) {
      this.mesh._relayPeerKeys.set(message.nodeId, message.publicKey);
    } else if (message.publicKey && message.nodeId && this.mesh) {
      // Initialize the map if it doesn't exist
      if (!this.mesh._relayPeerKeys) this.mesh._relayPeerKeys = new Map();
      this.mesh._relayPeerKeys.set(message.nodeId, message.publicKey);
    }

    // Only log when we actually discover a new peer
    if (isNewPeer) {
      log.info('Discovered peer', { name: message.name, peer: peerTag(message.nodeId) });
    }

    // If peer advertises relay endpoints and we have no direct connection to the
    // node behind that relay, auto-register — this is how relay knowledge spreads
    if (message.relayEndpoints?.length > 0 && this._connectRelay) {
      this._tryRelayConnect(message.relayEndpoints, message.nodeId);
    }

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
          relayEndpoints: peer.relayEndpoints || [],
          lastSeen: peer.lastSeen,
        });

        // Try to connect if we have an endpoint
        if (peer.endpoint && !this.mesh.isConnectedTo(peer.nodeId)) {
          log.debug('Attempting connection to discovered peer', { name: peer.name });
          this.mesh.connectToPeer(peer.endpoint).catch(() => {
            // Connection failed — try relay if available
            if (peer.relayEndpoints?.length > 0 && this._connectRelay) {
              this._tryRelayConnect(peer.relayEndpoints, peer.nodeId);
            }
          });
        } else if (!peer.endpoint && peer.relayEndpoints?.length > 0 && this._connectRelay) {
          // No WS endpoint but has relay — connect via relay
          this._tryRelayConnect(peer.relayEndpoints, peer.nodeId);
        }
      }
    }
  }

  /**
   * Try connecting to a peer via relay endpoints discovered through gossip.
   * Fire-and-forget — failure is silent (relay is a fallback, not primary path).
   */
  _tryRelayConnect(relayEndpoints, nodeId) {
    if (!this._connectRelay || !relayEndpoints?.length) return;

    // Don't relay-connect to ourselves
    if (nodeId === this.identity.identity.nodeId) return;

    for (const endpoint of relayEndpoints) {
      if (typeof endpoint !== 'string' || !endpoint.startsWith('http')) continue;

      log.info(`GOSSIP relay discovery → ${endpoint} for ${peerTag(nodeId)}`);
      this._connectRelay(endpoint, nodeId).catch(err => {
        log.debug(`GOSSIP relay connect failed: ${endpoint} — ${err.message}`);
      });
      break;  // Only try first viable relay endpoint
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

    // Verify origin's ML-DSA-65 signature before trusting the rumor
    if (!rumor.signature) {
      log.warn('Dropping unsigned rumor', { origin: peerTag(rumor.origin), messageId });
      return;
    }
    const originPubKey = this._getPeerPublicKey(rumor.origin);
    if (!originPubKey) {
      log.warn('Dropping rumor from unknown origin (no public key)', { origin: peerTag(rumor.origin), messageId });
      return;
    }
    const sigPayload = JSON.stringify({
      messageId: rumor.messageId,
      topic: rumor.topic,
      data: rumor.data,
      origin: rumor.origin,
      originTTL: rumor.originTTL,
      timestamp: rumor.timestamp,
    });
    if (!this.identity.verify(sigPayload, rumor.signature, originPubKey)) {
      log.warn('Dropping rumor with invalid signature', { origin: peerTag(rumor.origin), messageId });
      return;
    }

    // Mark as seen
    this.seenMessages.add(messageId);

    // Check bloom filter health
    if (this.seenMessages.shouldReset()) {
      this.seenMessages.reset();
    }

    // Buffer for HTTP API consumers
    this._bufferRumor(rumor);

    // Emit event for application layer (both on self and mesh for backward compat)
    this.emit('rumor', rumor.topic, rumor.data, rumor.origin);
    this.mesh.emit('rumor', rumor.topic, rumor.data, rumor.origin);

    log.debug('Received rumor', { topic: rumor.topic, origin: peerTag(rumor.origin) });

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
      return;
    }

    // Select random subset based on fanout
    const targets = this._selectRandom(peers, this.config.fanout);

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
   * Generate deterministic message ID using 144T ternary format
   * Eliminates hex "666" patterns while maintaining collision resistance
   * Returns tier 1 (36 trits) as compact string: "TT00TTT00:TTT00TTT0:0TTT00TTT:00TTT00TT"
   */
  _generateMessageId(topic, data) {
    const payload = JSON.stringify({ topic, data, origin: this.identity.identity.nodeId, ts: aguwa.now() });
    const hex = bytesToHex(sha3_256(new TextEncoder().encode(payload)));
    // Convert to 144T ternary address, extract tier 1 as compact string
    const tritAddr = TritAddress.fromHex(hex);
    return tritAddr.toString().split('.')[0];  // First tier only
  }

  /**
   * Select random items from array
   */
  _selectRandom(array, count) {
    // Fisher-Yates shuffle — unbiased (sort-based shuffle is statistically skewed)
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled.slice(0, Math.min(count, array.length));
  }

  /**
   * Buffer a rumor for HTTP API retrieval
   */
  _bufferRumor(rumor) {
    this.recentRumors.push({
      messageId: rumor.messageId,
      topic: rumor.topic,
      data: rumor.data,
      origin: rumor.origin,
      timestamp: rumor.timestamp || aguwa.now(),
    });

    // Evict old entries
    const cutoff = aguwa.now() - this.rumorRetentionMs;
    while (this.recentRumors.length > this.maxRecentRumors ||
      (this.recentRumors.length > 0 && this.recentRumors[0].timestamp < cutoff)) {
      this.recentRumors.shift();
    }
  }

  /**
   * Get recent rumors (for HTTP API polling)
   * @param {number} since - Timestamp to filter from (exclusive)
   * @param {string} [topic] - Optional topic filter
   * @returns {Array} Matching rumors
   */
  getRecentRumors(since = 0, topic = null) {
    return this.recentRumors.filter(r => {
      if (r.timestamp <= since) return false;
      if (topic && r.topic !== topic) return false;
      return true;
    });
  }

  /**
   * Resolve a peer's public key from mesh state.
   * Checks WS peers, relay keys, knownPeers, SHERPA registry, and self.
   */
  _getPeerPublicKey(nodeId) {
    // Self
    if (nodeId === this.identity.identity.nodeId) {
      return this.identity.identity.publicKey;
    }
    // WS peer info
    if (this.mesh?.peers) {
      const peer = this.mesh.peers.get(nodeId);
      if (peer?.identity?.publicKey) return peer.identity.publicKey;
    }
    // Relay peer keys (stored during signed registration)
    if (this.mesh?._relayPeerKeys) {
      const key = this.mesh._relayPeerKeys.get(nodeId);
      if (key) return key;
    }
    // knownPeers from HELLO messages (learned via gossip)
    const knownPeer = this.knownPeers.get(nodeId);
    if (knownPeer?.publicKey) return knownPeer.publicKey;
    // SHERPA registry
    if (this.mesh?.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.publicKey) return regPeer.publicKey;
    }
    return null;
  }

  /**
   * Get MANTRA statistics (prayer wheel metrics)
   */
  getStats() {
    return {
      knownPeers: this.knownPeers.size,          // Fellow travelers on the path
      seenMessages: this.seenMessages.count,     // Mantras spoken
      pendingRumors: this.pendingRumors.size,    // Mantras in flight
      bloomFilterHealth: this.seenMessages.count / this.seenMessages.size,
    };
  }
}

// Legacy export for backward compatibility
export const GossipProtocol = MantraProtocol;
export default MantraProtocol;
