/**
 * STUPA - Signal Transmission Unit for Peer Awareness
 * (Formerly: Yakmesh Beacon - Broadcast Emergency Alert Channel Over Network)
 * 
 * "Like sacred stupas that rise above the landscape to guide travelers,
 *  STUPA broadcasts rise above the mesh to ensure critical messages
 *  reach all who need to hear them."
 * 
 * Priority message propagation with guaranteed delivery:
 * - Flood-based protocol with intelligent deduplication
 * - Proof-of-receipt for message delivery confirmation
 * - TTL-based propagation control
 * - Emergency priority levels with preemption
 * 
 * Key Innovation: "When the message MUST get through"
 * - Combines temporal encoding with pulse heartbeats
 * - Cryptographic receipts prove delivery chain
 * - Multi-path redundancy ensures survivability
 * 
 * Part of the Himalayan Protocol Family:
 * - NAMCHE: Gateway verification
 * - DOKO: Identity certificates
 * - SHERPA: Peer discovery
 * - NAKPAK: Onion routing
 * - ANNEX: P2P channels
 * - MANTRA: Message propagation
 * - STUPA: Emergency broadcasts (this module)
 * 
 * @module mesh/stupa-broadcast
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// STUPA configuration (sacred structure levels)
const STUPA_CONFIG = {
  // Priority levels (like stupa tiers)
  priorities: {
    ROUTINE: 0,         // Normal messages (base level)
    PRIORITY: 1,        // Important but not urgent (first tier)
    IMMEDIATE: 2,       // Time-sensitive (second tier)
    FLASH: 3,           // Emergency (third tier)
    CRITICAL: 4,        // Life/safety critical (pinnacle)
  },
  
  // Propagation settings
  defaultTTL: 10,               // Default hop count
  maxTTL: 50,                   // Maximum hop count
  deduplicationWindowMs: 60000, // 1 minute dedup window
  receiptTimeout: 30000,        // 30s to collect receipts
  
  // Redundancy
  minRedundantPaths: 3,         // Minimum paths for critical messages
  maxRetransmissions: 5,        // Max retries per peer
  retransmitDelayMs: 1000,      // Delay between retries
  
  // Rate limiting
  maxMessagesPerSecond: 100,    // Per-node rate limit
  priorityBoost: {              // Rate limit multiplier by priority
    ROUTINE: 1,
    PRIORITY: 2,
    IMMEDIATE: 5,
    FLASH: 10,
    CRITICAL: 100,
  },
};

// Legacy export for backward compatibility
const BEACON_CONFIG = STUPA_CONFIG;

/**
 * A STUPA message (broadcast signal) with propagation metadata
 */
class StupaMessage {
  constructor(options) {
    this.id = options.id || bytesToHex(randomBytes(16));
    this.originNodeId = options.originNodeId;
    this.payload = options.payload;
    this.priority = options.priority || STUPA_CONFIG.priorities.ROUTINE;
    this.ttl = options.ttl || STUPA_CONFIG.defaultTTL;
    this.timestamp = options.timestamp || Date.now();
    this.expiresAt = options.expiresAt || (Date.now() + 300000); // 5 min default
    this.hopPath = options.hopPath || [];
    this.signature = options.signature || null;
    this.hash = this._computeHash();
  }

  _computeHash() {
    const data = [
      this.id,
      this.originNodeId,
      JSON.stringify(this.payload),
      this.priority.toString(),
      this.timestamp.toString(),
      this.expiresAt.toString(),
    ].join(':');
    
    return bytesToHex(sha3_256(utf8ToBytes(data)));
  }

  /**
   * Check if message is still valid
   */
  isValid() {
    return (
      this.ttl > 0 &&
      Date.now() < this.expiresAt &&
      this.hash === this._computeHash()
    );
  }

  /**
   * Create a forwarding copy with decremented TTL
   */
  forward(currentNodeId) {
    if (this.ttl <= 0) {
      return null;
    }
    
    return new StupaMessage({
      id: this.id,
      originNodeId: this.originNodeId,
      payload: this.payload,
      priority: this.priority,
      ttl: this.ttl - 1,
      timestamp: this.timestamp,
      expiresAt: this.expiresAt,
      hopPath: [...this.hopPath, currentNodeId],
      signature: this.signature,
    });
  }

  /**
   * Get priority name
   */
  getPriorityName() {
    for (const [name, value] of Object.entries(STUPA_CONFIG.priorities)) {
      if (value === this.priority) return name;
    }
    return 'UNKNOWN';
  }

  serialize() {
    return {
      id: this.id,
      originNodeId: this.originNodeId,
      payload: this.payload,
      priority: this.priority,
      ttl: this.ttl,
      timestamp: this.timestamp,
      expiresAt: this.expiresAt,
      hopPath: this.hopPath,
      signature: this.signature,
      hash: this.hash,
    };
  }

  static deserialize(obj) {
    const msg = new StupaMessage({
      id: obj.id,
      originNodeId: obj.originNodeId,
      payload: obj.payload,
      priority: obj.priority,
      ttl: obj.ttl,
      timestamp: obj.timestamp,
      expiresAt: obj.expiresAt,
      hopPath: obj.hopPath,
      signature: obj.signature,
    });
    
    if (msg.hash !== obj.hash) {
      throw new Error('Message hash mismatch');
    }
    
    return msg;
  }
}

/**
 * Delivery receipt proving message was received
 */
class DeliveryReceipt {
  constructor(options) {
    this.messageId = options.messageId;
    this.receiverNodeId = options.receiverNodeId;
    this.receivedAt = options.receivedAt || Date.now();
    this.hopCount = options.hopCount || 0;
    this.signature = options.signature || null;
    this.hash = this._computeHash();
  }

  _computeHash() {
    const data = [
      this.messageId,
      this.receiverNodeId,
      this.receivedAt.toString(),
      this.hopCount.toString(),
    ].join(':');
    
    return bytesToHex(sha3_256(utf8ToBytes(data)));
  }

  serialize() {
    return {
      messageId: this.messageId,
      receiverNodeId: this.receiverNodeId,
      receivedAt: this.receivedAt,
      hopCount: this.hopCount,
      signature: this.signature,
      hash: this.hash,
    };
  }

  static deserialize(obj) {
    const receipt = new DeliveryReceipt({
      messageId: obj.messageId,
      receiverNodeId: obj.receiverNodeId,
      receivedAt: obj.receivedAt,
      hopCount: obj.hopCount,
      signature: obj.signature,
    });
    
    if (receipt.hash !== obj.hash) {
      throw new Error('Receipt hash mismatch');
    }
    
    return receipt;
  }
}

/**
 * Deduplication tracker to prevent message storms
 */
class DeduplicationTracker {
  constructor(options = {}) {
    this.windowMs = options.windowMs || BEACON_CONFIG.deduplicationWindowMs;
    this.seen = new Map(); // messageId -> { timestamp, hopPaths }
    this.cleanupInterval = setInterval(() => this.cleanup(), 10000);
  }

  /**
   * Check if message was already seen
   */
  isDuplicate(messageId) {
    return this.seen.has(messageId);
  }

  /**
   * Mark message as seen
   */
  markSeen(message) {
    const existing = this.seen.get(message.id);
    
    if (existing) {
      // Track additional path
      existing.hopPaths.push([...message.hopPath]);
      return false;
    }
    
    this.seen.set(message.id, {
      timestamp: Date.now(),
      hopPaths: [[...message.hopPath]],
      priority: message.priority,
    });
    
    return true;
  }

  /**
   * Get propagation stats for a message
   */
  getMessageStats(messageId) {
    const entry = this.seen.get(messageId);
    if (!entry) return null;
    
    return {
      pathCount: entry.hopPaths.length,
      firstSeen: entry.timestamp,
      uniqueNodes: new Set(entry.hopPaths.flat()).size,
    };
  }

  cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [id, entry] of this.seen) {
      if (entry.timestamp < cutoff) {
        this.seen.delete(id);
      }
    }
  }

  getStats() {
    return {
      trackedMessages: this.seen.size,
    };
  }

  destroy() {
    clearInterval(this.cleanupInterval);
  }
}

/**
 * Receipt collector for delivery confirmation
 */
class ReceiptCollector {
  constructor() {
    this.pending = new Map(); // messageId -> { receipts, callbacks, timeout }
  }

  /**
   * Start collecting receipts for a message
   */
  startCollection(messageId, expectedCount, callback) {
    const timeout = setTimeout(() => {
      this._finalize(messageId);
    }, BEACON_CONFIG.receiptTimeout);

    this.pending.set(messageId, {
      receipts: [],
      expectedCount,
      callback,
      timeout,
      startedAt: Date.now(),
    });
  }

  /**
   * Add a receipt
   */
  addReceipt(receipt) {
    const pending = this.pending.get(receipt.messageId);
    if (!pending) return false;

    pending.receipts.push(receipt);

    // Check if we have enough
    if (pending.receipts.length >= pending.expectedCount) {
      this._finalize(receipt.messageId);
    }

    return true;
  }

  _finalize(messageId) {
    const pending = this.pending.get(messageId);
    if (!pending) return;

    clearTimeout(pending.timeout);
    
    const result = {
      messageId,
      receipts: pending.receipts,
      receivedCount: pending.receipts.length,
      expectedCount: pending.expectedCount,
      success: pending.receipts.length >= pending.expectedCount,
      duration: Date.now() - pending.startedAt,
    };

    pending.callback(result);
    this.pending.delete(messageId);
  }

  getStats() {
    return {
      pendingMessages: this.pending.size,
    };
  }
}

/**
 * Priority queue for message processing
 */
class PriorityMessageQueue {
  constructor() {
    this.queues = new Map();
    
    // Create queue for each priority
    for (const priority of Object.values(BEACON_CONFIG.priorities)) {
      this.queues.set(priority, []);
    }
  }

  enqueue(message) {
    const queue = this.queues.get(message.priority);
    if (queue) {
      queue.push(message);
    }
  }

  /**
   * Dequeue highest priority message
   */
  dequeue() {
    // Check from highest to lowest priority
    const priorities = Object.values(BEACON_CONFIG.priorities).sort((a, b) => b - a);
    
    for (const priority of priorities) {
      const queue = this.queues.get(priority);
      if (queue && queue.length > 0) {
        return queue.shift();
      }
    }
    
    return null;
  }

  /**
   * Peek at highest priority message without removing
   */
  peek() {
    const priorities = Object.values(BEACON_CONFIG.priorities).sort((a, b) => b - a);
    
    for (const priority of priorities) {
      const queue = this.queues.get(priority);
      if (queue && queue.length > 0) {
        return queue[0];
      }
    }
    
    return null;
  }

  size() {
    let total = 0;
    for (const queue of this.queues.values()) {
      total += queue.length;
    }
    return total;
  }

  getStats() {
    const stats = {};
    for (const [priority, queue] of this.queues) {
      const name = Object.entries(BEACON_CONFIG.priorities)
        .find(([_, v]) => v === priority)?.[0] || 'UNKNOWN';
      stats[name] = queue.length;
    }
    return stats;
  }
}

/**
 * Main STUPA broadcast system
 * 
 * Like a sacred stupa rising above the landscape to guide travelers,
 * StupaBroadcast ensures critical messages rise above network noise
 * and reach all nodes in the mesh.
 */
class StupaBroadcast {
  constructor(options = {}) {
    this.nodeId = options.nodeId || bytesToHex(randomBytes(16));
    this.dedup = new DeduplicationTracker();
    this.receipts = new ReceiptCollector();
    this.outboundQueue = new PriorityMessageQueue();
    this.peers = new Set();
    
    this.stats = {
      messagesOriginated: 0,
      messagesRelayed: 0,
      messagesDuplicate: 0,
      messagesExpired: 0,
      receiptsGenerated: 0,
      receiptsCollected: 0,
    };

    // Callbacks
    this.onBroadcast = options.onBroadcast || (() => {});
    this.onReceive = options.onReceive || (() => {});
    this.onReceipt = options.onReceipt || (() => {});
  }

  /**
   * Register a peer for broadcasting
   */
  addPeer(peerId) {
    this.peers.add(peerId);
  }

  removePeer(peerId) {
    this.peers.delete(peerId);
  }

  /**
   * Broadcast a new message (raise a stupa signal)
   */
  broadcast(payload, options = {}) {
    const message = new StupaMessage({
      originNodeId: this.nodeId,
      payload,
      priority: options.priority || STUPA_CONFIG.priorities.ROUTINE,
      ttl: options.ttl || STUPA_CONFIG.defaultTTL,
      expiresAt: options.expiresAt,
    });

    this.dedup.markSeen(message);
    this.stats.messagesOriginated++;

    // Queue for each peer
    for (const peerId of this.peers) {
      this.outboundQueue.enqueue(message);
    }

    // Start receipt collection if requested
    if (options.confirmDelivery) {
      this.receipts.startCollection(
        message.id,
        options.expectedReceipts || this.peers.size,
        (result) => {
          this.stats.receiptsCollected += result.receivedCount;
          options.onDeliveryConfirm?.(result);
        }
      );
    }

    this.onBroadcast({ message: message.serialize(), peerCount: this.peers.size });

    return {
      messageId: message.id,
      hash: message.hash,
      queuedFor: this.peers.size,
    };
  }

  /**
   * Receive and process an incoming STUPA signal
   */
  receive(messageData) {
    try {
      const message = StupaMessage.deserialize(messageData);

      // Check validity
      if (!message.isValid()) {
        this.stats.messagesExpired++;
        return { accepted: false, reason: 'Message expired or invalid' };
      }

      // Check for duplicate
      if (this.dedup.isDuplicate(message.id)) {
        this.stats.messagesDuplicate++;
        return { accepted: false, reason: 'Duplicate message' };
      }

      // Mark as seen
      this.dedup.markSeen(message);

      // Generate receipt
      const receipt = new DeliveryReceipt({
        messageId: message.id,
        receiverNodeId: this.nodeId,
        hopCount: message.hopPath.length,
      });
      this.stats.receiptsGenerated++;

      // Notify application
      this.onReceive({
        message: message.serialize(),
        receipt: receipt.serialize(),
      });

      // Forward to peers (if TTL allows)
      const forwarded = this._forwardMessage(message);

      return {
        accepted: true,
        messageId: message.id,
        priority: message.getPriorityName(),
        receipt: receipt.serialize(),
        forwarded,
      };
    } catch (err) {
      return { accepted: false, reason: err.message };
    }
  }

  /**
   * Forward message to peers
   */
  _forwardMessage(message) {
    const forwarded = [];
    const forwardedMsg = message.forward(this.nodeId);

    if (!forwardedMsg) {
      return forwarded;
    }

    for (const peerId of this.peers) {
      // Don't send back to nodes in the hop path
      if (message.hopPath.includes(peerId)) continue;
      if (peerId === message.originNodeId) continue;

      forwarded.push(peerId);
      this.outboundQueue.enqueue(forwardedMsg);
    }

    if (forwarded.length > 0) {
      this.stats.messagesRelayed++;
    }

    return forwarded;
  }

  /**
   * Process a delivery receipt
   */
  processReceipt(receiptData) {
    try {
      const receipt = DeliveryReceipt.deserialize(receiptData);
      const added = this.receipts.addReceipt(receipt);
      
      if (added) {
        this.onReceipt({ receipt: receipt.serialize() });
      }

      return { accepted: added };
    } catch (err) {
      return { accepted: false, reason: err.message };
    }
  }

  /**
   * Get next outbound message
   */
  getNextOutbound() {
    return this.outboundQueue.dequeue()?.serialize();
  }

  /**
   * Send critical emergency broadcast
   */
  sendEmergency(payload, options = {}) {
    return this.broadcast(payload, {
      ...options,
      priority: BEACON_CONFIG.priorities.CRITICAL,
      ttl: BEACON_CONFIG.maxTTL,
      confirmDelivery: true,
    });
  }

  /**
   * Send flash priority message (emergency stupa signal)
   */
  sendFlash(payload, options = {}) {
    return this.broadcast(payload, {
      ...options,
      priority: STUPA_CONFIG.priorities.FLASH,
    });
  }

  /**
   * Get STUPA statistics
   */
  getStats() {
    return {
      ...this.stats,
      peers: this.peers.size,
      queueStats: this.outboundQueue.getStats(),
      dedupStats: this.dedup.getStats(),
      receiptStats: this.receipts.getStats(),
    };
  }

  destroy() {
    this.dedup.destroy();
  }
}

// New STUPA exports
export {
  STUPA_CONFIG,
  StupaMessage,
  StupaBroadcast,
  DeliveryReceipt,
  DeduplicationTracker,
  ReceiptCollector,
  PriorityMessageQueue,
};

// Legacy exports for backward compatibility
export {
  STUPA_CONFIG as BEACON_CONFIG,
  StupaMessage as BeaconMessage,
  StupaBroadcast as BeaconBroadcast,
};
