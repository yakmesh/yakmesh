/**
 * KHATA Protocol - Kryptographic Handshake for Automated Trust Acceptance
 * 
 * Trust distribution messaging for the YAKMESH mesh network.
 * Handles DOKO announcements, requests, responses, and revocations.
 * 
 * Message Types:
 * - ANNOUNCE: Broadcast new/updated DOKO to mesh
 * - REQUEST: Ask for a specific DOKO by nodeId, domain, or hash
 * - RESPONSE: Reply with matching DOKO(s)
 * - REVOKE: Announce DOKO revocation
 * 
 * @module security/khata-protocol
 * @version 1.0.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';
import { EventEmitter } from 'events';

/**
 * KHATA Message Types
 */
export const KHATA_MESSAGE = {
  ANNOUNCE: 'khata:announce',
  REQUEST: 'khata:request',
  RESPONSE: 'khata:response',
  REVOKE: 'khata:revoke',
};

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  maxHops: 10,
  announceTTL: 3600000, // 1 hour
  requestTimeout: 30000, // 30 seconds
  maxPendingRequests: 100,
  propagateToK: 3, // Number of peers to propagate requests to
};

/**
 * Generate a unique message ID
 */
function generateMessageId() {
  return bytesToHex(randomBytes(16));
}

/**
 * Compute hash of message content for deduplication
 */
function computeMessageHash(message) {
  const content = JSON.stringify({
    type: message.type,
    doko: message.doko,
    dokoHash: message.dokoHash,
    query: message.query,
    timestamp: message.timestamp,
  });
  return bytesToHex(sha3_256(utf8ToBytes(content)));
}

/**
 * KhataProtocol - Trust Distribution Messaging
 * 
 * @example
 * const khata = new KhataProtocol(namcheGateway, nodeIdentity);
 * 
 * // Announce our DOKO
 * khata.announce(myDoko);
 * 
 * // Request a DOKO by nodeId
 * const doko = await khata.request({ nodeId: 'node-qubit-lattice-prism-pq-a7x9' });
 * 
 * // Listen for announcements
 * khata.on('announce', (doko) => console.log('New DOKO:', doko.nodeId));
 */
export class KhataProtocol extends EventEmitter {
  constructor(namcheGateway, nodeIdentity, options = {}) {
    super();
    this.gateway = namcheGateway;
    this.identity = nodeIdentity;
    this.config = { ...DEFAULT_CONFIG, ...options };
    
    // Message deduplication (messageHash -> timestamp)
    this.seenMessages = new Map();
    
    // Pending requests (requestId -> { resolve, reject, timeout })
    this.pendingRequests = new Map();
    
    // Peer send function (must be set by network layer)
    this.sendToPeer = null;
    this.broadcastToPeers = null;
    
    // Cleanup interval for seen messages
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);

    this.stats = {
      announcesReceived: 0,
      announcesSent: 0,
      requestsReceived: 0,
      requestsSent: 0,
      responsesReceived: 0,
      responsesSent: 0,
      revokesReceived: 0,
      revokesSent: 0,
      duplicatesDropped: 0,
      hopLimitDropped: 0,
      ttlExpiredDropped: 0,
    };
  }

  /**
   * Set the network layer functions for peer communication
   * @param {Function} sendToPeer - (peerId, message) => Promise
   * @param {Function} broadcastToPeers - (message, excludePeerId?) => Promise
   */
  setNetworkLayer(sendToPeer, broadcastToPeers) {
    this.sendToPeer = sendToPeer;
    this.broadcastToPeers = broadcastToPeers;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ANNOUNCE - Broadcast new/updated DOKO
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create and broadcast an ANNOUNCE message
   * @param {Object} doko - The DOKO to announce
   */
  async announce(doko) {
    const message = {
      type: KHATA_MESSAGE.ANNOUNCE,
      messageId: generateMessageId(),
      doko,
      timestamp: Date.now(),
      ttl: this.config.announceTTL,
      hops: 0,
      originNodeId: this.identity.identity.nodeId,
    };

    // Mark as seen so we don't process our own message
    const messageHash = computeMessageHash(message);
    this.seenMessages.set(messageHash, Date.now());

    this.stats.announcesSent++;
    this.emit('announce-sent', { doko, messageId: message.messageId });

    // Broadcast to all peers
    if (this.broadcastToPeers) {
      await this.broadcastToPeers(message);
    }

    return message.messageId;
  }

  /**
   * Handle incoming ANNOUNCE message
   */
  async handleAnnounce(message, fromPeerId) {
    // Check for duplicate
    const messageHash = computeMessageHash(message);
    if (this.seenMessages.has(messageHash)) {
      this.stats.duplicatesDropped++;
      return;
    }
    this.seenMessages.set(messageHash, Date.now());

    // Check hop limit
    if (message.hops >= this.config.maxHops) {
      this.stats.hopLimitDropped++;
      return;
    }

    // Check TTL
    const age = Date.now() - message.timestamp;
    if (age > message.ttl) {
      this.stats.ttlExpiredDropped++;
      return;
    }

    this.stats.announcesReceived++;

    // Verify the DOKO through NAMCHE gateway
    const verifyResult = await this.gateway.verify(message.doko);
    
    if (verifyResult.valid) {
      this.emit('announce', { 
        doko: message.doko, 
        dokoHash: verifyResult.dokoHash,
        fromPeerId,
        hops: message.hops,
      });

      // Propagate to peers (increment hops)
      if (this.broadcastToPeers) {
        const forwardMessage = {
          ...message,
          hops: message.hops + 1,
        };
        await this.broadcastToPeers(forwardMessage, fromPeerId);
      }
    } else {
      this.emit('announce-rejected', {
        doko: message.doko,
        reason: verifyResult.reason,
        detail: verifyResult.detail,
        fromPeerId,
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REQUEST - Ask for a specific DOKO
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Request a DOKO by query
   * @param {Object} query - { nodeId?, domain?, dokoHash? }
   * @returns {Promise<Object|null>} The DOKO or null if not found
   */
  async request(query) {
    // First check local cache
    if (query.dokoHash) {
      const cached = this.gateway.lookupByHash(query.dokoHash);
      if (cached) return cached;
    }
    if (query.nodeId) {
      const cached = this.gateway.lookupByNodeId(query.nodeId);
      if (cached) return cached;
    }

    // If not in cache, request from network
    return this.requestFromNetwork(query);
  }

  /**
   * Request DOKO from network peers
   */
  async requestFromNetwork(query) {
    if (this.pendingRequests.size >= this.config.maxPendingRequests) {
      throw new Error('Too many pending KHATA requests');
    }

    const requestId = generateMessageId();
    const message = {
      type: KHATA_MESSAGE.REQUEST,
      requestId,
      query,
      timestamp: Date.now(),
      requesterId: this.identity.identity.nodeId,
    };

    // Sign the request
    const requestPayload = JSON.stringify({
      requestId,
      query,
      timestamp: message.timestamp,
    });
    message.signature = this.identity.sign(requestPayload);

    // Create promise for response
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        resolve(null); // Not found
      }, this.config.requestTimeout);

      this.pendingRequests.set(requestId, { resolve, reject, timeout });

      this.stats.requestsSent++;
      
      // Broadcast request
      if (this.broadcastToPeers) {
        this.broadcastToPeers(message);
      }
    });
  }

  /**
   * Handle incoming REQUEST message
   */
  async handleRequest(message, fromPeerId) {
    this.stats.requestsReceived++;

    const { query, requestId, requesterId } = message;

    // Check if we have the requested DOKO
    let doko = null;

    if (query.dokoHash) {
      doko = this.gateway.lookupByHash(query.dokoHash);
    } else if (query.nodeId) {
      doko = this.gateway.lookupByNodeId(query.nodeId);
    } else if (query.domain) {
      // Lookup DOKO by verified domain claim
      doko = this.gateway.lookupByDomain?.(query.domain) || null;
    }

    if (doko) {
      // Send response
      const response = {
        type: KHATA_MESSAGE.RESPONSE,
        requestId,
        dokos: [doko],
        responderId: this.identity.identity.nodeId,
        timestamp: Date.now(),
      };

      // Sign response
      const responsePayload = JSON.stringify({
        requestId,
        dokosCount: response.dokos.length,
        timestamp: response.timestamp,
      });
      response.signature = this.identity.sign(responsePayload);

      this.stats.responsesSent++;

      if (this.sendToPeer) {
        await this.sendToPeer(fromPeerId, response);
      }
    } else {
      // Forward request to other peers if we don't have it
      if (this.broadcastToPeers) {
        await this.broadcastToPeers(message, fromPeerId);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RESPONSE - Reply with DOKO(s)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Handle incoming RESPONSE message
   */
  async handleResponse(message, fromPeerId) {
    this.stats.responsesReceived++;

    const pending = this.pendingRequests.get(message.requestId);
    if (!pending) {
      // Response for unknown request (maybe already timed out)
      return;
    }

    clearTimeout(pending.timeout);
    this.pendingRequests.delete(message.requestId);

    // Verify all DOKOs in response
    const verifiedDokos = [];
    for (const doko of message.dokos || []) {
      const result = await this.gateway.verify(doko);
      if (result.valid) {
        verifiedDokos.push(doko);
      }
    }

    if (verifiedDokos.length > 0) {
      pending.resolve(verifiedDokos[0]); // Return first verified DOKO
    } else {
      pending.resolve(null);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REVOKE - Announce DOKO revocation
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create and broadcast a REVOKE message
   * @param {string} dokoHash - Hash of DOKO to revoke
   * @param {string} reason - Revocation reason
   */
  async revoke(dokoHash, reason = 'voluntary') {
    const message = {
      type: KHATA_MESSAGE.REVOKE,
      dokoHash,
      reason,
      revokedAt: Date.now(),
      revokedBy: this.identity.identity.nodeId,
    };

    // Sign the revocation
    const revokePayload = JSON.stringify({
      dokoHash,
      reason,
      revokedAt: message.revokedAt,
      revokedBy: message.revokedBy,
    });
    message.signature = this.identity.sign(revokePayload);

    this.stats.revokesSent++;
    this.emit('revoke-sent', { dokoHash, reason });

    // Broadcast to all peers (high priority, no hop limit for revocations)
    if (this.broadcastToPeers) {
      await this.broadcastToPeers(message);
    }

    return message;
  }

  /**
   * Handle incoming REVOKE message
   */
  async handleRevoke(message, fromPeerId) {
    // Check for duplicate
    const messageHash = computeMessageHash(message);
    if (this.seenMessages.has(messageHash)) {
      this.stats.duplicatesDropped++;
      return;
    }
    this.seenMessages.set(messageHash, Date.now());

    this.stats.revokesReceived++;

    // Get the original DOKO to verify revocation authority
    const originalDoko = this.gateway.lookupByHash(message.dokoHash);
    
    if (originalDoko) {
      // Process revocation through gateway
      const result = await this.gateway.processRevocation(message, originalDoko);
      
      if (result.success) {
        this.emit('revoke', { 
          dokoHash: message.dokoHash, 
          reason: message.reason,
          fromPeerId,
        });

        // ALWAYS propagate revocations (high priority)
        if (this.broadcastToPeers) {
          await this.broadcastToPeers(message, fromPeerId);
        }
      } else {
        this.emit('revoke-rejected', {
          dokoHash: message.dokoHash,
          reason: result.reason,
          fromPeerId,
        });
      }
    } else {
      // We don't have the DOKO, but still propagate the revocation
      // Other nodes might have it
      if (this.broadcastToPeers) {
        await this.broadcastToPeers(message, fromPeerId);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MESSAGE ROUTING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Handle incoming KHATA message (called by network layer)
   */
  async handleMessage(message, fromPeerId) {
    switch (message.type) {
      case KHATA_MESSAGE.ANNOUNCE:
        await this.handleAnnounce(message, fromPeerId);
        break;
      case KHATA_MESSAGE.REQUEST:
        await this.handleRequest(message, fromPeerId);
        break;
      case KHATA_MESSAGE.RESPONSE:
        await this.handleResponse(message, fromPeerId);
        break;
      case KHATA_MESSAGE.REVOKE:
        await this.handleRevoke(message, fromPeerId);
        break;
      default:
        this.emit('unknown-message', { type: message.type, fromPeerId });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Cleanup old seen messages
   */
  cleanup() {
    const now = Date.now();
    const maxAge = this.config.announceTTL;
    
    for (const [hash, timestamp] of this.seenMessages.entries()) {
      if (now - timestamp > maxAge) {
        this.seenMessages.delete(hash);
      }
    }
  }

  /**
   * Get protocol statistics
   */
  getStats() {
    return {
      ...this.stats,
      pendingRequests: this.pendingRequests.size,
      seenMessagesSize: this.seenMessages.size,
    };
  }

  /**
   * Cleanup on shutdown
   */
  destroy() {
    clearInterval(this.cleanupInterval);
    
    // Reject all pending requests
    for (const [requestId, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Protocol shutdown'));
    }
    this.pendingRequests.clear();
    this.seenMessages.clear();
  }
}

export default KhataProtocol;
