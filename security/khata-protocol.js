/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
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
 * Now includes YPC-27 quantum-hard checksums for message integrity.
 * 
 * @module security/khata-protocol
 * @version 1.1.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { ternaryId } from '../utils/ternary-id.js';

// YPC-27 quantum-hard checksums for message integrity
import {
  PROTOCOL_DOMAIN,
  wrapWithChecksum,
  unwrapWithChecksum
} from '../oracle/packet-checksum.js';

const log = createLogger('security:khata');

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
 * Generate a unique message ID (balanced ternary — '666' impossible by design)
 */
function generateMessageId() {
  return ternaryId(16);
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
   * Wrap a KHATA message with YPC-27 quantum-hard checksum.
   * @param {Object} message - The message to wrap
   * @returns {Object} Message with ypc27 field
   * @private
   */
  _wrapWithYpc27(message) {
    return wrapWithChecksum(message, PROTOCOL_DOMAIN.KHATA, this.identity?.identity?.nodeId);
  }

  /**
   * Verify and unwrap a KHATA message with YPC-27 checksum.
   * @param {Object} message - The message to verify
   * @returns {{ message: Object, valid: boolean, error?: string }}
   * @private
   */
  _verifyYpc27(message) {
    // For backward compatibility, messages without ypc27 are considered valid
    if (!message.ypc27) {
      return { message, valid: true };
    }
    return unwrapWithChecksum(message, PROTOCOL_DOMAIN.KHATA);
  }

  /**
   * Create and broadcast an ANNOUNCE message
   * @param {Object} doko - The DOKO to announce
   */
  async announce(doko) {
    let message = {
      type: KHATA_MESSAGE.ANNOUNCE,
      messageId: generateMessageId(),
      doko,
      timestamp: Date.now(),
      ttl: this.config.announceTTL,
      hops: 0,
      originNodeId: this.identity.identity.nodeId,
    };

    // Add YPC-27 quantum-hard checksum
    message = this._wrapWithYpc27(message);

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
    // Verify YPC-27 checksum if present (quantum attack detection)
    const { valid, error } = this._verifyYpc27(message);
    if (!valid) {
      log.warn(`YPC-27 checksum failed for ANNOUNCE from ${fromPeerId}: ${error}`);
      this.stats.checksumFailed = (this.stats.checksumFailed || 0) + 1;
      return;
    }

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
    let message = {
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

    // Add YPC-27 quantum-hard checksum
    message = this._wrapWithYpc27(message);

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
    // Verify YPC-27 checksum if present
    const { valid, error } = this._verifyYpc27(message);
    if (!valid) {
      log.warn(`YPC-27 checksum failed for REQUEST from ${fromPeerId}: ${error}`);
      this.stats.checksumFailed = (this.stats.checksumFailed || 0) + 1;
      return;
    }

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
      let response = {
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

      // Add YPC-27 quantum-hard checksum
      response = this._wrapWithYpc27(response);

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
    // Verify YPC-27 checksum if present
    const { valid, error } = this._verifyYpc27(message);
    if (!valid) {
      log.warn(`YPC-27 checksum failed for RESPONSE from ${fromPeerId}: ${error}`);
      this.stats.checksumFailed = (this.stats.checksumFailed || 0) + 1;
      return;
    }

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
    let message = {
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

    // Add YPC-27 quantum-hard checksum
    message = this._wrapWithYpc27(message);

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
    // Verify YPC-27 checksum if present (CRITICAL for revocations)
    const { valid, error } = this._verifyYpc27(message);
    if (!valid) {
      log.warn(`YPC-27 checksum failed for REVOKE from ${fromPeerId}: ${error}`);
      this.stats.checksumFailed = (this.stats.checksumFailed || 0) + 1;
      return;
    }

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
