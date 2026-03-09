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
 * YAKMESH Connection Rate Limiter
 * 
 * Protects against:
 * - WebSocket connection floods
 * - Handshake spam (expensive signature verification)
 * - Gossip message floods
 * - Cross-network attack attempts
 * 
 * Trust-Proportional Limits:
 * - Trusted nodes get higher limits (they've earned it)
 * - But trusted nodes get STRICTER penalties if they abuse (betrayal tax)
 * - This balances power with accountability
 * 
 * @module mesh/rate-limiter
 */

/**
 * Trust levels for rate limiting
 * Higher trust = higher limits, but also higher abuse penalties
 */
export const TRUST_LEVEL = Object.freeze({
  UNKNOWN: 'unknown',       // New/unverified nodes
  SUSPICIOUS: 'suspicious', // Nodes with some bad behavior
  NORMAL: 'normal',         // Regular nodes
  TRUSTED: 'trusted',       // Established good actors
  VETERAN: 'veteran',       // Long-term high-trust nodes
});

/**
 * Trust-proportional multipliers
 * Format: { limit: multiplier, penalty: multiplier }
 */
const TRUST_MULTIPLIERS = Object.freeze({
  [TRUST_LEVEL.UNKNOWN]: { limit: 0.5, penalty: 1.0 },    // Half limits, normal penalty
  [TRUST_LEVEL.SUSPICIOUS]: { limit: 0.25, penalty: 1.5 }, // Quarter limits, 1.5x penalty
  [TRUST_LEVEL.NORMAL]: { limit: 1.0, penalty: 1.0 },     // Base limits
  [TRUST_LEVEL.TRUSTED]: { limit: 2.0, penalty: 2.0 },    // 2x limits, 2x penalty
  [TRUST_LEVEL.VETERAN]: { limit: 5.0, penalty: 3.0 },    // 5x limits, 3x penalty (betrayal tax)
});

/**
 * Sliding window rate limiter with per-IP and per-node tracking
 */
export class ConnectionRateLimiter {
  constructor(options = {}) {
    this.config = {
      // Connection rate limits (base values)
      maxConnectionsPerMinute: options.maxConnectionsPerMinute || 10,
      maxConnectionsPerHour: options.maxConnectionsPerHour || 60,
      
      // Message rate limits (base values)
      maxMessagesPerSecond: options.maxMessagesPerSecond || 50,
      maxMessagesPerMinute: options.maxMessagesPerMinute || 500,
      
      // Handshake limits (expensive operations)
      maxHandshakesPerMinute: options.maxHandshakesPerMinute || 5,
      
      // Gossip limits
      maxGossipPerSecond: options.maxGossipPerSecond || 20,
      maxRumorsPerMinute: options.maxRumorsPerMinute || 100,
      
      // Ban thresholds (adjusted by trust penalty multiplier)
      banThreshold: options.banThreshold || 5,  // violations before ban
      banDuration: options.banDuration || 300000, // 5 minutes
      
      // Cleanup interval
      cleanupInterval: options.cleanupInterval || 60000, // 1 minute
    };
    
    // Tracking maps
    this.connections = new Map();  // IP -> { count, firstSeen, hourlyCount }
    this.messages = new Map();     // IP/nodeId -> { count, windowStart }
    this.handshakes = new Map();   // IP -> { count, windowStart }
    this.gossip = new Map();       // nodeId -> { count, windowStart }
    this.violations = new Map();   // IP -> { count, lastViolation }
    this.banned = new Map();       // IP -> banExpiry timestamp
    
    // Trust level cache (nodeId -> TRUST_LEVEL)
    this.trustLevels = new Map();
    
    // Start cleanup interval
    this._cleanupInterval = setInterval(() => this._cleanup(), this.config.cleanupInterval);
  }
  
  /**
   * Set trust level for a node (call this when trust changes)
   * @param {string} nodeId - Node identifier
   * @param {string} trustLevel - One of TRUST_LEVEL values
   */
  setTrustLevel(nodeId, trustLevel) {
    if (!Object.values(TRUST_LEVEL).includes(trustLevel)) {
      trustLevel = TRUST_LEVEL.NORMAL;
    }
    this.trustLevels.set(nodeId, trustLevel);
  }
  
  /**
   * Get trust level for a node
   */
  getTrustLevel(nodeId) {
    return this.trustLevels.get(nodeId) || TRUST_LEVEL.UNKNOWN;
  }
  
  /**
   * Get effective limit based on trust level
   * @private
   */
  _getEffectiveLimit(baseLimit, nodeId) {
    const trustLevel = this.getTrustLevel(nodeId);
    const multiplier = TRUST_MULTIPLIERS[trustLevel]?.limit || 1.0;
    return Math.ceil(baseLimit * multiplier);
  }
  
  /**
   * Get effective penalty based on trust level
   * Higher trust = higher penalty (betrayal tax)
   * @private
   */
  _getEffectivePenalty(nodeId) {
    const trustLevel = this.getTrustLevel(nodeId);
    return TRUST_MULTIPLIERS[trustLevel]?.penalty || 1.0;
  }
  
  /**
   * Check if an IP is currently banned
   */
  isBanned(ip) {
    const banExpiry = this.banned.get(ip);
    if (!banExpiry) return false;
    
    if (Date.now() > banExpiry) {
      this.banned.delete(ip);
      return false;
    }
    return true;
  }
  
  /**
   * Record a violation and potentially ban
   * Uses trust-proportional penalty (higher trust = stricter penalty)
   */
  _recordViolation(ip, reason, nodeId = null) {
    const record = this.violations.get(ip) || { count: 0, reasons: [], nodeId };
    const penaltyMultiplier = nodeId ? this._getEffectivePenalty(nodeId) : 1.0;
    
    // Apply penalty multiplier - trusted nodes get penalized harder
    const effectivePenalty = penaltyMultiplier;
    record.count += effectivePenalty;
    record.lastViolation = Date.now();
    record.reasons.push(reason);
    if (nodeId) record.nodeId = nodeId;
    this.violations.set(ip, record);
    
    // Effective ban threshold (lower for high-trust nodes that betray)
    const effectiveThreshold = this.config.banThreshold / penaltyMultiplier;
    
    if (record.count >= effectiveThreshold) {
      // Ban duration is also extended for trusted nodes that abuse
      const effectiveBanDuration = this.config.banDuration * penaltyMultiplier;
      this.banned.set(ip, Date.now() + effectiveBanDuration);
      
      const trustLevel = nodeId ? this.getTrustLevel(nodeId) : TRUST_LEVEL.UNKNOWN;
      console.warn(`🚫 Banned IP ${ip} for ${effectiveBanDuration/1000}s (trust: ${trustLevel}, penalty: ${penaltyMultiplier}x). Reasons: ${record.reasons.slice(-3).join(', ')}`);
      return true;
    }
    
    console.warn(`⚠️ Rate limit violation from ${ip}: ${reason} (${record.count.toFixed(1)}/${effectiveThreshold} with ${penaltyMultiplier}x penalty)`);
    return false;
  }
  
  /**
   * Check if a new connection is allowed
   * @param {string} ip - Client IP address
   * @returns {{ allowed: boolean, reason?: string, retryAfter?: number }}
   */
  checkConnection(ip) {
    if (this.isBanned(ip)) {
      const retryAfter = Math.ceil((this.banned.get(ip) - Date.now()) / 1000);
      return { allowed: false, reason: 'IP is temporarily banned', retryAfter };
    }
    
    const now = Date.now();
    const record = this.connections.get(ip) || { 
      count: 0, 
      firstSeen: now, 
      hourlyCount: 0,
      hourStart: now 
    };
    
    // Reset minute window
    if (now - record.firstSeen > 60000) {
      record.count = 0;
      record.firstSeen = now;
    }
    
    // Reset hour window
    if (now - record.hourStart > 3600000) {
      record.hourlyCount = 0;
      record.hourStart = now;
    }
    
    // Check limits
    if (record.count >= this.config.maxConnectionsPerMinute) {
      this._recordViolation(ip, 'connection_flood_minute');
      return { 
        allowed: false, 
        reason: 'Too many connections per minute',
        retryAfter: Math.ceil((record.firstSeen + 60000 - now) / 1000)
      };
    }
    
    if (record.hourlyCount >= this.config.maxConnectionsPerHour) {
      this._recordViolation(ip, 'connection_flood_hour');
      return { 
        allowed: false, 
        reason: 'Too many connections per hour',
        retryAfter: Math.ceil((record.hourStart + 3600000 - now) / 1000)
      };
    }
    
    // Allow and record
    record.count++;
    record.hourlyCount++;
    this.connections.set(ip, record);
    
    return { allowed: true };
  }
  
  /**
   * Check if a handshake (signature verification) is allowed
   * These are expensive operations - strict rate limiting
   */
  checkHandshake(ip) {
    if (this.isBanned(ip)) {
      return { allowed: false, reason: 'IP is temporarily banned' };
    }
    
    const now = Date.now();
    const record = this.handshakes.get(ip) || { count: 0, windowStart: now };
    
    // Reset window
    if (now - record.windowStart > 60000) {
      record.count = 0;
      record.windowStart = now;
    }
    
    if (record.count >= this.config.maxHandshakesPerMinute) {
      this._recordViolation(ip, 'handshake_flood');
      return { 
        allowed: false, 
        reason: 'Too many handshake attempts',
        retryAfter: Math.ceil((record.windowStart + 60000 - now) / 1000)
      };
    }
    
    record.count++;
    this.handshakes.set(ip, record);
    return { allowed: true };
  }
  
  /**
   * Check if a message from a node is allowed
   * Uses trust-proportional limits
   */
  checkMessage(nodeIdOrIp, nodeId = null) {
    // If only one arg and it looks like a nodeId, use it for trust lookup
    const effectiveNodeId = nodeId || (nodeIdOrIp.startsWith('DOKO-') ? nodeIdOrIp : null);
    
    const now = Date.now();
    const record = this.messages.get(nodeIdOrIp) || { 
      count: 0, 
      secondCount: 0,
      windowStart: now,
      secondStart: now 
    };
    
    // Reset second window
    if (now - record.secondStart > 1000) {
      record.secondCount = 0;
      record.secondStart = now;
    }
    
    // Reset minute window
    if (now - record.windowStart > 60000) {
      record.count = 0;
      record.windowStart = now;
    }
    
    // Get trust-proportional limits
    const effectivePerSecond = this._getEffectiveLimit(this.config.maxMessagesPerSecond, effectiveNodeId);
    const effectivePerMinute = this._getEffectiveLimit(this.config.maxMessagesPerMinute, effectiveNodeId);
    
    // Check per-second limit
    if (record.secondCount >= effectivePerSecond) {
      return { 
        allowed: false, 
        reason: 'Message rate exceeded (per second)',
        retryAfter: 1
      };
    }
    
    // Check per-minute limit
    if (record.count >= effectivePerMinute) {
      return { 
        allowed: false, 
        reason: 'Message rate exceeded (per minute)',
        retryAfter: Math.ceil((record.windowStart + 60000 - now) / 1000)
      };
    }
    
    record.count++;
    record.secondCount++;
    this.messages.set(nodeIdOrIp, record);
    return { allowed: true };
  }
  
  /**
   * Check if a gossip/rumor from a node is allowed
   * Uses trust-proportional limits
   */
  checkGossip(nodeId) {
    const now = Date.now();
    const record = this.gossip.get(nodeId) || { 
      count: 0,
      secondCount: 0, 
      windowStart: now,
      secondStart: now
    };
    
    // Reset second window
    if (now - record.secondStart > 1000) {
      record.secondCount = 0;
      record.secondStart = now;
    }
    
    // Reset minute window  
    if (now - record.windowStart > 60000) {
      record.count = 0;
      record.windowStart = now;
    }
    
    // Get trust-proportional limits
    const effectivePerSecond = this._getEffectiveLimit(this.config.maxGossipPerSecond, nodeId);
    const effectivePerMinute = this._getEffectiveLimit(this.config.maxRumorsPerMinute, nodeId);
    
    // Check per-second limit
    if (record.secondCount >= effectivePerSecond) {
      return { allowed: false, reason: 'Gossip rate exceeded (per second)' };
    }
    
    // Check per-minute limit
    if (record.count >= effectivePerMinute) {
      return { allowed: false, reason: 'Gossip rate exceeded (per minute)' };
    }
    
    record.count++;
    record.secondCount++;
    this.gossip.set(nodeId, record);
    return { allowed: true };
  }
  
  /**
   * Get statistics for monitoring
   */
  getStats() {
    // Count nodes by trust level
    const trustDistribution = {
      [TRUST_LEVEL.UNKNOWN]: 0,
      [TRUST_LEVEL.SUSPICIOUS]: 0,
      [TRUST_LEVEL.NORMAL]: 0,
      [TRUST_LEVEL.TRUSTED]: 0,
      [TRUST_LEVEL.VETERAN]: 0,
    };
    
    for (const level of this.trustLevels.values()) {
      trustDistribution[level] = (trustDistribution[level] || 0) + 1;
    }
    
    return {
      activeConnections: this.connections.size,
      activeMessageTracking: this.messages.size,
      activeHandshakes: this.handshakes.size,
      activeGossipTracking: this.gossip.size,
      violations: this.violations.size,
      banned: this.banned.size,
      bannedIPs: Array.from(this.banned.keys()),
      trustLevelsTracked: this.trustLevels.size,
      trustDistribution,
    };
  }
  
  /**
   * Cleanup old records
   */
  _cleanup() {
    const now = Date.now();
    const staleThreshold = 300000; // 5 minutes
    
    // Clean old connection records
    for (const [ip, record] of this.connections) {
      if (now - record.firstSeen > staleThreshold && now - record.hourStart > staleThreshold) {
        this.connections.delete(ip);
      }
    }
    
    // Clean old message records
    for (const [id, record] of this.messages) {
      if (now - record.windowStart > staleThreshold) {
        this.messages.delete(id);
      }
    }
    
    // Clean old handshake records
    for (const [ip, record] of this.handshakes) {
      if (now - record.windowStart > staleThreshold) {
        this.handshakes.delete(ip);
      }
    }
    
    // Clean old gossip records
    for (const [id, record] of this.gossip) {
      if (now - record.windowStart > staleThreshold) {
        this.gossip.delete(id);
      }
    }
    
    // Clean old violations (after 1 hour)
    for (const [ip, record] of this.violations) {
      if (now - record.lastViolation > 3600000) {
        this.violations.delete(ip);
      }
    }
    
    // Clean expired bans
    for (const [ip, expiry] of this.banned) {
      if (now > expiry) {
        this.banned.delete(ip);
      }
    }
  }
  
  /**
   * Stop the rate limiter
   */
  stop() {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval);
    }
  }
}

/**
 * Singleton instance for easy import
 */
let _instance = null;

export function getRateLimiter(options) {
  if (!_instance) {
    _instance = new ConnectionRateLimiter(options);
  }
  return _instance;
}

export default ConnectionRateLimiter;
