/**
 * YAKMESH Connection Rate Limiter
 * 
 * Protects against:
 * - WebSocket connection floods
 * - Handshake spam (expensive signature verification)
 * - Gossip message floods
 * - Cross-network attack attempts
 * 
 * @module mesh/rate-limiter
 */

/**
 * Sliding window rate limiter with per-IP and per-node tracking
 */
export class ConnectionRateLimiter {
  constructor(options = {}) {
    this.config = {
      // Connection rate limits
      maxConnectionsPerMinute: options.maxConnectionsPerMinute || 10,
      maxConnectionsPerHour: options.maxConnectionsPerHour || 60,
      
      // Message rate limits  
      maxMessagesPerSecond: options.maxMessagesPerSecond || 50,
      maxMessagesPerMinute: options.maxMessagesPerMinute || 500,
      
      // Handshake limits (expensive operations)
      maxHandshakesPerMinute: options.maxHandshakesPerMinute || 5,
      
      // Gossip limits
      maxGossipPerSecond: options.maxGossipPerSecond || 20,
      maxRumorsPerMinute: options.maxRumorsPerMinute || 100,
      
      // Ban thresholds
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
    
    // Start cleanup interval
    this._cleanupInterval = setInterval(() => this._cleanup(), this.config.cleanupInterval);
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
   */
  _recordViolation(ip, reason) {
    const record = this.violations.get(ip) || { count: 0, reasons: [] };
    record.count++;
    record.lastViolation = Date.now();
    record.reasons.push(reason);
    this.violations.set(ip, record);
    
    if (record.count >= this.config.banThreshold) {
      this.banned.set(ip, Date.now() + this.config.banDuration);
      console.warn(`🚫 Banned IP ${ip} for ${this.config.banDuration/1000}s. Reasons: ${record.reasons.slice(-3).join(', ')}`);
      return true;
    }
    
    console.warn(`⚠️ Rate limit violation from ${ip}: ${reason} (${record.count}/${this.config.banThreshold})`);
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
   */
  checkMessage(nodeIdOrIp) {
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
    
    // Check per-second limit
    if (record.secondCount >= this.config.maxMessagesPerSecond) {
      return { 
        allowed: false, 
        reason: 'Message rate exceeded (per second)',
        retryAfter: 1
      };
    }
    
    // Check per-minute limit
    if (record.count >= this.config.maxMessagesPerMinute) {
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
    
    // Check per-second limit
    if (record.secondCount >= this.config.maxGossipPerSecond) {
      return { allowed: false, reason: 'Gossip rate exceeded (per second)' };
    }
    
    // Check per-minute limit
    if (record.count >= this.config.maxRumorsPerMinute) {
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
    return {
      activeConnections: this.connections.size,
      activeMessageTracking: this.messages.size,
      activeHandshakes: this.handshakes.size,
      activeGossipTracking: this.gossip.size,
      violations: this.violations.size,
      banned: this.banned.size,
      bannedIPs: Array.from(this.banned.keys()),
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
