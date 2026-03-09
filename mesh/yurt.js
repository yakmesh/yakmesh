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
 * YURT - YAK Unified Room Tags
 * 
 * A decentralized room directory protocol for YakApp chat rooms.
 * Rooms can be discovered through gossip OR accessed directly via yak:// links.
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║  "Every yurt on the steppe has its own fire.                                 ║
 * ║   Find them by the smoke, or follow the path you know."                      ║
 * ║                                                                               ║
 * ║  Discovery is optional. Direct access always works.                          ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * DISCOVERY MODES:
 * 1. DIRECT LINK - yak://hostname/bundleId (works immediately, no gossip needed)
 * 2. WEBSITE EMBED - "Join Chat" button linking to yak:// or https gateway
 * 3. GOSSIP - Browse rooms propagated through the mesh network
 * 4. QR CODE - Scan to join (encodes yak:// URI)
 * 
 * SECURITY:
 * - All entries are signed by the hosting node
 * - Joining still requires GUMBA proof (discovery != access)
 * - Nodes can filter/weight entries by reputation
 * - Spam entries die naturally (no re-propagation)
 * 
 * URI SCHEME:
 * yak://host:port/bundleId
 * yak://host:port/bundleId?invite=<attestation>
 * 
 * Part of the Himalayan Protocol Family:
 * - ANNEX: E2E encrypted channels
 * - DOKO: Identity certificates
 * - GUMBA: Access control (what YURT points to)
 * - YURT: Room discovery (this module)
 * 
 * Named after the portable tent homes of Central Asian nomads - 
 * visible from afar, welcoming to guests, but yours to control.
 * 
 * @module mesh/yurt
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createHash } from 'crypto';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { createLogger } from '../utils/logger.js';
import EventEmitter from 'events';

const log = createLogger('mesh:yurt');

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const YURT_CONFIG = Object.freeze({
  // Protocol
  version: 1,
  defaultPort: 8787,
  scheme: 'yak',
  
  // Gossip
  maxEntryAge: 7 * 24 * 60 * 60 * 1000,   // 7 days max
  refreshInterval: 60 * 60 * 1000,         // Refresh own listings hourly
  gossipInterval: 5 * 60 * 1000,           // Gossip every 5 minutes
  maxEntriesPerGossip: 50,                 // Limit per gossip message
  maxDirectorySize: 10000,                 // Max entries to store
  
  // Validation
  maxNameLength: 64,
  maxDescriptionLength: 256,
  maxTagCount: 10,
  maxTagLength: 24,
  
  // Entry types
  visibility: {
    PUBLIC: 'public',           // Anyone can request to join
    INVITE_ONLY: 'invite-only', // Requires attestation
    UNLISTED: 'unlisted',       // Direct link only, no gossip
  },
  
  // Message types
  messageTypes: {
    ANNOUNCE: 'yurt:announce',      // Publish/update a room listing
    WITHDRAW: 'yurt:withdraw',      // Remove a room listing
    GOSSIP: 'yurt:gossip',          // Share known listings
    QUERY: 'yurt:query',            // Search for rooms
    QUERY_RESPONSE: 'yurt:response', // Search results
  },
});

// ═══════════════════════════════════════════════════════════════════════════════
// YURT ENTRY - A single room listing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * YurtEntry - A discoverable room listing
 * 
 * "Like smoke rising from a yurt - visible from far away,
 *  but entering requires the owner's welcome."
 */
export class YurtEntry {
  /**
   * Create a new room listing
   */
  constructor(options = {}) {
    // Required
    this.bundleId = options.bundleId;
    this.hostNodeId = options.hostNodeId;
    this.hostEndpoint = options.hostEndpoint;
    
    // Metadata
    this.name = options.name || this.bundleId;
    this.description = options.description || '';
    this.visibility = options.visibility || YURT_CONFIG.visibility.PUBLIC;
    this.tags = options.tags || [];
    
    // Stats (approximate, gossip-updated)
    this.memberCount = options.memberCount || 0;
    this.messageCount = options.messageCount || 0;
    
    // Timestamps
    this.createdAt = options.createdAt || Date.now();
    this.updatedAt = options.updatedAt || Date.now();
    this.lastSeen = options.lastSeen || Date.now();
    
    // Signature (set by sign())
    this.signature = options.signature || null;
    
    // Entry ID (derived)
    this.entryId = this._computeEntryId();
  }
  
  /**
   * Compute unique entry ID from bundleId + hostNodeId
   */
  _computeEntryId() {
    return bytesToHex(sha3_256(utf8ToBytes(`${this.bundleId}:${this.hostNodeId}`)));
  }
  
  /**
   * Validate entry fields
   */
  validate() {
    const errors = [];
    
    if (!this.bundleId) errors.push('bundleId required');
    if (!this.hostNodeId) errors.push('hostNodeId required');
    if (!this.hostEndpoint) errors.push('hostEndpoint required');
    
    const name = this.name || '';
    const description = this.description || '';
    const tags = this.tags || [];
    
    if (name.length > YURT_CONFIG.maxNameLength) {
      errors.push(`name exceeds ${YURT_CONFIG.maxNameLength} chars`);
    }
    
    if (description.length > YURT_CONFIG.maxDescriptionLength) {
      errors.push(`description exceeds ${YURT_CONFIG.maxDescriptionLength} chars`);
    }
    
    if (tags.length > YURT_CONFIG.maxTagCount) {
      errors.push(`too many tags (max ${YURT_CONFIG.maxTagCount})`);
    }
    
    for (const tag of tags) {
      if (tag.length > YURT_CONFIG.maxTagLength) {
        errors.push(`tag "${tag}" exceeds ${YURT_CONFIG.maxTagLength} chars`);
      }
    }
    
    if (!Object.values(YURT_CONFIG.visibility).includes(this.visibility)) {
      errors.push(`invalid visibility: ${this.visibility}`);
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }
  
  /**
   * Get the signable payload (deterministic JSON)
   */
  getSignablePayload() {
    return JSON.stringify({
      bundleId: this.bundleId,
      hostNodeId: this.hostNodeId,
      hostEndpoint: this.hostEndpoint,
      name: this.name,
      description: this.description,
      visibility: this.visibility,
      tags: [...this.tags].sort(),
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    });
  }
  
  /**
   * Sign the entry with host's secret key
   */
  sign(secretKey) {
    const payload = utf8ToBytes(this.getSignablePayload());
    const keyBytes = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
    const signature = mlDsa65Sign(payload, keyBytes);
    this.signature = bytesToHex(signature);
    return this;
  }
  
  /**
   * Verify entry signature
   */
  verify(publicKey) {
    if (!this.signature) return false;
    
    try {
      const payload = utf8ToBytes(this.getSignablePayload());
      const signatureBytes = hexToBytes(this.signature);
      const publicKeyBytes = typeof publicKey === 'string' 
        ? hexToBytes(publicKey) 
        : publicKey;
      
      return mlDsa65Verify(signatureBytes, payload, publicKeyBytes);
    } catch (err) {
      log.warn('Signature verification failed', { error: err.message });
      return false;
    }
  }
  
  /**
   * Check if entry is expired
   */
  isExpired() {
    return Date.now() - this.lastSeen > YURT_CONFIG.maxEntryAge;
  }
  
  /**
   * Update stats (doesn't require re-signing)
   */
  updateStats(memberCount, messageCount) {
    this.memberCount = memberCount;
    this.messageCount = messageCount;
    this.lastSeen = Date.now();
  }
  
  /**
   * Generate yak:// URI for this room
   */
  toUri() {
    const url = new URL(`${YURT_CONFIG.scheme}://${this.hostEndpoint}`);
    url.pathname = `/${this.bundleId}`;
    return url.toString();
  }
  
  /**
   * Generate shareable invite link with optional attestation
   */
  toInviteUri(attestation = null) {
    let uri = this.toUri();
    if (attestation) {
      uri += `?invite=${encodeURIComponent(JSON.stringify(attestation))}`;
    }
    return uri;
  }
  
  /**
   * Export to JSON
   */
  toJSON() {
    return {
      entryId: this.entryId,
      bundleId: this.bundleId,
      hostNodeId: this.hostNodeId,
      hostEndpoint: this.hostEndpoint,
      name: this.name,
      description: this.description,
      visibility: this.visibility,
      tags: this.tags,
      memberCount: this.memberCount,
      messageCount: this.messageCount,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      lastSeen: this.lastSeen,
      signature: this.signature,
    };
  }
  
  /**
   * Create from JSON
   */
  static fromJSON(data) {
    return new YurtEntry(data);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// YURT LINK - URI Parser and Direct Access
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * YurtLink - Parse and create yak:// URIs
 * 
 * "The path is clear. No map needed. Just follow."
 */
export class YurtLink {
  /**
   * Parse a yak:// URI
   * 
   * Formats:
   * - yak://host/bundleId
   * - yak://host:port/bundleId
   * - yak://host/bundleId?invite=<attestation>
   */
  static parse(uri) {
    try {
      // Handle yak:// scheme (not recognized by URL constructor)
      const normalized = uri.replace(/^yak:\/\//, 'https://');
      const url = new URL(normalized);
      
      const bundleId = url.pathname.replace(/^\//, '').split('/')[0];
      const port = url.port || YURT_CONFIG.defaultPort;
      const host = url.hostname;
      
      // Parse invite attestation if present
      let invite = null;
      const inviteParam = url.searchParams.get('invite');
      if (inviteParam) {
        try {
          invite = JSON.parse(decodeURIComponent(inviteParam));
        } catch (e) {
          log.warn('Invalid invite parameter in URI');
        }
      }
      
      return {
        valid: true,
        scheme: YURT_CONFIG.scheme,
        host,
        port: parseInt(port, 10),
        bundleId,
        endpoint: `${host}:${port}`,
        invite,
        original: uri,
      };
    } catch (err) {
      return {
        valid: false,
        error: err.message,
        original: uri,
      };
    }
  }
  
  /**
   * Create a yak:// URI
   */
  static create(host, bundleId, options = {}) {
    const port = options.port || YURT_CONFIG.defaultPort;
    const portSuffix = port === YURT_CONFIG.defaultPort ? '' : `:${port}`;
    
    let uri = `${YURT_CONFIG.scheme}://${host}${portSuffix}/${bundleId}`;
    
    if (options.invite) {
      uri += `?invite=${encodeURIComponent(JSON.stringify(options.invite))}`;
    }
    
    return uri;
  }
  
  /**
   * Validate a yak:// URI format
   */
  static isValid(uri) {
    if (!uri || typeof uri !== 'string') return false;
    if (!uri.startsWith('yak://')) return false;
    
    const parsed = YurtLink.parse(uri);
    return !!(parsed.valid && parsed.bundleId);
  }
  
  /**
   * Convert to HTTPS gateway URL (for browser fallback)
   */
  static toHttpsGateway(uri, gatewayUrl = 'https://yak.to') {
    const parsed = YurtLink.parse(uri);
    if (!parsed.valid) return null;
    
    return `${gatewayUrl}/join/${parsed.host}:${parsed.port}/${parsed.bundleId}`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// YURT DIRECTORY - Local room index
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * YurtDirectory - Local index of known rooms
 * 
 * "The traveler's memory of welcoming fires."
 */
export class YurtDirectory extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = options;
    
    // All known entries
    this.entries = new Map(); // entryId -> YurtEntry
    
    // Indexes for fast lookup
    this.byBundle = new Map();     // bundleId -> entryId
    this.byHost = new Map();       // hostNodeId -> Set<entryId>
    this.byTag = new Map();        // tag -> Set<entryId>
    
    // Our own listings
    this.ownListings = new Set();  // entryIds we host
    
    // Stats
    this.stats = {
      entriesAdded: 0,
      entriesRemoved: 0,
      entriesExpired: 0,
    };
  }
  
  /**
   * Add or update an entry
   */
  add(entry, verifySignature = true, publicKeyLookup = null) {
    // Validate
    const validation = entry.validate();
    if (!validation.valid) {
      return { success: false, errors: validation.errors };
    }
    
    // Verify signature if required
    if (verifySignature && entry.signature) {
      if (publicKeyLookup) {
        const publicKey = publicKeyLookup(entry.hostNodeId);
        if (publicKey && !entry.verify(publicKey)) {
          return { success: false, errors: ['signature verification failed'] };
        }
      }
    }
    
    // Check size limit
    if (this.entries.size >= YURT_CONFIG.maxDirectorySize && !this.entries.has(entry.entryId)) {
      this._evictOldest();
    }
    
    // Remove from old indexes if updating
    if (this.entries.has(entry.entryId)) {
      this._removeFromIndexes(entry.entryId);
    }
    
    // Add to directory
    this.entries.set(entry.entryId, entry);
    this._addToIndexes(entry);
    
    this.stats.entriesAdded++;
    this.emit('entry:added', entry);
    
    log.debug('Entry added', { 
      bundleId: entry.bundleId, 
      name: entry.name,
      host: entry.hostEndpoint,
    });
    
    return { success: true, entryId: entry.entryId };
  }
  
  /**
   * Remove an entry
   */
  remove(entryId) {
    const entry = this.entries.get(entryId);
    if (!entry) return false;
    
    this._removeFromIndexes(entryId);
    this.entries.delete(entryId);
    this.ownListings.delete(entryId);
    
    this.stats.entriesRemoved++;
    this.emit('entry:removed', entry);
    
    return true;
  }
  
  /**
   * Get entry by ID
   */
  get(entryId) {
    return this.entries.get(entryId) || null;
  }
  
  /**
   * Get entry by bundle ID
   */
  getByBundle(bundleId) {
    const entryId = this.byBundle.get(bundleId);
    return entryId ? this.entries.get(entryId) : null;
  }
  
  /**
   * Search entries
   */
  search(options = {}) {
    const { query, tags, visibility, limit = 50 } = options;
    
    let results = Array.from(this.entries.values());
    
    // Filter by visibility
    if (visibility) {
      results = results.filter(e => e.visibility === visibility);
    }
    
    // Filter by tags
    if (tags && tags.length > 0) {
      results = results.filter(e => 
        tags.some(tag => e.tags.includes(tag.toLowerCase()))
      );
    }
    
    // Filter by text query (searches name, description)
    if (query) {
      const q = query.toLowerCase();
      results = results.filter(e => 
        e.name.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        e.tags.some(t => t.toLowerCase().includes(q))
      );
    }
    
    // Sort by activity (most recent first)
    results.sort((a, b) => b.lastSeen - a.lastSeen);
    
    // Apply limit
    return results.slice(0, limit);
  }
  
  /**
   * Get entries by host
   */
  getByHost(hostNodeId) {
    const entryIds = this.byHost.get(hostNodeId) || new Set();
    return Array.from(entryIds).map(id => this.entries.get(id)).filter(Boolean);
  }
  
  /**
   * Get entries by tag
   */
  getByTag(tag) {
    const entryIds = this.byTag.get(tag.toLowerCase()) || new Set();
    return Array.from(entryIds).map(id => this.entries.get(id)).filter(Boolean);
  }
  
  /**
   * List all public entries
   */
  listPublic(limit = 100) {
    return this.search({ 
      visibility: YURT_CONFIG.visibility.PUBLIC, 
      limit,
    });
  }
  
  /**
   * Mark an entry as our own listing
   */
  markAsOwn(entryId) {
    if (this.entries.has(entryId)) {
      this.ownListings.add(entryId);
    }
  }
  
  /**
   * Get our own listings
   */
  getOwnListings() {
    return Array.from(this.ownListings)
      .map(id => this.entries.get(id))
      .filter(Boolean);
  }
  
  /**
   * Cleanup expired entries
   */
  cleanup() {
    let cleaned = 0;
    
    for (const [entryId, entry] of this.entries) {
      // Don't expire our own listings
      if (this.ownListings.has(entryId)) continue;
      
      if (entry.isExpired()) {
        this.remove(entryId);
        cleaned++;
        this.stats.entriesExpired++;
      }
    }
    
    if (cleaned > 0) {
      log.debug('Cleaned expired entries', { count: cleaned });
    }
    
    return cleaned;
  }
  
  /**
   * Evict oldest entries when at capacity
   */
  _evictOldest() {
    const sorted = Array.from(this.entries.entries())
      .filter(([id]) => !this.ownListings.has(id))
      .sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    
    // Evict oldest 10%
    const toEvict = Math.max(1, Math.floor(sorted.length * 0.1));
    for (let i = 0; i < toEvict && i < sorted.length; i++) {
      this.remove(sorted[i][0]);
    }
  }
  
  /**
   * Add entry to indexes
   */
  _addToIndexes(entry) {
    this.byBundle.set(entry.bundleId, entry.entryId);
    
    if (!this.byHost.has(entry.hostNodeId)) {
      this.byHost.set(entry.hostNodeId, new Set());
    }
    this.byHost.get(entry.hostNodeId).add(entry.entryId);
    
    for (const tag of entry.tags) {
      const t = tag.toLowerCase();
      if (!this.byTag.has(t)) {
        this.byTag.set(t, new Set());
      }
      this.byTag.get(t).add(entry.entryId);
    }
  }
  
  /**
   * Remove entry from indexes
   */
  _removeFromIndexes(entryId) {
    const entry = this.entries.get(entryId);
    if (!entry) return;
    
    this.byBundle.delete(entry.bundleId);
    this.byHost.get(entry.hostNodeId)?.delete(entryId);
    
    for (const tag of entry.tags) {
      this.byTag.get(tag.toLowerCase())?.delete(entryId);
    }
  }
  
  /**
   * Get directory stats
   */
  getStats() {
    return {
      totalEntries: this.entries.size,
      ownListings: this.ownListings.size,
      uniqueHosts: this.byHost.size,
      uniqueTags: this.byTag.size,
      ...this.stats,
    };
  }
  
  /**
   * Export for persistence
   */
  export() {
    return {
      entries: Array.from(this.entries.values()).map(e => e.toJSON()),
      ownListings: Array.from(this.ownListings),
      exportedAt: Date.now(),
    };
  }
  
  /**
   * Import from persistence
   */
  import(data) {
    for (const entryData of data.entries) {
      const entry = YurtEntry.fromJSON(entryData);
      this.add(entry, false); // Skip signature verification for persisted data
    }
    
    for (const entryId of data.ownListings || []) {
      this.ownListings.add(entryId);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// YURT GOSSIP - Room discovery propagation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * YurtGossip - Propagate room listings through the mesh
 * 
 * "Stories spread around campfires. So do directions to new camps."
 */
export class YurtGossip extends EventEmitter {
  /**
   * @param {Object} identity - Node identity
   * @param {YurtDirectory} directory - Local directory
   * @param {Object} mesh - Mesh network interface
   */
  constructor(identity, directory, mesh, options = {}) {
    super();
    
    this.identity = identity;
    this.directory = directory;
    this.mesh = mesh;
    this.options = options;
    this.keyResolver = options.keyResolver || null;
    
    // Track what we've sent to avoid duplicate gossip
    this.sentTo = new Map(); // peerId -> { entryId -> timestamp }
    
    // Gossip timers
    this.gossipTimer = null;
    this.refreshTimer = null;
    
    // Stats
    this.stats = {
      gossipsSent: 0,
      gossipsReceived: 0,
      entriesReceived: 0,
      entriesForwarded: 0,
    };
    
    // Handle incoming gossip
    this._setupHandlers();
  }
  
  /**
   * Start gossip timers
   */
  start() {
    // Periodic gossip to peers
    this.gossipTimer = setInterval(() => {
      this._gossipToPeers();
    }, YURT_CONFIG.gossipInterval);
    
    // Refresh own listings
    this.refreshTimer = setInterval(() => {
      this._refreshOwnListings();
    }, YURT_CONFIG.refreshInterval);
    
    log.info('YURT gossip started');
    
    // Initial gossip
    setTimeout(() => this._gossipToPeers(), 5000);
  }
  
  /**
   * Stop gossip timers
   */
  stop() {
    if (this.gossipTimer) {
      clearInterval(this.gossipTimer);
      this.gossipTimer = null;
    }
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    log.info('YURT gossip stopped');
  }
  
  /**
   * Announce a room (publish to network)
   */
  announce(entry) {
    // Sign with our identity
    entry.sign(this.identity.identity.secretKey);
    
    // Add to directory
    const result = this.directory.add(entry, false);
    if (result.success) {
      this.directory.markAsOwn(entry.entryId);
      
      // Broadcast to peers
      this._broadcast({
        type: YURT_CONFIG.messageTypes.ANNOUNCE,
        entry: entry.toJSON(),
        from: this.identity.identity.nodeId,
        timestamp: Date.now(),
      });
      
      log.info('Room announced', { name: entry.name, bundleId: entry.bundleId });
    }
    
    return result;
  }
  
  /**
   * Withdraw a room (remove from network)
   */
  withdraw(bundleId) {
    const entry = this.directory.getByBundle(bundleId);
    if (!entry || !this.directory.ownListings.has(entry.entryId)) {
      return { success: false, error: 'NOT_OWN_LISTING' };
    }
    
    // Broadcast withdrawal
    this._broadcast({
      type: YURT_CONFIG.messageTypes.WITHDRAW,
      bundleId,
      hostNodeId: this.identity.identity.nodeId,
      timestamp: Date.now(),
    });
    
    this.directory.remove(entry.entryId);
    
    log.info('Room withdrawn', { bundleId });
    return { success: true };
  }
  
  /**
   * Query the network for rooms
   */
  query(options = {}) {
    const queryId = bytesToHex(randomBytes(16));
    
    this._broadcast({
      type: YURT_CONFIG.messageTypes.QUERY,
      queryId,
      query: options.query || null,
      tags: options.tags || [],
      from: this.identity.identity.nodeId,
      timestamp: Date.now(),
    });
    
    return queryId;
  }
  
  /**
   * Setup message handlers
   */
  _setupHandlers() {
    if (!this.mesh) return;
    
    this.mesh.on('message', (message) => {
      if (!message.type?.startsWith('yurt:')) return;
      
      switch (message.type) {
        case YURT_CONFIG.messageTypes.ANNOUNCE:
          this._handleAnnounce(message);
          break;
        case YURT_CONFIG.messageTypes.WITHDRAW:
          this._handleWithdraw(message);
          break;
        case YURT_CONFIG.messageTypes.GOSSIP:
          this._handleGossip(message);
          break;
        case YURT_CONFIG.messageTypes.QUERY:
          this._handleQuery(message);
          break;
        case YURT_CONFIG.messageTypes.QUERY_RESPONSE:
          this._handleQueryResponse(message);
          break;
      }
    });
  }
  
  /**
   * Handle incoming announcement
   */
  _handleAnnounce(message) {
    const entry = YurtEntry.fromJSON(message.entry);
    
    // Don't process our own announcements
    if (entry.hostNodeId === this.identity.identity.nodeId) return;
    
    // Verify and add
    const result = this.directory.add(entry, true, (nodeId) => {
      return this._getPublicKey(nodeId);
    });
    
    if (result.success) {
      this.stats.entriesReceived++;
      this.emit('entry:discovered', entry);
    }
  }
  
  /**
   * Handle withdrawal
   */
  _handleWithdraw(message) {
    const entry = this.directory.getByBundle(message.bundleId);
    if (entry && entry.hostNodeId === message.hostNodeId) {
      this.directory.remove(entry.entryId);
    }
  }
  
  /**
   * Handle incoming gossip
   */
  _handleGossip(message) {
    this.stats.gossipsReceived++;
    
    for (const entryData of message.entries || []) {
      const entry = YurtEntry.fromJSON(entryData);
      
      // Skip our own
      if (entry.hostNodeId === this.identity.identity.nodeId) continue;
      
      // Add with verification
      const result = this.directory.add(entry, true, (nodeId) => {
        return this._getPublicKey(nodeId);
      });
      
      if (result.success) {
        this.stats.entriesReceived++;
      }
    }
  }
  
  /**
   * Handle query
   */
  _handleQuery(message) {
    // Search local directory
    const results = this.directory.search({
      query: message.query,
      tags: message.tags,
      visibility: YURT_CONFIG.visibility.PUBLIC,
      limit: 20,
    });
    
    if (results.length === 0) return;
    
    // Send response directly to querier
    this.mesh.send(message.from, {
      type: YURT_CONFIG.messageTypes.QUERY_RESPONSE,
      queryId: message.queryId,
      entries: results.map(e => e.toJSON()),
      from: this.identity.identity.nodeId,
      timestamp: Date.now(),
    });
  }
  
  /**
   * Handle query response
   */
  _handleQueryResponse(message) {
    this.emit('query:response', {
      queryId: message.queryId,
      entries: message.entries.map(e => YurtEntry.fromJSON(e)),
      from: message.from,
    });
  }
  
  /**
   * Gossip to connected peers
   */
  _gossipToPeers() {
    const peers = this.mesh?.getPeers?.() || [];
    if (peers.length === 0) return;
    
    // Get entries to gossip (public only)
    const entries = this.directory.listPublic(YURT_CONFIG.maxEntriesPerGossip);
    if (entries.length === 0) return;
    
    const now = Date.now();
    
    for (const peer of peers) {
      // Check what we've already sent to this peer
      const sent = this.sentTo.get(peer.id) || new Map();
      
      // Filter to entries not recently sent
      const toSend = entries.filter(e => {
        const lastSent = sent.get(e.entryId) || 0;
        return now - lastSent > YURT_CONFIG.gossipInterval;
      });
      
      if (toSend.length === 0) continue;
      
      // Send gossip
      this.mesh.send(peer.id, {
        type: YURT_CONFIG.messageTypes.GOSSIP,
        entries: toSend.map(e => e.toJSON()),
        from: this.identity.identity.nodeId,
        timestamp: now,
      });
      
      // Update sent tracking
      for (const entry of toSend) {
        sent.set(entry.entryId, now);
      }
      this.sentTo.set(peer.id, sent);
      
      this.stats.gossipsSent++;
      this.stats.entriesForwarded += toSend.length;
    }
  }
  
  /**
   * Refresh our own listings
   */
  _refreshOwnListings() {
    const listings = this.directory.getOwnListings();
    
    for (const entry of listings) {
      entry.updatedAt = Date.now();
      entry.lastSeen = Date.now();
      entry.sign(this.identity.identity.secretKey);
      
      this._broadcast({
        type: YURT_CONFIG.messageTypes.ANNOUNCE,
        entry: entry.toJSON(),
        from: this.identity.identity.nodeId,
        timestamp: Date.now(),
      });
    }
  }
  
  /**
   * Broadcast to all peers
   */
  _broadcast(message) {
    const peers = this.mesh?.getPeers?.() || [];
    for (const peer of peers) {
      this.mesh.send(peer.id, message);
    }
  }
  
  /**
   * Get public key for a node — unified resolution cascade
   *
   * Resolution order:
   *   1. Custom publicKeyLookup callback (backwards compat)
   *   2. KeyResolver (DOKO cache, peers, SHERPA, etc.)
   */
  _getPublicKey(nodeId) {
    // Legacy callback path
    if (this.options.publicKeyLookup) {
      const key = this.options.publicKeyLookup(nodeId);
      if (key) return key;
    }
    
    // KeyResolver: unified key resolution
    if (this.keyResolver) {
      return this.keyResolver.resolve(nodeId);
    }
    
    return null;
  }
  
  /**
   * Get gossip stats
   */
  getStats() {
    return {
      ...this.stats,
      trackedPeers: this.sentTo.size,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// YURT HUB - Complete room discovery system
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * YurtHub - Full room discovery and direct access
 * 
 * "The gathering place where paths are shared."
 */
export class YurtHub extends EventEmitter {
  /**
   * @param {Object} identity - Node identity
   * @param {Object} gumbaHub - GUMBA hub for room access
   * @param {Object} mesh - Mesh network interface
   */
  constructor(identity, gumbaHub, mesh, options = {}) {
    super();
    
    this.identity = identity;
    this.gumbaHub = gumbaHub;
    this.mesh = mesh;
    this.options = options;
    
    // Directory and gossip
    this.directory = new YurtDirectory(options);
    this.gossip = new YurtGossip(identity, this.directory, mesh, options);
    
    // Forward events
    this.directory.on('entry:added', (e) => this.emit('room:discovered', e));
    this.directory.on('entry:removed', (e) => this.emit('room:removed', e));
    this.gossip.on('query:response', (r) => this.emit('query:response', r));
    
    log.info('YurtHub initialized');
  }
  
  /**
   * Start the hub
   */
  start() {
    this.gossip.start();
    
    // Periodic cleanup
    this._cleanupTimer = setInterval(() => {
      this.directory.cleanup();
    }, 60 * 60 * 1000); // Every hour
    
    return this;
  }
  
  /**
   * Stop the hub
   */
  stop() {
    this.gossip.stop();
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
    }
  }
  
  /**
   * Publish a room from our GUMBA hub
   */
  publishRoom(bundleId, options = {}) {
    const bundle = this.gumbaHub.getBundle(bundleId);
    if (!bundle) {
      return { success: false, error: 'BUNDLE_NOT_FOUND' };
    }
    
    // Don't publish unlisted rooms via gossip
    if (options.visibility === YURT_CONFIG.visibility.UNLISTED) {
      log.debug('Unlisted room - not gossiping', { bundleId });
    }
    
    const entry = new YurtEntry({
      bundleId: bundle.bundleId,
      hostNodeId: this.identity.identity.nodeId,
      hostEndpoint: options.endpoint || this._getOwnEndpoint(),
      name: options.name || bundle.name,
      description: options.description || bundle.description,
      visibility: options.visibility || YURT_CONFIG.visibility.PUBLIC,
      tags: options.tags || [],
      memberCount: bundle.memberTree.size,
      messageCount: bundle.metadata.messageCount,
    });
    
    if (options.visibility !== YURT_CONFIG.visibility.UNLISTED) {
      return this.gossip.announce(entry);
    } else {
      // Just add locally without gossip
      entry.sign(this.identity.identity.secretKey);
      const result = this.directory.add(entry, false);
      if (result.success) {
        this.directory.markAsOwn(entry.entryId);
      }
      return result;
    }
  }
  
  /**
   * Unpublish a room
   */
  unpublishRoom(bundleId) {
    return this.gossip.withdraw(bundleId);
  }
  
  /**
   * Join a room via yak:// link
   *
   * Flow: parse URI → resolve host via mesh → request GUMBA session → return access
   */
  async joinViaLink(uri) {
    const parsed = YurtLink.parse(uri);
    if (!parsed.valid) {
      return { success: false, error: 'INVALID_URI', details: parsed.error };
    }
    
    log.info('Joining via link', { 
      host: parsed.host, 
      bundleId: parsed.bundleId,
    });
    
    // Look up the room in our directory first
    const entry = this.directory.getByBundle(parsed.bundleId);
    
    // Request a GUMBA session on the target bundle
    try {
      const session = await this.gumbaHub.requestSession(
        parsed.bundleId,
        this.identity.identity.nodeId,
        { invite: parsed.invite }
      );
      
      if (session?.error) {
        return {
          success: false,
          error: session.error,
          parsed,
        };
      }
      
      return {
        success: true,
        parsed,
        endpoint: entry?.hostEndpoint || parsed.endpoint,
        bundleId: parsed.bundleId,
        invite: parsed.invite,
        sessionId: session?.sessionId || null,
      };
    } catch (err) {
      log.warn('joinViaLink failed', { error: err.message, uri });
      return {
        success: false,
        error: 'CONNECTION_FAILED',
        details: err.message,
        parsed,
      };
    }
  }
  
  /**
   * Browse public rooms
   */
  browse(options = {}) {
    return this.directory.search({
      visibility: YURT_CONFIG.visibility.PUBLIC,
      ...options,
    });
  }
  
  /**
   * Search rooms
   */
  search(query, options = {}) {
    return this.directory.search({ query, ...options });
  }
  
  /**
   * Search by tags
   */
  searchByTags(tags) {
    return this.directory.search({ tags });
  }
  
  /**
   * Query the network for rooms
   */
  queryNetwork(options = {}) {
    return this.gossip.query(options);
  }
  
  /**
   * Get room by bundle ID
   */
  getRoom(bundleId) {
    return this.directory.getByBundle(bundleId);
  }
  
  /**
   * Generate join link for a room
   */
  getJoinLink(bundleId, options = {}) {
    const entry = this.directory.getByBundle(bundleId);
    if (!entry) return null;
    
    if (options.invite) {
      return entry.toInviteUri(options.invite);
    }
    return entry.toUri();
  }
  
  /**
   * Get our own endpoint
   *
   * Priority: explicit option → mesh advertised address → default
   */
  _getOwnEndpoint() {
    if (this.options.endpoint) {
      return this.options.endpoint;
    }
    
    // Ask the mesh for our advertised address
    if (this.mesh?.getAdvertisedAddress) {
      const addr = this.mesh.getAdvertisedAddress();
      if (addr) return addr;
    }
    
    return `localhost:${YURT_CONFIG.defaultPort}`;
  }
  
  /**
   * Get hub stats
   */
  getStats() {
    return {
      directory: this.directory.getStats(),
      gossip: this.gossip.getStats(),
    };
  }
  
  /**
   * Export state
   */
  export() {
    return {
      directory: this.directory.export(),
    };
  }
  
  /**
   * Import state
   */
  import(data) {
    if (data.directory) {
      this.directory.import(data.directory);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  YurtEntry,
  YurtLink,
  YurtDirectory,
  YurtGossip,
  YurtHub,
  YURT_CONFIG,
};
