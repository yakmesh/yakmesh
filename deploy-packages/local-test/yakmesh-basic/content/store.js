/**
 * YAKMESH™ Content Store
 * Content-addressed storage with integrity verification
 * 
 * Content validity is determined by math, not votes:
 * - Integrity: SHA3-256 hash of content matches claimed hash
 * - Authorship: Publisher's ML-DSA-65 signature over the hash
 * - Any node can independently verify both — one proof = proven
 * 
 * No voting. No quorum. No 51% attack surface.
 * "The math checks out" is the only consensus needed.
 * 
 * @module content/store
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync, unlinkSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { createLogger } from '../utils/logger.js';

// Import iO system for human-readable content names
import { deriveNetworkName } from '../oracle/network-identity.js';

// Import 144T ternary system for hex-free content addressing
import { TritAddress, TOTAL_TRITS } from '../oracle/ternary-routing.js';

const log = createLogger('content:store');

/**
 * Content types supported
 */
export const ContentType = {
  JSON: 'application/json',
  HTML: 'text/html',
  TEXT: 'text/plain',
  BINARY: 'application/octet-stream',
  JAVASCRIPT: 'application/javascript',
  CSS: 'text/css',
  IMAGE_PNG: 'image/png',
  IMAGE_JPG: 'image/jpeg',
  IMAGE_SVG: 'image/svg+xml',
};

/**
 * Content status in the network
 * 
 * Yakmesh does NOT use voting/quorum consensus for content.
 * Content integrity = SHA3-256 hash match.
 * Content authorship = publisher's ML-DSA-65 signature over the hash.
 * Any node can independently verify both — one proof = proven.
 */
export const ContentStatus = {
  LOCAL: 'local',           // Stored on this node, not yet announced
  ANNOUNCED: 'announced',   // Published to mesh via gossip
  VERIFIED: 'verified',     // Hash integrity + publisher signature confirmed
};

/**
 * Compute content hash (SHA3-256) — returns hex string
 * @deprecated Use computeContentHashTernary for new content (hex-free addressing)
 */
export function computeContentHash(content) {
  if (typeof content === 'string') {
    return bytesToHex(sha3_256(utf8ToBytes(content)));
  }
  if (Buffer.isBuffer(content)) {
    return bytesToHex(sha3_256(new Uint8Array(content)));
  }
  if (content instanceof Uint8Array) {
    return bytesToHex(sha3_256(content));
  }
  // Object - serialize deterministically
  return bytesToHex(sha3_256(utf8ToBytes(JSON.stringify(content))));
}

/**
 * Compute content hash as 162T ternary address
 * 
 * This is the preferred content addressing format:
 * - No hex digits (no "666" ever)
 * - Unified with node/mesh addressing system
 * - Enables hierarchical content routing
 * - Alphabet: {T, 0, 1} only (T = -1 in balanced ternary)
 * 
 * @param {string | Buffer | Uint8Array | object} content — content to hash
 * @returns {{ hex: string, trit: string, tritAddress: TritAddress }} — both formats for compatibility
 */
export function computeContentHashTernary(content) {
  // First compute SHA3-256 as hex (internal only)
  const hex = computeContentHash(content);

  // Convert to 162T ternary address
  const tritAddress = TritAddress.fromHex(hex);
  const trit = tritAddress.toString(true); // compact format with tier separators

  return { hex, trit, tritAddress };
}

/** @deprecated Use computeContentHashTernary */
export const computeContentHash144T = computeContentHashTernary;

/**
 * Validate that a hex string doesn't contain forbidden patterns.
 * Used as a guard for any remaining hex output.
 * 
 * @param {string} hex — hex string to validate
 * @returns {boolean} — true if safe, false if contains forbidden pattern
 */
export function isHexSafe(hex) {
  // Reject any hex containing "666" sequence
  return !hex.toLowerCase().includes('666');
}

/**
 * Check if a string is a valid trit address.
 * Format: 3 tiers separated by dots, each tier has 6 sub-blocks separated by colons.
 * Characters: T (negative), 0 (neutral), 1 (positive)
 * 
 * @param {string} s — string to check
 * @returns {boolean}
 */
export function isTritAddress(s) {
  if (!s || typeof s !== 'string') return false;
  // Remove separators and check length + characters
  const clean = s.replace(/[.:]/g, '');
  if (clean.length !== TOTAL_TRITS) return false;
  return /^[T01]+$/i.test(clean);
}

/**
 * Derive human-readable iO name from content hash
 * Uses 3-word quantum wordlist for memorable, shareable names
 * 
 * @param {string} hash - SHA3-256 content hash (hex)
 * @returns {string} Human-readable name like "qubit-lattice-prism"
 */
export function deriveContentName(hash) {
  return deriveNetworkName(hash, 3);  // 3 words = 24 bits = 16M+ unique names
}

/**
 * Content metadata
 */
class ContentMetadata {
  constructor(options = {}) {
    this.hash = options.hash;             // SHA3-256 hex (legacy, internal)
    this.hash144t = options.hash144t || null;  // 144T ternary address (preferred, public)
    this.ioName = options.ioName || null;  // Auto-generated iO name (human-readable)
    this.contentType = options.contentType || ContentType.BINARY;
    this.size = options.size || 0;
    this.createdAt = options.createdAt || Date.now();
    this.publishedBy = options.publishedBy || null;
    this.status = options.status || ContentStatus.LOCAL;
    this.publisherSignature = options.publisherSignature || null;  // ML-DSA-65 sig over content hash
    this.publisherBackupSignature = options.publisherBackupSignature || null;  // SLH-DSA sig (dual-sig defense-in-depth)
    this.tags = options.tags || [];
    this.name = options.name || null;  // Optional custom name (user-provided)
    this.ttl = options.ttl || 0;       // 0 = permanent
  }

  toJSON() {
    return {
      hash: this.hash,
      hash144t: this.hash144t,
      ioName: this.ioName,
      contentType: this.contentType,
      size: this.size,
      createdAt: this.createdAt,
      publishedBy: this.publishedBy,
      status: this.status,
      publisherSignature: this.publisherSignature,
      publisherBackupSignature: this.publisherBackupSignature,
      tags: this.tags,
      name: this.name,
      ttl: this.ttl,
    };
  }

  /**
   * Get the public-facing content ID (144T preferred, fallback to iO name)
   * Never returns hex to external callers.
   */
  getPublicId() {
    return this.hash144t || this.ioName || this.name;
  }

  static fromJSON(json) {
    return new ContentMetadata(json);
  }
}

/**
 * YAKMESH Content Store
 * Content-addressed storage with mesh sync and public delivery
 */
export class ContentStore {
  constructor(config = {}) {
    this.config = {
      dataDir: config.dataDir || './data/content',
      maxContentSize: config.maxContentSize || 10 * 1024 * 1024, // 10MB default
      cacheSize: config.cacheSize || 100,                        // LRU cache entries
      ...config,
    };

    this.contentDir = join(this.config.dataDir, 'objects');
    this.metaDir = join(this.config.dataDir, 'meta');

    // In-memory caches
    this.contentCache = new Map();  // hash -> content (LRU)
    this.metaCache = new Map();     // hash -> ContentMetadata
    this.nameIndex = new Map();     // name -> hash (for human-readable lookup)

    // Mesh integration (set by init)
    this.mesh = null;
    this.identity = null;
    this.oracle = null;
    this.gossip = null;
  }

  /**
   * Initialize the content store
   */
  async init(node = null) {
    // Create directories
    mkdirSync(this.contentDir, { recursive: true });
    mkdirSync(this.metaDir, { recursive: true });

    // Load existing metadata into cache
    this._loadMetadataIndex();

    // Integrate with node if provided
    if (node) {
      this.mesh = node.mesh;
      this.identity = node.identity;
      this.oracle = node.oracle;
      this.gossip = node.gossip;

      // Content gossip is handled by the server via mesh.on('rumor')
      // which calls contentStore._handleContentGossip()
    }

    log.info('Content store initialized', { dataDir: this.config.dataDir, objectCount: this.metaCache.size });

    return this;
  }

  /**
   * Load metadata index from disk
   */
  _loadMetadataIndex() {
    if (!existsSync(this.metaDir)) return;

    const files = readdirSync(this.metaDir);
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const metaPath = join(this.metaDir, file);
        const json = JSON.parse(readFileSync(metaPath, 'utf8'));
        const meta = ContentMetadata.fromJSON(json);
        this.metaCache.set(meta.hash, meta);

        // Index iO name (auto-generated or derive if missing from old data)
        if (meta.ioName) {
          this.nameIndex.set(meta.ioName, meta.hash);
        } else {
          // Backfill ioName for content stored before iO naming was added
          const ioName = deriveContentName(meta.hash);
          meta.ioName = ioName;
          this.nameIndex.set(ioName, meta.hash);
        }

        // Index custom name if provided
        if (meta.name) {
          this.nameIndex.set(meta.name, meta.hash);
        }
      } catch (e) {
        console.warn(`Failed to load metadata: ${file}`);
      }
    }
  }

  /**
   * Get content path for a hash (supports both hex and 144T)
   * 
   * For ternary addresses, uses first tier's first sub-block (9 chars) as prefix.
   * For hex (legacy), uses first 2 chars as prefix.
   */
  _getContentPath(hash) {
    // Check if this is a 144T address (contains T, 0, 1 and dots/colons)
    if (isTritAddress(hash)) {
      // Use first 9 trits (first sub-block) as directory prefix
      const clean = hash.replace(/[.:]/g, '');
      const prefix = clean.slice(0, 9);
      const suffix = clean.slice(9);
      return join(this.contentDir, 't', prefix, suffix);
    }
    // Legacy hex: store in subdirectories for filesystem efficiency (git-style)
    const prefix = hash.slice(0, 2);
    const suffix = hash.slice(2);
    return join(this.contentDir, prefix, suffix);
  }

  /**
   * Get metadata path for a hash (supports both hex and 144T)
   */
  _getMetaPath(hash) {
    // Normalize 144T to filename-safe format (remove separators)
    const safeHash = hash.replace(/[.:]/g, '');
    return join(this.metaDir, `${safeHash}.json`);
  }

  /**
   * Store content
   * 
   * Returns the ternary hash (preferred) along with legacy hex for compatibility.
   * Internal storage uses hex paths for backward compatibility with existing content.
   */
  async store(content, options = {}) {
    // Compute both hash formats
    const { hex: hash, trit: hashTrit } = computeContentHashTernary(content);

    // Check size limit
    const size = Buffer.isBuffer(content) ? content.length :
      typeof content === 'string' ? Buffer.byteLength(content) :
        Buffer.byteLength(JSON.stringify(content));

    if (size > this.config.maxContentSize) {
      throw new Error(`Content exceeds max size: ${size} > ${this.config.maxContentSize}`);
    }

    // Check if already exists
    if (this.has(hash)) {
      const existing = this.getMeta(hash);
      return {
        hash,
        hash144t: existing.hash144t || hashTrit,
        ioName: existing.ioName,
        status: 'exists',
        meta: existing
      };
    }

    // Generate iO name for human-readable sharing
    const ioName = deriveContentName(hash);

    // Create metadata with both hash formats
    const meta = new ContentMetadata({
      hash,
      hash144t: hashTrit,
      ioName,
      contentType: options.contentType || this._detectContentType(content),
      size,
      publishedBy: this.identity?.identity?.nodeId || options.publishedBy || 'unknown',
      status: ContentStatus.LOCAL,
      tags: options.tags || [],
      name: options.name || null,
      ttl: options.ttl || 0,
    });

    // Write content to disk
    const contentPath = this._getContentPath(hash);
    mkdirSync(dirname(contentPath), { recursive: true });

    if (Buffer.isBuffer(content)) {
      writeFileSync(contentPath, content);
    } else if (typeof content === 'string') {
      writeFileSync(contentPath, content, 'utf8');
    } else {
      writeFileSync(contentPath, JSON.stringify(content), 'utf8');
    }

    // Write metadata
    writeFileSync(this._getMetaPath(hash), JSON.stringify(meta.toJSON(), null, 2));

    // Update caches
    this.metaCache.set(hash, meta);

    // Index by iO name, ternary address, and custom name for flexible lookup
    this.nameIndex.set(ioName, hash);     // iO name always indexed
    this.nameIndex.set(hashTrit, hash);   // ternary address indexed
    if (meta.name) {
      this.nameIndex.set(meta.name, hash);  // Custom name if provided
    }
    this._addToContentCache(hash, content);

    // Gossip to mesh
    if (this.gossip && options.publish !== false) {
      await this.publish(hash);
    }

    log.info('Content stored', { hash: hashTrit.split('.')[0] + '...', ioName, size });
    return { hash, hash144t: hashTrit, ioName, status: 'stored', meta };
  }

  /**
   * Resolve any content identifier to internal hex hash.
   * Accepts: hex hash, ternary address, iO name, or custom name.
   * @private
   */
  _resolveHash(id) {
    if (!id) return null;
    // Already hex?
    if (/^[a-f0-9]{64}$/i.test(id)) return id;
    // 144T address or name - look up in index
    return this.nameIndex.get(id) || id;
  }

  /**
   * Retrieve content by hash, ternary address, iO name, or custom name
   */
  get(id) {
    const hash = this._resolveHash(id);

    // Check memory cache
    if (this.contentCache.has(hash)) {
      return this.contentCache.get(hash);
    }

    // Check disk
    const contentPath = this._getContentPath(hash);
    if (!existsSync(contentPath)) {
      return null;
    }

    // Load and cache
    const content = readFileSync(contentPath);
    this._addToContentCache(hash, content);

    return content;
  }

  /**
   * Get content with metadata and verification status
   */
  getWithProof(id) {
    const hash = this._resolveHash(id);
    const content = this.get(hash);
    if (!content) return null;

    const meta = this.getMeta(hash);

    return {
      content,
      hash,
      hash144t: meta?.hash144t || null,
      meta: meta?.toJSON() || null,
      verified: meta?.status === ContentStatus.VERIFIED,
    };
  }

  /**
   * Get metadata for content
   */
  getMeta(id) {
    const hash = this._resolveHash(id);
    return this.metaCache.get(hash) || null;
  }

  /**
   * Check if content exists
   */
  has(id) {
    const hash = this._resolveHash(id);
    return this.metaCache.has(hash) || existsSync(this._getContentPath(hash));
  }

  /**
   * Delete content
   */
  delete(hash) {
    const meta = this.getMeta(hash);

    // Remove from disk
    const contentPath = this._getContentPath(hash);
    const metaPath = this._getMetaPath(hash);

    if (existsSync(contentPath)) unlinkSync(contentPath);
    if (existsSync(metaPath)) unlinkSync(metaPath);

    // Remove from caches
    this.contentCache.delete(hash);
    this.metaCache.delete(hash);
    if (meta?.name) {
      this.nameIndex.delete(meta.name);
    }

    return true;
  }

  /**
   * List all content
   */
  list(options = {}) {
    const { tag, status, limit = 100, offset = 0 } = options;

    let items = Array.from(this.metaCache.values());

    // Filter by tag
    if (tag) {
      items = items.filter(m => m.tags.includes(tag));
    }

    // Filter by status
    if (status) {
      items = items.filter(m => m.status === status);
    }

    // Sort by created date (newest first)
    items.sort((a, b) => b.createdAt - a.createdAt);

    // Paginate
    return items.slice(offset, offset + limit).map(m => m.toJSON());
  }

  /**
   * Publish content to mesh
   * Signs the content hash with the publisher's ML-DSA-65 identity.
   * Any receiving node can independently verify: hash(content) === hash AND
   * verify(hash, publisherSignature, publisherPubKey) === true.
   */
  async publish(hash) {
    const meta = this.getMeta(hash);
    if (!meta) {
      throw new Error(`Content not found: ${hash}`);
    }

    // Sign the content hash with publisher's identity (authorship proof)
    // Uses dual signature (ML-DSA-65 + SLH-DSA) when available for defense-in-depth
    let publisherSignature = null;
    let publisherBackupSignature = null;
    if (this.identity) {
      if (this.identity.hasDualSignature?.()) {
        // Critical op: use both ML-DSA-65 AND SLH-DSA (defense-in-depth)
        const sigs = this.identity.signCritical(hash);
        publisherSignature = sigs.primary;
        publisherBackupSignature = sigs.backup;
        meta.publisherSignature = publisherSignature;
        meta.publisherBackupSignature = publisherBackupSignature;
      } else {
        // Fallback: ML-DSA-65 only (no SLH-DSA backup key available)
        publisherSignature = this.identity.sign(hash);
        meta.publisherSignature = publisherSignature;
      }
    }

    // Create announcement message
    const announcement = {
      type: 'content_announce',
      hash,
      meta: {
        contentType: meta.contentType,
        size: meta.size,
        publishedBy: meta.publishedBy,
        publisherSignature,
        publisherBackupSignature,
        tags: meta.tags,
        name: meta.name,
      },
      timestamp: Date.now(),
    };

    // Gossip to mesh
    if (this.gossip) {
      log.debug('Gossiping content_announce', { hash: hash.slice(0, 16) });
      this.gossip.spreadRumor('content', announcement);
    } else {
      log.warn('No gossip protocol available for content announce');
    }

    // Update status to ANNOUNCED (published to mesh)
    meta.status = ContentStatus.ANNOUNCED;
    writeFileSync(this._getMetaPath(hash), JSON.stringify(meta.toJSON(), null, 2));

    return { published: true, hash };
  }

  /**
   * Request content from mesh
   */
  async request(hash) {
    if (this.has(hash)) {
      return this.getWithProof(hash);
    }

    // Broadcast request
    if (this.gossip) {
      this.gossip.spreadRumor('content', {
        type: 'content_request',
        hash,
        requestedBy: this.identity?.identity?.nodeId,
        timestamp: Date.now(),
      });
    }

    // Wait for response (with timeout)
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Content not found: ${hash}`));
      }, 10000);

      const checkInterval = setInterval(() => {
        if (this.has(hash)) {
          clearTimeout(timeout);
          clearInterval(checkInterval);
          resolve(this.getWithProof(hash));
        }
      }, 500);
    });
  }

  /**
   * Handle content gossip from peers
   */
  async _handleContentGossip(data, origin) {
    switch (data.type) {
      case 'content_announce':
        // Peer has new content - request it if we don't have it
        if (!this.has(data.hash)) {
          log.debug('New content announced', { hash: data.hash.slice(0, 16), origin: origin.slice(0, 16) });
          // Request full content via gossip
          if (this.gossip) {
            this.gossip.spreadRumor('content', {
              type: 'content_request',
              hash: data.hash,
              requestedBy: this.identity?.identity?.nodeId,
              timestamp: Date.now(),
            });
          }
        }
        break;

      case 'content_request':
        // Peer wants content - send if we have it
        if (this.has(data.hash)) {
          const result = this.getWithProof(data.hash);
          if (this.gossip && result) {
            // Ensure content is properly encoded as base64
            let contentBase64;
            if (Buffer.isBuffer(result.content)) {
              contentBase64 = result.content.toString('base64');
            } else if (typeof result.content === 'string') {
              contentBase64 = Buffer.from(result.content, 'utf8').toString('base64');
            } else {
              contentBase64 = Buffer.from(JSON.stringify(result.content), 'utf8').toString('base64');
            }

            this.gossip.spreadRumor('content', {
              type: 'content_response',
              hash: data.hash,
              content: contentBase64,
              meta: result.meta,
              timestamp: Date.now(),
            });
          }
        }
        break;

      case 'content_response':
        // Received content from peer — verify integrity + authorship
        if (!this.has(data.hash)) {
          const content = Buffer.from(data.content, 'base64');
          const computedHash = computeContentHash(content);

          // Gate 1: Verify hash integrity
          if (computedHash !== data.hash) {
            console.warn(`⚠️ Content hash mismatch from ${origin.slice(0, 16)}...`);
            return;
          }

          // Store it — use explicit allowlist, never spread remote meta directly (proto pollution defense)
          const remoteMeta = data.meta || {};
          await this.store(content, {
            contentType: remoteMeta.contentType,
            size: remoteMeta.size,
            publishedBy: remoteMeta.publishedBy,
            publisherSignature: remoteMeta.publisherSignature,
            publisherBackupSignature: remoteMeta.publisherBackupSignature,
            tags: remoteMeta.tags,
            name: remoteMeta.name,
            publish: false,  // Don't re-gossip
          });

          // Gate 2: Verify publisher signature (authorship)
          const meta = this.getMeta(data.hash);
          const publisherSig = data.meta?.publisherSignature;
          const publisherBackupSig = data.meta?.publisherBackupSignature;
          const publisherId = data.meta?.publishedBy;

          if (publisherSig && publisherId && this.identity) {
            const publisherPubKey = this._getPeerPublicKey(publisherId);
            if (!publisherPubKey) {
              // Can't look up publisher's key — store as ANNOUNCED
              meta.status = ContentStatus.ANNOUNCED;
              log.debug('Content received but publisher key unknown', { hash: data.hash.slice(0, 16) });
            } else if (publisherBackupSig) {
              // Dual-sig present: verify BOTH ML-DSA-65 + SLH-DSA (defense-in-depth)
              const backupPubKey = this._getPeerBackupPublicKey(publisherId);
              if (backupPubKey) {
                const result = this.identity.verifyCritical(
                  data.hash, publisherSig, publisherBackupSig, publisherPubKey, backupPubKey
                );
                if (result.valid) {
                  meta.status = ContentStatus.VERIFIED;
                  meta.publisherSignature = publisherSig;
                  meta.publisherBackupSignature = publisherBackupSig;
                  log.info('Content verified (dual-sig: ML-DSA + SLH-DSA)', {
                    hash: data.hash.slice(0, 16), publisher: publisherId.slice(0, 16),
                  });
                } else {
                  // At least one sig failed — reject as potentially tampered
                  meta.status = ContentStatus.ANNOUNCED;
                  log.warn('Content dual-sig verification FAILED', {
                    hash: data.hash.slice(0, 16),
                    primaryValid: result.primaryValid,
                    backupValid: result.backupValid,
                  });
                }
              } else {
                // No backup key for publisher — fall back to primary-only verification
                if (this.identity.verify(data.hash, publisherSig, publisherPubKey)) {
                  meta.status = ContentStatus.VERIFIED;
                  meta.publisherSignature = publisherSig;
                  log.info('Content verified (ML-DSA only, no backup key for publisher)', {
                    hash: data.hash.slice(0, 16), publisher: publisherId.slice(0, 16),
                  });
                } else {
                  meta.status = ContentStatus.ANNOUNCED;
                }
              }
            } else if (this.identity.verify(data.hash, publisherSig, publisherPubKey)) {
              // Single sig only — verify ML-DSA-65
              meta.status = ContentStatus.VERIFIED;
              meta.publisherSignature = publisherSig;
              log.info('Content verified (hash + publisher sig)', { hash: data.hash.slice(0, 16), publisher: publisherId.slice(0, 16) });
            } else {
              // Have content but can't confirm authorship — ANNOUNCED
              meta.status = ContentStatus.ANNOUNCED;
              log.debug('Content received but publisher sig unverifiable', { hash: data.hash.slice(0, 16) });
            }
          } else {
            // No publisher sig available — store as ANNOUNCED
            meta.status = ContentStatus.ANNOUNCED;
          }

          writeFileSync(this._getMetaPath(data.hash), JSON.stringify(meta.toJSON(), null, 2));
          log.info('Content received', { hash: data.hash.slice(0, 16), status: meta.status });
        }
        break;
    }
  }

  /**
   * Resolve a peer's public key from mesh state.
   * Checks WS peers, relay keys, SHERPA registry, and self.
   */
  _getPeerPublicKey(nodeId) {
    // Self
    if (this.identity && nodeId === this.identity.identity.nodeId) {
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
    // SHERPA registry
    if (this.mesh?.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.publicKey) return regPeer.publicKey;
    }
    return null;
  }

  /**
   * Resolve a peer's SLH-DSA backup public key from mesh state.
   * Same lookup chain as _getPeerPublicKey but for the backupPublicKey field.
   */
  _getPeerBackupPublicKey(nodeId) {
    // Self
    if (this.identity && nodeId === this.identity.identity.nodeId) {
      return this.identity.identity.backupPublicKey || null;
    }
    // WS peer info
    if (this.mesh?.peers) {
      const peer = this.mesh.peers.get(nodeId);
      if (peer?.identity?.backupPublicKey) return peer.identity.backupPublicKey;
    }
    // SHERPA registry
    if (this.mesh?.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.backupPublicKey) return regPeer.backupPublicKey;
    }
    return null;
  }

  /**
   * Add to LRU content cache
   */
  _addToContentCache(hash, content) {
    // Simple LRU: remove oldest if at capacity
    if (this.contentCache.size >= this.config.cacheSize) {
      const oldest = this.contentCache.keys().next().value;
      this.contentCache.delete(oldest);
    }
    this.contentCache.set(hash, content);
  }

  /**
   * Detect content type from content
   */
  _detectContentType(content) {
    if (typeof content === 'object' && !Buffer.isBuffer(content)) {
      return ContentType.JSON;
    }

    const str = content.toString().slice(0, 100);

    if (str.startsWith('<!DOCTYPE') || str.startsWith('<html')) {
      return ContentType.HTML;
    }
    if (str.startsWith('{') || str.startsWith('[')) {
      return ContentType.JSON;
    }
    if (str.includes('function') || str.includes('const ') || str.includes('import ')) {
      return ContentType.JAVASCRIPT;
    }

    return ContentType.TEXT;
  }

  /**
   * Get store statistics
   */
  getStats() {
    let totalSize = 0;
    let verified = 0;
    let announced = 0;
    let local = 0;

    for (const meta of this.metaCache.values()) {
      totalSize += meta.size;
      switch (meta.status) {
        case ContentStatus.VERIFIED: verified++; break;
        case ContentStatus.ANNOUNCED: announced++; break;
        case ContentStatus.LOCAL: local++; break;
      }
    }

    return {
      totalObjects: this.metaCache.size,
      totalSize,
      verified,
      announced,
      local,
      cacheSize: this.contentCache.size,
      dataDir: this.config.dataDir,
    };
  }
}

export { ContentMetadata };
export default ContentStore;
