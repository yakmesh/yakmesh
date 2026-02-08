/**
 * YAKMESH™ Content Store
 * Content-addressed storage with consensus proofs
 * 
 * Provides public content delivery while maintaining mesh security:
 * - Content addressed by hash (trustless verification)
 * - Consensus proofs for light client verification
 * - Edge caching for instant public access
 * - Mesh sync for decentralized replication
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
 */
export const ContentStatus = {
  LOCAL: 'local',           // Only on this node
  PENDING: 'pending',       // Awaiting consensus
  VERIFIED: 'verified',     // Consensus reached
  REJECTED: 'rejected',     // Failed consensus
};

/**
 * Compute content hash (SHA3-256)
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
    this.hash = options.hash;
    this.ioName = options.ioName || null;  // Auto-generated iO name (human-readable)
    this.contentType = options.contentType || ContentType.BINARY;
    this.size = options.size || 0;
    this.createdAt = options.createdAt || Date.now();
    this.publishedBy = options.publishedBy || null;
    this.status = options.status || ContentStatus.LOCAL;
    this.consensusProof = options.consensusProof || null;
    this.tags = options.tags || [];
    this.name = options.name || null;  // Optional custom name (user-provided)
    this.ttl = options.ttl || 0;       // 0 = permanent
  }

  toJSON() {
    return {
      hash: this.hash,
      ioName: this.ioName,
      contentType: this.contentType,
      size: this.size,
      createdAt: this.createdAt,
      publishedBy: this.publishedBy,
      status: this.status,
      consensusProof: this.consensusProof,
      tags: this.tags,
      name: this.name,
      ttl: this.ttl,
    };
  }

  static fromJSON(json) {
    return new ContentMetadata(json);
  }
}

/**
 * Consensus proof for light client verification
 */
class ConsensusProof {
  constructor(options = {}) {
    this.contentHash = options.contentHash;
    this.timestamp = options.timestamp || Date.now();
    this.validators = options.validators || [];  // Array of { nodeId, signature }
    this.quorum = options.quorum || 0;           // Required signatures
    this.networkId = options.networkId || null;
  }

  /**
   * Check if proof has quorum
   */
  hasQuorum() {
    return this.validators.length >= this.quorum;
  }

  /**
   * Add validator signature
   */
  addValidator(nodeId, signature) {
    if (!this.validators.find(v => v.nodeId === nodeId)) {
      this.validators.push({ nodeId, signature, timestamp: Date.now() });
    }
  }

  toJSON() {
    return {
      contentHash: this.contentHash,
      timestamp: this.timestamp,
      validators: this.validators,
      quorum: this.quorum,
      networkId: this.networkId,
    };
  }

  static fromJSON(json) {
    return new ConsensusProof(json);
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
      quorumSize: config.quorumSize || 2,                        // Minimum validators
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
   * Get content path for a hash
   */
  _getContentPath(hash) {
    // Store in subdirectories for filesystem efficiency (git-style)
    const prefix = hash.slice(0, 2);
    const suffix = hash.slice(2);
    return join(this.contentDir, prefix, suffix);
  }

  /**
   * Get metadata path for a hash
   */
  _getMetaPath(hash) {
    return join(this.metaDir, `${hash}.json`);
  }

  /**
   * Store content
   */
  async store(content, options = {}) {
    // Compute hash
    const hash = computeContentHash(content);
    
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
      return { hash, ioName: existing.ioName, status: 'exists', meta: existing };
    }

    // Generate iO name for human-readable sharing
    const ioName = deriveContentName(hash);

    // Create metadata
    const meta = new ContentMetadata({
      hash,
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
    
    // Index both iO name and custom name for lookup
    this.nameIndex.set(ioName, hash);  // iO name always indexed
    if (meta.name) {
      this.nameIndex.set(meta.name, hash);  // Custom name if provided
    }
    this._addToContentCache(hash, content);

    // Gossip to mesh
    if (this.gossip && options.publish !== false) {
      await this.publish(hash);
    }

    log.info('Content stored', { hash: hash.slice(0, 16), ioName, size });
    return { hash, ioName, status: 'stored', meta };
  }

  /**
   * Retrieve content by hash
   */
  get(hash) {
    // Resolve name to hash if needed
    if (!hash.match(/^[a-f0-9]{64}$/i)) {
      hash = this.nameIndex.get(hash) || hash;
    }

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
   * Get content with metadata and proof
   */
  getWithProof(hash) {
    const content = this.get(hash);
    if (!content) return null;

    const meta = this.getMeta(hash);
    
    return {
      content,
      hash,
      meta: meta?.toJSON() || null,
      proof: meta?.consensusProof || null,
      verified: meta?.status === ContentStatus.VERIFIED,
    };
  }

  /**
   * Get metadata for content
   */
  getMeta(hash) {
    // Resolve name if needed
    if (!hash.match(/^[a-f0-9]{64}$/i)) {
      hash = this.nameIndex.get(hash) || hash;
    }
    return this.metaCache.get(hash) || null;
  }

  /**
   * Check if content exists
   */
  has(hash) {
    // Resolve name if needed
    if (!hash.match(/^[a-f0-9]{64}$/i)) {
      hash = this.nameIndex.get(hash) || hash;
    }
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
   */
  async publish(hash) {
    const meta = this.getMeta(hash);
    if (!meta) {
      throw new Error(`Content not found: ${hash}`);
    }

    // Create announcement message
    const announcement = {
      type: 'content_announce',
      hash,
      meta: {
        contentType: meta.contentType,
        size: meta.size,
        publishedBy: meta.publishedBy,
        tags: meta.tags,
        name: meta.name,
      },
      timestamp: Date.now(),
    };

    // Sign with node identity
    if (this.identity) {
      announcement.signature = this.identity.sign(JSON.stringify(announcement));
    }

    // Gossip to mesh
    if (this.gossip) {
      log.debug('Gossiping content_announce', { hash: hash.slice(0, 16) });
      this.gossip.spreadRumor('content', announcement);
    } else {
      log.warn('No gossip protocol available for content announce');
    }

    // Update status
    meta.status = ContentStatus.PENDING;
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
              proof: result.proof,
              timestamp: Date.now(),
            });
          }
        }
        break;

      case 'content_response':
        // Received content from peer
        if (!this.has(data.hash)) {
          const content = Buffer.from(data.content, 'base64');
          const computedHash = computeContentHash(content);
          
          // Verify hash
          if (computedHash !== data.hash) {
            console.warn(`⚠️ Content hash mismatch from ${origin.slice(0, 16)}...`);
            return;
          }          // Store it
          await this.store(content, {
            ...data.meta,
            publish: false,  // Don't re-gossip
          });

          // Apply consensus proof if present
          if (data.proof) {
            const meta = this.getMeta(data.hash);
            meta.consensusProof = ConsensusProof.fromJSON(data.proof);
            meta.status = data.proof.hasQuorum?.() ? ContentStatus.VERIFIED : ContentStatus.PENDING;
            writeFileSync(this._getMetaPath(data.hash), JSON.stringify(meta.toJSON(), null, 2));
          }

          log.info('Content received', { hash: data.hash.slice(0, 16) });
        }
        break;

      case 'content_validate':
        // Peer is requesting validation vote
        if (this.has(data.hash) && this.identity && this.oracle) {
          const content = this.get(data.hash);
          const isValid = this.oracle.validateContent(content, data.contentType);
          
          if (isValid) {
            // Sign validation
            const vote = {
              type: 'content_vote',
              hash: data.hash,
              nodeId: this.identity.identity.nodeId,
              vote: 'valid',
              signature: this.identity.sign(data.hash),
              timestamp: Date.now(),
            };
            this.gossip.spreadRumor('content', vote);
          }
        }
        break;

      case 'content_vote':
        // Received validation vote
        const meta = this.getMeta(data.hash);
        if (meta) {
          if (!meta.consensusProof) {
            meta.consensusProof = new ConsensusProof({
              contentHash: data.hash,
              quorum: this.config.quorumSize,
              networkId: this.mesh?.networkId,
            });
          }
          meta.consensusProof.addValidator(data.nodeId, data.signature);
          
          if (meta.consensusProof.hasQuorum()) {
            meta.status = ContentStatus.VERIFIED;
            log.info('Content verified (quorum reached)', { hash: data.hash.slice(0, 16) });
          }
          
          writeFileSync(this._getMetaPath(data.hash), JSON.stringify(meta.toJSON(), null, 2));
        }
        break;
    }
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
    let pending = 0;
    let local = 0;

    for (const meta of this.metaCache.values()) {
      totalSize += meta.size;
      switch (meta.status) {
        case ContentStatus.VERIFIED: verified++; break;
        case ContentStatus.PENDING: pending++; break;
        case ContentStatus.LOCAL: local++; break;
      }
    }

    return {
      totalObjects: this.metaCache.size,
      totalSize,
      verified,
      pending,
      local,
      cacheSize: this.contentCache.size,
      dataDir: this.config.dataDir,
    };
  }
}

export { ContentMetadata, ConsensusProof };
export default ContentStore;
