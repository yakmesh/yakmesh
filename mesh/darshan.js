/**
 * DARSHAN - Decentralized Archive Remote Streaming and Hosting Access Network
 * 
 * A novel content streaming protocol where:
 * - Content STAYS at the host node
 * - Viewers SEE content, they don't COPY it
 * - Bytes stream on-demand through E2E encrypted mesh tunnels
 * - Host maintains complete sovereignty over their content
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║  "Content stays on the altar. Pilgrims come to see."                          ║
 * ║                                                                               ║
 * ║  दर्शन (darshan) = the act of viewing, sacred sight                          ║
 * ║  In Hindu tradition: the blessing received by beholding a deity               ║
 * ║  In Yakmesh: the privilege of viewing content from its source                 ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * PARADIGM SHIFT:
 * - Old: Creator → Upload → Central Server → Download × N (bandwidth waste)
 * - New: Creator's Node → Mesh Tunnel → Viewer's Node (view, not copy)
 * 
 * NOVEL PROPERTIES:
 * 1. View ≠ Copy - Content decrypts DURING streaming, no local cache by default
 * 2. Bandwidth Sovereignty - Host controls quality, priority, throttling
 * 3. Proof of Viewing - Cryptographic attestation of view events
 * 4. Lazy Byte Streaming - Only transfer what's being consumed
 * 5. OS Integration - Virtual mounts via FUSE-like interfaces
 * 
 * Part of the Himalayan Protocol Family:
 * - ANNEX: E2E encrypted channels (used for content transport)
 * - GUMBA: Access control (used for view permissions)
 * - DARSHAN: Content streaming (this module)
 * 
 * @module mesh/darshan
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createLogger } from '../utils/logger.js';
import EventEmitter from 'events';

const log = createLogger('mesh:darshan');

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const DARSHAN_CONFIG = Object.freeze({
  // Protocol
  version: 1,
  scheme: 'darshan',
  
  // Streaming
  defaultChunkSize: 64 * 1024,      // 64KB chunks
  maxChunkSize: 1024 * 1024,        // 1MB max chunk
  minChunkSize: 1024,               // 1KB min chunk
  prefetchChunks: 3,                // Prefetch ahead
  maxConcurrentStreams: 10,         // Per host limit
  streamTimeout: 30000,             // 30s stream timeout
  
  // Content
  maxContentSize: 10 * 1024 * 1024 * 1024, // 10GB max
  maxPathLength: 512,
  maxMetadataSize: 64 * 1024,       // 64KB metadata
  
  // Viewing
  viewSessionExpiry: 24 * 60 * 60 * 1000,  // 24 hours
  attestationInterval: 60000,       // Attest every 60s during viewing
  
  // Quality presets
  qualityPresets: {
    ORIGINAL: 'original',
    HIGH: 'high',       // 1080p or best below
    MEDIUM: 'medium',   // 720p
    LOW: 'low',         // 480p
    THUMBNAIL: 'thumb', // Preview only
  },
  
  // Content types
  contentTypes: {
    VIDEO: 'video',
    AUDIO: 'audio',
    IMAGE: 'image',
    DOCUMENT: 'document',
    STREAM: 'stream',   // Live stream
    ANY: 'any',
  },
  
  // Permissions
  permissions: {
    VIEW: 'view',           // Can view only
    DOWNLOAD: 'download',   // Can download (explicit opt-in)
    SHARE: 'share',         // Can share access tokens
    CACHE: 'cache',         // Can cache for offline (time-limited)
  },
  
  // Message types
  messageTypes: {
    // Discovery
    CONTENT_LIST: 'darshan:list',
    CONTENT_INFO: 'darshan:info',
    
    // Streaming
    STREAM_REQUEST: 'darshan:stream:request',
    STREAM_RESPONSE: 'darshan:stream:response',
    STREAM_CHUNK: 'darshan:stream:chunk',
    STREAM_END: 'darshan:stream:end',
    STREAM_ERROR: 'darshan:stream:error',
    
    // Control
    SEEK: 'darshan:seek',
    PAUSE: 'darshan:pause',
    RESUME: 'darshan:resume',
    QUALITY_CHANGE: 'darshan:quality',
    
    // Attestation
    VIEW_START: 'darshan:view:start',
    VIEW_HEARTBEAT: 'darshan:view:heartbeat',
    VIEW_END: 'darshan:view:end',
    
    // Mount
    MOUNT_REQUEST: 'darshan:mount:request',
    MOUNT_RESPONSE: 'darshan:mount:response',
    UNMOUNT: 'darshan:unmount',
  },
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN CONTENT - Content metadata
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanContent - Metadata for streamable content
 */
export class DarshanContent {
  constructor(options = {}) {
    // Identity
    this.contentId = options.contentId || DarshanContent.generateId();
    this.hostNodeId = options.hostNodeId;
    this.path = options.path;  // Local path on host (private)
    
    // Metadata
    this.name = options.name || '';
    this.description = options.description || '';
    this.contentType = options.contentType || DARSHAN_CONFIG.contentTypes.ANY;
    this.mimeType = options.mimeType || 'application/octet-stream';
    this.size = options.size || 0;
    this.duration = options.duration || null;  // For video/audio
    this.dimensions = options.dimensions || null;  // { width, height }
    
    // Hash for integrity
    this.hash = options.hash || null;  // SHA3-256 of full content
    this.chunkHashes = options.chunkHashes || [];  // Per-chunk verification
    
    // Access control
    this.permissions = options.permissions || [DARSHAN_CONFIG.permissions.VIEW];
    this.accessList = options.accessList || null;  // GUMBA bundle ID or null for public
    
    // Quality options (for video/audio)
    this.availableQualities = options.availableQualities || [DARSHAN_CONFIG.qualityPresets.ORIGINAL];
    this.defaultQuality = options.defaultQuality || DARSHAN_CONFIG.qualityPresets.ORIGINAL;
    
    // Timestamps
    this.createdAt = options.createdAt || Date.now();
    this.updatedAt = options.updatedAt || Date.now();
    
    // Stats
    this.viewCount = options.viewCount || 0;
    this.totalBytesServed = options.totalBytesServed || 0;
  }
  
  static generateId() {
    return 'd-' + bytesToHex(randomBytes(16));
  }
  
  /**
   * Get public metadata (safe to share)
   */
  getPublicMetadata() {
    return {
      contentId: this.contentId,
      hostNodeId: this.hostNodeId,
      name: this.name,
      description: this.description,
      contentType: this.contentType,
      mimeType: this.mimeType,
      size: this.size,
      duration: this.duration,
      dimensions: this.dimensions,
      hash: this.hash,
      permissions: this.permissions,
      availableQualities: this.availableQualities,
      defaultQuality: this.defaultQuality,
      createdAt: this.createdAt,
      viewCount: this.viewCount,
    };
  }
  
  /**
   * Validate content metadata
   */
  validate() {
    const errors = [];
    
    if (!this.hostNodeId) errors.push('hostNodeId required');
    if (!this.path) errors.push('path required');
    if (this.path && this.path.length > DARSHAN_CONFIG.maxPathLength) {
      errors.push('path too long');
    }
    if (this.size > DARSHAN_CONFIG.maxContentSize) {
      errors.push('content exceeds max size');
    }
    if (!Object.values(DARSHAN_CONFIG.contentTypes).includes(this.contentType)) {
      errors.push('invalid contentType');
    }
    
    return { valid: errors.length === 0, errors };
  }
  
  toJSON() {
    return {
      contentId: this.contentId,
      hostNodeId: this.hostNodeId,
      path: this.path,
      name: this.name,
      description: this.description,
      contentType: this.contentType,
      mimeType: this.mimeType,
      size: this.size,
      duration: this.duration,
      dimensions: this.dimensions,
      hash: this.hash,
      chunkHashes: this.chunkHashes,
      permissions: this.permissions,
      accessList: this.accessList,
      availableQualities: this.availableQualities,
      defaultQuality: this.defaultQuality,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      viewCount: this.viewCount,
      totalBytesServed: this.totalBytesServed,
    };
  }
  
  static fromJSON(json) {
    return new DarshanContent(json);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN STREAM - Byte-range streaming
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanStream - Manages streaming of content bytes
 * 
 * "Like water from a mountain spring - 
 *  you drink what you need, the source remains."
 */
export class DarshanStream extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.streamId = options.streamId || DarshanStream.generateId();
    this.contentId = options.contentId;
    this.viewerId = options.viewerId;
    this.hostId = options.hostId;
    
    // Stream state
    this.state = 'idle';  // idle, requesting, streaming, paused, ended, error
    this.position = 0;
    this.bytesReceived = 0;
    this.bytesTotal = options.size || 0;
    
    // Configuration
    this.chunkSize = options.chunkSize || DARSHAN_CONFIG.defaultChunkSize;
    this.quality = options.quality || DARSHAN_CONFIG.qualityPresets.ORIGINAL;
    this.prefetch = options.prefetch !== false;
    
    // Buffering
    this.chunks = new Map();  // offset -> { data, verified }
    this.pendingRequests = new Set();
    
    // Callbacks
    this.onChunk = options.onChunk || (() => {});
    this.onProgress = options.onProgress || (() => {});
    this.onError = options.onError || (() => {});
    this.onEnd = options.onEnd || (() => {});
    
    // Timers
    this._timeout = null;
    
    // Stats
    this.startTime = null;
    this.endTime = null;
  }
  
  static generateId() {
    return 'stream-' + bytesToHex(randomBytes(8));
  }
  
  /**
   * Calculate chunk boundaries for a byte range
   */
  getChunkRange(start, end) {
    const chunkStart = Math.floor(start / this.chunkSize);
    const chunkEnd = Math.floor(end / this.chunkSize);
    return { chunkStart, chunkEnd };
  }
  
  /**
   * Request a specific byte range
   */
  requestRange(start, end) {
    const { chunkStart, chunkEnd } = this.getChunkRange(start, end);
    const needed = [];
    
    for (let i = chunkStart; i <= chunkEnd; i++) {
      const offset = i * this.chunkSize;
      if (!this.chunks.has(offset) && !this.pendingRequests.has(offset)) {
        needed.push(offset);
        this.pendingRequests.add(offset);
      }
    }
    
    return needed;
  }
  
  /**
   * Store a received chunk
   */
  receiveChunk(offset, data, hash = null) {
    // Verify hash if provided
    if (hash) {
      const computed = bytesToHex(sha3_256(data));
      if (computed !== hash) {
        this.emit('error', { type: 'integrity', offset, expected: hash, got: computed });
        return false;
      }
    }
    
    this.chunks.set(offset, { data, verified: !!hash });
    this.pendingRequests.delete(offset);
    this.bytesReceived += data.length;
    
    this.onProgress({
      bytesReceived: this.bytesReceived,
      bytesTotal: this.bytesTotal,
      percent: (this.bytesReceived / this.bytesTotal) * 100,
    });
    
    this.emit('chunk', { offset, size: data.length });
    return true;
  }
  
  /**
   * Get bytes for a range (from buffer)
   */
  getBytes(start, length) {
    const result = Buffer.alloc(length);
    let filled = 0;
    
    const { chunkStart, chunkEnd } = this.getChunkRange(start, start + length - 1);
    
    for (let i = chunkStart; i <= chunkEnd; i++) {
      const offset = i * this.chunkSize;
      const chunk = this.chunks.get(offset);
      
      if (!chunk) {
        return null;  // Gap in buffer
      }
      
      const chunkData = chunk.data;
      const srcStart = Math.max(0, start - offset);
      const srcEnd = Math.min(chunkData.length, start + length - offset);
      const dstStart = offset + srcStart - start;
      
      chunkData.copy(result, dstStart, srcStart, srcEnd);
      filled += srcEnd - srcStart;
    }
    
    return filled === length ? result : null;
  }
  
  /**
   * Seek to position
   */
  seek(position) {
    if (position < 0 || position >= this.bytesTotal) {
      return false;
    }
    
    this.position = position;
    this.emit('seek', { position });
    return true;
  }
  
  /**
   * Pause streaming
   */
  pause() {
    if (this.state === 'streaming') {
      this.state = 'paused';
      this.emit('pause');
    }
  }
  
  /**
   * Resume streaming
   */
  resume() {
    if (this.state === 'paused') {
      this.state = 'streaming';
      this.emit('resume');
    }
  }
  
  /**
   * End the stream
   */
  end() {
    this.state = 'ended';
    this.endTime = Date.now();
    this._clearTimeout();
    this.onEnd();
    this.emit('end', {
      duration: this.endTime - this.startTime,
      bytesReceived: this.bytesReceived,
    });
  }
  
  /**
   * Clean up resources
   */
  destroy() {
    this._clearTimeout();
    this.chunks.clear();
    this.pendingRequests.clear();
    this.removeAllListeners();
  }
  
  _clearTimeout() {
    if (this._timeout) {
      clearTimeout(this._timeout);
      this._timeout = null;
    }
  }
  
  /**
   * Get stream stats
   */
  getStats() {
    const now = Date.now();
    const duration = (this.endTime || now) - (this.startTime || now);
    
    return {
      streamId: this.streamId,
      state: this.state,
      position: this.position,
      bytesReceived: this.bytesReceived,
      bytesTotal: this.bytesTotal,
      bufferedChunks: this.chunks.size,
      pendingRequests: this.pendingRequests.size,
      duration,
      throughput: duration > 0 ? this.bytesReceived / (duration / 1000) : 0,
    };
  }
  
  toJSON() {
    return this.getStats();
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN ATTESTATION - Proof of viewing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanAttestation - Cryptographic proof of content viewing
 * 
 * "The sacred witness records all who came to see."
 */
export class DarshanAttestation {
  constructor(options = {}) {
    this.attestationId = options.attestationId || DarshanAttestation.generateId();
    this.contentId = options.contentId;
    this.viewerId = options.viewerId;
    this.hostId = options.hostId;
    
    // View session
    this.sessionId = options.sessionId;
    this.startedAt = options.startedAt || Date.now();
    this.endedAt = options.endedAt || null;
    this.duration = options.duration || 0;
    
    // Progress
    this.bytesViewed = options.bytesViewed || 0;
    this.percentViewed = options.percentViewed || 0;
    this.seekCount = options.seekCount || 0;
    
    // Quality info
    this.quality = options.quality || DARSHAN_CONFIG.qualityPresets.ORIGINAL;
    
    // Signatures
    this.viewerSignature = options.viewerSignature || null;
    this.hostSignature = options.hostSignature || null;
  }
  
  static generateId() {
    return 'attest-' + bytesToHex(randomBytes(8));
  }
  
  /**
   * Get the attestation payload for signing
   */
  getSignablePayload() {
    return JSON.stringify({
      attestationId: this.attestationId,
      contentId: this.contentId,
      viewerId: this.viewerId,
      hostId: this.hostId,
      sessionId: this.sessionId,
      startedAt: this.startedAt,
      endedAt: this.endedAt,
      bytesViewed: this.bytesViewed,
      percentViewed: this.percentViewed,
      quality: this.quality,
    });
  }
  
  /**
   * Sign as viewer
   */
  signAsViewer(secretKey) {
    const payload = utf8ToBytes(this.getSignablePayload());
    const signature = ml_dsa65.sign(payload, secretKey);
    this.viewerSignature = bytesToHex(signature);
    return this;
  }
  
  /**
   * Sign as host (counter-signature)
   */
  signAsHost(secretKey) {
    // Include viewer signature in host signing
    const payload = utf8ToBytes(this.getSignablePayload() + (this.viewerSignature || ''));
    const signature = ml_dsa65.sign(payload, secretKey);
    this.hostSignature = bytesToHex(signature);
    return this;
  }
  
  /**
   * Verify viewer signature
   */
  verifyViewer(publicKey) {
    if (!this.viewerSignature) return false;
    
    try {
      const payload = utf8ToBytes(this.getSignablePayload());
      const signatureBytes = hexToBytes(this.viewerSignature);
      const publicKeyBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
      return ml_dsa65.verify(signatureBytes, payload, publicKeyBytes);
    } catch (err) {
      return false;
    }
  }
  
  /**
   * Verify host signature
   */
  verifyHost(publicKey) {
    if (!this.hostSignature) return false;
    
    try {
      const payload = utf8ToBytes(this.getSignablePayload() + (this.viewerSignature || ''));
      const signatureBytes = hexToBytes(this.hostSignature);
      const publicKeyBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
      return ml_dsa65.verify(signatureBytes, payload, publicKeyBytes);
    } catch (err) {
      return false;
    }
  }
  
  /**
   * Check if attestation is complete (both signatures)
   */
  isComplete() {
    return !!(this.viewerSignature && this.hostSignature && this.endedAt);
  }
  
  /**
   * Update during viewing session
   */
  update(stats) {
    this.bytesViewed = stats.bytesViewed || this.bytesViewed;
    this.percentViewed = stats.percentViewed || this.percentViewed;
    this.seekCount = stats.seekCount || this.seekCount;
    this.duration = Date.now() - this.startedAt;
  }
  
  /**
   * Finalize the attestation
   */
  finalize() {
    this.endedAt = Date.now();
    this.duration = this.endedAt - this.startedAt;
  }
  
  toJSON() {
    return {
      attestationId: this.attestationId,
      contentId: this.contentId,
      viewerId: this.viewerId,
      hostId: this.hostId,
      sessionId: this.sessionId,
      startedAt: this.startedAt,
      endedAt: this.endedAt,
      duration: this.duration,
      bytesViewed: this.bytesViewed,
      percentViewed: this.percentViewed,
      seekCount: this.seekCount,
      quality: this.quality,
      viewerSignature: this.viewerSignature,
      hostSignature: this.hostSignature,
    };
  }
  
  static fromJSON(json) {
    return new DarshanAttestation(json);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN REQUEST - Stream request message
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanRequest - Request to stream content
 */
export class DarshanRequest {
  constructor(options = {}) {
    this.requestId = options.requestId || DarshanRequest.generateId();
    this.type = options.type || DARSHAN_CONFIG.messageTypes.STREAM_REQUEST;
    this.contentId = options.contentId;
    this.viewerId = options.viewerId;
    this.timestamp = options.timestamp || Date.now();
    
    // Request parameters
    this.startByte = options.startByte || 0;
    this.endByte = options.endByte || null;  // null = to end
    this.quality = options.quality || DARSHAN_CONFIG.qualityPresets.ORIGINAL;
    this.chunkSize = options.chunkSize || DARSHAN_CONFIG.defaultChunkSize;
    
    // Access proof (GUMBA)
    this.accessProof = options.accessProof || null;
  }
  
  static generateId() {
    return 'req-' + bytesToHex(randomBytes(8));
  }
  
  /**
   * Create a stream request
   */
  static streamRequest(options) {
    return new DarshanRequest({
      type: DARSHAN_CONFIG.messageTypes.STREAM_REQUEST,
      ...options,
    });
  }
  
  /**
   * Create a seek request
   */
  static seekRequest(options) {
    return new DarshanRequest({
      type: DARSHAN_CONFIG.messageTypes.SEEK,
      ...options,
    });
  }
  
  validate() {
    const errors = [];
    if (!this.contentId) errors.push('contentId required');
    if (!this.viewerId) errors.push('viewerId required');
    if (this.startByte < 0) errors.push('startByte must be >= 0');
    if (this.endByte !== null && this.endByte < this.startByte) {
      errors.push('endByte must be >= startByte');
    }
    return { valid: errors.length === 0, errors };
  }
  
  toJSON() {
    return {
      requestId: this.requestId,
      type: this.type,
      contentId: this.contentId,
      viewerId: this.viewerId,
      timestamp: this.timestamp,
      startByte: this.startByte,
      endByte: this.endByte,
      quality: this.quality,
      chunkSize: this.chunkSize,
      accessProof: this.accessProof,
    };
  }
  
  static fromJSON(json) {
    return new DarshanRequest(json);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN CHUNK - Streamed content chunk
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanChunk - A chunk of streamed content
 */
export class DarshanChunk {
  constructor(options = {}) {
    this.streamId = options.streamId;
    this.contentId = options.contentId;
    this.offset = options.offset || 0;
    this.data = options.data || null;  // Buffer
    this.hash = options.hash || null;  // SHA3-256 of data
    this.timestamp = options.timestamp || Date.now();
    
    // Position info
    this.isFirst = options.isFirst || false;
    this.isLast = options.isLast || false;
    this.totalSize = options.totalSize || 0;
  }
  
  /**
   * Create from buffer with auto-hash
   */
  static fromBuffer(buffer, options = {}) {
    const hash = bytesToHex(sha3_256(buffer));
    return new DarshanChunk({
      ...options,
      data: buffer,
      hash,
    });
  }
  
  /**
   * Verify chunk integrity
   */
  verify() {
    if (!this.data || !this.hash) return false;
    const computed = bytesToHex(sha3_256(this.data));
    return computed === this.hash;
  }
  
  toJSON() {
    return {
      streamId: this.streamId,
      contentId: this.contentId,
      offset: this.offset,
      data: this.data ? this.data.toString('base64') : null,
      hash: this.hash,
      timestamp: this.timestamp,
      isFirst: this.isFirst,
      isLast: this.isLast,
      totalSize: this.totalSize,
    };
  }
  
  static fromJSON(json) {
    return new DarshanChunk({
      ...json,
      data: json.data ? Buffer.from(json.data, 'base64') : null,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN GATEWAY - Host-side content server
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanGateway - Serves content to viewers
 * 
 * "The temple guardian who opens doors to the worthy."
 * 
 * The gateway:
 * - Registers local content for sharing
 * - Validates access proofs (GUMBA integration)
 * - Streams bytes on demand
 * - Tracks view attestations
 * - Controls bandwidth and quality
 */
export class DarshanGateway extends EventEmitter {
  constructor(identity, options = {}) {
    super();
    
    this.identity = identity;
    this.nodeId = identity.identity?.nodeId || identity.nodeId;
    this.options = options;
    
    // Content registry
    this.contents = new Map();  // contentId -> DarshanContent
    this.contentByPath = new Map();  // path -> contentId
    
    // Active streams
    this.streams = new Map();  // streamId -> stream info
    this.streamsByViewer = new Map();  // viewerId -> Set<streamId>
    
    // Attestations
    this.attestations = new Map();  // attestationId -> DarshanAttestation
    this.attestationsBySession = new Map();  // sessionId -> attestationId
    
    // Access control (GUMBA integration)
    this.accessController = options.accessController || null;
    
    // Bandwidth control
    this.maxBandwidth = options.maxBandwidth || Infinity;
    this.currentBandwidth = 0;
    this.bandwidthHistory = [];
    
    // File reader (injected for testability)
    this.fileReader = options.fileReader || null;
    
    // Stats
    this.stats = {
      contentRegistered: 0,
      streamsCreated: 0,
      bytesServed: 0,
      attestationsCreated: 0,
    };
  }
  
  /**
   * Register content for sharing
   */
  async registerContent(options) {
    const content = new DarshanContent({
      hostNodeId: this.nodeId,
      ...options,
    });
    
    const validation = content.validate();
    if (!validation.valid) {
      return { success: false, errors: validation.errors };
    }
    
    // Compute content hash if file reader available
    if (this.fileReader && !content.hash) {
      try {
        const data = await this.fileReader.read(content.path);
        content.hash = bytesToHex(sha3_256(data));
        content.size = data.length;
        
        // Compute chunk hashes
        const chunks = Math.ceil(data.length / DARSHAN_CONFIG.defaultChunkSize);
        content.chunkHashes = [];
        for (let i = 0; i < chunks; i++) {
          const start = i * DARSHAN_CONFIG.defaultChunkSize;
          const end = Math.min(start + DARSHAN_CONFIG.defaultChunkSize, data.length);
          const chunkData = data.slice(start, end);
          content.chunkHashes.push(bytesToHex(sha3_256(chunkData)));
        }
      } catch (err) {
        return { success: false, errors: ['Failed to read content: ' + err.message] };
      }
    }
    
    this.contents.set(content.contentId, content);
    this.contentByPath.set(content.path, content.contentId);
    this.stats.contentRegistered++;
    
    this.emit('content:registered', content);
    log.info('Content registered', { contentId: content.contentId, name: content.name });
    
    return { success: true, content };
  }
  
  /**
   * Unregister content
   */
  unregisterContent(contentId) {
    const content = this.contents.get(contentId);
    if (!content) return false;
    
    this.contentByPath.delete(content.path);
    this.contents.delete(contentId);
    
    this.emit('content:unregistered', content);
    return true;
  }
  
  /**
   * Get content by ID
   */
  getContent(contentId) {
    return this.contents.get(contentId) || null;
  }
  
  /**
   * List all registered content
   */
  listContent() {
    return Array.from(this.contents.values()).map(c => c.getPublicMetadata());
  }
  
  /**
   * Handle stream request
   */
  async handleStreamRequest(request, sendChunk) {
    const content = this.contents.get(request.contentId);
    if (!content) {
      return { success: false, error: 'CONTENT_NOT_FOUND' };
    }
    
    // Check access if access controller configured
    if (this.accessController && content.accessList) {
      const accessResult = await this.accessController.verifyAccess(
        request.accessProof,
        () => {} // Public key lookup
      );
      if (!accessResult.granted) {
        this.emit('access:denied', { request, reason: accessResult.reason });
        return { success: false, error: 'ACCESS_DENIED', reason: accessResult.reason };
      }
    }
    
    // Check concurrent stream limit
    const viewerStreams = this.streamsByViewer.get(request.viewerId) || new Set();
    if (viewerStreams.size >= DARSHAN_CONFIG.maxConcurrentStreams) {
      return { success: false, error: 'TOO_MANY_STREAMS' };
    }
    
    // Create stream
    const streamId = DarshanStream.generateId();
    const stream = {
      streamId,
      contentId: request.contentId,
      viewerId: request.viewerId,
      startByte: request.startByte,
      endByte: request.endByte || content.size - 1,
      currentByte: request.startByte,
      quality: request.quality,
      chunkSize: Math.min(request.chunkSize, DARSHAN_CONFIG.maxChunkSize),
      createdAt: Date.now(),
      bytesServed: 0,
      state: 'streaming',
    };
    
    this.streams.set(streamId, stream);
    viewerStreams.add(streamId);
    this.streamsByViewer.set(request.viewerId, viewerStreams);
    this.stats.streamsCreated++;
    
    // Create attestation
    const attestation = new DarshanAttestation({
      contentId: content.contentId,
      viewerId: request.viewerId,
      hostId: this.nodeId,
      sessionId: streamId,
    });
    this.attestations.set(attestation.attestationId, attestation);
    this.attestationsBySession.set(streamId, attestation.attestationId);
    this.stats.attestationsCreated++;
    
    this.emit('stream:started', { streamId, viewerId: request.viewerId, content });
    
    // Start streaming (async generator pattern)
    this._streamContent(stream, content, sendChunk).catch(err => {
      log.error('Stream error', { streamId, error: err.message });
      this.emit('stream:error', { streamId, error: err });
    });
    
    return { success: true, streamId, attestationId: attestation.attestationId };
  }
  
  /**
   * Stream content chunks
   */
  async _streamContent(stream, content, sendChunk) {
    if (!this.fileReader) {
      throw new Error('No file reader configured');
    }
    
    const data = await this.fileReader.read(content.path);
    
    while (stream.currentByte <= stream.endByte && stream.state === 'streaming') {
      const chunkStart = stream.currentByte;
      const chunkEnd = Math.min(chunkStart + stream.chunkSize - 1, stream.endByte);
      const chunkData = data.slice(chunkStart, chunkEnd + 1);
      
      const chunk = DarshanChunk.fromBuffer(Buffer.from(chunkData), {
        streamId: stream.streamId,
        contentId: stream.contentId,
        offset: chunkStart,
        isFirst: chunkStart === stream.startByte,
        isLast: chunkEnd >= stream.endByte,
        totalSize: content.size,
      });
      
      await sendChunk(chunk);
      
      stream.currentByte = chunkEnd + 1;
      stream.bytesServed += chunkData.length;
      this.stats.bytesServed += chunkData.length;
      content.totalBytesServed += chunkData.length;
      
      this.emit('chunk:sent', { streamId: stream.streamId, offset: chunkStart, size: chunkData.length });
    }
    
    // Update attestation
    const attestationId = this.attestationsBySession.get(stream.streamId);
    if (attestationId) {
      const attestation = this.attestations.get(attestationId);
      if (attestation) {
        attestation.update({
          bytesViewed: stream.bytesServed,
          percentViewed: (stream.bytesServed / content.size) * 100,
        });
        attestation.finalize();
        attestation.signAsHost(this.identity.identity.secretKey);
      }
    }
    
    stream.state = 'ended';
    content.viewCount++;
    
    this.emit('stream:ended', { streamId: stream.streamId, bytesServed: stream.bytesServed });
    
    // Cleanup
    const viewerStreams = this.streamsByViewer.get(stream.viewerId);
    if (viewerStreams) {
      viewerStreams.delete(stream.streamId);
    }
  }
  
  /**
   * Pause a stream
   */
  pauseStream(streamId) {
    const stream = this.streams.get(streamId);
    if (stream && stream.state === 'streaming') {
      stream.state = 'paused';
      this.emit('stream:paused', { streamId });
      return true;
    }
    return false;
  }
  
  /**
   * Resume a stream
   */
  resumeStream(streamId) {
    const stream = this.streams.get(streamId);
    if (stream && stream.state === 'paused') {
      stream.state = 'streaming';
      this.emit('stream:resumed', { streamId });
      return true;
    }
    return false;
  }
  
  /**
   * End a stream
   */
  endStream(streamId) {
    const stream = this.streams.get(streamId);
    if (stream) {
      stream.state = 'ended';
      this.emit('stream:ended', { streamId, bytesServed: stream.bytesServed });
      return true;
    }
    return false;
  }
  
  /**
   * Get attestation
   */
  getAttestation(attestationId) {
    return this.attestations.get(attestationId) || null;
  }
  
  /**
   * Get gateway stats
   */
  getStats() {
    return {
      ...this.stats,
      activeStreams: this.streams.size,
      registeredContent: this.contents.size,
      activeViewers: this.streamsByViewer.size,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN VIEWER - Client-side content viewer
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanViewer - Views content from remote hosts
 * 
 * "The pilgrim who receives the blessing of sight."
 */
export class DarshanViewer extends EventEmitter {
  constructor(identity, options = {}) {
    super();
    
    this.identity = identity;
    this.nodeId = identity.identity?.nodeId || identity.nodeId;
    this.options = options;
    
    // Active streams
    this.streams = new Map();  // streamId -> DarshanStream
    this.streamsByContent = new Map();  // contentId -> streamId
    
    // Content cache (metadata only, not data by default)
    this.knownContent = new Map();  // contentId -> DarshanContent metadata
    
    // Attestations we've received
    this.attestations = new Map();  // attestationId -> DarshanAttestation
    
    // Access proofs provider (GUMBA integration)
    this.proofProvider = options.proofProvider || null;
    
    // Transport layer (send messages to hosts)
    this.sendMessage = options.sendMessage || (() => {});
    
    // Stats
    this.stats = {
      streamsOpened: 0,
      bytesReceived: 0,
      contentViewed: 0,
    };
  }
  
  /**
   * Request content info from a host
   */
  async requestContentInfo(hostId, contentId) {
    return new Promise((resolve, reject) => {
      const requestId = 'info-' + bytesToHex(randomBytes(4));
      
      const timeout = setTimeout(() => {
        reject(new Error('Content info request timeout'));
      }, DARSHAN_CONFIG.streamTimeout);
      
      const handler = (response) => {
        if (response.requestId === requestId) {
          clearTimeout(timeout);
          this.removeListener('content:info:response', handler);
          
          if (response.error) {
            reject(new Error(response.error));
          } else {
            const content = DarshanContent.fromJSON(response.content);
            this.knownContent.set(content.contentId, content);
            resolve(content);
          }
        }
      };
      
      this.on('content:info:response', handler);
      
      this.sendMessage(hostId, {
        type: DARSHAN_CONFIG.messageTypes.CONTENT_INFO,
        requestId,
        contentId,
        viewerId: this.nodeId,
      });
    });
  }
  
  /**
   * Start streaming content
   */
  async startStream(hostId, contentId, options = {}) {
    // Get content info if not cached
    let content = this.knownContent.get(contentId);
    if (!content && options.contentInfo) {
      content = DarshanContent.fromJSON(options.contentInfo);
      this.knownContent.set(contentId, content);
    }
    
    // Get access proof if needed
    let accessProof = null;
    if (this.proofProvider && content?.accessList) {
      accessProof = await this.proofProvider.getProof(content.accessList, this.nodeId);
    }
    
    // Create stream
    const stream = new DarshanStream({
      contentId,
      viewerId: this.nodeId,
      hostId,
      size: content?.size || 0,
      chunkSize: options.chunkSize || DARSHAN_CONFIG.defaultChunkSize,
      quality: options.quality || DARSHAN_CONFIG.qualityPresets.ORIGINAL,
      onChunk: options.onChunk,
      onProgress: options.onProgress,
      onError: options.onError,
      onEnd: options.onEnd,
    });
    
    stream.state = 'requesting';
    stream.startTime = Date.now();
    
    this.streams.set(stream.streamId, stream);
    this.streamsByContent.set(contentId, stream.streamId);
    this.stats.streamsOpened++;
    
    // Send stream request
    const request = DarshanRequest.streamRequest({
      contentId,
      viewerId: this.nodeId,
      startByte: options.startByte || 0,
      endByte: options.endByte || null,
      quality: stream.quality,
      chunkSize: stream.chunkSize,
      accessProof,
    });
    
    this.sendMessage(hostId, {
      type: DARSHAN_CONFIG.messageTypes.STREAM_REQUEST,
      request: request.toJSON(),
      streamId: stream.streamId,
    });
    
    this.emit('stream:requested', { streamId: stream.streamId, contentId, hostId });
    
    return stream;
  }
  
  /**
   * Handle stream response from host
   */
  handleStreamResponse(response) {
    const stream = this.streams.get(response.streamId);
    if (!stream) {
      log.warn('Stream response for unknown stream', { streamId: response.streamId });
      return;
    }
    
    if (response.success) {
      stream.state = 'streaming';
      stream.attestationId = response.attestationId;
      this.emit('stream:started', { streamId: stream.streamId });
    } else {
      stream.state = 'error';
      stream.onError(response.error);
      this.emit('stream:error', { streamId: stream.streamId, error: response.error });
    }
  }
  
  /**
   * Handle incoming chunk
   */
  handleChunk(chunkData) {
    const chunk = DarshanChunk.fromJSON(chunkData);
    const stream = this.streams.get(chunk.streamId);
    
    if (!stream) {
      log.warn('Chunk for unknown stream', { streamId: chunk.streamId });
      return;
    }
    
    // Verify chunk integrity
    if (!chunk.verify()) {
      stream.onError({ type: 'integrity', offset: chunk.offset });
      this.emit('chunk:invalid', { streamId: chunk.streamId, offset: chunk.offset });
      return;
    }
    
    // Store chunk
    stream.receiveChunk(chunk.offset, chunk.data, chunk.hash);
    stream.onChunk(chunk);
    
    this.stats.bytesReceived += chunk.data.length;
    
    // Check if stream complete
    if (chunk.isLast) {
      stream.state = 'ended';
      stream.endTime = Date.now();
      stream.onEnd();
      this.stats.contentViewed++;
      this.emit('stream:complete', { streamId: chunk.streamId });
    }
  }
  
  /**
   * Seek within a stream
   */
  seek(streamId, position) {
    const stream = this.streams.get(streamId);
    if (!stream) return false;
    
    stream.seek(position);
    
    this.sendMessage(stream.hostId, {
      type: DARSHAN_CONFIG.messageTypes.SEEK,
      streamId,
      position,
      viewerId: this.nodeId,
    });
    
    return true;
  }
  
  /**
   * Pause a stream
   */
  pause(streamId) {
    const stream = this.streams.get(streamId);
    if (!stream) return false;
    
    stream.pause();
    
    this.sendMessage(stream.hostId, {
      type: DARSHAN_CONFIG.messageTypes.PAUSE,
      streamId,
      viewerId: this.nodeId,
    });
    
    return true;
  }
  
  /**
   * Resume a stream
   */
  resume(streamId) {
    const stream = this.streams.get(streamId);
    if (!stream) return false;
    
    stream.resume();
    
    this.sendMessage(stream.hostId, {
      type: DARSHAN_CONFIG.messageTypes.RESUME,
      streamId,
      viewerId: this.nodeId,
    });
    
    return true;
  }
  
  /**
   * End a stream
   */
  endStream(streamId) {
    const stream = this.streams.get(streamId);
    if (!stream) return false;
    
    stream.end();
    this.streams.delete(streamId);
    this.streamsByContent.delete(stream.contentId);
    
    this.sendMessage(stream.hostId, {
      type: DARSHAN_CONFIG.messageTypes.STREAM_END,
      streamId,
      viewerId: this.nodeId,
    });
    
    return true;
  }
  
  /**
   * Sign attestation as viewer
   */
  signAttestation(attestation) {
    attestation.signAsViewer(this.identity.identity.secretKey);
    this.attestations.set(attestation.attestationId, attestation);
    return attestation;
  }
  
  /**
   * Get stream for content
   */
  getStreamForContent(contentId) {
    const streamId = this.streamsByContent.get(contentId);
    return streamId ? this.streams.get(streamId) : null;
  }
  
  /**
   * Get viewer stats
   */
  getStats() {
    return {
      ...this.stats,
      activeStreams: this.streams.size,
      knownContent: this.knownContent.size,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN MOUNT - Virtual filesystem mount
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * DarshanMount - Virtual mount point for remote content
 * 
 * Maps remote content to local virtual paths.
 * Actual FUSE integration would be platform-specific.
 * This provides the abstraction layer.
 * 
 * "A window into the temple, not a door."
 */
export class DarshanMount extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.mountPoint = options.mountPoint || '/yak';
    this.viewer = options.viewer;  // DarshanViewer instance
    
    // Virtual directory structure
    this.virtualFs = new Map();  // path -> { type, contentId, hostId, content }
    
    // Active file handles
    this.handles = new Map();  // handleId -> { path, stream, position }
    this.nextHandleId = 1;
    
    // Mount state
    this.mounted = false;
    
    // Cache policy
    this.cachePolicy = options.cachePolicy || 'none';  // none, session, persistent
  }
  
  /**
   * Mount the virtual filesystem
   */
  async mount() {
    if (this.mounted) {
      throw new Error('Already mounted');
    }
    
    this.mounted = true;
    this.emit('mount', { mountPoint: this.mountPoint });
    log.info('DARSHAN mounted', { mountPoint: this.mountPoint });
    
    return true;
  }
  
  /**
   * Unmount the virtual filesystem
   */
  async unmount() {
    if (!this.mounted) return false;
    
    // Close all open handles
    for (const [handleId, handle] of this.handles) {
      if (handle.stream) {
        this.viewer.endStream(handle.stream.streamId);
      }
    }
    this.handles.clear();
    
    this.mounted = false;
    this.emit('unmount', { mountPoint: this.mountPoint });
    
    return true;
  }
  
  /**
   * Add content to virtual filesystem
   */
  addContent(hostId, content, virtualPath = null) {
    const path = virtualPath || `${this.mountPoint}/${hostId}/${content.name}`;
    
    this.virtualFs.set(path, {
      type: 'file',
      contentId: content.contentId,
      hostId,
      content,
      size: content.size,
      mtime: content.updatedAt,
    });
    
    // Ensure parent directories exist
    const parts = path.split('/').filter(Boolean);
    let currentPath = '';
    for (let i = 0; i < parts.length - 1; i++) {
      currentPath += '/' + parts[i];
      if (!this.virtualFs.has(currentPath)) {
        this.virtualFs.set(currentPath, { type: 'directory', children: new Set() });
      }
      const dir = this.virtualFs.get(currentPath);
      if (dir.type === 'directory') {
        dir.children.add(parts[i + 1]);
      }
    }
    
    this.emit('content:added', { path, contentId: content.contentId });
    
    return path;
  }
  
  /**
   * Remove content from virtual filesystem
   */
  removeContent(path) {
    const entry = this.virtualFs.get(path);
    if (!entry) return false;
    
    this.virtualFs.delete(path);
    this.emit('content:removed', { path });
    
    return true;
  }
  
  /**
   * List directory contents
   */
  readdir(path) {
    const entry = this.virtualFs.get(path);
    if (!entry || entry.type !== 'directory') {
      return null;
    }
    return Array.from(entry.children);
  }
  
  /**
   * Get file/directory stats
   */
  stat(path) {
    const entry = this.virtualFs.get(path);
    if (!entry) return null;
    
    return {
      type: entry.type,
      size: entry.size || 0,
      mtime: entry.mtime || Date.now(),
      contentId: entry.contentId,
    };
  }
  
  /**
   * Open a file for reading
   */
  async open(path) {
    const entry = this.virtualFs.get(path);
    if (!entry || entry.type !== 'file') {
      throw new Error('File not found: ' + path);
    }
    
    // Start stream
    const stream = await this.viewer.startStream(
      entry.hostId,
      entry.contentId,
      { contentInfo: entry.content }
    );
    
    const handleId = this.nextHandleId++;
    this.handles.set(handleId, {
      path,
      stream,
      position: 0,
    });
    
    this.emit('file:opened', { handleId, path });
    
    return handleId;
  }
  
  /**
   * Read from an open file
   */
  async read(handleId, length) {
    const handle = this.handles.get(handleId);
    if (!handle) {
      throw new Error('Invalid handle: ' + handleId);
    }
    
    // Request specific range
    handle.stream.requestRange(handle.position, handle.position + length - 1);
    
    // Wait for data (simplified - real impl would use proper async)
    const data = handle.stream.getBytes(handle.position, length);
    
    if (data) {
      handle.position += data.length;
      return data;
    }
    
    return null;  // Data not yet available
  }
  
  /**
   * Seek within an open file
   */
  seek(handleId, position) {
    const handle = this.handles.get(handleId);
    if (!handle) return false;
    
    handle.position = position;
    handle.stream.seek(position);
    
    return true;
  }
  
  /**
   * Close an open file
   */
  close(handleId) {
    const handle = this.handles.get(handleId);
    if (!handle) return false;
    
    this.viewer.endStream(handle.stream.streamId);
    this.handles.delete(handleId);
    
    this.emit('file:closed', { handleId, path: handle.path });
    
    return true;
  }
  
  /**
   * Get mount stats
   */
  getStats() {
    return {
      mountPoint: this.mountPoint,
      mounted: this.mounted,
      virtualFiles: this.virtualFs.size,
      openHandles: this.handles.size,
    };
  }
}
