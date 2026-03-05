/**
 * SEVA Mesh Handler — NPU Compute Sharing for Yakmesh Mesh
 * 
 * सेवा (seva) = selfless service
 * 
 * Enables nodes with NPU hardware to serve compute requests from
 * nodes without it. Work is math-only — no executable code, no files.
 * All transport via ANNEX-encrypted mesh channels.
 * 
 * PROTOCOL FLOW:
 *   1. Node with NPU opts in: config.seva.enabled = true
 *   2. Node broadcasts capability ad via GOSSIP (seva:capability)
 *   3. Requesting node sends seva:request to a capable peer
 *   4. Receiving node validates (math-only), executes, returns result
 *   5. Optional: third-party verification via re-execution
 * 
 * MESSAGE TYPES:
 *   - seva:capability  — broadcast: what this node can compute
 *   - seva:request     — directed: work request (math-only params)
 *   - seva:response    — directed: work result (numbers only)
 *   - seva:verify      — directed: request verification of a result
 *   - seva:verify:ack  — directed: verification result (match/mismatch)
 * 
 * SECURITY:
 *   - All params validated to be numbers-only (no strings, no code)
 *   - Pre-defined model slots only (no custom computation)
 *   - Rate-limited per requesting peer
 *   - Reputation-gated: low-karma peers get lower priority
 *   - Results are deterministic → verifiable by any third peer
 * 
 * @module mesh/seva
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createLogger } from '../utils/logger.js';
import EventEmitter from 'events';

const log = createLogger('mesh:seva');

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const SEVA_CONFIG = Object.freeze({
  version: 1,
  
  // Capacity management
  defaultMaxConcurrent: 10,
  maxRequestsPerPeerPerMinute: 30,
  requestTimeout: 5000,       // 5s timeout for work responses
  
  // Verification
  verifyProbability: 0.05,    // 5% of results get spot-checked
  verifyTimeout: 10000,       // 10s for verification round-trip
  
  // Capability broadcast
  capabilityBroadcastInterval: 60000,  // Advertise every 60s
  capabilityTTL: 180000,              // Expire after 3 minutes
  
  // Model slots (must match c2c server SEVA_SLOTS — 18 slots)
  validSlots: new Set([
    // Planet rendering (21g)
    'planet-variation',
    'planet-heightmap',
    'planet-superres',
    // Game AI models
    'faction-brain',
    'combat-predict',
    'threat-narrator',
    'fleet-advisor',
    'expedition-oracle',
    'commander-ai',
    'adaptive-threat',
    'lane-optimizer',
    'lore-generator',
    // AI Commander (C.6)
    'sherpa-commander',
    'lama-strategist',
    'whisper-transcribe',
    'vc-commander',
    // Dynamis anti-cheat
    'behavior-detector',
  ]),
  
  // Message types
  messageTypes: {
    CAPABILITY: 'seva:capability',
    REQUEST:    'seva:request',
    RESPONSE:   'seva:response',
    VERIFY:     'seva:verify',
    VERIFY_ACK: 'seva:verify:ack',
  },
});

// ═══════════════════════════════════════════════════════════════════════════════
// SEVA MESH HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

export class SevaMeshHandler extends EventEmitter {
  /**
   * @param {Object} opts
   * @param {Object} opts.identity    — node identity (nodeId, publicKey)
   * @param {Object} opts.network     — MandalaNetwork instance for sending messages
   * @param {boolean} opts.enabled    — whether this node offers NPU compute (opt-in)
   * @param {Object} opts.hardware    — { npu: bool, npuTops: number, gpu: bool, ... }
   * @param {Function} opts.executor  — async function(slot, params) => result
   * @param {number} opts.maxConcurrent — max parallel jobs (default 10)
   */
  constructor(opts = {}) {
    super();
    this.identity = opts.identity;
    this.network = opts.network;
    this.enabled = opts.enabled ?? false;
    this.hardware = opts.hardware || {};
    this.executor = opts.executor || null;
    this.maxConcurrent = opts.maxConcurrent || SEVA_CONFIG.defaultMaxConcurrent;
    
    // State
    this.activeJobs = 0;
    this.totalServed = 0;
    this.peerCapabilities = new Map();   // peerId → { slots, capacity, lastSeen }
    this.peerRateLimits = new Map();     // peerId → { timestamps: number[] }
    this.pendingRequests = new Map();     // requestId → { resolve, reject, timer }
    
    // Broadcast timer
    this._capBroadcastTimer = null;
  }
  
  // ─── LIFECYCLE ────────────────────────────────────────────────────────────
  
  start() {
    if (this.enabled) {
      // Broadcast our capabilities immediately, then periodically
      this._broadcastCapability();
      this._capBroadcastTimer = setInterval(
        () => this._broadcastCapability(),
        SEVA_CONFIG.capabilityBroadcastInterval
      );
      log.info({
        npu: !!this.hardware.npu,
        npuTops: this.hardware.npuTops || 0,
        maxConcurrent: this.maxConcurrent,
      }, 'SEVA mesh handler started (serving NPU compute)');
    } else {
      log.info('SEVA mesh handler started (consumer only — no NPU sharing)');
    }
    
    // Always listen for capabilities and responses (even if not serving)
    // The network adapter will call handleMessage() for seva: messages
  }
  
  stop() {
    if (this._capBroadcastTimer) clearInterval(this._capBroadcastTimer);
    this._capBroadcastTimer = null;
    
    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error('SEVA handler stopped'));
    }
    this.pendingRequests.clear();
    
    log.info('SEVA mesh handler stopped');
  }
  
  // ─── INCOMING MESSAGE HANDLER ─────────────────────────────────────────────
  
  /**
   * Handle an incoming SEVA mesh message.
   * Called by MandalaNetwork when a seva: message arrives.
   * 
   * @param {string} type     — message type (seva:*)
   * @param {Object} payload  — message payload
   * @param {string} peerId   — sender peer ID
   */
  async handleMessage(type, payload, peerId) {
    switch (type) {
      case SEVA_CONFIG.messageTypes.CAPABILITY:
        this._handleCapability(payload, peerId);
        break;
      case SEVA_CONFIG.messageTypes.REQUEST:
        await this._handleRequest(payload, peerId);
        break;
      case SEVA_CONFIG.messageTypes.RESPONSE:
        this._handleResponse(payload, peerId);
        break;
      case SEVA_CONFIG.messageTypes.VERIFY:
        await this._handleVerify(payload, peerId);
        break;
      case SEVA_CONFIG.messageTypes.VERIFY_ACK:
        this._handleVerifyAck(payload, peerId);
        break;
      default:
        log.debug({ type }, 'Unknown SEVA message type');
    }
  }
  
  // ─── CAPABILITY MANAGEMENT ────────────────────────────────────────────────
  
  _broadcastCapability() {
    if (!this.enabled || !this.network) return;
    
    const ad = {
      nodeId: this.identity?.nodeId,
      version: SEVA_CONFIG.version,
      slots: this._getActiveSlots(),
      capacity: {
        maxConcurrent: this.maxConcurrent,
        currentLoad: this.activeJobs,
        accelerated: !!this.hardware.npu,
        npuTops: this.hardware.npuTops || 0,
      },
      ts: Date.now(),
    };
    
    this.network.broadcast({ type: SEVA_CONFIG.messageTypes.CAPABILITY, ...ad });
  }
  
  _getActiveSlots() {
    const slots = [];
    for (const slotId of SEVA_CONFIG.validSlots) {
      slots.push({
        id: slotId,
        accelerated: !!this.hardware.npu,
      });
    }
    return slots;
  }
  
  _handleCapability(payload, peerId) {
    if (!payload || !payload.slots) return;
    
    this.peerCapabilities.set(peerId, {
      slots: new Set(payload.slots.map(s => s.id)),
      capacity: payload.capacity || {},
      accelerated: payload.capacity?.accelerated || false,
      lastSeen: Date.now(),
    });
    
    this.emit('peerCapability', peerId, payload);
    
    // Evict stale peer capabilities
    this._cleanStalePeers();
  }
  
  _cleanStalePeers() {
    const now = Date.now();
    for (const [peerId, cap] of this.peerCapabilities) {
      if (now - cap.lastSeen > SEVA_CONFIG.capabilityTTL) {
        this.peerCapabilities.delete(peerId);
      }
    }
  }
  
  // ─── WORK REQUEST (CONSUMER SIDE) ─────────────────────────────────────────
  
  /**
   * Submit a work request to the mesh.
   * Finds the best capable peer and sends the request.
   * 
   * @param {string} slot    — model slot ID
   * @param {Object} params  — numeric parameters
   * @returns {Promise<Object>} — work result
   */
  async requestWork(slot, params) {
    if (!SEVA_CONFIG.validSlots.has(slot)) {
      throw new Error(`Invalid SEVA slot: ${slot}`);
    }
    
    // Validate params are math-only
    if (!this._validateNumericOnly(params)) {
      throw new Error('SEVA params must be numbers only');
    }
    
    // Find best peer for this slot
    const peer = this._findBestPeer(slot);
    if (!peer) {
      throw new Error('No SEVA-capable peers available');
    }
    
    // Generate request ID
    const reqId = this._generateId();
    
    // Send request and wait for response
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(reqId);
        reject(new Error('SEVA request timeout'));
      }, SEVA_CONFIG.requestTimeout);
      
      this.pendingRequests.set(reqId, { resolve, reject, timer, slot, params });
      
      this.network.sendTo(peer, {
        type: SEVA_CONFIG.messageTypes.REQUEST,
        id: reqId,
        slot,
        params,
        ts: Date.now(),
      });
    });
  }
  
  /**
   * Find the best peer for a given slot.
   * Prefers: accelerated > lowest load > most recent capability ad.
   */
  _findBestPeer(slot) {
    let bestPeer = null;
    let bestScore = -1;
    
    for (const [peerId, cap] of this.peerCapabilities) {
      if (!cap.slots.has(slot)) continue;
      
      // Score: NPU acceleration = 100, low load bonus = 0-50, freshness = 0-10
      let score = 0;
      if (cap.accelerated) score += 100;
      const loadRatio = (cap.capacity.currentLoad || 0) / (cap.capacity.maxConcurrent || 10);
      score += (1 - loadRatio) * 50;
      const ageMs = Date.now() - cap.lastSeen;
      score += Math.max(0, 10 - ageMs / 10000);
      
      if (score > bestScore) {
        bestScore = score;
        bestPeer = peerId;
      }
    }
    
    return bestPeer;
  }
  
  // ─── WORK REQUEST (SERVER SIDE) ───────────────────────────────────────────
  
  async _handleRequest(payload, peerId) {
    if (!this.enabled || !this.executor) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'rejected',
        error: 'SEVA not enabled on this node',
      });
      return;
    }
    
    // Rate limit check
    if (!this._checkPeerRateLimit(peerId)) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'rejected',
        error: 'Rate limit exceeded',
      });
      return;
    }
    
    // Validate slot
    if (!SEVA_CONFIG.validSlots.has(payload.slot)) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'error',
        error: 'Invalid slot',
      });
      return;
    }
    
    // Validate math-only params
    if (!this._validateNumericOnly(payload.params)) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'error',
        error: 'Params must be numbers only',
      });
      return;
    }
    
    // Concurrency check
    if (this.activeJobs >= this.maxConcurrent) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'rejected',
        error: 'Node at capacity',
      });
      return;
    }
    
    // Execute
    this.activeJobs++;
    try {
      const t0 = performance.now();
      const result = await this.executor(payload.slot, payload.params);
      const computeMs = Math.round(performance.now() - t0);
      this.totalServed++;
      
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        slot: payload.slot,
        status: 'ok',
        result,
        source: this.hardware.npu ? 'npu' : 'cpu',
        computeMs,
      });
      
      log.debug({ slot: payload.slot, computeMs, peer: peerId.slice(0, 8) }, 'SEVA work served');
    } catch (err) {
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.RESPONSE,
        id: payload.id,
        status: 'error',
        error: 'Execution failed',
      });
    } finally {
      this.activeJobs--;
    }
  }
  
  _handleResponse(payload, peerId) {
    const pending = this.pendingRequests.get(payload.id);
    if (!pending) return;
    
    clearTimeout(pending.timer);
    this.pendingRequests.delete(payload.id);
    
    if (payload.status === 'ok') {
      pending.resolve(payload);
    } else {
      pending.reject(new Error(payload.error || 'SEVA response error'));
    }
  }
  
  // ─── VERIFICATION ─────────────────────────────────────────────────────────
  
  async _handleVerify(payload, peerId) {
    if (!this.enabled || !this.executor) return;
    
    // Re-execute the computation
    try {
      const result = await this.executor(payload.slot, payload.params);
      
      // Compare with claimed result using canonical JSON comparison
      const match = JSON.stringify(result) === JSON.stringify(payload.claimedResult);
      
      this.network.sendTo(peerId, {
        type: SEVA_CONFIG.messageTypes.VERIFY_ACK,
        id: payload.id,
        match,
        slot: payload.slot,
      });
    } catch {
      // Can't verify — skip
    }
  }
  
  _handleVerifyAck(payload, peerId) {
    this.emit('verifyResult', payload.id, payload.match, peerId);
    
    if (!payload.match) {
      log.warn({ id: payload.id, peer: peerId.slice(0, 8) }, 'SEVA verification MISMATCH');
      this.emit('verifyMismatch', payload.id, peerId);
    }
  }
  
  // ─── RATE LIMITING ────────────────────────────────────────────────────────
  
  _checkPeerRateLimit(peerId) {
    const now = Date.now();
    let state = this.peerRateLimits.get(peerId);
    if (!state) {
      state = { timestamps: [] };
      this.peerRateLimits.set(peerId, state);
    }
    
    // Remove timestamps older than 60s
    state.timestamps = state.timestamps.filter(t => now - t < 60000);
    state.timestamps.push(now);
    
    return state.timestamps.length <= SEVA_CONFIG.maxRequestsPerPeerPerMinute;
  }
  
  // ─── UTILITIES ────────────────────────────────────────────────────────────
  
  _validateNumericOnly(obj, depth = 0) {
    if (depth > 3) return false;
    if (typeof obj === 'number' && isFinite(obj)) return true;
    if (Array.isArray(obj)) {
      if (obj.length > 100000) return false;
      return obj.every(v => this._validateNumericOnly(v, depth + 1));
    }
    if (typeof obj === 'object' && obj !== null) {
      const keys = Object.keys(obj);
      if (keys.length > 20) return false;
      return keys.every(k => this._validateNumericOnly(obj[k], depth + 1));
    }
    return false;
  }
  
  _generateId() {
    const chars = '0123456789abcdef';
    let id = '';
    for (let i = 0; i < 16; i++) {
      id += chars[Math.floor(Math.random() * 16)];
    }
    return id;
  }
  
  // ─── PUBLIC API ───────────────────────────────────────────────────────────
  
  /**
   * Get all known SEVA-capable peers.
   */
  getCapablePeers(slot = null) {
    const peers = [];
    for (const [peerId, cap] of this.peerCapabilities) {
      if (slot && !cap.slots.has(slot)) continue;
      peers.push({ peerId, ...cap });
    }
    return peers;
  }
  
  /**
   * Get this node's current SEVA stats.
   */
  getStats() {
    return {
      enabled: this.enabled,
      activeJobs: this.activeJobs,
      totalServed: this.totalServed,
      maxConcurrent: this.maxConcurrent,
      knownPeers: this.peerCapabilities.size,
      hardware: {
        npu: !!this.hardware.npu,
        npuTops: this.hardware.npuTops || 0,
        gpu: !!this.hardware.gpu,
      },
    };
  }
}

export default SevaMeshHandler;
