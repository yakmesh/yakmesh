/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * YPC-27 Packet Checksum Integration
 * 
 * Provides quantum-hard checksums for all YAKMESH protocols:
 * - STUPA (broadcast messages)
 * - NAKPAK (onion packets)
 * - KHATA (trust distribution)
 * - MANTRA (gossip messages)
 * 
 * Each packet type gets its own domain-separated checksum to prevent
 * cross-protocol attacks (e.g., replaying a KHATA message as STUPA).
 * 
 * @module oracle/packet-checksum
 * @version 1.0.0
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { YPC27Checksum, ypc27, bytesToTrits, tritsToBytes, seedFromPeerId, Poly27 } from './ypc27.js';
import { YPC27_SST } from './ypc27.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:packet-checksum');

// =============================================================================
// PROTOCOL DOMAIN TAGS
// =============================================================================

/**
 * Domain separation tags for different protocol types.
 * These ensure a valid checksum for one protocol cannot be reused for another.
 */
export const PROTOCOL_DOMAIN = Object.freeze({
  STUPA:   'YAKMESH.STUPA.v1',    // Broadcast messages
  NAKPAK:  'YAKMESH.NAKPAK.v1',   // Onion packets
  KHATA:   'YAKMESH.KHATA.v1',    // Trust distribution
  MANTRA:  'YAKMESH.MANTRA.v1',   // Gossip messages
  SHERPA:  'YAKMESH.SHERPA.v1',   // Discovery beacons
  ANNEX:   'YAKMESH.ANNEX.v1',    // P2P channels
  LAMA:    'YAKMESH.LAMA.v1',     // Consensus
  KARMA:   'YAKMESH.KARMA.v1',    // Reputation events
  MANI:    'YAKMESH.MANI.v1',     // Time sync
});

// =============================================================================
// CHECKSUM FIELD FORMAT
// =============================================================================

/**
 * Serialized checksum format for wire transmission.
 * 
 * Format: "YPC27:v1:<base64-encoded-trits>"
 * 
 * Example: "YPC27:v1:AQD/AQD/AQD/AQD/AQD/AQD/AQD/AQD/AQ=="
 * 
 * The trits are packed as int8 values (-1, 0, +1) and base64-encoded.
 */
export const CHECKSUM_PREFIX = 'YPC27:v1:';

/**
 * Convert a Poly27 checksum to wire format string.
 * @param {Poly27} checksum 
 * @returns {string}
 */
export function checksumToWire(checksum) {
  const trits = checksum.toTypedArray();
  // Pack trits as int8 and base64-encode
  const buffer = Buffer.from(trits);
  return CHECKSUM_PREFIX + buffer.toString('base64');
}

/**
 * Parse wire format string back to Poly27.
 * @param {string} wire 
 * @returns {Poly27}
 * @throws {Error} If format is invalid
 */
export function checksumFromWire(wire) {
  if (!wire || typeof wire !== 'string') {
    throw new Error('Invalid checksum: expected string');
  }
  if (!wire.startsWith(CHECKSUM_PREFIX)) {
    throw new Error(`Invalid checksum prefix, expected ${CHECKSUM_PREFIX}`);
  }
  
  const b64 = wire.slice(CHECKSUM_PREFIX.length);
  const buffer = Buffer.from(b64, 'base64');
  
  if (buffer.length !== 27) {
    throw new Error(`Invalid checksum length: expected 27 bytes, got ${buffer.length}`);
  }
  
  // Validate all values are in {-1, 0, +1}
  for (let i = 0; i < 27; i++) {
    const val = buffer[i] > 127 ? buffer[i] - 256 : buffer[i]; // Handle signed
    if (val < -1 || val > 1) {
      throw new Error(`Invalid trit value at index ${i}: ${val}`);
    }
  }
  
  return new Poly27(Array.from(buffer).map(b => b > 127 ? b - 256 : b));
}

// =============================================================================
// PACKET CHECKSUM ENGINE
// =============================================================================

/**
 * PacketChecksum - Generate and verify YPC-27 checksums for packets.
 * 
 * Usage:
 * ```javascript
 * const engine = new PacketChecksum(PROTOCOL_DOMAIN.STUPA, myNodeId);
 * 
 * // Compute checksum for outgoing packet
 * const checksum = engine.compute(packetData);
 * packet.ypc27 = checksumToWire(checksum);
 * 
 * // Verify checksum on incoming packet
 * const isValid = engine.verify(packetData, checksumFromWire(packet.ypc27));
 * ```
 */
export class PacketChecksum {
  /** @type {string} */
  #domain;
  
  /** @type {Poly27} */
  #seed;

  /**
   * Create a packet checksum engine.
   * @param {string} domain - Protocol domain from PROTOCOL_DOMAIN
   * @param {string} [nodeId] - Optional node ID for seed derivation
   */
  constructor(domain, nodeId = null) {
    if (!domain || typeof domain !== 'string') {
      throw new Error('Protocol domain is required');
    }
    
    this.#domain = domain;
    
    // Derive seed from domain + nodeId for extra domain separation
    this.#seed = nodeId 
      ? seedFromPeerId(`${domain}:${nodeId}`)
      : seedFromPeerId(domain);
  }

  /**
   * Get the domain this engine is configured for.
   * @returns {string}
   */
  get domain() {
    return this.#domain;
  }

  /**
   * Seed as 27 trits in F_3 {0,1,2} — the format the NPU bridge
   * (/ypc27/digest) takes for per-message seeds.
   * @returns {number[]}
   */
  get seedTrits() {
    return [...this.#seed.toTypedArray()];
  }

  /**
   * The exact bytes this engine hashes — domain||normalized(data).
   * Exposed so batch accelerators can reproduce the message stream.
   * @param {Object|string|Buffer|Uint8Array} data
   * @returns {Buffer}
   */
  bytesFor(data) {
    const bytes = this.#normalizeToBytes(data);
    const domainBytes = Buffer.from(this.#domain, 'utf-8');
    return Buffer.concat([domainBytes, bytes]);
  }

  /**
   * Compute checksum for packet data.
   * 
   * @param {Object|string|Buffer|Uint8Array} data - Packet data to checksum
   * @returns {Poly27} - The 27-trit checksum
   */
  compute(data) {
    // Normalize input to bytes
    const bytes = this.#normalizeToBytes(data);
    
    // Prepend domain tag for domain separation
    const domainBytes = Buffer.from(this.#domain, 'utf-8');
    const fullData = Buffer.concat([domainBytes, bytes]);
    
    // Compute checksum with seed - use YPC27Checksum.compute() which returns Poly27
    return YPC27Checksum.compute(fullData, this.#seed);
  }

  /**
   * Verify a checksum against packet data.
   * 
   * @param {Object|string|Buffer|Uint8Array} data - Packet data
   * @param {Poly27} checksum - Expected checksum
   * @returns {boolean} - True if valid
   */
  verify(data, checksum) {
    const computed = this.compute(data);
    return computed.equals(checksum);
  }

  /**
   * Normalize various input types to Buffer.
   * @param {Object|string|Buffer|Uint8Array} data 
   * @returns {Buffer}
   */
  #normalizeToBytes(data) {
    if (data instanceof Buffer) {
      return data;
    }
    if (data instanceof Uint8Array) {
      return Buffer.from(data);
    }
    if (typeof data === 'string') {
      return Buffer.from(data, 'utf-8');
    }
    if (typeof data === 'object') {
      // For objects, use deterministic JSON serialization
      return Buffer.from(this.#deterministicStringify(data), 'utf-8');
    }
    throw new Error(`Unsupported data type: ${typeof data}`);
  }

  /**
   * Deterministic JSON serialization (sorted keys).
   * Important for checksum consistency across nodes.
   * @param {Object} obj 
   * @returns {string}
   */
  #deterministicStringify(obj) {
    return JSON.stringify(obj, (key, value) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return Object.keys(value).sort().reduce((sorted, k) => {
          sorted[k] = value[k];
          return sorted;
        }, {});
      }
      return value;
    });
  }
}

// =============================================================================
// CONVENIENCE HELPERS FOR SPECIFIC PROTOCOLS
// =============================================================================

/**
 * Create a checksum engine for STUPA broadcast messages.
 * @param {string} [nodeId] - Node ID for seed derivation
 * @returns {PacketChecksum}
 */
export function createStupaChecksum(nodeId) {
  return new PacketChecksum(PROTOCOL_DOMAIN.STUPA, nodeId);
}

/**
 * Create a checksum engine for NAKPAK onion packets.
 * @param {string} [nodeId] - Node ID for seed derivation
 * @returns {PacketChecksum}
 */
export function createNakpakChecksum(nodeId) {
  return new PacketChecksum(PROTOCOL_DOMAIN.NAKPAK, nodeId);
}

/**
 * Create a checksum engine for KHATA trust messages.
 * @param {string} [nodeId] - Node ID for seed derivation
 * @returns {PacketChecksum}
 */
export function createKhataChecksum(nodeId) {
  return new PacketChecksum(PROTOCOL_DOMAIN.KHATA, nodeId);
}

/**
 * Create a checksum engine for MANTRA gossip messages.
 * @param {string} [nodeId] - Node ID for seed derivation
 * @returns {PacketChecksum}
 */
export function createMantraChecksum(nodeId) {
  return new PacketChecksum(PROTOCOL_DOMAIN.MANTRA, nodeId);
}

// =============================================================================
// MESSAGE WRAPPER - Add checksum to any message
// =============================================================================

/**
 * Wrapper to add YPC-27 checksums to existing message objects.
 * 
 * @example
 * // Wrap a message with checksum
 * const wrapped = wrapWithChecksum(myMessage, PROTOCOL_DOMAIN.STUPA);
 * // => { ...myMessage, ypc27: "YPC27:v1:..." }
 * 
 * // Verify and unwrap
 * const { message, valid } = unwrapWithChecksum(wrapped, PROTOCOL_DOMAIN.STUPA);
 */

/**
 * Add YPC-27 checksum to a message object.
 * @param {Object} message - Original message
 * @param {string} domain - Protocol domain
 * @param {string} [nodeId] - Optional node ID
 * @returns {Object} - Message with ypc27 field added
 */
export function wrapWithChecksum(message, domain, nodeId = null) {
  const engine = new PacketChecksum(domain, nodeId);
  
  // Compute checksum over original message (without ypc27 field)
  const { ypc27: _, ...messageWithoutChecksum } = message;
  const checksum = engine.compute(messageWithoutChecksum);
  
  return {
    ...message,
    ypc27: checksumToWire(checksum),
  };
}

/**
 * Verify and extract a message with YPC-27 checksum.
 * @param {Object} wrappedMessage - Message with ypc27 field
 * @param {string} domain - Protocol domain
 * @param {string} [nodeId] - Optional node ID
 * @returns {{ message: Object, valid: boolean, error?: string }}
 */
export function unwrapWithChecksum(wrappedMessage, domain, nodeId = null) {
  if (!wrappedMessage || !wrappedMessage.ypc27) {
    return { message: wrappedMessage, valid: false, error: 'Missing ypc27 checksum' };
  }

  try {
    const engine = new PacketChecksum(domain, nodeId);
    const expectedChecksum = checksumFromWire(wrappedMessage.ypc27);
    
    // Extract message without checksum for verification
    const { ypc27: _, ...message } = wrappedMessage;
    
    const valid = engine.verify(message, expectedChecksum);
    
    return {
      message,
      valid,
      error: valid ? undefined : 'Checksum mismatch - packet may be corrupted or tampered',
    };
  } catch (err) {
    return { message: wrappedMessage, valid: false, error: err.message };
  }
}

// =============================================================================
// BATCH CHECKSUM VERIFICATION ENGINE
// =============================================================================

// =============================================================================
// NPU BATCH ACCELERATION — YakOS MKC bridge (localhost:9995)
// =============================================================================
//
// When a YakOS node with a Hawk Point NPU is present, YPC-27 batch
// verification dispatches to MLIR_AIE_YPC on the fused xclbin — 16 AIE2
// tiles compute hashToField·seed in F_3^27 with zero host math. Verified
// bit-exact vs YPC27Checksum on this codebase (same hashToField, same
// field multiply, same F_3 trit encoding).
//
// This path is STRICTLY OPTIONAL: any failure (bridge down, HTTP error,
// digest mismatch on the first-use self-check) falls back to the pure-JS
// path in flush(). The NPU is never trusted blindly — the first batch
// recomputes one item in JS and compares trits before marking the
// device path usable.

const NPU_URL = process.env.YAKOS_PQ_BRIDGE_URL || 'http://127.0.0.1:9995';
let _npuAvailable = null;   // tri-state: unknown | true | false
let _npuCheckedAt = 0;
let _npuTrusted = false;    // set after the first self-checked batch

async function npuBridgeUp() {
  if (_npuAvailable !== null && Date.now() - _npuCheckedAt < 30000) {
    return _npuAvailable;
  }
  try {
    const r = await fetch(`${NPU_URL}/health`,
      { signal: AbortSignal.timeout(1500) });
    _npuAvailable = r.ok;
  } catch {
    _npuAvailable = false;
  }
  _npuCheckedAt = Date.now();
  return _npuAvailable;
}

/** Decode 'YPC27:v2:<b64>' → 27 trits in F_3 {0,1,2} (5 trits/byte). */
function decodeV2Digest(wire) {
  const raw = Buffer.from(wire.split(':')[2], 'base64');
  const trits = [];
  for (const byte of raw) {
    let v = byte;
    for (let k = 0; k < 5; k++) {
      trits.push(v % 3);
      v = Math.floor(v / 3);
    }
  }
  return trits.slice(0, 27);
}

/**
 * One /ypc27/digest call for a batch of messages.
 * @param {Buffer[]} messages — domain||data per item
 * @param {number[][]} seeds — 27 F_3 trits per item
 * @returns {Promise<{trits: number[][], device: string}>}
 */
async function npuYpc27Batch(messages, seeds) {
  const r = await fetch(`${NPU_URL}/ypc27/digest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: messages.map(m => m.toString('base64')),
      seeds,
    }),
    signal: AbortSignal.timeout(30000),
  });
  if (!r.ok) throw new Error(`ypc27/digest HTTP ${r.status}`);
  const j = await r.json();
  if (!j.digests || j.digests.length !== messages.length) {
    throw new Error('ypc27/digest: malformed response');
  }
  return {
    trits: j.digests.map(decodeV2Digest),
    device: j.device || 'unknown',
  };
}


/**
 * BatchChecksumVerifier — Batched YPC-27 verification for high-throughput
 * packet processing. Collects individual verify requests and processes them
 * in a single flush, suitable for routing through the ComputeScheduler.
 * 
 * Why batch?
 * - YPC-27 verification involves Poly27 cyclic convolution (O(N²) per check)
 * - Batching amortizes JS object creation overhead
 * - The batch can be routed to GPU via ComputeScheduler for parallel execution
 * - Under load, 50-100 packets/cycle is typical — perfect batch size
 * 
 * Usage patterns:
 * 
 * 1. Direct (no scheduler):
 *    const verifier = new BatchChecksumVerifier();
 *    const p1 = verifier.enqueue(data1, checksum1, PROTOCOL_DOMAIN.STUPA);
 *    const p2 = verifier.enqueue(data2, checksum2, PROTOCOL_DOMAIN.NAKPAK);
 *    // Auto-flushes after threshold or timer
 * 
 * 2. Via ComputeScheduler (recommended for production):
 *    const result = await scheduler.submit({
 *      type: 'ypc27-batch-verify',
 *      priority: Priority.HIGH,
 *      affinity: Affinity.GPU_PREFERRED,
 *      executors: {
 *        gpu: () => verifier.flush(),
 *        cpu: () => verifier.flush(),
 *      }
 *    });
 */
export class BatchChecksumVerifier {
  /**
   * @param {Object} [options]
   * @param {number} [options.minBatchSize=8] — Minimum items before auto-flush
   * @param {number} [options.maxBatchSize=128] — Maximum items per flush
   * @param {number} [options.flushInterval=5] — Ms before timer-triggered flush
   * @param {boolean} [options.useSST=false] — Use YPC27_SST enhanced checksums
   */
  constructor(options = {}) {
    this.minBatchSize = options.minBatchSize ?? 8;
    this.maxBatchSize = options.maxBatchSize ?? 128;
    this.flushInterval = options.flushInterval ?? 5;
    this.useSST = options.useSST ?? false;
    
    /** @type {Array<{data: Buffer, checksum: Poly27, domain: string, nodeId: string|null, resolve: Function, reject: Function}>} */
    this._queue = [];
    this._timer = null;
    
    // Telemetry
    this._stats = {
      totalEnqueued: 0,
      totalFlushed: 0,
      totalValid: 0,
      totalInvalid: 0,
      totalErrors: 0,
      batchCount: 0,
      avgBatchSize: 0,
      lastFlushMs: 0,
    };
  }

  /**
   * Enqueue a checksum verification.
   * Returns a promise that resolves with { valid: boolean, index: number }.
   * 
   * @param {Object|string|Buffer|Uint8Array} data — Packet data to verify
   * @param {Poly27|string} checksum — Expected checksum (Poly27 or wire format)
   * @param {string} domain — Protocol domain from PROTOCOL_DOMAIN
   * @param {string} [nodeId] — Optional node ID for seed derivation
   * @returns {Promise<{valid: boolean, index: number}>}
   */
  enqueue(data, checksum, domain, nodeId = null) {
    return new Promise((resolve, reject) => {
      const parsedChecksum = typeof checksum === 'string' 
        ? checksumFromWire(checksum)
        : checksum;
      
      this._queue.push({
        data,
        checksum: parsedChecksum,
        domain,
        nodeId,
        resolve,
        reject,
      });
      
      this._stats.totalEnqueued++;
      
      if (this._queue.length >= this.minBatchSize) {
        this._flushMaybeNpu();
      } else if (!this._timer) {
        this._timer = setTimeout(() => this._flushMaybeNpu(), this.flushInterval);
      }
    });
  }

  /**
   * Process all queued verifications in a single batch.
   * This is the method to pass as an executor to ComputeScheduler.
   * 
   * The batch verification leverages:
   * - Shared seed derivation (reuse for same domain+nodeId pairs)
   * - Pre-allocated typed arrays for trit conversion
   * - Sequential Poly27 operations (GPU-parallelizable in future)
   * 
   * @returns {{ verified: number, valid: number, invalid: number, errors: number, durationMs: number }}
   */
  flush() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    
    if (this._queue.length === 0) {
      return { verified: 0, valid: 0, invalid: 0, errors: 0, durationMs: 0 };
    }
    
    const batch = this._queue.splice(0, this.maxBatchSize);
    const t0 = performance.now();
    
    // Cache engines by domain+nodeId to avoid redundant seed derivation
    const engineCache = new Map();
    
    let valid = 0;
    let invalid = 0;
    let errors = 0;
    
    for (let i = 0; i < batch.length; i++) {
      const item = batch[i];
      try {
        const cacheKey = `${item.domain}:${item.nodeId || ''}`;
        
        if (!engineCache.has(cacheKey)) {
          engineCache.set(cacheKey, new PacketChecksum(item.domain, item.nodeId));
        }
        
        const engine = engineCache.get(cacheKey);
        const isValid = engine.verify(item.data, item.checksum);
        
        if (isValid) {
          valid++;
          this._stats.totalValid++;
        } else {
          invalid++;
          this._stats.totalInvalid++;
        }
        
        item.resolve({ valid: isValid, index: i });
      } catch (err) {
        errors++;
        this._stats.totalErrors++;
        item.reject(err);
      }
    }
    
    const durationMs = performance.now() - t0;
    
    // Update telemetry
    this._stats.totalFlushed += batch.length;
    this._stats.batchCount++;
    this._stats.avgBatchSize = this._stats.totalFlushed / this._stats.batchCount;
    this._stats.lastFlushMs = durationMs;
    this._stats.lastDevice = 'cpu';
    
    return { verified: batch.length, valid, invalid, errors, durationMs };
  }

  /**
   * Internal flush dispatcher — tries the NPU path first when the YakOS
   * bridge is reachable, falls through to the sync JS path on any failure.
   * Fire-and-forget: queue items resolve/reject inside whichever path runs.
   */
  _flushMaybeNpu() {
    this.flushNpu().catch(err => {
      log.debug(`NPU flush failed, JS fallback: ${err.message}`);
      try { this.flush(); } catch (e2) {
        log.error(`JS flush also failed: ${e2.message}`);
      }
    });
  }

  /**
   * NPU batch flush — one /ypc27/digest call for the whole batch.
   * 16 AIE2 tiles compute hashToField·seed in F_3^27; the first batch
   * re-verifies one item in JS before trusting the device path.
   * Falls back to flush() when the bridge is absent or misbehaving.
   * 
   * @returns {Promise<{verified: number, valid: number, invalid: number, errors: number, durationMs: number, device: string}>}
   */
  async flushNpu() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    
    if (this._queue.length === 0) {
      return { verified: 0, valid: 0, invalid: 0, errors: 0, durationMs: 0, device: 'none' };
    }
    
    if (!(await npuBridgeUp())) {
      return { ...this.flush(), device: 'cpu' };
    }
    
    const batch = this._queue.splice(0, this.maxBatchSize);
    const t0 = performance.now();
    
    try {
      // Per-item engine cache (domain+nodeId → PacketChecksum) — needed for
      // seed trits AND the JS self-check / per-item normalization.
      const engineCache = new Map();
      const engineFor = (item) => {
        const key = `${item.domain}:${item.nodeId || ''}`;
        if (!engineCache.has(key)) {
          engineCache.set(key, new PacketChecksum(item.domain, item.nodeId));
        }
        return engineCache.get(key);
      };
      
      const messages = batch.map(it => engineFor(it).bytesFor(it.data));
      const seeds = batch.map(it => engineFor(it).seedTrits);
      
      const { trits, device } = await npuYpc27Batch(messages, seeds);
      
      // First-use self-check: recompute item 0 in JS and compare trits.
      // A misbehaving bridge is never trusted — one bad digest drops the
      // whole device path back to JS for this batch (and stays untrusted).
      if (!_npuTrusted) {
        const ref = engineFor(batch[0]).compute(batch[0].data);
        const refTrits = [...ref.toTypedArray()];
        if (JSON.stringify(refTrits) !== JSON.stringify(trits[0])) {
          throw new Error('NPU digest self-check failed — staying on CPU');
        }
        _npuTrusted = true;
      }
      
      let valid = 0, invalid = 0, errors = 0;
      for (let i = 0; i < batch.length; i++) {
        const item = batch[i];
        try {
          const isValid = new Poly27(trits[i]).equals(item.checksum);
          if (isValid) {
            valid++;
            this._stats.totalValid++;
          } else {
            invalid++;
            this._stats.totalInvalid++;
          }
          item.resolve({ valid: isValid, index: i });
        } catch (err) {
          errors++;
          this._stats.totalErrors++;
          item.reject(err);
        }
      }
      
      const durationMs = performance.now() - t0;
      this._stats.totalFlushed += batch.length;
      this._stats.batchCount++;
      this._stats.avgBatchSize = this._stats.totalFlushed / this._stats.batchCount;
      this._stats.lastFlushMs = durationMs;
      this._stats.lastDevice = device;
      this._stats.npuBatches = (this._stats.npuBatches || 0) + 1;
      
      return { verified: batch.length, valid, invalid, errors, durationMs, device };
    } catch (err) {
      // Put the batch back and let the caller's catch run the JS flush.
      this._queue.unshift(...batch);
      throw err;
    }
  }

  /**
   * Get verification statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      ...this._stats,
      queueDepth: this._queue.length,
      avgBatchSize: +this._stats.avgBatchSize.toFixed(1),
      lastFlushMs: +this._stats.lastFlushMs.toFixed(2),
    };
  }

  /**
   * Drain queue and release timer.
   */
  destroy() {
    this.flush();
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }
}

/** Singleton batch verifier for packet checksums */
export const batchChecksumVerifier = new BatchChecksumVerifier();

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  PROTOCOL_DOMAIN,
  CHECKSUM_PREFIX,
  checksumToWire,
  checksumFromWire,
  PacketChecksum,
  createStupaChecksum,
  createNakpakChecksum,
  createKhataChecksum,
  createMantraChecksum,
  wrapWithChecksum,
  unwrapWithChecksum,
  BatchChecksumVerifier,
  batchChecksumVerifier,
};
