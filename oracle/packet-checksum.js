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
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { YPC27Checksum, ypc27, bytesToTrits, tritsToBytes, seedFromPeerId, Poly27 } from './ypc27.js';
import { YPC27_SST } from './ypc27.js';

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
        this.flush();
      } else if (!this._timer) {
        this._timer = setTimeout(() => this.flush(), this.flushInterval);
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
    
    return { verified: batch.length, valid, invalid, errors, durationMs };
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
