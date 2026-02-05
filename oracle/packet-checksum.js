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
};
