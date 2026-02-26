/**
 * Yakmesh Temporal Code Signing
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PHILOSOPHY: SIGNATURES THAT BREATHE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Traditional code signing: Sign once, valid forever (until key compromise).
 * Temporal signatures: Bound to GPS time, auto-expire, require re-attestation.
 * 
 * This creates a "living signature" that:
 * - Proves code was signed at a specific GPS time (±10ms precision)
 * - Automatically expires after a configurable period (default: 30 days)
 * - Forces regular re-attestation of releases
 * - Makes stolen/leaked signatures useless after expiry
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SIGNATURE STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * {
 *   version: 1,
 *   codeHash: SHA3-256 of the code/bundle,
 *   signerPubKey: ML-DSA-65 public key,
 *   signedAt: GPS timestamp (ms since epoch),
 *   expiresAt: signedAt + validity period,
 *   networkId: Network ID for cross-network prevention,
 *   signature: ML-DSA-65 signature over all above fields
 * }
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * VERIFICATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * 1. Check signature validity (ML-DSA-65 verify)
 * 2. Check current GPS time < expiresAt
 * 3. Check signedAt is in the past (prevent future-dated signatures)
 * 4. Check networkId matches current network
 * 5. Check signerPubKey is in trusted signers list
 * 
 * @module security/temporal-signing
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { EventEmitter } from 'events';

const log = createLogger('security:temporal-signing');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Signature version */
const SIGNATURE_VERSION = 1;

/** Default validity period (30 days in ms) */
const DEFAULT_VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;

/** Minimum validity period (1 hour) */
const MIN_VALIDITY_MS = 60 * 60 * 1000;

/** Maximum clock skew tolerance (10 seconds) */
const MAX_CLOCK_SKEW_MS = 10000;

/** Grace period after expiry (allows time for re-signing) */
const EXPIRY_GRACE_MS = 24 * 60 * 60 * 1000; // 1 day

// =============================================================================
// TEMPORAL SIGNATURE
// =============================================================================

/**
 * TemporalSignature — A time-bound code signature
 */
export class TemporalSignature {
  version;
  codeHash;
  signerPubKey;
  signedAt;
  expiresAt;
  networkId;
  signature;

  /**
   * @param {object} data - Signature data
   */
  constructor(data) {
    this.version = data.version || SIGNATURE_VERSION;
    this.codeHash = data.codeHash;
    this.signerPubKey = data.signerPubKey;
    this.signedAt = data.signedAt;
    this.expiresAt = data.expiresAt;
    this.networkId = data.networkId;
    this.signature = data.signature || null;

    Object.seal(this);
  }

  /**
   * Get the signable payload (all fields except signature)
   * @returns {Uint8Array}
   */
  getSignablePayload() {
    const payload = JSON.stringify({
      version: this.version,
      codeHash: this.codeHash,
      signerPubKey: this.signerPubKey,
      signedAt: this.signedAt,
      expiresAt: this.expiresAt,
      networkId: this.networkId,
    });
    return new TextEncoder().encode(payload);
  }

  /**
   * Check if signature has expired
   * @param {number} currentTime - Current GPS time in ms
   * @param {boolean} useGrace - Whether to use grace period
   * @returns {boolean}
   */
  isExpired(currentTime, useGrace = false) {
    const effectiveExpiry = useGrace
      ? this.expiresAt + EXPIRY_GRACE_MS
      : this.expiresAt;
    return currentTime > effectiveExpiry;
  }

  /**
   * Get remaining validity time
   * @param {number} currentTime - Current GPS time in ms
   * @returns {number} Remaining ms (negative if expired)
   */
  getRemainingValidity(currentTime) {
    return this.expiresAt - currentTime;
  }

  /**
   * Get human-readable expiry info
   * @param {number} currentTime - Current GPS time in ms
   * @returns {string}
   */
  getExpiryInfo(currentTime) {
    const remaining = this.getRemainingValidity(currentTime);
    if (remaining < 0) {
      const expired = Math.abs(remaining);
      const days = Math.floor(expired / (24 * 60 * 60 * 1000));
      return `Expired ${days} days ago`;
    }
    const days = Math.floor(remaining / (24 * 60 * 60 * 1000));
    const hours = Math.floor((remaining % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
    return `Valid for ${days}d ${hours}h`;
  }

  /**
   * Serialize to JSON
   * @returns {object}
   */
  toJSON() {
    return {
      version: this.version,
      codeHash: this.codeHash,
      signerPubKey: this.signerPubKey,
      signedAt: this.signedAt,
      expiresAt: this.expiresAt,
      networkId: this.networkId,
      signature: this.signature,
    };
  }

  /**
   * Create from JSON
   * @param {object|string} json
   * @returns {TemporalSignature}
   */
  static fromJSON(json) {
    const data = typeof json === 'string' ? JSON.parse(json) : json;
    return new TemporalSignature(data);
  }
}

// =============================================================================
// TEMPORAL SIGNER
// =============================================================================

/**
 * TemporalSigner — Creates and verifies temporal signatures
 */
export class TemporalSigner extends EventEmitter {
  #timeSource;
  #networkId;
  #trustedSigners;
  #signatureCache;

  /**
   * @param {object} options
   * @param {object} options.timeSource - GPS time source
   * @param {string} options.networkId - Current network ID
   */
  constructor({ timeSource = null, networkId = 'unknown' } = {}) {
    super();
    this.#timeSource = timeSource;
    this.#networkId = networkId;
    this.#trustedSigners = new Set();
    this.#signatureCache = new Map();

    Object.seal(this);
  }

  /**
   * Bind a GPS time source
   * @param {object} timeSource
   */
  bindTimeSource(timeSource) {
    this.#timeSource = timeSource;
    const sourceType = timeSource?.getStatus?.()?.primarySource ||
      timeSource?.getSourceType?.() ||
      'unknown';
    log.info('Temporal signer bound to time source', { type: sourceType });
  }

  /**
   * Set the network ID
   * @param {string} networkId
   */
  setNetworkId(networkId) {
    this.#networkId = networkId;
  }

  /**
   * Add a trusted signer public key
   * @param {string} pubKeyHex
   */
  addTrustedSigner(pubKeyHex) {
    this.#trustedSigners.add(pubKeyHex);
    log.info('Added trusted signer', { pubKey: pubKeyHex.slice(0, 32) + '...' });
  }

  /**
   * Remove a trusted signer
   * @param {string} pubKeyHex
   */
  removeTrustedSigner(pubKeyHex) {
    this.#trustedSigners.delete(pubKeyHex);
    log.info('Removed trusted signer', { pubKey: pubKeyHex.slice(0, 32) + '...' });
  }

  /**
   * Get current GPS time
   * @returns {number}
   */
  #getCurrentTime() {
    if (this.#timeSource?.getGPSTime) {
      return this.#timeSource.getGPSTime();
    }
    // Fallback to system time (less secure)
    return Date.now();
  }

  /**
   * Sign code with a temporal signature
   * @param {Uint8Array|string} code - Code content to sign
   * @param {string} secretKeyHex - Signer's secret key
   * @param {string} pubKeyHex - Signer's public key
   * @param {number} validityMs - Validity period in ms
   * @returns {TemporalSignature}
   */
  sign(code, secretKeyHex, pubKeyHex, validityMs = DEFAULT_VALIDITY_MS) {
    // Ensure minimum validity
    if (validityMs < MIN_VALIDITY_MS) {
      validityMs = MIN_VALIDITY_MS;
    }

    // Hash the code
    const codeBytes = typeof code === 'string'
      ? new TextEncoder().encode(code)
      : code;
    const codeHash = bytesToHex(sha3_256(codeBytes));

    // Get GPS time
    const signedAt = this.#getCurrentTime();
    const expiresAt = signedAt + validityMs;

    // Create signature object
    const sig = new TemporalSignature({
      version: SIGNATURE_VERSION,
      codeHash,
      signerPubKey: pubKeyHex,
      signedAt,
      expiresAt,
      networkId: this.#networkId,
    });

    // Sign the payload
    const payload = sig.getSignablePayload();
    const secretKey = hexToBytes(secretKeyHex);
    const signature = mlDsa65Sign(payload, secretKey);
    sig.signature = bytesToHex(signature);

    log.info('Created temporal signature', {
      codeHash: codeHash.slice(0, 16) + '...',
      expiresIn: sig.getExpiryInfo(signedAt),
      networkId: this.#networkId,
    });

    return sig;
  }

  /**
   * Verify a temporal signature
   * @param {Uint8Array|string} code - Code content to verify
   * @param {TemporalSignature|object} sig - Signature to verify
   * @returns {{ valid: boolean, error?: string, warnings?: string[] }}
   */
  verify(code, sig) {
    const signature = sig instanceof TemporalSignature
      ? sig
      : TemporalSignature.fromJSON(sig);

    const warnings = [];
    const currentTime = this.#getCurrentTime();

    // 1. Check version
    if (signature.version !== SIGNATURE_VERSION) {
      return { valid: false, error: `Unknown signature version: ${signature.version}` };
    }

    // 2. Check network ID
    if (signature.networkId !== this.#networkId) {
      return {
        valid: false,
        error: `Network mismatch: expected ${this.#networkId}, got ${signature.networkId}`,
      };
    }

    // 3. Check trusted signer
    if (!this.#trustedSigners.has(signature.signerPubKey)) {
      return {
        valid: false,
        error: 'Signer not in trusted signers list',
      };
    }

    // 4. Check signedAt is not in the future (with skew tolerance)
    if (signature.signedAt > currentTime + MAX_CLOCK_SKEW_MS) {
      return {
        valid: false,
        error: `Signature is from the future: signed at ${new Date(signature.signedAt).toISOString()}`,
      };
    }

    // 5. Check expiry
    if (signature.isExpired(currentTime)) {
      // Check if within grace period
      if (!signature.isExpired(currentTime, true)) {
        warnings.push('Signature expired but within grace period');
      } else {
        return {
          valid: false,
          error: `Signature expired: ${signature.getExpiryInfo(currentTime)}`,
        };
      }
    }

    // 6. Check code hash
    const codeBytes = typeof code === 'string'
      ? new TextEncoder().encode(code)
      : code;
    const computedHash = bytesToHex(sha3_256(codeBytes));

    if (computedHash !== signature.codeHash) {
      return {
        valid: false,
        error: 'Code hash mismatch - code has been modified',
      };
    }

    // 7. Verify cryptographic signature
    try {
      const payload = signature.getSignablePayload();
      const sigBytes = hexToBytes(signature.signature);
      const pubKey = hexToBytes(signature.signerPubKey);

      const valid = mlDsa65Verify(sigBytes, payload, pubKey);

      if (!valid) {
        return { valid: false, error: 'Cryptographic signature verification failed' };
      }
    } catch (e) {
      return { valid: false, error: `Signature verification error: ${e.message}` };
    }

    // Add remaining validity warning if < 7 days
    const remaining = signature.getRemainingValidity(currentTime);
    if (remaining < 7 * 24 * 60 * 60 * 1000) {
      const days = Math.floor(remaining / (24 * 60 * 60 * 1000));
      warnings.push(`Signature expires in ${days} days - consider re-signing`);
    }

    return {
      valid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
      expiryInfo: signature.getExpiryInfo(currentTime),
    };
  }

  /**
   * Sign a release bundle
   * @param {string} bundlePath - Path to the release bundle
   * @param {string} secretKeyHex - Signer's secret key
   * @param {string} pubKeyHex - Signer's public key
   * @param {number} validityMs - Validity period
   * @returns {TemporalSignature}
   */
  signFile(bundlePath, secretKeyHex, pubKeyHex, validityMs = DEFAULT_VALIDITY_MS) {
    const code = readFileSync(bundlePath);
    return this.sign(code, secretKeyHex, pubKeyHex, validityMs);
  }

  /**
   * Verify a release bundle
   * @param {string} bundlePath - Path to the release bundle
   * @param {TemporalSignature|object} sig - Signature to verify
   * @returns {{ valid: boolean, error?: string, warnings?: string[] }}
   */
  verifyFile(bundlePath, sig) {
    const code = readFileSync(bundlePath);
    return this.verify(code, sig);
  }

  /**
   * Save signature to file
   * @param {TemporalSignature} sig
   * @param {string} path
   */
  saveSignature(sig, path) {
    writeFileSync(path, JSON.stringify(sig.toJSON(), null, 2));
    log.info('Saved signature to file', { path });
  }

  /**
   * Load signature from file
   * @param {string} path
   * @returns {TemporalSignature}
   */
  loadSignature(path) {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return TemporalSignature.fromJSON(data);
  }

  /**
   * Get status
   */
  getStatus() {
    const sourceStatus = this.#timeSource?.getStatus?.();
    return {
      timeSourceBound: !!this.#timeSource,
      timeSourceType: sourceStatus?.primarySource || 'none',
      networkId: this.#networkId,
      trustedSigners: this.#trustedSigners.size,
      currentTime: this.#getCurrentTime(),
    };
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let _instance = null;

/**
 * Get the TemporalSigner singleton
 * @param {object} options
 * @returns {TemporalSigner}
 */
export function getTemporalSigner(options) {
  if (!_instance) {
    _instance = new TemporalSigner(options);
  }
  return _instance;
}

export default TemporalSigner;
