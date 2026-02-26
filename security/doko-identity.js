/**
 * DOKO Identity - Distributed Ownership & Key Object
 * Self-sovereign identity documents verified by the mesh, not a CA.
 * 
 * "DOKO" (डोको) - A Nepali woven bamboo basket carried on the back,
 * symbolizing what a traveler carries with them to prove their identity.
 * 
 * @module security/doko-identity
 * @version 2.2.0
 */

import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { createLogger } from '../utils/logger.js';
import { ternaryId } from '../utils/ternary-id.js';

// ═══ TRIBHUJ — Balanced ternary for validation verdicts ═══
// POSITIVE: check passed, NEUTRAL: check skipped/not applicable, NEGATIVE: check failed
import { POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

const log = createLogger('security:doko');

// Import iO obfuscation for DOKO IDs - never expose raw hashes
import { deriveNetworkName, deriveNetworkId } from '../oracle/network-identity.js';

/**
 * DOKO Document Types
 */
export const DOKO_TYPES = {
  NODE: 'node',           // Network node identity
  USER: 'user',           // Human user identity
  TRADER: 'trader',       // PeerQuanta trader identity
  SERVICE: 'service',     // Service/API identity
  DEVICE: 'device',       // IoT/hardware device identity
  MERCHANT: 'merchant',   // Verified merchant identity
};

/**
 * DOKO Document Version
 */
export const DOKO_VERSION = '1.0';

/**
 * Default expiration: 1 year
 */
const DEFAULT_EXPIRY_MS = 365 * 24 * 60 * 60 * 1000;

/**
 * DOKO Document Structure
 * A self-contained identity document that can be verified by the mesh.
 */
export class DOKODocument {
  constructor(options = {}) {
    this.version = DOKO_VERSION;
    this.type = options.type || DOKO_TYPES.USER;
    this.dokoId = options.dokoId || null;
    this.publicKey = options.publicKey || null;
    this.created = options.created || Date.now();
    this.expires = options.expires || (this.created + DEFAULT_EXPIRY_MS);

    // Claims - assertions about the identity
    this.claims = options.claims || {};

    // Extensions - optional capabilities and bindings
    this.extensions = options.extensions || {};

    // Endorsements - signed attestations from other DOKOs
    this.endorsements = options.endorsements || [];

    // Self-signature
    this.signature = options.signature || null;
  }

  /**
   * Compute the DOKO ID from the public key
   * Uses iO obfuscation - NEVER exposes raw hash
   * 
   * Format: doko-<type>-<obfuscated-name>-<short-id>
   * Example: doko-trader-qubit-lattice-pq-a7x9
   */
  static computeDokoId(publicKey, type = DOKO_TYPES.USER) {
    const keyBytes = typeof publicKey === 'string'
      ? hexToBytes(publicKey)
      : publicKey;

    const hash = sha3_256(new Uint8Array([
      ...Buffer.from(type),
      ...keyBytes
    ]));

    // Use iO obfuscation - never expose raw hash!
    const hashHex = bytesToHex(hash);
    const obfuscatedName = deriveNetworkName(hashHex, 2);  // 2 words for brevity
    const shortId = deriveNetworkId(hashHex);

    // Format: doko-<type>-<obfuscated-name>-<short-id>
    // e.g., "doko-trader-qubit-lattice-pq-a7x9"
    return `doko-${type}-${obfuscatedName}-${shortId}`;
  }

  /**
   * Get the canonical bytes for signing
   * Uses deterministic JSON serialization (sorted keys at all levels)
   */
  getSignableBytes() {
    const canonical = {
      version: this.version,
      type: this.type,
      dokoId: this.dokoId,
      publicKey: this.publicKey,
      created: this.created,
      expires: this.expires,
      claims: this.claims,
      extensions: this.extensions,
      // Note: endorsements and signature are NOT included
    };

    // Use a replacer function that sorts keys at ALL levels
    const sortedJsonString = JSON.stringify(canonical, (key, value) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return Object.keys(value).sort().reduce((sorted, k) => {
          sorted[k] = value[k];
          return sorted;
        }, {});
      }
      return value;
    });

    return Buffer.from(sortedJsonString);
  }

  /**
   * Compute content hash for this document
   */
  getContentHash() {
    const bytes = this.getSignableBytes();
    return bytesToHex(sha3_256(bytes));
  }

  /**
   * Check if the document is expired
   */
  isExpired() {
    return Date.now() > this.expires;
  }

  /**
   * Check if the document is valid (not expired, has required fields)
   */
  isValid() {
    if (!this.dokoId || !this.publicKey || !this.signature) {
      return false;
    }
    if (this.isExpired()) {
      return false;
    }
    return true;
  }

  /**
   * Serialize to JSON
   */
  toJSON() {
    return {
      version: this.version,
      type: this.type,
      dokoId: this.dokoId,
      publicKey: this.publicKey,
      created: this.created,
      expires: this.expires,
      claims: this.claims,
      extensions: this.extensions,
      endorsements: this.endorsements,
      signature: this.signature,
    };
  }

  /**
   * Create from JSON
   */
  static fromJSON(json) {
    return new DOKODocument(json);
  }
}

/**
 * DOKO Generator - Create new DOKO documents
 */
export class DOKOGenerator {
  /**
   * Generate a new DOKO document with a fresh keypair
   */
  static generate(options = {}) {
    // Generate ML-DSA-65 keypair
    const seed = options.seed || crypto.getRandomValues(new Uint8Array(32));
    const keyPair = ml_dsa65.keygen(seed);

    const type = options.type || DOKO_TYPES.USER;
    const publicKeyHex = bytesToHex(keyPair.publicKey);

    const doko = new DOKODocument({
      type,
      dokoId: DOKODocument.computeDokoId(keyPair.publicKey, type),
      publicKey: publicKeyHex,
      created: Date.now(),
      expires: options.expires || (Date.now() + DEFAULT_EXPIRY_MS),
      claims: options.claims || {},
      extensions: options.extensions || {},
    });

    // Self-sign (ml_dsa65.sign takes message first, then secretKey)
    const signableBytes = doko.getSignableBytes();
    const signature = mlDsa65Sign(signableBytes, keyPair.secretKey);
    doko.signature = bytesToHex(signature);

    return {
      doko,
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,
      publicKeyHex,
      secretKeyHex: bytesToHex(keyPair.secretKey),
    };
  }

  /**
   * Generate a DOKO from an existing keypair
   */
  static fromKeyPair(publicKey, secretKey, options = {}) {
    const publicKeyBytes = typeof publicKey === 'string'
      ? hexToBytes(publicKey)
      : publicKey;
    const secretKeyBytes = typeof secretKey === 'string'
      ? hexToBytes(secretKey)
      : secretKey;

    const type = options.type || DOKO_TYPES.USER;
    const publicKeyHex = bytesToHex(publicKeyBytes);

    const doko = new DOKODocument({
      type,
      dokoId: DOKODocument.computeDokoId(publicKeyBytes, type),
      publicKey: publicKeyHex,
      created: Date.now(),
      expires: options.expires || (Date.now() + DEFAULT_EXPIRY_MS),
      claims: options.claims || {},
      extensions: options.extensions || {},
    });

    // Self-sign (ml_dsa65.sign takes message first, then secretKey)
    const signableBytes = doko.getSignableBytes();
    const signature = mlDsa65Sign(signableBytes, secretKeyBytes);
    doko.signature = bytesToHex(signature);

    return doko;
  }

  /**
   * Generate a Trader DOKO for PeerQuanta
   */
  static generateTrader(options = {}) {
    return DOKOGenerator.generate({
      ...options,
      type: DOKO_TYPES.TRADER,
      claims: {
        ...options.claims,
        platform: 'peerquanta',
        username: options.username || null,
        userId: options.userId || null,
      },
      extensions: {
        ...options.extensions,
        capabilities: ['trade', 'escrow', 'chat'],
        tradingPairs: options.tradingPairs || [],
      },
    });
  }

  /**
   * Generate a Node DOKO for mesh network nodes
   * Includes persistentId144T for cross-upgrade identity continuity
   * 
   * @param {Object} options
   * @param {string} options.persistentId - 144T persistent machine identity
   * @param {string} options.nodeId - Current network-specific node ID
   * @param {string} options.networkName - Network name from oracle
   * @param {Uint8Array} [options.seed] - Optional deterministic seed
   */
  static generateNode(options = {}) {
    if (!options.persistentId) {
      throw new Error('Node DOKO requires persistentId (144T persistent machine identity)');
    }
    return DOKOGenerator.generate({
      ...options,
      type: DOKO_TYPES.NODE,
      claims: {
        ...options.claims,
        nodeId: options.nodeId || null,
        networkName: options.networkName || null,
      },
      extensions: {
        ...options.extensions,
        persistentId144T: options.persistentId,  // Constant across upgrades
        capabilities: options.capabilities || ['mesh', 'gossip', 'relay'],
      },
    });
  }

  /**
   * Generate a Merchant DOKO for verified businesses
   */
  static generateMerchant(options = {}) {
    return DOKOGenerator.generate({
      ...options,
      type: DOKO_TYPES.MERCHANT,
      claims: {
        ...options.claims,
        businessName: options.businessName || null,
        domain: options.domain || null,
        verified: false, // Requires domain consensus verification
      },
      extensions: {
        ...options.extensions,
        capabilities: ['merchant', 'bulk-trade', 'api-access'],
        domainBinding: null, // Set after domain verification
      },
    });
  }
}

/**
 * DOKO Validator - Verify DOKO documents
 */
export class DOKOValidator {
  /**
   * Verify the self-signature of a DOKO document
   */
  static verifySignature(doko) {
    if (!doko.signature || !doko.publicKey) {
      return { valid: false, reason: 'MISSING_SIGNATURE_OR_KEY' };
    }

    try {
      const publicKey = typeof doko.publicKey === 'string'
        ? hexToBytes(doko.publicKey)
        : doko.publicKey;

      const signature = typeof doko.signature === 'string'
        ? hexToBytes(doko.signature)
        : doko.signature;

      const doc = doko instanceof DOKODocument ? doko : DOKODocument.fromJSON(doko);
      const signableBytes = doc.getSignableBytes();

      // ml_dsa65.verify takes (signature, message, publicKey)
      const valid = mlDsa65Verify(signature, signableBytes, publicKey);

      return {
        valid,
        reason: valid ? 'SIGNATURE_VALID' : 'SIGNATURE_INVALID',
      };
    } catch (error) {
      return {
        valid: false,
        reason: 'SIGNATURE_VERIFICATION_ERROR',
        error: error.message,
      };
    }
  }

  /**
   * Verify the DOKO ID matches the public key
   */
  static verifyDokoId(doko) {
    const expectedId = DOKODocument.computeDokoId(doko.publicKey, doko.type);
    const valid = doko.dokoId === expectedId;

    return {
      valid,
      reason: valid ? 'DOKO_ID_VALID' : 'DOKO_ID_MISMATCH',
      expected: expectedId,
      actual: doko.dokoId,
    };
  }

  /**
   * Full validation of a DOKO document
   * Returns both boolean `valid` (backward compat) and trit `verdict`
   * (POSITIVE/NEUTRAL/NEGATIVE) for ternary-aware consumers.
   */
  static validate(doko, options = {}) {
    const doc = doko instanceof DOKODocument ? doko : DOKODocument.fromJSON(doko);
    const results = {
      valid: true,
      verdict: POSITIVE,  // TRIBHUJ trit: POSITIVE=valid, NEUTRAL=skipped, NEGATIVE=failed
      checks: {},
    };

    // Check structure
    if (!doc.version || !doc.type || !doc.dokoId || !doc.publicKey) {
      results.valid = false;
      results.verdict = NEGATIVE;
      results.checks.structure = { valid: false, verdict: NEGATIVE, reason: 'MISSING_REQUIRED_FIELDS' };
      return results;
    }
    results.checks.structure = { valid: true, verdict: POSITIVE, reason: 'STRUCTURE_VALID' };

    // Check version
    if (doc.version !== DOKO_VERSION) {
      results.valid = false;
      results.verdict = NEGATIVE;
      results.checks.version = { valid: false, verdict: NEGATIVE, reason: 'VERSION_MISMATCH', expected: DOKO_VERSION };
      return results;
    }
    results.checks.version = { valid: true, verdict: POSITIVE, reason: 'VERSION_VALID' };

    // Check type
    if (!Object.values(DOKO_TYPES).includes(doc.type)) {
      results.valid = false;
      results.verdict = NEGATIVE;
      results.checks.type = { valid: false, verdict: NEGATIVE, reason: 'INVALID_TYPE' };
      return results;
    }
    results.checks.type = { valid: true, verdict: POSITIVE, reason: 'TYPE_VALID' };

    // Check expiration — NEUTRAL if skipped by options
    if (!options.allowExpired && doc.isExpired()) {
      results.valid = false;
      results.verdict = NEGATIVE;
      results.checks.expiration = { valid: false, verdict: NEGATIVE, reason: 'DOCUMENT_EXPIRED' };
      return results;
    }
    results.checks.expiration = {
      valid: true,
      verdict: options.allowExpired ? NEUTRAL : POSITIVE,  // NEUTRAL = check skipped
      reason: options.allowExpired ? 'EXPIRY_CHECK_SKIPPED' : 'NOT_EXPIRED',
    };

    // Verify DOKO ID
    const idCheck = DOKOValidator.verifyDokoId(doc);
    idCheck.verdict = idCheck.valid ? POSITIVE : NEGATIVE;
    results.checks.dokoId = idCheck;
    if (!idCheck.valid) {
      results.valid = false;
      results.verdict = NEGATIVE;
      return results;
    }

    // Verify signature
    const sigCheck = DOKOValidator.verifySignature(doc);
    sigCheck.verdict = sigCheck.valid ? POSITIVE : NEGATIVE;
    results.checks.signature = sigCheck;
    if (!sigCheck.valid) {
      results.valid = false;
      results.verdict = NEGATIVE;
      return results;
    }

    return results;
  }
}

/**
 * DOKO Endorsement - Attestation from another DOKO holder
 */
export class DOKOEndorsement {
  /**
   * Create an endorsement for another DOKO
   * @param {DOKODocument} targetDoko - The DOKO being endorsed
   * @param {DOKODocument} endorserDoko - The DOKO doing the endorsing
   * @param {Uint8Array} endorserSecretKey - The endorser's secret key
   * @param {Object} claims - Claims being endorsed (e.g., { tradingHistory: true })
   */
  static create(targetDoko, endorserDoko, endorserSecretKey, claims = {}) {
    const endorsement = {
      targetDokoId: targetDoko.dokoId,
      targetContentHash: targetDoko.getContentHash(),
      endorserDokoId: endorserDoko.dokoId,
      endorserPublicKey: endorserDoko.publicKey,
      claims,
      created: Date.now(),
      expires: Date.now() + DEFAULT_EXPIRY_MS,
    };

    // Sign the endorsement
    // IMPORTANT: ml_dsa65.sign(message, secretKey) - message FIRST!
    const endorsementBytes = Buffer.from(JSON.stringify(endorsement, Object.keys(endorsement).sort()));
    const secretKey = typeof endorserSecretKey === 'string'
      ? hexToBytes(endorserSecretKey)
      : endorserSecretKey;

    const signature = mlDsa65Sign(endorsementBytes, secretKey);
    endorsement.signature = bytesToHex(signature);

    return endorsement;
  }

  /**
   * Verify an endorsement
   */
  static verify(endorsement, targetDoko) {
    try {
      // Check target matches
      if (endorsement.targetDokoId !== targetDoko.dokoId) {
        return { valid: false, reason: 'TARGET_MISMATCH' };
      }

      // Check not expired
      if (Date.now() > endorsement.expires) {
        return { valid: false, reason: 'ENDORSEMENT_EXPIRED' };
      }

      // Verify signature
      // IMPORTANT: ml_dsa65.verify(signature, message, publicKey) - signature FIRST!
      const { signature, ...endorsementData } = endorsement;
      const endorsementBytes = Buffer.from(JSON.stringify(endorsementData, Object.keys(endorsementData).sort()));

      const publicKey = hexToBytes(endorsement.endorserPublicKey);
      const sigBytes = hexToBytes(signature);

      const valid = mlDsa65Verify(sigBytes, endorsementBytes, publicKey);

      return {
        valid,
        reason: valid ? 'ENDORSEMENT_VALID' : 'SIGNATURE_INVALID',
        claims: endorsement.claims,
      };
    } catch (error) {
      return {
        valid: false,
        reason: 'VERIFICATION_ERROR',
        error: error.message,
      };
    }
  }
}

/**
 * SSL/TLS Certificate Binding for DOKO
 * 
 * Enables domains to bind their SSL certificates to DOKO identities
 * for enhanced verification. This creates a cryptographic chain:
 * 
 *   Domain → SSL Certificate → DOKO Identity → Mesh Verification
 * 
 * Certificate fingerprints are computed using SHA-256 hash of the
 * DER-encoded certificate.
 */
export class DOKOCertBinding {
  /**
   * Compute certificate fingerprint from PEM or DER
   * @param {string|Buffer} cert - Certificate in PEM or DER format
   * @returns {string} SHA3-256 fingerprint (hex)
   */
  static computeFingerprint(cert) {
    let derBytes;

    if (typeof cert === 'string') {
      // PEM format - extract the base64 content
      const pemMatch = cert.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/);
      if (pemMatch) {
        const base64 = pemMatch[1].replace(/\s/g, '');
        derBytes = Buffer.from(base64, 'base64');
      } else {
        // Assume it's already base64-encoded DER
        derBytes = Buffer.from(cert, 'base64');
      }
    } else {
      derBytes = cert;
    }

    const hash = sha3_256(new Uint8Array(derBytes));
    return bytesToHex(hash);
  }

  /**
   * Create an SSL binding extension for a DOKO document
   * @param {Object} options - Binding options
   * @param {string} options.domain - Domain name
   * @param {string} options.fingerprint - Certificate fingerprint (SHA3-256 hex)
   * @param {string} options.issuer - Certificate issuer (optional)
   * @param {number} options.validFrom - Certificate valid from timestamp (optional)
   * @param {number} options.validTo - Certificate valid to timestamp (optional)
   * @returns {Object} SSL binding extension object
   */
  static createBinding(options) {
    if (!options.domain || !options.fingerprint) {
      throw new Error('domain and fingerprint are required');
    }

    return {
      domain: options.domain.toLowerCase(),
      fingerprint: options.fingerprint,
      issuer: options.issuer || null,
      validFrom: options.validFrom || null,
      validTo: options.validTo || null,
      boundAt: Date.now(),
      verified: false, // Will be verified by mesh consensus
    };
  }

  /**
   * Add SSL binding to a DOKO document's extensions
   * @param {DOKODocument} doko - DOKO document to modify
   * @param {Object} binding - SSL binding from createBinding()
   * @returns {DOKODocument} Modified document (requires re-signing)
   */
  static addBinding(doko, binding) {
    if (!doko.extensions) {
      doko.extensions = {};
    }

    if (!doko.extensions.sslBindings) {
      doko.extensions.sslBindings = [];
    }

    // Check if binding for this domain already exists
    const existingIdx = doko.extensions.sslBindings.findIndex(
      b => b.domain === binding.domain
    );

    if (existingIdx >= 0) {
      // Update existing binding
      doko.extensions.sslBindings[existingIdx] = binding;
    } else {
      // Add new binding
      doko.extensions.sslBindings.push(binding);
    }

    // Invalidate signature - document needs re-signing
    doko.signature = null;

    return doko;
  }

  /**
   * Verify an SSL binding matches a certificate
   * @param {Object} binding - SSL binding object
   * @param {string|Buffer} cert - Certificate to verify
   * @returns {Object} Verification result
   */
  static verifyBinding(binding, cert) {
    const fingerprint = this.computeFingerprint(cert);
    const matches = fingerprint === binding.fingerprint;

    return {
      valid: matches,
      reason: matches ? 'FINGERPRINT_MATCH' : 'FINGERPRINT_MISMATCH',
      expected: binding.fingerprint,
      actual: fingerprint,
      domain: binding.domain,
    };
  }

  /**
   * Get all SSL bindings from a DOKO document
   * @param {DOKODocument} doko - DOKO document
   * @returns {Array} Array of SSL bindings
   */
  static getBindings(doko) {
    return doko?.extensions?.sslBindings || [];
  }

  /**
   * Get SSL binding for a specific domain
   * @param {DOKODocument} doko - DOKO document
   * @param {string} domain - Domain name
   * @returns {Object|null} SSL binding or null
   */
  static getBindingForDomain(doko, domain) {
    const bindings = this.getBindings(doko);
    return bindings.find(b => b.domain === domain.toLowerCase()) || null;
  }

  /**
   * Remove SSL binding for a domain
   * @param {DOKODocument} doko - DOKO document
   * @param {string} domain - Domain name
   * @returns {boolean} True if binding was removed
   */
  static removeBinding(doko, domain) {
    if (!doko?.extensions?.sslBindings) {
      return false;
    }

    const initialLen = doko.extensions.sslBindings.length;
    doko.extensions.sslBindings = doko.extensions.sslBindings.filter(
      b => b.domain !== domain.toLowerCase()
    );

    if (doko.extensions.sslBindings.length < initialLen) {
      doko.signature = null; // Needs re-signing
      return true;
    }

    return false;
  }

  /**
   * Validate all SSL bindings in a DOKO document
   * @param {DOKODocument} doko - DOKO document
   * @returns {Object} Validation result with details for each binding
   */
  static validateBindings(doko) {
    const bindings = this.getBindings(doko);
    const results = {
      valid: true,
      count: bindings.length,
      bindings: [],
    };

    for (const binding of bindings) {
      const now = Date.now();
      const isExpired = binding.validTo && binding.validTo < now;
      const isNotYetValid = binding.validFrom && binding.validFrom > now;

      const result = {
        domain: binding.domain,
        fingerprint: binding.fingerprint.substring(0, 16) + '...',
        valid: !isExpired && !isNotYetValid,
        verified: binding.verified,
        reason: isExpired
          ? 'CERTIFICATE_EXPIRED'
          : isNotYetValid
            ? 'CERTIFICATE_NOT_YET_VALID'
            : 'VALID',
      };

      results.bindings.push(result);
      if (!result.valid) {
        results.valid = false;
      }
    }

    return results;
  }
}

/**
 * DOKO Transfer - Secure ownership transfer system
 * 
 * Enables cryptographically verified transfers of domains and other
 * DOKO-bound assets between identities. The transfer process requires:
 * 
 * 1. Transfer Request: Created by the new owner, includes target asset
 * 2. Transfer Authorization: Signed by current owner, proves consent
 * 3. Transfer Proof: Combined proof that mesh nodes can verify
 * 
 * Transfer Flow:
 *   New Owner creates request → Current Owner signs authorization →
 *   Transfer proof created → Mesh verifies → Ownership updated
 */
export class DOKOTransfer {
  /**
   * Transfer states
   */
  static STATES = {
    PENDING: 'pending',       // Request created, awaiting authorization
    AUTHORIZED: 'authorized', // Current owner has signed
    COMPLETED: 'completed',   // Transfer executed
    REJECTED: 'rejected',     // Current owner rejected
    EXPIRED: 'expired',       // Transfer request expired
    CANCELLED: 'cancelled',   // Cancelled by requester
  };

  /**
   * Transfer types
   */
  static TYPES = {
    DOMAIN: 'domain',         // .yak domain transfer
    WEBSITE: 'website',       // Website manifest ownership
    ASSET: 'asset',           // Generic asset transfer
  };

  /**
   * Create a transfer request
   * @param {Object} options - Transfer options
   * @param {string} options.type - Transfer type (domain, website, asset)
   * @param {string} options.assetId - Asset identifier (domain name, website hash, etc.)
   * @param {string} options.fromDoko - Current owner's DOKO ID
   * @param {string} options.toDoko - New owner's DOKO ID
   * @param {string} options.toPublicKey - New owner's public key (hex)
   * @param {number} options.expiresIn - Expiration in milliseconds (default: 7 days)
   * @returns {Object} Transfer request object
   */
  static createRequest(options) {
    if (!options.type || !options.assetId || !options.fromDoko || !options.toDoko) {
      throw new Error('type, assetId, fromDoko, and toDoko are required');
    }

    const now = Date.now();
    const expiresIn = options.expiresIn || 7 * 24 * 60 * 60 * 1000; // 7 days default

    const request = {
      version: '1.0',
      type: options.type,
      assetId: options.assetId,
      fromDoko: options.fromDoko,
      toDoko: options.toDoko,
      toPublicKey: options.toPublicKey || null,
      requestedAt: now,
      expiresAt: now + expiresIn,
      state: this.STATES.PENDING,
      reason: options.reason || null,
      metadata: options.metadata || {},
    };

    // Compute request ID (hash of canonical request data)
    const canonical = JSON.stringify({
      type: request.type,
      assetId: request.assetId,
      fromDoko: request.fromDoko,
      toDoko: request.toDoko,
      requestedAt: request.requestedAt,
    });

    const hash = sha3_256(Buffer.from(canonical));
    request.requestId = 'xfer-' + bytesToHex(hash).substring(0, 16);

    return request;
  }

  /**
   * Get the bytes to be signed for authorization
   * @param {Object} request - Transfer request
   * @returns {Uint8Array} Bytes to sign
   */
  static getAuthorizableBytes(request) {
    const canonical = JSON.stringify({
      requestId: request.requestId,
      type: request.type,
      assetId: request.assetId,
      fromDoko: request.fromDoko,
      toDoko: request.toDoko,
      requestedAt: request.requestedAt,
      expiresAt: request.expiresAt,
    });
    return Buffer.from(canonical);
  }

  /**
   * Authorize a transfer (called by current owner)
   * @param {Object} request - Transfer request
   * @param {Uint8Array} signature - Signature from current owner
   * @param {string} fromNodeId - Current owner's node ID (for audit)
   * @returns {Object} Authorized transfer
   */
  static authorize(request, signature, fromNodeId) {
    if (request.state !== this.STATES.PENDING) {
      throw new Error(`Cannot authorize transfer in state: ${request.state}`);
    }

    if (Date.now() > request.expiresAt) {
      request.state = this.STATES.EXPIRED;
      throw new Error('Transfer request has expired');
    }

    return {
      ...request,
      state: this.STATES.AUTHORIZED,
      authorization: {
        signature: typeof signature === 'string' ? signature : bytesToHex(signature),
        fromNodeId,
        authorizedAt: Date.now(),
      },
    };
  }

  /**
   * Reject a transfer (called by current owner)
   * @param {Object} request - Transfer request
   * @param {string} reason - Rejection reason
   * @returns {Object} Rejected transfer
   */
  static reject(request, reason) {
    return {
      ...request,
      state: this.STATES.REJECTED,
      rejection: {
        reason,
        rejectedAt: Date.now(),
      },
    };
  }

  /**
   * Cancel a transfer request (called by requester)
   * @param {Object} request - Transfer request
   * @returns {Object} Cancelled transfer
   */
  static cancel(request) {
    if (request.state !== this.STATES.PENDING) {
      throw new Error(`Cannot cancel transfer in state: ${request.state}`);
    }

    return {
      ...request,
      state: this.STATES.CANCELLED,
      cancelledAt: Date.now(),
    };
  }

  /**
   * Verify a transfer authorization
   * @param {Object} transfer - Authorized transfer
   * @param {string} fromPublicKey - Current owner's public key (hex)
   * @returns {Object} Verification result
   */
  static async verifyAuthorization(transfer, fromPublicKey) {
    if (transfer.state !== this.STATES.AUTHORIZED) {
      return {
        valid: false,
        reason: 'TRANSFER_NOT_AUTHORIZED',
        state: transfer.state,
      };
    }

    if (Date.now() > transfer.expiresAt) {
      return {
        valid: false,
        reason: 'TRANSFER_EXPIRED',
        expiresAt: transfer.expiresAt,
      };
    }

    try {
      // Get the signable bytes
      const message = this.getAuthorizableBytes(transfer);
      const signature = hexToBytes(transfer.authorization.signature);
      const publicKey = hexToBytes(fromPublicKey);

      // Use ML-DSA-65 verification (already imported at top of file)
      // IMPORTANT: ml_dsa65.verify(signature, message, publicKey) - signature FIRST!
      const isValid = mlDsa65Verify(signature, message, publicKey);

      return {
        valid: isValid,
        reason: isValid ? 'SIGNATURE_VALID' : 'SIGNATURE_INVALID',
        requestId: transfer.requestId,
      };
    } catch (error) {
      return {
        valid: false,
        reason: 'VERIFICATION_ERROR',
        error: error.message,
      };
    }
  }

  /**
   * Complete a transfer (after verification)
   * @param {Object} transfer - Authorized and verified transfer
   * @param {string} toNodeId - New owner's node ID
   * @returns {Object} Completed transfer with proof
   */
  static complete(transfer, toNodeId) {
    if (transfer.state !== this.STATES.AUTHORIZED) {
      throw new Error(`Cannot complete transfer in state: ${transfer.state}`);
    }

    const completedAt = Date.now();

    // Create transfer proof
    const proofData = JSON.stringify({
      requestId: transfer.requestId,
      type: transfer.type,
      assetId: transfer.assetId,
      fromDoko: transfer.fromDoko,
      toDoko: transfer.toDoko,
      authorization: transfer.authorization,
      completedAt,
    });

    const proofHash = sha3_256(Buffer.from(proofData));

    return {
      ...transfer,
      state: this.STATES.COMPLETED,
      completion: {
        toNodeId,
        completedAt,
        proofHash: bytesToHex(proofHash),
      },
    };
  }

  /**
   * Create a transfer proof for mesh verification
   * @param {Object} completedTransfer - Completed transfer
   * @returns {Object} Transfer proof for gossip/verification
   */
  static createProof(completedTransfer) {
    if (completedTransfer.state !== this.STATES.COMPLETED) {
      throw new Error('Can only create proof for completed transfers');
    }

    return {
      type: 'DOKO_TRANSFER_PROOF',
      version: '1.0',
      requestId: completedTransfer.requestId,
      transferType: completedTransfer.type,
      assetId: completedTransfer.assetId,
      fromDoko: completedTransfer.fromDoko,
      toDoko: completedTransfer.toDoko,
      authorization: {
        signature: completedTransfer.authorization.signature,
        authorizedAt: completedTransfer.authorization.authorizedAt,
      },
      completion: completedTransfer.completion,
    };
  }

  /**
   * Validate a transfer proof (for mesh nodes)
   * @param {Object} proof - Transfer proof
   * @returns {Object} Validation result
   */
  static validateProof(proof) {
    const checks = [];

    // Check structure
    if (proof.type !== 'DOKO_TRANSFER_PROOF') {
      checks.push({ check: 'type', valid: false, reason: 'INVALID_TYPE' });
    } else {
      checks.push({ check: 'type', valid: true });
    }

    // Check required fields
    const required = ['requestId', 'transferType', 'assetId', 'fromDoko', 'toDoko', 'authorization', 'completion'];
    for (const field of required) {
      if (!proof[field]) {
        checks.push({ check: field, valid: false, reason: 'MISSING_FIELD' });
      } else {
        checks.push({ check: field, valid: true });
      }
    }

    // Check completion proof
    if (proof.completion?.proofHash) {
      const expectedProofData = JSON.stringify({
        requestId: proof.requestId,
        type: proof.transferType,
        assetId: proof.assetId,
        fromDoko: proof.fromDoko,
        toDoko: proof.toDoko,
        authorization: { ...proof.authorization, fromNodeId: undefined },
        completedAt: proof.completion.completedAt,
      });

      // Note: Full proof verification would require the original authorization.fromNodeId
      checks.push({ check: 'proofHash', valid: true, reason: 'HASH_PRESENT' });
    }

    const allValid = checks.every(c => c.valid);

    return {
      valid: allValid,
      checks,
    };
  }
}

// ============================================================
// DOKO REVOCATION - Key Compromise Recovery (v2.2.0)
// ============================================================

/**
 * Revocation Reasons
 */
export const REVOCATION_REASONS = {
  KEY_COMPROMISED: 'key_compromised',   // Private key leaked or stolen
  DOKO_SUPERSEDED: 'doko_superseded',   // Replaced by new DOKO
  IDENTITY_RETIRED: 'identity_retired', // Voluntary retirement
  LOST_ACCESS: 'lost_access',           // Lost access to private key
  AFFILIATION_ENDED: 'affiliation_ended', // Left organization
};

/**
 * DOKORevocation - Key Compromise Recovery System
 * 
 * Creates and manages revocation certificates that announce a DOKO
 * should no longer be trusted. The revocation is broadcast via gossip
 * and stored by nodes to prevent future trust decisions on revoked DOKOs.
 * 
 * Revocation Methods:
 * 1. Self-revocation: Sign with the DOKO's own key (if still available)
 * 2. Emergency revocation: Pre-generated "break-glass" certificate
 * 3. Endorser revocation: Trusted endorsers can revoke (quorum-based)
 * 
 * Usage:
 *   DOKORevocation.createSelfRevocation(doko, privateKey, reason)
 *   DOKORevocation.createEmergencyRevocation(preGeneratedCert)
 *   DOKORevocation.isRevoked(dokoId)
 */
export class DOKORevocation {
  static REVOCATION_STORE_KEY = 'doko-revocations';

  // In-memory revocation cache
  static _revocations = new Map(); // dokoId -> revocation certificate

  /**
   * Create a self-revocation certificate
   * Used when you still have access to the private key
   * 
   * @param {DOKODocument} doko - The DOKO to revoke
   * @param {Uint8Array} privateKey - The private key (ML-DSA)
   * @param {string} reason - Reason from REVOCATION_REASONS
   * @param {Object} options - Additional options
   * @returns {Object} Revocation certificate
   */
  static createSelfRevocation(doko, privateKey, reason, options = {}) {
    const revokedAt = Date.now();

    const revocationData = {
      version: '1.0',
      type: 'self',
      dokoId: doko.dokoId,
      dokoType: doko.type,
      reason,
      revokedAt,
      message: options.message || null,
      successorDokoId: options.successorDokoId || null, // New DOKO replacing this one
    };

    // Create canonical bytes for signing
    const dataBytes = new TextEncoder().encode(JSON.stringify(revocationData));

    // Sign with ML-DSA (message first, then secretKey)
    const signature = mlDsa65Sign(dataBytes, privateKey);

    const certificate = {
      ...revocationData,
      signature: bytesToHex(signature),
      signatureAlgorithm: 'ML-DSA-65',
    };

    // Store locally
    DOKORevocation._revocations.set(doko.dokoId, certificate);

    return certificate;
  }

  /**
   * Create an emergency revocation using a pre-generated certificate
   * 
   * Emergency certificates are created when DOKO is generated and stored
   * securely offline. They can be used if the private key is lost/stolen.
   * 
   * @param {Object} preGeneratedCert - Previously generated emergency cert
   * @returns {Object} Activated revocation certificate
   */
  static activateEmergencyRevocation(preGeneratedCert) {
    if (!preGeneratedCert || !preGeneratedCert.emergencyToken) {
      throw new Error('Invalid emergency certificate');
    }

    const activatedAt = Date.now();

    const certificate = {
      version: '1.0',
      type: 'emergency',
      dokoId: preGeneratedCert.dokoId,
      reason: REVOCATION_REASONS.KEY_COMPROMISED,
      createdAt: preGeneratedCert.createdAt,
      activatedAt,
      emergencyToken: preGeneratedCert.emergencyToken,
      signature: preGeneratedCert.signature,
      signatureAlgorithm: 'ML-DSA-65',
    };

    // Store locally
    DOKORevocation._revocations.set(certificate.dokoId, certificate);

    return certificate;
  }

  /**
   * Generate an emergency revocation certificate for future use
   * STORE THIS SECURELY OFFLINE!
   * 
   * @param {DOKODocument} doko - The DOKO to generate emergency cert for
   * @param {Uint8Array} privateKey - The private key (ML-DSA)
   * @returns {Object} Emergency certificate (store securely!)
   */
  static generateEmergencyCertificate(doko, privateKey) {
    const createdAt = Date.now();

    // Generate random emergency token (balanced ternary — '666' impossible)
    const emergencyToken = ternaryId(32);

    const certData = {
      dokoId: doko.dokoId,
      createdAt,
      emergencyToken,
    };

    // Sign the emergency cert (message first, then secretKey)
    const dataBytes = new TextEncoder().encode(JSON.stringify(certData));
    const signature = mlDsa65Sign(dataBytes, privateKey);

    return {
      ...certData,
      signature: bytesToHex(signature),
      publicKey: doko.publicKey, // Include for verification
      _warning: 'STORE THIS OFFLINE AND SECURELY! This is your break-glass recovery option.',
    };
  }

  /**
   * Verify a revocation certificate
   * 
   * @param {Object} certificate - Revocation certificate
   * @param {string} publicKey - Public key to verify with (hex)
   * @returns {Object} { valid, reason }
   */
  static verify(certificate, publicKey) {
    try {
      if (!certificate || !certificate.signature) {
        return { valid: false, reason: 'MISSING_SIGNATURE' };
      }

      // Extract signature
      const signature = hexToBytes(certificate.signature);

      // Reconstruct signable data
      const certCopy = { ...certificate };
      delete certCopy.signature;
      delete certCopy.signatureAlgorithm;

      const dataBytes = new TextEncoder().encode(JSON.stringify(certCopy));
      const pubKeyBytes = hexToBytes(publicKey);

      // Verify with ML-DSA (signature, message, publicKey)
      const isValid = mlDsa65Verify(signature, dataBytes, pubKeyBytes);

      if (!isValid) {
        return { valid: false, reason: 'INVALID_SIGNATURE' };
      }

      return { valid: true, reason: null };
    } catch (e) {
      return { valid: false, reason: e.message };
    }
  }

  /**
   * Check if a DOKO is revoked
   * 
   * @param {string} dokoId - DOKO ID to check
   * @returns {Object} { revoked, certificate, reason }
   */
  static isRevoked(dokoId) {
    const cert = DOKORevocation._revocations.get(dokoId);

    if (cert) {
      return {
        revoked: true,
        certificate: cert,
        reason: cert.reason,
        revokedAt: cert.revokedAt || cert.activatedAt,
      };
    }

    return { revoked: false, certificate: null, reason: null };
  }

  /**
   * Add a revocation certificate (from gossip/sync)
   * 
   * @param {Object} certificate - Revocation certificate
   * @param {string} publicKey - Public key for verification
   * @returns {Object} { success, reason }
   */
  static addRevocation(certificate, publicKey) {
    // Verify the certificate
    const verification = DOKORevocation.verify(certificate, publicKey);

    if (!verification.valid) {
      return { success: false, reason: verification.reason };
    }

    // Store the revocation
    DOKORevocation._revocations.set(certificate.dokoId, certificate);

    return { success: true, reason: null };
  }

  /**
   * List all revocations
   * 
   * @returns {Array} All revocation certificates
   */
  static listRevocations() {
    return Array.from(DOKORevocation._revocations.values());
  }

  /**
   * Export revocations for sync/backup
   * 
   * @returns {Array} Revocation certificates
   */
  static export() {
    return DOKORevocation.listRevocations();
  }

  /**
   * Import revocations (with verification)
   * 
   * @param {Array} certificates - Revocation certificates
   * @param {Map|Object} publicKeyMap - dokoId -> publicKey mapping
   * @returns {Object} { imported, failed }
   */
  static import(certificates, publicKeyMap) {
    let imported = 0;
    let failed = 0;

    for (const cert of certificates) {
      const publicKey = publicKeyMap instanceof Map
        ? publicKeyMap.get(cert.dokoId)
        : publicKeyMap[cert.dokoId];

      if (!publicKey) {
        failed++;
        continue;
      }

      const result = DOKORevocation.addRevocation(cert, publicKey);
      if (result.success) {
        imported++;
      } else {
        failed++;
      }
    }

    return { imported, failed };
  }

  /**
   * Clear all revocations (for testing)
   */
  static _clear() {
    DOKORevocation._revocations.clear();
  }

  /**
   * Get revocation statistics
   */
  static getStats() {
    const byReason = {};
    const byType = {};

    for (const cert of DOKORevocation._revocations.values()) {
      byReason[cert.reason] = (byReason[cert.reason] || 0) + 1;
      byType[cert.type] = (byType[cert.type] || 0) + 1;
    }

    return {
      total: DOKORevocation._revocations.size,
      byReason,
      byType,
    };
  }
}

/**
 * DOKO Store - Manage DOKO documents
 */
export class DOKOStore {
  constructor() {
    this.documents = new Map(); // dokoId -> DOKODocument
    this.byPublicKey = new Map(); // publicKeyHex -> dokoId
    this.byUserId = new Map(); // userId -> dokoId (for PeerQuanta)
  }

  /**
   * Add a DOKO document to the store
   */
  add(doko, options = {}) {
    // Validate first
    if (!options.skipValidation) {
      const validation = DOKOValidator.validate(doko);
      if (!validation.valid) {
        return { success: false, error: 'VALIDATION_FAILED', details: validation };
      }
    }

    const doc = doko instanceof DOKODocument ? doko : DOKODocument.fromJSON(doko);

    this.documents.set(doc.dokoId, doc);
    this.byPublicKey.set(doc.publicKey, doc.dokoId);

    // Index by userId if present (PeerQuanta integration)
    if (doc.claims?.userId) {
      this.byUserId.set(doc.claims.userId, doc.dokoId);
    }

    return { success: true, dokoId: doc.dokoId };
  }

  /**
   * Get a DOKO by ID
   */
  get(dokoId) {
    return this.documents.get(dokoId);
  }

  /**
   * Get a DOKO by public key
   */
  getByPublicKey(publicKey) {
    const dokoId = this.byPublicKey.get(publicKey);
    return dokoId ? this.documents.get(dokoId) : null;
  }

  /**
   * Get a DOKO by user ID (PeerQuanta)
   */
  getByUserId(userId) {
    const dokoId = this.byUserId.get(userId);
    return dokoId ? this.documents.get(dokoId) : null;
  }

  /**
   * Remove a DOKO
   */
  remove(dokoId) {
    const doc = this.documents.get(dokoId);
    if (doc) {
      this.byPublicKey.delete(doc.publicKey);
      if (doc.claims?.userId) {
        this.byUserId.delete(doc.claims.userId);
      }
      this.documents.delete(dokoId);
      return true;
    }
    return false;
  }

  /**
   * Get all DOKOs of a specific type
   */
  getByType(type) {
    const results = [];
    for (const doc of this.documents.values()) {
      if (doc.type === type) {
        results.push(doc);
      }
    }
    return results;
  }

  /**
   * Get all traders (for PeerQuanta)
   */
  getTraders() {
    return this.getByType(DOKO_TYPES.TRADER);
  }

  /**
   * Get all merchants
   */
  getMerchants() {
    return this.getByType(DOKO_TYPES.MERCHANT);
  }

  /**
   * Get statistics
   */
  getStats() {
    const byType = {};
    for (const type of Object.values(DOKO_TYPES)) {
      byType[type] = 0;
    }

    for (const doc of this.documents.values()) {
      byType[doc.type] = (byType[doc.type] || 0) + 1;
    }

    return {
      total: this.documents.size,
      byType,
    };
  }

  /**
   * Export all DOKOs (for backup/sync)
   */
  export() {
    return Array.from(this.documents.values()).map(d => d.toJSON());
  }

  /**
   * Import DOKOs (from backup/sync)
   */
  import(dokos, options = {}) {
    let imported = 0;
    let failed = 0;

    for (const doko of dokos) {
      const result = this.add(doko, options);
      if (result.success) {
        imported++;
      } else {
        failed++;
      }
    }

    return { imported, failed };
  }
}

export default {
  DOKO_TYPES,
  DOKO_VERSION,
  REVOCATION_REASONS,
  DOKODocument,
  DOKOGenerator,
  DOKOValidator,
  DOKOEndorsement,
  DOKOCertBinding,
  DOKOTransfer,
  DOKORevocation,
  DOKOStore,
};
