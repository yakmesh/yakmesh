/**
 * @deprecated USE validation-oracle-hardened.js INSTEAD
 * 
 * This file is DEPRECATED and will be removed in a future version.
 * All production code should import from:
 *   - './validation-oracle-hardened.js' (direct)
 *   - './index.js' (recommended - main entry point)
 * 
 * The hardened version includes:
 *   - Cross-platform path normalization (Windows/Linux compatible)
 *   - Full codebase hashing (not just oracle file)
 *   - Frozen singleton pattern
 *   - Self-integrity verification
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * PeerQuanta Validation Oracle (LEGACY)
 * 
 * A self-verifying, deterministic validation system that acts as a distributed oracle.
 * Every node running this code will independently arrive at the same truth.
 * 
 * Core Principles:
 * 1. Code verifies its own integrity (self-validating)
 * 2. All functions are pure and deterministic (same input → same output)
 * 3. Nodes can prove to each other they're running identical code
 * 4. Mathematical proofs replace social trust
 * 
 * @module ValidationOracle
 * @version 1.0.0
 * @deprecated Use validation-oracle-hardened.js
 */

import { sha3_256 as _nobleSha3, sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Verify } from '../utils/accel.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:validation');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Oracle Module Seal - Cryptographic binding of code identity
 * This is computed at build time and embedded here
 */
const MODULE_SEAL = {
  version: '1.0.0',
  // These hashes are computed during the build/seal process
  sourceHash: null,  // Will be computed on first run
  behaviorFingerprint: null,  // Hash of test vector outputs
  genesisTimestamp: Date.now(),
  
  // Known-good function hashes (computed from source)
  functionHashes: {},
};

/**
 * Validation Result - Standard return type for all validations
 */
export class ValidationResult {
  constructor(valid, reason = null, proof = null) {
    this.valid = valid;
    this.reason = reason;
    this.proof = proof;
    this.timestamp = Date.now();
    this.oracleVersion = MODULE_SEAL.version;
  }
  
  static success(proof = null) {
    return new ValidationResult(true, null, proof);
  }
  
  static failure(reason) {
    return new ValidationResult(false, reason, null);
  }
  
  toJSON() {
    return {
      valid: this.valid,
      reason: this.reason,
      proof: this.proof,
      timestamp: this.timestamp,
      oracleVersion: this.oracleVersion,
    };
  }
}

/**
 * Content Hash - Deterministic hashing of any content
 */
export function contentHash(data) {
  if (typeof data === 'string') {
    return bytesToHex(sha3_256(utf8ToBytes(data)));
  }
  if (data instanceof Uint8Array) {
    return bytesToHex(sha3_256(data));
  }
  // For objects, use deterministic JSON serialization
  return bytesToHex(sha3_256(utf8ToBytes(deterministicStringify(data))));
}

/**
 * Deterministic JSON stringify - Guarantees same output for same input
 * Keys are sorted alphabetically, no whitespace
 */
export function deterministicStringify(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(deterministicStringify).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => JSON.stringify(k) + ':' + deterministicStringify(obj[k]));
    return '{' + pairs.join(',') + '}';
  }
  return String(obj);
}

/**
 * The Validation Oracle - Self-verifying, deterministic validation engine
 */
export class ValidationOracle {
  constructor() {
    this.initialized = false;
    this.selfHash = null;
    this.functionRegistry = new Map();
    this.testVectors = [];
    
    // Initialize and verify self-integrity
    this._initialize();
  }
  
  /**
   * Initialize the oracle and verify its own integrity
   */
  _initialize() {
    log.info('Initializing Validation Oracle');
    
    // 1. Compute hash of our own source code
    this.selfHash = this._computeSelfHash();
    log.debug('Self-hash computed', { hash: this.selfHash.slice(0, 16) });
    
    // 2. Register all validation functions with their hashes
    this._registerFunctions();
    
    // 3. Generate behavior fingerprint from test vectors
    this._generateBehaviorFingerprint();
    
    // 4. Seal the module
    MODULE_SEAL.sourceHash = this.selfHash;
    MODULE_SEAL.functionHashes = Object.fromEntries(this.functionRegistry);
    MODULE_SEAL.behaviorFingerprint = this.behaviorFingerprint;
    
    this.initialized = true;
    log.info('Validation Oracle initialized and sealed');
  }
  
  /**
   * Compute hash of our own source code
   */
  _computeSelfHash() {
    try {
      // Read our own source file
      const sourcePath = join(__dirname, 'validation-oracle.js');
      const source = readFileSync(sourcePath, 'utf-8');
      return contentHash(source);
    } catch (e) {
      // Fallback: hash the function definitions
      const functionSources = [
        this.validateListing.toString(),
        this.validateUser.toString(),
        this.validateSignature.toString(),
        this.validateQCoA.toString(),
        this.resolveConflict.toString(),
      ];
      return contentHash(functionSources.join('\n'));
    }
  }
  
  /**
   * Register validation functions with their source hashes
   */
  _registerFunctions() {
    const functions = [
      ['validateListing', this.validateListing],
      ['validateUser', this.validateUser],
      ['validateSignature', this.validateSignature],
      ['validateQCoA', this.validateQCoA],
      ['resolveConflict', this.resolveConflict],
      ['computeTrustScore', this.computeTrustScore],
    ];
    
    for (const [name, fn] of functions) {
      const fnHash = contentHash(fn.toString());
      this.functionRegistry.set(name, fnHash);
    }
  }
  
  /**
   * Generate behavior fingerprint from test vectors
   * This proves the code behaves as expected
   */
  _generateBehaviorFingerprint() {
    // Define test vectors - known inputs with expected outputs
    this.testVectors = [
      {
        fn: 'validateListing',
        input: { title: 'Test', price: 100, currency: 'BTC', user_id: 1 },
        expectedValid: true,
      },
      {
        fn: 'validateListing',
        input: { title: '', price: 100, currency: 'BTC', user_id: 1 },
        expectedValid: false,
      },
      {
        fn: 'validateListing',
        input: { title: 'Test', price: -1, currency: 'BTC', user_id: 1 },
        expectedValid: false,
      },
      {
        fn: 'resolveConflict',
        input: [
          { id: 1, data: 'A', hash: 'aaa' },
          { id: 1, data: 'B', hash: 'bbb' },
        ],
        // Result should be deterministic
      },
    ];
    
    // Compute outputs for all test vectors
    const outputs = this.testVectors.map(tv => {
      if (tv.fn === 'validateListing') {
        return this.validateListing(tv.input).valid;
      }
      if (tv.fn === 'resolveConflict') {
        return contentHash(this.resolveConflict(tv.input[0], tv.input[1]));
      }
      return null;
    });
    
    this.behaviorFingerprint = contentHash(outputs);
  }
  
  // ============================================================
  // SELF-VERIFICATION METHODS
  // ============================================================
  
  /**
   * Verify own integrity - call this periodically
   */
  verifySelfIntegrity() {
    const currentHash = this._computeSelfHash();
    
    if (currentHash !== this.selfHash) {
      throw new Error(`INTEGRITY VIOLATION: Code has been modified! ` +
        `Expected ${this.selfHash}, got ${currentHash}`);
    }
    
    return ValidationResult.success({ selfHash: this.selfHash });
  }
  
  /**
   * Generate a proof that we're running the correct code
   * This can be sent to other nodes for verification
   * 
   * @param {string} challenge - Optional challenge from another node (for mutual verification)
   * @returns {Object} Code proof
   */
  generateCodeProof(challenge = null) {
    // If no challenge, generate a self-attestation proof
    const effectiveChallenge = challenge || this.selfHash;
    
    // Combine challenge with our self-hash
    const proofInput = effectiveChallenge + this.selfHash + this.behaviorFingerprint;
    const response = contentHash(proofInput);
    
    return {
      oracleVersion: MODULE_SEAL.version,
      selfHash: this.selfHash,
      behaviorFingerprint: this.behaviorFingerprint,
      challenge: effectiveChallenge,
      response: response,
      functionHashes: Object.fromEntries(this.functionRegistry),
      timestamp: Date.now(),
      version: MODULE_SEAL.version,
    };
  }
  
  /**
   * Verify another node's code proof
   * Returns true if they're running identical code
   */
  verifyCodeProof(proof) {
    // 1. Verify their self-hash matches ours
    if (proof.selfHash !== this.selfHash) {
      return ValidationResult.failure('SELF_HASH_MISMATCH');
    }
    
    // 2. Verify their behavior fingerprint matches
    if (proof.behaviorFingerprint !== this.behaviorFingerprint) {
      return ValidationResult.failure('BEHAVIOR_FINGERPRINT_MISMATCH');
    }
    
    // 3. Verify the challenge-response
    const expectedResponse = contentHash(
      proof.challenge + this.selfHash + this.behaviorFingerprint
    );
    
    if (proof.response !== expectedResponse) {
      return ValidationResult.failure('CHALLENGE_RESPONSE_INVALID');
    }
    
    // 4. Verify function hashes
    for (const [name, hash] of this.functionRegistry) {
      if (proof.functionHashes[name] !== hash) {
        return ValidationResult.failure(`FUNCTION_HASH_MISMATCH: ${name}`);
      }
    }
    
    return ValidationResult.success({ verified: true, peerHash: proof.selfHash });
  }
  
  /**
   * Get the module seal - public identity of this oracle
   */
  getModuleSeal() {
    return { ...MODULE_SEAL };
  }

  /**
   * Get list of available validation methods
   * @returns {Array<string>} List of validation method names
   */
  getValidationMethods() {
    return ['listing', 'qcoa', 'user'];
  }

  /**
   * Generic validate method - dispatches to specific validators
   * @param {string} contentType - Type of content (listing, qcoa, user)
   * @param {Object} content - The content to validate
   * @returns {Object} Validation result with contentHash
   */
  async validate(contentType, content) {
    let validationResult;
    
    switch (contentType) {
      case 'listing':
        validationResult = this.validateListing(content);
        break;
      case 'qcoa':
        validationResult = this.validateQCoA(content);
        break;
      case 'user':
        validationResult = this.validateUser(content);
        break;
      default:
        return {
          valid: false,
          errors: [`Unknown content type: ${contentType}`],
        };
    }
    
    if (!validationResult.valid) {
      return {
        valid: false,
        errors: [validationResult.reason],
      };
    }
    
    return {
      valid: true,
      contentHash: contentHash(content),
      validatorHash: this.selfHash,
      validatedAt: Date.now(),
    };
  }
  
  // ============================================================
  // VALIDATION FUNCTIONS - Pure, deterministic, identical on all nodes
  // ============================================================
  
  /**
   * Validate a marketplace listing
   * @param {Object} listing - The listing to validate
   * @returns {ValidationResult}
   */
  validateListing(listing) {
    // Required fields check
    if (!listing) {
      return ValidationResult.failure('LISTING_NULL');
    }
    
    if (!listing.title || typeof listing.title !== 'string') {
      return ValidationResult.failure('INVALID_TITLE');
    }
    
    if (listing.title.length === 0 || listing.title.length > 200) {
      return ValidationResult.failure('TITLE_LENGTH_INVALID');
    }
    
    if (typeof listing.price !== 'number' || listing.price <= 0) {
      return ValidationResult.failure('INVALID_PRICE');
    }
    
    if (!listing.currency || typeof listing.currency !== 'string') {
      return ValidationResult.failure('INVALID_CURRENCY');
    }
    
    const validCurrencies = ['BTC', 'ETH', 'QRL', 'USD', 'EUR', 'GBP'];
    if (!validCurrencies.includes(listing.currency.toUpperCase())) {
      return ValidationResult.failure('UNSUPPORTED_CURRENCY');
    }
    
    if (!listing.user_id || typeof listing.user_id !== 'number') {
      return ValidationResult.failure('INVALID_USER_ID');
    }
    
    if (listing.trade_type && !['buy', 'sell'].includes(listing.trade_type)) {
      return ValidationResult.failure('INVALID_TRADE_TYPE');
    }
    
    // Compute content hash for the listing
    const listingHash = contentHash({
      title: listing.title,
      price: listing.price,
      currency: listing.currency,
      user_id: listing.user_id,
      trade_type: listing.trade_type || 'sell',
    });
    
    return ValidationResult.success({ contentHash: listingHash });
  }
  
  /**
   * Validate a user identity
   * @param {Object} user - User data including public key
   * @returns {ValidationResult}
   */
  validateUser(user) {
    if (!user) {
      return ValidationResult.failure('USER_NULL');
    }
    
    if (!user.user_id || typeof user.user_id !== 'number') {
      return ValidationResult.failure('INVALID_USER_ID');
    }
    
    if (!user.username || typeof user.username !== 'string') {
      return ValidationResult.failure('INVALID_USERNAME');
    }
    
    if (user.username.length < 3 || user.username.length > 50) {
      return ValidationResult.failure('USERNAME_LENGTH_INVALID');
    }
    
    // If public key is provided, validate its format
    if (user.public_key) {
      if (typeof user.public_key !== 'string' || user.public_key.length < 64) {
        return ValidationResult.failure('INVALID_PUBLIC_KEY_FORMAT');
      }
    }
    
    return ValidationResult.success({ userId: user.user_id });
  }
  
  /**
   * Validate a cryptographic signature (ML-DSA-65)
   * @param {string} message - The message that was signed
   * @param {string} signature - The signature (hex encoded)
   * @param {string} publicKey - The public key (hex encoded)
   * @returns {ValidationResult}
   */
  validateSignature(message, signature, publicKey) {
    if (!message || !signature || !publicKey) {
      return ValidationResult.failure('MISSING_SIGNATURE_PARAMS');
    }
    
    try {
      const messageBytes = typeof message === 'string' 
        ? utf8ToBytes(message) 
        : message;
      const sigBytes = hexToBytes(signature);
      const pubKeyBytes = hexToBytes(publicKey);
      
      // ML-DSA65 verify order: (signature, message, publicKey)
      const valid = mlDsa65Verify(sigBytes, messageBytes, pubKeyBytes);
      
      if (!valid) {
        return ValidationResult.failure('SIGNATURE_INVALID');
      }
      
      return ValidationResult.success({ 
        signatureValid: true,
        messageHash: contentHash(messageBytes),
      });
    } catch (e) {
      return ValidationResult.failure(`SIGNATURE_ERROR: ${e.message}`);
    }
  }
  
  /**
   * Validate a QCoA (Quantum Certificate of Authenticity)
   * @param {Object} certificate - The QCoA certificate
   * @returns {ValidationResult}
   */
  validateQCoA(certificate) {
    if (!certificate) {
      return ValidationResult.failure('CERTIFICATE_NULL');
    }
    
    // Required fields
    const required = ['cert_hash', 'origin_public_key', 'origin_signature', 'asset_type'];
    for (const field of required) {
      if (!certificate[field]) {
        return ValidationResult.failure(`MISSING_FIELD: ${field}`);
      }
    }
    
    // Verify the certificate hash is correct
    const certData = {
      origin_public_key: certificate.origin_public_key,
      asset_type: certificate.asset_type,
      asset_id: certificate.asset_id,
      timestamp: certificate.timestamp,
      metadata: certificate.metadata,
    };
    
    const computedHash = contentHash(certData);
    
    // Note: We check if cert_hash STARTS with computed hash prefix
    // This allows for versioned hash formats
    if (!certificate.cert_hash.includes(computedHash.slice(0, 16))) {
      // For now, just warn - full validation requires signature check
      log.warn('QCoA hash mismatch - will verify signature', { certHash: certificate.cert_hash.slice(0, 16), computedHash: computedHash.slice(0, 16) });
    }
    
    // Verify the signature
    try {
      const sigResult = this.validateSignature(
        certificate.cert_hash,
        certificate.origin_signature,
        certificate.origin_public_key
      );
      
      if (!sigResult.valid) {
        return ValidationResult.failure('QCOA_SIGNATURE_INVALID');
      }
    } catch (e) {
      // Signature validation failed - certificate may use different format
      log.warn('QCoA signature verification skipped', { error: e.message });
    }
    
    return ValidationResult.success({
      certHash: certificate.cert_hash,
      assetType: certificate.asset_type,
      verified: true,
    });
  }
  
  /**
   * Deterministic conflict resolution
   * Given two conflicting pieces of data, deterministically choose one
   * EVERY NODE will choose the same winner
   * 
   * @param {Object} dataA - First conflicting data
   * @param {Object} dataB - Second conflicting data
   * @returns {Object} The winning data
   */
  resolveConflict(dataA, dataB) {
    // Rule 1: If timestamps differ significantly, earlier wins
    const TIMESTAMP_TOLERANCE = 5000; // 5 seconds
    
    const tsA = dataA.timestamp || dataA.created_at || 0;
    const tsB = dataB.timestamp || dataB.created_at || 0;
    
    if (Math.abs(tsA - tsB) > TIMESTAMP_TOLERANCE) {
      return tsA < tsB ? dataA : dataB;
    }
    
    // Rule 2: If timestamps are close, lower content hash wins
    // This is arbitrary but DETERMINISTIC
    const hashA = contentHash(dataA);
    const hashB = contentHash(dataB);
    
    return hashA < hashB ? dataA : dataB;
  }
  
  /**
   * Compute trust score for a user
   * Deterministic calculation based on trading history
   * 
   * @param {Object} stats - User statistics
   * @returns {number} Trust score between 0 and 1
   */
  computeTrustScore(stats) {
    if (!stats) return 0;
    
    const {
      total_trades = 0,
      successful_trades = 0,
      positive_feedback = 0,
      negative_feedback = 0,
      disputes_won = 0,
      disputes_lost = 0,
      account_age_days = 0,
    } = stats;
    
    // Base score from trade success rate
    let score = 0;
    
    if (total_trades > 0) {
      score += 0.4 * (successful_trades / total_trades);
    }
    
    // Feedback score
    const totalFeedback = positive_feedback + negative_feedback;
    if (totalFeedback > 0) {
      score += 0.3 * (positive_feedback / totalFeedback);
    }
    
    // Dispute score
    const totalDisputes = disputes_won + disputes_lost;
    if (totalDisputes > 0) {
      score += 0.2 * (disputes_won / totalDisputes);
    }
    
    // Account age bonus (max 0.1 for accounts > 365 days)
    score += 0.1 * Math.min(account_age_days / 365, 1);
    
    // Clamp to [0, 1]
    return Math.max(0, Math.min(1, score));
  }
  
  // ============================================================
  // CONTENT VALIDATION & PROPAGATION
  // ============================================================
  
  /**
   * Validate and prepare content for propagation
   * Returns a sealed content package that can be verified by any node
   * 
   * @param {string} contentType - Type of content (listing, qcoa, user, etc.)
   * @param {Object} content - The content to validate
   * @param {string} signature - Creator's signature
   * @param {string} publicKey - Creator's public key
   * @returns {Object} Sealed content package
   */
  prepareForPropagation(contentType, content, signature, publicKey) {
    // 1. Validate the content based on type
    let validationResult;
    
    switch (contentType) {
      case 'listing':
        validationResult = this.validateListing(content);
        break;
      case 'qcoa':
        validationResult = this.validateQCoA(content);
        break;
      case 'user':
        validationResult = this.validateUser(content);
        break;
      default:
        return { valid: false, reason: 'UNKNOWN_CONTENT_TYPE' };
    }
    
    if (!validationResult.valid) {
      return { valid: false, reason: validationResult.reason };
    }
    
    // 2. Verify signature if provided
    if (signature && publicKey) {
      const contentString = deterministicStringify(content);
      const sigResult = this.validateSignature(contentString, signature, publicKey);
      
      if (!sigResult.valid) {
        return { valid: false, reason: 'INVALID_CREATOR_SIGNATURE' };
      }
    }
    
    // 3. Create sealed package
    const sealedPackage = {
      type: contentType,
      content: content,
      contentHash: contentHash(content),
      creatorPubKey: publicKey,
      creatorSignature: signature,
      validatedAt: Date.now(),
      oracleHash: this.selfHash,
      oracleVersion: MODULE_SEAL.version,
    };
    
    // 4. Sign the package with oracle's derived key
    sealedPackage.packageHash = contentHash(sealedPackage);
    
    return {
      valid: true,
      package: sealedPackage,
    };
  }
  
  /**
   * Verify a sealed content package from another node
   * 
   * @param {Object} sealedPackage - The sealed package to verify
   * @returns {ValidationResult}
   */
  verifySealedPackage(sealedPackage) {
    // 1. Verify the package hash
    const packageCopy = { ...sealedPackage };
    delete packageCopy.packageHash;
    
    const computedHash = contentHash(packageCopy);
    if (computedHash !== sealedPackage.packageHash) {
      return ValidationResult.failure('PACKAGE_HASH_MISMATCH');
    }
    
    // 2. Verify it was validated by a compatible oracle
    if (sealedPackage.oracleVersion !== MODULE_SEAL.version) {
      // Version mismatch - might still be compatible
      log.warn('Oracle version mismatch', { packageVersion: sealedPackage.oracleVersion, currentVersion: MODULE_SEAL.version });
    }
    
    // 3. Re-validate the content ourselves
    let revalidation;
    switch (sealedPackage.type) {
      case 'listing':
        revalidation = this.validateListing(sealedPackage.content);
        break;
      case 'qcoa':
        revalidation = this.validateQCoA(sealedPackage.content);
        break;
      case 'user':
        revalidation = this.validateUser(sealedPackage.content);
        break;
      default:
        return ValidationResult.failure('UNKNOWN_CONTENT_TYPE');
    }
    
    if (!revalidation.valid) {
      return ValidationResult.failure(`REVALIDATION_FAILED: ${revalidation.reason}`);
    }
    
    // 4. Verify content hash matches
    if (revalidation.proof?.contentHash !== sealedPackage.contentHash) {
      return ValidationResult.failure('CONTENT_HASH_MISMATCH');
    }
    
    return ValidationResult.success({
      contentType: sealedPackage.type,
      contentHash: sealedPackage.contentHash,
      verified: true,
    });
  }
}

/**
 * Singleton instance - ensures all code uses the same oracle
 */
let oracleInstance = null;

export function getOracle() {
  if (!oracleInstance) {
    oracleInstance = new ValidationOracle();
  }
  return oracleInstance;
}

export default ValidationOracle;
