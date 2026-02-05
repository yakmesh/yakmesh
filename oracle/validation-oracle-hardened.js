/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                    YAKMESH VALIDATION ORACLE - HARDENED                       ║
 * ║                                                                               ║
 * ║  ⚠️  CRITICAL SECURITY MODULE - DO NOT MODIFY WITHOUT REVIEW  ⚠️              ║
 * ║                                                                               ║
 * ║  This module is the cryptographic foundation of network identity.             ║
 * ║  ANY change to this file will change the codebase hash, which will:           ║
 * ║    - Create a new network (nodes won't peer with old network)                 ║
 * ║    - Invalidate all existing node identities                                  ║
 * ║    - Require coordinated deployment across all nodes                          ║
 * ║                                                                               ║
 * ║  STABILITY REQUIREMENTS:                                                      ║
 * ║    1. All paths normalized to forward slashes (cross-platform)                ║
 * ║    2. Deterministic file ordering (localeCompare sort)                        ║
 * ║    3. Consistent hash algorithm (SHA3-256)                                    ║
 * ║    4. Frozen singleton pattern (no runtime modification)                      ║
 * ║                                                                               ║
 * ║  BEFORE MODIFYING:                                                            ║
 * ║    - Document the change in CHANGELOG.md                                      ║
 * ║    - Coordinate with all node operators                                       ║
 * ║    - Plan network migration strategy                                          ║
 * ║    - Update version number below                                              ║
 * ║                                                                               ║
 * ║  Last verified: 2026-01-19 | Version: 1.2.0-hardened                          ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * PeerQuanta Validation Oracle - HARDENED VERSION
 * 
 * Security-hardened self-verifying oracle with protection against:
 * - Runtime tampering (Object.freeze, prototype sealing)
 * - Prototype pollution (null prototype objects)
 * - Race conditions (validation locking)
 * - Edge case inputs (comprehensive validation)
 * 
 * @module ValidationOracle
 * @version 1.2.0-hardened
 */

import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { readFileSync, readdirSync, statSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createLogger } from '../utils/logger.js';
import { Trit, TritState, POSITIVE, NEUTRAL, NEGATIVE } from './tribhuj.js';

const log = createLogger('oracle:validation');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================
// SECURITY: Create objects with null prototype to prevent pollution
// ============================================================
const createSafeObject = (obj = {}) => Object.assign(Object.create(null), obj);

/**
 * SECURITY: Deep freeze an object to prevent modification
 */
function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  
  Object.getOwnPropertyNames(obj).forEach(prop => {
    const val = obj[prop];
    if (val && typeof val === 'object') {
      deepFreeze(val);
    }
  });
  
  return Object.freeze(obj);
}

/**
 * SECURITY: Safe property access that prevents prototype pollution
 */
function safeGet(obj, key) {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return undefined;
  }
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/**
 * Oracle Module Seal - Cryptographic binding of code identity
 * SECURITY: Uses null prototype and is frozen after initialization
 */
const MODULE_SEAL = createSafeObject({
  version: '1.1.0-hardened',
  sourceHash: null,
  behaviorFingerprint: null,
  genesisTimestamp: null,
  functionHashes: null,
  frozen: false,
});

/**
 * Validation Result - Immutable return type for all validations
 * 
 * Now uses TERNARY logic (TRIBHUJ):
 *   VALID   (+1) = Definitively valid, can propagate
 *   INVALID (-1) = Definitively invalid, reject
 *   PENDING  (0) = Indeterminate, awaiting consensus/propagation
 * 
 * The PENDING state prevents "flapping" in distributed consensus:
 * nodes can acknowledge receipt without committing to validity.
 */
export class ValidationResult {
  #state;      // Trit: VALID(+1), INVALID(-1), PENDING(0)
  #reason;
  #proof;
  #timestamp;
  #oracleVersion;
  
  /**
   * @param {number|Trit} state - Ternary state: +1 (valid), -1 (invalid), 0 (pending)
   * @param {string|null} reason - Reason for invalid/pending state
   * @param {object|null} proof - Cryptographic proof
   */
  constructor(state, reason = null, proof = null) {
    // Accept Trit, number, or boolean (backwards compat)
    if (state instanceof Trit) {
      this.#state = state;
    } else if (typeof state === 'boolean') {
      // BACKWARDS COMPAT: true → VALID, false → INVALID
      this.#state = new Trit(state ? POSITIVE : NEGATIVE);
    } else {
      this.#state = new Trit(state);
    }
    
    this.#reason = reason;
    this.#proof = proof ? deepFreeze({ ...proof }) : null;
    this.#timestamp = Date.now();
    this.#oracleVersion = MODULE_SEAL.version;
    
    // SECURITY: Freeze the instance
    Object.freeze(this);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Ternary State Accessors
  // ─────────────────────────────────────────────────────────────────────────
  
  /** The ternary state as a Trit */
  get state() { return this.#state; }
  
  /** Is this definitively VALID? (+1) */
  get isValid() { return this.#state.isPositive; }
  
  /** Is this definitively INVALID? (-1) */
  get isInvalid() { return this.#state.isNegative; }
  
  /** Is this PENDING/indeterminate? (0) */
  get isPending() { return this.#state.isNeutral; }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Backwards Compatibility (boolean interface)
  // ─────────────────────────────────────────────────────────────────────────
  
  /** @deprecated Use isValid instead. Returns true only for VALID state. */
  get valid() { return this.#state.isPositive; }
  
  get reason() { return this.#reason; }
  get proof() { return this.#proof; }
  get timestamp() { return this.#timestamp; }
  get oracleVersion() { return this.#oracleVersion; }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Static Constructors
  // ─────────────────────────────────────────────────────────────────────────
  
  /** Create a VALID (+1) result */
  static success(proof = null) {
    return new ValidationResult(POSITIVE, null, proof);
  }
  
  /** Create an INVALID (-1) result */
  static failure(reason) {
    return new ValidationResult(NEGATIVE, reason, null);
  }
  
  /** Create a PENDING (0) result - awaiting consensus/propagation */
  static pending(reason = 'AWAITING_CONSENSUS', proof = null) {
    return new ValidationResult(NEUTRAL, reason, proof);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Ternary Logic Operations
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Combine two validation results using ternary AND.
   * Both must be VALID for result to be VALID.
   * If either is INVALID, result is INVALID.
   * Otherwise PENDING.
   */
  and(other) {
    const newState = this.#state.and(other.state);
    const reason = this.#reason || other.reason;
    const proof = this.#proof || other.proof;
    return new ValidationResult(newState, reason, proof);
  }
  
  /**
   * Combine two validation results using ternary OR.
   * Either being VALID makes result VALID.
   * Both must be INVALID for result to be INVALID.
   * Otherwise PENDING.
   */
  or(other) {
    const newState = this.#state.or(other.state);
    const reason = this.isValid ? null : (this.#reason || other.reason);
    const proof = this.#proof || other.proof;
    return new ValidationResult(newState, reason, proof);
  }
  
  /**
   * Consensus operation: agree on validity.
   * If both agree (same state), return that state.
   * If they disagree, return PENDING.
   */
  consensus(other) {
    const newState = this.#state.consensus(other.state);
    const reason = newState.isNeutral ? 'CONSENSUS_DISAGREEMENT' : this.#reason;
    return new ValidationResult(newState, reason, this.#proof);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Serialization
  // ─────────────────────────────────────────────────────────────────────────
  
  toJSON() {
    return deepFreeze({
      state: this.#state.value,         // -1, 0, or +1
      valid: this.#state.isPositive,    // Backwards compat
      isValid: this.#state.isPositive,
      isInvalid: this.#state.isNegative,
      isPending: this.#state.isNeutral,
      reason: this.#reason,
      proof: this.#proof,
      timestamp: this.#timestamp,
      oracleVersion: this.#oracleVersion,
    });
  }
  
  toString() {
    const stateStr = this.isValid ? 'VALID' : (this.isInvalid ? 'INVALID' : 'PENDING');
    return `ValidationResult(${stateStr}${this.#reason ? ': ' + this.#reason : ''})`;
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
 * SECURITY: Ignores __proto__, constructor, prototype keys
 */
export function deterministicStringify(obj, seen = new WeakSet()) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  
  // SECURITY: Detect circular references
  if (typeof obj === 'object') {
    if (seen.has(obj)) {
      return '"[Circular]"';
    }
    seen.add(obj);
  }
  
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => deterministicStringify(item, seen)).join(',') + ']';
  }
  
  if (typeof obj === 'object') {
    // SECURITY: Filter dangerous keys and use hasOwnProperty
    const keys = Object.keys(obj)
      .filter(k => k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
      .filter(k => Object.prototype.hasOwnProperty.call(obj, k))
      .sort();
    const pairs = keys.map(k => JSON.stringify(k) + ':' + deterministicStringify(obj[k], seen));
    return '{' + pairs.join(',') + '}';
  }
  
  return String(obj);
}

/**
 * SECURITY: Validation lock to prevent race conditions
 */
class ValidationLock {
  #locks = new Map();
  #maxConcurrent = 100;
  
  async acquire(key) {
    if (this.#locks.size >= this.#maxConcurrent) {
      throw new Error('MAX_CONCURRENT_VALIDATIONS');
    }
    
    while (this.#locks.has(key)) {
      await new Promise(resolve => setTimeout(resolve, 1));
    }
    
    this.#locks.set(key, Date.now());
    return () => this.#locks.delete(key);
  }
  
  isLocked(key) {
    return this.#locks.has(key);
  }
}

/**
 * The Validation Oracle - HARDENED VERSION
 * Self-verifying, deterministic, tamper-resistant validation engine
 */
export class ValidationOracle {
  // SECURITY: Private fields cannot be accessed externally
  #initialized = false;
  #selfHash = null;
  #functionRegistry = new Map();
  #testVectors = [];
  #behaviorFingerprint = null;
  #validationLock = new ValidationLock();
  #submissionCache = new Map();
  #frozen = false;
  
  // SECURITY: Rate limiting
  #rateLimits = new Map();
  #maxRequestsPerSecond = 100;
  
  constructor() {
    // SECURITY: Prevent prototype pollution on this instance
    Object.setPrototypeOf(this, ValidationOracle.prototype);
    
    this.#initialize();
    
    // SECURITY: Freeze the prototype to prevent method modification
    Object.freeze(ValidationOracle.prototype);
  }
  
  /**
   * Initialize the oracle and verify its own integrity
   */
  #initialize() {
    log.info('Initializing Validation Oracle (HARDENED)');
    
    // 1. Compute hash of our own source code
    this.#selfHash = this.#computeSelfHash();
    log.debug('Self-hash computed', { hash: this.#selfHash.slice(0, 16) });
    
    // 2. Register all validation functions with their hashes
    this.#registerFunctions();
    
    // 3. Generate behavior fingerprint from test vectors
    this.#generateBehaviorFingerprint();
    
    // 4. Seal the module (only once - first instance wins)
    if (!MODULE_SEAL.frozen) {
      MODULE_SEAL.sourceHash = this.#selfHash;
      MODULE_SEAL.functionHashes = Object.fromEntries(this.#functionRegistry);
      MODULE_SEAL.behaviorFingerprint = this.#behaviorFingerprint;
      MODULE_SEAL.genesisTimestamp = Date.now();
      MODULE_SEAL.frozen = true;
      
      // SECURITY: Freeze MODULE_SEAL
      deepFreeze(MODULE_SEAL);
    }
    
    this.#initialized = true;
    log.info('Validation Oracle initialized and sealed (HARDENED)');
  }
  
  /**
   * SECURITY: Freeze the oracle instance after initialization
   * Once frozen, no modifications are possible
   */
  freeze() {
    if (this.#frozen) return;
    this.#frozen = true;
    Object.freeze(this);
    log.info('Oracle instance frozen - no further modifications possible');
  }
  
  /**
   * Compute hash of all critical source files
   * This ensures nodes with different codebases cannot peer
   * 
   * SECURITY: Hashes the ENTIRE codebase, not just selected files.
   * Any modification to ANY source file will produce a different hash,
   * making it impossible for nodes with different code to communicate.
   * 
   * This is the core of the Code Proof Protocol: mathematical certainty
   * that all peering nodes run identical code.
   */
  #computeSelfHash() {
    try {
      // Get the root directory (parent of oracle/)
      const rootDir = join(__dirname, '..');
      
      // Collect ALL source files recursively
      const allSources = [];
      this.#walkDirectory(rootDir, allSources);
      
      // Sort for deterministic ordering across all platforms
      allSources.sort((a, b) => a.path.localeCompare(b.path));
      
      // Compute hash of entire codebase
      const codebaseContent = allSources
        .map(f => `=== ${f.path} ===\n${f.content}`)
        .join('\n');
      
      return contentHash(codebaseContent);
    } catch (e) {
      log.error('Failed to hash codebase', { error: e.message });
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
   * Recursively walk directory and collect all source files
   * @private
   */
  #walkDirectory(dir, results, baseDir = null) {
    if (!baseDir) baseDir = dir;
    
    // Directories to EXCLUDE from hash (not part of codebase logic)
    const EXCLUDE_DIRS = [
      'node_modules',  // Dependencies (version-locked via package-lock.json)
      '.git',          // Git metadata
      'data',          // Runtime data
      'database',      // User data
      'logs',          // Runtime logs
      '.vscode',       // Editor config
      'coverage',      // Test coverage
      'dist',          // Build output
      'build',         // Build output
    ];
    
    // File extensions that ARE part of the codebase
    const SOURCE_EXTENSIONS = [
      '.js', '.mjs', '.cjs',  // JavaScript
      '.json',                 // Config (package.json matters!)
      '.ts', '.tsx',          // TypeScript (if any)
    ];
    
    // Files to explicitly EXCLUDE
    const EXCLUDE_FILES = [
      'package-lock.json',    // Too volatile, deps locked by package.json
      '.env',                 // Environment-specific
      '.env.local',
    ];
    
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        // ═══════════════════════════════════════════════════════════════════════
        // CRITICAL: Normalize ALL paths to forward slashes for cross-platform
        // consistency. Without this, Windows (\) and Linux (/) produce different
        // hashes for identical codebases, causing network fragmentation.
        // DO NOT CHANGE THIS LINE without understanding the consequences.
        // ═══════════════════════════════════════════════════════════════════════
        const relativePath = fullPath.replace(baseDir, '').replace(/^[/\\]/, '').replace(/\\/g, '/');
        
        if (entry.isDirectory()) {
          // Skip excluded directories
          if (EXCLUDE_DIRS.includes(entry.name)) continue;
          // Recurse into subdirectory
          this.#walkDirectory(fullPath, results, baseDir);
        } else if (entry.isFile()) {
          // Skip excluded files
          if (EXCLUDE_FILES.includes(entry.name)) continue;
          
          // Check extension
          const ext = entry.name.slice(entry.name.lastIndexOf('.'));
          if (!SOURCE_EXTENSIONS.includes(ext)) continue;
          
          // Read and store file content
          try {
            const content = readFileSync(fullPath, 'utf-8');
            results.push({ path: relativePath, content });
          } catch (readErr) {
            // Include read errors in hash (missing file = different hash)
            results.push({ path: relativePath, content: `ERROR: ${readErr.message}` });
          }
        }
      }
    } catch (dirErr) {
      log.warn('Cannot read directory', { dir, error: dirErr.message });
    }
  }
  
  /**
   * Register validation functions with their source hashes
   */
  #registerFunctions() {
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
      this.#functionRegistry.set(name, fnHash);
    }
  }
  
  /**
   * Generate behavior fingerprint from test vectors
   */
  #generateBehaviorFingerprint() {
    this.#testVectors = [
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
        fn: 'validateListing',
        input: { title: 'Test', price: 0.0001, currency: 'BTC', user_id: 1 },
        expectedValid: true,
      },
      {
        fn: 'validateListing',
        input: { title: 'Test', price: Number.MAX_SAFE_INTEGER, currency: 'BTC', user_id: 1 },
        expectedValid: true,
      },
    ];
    
    const outputs = this.#testVectors.map(tv => {
      if (tv.fn === 'validateListing') {
        return this.validateListing(tv.input).valid;
      }
      return null;
    });
    
    this.#behaviorFingerprint = contentHash(outputs);
  }
  
  // ============================================================
  // PUBLIC GETTERS (no setters - immutable)
  // ============================================================
  
  get selfHash() {
    return this.#selfHash;
  }
  
  get behaviorFingerprint() {
    return this.#behaviorFingerprint;
  }
  
  get isInitialized() {
    return this.#initialized;
  }
  
  get isFrozen() {
    return this.#frozen;
  }
  
  // ============================================================
  // SELF-VERIFICATION METHODS
  // ============================================================
  
  /**
   * Verify own integrity - call this periodically
   */
  verifySelfIntegrity() {
    const currentHash = this.#computeSelfHash();
    
    if (currentHash !== this.#selfHash) {
      throw new Error(`INTEGRITY VIOLATION: Code has been modified! ` +
        `Expected ${this.#selfHash}, got ${currentHash}`);
    }
    
    // Also verify behavior fingerprint
    const currentBehavior = this.#testVectors.map(tv => {
      if (tv.fn === 'validateListing') {
        return this.validateListing(tv.input).valid;
      }
      return null;
    });
    
    const currentFingerprint = contentHash(currentBehavior);
    if (currentFingerprint !== this.#behaviorFingerprint) {
      throw new Error(`BEHAVIOR VIOLATION: Validation logic has changed!`);
    }
    
    return ValidationResult.success({ selfHash: this.#selfHash });
  }
  
  /**
   * Generate a proof that we're running the correct code
   */
  generateCodeProof(challenge = null) {
    const effectiveChallenge = challenge || this.#selfHash;
    const proofInput = effectiveChallenge + this.#selfHash + this.#behaviorFingerprint;
    const response = contentHash(proofInput);
    
    return deepFreeze({
      oracleVersion: MODULE_SEAL.version,
      selfHash: this.#selfHash,
      behaviorFingerprint: this.#behaviorFingerprint,
      challenge: effectiveChallenge,
      response: response,
      functionHashes: Object.fromEntries(this.#functionRegistry),
      timestamp: Date.now(),
      version: MODULE_SEAL.version,
    });
  }
  
  /**
   * Verify another node's code proof
   */
  verifyCodeProof(proof) {
    if (!proof || typeof proof !== 'object') {
      return ValidationResult.failure('INVALID_PROOF_FORMAT');
    }
    
    if (proof.selfHash !== this.#selfHash) {
      return ValidationResult.failure('SELF_HASH_MISMATCH');
    }
    
    if (proof.behaviorFingerprint !== this.#behaviorFingerprint) {
      return ValidationResult.failure('BEHAVIOR_FINGERPRINT_MISMATCH');
    }
    
    const expectedResponse = contentHash(
      proof.challenge + this.#selfHash + this.#behaviorFingerprint
    );
    
    if (proof.response !== expectedResponse) {
      return ValidationResult.failure('CHALLENGE_RESPONSE_INVALID');
    }
    
    for (const [name, hash] of this.#functionRegistry) {
      if (safeGet(proof.functionHashes, name) !== hash) {
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

  getValidationMethods() {
    return ['listing', 'qcoa', 'user'];
  }

  async validate(contentType, content) {
    // SECURITY: Rate limiting
    const now = Date.now();
    const key = `validate:${contentType}`;
    const lastRequest = this.#rateLimits.get(key) || 0;
    
    if (now - lastRequest < 1000 / this.#maxRequestsPerSecond) {
      return { valid: false, errors: ['RATE_LIMITED'] };
    }
    this.#rateLimits.set(key, now);
    
    let validationResult;
    
    switch (contentType) {
      case 'listing':
        validationResult = await this.validateListingAsync(content);
        break;
      case 'qcoa':
        validationResult = this.validateQCoA(content);
        break;
      case 'user':
        validationResult = this.validateUser(content);
        break;
      default:
        return { valid: false, errors: [`Unknown content type: ${contentType}`] };
    }
    
    if (!validationResult.valid) {
      return { valid: false, errors: [validationResult.reason] };
    }
    
    return deepFreeze({
      valid: true,
      contentHash: contentHash(content),
      validatorHash: this.#selfHash,
      validatedAt: Date.now(),
    });
  }
  
  // ============================================================
  // VALIDATION FUNCTIONS - Pure, deterministic, tamper-resistant
  // ============================================================
  
  /**
   * SECURITY: Async validation with locking to prevent race conditions
   */
  async validateListingAsync(listing) {
    if (!listing) {
      return ValidationResult.failure('LISTING_NULL');
    }
    
    const lockKey = listing.id || contentHash(listing);
    const release = await this.#validationLock.acquire(lockKey);
    
    try {
      // Check for duplicate submission
      const listingHash = contentHash(listing);
      if (this.#submissionCache.has(listingHash)) {
        return ValidationResult.failure('DUPLICATE_SUBMISSION');
      }
      
      const result = this.validateListing(listing);
      
      if (result.valid) {
        // Cache successful validations to prevent duplicates
        this.#submissionCache.set(listingHash, Date.now());
        
        // Cleanup old cache entries (older than 1 hour)
        const oneHourAgo = Date.now() - 3600000;
        for (const [hash, time] of this.#submissionCache) {
          if (time < oneHourAgo) {
            this.#submissionCache.delete(hash);
          }
        }
      }
      
      return result;
    } finally {
      release();
    }
  }
  
  /**
   * Validate a marketplace listing
   * SECURITY: Comprehensive input validation
   */
  validateListing(listing) {
    // Required fields check
    if (!listing || typeof listing !== 'object') {
      return ValidationResult.failure('LISTING_NULL');
    }
    
    // SECURITY: Prevent prototype pollution - check own properties only
    if (Object.prototype.hasOwnProperty.call(listing, '__proto__') || 
        Object.prototype.hasOwnProperty.call(listing, 'constructor') || 
        Object.prototype.hasOwnProperty.call(listing, 'prototype')) {
      return ValidationResult.failure('INVALID_LISTING_STRUCTURE');
    }
    
    // Title validation
    const title = safeGet(listing, 'title');
    if (!title || typeof title !== 'string') {
      return ValidationResult.failure('INVALID_TITLE');
    }
    
    if (title.length === 0 || title.length > 200) {
      return ValidationResult.failure('TITLE_LENGTH_INVALID');
    }
    
    // SECURITY: Check for control characters in title
    if (/[\x00-\x1F\x7F]/.test(title)) {
      return ValidationResult.failure('INVALID_TITLE_CHARS');
    }
    
    // Price validation - HARDENED
    const price = safeGet(listing, 'price');
    if (typeof price !== 'number') {
      return ValidationResult.failure('INVALID_PRICE_TYPE');
    }
    
    // SECURITY: Comprehensive price validation
    if (!Number.isFinite(price)) {
      return ValidationResult.failure('INVALID_PRICE_INFINITE');
    }
    
    if (price <= 0) {
      return ValidationResult.failure('INVALID_PRICE_NEGATIVE');
    }
    
    // SECURITY: Minimum price (prevent dust attacks)
    if (price < 0.00000001) {
      return ValidationResult.failure('PRICE_TOO_SMALL');
    }
    
    // SECURITY: Maximum price (prevent overflow)
    if (price > Number.MAX_SAFE_INTEGER) {
      return ValidationResult.failure('PRICE_TOO_LARGE');
    }
    
    // Currency validation
    const currency = safeGet(listing, 'currency');
    if (!currency || typeof currency !== 'string') {
      return ValidationResult.failure('INVALID_CURRENCY');
    }
    
    // SECURITY: Strict currency validation (alphanumeric only, max 10 chars)
    if (!/^[A-Za-z0-9]{1,10}$/.test(currency)) {
      return ValidationResult.failure('INVALID_CURRENCY_FORMAT');
    }
    
    const validCurrencies = ['BTC', 'ETH', 'QRL', 'USD', 'EUR', 'GBP'];
    if (!validCurrencies.includes(currency.toUpperCase())) {
      return ValidationResult.failure('UNSUPPORTED_CURRENCY');
    }
    
    // User ID validation
    const userId = safeGet(listing, 'user_id');
    if (typeof userId !== 'number' || !Number.isInteger(userId) || userId <= 0) {
      return ValidationResult.failure('INVALID_USER_ID');
    }
    
    // Trade type validation
    const tradeType = safeGet(listing, 'trade_type');
    if (tradeType && !['buy', 'sell'].includes(tradeType)) {
      return ValidationResult.failure('INVALID_TRADE_TYPE');
    }
    
    // Compute content hash for the listing
    const listingHash = contentHash({
      title: title,
      price: price,
      currency: currency.toUpperCase(),
      user_id: userId,
      trade_type: tradeType || 'sell',
    });
    
    return ValidationResult.success({ contentHash: listingHash });
  }
  
  /**
   * Validate a user identity
   */
  validateUser(user) {
    if (!user || typeof user !== 'object') {
      return ValidationResult.failure('USER_NULL');
    }
    
    const userId = safeGet(user, 'user_id');
    if (typeof userId !== 'number' || !Number.isInteger(userId) || userId <= 0) {
      return ValidationResult.failure('INVALID_USER_ID');
    }
    
    const username = safeGet(user, 'username');
    if (!username || typeof username !== 'string') {
      return ValidationResult.failure('INVALID_USERNAME');
    }
    
    if (username.length < 3 || username.length > 50) {
      return ValidationResult.failure('USERNAME_LENGTH_INVALID');
    }
    
    // SECURITY: Username must be alphanumeric with underscores only
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return ValidationResult.failure('INVALID_USERNAME_CHARS');
    }
    
    const publicKey = safeGet(user, 'public_key');
    if (publicKey) {
      if (typeof publicKey !== 'string' || !/^[a-fA-F0-9]{64,}$/.test(publicKey)) {
        return ValidationResult.failure('INVALID_PUBLIC_KEY_FORMAT');
      }
    }
    
    return ValidationResult.success({ userId: userId });
  }
  
  /**
   * Validate a cryptographic signature (ML-DSA-65)
   */
  validateSignature(message, signature, publicKey) {
    if (!message || !signature || !publicKey) {
      return ValidationResult.failure('MISSING_SIGNATURE_PARAMS');
    }
    
    // SECURITY: Validate hex format
    if (!/^[a-fA-F0-9]+$/.test(signature) || !/^[a-fA-F0-9]+$/.test(publicKey)) {
      return ValidationResult.failure('INVALID_HEX_FORMAT');
    }
    
    try {
      const messageBytes = typeof message === 'string' 
        ? utf8ToBytes(message) 
        : message;
      const sigBytes = hexToBytes(signature);
      const pubKeyBytes = hexToBytes(publicKey);
      
      // ML-DSA65 verify order: (signature, message, publicKey)
      const valid = ml_dsa65.verify(sigBytes, messageBytes, pubKeyBytes);
      
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
   */
  validateQCoA(certificate) {
    if (!certificate || typeof certificate !== 'object') {
      return ValidationResult.failure('CERTIFICATE_NULL');
    }
    
    const required = ['cert_hash', 'origin_public_key', 'origin_signature', 'asset_type'];
    for (const field of required) {
      if (!safeGet(certificate, field)) {
        return ValidationResult.failure(`MISSING_FIELD: ${field}`);
      }
    }
    
    // SECURITY: Validate formats
    const certHash = safeGet(certificate, 'cert_hash');
    const publicKey = safeGet(certificate, 'origin_public_key');
    const signature = safeGet(certificate, 'origin_signature');
    
    if (!/^[a-fA-F0-9]+$/.test(certHash)) {
      return ValidationResult.failure('INVALID_CERT_HASH_FORMAT');
    }
    
    if (!/^[a-fA-F0-9]+$/.test(publicKey)) {
      return ValidationResult.failure('INVALID_PUBLIC_KEY_FORMAT');
    }
    
    if (!/^[a-fA-F0-9]+$/.test(signature)) {
      return ValidationResult.failure('INVALID_SIGNATURE_FORMAT');
    }
    
    // Verify the signature
    try {
      const sigResult = this.validateSignature(
        certHash,
        signature,
        publicKey
      );
      
      if (!sigResult.valid) {
        return ValidationResult.failure('QCOA_SIGNATURE_INVALID');
      }
    } catch (e) {
      return ValidationResult.failure(`QCOA_SIGNATURE_ERROR: ${e.message}`);
    }
    
    return ValidationResult.success({
      certHash: certHash,
      assetType: safeGet(certificate, 'asset_type'),
      verified: true,
    });
  }
  
  /**
   * Deterministic conflict resolution
   * Two nodes with the same inputs will always pick the same winner
   */
  resolveConflict(entry1, entry2) {
    if (!entry1 && !entry2) return null;
    if (!entry1) return entry2;
    if (!entry2) return entry1;
    
    const hash1 = contentHash(entry1);
    const hash2 = contentHash(entry2);
    
    // SECURITY: Pure deterministic - hash comparison
    if (hash1 < hash2) return entry1;
    if (hash2 < hash1) return entry2;
    
    // If hashes are equal, they're the same content
    return entry1;
  }
  
  /**
   * Compute trust score for a user based on history
   */
  computeTrustScore(userHistory) {
    if (!userHistory || !Array.isArray(userHistory)) {
      return 0;
    }
    
    // Pure function - same history always gives same score
    let score = 0;
    
    for (const event of userHistory) {
      const type = safeGet(event, 'type');
      const success = safeGet(event, 'success');
      const verified = safeGet(event, 'verified');
      
      if (type === 'trade' && success === true) {
        score += 10;
      }
      if (type === 'attestation' && verified === true) {
        score += 5;
      }
      if (type === 'dispute' && safeGet(event, 'lost') === true) {
        score -= 20;
      }
    }
    
    // Normalize to 0-100
    return Math.max(0, Math.min(100, score));
  }
}

// ============================================================
// SINGLETON EXPORT with security hardening
// ============================================================

let oracleInstance = null;

export function getOracle() {
  if (!oracleInstance) {
    oracleInstance = new ValidationOracle();
    oracleInstance.freeze();
  }
  return oracleInstance;
}

export function createOracle() {
  const oracle = new ValidationOracle();
  oracle.freeze();
  return oracle;
}

// Export for testing
export { MODULE_SEAL, deepFreeze, safeGet, createSafeObject };
