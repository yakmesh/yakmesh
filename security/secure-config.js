/**
 * Yakmesh Secure Defaults + Oracle-Attested Configuration
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PHILOSOPHY: THE ORACLE ATTESTS YOUR CONFIG
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Traditional secure defaults: Ship with good defaults, hope no one changes them.
 * Oracle-attested config: Runtime config is hashed and verified.
 * 
 * The Oracle maintains a "secure profile" — a hash of known-good configuration.
 * At startup and periodically, the actual config is compared against this profile.
 * 
 * If someone relaxes security settings (larger request sizes, longer timeouts,
 * disabled features), the config hash changes and the Oracle reports a violation.
 * 
 * This creates cryptographic accountability for configuration changes.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SECURE PROFILE LEVELS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * PARANOID:   Maximum security, minimal attack surface, may break some features
 * HARDENED:   Production-ready security, all protections enabled
 * STANDARD:   Balanced security with reasonable defaults
 * DEVELOPMENT: Relaxed for local development (warnings only, no enforcement)
 * 
 * @module security/secure-config
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';
import { sha3_256 } from '../utils/accel.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { EventEmitter } from 'events';

const log = createLogger('security:secure-config');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Security profile levels */
export const PROFILE_LEVEL = {
  PARANOID: 'PARANOID',
  HARDENED: 'HARDENED',
  STANDARD: 'STANDARD',
  DEVELOPMENT: 'DEVELOPMENT',
};

/** Default secure configuration values */
export const SECURE_DEFAULTS = {
  // -------------------------------------------------------------------------
  // NETWORK
  // -------------------------------------------------------------------------
  network: {
    maxConnections: 100,          // Max simultaneous peer connections
    connectionTimeout: 30000,     // Connection timeout (ms)
    handshakeTimeout: 10000,      // Handshake timeout (ms)
    maxMessageSize: 65536,        // Max message size (64 KB)
    heartbeatInterval: 30000,     // Heartbeat interval (ms)
    heartbeatTimeout: 90000,      // Heartbeat timeout (ms)
    minReconnectDelay: 1000,      // Min reconnect delay (ms)
    maxReconnectDelay: 60000,     // Max reconnect delay (ms)
  },
  
  // -------------------------------------------------------------------------
  // RATE LIMITING (per KARMA tier)
  // -------------------------------------------------------------------------
  rateLimiting: {
    unknown: 10,     // Requests/min for unknown peers
    hostile: 2,      // Requests/min for hostile peers
    low: 25,         // Requests/min for low-KARMA peers
    medium: 50,      // Requests/min for medium-KARMA peers
    high: 100,       // Requests/min for high-KARMA peers
    excellent: 200,  // Requests/min for excellent-KARMA peers
    burstMultiplier: 2,  // Burst allowance multiplier
  },
  
  // -------------------------------------------------------------------------
  // CRYPTO
  // -------------------------------------------------------------------------
  crypto: {
    algorithm: 'ML-DSA-65',       // Primary signing algorithm
    kemAlgorithm: 'ML-KEM-768',   // Key encapsulation mechanism
    hashAlgorithm: 'SHA3-256',    // Hash algorithm
    keyRotationInterval: 300000,  // TRIBHUJ rotation (5 min)
    sessionTimeout: 3600000,      // Session timeout (1 hour)
    nonceCacheSize: 10000,        // Replay nonce cache size
    nonceCacheTTL: 600000,        // Nonce TTL (10 min)
  },
  
  // -------------------------------------------------------------------------
  // IDENTITY
  // -------------------------------------------------------------------------
  identity: {
    dokoRequireSignature: true,   // Require DOKO signature verification
    dokoMaxAge: 86400000,         // Max DOKO age (24 hours)
    trustNewPeers: false,         // Don't trust new peers by default
    requireAttestation: true,     // Require attestation for sensitive ops
  },
  
  // -------------------------------------------------------------------------
  // CONTENT
  // -------------------------------------------------------------------------
  content: {
    maxUploadSize: 16777216,      // Max upload size (16 MB)
    maxDownloadSize: 67108864,    // Max download size (64 MB)
    requireDARSHAN: true,         // Require DARSHAN for streaming
    allowUnverified: false,       // Don't serve unverified content
  },
  
  // -------------------------------------------------------------------------
  // GOSSIP
  // -------------------------------------------------------------------------
  gossip: {
    maxPayloadSize: 4096,         // Max gossip payload (4 KB)
    ttlMax: 10,                   // Max TTL hops
    duplicateWindow: 60000,       // Duplicate detection window (1 min)
    propagationDelay: 100,        // Propagation delay (ms)
  },
  
  // -------------------------------------------------------------------------
  // ORACLE
  // -------------------------------------------------------------------------
  oracle: {
    hashAlgorithm: 'SHA3-256',    // Oracle hash algorithm
    verifyOnStart: true,          // Verify codebase on startup
    watchForTampering: true,      // Monitor for runtime tampering
    lockCodebase: true,           // Lock codebase files
  },
  
  // -------------------------------------------------------------------------
  // SANGHA
  // -------------------------------------------------------------------------
  sangha: {
    circulationInterval: 5000,    // Attestation circulation (5 sec)
    staleThreshold: 10000,        // Stale attestation threshold (10 sec)
    quorumPercentage: 0.67,       // Required quorum for consensus
    anomalyThreshold: 0.5,        // Anomaly detection threshold
  },
  
  // -------------------------------------------------------------------------
  // FS HARDENING
  // -------------------------------------------------------------------------
  fsHardening: {
    protectIdentityFiles: true,   // Lock identity files
    protectDatabase: true,        // Monitor database file
    verificationInterval: 30000,  // Verification interval (30 sec)
    gracePeriod: 5000,            // Startup grace period (5 sec)
  },
  
  // -------------------------------------------------------------------------
  // MEMORY SAFETY
  // -------------------------------------------------------------------------
  memorySafety: {
    enableCanaries: true,         // Enable memory canaries
    heapCanaries: 3,              // Number of heap canaries
    closureCanaries: 2,           // Number of closure canaries
    nativeCanaries: 2,            // Number of native canaries
    monitorInterval: 5000,        // Monitor interval (5 sec)
  },
};

// =============================================================================
// PROFILE MODIFICATIONS
// =============================================================================

/** Profile-specific overrides */
const PROFILE_OVERRIDES = {
  [PROFILE_LEVEL.PARANOID]: {
    network: { maxConnections: 50, maxMessageSize: 32768 },
    rateLimiting: { unknown: 5, hostile: 1 },
    identity: { dokoMaxAge: 43200000 }, // 12 hours
    content: { allowUnverified: false, maxUploadSize: 8388608 }, // 8 MB
    gossip: { ttlMax: 5 },
  },
  [PROFILE_LEVEL.HARDENED]: {
    // Uses all secure defaults
  },
  [PROFILE_LEVEL.STANDARD]: {
    network: { maxConnections: 200 },
    rateLimiting: { unknown: 20 },
    identity: { trustNewPeers: false },
  },
  [PROFILE_LEVEL.DEVELOPMENT]: {
    network: { maxConnections: 500, maxMessageSize: 1048576 },
    rateLimiting: { unknown: 100, hostile: 10 },
    identity: { trustNewPeers: true, requireAttestation: false },
    content: { allowUnverified: true },
    oracle: { lockCodebase: false, watchForTampering: false },
    fsHardening: { protectIdentityFiles: false },
    memorySafety: { enableCanaries: false },
  },
};

// =============================================================================
// SECURE CONFIG MANAGER
// =============================================================================

/**
 * SecureConfigManager — Oracle-attested configuration management
 */
export class SecureConfigManager extends EventEmitter {
  #config;
  #profileLevel;
  #profileHash;
  #actualHash;
  #sangha;
  #deviations;
  #lastVerification;
  
  constructor(profileLevel = PROFILE_LEVEL.HARDENED) {
    super();
    this.#profileLevel = profileLevel;
    this.#config = this.#buildConfig(profileLevel);
    this.#profileHash = this.#computeHash(this.#config);
    this.#actualHash = this.#profileHash;
    this.#sangha = null;
    this.#deviations = [];
    this.#lastVerification = Date.now();
    
    log.info('Secure config manager initialized', {
      profile: profileLevel,
      hash: this.#profileHash.slice(0, 16) + '...',
    });
    
    Object.seal(this);
  }
  
  /**
   * Build configuration for a profile level
   */
  #buildConfig(level) {
    // Start with secure defaults
    const config = JSON.parse(JSON.stringify(SECURE_DEFAULTS));
    
    // Apply profile overrides
    const overrides = PROFILE_OVERRIDES[level] || {};
    for (const [section, values] of Object.entries(overrides)) {
      if (config[section]) {
        Object.assign(config[section], values);
      }
    }
    
    return config;
  }
  
  /**
   * Compute SHA3-256 hash of configuration
   */
  #computeHash(config) {
    const json = JSON.stringify(config, Object.keys(config).sort());
    const hash = sha3_256(new TextEncoder().encode(json));
    return bytesToHex(hash);
  }
  
  /**
   * Get a configuration value
   * @param {string} path - Dot-separated path (e.g., 'network.maxConnections')
   * @returns {any}
   */
  get(path) {
    const parts = path.split('.');
    let value = this.#config;
    
    for (const part of parts) {
      if (value === undefined || value === null) return undefined;
      value = value[part];
    }
    
    return value;
  }
  
  /**
   * Set a configuration value (tracks deviations)
   * @param {string} path - Dot-separated path
   * @param {any} value - New value
   */
  set(path, value) {
    const parts = path.split('.');
    const key = parts.pop();
    let target = this.#config;
    
    for (const part of parts) {
      if (target[part] === undefined) {
        target[part] = {};
      }
      target = target[part];
    }
    
    const oldValue = target[key];
    target[key] = value;
    
    // Track deviation
    if (oldValue !== value) {
      this.#deviations.push({
        path,
        oldValue,
        newValue: value,
        timestamp: Date.now(),
      });
      
      log.warn('Configuration deviation', { path, oldValue, newValue: value });
    }
    
    // Recompute actual hash
    this.#actualHash = this.#computeHash(this.#config);
    
    // Check if we've deviated from profile
    if (this.#actualHash !== this.#profileHash) {
      this.emit('deviation', {
        profileLevel: this.#profileLevel,
        deviations: this.#deviations,
      });
    }
  }
  
  /**
   * Verify configuration matches expected profile
   * @returns {{ valid: boolean, deviations: object[], hash: string }}
   */
  verify() {
    this.#lastVerification = Date.now();
    this.#actualHash = this.#computeHash(this.#config);
    
    const valid = this.#actualHash === this.#profileHash;
    
    if (!valid) {
      log.warn('Configuration verification failed', {
        expected: this.#profileHash.slice(0, 16) + '...',
        actual: this.#actualHash.slice(0, 16) + '...',
        deviations: this.#deviations.length,
      });
    }
    
    return {
      valid,
      profileLevel: this.#profileLevel,
      expectedHash: this.#profileHash,
      actualHash: this.#actualHash,
      deviations: [...this.#deviations],
    };
  }
  
  /**
   * Reset to profile defaults
   */
  reset() {
    this.#config = this.#buildConfig(this.#profileLevel);
    this.#actualHash = this.#profileHash;
    this.#deviations = [];
    
    log.info('Configuration reset to profile defaults', {
      profile: this.#profileLevel,
    });
    
    this.emit('reset', { profileLevel: this.#profileLevel });
  }
  
  /**
   * Get the full configuration object (read-only copy)
   */
  getAll() {
    return JSON.parse(JSON.stringify(this.#config));
  }
  
  /**
   * Get a section of the configuration
   */
  getSection(section) {
    return this.#config[section]
      ? JSON.parse(JSON.stringify(this.#config[section]))
      : undefined;
  }
  
  /**
   * Bind SANGHA for collective verification
   */
  bindSangha(sangha) {
    this.#sangha = sangha;
    log.info('Secure config bound to SANGHA collective');
  }
  
  /**
   * Get state for SANGHA attestation
   */
  getState() {
    return {
      component: 'config',
      profileLevel: this.#profileLevel,
      profileHash: this.#profileHash,
      actualHash: this.#actualHash,
      isValid: this.#actualHash === this.#profileHash,
      deviations: this.#deviations.length,
      lastVerification: this.#lastVerification,
    };
  }
  
  /**
   * Get status for API
   */
  getStatus() {
    return {
      profileLevel: this.#profileLevel,
      profileHash: this.#profileHash,
      actualHash: this.#actualHash,
      isValid: this.#actualHash === this.#profileHash,
      deviations: this.#deviations.length,
      lastVerification: this.#lastVerification,
      sanghaBound: !!this.#sangha,
    };
  }
  
  /**
   * Get profile level
   */
  getProfileLevel() {
    return this.#profileLevel;
  }
  
  /**
   * Check if running in development mode
   */
  isDevelopment() {
    return this.#profileLevel === PROFILE_LEVEL.DEVELOPMENT;
  }
  
  /**
   * Check if a feature is enabled by the config
   */
  isEnabled(feature) {
    switch (feature) {
      case 'codebaseLock':
        return this.get('oracle.lockCodebase');
      case 'tamperWatch':
        return this.get('oracle.watchForTampering');
      case 'canaries':
        return this.get('memorySafety.enableCanaries');
      case 'fsHardening':
        return this.get('fsHardening.protectIdentityFiles');
      case 'attestation':
        return this.get('identity.requireAttestation');
      case 'darshan':
        return this.get('content.requireDARSHAN');
      default:
        return true;
    }
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let _instance = null;

/**
 * Get the SecureConfigManager singleton
 * @param {string} profileLevel - Profile level (only used on first call)
 * @returns {SecureConfigManager}
 */
export function getSecureConfig(profileLevel) {
  if (!_instance) {
    // Detect profile from environment
    const envProfile = process.env.YAKMESH_SECURITY_PROFILE;
    const level = profileLevel || envProfile || PROFILE_LEVEL.HARDENED;
    _instance = new SecureConfigManager(level);
  }
  return _instance;
}

export default SecureConfigManager;
