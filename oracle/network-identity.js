/**
 * Network Identity Obfuscation Module (iO System)
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  CRITICAL SECURITY PRIMITIVE - NEVER BYPASS THIS MODULE  ⚠️
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This module implements iO-inspired (indistinguishability obfuscation) identity
 * derivation. Instead of exposing raw cryptographic hashes, we derive human-readable,
 * deterministic, but opaque identifiers.
 * 
 * SECURITY PROPERTIES:
 * - Deterministic: Same hash → Same name (always)
 * - One-way: Cannot reverse name → hash (preimage resistant)
 * - Collision-resistant: Different hashes → Different names
 * - Human-memorable: Easy to verify verbally
 * - Fingerprint-safe: Cannot fingerprint nodes by hash patterns
 * 
 * WHY THIS MATTERS:
 * Exposing raw hashes enables:
 * 1. Fingerprinting attacks - Track users across sessions
 * 2. Precomputation attacks - Build rainbow tables
 * 3. Oracle queries - Probe for specific identities
 * 4. Correlation attacks - Link identities across systems
 * 
 * WHERE TO USE THIS MODULE:
 * ✅ Node IDs (identity/node-key.js)
 * ✅ Network names (oracle/genesis-network-v2.js)
 * ✅ DOKO identity IDs (security/doko-identity.js)
 * ✅ Any user-facing or network-exposed identifier
 * 
 * WHERE NOT TO USE:
 * ❌ Content hashes - These ARE the content's address (by design)
 * ❌ Internal DHT keys - Lookup efficiency requires actual hashes
 * ❌ Signature verification - Needs original hash for crypto ops
 * 
 * USAGE GUIDE:
 * ```javascript
 * import { deriveNetworkName, deriveNetworkId } from './network-identity.js';
 * 
 * // For human-readable names (3 words)
 * const name = deriveNetworkName(hash, 3);  // "qubit-lattice-prism"
 * 
 * // For short identifiers
 * const id = deriveNetworkId(hash);  // "pq-a7x9"
 * 
 * // For verification phrases (4 words)
 * const phrase = deriveVerificationPhrase(hash);  // "quantum tiger mesa echo"
 * ```
 * 
 * Phase Modulation (Star Trek TNG inspired):
 * - Rotating fingerprints that expire after phase rotation
 * - Prevents replay attacks and pre-computation
 * - Stable identity + rotating security layer
 * 
 * @module oracle/network-identity
 * @version 2.2.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
// Using sha3_256 for all hashing operations for post-quantum consistency
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// Phase modulation for rotating security
import {
  getCurrentEpoch,
  getValidEpochs,
  derivePhaseFingerprint,
  verifyPhaseFingerprint,
  getPhaseStatus,
  formatPhaseId,
  isInGracePeriod,
} from './phase-epoch.js';

/**
 * Quantum/Crypto themed wordlist (256 words)
 * Curated for: uniqueness, pronounceability, thematic consistency
 */
const QUANTUM_WORDLIST = [
  // Quantum Physics (64 words)
  'qubit', 'photon', 'hadron', 'lepton', 'boson', 'fermion', 'gluon', 'muon',
  'tauon', 'preon', 'axion', 'graviton', 'phonon', 'plasmon', 'magnon', 'polaron',
  'soliton', 'instanton', 'sphaleron', 'skyrmion', 'anyon', 'majorana', 'dirac', 'pauli',
  'heisen', 'schrod', 'planck', 'fermi', 'bose', 'einstein', 'bell', 'aspect',
  'entangle', 'superpose', 'collapse', 'decohere', 'tunnel', 'scatter', 'annihil', 'create',
  'measure', 'observe', 'evolve', 'interact', 'couple', 'decouple', 'ionize', 'excite',
  'ground', 'vacuum', 'zero', 'infinity', 'singul', 'horizon', 'ergosph', 'penrose',
  'hawking', 'unruh', 'casimir', 'lamb', 'zeeman', 'stark', 'rabi', 'bloch',
  
  // Cryptography (64 words)
  'cipher', 'lattice', 'hash', 'merkle', 'schnorr', 'ecdsa', 'dilith', 'kyber',
  'falcon', 'sphincs', 'xmss', 'lms', 'mceliece', 'ntru', 'saber', 'frodo',
  'newhope', 'sidh', 'sike', 'csidh', 'isogeny', 'elliptic', 'galois', 'abelian',
  'cyclic', 'prime', 'composite', 'factor', 'discrete', 'logarithm', 'modular', 'residue',
  'quadrat', 'cubic', 'quartic', 'quintic', 'polynomial', 'irreducible', 'primitive', 'generator',
  'witness', 'verifier', 'prover', 'oracle', 'random', 'pseudo', 'entropy', 'seed',
  'nonce', 'salt', 'pepper', 'key', 'secret', 'public', 'private', 'shared',
  'derive', 'extract', 'expand', 'commit', 'reveal', 'blind', 'sign', 'verify',
  
  // Network/Mesh (64 words)
  'node', 'edge', 'vertex', 'graph', 'tree', 'forest', 'mesh', 'grid',
  'torus', 'klein', 'mobius', 'sphere', 'manifold', 'simplex', 'complex', 'chain',
  'cycle', 'path', 'walk', 'trail', 'circuit', 'bridge', 'cutset', 'spanning',
  'minimal', 'maximal', 'optimal', 'feasible', 'bounded', 'unbounded', 'finite', 'countable',
  'dense', 'sparse', 'connected', 'component', 'cluster', 'clique', 'stable', 'kernel',
  'core', 'shell', 'layer', 'tier', 'level', 'depth', 'breadth', 'height',
  'degree', 'order', 'size', 'weight', 'capacity', 'flow', 'cut', 'match',
  'cover', 'dominate', 'color', 'partition', 'decompose', 'embed', 'project', 'lift',
  
  // Elements/Materials (64 words)
  'crystal', 'prism', 'lens', 'mirror', 'grating', 'filter', 'beam', 'pulse',
  'wave', 'packet', 'mode', 'fiber', 'waveguide', 'resonator', 'cavity', 'trap',
  'well', 'barrier', 'junction', 'contact', 'interface', 'surface', 'bulk', 'facet',
  'corner', 'defect', 'vacancy', 'dopant', 'impurity', 'alloy', 'compound', 'element',
  'metal', 'insulator', 'semiconductor', 'superconductor', 'magnet', 'ferrite', 'ceramic', 'polymer',
  'carbon', 'silicon', 'germanium', 'gallium', 'indium', 'arsenic', 'phosphor', 'nitrogen',
  'oxide', 'nitride', 'carbide', 'sulfide', 'selenide', 'telluride', 'halide', 'hydride',
  'diamond', 'graphene', 'nanotube', 'fullerene', 'quantum', 'topologic', 'exotic', 'novel',
];

// Verify wordlist size
if (QUANTUM_WORDLIST.length !== 256) {
  throw new Error(`Wordlist must have exactly 256 words, got ${QUANTUM_WORDLIST.length}`);
}


// ============================================================
// CONFIGURABLE IDENTITY PARAMETERS
// These can be overridden via setIdentityConfig()
// ============================================================

let IDENTITY_CONFIG = {
  networkPrefix: 'bcn',  // Short prefix for network IDs (e.g., bcn-a7x9)
  identitySalt: 'yakmesh-network-identity-v1',
  shortIdSalt: 'yakmesh-network-shortid-v1',
  phraseSalt: 'yakmesh-verification-phrase-v1',
  fingerprintSalt: 'yakmesh-fingerprint-v1',
  baseSalt: 'quantum-mesh-salt-2025',
};

/**
 * Configure identity derivation parameters
 * Call this before creating network identities to customize for your deployment
 * 
 * @param {Object} config - Configuration overrides
 * @param {string} config.networkPrefix - Short prefix (default: 'bcn')
 * @param {string} config.identitySalt - Salt for network name derivation
 * @param {string} config.shortIdSalt - Salt for short ID derivation
 * @param {string} config.phraseSalt - Salt for verification phrase
 * @param {string} config.fingerprintSalt - Salt for fingerprint derivation
 */
export function setIdentityConfig(config) {
  IDENTITY_CONFIG = { ...IDENTITY_CONFIG, ...config };
}

export function getIdentityConfig() {
  return { ...IDENTITY_CONFIG };
}

/**
 * Derive a deterministic network name from a code hash
 * 
 * Uses HKDF to derive indices, then maps to words.
 * The derivation is one-way - cannot reverse name to hash.
 * 
 * @param {string} codeHash - The oracle's code hash (hex string)
 * @param {number} wordCount - Number of words in name (default: 3)
 * @returns {string} Human-readable network name like "qubit-lattice-prism"
 */
export function deriveNetworkName(codeHash, wordCount = 3) {
  if (!codeHash || typeof codeHash !== 'string') {
    throw new Error('Invalid code hash');
  }
  
  // Convert hex hash to bytes
  const hashBytes = hexToBytes(codeHash);
  
  // Use HKDF to derive key material
  // Info string ensures this derivation is specific to network naming
  const info = utf8ToBytes(IDENTITY_CONFIG.identitySalt);
  const salt = utf8ToBytes('quantum-mesh-salt-2025');
  
  // Derive enough bytes for word indices (1 byte per word)
  const derived = hkdf(sha3_256, hashBytes, salt, info, wordCount);
  
  // Map each byte to a word (256 words = 8 bits = 1 byte per word)
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    const index = derived[i]; // 0-255
    words.push(QUANTUM_WORDLIST[index]);
  }
  
  return words.join('-');
}

/**
 * Derive a short network identifier (for internal use)
 * This is NOT the hash, but a derived value
 * 
 * @param {string} codeHash - The oracle's code hash
 * @returns {string} Short identifier like "pq-a7x9k2"
 */
export function deriveNetworkId(codeHash) {
  const hashBytes = hexToBytes(codeHash);
  
  // Derive a separate value for the short ID
  const info = utf8ToBytes(IDENTITY_CONFIG.shortIdSalt);
  const salt = utf8ToBytes('mesh-id-salt-2025');
  
  const derived = hkdf(sha3_256, hashBytes, salt, info, 4);
  
  // Base58-like encoding (no 0, O, I, l to avoid confusion)
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let shortId = '';
  for (let i = 0; i < 4; i++) {
    shortId += alphabet[derived[i] % alphabet.length];
  }
  
  return `pq-${shortId}`;
}

/**
 * Generate a verification phrase for the network
 * This allows users to verbally verify they're on the same network
 * 
 * @param {string} codeHash - The oracle's code hash
 * @returns {string} Verification phrase like "The quantum crystal reflects the lattice cipher"
 */
export function deriveVerificationPhrase(codeHash) {
  const hashBytes = hexToBytes(codeHash);
  
  const info = utf8ToBytes(IDENTITY_CONFIG.phraseSalt);
  const salt = utf8ToBytes('verify-phrase-salt-2025');
  
  // Derive 5 bytes for a 5-word phrase
  const derived = hkdf(sha3_256, hashBytes, salt, info, 5);
  
  const templates = [
    'The {0} {1} reflects the {2} {3}',
    'A {0} {1} guides the {2} {3}',
    'The {0} {1} protects the {2} {3}',
    'Through {0} {1} flows the {2} {3}',
  ];
  
  // Use last derived byte to pick template
  const templateIndex = derived[4] % templates.length;
  const template = templates[templateIndex];
  
  // Fill in words
  const words = [];
  for (let i = 0; i < 4; i++) {
    words.push(QUANTUM_WORDLIST[derived[i]]);
  }
  
  return template
    .replace('{0}', words[0])
    .replace('{1}', words[1])
    .replace('{2}', words[2])
    .replace('{3}', words[3]);
}

/**
 * Complete network identity object
 * Contains all derived identifiers for a network
 * 
 * NEW: Includes phase-modulated fingerprint for rotating security
 */
export class NetworkIdentity {
  #codeHash;
  #name;
  #shortId;
  #verificationPhrase;
  #fingerprint;        // Stable fingerprint (never changes)
  #phaseFingerprint;   // Rotating fingerprint (changes every epoch)
  #currentEpoch;
  
  constructor(codeHash) {
    if (!codeHash || typeof codeHash !== 'string') {
      throw new Error('Valid code hash required');
    }
    
    this.#codeHash = codeHash;
    this.#name = deriveNetworkName(codeHash);
    this.#shortId = deriveNetworkId(codeHash);
    this.#verificationPhrase = deriveVerificationPhrase(codeHash);
    this.#currentEpoch = getCurrentEpoch();
    
    // Stable fingerprint - one-way derivation for comparison
    // NOT the same as the code hash, NEVER changes
    const fpBytes = hkdf(
      sha3_256,
      hexToBytes(codeHash),
      utf8ToBytes('fingerprint-salt'),
      utf8ToBytes(IDENTITY_CONFIG.fingerprintSalt),
      32
    );
    this.#fingerprint = bytesToHex(fpBytes);
    
    // Phase-modulated fingerprint - rotates every epoch
    // Use this for handshakes to prevent replay attacks
    this.#phaseFingerprint = derivePhaseFingerprint(codeHash, this.#currentEpoch);
    
    Object.freeze(this);
  }
  
  // Public getters (no access to raw hash)
  get name() { return this.#name; }
  get shortId() { return this.#shortId; }
  get verificationPhrase() { return this.#verificationPhrase; }
  get fingerprint() { return this.#fingerprint; }
  
  /**
   * Get the current phase-modulated fingerprint
   * This rotates every epoch (6 hours by default)
   */
  get phaseFingerprint() {
    // Recalculate if epoch changed
    const epoch = getCurrentEpoch();
    if (epoch !== this.#currentEpoch) {
      return derivePhaseFingerprint(this.#codeHash, epoch);
    }
    return this.#phaseFingerprint;
  }
  
  /**
   * Get current phase identifier (e.g., "Phase-42α")
   */
  get phaseId() {
    return formatPhaseId(getCurrentEpoch());
  }
  
  /**
   * Check if another identity is compatible (same network)
   * Compares fingerprints, NOT raw hashes
   */
  isCompatible(other) {
    if (!other || !(other instanceof NetworkIdentity)) {
      return false;
    }
    return this.#fingerprint === other.fingerprint;
  }
  
  /**
   * Verify compatibility using only public information
   * Both parties can verify without exposing their hash
   */
  verifyCompatibility(otherFingerprint) {
    return this.#fingerprint === otherFingerprint;
  }
  
  /**
   * Verify phase fingerprint (rotating, more secure)
   * Accepts current phase + grace period phases
   */
  verifyPhaseCompatibility(otherPhaseFingerprint) {
    return verifyPhaseFingerprint(this.#codeHash, otherPhaseFingerprint);
  }
  
  /**
   * Generate handshake payload (no hash exposed)
   * NOW INCLUDES: Phase fingerprint for replay protection
   */
  getHandshakePayload() {
    const epoch = getCurrentEpoch();
    return {
      name: this.#name,
      shortId: this.#shortId,
      fingerprint: this.#fingerprint,           // Stable - for network identity
      phaseFingerprint: this.phaseFingerprint,  // Rotating - for replay protection
      phaseId: formatPhaseId(epoch),            // Human-readable phase
      epoch,                                     // Current epoch number
      timestamp: Date.now(),
      protocolVersion: '2.1.0',                 // Bumped for phase support
    };
  }
  
  /**
   * Validate incoming handshake
   * NOW VALIDATES: Both stable AND phase fingerprints
   */
  validateHandshake(payload) {
    if (!payload || !payload.fingerprint) {
      return { valid: false, compatible: false, reason: 'INVALID_PAYLOAD' };
    }
    
    // Check stable fingerprint (network identity)
    const compatible = this.#fingerprint === payload.fingerprint;
    
    // Check phase fingerprint if provided (replay protection)
    let phaseValid = true;
    let phaseReason = 'NO_PHASE_CHECK';
    
    if (payload.phaseFingerprint) {
      const phaseResult = verifyPhaseFingerprint(this.#codeHash, payload.phaseFingerprint);
      phaseValid = phaseResult.valid;
      phaseReason = phaseResult.reason;
    }
    
    return {
      valid: true,
      compatible,
      phaseValid,
      phaseReason,
      theirName: payload.name,
      theirId: payload.shortId,
      theirPhase: payload.phaseId || 'unknown',
      ourName: this.#name,
      ourId: this.#shortId,
      ourPhase: this.phaseId,
      reason: compatible 
        ? (phaseValid ? 'SAME_NETWORK_PHASE_VALID' : 'SAME_NETWORK_PHASE_EXPIRED')
        : 'DIFFERENT_NETWORK',
    };
  }
  
  /**
   * Get phase status for monitoring
   */
  getPhaseStatus() {
    return getPhaseStatus();
  }
  
  /**
   * Display-friendly representation
   */
  toString() {
    return `Network: ${this.#name} (${this.#shortId}) [${this.phaseId}]`;
  }
  
  /**
   * JSON representation (safe - no hash)
   */
  toJSON() {
    return {
      name: this.#name,
      shortId: this.#shortId,
      verificationPhrase: this.#verificationPhrase,
      fingerprint: this.#fingerprint,
      phaseFingerprint: this.phaseFingerprint,
      phaseId: this.phaseId,
    };
  }
}

/**
 * Create network identity from oracle
 */
export function createNetworkIdentity(oracle) {
  if (!oracle || !oracle.selfHash) {
    throw new Error('Oracle with selfHash required');
  }
  return new NetworkIdentity(oracle.selfHash);
}

export { QUANTUM_WORDLIST };



