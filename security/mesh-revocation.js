/**
 * Mesh Revocation - Mathematical Threshold-Based Revocation
 * 
 * Revocation through pure math: When 2/3 of active network nodes
 * attest that a DOKO should be revoked, it IS revoked. No voting,
 * no periods, no human decisions - just cryptographic attestations.
 * 
 * "The math doesn't care about your politics."
 * 
 * @module security/mesh-revocation
 * @version 1.0.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';

const log = createLogger('security:mesh-revocation');

/**
 * Revocation reasons - observable, provable behaviors
 */
export const REVOCATION_REASONS = {
  DOUBLE_SIGN: 'double_sign',           // Signed contradictory statements
  INVALID_PROOFS: 'invalid_proofs',     // Consistently produces bad proofs
  KEY_REUSE: 'key_reuse',               // Key used across incompatible DOKOs
  PROTOCOL_VIOLATION: 'protocol_violation', // Systematic protocol abuse
  EXPIRED_UNRENEWED: 'expired_unrenewed',   // DOKO expired, not renewed
};

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  threshold: 2/3,                    // Fraction of network required
  minNodes: 3,                       // Minimum nodes for revocation to be valid
  attestationTTL: 7 * 24 * 60 * 60 * 1000, // 7 days - attestations expire
  maxAttestationsPerNode: 100,       // Rate limit per node
};

/**
 * Attestation - A single node's statement about a DOKO
 * 
 * This is NOT a vote. It's a cryptographic attestation that the
 * signing node has observed behavior warranting revocation.
 */
export class Attestation {
  constructor(options = {}) {
    this.version = '1.0';
    this.dokoId = options.dokoId;           // Target DOKO
    this.reason = options.reason;           // From REVOCATION_REASONS
    this.attesterId = options.attesterId;   // Attesting node's DOKO ID
    this.timestamp = options.timestamp || Date.now();
    this.evidence = options.evidence || null; // Optional: hash of evidence data
    this.signature = options.signature || null;
  }

  /**
   * Get canonical bytes for signing
   */
  getSignableBytes() {
    const data = {
      version: this.version,
      dokoId: this.dokoId,
      reason: this.reason,
      attesterId: this.attesterId,
      timestamp: this.timestamp,
      evidence: this.evidence,
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }

  /**
   * Compute unique ID for this attestation
   */
  getId() {
    const hash = sha3_256(this.getSignableBytes());
    return bytesToHex(hash).slice(0, 32);
  }

  /**
   * Sign the attestation
   */
  sign(privateKey) {
    const bytes = this.getSignableBytes();
    const sig = ml_dsa65.sign(bytes, privateKey);
    this.signature = bytesToHex(sig);
    return this;
  }

  /**
   * Verify the attestation signature
   */
  verify(publicKey) {
    if (!this.signature) return false;
    
    try {
      const bytes = this.getSignableBytes();
      const sig = hexToBytes(this.signature);
      const pubKey = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
      return ml_dsa65.verify(sig, bytes, pubKey);
    } catch (e) {
      return false;
    }
  }

  /**
   * Check if attestation has expired
   */
  isExpired(ttl = DEFAULT_CONFIG.attestationTTL) {
    return Date.now() - this.timestamp > ttl;
  }

  /**
   * Serialize to JSON
   */
  toJSON() {
    return {
      version: this.version,
      dokoId: this.dokoId,
      reason: this.reason,
      attesterId: this.attesterId,
      timestamp: this.timestamp,
      evidence: this.evidence,
      signature: this.signature,
    };
  }

  /**
   * Deserialize from JSON
   */
  static fromJSON(json) {
    return new Attestation(json);
  }
}

/**
 * RevocationState - The mathematical state of a DOKO's revocation
 * 
 * Not a decision - a calculation.
 */
export class RevocationState {
  constructor(dokoId) {
    this.dokoId = dokoId;
    this.attestations = new Map(); // attesterId -> Attestation
    this.reasons = new Map();      // reason -> count
    this.firstSeen = null;
    this.lastUpdated = null;
  }

  /**
   * Add an attestation
   * Returns true if attestation was new
   */
  addAttestation(attestation) {
    if (attestation.dokoId !== this.dokoId) {
      throw new Error('Attestation dokoId mismatch');
    }

    // One attestation per attester (latest wins)
    const existing = this.attestations.get(attestation.attesterId);
    if (existing && existing.timestamp >= attestation.timestamp) {
      return false; // Already have a newer one
    }

    // Update reason counts
    if (existing) {
      const oldCount = this.reasons.get(existing.reason) || 0;
      this.reasons.set(existing.reason, Math.max(0, oldCount - 1));
    }

    this.attestations.set(attestation.attesterId, attestation);
    this.reasons.set(attestation.reason, (this.reasons.get(attestation.reason) || 0) + 1);

    if (!this.firstSeen) this.firstSeen = Date.now();
    this.lastUpdated = Date.now();

    return true;
  }

  /**
   * Remove expired attestations
   */
  pruneExpired(ttl = DEFAULT_CONFIG.attestationTTL) {
    let pruned = 0;
    for (const [attesterId, attestation] of this.attestations) {
      if (attestation.isExpired(ttl)) {
        const count = this.reasons.get(attestation.reason) || 0;
        this.reasons.set(attestation.reason, Math.max(0, count - 1));
        this.attestations.delete(attesterId);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Get attestation count
   */
  get count() {
    return this.attestations.size;
  }

  /**
   * Get primary reason (most attested)
   */
  get primaryReason() {
    let maxReason = null;
    let maxCount = 0;
    for (const [reason, count] of this.reasons) {
      if (count > maxCount) {
        maxCount = count;
        maxReason = reason;
      }
    }
    return maxReason;
  }

  /**
   * Check if threshold is met
   * This is THE mathematical determination
   */
  isRevoked(activeNodeCount, config = DEFAULT_CONFIG) {
    if (activeNodeCount < config.minNodes) {
      return { revoked: false, reason: 'INSUFFICIENT_NETWORK' };
    }

    const threshold = Math.ceil(activeNodeCount * config.threshold);
    const count = this.count;

    if (count >= threshold) {
      return {
        revoked: true,
        reason: this.primaryReason,
        attestationCount: count,
        threshold,
        activeNodes: activeNodeCount,
        confidence: count / activeNodeCount,
      };
    }

    return {
      revoked: false,
      reason: 'BELOW_THRESHOLD',
      attestationCount: count,
      threshold,
      activeNodes: activeNodeCount,
      progress: count / threshold,
    };
  }

  /**
   * Export attestations for gossip/sync
   */
  export() {
    return Array.from(this.attestations.values()).map(a => a.toJSON());
  }
}

/**
 * MeshRevocation - The revocation engine
 * 
 * Manages attestation collection and threshold calculations.
 * Emits 'revoked' event when math determines revocation.
 */
export class MeshRevocation extends EventEmitter {
  constructor(options = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...options };
    this.states = new Map();           // dokoId -> RevocationState
    this.myDokoId = options.myDokoId;
    this.myPrivateKey = options.privateKey;
    
    // Public key resolver: dokoId -> publicKey
    this.resolvePublicKey = options.resolvePublicKey || (() => null);
    
    // Active node counter: () -> count
    this.getActiveNodeCount = options.getActiveNodeCount || (() => 0);

    // Cleanup interval
    this.cleanupInterval = null;
  }

  /**
   * Start the revocation engine
   */
  start() {
    // Periodic cleanup of expired attestations
    this.cleanupInterval = setInterval(() => {
      this.pruneExpired();
    }, 60 * 60 * 1000); // Every hour
    
    log.info('mesh-revocation', 'Mesh revocation engine started');
  }

  /**
   * Stop the revocation engine
   */
  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Create an attestation for a DOKO
   * 
   * Call this when YOUR node observes bad behavior.
   */
  createAttestation(dokoId, reason, evidence = null) {
    if (!this.myDokoId || !this.myPrivateKey) {
      throw new Error('Node identity not configured');
    }

    if (!Object.values(REVOCATION_REASONS).includes(reason)) {
      throw new Error(`Invalid reason: ${reason}`);
    }

    const attestation = new Attestation({
      dokoId,
      reason,
      attesterId: this.myDokoId,
      evidence: evidence ? bytesToHex(sha3_256(new TextEncoder().encode(JSON.stringify(evidence)))) : null,
    });

    attestation.sign(this.myPrivateKey);

    // Add to local state
    this.addAttestation(attestation);

    log.info('attestation-created', { dokoId, reason, attesterId: this.myDokoId });

    return attestation;
  }

  /**
   * Add an attestation (from local creation or gossip)
   * 
   * Returns { accepted, revoked, error }
   */
  addAttestation(attestation) {
    // Validate attestation
    if (!(attestation instanceof Attestation)) {
      attestation = Attestation.fromJSON(attestation);
    }

    // Check expiration
    if (attestation.isExpired(this.config.attestationTTL)) {
      return { accepted: false, error: 'EXPIRED' };
    }

    // Verify signature
    const publicKey = this.resolvePublicKey(attestation.attesterId);
    if (!publicKey) {
      return { accepted: false, error: 'UNKNOWN_ATTESTER' };
    }

    if (!attestation.verify(publicKey)) {
      return { accepted: false, error: 'INVALID_SIGNATURE' };
    }

    // Get or create state
    let state = this.states.get(attestation.dokoId);
    if (!state) {
      state = new RevocationState(attestation.dokoId);
      this.states.set(attestation.dokoId, state);
    }

    // Add attestation
    const isNew = state.addAttestation(attestation);
    if (!isNew) {
      return { accepted: false, error: 'DUPLICATE' };
    }

    // Check threshold
    const activeNodes = this.getActiveNodeCount();
    const revocationStatus = state.isRevoked(activeNodes, this.config);

    if (revocationStatus.revoked) {
      this.emit('revoked', {
        dokoId: attestation.dokoId,
        ...revocationStatus,
        attestations: state.export(),
      });
    }

    return { accepted: true, revoked: revocationStatus.revoked };
  }

  /**
   * Check if a DOKO is revoked
   * 
   * This is a PURE CALCULATION, not a lookup.
   */
  isRevoked(dokoId) {
    const state = this.states.get(dokoId);
    if (!state) {
      return { revoked: false, reason: 'NO_ATTESTATIONS' };
    }

    const activeNodes = this.getActiveNodeCount();
    return state.isRevoked(activeNodes, this.config);
  }

  /**
   * Get revocation state for a DOKO
   */
  getState(dokoId) {
    return this.states.get(dokoId) || null;
  }

  /**
   * Get all attestations for a DOKO
   */
  getAttestations(dokoId) {
    const state = this.states.get(dokoId);
    return state ? state.export() : [];
  }

  /**
   * Prune expired attestations from all states
   */
  pruneExpired() {
    let totalPruned = 0;
    const emptyStates = [];

    for (const [dokoId, state] of this.states) {
      const pruned = state.pruneExpired(this.config.attestationTTL);
      totalPruned += pruned;
      
      if (state.count === 0) {
        emptyStates.push(dokoId);
      }
    }

    // Remove empty states
    for (const dokoId of emptyStates) {
      this.states.delete(dokoId);
    }

    if (totalPruned > 0) {
      log.info('pruned-attestations', { count: totalPruned, removedStates: emptyStates.length });
    }

    return totalPruned;
  }

  /**
   * Import attestations (from sync/gossip)
   */
  importAttestations(attestations) {
    let imported = 0;
    let failed = 0;

    for (const data of attestations) {
      const result = this.addAttestation(data);
      if (result.accepted) {
        imported++;
      } else {
        failed++;
      }
    }

    return { imported, failed };
  }

  /**
   * Export all attestations for sync
   */
  exportAttestations() {
    const all = [];
    for (const state of this.states.values()) {
      all.push(...state.export());
    }
    return all;
  }

  /**
   * Get statistics
   */
  getStats() {
    let totalAttestations = 0;
    let revokedCount = 0;
    const activeNodes = this.getActiveNodeCount();
    const byReason = {};

    for (const state of this.states.values()) {
      totalAttestations += state.count;
      
      const status = state.isRevoked(activeNodes, this.config);
      if (status.revoked) revokedCount++;

      for (const [reason, count] of state.reasons) {
        byReason[reason] = (byReason[reason] || 0) + count;
      }
    }

    return {
      trackedDokos: this.states.size,
      totalAttestations,
      revokedCount,
      activeNodes,
      threshold: this.config.threshold,
      byReason,
    };
  }

  /**
   * Create a verifiable revocation certificate
   * 
   * This is generated AFTER threshold is met, for distribution.
   * It contains enough attestations to prove revocation.
   */
  createRevocationCertificate(dokoId) {
    const state = this.states.get(dokoId);
    if (!state) {
      return null;
    }

    const activeNodes = this.getActiveNodeCount();
    const status = state.isRevoked(activeNodes, this.config);

    if (!status.revoked) {
      return null;
    }

    return {
      version: '1.0',
      type: 'mesh-consensus',
      dokoId,
      reason: status.reason,
      attestationCount: status.attestationCount,
      threshold: status.threshold,
      activeNodes: status.activeNodes,
      confidence: status.confidence,
      createdAt: Date.now(),
      // Include attestations for verification
      attestations: state.export(),
    };
  }

  /**
   * Verify a revocation certificate
   * 
   * Anyone can verify by checking:
   * 1. All attestation signatures are valid
   * 2. attestationCount >= threshold
   * 3. threshold = ceil(2/3 * activeNodes)
   */
  static verifyCertificate(certificate, resolvePublicKey) {
    if (!certificate || !certificate.attestations) {
      return { valid: false, reason: 'MISSING_DATA' };
    }

    // Verify threshold calculation
    const expectedThreshold = Math.ceil(certificate.activeNodes * (2/3));
    if (certificate.threshold !== expectedThreshold) {
      return { valid: false, reason: 'INVALID_THRESHOLD' };
    }

    // Verify attestation count meets threshold
    if (certificate.attestations.length < certificate.threshold) {
      return { valid: false, reason: 'BELOW_THRESHOLD' };
    }

    // Verify each attestation signature
    let validCount = 0;
    for (const data of certificate.attestations) {
      const attestation = Attestation.fromJSON(data);
      const publicKey = resolvePublicKey(attestation.attesterId);
      
      if (publicKey && attestation.verify(publicKey)) {
        validCount++;
      }
    }

    if (validCount < certificate.threshold) {
      return { valid: false, reason: 'INSUFFICIENT_VALID_SIGNATURES', validCount };
    }

    return {
      valid: true,
      validSignatures: validCount,
      threshold: certificate.threshold,
      confidence: validCount / certificate.activeNodes,
    };
  }
}

/**
 * KHATA integration - Message types for attestation gossip
 */
export const MESH_REVOCATION_MESSAGES = {
  ATTESTATION: 'mesh:attestation',      // Single attestation
  ATTESTATIONS_SYNC: 'mesh:attest-sync', // Bulk attestation sync
  REVOCATION_CERT: 'mesh:revoke-cert',   // Completed revocation certificate
};

export default MeshRevocation;
