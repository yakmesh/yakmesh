/**
 * Consensus Engine
 * 
 * Implements the distributed consensus mechanism where all nodes
 * independently arrive at the same truth through mathematical inevitability.
 * 
 * Key Features:
 * - Deterministic conflict resolution (no voting needed)
 * - Content-addressed storage (data is its own identity)
 * - Automatic outlier rejection
 * - Cryptographic proof of consensus
 * 
 * @module ConsensusEngine
 */

import { getOracle, contentHash, deterministicStringify } from './validation-oracle.js';
import { CodeProofProtocol } from './code-proof-protocol.js';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:consensus');

/**
 * Content State - represents the consensus state of a piece of content
 */
export const ContentState = {
  PENDING: 'pending',       // Received but not yet validated
  VALIDATED: 'validated',   // Passed local validation
  CONSENSUS: 'consensus',   // Confirmed by multiple nodes
  REJECTED: 'rejected',     // Failed validation or consensus
  CONFLICT: 'conflict',     // Conflicting versions exist (will be resolved)
};

/**
 * Consensus Engine
 * Manages distributed consensus through deterministic validation
 * 
 * Security Note (v1.2.0): Uses network fingerprint instead of raw oracle hash
 * for all external-facing operations (iO-inspired obfuscation).
 */
export class ConsensusEngine extends EventEmitter {
  constructor(nodeIdentity, options = {}) {
    super();
    
    this.nodeId = nodeIdentity?.identity?.nodeId || 'local';
    this.oracle = getOracle();
    this.codeProof = new CodeProofProtocol(nodeIdentity);
    
    // Network fingerprint for external use (hash never exposed)
    this.networkFingerprint = options.networkFingerprint || null;
    
    // Content storage
    this.contentStore = new Map();      // contentHash -> { content, state, attestations }
    this.conflictStore = new Map();     // primaryKey -> [contentHash, contentHash, ...]
    this.attestations = new Map();      // contentHash -> Set<nodeId>
    
    // Configuration
    this.config = {
      minAttestations: options.minAttestations || 1,      // Minimum nodes to confirm
      conflictResolutionDelay: options.conflictResolutionDelay || 5000,
      maxPendingContent: options.maxPendingContent || 10000,
    };
    
    // Statistics
    this.stats = {
      contentReceived: 0,
      contentValidated: 0,
      contentRejected: 0,
      conflictsResolved: 0,
      consensusReached: 0,
    };
  }
  
  /**
   * Submit content for consensus
   * Content goes through: validation → attestation collection → consensus/conflict resolution
   * 
   * @param {string} contentType - Type of content (listing, qcoa, etc.)
   * @param {Object} content - The content data
   * @param {Object} metadata - Additional metadata (signature, pubkey, etc.)
   * @returns {Object} Submission result
   */
  submitContent(contentType, content, metadata = {}) {
    this.stats.contentReceived++;
    
    // 1. Compute content hash (this IS the content's identity)
    const hash = contentHash(content);
    
    // 2. Check if we've already seen this exact content
    if (this.contentStore.has(hash)) {
      const existing = this.contentStore.get(hash);
      return {
        accepted: true,
        status: 'DUPLICATE',
        contentHash: hash,
        state: existing.state,
      };
    }
    
    // 3. Validate the content using the oracle
    const prepared = this.oracle.prepareForPropagation(
      contentType,
      content,
      metadata.signature,
      metadata.publicKey
    );
    
    if (!prepared.valid) {
      this.stats.contentRejected++;
      return {
        accepted: false,
        status: 'VALIDATION_FAILED',
        reason: prepared.reason,
      };
    }
    
    this.stats.contentValidated++;
    
    // 4. Check for conflicts (same primaryKey, different content)
    const primaryKey = this._getPrimaryKey(contentType, content);
    
    if (primaryKey && this.conflictStore.has(primaryKey)) {
      const existingHashes = this.conflictStore.get(primaryKey);
      
      if (!existingHashes.includes(hash)) {
        // This is a conflicting version!
        existingHashes.push(hash);
        
        // Store as conflict
        this.contentStore.set(hash, {
          content,
          contentType,
          sealedPackage: prepared.package,
          state: ContentState.CONFLICT,
          receivedAt: Date.now(),
          attestations: new Set([this.nodeId]),
        });
        
        // Schedule conflict resolution
        this._scheduleConflictResolution(primaryKey);
        
        return {
          accepted: true,
          status: 'CONFLICT_DETECTED',
          contentHash: hash,
          state: ContentState.CONFLICT,
          conflictingHashes: existingHashes,
        };
      }
    }
    
    // 5. Store the content
    this.contentStore.set(hash, {
      content,
      contentType,
      sealedPackage: prepared.package,
      state: ContentState.VALIDATED,
      receivedAt: Date.now(),
      attestations: new Set([this.nodeId]), // We attest to it
    });
    
    // 6. Track by primary key
    if (primaryKey) {
      if (!this.conflictStore.has(primaryKey)) {
        this.conflictStore.set(primaryKey, []);
      }
      this.conflictStore.get(primaryKey).push(hash);
    }
    
    // 7. Check if we've reached consensus
    this._checkConsensus(hash);
    
    return {
      accepted: true,
      status: 'VALIDATED',
      contentHash: hash,
      sealedPackage: prepared.package,
      state: ContentState.VALIDATED,
    };
  }
  
  /**
   * Receive an attestation from another node
   * An attestation means "I also validated this content and agree"
   * 
   * @param {string} contentHash - Hash of the content being attested
   * @param {string} nodeId - ID of the attesting node
   * @param {Object} proof - Code proof from the attesting node
   * @returns {Object} Attestation result
   */
  receiveAttestation(contentHash, nodeId, proof = null) {
    // 1. Verify the attesting node is running valid code
    if (proof) {
      const codeVerification = this.oracle.verifyCodeProof(proof);
      if (!codeVerification.valid) {
        return {
          accepted: false,
          reason: `INVALID_CODE_PROOF: ${codeVerification.reason}`,
        };
      }
    }
    
    // 2. Check if we have this content
    const stored = this.contentStore.get(contentHash);
    if (!stored) {
      return {
        accepted: false,
        reason: 'UNKNOWN_CONTENT',
      };
    }
    
    // 3. Add attestation
    stored.attestations.add(nodeId);
    
    // 4. Check if we've now reached consensus
    this._checkConsensus(contentHash);
    
    return {
      accepted: true,
      attestationCount: stored.attestations.size,
      state: stored.state,
    };
  }
  
  /**
   * Get content by hash
   * @param {string} hash - Content hash
   * @returns {Object|null} Content data or null
   */
  getContent(hash) {
    const stored = this.contentStore.get(hash);
    if (!stored) return null;
    
    return {
      content: stored.content,
      contentType: stored.contentType,
      state: stored.state,
      attestations: Array.from(stored.attestations),
      receivedAt: stored.receivedAt,
    };
  }
  
  /**
   * Get content by primary key (returns consensus winner if conflicts exist)
   * @param {string} contentType - Type of content
   * @param {string} primaryKey - Primary key value
   * @returns {Object|null} Content or null
   */
  getContentByKey(contentType, primaryKey) {
    const fullKey = `${contentType}:${primaryKey}`;
    const hashes = this.conflictStore.get(fullKey);
    
    if (!hashes || hashes.length === 0) return null;
    
    // If only one, return it
    if (hashes.length === 1) {
      return this.getContent(hashes[0]);
    }
    
    // Multiple - return the one in CONSENSUS state, or resolve now
    for (const hash of hashes) {
      const stored = this.contentStore.get(hash);
      if (stored && stored.state === ContentState.CONSENSUS) {
        return this.getContent(hash);
      }
    }
    
    // No consensus yet - resolve deterministically
    const winner = this._resolveConflict(hashes);
    return winner ? this.getContent(winner) : null;
  }
  
  /**
   * Get all content of a specific type
   * @param {string} contentType - Type of content
   * @param {string} state - Optional state filter
   * @returns {Array} Array of content
   */
  getContentByType(contentType, state = null) {
    const results = [];
    
    for (const [hash, stored] of this.contentStore) {
      if (stored.contentType !== contentType) continue;
      if (state && stored.state !== state) continue;
      
      results.push({
        contentHash: hash,
        content: stored.content,
        state: stored.state,
        attestations: stored.attestations.size,
      });
    }
    
    return results;
  }
  
  /**
   * Generate a sealed package for propagation to other nodes
   * @param {string} contentHash - Hash of content to propagate
   * @returns {Object|null} Sealed package or null
   */
  getPackageForPropagation(contentHash) {
    const stored = this.contentStore.get(contentHash);
    if (!stored) return null;
    
    return {
      sealedPackage: stored.sealedPackage,
      attestations: Array.from(stored.attestations),
      state: stored.state,
      consensusProof: this._generateConsensusProof(contentHash),
    };
  }
  
  /**
   * Receive a package from another node
   * @param {Object} pkg - The package to receive
   * @returns {Object} Reception result
   */
  receivePackage(pkg) {
    const { sealedPackage, attestations = [] } = pkg;
    
    // 1. Verify the sealed package
    const verification = this.oracle.verifySealedPackage(sealedPackage);
    
    if (!verification.valid) {
      this.stats.contentRejected++;
      return {
        accepted: false,
        reason: `PACKAGE_VERIFICATION_FAILED: ${verification.reason}`,
      };
    }
    
    // 2. Submit the content
    const submission = this.submitContent(
      sealedPackage.type,
      sealedPackage.content,
      {
        signature: sealedPackage.creatorSignature,
        publicKey: sealedPackage.creatorPubKey,
      }
    );
    
    // 3. Record attestations from other nodes
    for (const nodeId of attestations) {
      if (nodeId !== this.nodeId) {
        this.receiveAttestation(sealedPackage.contentHash, nodeId);
      }
    }
    
    return submission;
  }
  
  // ============================================================
  // INTERNAL METHODS
  // ============================================================
  
  /**
   * Get primary key for content (for conflict detection)
   */
  _getPrimaryKey(contentType, content) {
    switch (contentType) {
      case 'listing':
        return content.id ? `listing:${content.id}` : null;
      case 'qcoa':
        return content.cert_hash ? `qcoa:${content.cert_hash}` : null;
      case 'user':
        return content.user_id ? `user:${content.user_id}` : null;
      default:
        return null;
    }
  }
  
  /**
   * Check if content has reached consensus
   */
  _checkConsensus(contentHash) {
    const stored = this.contentStore.get(contentHash);
    if (!stored) return;
    
    if (stored.state === ContentState.CONSENSUS) return; // Already consensus
    if (stored.state === ContentState.REJECTED) return;  // Can't reach consensus
    
    // Check attestation count
    if (stored.attestations.size >= this.config.minAttestations) {
      stored.state = ContentState.CONSENSUS;
      this.stats.consensusReached++;
      
      this.emit('consensus', {
        contentHash,
        contentType: stored.contentType,
        attestations: Array.from(stored.attestations),
      });
    }
  }
  
  /**
   * Schedule conflict resolution
   */
  _scheduleConflictResolution(primaryKey) {
    // Initialize timers map if needed
    if (!this._conflictTimers) {
      this._conflictTimers = new Map();
    }
    
    // Clear any existing timer for this key
    if (this._conflictTimers.has(primaryKey)) {
      clearTimeout(this._conflictTimers.get(primaryKey));
    }
    
    const timer = setTimeout(() => {
      this._conflictTimers.delete(primaryKey);
      this._resolveConflictForKey(primaryKey);
    }, this.config.conflictResolutionDelay);
    
    this._conflictTimers.set(primaryKey, timer);
  }
  
  /**
   * Resolve conflict for a primary key
   */
  _resolveConflictForKey(primaryKey) {
    const hashes = this.conflictStore.get(primaryKey);
    if (!hashes || hashes.length <= 1) return;
    
    const winnerHash = this._resolveConflict(hashes);
    
    if (winnerHash) {
      // Mark winner as consensus
      const winner = this.contentStore.get(winnerHash);
      if (winner) {
        winner.state = ContentState.CONSENSUS;
      }
      
      // Mark losers as rejected
      for (const hash of hashes) {
        if (hash !== winnerHash) {
          const loser = this.contentStore.get(hash);
          if (loser) {
            loser.state = ContentState.REJECTED;
          }
        }
      }
      
      this.stats.conflictsResolved++;
      
      this.emit('conflict-resolved', {
        primaryKey,
        winnerHash,
        loserHashes: hashes.filter(h => h !== winnerHash),
      });
    }
  }
  
  /**
   * Deterministically resolve conflict between content versions
   * Uses the oracle's resolveConflict method
   */
  _resolveConflict(contentHashes) {
    if (!contentHashes || contentHashes.length === 0) return null;
    if (contentHashes.length === 1) return contentHashes[0];
    
    // Get all content
    const contents = contentHashes
      .map(hash => this.contentStore.get(hash))
      .filter(c => c !== null);
    
    if (contents.length === 0) return null;
    if (contents.length === 1) return contentHashes[0];
    
    // Use oracle's deterministic resolution
    let winner = contents[0];
    for (let i = 1; i < contents.length; i++) {
      winner = this.oracle.resolveConflict(winner.content, contents[i].content);
    }
    
    // Find the hash of the winner
    const winnerHash = contentHash(winner);
    
    // Find which original hash this corresponds to
    for (let i = 0; i < contents.length; i++) {
      if (contentHash(contents[i].content) === winnerHash) {
        return contentHashes[i];
      }
    }
    
    // Fallback: return first hash
    return contentHashes[0];
  }
  
  /**
   * Generate a proof of consensus
   * SECURITY: Uses network fingerprint, not raw oracle hash
   */
  _generateConsensusProof(contentHash) {
    const stored = this.contentStore.get(contentHash);
    if (!stored) return null;
    
    return {
      contentHash,
      state: stored.state,
      attestations: Array.from(stored.attestations),
      attestationCount: stored.attestations.size,
      networkFingerprint: this.networkFingerprint || 'local',  // Never expose raw hash
      timestamp: Date.now(),
    };
  }

  /**
   * Propose data for consensus (convenience wrapper)
   * This is the primary API for submitting local content for network consensus
   * 
   * @param {string} contentType - Type of content
   * @param {Object} sealedPackage - The sealed package with content and signature
   * @returns {Object} Proposal result with proposalId and attestation
   */
  proposeData(contentType, sealedPackage) {
    const { content, signature, contentHash: providedHash } = sealedPackage;
    
    // Submit through the standard flow
    const result = this.submitContent(contentType, content, {
      signature,
      publicKey: sealedPackage.validatorFingerprint || sealedPackage.validatorHash,  // Support both for backward compat
    });
    
    // Generate our attestation for the proposal
    // SECURITY: Use fingerprint, not raw hash
    const attestation = {
      nodeId: this.nodeId,
      contentHash: result.contentHash || providedHash,
      contentType,
      validatorFingerprint: this.networkFingerprint || 'local',  // Never expose raw hash
      attestedAt: Date.now(),
    };
    
    return {
      ...result,
      proposalId: `${this.nodeId}-${Date.now()}-${(result.contentHash || providedHash).slice(0, 8)}`,
      attestation,
    };
  }

  /**
   * Stop the consensus engine
   * Cleans up any pending timers and resources
   */
  stop() {
    // Clear any pending conflict resolution timers
    if (this._conflictTimers) {
      for (const timer of this._conflictTimers.values()) {
        clearTimeout(timer);
      }
      this._conflictTimers.clear();
    }
    
    // Emit stopped event
    this.emit('stopped', {
      nodeId: this.nodeId,
      stats: this.getStats(),
    });
    
    log.info('Consensus engine stopped');
  }
  
  /**
   * Get engine statistics
   * SECURITY: Uses network fingerprint, not raw oracle hash
   */
  getStats() {
    return {
      ...this.stats,
      contentStoreSize: this.contentStore.size,
      conflictsTracked: this.conflictStore.size,
      networkFingerprint: this.networkFingerprint || 'local',  // Never expose raw hash
      codeProofStats: this.codeProof.getStats(),
    };
  }
  
  /**
   * Export state for persistence or debugging
   */
  exportState() {
    const state = {
      nodeId: this.nodeId,
      content: [],
      conflicts: [],
      stats: this.getStats(),
      exportedAt: Date.now(),
    };
    
    for (const [hash, stored] of this.contentStore) {
      state.content.push({
        contentHash: hash,
        contentType: stored.contentType,
        state: stored.state,
        attestations: Array.from(stored.attestations),
      });
    }
    
    for (const [key, hashes] of this.conflictStore) {
      if (hashes.length > 1) {
        state.conflicts.push({
          primaryKey: key,
          contentHashes: hashes,
        });
      }
    }
    
    return state;
  }
}

export default ConsensusEngine;
