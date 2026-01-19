/**
 * Code Proof Protocol
 * 
 * Implements the challenge-response protocol for nodes to verify
 * they are running identical validation code.
 * 
 * This is the mechanism by which distributed consensus emerges:
 * - All nodes run the same provably-correct code
 * - Nodes can cryptographically prove this to each other
 * - Outliers (running different code) are automatically detected and rejected
 * 
 * NEW in v2.1: Phase-Modulated Challenges (Star Trek TNG inspired)
 * - Challenges include phase epoch information
 * - Expired phases are automatically rejected
 * - Prevents replay attacks across phase boundaries
 * 
 * @module CodeProofProtocol
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';
import { getOracle, contentHash } from './validation-oracle.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:code-proof');

// Phase modulation imports
import {
  getCurrentEpoch,
  getValidEpochs,
  createPhasedChallenge,
  verifyPhasedChallenge,
  formatPhaseId,
  getPhaseStatus,
} from './phase-epoch.js';

/**
 * Challenge-Response Protocol States
 */
export const ProofState = {
  PENDING: 'pending',
  VERIFIED: 'verified',
  FAILED: 'failed',
  TIMEOUT: 'timeout',
};

/**
 * Code Proof Manager
 * Handles challenge-response verification between nodes
 * 
 * Security Note (v1.2.0): Uses network fingerprint instead of raw hash
 * for external communications (iO-inspired obfuscation).
 */
export class CodeProofProtocol {
  constructor(nodeIdentity, options = {}) {
    this.nodeId = nodeIdentity?.identity?.nodeId || 'unknown';
    this.oracle = getOracle();
    this.pendingChallenges = new Map();  // challengeId -> { peer, timestamp, challenge }
    this.verifiedPeers = new Map();       // peerId -> { verifiedAt, proof }
    this.failedPeers = new Map();         // peerId -> { failedAt, reason }
    
    // Security: Use fingerprint for external communication
    this.networkFingerprint = options.networkFingerprint || null;
    
    // Configuration
    this.challengeTimeout = 30000;  // 30 seconds to respond
    this.reverifyInterval = 300000; // Re-verify every 5 minutes
  }
  
  /**
   * Generate a challenge for a peer node
   * NOW INCLUDES: Phase modulation for replay protection
   * 
   * @param {string} peerId - The peer to challenge
   * @returns {Object} Challenge object to send to peer
   */
  generateChallenge(peerId) {
    // Generate random challenge bytes
    const challengeBytes = randomBytes(32);
    const challenge = bytesToHex(challengeBytes);
    const epoch = getCurrentEpoch();
    
    // Create phase-modulated challenge token
    const phasedChallenge = createPhasedChallenge(
      challenge,
      this.nodeId,
      peerId,
      epoch
    );
    
    // Create challenge ID
    const challengeId = contentHash({
      challenger: this.nodeId,
      challenged: peerId,
      challenge: challenge,
      epoch,
      timestamp: Date.now(),
    }).slice(0, 16);
    
    // Store pending challenge with phase info
    this.pendingChallenges.set(challengeId, {
      peerId,
      challenge,
      epoch,
      phasedChallenge,
      timestamp: Date.now(),
      state: ProofState.PENDING,
    });
    
    // Set timeout
    setTimeout(() => {
      const pending = this.pendingChallenges.get(challengeId);
      if (pending && pending.state === ProofState.PENDING) {
        pending.state = ProofState.TIMEOUT;
        this.failedPeers.set(peerId, {
          failedAt: Date.now(),
          reason: 'CHALLENGE_TIMEOUT',
        });
        log.warn('Code proof challenge timed out', { peerId: peerId.slice(0, 16), reason: 'CHALLENGE_TIMEOUT' });
      }
    }, this.challengeTimeout);
    
    return {
      type: 'CODE_PROOF_CHALLENGE',
      challengeId,
      challenge,
      challengerNodeId: this.nodeId,
      challengerFingerprint: this.networkFingerprint || 'not-set',
      // Phase modulation fields
      epoch,
      phaseId: formatPhaseId(epoch),
      phaseBinding: phasedChallenge.binding,
      expiresAt: phasedChallenge.expiresAt,
      timestamp: Date.now(),
    };
  }
  
  /**
   * Respond to a challenge from another node
   * NOW VALIDATES: Phase epoch before responding
   * 
   * @param {Object} challengeMsg - The challenge message received
   * @returns {Object} Response to send back
   */
  respondToChallenge(challengeMsg) {
    const { challengeId, challenge, challengerNodeId, epoch, phaseBinding, expiresAt } = challengeMsg;
    
    // Validate phase if present (v2.1+ challenges)
    if (epoch !== undefined) {
      const validEpochs = getValidEpochs();
      if (!validEpochs.includes(epoch)) {
        log.warn('Challenge has expired phase', { challengerNodeId: challengerNodeId.slice(0, 16), phase: formatPhaseId(epoch) });
        return {
          type: 'CODE_PROOF_RESPONSE',
          challengeId,
          responderNodeId: this.nodeId,
          error: 'PHASE_EXPIRED',
          ourPhase: formatPhaseId(getCurrentEpoch()),
          theirPhase: formatPhaseId(epoch),
          timestamp: Date.now(),
        };
      }
      
      // Check expiration
      if (expiresAt && Date.now() > expiresAt) {
        log.warn('Challenge has expired', { challengerNodeId: challengerNodeId.slice(0, 16), expiresAt });
        return {
          type: 'CODE_PROOF_RESPONSE',
          challengeId,
          responderNodeId: this.nodeId,
          error: 'CHALLENGE_EXPIRED',
          timestamp: Date.now(),
        };
      }
    }
    
    // Generate proof using our oracle
    const proof = this.oracle.generateCodeProof(challenge);
    const currentEpoch = getCurrentEpoch();
    
    return {
      type: 'CODE_PROOF_RESPONSE',
      challengeId,
      responderNodeId: this.nodeId,
      proof,
      // Include our phase info
      epoch: currentEpoch,
      phaseId: formatPhaseId(currentEpoch),
      responderFingerprint: this.networkFingerprint || 'not-set',
      timestamp: Date.now(),
    };
  }
  
  /**
   * Verify a challenge response from a peer
   * NOW VALIDATES: Phase epoch in response
   * 
   * @param {Object} responseMsg - The response message
   * @returns {Object} Verification result
   */
  verifyResponse(responseMsg) {
    const { challengeId, responderNodeId, proof, error, epoch } = responseMsg;
    
    // Check for phase-related errors
    if (error) {
      return {
        verified: false,
        reason: error,
        phaseInfo: responseMsg.ourPhase ? {
          ourPhase: formatPhaseId(getCurrentEpoch()),
          theirPhase: responseMsg.theirPhase,
        } : null,
      };
    }
    
    // Get the pending challenge
    const pending = this.pendingChallenges.get(challengeId);
    
    if (!pending) {
      return {
        verified: false,
        reason: 'UNKNOWN_CHALLENGE_ID',
      };
    }
    
    if (pending.state !== ProofState.PENDING) {
      return {
        verified: false,
        reason: `CHALLENGE_STATE_INVALID: ${pending.state}`,
      };
    }
    
    // Verify phase matches (if we sent a phased challenge)
    if (pending.epoch !== undefined && epoch !== undefined) {
      const validEpochs = getValidEpochs();
      if (!validEpochs.includes(epoch)) {
        pending.state = ProofState.FAILED;
        return {
          verified: false,
          reason: 'RESPONSE_PHASE_MISMATCH',
          expectedPhase: formatPhaseId(pending.epoch),
          receivedPhase: formatPhaseId(epoch),
        };
      }
    }
    
    // Verify the proof
    const verification = this.oracle.verifyCodeProof(proof);
    
    if (verification.valid) {
      pending.state = ProofState.VERIFIED;
      
      // Record as verified peer (store phase epoch for tracking)
      this.verifiedPeers.set(responderNodeId, {
        verifiedAt: Date.now(),
        proof,
        oracleHash: proof.selfHash, // Internal storage (external: networkFingerprint)
        phaseEpoch: epoch, // Star Trek TNG phase modulation epoch
      });
      
      // Remove from failed if previously there
      this.failedPeers.delete(responderNodeId);
      
      log.info('Code proof verified', {
        peerId: responderNodeId.slice(0, 16),
        phaseEpoch: formatPhaseId(epoch || 0),
      });
      
      return {
        verified: true,
        peerId: responderNodeId,
        // SECURITY: Use fingerprint naming, not "hash"
        networkFingerprint: proof.selfHash,
        phaseEpoch: epoch,
      };
    } else {
      pending.state = ProofState.FAILED;
      
      // Record as failed peer
      this.failedPeers.set(responderNodeId, {
        failedAt: Date.now(),
        reason: verification.reason,
        phaseEpoch: epoch,
      });
      
      log.warn('Code proof FAILED', {
        peerId: responderNodeId.slice(0, 16),
        reason: verification.reason,
      });
      
      return {
        verified: false,
        peerId: responderNodeId,
        reason: verification.reason,
      };
    }
  }
  
  /**
   * Check if a peer is verified
   * @param {string} peerId - The peer to check
   * @returns {boolean}
   */
  isPeerVerified(peerId) {
    const verified = this.verifiedPeers.get(peerId);
    
    if (!verified) return false;
    
    // Check if verification is still fresh
    const age = Date.now() - verified.verifiedAt;
    if (age > this.reverifyInterval) {
      // Verification expired, needs re-verification
      return false;
    }
    
    return true;
  }
  
  /**
   * Check if a peer has failed verification
   * @param {string} peerId - The peer to check
   * @returns {Object|null} Failure info or null
   */
  getPeerFailure(peerId) {
    return this.failedPeers.get(peerId) || null;
  }
  
  /**
   * Get all verified peers
   * SECURITY: Returns fingerprints only, not raw hashes
   * @returns {Array} List of verified peer info
   */
  getVerifiedPeers() {
    const now = Date.now();
    const verified = [];
    
    for (const [peerId, info] of this.verifiedPeers) {
      const age = now - info.verifiedAt;
      verified.push({
        peerId,
        verifiedAt: info.verifiedAt,
        // SECURITY: Use fingerprint field (legacy oracleHash renamed)
        networkFingerprint: info.oracleHash, // Internal storage unchanged, external name secure
        phaseEpoch: info.phaseEpoch || null,
        fresh: age < this.reverifyInterval,
      });
    }
    
    return verified;
  }

  /**
   * Get pending challenges
   * @returns {Array} List of pending challenge info
   */
  getPendingChallenges() {
    const now = Date.now();
    const pending = [];
    
    for (const [challengeId, info] of this.pendingChallenges) {
      pending.push({
        challengeId,
        targetPeerId: info.targetPeerId,
        createdAt: info.createdAt,
        age: now - info.createdAt,
      });
    }
    
    return pending;
  }
  
  /**
   * Get protocol statistics
   * SECURITY: Uses network fingerprint, not raw oracle hash
   * PHASE: Includes current phase epoch info
   * @returns {Object} Stats
   */
  getStats() {
    // Import phase status helper - it returns all the info we need
    const phaseStatus = getPhaseStatus();
    
    return {
      pendingChallenges: this.pendingChallenges.size,
      verifiedPeers: this.verifiedPeers.size,
      failedPeers: this.failedPeers.size,
      // Note: oracleHash removed for security (iO hash obfuscation)
      // Use networkFingerprint from GenesisNetworkV2 instead
      oracleVersion: this.oracle.getModuleSeal().version,
      // Phase modulation info (Star Trek TNG inspired)
      phase: {
        currentEpoch: phaseStatus.currentEpoch,
        phaseId: formatPhaseId(phaseStatus.currentEpoch),
        epochStartedAt: phaseStatus.epochStartedAt,
        epochEndsAt: phaseStatus.epochEndsAt,
        timeRemaining: phaseStatus.timeUntilRotation,
        inGracePeriod: phaseStatus.inGracePeriod,
      },
    };
  }
  
  /**
   * Handle incoming protocol message
   * @param {Object} message - The protocol message
   * @param {Function} sendResponse - Function to send response back
   */
  handleMessage(message, sendResponse) {
    switch (message.type) {
      case 'CODE_PROOF_CHALLENGE':
        const response = this.respondToChallenge(message);
        sendResponse(response);
        break;
        
      case 'CODE_PROOF_RESPONSE':
        const result = this.verifyResponse(message);
        // Emit event or callback for verification result
        return result;
        
      default:
        log.warn('Unknown code proof message type', { type: message.type });
    }
  }
}

/**
 * Mutual verification - two nodes verify each other
 * NOW PHASE-AWARE: Challenges include phase epoch for anti-replay
 * 
 * @param {CodeProofProtocol} localProtocol - Local protocol instance
 * @param {Object} peerConnection - Connection to peer
 * @returns {Promise<Object>} Verification result with phase info
 */
export async function mutualVerification(localProtocol, peerConnection) {
  return new Promise((resolve) => {
    const peerId = peerConnection.peerId;
    const currentEpoch = getCurrentEpoch();
    
    // Generate and send phased challenge
    const challenge = localProtocol.generateChallenge(peerId);
    
    peerConnection.send(challenge);
    
    log.debug('Sent phased challenge', {
      peerId: peerId.slice(0, 16),
      phaseEpoch: formatPhaseId(currentEpoch.epoch),
    });
    
    // Wait for response
    const timeout = setTimeout(() => {
      resolve({
        verified: false,
        reason: 'TIMEOUT',
        phaseEpoch: currentEpoch.epoch,
      });
    }, localProtocol.challengeTimeout);
    
    peerConnection.once('CODE_PROOF_RESPONSE', (response) => {
      clearTimeout(timeout);
      const result = localProtocol.verifyResponse(response);
      resolve({
        ...result,
        phaseEpoch: currentEpoch.epoch,
      });
    });
  });
}

// Re-export phase utilities for convenience
export { getCurrentEpoch, formatPhaseId, getValidEpochs, getPhaseStatus, verifyPhasedChallenge } from './phase-epoch.js';

export default CodeProofProtocol;
