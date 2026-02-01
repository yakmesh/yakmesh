/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                    ☯️ KARMA TRUST MODEL - ACTIONS BEAR CONSEQUENCES ☯️         ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  In Buddhist philosophy, KARMA represents the universal law of cause and     ║
 * ║  effect—every action creates ripples that shape future outcomes. Good        ║
 * ║  actions accumulate merit; harmful actions diminish it.                      ║
 * ║                                                                               ║
 * ║  The KARMA Trust Model embodies this principle:                              ║
 * ║  - Trust is EARNED through consistent good behavior                          ║
 * ║  - Multiple independent sources strengthen karmic standing                   ║
 * ║  - Bad actions cause trust to decay (negative karma)                         ║
 * ║  - Time and consistency build toward higher levels (merit accumulation)      ║
 * ║                                                                               ║
 * ║  PROTOCOL PHILOSOPHY:                                                         ║
 * ║    "Actions bear consequences" - Trust reflects cumulative behavior          ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * KARMA Trust Model - Multi-Level Trust Assessment
 * 
 * Implements a 3-level trust system combining multiple verification sources:
 * 
 * KARMA LEVELS:
 * ═════════════════════════════════════════════════════════════════════════════
 * 
 * LEVEL 3: ENLIGHTENED (Highest - formerly PLATINUM)
 * - SSL certificate verified via CA
 * - Mesh quorum verification passed
 * - Consistent beacon presence >7 days
 * - Domain ownership verified via consensus
 * 
 * LEVEL 2: AWAKENED (Standard - formerly GOLD)
 * - Mesh quorum verification passed
 * - Diverse verifier set (Sybil defense passed)
 * - No SSL certificate or self-signed only
 * 
 * LEVEL 1: SEEKING (Basic - formerly BRONZE)
 * - Self-asserted beacon only
 * - No external verification
 * - New node or insufficient mesh history
 * 
 * UNTRUSTED (Level 0)
 * - Failed verification (negative karma)
 * - Revoked DOKO
 * - Suspicious activity detected
 * 
 * ═════════════════════════════════════════════════════════════════════════════
 * 
 * Security Philosophy:
 * "Trust is earned through multiple independent sources of evidence."
 * 
 * @module karma/trust-model
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

/**
 * KARMA Level Constants - Stages of spiritual trust
 */
export const KarmaLevel = {
  UNTRUSTED: 0,     // Negative karma - failed verification
  SEEKING: 1,       // Basic - Self-asserted only (on the path)
  AWAKENED: 2,      // Standard - Mesh verified (eyes opening)
  ENLIGHTENED: 3,   // Highest - Full verification (full realization)
};

// Backward compatibility alias
export const TrustLevel = KarmaLevel;

/**
 * KARMA Level Descriptions - Himalayan-themed trust levels
 */
export const KarmaLevelInfo = {
  [KarmaLevel.UNTRUSTED]: {
    name: 'UNTRUSTED',
    description: 'Negative karma - failed verification or revoked',
    color: '#FF0000',
    icon: '🚫',
    himalayan: 'Lost in samsara',
  },
  [KarmaLevel.SEEKING]: {
    name: 'SEEKING',
    description: 'On the path - self-asserted, awaiting verification',
    color: '#CD7F32',
    icon: '🥉',
    himalayan: 'Beginning the journey',
  },
  [KarmaLevel.AWAKENED]: {
    name: 'AWAKENED',
    description: 'Eyes opening - mesh verified with diverse quorum',
    color: '#FFD700',
    icon: '🥇',
    himalayan: 'Seeing clearly',
  },
  [KarmaLevel.ENLIGHTENED]: {
    name: 'ENLIGHTENED',
    description: 'Full realization - SSL + Mesh + Time verified',
    color: '#E5E4E2',
    icon: '💎',
    himalayan: 'Dharma embodied',
  },
};

// Backward compatibility alias
export const TrustLevelInfo = KarmaLevelInfo;

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  // Time requirements for trust levels
  minAgeForGold: 0,                              // Immediate if mesh verified
  minAgeForPlatinum: 7 * 24 * 60 * 60 * 1000,    // 7 days for platinum
  
  // Beacon consistency requirements
  minBeaconConsistency: 0.8,                     // 80% uptime for platinum
  beaconCheckWindow: 7 * 24 * 60 * 60 * 1000,    // 7 day window
  
  // SSL requirements for platinum
  requireSSLForPlatinum: true,
  acceptSelfSignedSSL: true,                     // For DOKO-bound self-signed
  
  // Mesh verification requirements
  minQuorumForGold: 3,
  minDiversityForGold: 3,                        // Different subnets
  
  // Domain verification
  requireDomainForPlatinum: true,
  
  // Trust decay
  trustDecayEnabled: true,
  trustDecayPeriod: 30 * 24 * 60 * 60 * 1000,    // Decay after 30 days inactive
  
  // Automatic promotion
  autoPromoteEnabled: true,
  promotionCheckInterval: 60 * 60 * 1000,        // Check every hour
};

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * Karma Evidence - Records karmic actions and verification for a node
 * Like a spiritual ledger tracking the node's journey toward enlightenment
 * ═══════════════════════════════════════════════════════════════════════════
 */
class KarmaEvidence {
  constructor(nodeId) {
    this.nodeId = nodeId;
    this.createdAt = Date.now();
    this.lastUpdated = Date.now();
    
    // Evidence sources
    this.sources = {
      // DOKO verification via NAMCHE
      doko: {
        verified: false,
        verifiedAt: null,
        gatesPassedCount: 0,
        dokoHash: null,
      },
      
      // Mesh quorum verification
      meshQuorum: {
        verified: false,
        verifiedAt: null,
        quorumSize: 0,
        verifiers: [],
        diversity: null,
      },
      
      // SSL/TLS verification
      ssl: {
        verified: false,
        verifiedAt: null,
        certType: null,         // 'ca-signed', 'self-signed', 'doko-bound'
        certFingerprint: null,
        issuer: null,
      },
      
      // Domain ownership
      domain: {
        verified: false,
        verifiedAt: null,
        domain: null,
        proofCount: 0,
      },
      
      // Beacon consistency
      beaconHistory: {
        firstSeen: null,
        lastSeen: null,
        sightings: 0,
        consistency: 0,         // 0-1, percentage of expected beacons seen
      },
    };
    
    // Computed trust level
    this.trustLevel = TrustLevel.UNTRUSTED;
    this.trustScore = 0;        // 0-100 detailed score
    this.levelHistory = [];     // Track level changes
  }

  /**
   * Record DOKO verification
   */
  recordDokoVerification(result) {
    this.sources.doko = {
      verified: result.passed,
      verifiedAt: Date.now(),
      gatesPassedCount: result.gatesChecked || 7,
      dokoHash: result.dokoHash || null,
    };
    this.lastUpdated = Date.now();
  }

  /**
   * Record mesh quorum verification
   */
  recordMeshQuorum(result) {
    this.sources.meshQuorum = {
      verified: result.valid,
      verifiedAt: Date.now(),
      quorumSize: result.validProofs || 0,
      verifiers: result.verifiers || [],
      diversity: result.diversity || null,
    };
    this.lastUpdated = Date.now();
  }

  /**
   * Record SSL verification
   */
  recordSSLVerification(result) {
    this.sources.ssl = {
      verified: result.verified,
      verifiedAt: Date.now(),
      certType: result.certType || 'unknown',
      certFingerprint: result.fingerprint || null,
      issuer: result.issuer || null,
    };
    this.lastUpdated = Date.now();
  }

  /**
   * Record domain verification
   */
  recordDomainVerification(result) {
    this.sources.domain = {
      verified: result.valid,
      verifiedAt: Date.now(),
      domain: result.domain || null,
      proofCount: result.proofCount || 0,
    };
    this.lastUpdated = Date.now();
  }

  /**
   * Record beacon sighting
   */
  recordBeaconSighting() {
    const now = Date.now();
    
    if (!this.sources.beaconHistory.firstSeen) {
      this.sources.beaconHistory.firstSeen = now;
    }
    
    this.sources.beaconHistory.lastSeen = now;
    this.sources.beaconHistory.sightings++;
    this.lastUpdated = now;
  }

  /**
   * Calculate beacon consistency
   * @param {number} windowMs - Time window to check
   * @param {number} expectedInterval - Expected beacon interval
   */
  calculateBeaconConsistency(windowMs, expectedInterval = 60000) {
    const { firstSeen, sightings } = this.sources.beaconHistory;
    
    if (!firstSeen) {
      this.sources.beaconHistory.consistency = 0;
      return 0;
    }
    
    const timeActive = Date.now() - firstSeen;
    const effectiveWindow = Math.min(timeActive, windowMs);
    const expectedSightings = Math.floor(effectiveWindow / expectedInterval);
    
    if (expectedSightings === 0) {
      this.sources.beaconHistory.consistency = 1;
      return 1;
    }
    
    const consistency = Math.min(1, sightings / expectedSightings);
    this.sources.beaconHistory.consistency = consistency;
    return consistency;
  }

  /**
   * Get age since first seen
   */
  getAge() {
    const firstSeen = this.sources.beaconHistory.firstSeen;
    if (!firstSeen) return 0;
    return Date.now() - firstSeen;
  }

  /**
   * Serialize for persistence
   */
  serialize() {
    return {
      nodeId: this.nodeId,
      createdAt: this.createdAt,
      lastUpdated: this.lastUpdated,
      sources: this.sources,
      trustLevel: this.trustLevel,
      trustScore: this.trustScore,
      levelHistory: this.levelHistory.slice(-10),  // Keep last 10
    };
  }

  /**
   * Restore from persistence
   */
  static deserialize(data) {
    const evidence = new TrustEvidence(data.nodeId);
    evidence.createdAt = data.createdAt;
    evidence.lastUpdated = data.lastUpdated;
    evidence.sources = data.sources;
    evidence.trustLevel = data.trustLevel;
    evidence.trustScore = data.trustScore;
    evidence.levelHistory = data.levelHistory || [];
    return evidence;
  }
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * KARMA Trust Model - The wheel of cause and effect
 * Assesses and tracks trust levels based on cumulative actions
 * ═══════════════════════════════════════════════════════════════════════════
 */
export class KarmaTrustModel extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    // Karma evidence per node (spiritual ledger)
    this.evidence = new Map();  // nodeId -> KarmaEvidence
    
    // Stats
    this.stats = {
      assessmentsPerformed: 0,
      promotions: 0,
      demotions: 0,
      nodesByLevel: {
        [KarmaLevel.UNTRUSTED]: 0,
        [KarmaLevel.SEEKING]: 0,
        [KarmaLevel.AWAKENED]: 0,
        [KarmaLevel.ENLIGHTENED]: 0,
      },
    };
    
    // Promotion check interval (karmic advancement)
    this.promotionInterval = null;
    if (this.config.autoPromoteEnabled) {
      this.startPromotionChecks();
    }
  }

  /**
   * Get or create karma evidence for a node
   */
  getEvidence(nodeId) {
    if (!this.evidence.has(nodeId)) {
      this.evidence.set(nodeId, new KarmaEvidence(nodeId));
    }
    return this.evidence.get(nodeId);
  }

  /**
   * Record verification events
   */
  recordDokoVerification(nodeId, result) {
    const evidence = this.getEvidence(nodeId);
    evidence.recordDokoVerification(result);
    return this.assessTrust(nodeId);
  }

  recordMeshQuorum(nodeId, result) {
    const evidence = this.getEvidence(nodeId);
    evidence.recordMeshQuorum(result);
    return this.assessTrust(nodeId);
  }

  recordSSLVerification(nodeId, result) {
    const evidence = this.getEvidence(nodeId);
    evidence.recordSSLVerification(result);
    return this.assessTrust(nodeId);
  }

  recordDomainVerification(nodeId, result) {
    const evidence = this.getEvidence(nodeId);
    evidence.recordDomainVerification(result);
    return this.assessTrust(nodeId);
  }

  recordBeaconSighting(nodeId) {
    const evidence = this.getEvidence(nodeId);
    evidence.recordBeaconSighting();
    // Don't reassess on every beacon - too expensive
  }

  /**
   * Assess trust level for a node
   * 
   * @param {string} nodeId - Node to assess
   * @returns {Object} Trust assessment result
   */
  assessTrust(nodeId) {
    this.stats.assessmentsPerformed++;
    
    const evidence = this.getEvidence(nodeId);
    const previousLevel = evidence.trustLevel;
    
    // Calculate detailed score and level
    const assessment = this.calculateTrustLevel(evidence);
    
    evidence.trustLevel = assessment.level;
    evidence.trustScore = assessment.score;
    
    // Track level changes
    if (assessment.level !== previousLevel) {
      evidence.levelHistory.push({
        from: previousLevel,
        to: assessment.level,
        at: Date.now(),
        reason: assessment.reason,
      });
      
      // Update stats
      this.stats.nodesByLevel[previousLevel]--;
      this.stats.nodesByLevel[assessment.level]++;
      
      if (assessment.level > previousLevel) {
        this.stats.promotions++;
        this.emit('promoted', {
          nodeId,
          from: previousLevel,
          to: assessment.level,
          reason: assessment.reason,
        });
      } else {
        this.stats.demotions++;
        this.emit('demoted', {
          nodeId,
          from: previousLevel,
          to: assessment.level,
          reason: assessment.reason,
        });
      }
    }
    
    return {
      nodeId,
      level: assessment.level,
      levelInfo: TrustLevelInfo[assessment.level],
      score: assessment.score,
      reason: assessment.reason,
      requirements: assessment.requirements,
      evidence: this.summarizeEvidence(evidence),
    };
  }

  /**
   * Calculate trust level based on evidence
   */
  calculateTrustLevel(evidence) {
    const sources = evidence.sources;
    const age = evidence.getAge();
    
    // ═════════════════════════════════════════════════════════════════════
    // Check for UNTRUSTED conditions first
    // ═════════════════════════════════════════════════════════════════════
    
    // If DOKO verification explicitly failed (not just missing)
    if (sources.doko.verified === false && sources.doko.verifiedAt !== null) {
      return {
        level: TrustLevel.UNTRUSTED,
        score: 0,
        reason: 'DOKO verification failed',
        requirements: { dokoVerification: 'FAILED' },
      };
    }
    
    // Check for trust decay
    if (this.config.trustDecayEnabled) {
      const lastActivity = evidence.lastUpdated;
      const decayThreshold = Date.now() - this.config.trustDecayPeriod;
      
      if (lastActivity < decayThreshold) {
        return {
          level: TrustLevel.UNTRUSTED,
          score: 0,
          reason: 'Trust decayed due to inactivity',
          requirements: { activity: 'STALE' },
        };
      }
    }
    
    // ═════════════════════════════════════════════════════════════════════
    // Check for PLATINUM level
    // ═════════════════════════════════════════════════════════════════════
    
    const platinumRequirements = {
      doko: sources.doko.verified,
      meshQuorum: sources.meshQuorum.verified && 
                  sources.meshQuorum.quorumSize >= this.config.minQuorumForGold,
      meshDiversity: sources.meshQuorum.diversity?.sufficient || false,
      ssl: !this.config.requireSSLForPlatinum || sources.ssl.verified,
      age: age >= this.config.minAgeForPlatinum,
      domain: !this.config.requireDomainForPlatinum || sources.domain.verified,
      consistency: evidence.calculateBeaconConsistency(this.config.beaconCheckWindow) 
                   >= this.config.minBeaconConsistency,
    };
    
    const platinumScore = Object.values(platinumRequirements).filter(Boolean).length;
    const platinumTotal = Object.keys(platinumRequirements).length;
    
    if (platinumScore === platinumTotal) {
      return {
        level: TrustLevel.PLATINUM,
        score: 90 + (platinumScore / platinumTotal) * 10,
        reason: 'Full verification: SSL + Mesh + Time + Domain',
        requirements: platinumRequirements,
      };
    }
    
    // ═════════════════════════════════════════════════════════════════════
    // Check for GOLD level
    // ═════════════════════════════════════════════════════════════════════
    
    const goldRequirements = {
      doko: sources.doko.verified,
      meshQuorum: sources.meshQuorum.verified && 
                  sources.meshQuorum.quorumSize >= this.config.minQuorumForGold,
      meshDiversity: sources.meshQuorum.diversity?.sufficient || false,
    };
    
    const goldScore = Object.values(goldRequirements).filter(Boolean).length;
    const goldTotal = Object.keys(goldRequirements).length;
    
    if (goldScore === goldTotal) {
      // Calculate how close to platinum
      const progressTowardsPlatinum = platinumScore / platinumTotal;
      
      return {
        level: TrustLevel.GOLD,
        score: 50 + (progressTowardsPlatinum * 40),
        reason: 'Mesh verified with diverse quorum',
        requirements: goldRequirements,
        platinumProgress: platinumRequirements,
      };
    }
    
    // ═════════════════════════════════════════════════════════════════════
    // Default to BRONZE level
    // ═════════════════════════════════════════════════════════════════════
    
    const bronzeScore = (
      (sources.doko.verified ? 20 : 0) +
      (sources.beaconHistory.sightings > 0 ? 10 : 0) +
      (goldScore / goldTotal) * 20
    );
    
    return {
      level: TrustLevel.BRONZE,
      score: bronzeScore,
      reason: 'Self-asserted, awaiting mesh verification',
      requirements: {
        doko: sources.doko.verified,
        beaconSeen: sources.beaconHistory.sightings > 0,
      },
      goldProgress: goldRequirements,
    };
  }

  /**
   * Get current trust level for a node
   */
  getTrustLevel(nodeId) {
    if (!this.evidence.has(nodeId)) {
      return {
        level: TrustLevel.UNTRUSTED,
        levelInfo: TrustLevelInfo[TrustLevel.UNTRUSTED],
        score: 0,
        reason: 'Unknown node',
      };
    }
    
    const evidence = this.evidence.get(nodeId);
    return {
      level: evidence.trustLevel,
      levelInfo: TrustLevelInfo[evidence.trustLevel],
      score: evidence.trustScore,
    };
  }

  /**
   * Check if node meets minimum trust level
   */
  meetsMinimumTrust(nodeId, minLevel) {
    const { level } = this.getTrustLevel(nodeId);
    return level >= minLevel;
  }

  /**
   * Get all nodes at a specific trust level
   */
  getNodesByLevel(level) {
    const nodes = [];
    for (const [nodeId, evidence] of this.evidence.entries()) {
      if (evidence.trustLevel === level) {
        nodes.push({
          nodeId,
          score: evidence.trustScore,
          lastUpdated: evidence.lastUpdated,
        });
      }
    }
    return nodes;
  }

  /**
   * Summarize evidence for a node
   */
  summarizeEvidence(evidence) {
    return {
      doko: {
        verified: evidence.sources.doko.verified,
        at: evidence.sources.doko.verifiedAt,
      },
      meshQuorum: {
        verified: evidence.sources.meshQuorum.verified,
        quorumSize: evidence.sources.meshQuorum.quorumSize,
        diverse: evidence.sources.meshQuorum.diversity?.sufficient,
      },
      ssl: {
        verified: evidence.sources.ssl.verified,
        type: evidence.sources.ssl.certType,
      },
      domain: {
        verified: evidence.sources.domain.verified,
        domain: evidence.sources.domain.domain,
      },
      age: evidence.getAge(),
      consistency: evidence.sources.beaconHistory.consistency,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // AUTO-PROMOTION
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Start periodic promotion checks
   */
  startPromotionChecks() {
    if (this.promotionInterval) return;
    
    this.promotionInterval = setInterval(() => {
      this.checkAllForPromotion();
    }, this.config.promotionCheckInterval);
  }

  /**
   * Stop promotion checks
   */
  stopPromotionChecks() {
    if (this.promotionInterval) {
      clearInterval(this.promotionInterval);
      this.promotionInterval = null;
    }
  }

  /**
   * Check all nodes for possible promotion
   */
  checkAllForPromotion() {
    for (const nodeId of this.evidence.keys()) {
      this.assessTrust(nodeId);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PERSISTENCE
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Serialize for persistence
   */
  serialize() {
    const serializedEvidence = [];
    for (const [nodeId, evidence] of this.evidence.entries()) {
      serializedEvidence.push(evidence.serialize());
    }
    
    return {
      version: 1,
      timestamp: Date.now(),
      evidence: serializedEvidence,
      stats: this.stats,
    };
  }

  /**
   * Restore from persistence
   */
  restore(data) {
    if (data?.version !== 1) return;
    
    this.evidence.clear();
    
    for (const evidenceData of data.evidence || []) {
      const evidence = TrustEvidence.deserialize(evidenceData);
      this.evidence.set(evidence.nodeId, evidence);
    }
    
    if (data.stats) {
      this.stats = { ...this.stats, ...data.stats };
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    // Recount nodes by level
    const byLevel = {
      [TrustLevel.UNTRUSTED]: 0,
      [TrustLevel.BRONZE]: 0,
      [TrustLevel.GOLD]: 0,
      [TrustLevel.PLATINUM]: 0,
    };
    
    for (const evidence of this.evidence.values()) {
      byLevel[evidence.trustLevel]++;
    }
    
    return {
      ...this.stats,
      nodesByLevel: byLevel,
      totalNodes: this.evidence.size,
    };
  }

  /**
   * Clear all evidence (for testing)
   */
  clear() {
    this.evidence.clear();
    this.stats = {
      assessmentsPerformed: 0,
      promotions: 0,
      demotions: 0,
      nodesByLevel: {
        [TrustLevel.UNTRUSTED]: 0,
        [TrustLevel.BRONZE]: 0,
        [TrustLevel.GOLD]: 0,
        [TrustLevel.PLATINUM]: 0,
      },
    };
  }
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * TrustBasedAccessControl - Enforce trust level requirements
 * ═══════════════════════════════════════════════════════════════════════════
 */
export class TrustBasedAccessControl {
  constructor(trustModel) {
    this.trustModel = trustModel;
    
    // Default access requirements
    this.accessRequirements = {
      // Content serving/requesting
      'content:request': TrustLevel.BRONZE,
      'content:serve': TrustLevel.BRONZE,
      
      // Mesh participation
      'mesh:relay': TrustLevel.GOLD,
      'mesh:route': TrustLevel.GOLD,
      
      // Verification participation
      'verify:domain': TrustLevel.GOLD,
      'verify:quorum': TrustLevel.GOLD,
      
      // Admin functions
      'admin:revoke': TrustLevel.PLATINUM,
      'admin:announce': TrustLevel.GOLD,
    };
  }

  /**
   * Set access requirement for an action
   */
  setRequirement(action, level) {
    this.accessRequirements[action] = level;
  }

  /**
   * Check if node can perform action
   */
  canPerform(nodeId, action) {
    const required = this.accessRequirements[action];
    if (required === undefined) {
      return { allowed: true, reason: 'No requirement set' };
    }
    
    const { level, levelInfo } = this.trustModel.getTrustLevel(nodeId);
    
    if (level >= required) {
      return {
        allowed: true,
        nodeLevel: level,
        nodeLevelInfo: levelInfo,
        requiredLevel: required,
      };
    }
    
    return {
      allowed: false,
      reason: `Insufficient trust level`,
      nodeLevel: level,
      nodeLevelInfo: levelInfo,
      requiredLevel: required,
      requiredLevelInfo: TrustLevelInfo[required],
    };
  }

  /**
   * Middleware-style access check
   */
  requireTrust(minLevel) {
    return (nodeId) => {
      const { level } = this.trustModel.getTrustLevel(nodeId);
      if (level < minLevel) {
        const error = new Error(`Trust level ${minLevel} required, have ${level}`);
        error.code = 'INSUFFICIENT_TRUST';
        error.requiredLevel = minLevel;
        error.actualLevel = level;
        throw error;
      }
      return true;
    };
  }
}

// ============================================================
// EXPORTS - KARMA naming with backward compatibility
// ============================================================

// Primary exports (KARMA naming)
// KarmaLevel, KarmaLevelInfo, KarmaTrustModel are exported inline above
export { KarmaEvidence };

// Backward compatibility exports (original naming)
export { KarmaEvidence as TrustEvidence };
export { KarmaTrustModel as HybridTrustModel };

export default KarmaTrustModel;
