/**
 * Yakmesh Strike System v2.4
 * 
 * "Three Strikes — Then Math Speaks"
 * 
 * Tracks revocation lineage across identity resets.
 * Hardware fingerprints connect new identities to past behavior.
 * Each strike carries graduated consequences:
 * 
 *   Strike 1: Fresh start allowed, recorded in lineage
 *   Strike 2: 7-day probation period, reduced trust tier
 *   Strike 3: Permanent ban from network participation
 * 
 * Mathematical principle: A node can escape one identity,
 * but not its hardware. The silicon remembers.
 * 
 * Strike verification uses TRIBHUJ balanced ternary:
 *   POSITIVE (+1): Confirmed by network consensus
 *   NEUTRAL  ( 0): Pending — awaiting verification
 *   NEGATIVE (-1): Disputed — contested by the accused node
 * 
 * @module security/strike-system
 */

// ═══ TRIBHUJ — Balanced ternary for strike verification state ═══
import { POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

// Constants
const STRIKE_LEVELS = {
  CLEAN: 0,       // No strikes
  WARNING: 1,     // Strike 1 - fresh start allowed
  PROBATION: 2,   // Strike 2 - 7 day reduced trust
  BANNED: 3,      // Strike 3 - permanent
};

const PROBATION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const STRIKE_CONSEQUENCES = {
  [STRIKE_LEVELS.CLEAN]: {
    name: 'CLEAN',
    description: 'No strikes on record',
    canParticipate: true,
    trustMultiplier: 1.0,
    probationDays: 0,
  },
  [STRIKE_LEVELS.WARNING]: {
    name: 'WARNING',
    description: 'Strike 1 - Fresh start granted',
    canParticipate: true,
    trustMultiplier: 0.75,
    probationDays: 0,
  },
  [STRIKE_LEVELS.PROBATION]: {
    name: 'PROBATION',
    description: 'Strike 2 - 7-day probation period',
    canParticipate: true,
    trustMultiplier: 0.5,
    probationDays: 7,
  },
  [STRIKE_LEVELS.BANNED]: {
    name: 'BANNED',
    description: 'Strike 3 - Permanent network ban',
    canParticipate: false,
    trustMultiplier: 0,
    probationDays: Infinity,
  },
};

/**
 * Represents a single strike event
 */
class StrikeEvent {
  /**
   * @param {Object} options
   * @param {string} options.hardwareFingerprint - AES-NI hardware fingerprint
   * @param {string} options.nodeId - Node ID at time of strike
   * @param {string} options.reason - Why the strike was issued
   * @param {number} [options.timestamp] - When the strike occurred
   * @param {string[]} [options.attestors] - Who voted for revocation
   * @param {Object} [options.evidence] - Supporting evidence
   */
  constructor(options) {
    this.id = `strike-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    this.hardwareFingerprint = options.hardwareFingerprint;
    this.nodeId = options.nodeId;
    this.reason = options.reason;
    this.timestamp = options.timestamp || Date.now();
    this.attestors = options.attestors || [];
    this.evidence = options.evidence || {};
    this.verified = NEUTRAL;          // TRIBHUJ trit: starts NEUTRAL (pending)
  }

  /**
   * Mark this strike as verified by network consensus → POSITIVE
   * @param {string[]} verifyingNodes - Nodes that verified the strike
   */
  verify(verifyingNodes) {
    this.verified = POSITIVE;
    this.verifiedBy = verifyingNodes;
    this.verifiedAt = Date.now();
  }

  /**
   * Mark this strike as disputed by the accused node → NEGATIVE
   * @param {string} disputedBy - Node disputing the strike
   * @param {string} disputeReason - Why the strike is disputed
   */
  dispute(disputedBy, disputeReason) {
    this.verified = NEGATIVE;
    this.disputedBy = disputedBy;
    this.disputeReason = disputeReason;
    this.disputedAt = Date.now();
  }

  /** Check if this strike is confirmed (POSITIVE trit) */
  get isConfirmed() { return this.verified === POSITIVE; }

  /** Check if this strike is pending (NEUTRAL trit) */
  get isPending() { return this.verified === NEUTRAL; }

  /** Check if this strike is disputed (NEGATIVE trit) */
  get isDisputed() { return this.verified === NEGATIVE; }

  toJSON() {
    return {
      id: this.id,
      hardwareFingerprint: this.hardwareFingerprint,
      nodeId: this.nodeId,
      reason: this.reason,
      timestamp: this.timestamp,
      attestors: this.attestors,
      verified: this.verified,
      verifiedBy: this.verifiedBy,
      verifiedAt: this.verifiedAt,
    };
  }

  static fromJSON(json) {
    const event = new StrikeEvent({
      hardwareFingerprint: json.hardwareFingerprint,
      nodeId: json.nodeId,
      reason: json.reason,
      timestamp: json.timestamp,
      attestors: json.attestors,
      evidence: json.evidence,
    });
    event.id = json.id;
    event.verified = json.verified;
    event.verifiedBy = json.verifiedBy;
    event.verifiedAt = json.verifiedAt;
    return event;
  }
}

/**
 * Represents a hardware identity's complete strike history
 */
class StrikeRecord {
  /**
   * @param {string} hardwareFingerprint - AES-NI hardware fingerprint
   */
  constructor(hardwareFingerprint) {
    this.hardwareFingerprint = hardwareFingerprint;
    this.strikes = [];
    this.identityLineage = []; // All nodeIds this hardware has used
    this.createdAt = Date.now();
    this.lastUpdated = Date.now();
    this.probationStart = null;
    this.probationEnd = null;
  }

  /**
   * Get current strike count
   */
  get strikeCount() {
    return this.strikes.length;
  }

  /**
   * Get current strike level
   */
  get level() {
    const count = this.strikeCount;
    if (count === 0) return STRIKE_LEVELS.CLEAN;
    if (count === 1) return STRIKE_LEVELS.WARNING;
    if (count === 2) return STRIKE_LEVELS.PROBATION;
    return STRIKE_LEVELS.BANNED;
  }

  /**
   * Get consequences for current level
   */
  get consequences() {
    return STRIKE_CONSEQUENCES[this.level];
  }

  /**
   * Check if currently on probation
   */
  get isOnProbation() {
    if (this.level !== STRIKE_LEVELS.PROBATION) return false;
    if (!this.probationEnd) return false;
    return Date.now() < this.probationEnd;
  }

  /**
   * Check if probation has expired (can participate normally)
   */
  get probationExpired() {
    if (this.level !== STRIKE_LEVELS.PROBATION) return false;
    if (!this.probationEnd) return false;
    return Date.now() >= this.probationEnd;
  }

  /**
   * Check if this hardware can participate in the network
   */
  get canParticipate() {
    return this.consequences.canParticipate;
  }

  /**
   * Get trust multiplier based on strike status
   */
  get trustMultiplier() {
    // If on probation, reduced trust
    if (this.isOnProbation) {
      return STRIKE_CONSEQUENCES[STRIKE_LEVELS.PROBATION].trustMultiplier;
    }
    // If probation expired, back to warning level
    if (this.probationExpired) {
      return STRIKE_CONSEQUENCES[STRIKE_LEVELS.WARNING].trustMultiplier;
    }
    return this.consequences.trustMultiplier;
  }

  /**
   * Add a strike to the record
   * @param {StrikeEvent} strike
   */
  addStrike(strike) {
    if (strike.hardwareFingerprint !== this.hardwareFingerprint) {
      throw new Error('Strike fingerprint mismatch');
    }

    this.strikes.push(strike);
    this.lastUpdated = Date.now();

    // Track identity lineage
    if (!this.identityLineage.includes(strike.nodeId)) {
      this.identityLineage.push(strike.nodeId);
    }

    // Start probation if at strike 2
    if (this.strikeCount === 2) {
      this.probationStart = Date.now();
      this.probationEnd = this.probationStart + PROBATION_DURATION_MS;
    }

    return this;
  }

  /**
   * Add a node ID to identity lineage (for tracking fresh starts)
   * @param {string} nodeId
   */
  trackIdentity(nodeId) {
    if (!this.identityLineage.includes(nodeId)) {
      this.identityLineage.push(nodeId);
      this.lastUpdated = Date.now();
    }
  }

  /**
   * Check if a node ID is in this hardware's lineage
   * @param {string} nodeId
   */
  hasIdentity(nodeId) {
    return this.identityLineage.includes(nodeId);
  }

  /**
   * Get time remaining on probation in milliseconds
   */
  getProbationRemaining() {
    if (!this.isOnProbation) return 0;
    return Math.max(0, this.probationEnd - Date.now());
  }

  toJSON() {
    return {
      hardwareFingerprint: this.hardwareFingerprint,
      strikes: this.strikes.map(s => s.toJSON()),
      identityLineage: this.identityLineage,
      createdAt: this.createdAt,
      lastUpdated: this.lastUpdated,
      probationStart: this.probationStart,
      probationEnd: this.probationEnd,
      strikeCount: this.strikeCount,
      level: this.level,
      canParticipate: this.canParticipate,
    };
  }

  static fromJSON(json) {
    const record = new StrikeRecord(json.hardwareFingerprint);
    record.strikes = json.strikes.map(s => StrikeEvent.fromJSON(s));
    record.identityLineage = json.identityLineage || [];
    record.createdAt = json.createdAt;
    record.lastUpdated = json.lastUpdated;
    record.probationStart = json.probationStart;
    record.probationEnd = json.probationEnd;
    return record;
  }
}

/**
 * Manages the strike system for the network
 */
class StrikeRegistry {
  constructor() {
    // Map: hardwareFingerprint -> StrikeRecord
    this.records = new Map();
    
    // Map: nodeId -> hardwareFingerprint (identity mapping)
    this.identityToHardware = new Map();
    
    // Statistics
    this.stats = {
      totalStrikes: 0,
      totalBans: 0,
      activeProbations: 0,
      lookups: 0,
    };
  }

  /**
   * Register a hardware fingerprint with a node ID
   * @param {string} hardwareFingerprint
   * @param {string} nodeId
   * @returns {StrikeRecord}
   */
  registerIdentity(hardwareFingerprint, nodeId) {
    // Get or create record
    let record = this.records.get(hardwareFingerprint);
    if (!record) {
      record = new StrikeRecord(hardwareFingerprint);
      this.records.set(hardwareFingerprint, record);
    }

    // Track identity mapping
    record.trackIdentity(nodeId);
    this.identityToHardware.set(nodeId, hardwareFingerprint);

    return record;
  }

  /**
   * Get hardware fingerprint for a node ID
   * @param {string} nodeId
   * @returns {string|null}
   */
  getHardwareForNode(nodeId) {
    this.stats.lookups++;
    return this.identityToHardware.get(nodeId) || null;
  }

  /**
   * Get strike record for hardware fingerprint
   * @param {string} hardwareFingerprint
   * @returns {StrikeRecord|null}
   */
  getRecord(hardwareFingerprint) {
    this.stats.lookups++;
    return this.records.get(hardwareFingerprint) || null;
  }

  /**
   * Get strike record for a node ID
   * @param {string} nodeId
   * @returns {StrikeRecord|null}
   */
  getRecordByNodeId(nodeId) {
    const fingerprint = this.getHardwareForNode(nodeId);
    if (!fingerprint) return null;
    return this.getRecord(fingerprint);
  }

  /**
   * Issue a strike against a hardware fingerprint
   * @param {Object} options
   * @param {string} options.hardwareFingerprint
   * @param {string} options.nodeId
   * @param {string} options.reason
   * @param {string[]} [options.attestors]
   * @param {Object} [options.evidence]
   * @returns {Object} Result with strike event and consequences
   */
  issueStrike(options) {
    const { hardwareFingerprint, nodeId, reason, attestors, evidence } = options;

    // Get or create record
    let record = this.records.get(hardwareFingerprint);
    if (!record) {
      record = new StrikeRecord(hardwareFingerprint);
      this.records.set(hardwareFingerprint, record);
    }

    // Track the identity
    this.identityToHardware.set(nodeId, hardwareFingerprint);

    // Check if already banned
    if (record.level === STRIKE_LEVELS.BANNED) {
      return {
        success: false,
        reason: 'Hardware already permanently banned',
        record: record,
        consequences: record.consequences,
      };
    }

    // Create strike event
    const strike = new StrikeEvent({
      hardwareFingerprint,
      nodeId,
      reason,
      attestors,
      evidence,
    });

    // Add to record
    record.addStrike(strike);
    this.stats.totalStrikes++;

    // Track bans
    if (record.level === STRIKE_LEVELS.BANNED) {
      this.stats.totalBans++;
    }

    // Track probations
    if (record.level === STRIKE_LEVELS.PROBATION) {
      this.stats.activeProbations++;
    }

    return {
      success: true,
      strike: strike,
      record: record,
      consequences: record.consequences,
      previousStrikes: record.strikeCount - 1,
      newLevel: record.level,
    };
  }

  /**
   * Check if a node can participate in the network
   * @param {string} nodeId
   * @returns {Object} Participation status
   */
  checkParticipation(nodeId) {
    const record = this.getRecordByNodeId(nodeId);

    if (!record) {
      return {
        canParticipate: true,
        strikes: 0,
        level: STRIKE_LEVELS.CLEAN,
        trustMultiplier: 1.0,
        message: 'No record found - clean slate',
      };
    }

    return {
      canParticipate: record.canParticipate,
      strikes: record.strikeCount,
      level: record.level,
      trustMultiplier: record.trustMultiplier,
      isOnProbation: record.isOnProbation,
      probationRemaining: record.getProbationRemaining(),
      message: record.consequences.description,
    };
  }

  /**
   * Check if hardware fingerprint has any strikes
   * @param {string} hardwareFingerprint
   * @returns {Object}
   */
  checkHardware(hardwareFingerprint) {
    const record = this.getRecord(hardwareFingerprint);

    if (!record) {
      return {
        known: false,
        strikes: 0,
        level: STRIKE_LEVELS.CLEAN,
        canParticipate: true,
        identityLineage: [],
      };
    }

    return {
      known: true,
      strikes: record.strikeCount,
      level: record.level,
      canParticipate: record.canParticipate,
      identityLineage: record.identityLineage,
      trustMultiplier: record.trustMultiplier,
      isOnProbation: record.isOnProbation,
    };
  }

  /**
   * Detect if a new node is a fresh start from banned hardware
   * @param {string} hardwareFingerprint
   * @param {string} newNodeId
   * @returns {Object}
   */
  detectFreshStart(hardwareFingerprint, newNodeId) {
    const record = this.getRecord(hardwareFingerprint);

    if (!record) {
      return {
        isFreshStart: false,
        previousIdentities: [],
        strikes: 0,
        allowed: true,
      };
    }

    // Check if this is a new identity
    const isNewIdentity = !record.hasIdentity(newNodeId);

    return {
      isFreshStart: isNewIdentity && record.strikeCount > 0,
      previousIdentities: record.identityLineage,
      strikes: record.strikeCount,
      allowed: record.canParticipate,
      level: record.level,
      message: isNewIdentity && record.level === STRIKE_LEVELS.BANNED
        ? 'New identity detected but hardware is permanently banned'
        : record.consequences.description,
    };
  }

  /**
   * Get all banned hardware fingerprints
   * @returns {string[]}
   */
  getBannedHardware() {
    const banned = [];
    for (const [fingerprint, record] of this.records) {
      if (record.level === STRIKE_LEVELS.BANNED) {
        banned.push(fingerprint);
      }
    }
    return banned;
  }

  /**
   * Get all nodes currently on probation
   * @returns {Object[]}
   */
  getProbationList() {
    const onProbation = [];
    for (const [fingerprint, record] of this.records) {
      if (record.isOnProbation) {
        onProbation.push({
          hardwareFingerprint: fingerprint,
          identities: record.identityLineage,
          probationEnd: record.probationEnd,
          remaining: record.getProbationRemaining(),
        });
      }
    }
    return onProbation;
  }

  /**
   * Cleanup expired probations
   * @returns {number} Number of probations that expired
   */
  cleanupProbations() {
    let expired = 0;
    for (const record of this.records.values()) {
      if (record.probationExpired) {
        expired++;
      }
    }
    // Update stats
    this.stats.activeProbations = this.getProbationList().length;
    return expired;
  }

  /**
   * Get statistics
   */
  getStats() {
    this.cleanupProbations();
    return {
      ...this.stats,
      totalRecords: this.records.size,
      totalIdentities: this.identityToHardware.size,
      bannedCount: this.getBannedHardware().length,
      probationCount: this.getProbationList().length,
    };
  }

  /**
   * Export all records for persistence
   */
  export() {
    const records = [];
    for (const record of this.records.values()) {
      records.push(record.toJSON());
    }
    return {
      records,
      identityMap: Object.fromEntries(this.identityToHardware),
      stats: this.stats,
      exportedAt: Date.now(),
    };
  }

  /**
   * Import records from persistence
   * @param {Object} data
   */
  import(data) {
    for (const recordData of data.records) {
      const record = StrikeRecord.fromJSON(recordData);
      this.records.set(record.hardwareFingerprint, record);
    }

    if (data.identityMap) {
      for (const [nodeId, fingerprint] of Object.entries(data.identityMap)) {
        this.identityToHardware.set(nodeId, fingerprint);
      }
    }

    if (data.stats) {
      this.stats = { ...this.stats, ...data.stats };
    }
  }

  /**
   * Clear all records (for testing)
   */
  clear() {
    this.records.clear();
    this.identityToHardware.clear();
    this.stats = {
      totalStrikes: 0,
      totalBans: 0,
      activeProbations: 0,
      lookups: 0,
    };
  }
}

/**
 * Integration helper for combining strike system with revocation
 */
class StrikeRevocationBridge {
  /**
   * @param {StrikeRegistry} strikeRegistry
   * @param {Object} meshRevocation - MeshRevocation instance
   */
  constructor(strikeRegistry, meshRevocation) {
    this.strikeRegistry = strikeRegistry;
    this.meshRevocation = meshRevocation;
  }

  /**
   * Handle a successful revocation by issuing a strike
   * @param {string} hardwareFingerprint
   * @param {string} nodeId
   * @param {Object} revocationResult - Result from MeshRevocation
   * @returns {Object}
   */
  handleRevocation(hardwareFingerprint, nodeId, revocationResult) {
    if (!revocationResult.revoked) {
      return {
        strikeIssued: false,
        reason: 'Revocation not approved',
      };
    }

    const strikeResult = this.strikeRegistry.issueStrike({
      hardwareFingerprint,
      nodeId,
      reason: `Revoked by network consensus`,
      attestors: revocationResult.attestors || [],
      evidence: {
        revocationId: revocationResult.id,
        threshold: revocationResult.threshold,
        yesVotes: revocationResult.yesVotes,
      },
    });

    return {
      strikeIssued: true,
      strike: strikeResult.strike,
      newLevel: strikeResult.newLevel,
      consequences: strikeResult.consequences,
      previousStrikes: strikeResult.previousStrikes,
    };
  }

  /**
   * Check if a join request should be allowed
   * @param {string} hardwareFingerprint
   * @param {string} nodeId
   * @returns {Object}
   */
  validateJoin(hardwareFingerprint, nodeId) {
    const freshStart = this.strikeRegistry.detectFreshStart(hardwareFingerprint, nodeId);

    if (!freshStart.allowed) {
      return {
        allowed: false,
        reason: 'Hardware permanently banned',
        previousIdentities: freshStart.previousIdentities,
        strikes: freshStart.strikes,
      };
    }

    if (freshStart.isFreshStart) {
      // Register the new identity
      this.strikeRegistry.registerIdentity(hardwareFingerprint, nodeId);

      return {
        allowed: true,
        isFreshStart: true,
        warning: `Fresh start #${freshStart.strikes + 1} - previous identities tracked`,
        previousIdentities: freshStart.previousIdentities,
        strikes: freshStart.strikes,
        trustMultiplier: this.strikeRegistry.getRecord(hardwareFingerprint).trustMultiplier,
      };
    }

    // Normal join
    this.strikeRegistry.registerIdentity(hardwareFingerprint, nodeId);

    return {
      allowed: true,
      isFreshStart: false,
      strikes: freshStart.strikes,
      trustMultiplier: freshStart.strikes > 0
        ? this.strikeRegistry.getRecord(hardwareFingerprint).trustMultiplier
        : 1.0,
    };
  }
}

export {
  STRIKE_LEVELS,
  STRIKE_CONSEQUENCES,
  PROBATION_DURATION_MS,
  StrikeEvent,
  StrikeRecord,
  StrikeRegistry,
  StrikeRevocationBridge,
};
