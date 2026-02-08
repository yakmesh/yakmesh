/**
 * SAKSHI - Signal Attestation for Karma-based Scoring and Hardware Index
 * साक्षी (Nepali: "witness") - One who observes without interfering
 * 
 * A purely observational capability system for YAKMESH nodes.
 * 
 * KEY PHILOSOPHY:
 * - Tiers are OBSERVATIONAL METADATA, not permission gates
 * - Every node can do everything (if the math checks out)
 * - No action is denied based on tier
 * - Disagreement is resolved by re-computing, not voting
 * - "The math testifies in place of the node"
 * 
 * WHAT TIERS REPRESENT:
 * - Precision coefficients (how accurate is this node's data?)
 * - Reliability indicators (how likely is this node to be available?)
 * - Capability profiles (what hardware/time sources does this node have?)
 * 
 * WHAT TIERS DO NOT DO:
 * - Gate permissions (no "only SIRDAR can do X")
 * - Weight votes (no "SARATHI's opinion counts 3x")
 * - Create hierarchy of power (all correct answers are equal)
 * 
 * @module security/sakshi
 * @version 1.0.0
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { TIME_SOURCE } from './trust-tier.js';
import { Trit, POSITIVE, NEGATIVE, NEUTRAL, TritState } from '../oracle/tribhuj.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('security:sakshi');

// =============================================================================
// TERNARY OBSERVATION RESULT
// =============================================================================

/**
 * Ternary Observation States for SAKSHI
 * 
 * Aligns with TRIBHUJ balanced ternary:
 *   AGREED   (+1) = Observations match, math verified
 *   PENDING   (0) = Inconclusive, need more observations
 *   DISAGREED (-1) = Observations conflict, requires investigation
 */
export const OBSERVATION_STATE = Object.freeze({
  AGREED: POSITIVE,      // +1: All observations agree
  PENDING: NEUTRAL,      // 0: Inconclusive/need more data
  DISAGREED: NEGATIVE,   // -1: Observations conflict
});

/**
 * ObservationResult - Ternary result for SAKSHI observations
 * 
 * Like ValidationResult, but for observational consensus:
 * - AGREED: "The math matches across all witnesses"
 * - PENDING: "We need more witnesses or time to conclude"
 * - DISAGREED: "Witnesses report conflicting observations"
 * 
 * The third state (PENDING) is crucial for SAKSHI's philosophy:
 * "Observe without judging" - sometimes we genuinely don't know yet.
 */
export class ObservationResult {
  #state;      // Trit: AGREED(+1), DISAGREED(-1), PENDING(0)
  #reason;
  #data;       // Observation-specific data
  #confidence;
  
  /**
   * @param {number|Trit} state - Ternary state: +1 (agreed), -1 (disagreed), 0 (pending)
   * @param {string|null} reason - Reason for disagreed/pending state
   * @param {object|null} data - Observation data
   * @param {number} confidence - Confidence level 0-1
   */
  constructor(state, reason = null, data = null, confidence = 1.0) {
    if (state instanceof Trit) {
      this.#state = state;
    } else if (typeof state === 'boolean') {
      // BACKWARDS COMPAT: true → AGREED, false → DISAGREED
      this.#state = new Trit(state ? POSITIVE : NEGATIVE);
    } else {
      this.#state = new Trit(state);
    }
    
    this.#reason = reason;
    this.#data = data ? Object.freeze({ ...data }) : null;
    this.#confidence = Math.max(0, Math.min(1, confidence));
    
    Object.freeze(this);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Ternary State Accessors
  // ─────────────────────────────────────────────────────────────────────────
  
  /** The ternary state as a Trit */
  get state() { return this.#state; }
  
  /** Did all observations agree? (+1) */
  get isAgreed() { return this.#state.isPositive; }
  
  /** Did observations conflict? (-1) */
  get isDisagreed() { return this.#state.isNegative; }
  
  /** Is this inconclusive/pending? (0) */
  get isPending() { return this.#state.isNeutral; }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Backwards Compatibility (boolean interface)
  // ─────────────────────────────────────────────────────────────────────────
  
  /** @deprecated Use isAgreed instead. Returns true only for AGREED state. */
  get agreed() { return this.#state.isPositive; }
  
  get reason() { return this.#reason; }
  get data() { return this.#data; }
  get confidence() { return this.#confidence; }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Static Constructors
  // ─────────────────────────────────────────────────────────────────────────
  
  /** Create an AGREED (+1) result - observations match */
  static agreed(data = null, confidence = 1.0) {
    return new ObservationResult(POSITIVE, null, data, confidence);
  }
  
  /** Create a DISAGREED (-1) result - observations conflict */
  static disagreed(reason, data = null) {
    return new ObservationResult(NEGATIVE, reason, data, 0);
  }
  
  /** Create a PENDING (0) result - need more observations */
  static pending(reason = 'AWAITING_OBSERVATIONS', data = null, confidence = 0.5) {
    return new ObservationResult(NEUTRAL, reason, data, confidence);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Ternary Logic Operations
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Combine two observations using ternary AND.
   * Both must AGREE for result to be AGREED.
   * If either DISAGREES, result is DISAGREED.
   * Otherwise PENDING.
   */
  and(other) {
    const newState = this.#state.and(other.state);
    const reason = this.#reason || other.reason;
    const confidence = Math.min(this.#confidence, other.confidence);
    return new ObservationResult(newState, reason, this.#data || other.data, confidence);
  }
  
  /**
   * Combine two observations using ternary OR.
   * Either AGREEING makes result AGREED.
   * Both must DISAGREE for result to be DISAGREED.
   * Otherwise PENDING.
   */
  or(other) {
    const newState = this.#state.or(other.state);
    const reason = this.isAgreed ? null : (this.#reason || other.reason);
    const confidence = Math.max(this.#confidence, other.confidence);
    return new ObservationResult(newState, reason, this.#data || other.data, confidence);
  }
  
  /**
   * Consensus: do observations agree?
   * If both have same state, return that state.
   * If they differ, return PENDING.
   */
  consensus(other) {
    const newState = this.#state.consensus(other.state);
    const reason = newState.isNeutral ? 'OBSERVATION_DISAGREEMENT' : this.#reason;
    const confidence = newState.isNeutral ? 0.5 : this.#confidence;
    return new ObservationResult(newState, reason, this.#data, confidence);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Serialization
  // ─────────────────────────────────────────────────────────────────────────
  
  toJSON() {
    return Object.freeze({
      state: this.#state.value,
      agreed: this.#state.isPositive,   // Backwards compat
      isAgreed: this.#state.isPositive,
      isDisagreed: this.#state.isNegative,
      isPending: this.#state.isNeutral,
      reason: this.#reason,
      data: this.#data,
      confidence: this.#confidence,
    });
  }
  
  toString() {
    const stateStr = this.isAgreed ? 'AGREED' : (this.isDisagreed ? 'DISAGREED' : 'PENDING');
    return `ObservationResult(${stateStr}${this.#reason ? ': ' + this.#reason : ''})`;
  }
}

// =============================================================================
// CAPABILITY PROFILES
// =============================================================================

/**
 * Capability levels - purely descriptive, not hierarchical for permissions
 * 
 * These describe WHAT a node can contribute, not WHAT it's allowed to do.
 */
export const CAPABILITY_LEVEL = Object.freeze({
  // Precision time + hardware attestation + long history
  ATOMIC_VETERAN: 'atomic_veteran',
  
  // Precision time + hardware attestation
  PRECISION_NODE: 'precision_node',
  
  // Good time source + hardware
  RELIABLE_NODE: 'reliable_node',
  
  // Standard time source + hardware
  STANDARD_NODE: 'standard_node',
  
  // Basic participation
  BASIC_NODE: 'basic_node',
  
  // New/unverified
  NEW_NODE: 'new_node',
});

/**
 * Human-readable metadata for capability levels
 */
export const CAPABILITY_INFO = Object.freeze({
  [CAPABILITY_LEVEL.ATOMIC_VETERAN]: {
    name: 'Atomic Veteran',
    nepali: 'परमाणु वरिष्ठ',
    description: 'Atomic time precision with proven reliability history',
    color: '#FFD700',
  },
  [CAPABILITY_LEVEL.PRECISION_NODE]: {
    name: 'Precision Node',
    nepali: 'सटीक नोड',
    description: 'High-precision time source with hardware attestation',
    color: '#C0C0C0',
  },
  [CAPABILITY_LEVEL.RELIABLE_NODE]: {
    name: 'Reliable Node',
    nepali: 'विश्वसनीय नोड',
    description: 'GPS/PTP time with consistent uptime',
    color: '#CD7F32',
  },
  [CAPABILITY_LEVEL.STANDARD_NODE]: {
    name: 'Standard Node',
    nepali: 'मानक नोड',
    description: 'NTP synchronized with hardware attestation',
    color: '#4A90D9',
  },
  [CAPABILITY_LEVEL.BASIC_NODE]: {
    name: 'Basic Node',
    nepali: 'आधारभूत नोड',
    description: 'Meets minimum requirements for participation',
    color: '#7CB342',
  },
  [CAPABILITY_LEVEL.NEW_NODE]: {
    name: 'New Node',
    nepali: 'नयाँ नोड',
    description: 'Recently joined, building reliability history',
    color: '#9E9E9E',
  },
});

// =============================================================================
// PRECISION COEFFICIENTS
// =============================================================================

/**
 * Time precision coefficients (in milliseconds)
 * 
 * These indicate the expected accuracy of time-based attestations.
 * Lower = more precise. Used for data fusion, not voting.
 */
export const TIME_PRECISION = Object.freeze({
  [TIME_SOURCE.ATOMIC]: 0.1,     // ±0.1ms - atomic clock precision
  [TIME_SOURCE.GPS]: 1,          // ±1ms - GPS receiver precision
  [TIME_SOURCE.PTP]: 1,          // ±1ms - PTP network precision
  [TIME_SOURCE.NTP]: 50,         // ±50ms - typical NTP precision
  [TIME_SOURCE.SYSTEM]: 1000,    // ±1s - system clock only
});

/**
 * Reliability coefficients based on observed uptime
 * 
 * Maps uptime percentage to reliability coefficient (0-1).
 * Used for routing decisions and data fusion weighting.
 */
export function calculateReliabilityCoefficient(uptimePercent) {
  // Simple linear mapping with floor
  // 99%+ uptime = 1.0 reliability
  // 0% uptime = 0.1 reliability (not zero - new nodes still participate)
  return Math.max(0.1, Math.min(1.0, uptimePercent));
}

/**
 * Age confidence - how much history do we have?
 * 
 * Newer nodes have less historical data to base reliability on.
 * This doesn't gate actions - it indicates confidence in our assessment.
 */
export function calculateAgeConfidence(networkAgeDays) {
  // Confidence grows logarithmically, maxes at ~180 days
  if (networkAgeDays <= 0) return 0.1;
  if (networkAgeDays >= 180) return 1.0;
  return 0.1 + 0.9 * (Math.log10(networkAgeDays + 1) / Math.log10(181));
}

// =============================================================================
// NODE WITNESS PROFILE
// =============================================================================

/**
 * NodeWitness - A node's observed capability profile
 * 
 * This is purely descriptive - it witnesses what a node CAN do,
 * not what it's ALLOWED to do. Every node can attempt any action;
 * the math determines if the action succeeds.
 */
export class NodeWitness {
  /**
   * @param {Object} observed - Observed facts about the node
   * @param {string} observed.nodeId - Node identifier
   * @param {string} observed.timeSource - Best available time source
   * @param {boolean} observed.hasAESNI - Hardware attestation result
   * @param {number} observed.networkAgeDays - Days since first observed
   * @param {number} observed.uptimePercent - Observed uptime (0-1)
   * @param {number} observed.karmaScore - Accumulated positive actions
   */
  constructor(observed) {
    this.nodeId = observed.nodeId;
    this.timeSource = observed.timeSource || TIME_SOURCE.SYSTEM;
    this.hasAESNI = observed.hasAESNI || false;
    this.networkAgeDays = observed.networkAgeDays || 0;
    this.uptimePercent = observed.uptimePercent || 0;
    this.karmaScore = observed.karmaScore || 0;
    
    // Compute derived values
    this._capabilityLevel = this._assessCapability();
    this._timePrecision = TIME_PRECISION[this.timeSource] || TIME_PRECISION[TIME_SOURCE.SYSTEM];
    this._reliabilityCoefficient = calculateReliabilityCoefficient(this.uptimePercent);
    this._ageConfidence = calculateAgeConfidence(this.networkAgeDays);
    
    Object.freeze(this);
  }

  /**
   * Assess capability level based on observed facts
   * 
   * This is descriptive classification, not permission assignment.
   */
  _assessCapability() {
    const hasAtomicTime = this.timeSource === TIME_SOURCE.ATOMIC;
    const hasPrecisionTime = [TIME_SOURCE.ATOMIC, TIME_SOURCE.GPS, TIME_SOURCE.PTP].includes(this.timeSource);
    const hasGoodTime = [TIME_SOURCE.ATOMIC, TIME_SOURCE.GPS, TIME_SOURCE.PTP, TIME_SOURCE.NTP].includes(this.timeSource);
    const isVeteran = this.networkAgeDays >= 180 && this.uptimePercent >= 0.99;
    const isReliable = this.networkAgeDays >= 14 && this.uptimePercent >= 0.90;
    const isEstablished = this.networkAgeDays >= 1 && this.hasAESNI;

    if (hasAtomicTime && this.hasAESNI && isVeteran) {
      return CAPABILITY_LEVEL.ATOMIC_VETERAN;
    }
    if (hasPrecisionTime && this.hasAESNI && isReliable) {
      return CAPABILITY_LEVEL.PRECISION_NODE;
    }
    if (hasPrecisionTime && this.hasAESNI) {
      return CAPABILITY_LEVEL.RELIABLE_NODE;
    }
    if (hasGoodTime && isEstablished) {
      return CAPABILITY_LEVEL.STANDARD_NODE;
    }
    if (this.hasAESNI) {
      return CAPABILITY_LEVEL.BASIC_NODE;
    }
    return CAPABILITY_LEVEL.NEW_NODE;
  }

  // =========================================================================
  // GETTERS - All observational, no permissions
  // =========================================================================

  /** Observed capability level */
  get capabilityLevel() {
    return this._capabilityLevel;
  }

  /** Capability info for display */
  get capabilityInfo() {
    return CAPABILITY_INFO[this._capabilityLevel];
  }

  /** 
   * Time precision in milliseconds
   * Lower = more precise. Use for data fusion weighting.
   */
  get timePrecision() {
    return this._timePrecision;
  }

  /**
   * Reliability coefficient (0-1)
   * Based on observed uptime. Use for routing decisions.
   */
  get reliabilityCoefficient() {
    return this._reliabilityCoefficient;
  }

  /**
   * Age confidence (0-1)
   * How much history do we have to base our assessment on?
   */
  get ageConfidence() {
    return this._ageConfidence;
  }

  /**
   * Combined quality score for data fusion
   * 
   * This is NOT a voting weight - it's a quality indicator.
   * When fusing data from multiple sources, weight by quality.
   */
  get qualityScore() {
    // Combine reliability and age confidence
    // More uptime + more history = higher quality indicator
    return this._reliabilityCoefficient * this._ageConfidence;
  }

  /**
   * Can this node provide high-precision time attestations?
   * 
   * This is a capability check, not a permission check.
   * Even if false, the node can still participate - just with lower precision.
   */
  get canProvideHighPrecisionTime() {
    return this._timePrecision <= 1; // ≤1ms precision
  }

  /**
   * Is this node's hardware attested?
   * 
   * Hardware attestation increases confidence in cryptographic operations.
   */
  get isHardwareAttested() {
    return this.hasAESNI;
  }

  /**
   * Serialize to JSON
   */
  toJSON() {
    return {
      nodeId: this.nodeId,
      capabilityLevel: this._capabilityLevel,
      capabilityInfo: this.capabilityInfo,
      observed: {
        timeSource: this.timeSource,
        hasAESNI: this.hasAESNI,
        networkAgeDays: this.networkAgeDays,
        uptimePercent: this.uptimePercent,
        karmaScore: this.karmaScore,
      },
      derived: {
        timePrecision: this._timePrecision,
        reliabilityCoefficient: this._reliabilityCoefficient,
        ageConfidence: this._ageConfidence,
        qualityScore: this.qualityScore,
      },
    };
  }
}

// =============================================================================
// DATA FUSION (Not Voting!)
// =============================================================================

/**
 * PRAMAAN - Proof through mathematical agreement
 * प्रमाण (Sanskrit: "evidence, proof")
 * 
 * When multiple nodes provide data, we fuse it based on precision,
 * not vote on it based on tier weight.
 */

/**
 * Fuse time attestations from multiple witnesses
 * 
 * This is NOT voting. It's weighted averaging based on precision.
 * All nodes contribute - higher precision nodes' data is weighted more
 * because it's MORE ACCURATE, not because they have more "power."
 * 
 * @param {Array<{witness: NodeWitness, timestamp: number}>} attestations
 * @returns {Object} Fused result with confidence interval
 */
export function fuseTimeAttestations(attestations) {
  if (attestations.length === 0) {
    return { timestamp: null, confidence: 0, contributors: 0 };
  }

  if (attestations.length === 1) {
    const { witness, timestamp } = attestations[0];
    return {
      timestamp,
      precision: witness.timePrecision,
      confidence: witness.qualityScore,
      contributors: 1,
    };
  }

  // Weight by inverse precision (higher precision = higher weight)
  // This is physics, not politics - more accurate measurements dominate
  let weightSum = 0;
  let weightedSum = 0;
  
  for (const { witness, timestamp } of attestations) {
    // Weight = 1 / variance (precision squared)
    // This is standard sensor fusion math
    const weight = 1 / (witness.timePrecision * witness.timePrecision);
    weightSum += weight;
    weightedSum += weight * timestamp;
  }

  const fusedTimestamp = weightedSum / weightSum;
  
  // Combined precision improves with more measurements
  // This is the beauty of fusion - many imprecise measurements
  // can triangulate to high precision
  const fusedPrecision = Math.sqrt(1 / weightSum);

  // Confidence based on agreement
  // If all timestamps are within precision bounds, high confidence
  const deviations = attestations.map(({ witness, timestamp }) => 
    Math.abs(timestamp - fusedTimestamp) / witness.timePrecision
  );
  const maxDeviation = Math.max(...deviations);
  const agreementConfidence = maxDeviation <= 2 ? 1.0 : 1 / maxDeviation;

  return {
    timestamp: fusedTimestamp,
    precision: fusedPrecision,
    confidence: agreementConfidence,
    contributors: attestations.length,
  };
}

/**
 * Check for mathematical agreement on a value
 * 
 * This replaces "voting" - we don't ask "who agrees?"
 * We ask "does the math match?"
 * 
 * Returns TERNARY result (TRIBHUJ-aligned):
 *   AGREED (+1)   - All observations match
 *   PENDING (0)   - Not enough observations to conclude
 *   DISAGREED (-1) - Observations conflict, needs investigation
 * 
 * @param {Array<{witness: NodeWitness, value: any}>} observations
 * @param {Function} equalityFn - How to compare values (default: strict equality)
 * @param {Object} options - Agreement options
 * @returns {ObservationResult} Ternary agreement result
 */
export function checkMathematicalAgreement(observations, equalityFn = (a, b) => a === b, options = {}) {
  const { minObservations = 1 } = options;
  
  if (observations.length === 0) {
    // No observations - PENDING (we don't know yet)
    return ObservationResult.pending('NO_OBSERVATIONS', { count: 0 });
  }
  
  if (observations.length < minObservations) {
    // Not enough to conclude - PENDING
    return ObservationResult.pending('INSUFFICIENT_OBSERVATIONS', {
      count: observations.length,
      required: minObservations,
    }, observations.length / minObservations);
  }

  // Group by value
  const groups = new Map();
  for (const { witness, value } of observations) {
    let found = false;
    for (const [groupValue, members] of groups) {
      if (equalityFn(value, groupValue)) {
        members.push({ witness, value });
        found = true;
        break;
      }
    }
    if (!found) {
      groups.set(value, [{ witness, value }]);
    }
  }

  // If all agree (one group), the math matches - AGREED
  if (groups.size === 1) {
    const [[value, members]] = groups;
    return ObservationResult.agreed({
      value,
      contributors: members.length,
    }, 1.0);
  }

  // Disagreement - DISAGREED
  // This is a signal to RE-COMPUTE, not to vote
  const groupSizes = [...groups.values()].map(g => g.length);
  const largestGroup = Math.max(...groupSizes);
  
  return ObservationResult.disagreed('MATHEMATICAL_DISAGREEMENT', {
    groupCount: groups.size,
    largestGroupSize: largestGroup,
    totalObservations: observations.length,
    action: 'RECOMPUTE_AND_VERIFY',
  });
}

/**
 * Select best data source for routing
 * 
 * When we need to route through nodes, prefer reliable ones.
 * This is optimization, not gatekeeping - any node CAN route,
 * but we prefer nodes more likely to be available.
 * 
 * @param {NodeWitness[]} candidates - Available nodes
 * @param {Object} criteria - Selection criteria
 * @returns {NodeWitness[]} Sorted by suitability (best first)
 */
export function rankByReliability(candidates, criteria = {}) {
  const { 
    preferPrecisionTime = false,
    minimumReliability = 0, // No minimum by default - all can participate
  } = criteria;

  return candidates
    .filter(w => w.reliabilityCoefficient >= minimumReliability)
    .sort((a, b) => {
      // Primary: reliability coefficient
      let score = b.reliabilityCoefficient - a.reliabilityCoefficient;
      
      // Secondary: if precision time preferred, factor it in
      if (preferPrecisionTime && score === 0) {
        score = a.timePrecision - b.timePrecision; // Lower precision value = better
      }
      
      return score;
    });
}

// =============================================================================
// BUDDY SYSTEM - Mutual Verification
// =============================================================================

/**
 * The buddy system: nodes verify each other's work
 * 
 * This is not "permission to act" - it's "mutual checking."
 * A node performs an action, other nodes verify the math.
 * If the math matches, the action is valid. Period.
 */

/**
 * Create a verification request
 * 
 * Any node can request verification of any computation.
 * The verifiers check the math - they don't "approve" or "deny."
 * 
 * @param {Object} computation - What was computed
 * @param {NodeWitness} requester - Who computed it
 * @returns {Object} Verification request
 */
export function createVerificationRequest(computation, requester) {
  return {
    type: 'VERIFY_COMPUTATION',
    requesterId: requester.nodeId,
    computation,
    requestedAt: Date.now(),
    // Note: No "minimum tier required" - any node can verify
    // The math is the same regardless of who checks it
  };
}

/**
 * Process a verification response
 * 
 * A verifier independently computes the same thing.
 * If their result matches, that's mathematical agreement.
 * 
 * @param {Object} original - Original computation
 * @param {Object} verification - Verifier's independent computation
 * @param {Function} compareFn - How to compare results
 * @returns {Object} Verification result
 */
export function processVerification(original, verification, compareFn) {
  const matches = compareFn(original.result, verification.result);
  
  return {
    verified: matches,
    originalResult: original.result,
    verificationResult: verification.result,
    // If they don't match, one computation is wrong
    // The fix is to re-compute, not to vote on who's right
    action: matches ? 'ACCEPT' : 'RECOMPUTE_BOTH',
  };
}

// =============================================================================
// DISAGREEMENT ANALYSIS & REMEDIATION
// =============================================================================

/**
 * VIVAAD - Disagreement Analysis Module
 * विवाद (Sanskrit: "dispute, disagreement")
 * 
 * When mathematical disagreement occurs, we need to understand WHY.
 * Most disagreements are NOT malicious - they're due to:
 * 
 * 1. HARDWARE LIMITATIONS (~70% of cases)
 *    - Slower processor couldn't complete in time
 *    - Floating point precision differences (x87 vs SSE vs AVX)
 *    - Memory constraints causing partial results
 *    - No AES-NI causing crypto to fail or timeout
 * 
 * 2. TIMING/SYNCHRONIZATION (~15% of cases)
 *    - Nodes computing at different actual times (clock drift)
 *    - Phase epoch boundary edge cases
 *    - State changed during computation (race condition)
 *    - Timestamp disagreements due to NTP vs atomic
 * 
 * 3. NETWORK/DATA ISSUES (~10% of cases)
 *    - Different nodes received different input data
 *    - Incomplete information propagation
 *    - Message ordering differences
 *    - Packet loss causing stale data
 * 
 * 4. BYZANTINE/MALICIOUS (~5% of cases)
 *    - Node deliberately providing wrong answers
 *    - Sybil attacks
 *    - Compromised hardware
 *    - Malicious software
 * 
 * The key insight: treating all disagreements as attacks is wrong.
 * Most are honest failures that deserve remediation, not punishment.
 */

/**
 * Disagreement causes with estimated frequency
 */
export const DISAGREEMENT_CAUSE = Object.freeze({
  // Hardware limitations (~70%)
  COMPUTE_TIMEOUT: 'compute_timeout',           // CPU too slow
  FLOATING_POINT_VARIANCE: 'fp_variance',       // FP precision differs
  MEMORY_EXHAUSTED: 'memory_exhausted',         // OOM during computation
  CRYPTO_FAILURE: 'crypto_failure',             // Missing hardware accel
  
  // Timing issues (~15%)
  CLOCK_DRIFT: 'clock_drift',                   // Time desync
  EPOCH_BOUNDARY: 'epoch_boundary',             // Edge case at phase change
  RACE_CONDITION: 'race_condition',             // State changed mid-compute
  STALE_TIMESTAMP: 'stale_timestamp',           // Used old time data
  
  // Network issues (~10%)
  INCOMPLETE_DATA: 'incomplete_data',           // Didn't receive all inputs
  MESSAGE_ORDERING: 'message_ordering',         // Different order = different result
  PARTITION_VIEW: 'partition_view',             // Network partition caused divergence
  PROPAGATION_DELAY: 'propagation_delay',       // Got update late
  
  // Byzantine (~5%)
  DELIBERATE_WRONG: 'deliberate_wrong',         // Malicious answer
  SYBIL_ATTACK: 'sybil_attack',                 // Fake node cluster
  COMPROMISED: 'compromised',                   // Hardware/software compromised
  
  // Unknown
  UNKNOWN: 'unknown',                           // Can't determine cause
});

/**
 * Remediation actions based on disagreement cause
 */
export const REMEDIATION = Object.freeze({
  // Gentle remediations (honor system)
  RETRY_COMPUTATION: 'retry_computation',       // Just try again
  EXTEND_DEADLINE: 'extend_deadline',           // Give more time
  SHARE_RESULT: 'share_result',                 // Send correct answer to verify
  SYNC_STATE: 'sync_state',                     // Resync before retry
  REQUEST_INPUTS: 'request_inputs',             // Ask for missing data
  
  // Observational (update witness profile)
  NOTE_CAPABILITY: 'note_capability',           // Record this node can't do X
  REDUCE_PRECISION_EXPECTATION: 'reduce_precision', // Don't expect atomic precision
  INCREASE_TIMEOUT: 'increase_timeout',         // Remember this node is slow
  
  // Isolation (only for repeated byzantine behavior)
  TEMPORARY_COOLDOWN: 'temporary_cooldown',     // Pause interaction, 5 min
  REQUIRE_BUDDY: 'require_buddy',               // Must work with a partner
  ESCALATE_TO_MESH: 'escalate_to_mesh',         // Let the mesh observe
});

/**
 * Analyze a disagreement to determine likely cause
 * 
 * Uses TERNARY assessment (TRIBHUJ-aligned):
 *   BENIGN (+1)     - Clearly hardware/timing issue (no concern)
 *   INCONCLUSIVE (0) - Can't determine cause with certainty
 *   SUSPICIOUS (-1)  - Unexplained, warrants investigation
 * 
 * @param {Object} context - Disagreement context
 * @param {NodeWitness} context.nodeA - First node
 * @param {NodeWitness} context.nodeB - Second node  
 * @param {any} context.valueA - Node A's result
 * @param {any} context.valueB - Node B's result
 * @param {number} context.computeTimeA - How long A took (ms)
 * @param {number} context.computeTimeB - How long B took (ms)
 * @param {number} context.expectedTime - Expected computation time
 * @param {number} context.timestampDelta - Time difference between computations
 * @returns {Object} Analysis with likely cause and ternary assessment
 */
export function analyzeDisagreement(context) {
  const {
    nodeA, nodeB,
    valueA, valueB,
    computeTimeA = 0, computeTimeB = 0,
    expectedTime = 1000,
    timestampDelta = 0,
  } = context;

  // Analysis results with TERNARY assessment
  const analysis = {
    likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
    confidence: 0,
    factors: [],
    remediation: [],
    // TERNARY: BENIGN(+1), INCONCLUSIVE(0), SUSPICIOUS(-1)
    assessment: new Trit(NEUTRAL),  // Start inconclusive
    // Backwards compat (deprecated)
    get isBenign() { return this.assessment.isPositive; },
  };

  // ==========================================================================
  // HARDWARE ANALYSIS (~70% of disagreements)
  // ==========================================================================
  
  // Check for compute timeout
  const timeoutThreshold = expectedTime * 2;
  if (computeTimeA > timeoutThreshold || computeTimeB > timeoutThreshold) {
    analysis.factors.push({
      factor: 'COMPUTE_SLOW',
      detail: `Computation took ${Math.max(computeTimeA, computeTimeB)}ms vs expected ${expectedTime}ms`,
    });
    analysis.likelyCause = DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT;
    analysis.confidence = 0.8;
    analysis.assessment = new Trit(POSITIVE);  // BENIGN - hardware limitation
    analysis.remediation.push(REMEDIATION.EXTEND_DEADLINE);
    analysis.remediation.push(REMEDIATION.NOTE_CAPABILITY);
    return analysis;
  }

  // Check for floating point variance (numeric results close but not equal)
  if (typeof valueA === 'number' && typeof valueB === 'number') {
    const diff = Math.abs(valueA - valueB);
    const magnitude = Math.max(Math.abs(valueA), Math.abs(valueB), 1);
    const relativeDiff = diff / magnitude;
    
    if (relativeDiff < 1e-10) {
      analysis.factors.push({
        factor: 'FP_PRECISION',
        detail: `Values differ by ${relativeDiff} (floating point variance)`,
      });
      analysis.likelyCause = DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE;
      analysis.confidence = 0.9;
      analysis.assessment = new Trit(POSITIVE);  // BENIGN - expected FP behavior
      analysis.remediation.push(REMEDIATION.REDUCE_PRECISION_EXPECTATION);
      // This isn't really a disagreement - they agree within FP precision
      analysis.effectivelyAgree = true;
      return analysis;
    }
  }

  // Check for crypto hardware differences
  if (nodeA.hasAESNI !== nodeB.hasAESNI) {
    analysis.factors.push({
      factor: 'CRYPTO_HARDWARE_MISMATCH',
      detail: `Node A has AES-NI: ${nodeA.hasAESNI}, Node B: ${nodeB.hasAESNI}`,
    });
    // Node without AES-NI might timeout or produce different intermediate states
    analysis.likelyCause = DISAGREEMENT_CAUSE.CRYPTO_FAILURE;
    analysis.confidence = 0.7;
    analysis.assessment = new Trit(POSITIVE);  // BENIGN - hardware difference
    analysis.remediation.push(REMEDIATION.NOTE_CAPABILITY);
    analysis.remediation.push(REMEDIATION.INCREASE_TIMEOUT);
    return analysis;
  }

  // ==========================================================================
  // TIMING ANALYSIS (~15% of disagreements)
  // ==========================================================================
  
  // Check for clock drift
  const combinedPrecision = nodeA.timePrecision + nodeB.timePrecision;
  if (Math.abs(timestampDelta) > combinedPrecision) {
    analysis.factors.push({
      factor: 'CLOCK_DISAGREEMENT',
      detail: `Timestamp delta ${timestampDelta}ms exceeds combined precision ${combinedPrecision}ms`,
    });
    analysis.likelyCause = DISAGREEMENT_CAUSE.CLOCK_DRIFT;
    analysis.confidence = 0.75;
    analysis.assessment = new Trit(POSITIVE);  // BENIGN - clock issue
    analysis.remediation.push(REMEDIATION.SYNC_STATE);
    analysis.remediation.push(REMEDIATION.RETRY_COMPUTATION);
    return analysis;
  }

  // Check for significant precision difference
  if (nodeA.timePrecision / nodeB.timePrecision > 10 || nodeB.timePrecision / nodeA.timePrecision > 10) {
    analysis.factors.push({
      factor: 'PRECISION_MISMATCH',
      detail: `Time precision differs significantly: ${nodeA.timePrecision}ms vs ${nodeB.timePrecision}ms`,
    });
    analysis.likelyCause = DISAGREEMENT_CAUSE.STALE_TIMESTAMP;
    analysis.confidence = 0.6;
    analysis.assessment = new Trit(POSITIVE);  // BENIGN - precision mismatch
    analysis.remediation.push(REMEDIATION.SHARE_RESULT);
    return analysis;
  }

  // ==========================================================================
  // NETWORK ANALYSIS (~10% of disagreements)
  // ==========================================================================
  
  // If values are completely different types, likely incomplete data
  if (typeof valueA !== typeof valueB) {
    analysis.factors.push({
      factor: 'TYPE_MISMATCH',
      detail: `Value types differ: ${typeof valueA} vs ${typeof valueB}`,
    });
    analysis.likelyCause = DISAGREEMENT_CAUSE.INCOMPLETE_DATA;
    analysis.confidence = 0.8;
    analysis.assessment = new Trit(NEUTRAL);  // INCONCLUSIVE - could be network or malicious
    analysis.remediation.push(REMEDIATION.REQUEST_INPUTS);
    analysis.remediation.push(REMEDIATION.RETRY_COMPUTATION);
    return analysis;
  }

  // ==========================================================================
  // BYZANTINE ANALYSIS (~5% of disagreements)
  // ==========================================================================
  
  // Only consider byzantine if:
  // 1. Hardware is similar
  // 2. Timing is similar
  // 3. Data should be complete
  // AND they still disagree significantly
  
  const hardwareSimilar = nodeA.hasAESNI === nodeB.hasAESNI;
  const timingSimilar = Math.abs(computeTimeA - computeTimeB) < expectedTime * 0.5;
  const clocksSynced = Math.abs(timestampDelta) <= combinedPrecision;
  
  if (hardwareSimilar && timingSimilar && clocksSynced) {
    // Can't explain the disagreement with benign causes
    analysis.factors.push({
      factor: 'UNEXPLAINED_DISAGREEMENT',
      detail: 'Hardware, timing, and data all appear consistent, but values differ',
    });
    analysis.likelyCause = DISAGREEMENT_CAUSE.UNKNOWN;
    analysis.confidence = 0.5;
    analysis.assessment = new Trit(NEGATIVE);  // SUSPICIOUS - no benign explanation
    analysis.remediation.push(REMEDIATION.REQUIRE_BUDDY);
    analysis.remediation.push(REMEDIATION.ESCALATE_TO_MESH);
    return analysis;
  }

  // Default: unknown cause, INCONCLUSIVE, try again
  analysis.assessment = new Trit(NEUTRAL);  // INCONCLUSIVE
  analysis.remediation.push(REMEDIATION.RETRY_COMPUTATION);
  return analysis;
}

/**
 * Execute remediation for a disagreement
 * 
 * @param {Object} analysis - Analysis from analyzeDisagreement
 * @param {Object} options - Remediation options
 * @returns {Object} Remediation plan
 */
export function createRemediationPlan(analysis, options = {}) {
  const { 
    maxRetries = 3,
    timeoutMultiplier = 2,
    requireBuddyAfterFailures = 2,
  } = options;

  const plan = {
    steps: [],
    estimatedResolutionTime: 0,
    involvesOtherNodes: false,
  };

  for (const remediation of analysis.remediation) {
    switch (remediation) {
      case REMEDIATION.RETRY_COMPUTATION:
        plan.steps.push({
          action: 'RETRY',
          description: 'Re-run the computation with same inputs',
          maxAttempts: maxRetries,
          backoffMs: 1000,
        });
        plan.estimatedResolutionTime += 3000;
        break;

      case REMEDIATION.EXTEND_DEADLINE:
        plan.steps.push({
          action: 'EXTEND_TIMEOUT',
          description: 'Allow more time for slower hardware',
          multiplier: timeoutMultiplier,
        });
        break;

      case REMEDIATION.SHARE_RESULT:
        plan.steps.push({
          action: 'SHARE_AND_VERIFY',
          description: 'Share the computed result for independent verification',
        });
        plan.involvesOtherNodes = true;
        plan.estimatedResolutionTime += 5000;
        break;

      case REMEDIATION.SYNC_STATE:
        plan.steps.push({
          action: 'STATE_SYNC',
          description: 'Synchronize state/time before retrying',
        });
        plan.estimatedResolutionTime += 2000;
        break;

      case REMEDIATION.REQUEST_INPUTS:
        plan.steps.push({
          action: 'REQUEST_DATA',
          description: 'Request any missing input data',
        });
        plan.involvesOtherNodes = true;
        plan.estimatedResolutionTime += 3000;
        break;

      case REMEDIATION.NOTE_CAPABILITY:
        plan.steps.push({
          action: 'UPDATE_WITNESS',
          description: 'Record observed capability limitation for future reference',
          updateField: 'capabilityNotes',
        });
        break;

      case REMEDIATION.REDUCE_PRECISION_EXPECTATION:
        plan.steps.push({
          action: 'ACCEPT_VARIANCE',
          description: 'Accept floating point variance as agreement',
        });
        break;

      case REMEDIATION.REQUIRE_BUDDY:
        plan.steps.push({
          action: 'ASSIGN_BUDDY',
          description: 'Require buddy verification for future computations',
          afterFailures: requireBuddyAfterFailures,
        });
        plan.involvesOtherNodes = true;
        break;

      case REMEDIATION.ESCALATE_TO_MESH:
        plan.steps.push({
          action: 'MESH_OBSERVATION',
          description: 'Allow the mesh to observe and form opinion',
          isPassive: true,  // Not active punishment
        });
        plan.involvesOtherNodes = true;
        plan.estimatedResolutionTime += 60000;  // Let the mesh observe
        break;

      default:
        plan.steps.push({
          action: 'UNKNOWN_REMEDIATION',
          description: `Unhandled remediation: ${remediation}`,
        });
    }
  }

  return plan;
}

/**
 * Track disagreement history for a node
 * 
 * This is observational - we're recording patterns, not punishing.
 * A pattern of disagreements helps us understand the node's capabilities.
 * 
 * @param {Map} history - Node disagreement history (nodeId -> records)
 * @param {string} nodeId - Node identifier
 * @param {Object} analysis - Disagreement analysis
 * @returns {Object} Updated pattern assessment
 */
export function trackDisagreementPattern(history, nodeId, analysis) {
  if (!history.has(nodeId)) {
    history.set(nodeId, {
      disagreements: [],
      causeCounts: new Map(),
      firstSeen: Date.now(),
    });
  }

  const record = history.get(nodeId);
  
  // Add to history
  record.disagreements.push({
    cause: analysis.likelyCause,
    timestamp: Date.now(),
    isBenign: analysis.isBenign,
  });

  // Keep only last 100 disagreements
  if (record.disagreements.length > 100) {
    record.disagreements.shift();
  }

  // Update cause counts
  const count = record.causeCounts.get(analysis.likelyCause) || 0;
  record.causeCounts.set(analysis.likelyCause, count + 1);

  // Assess pattern
  const total = record.disagreements.length;
  const benignCount = record.disagreements.filter(d => d.isBenign).length;
  const suspiciousCount = total - benignCount;

  return {
    nodeId,
    totalDisagreements: total,
    benignRatio: total > 0 ? benignCount / total : 1,
    dominantCause: [...record.causeCounts.entries()]
      .sort((a, b) => b[1] - a[1])[0]?.[0] || null,
    // Insight: Is this node limited, or suspicious?
    assessment: suspiciousCount > 5 && benignCount / total < 0.5
      ? 'NEEDS_OBSERVATION'  // Many unexplained disagreements
      : 'NORMAL',           // Mostly benign disagreements (hardware/timing)
  };
}

// =============================================================================
// TRUST-TIER INTEGRATION BRIDGE
// =============================================================================

/**
 * SETU - Bridge between trust-tier and SAKSHI
 * सेतु (Sanskrit: "bridge")
 * 
 * Provides migration path from voting-based trust-tier patterns
 * to observation-based SAKSHI patterns.
 */

/**
 * Create a NodeWitness from a TrustProfile
 * 
 * This bridges the old TrustProfile (trust-tier.js) to the new
 * NodeWitness (sakshi.js) observational system.
 * 
 * @param {Object} trustProfile - TrustProfile instance or plain object
 * @returns {NodeWitness} SAKSHI NodeWitness
 */
export function witnessFromTrustProfile(trustProfile) {
  return new NodeWitness({
    nodeId: trustProfile.dokoId,
    timeSource: trustProfile.timeSource || TIME_SOURCE.SYSTEM,
    hasAESNI: trustProfile.hardwareAttestation?.validation?.hasAESNI || false,
    networkAgeDays: Math.floor((trustProfile.networkAge || 0) / (24 * 60 * 60 * 1000)),
    uptimePercent: 0.8,  // Default assumption if not tracked
    karmaScore: trustProfile.endorsementCount * 1000 || 0,
  });
}

/**
 * Create a TrustProfile-compatible object from a NodeWitness
 * 
 * For backwards compatibility with code expecting TrustProfile.
 * 
 * @param {NodeWitness} witness - SAKSHI NodeWitness
 * @param {string} dokoId - DOKO identifier
 * @returns {Object} TrustProfile-compatible object
 */
export function trustProfileFromWitness(witness, dokoId) {
  return {
    dokoId: dokoId || witness.nodeId,
    timeSource: witness.timeSource,
    networkAge: witness.networkAgeDays * 24 * 60 * 60 * 1000,
    // Note: We don't expose getWeight() - that's the voting pattern we're removing
    // Instead, provide precision-based quality score
    qualityScore: witness.qualityScore,
    timePrecision: witness.timePrecision,
    reliabilityCoefficient: witness.reliabilityCoefficient,
    capabilityLevel: witness.capabilityLevel,
  };
}

/**
 * SAKSHI-aligned revocation check
 * 
 * Replaces WeightedRevocationCalculator.isRevoked()
 * 
 * Instead of weighted voting ("SIRDAR's vote counts 2x"),
 * we check for mathematical agreement on revocation evidence.
 * 
 * Returns TERNARY result (TRIBHUJ-aligned):
 *   AGREED (+1)   - Evidence agrees, revocation confirmed
 *   PENDING (0)   - Not enough evidence to conclude
 *   DISAGREED (-1) - Evidence conflicts, needs investigation
 * 
 * @param {Array<{witness: NodeWitness, evidence: Object}>} revocationReports
 * @param {Object} options
 * @returns {ObservationResult} Ternary revocation assessment
 */
export function checkRevocationAgreement(revocationReports, options = {}) {
  const {
    minReports = 3,
    requirePrecisionNode = false,
  } = options;

  if (revocationReports.length < minReports) {
    // Not enough reports - PENDING (need more witnesses)
    return ObservationResult.pending('INSUFFICIENT_REPORTS', {
      reportCount: revocationReports.length,
      minRequired: minReports,
    }, revocationReports.length / minReports);
  }

  // Check if reports agree on the revocation reason
  const evidenceAgreement = checkMathematicalAgreement(
    revocationReports.map(r => ({
      witness: r.witness,
      value: JSON.stringify({
        reason: r.evidence.reason,
        targetId: r.evidence.targetId,
      }),
    }))
  );

  if (evidenceAgreement.isDisagreed) {
    // Evidence conflicts - DISAGREED (needs investigation)
    return ObservationResult.disagreed('EVIDENCE_DISAGREEMENT', {
      groupCount: evidenceAgreement.data?.groupCount,
      suggestion: 'Gather more evidence or investigate discrepancies',
    });
  }
  
  if (evidenceAgreement.isPending) {
    // Still awaiting consensus
    return ObservationResult.pending(evidenceAgreement.reason, evidenceAgreement.data);
  }

  // All reports agree on the evidence
  // Fuse the timestamps to establish when it happened
  const timestampFusion = fuseTimeAttestations(
    revocationReports
      .filter(r => r.evidence.timestamp)
      .map(r => ({
        witness: r.witness,
        timestamp: r.evidence.timestamp,
      }))
  );

  // Check for at least one precision node if required
  if (requirePrecisionNode) {
    const hasPrecisionWitness = revocationReports.some(r => 
      [TIME_SOURCE.ATOMIC, TIME_SOURCE.GPS, TIME_SOURCE.PTP].includes(r.witness.timeSource)
    );
    
    if (!hasPrecisionWitness) {
      // Need precision witness - PENDING
      return ObservationResult.pending('NO_PRECISION_WITNESS', {
        suggestion: 'Wait for confirmation from a precision time node',
        currentReports: revocationReports.length,
      }, 0.7);
    }
  }

  // Mathematical agreement achieved - AGREED (revocation confirmed)
  return ObservationResult.agreed({
    evidence: JSON.parse(evidenceAgreement.data?.value || '{}'),
    reportCount: revocationReports.length,
    timestamp: timestampFusion.timestamp,
    timestampPrecision: timestampFusion.precision,
  }, evidenceAgreement.confidence);
}

/**
 * SAKSHI-aligned attestation aggregation
 * 
 * Replaces calculateEffectiveCount() (weighted voting)
 * 
 * Instead of "SIRDAR's attestation counts 2x", we:
 * 1. Check if attestations mathematically agree
 * 2. Fuse timestamps with precision weighting (physics, not politics)
 * 3. Rank by reliability for informational purposes only
 * 
 * Returns TERNARY result (TRIBHUJ-aligned):
 *   AGREED (+1)   - All attestations agree
 *   PENDING (0)   - Not enough attestations
 *   DISAGREED (-1) - Attestations conflict
 * 
 * @param {Array<{witness: NodeWitness, attestation: Object}>} attestations
 * @param {Object} options - Aggregation options
 * @returns {ObservationResult} Ternary aggregation result
 */
export function aggregateAttestations(attestations, options = {}) {
  const { minAttestations = 1 } = options;
  
  if (attestations.length === 0) {
    return ObservationResult.pending('NO_ATTESTATIONS', { count: 0 });
  }
  
  if (attestations.length < minAttestations) {
    return ObservationResult.pending('INSUFFICIENT_ATTESTATIONS', {
      count: attestations.length,
      required: minAttestations,
    }, attestations.length / minAttestations);
  }

  // Extract the attestation values for agreement check
  const agreement = checkMathematicalAgreement(
    attestations.map(a => ({
      witness: a.witness,
      value: JSON.stringify(a.attestation.claim),
    }))
  );

  // If disagreed, return the disagreement
  if (agreement.isDisagreed) {
    return ObservationResult.disagreed('ATTESTATION_DISAGREEMENT', {
      groupCount: agreement.data?.groupCount,
      totalAttestations: attestations.length,
    });
  }
  
  // If still pending, propagate
  if (agreement.isPending) {
    return ObservationResult.pending(agreement.reason, agreement.data, agreement.confidence);
  }

  // Attestations agree - fuse any timestamp data
  const withTimestamps = attestations.filter(a => a.attestation.timestamp);
  const timestampFusion = withTimestamps.length > 0
    ? fuseTimeAttestations(withTimestamps.map(a => ({
        witness: a.witness,
        timestamp: a.attestation.timestamp,
      })))
    : null;

  // Rank witnesses by reliability (informational, not gatekeeping)
  const rankedWitnesses = rankByReliability(attestations.map(a => a.witness));

  return ObservationResult.agreed({
    claim: JSON.parse(agreement.data?.value || '{}'),
    attestationCount: attestations.length,
    // Note: No "effectiveCount" - all agreeing attestations are equal
    timestamp: timestampFusion?.timestamp,
    timestampPrecision: timestampFusion?.precision,
    // Informational: who contributed (sorted by reliability)
    contributors: rankedWitnesses.map(w => ({
      nodeId: w.nodeId,
      capabilityLevel: w.capabilityLevel,
      qualityScore: w.qualityScore,
    })),
  }, agreement.confidence);
}

/**
 * Check if a computation should be trusted
 * 
 * SAKSHI approach: We don't trust based on WHO computed it,
 * we trust based on WHETHER the math is verifiable.
 * 
 * @param {Object} computation - The computation result
 * @param {NodeWitness} computedBy - Who performed the computation
 * @param {Object} options - Verification options
 * @returns {Object} Trust assessment
 */
export function assessComputationTrust(computation, computedBy, options = {}) {
  const {
    requireVerification = false,
    verifications = [],
  } = options;

  // Base trust: Is the computation mathematically verifiable?
  const isVerifiable = computation.proof !== undefined || 
                       computation.checksum !== undefined ||
                       computation.signature !== undefined;

  if (!isVerifiable && !requireVerification) {
    // No proof, but verification not required
    // Trust is based on being able to reproduce
    return {
      trusted: true,
      basis: 'REPRODUCIBLE',
      suggestion: 'Verify by independent recomputation if critical',
      computedBy: {
        nodeId: computedBy.nodeId,
        capabilityLevel: computedBy.capabilityLevel,
        // Note: No "weight" or "trustLevel" - just capability info
      },
    };
  }

  if (!isVerifiable && requireVerification) {
    return {
      trusted: false,
      basis: 'UNVERIFIABLE',
      action: 'REQUEST_PROOF',
      suggestion: 'Ask the computing node to provide verifiable proof',
    };
  }

  // Has proof - check if we have verifications
  if (verifications.length === 0) {
    return {
      trusted: true,
      basis: 'HAS_PROOF',
      proofType: computation.proof ? 'PROOF' : computation.checksum ? 'CHECKSUM' : 'SIGNATURE',
      suggestion: 'Independently verify the proof for higher confidence',
    };
  }

  // Check if verifications agree
  const verificationAgreement = checkMathematicalAgreement(
    verifications.map(v => ({
      witness: v.verifier,
      value: v.verified ? 'VALID' : 'INVALID',
    }))
  );

  if (verificationAgreement.agreed && verificationAgreement.value === 'VALID') {
    return {
      trusted: true,
      basis: 'VERIFIED',
      verifierCount: verifications.length,
      confidence: verificationAgreement.confidence,
    };
  }

  if (verificationAgreement.agreed && verificationAgreement.value === 'INVALID') {
    return {
      trusted: false,
      basis: 'VERIFICATION_FAILED',
      verifierCount: verifications.length,
      action: 'RECOMPUTE',
    };
  }

  // Verifiers disagree
  return {
    trusted: false,
    basis: 'VERIFIERS_DISAGREE',
    action: verificationAgreement.action,
    suggestion: 'Need more verifiers or investigate disagreement',
  };
}

// =============================================================================
// BEHAVIOR VELOCITY MONITORING
// =============================================================================

/**
 * VEGATI - Velocity-based Behavior Change Detection
 * वेगति (Sanskrit: "velocity, momentum")
 * 
 * Monitors nodes for sudden behavioral changes that may indicate:
 * - Compromised hardware/keys
 * - Reputation farming then abuse
 * - Insider threat activation
 * 
 * Uses exponential moving average to establish behavioral baselines,
 * then triggers alerts when current behavior deviates significantly.
 */

/**
 * Velocity alert severity levels
 */
export const VELOCITY_ALERT = Object.freeze({
  NORMAL: 'normal',           // Within expected variance
  ELEVATED: 'elevated',       // Notable change, monitor closely
  WARNING: 'warning',         // Significant deviation
  CRITICAL: 'critical',       // Dramatic behavioral shift
});

/**
 * Behavior dimensions tracked for velocity detection
 */
export const BEHAVIOR_DIMENSION = Object.freeze({
  MESSAGE_RATE: 'message_rate',         // Messages per minute
  GOSSIP_RATIO: 'gossip_ratio',         // Gossip vs direct messages
  ERROR_RATE: 'error_rate',             // Invalid messages/signatures
  ATTESTATION_RATE: 'attestation_rate', // Revocation attestations filed
  CONNECTION_CHURN: 'connection_churn', // Connect/disconnect frequency
  RESPONSE_LATENCY: 'response_latency', // Average response time
});

/**
 * BehaviorVelocityMonitor - Tracks behavioral baselines and detects anomalies
 * 
 * Each node builds a behavioral "fingerprint" over time.
 * Sudden changes from this fingerprint trigger velocity alerts.
 */
export class BehaviorVelocityMonitor {
  constructor(options = {}) {
    this.profiles = new Map();  // nodeId -> BehaviorProfile
    
    // Configuration
    this.config = {
      // EMA smoothing factor (0-1, lower = slower adaptation)
      emaSmoothingFactor: options.emaSmoothingFactor || 0.1,
      
      // Minimum observations before establishing baseline
      minObservationsForBaseline: options.minObservationsForBaseline || 50,
      
      // Standard deviation thresholds for alerts
      thresholds: {
        elevated: options.elevatedThreshold || 2.0,   // 2 sigma
        warning: options.warningThreshold || 3.0,     // 3 sigma
        critical: options.criticalThreshold || 4.0,   // 4 sigma
      },
      
      // Cooldown period after alert before re-alerting (ms)
      alertCooldown: options.alertCooldown || 60000,
      
      // Profile retention (ms)
      profileTTL: options.profileTTL || 7 * 24 * 60 * 60 * 1000, // 7 days
    };
    
    // Alert callbacks
    this.alertCallbacks = [];
    
    log.info('vegati', 'Behavior velocity monitor initialized');
  }

  /**
   * Register a callback for velocity alerts
   */
  onAlert(callback) {
    this.alertCallbacks.push(callback);
  }

  /**
   * Record an observation for a node
   * 
   * @param {string} nodeId - Node identifier
   * @param {string} dimension - Which behavior dimension (from BEHAVIOR_DIMENSION)
   * @param {number} value - Observed value
   * @returns {Object} Current velocity status for this dimension
   */
  observe(nodeId, dimension, value) {
    let profile = this.profiles.get(nodeId);
    
    if (!profile) {
      profile = this._createProfile(nodeId);
      this.profiles.set(nodeId, profile);
    }
    
    profile.lastSeen = Date.now();
    
    // Get or create dimension stats
    let stats = profile.dimensions.get(dimension);
    if (!stats) {
      stats = {
        count: 0,
        ema: value,          // Exponential moving average
        emVar: 0,            // Exponential moving variance
        lastValue: value,
        lastAlert: 0,
        alertCount: 0,
      };
      profile.dimensions.set(dimension, stats);
    }
    
    stats.count++;
    stats.lastValue = value;
    
    // Update EMA (baseline)
    const alpha = this.config.emaSmoothingFactor;
    const delta = value - stats.ema;
    stats.ema = stats.ema + alpha * delta;
    
    // Update exponential moving variance (for std dev calculation)
    stats.emVar = (1 - alpha) * (stats.emVar + alpha * delta * delta);
    
    // Only check velocity once we have baseline
    if (stats.count < this.config.minObservationsForBaseline) {
      return {
        status: VELOCITY_ALERT.NORMAL,
        reason: 'BUILDING_BASELINE',
        progress: stats.count / this.config.minObservationsForBaseline,
      };
    }
    
    // Calculate z-score (standard deviations from mean)
    const stdDev = Math.sqrt(stats.emVar);
    const zScore = stdDev > 0 ? Math.abs(delta) / stdDev : 0;
    
    // Determine alert level
    let alertLevel = VELOCITY_ALERT.NORMAL;
    if (zScore >= this.config.thresholds.critical) {
      alertLevel = VELOCITY_ALERT.CRITICAL;
    } else if (zScore >= this.config.thresholds.warning) {
      alertLevel = VELOCITY_ALERT.WARNING;
    } else if (zScore >= this.config.thresholds.elevated) {
      alertLevel = VELOCITY_ALERT.ELEVATED;
    }
    
    // Emit alert if significant and not in cooldown
    const now = Date.now();
    if (alertLevel !== VELOCITY_ALERT.NORMAL && 
        now - stats.lastAlert > this.config.alertCooldown) {
      stats.lastAlert = now;
      stats.alertCount++;
      
      const alert = {
        nodeId,
        dimension,
        level: alertLevel,
        zScore,
        currentValue: value,
        baselineEma: stats.ema,
        baselineStdDev: stdDev,
        deviation: delta,
        alertCount: stats.alertCount,
        timestamp: now,
      };
      
      // Emit to callbacks
      for (const callback of this.alertCallbacks) {
        try {
          callback(alert);
        } catch (e) {
          log.error('vegati', 'Alert callback error', { error: e.message });
        }
      }
      
      log.warn('vegati', `Velocity alert: ${alertLevel}`, {
        nodeId,
        dimension,
        zScore: zScore.toFixed(2),
        deviation: delta.toFixed(4),
      });
    }
    
    return {
      status: alertLevel,
      zScore,
      deviation: delta,
      baseline: stats.ema,
      stdDev,
    };
  }

  /**
   * Get the current behavioral profile for a node
   */
  getProfile(nodeId) {
    const profile = this.profiles.get(nodeId);
    if (!profile) return null;
    
    const dimensions = {};
    for (const [dim, stats] of profile.dimensions) {
      dimensions[dim] = {
        baseline: stats.ema,
        stdDev: Math.sqrt(stats.emVar),
        observations: stats.count,
        lastValue: stats.lastValue,
        alertCount: stats.alertCount,
        hasBaseline: stats.count >= this.config.minObservationsForBaseline,
      };
    }
    
    return {
      nodeId: profile.nodeId,
      createdAt: profile.createdAt,
      lastSeen: profile.lastSeen,
      dimensions,
    };
  }

  /**
   * Get nodes with active alerts
   */
  getActiveAlerts() {
    const alerts = [];
    const now = Date.now();
    
    for (const profile of this.profiles.values()) {
      for (const [dim, stats] of profile.dimensions) {
        if (stats.alertCount > 0 && now - stats.lastAlert < this.config.alertCooldown * 2) {
          const stdDev = Math.sqrt(stats.emVar);
          const zScore = stdDev > 0 ? Math.abs(stats.lastValue - stats.ema) / stdDev : 0;
          
          let level = VELOCITY_ALERT.NORMAL;
          if (zScore >= this.config.thresholds.critical) level = VELOCITY_ALERT.CRITICAL;
          else if (zScore >= this.config.thresholds.warning) level = VELOCITY_ALERT.WARNING;
          else if (zScore >= this.config.thresholds.elevated) level = VELOCITY_ALERT.ELEVATED;
          
          if (level !== VELOCITY_ALERT.NORMAL) {
            alerts.push({
              nodeId: profile.nodeId,
              dimension: dim,
              level,
              zScore,
              totalAlerts: stats.alertCount,
              lastAlert: stats.lastAlert,
            });
          }
        }
      }
    }
    
    return alerts;
  }

  /**
   * Get aggregate velocity statistics
   */
  getStats() {
    let totalProfiles = 0;
    let profilesWithBaseline = 0;
    let activeAlerts = 0;
    const alertsByLevel = {
      [VELOCITY_ALERT.ELEVATED]: 0,
      [VELOCITY_ALERT.WARNING]: 0,
      [VELOCITY_ALERT.CRITICAL]: 0,
    };
    
    for (const profile of this.profiles.values()) {
      totalProfiles++;
      let hasAnyBaseline = false;
      
      for (const [dim, stats] of profile.dimensions) {
        if (stats.count >= this.config.minObservationsForBaseline) {
          hasAnyBaseline = true;
        }
        
        if (stats.alertCount > 0) {
          const stdDev = Math.sqrt(stats.emVar);
          const zScore = stdDev > 0 ? Math.abs(stats.lastValue - stats.ema) / stdDev : 0;
          
          if (zScore >= this.config.thresholds.critical) {
            activeAlerts++;
            alertsByLevel[VELOCITY_ALERT.CRITICAL]++;
          } else if (zScore >= this.config.thresholds.warning) {
            activeAlerts++;
            alertsByLevel[VELOCITY_ALERT.WARNING]++;
          } else if (zScore >= this.config.thresholds.elevated) {
            activeAlerts++;
            alertsByLevel[VELOCITY_ALERT.ELEVATED]++;
          }
        }
      }
      
      if (hasAnyBaseline) profilesWithBaseline++;
    }
    
    return {
      totalProfiles,
      profilesWithBaseline,
      activeAlerts,
      alertsByLevel,
    };
  }

  /**
   * Cleanup old profiles
   */
  cleanup() {
    const now = Date.now();
    let removed = 0;
    
    for (const [nodeId, profile] of this.profiles) {
      if (now - profile.lastSeen > this.config.profileTTL) {
        this.profiles.delete(nodeId);
        removed++;
      }
    }
    
    if (removed > 0) {
      log.info('vegati', `Cleaned up ${removed} stale profiles`);
    }
    
    return removed;
  }

  _createProfile(nodeId) {
    return {
      nodeId,
      createdAt: Date.now(),
      lastSeen: Date.now(),
      dimensions: new Map(),
    };
  }
}

// Singleton instance
let _velocityMonitor = null;

/**
 * Get the singleton velocity monitor instance
 */
export function getVelocityMonitor(options) {
  if (!_velocityMonitor) {
    _velocityMonitor = new BehaviorVelocityMonitor(options);
  }
  return _velocityMonitor;
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Capability system
  CAPABILITY_LEVEL,
  CAPABILITY_INFO,
  TIME_PRECISION,
  
  // Coefficient calculators
  calculateReliabilityCoefficient,
  calculateAgeConfidence,
  
  // Core class
  NodeWitness,
  
  // Data fusion (PRAMAAN)
  fuseTimeAttestations,
  checkMathematicalAgreement,
  rankByReliability,
  
  // Buddy system
  createVerificationRequest,
  processVerification,
  
  // Disagreement handling (VIVAAD)
  DISAGREEMENT_CAUSE,
  REMEDIATION,
  analyzeDisagreement,
  createRemediationPlan,
  trackDisagreementPattern,
  
  // Trust-tier bridge (SETU)
  witnessFromTrustProfile,
  trustProfileFromWitness,
  checkRevocationAgreement,
  aggregateAttestations,
  assessComputationTrust,
  
  // Velocity detection (VEGATI)
  VELOCITY_ALERT,
  BEHAVIOR_DIMENSION,
  BehaviorVelocityMonitor,
  getVelocityMonitor,
};
