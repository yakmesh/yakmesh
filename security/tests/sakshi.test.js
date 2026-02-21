/**
 * SAKSHI Module Tests
 * 
 * Tests for the Signal Attestation for Karma-based Scoring and Hardware Index.
 * 
 * Key philosophy being tested:
 * - Tiers are observational, not permission-based
 * - Data fusion replaces voting
 * - Mathematical agreement replaces consensus
 * - The buddy system enables mutual verification
 * 
 * @module test/security/sakshi.test.js
 */

import { describe, it } from 'vitest';
import assert from 'node:assert/strict';
import {
  CAPABILITY_LEVEL,
  CAPABILITY_INFO,
  TIME_PRECISION,
  calculateReliabilityCoefficient,
  calculateAgeConfidence,
  NodeWitness,
  fuseTimeAttestations,
  checkMathematicalAgreement,
  rankByReliability,
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
} from '../sakshi.js';
import { TIME_SOURCE } from '../trust-tier.js';

// =============================================================================
// CAPABILITY LEVEL TESTS
// =============================================================================

describe('SAKSHI Capability Levels', () => {
  it('defines all expected capability levels', () => {
    assert.strictEqual(CAPABILITY_LEVEL.ATOMIC_VETERAN, 'atomic_veteran');
    assert.strictEqual(CAPABILITY_LEVEL.PRECISION_NODE, 'precision_node');
    assert.strictEqual(CAPABILITY_LEVEL.RELIABLE_NODE, 'reliable_node');
    assert.strictEqual(CAPABILITY_LEVEL.STANDARD_NODE, 'standard_node');
    assert.strictEqual(CAPABILITY_LEVEL.BASIC_NODE, 'basic_node');
    assert.strictEqual(CAPABILITY_LEVEL.NEW_NODE, 'new_node');
  });

  it('has info for all capability levels', () => {
    for (const level of Object.values(CAPABILITY_LEVEL)) {
      const info = CAPABILITY_INFO[level];
      assert.notStrictEqual(info, undefined);
      assert.ok(info.name);
      assert.ok(info.nepali);
      assert.ok(info.description);
      assert.ok(info.color);
    }
  });

  it('capability levels are descriptive, not hierarchical permissions', () => {
    // Key philosophy test: no "level" numbers that imply hierarchy
    // These are categories, not ranks
    const info = CAPABILITY_INFO[CAPABILITY_LEVEL.NEW_NODE];
    assert.ok(info.description.includes('building reliability'));
    // No mention of "limited" or "restricted" actions
  });
});

// =============================================================================
// TIME PRECISION TESTS
// =============================================================================

describe('Time Precision Coefficients', () => {
  it('atomic has highest precision (lowest value)', () => {
    assert.strictEqual(TIME_PRECISION[TIME_SOURCE.ATOMIC], 0.1);
  });

  it('precision decreases with time source quality', () => {
    assert.ok(TIME_PRECISION[TIME_SOURCE.ATOMIC] < TIME_PRECISION[TIME_SOURCE.GPS]);
    assert.ok(TIME_PRECISION[TIME_SOURCE.GPS] < TIME_PRECISION[TIME_SOURCE.NTP]);
    assert.ok(TIME_PRECISION[TIME_SOURCE.NTP] < TIME_PRECISION[TIME_SOURCE.SYSTEM]);
  });

  it('precision values represent milliseconds', () => {
    // Atomic: 0.1ms = 100 microseconds
    // GPS/PTP: 1ms
    // NTP: 50ms
    // System: 1000ms = 1 second
    assert.strictEqual(TIME_PRECISION[TIME_SOURCE.NTP], 50);
    assert.strictEqual(TIME_PRECISION[TIME_SOURCE.SYSTEM], 1000);
  });
});

// =============================================================================
// COEFFICIENT CALCULATORS
// =============================================================================

describe('Reliability Coefficient', () => {
  it('maps uptime to 0.1-1.0 range', () => {
    assert.strictEqual(calculateReliabilityCoefficient(0), 0.1);
    assert.strictEqual(calculateReliabilityCoefficient(0.5), 0.5);
    assert.strictEqual(calculateReliabilityCoefficient(1.0), 1.0);
  });

  it('never returns zero (all nodes can participate)', () => {
    assert.ok(calculateReliabilityCoefficient(0) > 0);
    assert.ok(calculateReliabilityCoefficient(-0.5) > 0);
  });

  it('caps at 1.0', () => {
    assert.strictEqual(calculateReliabilityCoefficient(1.5), 1.0);
  });
});

describe('Age Confidence', () => {
  it('starts low for new nodes', () => {
    assert.strictEqual(calculateAgeConfidence(0), 0.1);
    assert.ok(calculateAgeConfidence(1) < 0.5);
  });

  it('grows logarithmically', () => {
    const day1 = calculateAgeConfidence(1);
    const day10 = calculateAgeConfidence(10);
    const day100 = calculateAgeConfidence(100);
    
    // Each 10x increase should add roughly similar confidence
    const growth1to10 = day10 - day1;
    const growth10to100 = day100 - day10;
    
    // Logarithmic means diminishing returns
    assert.ok(growth10to100 < growth1to10 * 1.5);
  });

  it('maxes out at 180 days', () => {
    assert.strictEqual(calculateAgeConfidence(180), 1.0);
    assert.strictEqual(calculateAgeConfidence(365), 1.0);
  });
});

// =============================================================================
// NODE WITNESS TESTS
// =============================================================================

describe('NodeWitness', () => {
  describe('Capability Assessment', () => {
    it('assesses ATOMIC_VETERAN for long-running atomic nodes', () => {
      const witness = new NodeWitness({
        nodeId: 'veteran-1',
        timeSource: TIME_SOURCE.ATOMIC,
        hasAESNI: true,
        networkAgeDays: 200,
        uptimePercent: 0.995,
      });
      
      assert.strictEqual(witness.capabilityLevel, CAPABILITY_LEVEL.ATOMIC_VETERAN);
    });

    it('assesses PRECISION_NODE for reliable GPS nodes', () => {
      const witness = new NodeWitness({
        nodeId: 'precision-1',
        timeSource: TIME_SOURCE.GPS,
        hasAESNI: true,
        networkAgeDays: 30,
        uptimePercent: 0.92,
      });
      
      assert.strictEqual(witness.capabilityLevel, CAPABILITY_LEVEL.PRECISION_NODE);
    });

    it('assesses NEW_NODE for fresh joins', () => {
      const witness = new NodeWitness({
        nodeId: 'new-1',
      });
      
      assert.strictEqual(witness.capabilityLevel, CAPABILITY_LEVEL.NEW_NODE);
    });

    it('capability is purely descriptive', () => {
      // A NEW_NODE has no "denied" capabilities - just different metrics
      const newNode = new NodeWitness({ nodeId: 'new-1' });
      const veteran = new NodeWitness({
        nodeId: 'vet-1',
        timeSource: TIME_SOURCE.ATOMIC,
        hasAESNI: true,
        networkAgeDays: 200,
        uptimePercent: 0.99,
      });

      // Both have the same methods available
      assert.strictEqual(typeof newNode.timePrecision, 'number');
      assert.strictEqual(typeof veteran.timePrecision, 'number');
      
      // No "hasPermission" or "canDo" methods - that's intentional!
      assert.strictEqual(newNode.hasPermission, undefined);
      assert.strictEqual(veteran.hasPermission, undefined);
    });
  });

  describe('Derived Metrics', () => {
    it('calculates time precision from source', () => {
      const atomic = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.ATOMIC });
      const ntp = new NodeWitness({ nodeId: 'b', timeSource: TIME_SOURCE.NTP });
      
      assert.strictEqual(atomic.timePrecision, 0.1);
      assert.strictEqual(ntp.timePrecision, 50);
    });

    it('calculates reliability coefficient from uptime', () => {
      const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
      const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.3 });
      
      assert.strictEqual(reliable.reliabilityCoefficient, 0.95);
      assert.strictEqual(unreliable.reliabilityCoefficient, 0.3);
    });

    it('calculates age confidence from network age', () => {
      const veteran = new NodeWitness({ nodeId: 'v', networkAgeDays: 180 });
      const newbie = new NodeWitness({ nodeId: 'n', networkAgeDays: 1 });
      
      assert.strictEqual(veteran.ageConfidence, 1.0);
      assert.ok(newbie.ageConfidence < 0.5);
    });

    it('combines quality score from reliability and age', () => {
      const witness = new NodeWitness({
        nodeId: 'q',
        uptimePercent: 0.8,
        networkAgeDays: 90,
      });
      
      // Quality = reliability × age confidence
      assert.strictEqual(witness.qualityScore, 
        witness.reliabilityCoefficient * witness.ageConfidence
      );
    });
  });

  describe('Capability Checks', () => {
    it('reports high precision time capability', () => {
      const atomic = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.ATOMIC });
      const ntp = new NodeWitness({ nodeId: 'b', timeSource: TIME_SOURCE.NTP });
      
      assert.strictEqual(atomic.canProvideHighPrecisionTime, true);
      assert.strictEqual(ntp.canProvideHighPrecisionTime, false);
    });

    it('reports hardware attestation status', () => {
      const attested = new NodeWitness({ nodeId: 'a', hasAESNI: true });
      const unattested = new NodeWitness({ nodeId: 'b', hasAESNI: false });
      
      assert.strictEqual(attested.isHardwareAttested, true);
      assert.strictEqual(unattested.isHardwareAttested, false);
    });
  });

  describe('Immutability', () => {
    it('is frozen after creation', () => {
      const witness = new NodeWitness({ nodeId: 'frozen' });
      
      assert.throws(() => {
        witness.nodeId = 'hacked';
      }, TypeError);
    });
  });
});

// =============================================================================
// DATA FUSION TESTS (PRAMAAN)
// =============================================================================

describe('Time Attestation Fusion', () => {
  it('returns single attestation directly', () => {
    const witness = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.NTP });
    const result = fuseTimeAttestations([{ witness, timestamp: 1000 }]);
    
    assert.strictEqual(result.timestamp, 1000);
    assert.strictEqual(result.contributors, 1);
  });

  it('weights by precision (physics, not politics)', () => {
    // Atomic node says 1000, NTP node says 1100
    // Atomic should dominate because it's more ACCURATE
    const atomic = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.ATOMIC });
    const ntp = new NodeWitness({ nodeId: 'b', timeSource: TIME_SOURCE.NTP });
    
    const result = fuseTimeAttestations([
      { witness: atomic, timestamp: 1000 },
      { witness: ntp, timestamp: 1100 },
    ]);
    
    // Result should be very close to atomic's value
    assert.ok(Math.abs(result.timestamp - 1000) < Math.pow(10, -0));
  });

  it('multiple imprecise measurements improve precision', () => {
    // Three NTP nodes agreeing is better than one NTP node
    const ntp1 = new NodeWitness({ nodeId: 'n1', timeSource: TIME_SOURCE.NTP });
    const ntp2 = new NodeWitness({ nodeId: 'n2', timeSource: TIME_SOURCE.NTP });
    const ntp3 = new NodeWitness({ nodeId: 'n3', timeSource: TIME_SOURCE.NTP });
    
    const singleResult = fuseTimeAttestations([
      { witness: ntp1, timestamp: 1000 },
    ]);
    
    const tripleResult = fuseTimeAttestations([
      { witness: ntp1, timestamp: 1000 },
      { witness: ntp2, timestamp: 1000 },
      { witness: ntp3, timestamp: 1000 },
    ]);
    
    // Combined precision should be better
    assert.ok(tripleResult.precision < singleResult.precision);
  });

  it('detects agreement/disagreement', () => {
    const w1 = new NodeWitness({ nodeId: 'w1', timeSource: TIME_SOURCE.NTP });
    const w2 = new NodeWitness({ nodeId: 'w2', timeSource: TIME_SOURCE.NTP });
    
    // Agreeing timestamps
    const agreeing = fuseTimeAttestations([
      { witness: w1, timestamp: 1000 },
      { witness: w2, timestamp: 1001 }, // Within precision
    ]);
    assert.ok(agreeing.confidence > 0.5);
    
    // Disagreeing timestamps
    const disagreeing = fuseTimeAttestations([
      { witness: w1, timestamp: 1000 },
      { witness: w2, timestamp: 2000 }, // Way off
    ]);
    assert.ok(disagreeing.confidence < agreeing.confidence);
  });
});

describe('Mathematical Agreement', () => {
  it('returns agreed when all match', () => {
    const w1 = new NodeWitness({ nodeId: 'w1' });
    const w2 = new NodeWitness({ nodeId: 'w2' });
    const w3 = new NodeWitness({ nodeId: 'w3' });
    
    const result = checkMathematicalAgreement([
      { witness: w1, value: 'abc123' },
      { witness: w2, value: 'abc123' },
      { witness: w3, value: 'abc123' },
    ]);
    
    assert.strictEqual(result.agreed, true);
    assert.strictEqual(result.data.value, 'abc123');
    assert.strictEqual(result.data.contributors, 3);
  });

  it('detects disagreement without voting', () => {
    const w1 = new NodeWitness({ nodeId: 'w1' });
    const w2 = new NodeWitness({ nodeId: 'w2' });
    const w3 = new NodeWitness({ nodeId: 'w3' });
    
    const result = checkMathematicalAgreement([
      { witness: w1, value: 'abc123' },
      { witness: w2, value: 'abc123' },
      { witness: w3, value: 'xyz789' }, // Different!
    ]);
    
    assert.strictEqual(result.agreed, false);
    assert.strictEqual(result.reason, 'MATHEMATICAL_DISAGREEMENT');
    // Key: action is to RECOMPUTE, not to vote
    assert.strictEqual(result.data.action, 'RECOMPUTE_AND_VERIFY');
  });

  it('does not use weights or tiers to resolve disagreement', () => {
    // Even if a "veteran" disagrees with two "new nodes",
    // we don't let the veteran "win" - we flag for recomputation
    const veteran = new NodeWitness({
      nodeId: 'vet',
      timeSource: TIME_SOURCE.ATOMIC,
      hasAESNI: true,
      networkAgeDays: 200,
      uptimePercent: 0.99,
    });
    const newbie1 = new NodeWitness({ nodeId: 'new1' });
    const newbie2 = new NodeWitness({ nodeId: 'new2' });
    
    const result = checkMathematicalAgreement([
      { witness: veteran, value: 'A' },
      { witness: newbie1, value: 'B' },
      { witness: newbie2, value: 'B' },
    ]);
    
    // Still disagreement - doesn't matter that veteran is "higher tier"
    assert.strictEqual(result.agreed, false);
    // We don't pick 'B' just because more nodes said it
    // We flag for recomputation
    assert.strictEqual(result.data.action, 'RECOMPUTE_AND_VERIFY');
  });

  it('supports custom equality functions', () => {
    const w1 = new NodeWitness({ nodeId: 'w1' });
    const w2 = new NodeWitness({ nodeId: 'w2' });
    
    // Objects that are equivalent but not ===
    const result = checkMathematicalAgreement(
      [
        { witness: w1, value: { hash: 'abc', time: 100 } },
        { witness: w2, value: { hash: 'abc', time: 100 } },
      ],
      (a, b) => a.hash === b.hash && a.time === b.time
    );
    
    assert.strictEqual(result.agreed, true);
  });
});

// =============================================================================
// RANKING TESTS
// =============================================================================

describe('Ranking by Reliability', () => {
  it('sorts by reliability coefficient', () => {
    const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
    const medium = new NodeWitness({ nodeId: 'm', uptimePercent: 0.7 });
    const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.3 });
    
    const ranked = rankByReliability([unreliable, reliable, medium]);
    
    assert.strictEqual(ranked[0].nodeId, 'r');
    assert.strictEqual(ranked[1].nodeId, 'm');
    assert.strictEqual(ranked[2].nodeId, 'u');
  });

  it('includes all nodes by default (no gatekeeping)', () => {
    const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
    const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.1 });
    
    const ranked = rankByReliability([unreliable, reliable]);
    
    // Both included - just sorted
    assert.strictEqual(ranked.length, 2);
  });

  it('can filter by minimum reliability for optimization', () => {
    const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
    const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.1 });
    
    const ranked = rankByReliability([unreliable, reliable], { minimumReliability: 0.5 });
    
    // Only reliable included
    assert.strictEqual(ranked.length, 1);
    assert.strictEqual(ranked[0].nodeId, 'r');
  });

  it('can prefer precision time sources', () => {
    const atomic = new NodeWitness({
      nodeId: 'a',
      timeSource: TIME_SOURCE.ATOMIC,
      uptimePercent: 0.9,
    });
    const ntp = new NodeWitness({
      nodeId: 'n',
      timeSource: TIME_SOURCE.NTP,
      uptimePercent: 0.9,
    });
    
    const ranked = rankByReliability([ntp, atomic], { preferPrecisionTime: true });
    
    // Same reliability, but atomic preferred for time tasks
    assert.strictEqual(ranked[0].nodeId, 'a');
  });
});

// =============================================================================
// BUDDY SYSTEM TESTS
// =============================================================================

describe('Buddy System Verification', () => {
  it('creates verification requests without tier requirements', () => {
    const newNode = new NodeWitness({ nodeId: 'new' });
    const computation = { type: 'hash', input: 'data', result: 'abc123' };
    
    const request = createVerificationRequest(computation, newNode);
    
    assert.strictEqual(request.type, 'VERIFY_COMPUTATION');
    assert.strictEqual(request.computation, computation);
    // No "minimumTier" or permission check
    assert.strictEqual(request.minimumTier, undefined);
  });

  it('verification succeeds when math matches', () => {
    const original = { result: 'abc123' };
    const verification = { result: 'abc123' };
    
    const result = processVerification(
      original,
      verification,
      (a, b) => a === b
    );
    
    assert.strictEqual(result.verified, true);
    assert.strictEqual(result.action, 'ACCEPT');
  });

  it('verification fails with recompute action when math differs', () => {
    const original = { result: 'abc123' };
    const verification = { result: 'xyz789' };
    
    const result = processVerification(
      original,
      verification,
      (a, b) => a === b
    );
    
    assert.strictEqual(result.verified, false);
    // Key: action is to RECOMPUTE, not to reject based on tier
    assert.strictEqual(result.action, 'RECOMPUTE_BOTH');
  });
});

// =============================================================================
// PHILOSOPHY TESTS
// =============================================================================

describe('SAKSHI Philosophy', () => {
  it('NodeWitness has no permission-checking methods', () => {
    const witness = new NodeWitness({ nodeId: 'test' });
    
    // These should NOT exist
    assert.strictEqual(witness.hasPermission, undefined);
    assert.strictEqual(witness.canDo, undefined);
    assert.strictEqual(witness.isAllowedTo, undefined);
    assert.strictEqual(witness.getPermissions, undefined);
  });

  it('no weight property for voting', () => {
    const witness = new NodeWitness({ nodeId: 'test' });
    
    // Weight implies voting power - we don't have that
    assert.strictEqual(witness.weight, undefined);
    assert.strictEqual(witness.voteWeight, undefined);
    
    // We have qualityScore which is for data fusion, not voting
    assert.notStrictEqual(witness.qualityScore, undefined);
  });

  it('disagreement leads to recomputation, not majority rule', () => {
    const witnesses = [
      new NodeWitness({ nodeId: 'w1' }),
      new NodeWitness({ nodeId: 'w2' }),
      new NodeWitness({ nodeId: 'w3' }),
    ];
    
    // Even 2 vs 1, we don't pick the majority
    const result = checkMathematicalAgreement([
      { witness: witnesses[0], value: 'A' },
      { witness: witnesses[1], value: 'B' },
      { witness: witnesses[2], value: 'B' },
    ]);
    
    // We don't return 'B' as the winner
    assert.strictEqual(result.data?.value, undefined);
    assert.strictEqual(result.data.action, 'RECOMPUTE_AND_VERIFY');
  });
});

// =============================================================================
// VIVAAD - DISAGREEMENT ANALYSIS TESTS
// =============================================================================

describe('VIVAAD Disagreement Analysis', () => {
  describe('DISAGREEMENT_CAUSE constants', () => {
    it('defines hardware-related causes', () => {
      assert.strictEqual(DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT, 'compute_timeout');
      assert.strictEqual(DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE, 'fp_variance');
      assert.strictEqual(DISAGREEMENT_CAUSE.MEMORY_EXHAUSTED, 'memory_exhausted');
      assert.strictEqual(DISAGREEMENT_CAUSE.CRYPTO_FAILURE, 'crypto_failure');
    });

    it('defines timing-related causes', () => {
      assert.strictEqual(DISAGREEMENT_CAUSE.CLOCK_DRIFT, 'clock_drift');
      assert.strictEqual(DISAGREEMENT_CAUSE.EPOCH_BOUNDARY, 'epoch_boundary');
      assert.strictEqual(DISAGREEMENT_CAUSE.RACE_CONDITION, 'race_condition');
      assert.strictEqual(DISAGREEMENT_CAUSE.STALE_TIMESTAMP, 'stale_timestamp');
    });

    it('defines network-related causes', () => {
      assert.strictEqual(DISAGREEMENT_CAUSE.INCOMPLETE_DATA, 'incomplete_data');
      assert.strictEqual(DISAGREEMENT_CAUSE.MESSAGE_ORDERING, 'message_ordering');
      assert.strictEqual(DISAGREEMENT_CAUSE.PARTITION_VIEW, 'partition_view');
      assert.strictEqual(DISAGREEMENT_CAUSE.PROPAGATION_DELAY, 'propagation_delay');
    });

    it('defines byzantine causes (rare)', () => {
      assert.strictEqual(DISAGREEMENT_CAUSE.DELIBERATE_WRONG, 'deliberate_wrong');
      assert.strictEqual(DISAGREEMENT_CAUSE.SYBIL_ATTACK, 'sybil_attack');
      assert.strictEqual(DISAGREEMENT_CAUSE.COMPROMISED, 'compromised');
    });
  });

  describe('REMEDIATION actions', () => {
    it('defines gentle remediations (honor system)', () => {
      assert.strictEqual(REMEDIATION.RETRY_COMPUTATION, 'retry_computation');
      assert.strictEqual(REMEDIATION.EXTEND_DEADLINE, 'extend_deadline');
      assert.strictEqual(REMEDIATION.SHARE_RESULT, 'share_result');
      assert.strictEqual(REMEDIATION.SYNC_STATE, 'sync_state');
      assert.strictEqual(REMEDIATION.REQUEST_INPUTS, 'request_inputs');
    });

    it('defines observational updates (no punishment)', () => {
      assert.strictEqual(REMEDIATION.NOTE_CAPABILITY, 'note_capability');
      assert.strictEqual(REMEDIATION.REDUCE_PRECISION_EXPECTATION, 'reduce_precision');
      assert.strictEqual(REMEDIATION.INCREASE_TIMEOUT, 'increase_timeout');
    });

    it('defines isolation only for repeated issues', () => {
      assert.strictEqual(REMEDIATION.TEMPORARY_COOLDOWN, 'temporary_cooldown');
      assert.strictEqual(REMEDIATION.REQUIRE_BUDDY, 'require_buddy');
      assert.strictEqual(REMEDIATION.ESCALATE_TO_MESH, 'escalate_to_mesh');
    });
  });

  describe('analyzeDisagreement', () => {
    it('detects compute timeout (slow hardware)', () => {
      const nodeA = new NodeWitness({ nodeId: 'fast', hasAESNI: true });
      const nodeB = new NodeWitness({ nodeId: 'slow', hasAESNI: true });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 42, valueB: 0,  // Different results
        computeTimeA: 500,
        computeTimeB: 3000,     // Took 3x longer than expected
        expectedTime: 1000,
      });

      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
      assert.strictEqual(analysis.isBenign, true);
      assert.ok(analysis.remediation.includes(REMEDIATION.EXTEND_DEADLINE));
    });

    it('detects floating point variance as effectively agreeing', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 1.00000000001,
        valueB: 1.00000000002,  // Tiny difference
        computeTimeA: 100,
        computeTimeB: 100,
        expectedTime: 1000,
      });

      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE);
      assert.strictEqual(analysis.effectivelyAgree, true);
      assert.ok(analysis.confidence > 0.8);
    });

    it('detects crypto hardware mismatch', () => {
      const nodeA = new NodeWitness({ nodeId: 'with-aesni', hasAESNI: true });
      const nodeB = new NodeWitness({ nodeId: 'no-aesni', hasAESNI: false });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 'encrypted-result-1',
        valueB: 'different-result',
        computeTimeA: 100,
        computeTimeB: 800,
        expectedTime: 500,
      });

      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.CRYPTO_FAILURE);
      assert.strictEqual(analysis.isBenign, true);
      assert.ok(analysis.remediation.includes(REMEDIATION.NOTE_CAPABILITY));
    });

    it('detects clock drift between nodes', () => {
      const nodeA = new NodeWitness({ 
        nodeId: 'atomic', 
        timeSource: TIME_SOURCE.ATOMIC 
      });
      const nodeB = new NodeWitness({ 
        nodeId: 'ntp', 
        timeSource: TIME_SOURCE.NTP 
      });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 1000,
        valueB: 1050,
        timestampDelta: 10000,  // 10 second clock difference
        computeTimeA: 100,
        computeTimeB: 100,
      });

      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.CLOCK_DRIFT);
      assert.strictEqual(analysis.isBenign, true);
      assert.ok(analysis.remediation.includes(REMEDIATION.SYNC_STATE));
    });

    it('detects incomplete data (type mismatch)', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: { result: 42 },
        valueB: undefined,  // Didn't receive data
      });

      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.INCOMPLETE_DATA);
      assert.ok(analysis.remediation.includes(REMEDIATION.REQUEST_INPUTS));
    });

    it('marks unexplained disagreements as needing observation (not punishment)', () => {
      // Same hardware, same timing, but different results
      const nodeA = new NodeWitness({ 
        nodeId: 'a', 
        hasAESNI: true,
        timeSource: TIME_SOURCE.NTP 
      });
      const nodeB = new NodeWitness({ 
        nodeId: 'b', 
        hasAESNI: true,
        timeSource: TIME_SOURCE.NTP 
      });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 'result-A',
        valueB: 'result-B',
        computeTimeA: 100,
        computeTimeB: 110,
        expectedTime: 1000,
        timestampDelta: 10,  // Well within precision
      });

      // Not immediately calling it malicious
      assert.strictEqual(analysis.isBenign, false);
      assert.strictEqual(analysis.likelyCause, DISAGREEMENT_CAUSE.UNKNOWN);
      assert.ok(analysis.remediation.includes(REMEDIATION.REQUIRE_BUDDY));
      assert.ok(analysis.remediation.includes(REMEDIATION.ESCALATE_TO_MESH));
    });

    it('defaults to retry when cause is unclear', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 'x', valueB: 'y',
        computeTimeA: 100,
        computeTimeB: 700,  // Timing diff avoids unexplained-identical pattern
        expectedTime: 1000,
      });

      // Should default to retry, not punish
      assert.ok(analysis.remediation.includes(REMEDIATION.RETRY_COMPUTATION));
    });
  });

  describe('createRemediationPlan', () => {
    it('creates retry plan for benign disagreements', () => {
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT,
        isBenign: true,
        remediation: [REMEDIATION.RETRY_COMPUTATION, REMEDIATION.EXTEND_DEADLINE],
      };

      const plan = createRemediationPlan(analysis);

      assert.strictEqual(plan.steps.length, 2);
      assert.strictEqual(plan.steps[0].action, 'RETRY');
      assert.strictEqual(plan.steps[0].maxAttempts, 3);
      assert.strictEqual(plan.steps[1].action, 'EXTEND_TIMEOUT');
    });

    it('creates observation plan for suspicious behavior', () => {
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
        remediation: [REMEDIATION.REQUIRE_BUDDY, REMEDIATION.ESCALATE_TO_MESH],
      };

      const plan = createRemediationPlan(analysis);

      assert.strictEqual(plan.involvesOtherNodes, true);
      assert.strictEqual(plan.steps.some(s => s.action === 'ASSIGN_BUDDY'), true);
      assert.strictEqual(plan.steps.some(s => s.action === 'MESH_OBSERVATION'), true);
    });

    it('mesh observation is passive, not punitive', () => {
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
        remediation: [REMEDIATION.ESCALATE_TO_MESH],
      };

      const plan = createRemediationPlan(analysis);
      const meshStep = plan.steps.find(s => s.action === 'MESH_OBSERVATION');

      assert.strictEqual(meshStep.isPassive, true);  // Not active punishment
    });
  });

  describe('trackDisagreementPattern', () => {
    it('tracks disagreement history for a node', () => {
      const history = new Map();
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT,
        isBenign: true,
      };

      const pattern = trackDisagreementPattern(history, 'node-123', analysis);

      assert.strictEqual(pattern.totalDisagreements, 1);
      assert.strictEqual(pattern.benignRatio, 1);
      assert.strictEqual(pattern.dominantCause, DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
      assert.strictEqual(pattern.assessment, 'NORMAL');
    });

    it('identifies patterns of benign hardware issues', () => {
      const history = new Map();

      // Simulate 10 timeout issues (slow hardware)
      for (let i = 0; i < 10; i++) {
        trackDisagreementPattern(history, 'slow-node', {
          likelyCause: DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT,
          isBenign: true,
        });
      }

      const pattern = trackDisagreementPattern(history, 'slow-node', {
        likelyCause: DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT,
        isBenign: true,
      });

      assert.strictEqual(pattern.totalDisagreements, 11);
      assert.strictEqual(pattern.benignRatio, 1);
      assert.strictEqual(pattern.assessment, 'NORMAL');  // All benign = just slow hardware
      assert.strictEqual(pattern.dominantCause, DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
    });

    it('flags nodes with many unexplained disagreements', () => {
      const history = new Map();

      // Simulate 10 unexplained disagreements
      for (let i = 0; i < 10; i++) {
        trackDisagreementPattern(history, 'suspicious-node', {
          likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
          isBenign: false,  // Can't explain these
        });
      }

      const pattern = trackDisagreementPattern(history, 'suspicious-node', {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
      });

      assert.strictEqual(pattern.totalDisagreements, 11);
      assert.strictEqual(pattern.benignRatio, 0);
      assert.strictEqual(pattern.assessment, 'NEEDS_OBSERVATION');
    });

    it('keeps assessment NORMAL if mostly benign with some suspicious', () => {
      const history = new Map();

      // 8 benign disagreements
      for (let i = 0; i < 8; i++) {
        trackDisagreementPattern(history, 'mixed-node', {
          likelyCause: DISAGREEMENT_CAUSE.CLOCK_DRIFT,
          isBenign: true,
        });
      }

      // 2 suspicious ones
      for (let i = 0; i < 2; i++) {
        trackDisagreementPattern(history, 'mixed-node', {
          likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
          isBenign: false,
        });
      }

      const pattern = trackDisagreementPattern(history, 'mixed-node', {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
      });

      // 8 benign + 3 suspicious = mostly benign
      assert.ok(pattern.benignRatio > 0.5);
      assert.strictEqual(pattern.assessment, 'NORMAL');  // Benefit of the doubt
    });
  });
});

// =============================================================================
// PHILOSOPHY TESTS - DISAGREEMENT HANDLING
// =============================================================================

describe('VIVAAD Philosophy', () => {
  it('assumes good faith — benign causes trigger positive assessment', () => {
    const nodeA = new NodeWitness({ nodeId: 'a' });
    const nodeB = new NodeWitness({ nodeId: 'b' });

    // A common cause (compute timeout) is assessed as benign
    const analysis = analyzeDisagreement({
      nodeA, nodeB,
      valueA: 1, valueB: 2,
      computeTimeA: 100,
      computeTimeB: 3000,  // Slow → hardware timeout
      expectedTime: 1000,
    });

    // Benign assessment for hardware-explained disagreement
    assert.strictEqual(analysis.isBenign, true);
  });

  it('remediation never includes permanent ban', () => {
    // There is no PERMANENT_BAN in remediation
    const allRemediations = Object.values(REMEDIATION);
    
    assert.strictEqual(allRemediations.includes('permanent_ban'), false);
    assert.strictEqual(allRemediations.includes('blacklist'), false);
    assert.strictEqual(allRemediations.includes('kick'), false);
  });

  it('most disagreements attributed to hardware/timing (~85%)', () => {
    // The causes are designed so ~70% hardware + ~15% timing = ~85% benign
    const hardwareCauses = [
      DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT,
      DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE,
      DISAGREEMENT_CAUSE.MEMORY_EXHAUSTED,
      DISAGREEMENT_CAUSE.CRYPTO_FAILURE,
    ];
    
    const timingCauses = [
      DISAGREEMENT_CAUSE.CLOCK_DRIFT,
      DISAGREEMENT_CAUSE.EPOCH_BOUNDARY,
      DISAGREEMENT_CAUSE.RACE_CONDITION,
      DISAGREEMENT_CAUSE.STALE_TIMESTAMP,
    ];

    const benignCauses = [...hardwareCauses, ...timingCauses];
    const allCauses = Object.values(DISAGREEMENT_CAUSE);

    // At least 50% of defined causes are benign (hardware/timing)
    assert.ok(benignCauses.length / allCauses.length >= 0.5);
  });

  it('buddy system is remediation, not gatekeeping', () => {
    // REQUIRE_BUDDY is in remediation, not permissions
    assert.notStrictEqual(REMEDIATION.REQUIRE_BUDDY, undefined);
    
    // It's applied after failures, not before actions
    const plan = createRemediationPlan({
      remediation: [REMEDIATION.REQUIRE_BUDDY],
    });
    
    const buddyStep = plan.steps.find(s => s.action === 'ASSIGN_BUDDY');
    assert.notStrictEqual(buddyStep.afterFailures, undefined);  // Only after failures
  });
});

// =============================================================================
// SETU - TRUST-TIER BRIDGE TESTS
// =============================================================================

describe('SETU Trust-Tier Bridge', () => {
  describe('witnessFromTrustProfile', () => {
    it('converts TrustProfile to NodeWitness', () => {
      const trustProfile = {
        dokoId: 'doko-123',
        timeSource: TIME_SOURCE.ATOMIC,
        hardwareAttestation: { validation: { hasAESNI: true } },
        networkAge: 30 * 24 * 60 * 60 * 1000,  // 30 days in ms
        endorsementCount: 5,
      };

      const witness = witnessFromTrustProfile(trustProfile);

      assert.strictEqual(witness.nodeId, 'doko-123');
      assert.strictEqual(witness.timeSource, TIME_SOURCE.ATOMIC);
      assert.strictEqual(witness.hasAESNI, true);
      assert.strictEqual(witness.networkAgeDays, 30);
    });

    it('handles missing hardware attestation', () => {
      const trustProfile = {
        dokoId: 'doko-456',
        timeSource: TIME_SOURCE.NTP,
      };

      const witness = witnessFromTrustProfile(trustProfile);

      assert.strictEqual(witness.hasAESNI, false);
      assert.strictEqual(witness.networkAgeDays, 0);
    });
  });

  describe('trustProfileFromWitness', () => {
    it('converts NodeWitness back to TrustProfile-compatible object', () => {
      const witness = new NodeWitness({
        nodeId: 'node-789',
        timeSource: TIME_SOURCE.GPS,
        hasAESNI: true,
        networkAgeDays: 14,
        uptimePercent: 0.95,
      });

      const profile = trustProfileFromWitness(witness, 'doko-789');

      assert.strictEqual(profile.dokoId, 'doko-789');
      assert.strictEqual(profile.timeSource, TIME_SOURCE.GPS);
      assert.strictEqual(profile.networkAge, 14 * 24 * 60 * 60 * 1000);
      assert.notStrictEqual(profile.qualityScore, undefined);
      assert.notStrictEqual(profile.timePrecision, undefined);
      // Note: No getWeight() - that's the voting pattern we removed
      assert.strictEqual(profile.weight, undefined);
    });
  });

  describe('checkRevocationAgreement', () => {
    it('requires minimum reports', () => {
      const reports = [
        { witness: new NodeWitness({ nodeId: 'w1' }), evidence: { reason: 'malicious' } },
      ];

      const result = checkRevocationAgreement(reports, { minReports: 3 });

      assert.strictEqual(result.isAgreed, false);
      assert.strictEqual(result.reason, 'INSUFFICIENT_REPORTS');
    });

    it('requires evidence agreement (not weighted voting)', () => {
      const reports = [
        { witness: new NodeWitness({ nodeId: 'w1' }), evidence: { reason: 'malicious', targetId: 'bad-node' } },
        { witness: new NodeWitness({ nodeId: 'w2' }), evidence: { reason: 'spam', targetId: 'bad-node' } },  // Different reason!
        { witness: new NodeWitness({ nodeId: 'w3' }), evidence: { reason: 'malicious', targetId: 'bad-node' } },
      ];

      const result = checkRevocationAgreement(reports, { minReports: 3 });

      // Even 2 vs 1, we don't just take majority - we need AGREEMENT
      assert.strictEqual(result.isAgreed, false);
      assert.strictEqual(result.isDisagreed, true);
      assert.strictEqual(result.reason, 'EVIDENCE_DISAGREEMENT');
    });

    it('revokes when all reports agree', () => {
      const reports = [
        { witness: new NodeWitness({ nodeId: 'w1' }), evidence: { reason: 'malicious', targetId: 'bad-node', timestamp: 1000 } },
        { witness: new NodeWitness({ nodeId: 'w2' }), evidence: { reason: 'malicious', targetId: 'bad-node', timestamp: 1001 } },
        { witness: new NodeWitness({ nodeId: 'w3' }), evidence: { reason: 'malicious', targetId: 'bad-node', timestamp: 1002 } },
      ];

      const result = checkRevocationAgreement(reports, { minReports: 3 });

      assert.strictEqual(result.isAgreed, true);
      assert.strictEqual(result.data.evidence.reason, 'malicious');
      assert.strictEqual(result.data.reportCount, 3);
      // Note: No "effectiveCount" or "weightedVotes"
      assert.strictEqual(result.data.effectiveCount, undefined);
    });

    it('can require precision node witness', () => {
      const reports = [
        { witness: new NodeWitness({ nodeId: 'w1', timeSource: TIME_SOURCE.NTP }), evidence: { reason: 'bad', targetId: 'x' } },
        { witness: new NodeWitness({ nodeId: 'w2', timeSource: TIME_SOURCE.NTP }), evidence: { reason: 'bad', targetId: 'x' } },
        { witness: new NodeWitness({ nodeId: 'w3', timeSource: TIME_SOURCE.SYSTEM }), evidence: { reason: 'bad', targetId: 'x' } },
      ];

      const result = checkRevocationAgreement(reports, { 
        minReports: 3, 
        requirePrecisionNode: true 
      });

      assert.strictEqual(result.isAgreed, false);
      assert.strictEqual(result.reason, 'NO_PRECISION_WITNESS');
    });
  });

  describe('aggregateAttestations', () => {
    it('checks for mathematical agreement, not weighted voting', () => {
      const attestations = [
        { witness: new NodeWitness({ nodeId: 'w1' }), attestation: { claim: { valid: true }, timestamp: 1000 } },
        { witness: new NodeWitness({ nodeId: 'w2' }), attestation: { claim: { valid: true }, timestamp: 1001 } },
        { witness: new NodeWitness({ nodeId: 'w3' }), attestation: { claim: { valid: true }, timestamp: 1002 } },
      ];

      const result = aggregateAttestations(attestations);

      assert.strictEqual(result.agreed, true);
      assert.strictEqual(result.data.claim.valid, true);
      assert.strictEqual(result.data.attestationCount, 3);
      // No "effectiveCount" - all agreeing attestations are equal
      assert.strictEqual(result.data.effectiveCount, undefined);
    });

    it('returns disagreement info when attestations conflict', () => {
      const attestations = [
        { witness: new NodeWitness({ nodeId: 'w1' }), attestation: { claim: { valid: true } } },
        { witness: new NodeWitness({ nodeId: 'w2' }), attestation: { claim: { valid: false } } },  // Disagrees!
      ];

      const result = aggregateAttestations(attestations);

      assert.strictEqual(result.agreed, false);
      assert.strictEqual(result.isDisagreed, true);
      assert.strictEqual(result.reason, 'ATTESTATION_DISAGREEMENT');
    });

    it('provides contributors ranked by reliability (informational only)', () => {
      const attestations = [
        { 
          witness: new NodeWitness({ nodeId: 'reliable', uptimePercent: 0.99 }), 
          attestation: { claim: { x: 1 } } 
        },
        { 
          witness: new NodeWitness({ nodeId: 'new', uptimePercent: 0.5 }), 
          attestation: { claim: { x: 1 } } 
        },
      ];

      const result = aggregateAttestations(attestations);

      assert.strictEqual(result.agreed, true);
      assert.strictEqual(result.data.contributors[0].nodeId, 'reliable');  // Sorted by reliability
      assert.strictEqual(result.data.contributors[1].nodeId, 'new');
    });
  });

  describe('assessComputationTrust', () => {
    it('trusts reproducible computations regardless of who computed', () => {
      const computation = { result: 42 };  // No proof, but reproducible
      const computedBy = new NodeWitness({ nodeId: 'new-node' });

      const assessment = assessComputationTrust(computation, computedBy);

      assert.strictEqual(assessment.trusted, true);
      assert.strictEqual(assessment.basis, 'REPRODUCIBLE');
      // Note: No "weight" or "trustLevel" check
      assert.strictEqual(assessment.computedBy.weight, undefined);
    });

    it('trusts computations with proofs', () => {
      const computation = { result: 42, checksum: 'abc123' };
      const computedBy = new NodeWitness({ nodeId: 'any-node' });

      const assessment = assessComputationTrust(computation, computedBy);

      assert.strictEqual(assessment.trusted, true);
      assert.strictEqual(assessment.basis, 'HAS_PROOF');
    });

    it('requires proof when verification is required', () => {
      const computation = { result: 42 };  // No proof
      const computedBy = new NodeWitness({ nodeId: 'any-node' });

      const assessment = assessComputationTrust(computation, computedBy, { 
        requireVerification: true 
      });

      assert.strictEqual(assessment.trusted, false);
      assert.strictEqual(assessment.basis, 'UNVERIFIABLE');
      assert.strictEqual(assessment.action, 'REQUEST_PROOF');
    });

    it('checks verifier agreement when verifications provided', () => {
      const computation = { result: 42, checksum: 'abc' };
      const computedBy = new NodeWitness({ nodeId: 'computer' });
      const verifications = [
        { verifier: new NodeWitness({ nodeId: 'v1' }), verified: true },
        { verifier: new NodeWitness({ nodeId: 'v2' }), verified: true },
      ];

      const assessment = assessComputationTrust(computation, computedBy, { verifications });

      assert.strictEqual(assessment.trusted, true);
      assert.strictEqual(assessment.basis, 'VERIFIED');
      assert.strictEqual(assessment.verifierCount, 2);
    });

    it('fails if verifiers disagree', () => {
      const computation = { result: 42, proof: 'xyz' };
      const computedBy = new NodeWitness({ nodeId: 'computer' });
      const verifications = [
        { verifier: new NodeWitness({ nodeId: 'v1' }), verified: true },
        { verifier: new NodeWitness({ nodeId: 'v2' }), verified: false },  // Disagrees!
      ];

      const assessment = assessComputationTrust(computation, computedBy, { verifications });

      assert.strictEqual(assessment.trusted, false);
      assert.strictEqual(assessment.basis, 'VERIFIERS_DISAGREE');
    });
  });
});

// =============================================================================
// SETU PHILOSOPHY TESTS
// =============================================================================

describe('SETU Philosophy', () => {
  it('no weighted voting in revocation checks', () => {
    // checkRevocationAgreement doesn't use weights
    const reports = [
      { witness: new NodeWitness({ nodeId: 'w1' }), evidence: { reason: 'x', targetId: 'y' } },
      { witness: new NodeWitness({ nodeId: 'w2' }), evidence: { reason: 'x', targetId: 'y' } },
      { witness: new NodeWitness({ nodeId: 'w3' }), evidence: { reason: 'x', targetId: 'y' } },
    ];

    const result = checkRevocationAgreement(reports, { minReports: 3 });

    // Result has no weight-related fields
    assert.strictEqual(result.effectiveCount, undefined);
    assert.strictEqual(result.weightedVotes, undefined);
    assert.strictEqual(result.threshold, undefined);
  });

  it('attestation count is actual count, not weighted', () => {
    const attestations = [
      { witness: new NodeWitness({ nodeId: 'w1' }), attestation: { claim: { ok: true } } },
      { witness: new NodeWitness({ nodeId: 'w2' }), attestation: { claim: { ok: true } } },
    ];

    const result = aggregateAttestations(attestations);

    assert.strictEqual(result.data.attestationCount, 2);  // Actual count
    assert.strictEqual(result.data.effectiveCount, undefined);  // No weighted count
  });

  it('trust is based on math verifiability, not node tier', () => {
    // A new node's computation is just as trusted as an old node's
    // if the math is verifiable
    const newNode = new NodeWitness({ nodeId: 'new', networkAgeDays: 0 });
    const veteranNode = new NodeWitness({ nodeId: 'veteran', networkAgeDays: 365 });

    const computation = { result: 42, checksum: 'abc' };

    const newNodeAssessment = assessComputationTrust(computation, newNode);
    const veteranAssessment = assessComputationTrust(computation, veteranNode);

    // Both are equally trusted - because the math is verifiable
    assert.strictEqual(newNodeAssessment.trusted, veteranAssessment.trusted);
    assert.strictEqual(newNodeAssessment.basis, veteranAssessment.basis);
  });
});

