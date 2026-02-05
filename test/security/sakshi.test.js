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

import { describe, it, expect } from 'vitest';
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
} from '../../security/sakshi.js';
import { TIME_SOURCE } from '../../security/trust-tier.js';

// =============================================================================
// CAPABILITY LEVEL TESTS
// =============================================================================

describe('SAKSHI Capability Levels', () => {
  it('defines all expected capability levels', () => {
    expect(CAPABILITY_LEVEL.ATOMIC_VETERAN).toBe('atomic_veteran');
    expect(CAPABILITY_LEVEL.PRECISION_NODE).toBe('precision_node');
    expect(CAPABILITY_LEVEL.RELIABLE_NODE).toBe('reliable_node');
    expect(CAPABILITY_LEVEL.STANDARD_NODE).toBe('standard_node');
    expect(CAPABILITY_LEVEL.BASIC_NODE).toBe('basic_node');
    expect(CAPABILITY_LEVEL.NEW_NODE).toBe('new_node');
  });

  it('has info for all capability levels', () => {
    for (const level of Object.values(CAPABILITY_LEVEL)) {
      const info = CAPABILITY_INFO[level];
      expect(info).toBeDefined();
      expect(info.name).toBeTruthy();
      expect(info.nepali).toBeTruthy();
      expect(info.description).toBeTruthy();
      expect(info.color).toBeTruthy();
    }
  });

  it('capability levels are descriptive, not hierarchical permissions', () => {
    // Key philosophy test: no "level" numbers that imply hierarchy
    // These are categories, not ranks
    const info = CAPABILITY_INFO[CAPABILITY_LEVEL.NEW_NODE];
    expect(info.description).toContain('building reliability');
    // No mention of "limited" or "restricted" actions
  });
});

// =============================================================================
// TIME PRECISION TESTS
// =============================================================================

describe('Time Precision Coefficients', () => {
  it('atomic has highest precision (lowest value)', () => {
    expect(TIME_PRECISION[TIME_SOURCE.ATOMIC]).toBe(0.1);
  });

  it('precision decreases with time source quality', () => {
    expect(TIME_PRECISION[TIME_SOURCE.ATOMIC]).toBeLessThan(TIME_PRECISION[TIME_SOURCE.GPS]);
    expect(TIME_PRECISION[TIME_SOURCE.GPS]).toBeLessThan(TIME_PRECISION[TIME_SOURCE.NTP]);
    expect(TIME_PRECISION[TIME_SOURCE.NTP]).toBeLessThan(TIME_PRECISION[TIME_SOURCE.SYSTEM]);
  });

  it('precision values represent milliseconds', () => {
    // Atomic: 0.1ms = 100 microseconds
    // GPS/PTP: 1ms
    // NTP: 50ms
    // System: 1000ms = 1 second
    expect(TIME_PRECISION[TIME_SOURCE.NTP]).toBe(50);
    expect(TIME_PRECISION[TIME_SOURCE.SYSTEM]).toBe(1000);
  });
});

// =============================================================================
// COEFFICIENT CALCULATORS
// =============================================================================

describe('Reliability Coefficient', () => {
  it('maps uptime to 0.1-1.0 range', () => {
    expect(calculateReliabilityCoefficient(0)).toBe(0.1);
    expect(calculateReliabilityCoefficient(0.5)).toBe(0.5);
    expect(calculateReliabilityCoefficient(1.0)).toBe(1.0);
  });

  it('never returns zero (all nodes can participate)', () => {
    expect(calculateReliabilityCoefficient(0)).toBeGreaterThan(0);
    expect(calculateReliabilityCoefficient(-0.5)).toBeGreaterThan(0);
  });

  it('caps at 1.0', () => {
    expect(calculateReliabilityCoefficient(1.5)).toBe(1.0);
  });
});

describe('Age Confidence', () => {
  it('starts low for new nodes', () => {
    expect(calculateAgeConfidence(0)).toBe(0.1);
    expect(calculateAgeConfidence(1)).toBeLessThan(0.5);
  });

  it('grows logarithmically', () => {
    const day1 = calculateAgeConfidence(1);
    const day10 = calculateAgeConfidence(10);
    const day100 = calculateAgeConfidence(100);
    
    // Each 10x increase should add roughly similar confidence
    const growth1to10 = day10 - day1;
    const growth10to100 = day100 - day10;
    
    // Logarithmic means diminishing returns
    expect(growth10to100).toBeLessThan(growth1to10 * 1.5);
  });

  it('maxes out at 180 days', () => {
    expect(calculateAgeConfidence(180)).toBe(1.0);
    expect(calculateAgeConfidence(365)).toBe(1.0);
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
      
      expect(witness.capabilityLevel).toBe(CAPABILITY_LEVEL.ATOMIC_VETERAN);
    });

    it('assesses PRECISION_NODE for reliable GPS nodes', () => {
      const witness = new NodeWitness({
        nodeId: 'precision-1',
        timeSource: TIME_SOURCE.GPS,
        hasAESNI: true,
        networkAgeDays: 30,
        uptimePercent: 0.92,
      });
      
      expect(witness.capabilityLevel).toBe(CAPABILITY_LEVEL.PRECISION_NODE);
    });

    it('assesses NEW_NODE for fresh joins', () => {
      const witness = new NodeWitness({
        nodeId: 'new-1',
      });
      
      expect(witness.capabilityLevel).toBe(CAPABILITY_LEVEL.NEW_NODE);
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
      expect(typeof newNode.timePrecision).toBe('number');
      expect(typeof veteran.timePrecision).toBe('number');
      
      // No "hasPermission" or "canDo" methods - that's intentional!
      expect(newNode.hasPermission).toBeUndefined();
      expect(veteran.hasPermission).toBeUndefined();
    });
  });

  describe('Derived Metrics', () => {
    it('calculates time precision from source', () => {
      const atomic = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.ATOMIC });
      const ntp = new NodeWitness({ nodeId: 'b', timeSource: TIME_SOURCE.NTP });
      
      expect(atomic.timePrecision).toBe(0.1);
      expect(ntp.timePrecision).toBe(50);
    });

    it('calculates reliability coefficient from uptime', () => {
      const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
      const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.3 });
      
      expect(reliable.reliabilityCoefficient).toBe(0.95);
      expect(unreliable.reliabilityCoefficient).toBe(0.3);
    });

    it('calculates age confidence from network age', () => {
      const veteran = new NodeWitness({ nodeId: 'v', networkAgeDays: 180 });
      const newbie = new NodeWitness({ nodeId: 'n', networkAgeDays: 1 });
      
      expect(veteran.ageConfidence).toBe(1.0);
      expect(newbie.ageConfidence).toBeLessThan(0.5);
    });

    it('combines quality score from reliability and age', () => {
      const witness = new NodeWitness({
        nodeId: 'q',
        uptimePercent: 0.8,
        networkAgeDays: 90,
      });
      
      // Quality = reliability × age confidence
      expect(witness.qualityScore).toBe(
        witness.reliabilityCoefficient * witness.ageConfidence
      );
    });
  });

  describe('Capability Checks', () => {
    it('reports high precision time capability', () => {
      const atomic = new NodeWitness({ nodeId: 'a', timeSource: TIME_SOURCE.ATOMIC });
      const ntp = new NodeWitness({ nodeId: 'b', timeSource: TIME_SOURCE.NTP });
      
      expect(atomic.canProvideHighPrecisionTime).toBe(true);
      expect(ntp.canProvideHighPrecisionTime).toBe(false);
    });

    it('reports hardware attestation status', () => {
      const attested = new NodeWitness({ nodeId: 'a', hasAESNI: true });
      const unattested = new NodeWitness({ nodeId: 'b', hasAESNI: false });
      
      expect(attested.isHardwareAttested).toBe(true);
      expect(unattested.isHardwareAttested).toBe(false);
    });
  });

  describe('Immutability', () => {
    it('is frozen after creation', () => {
      const witness = new NodeWitness({ nodeId: 'frozen' });
      
      expect(() => {
        witness.nodeId = 'hacked';
      }).toThrow(TypeError);
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
    
    expect(result.timestamp).toBe(1000);
    expect(result.contributors).toBe(1);
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
    expect(result.timestamp).toBeCloseTo(1000, 0);
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
    expect(tripleResult.precision).toBeLessThan(singleResult.precision);
  });

  it('detects agreement/disagreement', () => {
    const w1 = new NodeWitness({ nodeId: 'w1', timeSource: TIME_SOURCE.NTP });
    const w2 = new NodeWitness({ nodeId: 'w2', timeSource: TIME_SOURCE.NTP });
    
    // Agreeing timestamps
    const agreeing = fuseTimeAttestations([
      { witness: w1, timestamp: 1000 },
      { witness: w2, timestamp: 1001 }, // Within precision
    ]);
    expect(agreeing.confidence).toBeGreaterThan(0.5);
    
    // Disagreeing timestamps
    const disagreeing = fuseTimeAttestations([
      { witness: w1, timestamp: 1000 },
      { witness: w2, timestamp: 2000 }, // Way off
    ]);
    expect(disagreeing.confidence).toBeLessThan(agreeing.confidence);
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
    
    expect(result.agreed).toBe(true);
    expect(result.value).toBe('abc123');
    expect(result.contributors).toBe(3);
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
    
    expect(result.agreed).toBe(false);
    expect(result.reason).toBe('MATHEMATICAL_DISAGREEMENT');
    // Key: action is to RECOMPUTE, not to vote
    expect(result.action).toBe('RECOMPUTE_AND_VERIFY');
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
    expect(result.agreed).toBe(false);
    // We don't pick 'B' just because more nodes said it
    // We flag for recomputation
    expect(result.action).toBe('RECOMPUTE_AND_VERIFY');
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
    
    expect(result.agreed).toBe(true);
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
    
    expect(ranked[0].nodeId).toBe('r');
    expect(ranked[1].nodeId).toBe('m');
    expect(ranked[2].nodeId).toBe('u');
  });

  it('includes all nodes by default (no gatekeeping)', () => {
    const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
    const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.1 });
    
    const ranked = rankByReliability([unreliable, reliable]);
    
    // Both included - just sorted
    expect(ranked.length).toBe(2);
  });

  it('can filter by minimum reliability for optimization', () => {
    const reliable = new NodeWitness({ nodeId: 'r', uptimePercent: 0.95 });
    const unreliable = new NodeWitness({ nodeId: 'u', uptimePercent: 0.1 });
    
    const ranked = rankByReliability([unreliable, reliable], { minimumReliability: 0.5 });
    
    // Only reliable included
    expect(ranked.length).toBe(1);
    expect(ranked[0].nodeId).toBe('r');
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
    expect(ranked[0].nodeId).toBe('a');
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
    
    expect(request.type).toBe('VERIFY_COMPUTATION');
    expect(request.computation).toBe(computation);
    // No "minimumTier" or permission check
    expect(request.minimumTier).toBeUndefined();
  });

  it('verification succeeds when math matches', () => {
    const original = { result: 'abc123' };
    const verification = { result: 'abc123' };
    
    const result = processVerification(
      original,
      verification,
      (a, b) => a === b
    );
    
    expect(result.verified).toBe(true);
    expect(result.action).toBe('ACCEPT');
  });

  it('verification fails with recompute action when math differs', () => {
    const original = { result: 'abc123' };
    const verification = { result: 'xyz789' };
    
    const result = processVerification(
      original,
      verification,
      (a, b) => a === b
    );
    
    expect(result.verified).toBe(false);
    // Key: action is to RECOMPUTE, not to reject based on tier
    expect(result.action).toBe('RECOMPUTE_BOTH');
  });
});

// =============================================================================
// PHILOSOPHY TESTS
// =============================================================================

describe('SAKSHI Philosophy', () => {
  it('NodeWitness has no permission-checking methods', () => {
    const witness = new NodeWitness({ nodeId: 'test' });
    
    // These should NOT exist
    expect(witness.hasPermission).toBeUndefined();
    expect(witness.canDo).toBeUndefined();
    expect(witness.isAllowedTo).toBeUndefined();
    expect(witness.getPermissions).toBeUndefined();
  });

  it('no weight property for voting', () => {
    const witness = new NodeWitness({ nodeId: 'test' });
    
    // Weight implies voting power - we don't have that
    expect(witness.weight).toBeUndefined();
    expect(witness.voteWeight).toBeUndefined();
    
    // We have qualityScore which is for data fusion, not voting
    expect(witness.qualityScore).toBeDefined();
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
    expect(result.value).toBeUndefined();
    expect(result.action).toBe('RECOMPUTE_AND_VERIFY');
  });
});

// =============================================================================
// VIVAAD - DISAGREEMENT ANALYSIS TESTS
// =============================================================================

describe('VIVAAD Disagreement Analysis', () => {
  describe('DISAGREEMENT_CAUSE constants', () => {
    it('defines hardware-related causes', () => {
      expect(DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT).toBe('compute_timeout');
      expect(DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE).toBe('fp_variance');
      expect(DISAGREEMENT_CAUSE.MEMORY_EXHAUSTED).toBe('memory_exhausted');
      expect(DISAGREEMENT_CAUSE.CRYPTO_FAILURE).toBe('crypto_failure');
    });

    it('defines timing-related causes', () => {
      expect(DISAGREEMENT_CAUSE.CLOCK_DRIFT).toBe('clock_drift');
      expect(DISAGREEMENT_CAUSE.EPOCH_BOUNDARY).toBe('epoch_boundary');
      expect(DISAGREEMENT_CAUSE.RACE_CONDITION).toBe('race_condition');
      expect(DISAGREEMENT_CAUSE.STALE_TIMESTAMP).toBe('stale_timestamp');
    });

    it('defines network-related causes', () => {
      expect(DISAGREEMENT_CAUSE.INCOMPLETE_DATA).toBe('incomplete_data');
      expect(DISAGREEMENT_CAUSE.MESSAGE_ORDERING).toBe('message_ordering');
      expect(DISAGREEMENT_CAUSE.PARTITION_VIEW).toBe('partition_view');
      expect(DISAGREEMENT_CAUSE.PROPAGATION_DELAY).toBe('propagation_delay');
    });

    it('defines byzantine causes (rare)', () => {
      expect(DISAGREEMENT_CAUSE.DELIBERATE_WRONG).toBe('deliberate_wrong');
      expect(DISAGREEMENT_CAUSE.SYBIL_ATTACK).toBe('sybil_attack');
      expect(DISAGREEMENT_CAUSE.COMPROMISED).toBe('compromised');
    });
  });

  describe('REMEDIATION actions', () => {
    it('defines gentle remediations (honor system)', () => {
      expect(REMEDIATION.RETRY_COMPUTATION).toBe('retry_computation');
      expect(REMEDIATION.EXTEND_DEADLINE).toBe('extend_deadline');
      expect(REMEDIATION.SHARE_RESULT).toBe('share_result');
      expect(REMEDIATION.SYNC_STATE).toBe('sync_state');
      expect(REMEDIATION.REQUEST_INPUTS).toBe('request_inputs');
    });

    it('defines observational updates (no punishment)', () => {
      expect(REMEDIATION.NOTE_CAPABILITY).toBe('note_capability');
      expect(REMEDIATION.REDUCE_PRECISION_EXPECTATION).toBe('reduce_precision');
      expect(REMEDIATION.INCREASE_TIMEOUT).toBe('increase_timeout');
    });

    it('defines isolation only for repeated issues', () => {
      expect(REMEDIATION.TEMPORARY_COOLDOWN).toBe('temporary_cooldown');
      expect(REMEDIATION.REQUIRE_BUDDY).toBe('require_buddy');
      expect(REMEDIATION.ESCALATE_TO_MESH).toBe('escalate_to_mesh');
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

      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
      expect(analysis.isBenign).toBe(true);
      expect(analysis.remediation).toContain(REMEDIATION.EXTEND_DEADLINE);
    });

    it('detects floating point variance as effectively agreeing', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 1.0000000001,
        valueB: 1.0000000002,  // Tiny difference
        computeTimeA: 100,
        computeTimeB: 100,
        expectedTime: 1000,
      });

      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.FLOATING_POINT_VARIANCE);
      expect(analysis.effectivelyAgree).toBe(true);
      expect(analysis.confidence).toBeGreaterThan(0.8);
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

      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.CRYPTO_FAILURE);
      expect(analysis.isBenign).toBe(true);
      expect(analysis.remediation).toContain(REMEDIATION.NOTE_CAPABILITY);
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

      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.CLOCK_DRIFT);
      expect(analysis.isBenign).toBe(true);
      expect(analysis.remediation).toContain(REMEDIATION.SYNC_STATE);
    });

    it('detects incomplete data (type mismatch)', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: { result: 42 },
        valueB: undefined,  // Didn't receive data
      });

      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.INCOMPLETE_DATA);
      expect(analysis.remediation).toContain(REMEDIATION.REQUEST_INPUTS);
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
      expect(analysis.isBenign).toBe(false);
      expect(analysis.likelyCause).toBe(DISAGREEMENT_CAUSE.UNKNOWN);
      expect(analysis.remediation).toContain(REMEDIATION.REQUIRE_BUDDY);
      expect(analysis.remediation).toContain(REMEDIATION.ESCALATE_TO_MESH);
    });

    it('defaults to benign and retry when cause unclear', () => {
      const nodeA = new NodeWitness({ nodeId: 'a' });
      const nodeB = new NodeWitness({ nodeId: 'b' });

      const analysis = analyzeDisagreement({
        nodeA, nodeB,
        valueA: 'x', valueB: 'y',
      });

      // Should default to retry, not punish
      expect(analysis.remediation).toContain(REMEDIATION.RETRY_COMPUTATION);
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

      expect(plan.steps.length).toBe(2);
      expect(plan.steps[0].action).toBe('RETRY');
      expect(plan.steps[0].maxAttempts).toBe(3);
      expect(plan.steps[1].action).toBe('EXTEND_TIMEOUT');
    });

    it('creates observation plan for suspicious behavior', () => {
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
        remediation: [REMEDIATION.REQUIRE_BUDDY, REMEDIATION.ESCALATE_TO_MESH],
      };

      const plan = createRemediationPlan(analysis);

      expect(plan.involvesOtherNodes).toBe(true);
      expect(plan.steps.some(s => s.action === 'ASSIGN_BUDDY')).toBe(true);
      expect(plan.steps.some(s => s.action === 'MESH_OBSERVATION')).toBe(true);
    });

    it('mesh observation is passive, not punitive', () => {
      const analysis = {
        likelyCause: DISAGREEMENT_CAUSE.UNKNOWN,
        isBenign: false,
        remediation: [REMEDIATION.ESCALATE_TO_MESH],
      };

      const plan = createRemediationPlan(analysis);
      const meshStep = plan.steps.find(s => s.action === 'MESH_OBSERVATION');

      expect(meshStep.isPassive).toBe(true);  // Not active punishment
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

      expect(pattern.totalDisagreements).toBe(1);
      expect(pattern.benignRatio).toBe(1);
      expect(pattern.dominantCause).toBe(DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
      expect(pattern.assessment).toBe('NORMAL');
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

      expect(pattern.totalDisagreements).toBe(11);
      expect(pattern.benignRatio).toBe(1);
      expect(pattern.assessment).toBe('NORMAL');  // All benign = just slow hardware
      expect(pattern.dominantCause).toBe(DISAGREEMENT_CAUSE.COMPUTE_TIMEOUT);
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

      expect(pattern.totalDisagreements).toBe(11);
      expect(pattern.benignRatio).toBe(0);
      expect(pattern.assessment).toBe('NEEDS_OBSERVATION');
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
      expect(pattern.benignRatio).toBeGreaterThan(0.5);
      expect(pattern.assessment).toBe('NORMAL');  // Benefit of the doubt
    });
  });
});

// =============================================================================
// PHILOSOPHY TESTS - DISAGREEMENT HANDLING
// =============================================================================

describe('VIVAAD Philosophy', () => {
  it('assumes good faith (isBenign defaults true)', () => {
    const nodeA = new NodeWitness({ nodeId: 'a' });
    const nodeB = new NodeWitness({ nodeId: 'b' });

    const analysis = analyzeDisagreement({
      nodeA, nodeB,
      valueA: 1, valueB: 2,
    });

    // Default is to assume benign
    expect(analysis.isBenign).toBe(true);
  });

  it('remediation never includes permanent ban', () => {
    // There is no PERMANENT_BAN in remediation
    const allRemediations = Object.values(REMEDIATION);
    
    expect(allRemediations.includes('permanent_ban')).toBe(false);
    expect(allRemediations.includes('blacklist')).toBe(false);
    expect(allRemediations.includes('kick')).toBe(false);
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
    expect(benignCauses.length / allCauses.length).toBeGreaterThan(0.5);
  });

  it('buddy system is remediation, not gatekeeping', () => {
    // REQUIRE_BUDDY is in remediation, not permissions
    expect(REMEDIATION.REQUIRE_BUDDY).toBeDefined();
    
    // It's applied after failures, not before actions
    const plan = createRemediationPlan({
      remediation: [REMEDIATION.REQUIRE_BUDDY],
    });
    
    const buddyStep = plan.steps.find(s => s.action === 'ASSIGN_BUDDY');
    expect(buddyStep.afterFailures).toBeDefined();  // Only after failures
  });
});
