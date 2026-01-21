/**
 * Trust Tier Tests
 * 
 * Tests for the combined Hardware + Time Source trust system.
 * 
 * @module security/tests/trust-tier.test.js
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import {
  TrustProfile,
  TrustTierRegistry,
  WeightedRevocationCalculator,
  TRUST_TIER,
  TIME_SOURCE,
  TIER_WEIGHT,
  TIER_REQUIREMENTS,
} from '../trust-tier.js';

import { HardwareAttestation, measureAESPerformance, validateAESTiming } from '../hardware-attestation.js';

// Helper to create a mock hardware attestation
function createMockHardwareAttestation(hasAESNI = true) {
  return {
    version: '1.0',
    createdAt: Date.now(),
    cpu: {
      vendor: 'GenuineIntel',
      model: 'Test CPU',
      hasAESNI,
    },
    timing: {
      meanMs: hasAESNI ? 3.5 : 45.0,
      stddevMs: hasAESNI ? 0.3 : 8.0,
      throughputMBps: hasAESNI ? 2500 : 80,
      varianceRatio: hasAESNI ? 0.08 : 0.18,
    },
    validation: {
      valid: hasAESNI,
      hasAESNI,
      issues: hasAESNI ? [] : ['Timing too slow'],
    },
  };
}

function createDokoId(prefix = 'test') {
  return `doko-node-${prefix}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

describe('TRUST_TIER constants', () => {
  it('should have all tier levels', () => {
    expect(TRUST_TIER.ORACLE).toBe('oracle');
    expect(TRUST_TIER.ANCHOR).toBe('anchor');
    expect(TRUST_TIER.SENTINEL).toBe('sentinel');
    expect(TRUST_TIER.PARTICIPANT).toBe('participant');
    expect(TRUST_TIER.OBSERVER).toBe('observer');
  });

  it('should have correct weights', () => {
    expect(TIER_WEIGHT[TRUST_TIER.ORACLE]).toBe(2.0);
    expect(TIER_WEIGHT[TRUST_TIER.ANCHOR]).toBe(1.5);
    expect(TIER_WEIGHT[TRUST_TIER.SENTINEL]).toBe(1.25);
    expect(TIER_WEIGHT[TRUST_TIER.PARTICIPANT]).toBe(1.0);
    expect(TIER_WEIGHT[TRUST_TIER.OBSERVER]).toBe(0.25);
  });

  it('should have requirements for all tiers', () => {
    for (const tier of Object.values(TRUST_TIER)) {
      expect(TIER_REQUIREMENTS[tier], `Missing requirements for ${tier}`).toBeTruthy();
    }
  });
});

describe('TrustProfile', () => {
  describe('calculateTier', () => {
    it('should return ORACLE for atomic clock + AES-NI + 30 days + 3 endorsements', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 31 * 24 * 60 * 60 * 1000, // 31 days
        endorsementCount: 5,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.ORACLE);
      expect(profile.getWeight()).toBe(2.0);
    });

    it('should return ANCHOR for GPS + AES-NI + 14 days + 2 endorsements', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.GPS,
        networkAge: 15 * 24 * 60 * 60 * 1000, // 15 days
        endorsementCount: 3,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.ANCHOR);
      expect(profile.getWeight()).toBe(1.5);
    });

    it('should return SENTINEL for PTP + AES-NI + 7 days + 1 endorsement', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.PTP,
        networkAge: 8 * 24 * 60 * 60 * 1000, // 8 days
        endorsementCount: 2,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.SENTINEL);
      expect(profile.getWeight()).toBe(1.25);
    });

    it('should return PARTICIPANT for NTP + AES-NI + 1 day', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.NTP,
        networkAge: 2 * 24 * 60 * 60 * 1000, // 2 days
        endorsementCount: 0,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.PARTICIPANT);
      expect(profile.getWeight()).toBe(1.0);
    });

    it('should return OBSERVER for no AES-NI', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(false),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 365 * 24 * 60 * 60 * 1000, // 1 year
        endorsementCount: 100,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.OBSERVER);
      expect(profile.getWeight()).toBe(0.25);
    });

    it('should return OBSERVER for no hardware attestation', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: null,
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 365 * 24 * 60 * 60 * 1000,
        endorsementCount: 100,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.OBSERVER);
    });

    it('should return OBSERVER for new node', () => {
      const profile = new TrustProfile({
        dokoId: createDokoId(),
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.NTP,
        networkAge: 0,
        endorsementCount: 0,
      });

      expect(profile.calculateTier()).toBe(TRUST_TIER.OBSERVER);
    });
  });

  describe('meetsTierRequirements', () => {
    it('should check time source requirement', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.NTP, // Not atomic
        networkAge: 365 * 24 * 60 * 60 * 1000,
        endorsementCount: 100,
      });

      expect(profile.meetsTierRequirements(TRUST_TIER.ORACLE)).toBe(false);
    });

    it('should check AES-NI requirement', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(false),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 365 * 24 * 60 * 60 * 1000,
        endorsementCount: 100,
      });

      expect(profile.meetsTierRequirements(TRUST_TIER.ORACLE)).toBe(false);
    });

    it('should check network age requirement', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 10 * 24 * 60 * 60 * 1000, // 10 days, need 30
        endorsementCount: 100,
      });

      expect(profile.meetsTierRequirements(TRUST_TIER.ORACLE)).toBe(false);
    });

    it('should check endorsement requirement', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 365 * 24 * 60 * 60 * 1000,
        endorsementCount: 1, // Need 3 for ORACLE
      });

      expect(profile.meetsTierRequirements(TRUST_TIER.ORACLE)).toBe(false);
    });
  });

  describe('getNextTierRequirements', () => {
    it('should return null for ORACLE tier', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.ATOMIC,
        networkAge: 365 * 24 * 60 * 60 * 1000,
        endorsementCount: 100,
      });

      expect(profile.getNextTierRequirements()).toBeNull();
    });

    it('should suggest upgrades for PARTICIPANT', () => {
      const profile = new TrustProfile({
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.NTP,
        networkAge: 2 * 24 * 60 * 60 * 1000,
        endorsementCount: 0,
      });

      const next = profile.getNextTierRequirements();
      
      expect(next.tier).toBe(TRUST_TIER.SENTINEL);
      expect(next.missing.length > 0).toBeTruthy();
      expect(next.missing.some(m => m.includes('time source'))).toBeTruthy();
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize', () => {
      const profile = new TrustProfile({
        dokoId: 'test-doko',
        hardwareAttestation: createMockHardwareAttestation(true),
        timeSource: TIME_SOURCE.GPS,
        networkAge: 20 * 24 * 60 * 60 * 1000,
        endorsementCount: 5,
      });

      const json = profile.toJSON();
      const restored = TrustProfile.fromJSON(json);

      expect(restored.dokoId).toBe(profile.dokoId);
      expect(restored.calculateTier()).toBe(profile.calculateTier());
      expect(restored.getWeight()).toBe(profile.getWeight());
    });
  });
});

describe('TrustTierRegistry', () => {
  let registry;

  beforeEach(() => {
    registry = new TrustTierRegistry({
      getTimeSource: async (dokoId) => TIME_SOURCE.NTP,
      getNetworkAge: async (dokoId) => 5 * 24 * 60 * 60 * 1000, // 5 days
      getEndorsementCount: async (dokoId) => 1,
      getHardwareAttestation: async (dokoId) => createMockHardwareAttestation(true),
    });
  });

  it('should get profile for node', async () => {
    const profile = await registry.getProfile('test-node');
    
    expect(profile).toBeTruthy();
    expect(profile.dokoId).toBe('test-node');
  });

  it('should calculate tier', async () => {
    const tier = await registry.getTier('test-node');
    
    // NTP + AES-NI + 5 days = PARTICIPANT
    expect(tier).toBe(TRUST_TIER.PARTICIPANT);
  });

  it('should calculate weight', async () => {
    const weight = await registry.getWeight('test-node');
    
    expect(weight).toBe(1.0);
  });

  it('should cache profiles', async () => {
    await registry.getProfile('test-node');
    
    expect(registry.profiles.size).toBe(1);
  });

  it('should calculate tier distribution', async () => {
    // Add several nodes
    await registry.getProfile('node-1');
    await registry.getProfile('node-2');
    await registry.getProfile('node-3');

    const distribution = registry.getTierDistribution();
    
    expect(distribution[TRUST_TIER.PARTICIPANT]).toBe(3);
  });

  it('should calculate effective network size', async () => {
    await registry.getProfile('node-1');
    await registry.getProfile('node-2');
    await registry.getProfile('node-3');

    const size = registry.getEffectiveNetworkSize();
    
    // 3 nodes * 1.0 weight = 3.0
    expect(size).toBe(3.0);
  });

  it('should get statistics', async () => {
    await registry.getProfile('node-1');
    await registry.getProfile('node-2');

    const stats = registry.getStats();
    
    expect(stats.totalNodes).toBe(2);
    expect(stats.effectiveSize).toBe(2.0);
    expect(stats.averageWeight).toBe(1.0);
  });
});

describe('WeightedRevocationCalculator', () => {
  let registry;
  let calculator;

  beforeEach(() => {
    registry = new TrustTierRegistry({
      getTimeSource: async () => TIME_SOURCE.NTP,
      getNetworkAge: async () => 5 * 24 * 60 * 60 * 1000,
      getEndorsementCount: async () => 1,
      getHardwareAttestation: async () => createMockHardwareAttestation(true),
    });
    calculator = new WeightedRevocationCalculator(registry);
  });

  it('should calculate effective attestation count', async () => {
    // Add some nodes to registry
    await registry.getProfile('attester-1');
    await registry.getProfile('attester-2');
    await registry.getProfile('attester-3');

    const attestations = [
      { attesterId: 'attester-1' },
      { attesterId: 'attester-2' },
      { attesterId: 'attester-3' },
    ];

    const count = await registry.calculateEffectiveCount(attestations);
    
    // 3 PARTICIPANT nodes * 1.0 weight = 3.0
    expect(count).toBe(3.0);
  });

  it('should not revoke with insufficient attestations', async () => {
    // Create 10 nodes
    for (let i = 0; i < 10; i++) {
      await registry.getProfile(`node-${i}`);
    }

    // Only 3 attestations (need 2/3 of 10 = ~6.67)
    const attestations = [
      { attesterId: 'node-0' },
      { attesterId: 'node-1' },
      { attesterId: 'node-2' },
    ];

    const result = await calculator.isRevoked(attestations);
    
    expect(result.revoked).toBe(false);
    expect(result.reason).toBe('BELOW_THRESHOLD');
  });

  it('should revoke with sufficient attestations', async () => {
    // Create 10 nodes
    for (let i = 0; i < 10; i++) {
      await registry.getProfile(`node-${i}`);
    }

    // 7 attestations (>= 2/3 of 10)
    const attestations = [];
    for (let i = 0; i < 7; i++) {
      attestations.push({ attesterId: `node-${i}` });
    }

    const result = await calculator.isRevoked(attestations);
    
    expect(result.revoked).toBe(true);
    expect(result.confidence >= 0.66).toBeTruthy();
  });

  it('should handle mixed tier weights', async () => {
    // Custom registry with different tiers
    const mixedRegistry = new TrustTierRegistry({
      getTimeSource: async (id) => {
        if (id === 'oracle') return TIME_SOURCE.ATOMIC;
        if (id === 'anchor') return TIME_SOURCE.GPS;
        return TIME_SOURCE.NTP;
      },
      getNetworkAge: async () => 60 * 24 * 60 * 60 * 1000, // 60 days
      getEndorsementCount: async () => 5,
      getHardwareAttestation: async () => createMockHardwareAttestation(true),
    });

    await mixedRegistry.getProfile('oracle');   // 2.0x weight
    await mixedRegistry.getProfile('anchor');   // 1.5x weight
    await mixedRegistry.getProfile('participant'); // 1.0x weight

    const effectiveSize = mixedRegistry.getEffectiveNetworkSize();
    
    // 2.0 + 1.5 + 1.0 = 4.5
    expect(effectiveSize).toBe(4.5);
  });

  it('should require minimum nodes', async () => {
    await registry.getProfile('node-1');
    await registry.getProfile('node-2');

    const attestations = [
      { attesterId: 'node-1' },
      { attesterId: 'node-2' },
    ];

    const result = await calculator.isRevoked(attestations, 3);
    
    expect(result.revoked).toBe(false);
    expect(result.reason).toBe('INSUFFICIENT_NETWORK');
  });
});

describe('HardwareAttestation', () => {
  it('should measure AES performance', async () => {
    const timing = await measureAESPerformance({
      dataSize: 64 * 1024, // 64KB for faster test
      iterations: 10,
    });

    expect(timing.meanMs > 0).toBeTruthy();
    expect(timing.stddevMs >= 0).toBeTruthy();
    expect(timing.throughputMBps > 0).toBeTruthy();
  });

  it('should validate good timing', () => {
    const timing = {
      meanMs: 3.5,
      stddevMs: 0.3,
      throughputMBps: 2500,
      varianceRatio: 0.08,
    };

    const result = validateAESTiming(timing);
    
    expect(result.valid).toBe(true);
    expect(result.hasAESNI).toBe(true);
  });

  it('should reject slow timing', () => {
    const timing = {
      meanMs: 50,
      stddevMs: 10,
      throughputMBps: 80,
      varianceRatio: 0.2,
    };

    const result = validateAESTiming(timing);
    
    expect(result.valid).toBe(false);
    expect(result.issues.length > 0).toBeTruthy();
  });

  it('should create local attestation', async () => {
    const attestation = await HardwareAttestation.createLocal();
    
    expect(attestation.version).toBeTruthy();
    expect(attestation.createdAt).toBeTruthy();
    expect(attestation.cpu).toBeTruthy();
    expect(attestation.timing).toBeTruthy();
    expect(attestation.validation).toBeTruthy();
  });

  it('should create challenge', () => {
    const challenge = HardwareAttestation.createChallenge();
    
    expect(challenge.nonce).toBeTruthy();
    expect(challenge.dataHash).toBeTruthy();
    expect(challenge.expiresAt > Date.now()).toBeTruthy();
  });
});

describe('Integration: Trust Tiers with Revocation', () => {
  it('should weight ORACLE attestations higher', async () => {
    const registry = new TrustTierRegistry({
      getTimeSource: async (id) => id.startsWith('oracle') ? TIME_SOURCE.ATOMIC : TIME_SOURCE.NTP,
      getNetworkAge: async () => 60 * 24 * 60 * 60 * 1000,
      getEndorsementCount: async (id) => id.startsWith('oracle') ? 5 : 0,
      getHardwareAttestation: async () => createMockHardwareAttestation(true),
    });

    // 2 ORACLE nodes (2.0x each = 4.0 effective)
    await registry.getProfile('oracle-1');
    await registry.getProfile('oracle-2');

    // 10 PARTICIPANT nodes (1.0x each = 10.0 effective)
    for (let i = 0; i < 10; i++) {
      await registry.getProfile(`participant-${i}`);
    }

    // Total effective size: 4.0 + 10.0 = 14.0
    // Threshold: 14.0 * 2/3 = 9.33

    const calculator = new WeightedRevocationCalculator(registry);

    // Just 2 ORACLE attestations = 4.0 effective
    const oracleOnlyResult = await calculator.isRevoked([
      { attesterId: 'oracle-1' },
      { attesterId: 'oracle-2' },
    ]);
    
    expect(oracleOnlyResult.revoked).toBe(false);
    expect(oracleOnlyResult.effectiveCount).toBe(4.0);

    // 2 ORACLE + 6 PARTICIPANT = 4.0 + 6.0 = 10.0 >= 9.33
    const mixedResult = await calculator.isRevoked([
      { attesterId: 'oracle-1' },
      { attesterId: 'oracle-2' },
      { attesterId: 'participant-0' },
      { attesterId: 'participant-1' },
      { attesterId: 'participant-2' },
      { attesterId: 'participant-3' },
      { attesterId: 'participant-4' },
      { attesterId: 'participant-5' },
    ]);
    
    expect(mixedResult.revoked).toBe(true);
    expect(mixedResult.effectiveCount).toBe(10.0);
  });
});
