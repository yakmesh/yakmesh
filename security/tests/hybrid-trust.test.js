/**
 * Hybrid Trust Model Tests
 * 
 * Tests for the multi-level trust assessment system.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { POSITIVE } from '../../oracle/tribhuj.js';
import HybridTrustModel, { 
  TrustLevel, 
  TrustLevelInfo, 
  TrustEvidence,
  TrustBasedAccessControl 
} from '../hybrid-trust.js';

// ═══════════════════════════════════════════════════════════════════════════
// TRUST EVIDENCE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('TrustEvidence', () => {
  let evidence;

  beforeEach(() => {
    evidence = new TrustEvidence('node-test-123');
  });

  describe('Evidence Recording', () => {
    test('records DOKO verification', () => {
      evidence.recordDokoVerification({ passed: true, gatesChecked: 7 });
      
      expect(evidence.sources.doko.verified).toBe(POSITIVE);
      expect(evidence.sources.doko.gatesPassedCount).toBe(7);
      expect(evidence.sources.doko.verifiedAt).toBeDefined();
    });

    test('records mesh quorum verification', () => {
      evidence.recordMeshQuorum({
        valid: true,
        validProofs: 5,
        verifiers: ['v1', 'v2', 'v3', 'v4', 'v5'],
        diversity: { sufficient: true },
      });
      
      expect(evidence.sources.meshQuorum.verified).toBe(POSITIVE);
      expect(evidence.sources.meshQuorum.quorumSize).toBe(5);
      expect(evidence.sources.meshQuorum.diversity.sufficient).toBe(true);
    });

    test('records SSL verification', () => {
      evidence.recordSSLVerification({
        verified: true,
        certType: 'doko-bound',
        fingerprint: 'sha256:abc123',
      });
      
      expect(evidence.sources.ssl.verified).toBe(POSITIVE);
      expect(evidence.sources.ssl.certType).toBe('doko-bound');
    });

    test('records domain verification', () => {
      evidence.recordDomainVerification({
        valid: true,
        domain: 'example.com',
        proofCount: 5,
      });
      
      expect(evidence.sources.domain.verified).toBe(POSITIVE);
      expect(evidence.sources.domain.domain).toBe('example.com');
    });

    test('records beacon sightings', () => {
      evidence.recordBeaconSighting();
      evidence.recordBeaconSighting();
      evidence.recordBeaconSighting();
      
      expect(evidence.sources.beaconHistory.sightings).toBe(3);
      expect(evidence.sources.beaconHistory.firstSeen).toBeDefined();
      expect(evidence.sources.beaconHistory.lastSeen).toBeDefined();
    });
  });

  describe('Age Calculation', () => {
    test('returns 0 for new evidence', () => {
      expect(evidence.getAge()).toBe(0);
    });

    test('calculates age from first beacon sighting', () => {
      evidence.sources.beaconHistory.firstSeen = Date.now() - (5 * 24 * 60 * 60 * 1000);
      
      const age = evidence.getAge();
      const ageDays = age / (24 * 60 * 60 * 1000);
      
      expect(ageDays).toBeCloseTo(5, 0);
    });
  });

  describe('Beacon Consistency', () => {
    test('calculates consistency correctly', () => {
      const now = Date.now();
      evidence.sources.beaconHistory.firstSeen = now - (60 * 60 * 1000);  // 1 hour ago
      evidence.sources.beaconHistory.sightings = 30;  // 30 sightings
      
      // With 60-second expected interval, 60 expected sightings in 1 hour
      const consistency = evidence.calculateBeaconConsistency(60 * 60 * 1000, 60000);
      
      expect(consistency).toBeCloseTo(0.5, 1);  // 30/60 = 0.5
    });

    test('caps consistency at 1.0', () => {
      const now = Date.now();
      evidence.sources.beaconHistory.firstSeen = now - (60 * 60 * 1000);
      evidence.sources.beaconHistory.sightings = 1000;  // Way more than expected
      
      const consistency = evidence.calculateBeaconConsistency(60 * 60 * 1000, 60000);
      
      expect(consistency).toBe(1);
    });
  });

  describe('Serialization', () => {
    test('serializes and deserializes correctly', () => {
      evidence.recordDokoVerification({ passed: true, gatesChecked: 7 });
      evidence.recordBeaconSighting();
      evidence.trustLevel = TrustLevel.GOLD;
      evidence.trustScore = 75;
      
      const serialized = evidence.serialize();
      const restored = TrustEvidence.deserialize(serialized);
      
      expect(restored.nodeId).toBe('node-test-123');
      expect(restored.sources.doko.verified).toBe(POSITIVE);
      expect(restored.trustLevel).toBe(TrustLevel.GOLD);
      expect(restored.trustScore).toBe(75);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID TRUST MODEL TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('HybridTrustModel', () => {
  let model;

  beforeEach(() => {
    model = new HybridTrustModel({
      autoPromoteEnabled: false,  // Disable for testing
    });
  });

  afterEach(() => {
    model.stopPromotionChecks();
    model.clear();
  });

  describe('Trust Level Assessment', () => {
    test('unknown node starts as UNTRUSTED', () => {
      const result = model.getTrustLevel('unknown-node');
      
      expect(result.level).toBe(TrustLevel.UNTRUSTED);
      expect(result.score).toBe(0);
    });

    test('node with beacon sighting gets BRONZE', () => {
      model.recordBeaconSighting('node-1');
      const result = model.assessTrust('node-1');
      
      expect(result.level).toBe(TrustLevel.BRONZE);
    });

    test('node with DOKO + mesh quorum gets GOLD', () => {
      const nodeId = 'node-gold';
      
      model.recordDokoVerification(nodeId, { passed: true, gatesChecked: 7 });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        verifiers: ['v1', 'v2', 'v3', 'v4', 'v5'],
        diversity: { sufficient: true },
      });
      
      const result = model.getTrustLevel(nodeId);
      
      expect(result.level).toBe(TrustLevel.GOLD);
    });

    test('full verification gets PLATINUM', () => {
      const nodeId = 'node-platinum';
      
      // Set up evidence with age
      const evidence = model.getEvidence(nodeId);
      evidence.sources.beaconHistory.firstSeen = Date.now() - (8 * 24 * 60 * 60 * 1000);  // 8 days
      evidence.sources.beaconHistory.sightings = 10000;  // Good consistency
      
      model.recordDokoVerification(nodeId, { passed: true, gatesChecked: 7 });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        verifiers: ['v1', 'v2', 'v3', 'v4', 'v5'],
        diversity: { sufficient: true },
      });
      model.recordSSLVerification(nodeId, { verified: true, certType: 'doko-bound' });
      model.recordDomainVerification(nodeId, { valid: true, domain: 'example.com', proofCount: 5 });
      
      const result = model.getTrustLevel(nodeId);
      
      expect(result.level).toBe(TrustLevel.PLATINUM);
    });
  });

  describe('Trust Level Transitions', () => {
    test('emits promoted event on level increase', () => {
      const nodeId = 'node-promote';
      const promotedHandler = vi.fn();
      
      model.on('promoted', promotedHandler);
      
      model.recordBeaconSighting(nodeId);
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      expect(promotedHandler).toHaveBeenCalled();
      const call = promotedHandler.mock.calls[0][0];
      expect(call.nodeId).toBe(nodeId);
      expect(call.to).toBeGreaterThan(call.from);
    });

    test('emits demoted event on failed verification', () => {
      const nodeId = 'node-demote';
      const demotedHandler = vi.fn();
      
      // First, get to GOLD
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      model.on('demoted', demotedHandler);
      
      // Now fail DOKO verification
      model.recordDokoVerification(nodeId, { passed: false });
      
      expect(demotedHandler).toHaveBeenCalled();
    });

    test('tracks level history', () => {
      const nodeId = 'node-history';
      
      model.recordBeaconSighting(nodeId);
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      const evidence = model.getEvidence(nodeId);
      
      expect(evidence.levelHistory.length).toBeGreaterThan(0);
    });
  });

  describe('Trust Decay', () => {
    test('decays trust for inactive nodes', () => {
      const nodeId = 'node-decay';
      
      // Set up as GOLD
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      expect(model.getTrustLevel(nodeId).level).toBe(TrustLevel.GOLD);
      
      // Simulate old lastUpdated — SST geometric decay uses 7-day half-life
      // Need ~50+ days for score 70 to decay below 1% threshold
      const evidence = model.getEvidence(nodeId);
      evidence.lastUpdated = Date.now() - (90 * 24 * 60 * 60 * 1000);  // 90 days ago
      
      // Reassess
      const result = model.assessTrust(nodeId);
      
      expect(result.level).toBe(TrustLevel.UNTRUSTED);
      expect(result.reason).toContain('decay');
    });
  });

  describe('Minimum Trust Check', () => {
    test('meetsMinimumTrust returns correct result', () => {
      const nodeId = 'node-check';
      
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      expect(model.meetsMinimumTrust(nodeId, TrustLevel.BRONZE)).toBe(true);
      expect(model.meetsMinimumTrust(nodeId, TrustLevel.GOLD)).toBe(true);
      expect(model.meetsMinimumTrust(nodeId, TrustLevel.PLATINUM)).toBe(false);
    });
  });

  describe('Nodes By Level', () => {
    test('getNodesByLevel returns correct nodes', () => {
      // Create some GOLD nodes
      for (let i = 0; i < 3; i++) {
        const nodeId = `gold-node-${i}`;
        model.recordDokoVerification(nodeId, { passed: true });
        model.recordMeshQuorum(nodeId, {
          valid: true,
          validProofs: 5,
          diversity: { sufficient: true },
        });
      }
      
      // Create some BRONZE nodes
      for (let i = 0; i < 2; i++) {
        const nodeId = `bronze-node-${i}`;
        model.recordBeaconSighting(nodeId);
        model.assessTrust(nodeId);
      }
      
      const goldNodes = model.getNodesByLevel(TrustLevel.GOLD);
      const bronzeNodes = model.getNodesByLevel(TrustLevel.BRONZE);
      
      expect(goldNodes.length).toBe(3);
      expect(bronzeNodes.length).toBe(2);
    });
  });

  describe('Statistics', () => {
    test('tracks assessment statistics', () => {
      model.recordDokoVerification('node-1', { passed: true });
      model.recordMeshQuorum('node-1', { valid: true, validProofs: 5, diversity: { sufficient: true } });
      
      model.recordBeaconSighting('node-2');
      model.assessTrust('node-2');
      
      const stats = model.getStats();
      
      expect(stats.assessmentsPerformed).toBeGreaterThan(0);
      expect(stats.totalNodes).toBe(2);
    });
  });

  describe('Persistence', () => {
    test('serializes and restores state', () => {
      // Create some evidence
      model.recordDokoVerification('node-1', { passed: true });
      model.recordMeshQuorum('node-1', {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      const serialized = model.serialize();
      
      expect(serialized.version).toBe(1);
      expect(serialized.evidence.length).toBe(1);
      
      // Create new model and restore
      const newModel = new HybridTrustModel({ autoPromoteEnabled: false });
      newModel.restore(serialized);
      
      const level = newModel.getTrustLevel('node-1');
      expect(level.level).toBe(TrustLevel.GOLD);
      
      newModel.clear();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TRUST BASED ACCESS CONTROL TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('TrustBasedAccessControl', () => {
  let model;
  let accessControl;

  beforeEach(() => {
    model = new HybridTrustModel({ autoPromoteEnabled: false });
    accessControl = new TrustBasedAccessControl(model);
  });

  afterEach(() => {
    model.clear();
  });

  describe('Access Checks', () => {
    test('allows action when trust level sufficient', () => {
      const nodeId = 'node-access';
      
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      const result = accessControl.canPerform(nodeId, 'mesh:relay');
      
      expect(result.allowed).toBe(true);
    });

    test('denies action when trust level insufficient', () => {
      const nodeId = 'node-low';
      
      model.recordBeaconSighting(nodeId);
      model.assessTrust(nodeId);
      
      const result = accessControl.canPerform(nodeId, 'mesh:relay');  // Requires GOLD
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Insufficient');
    });

    test('allows action with no requirement set', () => {
      const result = accessControl.canPerform('any-node', 'unknown:action');
      
      expect(result.allowed).toBe(true);
    });
  });

  describe('Custom Requirements', () => {
    test('setRequirement updates access requirements', () => {
      accessControl.setRequirement('custom:action', TrustLevel.PLATINUM);
      
      const nodeId = 'node-custom';
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      const result = accessControl.canPerform(nodeId, 'custom:action');
      
      expect(result.allowed).toBe(false);  // GOLD < PLATINUM
    });
  });

  describe('Middleware', () => {
    test('requireTrust middleware passes for sufficient trust', () => {
      const nodeId = 'node-middleware';
      
      model.recordDokoVerification(nodeId, { passed: true });
      model.recordMeshQuorum(nodeId, {
        valid: true,
        validProofs: 5,
        diversity: { sufficient: true },
      });
      
      const middleware = accessControl.requireTrust(TrustLevel.GOLD);
      
      expect(() => middleware(nodeId)).not.toThrow();
    });

    test('requireTrust middleware throws for insufficient trust', () => {
      const nodeId = 'node-middleware-fail';
      
      model.recordBeaconSighting(nodeId);
      model.assessTrust(nodeId);
      
      const middleware = accessControl.requireTrust(TrustLevel.GOLD);
      
      expect(() => middleware(nodeId)).toThrow('Trust level');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TRUST LEVEL INFO TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('TrustLevelInfo', () => {
  test('all trust levels have info defined', () => {
    expect(TrustLevelInfo[TrustLevel.UNTRUSTED]).toBeDefined();
    expect(TrustLevelInfo[TrustLevel.BRONZE]).toBeDefined();
    expect(TrustLevelInfo[TrustLevel.GOLD]).toBeDefined();
    expect(TrustLevelInfo[TrustLevel.PLATINUM]).toBeDefined();
  });

  test('trust level info has required fields', () => {
    for (const level of Object.values(TrustLevel)) {
      const info = TrustLevelInfo[level];
      expect(info.name).toBeDefined();
      expect(info.description).toBeDefined();
      expect(info.color).toBeDefined();
      expect(info.icon).toBeDefined();
    }
  });
});
