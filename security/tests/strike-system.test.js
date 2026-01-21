/**
 * Strike System Tests
 * 
 * Tests for "Three Strikes — Then Math Speaks"
 * Validates revocation lineage tracking and graduated consequences
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  STRIKE_LEVELS,
  STRIKE_CONSEQUENCES,
  PROBATION_DURATION_MS,
  StrikeEvent,
  StrikeRecord,
  StrikeRegistry,
  StrikeRevocationBridge,
} from '../strike-system.js';

describe('Strike System', () => {

  describe('STRIKE_LEVELS', () => {
    it('should define all strike levels', () => {
      expect(STRIKE_LEVELS.CLEAN).toBe(0);
      expect(STRIKE_LEVELS.WARNING).toBe(1);
      expect(STRIKE_LEVELS.PROBATION).toBe(2);
      expect(STRIKE_LEVELS.BANNED).toBe(3);
    });
  });

  describe('STRIKE_CONSEQUENCES', () => {
    it('should define consequences for each level', () => {
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.CLEAN].canParticipate).toBe(true);
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.CLEAN].trustMultiplier).toBe(1.0);

      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.WARNING].canParticipate).toBe(true);
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.WARNING].trustMultiplier).toBe(0.75);

      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.PROBATION].canParticipate).toBe(true);
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.PROBATION].trustMultiplier).toBe(0.5);
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.PROBATION].probationDays).toBe(7);

      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.BANNED].canParticipate).toBe(false);
      expect(STRIKE_CONSEQUENCES[STRIKE_LEVELS.BANNED].trustMultiplier).toBe(0);
    });

    it('should have 7-day probation duration', () => {
      expect(PROBATION_DURATION_MS).toBe(7 * 24 * 60 * 60 * 1000);
    });
  });

  describe('StrikeEvent', () => {
    it('should create a strike event', () => {
      const strike = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-123',
        nodeId: 'doko:bad-actor',
        reason: 'Propagated invalid blocks',
      });

      expect(strike.id).toMatch(/^strike-/);
      expect(strike.hardwareFingerprint).toBe('aes-fp-123');
      expect(strike.nodeId).toBe('doko:bad-actor');
      expect(strike.reason).toBe('Propagated invalid blocks');
      expect(strike.timestamp).toBeGreaterThan(0);
      expect(strike.verified).toBe(false);
    });

    it('should verify a strike', () => {
      const strike = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-123',
        nodeId: 'doko:bad-actor',
        reason: 'Test',
      });

      strike.verify(['node-1', 'node-2', 'node-3']);

      expect(strike.verified).toBe(true);
      expect(strike.verifiedBy).toEqual(['node-1', 'node-2', 'node-3']);
      expect(strike.verifiedAt).toBeGreaterThan(0);
    });

    it('should serialize and deserialize', () => {
      const strike = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-123',
        nodeId: 'doko:bad-actor',
        reason: 'Test reason',
        attestors: ['attestor-1'],
      });
      strike.verify(['verifier-1']);

      const json = strike.toJSON();
      const restored = StrikeEvent.fromJSON(json);

      expect(restored.id).toBe(strike.id);
      expect(restored.hardwareFingerprint).toBe(strike.hardwareFingerprint);
      expect(restored.nodeId).toBe(strike.nodeId);
      expect(restored.reason).toBe(strike.reason);
      expect(restored.verified).toBe(true);
    });
  });

  describe('StrikeRecord', () => {
    let record;

    beforeEach(() => {
      record = new StrikeRecord('aes-fp-abc123');
    });

    it('should create with clean slate', () => {
      expect(record.strikeCount).toBe(0);
      expect(record.level).toBe(STRIKE_LEVELS.CLEAN);
      expect(record.canParticipate).toBe(true);
      expect(record.trustMultiplier).toBe(1.0);
    });

    it('should track identity lineage', () => {
      record.trackIdentity('doko:node-1');
      record.trackIdentity('doko:node-2');
      record.trackIdentity('doko:node-1'); // Duplicate

      expect(record.identityLineage).toHaveLength(2);
      expect(record.hasIdentity('doko:node-1')).toBe(true);
      expect(record.hasIdentity('doko:node-3')).toBe(false);
    });

    it('should progress through strike levels', () => {
      // Strike 1 -> WARNING
      const strike1 = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-1',
        reason: 'First offense',
      });
      record.addStrike(strike1);

      expect(record.strikeCount).toBe(1);
      expect(record.level).toBe(STRIKE_LEVELS.WARNING);
      expect(record.canParticipate).toBe(true);
      expect(record.trustMultiplier).toBe(0.75);

      // Strike 2 -> PROBATION
      const strike2 = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-2',
        reason: 'Second offense',
      });
      record.addStrike(strike2);

      expect(record.strikeCount).toBe(2);
      expect(record.level).toBe(STRIKE_LEVELS.PROBATION);
      expect(record.canParticipate).toBe(true);
      expect(record.isOnProbation).toBe(true);
      expect(record.probationStart).toBeGreaterThan(0);
      expect(record.probationEnd).toBe(record.probationStart + PROBATION_DURATION_MS);

      // Strike 3 -> BANNED
      const strike3 = new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-3',
        reason: 'Third offense - permanent ban',
      });
      record.addStrike(strike3);

      expect(record.strikeCount).toBe(3);
      expect(record.level).toBe(STRIKE_LEVELS.BANNED);
      expect(record.canParticipate).toBe(false);
      expect(record.trustMultiplier).toBe(0);
    });

    it('should reject mismatched fingerprints', () => {
      const strike = new StrikeEvent({
        hardwareFingerprint: 'different-fp',
        nodeId: 'doko:node',
        reason: 'Test',
      });

      expect(() => record.addStrike(strike)).toThrow('Strike fingerprint mismatch');
    });

    it('should calculate probation remaining', () => {
      // Add two strikes to enter probation
      record.addStrike(new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-1',
        reason: 'Strike 1',
      }));
      record.addStrike(new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-2',
        reason: 'Strike 2',
      }));

      const remaining = record.getProbationRemaining();
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(PROBATION_DURATION_MS);
    });

    it('should serialize and deserialize', () => {
      record.trackIdentity('doko:node-1');
      record.addStrike(new StrikeEvent({
        hardwareFingerprint: 'aes-fp-abc123',
        nodeId: 'doko:node-1',
        reason: 'Test',
      }));

      const json = record.toJSON();
      const restored = StrikeRecord.fromJSON(json);

      expect(restored.hardwareFingerprint).toBe(record.hardwareFingerprint);
      expect(restored.strikeCount).toBe(1);
      expect(restored.level).toBe(STRIKE_LEVELS.WARNING);
      expect(restored.identityLineage).toContain('doko:node-1');
    });
  });

  describe('StrikeRegistry', () => {
    let registry;

    beforeEach(() => {
      registry = new StrikeRegistry();
    });

    it('should register identities', () => {
      const record = registry.registerIdentity('aes-fp-123', 'doko:node-1');

      expect(record.hardwareFingerprint).toBe('aes-fp-123');
      expect(record.identityLineage).toContain('doko:node-1');
      expect(registry.getHardwareForNode('doko:node-1')).toBe('aes-fp-123');
    });

    it('should issue strikes', () => {
      registry.registerIdentity('aes-fp-123', 'doko:node-1');

      const result = registry.issueStrike({
        hardwareFingerprint: 'aes-fp-123',
        nodeId: 'doko:node-1',
        reason: 'Malicious behavior',
        attestors: ['attestor-1', 'attestor-2'],
      });

      expect(result.success).toBe(true);
      expect(result.strike.reason).toBe('Malicious behavior');
      expect(result.newLevel).toBe(STRIKE_LEVELS.WARNING);
      expect(result.previousStrikes).toBe(0);
    });

    it('should prevent strikes on already banned hardware', () => {
      const fp = 'aes-fp-banned';

      // Issue 3 strikes
      for (let i = 0; i < 3; i++) {
        registry.issueStrike({
          hardwareFingerprint: fp,
          nodeId: `doko:node-${i}`,
          reason: `Strike ${i + 1}`,
        });
      }

      // Try to issue 4th strike
      const result = registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-new',
        reason: 'Fourth attempt',
      });

      expect(result.success).toBe(false);
      expect(result.reason).toBe('Hardware already permanently banned');
    });

    it('should check participation status', () => {
      const fp = 'aes-fp-123';

      // Clean node
      let status = registry.checkParticipation('doko:unknown');
      expect(status.canParticipate).toBe(true);
      expect(status.strikes).toBe(0);

      // Register and strike
      registry.registerIdentity(fp, 'doko:node-1');
      registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-1',
        reason: 'Strike 1',
      });

      status = registry.checkParticipation('doko:node-1');
      expect(status.canParticipate).toBe(true);
      expect(status.strikes).toBe(1);
      expect(status.level).toBe(STRIKE_LEVELS.WARNING);
      expect(status.trustMultiplier).toBe(0.75);
    });

    it('should check hardware status', () => {
      const fp = 'aes-fp-known';

      // Unknown hardware
      let check = registry.checkHardware('aes-fp-unknown');
      expect(check.known).toBe(false);

      // Known hardware
      registry.registerIdentity(fp, 'doko:node-1');
      registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-1',
        reason: 'Strike',
      });

      check = registry.checkHardware(fp);
      expect(check.known).toBe(true);
      expect(check.strikes).toBe(1);
      expect(check.identityLineage).toContain('doko:node-1');
    });

    it('should detect fresh starts', () => {
      const fp = 'aes-fp-fresh';

      // First identity
      registry.registerIdentity(fp, 'doko:node-1');
      registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-1',
        reason: 'Strike 1',
      });

      // New identity from same hardware
      const detection = registry.detectFreshStart(fp, 'doko:node-2');

      expect(detection.isFreshStart).toBe(true);
      expect(detection.previousIdentities).toContain('doko:node-1');
      expect(detection.strikes).toBe(1);
      expect(detection.allowed).toBe(true);
    });

    it('should block fresh starts from banned hardware', () => {
      const fp = 'aes-fp-banned';

      // Issue 3 strikes
      for (let i = 0; i < 3; i++) {
        registry.issueStrike({
          hardwareFingerprint: fp,
          nodeId: `doko:node-${i}`,
          reason: `Strike ${i + 1}`,
        });
      }

      // Attempt fresh start
      const detection = registry.detectFreshStart(fp, 'doko:node-new');

      expect(detection.isFreshStart).toBe(true);
      expect(detection.allowed).toBe(false);
      expect(detection.strikes).toBe(3);
      expect(detection.level).toBe(STRIKE_LEVELS.BANNED);
    });

    it('should list banned hardware', () => {
      // Create banned hardware
      for (let i = 0; i < 3; i++) {
        registry.issueStrike({
          hardwareFingerprint: 'aes-fp-banned-1',
          nodeId: `doko:node-${i}`,
          reason: `Strike ${i + 1}`,
        });
      }

      // Create warning-level hardware
      registry.issueStrike({
        hardwareFingerprint: 'aes-fp-warning',
        nodeId: 'doko:node-x',
        reason: 'Single strike',
      });

      const banned = registry.getBannedHardware();
      expect(banned).toContain('aes-fp-banned-1');
      expect(banned).not.toContain('aes-fp-warning');
    });

    it('should get probation list', () => {
      const fp = 'aes-fp-probation';

      // Two strikes -> probation
      registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-1',
        reason: 'Strike 1',
      });
      registry.issueStrike({
        hardwareFingerprint: fp,
        nodeId: 'doko:node-2',
        reason: 'Strike 2',
      });

      const probationList = registry.getProbationList();
      expect(probationList).toHaveLength(1);
      expect(probationList[0].hardwareFingerprint).toBe(fp);
      expect(probationList[0].remaining).toBeGreaterThan(0);
    });

    it('should track statistics', () => {
      registry.issueStrike({
        hardwareFingerprint: 'fp-1',
        nodeId: 'node-1',
        reason: 'Strike 1',
      });
      registry.issueStrike({
        hardwareFingerprint: 'fp-1',
        nodeId: 'node-2',
        reason: 'Strike 2',
      });
      registry.issueStrike({
        hardwareFingerprint: 'fp-1',
        nodeId: 'node-3',
        reason: 'Strike 3',
      });

      const stats = registry.getStats();
      expect(stats.totalStrikes).toBe(3);
      expect(stats.totalBans).toBe(1);
      expect(stats.totalRecords).toBe(1);
    });

    it('should export and import', () => {
      registry.registerIdentity('fp-1', 'node-1');
      registry.issueStrike({
        hardwareFingerprint: 'fp-1',
        nodeId: 'node-1',
        reason: 'Test strike',
      });

      const exported = registry.export();
      expect(exported.records).toHaveLength(1);
      expect(exported.identityMap['node-1']).toBe('fp-1');

      // Import to new registry
      const newRegistry = new StrikeRegistry();
      newRegistry.import(exported);

      expect(newRegistry.getHardwareForNode('node-1')).toBe('fp-1');
      expect(newRegistry.getRecord('fp-1').strikeCount).toBe(1);
    });
  });

  describe('StrikeRevocationBridge', () => {
    let registry;
    let mockRevocation;
    let bridge;

    beforeEach(() => {
      registry = new StrikeRegistry();
      mockRevocation = {
        revoke: vi.fn(),
      };
      bridge = new StrikeRevocationBridge(registry, mockRevocation);
    });

    it('should handle successful revocation', () => {
      const revocationResult = {
        revoked: true,
        id: 'revocation-123',
        threshold: 0.67,
        yesVotes: 10,
        attestors: ['attestor-1', 'attestor-2'],
      };

      const result = bridge.handleRevocation(
        'aes-fp-123',
        'doko:bad-node',
        revocationResult
      );

      expect(result.strikeIssued).toBe(true);
      expect(result.newLevel).toBe(STRIKE_LEVELS.WARNING);
      expect(result.previousStrikes).toBe(0);
    });

    it('should not issue strike for failed revocation', () => {
      const revocationResult = {
        revoked: false,
      };

      const result = bridge.handleRevocation(
        'aes-fp-123',
        'doko:node',
        revocationResult
      );

      expect(result.strikeIssued).toBe(false);
    });

    it('should validate clean join', () => {
      const result = bridge.validateJoin('aes-fp-new', 'doko:new-node');

      expect(result.allowed).toBe(true);
      expect(result.isFreshStart).toBe(false);
      expect(result.strikes).toBe(0);
      expect(result.trustMultiplier).toBe(1.0);
    });

    it('should validate fresh start join', () => {
      // First identity with a strike
      registry.registerIdentity('aes-fp-123', 'doko:node-1');
      registry.issueStrike({
        hardwareFingerprint: 'aes-fp-123',
        nodeId: 'doko:node-1',
        reason: 'Bad behavior',
      });

      // New identity from same hardware
      const result = bridge.validateJoin('aes-fp-123', 'doko:node-2');

      expect(result.allowed).toBe(true);
      expect(result.isFreshStart).toBe(true);
      expect(result.warning).toContain('Fresh start #2');
      expect(result.previousIdentities).toContain('doko:node-1');
      expect(result.trustMultiplier).toBe(0.75);
    });

    it('should block banned hardware join', () => {
      // Issue 3 strikes
      for (let i = 0; i < 3; i++) {
        registry.issueStrike({
          hardwareFingerprint: 'aes-fp-banned',
          nodeId: `doko:node-${i}`,
          reason: `Strike ${i + 1}`,
        });
      }

      // Attempt join with new identity
      const result = bridge.validateJoin('aes-fp-banned', 'doko:new-attempt');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Hardware permanently banned');
      expect(result.previousIdentities).toHaveLength(3);
    });
  });

  describe('Edge Cases', () => {
    let registry;

    beforeEach(() => {
      registry = new StrikeRegistry();
    });

    it('should handle concurrent strikes on same hardware', () => {
      const fp = 'aes-fp-concurrent';

      // Rapid strikes
      registry.issueStrike({ hardwareFingerprint: fp, nodeId: 'node-1', reason: 'Strike 1' });
      registry.issueStrike({ hardwareFingerprint: fp, nodeId: 'node-1', reason: 'Strike 2' });
      registry.issueStrike({ hardwareFingerprint: fp, nodeId: 'node-1', reason: 'Strike 3' });
      registry.issueStrike({ hardwareFingerprint: fp, nodeId: 'node-1', reason: 'Strike 4' }); // Should fail

      const record = registry.getRecord(fp);
      expect(record.strikeCount).toBe(3); // Max 3 strikes
      expect(record.level).toBe(STRIKE_LEVELS.BANNED);
    });

    it('should track all identities used by hardware', () => {
      const fp = 'aes-fp-many-identities';

      registry.registerIdentity(fp, 'node-1');
      registry.registerIdentity(fp, 'node-2');
      registry.registerIdentity(fp, 'node-3');
      registry.issueStrike({ hardwareFingerprint: fp, nodeId: 'node-4', reason: 'Strike' });

      const record = registry.getRecord(fp);
      expect(record.identityLineage).toContain('node-1');
      expect(record.identityLineage).toContain('node-2');
      expect(record.identityLineage).toContain('node-3');
      expect(record.identityLineage).toContain('node-4');
    });

    it('should handle registry clear', () => {
      registry.issueStrike({
        hardwareFingerprint: 'fp-1',
        nodeId: 'node-1',
        reason: 'Test',
      });

      expect(registry.getStats().totalStrikes).toBe(1);

      registry.clear();

      expect(registry.getStats().totalStrikes).toBe(0);
      expect(registry.records.size).toBe(0);
    });
  });

});
