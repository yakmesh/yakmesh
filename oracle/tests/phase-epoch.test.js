/**
 * Phase Epoch Tests - Star Trek TNG Inspired Phase Modulation
 * 
 * Tests the time-based phase rotation system that adds anti-replay
 * protection to network identity fingerprints.
 * 
 * "Modulate the shield frequency!" - Geordi La Forge
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import {
  getCurrentEpoch,
  getEpochStartTime,
  getEpochEndTime,
  getTimeUntilRotation,
  isInGracePeriod,
  getValidEpochs,
  modulateSalt,
  modulateInfo,
  derivePhaseModulated,
  derivePhaseModulatedHex,
  derivePhaseFingerprint,
  verifyPhaseFingerprint,
  createPhasedChallenge,
  verifyPhasedChallenge,
  getPhaseStatus,
  formatPhaseId,
  EPOCH_DURATION_HOURS,
  GRACE_PERIOD_MINUTES,
  LOOKAHEAD_PHASES,
} from '../phase-epoch.js';

// Calculate derived constants
const EPOCH_DURATION_MS = EPOCH_DURATION_HOURS * 60 * 60 * 1000;

describe('Phase Epoch System', () => {
  
  describe('getCurrentEpoch()', () => {
    it('should return current epoch number', () => {
      const epoch = getCurrentEpoch();
      
      assert(typeof epoch === 'number', 'epoch should be a number');
      assert(epoch > 0, 'epoch should be positive');
      
      console.log(`  ⚡ Current epoch: ${epoch}`);
    });
    
    it('should return same epoch within same period', () => {
      const epoch1 = getCurrentEpoch();
      const epoch2 = getCurrentEpoch();
      
      assert.strictEqual(epoch1, epoch2, 'epochs should match');
    });
    
    it('should accept optional timestamp', () => {
      const now = Date.now();
      const epochNow = getCurrentEpoch(now);
      const epochFuture = getCurrentEpoch(now + EPOCH_DURATION_MS);
      
      assert.strictEqual(epochFuture, epochNow + 1, 'future should be next epoch');
    });
  });
  
  describe('getEpochStartTime() / getEpochEndTime()', () => {
    it('should return valid time boundaries', () => {
      const epoch = getCurrentEpoch();
      const start = getEpochStartTime(epoch);
      const end = getEpochEndTime(epoch);
      const now = Date.now();
      
      assert(start <= now, 'startTime should be in the past or now');
      assert(end > now, 'endTime should be in the future');
      assert(end - start === EPOCH_DURATION_MS, 
        'epoch duration should match configured duration');
      
      console.log(`  ⏰ Epoch ${epoch}: ${new Date(start).toISOString()} - ${new Date(end).toISOString()}`);
    });
  });
  
  describe('getTimeUntilRotation()', () => {
    it('should return time info', () => {
      const remaining = getTimeUntilRotation();
      
      assert(typeof remaining.hours === 'number', 'hours should be number');
      assert(typeof remaining.minutes === 'number', 'minutes should be number');
      assert(typeof remaining.seconds === 'number', 'seconds should be number');
      assert(typeof remaining.totalMs === 'number', 'totalMs should be number');
      
      console.log(`  ⏳ Time until rotation: ${remaining.hours}h ${remaining.minutes}m ${remaining.seconds}s`);
    });
  });
  
  describe('getValidEpochs()', () => {
    it('should return array of valid epochs', () => {
      const validEpochs = getValidEpochs();
      
      assert(Array.isArray(validEpochs), 'should return array');
      assert(validEpochs.length >= 1, 'should have at least current epoch');
      
      console.log(`  ✅ Valid epochs: ${validEpochs.join(', ')}`);
    });
    
    it('should include current epoch', () => {
      const validEpochs = getValidEpochs();
      const currentEpoch = getCurrentEpoch();
      
      assert(validEpochs.includes(currentEpoch), 'should include current epoch');
    });
  });
  
  describe('modulateSalt()', () => {
    it('should generate consistent salt for same epoch', () => {
      const epoch = getCurrentEpoch();
      const salt1 = modulateSalt('test-salt', epoch);
      const salt2 = modulateSalt('test-salt', epoch);
      
      assert.deepStrictEqual(salt1, salt2, 'salts should match for same epoch');
    });
    
    it('should generate different salts for different epochs', () => {
      const epoch = getCurrentEpoch();
      const salt1 = modulateSalt('test-salt', epoch);
      const salt2 = modulateSalt('test-salt', epoch + 1);
      
      assert.notDeepStrictEqual(salt1, salt2, 'different epochs should have different salts');
      
      console.log('  ⚡ Phase modulation creates unique salts per epoch');
    });
  });
  
  describe('derivePhaseFingerprint()', () => {
    // A valid 64-char hex hash for testing
    const testCodeHash = 'a'.repeat(64);
    
    it('should derive fingerprint from hash and epoch', () => {
      const fingerprint = derivePhaseFingerprint(testCodeHash);
      
      assert(typeof fingerprint === 'string', 'fingerprint should be a string');
      assert(fingerprint.length === 32, 'fingerprint should be 32 hex chars (16 bytes)');
      
      console.log(`  🔒 Phase fingerprint: ${fingerprint}`);
    });
    
    it('should produce same fingerprint for same hash and epoch', () => {
      const fp1 = derivePhaseFingerprint(testCodeHash);
      const fp2 = derivePhaseFingerprint(testCodeHash);
      
      assert.strictEqual(fp1, fp2, 'same inputs should produce same fingerprint');
    });
    
    it('should produce different fingerprint for different epochs', () => {
      const currentEpoch = getCurrentEpoch();
      const fp1 = derivePhaseFingerprint(testCodeHash, currentEpoch);
      const fp2 = derivePhaseFingerprint(testCodeHash, currentEpoch + 1);
      
      assert.notStrictEqual(fp1, fp2, 'different epochs should produce different fingerprints');
      
      console.log('  🔒 Fingerprints rotate with phase epochs (anti-replay protection)');
    });
    
    it('should produce different fingerprint for different hashes', () => {
      const hash1 = 'a'.repeat(64);
      const hash2 = 'b'.repeat(64);
      const fp1 = derivePhaseFingerprint(hash1);
      const fp2 = derivePhaseFingerprint(hash2);
      
      assert.notStrictEqual(fp1, fp2, 'different hashes should produce different fingerprints');
    });
  });
  
  describe('verifyPhaseFingerprint()', () => {
    const testCodeHash = 'c'.repeat(64);
    
    it('should verify correct current fingerprint', () => {
      const fingerprint = derivePhaseFingerprint(testCodeHash);
      const result = verifyPhaseFingerprint(testCodeHash, fingerprint);
      
      assert(result.valid, 'should verify current fingerprint');
      assert.strictEqual(result.epoch, getCurrentEpoch(), 'should match current epoch');
      
      console.log(`  ✓ Fingerprint verified: ${result.reason}`);
    });
    
    it('should reject incorrect fingerprint', () => {
      const result = verifyPhaseFingerprint(testCodeHash, 'wrong'.repeat(8));
      
      assert(!result.valid, 'should reject wrong fingerprint');
      assert.strictEqual(result.reason, 'PHASE_MISMATCH');
    });
  });
  
  describe('formatPhaseId()', () => {
    it('should format phase ID with Greek letter', () => {
      const phaseId = formatPhaseId(getCurrentEpoch());
      
      assert(phaseId.startsWith('Phase-'), 'should start with Phase-');
      assert(/Phase-\d+[αβγδεζηθ]/.test(phaseId), 'should match pattern Phase-N{greek}');
      
      console.log(`  🖖 Phase ID: ${phaseId}`);
    });
    
    it('should cycle through Greek letters', () => {
      const ids = [];
      for (let i = 0; i < 8; i++) {
        ids.push(formatPhaseId(i));
      }
      
      // Should have different Greek letters
      const expected = ['Phase-0α', 'Phase-0β', 'Phase-0γ', 'Phase-0δ', 
                       'Phase-0ε', 'Phase-0ζ', 'Phase-0η', 'Phase-0θ'];
      
      assert.deepStrictEqual(ids, expected, 'should cycle through Greek letters');
      console.log('  🖖 Greek letters: ' + ids.join(', '));
    });
  });
  
  describe('createPhasedChallenge() / verifyPhasedChallenge()', () => {
    it('should create phased challenge', () => {
      const challenge = createPhasedChallenge(
        'deadbeef12345678',
        'challenger-node',
        'target-node'
      );
      
      assert(challenge.challenge, 'should have challenge');
      assert(typeof challenge.epoch === 'number', 'should have epoch');
      assert(challenge.binding, 'should have binding');
      assert(challenge.expiresAt > Date.now(), 'should expire in future');
      
      console.log(`  📨 Challenge created, epoch ${challenge.epoch}, binding ${challenge.binding}`);
    });
    
    it('should verify valid challenge', () => {
      const challenge = createPhasedChallenge(
        'abcd1234abcd1234',
        'node-1',
        'node-2'
      );
      
      const result = verifyPhasedChallenge(challenge);
      
      assert(result.valid, 'current challenge should be valid');
      assert.strictEqual(result.reason, 'VALID');
    });
    
    it('should reject expired challenge', () => {
      const oldEpoch = getCurrentEpoch() - 10;
      const challenge = createPhasedChallenge(
        '1234567890abcdef',
        'node-a',
        'node-b',
        oldEpoch
      );
      
      const result = verifyPhasedChallenge(challenge);
      
      assert(!result.valid, 'old challenge should be invalid');
    });
  });
  
  describe('getPhaseStatus()', () => {
    it('should return comprehensive status', () => {
      const status = getPhaseStatus();
      
      assert(typeof status.currentEpoch === 'number', 'should have currentEpoch');
      assert.strictEqual(status.epochDurationHours, EPOCH_DURATION_HOURS, 'should have duration');
      assert.strictEqual(status.gracePeriodMinutes, GRACE_PERIOD_MINUTES, 'should have grace period');
      assert(typeof status.inGracePeriod === 'boolean', 'should have inGracePeriod');
      assert(Array.isArray(status.validEpochs), 'should have validEpochs');
      assert(status.epochStartedAt, 'should have epochStartedAt');
      assert(status.epochEndsAt, 'should have epochEndsAt');
      assert(status.timeUntilRotation, 'should have timeUntilRotation');
      assert(status.rotationMessage, 'should have rotationMessage');
      
      console.log('\n  📊 Phase Status:');
      console.log(`     Current Epoch: ${status.currentEpoch}`);
      console.log(`     In Grace Period: ${status.inGracePeriod}`);
      console.log(`     Valid Epochs: [${status.validEpochs.join(', ')}]`);
      console.log(`     ${status.rotationMessage}`);
    });
  });
  
  describe('Anti-Replay Protection', () => {
    const testHash = 'd'.repeat(64);
    
    it('should demonstrate fingerprint rotation', () => {
      const currentEpoch = getCurrentEpoch();
      
      const fingerprints = [];
      for (let i = -2; i <= 2; i++) {
        fingerprints.push({
          epoch: currentEpoch + i,
          phaseId: formatPhaseId(currentEpoch + i),
          fingerprint: derivePhaseFingerprint(testHash, currentEpoch + i),
        });
      }
      
      console.log('\n  📊 Fingerprint Rotation Demo:');
      fingerprints.forEach(f => {
        const marker = f.epoch === currentEpoch ? ' ← current' : '';
        console.log(`     ${f.phaseId}: ${f.fingerprint}${marker}`);
      });
      
      // Verify all fingerprints are unique
      const unique = new Set(fingerprints.map(f => f.fingerprint));
      assert.strictEqual(unique.size, 5, 'all fingerprints should be unique');
    });
    
    it('should prevent replay attacks with expired epochs', () => {
      const currentEpoch = getCurrentEpoch();
      const oldEpoch = currentEpoch - 5; // Outside grace period
      
      // Old fingerprint
      const oldFingerprint = derivePhaseFingerprint(testHash, oldEpoch);
      
      // Current fingerprint
      const currentFingerprint = derivePhaseFingerprint(testHash, currentEpoch);
      
      // They should be different
      assert.notStrictEqual(oldFingerprint, currentFingerprint, 
        'fingerprints should differ between epochs');
      
      // Old epoch should fail verification
      const oldResult = verifyPhaseFingerprint(testHash, oldFingerprint);
      assert(!oldResult.valid, 'old fingerprint should fail verification');
      
      // Current epoch should pass verification  
      const currentResult = verifyPhaseFingerprint(testHash, currentFingerprint);
      assert(currentResult.valid, 'current fingerprint should pass verification');
      
      console.log('  🛡️ Replay attack with expired phase would be rejected');
    });
  });
  
  describe('Constants', () => {
    it('should have sensible epoch duration', () => {
      // 6 hours default
      assert.strictEqual(EPOCH_DURATION_HOURS, 6, 'default epoch should be 6 hours');
      
      console.log(`  ⏰ Epoch duration: ${EPOCH_DURATION_HOURS} hours`);
    });
    
    it('should have reasonable grace period', () => {
      assert(GRACE_PERIOD_MINUTES >= 5, 'grace period should be at least 5 minutes');
      assert(GRACE_PERIOD_MINUTES <= 60, 'grace period should not be too long');
      
      console.log(`  🔧 Grace period: ${GRACE_PERIOD_MINUTES} minutes`);
    });
    
    it('should have lookahead phases', () => {
      assert(LOOKAHEAD_PHASES >= 1, 'should have at least 1 lookahead phase');
      
      console.log(`  👁️ Lookahead phases: ${LOOKAHEAD_PHASES}`);
    });
  });
});

console.log('\n🖖 "Modulate the shield frequency, Mr. La Forge!" - Captain Picard\n');
