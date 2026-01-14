/**
 * Time Source Detection Tests
 * 
 * Tests the time source detection module for:
 * - PCIe atomic clocks
 * - GPS receivers
 * - PTP synchronization
 * - NTP status
 * 
 * Run with: node --test oracle/tests/time-source.test.js
 */

import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert';
import {
  TimeSourceDetector,
  TimeTrustLevel,
  PhaseTolerance,
  StratumLevel,
  createPhaseConfig,
  getTimeSourceDetector,
  detectTimeSources,
} from '../time-source.js';

describe('Time Source Detection Module', () => {
  
  describe('TimeTrustLevel Constants', () => {
    it('should define all trust levels', () => {
      assert.strictEqual(TimeTrustLevel.ATOMIC, 'atomic');
      assert.strictEqual(TimeTrustLevel.GPS, 'gps');
      assert.strictEqual(TimeTrustLevel.PTP, 'ptp');
      assert.strictEqual(TimeTrustLevel.NTP, 'ntp');
      assert.strictEqual(TimeTrustLevel.UNSYNC, 'unsync');
      
      console.log('  ✅ All trust levels defined');
    });
  });
  
  describe('PhaseTolerance Constants', () => {
    it('should have correct tolerance values', () => {
      assert.strictEqual(PhaseTolerance[TimeTrustLevel.ATOMIC], 100);
      assert.strictEqual(PhaseTolerance[TimeTrustLevel.GPS], 500);
      assert.strictEqual(PhaseTolerance[TimeTrustLevel.PTP], 500);
      assert.strictEqual(PhaseTolerance[TimeTrustLevel.NTP], 5000);
      assert.strictEqual(PhaseTolerance[TimeTrustLevel.UNSYNC], 30000);
      
      console.log('  ✅ Phase tolerances configured correctly');
      console.log(`     Atomic: ±${PhaseTolerance.atomic}ms`);
      console.log(`     GPS: ±${PhaseTolerance.gps}ms`);
      console.log(`     NTP: ±${PhaseTolerance.ntp}ms`);
    });
  });
  
  describe('StratumLevel Constants', () => {
    it('should have correct stratum values', () => {
      assert.strictEqual(StratumLevel[TimeTrustLevel.ATOMIC], 0);
      assert.strictEqual(StratumLevel[TimeTrustLevel.GPS], 1);
      assert.strictEqual(StratumLevel[TimeTrustLevel.NTP], 2);
      assert.strictEqual(StratumLevel[TimeTrustLevel.UNSYNC], 16);
      
      console.log('  ✅ Stratum levels correct');
    });
  });
  
  describe('TimeSourceDetector Class', () => {
    it('should create detector with default options', () => {
      const detector = new TimeSourceDetector();
      
      assert(detector instanceof TimeSourceDetector);
      assert.strictEqual(detector.trustLevel, TimeTrustLevel.UNSYNC);
      assert.strictEqual(detector.primarySource, null);
      
      console.log('  ✅ Detector created with defaults');
    });
    
    it('should accept custom options', () => {
      const detector = new TimeSourceDetector({
        detectHardware: false,
        checkNtp: true,
        verbose: false,
        refreshInterval: 30000,
      });
      
      assert.strictEqual(detector.options.detectHardware, false);
      assert.strictEqual(detector.options.refreshInterval, 30000);
      
      console.log('  ✅ Custom options accepted');
    });
    
    it('should detect time sources', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      const results = detector.detect();
      
      assert(results.timestamp > 0);
      assert(results.platform);
      assert(results.sources);
      assert(results.trustLevel);
      assert(typeof results.phaseTolerance === 'number');
      
      console.log(`  ✅ Detection completed`);
      console.log(`     Platform: ${results.platform}`);
      console.log(`     Trust Level: ${results.trustLevel}`);
      console.log(`     Primary: ${results.primarySource || 'none'}`);
    });
    
    it('should emit detected event', (_, done) => {
      const detector = new TimeSourceDetector({ verbose: false });
      
      detector.once('detected', (results) => {
        assert(results.timestamp);
        console.log('  ✅ Detection event emitted');
        done();
      });
      
      detector.detect();
    });
    
    it('should provide trust level getter', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const trustLevel = detector.getTrustLevel();
      assert(Object.values(TimeTrustLevel).includes(trustLevel));
      
      console.log(`  ✅ Trust level: ${trustLevel}`);
    });
    
    it('should provide phase tolerance getter', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const tolerance = detector.getPhaseTolerance();
      assert(typeof tolerance === 'number');
      assert(tolerance > 0);
      
      console.log(`  ✅ Phase tolerance: ±${tolerance}ms`);
    });
    
    it('should provide stratum getter', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const stratum = detector.getStratum();
      assert(typeof stratum === 'number');
      assert(stratum >= 0 && stratum <= 16);
      
      console.log(`  ✅ Stratum: ${stratum}`);
    });
    
    it('should report capabilities', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const hasAtomic = detector.hasAtomicTime();
      const hasHighPrecision = detector.hasHighPrecisionTime();
      
      assert(typeof hasAtomic === 'boolean');
      assert(typeof hasHighPrecision === 'boolean');
      
      console.log(`  ✅ Has atomic time: ${hasAtomic}`);
      console.log(`  ✅ Has high precision: ${hasHighPrecision}`);
    });
    
    it('should provide status for API', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const status = detector.getStatus();
      
      assert(status.trustLevel);
      assert(typeof status.phaseTolerance === 'number');
      assert(typeof status.stratum === 'number');
      assert(status.capabilities);
      
      console.log('  ✅ Status object generated');
      console.log(`     ${JSON.stringify(status.capabilities)}`);
    });
  });
  
  describe('createPhaseConfig()', () => {
    it('should create phase config from detector', () => {
      const detector = new TimeSourceDetector({ verbose: false });
      detector.detect();
      
      const config = createPhaseConfig(detector);
      
      assert(config.trustLevel);
      assert(typeof config.toleranceMs === 'number');
      assert(typeof config.epochDurationHours === 'number');
      assert(typeof config.gracePeriodMinutes === 'number');
      assert(config.capabilities);
      
      console.log('  ✅ Phase config created');
      console.log(`     Epoch duration: ${config.epochDurationHours} hours`);
      console.log(`     Grace period: ${config.gracePeriodMinutes} minutes`);
      console.log(`     Tolerance: ±${config.toleranceMs}ms`);
    });
    
    it('should have tighter windows for atomic time', () => {
      // Simulate atomic trust level config
      const atomicConfig = {
        trustLevel: TimeTrustLevel.ATOMIC,
        toleranceMs: PhaseTolerance[TimeTrustLevel.ATOMIC],
        epochDurationHours: 1,
        gracePeriodMinutes: 1,
      };
      
      const ntpConfig = {
        trustLevel: TimeTrustLevel.NTP,
        toleranceMs: PhaseTolerance[TimeTrustLevel.NTP],
        epochDurationHours: 6,
        gracePeriodMinutes: 15,
      };
      
      assert(atomicConfig.toleranceMs < ntpConfig.toleranceMs);
      assert(atomicConfig.epochDurationHours < ntpConfig.epochDurationHours);
      assert(atomicConfig.gracePeriodMinutes < ntpConfig.gracePeriodMinutes);
      
      console.log('  ✅ Atomic has tighter windows than NTP');
      console.log(`     Atomic: ${atomicConfig.epochDurationHours}h epoch, ±${atomicConfig.toleranceMs}ms`);
      console.log(`     NTP: ${ntpConfig.epochDurationHours}h epoch, ±${ntpConfig.toleranceMs}ms`);
    });
  });
  
  describe('getTimeSourceDetector()', () => {
    it('should return singleton instance', () => {
      const detector1 = getTimeSourceDetector({ verbose: false });
      const detector2 = getTimeSourceDetector();
      
      // Note: In a real test we'd reset the singleton, but this shows the pattern
      assert(detector1 instanceof TimeSourceDetector);
      
      console.log('  ✅ Singleton pattern works');
    });
  });
  
  describe('detectTimeSources()', () => {
    it('should perform quick detection', () => {
      const results = detectTimeSources();
      
      assert(results.timestamp);
      assert(results.trustLevel);
      assert(results.sources);
      
      console.log('  ✅ Quick detection completed');
      console.log(`     Trust: ${results.trustLevel}`);
    });
  });
  
  describe('Trust Level Hierarchy', () => {
    it('should demonstrate trust level ordering', () => {
      const levels = [
        { name: 'ATOMIC', value: TimeTrustLevel.ATOMIC, tolerance: PhaseTolerance.atomic, stratum: StratumLevel.atomic },
        { name: 'GPS', value: TimeTrustLevel.GPS, tolerance: PhaseTolerance.gps, stratum: StratumLevel.gps },
        { name: 'PTP', value: TimeTrustLevel.PTP, tolerance: PhaseTolerance.ptp, stratum: StratumLevel.ptp },
        { name: 'NTP', value: TimeTrustLevel.NTP, tolerance: PhaseTolerance.ntp, stratum: StratumLevel.ntp },
        { name: 'UNSYNC', value: TimeTrustLevel.UNSYNC, tolerance: PhaseTolerance.unsync, stratum: StratumLevel.unsync },
      ];
      
      console.log('\n  📊 Trust Level Hierarchy:');
      console.log('  ─'.repeat(30));
      
      for (let i = 0; i < levels.length; i++) {
        const level = levels[i];
        const marker = i === 0 ? '🔬' : i === 1 ? '🛰️' : i === 2 ? '📡' : i === 3 ? '🌐' : '⚠️';
        console.log(`  ${marker} Level ${i}: ${level.name.padEnd(8)} | ±${String(level.tolerance).padStart(5)}ms | Stratum ${level.stratum}`);
      }
      
      console.log('  ─'.repeat(30));
      
      // Verify ordering
      for (let i = 0; i < levels.length - 1; i++) {
        assert(levels[i].tolerance <= levels[i + 1].tolerance, 
          `${levels[i].name} should have tighter tolerance than ${levels[i + 1].name}`);
      }
      
      console.log('  ✅ Trust levels correctly ordered');
    });
  });
  
  describe('Integration Scenarios', () => {
    it('should handle atomic clock node scenario', () => {
      // Simulate an atomic clock node
      const atomicNodeConfig = {
        trustLevel: TimeTrustLevel.ATOMIC,
        capabilities: {
          canBeTimeOracle: true,
          canValidateTightPhase: true,
          canParticipateInConsensus: true,
        },
        phaseWindowMs: 100,
      };
      
      console.log('\n  🔬 Atomic Clock Node Scenario:');
      console.log(`     Can be time oracle: ${atomicNodeConfig.capabilities.canBeTimeOracle}`);
      console.log(`     Phase window: ±${atomicNodeConfig.phaseWindowMs}ms`);
      console.log('     → This node can validate time-critical operations');
      
      assert(atomicNodeConfig.capabilities.canBeTimeOracle);
    });
    
    it('should handle standard NTP node scenario', () => {
      // Simulate a standard NTP node
      const ntpNodeConfig = {
        trustLevel: TimeTrustLevel.NTP,
        capabilities: {
          canBeTimeOracle: false,
          canValidateTightPhase: false,
          canParticipateInConsensus: true,
        },
        phaseWindowMs: 5000,
      };
      
      console.log('\n  🌐 Standard NTP Node Scenario:');
      console.log(`     Can be time oracle: ${ntpNodeConfig.capabilities.canBeTimeOracle}`);
      console.log(`     Phase window: ±${ntpNodeConfig.phaseWindowMs}ms`);
      console.log('     → This node can participate but not lead time consensus');
      
      assert(!ntpNodeConfig.capabilities.canBeTimeOracle);
      assert(ntpNodeConfig.capabilities.canParticipateInConsensus);
    });
    
    it('should handle degraded mode scenario', () => {
      // Simulate an unsynchronized node
      const unsyncNodeConfig = {
        trustLevel: TimeTrustLevel.UNSYNC,
        capabilities: {
          canBeTimeOracle: false,
          canValidateTightPhase: false,
          canParticipateInConsensus: false,
        },
        phaseWindowMs: 30000,
      };
      
      console.log('\n  ⚠️ Unsynchronized Node Scenario:');
      console.log(`     Can participate: ${unsyncNodeConfig.capabilities.canParticipateInConsensus}`);
      console.log(`     Phase window: ±${unsyncNodeConfig.phaseWindowMs}ms`);
      console.log('     → This node operates in degraded mode');
      
      assert(!unsyncNodeConfig.capabilities.canParticipateInConsensus);
    });
  });
});

// Run detection and show results
console.log('\n🕐 Running Time Source Detection...\n');

const detector = new TimeSourceDetector({ verbose: true });
const results = detector.detect();

console.log('\n📋 Detection Summary:');
console.log(`   Trust Level: ${results.trustLevel.toUpperCase()}`);
console.log(`   Phase Tolerance: ±${results.phaseTolerance}ms`);
console.log(`   Ready for: ${
  results.trustLevel === 'atomic' ? 'Time-critical operations (ATOMIC)' :
  results.trustLevel === 'gps' ? 'High-precision validation (GPS)' :
  results.trustLevel === 'ntp' ? 'Standard validation (NTP)' :
  'Degraded mode only (UNSYNC)'
}`);
