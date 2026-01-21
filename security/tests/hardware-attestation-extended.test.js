/**
 * Hardware Attestation Extended Tests
 * 
 * Tests for VAES, GFNI, and crypto tier detection
 * Added in v2.4.1
 */

import { describe, it, expect, vi } from 'vitest';
import {
  detectCPUFeatures,
  measureAESPerformance,
  measureAESPerformanceExtended,
  validateAESTiming,
  determineCryptoTier,
  getCryptoCapabilitySummary,
  HardwareAttestation,
  HARDWARE_THRESHOLDS,
  CPU_FEATURES,
  CRYPTO_ACCELERATION_TIER,
  TIER_NAMES,
} from '../hardware-attestation.js';

describe('Hardware Attestation Extended (v2.4.1)', () => {

  describe('CPU_FEATURES', () => {
    it('should define all feature flags', () => {
      expect(CPU_FEATURES.AES_NI).toBe('aes');
      expect(CPU_FEATURES.VAES).toBe('vaes');
      expect(CPU_FEATURES.AVX512).toBe('avx512');
      expect(CPU_FEATURES.GFNI).toBe('gfni');
      expect(CPU_FEATURES.NTT_ACCEL).toBe('ntt');
      expect(CPU_FEATURES.SHA3_NI).toBe('sha3ni');
    });
  });

  describe('CRYPTO_ACCELERATION_TIER', () => {
    it('should define all acceleration tiers', () => {
      expect(CRYPTO_ACCELERATION_TIER.NONE).toBe(0);
      expect(CRYPTO_ACCELERATION_TIER.AES_NI).toBe(1);
      expect(CRYPTO_ACCELERATION_TIER.VAES_256).toBe(2);
      expect(CRYPTO_ACCELERATION_TIER.VAES_512).toBe(3);
      expect(CRYPTO_ACCELERATION_TIER.GFNI).toBe(4);
      expect(CRYPTO_ACCELERATION_TIER.PQC_READY).toBe(5);
    });

    it('should have tier names', () => {
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.NONE]).toBe('Software');
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.AES_NI]).toBe('AES-NI');
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.VAES_256]).toBe('VAES-256');
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.VAES_512]).toBe('VAES-512');
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.GFNI]).toBe('GFNI');
      expect(TIER_NAMES[CRYPTO_ACCELERATION_TIER.PQC_READY]).toBe('PQC-Ready');
    });
  });

  describe('detectCPUFeatures', () => {
    it('should detect CPU vendor', () => {
      const features = detectCPUFeatures();
      expect(features.vendor).toBeTruthy();
      expect(['GenuineIntel', 'AuthenticAMD', 'Apple', 'ARM', 'Unknown']).toContain(features.vendor);
    });

    it('should detect core count', () => {
      const features = detectCPUFeatures();
      expect(features.cores).toBeGreaterThan(0);
    });

    it('should have extended feature flags', () => {
      const features = detectCPUFeatures();
      expect(typeof features.hasVAES).toBe('boolean');
      expect(typeof features.hasAVX).toBe('boolean');
      expect(typeof features.hasAVX2).toBe('boolean');
      expect(typeof features.hasAVX512).toBe('boolean');
      expect(typeof features.hasGFNI).toBe('boolean');
      expect(typeof features.hasNTTAccel).toBe('boolean');
      expect(typeof features.hasSHA3NI).toBe('boolean');
    });

    it('should have crypto tier fields', () => {
      const features = detectCPUFeatures();
      expect(typeof features.cryptoTier).toBe('number');
      expect(typeof features.cryptoTierName).toBe('string');
    });
  });

  describe('measureAESPerformanceExtended', () => {
    it('should measure standard and large data sizes', async () => {
      const results = await measureAESPerformanceExtended({ iterations: 5 });
      
      expect(results.standard).toBeDefined();
      expect(results.large).toBeDefined();
      expect(results.standard.dataSize).toBe(1024 * 1024); // 1MB
      expect(results.large.dataSize).toBe(4 * 1024 * 1024); // 4MB
    });

    it('should calculate VAES indicators', async () => {
      const results = await measureAESPerformanceExtended({ iterations: 5 });
      
      expect(results.vaesIndicators).toBeDefined();
      expect(typeof results.vaesIndicators.highThroughput).toBe('boolean');
      expect(typeof results.vaesIndicators.veryHighThroughput).toBe('boolean');
      expect(typeof results.vaesIndicators.maintainsThroughput).toBe('boolean');
      expect(typeof results.vaesIndicators.throughputRatio).toBe('number');
    });

    it('should have likelyVAES flags', async () => {
      const results = await measureAESPerformanceExtended({ iterations: 5 });
      
      expect(typeof results.likelyVAES).toBe('boolean');
      expect(typeof results.likelyVAES512).toBe('boolean');
    });
  });

  describe('determineCryptoTier', () => {
    it('should return NONE for slow timing', () => {
      const features = { hasVAES: false, hasGFNI: false, hasAVX512: false };
      const timing = { meanMs: 100, varianceRatio: 0.5, throughputMBps: 50 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.NONE);
      expect(result.tierName).toBe('Software');
    });

    it('should return AES_NI for fast timing', () => {
      const features = { hasVAES: false, hasGFNI: false, hasAVX512: false };
      const timing = { meanMs: 5, varianceRatio: 0.05, throughputMBps: 1500 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.AES_NI);
      expect(result.tierName).toBe('AES-NI');
    });

    it('should return VAES_256 for VAES features', () => {
      const features = { hasVAES: true, hasGFNI: false, hasAVX512: false };
      const timing = { meanMs: 3, varianceRatio: 0.03, throughputMBps: 2500 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.VAES_256);
    });

    it('should return VAES_512 for VAES + AVX512', () => {
      const features = { hasVAES: true, hasGFNI: false, hasAVX512: true };
      const timing = { meanMs: 2, varianceRatio: 0.02, throughputMBps: 5000 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.VAES_512);
    });

    it('should return GFNI for GFNI feature', () => {
      const features = { hasVAES: true, hasGFNI: true, hasAVX512: true };
      const timing = { meanMs: 2, varianceRatio: 0.02, throughputMBps: 5000 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.GFNI);
    });

    it('should return PQC_READY for NTT + SHA3', () => {
      const features = { 
        hasVAES: true, 
        hasGFNI: true, 
        hasAVX512: true, 
        hasNTTAccel: true, 
        hasSHA3NI: true 
      };
      const timing = { meanMs: 1, varianceRatio: 0.01, throughputMBps: 8000 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.tier).toBe(CRYPTO_ACCELERATION_TIER.PQC_READY);
    });

    it('should include description', () => {
      const features = { hasVAES: false, hasGFNI: false, hasAVX512: false };
      const timing = { meanMs: 5, varianceRatio: 0.05, throughputMBps: 1500 };
      
      const result = determineCryptoTier(features, timing);
      expect(result.description).toContain('AES-NI');
    });
  });

  describe('HardwareAttestation.createLocal', () => {
    it('should return v2.4.1 attestation format', async () => {
      const attestation = await HardwareAttestation.createLocal();
      
      expect(attestation.version).toBe('2.4.1');
      expect(attestation.cryptoAcceleration).toBeDefined();
      expect(typeof attestation.cryptoAcceleration.tier).toBe('number');
      expect(typeof attestation.cryptoAcceleration.tierName).toBe('string');
    });

    it('should include extended fields', async () => {
      const attestation = await HardwareAttestation.createLocal();
      
      expect(typeof attestation.cryptoAcceleration.hasVAES).toBe('boolean');
      expect(typeof attestation.cryptoAcceleration.hasGFNI).toBe('boolean');
      expect(typeof attestation.cryptoAcceleration.hasAVX512).toBe('boolean');
      expect(typeof attestation.cryptoAcceleration.pqcReady).toBe('boolean');
    });

    it('should include extended timing when not quick mode', async () => {
      const attestation = await HardwareAttestation.createLocal({ extended: true });
      
      expect(attestation.extendedTiming).toBeDefined();
      expect(typeof attestation.extendedTiming.standardThroughputMBps).toBe('number');
      expect(typeof attestation.extendedTiming.likelyVAES).toBe('boolean');
    });
  });

  describe('HardwareAttestation.createLocalQuick', () => {
    it('should skip extended timing', async () => {
      const attestation = await HardwareAttestation.createLocalQuick();
      
      expect(attestation.version).toBe('2.4.1');
      expect(attestation.extendedTiming).toBeNull();
    });

    it('should still have crypto tier', async () => {
      const attestation = await HardwareAttestation.createLocalQuick();
      
      expect(attestation.cryptoAcceleration).toBeDefined();
      expect(typeof attestation.cryptoAcceleration.tier).toBe('number');
    });
  });

  describe('getCryptoCapabilitySummary', () => {
    it('should return complete summary', async () => {
      const summary = await getCryptoCapabilitySummary();
      
      expect(summary.cpu).toBeDefined();
      expect(summary.capabilities).toBeDefined();
      expect(summary.performance).toBeDefined();
      expect(summary.tier).toBeDefined();
      expect(summary.recommendation).toBeDefined();
    });

    it('should have CPU info', async () => {
      const summary = await getCryptoCapabilitySummary();
      
      expect(summary.cpu.vendor).toBeTruthy();
      expect(summary.cpu.cores).toBeGreaterThan(0);
    });

    it('should have all capability flags', async () => {
      const summary = await getCryptoCapabilitySummary();
      
      expect(typeof summary.capabilities.aesNI).toBe('boolean');
      expect(typeof summary.capabilities.vaes).toBe('boolean');
      expect(typeof summary.capabilities.avx512).toBe('boolean');
      expect(typeof summary.capabilities.gfni).toBe('boolean');
      expect(typeof summary.capabilities.pqcReady).toBe('boolean');
    });

    it('should have performance metrics', async () => {
      const summary = await getCryptoCapabilitySummary();
      
      expect(typeof summary.performance.throughputMBps).toBe('number');
      expect(summary.performance.meanMs).toBeTruthy();
      expect(summary.performance.varianceRatio).toBeTruthy();
    });

    it('should have recommendation string', async () => {
      const summary = await getCryptoCapabilitySummary();
      
      expect(typeof summary.recommendation).toBe('string');
      expect(summary.recommendation.length).toBeGreaterThan(10);
    });
  });

  describe('Backward Compatibility', () => {
    it('should still work with existing timing validation', async () => {
      const timing = await measureAESPerformance({ iterations: 10 });
      const validation = validateAESTiming(timing);
      
      expect(typeof validation.valid).toBe('boolean');
      expect(typeof validation.hasAESNI).toBe('boolean');
      expect(Array.isArray(validation.issues)).toBe(true);
    });

    it('should maintain HARDWARE_THRESHOLDS', () => {
      expect(HARDWARE_THRESHOLDS.AES_1MB_MAX_MEAN_MS).toBe(20);
      expect(HARDWARE_THRESHOLDS.AES_1MB_MIN_THROUGHPUT_MBPS).toBe(500);
    });
  });

});
