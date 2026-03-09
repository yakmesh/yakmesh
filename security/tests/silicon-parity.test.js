/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Silicon Parity Tests
 * 
 * Tests for the "one silicon = one vote" anti-farming system
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  SiliconIdentity,
  SiliconParityManager,
  ParityWeightCalculator,
  collectTimingHistogram,
  createFingerprint,
  detectTopology,
  analyzeJitter,
  SILICON_CONFIG,
  SILICON_PARITY_MESSAGES,
} from '../silicon-parity.js';

describe('Silicon Parity', () => {
  
  describe('SiliconIdentity', () => {
    
    it('should create identity with all required fields', () => {
      const identity = new SiliconIdentity({
        id: 'test-id-123',
        platformUUID: 'uuid-123',
        aesFingerprint: 'abc123def456',
        timingHistogram: [0.1, 0.2, 0.3],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 8,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      expect(identity.id).toBe('test-id-123');
      expect(identity.platformUUID).toBe('uuid-123');
      expect(identity.coreCount).toBe(8);
      expect(identity.isRealSilicon).toBe(true);
    });
    
    it('should calculate weight division correctly', () => {
      const identity = new SiliconIdentity({
        id: 'test',
        platformUUID: 'uuid',
        aesFingerprint: 'fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 4,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // tierMax 1.0 / 4 cores = 0.25 per core
      expect(identity.calculateWeight(1.0)).toBe(0.25);
      
      // tierMax 2.0 / 4 cores = 0.5 per core
      expect(identity.calculateWeight(2.0)).toBe(0.5);
    });
    
    it('should handle single core (full weight)', () => {
      const identity = new SiliconIdentity({
        id: 'test',
        platformUUID: 'uuid',
        aesFingerprint: 'fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 1,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // tierMax 1.0 / 1 core = 1.0 (full weight)
      expect(identity.calculateWeight(1.0)).toBe(1.0);
    });
    
    it('should prevent zero division with 0 cores', () => {
      const identity = new SiliconIdentity({
        id: 'test',
        platformUUID: 'uuid',
        aesFingerprint: 'fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 0, // Edge case
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // Should use max(1, 0) = 1
      expect(identity.calculateWeight(1.0)).toBe(1.0);
    });
    
    it('should demonstrate ASIC-farm futility', () => {
      // 100-core farm rig
      const farmRig = new SiliconIdentity({
        id: 'farm-rig',
        platformUUID: 'uuid',
        aesFingerprint: 'fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 4,
        coreCount: 100,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // Single honest node
      const honestNode = new SiliconIdentity({
        id: 'honest',
        platformUUID: 'uuid2',
        aesFingerprint: 'fp2',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 1,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // Both get same total weight for PARTICIPANT tier (1.0)!
      const farmWeight = farmRig.calculateWeight(1.0) * 100; // 0.01 * 100 = 1.0
      const honestWeight = honestNode.calculateWeight(1.0) * 1; // 1.0 * 1 = 1.0
      
      expect(farmWeight).toBe(1.0);
      expect(honestWeight).toBe(1.0);
      
      // Farm spent $50k for same weight as $500 consumer PC
    });
    
    it('should serialize and deserialize correctly', () => {
      const original = new SiliconIdentity({
        id: 'test-id',
        platformUUID: 'uuid-abc',
        aesFingerprint: 'fingerprint-xyz',
        timingHistogram: [0.1, 0.2, 0.3, 0.4],
        jitterRatio: 0.08,
        socketCount: 2,
        coreCount: 16,
        isRealSilicon: true,
        createdAt: 1705123456789,
        lastVerified: 1705123456999,
        verificationCount: 5,
      });
      
      const json = original.toJSON();
      const restored = SiliconIdentity.fromJSON(json);
      
      expect(restored.id).toBe(original.id);
      expect(restored.platformUUID).toBe(original.platformUUID);
      expect(restored.coreCount).toBe(original.coreCount);
      expect(restored.verificationCount).toBe(original.verificationCount);
    });
    
    it('should calculate weight multiplier', () => {
      const identity = new SiliconIdentity({
        id: 'test',
        platformUUID: 'uuid',
        aesFingerprint: 'fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 8,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      expect(identity.weightMultiplier).toBe(0.125); // 1/8
    });
  });
  
  describe('collectTimingHistogram', () => {
    
    it('should collect timing data', async () => {
      const result = await collectTimingHistogram({ ops: 100 });
      
      expect(result.timings).toHaveLength(100);
      expect(result.histogram).toHaveLength(32);
      expect(result.mean).toBeGreaterThan(0);
      expect(result.stddev).toBeGreaterThan(0);
      expect(result.jitterRatio).toBeGreaterThanOrEqual(0);
    });
    
    it('should produce normalized histogram', async () => {
      const result = await collectTimingHistogram({ ops: 100 });
      
      // Sum of normalized histogram should be close to 1
      const sum = result.histogram.reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 1);
    });
    
    it('should be deterministic-ish for same hardware', async () => {
      // Run twice on same machine
      const result1 = await collectTimingHistogram({ ops: 500 });
      const result2 = await collectTimingHistogram({ ops: 500 });
      
      // Means should be in same ballpark (within 3x due to system load variance)
      const ratio = result1.mean / result2.mean;
      expect(ratio).toBeGreaterThan(0.33);
      expect(ratio).toBeLessThan(3.0);
    });
  });
  
  describe('createFingerprint', () => {
    
    it('should create 64-char hex fingerprint', () => {
      const histogram = [0.1, 0.2, 0.3, 0.4];
      const fingerprint = createFingerprint(histogram);
      
      expect(fingerprint).toHaveLength(64);
      expect(fingerprint).toMatch(/^[0-9a-f]+$/);
    });
    
    it('should be deterministic', () => {
      const histogram = [0.1, 0.2, 0.3, 0.4];
      
      const fp1 = createFingerprint(histogram);
      const fp2 = createFingerprint(histogram);
      
      expect(fp1).toBe(fp2);
    });
    
    it('should be different for different histograms', () => {
      const fp1 = createFingerprint([0.1, 0.2, 0.3, 0.4]);
      const fp2 = createFingerprint([0.4, 0.3, 0.2, 0.1]);
      
      expect(fp1).not.toBe(fp2);
    });
  });
  
  describe('detectTopology', () => {
    
    it('should detect core count', () => {
      const topology = detectTopology();
      
      expect(topology.coreCount).toBeGreaterThan(0);
      expect(topology.socketCount).toBeGreaterThanOrEqual(1);
      expect(typeof topology.model).toBe('string');
    });
    
    it('should have isMultiSocket flag', () => {
      const topology = detectTopology();
      
      expect(typeof topology.isMultiSocket).toBe('boolean');
      expect(topology.isMultiSocket).toBe(topology.socketCount > 1);
    });
  });
  
  describe('analyzeJitter', () => {
    
    it('should analyze consistent timings as real silicon', () => {
      // Simulate consistent AES-NI timing (low variance)
      const mean = 50000; // 50μs
      const timings = Array(100).fill(0).map(() => 
        mean + (Math.random() - 0.5) * mean * 0.05 // ±2.5% variance
      );
      
      const result = analyzeJitter(timings);
      
      expect(result.jitterRatio).toBeLessThan(0.1);
      expect(result.isRealSilicon).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
    });
    
    it('should analyze high-jitter timings as VM', () => {
      // Simulate VM timing (high variance with spikes)
      const mean = 100000; // 100μs
      const timings = Array(100).fill(0).map((_, i) => {
        if (i % 10 === 0) {
          return mean * 3; // Spike every 10th
        }
        return mean + (Math.random() - 0.5) * mean * 0.4; // ±20% variance
      });
      
      const result = analyzeJitter(timings);
      
      expect(result.jitterRatio).toBeGreaterThan(0.15);
      expect(result.isRealSilicon).toBe(false);
    });
    
    it('should calculate percentiles correctly', () => {
      const timings = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const result = analyzeJitter(timings);
      
      // With 10 elements:
      // p1 = index 0 = 1
      // p50 = index 5 = 6 (after sort)
      // p99 = index 9 = 10
      expect(result.p1).toBe(1);
      expect(result.p50).toBe(6); // Floor(10 * 0.5) = 5, sorted[5] = 6
      expect(result.p99).toBe(10);
    });
  });
  
  describe('SiliconParityManager', () => {
    let manager;
    
    beforeEach(() => {
      manager = new SiliconParityManager();
    });
    
    it('should collect identity for a node', async () => {
      const identity = await manager.collectIdentity('doko:test123');
      
      expect(identity).toBeInstanceOf(SiliconIdentity);
      expect(identity.id).toBeTruthy();
      expect(identity.aesFingerprint).toHaveLength(64);
      expect(identity.coreCount).toBeGreaterThan(0);
    });
    
    it('should store and retrieve identity', async () => {
      await manager.collectIdentity('doko:node1');
      
      const retrieved = manager.getIdentity('doko:node1');
      expect(retrieved).toBeDefined();
      expect(retrieved.id).toBeTruthy();
    });
    
    it('should index fingerprints', async () => {
      const identity = await manager.collectIdentity('doko:node1');
      
      expect(manager.fingerprintIndex.has(identity.aesFingerprint)).toBe(true);
      expect(manager.fingerprintIndex.get(identity.aesFingerprint).has('doko:node1')).toBe(true);
    });
    
    it('should detect duplicate fingerprints', async () => {
      const onDuplicate = vi.fn();
      manager = new SiliconParityManager({ onDuplicateFingerprint: onDuplicate });
      
      // Collect first identity
      const identity1 = await manager.collectIdentity('doko:node1');
      
      // Manually add same fingerprint for different node (simulating clone)
      manager.fingerprintIndex.get(identity1.aesFingerprint).add('doko:clone');
      
      // Check duplicate detection
      expect(manager.isDuplicateFingerprint(identity1.aesFingerprint, 'doko:node1')).toBe(true);
    });
    
    it('should calculate weight with parity division', async () => {
      await manager.collectIdentity('doko:node1');
      
      const weight = manager.calculateWeight('doko:node1', 1.0);
      
      // Weight should be tierMax / coreCount
      const identity = manager.getIdentity('doko:node1');
      expect(weight).toBe(1.0 / identity.coreCount);
    });
    
    it('should return reduced weight for unknown nodes', () => {
      const weight = manager.calculateWeight('doko:unknown', 1.0);
      
      expect(weight).toBe(0.1); // 10% of tier max
    });
    
    it('should calculate Hamming distance correctly', () => {
      expect(manager.hammingDistance('abc', 'abc')).toBe(0);
      expect(manager.hammingDistance('abc', 'abd')).toBe(1);
      expect(manager.hammingDistance('abc', 'xyz')).toBe(3);
      expect(manager.hammingDistance('ab', 'abcd')).toBe(2);
    });
    
    it('should calculate histogram drift', () => {
      const hist1 = [0.25, 0.25, 0.25, 0.25];
      const hist2 = [0.25, 0.25, 0.25, 0.25];
      
      expect(manager.calculateFingerprintDrift(hist1, hist2)).toBe(0);
      
      const hist3 = [0.5, 0.5, 0.0, 0.0];
      // Total diff = 0.25 + 0.25 + 0.25 + 0.25 = 1.0, normalized = 0.5
      expect(manager.calculateFingerprintDrift(hist1, hist3)).toBeCloseTo(0.5, 1);
    });
    
    it('should get statistics', async () => {
      await manager.collectIdentity('doko:node1');
      await manager.collectIdentity('doko:node2');
      
      const stats = manager.getStats();
      
      expect(stats.totalIdentities).toBe(2);
      expect(stats.totalCores).toBeGreaterThan(0);
      expect(stats.uniqueFingerprints).toBeGreaterThanOrEqual(1);
    });
    
    it('should perform bitslice verification', async () => {
      await manager.collectIdentity('doko:node1');
      
      const result = await manager.bitsliceVerify('doko:node1');
      
      expect(result).toHaveProperty('match');
      expect(result).toHaveProperty('distance');
      expect(result).toHaveProperty('threshold');
      expect(result.threshold).toBe(SILICON_CONFIG.SAMPLE_MAX_DRIFT);
    });
    
    it('should perform full verification', async () => {
      await manager.collectIdentity('doko:node1');
      
      const result = await manager.fullVerify('doko:node1');
      
      expect(result).toHaveProperty('match');
      expect(result).toHaveProperty('drift');
      expect(result).toHaveProperty('threshold');
      expect(result).toHaveProperty('jitterAnalysis');
    });
    
    it('should call epochVerify with appropriate method', async () => {
      await manager.collectIdentity('doko:node1');
      
      // First 7 epochs should be bitslice
      for (let i = 0; i < 7; i++) {
        await manager.epochVerify('doko:node1');
      }
      expect(manager.epochCount).toBe(7);
      
      // 8th epoch should be full verify
      const result = await manager.epochVerify('doko:node1');
      expect(manager.epochCount).toBe(8);
    });
  });
  
  describe('ParityWeightCalculator', () => {
    
    it('should combine trust tier with silicon parity', async () => {
      const siliconManager = new SiliconParityManager();
      
      // Mock trust registry
      const mockTrustRegistry = {
        getWeight: vi.fn().mockResolvedValue(1.5), // ANCHOR tier
      };
      
      const calculator = new ParityWeightCalculator(siliconManager, mockTrustRegistry);
      
      // Collect identity
      await siliconManager.collectIdentity('doko:node1');
      const identity = siliconManager.getIdentity('doko:node1');
      
      const weight = await calculator.calculateWeight('doko:node1');
      
      // Should be tierWeight / coreCount
      expect(weight).toBe(1.5 / identity.coreCount);
    });
    
    it('should calculate weighted count for attestations', async () => {
      const siliconManager = new SiliconParityManager();
      const mockTrustRegistry = {
        getWeight: vi.fn().mockResolvedValue(1.0),
      };
      
      const calculator = new ParityWeightCalculator(siliconManager, mockTrustRegistry);
      
      // Collect identities
      await siliconManager.collectIdentity('doko:node1');
      await siliconManager.collectIdentity('doko:node2');
      
      const attestations = [
        { attestorId: 'doko:node1' },
        { attestorId: 'doko:node2' },
      ];
      
      const total = await calculator.calculateWeightedCount(attestations);
      
      // Each should contribute 1.0 / coreCount
      expect(total).toBeGreaterThan(0);
    });
  });
  
  describe('SILICON_CONFIG', () => {
    
    it('should have all required configuration', () => {
      expect(SILICON_CONFIG.FINGERPRINT_OPS).toBe(1000);
      expect(SILICON_CONFIG.SAMPLE_OPS).toBe(125);
      expect(SILICON_CONFIG.FULL_VERIFY_INTERVAL).toBe(8);
      expect(SILICON_CONFIG.VM_JITTER_THRESHOLD).toBe(0.15);
      expect(SILICON_CONFIG.DRIFT_TOLERANCE).toBe(0.05);
    });
  });
  
  describe('SILICON_PARITY_MESSAGES', () => {
    
    it('should export all protocol messages', () => {
      expect(SILICON_PARITY_MESSAGES.IDENTITY_REQUEST).toBe('silicon:identity:request');
      expect(SILICON_PARITY_MESSAGES.IDENTITY_RESPONSE).toBe('silicon:identity:response');
      expect(SILICON_PARITY_MESSAGES.VERIFY_CHALLENGE).toBe('silicon:verify:challenge');
      expect(SILICON_PARITY_MESSAGES.VERIFY_RESPONSE).toBe('silicon:verify:response');
      expect(SILICON_PARITY_MESSAGES.DUPLICATE_ALERT).toBe('silicon:duplicate:alert');
      expect(SILICON_PARITY_MESSAGES.VM_DETECTED).toBe('silicon:vm:detected');
    });
  });
  
  describe('Attack Economics Validation', () => {
    
    it('should make 100-core farm equivalent to 1-core honest node', () => {
      // Farm with 100 cores
      const farm = new SiliconIdentity({
        id: 'farm',
        platformUUID: 'farm-uuid',
        aesFingerprint: 'farm-fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 4,
        coreCount: 100,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // Honest node with 1 core
      const honest = new SiliconIdentity({
        id: 'honest',
        platformUUID: 'honest-uuid',
        aesFingerprint: 'honest-fp',
        timingHistogram: [],
        jitterRatio: 0.05,
        socketCount: 1,
        coreCount: 1,
        isRealSilicon: true,
        createdAt: Date.now(),
        lastVerified: Date.now(),
      });
      
      // For PARTICIPANT tier (1.0x max):
      const farmTotalWeight = farm.calculateWeight(1.0) * 100;
      const honestTotalWeight = honest.calculateWeight(1.0) * 1;
      
      expect(farmTotalWeight).toBe(honestTotalWeight);
      expect(farmTotalWeight).toBe(1.0);
    });
    
    it('should scale weight division linearly', () => {
      const tierMax = 2.0; // ORACLE tier
      
      const testCases = [
        { cores: 1, expectedPerCore: 2.0, expectedTotal: 2.0 },
        { cores: 2, expectedPerCore: 1.0, expectedTotal: 2.0 },
        { cores: 4, expectedPerCore: 0.5, expectedTotal: 2.0 },
        { cores: 10, expectedPerCore: 0.2, expectedTotal: 2.0 },
        { cores: 100, expectedPerCore: 0.02, expectedTotal: 2.0 },
        { cores: 1000, expectedPerCore: 0.002, expectedTotal: 2.0 },
      ];
      
      for (const tc of testCases) {
        const identity = new SiliconIdentity({
          id: 'test',
          platformUUID: 'uuid',
          aesFingerprint: 'fp',
          timingHistogram: [],
          jitterRatio: 0.05,
          socketCount: 1,
          coreCount: tc.cores,
          isRealSilicon: true,
          createdAt: Date.now(),
          lastVerified: Date.now(),
        });
        
        const perCoreWeight = identity.calculateWeight(tierMax);
        const totalWeight = perCoreWeight * tc.cores;
        
        expect(perCoreWeight).toBeCloseTo(tc.expectedPerCore, 6);
        expect(totalWeight).toBeCloseTo(tc.expectedTotal, 6);
      }
    });
  });
});
