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
 * Geographic Proof Tests
 * 
 * Tests for speed-of-light based geographic exclusion zones.
 * 
 * @module security/tests/geo-proof.test
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  LIGHT_SPEED,
  GEO_PROOF_CONFIG,
  DISTANCE_PRECISION,
  LandmarkRegistry,
  RTTMeasurement,
  calculateMinDistance,
  getDistancePrecision,
  haversineDistance,
  ExclusionZone,
  GeographicProof,
  GeoProofService,
} from '../geo-proof.js';
import { TimeTrustLevel } from '../../oracle/time-source.js';

// ============================================================
// PHYSICAL CONSTANTS TESTS
// ============================================================

describe('Physical Constants', () => {
  it('should have correct speed of light in vacuum', () => {
    expect(LIGHT_SPEED.VACUUM).toBeCloseTo(299792.458, 2);
  });

  it('should have correct speed of light in fiber (~0.67c)', () => {
    const ratio = LIGHT_SPEED.FIBER / LIGHT_SPEED.VACUUM;
    expect(ratio).toBeCloseTo(0.67, 1);
  });

  it('should have fiber speed around 200,000 km/s', () => {
    expect(LIGHT_SPEED.FIBER).toBeGreaterThan(190000);
    expect(LIGHT_SPEED.FIBER).toBeLessThan(210000);
  });
});

// ============================================================
// DISTANCE CALCULATION TESTS
// ============================================================

describe('Distance Calculation', () => {
  describe('calculateMinDistance', () => {
    it('should calculate correct distance for known RTT', () => {
      // 1ms RTT in fiber
      // One-way = 0.5ms = 0.0005s
      // Distance = 0.0005 * 199861.639 ≈ 99.93 km
      const distance = calculateMinDistance(1, 'FIBER');
      expect(distance).toBeCloseTo(100, 0);
    });

    it('should calculate distance for 40ms RTT (transatlantic)', () => {
      // 40ms RTT → 20ms one-way → ~4000km
      const distance = calculateMinDistance(40, 'FIBER');
      expect(distance).toBeGreaterThan(3900);
      expect(distance).toBeLessThan(4100);
    });

    it('should calculate distance for 100ms RTT (intercontinental)', () => {
      // 100ms RTT → 50ms one-way → ~10000km
      const distance = calculateMinDistance(100, 'FIBER');
      expect(distance).toBeGreaterThan(9900);
      expect(distance).toBeLessThan(10100);
    });

    it('should return 0 for 0ms RTT', () => {
      const distance = calculateMinDistance(0, 'FIBER');
      expect(distance).toBe(0);
    });

    it('should use vacuum speed when specified', () => {
      const fiberDist = calculateMinDistance(10, 'FIBER');
      const vacuumDist = calculateMinDistance(10, 'VACUUM');
      expect(vacuumDist).toBeGreaterThan(fiberDist);
    });

    it('should apply safety margin correctly', () => {
      const baseDist = calculateMinDistance(10, 'FIBER', 1.0);
      const marginDist = calculateMinDistance(10, 'FIBER', 1.1);
      expect(marginDist).toBeCloseTo(baseDist * 1.1, 1);
    });
  });

  describe('getDistancePrecision', () => {
    it('should return correct precision for atomic time source', () => {
      expect(getDistancePrecision(TimeTrustLevel.ATOMIC)).toBe(10);
    });

    it('should return correct precision for GPS time source', () => {
      expect(getDistancePrecision(TimeTrustLevel.GPS)).toBe(100);
    });

    it('should return correct precision for NTP time source', () => {
      expect(getDistancePrecision(TimeTrustLevel.NTP)).toBe(1000);
    });

    it('should return NTP precision for unknown time source', () => {
      expect(getDistancePrecision('unknown')).toBe(1000);
    });
  });
});

// ============================================================
// HAVERSINE DISTANCE TESTS
// ============================================================

describe('Haversine Distance', () => {
  it('should return 0 for same coordinates', () => {
    const distance = haversineDistance(40.7128, -74.0060, 40.7128, -74.0060);
    expect(distance).toBe(0);
  });

  it('should calculate NYC to London correctly (~5500km)', () => {
    const distance = haversineDistance(
      40.7128, -74.0060,  // NYC
      51.5074, -0.1278   // London
    );
    expect(distance).toBeGreaterThan(5500);
    expect(distance).toBeLessThan(5600);
  });

  it('should calculate NYC to Tokyo correctly (~10800km)', () => {
    const distance = haversineDistance(
      40.7128, -74.0060,  // NYC
      35.6762, 139.6503  // Tokyo
    );
    expect(distance).toBeGreaterThan(10800);
    expect(distance).toBeLessThan(10900);
  });

  it('should calculate antipodal points (~20000km)', () => {
    const distance = haversineDistance(0, 0, 0, 180);
    expect(distance).toBeCloseTo(20015, 0);  // Half Earth circumference
  });

  it('should be symmetric', () => {
    const d1 = haversineDistance(40.7128, -74.0060, 51.5074, -0.1278);
    const d2 = haversineDistance(51.5074, -0.1278, 40.7128, -74.0060);
    expect(d1).toBeCloseTo(d2, 5);
  });
});

// ============================================================
// RTT MEASUREMENT TESTS
// ============================================================

describe('RTTMeasurement', () => {
  let measurement;

  beforeEach(() => {
    measurement = new RTTMeasurement({
      landmarkId: 'test-landmark',
      timeSource: TimeTrustLevel.NTP,
    });
  });

  it('should initialize with empty samples', () => {
    expect(measurement.samples).toHaveLength(0);
  });

  it('should add samples correctly', () => {
    measurement.addSample(10);
    measurement.addSample(12);
    measurement.addSample(11);
    expect(measurement.samples).toHaveLength(3);
  });

  describe('getMinRTT', () => {
    it('should return null for empty samples', () => {
      expect(measurement.getMinRTT()).toBeNull();
    });

    it('should return minimum value', () => {
      measurement.addSample(15);
      measurement.addSample(10);
      measurement.addSample(12);
      expect(measurement.getMinRTT()).toBe(10);
    });
  });

  describe('getMedianRTT', () => {
    it('should return null for empty samples', () => {
      expect(measurement.getMedianRTT()).toBeNull();
    });

    it('should return median for odd count', () => {
      measurement.addSample(10);
      measurement.addSample(20);
      measurement.addSample(15);
      expect(measurement.getMedianRTT()).toBe(15);
    });

    it('should return average of middle values for even count', () => {
      measurement.addSample(10);
      measurement.addSample(20);
      measurement.addSample(15);
      measurement.addSample(25);
      expect(measurement.getMedianRTT()).toBe(17.5);
    });
  });

  describe('getStdDev', () => {
    it('should return 0 for single sample', () => {
      measurement.addSample(10);
      expect(measurement.getStdDev()).toBe(0);
    });

    it('should return 0 for identical samples', () => {
      measurement.addSample(10);
      measurement.addSample(10);
      measurement.addSample(10);
      expect(measurement.getStdDev()).toBe(0);
    });

    it('should calculate stddev correctly', () => {
      measurement.addSample(10);
      measurement.addSample(20);
      measurement.addSample(30);
      // Mean = 20, variance = 66.67, stddev ≈ 8.16
      expect(measurement.getStdDev()).toBeCloseTo(8.16, 1);
    });
  });

  describe('isReliable', () => {
    it('should be unreliable with few samples', () => {
      measurement.addSample(10);
      measurement.addSample(12);
      expect(measurement.isReliable()).toBe(false);
    });

    it('should be reliable with consistent samples', () => {
      measurement.addSample(10);
      measurement.addSample(11);
      measurement.addSample(10);
      measurement.addSample(12);
      measurement.addSample(11);
      expect(measurement.isReliable()).toBe(true);
    });

    it('should be unreliable with highly variable samples', () => {
      measurement.addSample(10);
      measurement.addSample(100);
      measurement.addSample(50);
      measurement.addSample(200);
      expect(measurement.isReliable()).toBe(false);
    });
  });
});

// ============================================================
// LANDMARK REGISTRY TESTS
// ============================================================

describe('LandmarkRegistry', () => {
  let registry;

  beforeEach(() => {
    registry = new LandmarkRegistry();
  });

  it('should start empty', () => {
    expect(registry.getAll()).toHaveLength(0);
  });

  it('should register a landmark', () => {
    const id = registry.register({
      nodeId: 'node-1',
      name: 'NYC-ANCHOR-1',
      region: 'NA-EAST',
      endpoint: 'https://nyc.yakmesh.dev/.well-known/yakmesh/beacon',
      coordinates: { lat: 40.7128, lon: -74.0060 },
    });

    expect(id).toBe('node-1');
    expect(registry.getAll()).toHaveLength(1);
  });

  it('should get landmark by ID', () => {
    registry.register({
      nodeId: 'node-1',
      name: 'NYC-ANCHOR-1',
      region: 'NA-EAST',
    });

    const landmark = registry.get('node-1');
    expect(landmark).toBeDefined();
    expect(landmark.name).toBe('NYC-ANCHOR-1');
  });

  it('should filter by region', () => {
    registry.register({ nodeId: 'node-1', name: 'NYC', region: 'NA-EAST' });
    registry.register({ nodeId: 'node-2', name: 'London', region: 'EU-WEST' });
    registry.register({ nodeId: 'node-3', name: 'LA', region: 'NA-WEST' });

    const naEast = registry.getByRegion('NA-EAST');
    expect(naEast).toHaveLength(1);
    expect(naEast[0].name).toBe('NYC');
  });

  it('should prune stale landmarks', () => {
    registry.register({ nodeId: 'node-1', name: 'NYC' });
    const landmark = registry.get('node-1');
    landmark.lastVerified = Date.now() - 7200000;  // 2 hours ago

    const pruned = registry.prune(3600000);  // 1 hour max age
    expect(pruned).toBe(1);
    expect(registry.getAll()).toHaveLength(0);
  });
});

// ============================================================
// EXCLUSION ZONE TESTS
// ============================================================

describe('ExclusionZone', () => {
  let zone;

  beforeEach(() => {
    zone = new ExclusionZone({
      landmarkId: 'nyc-anchor',
      landmarkName: 'NYC-ANCHOR-1',
      landmarkRegion: 'NA-EAST',
      landmarkCoordinates: { lat: 40.7128, lon: -74.0060 },
      minDistanceKm: 5000,  // Node is at least 5000km from NYC
      precisionKm: 100,
      rttMs: 50,
      timeSource: TimeTrustLevel.NTP,
    });
  });

  it('should exclude locations closer than min distance', () => {
    // Node claims to be in NYC, but we proved they're >5000km away
    const excluded = zone.isExcluded({ lat: 40.7128, lon: -74.0060 });
    expect(excluded).toBe(true);
  });

  it('should NOT exclude locations beyond min distance', () => {
    // Tokyo is ~10800km from NYC, which is beyond 5000km minimum
    const excluded = zone.isExcluded({ lat: 35.6762, lon: 139.6503 });
    expect(excluded).toBe(false);
  });

  it('should account for precision margin', () => {
    // London is ~5500km from NYC
    // With minDistance=5000km and precision=100km
    // 5500 > (5000 - 100) = 4900, so NOT excluded
    const excluded = zone.isExcluded({ lat: 51.5074, lon: -0.1278 });
    expect(excluded).toBe(false);
  });

  it('should serialize and deserialize correctly', () => {
    const serialized = zone.serialize();
    const restored = ExclusionZone.deserialize(serialized);

    expect(restored.landmarkId).toBe(zone.landmarkId);
    expect(restored.minDistanceKm).toBe(zone.minDistanceKm);
    expect(restored.rttMs).toBe(zone.rttMs);
  });
});

// ============================================================
// GEOGRAPHIC PROOF TESTS
// ============================================================

describe('GeographicProof', () => {
  let proof;

  beforeEach(() => {
    proof = new GeographicProof({
      nodeId: 'test-node',
      dokoId: 'doko-123',
      timeSource: TimeTrustLevel.NTP,
    });
  });

  it('should start with no exclusion zones', () => {
    expect(proof.exclusionZones).toHaveLength(0);
    expect(proof.confidence).toBe(0);
  });

  it('should add exclusion zones', () => {
    proof.addExclusionZone(new ExclusionZone({
      landmarkId: 'nyc',
      minDistanceKm: 5000,
    }));

    expect(proof.exclusionZones).toHaveLength(1);
  });

  it('should increase confidence with more landmarks', () => {
    proof.addExclusionZone(new ExclusionZone({ landmarkId: 'nyc', minDistanceKm: 5000 }));
    const conf1 = proof.confidence;

    proof.addExclusionZone(new ExclusionZone({ landmarkId: 'london', minDistanceKm: 3000 }));
    const conf2 = proof.confidence;

    proof.addExclusionZone(new ExclusionZone({ landmarkId: 'tokyo', minDistanceKm: 8000 }));
    const conf3 = proof.confidence;

    expect(conf2).toBeGreaterThan(conf1);
    expect(conf3).toBeGreaterThan(conf2);
  });

  describe('checkLocation', () => {
    beforeEach(() => {
      // Add zones that prove node is far from NYC and London
      proof.addExclusionZone(new ExclusionZone({
        landmarkId: 'nyc',
        landmarkName: 'NYC',
        landmarkCoordinates: { lat: 40.7128, lon: -74.0060 },
        minDistanceKm: 8000,
        precisionKm: 100,
      }));
      proof.addExclusionZone(new ExclusionZone({
        landmarkId: 'london',
        landmarkName: 'London',
        landmarkCoordinates: { lat: 51.5074, lon: -0.1278 },
        minDistanceKm: 6000,
        precisionKm: 100,
      }));
    });

    it('should detect violations when claimed location is impossible', () => {
      // Claim to be in NYC, but we proved >8000km away
      const result = proof.checkLocation({ lat: 40.7128, lon: -74.0060 });
      expect(result.consistent).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      // At least one violation should be from NYC landmark
      const nycViolation = result.violations.find(v => v.landmarkName === 'NYC');
      expect(nycViolation).toBeDefined();
    });

    it('should accept consistent locations', () => {
      // Tokyo is 10800km from NYC and 9500km from London
      // Both beyond our minimums
      const result = proof.checkLocation({ lat: 35.6762, lon: 139.6503 });
      expect(result.consistent).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });

  it('should serialize and deserialize correctly', () => {
    proof.addExclusionZone(new ExclusionZone({
      landmarkId: 'nyc',
      minDistanceKm: 5000,
      rttMs: 50,
    }));

    const serialized = proof.serialize();
    const restored = GeographicProof.deserialize(serialized);

    expect(restored.nodeId).toBe(proof.nodeId);
    expect(restored.dokoId).toBe(proof.dokoId);
    expect(restored.exclusionZones).toHaveLength(1);
  });
});

// ============================================================
// GEO PROOF SERVICE TESTS
// ============================================================

describe('GeoProofService', () => {
  let service;

  beforeEach(() => {
    service = new GeoProofService({
      nodeId: 'test-node',
      dokoId: 'doko-123',
      timeSource: TimeTrustLevel.NTP,
      rttInterval: 0,  // Disable auto-refresh for tests
    });
  });

  it('should initialize correctly', () => {
    expect(service.nodeId).toBe('test-node');
    expect(service.landmarkRegistry).toBeDefined();
  });

  it('should register landmarks', () => {
    service.registerLandmark({
      nodeId: 'landmark-1',
      name: 'NYC-ANCHOR',
      region: 'NA-EAST',
      endpoint: 'https://nyc.example.com/.well-known/yakmesh/beacon',
    });

    expect(service.landmarkRegistry.getAll()).toHaveLength(1);
  });

  it('should register multiple landmarks', () => {
    service.registerLandmarks([
      { nodeId: 'l1', name: 'NYC', region: 'NA-EAST' },
      { nodeId: 'l2', name: 'London', region: 'EU-WEST' },
      { nodeId: 'l3', name: 'Tokyo', region: 'ASIA-PAC' },
    ]);

    expect(service.landmarkRegistry.getAll()).toHaveLength(3);
  });

  it('should generate proof from cached measurements', () => {
    // Register a landmark
    service.registerLandmark({
      nodeId: 'nyc-anchor',
      name: 'NYC-ANCHOR',
      region: 'NA-EAST',
      endpoint: 'https://nyc.example.com',
      coordinates: { lat: 40.7128, lon: -74.0060 },
    });

    // Manually add a measurement to cache
    const measurement = new RTTMeasurement({
      landmarkId: 'nyc-anchor',
      timeSource: TimeTrustLevel.NTP,
    });
    measurement.addSample(50);
    measurement.addSample(52);
    measurement.addSample(51);
    service.measurementCache.set('nyc-anchor', measurement);

    // Generate proof
    const proof = service.generateProof();
    expect(proof).toBeDefined();
    expect(proof.exclusionZones.length).toBeGreaterThan(0);
  });

  it('should report correct status', () => {
    service.registerLandmark({
      nodeId: 'l1',
      name: 'NYC',
      region: 'NA-EAST',
    });

    const status = service.getStatus();
    expect(status.nodeId).toBe('test-node');
    expect(status.landmarks).toBe(1);
    expect(status.proofReady).toBe(false);
  });
});

// ============================================================
// EDGE CASES & PHYSICS VERIFICATION
// ============================================================

describe('Edge Cases', () => {
  it('should handle very small RTT (local network)', () => {
    const distance = calculateMinDistance(0.1, 'FIBER');  // 0.1ms
    expect(distance).toBeGreaterThan(0);
    expect(distance).toBeLessThan(20);  // ~10km
  });

  it('should handle very large RTT (satellite)', () => {
    const distance = calculateMinDistance(600, 'FIBER');  // 600ms
    expect(distance).toBeGreaterThan(50000);
  });

  it('should handle negative RTT gracefully', () => {
    const distance = calculateMinDistance(-10, 'FIBER');
    expect(distance).toBeLessThan(0);  // Mathematically correct but nonsensical
  });

  it('should handle coordinates at poles', () => {
    const distance = haversineDistance(90, 0, -90, 0);  // North to South pole
    expect(distance).toBeCloseTo(20015, 0);  // Half circumference
  });

  it('should handle coordinates crossing dateline', () => {
    const d1 = haversineDistance(0, 179, 0, -179);  // Cross dateline
    expect(d1).toBeLessThan(300);  // Should be ~222km
  });
});

describe('Physics Verification', () => {
  it('should correctly model NYC to London RTT (~28ms theoretical minimum)', () => {
    // NYC to London is ~5570km
    // In fiber: 5570km / 199861.639 km/s = 0.0279s = 27.9ms one-way
    // RTT = 55.8ms theoretical minimum
    const distance = calculateMinDistance(56, 'FIBER');
    expect(distance).toBeCloseTo(5596, -1);  // Allow ±50km variance
  });

  it('should correctly model transatlantic submarine cable', () => {
    // Real-world transatlantic cables have ~60-70ms RTT
    // This proves nodes are in different continents
    const distance = calculateMinDistance(65, 'FIBER');
    expect(distance).toBeGreaterThan(6000);
    expect(distance).toBeLessThan(7000);
  });

  it('should correctly model Earth circumference bound', () => {
    // Maximum distance through fiber = half circumference ≈ 20,000km
    // Theoretical minimum RTT for antipodal = 20000 / 199861.639 * 2 = 200ms
    const distance = calculateMinDistance(200, 'FIBER');
    expect(distance).toBeCloseTo(19986, -1);  // Allow ±50km variance
  });
});
