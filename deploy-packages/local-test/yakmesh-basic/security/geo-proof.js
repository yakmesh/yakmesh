/**
 * Geographic Proof - Speed-of-Light Location Verification
 * 
 * Uses RTT measurements to known landmark nodes combined with
 * speed-of-light physics to create geographic exclusion zones.
 * 
 * KEY INSIGHT: Network latency only makes nodes appear FARTHER,
 * never closer. We can prove "node X is NOT within Y km of landmark Z"
 * but cannot prove precise location.
 * 
 * WHAT THIS PROVES:
 * ✅ "Node X is NOT within 500km of landmark Y" (exclusion)
 * ✅ "Node X is consistent with being in region Z" (plausibility)
 * ❌ "Node X is definitely at coordinates (lat, lon)" (NOT provable)
 * 
 * PHYSICS:
 * - Speed of light in fiber: ~200,000 km/s (0.67c due to refractive index)
 * - Minimum distance = (RTT / 2) × fiber_speed
 * - Network overhead only INFLATES RTT, never reduces it
 * 
 * INTEGRATION:
 * - Uses TimeSourceDetector for precision timestamps
 * - Uses SHERPA beacons for RTT measurement
 * - Uses KHATA gossip for attestation propagation
 * - Integrates with trust-tier for precision-based bounds
 * 
 * @module security/geo-proof
 * @version 2.5.0
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { TimeTrustLevel, PhaseTolerance } from '../oracle/time-source.js';
import { TRUST_TIER, TIER_WEIGHT } from './trust-tier.js';

const log = createLogger('security:geo-proof');

// ============================================================
// PHYSICAL CONSTANTS
// ============================================================

/**
 * Speed of light in various media (km/s)
 */
export const LIGHT_SPEED = {
  VACUUM: 299792.458,           // c in vacuum
  FIBER: 199861.639,            // ~0.67c in fiber optic (n ≈ 1.5)
  COPPER: 199861.639,           // Similar to fiber for calculations
  WIRELESS: 299792.458,         // Approximately c for radio/microwave
};

/**
 * Default configuration
 */
export const GEO_PROOF_CONFIG = {
  // RTT measurement
  rttSamples: 5,                    // Number of RTT samples per measurement
  rttTimeout: 10000,                // Timeout per sample (ms)
  rttInterval: 60000,               // Re-measure interval (ms)

  // Distance calculation
  defaultMedium: 'FIBER',           // Assume fiber for conservative estimate
  safetyMargin: 1.1,                // 10% safety margin for calculation errors

  // Landmark requirements
  minLandmarks: 3,                  // Minimum landmarks for trilateration
  maxLandmarkAge: 3600000,          // Max age of landmark data (1 hour)

  // Exclusion zone
  minExclusionRadius: 50,           // Minimum exclusion radius (km)

  // Attestation
  attestationTTL: 86400000,         // Attestation validity (24 hours)
  maxAttestationsPerNode: 100,      // Prevent spam

  // Protocol version
  version: '1.0',
};

// ============================================================
// DISTANCE PRECISION BY TIME SOURCE
// ============================================================

/**
 * Distance precision based on time source quality
 * Higher precision timing = tighter geographic bounds
 */
export const DISTANCE_PRECISION = {
  [TimeTrustLevel.QUANTUM]: 1,      // ±1km with quantum timing
  [TimeTrustLevel.ATOMIC]: 10,      // ±10km with atomic clock
  [TimeTrustLevel.GPS]: 100,        // ±100km with GPS/PPS
  [TimeTrustLevel.PTP]: 100,        // ±100km with PTP
  [TimeTrustLevel.NTP]: 1000,       // ±1000km with NTP
  [TimeTrustLevel.UNSYNC]: 5000,    // ±5000km without sync (nearly useless)
};

// ============================================================
// LANDMARK REGISTRY
// ============================================================

/**
 * Known landmark nodes for geographic reference
 * These are well-known nodes with verified physical locations
 */
export class LandmarkRegistry {
  constructor() {
    this.landmarks = new Map();  // landmarkId -> LandmarkInfo
  }

  /**
   * Register a landmark node
   * @param {Object} landmark - Landmark information
   */
  register(landmark) {
    const id = landmark.dokoId || landmark.nodeId;

    this.landmarks.set(id, {
      id,
      name: landmark.name,
      region: landmark.region,              // e.g., 'NA-EAST', 'EU-WEST', 'ASIA-PAC'
      coordinates: landmark.coordinates,     // { lat, lon } - approximate, for display only
      endpoint: landmark.endpoint,           // SHERPA beacon endpoint
      wsEndpoint: landmark.wsEndpoint,       // WebSocket endpoint for RTT
      publicKey: landmark.publicKey,         // For verification
      trustTier: landmark.trustTier || TRUST_TIER.SENTINEL,
      timeSource: landmark.timeSource || TimeTrustLevel.NTP,
      registeredAt: Date.now(),
      lastVerified: null,
    });

    log.info('Registered landmark', { id, name: landmark.name, region: landmark.region });
    return id;
  }

  /**
   * Get all landmarks
   */
  getAll() {
    return Array.from(this.landmarks.values());
  }

  /**
   * Get landmark by ID
   */
  get(id) {
    return this.landmarks.get(id);
  }

  /**
   * Get landmarks by region
   */
  getByRegion(region) {
    return this.getAll().filter(l => l.region === region);
  }

  /**
   * Remove stale landmarks
   */
  prune(maxAge = GEO_PROOF_CONFIG.maxLandmarkAge) {
    const now = Date.now();
    let pruned = 0;

    for (const [id, landmark] of this.landmarks) {
      if (landmark.lastVerified && (now - landmark.lastVerified) > maxAge) {
        this.landmarks.delete(id);
        pruned++;
      }
    }

    return pruned;
  }
}

// ============================================================
// RTT MEASUREMENT
// ============================================================

/**
 * RTT Measurement Result
 */
export class RTTMeasurement {
  constructor(options = {}) {
    this.landmarkId = options.landmarkId;
    this.samples = options.samples || [];
    this.timestamp = options.timestamp || Date.now();
    this.timeSource = options.timeSource || TimeTrustLevel.NTP;
  }

  /**
   * Add a sample
   */
  addSample(rttMs) {
    this.samples.push(rttMs);
  }

  /**
   * Get minimum RTT (most accurate - least network overhead)
   */
  getMinRTT() {
    if (this.samples.length === 0) return null;
    return Math.min(...this.samples);
  }

  /**
   * Get median RTT
   */
  getMedianRTT() {
    if (this.samples.length === 0) return null;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  }

  /**
   * Get standard deviation
   */
  getStdDev() {
    if (this.samples.length < 2) return 0;
    const mean = this.samples.reduce((a, b) => a + b, 0) / this.samples.length;
    const variance = this.samples.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / this.samples.length;
    return Math.sqrt(variance);
  }

  /**
   * Check if measurement is reliable
   */
  isReliable() {
    if (this.samples.length < 3) return false;
    const stdDev = this.getStdDev();
    const median = this.getMedianRTT();
    // Coefficient of variation should be < 50%
    return (stdDev / median) < 0.5;
  }
}

/**
 * Measure RTT to a landmark
 * Uses WebSocket ping/pong or SHERPA beacon
 * 
 * @param {string} endpoint - Landmark endpoint
 * @param {Object} options - Measurement options
 * @returns {Promise<RTTMeasurement>}
 */
export async function measureRTT(endpoint, options = {}) {
  const measurement = new RTTMeasurement({
    landmarkId: options.landmarkId,
    timeSource: options.timeSource || TimeTrustLevel.NTP,
  });

  const samples = options.samples || GEO_PROOF_CONFIG.rttSamples;
  const timeout = options.timeout || GEO_PROOF_CONFIG.rttTimeout;

  for (let i = 0; i < samples; i++) {
    try {
      const start = performance.now();

      // HTTP beacon fetch (SHERPA style)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(endpoint, {
        method: 'GET',
        signal: controller.signal,
        cache: 'no-store',
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const rtt = performance.now() - start;
        measurement.addSample(rtt);
      }
    } catch (error) {
      // Sample failed, continue with others
      log.debug('RTT sample failed', { endpoint, error: error.message });
    }

    // Small delay between samples to avoid burst patterns
    if (i < samples - 1) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  return measurement;
}

// ============================================================
// DISTANCE CALCULATION
// ============================================================

/**
 * Calculate minimum possible distance from RTT
 * 
 * @param {number} rttMs - Round-trip time in milliseconds
 * @param {string} medium - Transmission medium (FIBER, VACUUM, etc.)
 * @param {number} safetyMargin - Safety margin multiplier
 * @returns {number} Minimum distance in kilometers
 */
export function calculateMinDistance(rttMs, medium = 'FIBER', safetyMargin = 1.0) {
  const speed = LIGHT_SPEED[medium] || LIGHT_SPEED.FIBER;

  // One-way time = RTT / 2
  // Distance = speed × time
  // Convert ms to seconds: rttMs / 1000
  const distanceKm = (rttMs / 2 / 1000) * speed;

  // Apply safety margin (typically 1.0 for lower bound)
  return distanceKm * safetyMargin;
}

/**
 * Calculate distance precision based on time source
 * 
 * @param {string} timeSource - Time trust level
 * @returns {number} Distance precision in km
 */
export function getDistancePrecision(timeSource) {
  return DISTANCE_PRECISION[timeSource] || DISTANCE_PRECISION[TimeTrustLevel.NTP];
}

// ============================================================
// EXCLUSION ZONE
// ============================================================

/**
 * Geographic Exclusion Zone
 * Represents a region where a node CANNOT be located
 */
export class ExclusionZone {
  constructor(options = {}) {
    this.landmarkId = options.landmarkId;
    this.landmarkName = options.landmarkName;
    this.landmarkRegion = options.landmarkRegion;
    this.landmarkCoordinates = options.landmarkCoordinates;  // For display

    this.minDistanceKm = options.minDistanceKm;              // Node is AT LEAST this far
    this.precisionKm = options.precisionKm;                  // Error margin
    this.rttMs = options.rttMs;                              // Source RTT
    this.timeSource = options.timeSource;                    // Time source used

    this.timestamp = options.timestamp || Date.now();
    this.signature = options.signature || null;
  }

  /**
   * Check if a coordinate is within the exclusion zone
   * (i.e., the node CANNOT be at this location)
   * 
   * @param {Object} coords - { lat, lon }
   * @returns {boolean} True if location is EXCLUDED (impossible)
   */
  isExcluded(coords) {
    if (!this.landmarkCoordinates) return false;

    const distance = haversineDistance(
      this.landmarkCoordinates.lat,
      this.landmarkCoordinates.lon,
      coords.lat,
      coords.lon
    );

    // If claimed location is closer than physics allows, it's excluded
    return distance < (this.minDistanceKm - this.precisionKm);
  }

  /**
   * Serialize for transmission
   */
  serialize() {
    return {
      landmarkId: this.landmarkId,
      landmarkName: this.landmarkName,
      landmarkRegion: this.landmarkRegion,
      minDistanceKm: this.minDistanceKm,
      precisionKm: this.precisionKm,
      rttMs: this.rttMs,
      timeSource: this.timeSource,
      timestamp: this.timestamp,
      signature: this.signature,
    };
  }

  /**
   * Deserialize from transmission
   */
  static deserialize(data) {
    return new ExclusionZone(data);
  }
}

/**
 * Calculate Haversine distance between two coordinates
 * 
 * @param {number} lat1 - Latitude 1
 * @param {number} lon1 - Longitude 1
 * @param {number} lat2 - Latitude 2
 * @param {number} lon2 - Longitude 2
 * @returns {number} Distance in kilometers
 */
export function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in km

  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);

  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

function toRadians(degrees) {
  return degrees * (Math.PI / 180);
}

// ============================================================
// GEOGRAPHIC PROOF
// ============================================================

/**
 * Geographic Proof - Aggregated exclusion zones
 * Proves where a node CANNOT be
 */
export class GeographicProof {
  constructor(options = {}) {
    this.nodeId = options.nodeId;
    this.dokoId = options.dokoId;
    this.exclusionZones = [];
    this.timestamp = options.timestamp || Date.now();
    this.timeSource = options.timeSource || TimeTrustLevel.NTP;

    // Computed fields
    this.possibleRegions = [];
    this.excludedRegions = [];
    this.confidence = 0;
  }

  /**
   * Add an exclusion zone
   */
  addExclusionZone(zone) {
    this.exclusionZones.push(zone);
    this._recompute();
  }

  /**
   * Recompute possible/excluded regions
   */
  _recompute() {
    // With 3+ landmarks, we can do trilateration
    if (this.exclusionZones.length >= GEO_PROOF_CONFIG.minLandmarks) {
      this.confidence = Math.min(1.0, this.exclusionZones.length / 5);
    } else {
      this.confidence = this.exclusionZones.length / GEO_PROOF_CONFIG.minLandmarks * 0.5;
    }

    // Determine excluded regions based on physics
    this.excludedRegions = [];
    for (const zone of this.exclusionZones) {
      if (zone.minDistanceKm < 100) {
        // Very close to this landmark's region
      } else {
        // Far from this landmark
        const rttStr = zone.rttMs != null ? `RTT ${zone.rttMs.toFixed(1)}ms implies ` : '';
        const distStr = zone.minDistanceKm != null ? zone.minDistanceKm.toFixed(0) : 'unknown';
        this.excludedRegions.push({
          region: zone.landmarkRegion,
          reason: `${rttStr}>${distStr}km`,
        });
      }
    }
  }

  /**
   * Check if a claimed location is consistent with proof
   * 
   * @param {Object} coords - { lat, lon }
   * @returns {Object} { consistent, violations }
   */
  checkLocation(coords) {
    const violations = [];

    for (const zone of this.exclusionZones) {
      if (zone.isExcluded(coords)) {
        violations.push({
          landmarkId: zone.landmarkId,
          landmarkName: zone.landmarkName,
          claimedDistanceKm: zone.landmarkCoordinates ?
            haversineDistance(zone.landmarkCoordinates.lat, zone.landmarkCoordinates.lon, coords.lat, coords.lon) : null,
          minAllowedKm: zone.minDistanceKm,
          message: `Claimed location violates physics - RTT proves node is >${zone.minDistanceKm.toFixed(0)}km from ${zone.landmarkName}`,
        });
      }
    }

    return {
      consistent: violations.length === 0,
      violations,
      confidence: this.confidence,
    };
  }

  /**
   * Get summary
   */
  getSummary() {
    return {
      nodeId: this.nodeId,
      dokoId: this.dokoId,
      landmarkCount: this.exclusionZones.length,
      excludedRegions: this.excludedRegions,
      confidence: this.confidence,
      timestamp: this.timestamp,
      timeSource: this.timeSource,
    };
  }

  /**
   * Serialize for transmission/storage
   */
  serialize() {
    return {
      nodeId: this.nodeId,
      dokoId: this.dokoId,
      exclusionZones: this.exclusionZones.map(z => z.serialize()),
      timestamp: this.timestamp,
      timeSource: this.timeSource,
    };
  }

  /**
   * Deserialize from transmission
   */
  static deserialize(data) {
    const proof = new GeographicProof({
      nodeId: data.nodeId,
      dokoId: data.dokoId,
      timestamp: data.timestamp,
      timeSource: data.timeSource,
    });

    for (const zoneData of data.exclusionZones || []) {
      proof.addExclusionZone(ExclusionZone.deserialize(zoneData));
    }

    return proof;
  }
}

// ============================================================
// GEO PROOF SERVICE
// ============================================================

/**
 * Geographic Proof Service
 * Manages landmark registry, RTT measurements, and proof generation
 */
export class GeoProofService extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = { ...GEO_PROOF_CONFIG, ...options };
    this.landmarkRegistry = new LandmarkRegistry();
    this.proofs = new Map();  // nodeId -> GeographicProof
    this.measurementCache = new Map();  // landmarkId -> RTTMeasurement

    this.nodeId = options.nodeId;
    this.dokoId = options.dokoId;
    this.timeSource = options.timeSource || TimeTrustLevel.NTP;
    this.privateKey = options.privateKey;  // For signing attestations

    this.measurementTimer = null;
  }

  /**
   * Start the service
   */
  start() {
    log.info('GeoProof service starting', {
      landmarks: this.landmarkRegistry.getAll().length,
      nodeId: this.nodeId,
    });

    // Initial measurement
    this.measureAllLandmarks();

    // Periodic re-measurement
    if (this.config.rttInterval > 0) {
      this.measurementTimer = setInterval(() => {
        this.measureAllLandmarks();
      }, this.config.rttInterval);
    }

    return this;
  }

  /**
   * Stop the service
   */
  stop() {
    if (this.measurementTimer) {
      clearInterval(this.measurementTimer);
      this.measurementTimer = null;
    }
  }

  /**
   * Register a landmark
   */
  registerLandmark(landmark) {
    return this.landmarkRegistry.register(landmark);
  }

  /**
   * Register multiple landmarks
   */
  registerLandmarks(landmarks) {
    for (const landmark of landmarks) {
      this.registerLandmark(landmark);
    }
  }

  /**
   * Measure RTT to all landmarks
   */
  async measureAllLandmarks() {
    const landmarks = this.landmarkRegistry.getAll();
    const results = [];

    for (const landmark of landmarks) {
      try {
        const measurement = await measureRTT(landmark.endpoint, {
          landmarkId: landmark.id,
          timeSource: this.timeSource,
          samples: this.config.rttSamples,
          timeout: this.config.rttTimeout,
        });

        if (measurement.samples.length > 0) {
          this.measurementCache.set(landmark.id, measurement);
          landmark.lastVerified = Date.now();
          results.push({ landmark: landmark.id, success: true, rtt: measurement.getMinRTT() });
        } else {
          results.push({ landmark: landmark.id, success: false, error: 'No samples' });
        }
      } catch (error) {
        results.push({ landmark: landmark.id, success: false, error: error.message });
      }
    }

    this.emit('measurements', results);
    return results;
  }

  /**
   * Generate geographic proof for this node
   */
  generateProof() {
    const proof = new GeographicProof({
      nodeId: this.nodeId,
      dokoId: this.dokoId,
      timeSource: this.timeSource,
    });

    for (const [landmarkId, measurement] of this.measurementCache) {
      const landmark = this.landmarkRegistry.get(landmarkId);
      if (!landmark) continue;

      const rtt = measurement.getMinRTT();
      if (rtt === null) continue;

      const minDistance = calculateMinDistance(rtt, this.config.defaultMedium);
      const precision = getDistancePrecision(measurement.timeSource);

      // Only add if distance is meaningful
      if (minDistance >= this.config.minExclusionRadius) {
        const zone = new ExclusionZone({
          landmarkId: landmark.id,
          landmarkName: landmark.name,
          landmarkRegion: landmark.region,
          landmarkCoordinates: landmark.coordinates,
          minDistanceKm: minDistance,
          precisionKm: precision,
          rttMs: rtt,
          timeSource: measurement.timeSource,
        });

        proof.addExclusionZone(zone);
      }
    }

    // Cache the proof
    this.proofs.set(this.nodeId, proof);

    this.emit('proof-generated', proof.getSummary());
    return proof;
  }

  /**
   * Verify a claimed location against our proof
   * 
   * @param {Object} coords - { lat, lon }
   * @returns {Object} Verification result
   */
  verifyLocation(coords) {
    const proof = this.proofs.get(this.nodeId);
    if (!proof) {
      return { verified: false, reason: 'No proof available' };
    }

    const result = proof.checkLocation(coords);
    return {
      verified: result.consistent,
      violations: result.violations,
      confidence: result.confidence,
      landmarkCount: proof.exclusionZones.length,
    };
  }

  /**
   * Get current proof
   */
  getProof() {
    return this.proofs.get(this.nodeId);
  }

  /**
   * Get service status
   */
  getStatus() {
    const proof = this.getProof();
    return {
      nodeId: this.nodeId,
      landmarks: this.landmarkRegistry.getAll().length,
      measurements: this.measurementCache.size,
      proofReady: !!proof,
      proofConfidence: proof?.confidence || 0,
      excludedRegions: proof?.excludedRegions || [],
      timeSource: this.timeSource,
    };
  }

  /**
   * Ingest propagation delay measurements from AGUWA heartbeat timing.
   * Converts one-way delay (ms) to RTT-equivalent and stores as measurements,
   * allowing generateProof() to include heartbeat-derived distance bounds.
   *
   * @param {Map<string, {delayMs: number, trustLevel: string, aguwaScore: number}>} delays
   *   From aguwa.getPropagationDelays()
   * @returns {number} Number of measurements ingested
   */
  addAGUWAMeasurements(delays) {
    let ingested = 0;

    for (const [nodeId, info] of delays) {
      const landmark = this.landmarkRegistry.get(nodeId);
      if (!landmark) continue; // Only count registered landmarks

      // AGUWA delayMs is one-way residual — convert to equivalent RTT
      const equivalentRttMs = info.delayMs * 2;

      // Create or update measurement
      const measurement = new RTTMeasurement({
        landmarkId: nodeId,
        samples: [equivalentRttMs],
        timeSource: info.trustLevel,
      });

      // Keep best of HTTP beacon RTT and AGUWA heartbeat RTT
      const existing = this.measurementCache.get(nodeId);
      if (existing && existing.getMinRTT() < equivalentRttMs) {
        continue; // HTTP beacon was tighter — keep it
      }

      this.measurementCache.set(nodeId, measurement);
      landmark.lastVerified = Date.now();
      ingested++;
    }

    if (ingested > 0) {
      log.debug('AGUWA measurements ingested', { count: ingested });
    }
    return ingested;
  }
}

// ============================================================
// EXPORTS
// ============================================================

// Default export
export default GeoProofService;
