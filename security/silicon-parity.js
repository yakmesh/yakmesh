/**
 * Silicon Parity - One Silicon = One Vote
 * 
 * Prevents ASIC-style gaming where attackers use multiple AES cores
 * on a single rig to gain disproportionate attestation power.
 * 
 * Key principles:
 * - Weight division: tierMax / coreCount (100 cores = 0.01x each)
 * - AES timing fingerprint: Unique per-CPU silicon signature
 * - Bitslice verification: Fast epoch checks (~1ms)
 * - VM detection: Jitter analysis reveals emulation
 * 
 * "You can't fake physics. One silicon, one vote."
 * 
 * @module security/silicon-parity
 * @version 1.0.0
 */

import { createCipheriv, randomBytes, createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';
import os from 'os';

const log = createLogger('security:silicon');

/**
 * Silicon Parity configuration
 */
export const SILICON_CONFIG = {
  // Fingerprint collection
  FINGERPRINT_OPS: 1000,           // AES operations for full fingerprint
  FINGERPRINT_DATA_SIZE: 4096,     // 4KB per operation (cache-friendly)
  
  // Bitslice sampling (epoch verification)
  SAMPLE_OPS: 125,                 // 1/8th of full fingerprint
  SAMPLE_SLICE_SIZE: 8,            // 32 bits (8 hex chars)
  SAMPLE_MAX_DRIFT: 4,             // Hamming distance tolerance
  
  // Verification schedule
  FULL_VERIFY_INTERVAL: 8,         // Full fingerprint every 8 epochs
  
  // VM detection thresholds
  VM_JITTER_THRESHOLD: 0.15,       // 15% variance = likely VM
  REAL_SILICON_JITTER: 0.05,       // Real silicon < 5% variance
  
  // Thermal drift tolerance
  DRIFT_TOLERANCE: 0.05,           // 5% allowed drift over time
  
  // Platform UUID sources (priority order)
  UUID_SOURCES: {
    WINDOWS: 'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid',
    LINUX: '/sys/class/dmi/id/product_uuid',
    LINUX_ALT: '/etc/machine-id',
    MACOS: 'IOPlatformUUID',
  },
};

/**
 * Silicon Identity - Unique hardware identifier
 */
export class SiliconIdentity {
  constructor(data) {
    this.id = data.id;
    this.platformUUID = data.platformUUID;
    this.aesFingerprint = data.aesFingerprint;
    this.timingHistogram = data.timingHistogram;
    this.jitterRatio = data.jitterRatio;
    this.socketCount = data.socketCount;
    this.coreCount = data.coreCount;
    this.isRealSilicon = data.isRealSilicon;
    this.createdAt = data.createdAt;
    this.lastVerified = data.lastVerified;
    this.verificationCount = data.verificationCount || 0;
  }
  
  /**
   * Calculate effective weight for this identity
   * Weight is divided by core count to prevent ASIC-style gaming
   */
  calculateWeight(tierMaxWeight) {
    // Ensure minimum of 1 core for division
    const cores = Math.max(1, this.coreCount);
    return tierMaxWeight / cores;
  }
  
  /**
   * Get weight multiplier (inverse of core count)
   */
  get weightMultiplier() {
    return 1 / Math.max(1, this.coreCount);
  }
  
  /**
   * Serialize for storage/transmission
   */
  toJSON() {
    return {
      id: this.id,
      platformUUID: this.platformUUID,
      aesFingerprint: this.aesFingerprint,
      jitterRatio: this.jitterRatio,
      socketCount: this.socketCount,
      coreCount: this.coreCount,
      isRealSilicon: this.isRealSilicon,
      createdAt: this.createdAt,
      lastVerified: this.lastVerified,
      verificationCount: this.verificationCount,
    };
  }
  
  /**
   * Deserialize from storage
   */
  static fromJSON(json) {
    return new SiliconIdentity(json);
  }
}

/**
 * Collect AES timing histogram (fingerprint)
 * The variance pattern is unique per CPU due to silicon lottery
 */
export async function collectTimingHistogram(options = {}) {
  const ops = options.ops || SILICON_CONFIG.FINGERPRINT_OPS;
  const dataSize = options.dataSize || SILICON_CONFIG.FINGERPRINT_DATA_SIZE;
  
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const data = randomBytes(dataSize);
  
  const timings = [];
  
  for (let i = 0; i < ops; i++) {
    const start = process.hrtime.bigint();
    
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.update(data);
    cipher.final();
    cipher.getAuthTag();
    
    const end = process.hrtime.bigint();
    timings.push(Number(end - start));
  }
  
  // Calculate statistics
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
  const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
  const stddev = Math.sqrt(variance);
  const jitterRatio = stddev / mean;
  
  // Create histogram buckets (normalized)
  const bucketCount = 32;
  const min = Math.min(...timings);
  const max = Math.max(...timings);
  const bucketSize = (max - min) / bucketCount || 1;
  
  const histogram = new Array(bucketCount).fill(0);
  for (const t of timings) {
    const bucket = Math.min(bucketCount - 1, Math.floor((t - min) / bucketSize));
    histogram[bucket]++;
  }
  
  // Normalize histogram
  const normalizedHistogram = histogram.map(h => h / ops);
  
  return {
    timings,
    histogram: normalizedHistogram,
    mean,
    stddev,
    jitterRatio,
    min,
    max,
    ops,
  };
}

/**
 * Create AES fingerprint from timing histogram
 * SHA3-256 of the normalized histogram
 */
export function createFingerprint(histogram) {
  // Convert histogram to stable string representation
  const histogramStr = histogram.map(h => h.toFixed(6)).join(',');
  const hash = sha3_256(new TextEncoder().encode(histogramStr));
  return bytesToHex(hash);
}

/**
 * Detect platform UUID (motherboard identifier)
 */
export async function getPlatformUUID() {
  const platform = os.platform();
  
  try {
    if (platform === 'win32') {
      return await getWindowsUUID();
    } else if (platform === 'linux') {
      return await getLinuxUUID();
    } else if (platform === 'darwin') {
      return await getMacOSUUID();
    }
  } catch (err) {
    log.warn('silicon-parity', `Failed to get platform UUID: ${err.message}`);
  }
  
  // Fallback: Generate stable ID from hardware characteristics
  return generateFallbackUUID();
}

/**
 * Get Windows machine GUID
 */
async function getWindowsUUID() {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);
  
  try {
    const { stdout } = await execAsync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
      { timeout: 5000 }
    );
    const match = stdout.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
    if (match) return match[1];
  } catch (err) {
    // Try WMI as fallback
    try {
      const { stdout } = await execAsync(
        'wmic csproduct get uuid',
        { timeout: 5000 }
      );
      const lines = stdout.trim().split('\n');
      if (lines.length > 1) {
        const uuid = lines[1].trim();
        if (uuid && uuid !== 'UUID') return uuid;
      }
    } catch (e) {
      // Ignore
    }
  }
  
  throw new Error('Could not get Windows UUID');
}

/**
 * Get Linux machine UUID
 */
async function getLinuxUUID() {
  const { readFile } = await import('fs/promises');
  
  // Try DMI product UUID first (requires root on some systems)
  try {
    const uuid = await readFile('/sys/class/dmi/id/product_uuid', 'utf8');
    return uuid.trim();
  } catch (err) {
    // Ignore, try machine-id
  }
  
  // Fallback to machine-id (always readable)
  try {
    const machineId = await readFile('/etc/machine-id', 'utf8');
    return machineId.trim();
  } catch (err) {
    // Ignore
  }
  
  throw new Error('Could not get Linux UUID');
}

/**
 * Get macOS IOPlatformUUID
 */
async function getMacOSUUID() {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);
  
  const { stdout } = await execAsync(
    'ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID',
    { timeout: 5000 }
  );
  
  const match = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
  if (match) return match[1];
  
  throw new Error('Could not get macOS UUID');
}

/**
 * Generate fallback UUID from hardware characteristics
 */
function generateFallbackUUID() {
  const cpus = os.cpus();
  const cpu = cpus[0] || {};
  
  // Combine hardware characteristics that are stable but unique-ish
  const characteristics = [
    os.platform(),
    os.arch(),
    cpu.model || 'unknown',
    cpus.length.toString(),
    os.totalmem().toString(),
    os.hostname(),
  ].join('|');
  
  const hash = createHash('sha256').update(characteristics).digest('hex');
  
  // Format as UUID
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    hash.slice(12, 16),
    hash.slice(16, 20),
    hash.slice(20, 32),
  ].join('-');
}

/**
 * Detect socket/CPU topology
 */
export function detectTopology() {
  const cpus = os.cpus();
  
  // On Linux, we could parse /proc/cpuinfo for physical id
  // For now, use heuristics based on core count and model
  const model = cpus[0]?.model || '';
  const coreCount = cpus.length;
  
  // Detect likely multi-socket scenarios
  // (This is a heuristic - true detection requires /proc/cpuinfo parsing)
  let socketCount = 1;
  
  // High core counts often indicate multi-socket
  if (coreCount > 64) {
    socketCount = Math.ceil(coreCount / 64);
  }
  
  // Server-class CPUs with "Platinum", "Gold", "EPYC" in name
  if (model.includes('Platinum') || model.includes('Gold') || model.includes('EPYC')) {
    if (coreCount > 32) {
      socketCount = Math.max(socketCount, 2);
    }
  }
  
  return {
    socketCount,
    coreCount,
    model,
    isMultiSocket: socketCount > 1,
  };
}

/**
 * Analyze jitter to detect VM/emulation
 */
export function analyzeJitter(timings) {
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
  const sorted = [...timings].sort((a, b) => a - b);
  
  // Calculate percentiles
  const p1 = sorted[Math.floor(sorted.length * 0.01)];
  const p50 = sorted[Math.floor(sorted.length * 0.5)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  
  // Calculate jitter ratio
  const stddev = Math.sqrt(
    timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length
  );
  const jitterRatio = stddev / mean;
  
  // Calculate spike ratio (p99 vs median)
  const spikeRatio = (p99 - p50) / p50;
  
  // VM characteristics:
  // - High jitter ratio (>15%)
  // - Occasional spikes (high p99/p50 ratio)
  // - Irregular timing distribution
  
  const isRealSilicon = jitterRatio < SILICON_CONFIG.VM_JITTER_THRESHOLD &&
                        spikeRatio < 0.5;
  
  const confidence = isRealSilicon
    ? Math.max(0, 1 - (jitterRatio / SILICON_CONFIG.VM_JITTER_THRESHOLD))
    : Math.max(0, 1 - (SILICON_CONFIG.VM_JITTER_THRESHOLD / jitterRatio));
  
  return {
    jitterRatio,
    spikeRatio,
    mean,
    stddev,
    p1,
    p50,
    p99,
    isRealSilicon,
    confidence,
  };
}

/**
 * Silicon Parity Manager
 * Collects, stores, and verifies silicon identities
 */
export class SiliconParityManager {
  constructor(options = {}) {
    this.identities = new Map(); // dokoId -> SiliconIdentity
    this.fingerprintIndex = new Map(); // fingerprint -> Set<dokoId>
    this.epochCount = 0;
    
    // Callbacks for integration
    this.onDuplicateFingerprint = options.onDuplicateFingerprint || (() => {});
    this.onVMDetected = options.onVMDetected || (() => {});
    this.onVerificationFailed = options.onVerificationFailed || (() => {});
  }
  
  /**
   * Collect silicon identity for a node
   */
  async collectIdentity(dokoId) {
    log.info('silicon-parity', `Collecting silicon identity for ${dokoId}`);
    
    // Collect all hardware markers in parallel
    const [platformUUID, histogramData, topology] = await Promise.all([
      getPlatformUUID(),
      collectTimingHistogram(),
      Promise.resolve(detectTopology()),
    ]);
    
    // Create fingerprint from histogram
    const aesFingerprint = createFingerprint(histogramData.histogram);
    
    // Analyze jitter for VM detection
    const jitterAnalysis = analyzeJitter(histogramData.timings);
    
    // Create identity commitment
    const identityData = [
      platformUUID,
      aesFingerprint,
      topology.coreCount.toString(),
    ].join('|');
    
    const identityHash = bytesToHex(sha3_256(new TextEncoder().encode(identityData)));
    
    const identity = new SiliconIdentity({
      id: identityHash,
      platformUUID,
      aesFingerprint,
      timingHistogram: histogramData.histogram,
      jitterRatio: jitterAnalysis.jitterRatio,
      socketCount: topology.socketCount,
      coreCount: topology.coreCount,
      isRealSilicon: jitterAnalysis.isRealSilicon,
      createdAt: Date.now(),
      lastVerified: Date.now(),
      verificationCount: 1,
    });
    
    // Check for duplicate fingerprints (potential spoofing)
    if (this.fingerprintIndex.has(aesFingerprint)) {
      const existing = this.fingerprintIndex.get(aesFingerprint);
      if (!existing.has(dokoId)) {
        log.warn('silicon-parity', 
          `Duplicate fingerprint detected! ${dokoId} matches ${[...existing].join(', ')}`);
        this.onDuplicateFingerprint(dokoId, [...existing]);
      }
    }
    
    // Store identity
    this.identities.set(dokoId, identity);
    
    // Index fingerprint
    if (!this.fingerprintIndex.has(aesFingerprint)) {
      this.fingerprintIndex.set(aesFingerprint, new Set());
    }
    this.fingerprintIndex.get(aesFingerprint).add(dokoId);
    
    // Check for VM
    if (!jitterAnalysis.isRealSilicon) {
      log.warn('silicon-parity', 
        `VM/emulation detected for ${dokoId}: jitter=${(jitterAnalysis.jitterRatio * 100).toFixed(1)}%`);
      this.onVMDetected(dokoId, jitterAnalysis);
    }
    
    log.info('silicon-parity', 
      `Identity collected for ${dokoId}: ${topology.coreCount} cores, ` +
      `silicon=${jitterAnalysis.isRealSilicon}, weight=${identity.weightMultiplier.toFixed(4)}x`);
    
    return identity;
  }
  
  /**
   * Perform bitslice verification (fast epoch check)
   */
  async bitsliceVerify(dokoId) {
    const identity = this.identities.get(dokoId);
    if (!identity) {
      throw new Error(`No identity found for ${dokoId}`);
    }
    
    // Collect partial histogram (1/8th of full)
    const partialData = await collectTimingHistogram({
      ops: SILICON_CONFIG.SAMPLE_OPS,
    });
    
    const partialFingerprint = createFingerprint(partialData.histogram);
    
    // Pick random slice position
    const sliceIndex = Math.floor(Math.random() * (64 - SILICON_CONFIG.SAMPLE_SLICE_SIZE));
    
    // Compare slices
    const storedSlice = identity.aesFingerprint.slice(sliceIndex, sliceIndex + SILICON_CONFIG.SAMPLE_SLICE_SIZE);
    const currentSlice = partialFingerprint.slice(sliceIndex, sliceIndex + SILICON_CONFIG.SAMPLE_SLICE_SIZE);
    
    // Calculate Hamming distance
    const distance = this.hammingDistance(storedSlice, currentSlice);
    const match = distance <= SILICON_CONFIG.SAMPLE_MAX_DRIFT;
    
    if (match) {
      identity.lastVerified = Date.now();
      identity.verificationCount++;
    }
    
    return {
      match,
      distance,
      threshold: SILICON_CONFIG.SAMPLE_MAX_DRIFT,
      sliceIndex,
      storedSlice,
      currentSlice,
    };
  }
  
  /**
   * Perform full fingerprint verification
   */
  async fullVerify(dokoId) {
    const identity = this.identities.get(dokoId);
    if (!identity) {
      throw new Error(`No identity found for ${dokoId}`);
    }
    
    // Collect full histogram
    const histogramData = await collectTimingHistogram();
    const currentFingerprint = createFingerprint(histogramData.histogram);
    
    // Calculate drift
    const drift = this.calculateFingerprintDrift(
      identity.timingHistogram,
      histogramData.histogram
    );
    
    const match = drift < SILICON_CONFIG.DRIFT_TOLERANCE;
    
    // Re-analyze jitter
    const jitterAnalysis = analyzeJitter(histogramData.timings);
    
    if (match) {
      // Update with rolling average
      identity.timingHistogram = this.rollingAverage(
        identity.timingHistogram,
        histogramData.histogram,
        0.1 // 10% weight to new data
      );
      identity.aesFingerprint = createFingerprint(identity.timingHistogram);
      identity.lastVerified = Date.now();
      identity.verificationCount++;
      identity.jitterRatio = jitterAnalysis.jitterRatio;
      identity.isRealSilicon = jitterAnalysis.isRealSilicon;
    } else {
      log.warn('silicon-parity', 
        `Fingerprint drift exceeded for ${dokoId}: ${(drift * 100).toFixed(1)}%`);
      this.onVerificationFailed(dokoId, { drift, threshold: SILICON_CONFIG.DRIFT_TOLERANCE });
    }
    
    return {
      match,
      drift,
      threshold: SILICON_CONFIG.DRIFT_TOLERANCE,
      currentFingerprint,
      jitterAnalysis,
    };
  }
  
  /**
   * Epoch verification - called every epoch
   */
  async epochVerify(dokoId) {
    this.epochCount++;
    
    // Every Nth epoch, do full verification
    if (this.epochCount % SILICON_CONFIG.FULL_VERIFY_INTERVAL === 0) {
      return this.fullVerify(dokoId);
    }
    
    // Otherwise, bitslice sample
    return this.bitsliceVerify(dokoId);
  }
  
  /**
   * Calculate effective weight for a node
   */
  calculateWeight(dokoId, tierMaxWeight) {
    const identity = this.identities.get(dokoId);
    if (!identity) {
      // Unknown identity gets minimum weight
      return tierMaxWeight * 0.1;
    }
    
    return identity.calculateWeight(tierMaxWeight);
  }
  
  /**
   * Get identity for a node
   */
  getIdentity(dokoId) {
    return this.identities.get(dokoId);
  }
  
  /**
   * Check if fingerprint is duplicate
   */
  isDuplicateFingerprint(fingerprint, excludeDokoId = null) {
    const existing = this.fingerprintIndex.get(fingerprint);
    if (!existing) return false;
    
    if (excludeDokoId) {
      return existing.size > 1 || !existing.has(excludeDokoId);
    }
    
    return existing.size > 0;
  }
  
  /**
   * Calculate Hamming distance between two hex strings
   */
  hammingDistance(a, b) {
    let distance = 0;
    const len = Math.min(a.length, b.length);
    
    for (let i = 0; i < len; i++) {
      if (a[i] !== b[i]) distance++;
    }
    
    // Add difference in length
    distance += Math.abs(a.length - b.length);
    
    return distance;
  }
  
  /**
   * Calculate drift between two histograms
   */
  calculateFingerprintDrift(oldHist, newHist) {
    if (oldHist.length !== newHist.length) {
      return 1.0; // Max drift if sizes differ
    }
    
    let totalDiff = 0;
    for (let i = 0; i < oldHist.length; i++) {
      totalDiff += Math.abs(oldHist[i] - newHist[i]);
    }
    
    // Normalize by 2 (max possible difference per bucket is ~1)
    return totalDiff / 2;
  }
  
  /**
   * Calculate rolling average of histograms
   */
  rollingAverage(oldHist, newHist, newWeight) {
    const oldWeight = 1 - newWeight;
    return oldHist.map((old, i) => old * oldWeight + newHist[i] * newWeight);
  }
  
  /**
   * Get statistics about managed identities
   */
  getStats() {
    let realSiliconCount = 0;
    let vmCount = 0;
    let totalCores = 0;
    let multiSocketCount = 0;
    
    for (const identity of this.identities.values()) {
      if (identity.isRealSilicon) {
        realSiliconCount++;
      } else {
        vmCount++;
      }
      totalCores += identity.coreCount;
      if (identity.socketCount > 1) {
        multiSocketCount++;
      }
    }
    
    return {
      totalIdentities: this.identities.size,
      realSiliconCount,
      vmCount,
      totalCores,
      multiSocketCount,
      uniqueFingerprints: this.fingerprintIndex.size,
      epochCount: this.epochCount,
    };
  }
}

/**
 * Weight Calculator with Silicon Parity
 */
export class ParityWeightCalculator {
  constructor(siliconManager, trustRegistry) {
    this.silicon = siliconManager;
    this.trust = trustRegistry;
  }
  
  /**
   * Calculate effective weight for a node
   * Combines trust tier weight with silicon parity division
   */
  async calculateWeight(dokoId) {
    // Get tier max weight
    const tierWeight = await this.trust.getWeight(dokoId);
    
    // Apply silicon parity division
    return this.silicon.calculateWeight(dokoId, tierWeight);
  }
  
  /**
   * Calculate weighted count for attestations
   */
  async calculateWeightedCount(attestations) {
    let total = 0;
    
    for (const attestation of attestations) {
      const weight = await this.calculateWeight(attestation.attestorId);
      total += weight;
    }
    
    return total;
  }
  
  /**
   * Calculate effective network size with parity
   */
  async calculateEffectiveNetworkSize(dokoIds) {
    let total = 0;
    
    for (const dokoId of dokoIds) {
      const weight = await this.calculateWeight(dokoId);
      total += weight;
    }
    
    return total;
  }
}

/**
 * Export silicon parity messages for protocol integration
 */
export const SILICON_PARITY_MESSAGES = {
  IDENTITY_REQUEST: 'silicon:identity:request',
  IDENTITY_RESPONSE: 'silicon:identity:response',
  VERIFY_CHALLENGE: 'silicon:verify:challenge',
  VERIFY_RESPONSE: 'silicon:verify:response',
  DUPLICATE_ALERT: 'silicon:duplicate:alert',
  VM_DETECTED: 'silicon:vm:detected',
};

export default {
  SiliconIdentity,
  SiliconParityManager,
  ParityWeightCalculator,
  collectTimingHistogram,
  createFingerprint,
  getPlatformUUID,
  detectTopology,
  analyzeJitter,
  SILICON_CONFIG,
  SILICON_PARITY_MESSAGES,
};
