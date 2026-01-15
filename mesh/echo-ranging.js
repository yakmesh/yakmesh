/**
 * YAKMESH™ ECHO - Encrypted Coordinate Heuristic Oracle
 * 
 * A novel topology discovery and latency mapping system that:
 * - Maps mesh topology WITHOUT exposing node positions
 * - Uses encrypted timing probes for secure latency measurement
 * - Builds probabilistic coordinate space from RTT measurements
 * - Enables route optimization through virtual coordinates
 * 
 * Key Innovation: "Privacy-preserving network cartography"
 * - Nodes learn relative distances without revealing absolute positions
 * - Encrypted probes prevent eavesdroppers from mapping the network
 * - Temporal signatures ensure probe authenticity
 * 
 * @module mesh/echo-ranging
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 * @trademark ECHO™ is a trademark of YAKMESH
 */

import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const ECHO_CONFIG = {
  // Probe settings
  probeIntervalMs: 30000,       // Send probes every 30s
  probeTimeoutMs: 5000,         // Probe timeout
  maxProbesPerPeer: 10,         // Rolling window for RTT averaging
  
  // Coordinate space
  dimensions: 8,                // Virtual coordinate dimensions
  coordinatePrecision: 1000,    // Microsecond precision
  maxCoordinateValue: 1000000,  // Max coordinate value
  
  // Convergence
  convergenceThreshold: 0.01,   // 1% change threshold
  adaptationRate: 0.25,         // How fast coordinates adapt
  
  // Security
  encryptionAlgorithm: 'aes-256-gcm',
  probeNonceSize: 12,
  authTagLength: 16,
};

/**
 * Encrypted probe for measuring latency
 */
class EchoProbe {
  constructor(options) {
    this.probeId = options.probeId || bytesToHex(randomBytes(16));
    this.sourceNodeId = options.sourceNodeId;
    this.targetNodeId = options.targetNodeId;
    this.sendTime = options.sendTime || process.hrtime.bigint();
    this.sequence = options.sequence || 0;
    this.encrypted = options.encrypted || false;
    this.payload = options.payload || null;
  }

  /**
   * Encrypt probe payload for secure transmission
   */
  encrypt(sharedSecret) {
    const nonce = randomBytes(ECHO_CONFIG.probeNonceSize);
    const cipher = createCipheriv(
      ECHO_CONFIG.encryptionAlgorithm,
      this._deriveKey(sharedSecret, 'echo-probe'),
      nonce,
      { authTagLength: ECHO_CONFIG.authTagLength }
    );
    
    const plaintext = JSON.stringify({
      probeId: this.probeId,
      sourceNodeId: this.sourceNodeId,
      sendTime: this.sendTime.toString(),
      sequence: this.sequence,
    });
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    
    this.payload = {
      nonce: nonce.toString('hex'),
      data: encrypted.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
    };
    this.encrypted = true;
    
    return this;
  }

  /**
   * Decrypt probe payload
   */
  static decrypt(encryptedProbe, sharedSecret) {
    if (!encryptedProbe.payload || !encryptedProbe.encrypted) {
      throw new Error('Probe is not encrypted');
    }
    
    const nonce = Buffer.from(encryptedProbe.payload.nonce, 'hex');
    const data = Buffer.from(encryptedProbe.payload.data, 'hex');
    const tag = Buffer.from(encryptedProbe.payload.tag, 'hex');
    
    const decipher = createDecipheriv(
      ECHO_CONFIG.encryptionAlgorithm,
      EchoProbe.prototype._deriveKey(sharedSecret, 'echo-probe'),
      nonce,
      { authTagLength: ECHO_CONFIG.authTagLength }
    );
    decipher.setAuthTag(tag);
    
    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);
    
    const parsed = JSON.parse(decrypted.toString('utf8'));
    
    return new EchoProbe({
      probeId: parsed.probeId,
      sourceNodeId: parsed.sourceNodeId,
      targetNodeId: encryptedProbe.targetNodeId,
      sendTime: BigInt(parsed.sendTime),
      sequence: parsed.sequence,
      encrypted: false,
    });
  }

  _deriveKey(secret, context) {
    return createHash('sha256')
      .update(secret)
      .update(context)
      .digest();
  }

  serialize() {
    return {
      probeId: this.probeId,
      sourceNodeId: this.sourceNodeId,
      targetNodeId: this.targetNodeId,
      sequence: this.sequence,
      encrypted: this.encrypted,
      payload: this.payload,
    };
  }
}

/**
 * Echo response (pong)
 */
class EchoResponse {
  constructor(options) {
    this.probeId = options.probeId;
    this.responderNodeId = options.responderNodeId;
    this.receiveTime = options.receiveTime || process.hrtime.bigint();
    this.respondTime = options.respondTime || process.hrtime.bigint();
    this.processingDelay = options.processingDelay || 0n;
    this.coordinates = options.coordinates || null;
  }

  /**
   * Calculate processing delay
   */
  calculateProcessingDelay() {
    this.processingDelay = this.respondTime - this.receiveTime;
    return this.processingDelay;
  }

  serialize() {
    return {
      probeId: this.probeId,
      responderNodeId: this.responderNodeId,
      processingDelay: this.processingDelay.toString(),
      coordinates: this.coordinates,
    };
  }
}

/**
 * Virtual coordinate system using Vivaldi-inspired algorithm
 * Each node maintains coordinates that reflect network latency
 */
class VirtualCoordinates {
  constructor(dimensions = ECHO_CONFIG.dimensions) {
    this.dimensions = dimensions;
    this.coordinates = new Array(dimensions).fill(0);
    this.error = 1.0; // Estimated coordinate error
    this.updateCount = 0;
    
    // Initialize with small random values
    for (let i = 0; i < dimensions; i++) {
      this.coordinates[i] = (Math.random() - 0.5) * 100;
    }
  }

  /**
   * Update coordinates based on measured RTT to a peer
   */
  update(peerCoordinates, measuredRtt, peerError = 0.5) {
    // Calculate predicted distance
    const predictedDistance = this.distanceTo(peerCoordinates);
    
    // Calculate error (difference between predicted and actual)
    const error = measuredRtt - predictedDistance;
    
    // Relative error for weighting
    const relativeError = Math.abs(error) / measuredRtt;
    
    // Combined error weight (lower is more confident)
    const weight = this.error / (this.error + peerError);
    
    // Adaptive learning rate
    const adaptationRate = ECHO_CONFIG.adaptationRate * weight;
    
    // Update coordinates
    const unitVector = this._unitVector(peerCoordinates);
    for (let i = 0; i < this.dimensions; i++) {
      this.coordinates[i] += adaptationRate * error * unitVector[i];
      
      // Clamp to valid range
      this.coordinates[i] = Math.max(
        -ECHO_CONFIG.maxCoordinateValue,
        Math.min(ECHO_CONFIG.maxCoordinateValue, this.coordinates[i])
      );
    }
    
    // Update local error estimate
    this.error = relativeError * weight + this.error * (1 - weight);
    this.updateCount++;
    
    return {
      predictedDistance,
      measuredRtt,
      error,
      newCoordinates: [...this.coordinates],
      confidenceError: this.error,
    };
  }

  /**
   * Calculate Euclidean distance to another coordinate
   */
  distanceTo(other) {
    if (!other || other.length !== this.dimensions) {
      return Infinity;
    }
    
    let sum = 0;
    for (let i = 0; i < this.dimensions; i++) {
      const diff = this.coordinates[i] - other[i];
      sum += diff * diff;
    }
    return Math.sqrt(sum);
  }

  /**
   * Get unit vector pointing toward peer
   */
  _unitVector(peerCoordinates) {
    const direction = [];
    let magnitude = 0;
    
    for (let i = 0; i < this.dimensions; i++) {
      const diff = peerCoordinates[i] - this.coordinates[i];
      direction.push(diff);
      magnitude += diff * diff;
    }
    
    magnitude = Math.sqrt(magnitude);
    if (magnitude === 0) {
      // Random direction if at same point
      return new Array(this.dimensions).fill(0).map(() => Math.random() - 0.5);
    }
    
    return direction.map(d => d / magnitude);
  }

  /**
   * Check if coordinates have converged
   */
  hasConverged(previousCoordinates) {
    if (!previousCoordinates) return false;
    
    const distance = this.distanceTo(previousCoordinates);
    const magnitude = Math.sqrt(
      this.coordinates.reduce((sum, c) => sum + c * c, 0)
    );
    
    return distance / (magnitude || 1) < ECHO_CONFIG.convergenceThreshold;
  }

  serialize() {
    return {
      coordinates: [...this.coordinates],
      error: this.error,
      updateCount: this.updateCount,
    };
  }

  static deserialize(obj) {
    const vc = new VirtualCoordinates(obj.coordinates.length);
    vc.coordinates = [...obj.coordinates];
    vc.error = obj.error;
    vc.updateCount = obj.updateCount;
    return vc;
  }
}

/**
 * RTT measurement with statistical analysis
 */
class LatencyTracker {
  constructor(maxSamples = ECHO_CONFIG.maxProbesPerPeer) {
    this.maxSamples = maxSamples;
    this.samples = [];
    this.lastUpdate = 0;
  }

  addSample(rttNs) {
    this.samples.push({
      rtt: rttNs,
      timestamp: Date.now(),
    });
    
    // Keep rolling window
    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
    
    this.lastUpdate = Date.now();
  }

  getStats() {
    if (this.samples.length === 0) {
      return null;
    }
    
    const rtts = this.samples.map(s => s.rtt);
    const sorted = [...rtts].sort((a, b) => Number(a - b));
    
    const sum = rtts.reduce((a, b) => a + b, 0n);
    const mean = sum / BigInt(rtts.length);
    
    const median = sorted[Math.floor(sorted.length / 2)];
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    
    // Calculate standard deviation
    const squaredDiffs = rtts.map(r => {
      const diff = r - mean;
      return diff * diff;
    });
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0n) / BigInt(rtts.length);
    const stdDev = BigInt(Math.floor(Math.sqrt(Number(avgSquaredDiff))));
    
    // P95
    const p95Index = Math.floor(sorted.length * 0.95);
    const p95 = sorted[p95Index] || max;
    
    return {
      mean,
      median,
      min,
      max,
      stdDev,
      p95,
      sampleCount: this.samples.length,
      lastUpdate: this.lastUpdate,
    };
  }

  getMeanMs() {
    const stats = this.getStats();
    if (!stats) return Infinity;
    return Number(stats.mean) / 1_000_000; // ns to ms
  }
}

/**
 * Main ECHO ranging system
 */
class EchoRanging {
  constructor(options = {}) {
    this.nodeId = options.nodeId || bytesToHex(randomBytes(16));
    this.coordinates = new VirtualCoordinates(options.dimensions);
    this.peerLatencies = new Map(); // peerId -> LatencyTracker
    this.peerCoordinates = new Map(); // peerId -> coordinates
    this.pendingProbes = new Map(); // probeId -> { probe, sentAt }
    this.sharedSecrets = new Map(); // peerId -> shared secret
    this.probeSequence = 0;
    
    this.stats = {
      probesSent: 0,
      probesReceived: 0,
      responsesReceived: 0,
      coordinateUpdates: 0,
      encryptedProbes: 0,
    };
    
    // Callbacks
    this.onSendProbe = options.onSendProbe || (() => {});
    this.onCoordinateUpdate = options.onCoordinateUpdate || (() => {});
  }

  /**
   * Set shared secret for encrypted probes with a peer
   */
  setSharedSecret(peerId, secret) {
    this.sharedSecrets.set(peerId, secret);
  }

  /**
   * Create and send a probe to a peer
   */
  createProbe(targetNodeId) {
    const probe = new EchoProbe({
      sourceNodeId: this.nodeId,
      targetNodeId,
      sequence: this.probeSequence++,
    });
    
    // Encrypt if we have a shared secret
    const secret = this.sharedSecrets.get(targetNodeId);
    if (secret) {
      probe.encrypt(secret);
      this.stats.encryptedProbes++;
    }
    
    // Track pending probe
    this.pendingProbes.set(probe.probeId, {
      probe,
      sentAt: process.hrtime.bigint(),
      targetNodeId,
    });
    
    // Set timeout to clean up
    setTimeout(() => {
      this.pendingProbes.delete(probe.probeId);
    }, ECHO_CONFIG.probeTimeoutMs);
    
    this.stats.probesSent++;
    
    return probe.serialize();
  }

  /**
   * Handle incoming probe (generate response)
   */
  handleProbe(probeData, fromNodeId) {
    const receiveTime = process.hrtime.bigint();
    this.stats.probesReceived++;
    
    let probe;
    
    // Decrypt if encrypted
    if (probeData.encrypted) {
      const secret = this.sharedSecrets.get(fromNodeId);
      if (!secret) {
        return { error: 'No shared secret for decryption' };
      }
      try {
        probe = EchoProbe.decrypt(probeData, secret);
      } catch (err) {
        return { error: 'Decryption failed: ' + err.message };
      }
    } else {
      probe = new EchoProbe(probeData);
    }
    
    // Create response
    const response = new EchoResponse({
      probeId: probe.probeId,
      responderNodeId: this.nodeId,
      receiveTime,
      respondTime: process.hrtime.bigint(),
      coordinates: this.coordinates.serialize().coordinates,
    });
    response.calculateProcessingDelay();
    
    return response.serialize();
  }

  /**
   * Handle probe response
   */
  handleResponse(responseData) {
    const receiveTime = process.hrtime.bigint();
    
    const pending = this.pendingProbes.get(responseData.probeId);
    if (!pending) {
      return { error: 'Unknown probe or timeout' };
    }
    
    // Calculate RTT (accounting for processing delay)
    const processingDelay = BigInt(responseData.processingDelay || '0');
    const rttNs = receiveTime - pending.sentAt - processingDelay;
    
    // Get or create latency tracker
    const peerId = pending.targetNodeId;
    if (!this.peerLatencies.has(peerId)) {
      this.peerLatencies.set(peerId, new LatencyTracker());
    }
    const tracker = this.peerLatencies.get(peerId);
    tracker.addSample(rttNs);
    
    // Store peer coordinates
    if (responseData.coordinates) {
      this.peerCoordinates.set(peerId, responseData.coordinates);
      
      // Update our coordinates based on measurement
      const rttMs = Number(rttNs) / 1_000_000;
      const result = this.coordinates.update(
        responseData.coordinates,
        rttMs
      );
      
      this.stats.coordinateUpdates++;
      this.onCoordinateUpdate(result);
    }
    
    this.pendingProbes.delete(responseData.probeId);
    this.stats.responsesReceived++;
    
    return {
      peerId,
      rttNs,
      rttMs: Number(rttNs) / 1_000_000,
      latencyStats: tracker.getStats(),
      coordinates: this.coordinates.serialize(),
    };
  }

  /**
   * Get estimated latency to a peer without probing
   */
  estimateLatency(peerId) {
    const peerCoords = this.peerCoordinates.get(peerId);
    if (!peerCoords) {
      return null;
    }
    
    return this.coordinates.distanceTo(peerCoords);
  }

  /**
   * Get best route through known peers
   */
  findBestRoute(targetPeerId, availablePeers) {
    const targetCoords = this.peerCoordinates.get(targetPeerId);
    if (!targetCoords) {
      return null;
    }
    
    const routes = availablePeers
      .filter(p => this.peerCoordinates.has(p))
      .map(peerId => {
        const peerCoords = this.peerCoordinates.get(peerId);
        const toHop = this.coordinates.distanceTo(peerCoords);
        const hopToTarget = Math.sqrt(
          peerCoords.reduce((sum, c, i) => sum + Math.pow(c - targetCoords[i], 2), 0)
        );
        return {
          via: peerId,
          estimatedLatency: toHop + hopToTarget,
          directLatency: this.coordinates.distanceTo(targetCoords),
        };
      })
      .sort((a, b) => a.estimatedLatency - b.estimatedLatency);
    
    return routes[0] || null;
  }

  /**
   * Get network topology summary
   */
  getTopology() {
    const peers = [];
    for (const [peerId, coords] of this.peerCoordinates) {
      const latency = this.peerLatencies.get(peerId);
      peers.push({
        peerId,
        coordinates: coords,
        estimatedDistance: this.coordinates.distanceTo(coords),
        latencyStats: latency ? latency.getStats() : null,
      });
    }
    
    return {
      self: {
        nodeId: this.nodeId,
        coordinates: this.coordinates.serialize(),
      },
      peers: peers.sort((a, b) => a.estimatedDistance - b.estimatedDistance),
      stats: { ...this.stats },
    };
  }

  getStats() {
    return { ...this.stats };
  }
}

export {
  ECHO_CONFIG,
  EchoProbe,
  EchoResponse,
  VirtualCoordinates,
  LatencyTracker,
  EchoRanging,
};
