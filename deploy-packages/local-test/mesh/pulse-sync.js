/**
 * Yakmesh Pulse - Precision Universal Latency Sync Engine
 * 
 * The heartbeat of the mesh network that provides:
 * - Distributed liveness detection with temporal proofs
 * - Mesh health monitoring and partition detection
 * - Leader election using cryptographic timing
 * - Consensus-ready heartbeat chains
 * 
 * Key Innovation: "Heartbeats that prove themselves"
 * - Each heartbeat contains a temporal hash chain
 * - Nodes can verify liveness through cryptographic proofs
 * - Partition detection through heartbeat gap analysis
 * 
 * @module mesh/pulse-sync
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createHash } from 'crypto';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// ACCEL: Hardware-accelerated SHA3-256 (OpenSSL/SHA-NI — 4.6x faster)
import { sha3_256 } from '../utils/accel.js';

const PULSE_CONFIG = {
  // Heartbeat timing
  heartbeatIntervalMs: 1000,      // 1 second between heartbeats
  missedBeatsThreshold: 5,        // Node considered dead after 5 missed beats
  suspectThreshold: 2,            // Node suspected after 2 missed beats
  
  // Health monitoring
  healthWindowSize: 60,           // Track last 60 heartbeats
  healthyThreshold: 0.95,         // 95% heartbeat success = healthy
  degradedThreshold: 0.8,         // 80% = degraded
  
  // Partition detection
  partitionDetectionWindow: 10000, // 10s window
  minPartitionNodes: 2,           // Minimum nodes to declare partition
  
  // Leader election
  leaderElectionTimeout: 5000,    // 5s to elect leader
  termDurationMs: 30000,          // Leader term duration
  
  // Chain settings
  maxChainLength: 1000,           // Max heartbeats to keep
  chainPruneInterval: 60000,      // Prune chain every minute
};

/**
 * A single heartbeat with cryptographic proof
 */
class Heartbeat {
  constructor(options) {
    this.nodeId = options.nodeId;
    this.sequence = options.sequence || 0;
    this.timestamp = options.timestamp || Date.now();
    this.prevHash = options.prevHash || '0'.repeat(64);
    this.nonce = options.nonce || bytesToHex(randomBytes(8));
    this.meshState = options.meshState || {};
    this.hash = this._computeHash();
  }

  _computeHash() {
    const data = [
      this.nodeId,
      this.sequence.toString(),
      this.timestamp.toString(),
      this.prevHash,
      this.nonce,
      JSON.stringify(this.meshState),
    ].join(':');
    
    return bytesToHex(sha3_256(utf8ToBytes(data)));
  }

  verify() {
    return this.hash === this._computeHash();
  }

  /**
   * Verify this heartbeat chains from previous
   */
  chainsFrom(prevHeartbeat) {
    if (!prevHeartbeat) return this.sequence === 0;
    return (
      this.prevHash === prevHeartbeat.hash &&
      this.sequence === prevHeartbeat.sequence + 1 &&
      this.timestamp > prevHeartbeat.timestamp
    );
  }

  serialize() {
    return {
      nodeId: this.nodeId,
      sequence: this.sequence,
      timestamp: this.timestamp,
      prevHash: this.prevHash,
      nonce: this.nonce,
      meshState: this.meshState,
      hash: this.hash,
    };
  }

  static deserialize(obj) {
    const hb = new Heartbeat({
      nodeId: obj.nodeId,
      sequence: obj.sequence,
      timestamp: obj.timestamp,
      prevHash: obj.prevHash,
      nonce: obj.nonce,
      meshState: obj.meshState,
    });
    
    if (hb.hash !== obj.hash) {
      throw new Error('Heartbeat hash verification failed');
    }
    
    return hb;
  }
}

/**
 * Heartbeat chain for a single node
 */
class HeartbeatChain {
  constructor(nodeId) {
    this.nodeId = nodeId;
    this.chain = [];
    this.lastReceived = 0;
    this.status = 'unknown'; // unknown, alive, suspect, dead
    this.missedBeats = 0;
    this.metrics = {
      totalReceived: 0,
      totalMissed: 0,
      avgLatency: 0,
      lastLatency: 0,
    };
  }

  /**
   * Add heartbeat to chain with validation
   */
  addHeartbeat(heartbeat, receivedAt = Date.now()) {
    if (heartbeat.nodeId !== this.nodeId) {
      return { success: false, reason: 'Node ID mismatch' };
    }

    if (!heartbeat.verify()) {
      return { success: false, reason: 'Hash verification failed' };
    }

    // Verify chaining
    const lastHb = this.chain[this.chain.length - 1];
    if (lastHb && !heartbeat.chainsFrom(lastHb)) {
      // Could be a gap - check sequence
      if (heartbeat.sequence <= lastHb.sequence) {
        return { success: false, reason: 'Duplicate or old heartbeat' };
      }
      // Gap detected
      const gap = heartbeat.sequence - lastHb.sequence - 1;
      this.metrics.totalMissed += gap;
    }

    // Calculate latency
    const latency = receivedAt - heartbeat.timestamp;
    this.metrics.lastLatency = latency;
    this.metrics.avgLatency = this.metrics.totalReceived === 0
      ? latency
      : (this.metrics.avgLatency * 0.9 + latency * 0.1);

    this.chain.push(heartbeat);
    this.lastReceived = receivedAt;
    this.missedBeats = 0;
    this.status = 'alive';
    this.metrics.totalReceived++;

    // Prune old heartbeats
    while (this.chain.length > PULSE_CONFIG.maxChainLength) {
      this.chain.shift();
    }

    return { success: true, latency, sequence: heartbeat.sequence };
  }

  /**
   * Check if node has missed heartbeats
   */
  checkLiveness(currentTime = Date.now()) {
    if (this.lastReceived === 0) {
      return { status: 'unknown', missedBeats: 0 };
    }

    const elapsed = currentTime - this.lastReceived;
    const expectedBeats = Math.floor(elapsed / PULSE_CONFIG.heartbeatIntervalMs);

    if (expectedBeats > this.missedBeats) {
      this.missedBeats = expectedBeats;
      this.metrics.totalMissed += expectedBeats - this.missedBeats;
    }

    if (this.missedBeats >= PULSE_CONFIG.missedBeatsThreshold) {
      this.status = 'dead';
    } else if (this.missedBeats >= PULSE_CONFIG.suspectThreshold) {
      this.status = 'suspect';
    } else {
      this.status = 'alive';
    }

    return {
      status: this.status,
      missedBeats: this.missedBeats,
      lastReceived: this.lastReceived,
      elapsed,
    };
  }

  /**
   * Get health score (0-1)
   */
  getHealthScore() {
    const total = this.metrics.totalReceived + this.metrics.totalMissed;
    if (total === 0) return 0;
    return this.metrics.totalReceived / total;
  }

  /**
   * Get the latest N heartbeats as proof of liveness
   */
  getLivenessProof(count = 5) {
    const recent = this.chain.slice(-count);
    return {
      nodeId: this.nodeId,
      status: this.status,
      heartbeats: recent.map(h => h.serialize()),
      healthScore: this.getHealthScore(),
      metrics: { ...this.metrics },
    };
  }
}

/**
 * Mesh health monitor - tracks overall network health
 */
class MeshHealthMonitor {
  constructor() {
    this.nodes = new Map(); // nodeId -> HeartbeatChain
    this.partitions = [];
    this.healthHistory = [];
    this.alerts = [];
  }

  /**
   * Process incoming heartbeat
   */
  processHeartbeat(heartbeat, receivedAt = Date.now()) {
    if (!this.nodes.has(heartbeat.nodeId)) {
      this.nodes.set(heartbeat.nodeId, new HeartbeatChain(heartbeat.nodeId));
    }

    const chain = this.nodes.get(heartbeat.nodeId);
    return chain.addHeartbeat(heartbeat, receivedAt);
  }

  /**
   * Run liveness check on all nodes
   */
  runLivenessCheck(currentTime = Date.now()) {
    const results = {
      alive: [],
      suspect: [],
      dead: [],
      unknown: [],
    };

    for (const [nodeId, chain] of this.nodes) {
      const check = chain.checkLiveness(currentTime);
      results[check.status].push({
        nodeId,
        ...check,
        healthScore: chain.getHealthScore(),
      });
    }

    // Check for partition
    this._detectPartition(results, currentTime);

    return results;
  }

  /**
   * Detect network partition
   */
  _detectPartition(livenessResults, currentTime) {
    const deadCount = livenessResults.dead.length;
    const totalCount = this.nodes.size;

    if (deadCount >= PULSE_CONFIG.minPartitionNodes && 
        deadCount > totalCount * 0.3) {
      // Possible partition - check if dead nodes have similar last-seen times
      const deadNodes = livenessResults.dead;
      const lastSeenTimes = deadNodes.map(n => n.lastReceived);
      const avgLastSeen = lastSeenTimes.reduce((a, b) => a + b, 0) / deadNodes.length;
      const variance = lastSeenTimes.reduce((s, t) => s + Math.pow(t - avgLastSeen, 2), 0) / deadNodes.length;

      // Low variance = simultaneous failure = likely partition
      if (Math.sqrt(variance) < PULSE_CONFIG.partitionDetectionWindow) {
        const partition = {
          detectedAt: currentTime,
          affectedNodes: deadNodes.map(n => n.nodeId),
          lastSeenRange: [Math.min(...lastSeenTimes), Math.max(...lastSeenTimes)],
          confidence: 1 - (Math.sqrt(variance) / PULSE_CONFIG.partitionDetectionWindow),
        };
        this.partitions.push(partition);
        this.alerts.push({
          type: 'PARTITION_DETECTED',
          severity: 'critical',
          ...partition,
        });
      }
    }
  }

  /**
   * Get overall mesh health
   */
  getMeshHealth() {
    const liveness = this.runLivenessCheck();
    const totalNodes = this.nodes.size;

    if (totalNodes === 0) {
      return { status: 'unknown', score: 0, details: liveness };
    }

    const aliveRatio = liveness.alive.length / totalNodes;
    const avgHealthScore = Array.from(this.nodes.values())
      .reduce((sum, chain) => sum + chain.getHealthScore(), 0) / totalNodes;

    let status;
    if (aliveRatio >= PULSE_CONFIG.healthyThreshold && avgHealthScore >= PULSE_CONFIG.healthyThreshold) {
      status = 'healthy';
    } else if (aliveRatio >= PULSE_CONFIG.degradedThreshold) {
      status = 'degraded';
    } else {
      status = 'critical';
    }

    return {
      status,
      score: Math.round((aliveRatio * 0.5 + avgHealthScore * 0.5) * 100),
      details: liveness,
      partitions: this.partitions,
      alerts: this.alerts.slice(-10),
    };
  }
}

/**
 * Leader election using heartbeat timing
 */
class PulseLeaderElection {
  constructor(options = {}) {
    this.nodeId = options.nodeId;
    this.currentTerm = 0;
    this.currentLeader = null;
    this.leaderSince = null;
    this.votes = new Map();
    this.state = 'follower'; // follower, candidate, leader
    this.heartbeatChains = new Map();
  }

  /**
   * Start leader election
   */
  startElection() {
    this.currentTerm++;
    this.state = 'candidate';
    this.votes.clear();
    this.votes.set(this.nodeId, this.currentTerm); // Vote for self

    return {
      type: 'VOTE_REQUEST',
      term: this.currentTerm,
      candidateId: this.nodeId,
      lastHeartbeatSeq: this._getLastHeartbeatSeq(),
      timestamp: Date.now(),
    };
  }

  /**
   * Handle vote request
   */
  handleVoteRequest(request) {
    // Only vote if candidate has higher term or same term with better heartbeat history
    if (request.term < this.currentTerm) {
      return { voteGranted: false, term: this.currentTerm };
    }

    if (request.term > this.currentTerm) {
      this.currentTerm = request.term;
      this.state = 'follower';
      this.currentLeader = null;
    }

    // Check if we haven't voted this term
    const existingVote = this.votes.get(this.nodeId);
    if (existingVote && existingVote === this.currentTerm) {
      return { voteGranted: false, term: this.currentTerm };
    }

    // Vote for candidate with better heartbeat history
    const mySeq = this._getLastHeartbeatSeq();
    if (request.lastHeartbeatSeq >= mySeq) {
      this.votes.set(this.nodeId, this.currentTerm);
      return { voteGranted: true, term: this.currentTerm, voterId: this.nodeId };
    }

    return { voteGranted: false, term: this.currentTerm };
  }

  /**
   * Handle vote response
   */
  handleVoteResponse(response, totalNodes) {
    if (response.term > this.currentTerm) {
      this.currentTerm = response.term;
      this.state = 'follower';
      return { elected: false };
    }

    if (response.voteGranted && response.term === this.currentTerm) {
      this.votes.set(response.voterId, response.term);
    }

    // Check if we have majority
    const voteCount = Array.from(this.votes.values())
      .filter(t => t === this.currentTerm).length;

    if (voteCount > totalNodes / 2) {
      this.state = 'leader';
      this.currentLeader = this.nodeId;
      this.leaderSince = Date.now();
      return { elected: true, term: this.currentTerm };
    }

    return { elected: false, votes: voteCount, needed: Math.floor(totalNodes / 2) + 1 };
  }

  /**
   * Receive leader heartbeat (prevents election)
   */
  acknowledgeLeader(leaderId, term) {
    if (term >= this.currentTerm) {
      this.currentTerm = term;
      this.currentLeader = leaderId;
      this.state = 'follower';
      return true;
    }
    return false;
  }

  _getLastHeartbeatSeq() {
    const myChain = this.heartbeatChains.get(this.nodeId);
    if (!myChain || myChain.chain.length === 0) return 0;
    return myChain.chain[myChain.chain.length - 1].sequence;
  }

  getState() {
    return {
      nodeId: this.nodeId,
      state: this.state,
      term: this.currentTerm,
      leader: this.currentLeader,
      leaderSince: this.leaderSince,
      votes: Object.fromEntries(this.votes),
    };
  }
}

/**
 * Main PULSE sync engine
 */
class PulseSync {
  constructor(options = {}) {
    this.nodeId = options.nodeId || bytesToHex(randomBytes(16));
    this.sequence = 0;
    this.lastHeartbeat = null;
    this.healthMonitor = new MeshHealthMonitor();
    this.election = new PulseLeaderElection({ nodeId: this.nodeId });
    this.election.heartbeatChains = this.healthMonitor.nodes;
    
    this.stats = {
      heartbeatsSent: 0,
      heartbeatsReceived: 0,
      electionsStarted: 0,
      termsAsLeader: 0,
    };

    // Callbacks
    this.onHeartbeat = options.onHeartbeat || (() => {});
    this.onLeaderChange = options.onLeaderChange || (() => {});
    this.onPartitionDetected = options.onPartitionDetected || (() => {});
  }

  /**
   * Generate next heartbeat
   */
  createHeartbeat(meshState = {}) {
    const prevHash = this.lastHeartbeat ? this.lastHeartbeat.hash : '0'.repeat(64);
    
    const heartbeat = new Heartbeat({
      nodeId: this.nodeId,
      sequence: this.sequence++,
      prevHash,
      meshState: {
        ...meshState,
        isLeader: this.election.state === 'leader',
        term: this.election.currentTerm,
      },
    });

    this.lastHeartbeat = heartbeat;
    this.stats.heartbeatsSent++;

    // Also process our own heartbeat for monitoring
    this.healthMonitor.processHeartbeat(heartbeat);

    return heartbeat.serialize();
  }

  /**
   * Process received heartbeat
   */
  receiveHeartbeat(heartbeatData, receivedAt = Date.now()) {
    try {
      const heartbeat = Heartbeat.deserialize(heartbeatData);
      const result = this.healthMonitor.processHeartbeat(heartbeat, receivedAt);
      
      if (result.success) {
        this.stats.heartbeatsReceived++;
        
        // Check if this is from the leader
        if (heartbeat.meshState.isLeader) {
          this.election.acknowledgeLeader(heartbeat.nodeId, heartbeat.meshState.term);
        }
      }

      return result;
    } catch (err) {
      return { success: false, reason: err.message };
    }
  }

  /**
   * Start leader election
   */
  startElection() {
    this.stats.electionsStarted++;
    return this.election.startElection();
  }

  /**
   * Handle vote request
   */
  handleVoteRequest(request) {
    return this.election.handleVoteRequest(request);
  }

  /**
   * Handle vote response
   */
  handleVoteResponse(response) {
    const totalNodes = this.healthMonitor.nodes.size;
    const result = this.election.handleVoteResponse(response, totalNodes);
    
    if (result.elected) {
      this.stats.termsAsLeader++;
      this.onLeaderChange({ leader: this.nodeId, term: result.term });
    }

    return result;
  }

  /**
   * Get mesh health summary
   */
  getHealth() {
    return this.healthMonitor.getMeshHealth();
  }

  /**
   * Get liveness proof for this node
   */
  getLivenessProof(count = 5) {
    const chain = this.healthMonitor.nodes.get(this.nodeId);
    if (!chain) return null;
    return chain.getLivenessProof(count);
  }

  /**
   * Get full stats
   */
  getStats() {
    return {
      ...this.stats,
      election: this.election.getState(),
      health: this.healthMonitor.getMeshHealth(),
    };
  }
}

export {
  PULSE_CONFIG,
  Heartbeat,
  HeartbeatChain,
  MeshHealthMonitor,
  PulseLeaderElection,
  PulseSync,
};
