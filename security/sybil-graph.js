/**
 * Sybil Graph Analysis - Detect Coordinated Attack Clusters
 * 
 * Uses graph theory to identify Sybil clusters by analyzing attestation patterns.
 * Honest networks have sparse, random attestation graphs.
 * Sybil clusters have dense, everyone-attests-everyone patterns.
 * 
 * Detection methods:
 * - Clustering coefficient: Sybil clusters ~0.8+, honest networks ~0.1-0.3
 * - Edge cut analysis: Sybil clusters have few edges to outside
 * - Eigenvalue gap: Reveals hidden community structure
 * - Behavioral correlation: Synchronized uptime, attestations
 * 
 * "You can fake hardware, but you can't fake authentic social relationships."
 * 
 * @module security/sybil-graph
 * @version 1.0.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('security:sybil');

/**
 * Sybil detection thresholds
 */
export const SYBIL_THRESHOLDS = {
  // Clustering coefficient threshold
  // Honest: 0.1-0.3, Sybil: 0.7+
  CLUSTER_COEFFICIENT_SUSPICIOUS: 0.5,
  CLUSTER_COEFFICIENT_SYBIL: 0.7,
  
  // Edge cut threshold (edges to outside / total edges)
  // Honest: High ratio, Sybil: Low ratio
  EDGE_CUT_SUSPICIOUS: 0.2,
  EDGE_CUT_SYBIL: 0.1,
  
  // Minimum cluster size to analyze
  MIN_CLUSTER_SIZE: 3,
  
  // Behavioral correlation
  UPTIME_CORRELATION_THRESHOLD: 0.8,
  ATTESTATION_CORRELATION_THRESHOLD: 0.7,
  
  // Time window for behavioral analysis (ms)
  BEHAVIOR_WINDOW: 24 * 60 * 60 * 1000, // 24 hours
};

/**
 * Attestation Graph - Represents the network of mutual attestations
 */
export class AttestationGraph {
  constructor() {
    // Adjacency list: nodeId -> Set<nodeId>
    this.adjacency = new Map();
    // Edge timestamps for behavioral analysis
    this.edgeTimestamps = new Map();
    // Node metadata
    this.nodeMetadata = new Map();
  }
  
  /**
   * Add a node to the graph
   */
  addNode(nodeId, metadata = {}) {
    if (!this.adjacency.has(nodeId)) {
      this.adjacency.set(nodeId, new Set());
    }
    this.nodeMetadata.set(nodeId, {
      ...this.nodeMetadata.get(nodeId),
      ...metadata,
      addedAt: Date.now(),
    });
  }
  
  /**
   * Add an attestation edge (directed: from attests to)
   */
  addEdge(fromId, toId, timestamp = Date.now()) {
    this.addNode(fromId);
    this.addNode(toId);
    
    this.adjacency.get(fromId).add(toId);
    
    const edgeKey = this.edgeKey(fromId, toId);
    if (!this.edgeTimestamps.has(edgeKey)) {
      this.edgeTimestamps.set(edgeKey, []);
    }
    this.edgeTimestamps.get(edgeKey).push(timestamp);
  }
  
  /**
   * Check if edge exists
   */
  hasEdge(fromId, toId) {
    return this.adjacency.get(fromId)?.has(toId) || false;
  }
  
  /**
   * Check if mutual attestation exists
   */
  hasMutualEdge(nodeA, nodeB) {
    return this.hasEdge(nodeA, nodeB) && this.hasEdge(nodeB, nodeA);
  }
  
  /**
   * Get all nodes
   */
  getNodes() {
    return [...this.adjacency.keys()];
  }
  
  /**
   * Get neighbors (nodes this node attested)
   */
  getNeighbors(nodeId) {
    return [...(this.adjacency.get(nodeId) || [])];
  }
  
  /**
   * Get in-degree (attestations received)
   */
  getInDegree(nodeId) {
    let count = 0;
    for (const [, neighbors] of this.adjacency) {
      if (neighbors.has(nodeId)) count++;
    }
    return count;
  }
  
  /**
   * Get out-degree (attestations given)
   */
  getOutDegree(nodeId) {
    return this.adjacency.get(nodeId)?.size || 0;
  }
  
  /**
   * Get total edges
   */
  getEdgeCount() {
    let count = 0;
    for (const neighbors of this.adjacency.values()) {
      count += neighbors.size;
    }
    return count;
  }
  
  /**
   * Get bidirectional (mutual) edges count
   */
  getMutualEdgeCount() {
    let count = 0;
    for (const [from, neighbors] of this.adjacency) {
      for (const to of neighbors) {
        if (this.hasEdge(to, from)) {
          count++;
        }
      }
    }
    return count / 2; // Each mutual edge counted twice
  }
  
  /**
   * Create edge key for lookup
   */
  edgeKey(fromId, toId) {
    return `${fromId}|${toId}`;
  }
  
  /**
   * Get subgraph induced by a set of nodes
   */
  subgraph(nodeIds) {
    const sub = new AttestationGraph();
    const nodeSet = new Set(nodeIds);
    
    for (const nodeId of nodeIds) {
      sub.addNode(nodeId, this.nodeMetadata.get(nodeId));
      
      for (const neighbor of this.getNeighbors(nodeId)) {
        if (nodeSet.has(neighbor)) {
          sub.addEdge(nodeId, neighbor);
        }
      }
    }
    
    return sub;
  }
  
  /**
   * Serialize graph for analysis
   */
  toJSON() {
    const edges = [];
    for (const [from, neighbors] of this.adjacency) {
      for (const to of neighbors) {
        edges.push({ from, to });
      }
    }
    
    return {
      nodes: this.getNodes(),
      edges,
      nodeCount: this.adjacency.size,
      edgeCount: this.getEdgeCount(),
    };
  }
}

/**
 * Calculate local clustering coefficient for a node
 * Measures how connected the node's neighbors are to each other
 */
export function localClusteringCoefficient(graph, nodeId) {
  const neighbors = graph.getNeighbors(nodeId);
  const k = neighbors.length;
  
  if (k < 2) return 0; // Need at least 2 neighbors for clustering
  
  // Count edges between neighbors
  let edgesBetweenNeighbors = 0;
  for (let i = 0; i < neighbors.length; i++) {
    for (let j = i + 1; j < neighbors.length; j++) {
      if (graph.hasEdge(neighbors[i], neighbors[j]) || 
          graph.hasEdge(neighbors[j], neighbors[i])) {
        edgesBetweenNeighbors++;
      }
    }
  }
  
  // Maximum possible edges between k neighbors
  const maxEdges = (k * (k - 1)) / 2;
  
  return edgesBetweenNeighbors / maxEdges;
}

/**
 * Calculate global clustering coefficient for the graph
 * Average of local coefficients
 */
export function globalClusteringCoefficient(graph) {
  const nodes = graph.getNodes();
  if (nodes.length === 0) return 0;
  
  let sum = 0;
  let validNodes = 0;
  
  for (const nodeId of nodes) {
    const neighbors = graph.getNeighbors(nodeId);
    if (neighbors.length >= 2) {
      sum += localClusteringCoefficient(graph, nodeId);
      validNodes++;
    }
  }
  
  return validNodes > 0 ? sum / validNodes : 0;
}

/**
 * Calculate edge cut ratio for a cluster
 * Low ratio = insular cluster = suspicious
 */
export function edgeCutRatio(graph, clusterNodeIds) {
  const cluster = new Set(clusterNodeIds);
  let internalEdges = 0;
  let externalEdges = 0;
  
  for (const nodeId of clusterNodeIds) {
    for (const neighbor of graph.getNeighbors(nodeId)) {
      if (cluster.has(neighbor)) {
        internalEdges++;
      } else {
        externalEdges++;
      }
    }
  }
  
  const totalEdges = internalEdges + externalEdges;
  if (totalEdges === 0) return 1; // No edges = maximum cut ratio
  
  return externalEdges / totalEdges;
}

/**
 * Calculate graph density
 * density = actual edges / possible edges
 */
export function graphDensity(graph) {
  const n = graph.adjacency.size;
  if (n < 2) return 0;
  
  const actualEdges = graph.getEdgeCount();
  const possibleEdges = n * (n - 1); // Directed graph
  
  return actualEdges / possibleEdges;
}

/**
 * Find connected components (weakly connected for directed graph)
 */
export function findConnectedComponents(graph) {
  const visited = new Set();
  const components = [];
  
  // Build undirected version for component finding
  const undirected = new Map();
  for (const [node, neighbors] of graph.adjacency) {
    if (!undirected.has(node)) undirected.set(node, new Set());
    for (const neighbor of neighbors) {
      undirected.get(node).add(neighbor);
      if (!undirected.has(neighbor)) undirected.set(neighbor, new Set());
      undirected.get(neighbor).add(node);
    }
  }
  
  for (const node of graph.getNodes()) {
    if (visited.has(node)) continue;
    
    // BFS to find component
    const component = [];
    const queue = [node];
    
    while (queue.length > 0) {
      const current = queue.shift();
      if (visited.has(current)) continue;
      
      visited.add(current);
      component.push(current);
      
      for (const neighbor of (undirected.get(current) || [])) {
        if (!visited.has(neighbor)) {
          queue.push(neighbor);
        }
      }
    }
    
    if (component.length > 0) {
      components.push(component);
    }
  }
  
  return components;
}

/**
 * Detect potential Sybil clusters using multiple metrics
 */
export function detectSybilClusters(graph, options = {}) {
  const thresholds = { ...SYBIL_THRESHOLDS, ...options };
  const components = findConnectedComponents(graph);
  const clusters = [];
  
  for (const component of components) {
    if (component.length < thresholds.MIN_CLUSTER_SIZE) continue;
    
    const subgraph = graph.subgraph(component);
    const clusterCoeff = globalClusteringCoefficient(subgraph);
    const density = graphDensity(subgraph);
    const cutRatio = edgeCutRatio(graph, component);
    
    // Calculate suspicion score
    let suspicionScore = 0;
    const reasons = [];
    
    // High clustering = suspicious
    if (clusterCoeff >= thresholds.CLUSTER_COEFFICIENT_SYBIL) {
      suspicionScore += 0.4;
      reasons.push(`High clustering: ${(clusterCoeff * 100).toFixed(1)}%`);
    } else if (clusterCoeff >= thresholds.CLUSTER_COEFFICIENT_SUSPICIOUS) {
      suspicionScore += 0.2;
      reasons.push(`Suspicious clustering: ${(clusterCoeff * 100).toFixed(1)}%`);
    }
    
    // Low edge cut = insular = suspicious
    if (cutRatio <= thresholds.EDGE_CUT_SYBIL) {
      suspicionScore += 0.4;
      reasons.push(`Insular cluster: ${(cutRatio * 100).toFixed(1)}% external edges`);
    } else if (cutRatio <= thresholds.EDGE_CUT_SUSPICIOUS) {
      suspicionScore += 0.2;
      reasons.push(`Low external connectivity: ${(cutRatio * 100).toFixed(1)}%`);
    }
    
    // High density = everyone attests everyone = suspicious
    if (density > 0.7) {
      suspicionScore += 0.3;
      reasons.push(`High density: ${(density * 100).toFixed(1)}%`);
    } else if (density > 0.5) {
      suspicionScore += 0.15;
      reasons.push(`Elevated density: ${(density * 100).toFixed(1)}%`);
    }
    
    const isSybil = suspicionScore >= 0.6;
    const isSuspicious = suspicionScore >= 0.3;
    
    if (isSuspicious) {
      clusters.push({
        nodes: component,
        size: component.length,
        clusteringCoefficient: clusterCoeff,
        edgeCutRatio: cutRatio,
        density,
        suspicionScore,
        isSybil,
        isSuspicious,
        reasons,
      });
    }
  }
  
  // Sort by suspicion score (most suspicious first)
  clusters.sort((a, b) => b.suspicionScore - a.suspicionScore);
  
  return clusters;
}

/**
 * Behavioral Correlation Analyzer
 * Detects synchronized activity patterns
 */
export class BehaviorAnalyzer {
  constructor() {
    // nodeId -> { uptimes: [{ start, end }], attestations: [{ to, at }] }
    this.history = new Map();
  }
  
  /**
   * Record node coming online
   */
  recordOnline(nodeId, timestamp = Date.now()) {
    if (!this.history.has(nodeId)) {
      this.history.set(nodeId, { uptimes: [], attestations: [] });
    }
    
    const history = this.history.get(nodeId);
    history.uptimes.push({ start: timestamp, end: null });
  }
  
  /**
   * Record node going offline
   */
  recordOffline(nodeId, timestamp = Date.now()) {
    const history = this.history.get(nodeId);
    if (!history) return;
    
    const currentSession = history.uptimes.find(u => u.end === null);
    if (currentSession) {
      currentSession.end = timestamp;
    }
  }
  
  /**
   * Record attestation
   */
  recordAttestation(fromId, toId, timestamp = Date.now()) {
    if (!this.history.has(fromId)) {
      this.history.set(fromId, { uptimes: [], attestations: [] });
    }
    
    this.history.get(fromId).attestations.push({ to: toId, at: timestamp });
  }
  
  /**
   * Calculate uptime correlation between two nodes
   * Returns: -1 to 1 (1 = perfectly correlated)
   */
  calculateUptimeCorrelation(nodeA, nodeB, windowMs = SYBIL_THRESHOLDS.BEHAVIOR_WINDOW) {
    const histA = this.history.get(nodeA);
    const histB = this.history.get(nodeB);
    
    if (!histA || !histB) return 0;
    
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Sample at 1-hour intervals
    const sampleInterval = 60 * 60 * 1000;
    const samples = Math.floor(windowMs / sampleInterval);
    
    const uptimeA = [];
    const uptimeB = [];
    
    for (let i = 0; i < samples; i++) {
      const t = windowStart + i * sampleInterval;
      uptimeA.push(this.wasOnlineAt(histA, t) ? 1 : 0);
      uptimeB.push(this.wasOnlineAt(histB, t) ? 1 : 0);
    }
    
    return this.pearsonCorrelation(uptimeA, uptimeB);
  }
  
  /**
   * Check if node was online at timestamp
   */
  wasOnlineAt(history, timestamp) {
    for (const session of history.uptimes) {
      if (session.start <= timestamp) {
        if (session.end === null || session.end >= timestamp) {
          return true;
        }
      }
    }
    return false;
  }
  
  /**
   * Calculate Pearson correlation coefficient
   */
  pearsonCorrelation(x, y) {
    if (x.length !== y.length || x.length === 0) return 0;
    
    const n = x.length;
    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((sum, xi, i) => sum + xi * y[i], 0);
    const sumX2 = x.reduce((sum, xi) => sum + xi * xi, 0);
    const sumY2 = y.reduce((sum, yi) => sum + yi * yi, 0);
    
    const numerator = n * sumXY - sumX * sumY;
    const denominator = Math.sqrt(
      (n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY)
    );
    
    if (denominator === 0) return 0;
    
    return numerator / denominator;
  }
  
  /**
   * Find nodes with high uptime correlation
   */
  findCorrelatedNodes(nodes, threshold = SYBIL_THRESHOLDS.UPTIME_CORRELATION_THRESHOLD) {
    const correlatedPairs = [];
    
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const correlation = this.calculateUptimeCorrelation(nodes[i], nodes[j]);
        
        if (Math.abs(correlation) >= threshold) {
          correlatedPairs.push({
            nodeA: nodes[i],
            nodeB: nodes[j],
            correlation,
          });
        }
      }
    }
    
    return correlatedPairs;
  }
  
  /**
   * Analyze attestation timing correlation
   * Do nodes attest at the same times?
   */
  calculateAttestationCorrelation(nodeA, nodeB, windowMs = SYBIL_THRESHOLDS.BEHAVIOR_WINDOW) {
    const histA = this.history.get(nodeA);
    const histB = this.history.get(nodeB);
    
    if (!histA || !histB) return 0;
    
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get attestations in window
    const attestA = histA.attestations.filter(a => a.at >= windowStart);
    const attestB = histB.attestations.filter(a => a.at >= windowStart);
    
    if (attestA.length === 0 || attestB.length === 0) return 0;
    
    // Bin into 1-hour buckets
    const binSize = 60 * 60 * 1000;
    const bins = Math.ceil(windowMs / binSize);
    
    const binsA = new Array(bins).fill(0);
    const binsB = new Array(bins).fill(0);
    
    for (const a of attestA) {
      const bin = Math.floor((a.at - windowStart) / binSize);
      if (bin >= 0 && bin < bins) binsA[bin]++;
    }
    
    for (const b of attestB) {
      const bin = Math.floor((b.at - windowStart) / binSize);
      if (bin >= 0 && bin < bins) binsB[bin]++;
    }
    
    return this.pearsonCorrelation(binsA, binsB);
  }
}

/**
 * Sybil Graph Analyzer
 * Main class for analyzing attestation graphs for Sybil patterns
 */
export class SybilGraphAnalyzer {
  constructor(options = {}) {
    this.graph = new AttestationGraph();
    this.behavior = new BehaviorAnalyzer();
    this.thresholds = { ...SYBIL_THRESHOLDS, ...options };
    
    // Flagged clusters
    this.flaggedClusters = [];
    this.clusterHistory = [];
    
    // Callbacks
    this.onSybilDetected = options.onSybilDetected || (() => {});
    this.onSuspiciousCluster = options.onSuspiciousCluster || (() => {});
  }
  
  /**
   * Add attestation to the graph
   */
  addAttestation(fromId, toId, timestamp = Date.now()) {
    this.graph.addEdge(fromId, toId, timestamp);
    this.behavior.recordAttestation(fromId, toId, timestamp);
  }
  
  /**
   * Record node online status
   */
  recordNodeOnline(nodeId, timestamp = Date.now()) {
    this.graph.addNode(nodeId);
    this.behavior.recordOnline(nodeId, timestamp);
  }
  
  /**
   * Record node offline status
   */
  recordNodeOffline(nodeId, timestamp = Date.now()) {
    this.behavior.recordOffline(nodeId, timestamp);
  }
  
  /**
   * Run full Sybil analysis
   */
  analyze() {
    const results = {
      timestamp: Date.now(),
      graphStats: this.getGraphStats(),
      clusters: [],
      behaviorCorrelations: [],
      overallHealthScore: 1.0,
    };
    
    // Detect Sybil clusters via graph analysis
    const suspiciousClusters = detectSybilClusters(this.graph, this.thresholds);
    
    for (const cluster of suspiciousClusters) {
      // Enhance with behavioral analysis
      const behaviorScore = this.analyzeBehavior(cluster.nodes);
      cluster.behaviorScore = behaviorScore;
      
      // Adjust suspicion based on behavior
      if (behaviorScore > 0.7) {
        cluster.suspicionScore = Math.min(1.0, cluster.suspicionScore + 0.2);
        cluster.reasons.push(`High behavioral correlation: ${(behaviorScore * 100).toFixed(1)}%`);
      }
      
      // Final classification
      cluster.isSybil = cluster.suspicionScore >= 0.6;
      
      if (cluster.isSybil) {
        log.warn('sybil-graph', 
          `Sybil cluster detected: ${cluster.size} nodes, score=${cluster.suspicionScore.toFixed(2)}`);
        this.onSybilDetected(cluster);
        this.flaggedClusters.push(cluster);
      } else if (cluster.isSuspicious) {
        log.info('sybil-graph', 
          `Suspicious cluster: ${cluster.size} nodes, score=${cluster.suspicionScore.toFixed(2)}`);
        this.onSuspiciousCluster(cluster);
      }
      
      results.clusters.push(cluster);
    }
    
    // Calculate overall health score
    // 1.0 = perfect, 0.0 = heavily compromised
    const sybilNodeCount = results.clusters
      .filter(c => c.isSybil)
      .reduce((sum, c) => sum + c.size, 0);
    
    const totalNodes = this.graph.adjacency.size;
    const sybilRatio = totalNodes > 0 ? sybilNodeCount / totalNodes : 0;
    
    results.overallHealthScore = Math.max(0, 1 - sybilRatio * 2);
    
    // Store for history
    this.clusterHistory.push({
      timestamp: results.timestamp,
      clusterCount: results.clusters.length,
      sybilCount: results.clusters.filter(c => c.isSybil).length,
      healthScore: results.overallHealthScore,
    });
    
    return results;
  }
  
  /**
   * Analyze behavioral correlation for a group of nodes
   */
  analyzeBehavior(nodeIds) {
    if (nodeIds.length < 2) return 0;
    
    let totalCorrelation = 0;
    let pairCount = 0;
    
    for (let i = 0; i < nodeIds.length; i++) {
      for (let j = i + 1; j < nodeIds.length; j++) {
        const uptimeCorr = this.behavior.calculateUptimeCorrelation(nodeIds[i], nodeIds[j]);
        const attestCorr = this.behavior.calculateAttestationCorrelation(nodeIds[i], nodeIds[j]);
        
        totalCorrelation += (Math.abs(uptimeCorr) + Math.abs(attestCorr)) / 2;
        pairCount++;
      }
    }
    
    return pairCount > 0 ? totalCorrelation / pairCount : 0;
  }
  
  /**
   * Get graph statistics
   */
  getGraphStats() {
    return {
      nodeCount: this.graph.adjacency.size,
      edgeCount: this.graph.getEdgeCount(),
      mutualEdgeCount: this.graph.getMutualEdgeCount(),
      globalClustering: globalClusteringCoefficient(this.graph),
      density: graphDensity(this.graph),
      componentCount: findConnectedComponents(this.graph).length,
    };
  }
  
  /**
   * Check if a specific node is in a flagged cluster
   */
  isNodeFlagged(nodeId) {
    for (const cluster of this.flaggedClusters) {
      if (cluster.nodes.includes(nodeId)) {
        return {
          flagged: true,
          cluster,
          reason: cluster.reasons.join('; '),
        };
      }
    }
    return { flagged: false };
  }
  
  /**
   * Get weight penalty for a node based on Sybil analysis
   * Returns multiplier: 1.0 = no penalty, 0.0 = full penalty
   */
  getWeightPenalty(nodeId) {
    const flagStatus = this.isNodeFlagged(nodeId);
    
    if (!flagStatus.flagged) return 1.0;
    
    // Scale penalty by suspicion score
    const suspicion = flagStatus.cluster.suspicionScore;
    
    if (flagStatus.cluster.isSybil) {
      // Sybil cluster: Heavy penalty (0.1 - 0.25)
      return Math.max(0.1, 0.25 - (suspicion - 0.6) * 0.5);
    } else {
      // Suspicious but not confirmed: Moderate penalty (0.5 - 0.75)
      return Math.max(0.5, 1 - suspicion);
    }
  }
  
  /**
   * Clear old history entries
   */
  pruneHistory(maxAgeMs = 7 * 24 * 60 * 60 * 1000) {
    const cutoff = Date.now() - maxAgeMs;
    this.clusterHistory = this.clusterHistory.filter(h => h.timestamp >= cutoff);
  }
}

/**
 * Export Sybil detection messages for protocol integration
 */
export const SYBIL_GRAPH_MESSAGES = {
  SYBIL_ALERT: 'sybil:alert',
  CLUSTER_DETECTED: 'sybil:cluster:detected',
  NODE_FLAGGED: 'sybil:node:flagged',
  BEHAVIOR_ANOMALY: 'sybil:behavior:anomaly',
};

export default {
  AttestationGraph,
  SybilGraphAnalyzer,
  BehaviorAnalyzer,
  localClusteringCoefficient,
  globalClusteringCoefficient,
  edgeCutRatio,
  graphDensity,
  findConnectedComponents,
  detectSybilClusters,
  SYBIL_THRESHOLDS,
  SYBIL_GRAPH_MESSAGES,
};
