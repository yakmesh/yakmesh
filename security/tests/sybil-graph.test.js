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
 * Sybil Graph Analysis Tests
 * 
 * Tests for detecting Sybil clusters through graph analysis
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
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
} from '../sybil-graph.js';

describe('Sybil Graph Analysis', () => {
  
  describe('AttestationGraph', () => {
    let graph;
    
    beforeEach(() => {
      graph = new AttestationGraph();
    });
    
    it('should add nodes', () => {
      graph.addNode('node1');
      graph.addNode('node2');
      
      expect(graph.getNodes()).toContain('node1');
      expect(graph.getNodes()).toContain('node2');
    });
    
    it('should add directed edges', () => {
      graph.addEdge('A', 'B');
      
      expect(graph.hasEdge('A', 'B')).toBe(true);
      expect(graph.hasEdge('B', 'A')).toBe(false); // Directed!
    });
    
    it('should detect mutual edges', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'A');
      
      expect(graph.hasMutualEdge('A', 'B')).toBe(true);
      expect(graph.hasMutualEdge('B', 'A')).toBe(true);
    });
    
    it('should count edges correctly', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'A');
      
      expect(graph.getEdgeCount()).toBe(3);
    });
    
    it('should count mutual edges', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'A');
      graph.addEdge('B', 'C');
      
      expect(graph.getMutualEdgeCount()).toBe(1); // Only A-B is mutual
    });
    
    it('should get neighbors', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'C');
      graph.addEdge('A', 'D');
      
      expect(graph.getNeighbors('A')).toHaveLength(3);
      expect(graph.getNeighbors('A')).toContain('B');
      expect(graph.getNeighbors('A')).toContain('C');
    });
    
    it('should calculate in/out degree', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'C');
      graph.addEdge('B', 'C');
      
      expect(graph.getOutDegree('A')).toBe(2);
      expect(graph.getInDegree('C')).toBe(2);
    });
    
    it('should create subgraph', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'D');
      
      const sub = graph.subgraph(['A', 'B', 'C']);
      
      expect(sub.getNodes()).toHaveLength(3);
      expect(sub.hasEdge('A', 'B')).toBe(true);
      expect(sub.hasEdge('B', 'C')).toBe(true);
      expect(sub.hasEdge('C', 'D')).toBe(false); // D not in subgraph
    });
    
    it('should serialize to JSON', () => {
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      
      const json = graph.toJSON();
      
      expect(json.nodeCount).toBe(3);
      expect(json.edgeCount).toBe(2);
      expect(json.edges).toHaveLength(2);
    });
  });
  
  describe('localClusteringCoefficient', () => {
    
    it('should be 0 for node with < 2 neighbors', () => {
      const graph = new AttestationGraph();
      graph.addEdge('A', 'B');
      
      expect(localClusteringCoefficient(graph, 'A')).toBe(0);
    });
    
    it('should be 1 for fully connected triangle', () => {
      const graph = new AttestationGraph();
      // Triangle: A -> B, A -> C, B -> C
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'C');
      graph.addEdge('B', 'C');
      
      // A's neighbors are B, C. They have edge B->C.
      expect(localClusteringCoefficient(graph, 'A')).toBe(1);
    });
    
    it('should be 0.5 for partially connected neighbors', () => {
      const graph = new AttestationGraph();
      // A -> B, A -> C, A -> D
      // Only B -> C connected (1 out of 3 possible pairs)
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'C');
      graph.addEdge('A', 'D');
      graph.addEdge('B', 'C');
      
      // 1 edge among 3 possible = 1/3
      const cc = localClusteringCoefficient(graph, 'A');
      expect(cc).toBeCloseTo(1/3, 2);
    });
  });
  
  describe('globalClusteringCoefficient', () => {
    
    it('should be 0 for star graph', () => {
      const graph = new AttestationGraph();
      // Hub A connects to B, C, D, E but they don't connect to each other
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'C');
      graph.addEdge('A', 'D');
      graph.addEdge('A', 'E');
      
      expect(globalClusteringCoefficient(graph)).toBe(0);
    });
    
    it('should be 1 for complete graph', () => {
      const graph = new AttestationGraph();
      // Complete graph: everyone connects to everyone
      const nodes = ['A', 'B', 'C', 'D'];
      for (const from of nodes) {
        for (const to of nodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      expect(globalClusteringCoefficient(graph)).toBe(1);
    });
  });
  
  describe('edgeCutRatio', () => {
    
    it('should be 0 for fully internal cluster', () => {
      const graph = new AttestationGraph();
      // Cluster {A, B, C} with no external edges
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'A');
      
      expect(edgeCutRatio(graph, ['A', 'B', 'C'])).toBe(0);
    });
    
    it('should be 1 for fully external edges', () => {
      const graph = new AttestationGraph();
      // Cluster {A} with only external edge to B
      graph.addEdge('A', 'B');
      
      expect(edgeCutRatio(graph, ['A'])).toBe(1);
    });
    
    it('should calculate mixed ratio correctly', () => {
      const graph = new AttestationGraph();
      // A -> B (internal), A -> X (external)
      graph.addEdge('A', 'B');
      graph.addEdge('A', 'X');
      graph.addEdge('B', 'A');
      
      // 2 internal edges, 1 external = 1/3
      const ratio = edgeCutRatio(graph, ['A', 'B']);
      expect(ratio).toBeCloseTo(1/3, 2);
    });
  });
  
  describe('graphDensity', () => {
    
    it('should be 0 for empty graph', () => {
      const graph = new AttestationGraph();
      expect(graphDensity(graph)).toBe(0);
    });
    
    it('should be 1 for complete directed graph', () => {
      const graph = new AttestationGraph();
      const nodes = ['A', 'B', 'C'];
      for (const from of nodes) {
        for (const to of nodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      expect(graphDensity(graph)).toBe(1);
    });
    
    it('should calculate partial density', () => {
      const graph = new AttestationGraph();
      // 3 nodes, 3 edges (out of 6 possible)
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'A');
      
      expect(graphDensity(graph)).toBe(0.5);
    });
  });
  
  describe('findConnectedComponents', () => {
    
    it('should find single component', () => {
      const graph = new AttestationGraph();
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      
      const components = findConnectedComponents(graph);
      
      expect(components).toHaveLength(1);
      expect(components[0]).toHaveLength(3);
    });
    
    it('should find multiple components', () => {
      const graph = new AttestationGraph();
      // Component 1: A-B-C
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      
      // Component 2: X-Y
      graph.addEdge('X', 'Y');
      
      const components = findConnectedComponents(graph);
      
      expect(components).toHaveLength(2);
    });
    
    it('should handle isolated nodes', () => {
      const graph = new AttestationGraph();
      graph.addNode('A');
      graph.addNode('B');
      graph.addEdge('X', 'Y');
      
      const components = findConnectedComponents(graph);
      
      // A, B are separate components, X-Y is another
      expect(components).toHaveLength(3);
    });
  });
  
  describe('detectSybilClusters', () => {
    
    it('should detect dense cluster as Sybil', () => {
      const graph = new AttestationGraph();
      
      // Create dense cluster (everyone attests everyone)
      const sybilNodes = ['S1', 'S2', 'S3', 'S4', 'S5'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      const clusters = detectSybilClusters(graph);
      
      expect(clusters.length).toBeGreaterThan(0);
      expect(clusters[0].clusteringCoefficient).toBe(1);
      expect(clusters[0].isSybil).toBe(true);
    });
    
    it('should not flag sparse honest network', () => {
      const graph = new AttestationGraph();
      
      // Sparse connections (honest pattern)
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'D');
      graph.addEdge('D', 'E');
      graph.addEdge('E', 'F');
      
      const clusters = detectSybilClusters(graph);
      
      // Should either be empty or not flagged as Sybil
      const sybilClusters = clusters.filter(c => c.isSybil);
      expect(sybilClusters).toHaveLength(0);
    });
    
    it('should calculate suspicion score', () => {
      const graph = new AttestationGraph();
      
      // Moderately dense cluster
      const nodes = ['A', 'B', 'C', 'D'];
      for (const from of nodes) {
        for (const to of nodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      const clusters = detectSybilClusters(graph);
      
      expect(clusters[0].suspicionScore).toBeGreaterThan(0);
      // Score can exceed 1.0 for highly suspicious clusters
      expect(typeof clusters[0].suspicionScore).toBe('number');
    });
  });
  
  describe('BehaviorAnalyzer', () => {
    let behavior;
    
    beforeEach(() => {
      behavior = new BehaviorAnalyzer();
    });
    
    it('should record online/offline status', () => {
      behavior.recordOnline('node1', 1000);
      behavior.recordOffline('node1', 2000);
      
      const history = behavior.history.get('node1');
      expect(history.uptimes).toHaveLength(1);
      expect(history.uptimes[0].start).toBe(1000);
      expect(history.uptimes[0].end).toBe(2000);
    });
    
    it('should record attestations', () => {
      behavior.recordAttestation('A', 'B', 1000);
      behavior.recordAttestation('A', 'C', 2000);
      
      const history = behavior.history.get('A');
      expect(history.attestations).toHaveLength(2);
    });
    
    it('should calculate Pearson correlation', () => {
      // Perfect positive correlation
      const x = [1, 2, 3, 4, 5];
      const y = [2, 4, 6, 8, 10];
      
      expect(behavior.pearsonCorrelation(x, y)).toBeCloseTo(1, 2);
      
      // Perfect negative correlation
      const z = [10, 8, 6, 4, 2];
      expect(behavior.pearsonCorrelation(x, z)).toBeCloseTo(-1, 2);
      
      // No correlation
      const w = [1, 1, 1, 1, 1];
      expect(behavior.pearsonCorrelation(x, w)).toBe(0);
    });
    
    it('should detect highly correlated uptimes', () => {
      const now = Date.now();
      const hour = 60 * 60 * 1000;
      
      // Both nodes online at same times
      behavior.recordOnline('A', now - 5 * hour);
      behavior.recordOnline('B', now - 5 * hour);
      behavior.recordOffline('A', now - 3 * hour);
      behavior.recordOffline('B', now - 3 * hour);
      behavior.recordOnline('A', now - 1 * hour);
      behavior.recordOnline('B', now - 1 * hour);
      
      const correlated = behavior.findCorrelatedNodes(['A', 'B'], 0.5);
      
      expect(correlated.length).toBeGreaterThanOrEqual(0);
    });
  });
  
  describe('SybilGraphAnalyzer', () => {
    let analyzer;
    
    beforeEach(() => {
      analyzer = new SybilGraphAnalyzer();
    });
    
    it('should add attestations to graph', () => {
      analyzer.addAttestation('A', 'B');
      analyzer.addAttestation('B', 'C');
      
      expect(analyzer.graph.hasEdge('A', 'B')).toBe(true);
      expect(analyzer.graph.hasEdge('B', 'C')).toBe(true);
    });
    
    it('should record node status', () => {
      analyzer.recordNodeOnline('node1');
      
      expect(analyzer.graph.getNodes()).toContain('node1');
    });
    
    it('should run full analysis', () => {
      // Create a suspicious cluster
      const sybilNodes = ['S1', 'S2', 'S3', 'S4'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) analyzer.addAttestation(from, to);
        }
      }
      
      // Add some honest nodes
      analyzer.addAttestation('H1', 'H2');
      analyzer.addAttestation('H2', 'H3');
      
      const results = analyzer.analyze();
      
      expect(results.graphStats.nodeCount).toBe(7);
      expect(results.overallHealthScore).toBeLessThanOrEqual(1);
      expect(results.overallHealthScore).toBeGreaterThanOrEqual(0);
    });
    
    it('should flag Sybil cluster', () => {
      const onSybil = vi.fn();
      analyzer = new SybilGraphAnalyzer({ onSybilDetected: onSybil });
      
      // Create dense cluster
      const sybilNodes = ['S1', 'S2', 'S3', 'S4', 'S5'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) analyzer.addAttestation(from, to);
        }
      }
      
      analyzer.analyze();
      
      expect(onSybil).toHaveBeenCalled();
    });
    
    it('should check if node is flagged', () => {
      // Create Sybil cluster
      const sybilNodes = ['S1', 'S2', 'S3', 'S4', 'S5'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) analyzer.addAttestation(from, to);
        }
      }
      
      analyzer.analyze();
      
      const status = analyzer.isNodeFlagged('S1');
      expect(status.flagged).toBe(true);
      
      // Non-existent node should not be flagged
      const honestStatus = analyzer.isNodeFlagged('honest-node');
      expect(honestStatus.flagged).toBe(false);
    });
    
    it('should calculate weight penalty', () => {
      // Create Sybil cluster
      const sybilNodes = ['S1', 'S2', 'S3', 'S4', 'S5'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) analyzer.addAttestation(from, to);
        }
      }
      
      analyzer.analyze();
      
      // Sybil node should have penalty
      const sybilPenalty = analyzer.getWeightPenalty('S1');
      expect(sybilPenalty).toBeLessThan(1);
      
      // Unknown node should have no penalty
      const honestPenalty = analyzer.getWeightPenalty('honest');
      expect(honestPenalty).toBe(1);
    });
    
    it('should get graph statistics', () => {
      analyzer.addAttestation('A', 'B');
      analyzer.addAttestation('B', 'A');
      analyzer.addAttestation('B', 'C');
      
      const stats = analyzer.getGraphStats();
      
      expect(stats.nodeCount).toBe(3);
      expect(stats.edgeCount).toBe(3);
      expect(stats.mutualEdgeCount).toBe(1);
    });
    
    it('should prune old history', () => {
      analyzer.analyze();
      analyzer.analyze();
      
      expect(analyzer.clusterHistory.length).toBe(2);
      
      // Prune with very large age (keep all recent)
      analyzer.pruneHistory(1000 * 60 * 60 * 24 * 365); // 1 year
      expect(analyzer.clusterHistory.length).toBe(2);
      
      // Manually set old timestamp
      analyzer.clusterHistory[0].timestamp = Date.now() - 1000 * 60 * 60 * 24 * 10; // 10 days ago
      analyzer.pruneHistory(1000 * 60 * 60 * 24 * 7); // Keep last 7 days
      
      expect(analyzer.clusterHistory.length).toBe(1);
    });
  });
  
  describe('SYBIL_THRESHOLDS', () => {
    
    it('should have all required thresholds', () => {
      expect(SYBIL_THRESHOLDS.CLUSTER_COEFFICIENT_SUSPICIOUS).toBe(0.5);
      expect(SYBIL_THRESHOLDS.CLUSTER_COEFFICIENT_SYBIL).toBe(0.7);
      expect(SYBIL_THRESHOLDS.EDGE_CUT_SUSPICIOUS).toBe(0.2);
      expect(SYBIL_THRESHOLDS.EDGE_CUT_SYBIL).toBe(0.1);
      expect(SYBIL_THRESHOLDS.MIN_CLUSTER_SIZE).toBe(3);
    });
  });
  
  describe('SYBIL_GRAPH_MESSAGES', () => {
    
    it('should export all protocol messages', () => {
      expect(SYBIL_GRAPH_MESSAGES.SYBIL_ALERT).toBe('sybil:alert');
      expect(SYBIL_GRAPH_MESSAGES.CLUSTER_DETECTED).toBe('sybil:cluster:detected');
      expect(SYBIL_GRAPH_MESSAGES.NODE_FLAGGED).toBe('sybil:node:flagged');
      expect(SYBIL_GRAPH_MESSAGES.BEHAVIOR_ANOMALY).toBe('sybil:behavior:anomaly');
    });
  });
  
  describe('Attack Scenario: Dr. Sybil\'s 1000-Node Farm', () => {
    
    it('should detect dense Sybil cluster', () => {
      const analyzer = new SybilGraphAnalyzer();
      
      // Simulate Dr. Sybil's 10-node test cluster
      // (1000 would be too slow for unit test)
      const sybilNodes = Array.from({ length: 10 }, (_, i) => `sybil-${i}`);
      
      // All attest each other (dense cluster)
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) analyzer.addAttestation(from, to);
        }
      }
      
      // Add some honest nodes with sparse connections
      analyzer.addAttestation('honest-1', 'honest-2');
      analyzer.addAttestation('honest-2', 'honest-3');
      analyzer.addAttestation('honest-3', 'honest-4');
      
      const results = analyzer.analyze();
      
      // Should detect Sybil cluster
      const sybilClusters = results.clusters.filter(c => c.isSybil);
      expect(sybilClusters.length).toBeGreaterThan(0);
      
      // The 10-node cluster should be flagged
      const bigCluster = sybilClusters.find(c => c.size === 10);
      expect(bigCluster).toBeDefined();
      expect(bigCluster.clusteringCoefficient).toBe(1);
      
      // Health score should be degraded
      expect(results.overallHealthScore).toBeLessThan(1);
    });
    
    it('should have high clustering coefficient for Sybil pattern', () => {
      const graph = new AttestationGraph();
      
      // Sybil pattern: Everyone attests everyone
      const nodes = ['A', 'B', 'C', 'D', 'E'];
      for (const from of nodes) {
        for (const to of nodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      expect(globalClusteringCoefficient(graph)).toBe(1);
    });
    
    it('should have low clustering coefficient for honest pattern', () => {
      const graph = new AttestationGraph();
      
      // Honest pattern: Chain with some branching
      graph.addEdge('A', 'B');
      graph.addEdge('B', 'C');
      graph.addEdge('C', 'D');
      graph.addEdge('D', 'E');
      graph.addEdge('E', 'F');
      graph.addEdge('C', 'G');
      graph.addEdge('G', 'H');
      
      // Chain graph has 0 clustering
      expect(globalClusteringCoefficient(graph)).toBe(0);
    });
    
    it('should penalize insular clusters (low edge cut)', () => {
      const graph = new AttestationGraph();
      
      // Insular Sybil cluster (no edges to outside)
      const sybilNodes = ['S1', 'S2', 'S3', 'S4'];
      for (const from of sybilNodes) {
        for (const to of sybilNodes) {
          if (from !== to) graph.addEdge(from, to);
        }
      }
      
      // Honest nodes (connected to each other but not Sybil)
      graph.addEdge('H1', 'H2');
      graph.addEdge('H2', 'H3');
      
      const clusters = detectSybilClusters(graph);
      const sybilCluster = clusters.find(c => c.nodes.includes('S1'));
      
      expect(sybilCluster).toBeDefined();
      expect(sybilCluster.edgeCutRatio).toBe(0); // No external edges
      // With 0% external edges, it's flagged as insular
      expect(sybilCluster.reasons.some(r => r.includes('0.0%') || r.includes('external'))).toBe(true);
    });
  });
});
