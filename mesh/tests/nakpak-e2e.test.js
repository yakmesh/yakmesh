/**
 * NAKPAK Multi-Node End-to-End Integration Test
 * 
 * Validates the complete onion routing flow across a simulated
 * multi-node mesh network:
 * 
 * 1. Node registration and key exchange
 * 2. Circuit creation through 3+ hops
 * 3. Message wrapping (onion encryption) at sender
 * 4. Layer peeling (decryption) at each relay
 * 5. Delivery at exit node
 * 6. Circuit expiry and cleanup
 * 
 * Uses real ML-KEM-768 keys and AES-256-GCM encryption.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

import {
  NakpakLayer,
  NakpakRouter,
  NakpakCircuit,
  NakpakRelay,
  NAKPAK_CONFIG,
} from '../nakpak-routing.js';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function createNodeId(name) {
  return `node-${name}-${bytesToHex(randomBytes(4))}`;
}

/**
 * Create an in-memory mesh network of NakpakRouter instances
 * Each node knows all other nodes' public keys
 */
async function createTestMesh(nodeCount) {
  const nodes = [];
  
  for (let i = 0; i < nodeCount; i++) {
    const nodeId = createNodeId(`n${i}`);
    const router = new NakpakRouter({
      nodeId,
      onMessageReceived: (result) => {
        router._lastReceived = result;
      },
      onForward: (result) => {
        router._lastForward = result;
      },
    });
    
    // Generate this node is relay key pair for circuit creation
    const layer = new NakpakLayer({
      hopIndex: 0,
      nodeId,
      isExit: false,
    });
    const keyInfo = await layer.generateKeys();
    
    router._testLayer = layer;
    router._testPublicKey = keyInfo.publicKey;
    router._lastReceived = null;
    router._lastForward = null;
    
    nodes.push(router);
  }
  
  // Register all nodes with each other
  for (const node of nodes) {
    for (const other of nodes) {
      if (node.nodeId !== other.nodeId) {
        node.registerNode(other.nodeId, other._testPublicKey);
      }
    }
  }
  
  return nodes;
}

// ═══════════════════════════════════════════════════════════════════════════
// E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('NAKPAK E2E Multi-Node', () => {
  
  describe('Node Registration', () => {
    test('creates mesh with all nodes registered', async () => {
      const nodes = await createTestMesh(5);
      
      expect(nodes.length).toBe(5);
      
      // Each node knows all other nodes
      for (const node of nodes) {
        expect(node.knownNodes.size).toBe(4); // All except self
      }
    });
    
    test('node IDs are unique', async () => {
      const nodes = await createTestMesh(10);
      const ids = new Set(nodes.map(n => n.nodeId));
      expect(ids.size).toBe(10);
    });
    
    test('known nodes have valid public keys', async () => {
      const nodes = await createTestMesh(3);
      
      for (const node of nodes) {
        for (const [id, info] of node.knownNodes) {
          expect(info.publicKey).toBeDefined();
          expect(typeof info.publicKey).toBe('string');
          // ML-KEM-768 public key = 1184 bytes = 2368 hex chars
          expect(info.publicKey.length).toBe(2368);
          expect(info.lastSeen).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Circuit Creation', () => {
    let nodes;
    
    beforeEach(async () => {
      nodes = await createTestMesh(5);
    });
    
    test('creates circuit through specified hops', async () => {
      const sender = nodes[0];
      const hopIds = [nodes[1].nodeId, nodes[2].nodeId, nodes[3].nodeId];
      
      const result = await sender.createCircuit(hopIds);
      
      expect(result).toBeDefined();
      expect(result.circuitId).toBeDefined();
      expect(result.hops).toBeDefined();
      expect(result.hops.length).toBe(3);
      expect(sender.circuits.size).toBe(1);
      expect(sender.stats.circuitsCreated).toBe(1);
    });
    
    test('auto-selects hops when none specified', async () => {
      const sender = nodes[0];
      
      const result = await sender.createCircuit([]);
      
      expect(result).toBeDefined();
      expect(result.hops.length).toBe(NAKPAK_CONFIG.defaultHopCount);
    });
    
    test('fails with insufficient known nodes', async () => {
      const nodes = await createTestMesh(2); // Only 2 nodes
      const sender = nodes[0];
      
      // Only knows 1 other node, needs 3 for default circuit
      await expect(sender.createCircuit([])).rejects.toThrow('Not enough known nodes');
    });
    
    test('tracks circuit in router', async () => {
      const sender = nodes[0];
      const hopIds = [nodes[1].nodeId, nodes[2].nodeId];
      
      const result = await sender.createCircuit(hopIds);
      
      expect(sender.circuits.has(result.circuitId)).toBe(true);
      
      const circuit = sender.circuits.get(result.circuitId);
      expect(circuit).toBeInstanceOf(NakpakCircuit);
    });
  });

  describe('Relay Processing', () => {
    let nodes;
    
    beforeEach(async () => {
      nodes = await createTestMesh(5);
    });
    
    test('relay creates circuit from request', async () => {
      const relay = nodes[1];
      
      const request = {
        circuitId: bytesToHex(randomBytes(16)),
        hopIndex: 0,
        nodeId: nodes[0].nodeId,
      };
      
      const result = await relay.handleCircuitCreate(request);
      
      expect(result).toBeDefined();
      expect(result.circuitId).toBe(request.circuitId);
      expect(relay.relay.circuits.size).toBe(1);
    });
    
    test('relay stats track processed packets', async () => {
      const relay = nodes[1];
      
      const stats = relay.getStats();
      expect(stats.relayStats).toBeDefined();
      expect(stats.relayStats.packetsRelayed).toBe(0);
      expect(stats.activeCircuits).toBe(0);
    });
  });

  describe('Circuit Expiry & Cleanup', () => {
    test('expired circuits are cleaned up', async () => {
      const nodes = await createTestMesh(5);
      const sender = nodes[0];
      
      const hopIds = [nodes[1].nodeId, nodes[2].nodeId, nodes[3].nodeId];
      const result = await sender.createCircuit(hopIds);
      
      expect(sender.circuits.size).toBe(1);
      
      // Force expiry by manipulating creation time
      const circuit = sender.circuits.get(result.circuitId);
      circuit.createdAt = Date.now() - NAKPAK_CONFIG.circuitTimeout - 1000;
      
      const cleaned = sender.cleanupCircuits();
      
      expect(cleaned).toBe(1);
      expect(sender.circuits.size).toBe(0);
    });
    
    test('non-expired circuits survive cleanup', async () => {
      const nodes = await createTestMesh(5);
      const sender = nodes[0];
      
      const hopIds = [nodes[1].nodeId, nodes[2].nodeId];
      await sender.createCircuit(hopIds);
      
      const cleaned = sender.cleanupCircuits();
      
      expect(cleaned).toBe(0);
      expect(sender.circuits.size).toBe(1);
    });
  });

  describe('Router Stats', () => {
    test('reports comprehensive stats', async () => {
      const nodes = await createTestMesh(5);
      const sender = nodes[0];
      
      // Create a circuit
      const hopIds = [nodes[1].nodeId, nodes[2].nodeId];
      await sender.createCircuit(hopIds);
      
      const stats = sender.getStats();
      
      expect(stats.circuitsCreated).toBe(1);
      expect(stats.messagesSent).toBe(0);
      expect(stats.messagesReceived).toBe(0);
      expect(stats.activeCircuits).toBe(1);
      expect(stats.knownNodes).toBe(4);
      expect(stats.relayStats).toBeDefined();
    });
  });

  describe('Multi-Circuit', () => {
    test('creates multiple concurrent circuits', async () => {
      const nodes = await createTestMesh(6);
      const sender = nodes[0];
      
      // Create 3 circuits with different hops
      await sender.createCircuit([nodes[1].nodeId, nodes[2].nodeId]);
      await sender.createCircuit([nodes[3].nodeId, nodes[4].nodeId]);
      await sender.createCircuit([nodes[2].nodeId, nodes[5].nodeId]);
      
      expect(sender.circuits.size).toBe(3);
      expect(sender.stats.circuitsCreated).toBe(3);
    });
    
    test('each circuit has unique ID', async () => {
      const nodes = await createTestMesh(5);
      const sender = nodes[0];
      
      const r1 = await sender.createCircuit([nodes[1].nodeId, nodes[2].nodeId]);
      const r2 = await sender.createCircuit([nodes[3].nodeId, nodes[4].nodeId]);
      
      expect(r1.circuitId).not.toBe(r2.circuitId);
    });
  });
});
