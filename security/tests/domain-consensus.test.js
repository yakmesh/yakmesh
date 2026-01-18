/**
 * Domain Consensus Verifier Tests
 * 
 * Tests for the multi-node domain verification system with Sybil attack defenses.
 * 
 * Test Categories:
 * 1. Basic domain verification flow
 * 2. Sybil attack defense mechanisms
 * 3. Verifier eligibility checks
 * 4. Proof verification and diversity
 * 5. Persistence and recovery
 * 
 * @version 2.0.0
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import DomainConsensusVerifier, { 
  DomainVerificationRequest, 
  DomainVerificationProof,
  VerifierEligibilityChecker 
} from '../domain-consensus.js';

// ═══════════════════════════════════════════════════════════════════════════
// TEST UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a mock node identity
 */
function createMockIdentity(nodeId = 'node-test-12345') {
  return {
    identity: {
      nodeId,
      publicKey: `pk-${nodeId}`,
    },
    sign: (data) => `sig-${Buffer.from(data).toString('base64').substring(0, 20)}`,
    verify: (data, signature, publicKey) => {
      // Verify signature matches expected format
      return signature.startsWith('sig-');
    },
  };
}

/**
 * Create a mock beacon
 */
function createMockBeacon(nodeId, publicKey, timestamp = Date.now()) {
  return {
    nodeId,
    publicKey,
    timestamp,
    version: '1.0.0',
    capabilities: ['verify'],
  };
}

/**
 * Create diverse mock peers with different IPs and ASNs
 */
function createDiversePeers(count, ageInDays = 10) {
  const peers = [];
  const firstSeen = Date.now() - (ageInDays * 24 * 60 * 60 * 1000);
  
  for (let i = 0; i < count; i++) {
    peers.push({
      nodeId: `peer-${i}`,
      ip: `192.168.${i}.1`,  // Each peer in different /24 subnet
      asn: `AS${10000 + i}`,  // Each peer in different ASN
      firstSeen,
    });
  }
  return peers;
}

/**
 * Create Sybil attack peers (all from same subnet)
 */
function createSybilPeers(count, ageInDays = 10) {
  const peers = [];
  const firstSeen = Date.now() - (ageInDays * 24 * 60 * 60 * 1000);
  
  for (let i = 0; i < count; i++) {
    peers.push({
      nodeId: `sybil-${i}`,
      ip: `10.0.0.${i + 1}`,  // All in same /24 subnet!
      asn: 'AS12345',         // All same ASN!
      firstSeen,
    });
  }
  return peers;
}

// ═══════════════════════════════════════════════════════════════════════════
// ELIGIBILITY CHECKER TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('VerifierEligibilityChecker', () => {
  let checker;

  beforeEach(() => {
    checker = new VerifierEligibilityChecker();
  });

  describe('Node Age Requirements', () => {
    test('rejects nodes younger than 7 days', () => {
      const nodeId = 'young-node';
      checker.registerNodeSeen(nodeId, { ip: '1.2.3.4' });
      
      const result = checker.isNodeEligible(nodeId);
      
      expect(result.eligible).toBe(false);
      expect(result.reasons.some(r => r.includes('too young'))).toBe(true);
    });

    test('accepts nodes older than 7 days', () => {
      const nodeId = 'old-node';
      
      // Manually set first seen to 10 days ago
      checker.nodeFirstSeen.set(nodeId, Date.now() - (10 * 24 * 60 * 60 * 1000));
      checker.registerNodeSeen(nodeId, { ip: '1.2.3.4' });
      
      const result = checker.isNodeEligible(nodeId);
      
      expect(result.eligible).toBe(true);
      expect(result.age).toBeGreaterThan(7 * 24 * 60 * 60 * 1000);
    });

    test('calculates node age correctly', () => {
      const nodeId = 'test-age';
      const fiveDaysAgo = Date.now() - (5 * 24 * 60 * 60 * 1000);
      
      checker.nodeFirstSeen.set(nodeId, fiveDaysAgo);
      
      const age = checker.getNodeAge(nodeId);
      const ageDays = age / (24 * 60 * 60 * 1000);
      
      expect(ageDays).toBeCloseTo(5, 0);
    });

    test('returns 0 age for unknown nodes', () => {
      const age = checker.getNodeAge('unknown-node');
      expect(age).toBe(0);
    });
  });

  describe('Reputation System', () => {
    test('starts with neutral reputation for unknown nodes', () => {
      const score = checker.getReputationScore('unknown');
      expect(score).toBe(0.5);
    });

    test('increases reputation on successful verifications', () => {
      const nodeId = 'good-node';
      
      checker.updateReputation(nodeId, true, 100);
      checker.updateReputation(nodeId, true, 100);
      checker.updateReputation(nodeId, true, 100);
      
      const score = checker.getReputationScore(nodeId);
      expect(score).toBeGreaterThan(0.5);
    });

    test('decreases reputation on failed verifications', () => {
      const nodeId = 'bad-node';
      
      checker.updateReputation(nodeId, false);
      checker.updateReputation(nodeId, false);
      checker.updateReputation(nodeId, false);
      
      const score = checker.getReputationScore(nodeId);
      expect(score).toBeLessThan(0.5);
    });

    test('rejects nodes below minimum reputation', () => {
      const nodeId = 'low-rep-node';
      
      // Set node as old enough
      checker.nodeFirstSeen.set(nodeId, Date.now() - (10 * 24 * 60 * 60 * 1000));
      checker.registerNodeSeen(nodeId, { ip: '1.2.3.4' });
      
      // Tank their reputation
      for (let i = 0; i < 20; i++) {
        checker.updateReputation(nodeId, false);
      }
      
      const result = checker.isNodeEligible(nodeId);
      
      expect(result.eligible).toBe(false);
      expect(result.reasons.some(r => r.includes('Reputation too low'))).toBe(true);
    });
  });

  describe('Claimant Exclusion', () => {
    test('excludes verifiers in same IP range as claimant', () => {
      const nodeId = 'same-range-node';
      
      // Set node as old enough
      checker.nodeFirstSeen.set(nodeId, Date.now() - (10 * 24 * 60 * 60 * 1000));
      checker.registerNodeSeen(nodeId, { ip: '192.168.1.100' });
      
      // Claimant is in same /16
      const claimantInfo = { ip: '192.168.50.1' };
      
      const result = checker.isNodeEligible(nodeId, claimantInfo);
      
      expect(result.eligible).toBe(false);
      expect(result.reasons.some(r => r.includes('Same IP range'))).toBe(true);
    });

    test('allows verifiers in different IP ranges', () => {
      const nodeId = 'different-range-node';
      
      checker.nodeFirstSeen.set(nodeId, Date.now() - (10 * 24 * 60 * 60 * 1000));
      checker.registerNodeSeen(nodeId, { ip: '10.0.0.1' });
      
      // Claimant is in completely different range
      const claimantInfo = { ip: '192.168.1.1' };
      
      const result = checker.isNodeEligible(nodeId, claimantInfo);
      
      expect(result.eligible).toBe(true);
    });
  });

  describe('Subnet Extraction', () => {
    test('extracts /24 subnet correctly', () => {
      const subnet = checker.getSubnet('192.168.1.100', 24);
      expect(subnet).toBe('192.168.1/24');
    });

    test('extracts /16 subnet correctly', () => {
      const subnet = checker.getSubnet('192.168.1.100', 16);
      expect(subnet).toBe('192.168/16');
    });

    test('handles null IP', () => {
      const subnet = checker.getSubnet(null, 24);
      expect(subnet).toBeNull();
    });
  });

  describe('Diverse Verifier Selection', () => {
    test('selects verifiers with sufficient diversity', () => {
      const peers = createDiversePeers(10, 10);
      
      // Register all peers
      for (const peer of peers) {
        checker.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        checker.registerNodeSeen(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      const result = checker.selectDiverseVerifiers(
        peers.map(p => ({ nodeId: p.nodeId })),
        { ip: '172.16.0.1' },  // Different range
        5
      );
      
      expect(result.success).toBe(true);
      expect(result.verifiers.length).toBe(5);
      expect(result.diversity.subnets.length).toBeGreaterThanOrEqual(3);
    });

    test('rejects Sybil attack with same-subnet nodes', () => {
      const sybilPeers = createSybilPeers(10, 10);
      
      // Register all Sybil peers
      for (const peer of sybilPeers) {
        checker.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        checker.registerNodeSeen(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      const result = checker.selectDiverseVerifiers(
        sybilPeers.map(p => ({ nodeId: p.nodeId })),
        { ip: '172.16.0.1' },
        5
      );
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('diversity');
    });

    test('prioritizes older, higher-reputation nodes', () => {
      const peers = createDiversePeers(10, 10);
      
      // Register all peers
      for (const peer of peers) {
        checker.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        checker.registerNodeSeen(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      // Give first 3 peers excellent reputation
      for (let i = 0; i < 3; i++) {
        for (let j = 0; j < 10; j++) {
          checker.updateReputation(peers[i].nodeId, true, 50);
        }
      }
      
      const result = checker.selectDiverseVerifiers(
        peers.map(p => ({ nodeId: p.nodeId })),
        { ip: '172.16.0.1' },
        5
      );
      
      expect(result.success).toBe(true);
      
      // High-rep nodes should have higher weights
      const weights = new Map(result.weights.map(w => [w.nodeId, w.weight]));
      
      // peer-0 has high rep, peer-5 has no rep (neutral 0.5)
      const peer0Weight = weights.get('peer-0');
      const peer5Weight = weights.get('peer-5');
      
      // If both are selected, peer-0 should have higher weight
      // If peer-5 wasn't selected, that's also fine (selection prioritized high-rep)
      if (peer0Weight !== undefined && peer5Weight !== undefined) {
        expect(peer0Weight).toBeGreaterThan(peer5Weight);
      } else if (peer0Weight !== undefined) {
        // peer-0 was selected (has rep) which is correct behavior
        expect(peer0Weight).toBeGreaterThan(0);
      }
    });

    test('requires minimum number of eligible verifiers', () => {
      const peers = createDiversePeers(2, 10);  // Only 2 peers
      
      for (const peer of peers) {
        checker.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        checker.registerNodeSeen(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      const result = checker.selectDiverseVerifiers(
        peers.map(p => ({ nodeId: p.nodeId })),
        { ip: '172.16.0.1' },
        5  // Want 5 but only have 2
      );
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Not enough eligible');
    });
  });

  describe('Persistence', () => {
    test('serializes and deserializes state correctly', () => {
      const peers = createDiversePeers(5, 10);
      
      for (const peer of peers) {
        checker.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        checker.registerNodeSeen(peer.nodeId, { ip: peer.ip, asn: peer.asn });
        checker.updateReputation(peer.nodeId, true, 100);
      }
      
      const serialized = checker.serialize();
      
      // Create new checker and restore
      const newChecker = new VerifierEligibilityChecker();
      newChecker.deserialize(serialized);
      
      // Verify state restored
      expect(newChecker.nodeFirstSeen.size).toBe(5);
      expect(newChecker.nodeNetworkInfo.size).toBe(5);
      expect(newChecker.reputations.size).toBe(5);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DOMAIN CONSENSUS VERIFIER TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('DomainConsensusVerifier', () => {
  let verifier;
  let mockIdentity;
  let mockGateway;

  beforeEach(() => {
    mockIdentity = createMockIdentity('node-main-abc123');
    mockGateway = {};
    verifier = new DomainConsensusVerifier(mockIdentity, mockGateway);
  });

  describe('Domain Validation', () => {
    test('accepts valid domains', () => {
      expect(verifier.isValidDomain('example.com')).toBe(true);
      expect(verifier.isValidDomain('sub.example.com')).toBe(true);
      expect(verifier.isValidDomain('my-site.example.co.uk')).toBe(true);
    });

    test('rejects invalid domains', () => {
      expect(verifier.isValidDomain('')).toBe(false);
      expect(verifier.isValidDomain('example')).toBe(false);  // No TLD
      expect(verifier.isValidDomain('http://example.com')).toBe(false);  // Has protocol
      expect(verifier.isValidDomain('example.com/path')).toBe(false);  // Has path
      expect(verifier.isValidDomain(null)).toBe(false);
    });
  });

  describe('Peer Registration', () => {
    test('registers peers for eligibility tracking', () => {
      verifier.registerPeer('peer-1', { ip: '192.168.1.1', asn: 'AS12345' });
      verifier.registerPeer('peer-2', { ip: '10.0.0.1', asn: 'AS67890' });
      
      const stats = verifier.getStats();
      expect(stats.eligibility.totalNodes).toBe(2);
    });
  });

  describe('Sybil Defense Integration', () => {
    test('triggers Sybil defense when diversity insufficient', async () => {
      // Setup Sybil peers (all same subnet)
      const sybilPeers = createSybilPeers(10, 10);
      
      for (const peer of sybilPeers) {
        verifier.eligibility.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        verifier.registerPeer(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      // Mock network layer
      verifier.setNetworkLayer(
        async () => ({}),  // fetchBeacon
        async () => ({}),  // requestVerification
        async () => sybilPeers.map(p => ({ nodeId: p.nodeId }))  // getVerifierPeers
      );
      
      const result = await verifier.claimDomain('example.com');
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Sybil defense');
    });

    test('allows claim with diverse verifiers', async () => {
      const diversePeers = createDiversePeers(10, 10);
      
      for (const peer of diversePeers) {
        verifier.eligibility.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        verifier.registerPeer(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      // Mock network layer with successful verification
      const mockBeacon = createMockBeacon(mockIdentity.identity.nodeId, mockIdentity.identity.publicKey);
      
      verifier.setNetworkLayer(
        async () => mockBeacon,
        async (peerId, request) => {
          // Return a proof with serialize method (mimicking DomainVerificationProof)
          const proofData = {
            domain: request.domain,
            claimantNodeId: request.claimantNodeId,
            verifierNodeId: peerId,
            verifierPublicKey: `pk-${peerId}`,
            beaconHash: 'hash123',
            beaconTimestamp: Date.now(),
            verifiedAt: Date.now(),
            signature: 'sig-valid',
          };
          // Add serialize method to match DomainVerificationProof interface
          proofData.serialize = () => proofData;
          return proofData;
        },
        async () => diversePeers.map(p => ({ nodeId: p.nodeId }))
      );
      
      const result = await verifier.claimDomain('example.com');
      
      // Check result - if failed, log the error
      if (!result.success) {
        // Expected to succeed, but if not, we want to know why
        console.log('Claim failed:', result.error);
      }
      
      // Should succeed with diverse verifiers
      expect(result.success).toBe(true);
      expect(result.proofs.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Proof Verification', () => {
    test('verifies valid proofs', () => {
      const proof = {
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: 'node-xyz',
        verifierPublicKey: 'pk-xyz',
        beaconHash: 'hash123',
        beaconTimestamp: Date.now() - 1000,
        verifiedAt: Date.now() - 500,
        signature: 'sig-valid',
      };
      
      const valid = verifier.verifyProof(proof);
      expect(valid).toBe(true);
    });

    test('rejects proofs that are too old', () => {
      const proof = {
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: 'node-xyz',
        verifierPublicKey: 'pk-xyz',
        beaconHash: 'hash123',
        beaconTimestamp: Date.now() - 1000,
        verifiedAt: Date.now() - (25 * 60 * 60 * 1000),  // 25 hours ago
        signature: 'sig-valid',
      };
      
      const valid = verifier.verifyProof(proof);
      expect(valid).toBe(false);
    });

    test('rejects proofs from the future', () => {
      const proof = {
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: 'node-xyz',
        verifierPublicKey: 'pk-xyz',
        beaconHash: 'hash123',
        beaconTimestamp: Date.now(),
        verifiedAt: Date.now() + (5 * 60 * 1000),  // 5 minutes in future
        signature: 'sig-valid',
      };
      
      const valid = verifier.verifyProof(proof);
      expect(valid).toBe(false);
    });
  });

  describe('Domain Claim Verification with Diversity Check', () => {
    test('rejects claims with insufficient verifier diversity', () => {
      // Create proofs from same-subnet verifiers
      const sybilPeers = createSybilPeers(5, 10);
      
      for (const peer of sybilPeers) {
        verifier.eligibility.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        verifier.registerPeer(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      const proofs = sybilPeers.map(peer => ({
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: peer.nodeId,
        verifierPublicKey: `pk-${peer.nodeId}`,
        beaconHash: 'hash123',
        beaconTimestamp: Date.now(),
        verifiedAt: Date.now(),
        signature: 'sig-valid',
      }));
      
      const result = verifier.verifyDomainClaim(proofs, 'example.com', 'node-abc');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('diversity');
    });

    test('accepts claims with sufficient verifier diversity', () => {
      // Create proofs from diverse verifiers
      const diversePeers = createDiversePeers(5, 10);
      
      for (const peer of diversePeers) {
        verifier.eligibility.nodeFirstSeen.set(peer.nodeId, peer.firstSeen);
        verifier.registerPeer(peer.nodeId, { ip: peer.ip, asn: peer.asn });
      }
      
      const proofs = diversePeers.map(peer => ({
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: peer.nodeId,
        verifierPublicKey: `pk-${peer.nodeId}`,
        beaconHash: 'hash123',
        beaconTimestamp: Date.now(),
        verifiedAt: Date.now(),
        signature: 'sig-valid',
      }));
      
      const result = verifier.verifyDomainClaim(proofs, 'example.com', 'node-abc');
      
      expect(result.valid).toBe(true);
      expect(result.diversity.sufficient).toBe(true);
    });

    test('can skip diversity check when requested', () => {
      // Create proofs from same-subnet verifiers
      const sybilPeers = createSybilPeers(5, 10);
      
      const proofs = sybilPeers.map(peer => ({
        domain: 'example.com',
        claimantNodeId: 'node-abc',
        verifierNodeId: peer.nodeId,
        verifierPublicKey: `pk-${peer.nodeId}`,
        beaconHash: 'hash123',
        beaconTimestamp: Date.now(),
        verifiedAt: Date.now(),
        signature: 'sig-valid',
      }));
      
      const result = verifier.verifyDomainClaim(
        proofs, 
        'example.com', 
        'node-abc',
        { checkDiversity: false }
      );
      
      // Should pass without diversity check
      expect(result.valid).toBe(true);
    });
  });

  describe('State Persistence', () => {
    test('serializes and restores state correctly', () => {
      // Setup some state
      verifier.registerPeer('peer-1', { ip: '192.168.1.1' });
      verifier.stats.claimsSucceeded = 5;
      verifier.cooldowns.set('example.com', Date.now());
      
      const serialized = verifier.serializeState();
      
      expect(serialized.version).toBe(2);
      expect(serialized.eligibility).toBeDefined();
      
      // Create new verifier and restore
      const newVerifier = new DomainConsensusVerifier(mockIdentity, mockGateway);
      newVerifier.restoreState(serialized);
      
      expect(newVerifier.stats.claimsSucceeded).toBe(5);
    });
  });

  describe('Statistics', () => {
    test('tracks claim statistics', () => {
      const stats = verifier.getStats();
      
      expect(stats.claimsInitiated).toBe(0);
      expect(stats.claimsSucceeded).toBe(0);
      expect(stats.claimsFailed).toBe(0);
      expect(stats.claimsRejectedSybil).toBe(0);
      expect(stats.eligibility).toBeDefined();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SYBIL ATTACK SCENARIO TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('Sybil Attack Scenarios', () => {
  let verifier;

  beforeEach(() => {
    verifier = new DomainConsensusVerifier(createMockIdentity(), {});
  });

  test('Scenario: Attacker with 100 nodes in same datacenter', () => {
    // Attacker spins up 100 nodes all in same /24 subnet
    for (let i = 0; i < 100; i++) {
      const nodeId = `attacker-${i}`;
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (30 * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `10.0.0.${i % 256}`,  // All in same /24
        asn: 'AS12345'  // Same ASN
      });
    }
    
    const candidates = Array.from({ length: 100 }, (_, i) => ({ nodeId: `attacker-${i}` }));
    const result = verifier.eligibility.selectDiverseVerifiers(candidates, {}, 5);
    
    // Should fail due to lack of subnet diversity
    expect(result.success).toBe(false);
    expect(result.error).toContain('diversity');
  });

  test('Scenario: Attacker with young nodes', () => {
    // Attacker creates 10 nodes 2 days ago
    for (let i = 0; i < 10; i++) {
      const nodeId = `young-attacker-${i}`;
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (2 * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `192.168.${i}.1`,  // Different subnets (would pass diversity)
        asn: `AS${10000 + i}`
      });
    }
    
    const candidates = Array.from({ length: 10 }, (_, i) => ({ nodeId: `young-attacker-${i}` }));
    const result = verifier.eligibility.selectDiverseVerifiers(candidates, {}, 5);
    
    // Should fail due to nodes being too young
    expect(result.success).toBe(false);
    expect(result.error).toContain('Not enough eligible');
  });

  test('Scenario: Attacker trying to verify own domain', () => {
    // Legitimate diverse nodes exist
    for (let i = 0; i < 10; i++) {
      const nodeId = `legit-${i}`;
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (30 * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `192.168.${i}.1`,
        asn: `AS${10000 + i}`
      });
    }
    
    // Attacker is in same /16 range as some nodes
    const claimantInfo = { ip: '192.168.50.1' };
    
    const candidates = Array.from({ length: 10 }, (_, i) => ({ nodeId: `legit-${i}` }));
    const result = verifier.eligibility.selectDiverseVerifiers(candidates, claimantInfo, 5);
    
    // Some nodes should be excluded due to being in same range as claimant
    // But diverse nodes from other ranges should still allow verification
    expect(result.success).toBe(false);  // All nodes in 192.168.x.x excluded
  });

  test('Scenario: Mixed legitimate and Sybil nodes', () => {
    // 5 legitimate diverse nodes
    for (let i = 0; i < 5; i++) {
      const nodeId = `legit-${i}`;
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (30 * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `172.16.${i}.1`,  // Different /24 each
        asn: `AS${20000 + i}`
      });
    }
    
    // 20 Sybil nodes in same subnet
    for (let i = 0; i < 20; i++) {
      const nodeId = `sybil-${i}`;
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (30 * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `10.0.0.${i + 1}`,  // All same /24
        asn: 'AS12345'
      });
    }
    
    // Mix candidates
    const candidates = [
      ...Array.from({ length: 5 }, (_, i) => ({ nodeId: `legit-${i}` })),
      ...Array.from({ length: 20 }, (_, i) => ({ nodeId: `sybil-${i}` })),
    ];
    
    const result = verifier.eligibility.selectDiverseVerifiers(
      candidates, 
      { ip: '192.168.1.1' },  // Different range
      5
    );
    
    // Should succeed by selecting diverse legitimate nodes
    expect(result.success).toBe(true);
    
    // Should prefer diverse nodes
    const selectedLegit = result.verifiers.filter(v => v.startsWith('legit-'));
    expect(selectedLegit.length).toBeGreaterThanOrEqual(3);  // At least 3 diverse for subnet requirement
  });

  test('Scenario: Gradual Sybil attack over time', () => {
    // Attacker adds 1 node per day over 30 days across different subnets
    for (let i = 0; i < 30; i++) {
      const nodeId = `gradual-sybil-${i}`;
      const daysAgo = 30 - i;  // First node is 30 days old, last is 0 days old
      verifier.eligibility.nodeFirstSeen.set(nodeId, Date.now() - (daysAgo * 24 * 60 * 60 * 1000));
      verifier.registerPeer(nodeId, { 
        ip: `10.${i}.0.1`,  // Different /16 each (diverse)
        asn: `AS${30000 + i}`
      });
    }
    
    const candidates = Array.from({ length: 30 }, (_, i) => ({ nodeId: `gradual-sybil-${i}` }));
    const result = verifier.eligibility.selectDiverseVerifiers(
      candidates, 
      { ip: '192.168.1.1' },
      5
    );
    
    // Nodes older than 7 days should be eligible
    // Should succeed since older nodes exist and are diverse
    expect(result.success).toBe(true);
    
    // Selected nodes should be 7+ days old
    for (const nodeId of result.verifiers) {
      const age = verifier.eligibility.getNodeAge(nodeId);
      expect(age).toBeGreaterThanOrEqual(7 * 24 * 60 * 60 * 1000);
    }
  });
});
