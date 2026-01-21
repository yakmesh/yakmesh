/**
 * KHATA Trust Integration Tests
 * 
 * Tests for the v2.4 trust system network layer integration
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  KhataTrustIntegration,
  KHATA_TRUST_MESSAGE,
} from '../khata-trust-integration.js';

describe('KHATA Trust Integration', () => {
  
  describe('KHATA_TRUST_MESSAGE', () => {
    
    it('should have all message types', () => {
      expect(KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE).toBe('khata:trust:attestation:announce');
      expect(KHATA_TRUST_MESSAGE.ATTESTATION_REQUEST).toBe('khata:trust:attestation:request');
      expect(KHATA_TRUST_MESSAGE.REVOCATION_CERTIFICATE).toBe('khata:trust:revocation:cert');
      expect(KHATA_TRUST_MESSAGE.SILICON_CHALLENGE).toBe('khata:trust:silicon:challenge');
      expect(KHATA_TRUST_MESSAGE.SILICON_RESPONSE).toBe('khata:trust:silicon:response');
      expect(KHATA_TRUST_MESSAGE.SILICON_IDENTITY).toBe('khata:trust:silicon:identity');
      expect(KHATA_TRUST_MESSAGE.GRAPH_UPDATE).toBe('khata:trust:graph:update');
      expect(KHATA_TRUST_MESSAGE.CLUSTER_ALERT).toBe('khata:trust:cluster:alert');
      expect(KHATA_TRUST_MESSAGE.TIER_ANNOUNCE).toBe('khata:trust:tier:announce');
      expect(KHATA_TRUST_MESSAGE.TIER_REQUEST).toBe('khata:trust:tier:request');
    });
  });
  
  describe('KhataTrustIntegration', () => {
    let integration;
    let mockSendToPeer;
    let mockBroadcastToPeers;
    
    beforeEach(() => {
      integration = new KhataTrustIntegration();
      
      mockSendToPeer = vi.fn().mockResolvedValue(undefined);
      mockBroadcastToPeers = vi.fn().mockResolvedValue(undefined);
      
      integration.setNetworkLayer(mockSendToPeer, mockBroadcastToPeers);
    });
    
    afterEach(() => {
      integration.destroy();
    });
    
    it('should set network layer', () => {
      expect(integration.sendToPeer).toBe(mockSendToPeer);
      expect(integration.broadcastToPeers).toBe(mockBroadcastToPeers);
    });
    
    it('should set components', () => {
      const mockMeshRevocation = { addAttestation: vi.fn() };
      const mockSiliconParity = { getIdentity: vi.fn() };
      const mockSybilGraph = { analyze: vi.fn() };
      const mockTrustRegistry = { getTier: vi.fn() };
      
      integration.setComponents({
        meshRevocation: mockMeshRevocation,
        siliconParity: mockSiliconParity,
        sybilGraph: mockSybilGraph,
        trustRegistry: mockTrustRegistry,
      });
      
      expect(integration.meshRevocation).toBe(mockMeshRevocation);
      expect(integration.siliconParity).toBe(mockSiliconParity);
      expect(integration.sybilGraph).toBe(mockSybilGraph);
      expect(integration.trustRegistry).toBe(mockTrustRegistry);
    });
    
    describe('Attestation Gossip', () => {
      
      it('should gossip attestation', async () => {
        const attestation = {
          toJSON: () => ({
            id: 'attest-123',
            targetDokoId: 'doko:target',
            attestorId: 'doko:attestor',
          }),
        };
        
        const messageId = await integration.gossipAttestation(attestation);
        
        expect(messageId).toBeTruthy();
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        
        const broadcastCall = mockBroadcastToPeers.mock.calls[0][0];
        expect(broadcastCall.type).toBe(KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE);
        expect(broadcastCall.attestation.id).toBe('attest-123');
      });
      
      it('should handle incoming attestation', async () => {
        const mockMeshRevocation = {
          addAttestation: vi.fn().mockResolvedValue({ added: true, revoked: false }),
        };
        const mockSybilGraph = {
          addAttestation: vi.fn(),
        };
        
        integration.setComponents({ meshRevocation: mockMeshRevocation, sybilGraph: mockSybilGraph });
        
        const message = {
          type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE,
          messageId: 'msg-123',
          attestation: {
            id: 'attest-123',
            targetDokoId: 'doko:target',
            attestorId: 'doko:attestor',
          },
          timestamp: Date.now(),
          ttl: 3600000,
          hops: 0,
        };
        
        const eventPromise = new Promise(resolve => {
          integration.on('attestation-received', resolve);
        });
        
        await integration.handleAttestationAnnounce(message, 'peer-123');
        
        const event = await eventPromise;
        expect(event.attestation.id).toBe('attest-123');
        expect(mockMeshRevocation.addAttestation).toHaveBeenCalled();
        expect(mockSybilGraph.addAttestation).toHaveBeenCalled();
      });
      
      it('should deduplicate messages', async () => {
        const mockMeshRevocation = {
          addAttestation: vi.fn().mockResolvedValue({ added: true }),
        };
        integration.setComponents({ meshRevocation: mockMeshRevocation });
        
        const message = {
          type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE,
          messageId: 'msg-123',
          attestation: { id: 'attest-123' },
          timestamp: Date.now(),
          ttl: 3600000,
          hops: 0,
        };
        
        await integration.handleAttestationAnnounce(message, 'peer-1');
        await integration.handleAttestationAnnounce(message, 'peer-2');
        
        // Should only process once
        expect(mockMeshRevocation.addAttestation).toHaveBeenCalledTimes(1);
      });
      
      it('should respect hop limit', async () => {
        const mockMeshRevocation = {
          addAttestation: vi.fn().mockResolvedValue({ added: true }),
        };
        integration.setComponents({ meshRevocation: mockMeshRevocation });
        
        const message = {
          type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE,
          messageId: 'msg-new',
          attestation: { id: 'attest-123' },
          timestamp: Date.now(),
          ttl: 3600000,
          hops: 15, // Over limit
        };
        
        await integration.handleAttestationAnnounce(message, 'peer-1');
        
        expect(mockMeshRevocation.addAttestation).not.toHaveBeenCalled();
      });
      
      it('should propagate attestations', async () => {
        const mockMeshRevocation = {
          addAttestation: vi.fn().mockResolvedValue({ added: true }),
        };
        integration.setComponents({ meshRevocation: mockMeshRevocation });
        
        const message = {
          type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE,
          messageId: 'msg-456',
          attestation: { id: 'attest-456' },
          timestamp: Date.now(),
          ttl: 3600000,
          hops: 2,
        };
        
        await integration.handleAttestationAnnounce(message, 'peer-1');
        
        // Should broadcast with incremented hops
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        const broadcastCall = mockBroadcastToPeers.mock.calls[0][0];
        expect(broadcastCall.hops).toBe(3);
      });
    });
    
    describe('Silicon Parity Challenges', () => {
      
      it('should send silicon challenge', async () => {
        integration.nodeIdentity = { identity: { nodeId: 'doko:me' } };
        
        // Don't await - it will timeout
        const challengePromise = integration.challengeSilicon('peer-target');
        
        // Catch the expected rejection when we destroy
        challengePromise.catch(() => {});
        
        // Immediately check that send was called
        await new Promise(r => setTimeout(r, 10));
        
        expect(mockSendToPeer).toHaveBeenCalled();
        const message = mockSendToPeer.mock.calls[0][1];
        expect(message.type).toBe(KHATA_TRUST_MESSAGE.SILICON_CHALLENGE);
        expect(message.challengerId).toBe('doko:me');
        expect(message.nonce).toBeTruthy();
        
        // Cleanup the pending promise
        integration.destroy();
      });
      
      it('should handle silicon challenge', async () => {
        const mockIdentity = {
          id: 'identity-123',
          aesFingerprint: 'fingerprint-abc',
          coreCount: 8,
          isRealSilicon: true,
          toJSON: () => ({
            id: 'identity-123',
            aesFingerprint: 'fingerprint-abc',
            coreCount: 8,
            isRealSilicon: true,
          }),
        };
        
        const mockSiliconParity = {
          getIdentity: vi.fn().mockReturnValue(mockIdentity),
        };
        
        integration.setComponents({ siliconParity: mockSiliconParity });
        integration.nodeIdentity = { 
          identity: { nodeId: 'doko:me' },
          sign: vi.fn().mockReturnValue('mock-signature-xyz'),
        };
        
        const challenge = {
          type: KHATA_TRUST_MESSAGE.SILICON_CHALLENGE,
          challengeId: 'challenge-123',
          nonce: 'nonce-abc',
          timestamp: Date.now(),
        };
        
        await integration.handleSiliconChallenge(challenge, 'peer-challenger');
        
        expect(mockSendToPeer).toHaveBeenCalled();
        const response = mockSendToPeer.mock.calls[0][1];
        expect(response.type).toBe(KHATA_TRUST_MESSAGE.SILICON_RESPONSE);
        expect(response.challengeId).toBe('challenge-123');
        expect(response.identity.coreCount).toBe(8);
      });
      
      it('should announce silicon identity', async () => {
        const mockIdentity = {
          id: 'identity-123',
          toJSON: () => ({ id: 'identity-123' }),
        };
        
        const mockSiliconParity = {
          getIdentity: vi.fn().mockReturnValue(mockIdentity),
        };
        
        integration.setComponents({ siliconParity: mockSiliconParity });
        integration.nodeIdentity = { identity: { nodeId: 'doko:me' } };
        
        await integration.announceSiliconIdentity();
        
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        const message = mockBroadcastToPeers.mock.calls[0][0];
        expect(message.type).toBe(KHATA_TRUST_MESSAGE.SILICON_IDENTITY);
      });
    });
    
    describe('Sybil Graph Updates', () => {
      
      it('should share graph update', async () => {
        const mockSybilGraph = {
          getGraphStats: vi.fn().mockReturnValue({
            nodeCount: 100,
            edgeCount: 250,
            density: 0.5,
          }),
        };
        
        integration.setComponents({ sybilGraph: mockSybilGraph });
        integration.nodeIdentity = { identity: { nodeId: 'doko:me' } };
        
        await integration.shareGraphUpdate();
        
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        const message = mockBroadcastToPeers.mock.calls[0][0];
        expect(message.type).toBe(KHATA_TRUST_MESSAGE.GRAPH_UPDATE);
        expect(message.graphStats.nodeCount).toBe(100);
      });
      
      it('should broadcast cluster alert', async () => {
        integration.nodeIdentity = { identity: { nodeId: 'doko:me' } };
        
        const cluster = {
          nodes: ['S1', 'S2', 'S3'],
          size: 3,
          suspicionScore: 0.8,
          reasons: ['High clustering'],
          isSybil: true,
        };
        
        await integration.broadcastClusterAlert(cluster);
        
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        const message = mockBroadcastToPeers.mock.calls[0][0];
        expect(message.type).toBe(KHATA_TRUST_MESSAGE.CLUSTER_ALERT);
        expect(message.cluster.size).toBe(3);
        expect(message.cluster.isSybil).toBe(true);
      });
      
      it('should handle incoming cluster alert', async () => {
        const mockSybilGraph = {
          analyze: vi.fn().mockReturnValue({ clusters: [] }),
        };
        
        integration.setComponents({ sybilGraph: mockSybilGraph });
        
        const message = {
          type: KHATA_TRUST_MESSAGE.CLUSTER_ALERT,
          cluster: {
            nodes: ['S1', 'S2', 'S3'],
            size: 3,
            suspicionScore: 0.8,
            isSybil: true,
          },
          detectedBy: 'doko:other',
          timestamp: Date.now(),
        };
        
        const eventPromise = new Promise(resolve => {
          integration.on('cluster-alert', resolve);
        });
        
        await integration.handleClusterAlert(message, 'peer-123');
        
        const event = await eventPromise;
        expect(event.cluster.size).toBe(3);
        expect(integration.stats.clusterAlertsReceived).toBe(1);
      });
    });
    
    describe('Trust Tier Announcements', () => {
      
      it('should announce tier', async () => {
        const mockTrustRegistry = {
          getTier: vi.fn().mockResolvedValue('anchor'),
          getWeight: vi.fn().mockResolvedValue(1.5),
        };
        
        integration.setComponents({ trustRegistry: mockTrustRegistry });
        integration.nodeIdentity = { 
          identity: { nodeId: 'doko:me' },
          sign: vi.fn().mockReturnValue('signature'),
        };
        
        await integration.announceTier();
        
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        const message = mockBroadcastToPeers.mock.calls[0][0];
        expect(message.type).toBe(KHATA_TRUST_MESSAGE.TIER_ANNOUNCE);
        expect(message.tier).toBe('anchor');
        expect(message.weight).toBe(1.5);
        expect(message.signature).toBe('signature');
      });
    });
    
    describe('Message Routing', () => {
      
      it('should route attestation announce', async () => {
        const handleSpy = vi.spyOn(integration, 'handleAttestationAnnounce').mockResolvedValue();
        
        const message = { type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE };
        const result = await integration.handleMessage(message, 'peer-1');
        
        expect(result).toBe(true);
        expect(handleSpy).toHaveBeenCalled();
      });
      
      it('should route silicon challenge', async () => {
        const handleSpy = vi.spyOn(integration, 'handleSiliconChallenge').mockResolvedValue();
        
        const message = { type: KHATA_TRUST_MESSAGE.SILICON_CHALLENGE };
        const result = await integration.handleMessage(message, 'peer-1');
        
        expect(result).toBe(true);
        expect(handleSpy).toHaveBeenCalled();
      });
      
      it('should route cluster alert', async () => {
        const handleSpy = vi.spyOn(integration, 'handleClusterAlert').mockResolvedValue();
        
        const message = { type: KHATA_TRUST_MESSAGE.CLUSTER_ALERT };
        const result = await integration.handleMessage(message, 'peer-1');
        
        expect(result).toBe(true);
        expect(handleSpy).toHaveBeenCalled();
      });
      
      it('should return false for unknown message', async () => {
        const message = { type: 'unknown:message:type' };
        const result = await integration.handleMessage(message, 'peer-1');
        
        expect(result).toBe(false);
      });
      
      it('should identify trust messages', () => {
        expect(integration.isTrustMessage(KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE)).toBe(true);
        expect(integration.isTrustMessage(KHATA_TRUST_MESSAGE.SILICON_CHALLENGE)).toBe(true);
        expect(integration.isTrustMessage('khata:announce')).toBe(false);
      });
    });
    
    describe('Statistics and Cleanup', () => {
      
      it('should track statistics', async () => {
        const stats = integration.getStats();
        
        expect(stats.attestationsGossiped).toBe(0);
        expect(stats.attestationsReceived).toBe(0);
        expect(stats.siliconChallengesSent).toBe(0);
        expect(stats.seenMessagesSize).toBe(0);
      });
      
      it('should cleanup on destroy', () => {
        // Add some state
        integration.seenMessages.set('hash1', Date.now());
        integration.pendingChallenges.set('challenge1', {
          resolve: vi.fn(),
          reject: vi.fn(),
          timeout: setTimeout(() => {}, 1000),
        });
        
        integration.destroy();
        
        expect(integration.seenMessages.size).toBe(0);
        expect(integration.pendingChallenges.size).toBe(0);
      });
    });
    
    // ═══════════════════════════════════════════════════════════════════════════
    // v2.5.0 GEOGRAPHIC PROOF GOSSIP TESTS
    // ═══════════════════════════════════════════════════════════════════════════
    
    describe('Geographic Proof Gossip (v2.5.0)', () => {
      
      it('should have geo-proof message types', () => {
        expect(KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE).toBe('khata:trust:geo:announce');
        expect(KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST).toBe('khata:trust:geo:request');
        expect(KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE).toBe('khata:trust:geo:response');
        expect(KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE).toBe('khata:trust:landmark:announce');
        expect(KHATA_TRUST_MESSAGE.LANDMARK_VERIFY).toBe('khata:trust:landmark:verify');
      });
      
      it('should set geoProofService component', () => {
        const mockGeoProofService = { getProof: vi.fn(), registerLandmark: vi.fn() };
        
        integration.setComponents({ geoProofService: mockGeoProofService });
        
        expect(integration.geoProofService).toBe(mockGeoProofService);
      });
      
      it('should announce geo-proof', async () => {
        const mockProof = {
          exclusionZones: [{ landmarkId: 'nyc', minDistanceKm: 5000 }],
          serialize: () => ({
            nodeId: 'node-1',
            exclusionZones: [{ landmarkId: 'nyc', minDistanceKm: 5000 }],
          }),
        };
        
        const mockGeoProofService = { getProof: vi.fn().mockReturnValue(mockProof) };
        integration.setComponents({ geoProofService: mockGeoProofService });
        
        const messageId = await integration.announceGeoProof();
        
        expect(messageId).toBeTruthy();
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        
        const broadcastCall = mockBroadcastToPeers.mock.calls[0][0];
        expect(broadcastCall.type).toBe(KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE);
        expect(broadcastCall.proof.exclusionZones).toHaveLength(1);
        expect(integration.stats.geoProofsGossiped).toBe(1);
      });
      
      it('should not announce if no proof available', async () => {
        const mockGeoProofService = { getProof: vi.fn().mockReturnValue(null) };
        integration.setComponents({ geoProofService: mockGeoProofService });
        
        const messageId = await integration.announceGeoProof();
        
        expect(messageId).toBeUndefined();
        expect(mockBroadcastToPeers).not.toHaveBeenCalled();
      });
      
      it('should request geo-proof from peer', async () => {
        integration.nodeIdentity = { identity: { nodeId: 'my-node' } };
        
        const messageId = await integration.requestGeoProof('peer-123');
        
        expect(messageId).toBeTruthy();
        expect(mockSendToPeer).toHaveBeenCalledWith('peer-123', expect.objectContaining({
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST,
          requesterId: 'my-node',
        }));
      });
      
      it('should handle geo-proof announce', async () => {
        const receivedEvents = [];
        integration.on('geo-proof-received', (data) => receivedEvents.push(data));
        
        const message = {
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE,
          messageId: 'msg-123',
          proof: { nodeId: 'node-1', exclusionZones: [] },
          dokoId: 'doko-1',
          timestamp: Date.now(),
          hops: 0,
        };
        
        await integration.handleGeoProofAnnounce(message, 'peer-1');
        
        expect(receivedEvents).toHaveLength(1);
        expect(receivedEvents[0].dokoId).toBe('doko-1');
        expect(integration.stats.geoProofsReceived).toBe(1);
      });
      
      it('should deduplicate geo-proof messages', async () => {
        const message = {
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE,
          messageId: 'msg-123',
          proof: { nodeId: 'node-1', exclusionZones: [] },
          dokoId: 'doko-1',
          timestamp: Date.now(),
          hops: 0,
        };
        
        await integration.handleGeoProofAnnounce(message, 'peer-1');
        await integration.handleGeoProofAnnounce(message, 'peer-2');
        
        // Only processed once
        expect(integration.stats.geoProofsReceived).toBe(1);
      });
      
      it('should handle geo-proof request', async () => {
        const mockProof = {
          serialize: () => ({ nodeId: 'node-1', exclusionZones: [] }),
        };
        
        const mockGeoProofService = { getProof: vi.fn().mockReturnValue(mockProof) };
        integration.setComponents({ geoProofService: mockGeoProofService });
        integration.nodeIdentity = { identity: { nodeId: 'my-node' } };
        
        const requestMessage = {
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST,
          messageId: 'req-123',
          requesterId: 'peer-1',
          timestamp: Date.now(),
        };
        
        await integration.handleGeoProofRequest(requestMessage, 'peer-1');
        
        expect(mockSendToPeer).toHaveBeenCalledWith('peer-1', expect.objectContaining({
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE,
          requestId: 'req-123',
        }));
      });
      
      it('should handle geo-proof response', async () => {
        const receivedEvents = [];
        integration.on('geo-proof-response', (data) => receivedEvents.push(data));
        
        const message = {
          type: KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE,
          requestId: 'req-123',
          proof: { nodeId: 'node-1', exclusionZones: [] },
          dokoId: 'doko-1',
          timestamp: Date.now(),
        };
        
        await integration.handleGeoProofResponse(message, 'peer-1');
        
        expect(receivedEvents).toHaveLength(1);
        expect(receivedEvents[0].requestId).toBe('req-123');
      });
      
      it('should announce landmark', async () => {
        integration.nodeIdentity = { identity: { nodeId: 'my-node' }, sign: vi.fn().mockReturnValue('signature') };
        
        const landmarkInfo = {
          name: 'NYC-ANCHOR-1',
          region: 'NA-EAST',
          coordinates: { lat: 40.7128, lon: -74.0060 },
          endpoint: 'https://nyc.yakmesh.dev/.well-known/yakmesh/beacon',
        };
        
        const messageId = await integration.announceLandmark(landmarkInfo);
        
        expect(messageId).toBeTruthy();
        expect(mockBroadcastToPeers).toHaveBeenCalled();
        
        const broadcastCall = mockBroadcastToPeers.mock.calls[0][0];
        expect(broadcastCall.type).toBe(KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE);
        expect(broadcastCall.landmark.name).toBe('NYC-ANCHOR-1');
        expect(broadcastCall.landmark.region).toBe('NA-EAST');
        expect(integration.stats.landmarksAnnounced).toBe(1);
      });
      
      it('should handle landmark announce and register', async () => {
        const mockGeoProofService = { registerLandmark: vi.fn() };
        integration.setComponents({ geoProofService: mockGeoProofService });
        
        const receivedEvents = [];
        integration.on('landmark-announce', (data) => receivedEvents.push(data));
        
        const message = {
          type: KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE,
          messageId: 'msg-123',
          landmark: {
            nodeId: 'landmark-1',
            name: 'NYC-ANCHOR',
            region: 'NA-EAST',
            coordinates: { lat: 40.7128, lon: -74.0060 },
          },
          timestamp: Date.now(),
        };
        
        await integration.handleLandmarkAnnounce(message, 'peer-1');
        
        expect(receivedEvents).toHaveLength(1);
        expect(mockGeoProofService.registerLandmark).toHaveBeenCalledWith(message.landmark);
      });
      
      it('should route geo-proof messages', async () => {
        const handleAnnounce = vi.spyOn(integration, 'handleGeoProofAnnounce').mockResolvedValue();
        const handleRequest = vi.spyOn(integration, 'handleGeoProofRequest').mockResolvedValue();
        const handleResponse = vi.spyOn(integration, 'handleGeoProofResponse').mockResolvedValue();
        const handleLandmark = vi.spyOn(integration, 'handleLandmarkAnnounce').mockResolvedValue();
        
        await integration.handleMessage({ type: KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE }, 'peer-1');
        expect(handleAnnounce).toHaveBeenCalled();
        
        await integration.handleMessage({ type: KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST }, 'peer-1');
        expect(handleRequest).toHaveBeenCalled();
        
        await integration.handleMessage({ type: KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE }, 'peer-1');
        expect(handleResponse).toHaveBeenCalled();
        
        await integration.handleMessage({ type: KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE }, 'peer-1');
        expect(handleLandmark).toHaveBeenCalled();
      });
      
      it('should emit landmark-verify-request event', async () => {
        const receivedEvents = [];
        integration.on('landmark-verify-request', (data) => receivedEvents.push(data));
        
        const message = {
          type: KHATA_TRUST_MESSAGE.LANDMARK_VERIFY,
          landmarkId: 'landmark-1',
          requesterId: 'peer-1',
        };
        
        await integration.handleMessage(message, 'peer-1');
        
        expect(receivedEvents).toHaveLength(1);
        expect(receivedEvents[0].landmarkId).toBe('landmark-1');
      });
      
      it('should track geo-proof statistics', async () => {
        const mockProof = {
          exclusionZones: [],
          serialize: () => ({ nodeId: 'node-1', exclusionZones: [] }),
        };
        
        const mockGeoProofService = { getProof: vi.fn().mockReturnValue(mockProof) };
        integration.setComponents({ geoProofService: mockGeoProofService });
        
        await integration.announceGeoProof();
        
        const stats = integration.getStats();
        expect(stats.geoProofsGossiped).toBe(1);
        expect(stats.landmarksAnnounced).toBe(0);
      });
    });
  });
});
