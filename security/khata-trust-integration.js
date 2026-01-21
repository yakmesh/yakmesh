/**
 * KHATA Trust Integration - v2.4 Trust System Integration
 * 
 * Extends KHATA protocol with:
 * - Mesh Revocation gossip (attestation propagation)
 * - Silicon Parity challenges (hardware verification)
 * - Sybil Graph updates (cluster detection data)
 * 
 * This module bridges the trust components into the network layer.
 * 
 * @module security/khata-trust-integration
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';
import { MESH_REVOCATION_MESSAGES } from './mesh-revocation.js';
import { SILICON_PARITY_MESSAGES } from './silicon-parity.js';
import { SYBIL_GRAPH_MESSAGES } from './sybil-graph.js';

const log = createLogger('security:khata-trust');

/**
 * Extended KHATA message types for v2.4 trust system
 */
export const KHATA_TRUST_MESSAGE = {
  // Mesh Revocation messages
  ATTESTATION_ANNOUNCE: 'khata:trust:attestation:announce',
  ATTESTATION_REQUEST: 'khata:trust:attestation:request',
  REVOCATION_CERTIFICATE: 'khata:trust:revocation:cert',
  
  // Silicon Parity messages
  SILICON_CHALLENGE: 'khata:trust:silicon:challenge',
  SILICON_RESPONSE: 'khata:trust:silicon:response',
  SILICON_IDENTITY: 'khata:trust:silicon:identity',
  
  // Sybil Graph messages
  GRAPH_UPDATE: 'khata:trust:graph:update',
  CLUSTER_ALERT: 'khata:trust:cluster:alert',
  
  // Trust Tier messages
  TIER_ANNOUNCE: 'khata:trust:tier:announce',
  TIER_REQUEST: 'khata:trust:tier:request',
  
  // v2.5.0 Geographic Proof messages
  GEO_PROOF_ANNOUNCE: 'khata:trust:geo:announce',
  GEO_PROOF_REQUEST: 'khata:trust:geo:request',
  GEO_PROOF_RESPONSE: 'khata:trust:geo:response',
  LANDMARK_ANNOUNCE: 'khata:trust:landmark:announce',
  LANDMARK_VERIFY: 'khata:trust:landmark:verify',
};

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  attestationTTL: 24 * 60 * 60 * 1000, // 24 hours
  siliconChallengeTimeout: 30000, // 30 seconds
  graphUpdateInterval: 5 * 60 * 1000, // 5 minutes
  maxHops: 10,
};

/**
 * Generate unique message ID
 */
function generateMessageId() {
  return bytesToHex(randomBytes(16));
}

/**
 * KhataTrustIntegration - Trust System Network Layer
 * 
 * Integrates MeshRevocation, SiliconParity, and SybilGraph
 * into the KHATA gossip protocol.
 */
export class KhataTrustIntegration extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = { ...DEFAULT_CONFIG, ...options };
    
    // Core components (injected)
    this.meshRevocation = options.meshRevocation || null;
    this.siliconParity = options.siliconParity || null;
    this.sybilGraph = options.sybilGraph || null;
    this.trustRegistry = options.trustRegistry || null;
    this.nodeIdentity = options.nodeIdentity || null;
    this.geoProofService = options.geoProofService || null;  // v2.5.0
    
    // Network layer (set by setNetworkLayer)
    this.sendToPeer = null;
    this.broadcastToPeers = null;
    
    // Message deduplication
    this.seenMessages = new Map();
    
    // Pending silicon challenges
    this.pendingChallenges = new Map();
    
    // Statistics
    this.stats = {
      attestationsGossiped: 0,
      attestationsReceived: 0,
      siliconChallengesSent: 0,
      siliconChallengesReceived: 0,
      graphUpdatesReceived: 0,
      clusterAlertsReceived: 0,
      geoProofsGossiped: 0,
      geoProofsReceived: 0,
      landmarksAnnounced: 0,
    };
    
    // Cleanup interval
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }
  
  /**
   * Set network layer functions
   */
  setNetworkLayer(sendToPeer, broadcastToPeers) {
    this.sendToPeer = sendToPeer;
    this.broadcastToPeers = broadcastToPeers;
  }
  
  /**
   * Set core components
   */
  setComponents({ meshRevocation, siliconParity, sybilGraph, trustRegistry, nodeIdentity, geoProofService }) {
    if (meshRevocation) this.meshRevocation = meshRevocation;
    if (siliconParity) this.siliconParity = siliconParity;
    if (sybilGraph) this.sybilGraph = sybilGraph;
    if (trustRegistry) this.trustRegistry = trustRegistry;
    if (nodeIdentity) this.nodeIdentity = nodeIdentity;
    if (geoProofService) this.geoProofService = geoProofService;
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // MESH REVOCATION GOSSIP
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Gossip an attestation to the network
   */
  async gossipAttestation(attestation) {
    if (!this.broadcastToPeers) {
      log.warn('khata-trust', 'Cannot gossip: network layer not set');
      return;
    }
    
    const message = {
      type: KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE,
      messageId: generateMessageId(),
      attestation: attestation.toJSON(),
      timestamp: Date.now(),
      ttl: this.config.attestationTTL,
      hops: 0,
    };
    
    // Mark as seen
    const hash = this.computeMessageHash(message);
    this.seenMessages.set(hash, Date.now());
    
    this.stats.attestationsGossiped++;
    log.debug('khata-trust', `Gossiping attestation for ${attestation.targetDokoId}`);
    
    await this.broadcastToPeers(message);
    
    return message.messageId;
  }
  
  /**
   * Handle incoming attestation announcement
   */
  async handleAttestationAnnounce(message, fromPeerId) {
    // Check for duplicate
    const hash = this.computeMessageHash(message);
    if (this.seenMessages.has(hash)) {
      return;
    }
    this.seenMessages.set(hash, Date.now());
    
    // Check hop limit
    if (message.hops >= this.config.maxHops) {
      return;
    }
    
    // Check TTL
    const age = Date.now() - message.timestamp;
    if (age > message.ttl) {
      return;
    }
    
    this.stats.attestationsReceived++;
    
    // Add to local mesh revocation system
    if (this.meshRevocation) {
      try {
        const result = await this.meshRevocation.addAttestation(message.attestation);
        
        if (result.added) {
          this.emit('attestation-received', {
            attestation: message.attestation,
            fromPeerId,
            revocationTriggered: result.revoked,
          });
          
          // Update sybil graph with attestation
          if (this.sybilGraph) {
            this.sybilGraph.addAttestation(
              message.attestation.attestorId,
              message.attestation.targetDokoId,
              message.timestamp
            );
          }
          
          // Propagate to other peers
          if (this.broadcastToPeers) {
            await this.broadcastToPeers({
              ...message,
              hops: message.hops + 1,
            }, fromPeerId);
          }
        }
      } catch (err) {
        log.warn('khata-trust', `Failed to add attestation: ${err.message}`);
      }
    }
  }
  
  /**
   * Broadcast revocation certificate
   */
  async broadcastRevocationCertificate(certificate) {
    if (!this.broadcastToPeers) return;
    
    const message = {
      type: KHATA_TRUST_MESSAGE.REVOCATION_CERTIFICATE,
      messageId: generateMessageId(),
      certificate,
      timestamp: Date.now(),
    };
    
    log.info('khata-trust', `Broadcasting revocation certificate for ${certificate.targetDokoId}`);
    
    await this.broadcastToPeers(message);
  }
  
  /**
   * Handle incoming revocation certificate
   */
  async handleRevocationCertificate(message, fromPeerId) {
    const { certificate } = message;
    
    // Verify certificate
    if (this.meshRevocation) {
      const valid = await this.meshRevocation.constructor.verifyCertificate(
        certificate,
        async (dokoId) => {
          // Resolver for public keys
          if (this.trustRegistry) {
            const profile = await this.trustRegistry.getProfile(dokoId);
            return profile?.publicKey || null;
          }
          return null;
        }
      );
      
      if (valid) {
        this.emit('revocation-certificate', {
          certificate,
          fromPeerId,
          targetDokoId: certificate.targetDokoId,
        });
        
        // Mark node as revoked in local state
        log.info('khata-trust', 
          `Verified revocation certificate for ${certificate.targetDokoId}`);
      } else {
        log.warn('khata-trust', 
          `Invalid revocation certificate for ${certificate.targetDokoId}`);
      }
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SILICON PARITY CHALLENGES
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Challenge a peer to prove their silicon identity
   */
  async challengeSilicon(peerId) {
    if (!this.sendToPeer) {
      throw new Error('Network layer not set');
    }
    
    const challengeId = generateMessageId();
    const challenge = {
      type: KHATA_TRUST_MESSAGE.SILICON_CHALLENGE,
      challengeId,
      challengerId: this.nodeIdentity?.identity?.nodeId,
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
    };
    
    // Create promise for response
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingChallenges.delete(challengeId);
        reject(new Error('Silicon challenge timeout'));
      }, this.config.siliconChallengeTimeout);
      
      this.pendingChallenges.set(challengeId, { 
        resolve, 
        reject, 
        timeout,
        peerId,
      });
      
      this.stats.siliconChallengesSent++;
      this.sendToPeer(peerId, challenge);
    });
  }
  
  /**
   * Handle incoming silicon challenge
   */
  async handleSiliconChallenge(message, fromPeerId) {
    this.stats.siliconChallengesReceived++;
    
    if (!this.siliconParity) {
      log.warn('khata-trust', 'Received silicon challenge but SiliconParity not configured');
      return;
    }
    
    // Collect or retrieve our silicon identity
    const myDokoId = this.nodeIdentity?.identity?.nodeId;
    let identity = this.siliconParity.getIdentity(myDokoId);
    
    if (!identity) {
      // Collect identity on demand
      identity = await this.siliconParity.collectIdentity(myDokoId);
    }
    
    // Create response
    const response = {
      type: KHATA_TRUST_MESSAGE.SILICON_RESPONSE,
      challengeId: message.challengeId,
      responderId: myDokoId,
      identity: identity.toJSON(),
      challengeNonce: message.nonce,
      responseNonce: bytesToHex(randomBytes(16)),
      timestamp: Date.now(),
    };
    
    // Sign response
    if (this.nodeIdentity) {
      const payload = JSON.stringify({
        challengeId: message.challengeId,
        challengeNonce: message.nonce,
        responseNonce: response.responseNonce,
        fingerprint: identity.aesFingerprint,
      });
      response.signature = this.nodeIdentity.sign(payload);
    }
    
    if (this.sendToPeer) {
      await this.sendToPeer(fromPeerId, response);
    }
  }
  
  /**
   * Handle silicon challenge response
   */
  async handleSiliconResponse(message, fromPeerId) {
    const pending = this.pendingChallenges.get(message.challengeId);
    if (!pending) {
      return; // Unknown or expired challenge
    }
    
    clearTimeout(pending.timeout);
    this.pendingChallenges.delete(message.challengeId);
    
    // Verify response
    const result = {
      valid: true,
      identity: message.identity,
      responderId: message.responderId,
      issues: [],
    };
    
    // Check signature if we have the public key
    if (message.signature && this.nodeIdentity) {
      const payload = JSON.stringify({
        challengeId: message.challengeId,
        challengeNonce: pending.nonce,
        responseNonce: message.responseNonce,
        fingerprint: message.identity.aesFingerprint,
      });
      
      // TODO: Verify signature with responder's public key
    }
    
    // Check for VM indicators
    if (!message.identity.isRealSilicon) {
      result.issues.push('VM or emulation detected');
    }
    
    // Check core count for weight calculation
    if (message.identity.coreCount > 64) {
      result.issues.push(`High core count: ${message.identity.coreCount}`);
    }
    
    pending.resolve(result);
  }
  
  /**
   * Announce silicon identity to network
   */
  async announceSiliconIdentity() {
    if (!this.broadcastToPeers || !this.siliconParity) return;
    
    const myDokoId = this.nodeIdentity?.identity?.nodeId;
    let identity = this.siliconParity.getIdentity(myDokoId);
    
    if (!identity) {
      identity = await this.siliconParity.collectIdentity(myDokoId);
    }
    
    const message = {
      type: KHATA_TRUST_MESSAGE.SILICON_IDENTITY,
      messageId: generateMessageId(),
      dokoId: myDokoId,
      identity: identity.toJSON(),
      timestamp: Date.now(),
    };
    
    await this.broadcastToPeers(message);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SYBIL GRAPH UPDATES
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Share graph update with network
   */
  async shareGraphUpdate() {
    if (!this.broadcastToPeers || !this.sybilGraph) return;
    
    const stats = this.sybilGraph.getGraphStats();
    const myDokoId = this.nodeIdentity?.identity?.nodeId;
    
    const message = {
      type: KHATA_TRUST_MESSAGE.GRAPH_UPDATE,
      messageId: generateMessageId(),
      senderId: myDokoId,
      graphStats: stats,
      timestamp: Date.now(),
    };
    
    await this.broadcastToPeers(message);
  }
  
  /**
   * Handle incoming graph update
   */
  async handleGraphUpdate(message, fromPeerId) {
    this.stats.graphUpdatesReceived++;
    
    this.emit('graph-update', {
      senderId: message.senderId,
      stats: message.graphStats,
      fromPeerId,
    });
    
    // Could merge graph data here if implementing distributed analysis
  }
  
  /**
   * Broadcast cluster alert
   */
  async broadcastClusterAlert(cluster) {
    if (!this.broadcastToPeers) return;
    
    const message = {
      type: KHATA_TRUST_MESSAGE.CLUSTER_ALERT,
      messageId: generateMessageId(),
      cluster: {
        nodes: cluster.nodes,
        size: cluster.size,
        suspicionScore: cluster.suspicionScore,
        reasons: cluster.reasons,
        isSybil: cluster.isSybil,
      },
      detectedBy: this.nodeIdentity?.identity?.nodeId,
      timestamp: Date.now(),
    };
    
    log.warn('khata-trust', 
      `Broadcasting cluster alert: ${cluster.size} nodes, score=${cluster.suspicionScore}`);
    
    await this.broadcastToPeers(message);
  }
  
  /**
   * Handle incoming cluster alert
   */
  async handleClusterAlert(message, fromPeerId) {
    this.stats.clusterAlertsReceived++;
    
    this.emit('cluster-alert', {
      cluster: message.cluster,
      detectedBy: message.detectedBy,
      fromPeerId,
    });
    
    // Cross-reference with our own analysis
    if (this.sybilGraph) {
      const ourAnalysis = this.sybilGraph.analyze();
      const matchingCluster = ourAnalysis.clusters.find(c => 
        c.nodes.some(n => message.cluster.nodes.includes(n))
      );
      
      if (matchingCluster) {
        log.info('khata-trust', 
          `Cluster alert confirmed by local analysis: ${matchingCluster.size} nodes`);
      }
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TRUST TIER ANNOUNCEMENTS
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Announce our trust tier
   */
  async announceTier() {
    if (!this.broadcastToPeers || !this.trustRegistry) return;
    
    const myDokoId = this.nodeIdentity?.identity?.nodeId;
    const tier = await this.trustRegistry.getTier(myDokoId);
    const weight = await this.trustRegistry.getWeight(myDokoId);
    
    const message = {
      type: KHATA_TRUST_MESSAGE.TIER_ANNOUNCE,
      messageId: generateMessageId(),
      dokoId: myDokoId,
      tier,
      weight,
      timestamp: Date.now(),
    };
    
    // Sign announcement
    if (this.nodeIdentity) {
      const payload = JSON.stringify({
        dokoId: myDokoId,
        tier,
        weight,
        timestamp: message.timestamp,
      });
      message.signature = this.nodeIdentity.sign(payload);
    }
    
    await this.broadcastToPeers(message);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // GEOGRAPHIC PROOF (v2.5.0)
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Announce our geographic proof to the network
   */
  async announceGeoProof() {
    if (!this.broadcastToPeers || !this.geoProofService) return;
    
    const proof = this.geoProofService.getProof();
    if (!proof) {
      log.debug('khata-trust', 'No geo-proof available to announce');
      return;
    }
    
    const message = {
      type: KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE,
      messageId: generateMessageId(),
      proof: proof.serialize(),
      dokoId: this.nodeIdentity?.identity?.nodeId,
      timestamp: Date.now(),
      hops: 0,
    };
    
    // Sign announcement
    if (this.nodeIdentity) {
      const payload = JSON.stringify({
        proof: message.proof,
        dokoId: message.dokoId,
        timestamp: message.timestamp,
      });
      message.signature = this.nodeIdentity.sign(payload);
    }
    
    this.stats.geoProofsGossiped++;
    log.debug('khata-trust', `Announcing geo-proof with ${proof.exclusionZones.length} zones`);
    
    await this.broadcastToPeers(message);
    return message.messageId;
  }
  
  /**
   * Request geographic proof from a specific peer
   */
  async requestGeoProof(peerId) {
    if (!this.sendToPeer) {
      throw new Error('Network layer not set');
    }
    
    const message = {
      type: KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST,
      messageId: generateMessageId(),
      requesterId: this.nodeIdentity?.identity?.nodeId,
      timestamp: Date.now(),
    };
    
    await this.sendToPeer(peerId, message);
    return message.messageId;
  }
  
  /**
   * Handle incoming geo-proof announcement
   */
  async handleGeoProofAnnounce(message, fromPeerId) {
    // Check for duplicate
    const hash = this.computeMessageHash(message);
    if (this.seenMessages.has(hash)) {
      return;
    }
    this.seenMessages.set(hash, Date.now());
    
    // Check hop limit
    if (message.hops >= this.config.maxHops) {
      return;
    }
    
    this.stats.geoProofsReceived++;
    
    this.emit('geo-proof-received', {
      proof: message.proof,
      dokoId: message.dokoId,
      fromPeerId,
    });
    
    // Store in local registry if trust registry supports it
    if (this.trustRegistry && this.trustRegistry.setGeoProof) {
      try {
        await this.trustRegistry.setGeoProof(message.dokoId, message.proof);
      } catch (err) {
        log.warn('khata-trust', `Failed to store geo-proof: ${err.message}`);
      }
    }
    
    // Propagate to other peers
    if (this.broadcastToPeers) {
      await this.broadcastToPeers({
        ...message,
        hops: message.hops + 1,
      }, fromPeerId);
    }
  }
  
  /**
   * Handle incoming geo-proof request
   */
  async handleGeoProofRequest(message, fromPeerId) {
    if (!this.sendToPeer || !this.geoProofService) return;
    
    const proof = this.geoProofService.getProof();
    if (!proof) {
      log.debug('khata-trust', 'No geo-proof available to respond with');
      return;
    }
    
    const response = {
      type: KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE,
      requestId: message.messageId,
      proof: proof.serialize(),
      dokoId: this.nodeIdentity?.identity?.nodeId,
      timestamp: Date.now(),
    };
    
    await this.sendToPeer(fromPeerId, response);
  }
  
  /**
   * Handle incoming geo-proof response
   */
  async handleGeoProofResponse(message, fromPeerId) {
    this.emit('geo-proof-response', {
      requestId: message.requestId,
      proof: message.proof,
      dokoId: message.dokoId,
      fromPeerId,
    });
  }
  
  /**
   * Announce this node as a landmark
   */
  async announceLandmark(landmarkInfo) {
    if (!this.broadcastToPeers) return;
    
    const message = {
      type: KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE,
      messageId: generateMessageId(),
      landmark: {
        nodeId: this.nodeIdentity?.identity?.nodeId,
        name: landmarkInfo.name,
        region: landmarkInfo.region,
        coordinates: landmarkInfo.coordinates,  // { lat, lon }
        endpoint: landmarkInfo.endpoint,
        wsEndpoint: landmarkInfo.wsEndpoint,
        trustTier: landmarkInfo.trustTier,
        timeSource: landmarkInfo.timeSource,
      },
      timestamp: Date.now(),
    };
    
    // Sign announcement
    if (this.nodeIdentity) {
      const payload = JSON.stringify({
        landmark: message.landmark,
        timestamp: message.timestamp,
      });
      message.signature = this.nodeIdentity.sign(payload);
    }
    
    this.stats.landmarksAnnounced++;
    log.info('khata-trust', `Announcing as landmark: ${landmarkInfo.name} (${landmarkInfo.region})`);
    
    await this.broadcastToPeers(message);
    return message.messageId;
  }
  
  /**
   * Handle incoming landmark announcement
   */
  async handleLandmarkAnnounce(message, fromPeerId) {
    // Check for duplicate
    const hash = this.computeMessageHash(message);
    if (this.seenMessages.has(hash)) {
      return;
    }
    this.seenMessages.set(hash, Date.now());
    
    this.emit('landmark-announce', {
      landmark: message.landmark,
      fromPeerId,
    });
    
    // Register landmark if geo-proof service is available
    if (this.geoProofService) {
      try {
        this.geoProofService.registerLandmark(message.landmark);
        log.info('khata-trust', 
          `Registered landmark from gossip: ${message.landmark.name} (${message.landmark.region})`);
      } catch (err) {
        log.warn('khata-trust', `Failed to register landmark: ${err.message}`);
      }
    }
    
    // Propagate to other peers
    if (this.broadcastToPeers) {
      await this.broadcastToPeers(message, fromPeerId);
    }
  }
  
  /**
   * Request landmark verification from peer
   */
  async requestLandmarkVerify(peerId, landmarkId) {
    if (!this.sendToPeer) {
      throw new Error('Network layer not set');
    }
    
    const message = {
      type: KHATA_TRUST_MESSAGE.LANDMARK_VERIFY,
      messageId: generateMessageId(),
      landmarkId,
      requesterId: this.nodeIdentity?.identity?.nodeId,
      timestamp: Date.now(),
    };
    
    await this.sendToPeer(peerId, message);
    return message.messageId;
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // MESSAGE ROUTING
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Handle incoming trust message
   */
  async handleMessage(message, fromPeerId) {
    switch (message.type) {
      // Mesh Revocation
      case KHATA_TRUST_MESSAGE.ATTESTATION_ANNOUNCE:
        await this.handleAttestationAnnounce(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.REVOCATION_CERTIFICATE:
        await this.handleRevocationCertificate(message, fromPeerId);
        break;
        
      // Silicon Parity
      case KHATA_TRUST_MESSAGE.SILICON_CHALLENGE:
        await this.handleSiliconChallenge(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.SILICON_RESPONSE:
        await this.handleSiliconResponse(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.SILICON_IDENTITY:
        this.emit('silicon-identity', { identity: message.identity, dokoId: message.dokoId, fromPeerId });
        break;
        
      // Sybil Graph
      case KHATA_TRUST_MESSAGE.GRAPH_UPDATE:
        await this.handleGraphUpdate(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.CLUSTER_ALERT:
        await this.handleClusterAlert(message, fromPeerId);
        break;
        
      // Trust Tier
      case KHATA_TRUST_MESSAGE.TIER_ANNOUNCE:
        this.emit('tier-announce', { dokoId: message.dokoId, tier: message.tier, weight: message.weight, fromPeerId });
        break;
        
      // Geographic Proof (v2.5.0)
      case KHATA_TRUST_MESSAGE.GEO_PROOF_ANNOUNCE:
        await this.handleGeoProofAnnounce(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.GEO_PROOF_REQUEST:
        await this.handleGeoProofRequest(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.GEO_PROOF_RESPONSE:
        await this.handleGeoProofResponse(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.LANDMARK_ANNOUNCE:
        await this.handleLandmarkAnnounce(message, fromPeerId);
        break;
      case KHATA_TRUST_MESSAGE.LANDMARK_VERIFY:
        this.emit('landmark-verify-request', { landmarkId: message.landmarkId, requesterId: message.requesterId, fromPeerId });
        break;
        
      default:
        // Unknown message type - might be handled by base KHATA protocol
        return false;
    }
    
    return true;
  }
  
  /**
   * Check if message type is a trust message
   */
  isTrustMessage(messageType) {
    return Object.values(KHATA_TRUST_MESSAGE).includes(messageType);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════
  
  /**
   * Compute message hash for deduplication
   */
  computeMessageHash(message) {
    const content = JSON.stringify({
      type: message.type,
      messageId: message.messageId,
    });
    return bytesToHex(sha3_256(new TextEncoder().encode(content)));
  }
  
  /**
   * Cleanup old data
   */
  cleanup() {
    const now = Date.now();
    const maxAge = this.config.attestationTTL;
    
    for (const [hash, timestamp] of this.seenMessages.entries()) {
      if (now - timestamp > maxAge) {
        this.seenMessages.delete(hash);
      }
    }
  }
  
  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      seenMessagesSize: this.seenMessages.size,
      pendingChallenges: this.pendingChallenges.size,
    };
  }
  
  /**
   * Shutdown
   */
  destroy() {
    clearInterval(this.cleanupInterval);
    
    // Cleanup pending challenges
    for (const [id, pending] of this.pendingChallenges.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Integration shutdown'));
    }
    this.pendingChallenges.clear();
    this.seenMessages.clear();
  }
}

export default KhataTrustIntegration;
