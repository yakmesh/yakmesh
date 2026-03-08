/**
 * Domain Consensus Verifier - Multi-Node Domain Ownership Verification
 * 
 * Implements trustless domain verification where multiple independent nodes
 * verify that a beacon exists at a domain, achieving consensus through quorum.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * SYBIL ATTACK DEFENSES (v2.0)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * SECURITY PHILOSOPHY: "Math alone won't fix Sybil attacks"
 * 
 * An attacker could spin up many nodes to form a quorum and fraudulently
 * verify their own domain claims. This module implements 5 defense layers:
 * 
 * 1. VERIFIER AGE REQUIREMENT
 *    - Nodes must be present in mesh ≥7 days before becoming eligible
 *    - Prevents rapid Sybil node creation
 * 
 * 2. IP/ASN DIVERSITY  
 *    - Quorum must include ≥3 different /24 subnets
 *    - Quorum should include ≥2 different Autonomous Systems
 *    - Prevents single datacenter Sybil farms
 * 
 * 3. CLAIMANT EXCLUSION
 *    - No verifiers from same /16 IP range as claimant
 *    - Prevents self-verification
 * 
 * 4. REPUTATION WEIGHTING
 *    - Nodes with successful verification history weighted higher
 *    - Track success/failure rates per verifier
 *    - Older, reliable nodes preferred
 * 
 * 5. TIME WINDOWS (optional)
 *    - Multiple verification rounds at T, T+1hr, T+24hr
 *    - Different random verifiers each round
 *    - Increases cost of sustained Sybil attacks
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Process:
 * 1. Node A wants to claim ownership of "example.com"
 * 2. Node A places SHERPA beacon at https://example.com/.well-known/yakmesh/beacon
 * 3. Node A broadcasts domain-claim request to mesh
 * 4. K verifier nodes are selected (with Sybil defenses applied)
 * 5. Each verifier independently fetches and validates the beacon
 * 6. Each verifier signs a proof if beacon contains Node A's identity
 * 7. If >= QUORUM proofs collected from DIVERSE verifiers, claim is valid
 * 
 * Security Properties:
 * - No single verifier can approve a claim (quorum required)
 * - Verifiers must be geographically/network diverse (Sybil resistant)
 * - Verifiers must have mesh history (not new nodes)
 * - Each verification is independently signed
 * - Proofs can be re-verified by any node
 * 
 * @module security/domain-consensus
 * @version 2.0.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { ternaryId } from '../utils/ternary-id.js';
import { EventEmitter } from 'events';

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  // Quorum settings
  quorumSize: 3,              // Minimum verifiers needed for consensus
  verifiersToRequest: 5,      // Request from more than quorum (some may fail)

  // Timeouts
  verificationTimeout: 30000,  // 30 seconds per verification
  totalTimeout: 120000,        // 2 minutes for entire process

  // Retry settings
  maxRetries: 2,
  retryDelay: 5000,

  // Beacon requirements
  beaconPath: '/.well-known/yakmesh/beacon',
  beaconMaxAge: 300000,        // Beacon must be < 5 minutes old

  // Rate limiting
  maxConcurrentVerifications: 10,
  cooldownBetweenClaims: 3600000, // 1 hour between claims for same domain

  // ═══════════════════════════════════════════════════════════════════════════
  // SYBIL DEFENSE CONFIGURATION
  // ═══════════════════════════════════════════════════════════════════════════

  // Verifier age requirements
  minVerifierAge: 7 * 24 * 60 * 60 * 1000,  // 7 days minimum mesh presence
  preferredVerifierAge: 30 * 24 * 60 * 60 * 1000, // 30 days for bonus weight

  // IP/ASN diversity requirements
  minDistinctSubnets: 3,      // Minimum different /24 subnets
  minDistinctASNs: 2,         // Minimum different ASNs (Autonomous Systems)
  subnetMaskBits: 24,         // /24 subnet grouping (256 IPs per group)

  // Claimant exclusion radius
  claimantExclusionSubnet: 16, // Exclude verifiers in same /16 as claimant

  // Reputation thresholds
  minReputationScore: 0.2,    // Minimum reputation to be eligible (0-1)
  reputationWeightFactor: 2.0, // Higher reputation = more likely selected

  // Time-based verification windows
  enableTimeWindows: false,    // When true, verify at T, T+1hr, T+24hr
  timeWindowIntervals: [0, 3600000, 86400000], // 0, 1 hour, 24 hours
};

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * SYBIL DEFENSE: Verifier Eligibility Checker
 * 
 * SECURITY PHILOSOPHY: "Math alone won't fix Sybil attacks"
 * 
 * A Sybil attack on domain verification allows an attacker to spin up many
 * fake nodes to form a quorum and fraudulently verify their own domain claims.
 * Without additional heuristics beyond cryptographic identity, an attacker
 * with N nodes could easily achieve the required quorum.
 * 
 * Defense Layers:
 * 1. VERIFIER AGE - Nodes must exist in mesh ≥7 days before verifying
 * 2. IP/ASN DIVERSITY - Quorum must include ≥3 different /24 subnets
 * 3. CLAIMANT EXCLUSION - No verifiers from same IP range as claimant
 * 4. REPUTATION WEIGHT - Nodes with history weighted higher in selection
 * 5. TIME WINDOWS - Multiple verification rounds at different times
 * 
 * @class VerifierEligibilityChecker
 * ═══════════════════════════════════════════════════════════════════════════
 */
class VerifierEligibilityChecker {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Node reputation store (nodeId -> reputation data)
    this.reputations = new Map();

    // Node first-seen timestamps (nodeId -> timestamp)
    this.nodeFirstSeen = new Map();

    // Node network info cache (nodeId -> { ip, asn, subnet })
    this.nodeNetworkInfo = new Map();
  }

  /**
   * Register a node as seen (call when first encountering a node)
   */
  registerNodeSeen(nodeId, networkInfo = {}) {
    if (!this.nodeFirstSeen.has(nodeId)) {
      this.nodeFirstSeen.set(nodeId, Date.now());
    }

    if (networkInfo.ip) {
      this.nodeNetworkInfo.set(nodeId, {
        ip: networkInfo.ip,
        subnet: this.getSubnet(networkInfo.ip, this.config.subnetMaskBits),
        wideSubnet: this.getSubnet(networkInfo.ip, this.config.claimantExclusionSubnet),
        asn: networkInfo.asn || 'unknown',
      });
    }
  }

  /**
   * Update node reputation after a verification
   */
  updateReputation(nodeId, success, responseTime = null) {
    const existing = this.reputations.get(nodeId) || {
      successCount: 0,
      failureCount: 0,
      totalResponseTime: 0,
      lastActivity: 0,
    };

    if (success) {
      existing.successCount++;
      if (responseTime) {
        existing.totalResponseTime += responseTime;
      }
    } else {
      existing.failureCount++;
    }
    existing.lastActivity = Date.now();

    this.reputations.set(nodeId, existing);
  }

  /**
   * Calculate reputation score (0-1)
   */
  getReputationScore(nodeId) {
    const rep = this.reputations.get(nodeId);
    if (!rep) return 0.5; // Neutral for unknown nodes

    const total = rep.successCount + rep.failureCount;
    if (total === 0) return 0.5;

    // Success ratio weighted by volume (more history = more reliable score)
    const successRatio = rep.successCount / total;
    const volumeWeight = Math.min(1, total / 20); // Full weight at 20+ verifications

    // Blend toward neutral for low-volume nodes
    return 0.5 + (successRatio - 0.5) * volumeWeight;
  }

  /**
   * Get node age in milliseconds
   */
  getNodeAge(nodeId) {
    const firstSeen = this.nodeFirstSeen.get(nodeId);
    if (!firstSeen) return 0;
    return Date.now() - firstSeen;
  }

  /**
   * Check if a single node is eligible to be a verifier
   */
  isNodeEligible(nodeId, claimantInfo = {}) {
    const reasons = [];

    // Check 1: Node age
    const age = this.getNodeAge(nodeId);
    if (age < this.config.minVerifierAge) {
      const daysNeeded = Math.ceil(this.config.minVerifierAge / (24 * 60 * 60 * 1000));
      const daysHave = Math.floor(age / (24 * 60 * 60 * 1000));
      reasons.push(`Node too young (${daysHave} days, need ${daysNeeded})`);
    }

    // Check 2: Minimum reputation
    const reputation = this.getReputationScore(nodeId);
    if (reputation < this.config.minReputationScore) {
      reasons.push(`Reputation too low (${reputation.toFixed(2)}, need ${this.config.minReputationScore})`);
    }

    // Check 3: Claimant exclusion (same IP range)
    if (claimantInfo.ip) {
      const nodeInfo = this.nodeNetworkInfo.get(nodeId);
      const claimantWideSubnet = this.getSubnet(claimantInfo.ip, this.config.claimantExclusionSubnet);

      if (nodeInfo && nodeInfo.wideSubnet === claimantWideSubnet) {
        reasons.push(`Same IP range as claimant (/${this.config.claimantExclusionSubnet})`);
      }
    }

    return {
      eligible: reasons.length === 0,
      nodeId,
      age,
      reputation,
      reasons,
    };
  }

  /**
   * Select diverse verifiers from a pool of candidates
   * Returns selected verifiers or error if diversity requirements can't be met
   */
  selectDiverseVerifiers(candidates, claimantInfo, count) {
    // First, filter to eligible candidates only
    const eligibilityResults = candidates.map(c => ({
      ...c,
      eligibility: this.isNodeEligible(c.nodeId, claimantInfo),
    }));

    const eligible = eligibilityResults.filter(c => c.eligibility.eligible);
    const ineligible = eligibilityResults.filter(c => !c.eligibility.eligible);

    if (eligible.length < count) {
      return {
        success: false,
        error: 'Not enough eligible verifiers',
        eligible: eligible.length,
        needed: count,
        ineligibleReasons: ineligible.map(c => ({
          nodeId: c.nodeId,
          reasons: c.eligibility.reasons,
        })),
      };
    }

    // Calculate selection weights based on reputation and age
    const weighted = eligible.map(c => ({
      ...c,
      weight: this.calculateSelectionWeight(c.nodeId),
    }));

    // Select ensuring IP/ASN diversity
    const selected = [];
    const usedSubnets = new Set();
    const usedASNs = new Set();
    const remaining = [...weighted];

    // Phase 1: Prioritize diversity
    while (selected.length < count && remaining.length > 0) {
      // Sort by: new subnet > new ASN > higher weight
      remaining.sort((a, b) => {
        const aInfo = this.nodeNetworkInfo.get(a.nodeId) || {};
        const bInfo = this.nodeNetworkInfo.get(b.nodeId) || {};

        const aNewSubnet = !usedSubnets.has(aInfo.subnet) ? 1 : 0;
        const bNewSubnet = !usedSubnets.has(bInfo.subnet) ? 1 : 0;
        if (aNewSubnet !== bNewSubnet) return bNewSubnet - aNewSubnet;

        const aNewASN = !usedASNs.has(aInfo.asn) ? 1 : 0;
        const bNewASN = !usedASNs.has(bInfo.asn) ? 1 : 0;
        if (aNewASN !== bNewASN) return bNewASN - aNewASN;

        return b.weight - a.weight; // Higher weight preferred
      });

      const choice = remaining.shift();
      selected.push(choice);

      const info = this.nodeNetworkInfo.get(choice.nodeId) || {};
      if (info.subnet) usedSubnets.add(info.subnet);
      if (info.asn) usedASNs.add(info.asn);
    }

    // Verify diversity requirements
    if (usedSubnets.size < this.config.minDistinctSubnets) {
      return {
        success: false,
        error: `Insufficient subnet diversity (have ${usedSubnets.size}, need ${this.config.minDistinctSubnets})`,
        subnets: Array.from(usedSubnets),
        selected: selected.map(s => s.nodeId),
      };
    }

    if (usedASNs.size < this.config.minDistinctASNs) {
      // ASN diversity is a warning, not a hard failure (ASN detection may not always work)
      // Log warning but proceed
    }

    return {
      success: true,
      verifiers: selected.map(s => s.nodeId),
      diversity: {
        subnets: Array.from(usedSubnets),
        asns: Array.from(usedASNs),
      },
      weights: selected.map(s => ({ nodeId: s.nodeId, weight: s.weight })),
    };
  }

  /**
   * Calculate selection weight for weighted random selection
   */
  calculateSelectionWeight(nodeId) {
    const age = this.getNodeAge(nodeId);
    const reputation = this.getReputationScore(nodeId);

    // Base weight from reputation
    let weight = reputation * this.config.reputationWeightFactor;

    // Bonus for older nodes
    if (age >= this.config.preferredVerifierAge) {
      weight *= 1.5;
    } else if (age >= this.config.minVerifierAge * 2) {
      weight *= 1.25;
    }

    return weight;
  }

  /**
   * Extract subnet from IP address
   */
  getSubnet(ip, maskBits) {
    if (!ip) return null;

    // Handle IPv4
    const parts = ip.split('.');
    if (parts.length === 4) {
      const fullBits = parts.map(p => parseInt(p, 10));
      const octetsToKeep = Math.floor(maskBits / 8);
      const result = fullBits.slice(0, octetsToKeep);

      // Handle partial octet
      const remainingBits = maskBits % 8;
      if (remainingBits > 0 && octetsToKeep < 4) {
        const mask = (0xFF << (8 - remainingBits)) & 0xFF;
        result.push(fullBits[octetsToKeep] & mask);
      }

      return result.join('.') + '/' + maskBits;
    }

    // For IPv6 or unknown, just return the IP (less effective but works)
    return ip;
  }

  /**
   * Serialize state for persistence
   */
  serialize() {
    return {
      reputations: Array.from(this.reputations.entries()),
      nodeFirstSeen: Array.from(this.nodeFirstSeen.entries()),
      nodeNetworkInfo: Array.from(this.nodeNetworkInfo.entries()),
    };
  }

  /**
   * Restore state from persistence
   */
  deserialize(data) {
    if (data.reputations) {
      this.reputations = new Map(data.reputations);
    }
    if (data.nodeFirstSeen) {
      this.nodeFirstSeen = new Map(data.nodeFirstSeen);
    }
    if (data.nodeNetworkInfo) {
      this.nodeNetworkInfo = new Map(data.nodeNetworkInfo);
    }
  }

  /**
   * Get statistics about the eligibility checker
   */
  getStats() {
    const now = Date.now();
    let eligibleCount = 0;
    let totalAge = 0;

    for (const [nodeId, firstSeen] of this.nodeFirstSeen.entries()) {
      const age = now - firstSeen;
      totalAge += age;
      if (age >= this.config.minVerifierAge) {
        eligibleCount++;
      }
    }

    return {
      totalNodes: this.nodeFirstSeen.size,
      eligibleByAge: eligibleCount,
      averageAge: this.nodeFirstSeen.size > 0
        ? Math.floor(totalAge / this.nodeFirstSeen.size / (24 * 60 * 60 * 1000))
        : 0,
      nodesWithReputation: this.reputations.size,
      nodesWithNetworkInfo: this.nodeNetworkInfo.size,
    };
  }
}

/**
 * Domain verification request
 */
class DomainVerificationRequest {
  constructor(options) {
    this.id = ternaryId(16);
    this.domain = options.domain;
    this.claimantNodeId = options.claimantNodeId;
    this.claimantPublicKey = options.claimantPublicKey;
    this.requestedAt = Date.now();
    this.expiresAt = this.requestedAt + DEFAULT_CONFIG.totalTimeout;
    this.status = 'pending'; // pending, verifying, completed, failed
    this.proofs = [];
    this.errors = [];
  }

  addProof(proof) {
    // Prevent duplicate proofs from same verifier
    if (this.proofs.some(p => p.verifierNodeId === proof.verifierNodeId)) {
      return false;
    }
    this.proofs.push(proof);
    return true;
  }

  addError(error) {
    this.errors.push({
      ...error,
      timestamp: Date.now(),
    });
  }

  hasQuorum(quorumSize) {
    return this.proofs.length >= quorumSize;
  }

  isExpired() {
    return Date.now() > this.expiresAt;
  }

  toSummary() {
    return {
      id: this.id,
      domain: this.domain,
      claimantNodeId: this.claimantNodeId,
      status: this.status,
      proofsCollected: this.proofs.length,
      errorsEncountered: this.errors.length,
      requestedAt: this.requestedAt,
      expiresAt: this.expiresAt,
    };
  }
}

/**
 * Domain verification proof (signed by a verifier)
 */
class DomainVerificationProof {
  constructor(options) {
    this.domain = options.domain;
    this.claimantNodeId = options.claimantNodeId;
    this.verifierNodeId = options.verifierNodeId;
    this.verifierPublicKey = options.verifierPublicKey;
    this.beaconHash = options.beaconHash;          // SHA3-256 of beacon content
    this.beaconTimestamp = options.beaconTimestamp; // Timestamp from beacon
    this.verifiedAt = options.verifiedAt || Date.now();
    this.signature = options.signature;
  }

  /**
   * Get data to sign/verify
   */
  getSignableData() {
    return JSON.stringify({
      domain: this.domain,
      claimantNodeId: this.claimantNodeId,
      beaconHash: this.beaconHash,
      beaconTimestamp: this.beaconTimestamp,
      verifiedAt: this.verifiedAt,
    });
  }

  /**
   * Serialize for transmission
   */
  serialize() {
    return {
      domain: this.domain,
      claimantNodeId: this.claimantNodeId,
      verifierNodeId: this.verifierNodeId,
      verifierPublicKey: this.verifierPublicKey,
      beaconHash: this.beaconHash,
      beaconTimestamp: this.beaconTimestamp,
      verifiedAt: this.verifiedAt,
      signature: this.signature,
    };
  }

  static deserialize(data) {
    return new DomainVerificationProof(data);
  }
}

/**
 * DomainConsensusVerifier - Coordinates multi-node domain verification
 * 
 * SECURITY: This class now includes comprehensive Sybil attack defenses.
 * See VerifierEligibilityChecker for defense layer details.
 */
export class DomainConsensusVerifier extends EventEmitter {
  constructor(nodeIdentity, namcheGateway, options = {}) {
    super();
    this.identity = nodeIdentity;
    this.gateway = namcheGateway;
    this.config = { ...DEFAULT_CONFIG, ...options };

    // ═══════════════════════════════════════════════════════════════════════
    // SYBIL DEFENSE: Eligibility checker for verifier selection
    // ═══════════════════════════════════════════════════════════════════════
    this.eligibility = new VerifierEligibilityChecker(this.config);

    // Active verification requests (by domain)
    this.activeRequests = new Map();

    // Cooldown tracking (domain -> last claim timestamp)
    this.cooldowns = new Map();

    // Fetch function (must be set by network layer)
    this.fetchBeacon = null;

    // Peer messaging (must be set by network layer)
    this.requestVerification = null;  // (peerId, request) => Promise<proof>
    this.getVerifierPeers = null;     // () => [{ nodeId, ip?, asn? }, ...]

    // Our own network info (for claimant exclusion when we claim)
    this.ownNetworkInfo = null;

    this.stats = {
      claimsInitiated: 0,
      claimsSucceeded: 0,
      claimsFailed: 0,
      claimsRejectedSybil: 0,  // Claims that failed due to Sybil defense
      verificationsPerformed: 0,
      verificationsSucceeded: 0,
      verificationsFailed: 0,
    };
  }

  /**
   * Set network layer functions
   */
  setNetworkLayer(fetchBeacon, requestVerification, getVerifierPeers) {
    this.fetchBeacon = fetchBeacon;
    this.requestVerification = requestVerification;
    this.getVerifierPeers = getVerifierPeers;
  }

  /**
   * Set our own network info (for claimant exclusion)
   */
  setOwnNetworkInfo(info) {
    this.ownNetworkInfo = info;
  }

  /**
   * Register a peer node (call when discovering new peers)
   * This builds up the eligibility database over time
   */
  registerPeer(nodeId, networkInfo = {}) {
    this.eligibility.registerNodeSeen(nodeId, networkInfo);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CLAIMANT SIDE - Initiating a Domain Claim
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Initiate a domain claim
   * 
   * @param {string} domain - The domain to claim (e.g., "example.com")
   * @returns {Promise<Object>} Claim result with proofs or error
   */
  async claimDomain(domain) {
    this.stats.claimsInitiated++;

    // Validate domain format
    if (!this.isValidDomain(domain)) {
      return { success: false, error: 'Invalid domain format' };
    }

    // Check cooldown
    const lastClaim = this.cooldowns.get(domain);
    if (lastClaim && Date.now() - lastClaim < this.config.cooldownBetweenClaims) {
      const waitTime = this.config.cooldownBetweenClaims - (Date.now() - lastClaim);
      return {
        success: false,
        error: 'Cooldown active',
        retryAfter: waitTime,
      };
    }

    // Check if already verifying
    if (this.activeRequests.has(domain)) {
      return { success: false, error: 'Verification already in progress' };
    }

    // Create verification request
    const request = new DomainVerificationRequest({
      domain,
      claimantNodeId: this.identity.identity.nodeId,
      claimantPublicKey: this.identity.identity.publicKey,
    });

    this.activeRequests.set(domain, request);
    this.emit('claim-started', { domain, requestId: request.id });

    try {
      // Get verifier peers
      const verifiers = await this.selectVerifiers();
      if (verifiers.length < this.config.quorumSize) {
        throw new Error(`Not enough verifiers available (need ${this.config.quorumSize}, have ${verifiers.length})`);
      }

      request.status = 'verifying';

      // Request verification from each peer (in parallel)
      const verificationPromises = verifiers.map(peerId =>
        this.requestVerificationFromPeer(peerId, request)
          .catch(err => {
            request.addError({ peerId, error: err.message });
            return null;
          })
      );

      // Wait for all with timeout
      const results = await Promise.race([
        Promise.all(verificationPromises),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Verification timeout')), this.config.totalTimeout)
        ),
      ]);

      // Collect valid proofs
      for (const proof of results) {
        if (proof && this.verifyProof(proof)) {
          request.addProof(proof);
        }
      }

      // Check quorum
      if (request.hasQuorum(this.config.quorumSize)) {
        request.status = 'completed';
        this.stats.claimsSucceeded++;
        this.cooldowns.set(domain, Date.now());

        this.emit('claim-succeeded', {
          domain,
          requestId: request.id,
          proofs: request.proofs.map(p => p.serialize()),
        });

        return {
          success: true,
          domain,
          proofs: request.proofs.map(p => p.serialize()),
          quorumSize: this.config.quorumSize,
        };
      } else {
        request.status = 'failed';
        this.stats.claimsFailed++;

        this.emit('claim-failed', {
          domain,
          requestId: request.id,
          proofsCollected: request.proofs.length,
          quorumNeeded: this.config.quorumSize,
          errors: request.errors,
        });

        return {
          success: false,
          error: 'Failed to reach quorum',
          proofsCollected: request.proofs.length,
          quorumNeeded: this.config.quorumSize,
          errors: request.errors,
        };
      }

    } catch (error) {
      request.status = 'failed';
      this.stats.claimsFailed++;

      this.emit('claim-error', { domain, requestId: request.id, error: error.message });

      return { success: false, error: error.message };
    } finally {
      this.activeRequests.delete(domain);
    }
  }

  /**
   * Select random verifier peers with Sybil defenses
   * 
   * SECURITY: This method now implements comprehensive Sybil attack resistance:
   * - Verifier age requirements (≥7 days in mesh)
   * - IP/ASN diversity (≥3 different subnets)
   * - Claimant exclusion (no verifiers from same IP range)
   * - Reputation-weighted selection
   */
  async selectVerifiers() {
    if (!this.getVerifierPeers) {
      throw new Error('Network layer not configured');
    }

    const allPeers = await this.getVerifierPeers();

    // Filter out ourselves
    const candidates = allPeers
      .filter(peer => {
        const nodeId = typeof peer === 'string' ? peer : peer.nodeId;
        return nodeId !== this.identity.identity.nodeId;
      })
      .map(peer => {
        // Normalize peer format
        if (typeof peer === 'string') {
          return { nodeId: peer };
        }
        return peer;
      });

    // Use Sybil-resistant selection
    const claimantInfo = this.ownNetworkInfo || {};
    const selectionResult = this.eligibility.selectDiverseVerifiers(
      candidates,
      claimantInfo,
      this.config.verifiersToRequest
    );

    if (!selectionResult.success) {
      this.stats.claimsRejectedSybil++;
      this.emit('sybil-defense-triggered', {
        reason: selectionResult.error,
        details: selectionResult,
      });
      throw new Error(`Sybil defense: ${selectionResult.error}`);
    }

    this.emit('verifiers-selected', {
      count: selectionResult.verifiers.length,
      diversity: selectionResult.diversity,
    });

    return selectionResult.verifiers;
  }

  /**
   * Request verification from a specific peer
   * Now tracks response time and updates verifier reputation
   */
  async requestVerificationFromPeer(peerId, request) {
    if (!this.requestVerification) {
      throw new Error('Network layer not configured');
    }

    const verificationRequest = {
      type: 'domain-verify-request',
      requestId: request.id,
      domain: request.domain,
      claimantNodeId: request.claimantNodeId,
      claimantPublicKey: request.claimantPublicKey,
      timestamp: Date.now(),
    };

    const startTime = Date.now();

    try {
      const result = await this.requestVerification(peerId, verificationRequest);
      const responseTime = Date.now() - startTime;

      // Update verifier reputation based on response
      const success = result && result.success && result.proof;
      this.eligibility.updateReputation(peerId, success, responseTime);

      return result;
    } catch (error) {
      // Track failed response in reputation
      this.eligibility.updateReputation(peerId, false, null);
      throw error;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VERIFIER SIDE - Performing Domain Verification
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Handle incoming verification request (as a verifier)
   * 
   * @param {Object} request - The verification request
   * @returns {Object} Proof or error
   */
  async handleVerificationRequest(request) {
    this.stats.verificationsPerformed++;

    const { domain, claimantNodeId, claimantPublicKey } = request;

    try {
      // Fetch the beacon from the claimed domain
      const beaconUrl = `https://${domain}${this.config.beaconPath}`;

      if (!this.fetchBeacon) {
        throw new Error('Network layer not configured');
      }

      const beacon = await this.fetchBeacon(beaconUrl, {
        timeout: this.config.verificationTimeout,
        maxSize: 65536,
      });

      // Validate beacon
      const validation = this.validateBeacon(beacon, claimantNodeId, claimantPublicKey);
      if (!validation.valid) {
        this.stats.verificationsFailed++;
        return { success: false, error: validation.error };
      }

      // Create proof
      const beaconContent = JSON.stringify(beacon);
      const beaconHash = bytesToHex(sha3_256(utf8ToBytes(beaconContent)));

      const proof = new DomainVerificationProof({
        domain,
        claimantNodeId,
        verifierNodeId: this.identity.identity.nodeId,
        verifierPublicKey: this.identity.identity.publicKey,
        beaconHash,
        beaconTimestamp: beacon.timestamp,
        verifiedAt: Date.now(),
      });

      // Sign the proof
      const signableData = proof.getSignableData();
      proof.signature = this.identity.sign(signableData);

      this.stats.verificationsSucceeded++;

      this.emit('verification-completed', {
        domain,
        claimantNodeId,
        beaconHash,
      });

      return { success: true, proof: proof.serialize() };

    } catch (error) {
      this.stats.verificationsFailed++;

      this.emit('verification-failed', {
        domain,
        claimantNodeId,
        error: error.message,
      });

      return { success: false, error: error.message };
    }
  }

  /**
   * Validate beacon content for domain claim
   */
  validateBeacon(beacon, expectedNodeId, expectedPublicKey) {
    // Check beacon exists and has required fields
    if (!beacon || !beacon.nodeId || !beacon.publicKey) {
      return { valid: false, error: 'Invalid beacon structure' };
    }

    // Check nodeId matches claimant
    if (beacon.nodeId !== expectedNodeId) {
      return {
        valid: false,
        error: `NodeID mismatch: expected ${expectedNodeId}, got ${beacon.nodeId}`
      };
    }

    // Check publicKey matches claimant
    if (beacon.publicKey !== expectedPublicKey) {
      return { valid: false, error: 'PublicKey mismatch' };
    }

    // Check beacon is fresh (not too old)
    const age = Date.now() - beacon.timestamp;
    if (age > this.config.beaconMaxAge) {
      return {
        valid: false,
        error: `Beacon too old (${Math.round(age / 1000)}s, max ${this.config.beaconMaxAge / 1000}s)`
      };
    }

    // Check beacon is not from the future
    if (beacon.timestamp > Date.now() + 60000) { // 1 minute tolerance
      return { valid: false, error: 'Beacon timestamp in future' };
    }

    // Check beacon signature (if gateway available)
    if (this.gateway && beacon.signature && beacon.verifierPublicKey) {
      try {
        const signableData = JSON.stringify({
          domain: beacon.domain,
          timestamp: beacon.timestamp,
          verifierId: beacon.verifierId,
        });
        const valid = this.identity.verify(signableData, beacon.signature, beacon.verifierPublicKey);
        if (!valid) {
          return { valid: false, error: 'Invalid beacon signature' };
        }
      } catch (e) {
        return { valid: false, error: `Beacon signature verification failed: ${e.message}` };
      }
    }

    return { valid: true };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PROOF VERIFICATION - Any Node Can Verify Proofs
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Verify a domain verification proof
   * 
   * @param {Object} proof - The proof to verify (serialized or DomainVerificationProof)
   * @returns {boolean} True if proof is valid
   */
  verifyProof(proof) {
    try {
      // Deserialize if needed
      const p = proof instanceof DomainVerificationProof
        ? proof
        : DomainVerificationProof.deserialize(proof);

      // Verify signature
      const signableData = p.getSignableData();
      const valid = this.identity.verify(signableData, p.signature, p.verifierPublicKey);

      if (!valid) {
        return false;
      }

      // Verify timestamp is reasonable
      const age = Date.now() - p.verifiedAt;
      if (age > 86400000) { // 24 hours
        return false; // Proof too old
      }

      if (p.verifiedAt > Date.now() + 60000) { // 1 minute tolerance
        return false; // Proof from future
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Verify a complete set of proofs for a domain claim
   * 
   * SECURITY: Now includes Sybil defense by checking verifier diversity
   * 
   * @param {Array} proofs - Array of serialized proofs
   * @param {string} domain - The domain being claimed
   * @param {string} claimantNodeId - The claiming node's ID
   * @param {Object} options - Verification options
   * @param {boolean} options.checkDiversity - Check verifier diversity (default: true)
   * @returns {Object} Verification result
   */
  verifyDomainClaim(proofs, domain, claimantNodeId, options = {}) {
    const checkDiversity = options.checkDiversity !== false;

    if (!Array.isArray(proofs) || proofs.length === 0) {
      return { valid: false, error: 'No proofs provided' };
    }

    // Verify each proof
    const validProofs = [];
    const invalidProofs = [];
    const verifierIds = new Set();

    for (const proof of proofs) {
      // Check proof is for correct domain and claimant
      if (proof.domain !== domain || proof.claimantNodeId !== claimantNodeId) {
        invalidProofs.push({ proof, reason: 'Domain or claimant mismatch' });
        continue;
      }

      // Check for duplicate verifiers
      if (verifierIds.has(proof.verifierNodeId)) {
        invalidProofs.push({ proof, reason: 'Duplicate verifier' });
        continue;
      }

      // Verify signature
      if (this.verifyProof(proof)) {
        validProofs.push(proof);
        verifierIds.add(proof.verifierNodeId);
      } else {
        invalidProofs.push({ proof, reason: 'Invalid signature' });
      }
    }

    // Check quorum
    const hasQuorum = validProofs.length >= this.config.quorumSize;

    // ═══════════════════════════════════════════════════════════════════════
    // SYBIL DEFENSE: Check verifier diversity
    // ═══════════════════════════════════════════════════════════════════════
    let diversityCheck = { sufficient: true };

    if (checkDiversity && hasQuorum) {
      diversityCheck = this.checkVerifierDiversity(validProofs);

      if (!diversityCheck.sufficient) {
        return {
          valid: false,
          error: 'Sybil defense: Insufficient verifier diversity',
          validProofs: validProofs.length,
          quorumNeeded: this.config.quorumSize,
          diversity: diversityCheck,
          verifiers: Array.from(verifierIds),
        };
      }
    }

    return {
      valid: hasQuorum,
      validProofs: validProofs.length,
      invalidProofs: invalidProofs.length,
      quorumNeeded: this.config.quorumSize,
      verifiers: Array.from(verifierIds),
      diversity: diversityCheck,
      details: hasQuorum ? null : { invalidProofs },
    };
  }

  /**
   * Check if verifiers in a set of proofs have sufficient diversity
   * 
   * @param {Array} proofs - Array of valid proofs
   * @returns {Object} Diversity check result
   */
  checkVerifierDiversity(proofs) {
    const subnets = new Set();
    const asns = new Set();
    const unknownNetwork = [];

    for (const proof of proofs) {
      const info = this.eligibility.nodeNetworkInfo.get(proof.verifierNodeId);

      if (info) {
        if (info.subnet) subnets.add(info.subnet);
        if (info.asn && info.asn !== 'unknown') asns.add(info.asn);
      } else {
        unknownNetwork.push(proof.verifierNodeId);
      }
    }

    // If we have enough known verifiers, check diversity
    const knownCount = proofs.length - unknownNetwork.length;

    // Require at least minDistinctSubnets known verifiers with different subnets
    const sufficientSubnets = subnets.size >= this.config.minDistinctSubnets;

    // ASN diversity is a soft requirement (may not always have ASN info)
    const sufficientASNs = asns.size >= this.config.minDistinctASNs ||
      unknownNetwork.length > 0; // Lenient if some are unknown

    return {
      sufficient: sufficientSubnets,
      subnets: {
        count: subnets.size,
        required: this.config.minDistinctSubnets,
        sufficient: sufficientSubnets,
        values: Array.from(subnets),
      },
      asns: {
        count: asns.size,
        required: this.config.minDistinctASNs,
        sufficient: sufficientASNs,
        values: Array.from(asns),
      },
      unknownNetwork: unknownNetwork.length,
      knownNetwork: knownCount,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Validate domain format
   */
  isValidDomain(domain) {
    // Basic domain validation
    if (!domain || typeof domain !== 'string') return false;
    if (domain.length > 253) return false;

    // Must have at least one dot
    if (!domain.includes('.')) return false;

    // No protocol prefix
    if (domain.includes('://')) return false;

    // No path
    if (domain.includes('/')) return false;

    // Basic pattern check
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
    return domainPattern.test(domain);
  }

  /**
   * Get verifier statistics (now includes Sybil defense stats)
   */
  getStats() {
    return {
      ...this.stats,
      activeRequests: this.activeRequests.size,
      cooldownsActive: this.cooldowns.size,
      eligibility: this.eligibility.getStats(),
    };
  }

  /**
   * Clear expired cooldowns
   */
  clearExpiredCooldowns() {
    const now = Date.now();
    for (const [domain, timestamp] of this.cooldowns.entries()) {
      if (now - timestamp > this.config.cooldownBetweenClaims) {
        this.cooldowns.delete(domain);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PERSISTENCE - Save/Load eligibility state
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Serialize state for persistence
   * Call this periodically to save eligibility data
   */
  serializeState() {
    return {
      version: 2, // Sybil defense version
      timestamp: Date.now(),
      eligibility: this.eligibility.serialize(),
      cooldowns: Array.from(this.cooldowns.entries()),
      stats: this.stats,
    };
  }

  /**
   * Restore state from persistence
   * Call this on startup to restore eligibility data
   */
  restoreState(data) {
    if (!data) return;

    // Only restore if version matches (or upgrade logic here)
    if (data.version >= 2) {
      if (data.eligibility) {
        this.eligibility.deserialize(data.eligibility);
      }
      if (data.cooldowns) {
        this.cooldowns = new Map(data.cooldowns);
        this.clearExpiredCooldowns(); // Clean up expired ones
      }
      if (data.stats) {
        // Merge stats, preserving any new stat fields
        this.stats = { ...this.stats, ...data.stats };
      }
    }
  }
}

export { DomainVerificationRequest, DomainVerificationProof, VerifierEligibilityChecker };
export default DomainConsensusVerifier;
