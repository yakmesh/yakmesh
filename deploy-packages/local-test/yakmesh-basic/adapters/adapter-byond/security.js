/**
 * BYOND Adapter Security Integration
 * 
 * Integrates Yakmesh v2.0 security features with BYOND game servers:
 * 1. Player DOKO Identities - Self-sovereign player identities
 * 2. Server Verification - NAMCHE-style multi-gate verification
 * 3. Trust-Based Features - Variable access based on trust level
 * 4. Encrypted Messaging - ANNEX integration for server-to-server comms
 * 
 * @module adapters/adapter-byond/security
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { 
  DOKO_TYPES,
  DOKODocument,
  DOKOGenerator,
  DOKOValidator,
  DOKOStore,
} from '../../security/doko-identity.js';

import HybridTrustModel, {
  TrustEvidence,
  TrustLevel,
} from '../../security/hybrid-trust.js';

// ═══════════════════════════════════════════════════════════════════════════════
// PLAYER IDENTITY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Player Identity Manager
 * Links BYOND ckeys to DOKO identities
 */
export class PlayerIdentityManager {
  constructor(adapter) {
    this.adapter = adapter;
    this.dokoStore = new DOKOStore();
    this.ckeyToDokoMap = new Map();  // ckey -> dokoId
    this.pendingVerifications = new Map();
  }

  /**
   * Create a DOKO for a BYOND player
   * @param {string} ckey - BYOND ckey (case-insensitive username)
   * @param {Object} options - Additional options
   */
  createPlayerIdentity(ckey, options = {}) {
    const normalizedCkey = ckey.toLowerCase().replace(/[^a-z0-9]/g, '');
    
    // Check for existing DOKO
    const existing = this.dokoStore.getByCkey(normalizedCkey);
    if (existing) {
      return {
        success: false,
        error: 'PLAYER_ALREADY_HAS_DOKO',
        existingDokoId: existing.dokoId,
      };
    }

    // Generate player DOKO
    const result = DOKOGenerator.generateTrader({
      username: normalizedCkey,
      claims: {
        platform: 'byond',
        ckey: normalizedCkey,
        displayName: ckey,
        registeredAt: Date.now(),
        ...options.claims,
      },
    });

    // Store DOKO
    this.dokoStore.add(result.doko);
    this.ckeyToDokoMap.set(normalizedCkey, result.doko.dokoId);

    // Propagate to mesh
    this.adapter.node.gossip.spreadRumor('byond:doko:player', {
      doko: result.doko.toJSON(),
      ckey: normalizedCkey,
      timestamp: Date.now(),
    });

    return {
      success: true,
      dokoId: result.doko.dokoId,
      doko: result.doko,
      // IMPORTANT: Return secret key only once
      secretKey: result.secretKey,
    };
  }

  /**
   * Get DOKO for a player by ckey
   * @param {string} ckey - BYOND ckey
   */
  getPlayerDoko(ckey) {
    const normalizedCkey = ckey.toLowerCase().replace(/[^a-z0-9]/g, '');
    const dokoId = this.ckeyToDokoMap.get(normalizedCkey);
    if (!dokoId) return null;
    return this.dokoStore.get(dokoId);
  }

  /**
   * Verify a player's DOKO signature
   * @param {string} ckey - Player ckey
   * @param {string} challenge - Challenge string
   * @param {string} signature - Signed challenge
   */
  verifyPlayerSignature(ckey, challenge, signature) {
    const doko = this.getPlayerDoko(ckey);
    if (!doko) {
      return { valid: false, error: 'DOKO_NOT_FOUND' };
    }

    const isValid = DOKOValidator.verifySignature(doko, challenge, signature);
    return { valid: isValid, dokoId: doko.dokoId };
  }

  /**
   * Link an existing DOKO to a BYOND ckey
   * Requires proof of DOKO ownership
   */
  linkExistingDoko(ckey, dokoId, proof) {
    const doko = this.dokoStore.get(dokoId);
    if (!doko) {
      return { success: false, error: 'DOKO_NOT_FOUND' };
    }

    // Verify ownership proof
    const isValid = DOKOValidator.verifySignature(doko, ckey, proof);
    if (!isValid) {
      return { success: false, error: 'INVALID_PROOF' };
    }

    const normalizedCkey = ckey.toLowerCase().replace(/[^a-z0-9]/g, '');
    this.ckeyToDokoMap.set(normalizedCkey, dokoId);

    return { success: true, dokoId };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVER VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Server Verification Manager
 * NAMCHE-style multi-gate verification for BYOND servers
 */
export class ServerVerificationManager {
  constructor(adapter) {
    this.adapter = adapter;
    this.verifications = new Map();  // serverId -> VerificationState
  }

  /**
   * Verification gates for BYOND servers
   */
  static GATES = {
    // Gate 1: Server responds to Topic ping
    TOPIC_REACHABLE: 'topic_reachable',
    
    // Gate 2: Server version matches claimed version
    VERSION_MATCH: 'version_match',
    
    // Gate 3: Server responds to signed challenge
    CHALLENGE_RESPONSE: 'challenge_response',
    
    // Gate 4: Server is registered on BYOND hub (if claimed)
    HUB_REGISTRATION: 'hub_registration',
    
    // Gate 5: Multiple mesh nodes confirm server
    MESH_CONSENSUS: 'mesh_consensus',
  };

  /**
   * Start verification process for a server
   * @param {string} serverId - Server ID to verify
   */
  async verifyServer(serverId) {
    const server = this.adapter.localServers.get(serverId) || 
                   this.adapter.remoteServers.get(serverId);
    
    if (!server) {
      return { success: false, error: 'SERVER_NOT_FOUND' };
    }

    const state = {
      serverId,
      startTime: Date.now(),
      gates: {},
      verified: false,
    };

    // Gate 1: Topic Reachable
    state.gates[ServerVerificationManager.GATES.TOPIC_REACHABLE] = 
      await this._checkTopicReachable(server);

    // Gate 2: Version Match
    state.gates[ServerVerificationManager.GATES.VERSION_MATCH] = 
      await this._checkVersionMatch(server);

    // Gate 3: Challenge Response (optional - requires DMAPI integration)
    state.gates[ServerVerificationManager.GATES.CHALLENGE_RESPONSE] = 
      await this._checkChallengeResponse(server);

    // Gate 4: Hub Registration (if applicable)
    if (server.metadata.hub) {
      state.gates[ServerVerificationManager.GATES.HUB_REGISTRATION] = 
        await this._checkHubRegistration(server);
    } else {
      state.gates[ServerVerificationManager.GATES.HUB_REGISTRATION] = null;
    }

    // Count passed gates
    const passedGates = Object.values(state.gates).filter(g => g === true).length;
    const totalGates = Object.values(state.gates).filter(g => g !== null).length;
    
    // Need at least 3 gates to verify (or 2 if hub registration N/A)
    state.verified = passedGates >= Math.min(3, totalGates);
    state.passedGates = passedGates;
    state.totalGates = totalGates;

    this.verifications.set(serverId, state);

    // Update server verification status
    server.verified = state.verified;

    // Broadcast verification result
    this.adapter.node.gossip.spreadRumor('byond:server:verified', {
      serverId,
      verified: state.verified,
      passedGates,
      totalGates,
      timestamp: Date.now(),
    });

    return state;
  }

  async _checkTopicReachable(server) {
    try {
      const online = await this.adapter.topicClient.ping(server.host, server.port);
      return online;
    } catch {
      return false;
    }
  }

  async _checkVersionMatch(server) {
    try {
      const status = await this.adapter.topicClient.queryStatus(server.host, server.port);
      if (status.parsed?.version) {
        return status.parsed.version === server.version;
      }
      return true; // No version claim to verify
    } catch {
      return false;
    }
  }

  async _checkChallengeResponse(server) {
    // This requires the game to have DMAPI integration
    // For now, skip this gate
    return null;
  }

  async _checkHubRegistration(server) {
    // Check BYOND hub registration
    // Would need to query byond.com/games API
    // For now, return null (skip)
    return null;
  }

  /**
   * Get verification state for a server
   */
  getVerificationState(serverId) {
    return this.verifications.get(serverId);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRUST-BASED FEATURES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Trust-based feature manager for BYOND
 */
export class BYONDTrustManager {
  constructor(adapter) {
    this.adapter = adapter;
    this.trustModel = new HybridTrustModel();
    
    // Feature thresholds
    this.featureThresholds = {
      // Basic features available to all
      SERVER_DISCOVERY: TrustLevel.STRANGER,
      TOPIC_QUERY: TrustLevel.STRANGER,
      
      // Requires some trust
      WORLD_PERSISTENCE: TrustLevel.ACQUAINTANCE,
      TOPIC_RELAY: TrustLevel.ACQUAINTANCE,
      
      // Requires established trust
      SERVER_TO_SERVER_MESSAGING: TrustLevel.FRIEND,
      CROSS_SERVER_PLAYER_DATA: TrustLevel.FRIEND,
      
      // Maximum trust required
      MESH_VERIFICATION_VOTE: TrustLevel.TRUSTED_PARTNER,
    };
  }

  /**
   * Check if a server can use a feature
   */
  canUseFeature(serverId, feature) {
    const threshold = this.featureThresholds[feature];
    if (threshold === undefined) {
      return false;
    }
    
    const trust = this.getServerTrust(serverId);
    return trust.level >= threshold;
  }

  /**
   * Get trust level for a server
   */
  getServerTrust(serverId) {
    // Get server's DOKO if it has one
    const server = this.adapter.localServers.get(serverId) || 
                   this.adapter.remoteServers.get(serverId);
    
    if (!server) {
      return { level: TrustLevel.UNTRUSTED, score: 0 };
    }

    // Calculate trust from evidence
    const evidence = [];
    
    // Evidence: Server age
    if (server.lastSeen) {
      const ageMs = Date.now() - (server.metadata.firstSeen || server.lastSeen);
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays > 7) {
        evidence.push(new TrustEvidence('SERVER_AGE', 0.2, { ageDays }));
      }
    }
    
    // Evidence: Verified status
    if (server.verified) {
      evidence.push(new TrustEvidence('VERIFIED', 0.3, {}));
    }
    
    // Evidence: Player count history
    if (server.players > 0) {
      evidence.push(new TrustEvidence('ACTIVE_PLAYERS', 0.1, { players: server.players }));
    }

    const trustResult = this.trustModel.calculateTrust(evidence);
    return trustResult;
  }

  /**
   * Record positive/negative evidence for a server
   */
  recordEvidence(serverId, type, positive, data = {}) {
    const weight = positive ? 0.1 : -0.2;
    const evidence = new TrustEvidence(type, weight, data);
    this.trustModel.recordEvidence(serverId, evidence);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SECURITY CLASS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * BYOND Security Integration
 * Combines all security features for the BYOND adapter
 */
export class BYONDSecurity extends EventEmitter {
  constructor(adapter) {
    super();
    
    this.adapter = adapter;
    this.players = new PlayerIdentityManager(adapter);
    this.verification = new ServerVerificationManager(adapter);
    this.trust = new BYONDTrustManager(adapter);
    
    this._registerMeshHandlers();
  }

  _registerMeshHandlers() {
    this.adapter.node.mesh.on('rumor', (topic, data, origin) => {
      switch (topic) {
        case 'byond:doko:player':
          this._handlePlayerDoko(data, origin);
          break;
        case 'byond:server:verified':
          this._handleServerVerified(data, origin);
          break;
      }
    });
  }

  _handlePlayerDoko(data, origin) {
    // Store discovered player DOKOs
    if (data.doko) {
      try {
        const doko = DOKODocument.fromJSON(data.doko);
        this.players.dokoStore.add(doko);
        if (data.ckey) {
          this.players.ckeyToDokoMap.set(data.ckey, doko.dokoId);
        }
        this.emit('player-discovered', { doko, ckey: data.ckey, origin });
      } catch (err) {
        console.warn(`Invalid player DOKO from ${origin}: ${err.message}`);
      }
    }
  }

  _handleServerVerified(data, origin) {
    const server = this.adapter.remoteServers.get(data.serverId);
    if (server && data.verified) {
      server.verified = true;
      this.emit('server-verified', { serverId: data.serverId, origin });
    }
  }

  /**
   * Quick access methods
   */
  createPlayerDoko(ckey, options) {
    return this.players.createPlayerIdentity(ckey, options);
  }

  getPlayerDoko(ckey) {
    return this.players.getPlayerDoko(ckey);
  }

  verifyServer(serverId) {
    return this.verification.verifyServer(serverId);
  }

  canUseFeature(serverId, feature) {
    return this.trust.canUseFeature(serverId, feature);
  }
}

export default BYONDSecurity;
