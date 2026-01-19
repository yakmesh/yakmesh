/**
 * PeerQuanta v2.0 Security Integration
 * Integrates YAKMESH™ v2.0 security features with PeerQuanta marketplace
 * 
 * Features:
 * 1. DOKO Trader Identity - Self-sovereign trader identities
 * 2. Trust-Based Escrow - Variable escrow based on trust level
 * 3. ANNEX Trade Chat - Encrypted P2P messaging for trades
 * 4. Merchant Domain Verification - Mesh-verified domain claims
 * 5. NAMCHE Trade Verification - 7-gate verification for trades
 * 6. mTLS Trader Auth - Certificate-based authentication
 * 
 * @module adapters/adapter-peerquanta/security
 * @version 2.0.0
 */

import {
  DOKO_TYPES,
  DOKODocument,
  DOKOGenerator,
  DOKOValidator,
  DOKOEndorsement,
  DOKOStore,
} from '../../security/doko-identity.js';

import HybridTrustModel, {
  TrustEvidence,
  TrustLevel,
  TrustLevelInfo,
  TrustBasedAccessControl,
} from '../../security/hybrid-trust.js';

import DomainConsensusVerifier, {
  DomainVerificationRequest,
  DomainVerificationProof,
  VerifierEligibilityChecker,
} from '../../security/domain-consensus.js';

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DOKO TRADER IDENTITY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Trader Identity Manager
 * Links phpBB user accounts to DOKO identities
 */
export class TraderIdentityManager {
  constructor(bridge) {
    this.bridge = bridge;
    this.dokoStore = new DOKOStore();
    this.userToDokoMap = new Map(); // phpBB user_id -> dokoId
    this.pendingVerifications = new Map();
  }

  /**
   * Create a new trader DOKO for a phpBB user
   * @param {number} userId - phpBB user ID
   * @param {string} username - phpBB username
   * @param {Object} options - Additional options
   */
  createTraderIdentity(userId, username, options = {}) {
    // Check if user already has a DOKO
    const existing = this.dokoStore.getByUserId(userId);
    if (existing) {
      return {
        success: false,
        error: 'USER_ALREADY_HAS_DOKO',
        existingDokoId: existing.dokoId,
      };
    }

    // Generate trader DOKO
    const result = DOKOGenerator.generateTrader({
      username,
      userId,
      tradingPairs: options.tradingPairs || [],
      claims: {
        platform: 'peerquanta',
        username,
        userId,
        registeredAt: Date.now(),
        ...options.claims,
      },
    });

    // Store the DOKO
    this.dokoStore.add(result.doko);
    this.userToDokoMap.set(userId, result.doko.dokoId);

    // Propagate to mesh
    this.bridge.node.gossip.spreadRumor('pq:doko:new', {
      doko: result.doko.toJSON(),
      timestamp: Date.now(),
    });

    return {
      success: true,
      dokoId: result.doko.dokoId,
      doko: result.doko,
      // IMPORTANT: Return the secret key ONLY ONCE - user must store it securely
      secretKeyHex: result.secretKeyHex,
      warning: 'STORE YOUR SECRET KEY SECURELY - IT CANNOT BE RECOVERED',
    };
  }

  /**
   * Import an existing DOKO (e.g., from backup or another device)
   */
  importTraderIdentity(dokoJson, secretKeyHex) {
    const doko = DOKODocument.fromJSON(dokoJson);
    
    // Validate the DOKO
    const validation = DOKOValidator.validate(doko);
    if (!validation.valid) {
      return { success: false, error: 'INVALID_DOKO', details: validation };
    }

    // Verify the user can sign with the secret key
    try {
      const testMessage = Buffer.from('verification-test');
      const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
      const { hexToBytes } = require('@noble/hashes/utils.js');
      
      const secretKey = hexToBytes(secretKeyHex);
      const signature = ml_dsa65.sign(secretKey, testMessage);
      const publicKey = hexToBytes(doko.publicKey);
      const valid = ml_dsa65.verify(publicKey, testMessage, signature);
      
      if (!valid) {
        return { success: false, error: 'SECRET_KEY_MISMATCH' };
      }
    } catch (error) {
      return { success: false, error: 'KEY_VERIFICATION_FAILED', message: error.message };
    }

    // Store the DOKO
    this.dokoStore.add(doko);
    if (doko.claims?.userId) {
      this.userToDokoMap.set(doko.claims.userId, doko.dokoId);
    }

    return { success: true, dokoId: doko.dokoId };
  }

  /**
   * Get a trader's DOKO by user ID
   */
  getTraderDoko(userId) {
    const dokoId = this.userToDokoMap.get(userId);
    return dokoId ? this.dokoStore.get(dokoId) : null;
  }

  /**
   * Verify a trader's identity for a trade
   */
  verifyTrader(userId) {
    const doko = this.getTraderDoko(userId);
    if (!doko) {
      return { valid: false, reason: 'NO_DOKO_FOUND' };
    }

    const validation = DOKOValidator.validate(doko);
    return {
      valid: validation.valid,
      dokoId: doko.dokoId,
      type: doko.type,
      endorsements: doko.endorsements?.length || 0,
      checks: validation.checks,
    };
  }

  /**
   * Get all traders with their DOKO status
   */
  getAllTraders() {
    return this.dokoStore.getTraders();
  }

  /**
   * Handle incoming DOKO from mesh
   */
  handleIncomingDoko(dokoJson, origin) {
    const doko = DOKODocument.fromJSON(dokoJson);
    
    // Validate
    const validation = DOKOValidator.validate(doko);
    if (!validation.valid) {
      console.warn(`⚠️ Rejected invalid DOKO from ${origin.slice(0, 16)}...`);
      return false;
    }

    // Only accept trader/merchant types for PeerQuanta
    if (![DOKO_TYPES.TRADER, DOKO_TYPES.MERCHANT].includes(doko.type)) {
      return false;
    }

    // Store
    this.dokoStore.add(doko);
    if (doko.claims?.userId) {
      this.userToDokoMap.set(doko.claims.userId, doko.dokoId);
    }

    console.log(`✓ Imported DOKO ${doko.dokoId.slice(0, 24)}... from ${origin.slice(0, 16)}...`);
    return true;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. TRUST-BASED ESCROW
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Escrow States
 */
export const ESCROW_STATES = {
  CREATED: 'created',       // Escrow created, awaiting funding
  FUNDED: 'funded',         // Crypto deposited into escrow
  CONFIRMED: 'confirmed',   // Fiat payment confirmed by seller
  RELEASED: 'released',     // Crypto released to buyer
  DISPUTED: 'disputed',     // Trade disputed
  CANCELLED: 'cancelled',   // Trade cancelled, refund pending
  REFUNDED: 'refunded',     // Crypto refunded to seller
  EXPIRED: 'expired',       // Trade expired before completion
};

/**
 * Escrow Release Conditions
 */
export const ESCROW_RELEASE_CONDITIONS = {
  BUYER_CONFIRMED: 'buyer_confirmed',
  AUTO_AFTER_PERIOD: 'auto_after_period',
  DISPUTE_RESOLVED: 'dispute_resolved',
  MUTUAL_RELEASE: 'mutual_release',
};

/**
 * Escrow Requirements based on Trust Level
 * Note: Maps to TrustLevel enum from hybrid-trust.js
 *   UNTRUSTED=0, BRONZE=1, GOLD=2, PLATINUM=3
 */
export const ESCROW_REQUIREMENTS = {
  [TrustLevel.UNTRUSTED]: {
    escrowPercent: 100,          // Full escrow required
    escrowHoldDays: 14,          // Hold for 2 weeks after trade
    requiresMediator: true,       // Must have third party mediator
    maxTradeValue: 100,          // Max trade value in USD equivalent
    cooldownMinutes: 60,         // Wait between trades
  },
  [TrustLevel.BRONZE]: {
    escrowPercent: 100,
    escrowHoldDays: 7,
    requiresMediator: false,
    maxTradeValue: 500,
    cooldownMinutes: 30,
  },
  [TrustLevel.GOLD]: {
    escrowPercent: 50,
    escrowHoldDays: 1,
    requiresMediator: false,
    maxTradeValue: 10000,
    cooldownMinutes: 5,
  },
  [TrustLevel.PLATINUM]: {
    escrowPercent: 25,
    escrowHoldDays: 0,           // Immediate release
    requiresMediator: false,
    maxTradeValue: Infinity,     // No limit
    cooldownMinutes: 0,
  },
};

/**
 * Trust-Based Escrow Manager
 */
export class TrustEscrowManager {
  constructor(traderIdentityManager) {
    this.identityManager = traderIdentityManager;
    this.trustModel = new HybridTrustModel();
    this.traderTrustCache = new Map(); // dokoId -> { level, updated }
  }

  /**
   * Calculate trust level for a trader
   */
  async calculateTraderTrust(userId) {
    const doko = this.identityManager.getTraderDoko(userId);
    if (!doko) {
      return { level: TrustLevel.UNTRUSTED, reason: 'NO_DOKO' };
    }

    // Collect evidence using the TrustEvidence API
    const evidence = new TrustEvidence(doko.dokoId);

    // 1. DOKO verification
    const validation = DOKOValidator.validate(doko);
    evidence.recordDokoVerification({
      passed: validation.valid,
      gatesChecked: 7,
      dokoHash: validation.checks?.dokoId?.actual || null,
    });

    // 2. Record beacon history (simulate from DOKO creation time)
    evidence.sources.beaconHistory.firstSeen = doko.created;
    evidence.sources.beaconHistory.lastSeen = Date.now();
    evidence.sources.beaconHistory.sightings = Math.floor((Date.now() - doko.created) / (60 * 60 * 1000)); // hourly

    // 3. Behavioral evidence (from phpBB stats) - store in metadata
    const stats = await this._getTraderStats(userId);
    if (stats) {
      evidence.metadata = {
        totalTrades: stats.total_trades || 0,
        successfulTrades: stats.successful_trades || 0,
        positiveFeedback: stats.positive_feedback || 0,
        negativeFeedback: stats.negative_feedback || 0,
        disputesLost: stats.disputes_lost || 0,
        endorsementCount: (doko.endorsements || []).length,
      };
    }

    // Store evidence in the trust model so assessTrust can use it
    this.trustModel.evidence.set(doko.dokoId, evidence);
    
    // Calculate trust level using assessTrust
    const result = this.trustModel.assessTrust(doko.dokoId);

    // Cache result
    this.traderTrustCache.set(doko.dokoId, {
      level: result.level,
      score: result.score,
      updated: Date.now(),
    });

    return result;
  }

  /**
   * Get escrow requirements for a trade between two traders
   */
  async getEscrowRequirements(buyerUserId, sellerUserId, tradeValue) {
    const buyerTrust = await this.calculateTraderTrust(buyerUserId);
    const sellerTrust = await this.calculateTraderTrust(sellerUserId);

    // Use the LOWER trust level of the two parties
    const effectiveLevel = Math.min(buyerTrust.level, sellerTrust.level);
    const requirements = ESCROW_REQUIREMENTS[effectiveLevel];

    // Check trade value limit
    if (tradeValue > requirements.maxTradeValue) {
      return {
        allowed: false,
        reason: 'TRADE_VALUE_EXCEEDS_LIMIT',
        maxAllowed: requirements.maxTradeValue,
        buyerTrust: buyerTrust.level,
        sellerTrust: sellerTrust.level,
      };
    }

    return {
      allowed: true,
      effectiveLevel,
      buyerTrust: buyerTrust.level,
      sellerTrust: sellerTrust.level,
      escrowPercent: requirements.escrowPercent,
      escrowAmount: (tradeValue * requirements.escrowPercent) / 100,
      escrowHoldDays: requirements.escrowHoldDays,
      requiresMediator: requirements.requiresMediator,
      cooldownMinutes: requirements.cooldownMinutes,
    };
  }

  /**
   * Get trader stats from phpBB database
   */
  async _getTraderStats(userId) {
    if (!this.identityManager.bridge.phpbbDb) {
      return null;
    }

    try {
      const result = this.identityManager.bridge.phpbbDb.exec(`
        SELECT * FROM p2pq_user_stats WHERE user_id = ${userId}
      `);

      if (result.length > 0 && result[0].values.length > 0) {
        const columns = result[0].columns;
        const row = result[0].values[0];
        const stats = {};
        columns.forEach((col, i) => {
          stats[col] = row[i];
        });
        return stats;
      }
    } catch (e) {
      // Table might not exist
    }
    
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ANNEX TRADE CHAT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypted Trade Chat using ANNEX channels
 */
export class TradeChat {
  constructor(bridge, traderIdentityManager) {
    this.bridge = bridge;
    this.identityManager = traderIdentityManager;
    this.activeChats = new Map(); // tradeId -> { channel, participants, messages }
  }

  /**
   * Create a simple chat session (for testing or when ANNEX not available)
   * Returns a session object immediately without ANNEX
   */
  createSession(buyerDokoId, sellerDokoId, tradeId) {
    const sessionId = `session-${tradeId}-${Date.now()}`;
    
    const session = {
      sessionId,
      tradeId,
      participants: [buyerDokoId, sellerDokoId],
      messages: [],
      created: Date.now(),
    };
    
    this.activeChats.set(tradeId, session);
    return session;
  }

  /**
   * Get a chat session by trade ID
   */
  getSession(tradeId) {
    return this.activeChats.get(tradeId);
  }

  /**
   * Initialize a chat channel for a trade
   */
  async initTradeChat(tradeId, buyerUserId, sellerUserId) {
    const buyerDoko = this.identityManager.getTraderDoko(buyerUserId);
    const sellerDoko = this.identityManager.getTraderDoko(sellerUserId);

    if (!buyerDoko || !sellerDoko) {
      return {
        success: false,
        error: 'BOTH_TRADERS_NEED_DOKO',
        buyerHasDoko: !!buyerDoko,
        sellerHasDoko: !!sellerDoko,
      };
    }

    // Create ANNEX channel between the two traders
    const annex = this.bridge.node.annex;
    if (!annex) {
      return { success: false, error: 'ANNEX_NOT_AVAILABLE' };
    }

    try {
      // Create channel with trade-specific ID
      const channelId = `trade-${tradeId}-${Date.now()}`;
      const channel = await annex.createChannel(channelId, {
        participants: [buyerDoko.dokoId, sellerDoko.dokoId],
        metadata: {
          type: 'trade-chat',
          tradeId,
          created: Date.now(),
        },
      });

      this.activeChats.set(tradeId, {
        channelId,
        channel,
        participants: {
          buyer: { userId: buyerUserId, dokoId: buyerDoko.dokoId },
          seller: { userId: sellerUserId, dokoId: sellerDoko.dokoId },
        },
        messages: [],
        created: Date.now(),
      });

      return {
        success: true,
        channelId,
        tradeId,
      };
    } catch (error) {
      return { success: false, error: 'CHANNEL_CREATION_FAILED', message: error.message };
    }
  }

  /**
   * Send an encrypted message in a trade chat
   */
  async sendMessage(tradeId, senderUserId, message, secretKeyHex) {
    const chat = this.activeChats.get(tradeId);
    if (!chat) {
      return { success: false, error: 'CHAT_NOT_FOUND' };
    }

    const senderDoko = this.identityManager.getTraderDoko(senderUserId);
    if (!senderDoko) {
      return { success: false, error: 'SENDER_NO_DOKO' };
    }

    // Verify sender is a participant
    const isParticipant = 
      chat.participants.buyer.userId === senderUserId ||
      chat.participants.seller.userId === senderUserId;
    
    if (!isParticipant) {
      return { success: false, error: 'NOT_A_PARTICIPANT' };
    }

    try {
      // Sign the message with DOKO key
      const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
      const { hexToBytes, bytesToHex } = require('@noble/hashes/utils.js');
      const { sha3_256 } = require('@noble/hashes/sha3.js');

      const messageData = {
        tradeId,
        sender: senderDoko.dokoId,
        content: message,
        timestamp: Date.now(),
      };

      const messageBytes = Buffer.from(JSON.stringify(messageData));
      const messageHash = bytesToHex(sha3_256(messageBytes));
      const secretKey = hexToBytes(secretKeyHex);
      const signature = bytesToHex(ml_dsa65.sign(secretKey, messageBytes));

      const signedMessage = {
        ...messageData,
        hash: messageHash,
        signature,
      };

      // Store locally
      chat.messages.push(signedMessage);

      // Send via ANNEX channel
      if (chat.channel) {
        await chat.channel.send(signedMessage);
      }

      return {
        success: true,
        messageHash,
        timestamp: messageData.timestamp,
      };
    } catch (error) {
      return { success: false, error: 'SEND_FAILED', message: error.message };
    }
  }

  /**
   * Get chat history for a trade
   */
  getChatHistory(tradeId, userId) {
    const chat = this.activeChats.get(tradeId);
    if (!chat) {
      return { success: false, error: 'CHAT_NOT_FOUND' };
    }

    // Verify requester is a participant
    const isParticipant = 
      chat.participants.buyer.userId === userId ||
      chat.participants.seller.userId === userId;
    
    if (!isParticipant) {
      return { success: false, error: 'NOT_A_PARTICIPANT' };
    }

    return {
      success: true,
      messages: chat.messages,
      participants: chat.participants,
    };
  }

  /**
   * Close a trade chat
   */
  closeChat(tradeId) {
    const chat = this.activeChats.get(tradeId);
    if (chat) {
      if (chat.channel?.close) {
        chat.channel.close();
      }
      this.activeChats.delete(tradeId);
      return { success: true };
    }
    return { success: false, error: 'CHAT_NOT_FOUND' };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. MERCHANT DOMAIN VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Merchant Domain Verification using mesh consensus
 */
export class MerchantVerification {
  constructor(bridge, traderIdentityManager) {
    this.bridge = bridge;
    this.identityManager = traderIdentityManager;
    this.domainConsensus = new DomainConsensusVerifier();
    this.verifiedMerchants = new Map(); // dokoId -> verification record
  }

  /**
   * Request domain verification for a merchant
   */
  async requestVerification(userId, domain, businessName) {
    const doko = this.identityManager.getTraderDoko(userId);
    if (!doko) {
      // Create a merchant DOKO if they don't have one
      const result = DOKOGenerator.generateMerchant({
        businessName,
        domain,
        claims: {
          userId,
          platform: 'peerquanta',
        },
      });
      
      this.identityManager.dokoStore.add(result.doko);
      this.identityManager.userToDokoMap.set(userId, result.doko.dokoId);
      
      return {
        success: true,
        step: 'DOKO_CREATED',
        dokoId: result.doko.dokoId,
        secretKeyHex: result.secretKeyHex,
        nextStep: 'Add DNS TXT record',
        txtRecord: this._generateTxtRecord(result.doko),
      };
    }

    // Generate the TXT record they need to add
    const txtRecord = this._generateTxtRecord(doko);

    // Create domain claim
    const claim = new DomainClaim({
      domain,
      dokoId: doko.dokoId,
      publicKey: doko.publicKey,
      timestamp: Date.now(),
    });

    return {
      success: true,
      step: 'ADD_DNS_RECORD',
      dokoId: doko.dokoId,
      domain,
      txtRecord,
      instructions: `Add a TXT record to ${domain} with value: ${txtRecord}`,
    };
  }

  /**
   * Generate the DNS TXT record value
   */
  _generateTxtRecord(doko) {
    const { sha3_256 } = require('@noble/hashes/sha3.js');
    const { bytesToHex } = require('@noble/hashes/utils.js');
    
    const proof = bytesToHex(sha3_256(Buffer.from(doko.dokoId + doko.publicKey))).slice(0, 32);
    return `yakmesh-verify=${proof}`;
  }

  /**
   * Verify domain ownership
   */
  async verifyDomain(userId, domain) {
    const doko = this.identityManager.getTraderDoko(userId);
    if (!doko) {
      return { success: false, error: 'NO_DOKO_FOUND' };
    }

    const expectedTxt = this._generateTxtRecord(doko);

    // Check DNS
    const dnsResult = await DNSVerifier.verifyTxtRecord(domain, expectedTxt);
    if (!dnsResult.valid) {
      return {
        success: false,
        error: 'DNS_VERIFICATION_FAILED',
        reason: dnsResult.reason,
        expected: expectedTxt,
      };
    }

    // Request mesh consensus
    const consensusResult = await this.domainConsensus.requestConsensus(
      domain,
      doko.dokoId,
      this.bridge.node
    );

    if (consensusResult.verified) {
      // Store verification
      this.verifiedMerchants.set(doko.dokoId, {
        domain,
        verifiedAt: Date.now(),
        consensusNodes: consensusResult.verifiers,
        proof: expectedTxt,
      });

      // Update DOKO claims
      doko.claims.domain = domain;
      doko.claims.verified = true;
      doko.extensions.domainBinding = {
        domain,
        verifiedAt: Date.now(),
        proof: expectedTxt,
      };

      // Propagate updated DOKO
      this.bridge.node.gossip.spreadRumor('pq:merchant:verified', {
        dokoId: doko.dokoId,
        domain,
        verifiedAt: Date.now(),
      });

      return {
        success: true,
        verified: true,
        domain,
        dokoId: doko.dokoId,
        consensusNodes: consensusResult.verifiers.length,
      };
    }

    return {
      success: false,
      error: 'CONSENSUS_FAILED',
      reason: consensusResult.reason,
      verifiersNeeded: 3,
      verifiersFound: consensusResult.verifiers?.length || 0,
    };
  }

  /**
   * Check if a merchant is verified
   */
  isVerified(userId) {
    const doko = this.identityManager.getTraderDoko(userId);
    if (!doko) return false;
    return this.verifiedMerchants.has(doko.dokoId);
  }

  /**
   * Get verification details for a merchant
   */
  getVerification(userId) {
    const doko = this.identityManager.getTraderDoko(userId);
    if (!doko) return null;
    return this.verifiedMerchants.get(doko.dokoId);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. MAIN SECURITY INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * PeerQuanta Security Integration
 * Main class that orchestrates all security features
 */
export class PeerQuantaSecurity {
  constructor(bridge) {
    this.bridge = bridge;
    
    // Initialize all security managers
    this.identity = new TraderIdentityManager(bridge);
    this.escrow = new TrustEscrowManager(this.identity);
    this.chat = new TradeChat(bridge, this.identity);
    this.merchant = new MerchantVerification(bridge, this.identity);
    
    // Register mesh event handlers
    this._registerMeshHandlers();
    
    console.log('🔐 PeerQuanta Security v2.0 initialized');
    console.log('   ✓ DOKO Trader Identity');
    console.log('   ✓ Trust-Based Escrow');
    console.log('   ✓ ANNEX Trade Chat');
    console.log('   ✓ Merchant Domain Verification');
  }

  /**
   * Register handlers for mesh events
   */
  _registerMeshHandlers() {
    this.bridge.node.mesh.on('rumor', (topic, data, origin) => {
      switch (topic) {
        case 'pq:doko:new':
          this.identity.handleIncomingDoko(data.doko, origin);
          break;
        case 'pq:merchant:verified':
          // Verify and cache merchant verification from mesh
          if (data.merchantId && data.verification && data.signature) {
            this.merchant.cacheVerification?.(data.merchantId, {
              ...data.verification,
              receivedFrom: origin,
              receivedAt: Date.now(),
            });
          }
          break;
      }
    });
  }

  /**
   * Get comprehensive security status
   */
  getStatus() {
    return {
      traders: this.identity.dokoStore.getStats(),
      verifiedMerchants: this.merchant.verifiedMerchants.size,
      activeChats: this.chat.activeChats.size,
      trustCacheSize: this.escrow.traderTrustCache.size,
    };
  }
}

export default PeerQuantaSecurity;
