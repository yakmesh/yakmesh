/**
 * Genesis Network Identity System v2
 * 
 * PHILOSOPHY:
 * There is no authority - only mathematical truth.
 * Code hash → Derived identity (hash NEVER exposed).
 * Same code → Same identity → Same network.
 * Different code → Different identity → Different network.
 * 
 * SECURITY IMPROVEMENT (v2):
 * Uses iO-inspired identity derivation to prevent hash exposure.
 * Network names are human-readable but cryptographically derived.
 * Fingerprints allow compatibility checking without revealing hashes.
 * 
 * @module oracle/genesis-network-v2
 */

import { NetworkIdentity, createNetworkIdentity, deriveNetworkName } from './network-identity.js';

/**
 * Genesis Network with obfuscated identity
 * Hash is never exposed in network communication
 */
export class GenesisNetworkV2 {
  #codeHash;  // Private - never exposed
  #identity;
  #knownPeers;
  #upgradeProposals;
  #pendingUpgrade;
  
  constructor(oracleHashOrOracle) {
    // Accept either a hash string or an oracle object
    const hash = typeof oracleHashOrOracle === 'string' 
      ? oracleHashOrOracle 
      : oracleHashOrOracle?.selfHash;
    
    if (!hash || typeof hash !== 'string') {
      throw new Error('Valid code hash or oracle required');
    }
    
    this.#codeHash = hash;
    this.#identity = new NetworkIdentity(hash);
    this.#knownPeers = new Map();
    this.#upgradeProposals = new Map();
    this.#pendingUpgrade = null;
    
    console.log(`🌐 Genesis Network initialized:`);
    console.log(`   Name: ${this.#identity.name}`);
    console.log(`   ID: ${this.#identity.shortId}`);
    console.log(`   Verify: "${this.#identity.verificationPhrase}"`);
  }
  
  // ============================================================
  // PUBLIC GETTERS (hash never exposed)
  // ============================================================
  
  get networkName() { return this.#identity.name; }
  get networkId() { return this.#identity.shortId; }
  get verificationPhrase() { return this.#identity.verificationPhrase; }
  get fingerprint() { return this.#identity.fingerprint; }
  
  // ============================================================
  // PEER MANAGEMENT
  // ============================================================
  
  /**
   * Check if a peer is compatible using their fingerprint
   * No hash comparison - uses derived fingerprints
   */
  isCompatiblePeer(peerFingerprint) {
    return this.#identity.fingerprint === peerFingerprint;
  }
  
  /**
   * Register a peer from their handshake
   */
  registerPeer(peerId, handshake) {
    const compatible = this.#identity.fingerprint === handshake.fingerprint;
    
    this.#knownPeers.set(peerId, {
      name: handshake.name,
      shortId: handshake.shortId,
      fingerprint: handshake.fingerprint,
      lastSeen: Date.now(),
      compatible,
    });
    
    if (!compatible) {
      console.log(`⚠️ Peer ${peerId.slice(0, 8)}... is on different network:`);
      console.log(`   Their network: ${handshake.name} (${handshake.shortId})`);
      console.log(`   Our network:   ${this.#identity.name} (${this.#identity.shortId})`);
    }
    
    return compatible;
  }
  
  /**
   * Get compatible peers (same network)
   */
  getCompatiblePeers() {
    return Array.from(this.#knownPeers.entries())
      .filter(([_, info]) => info.compatible)
      .map(([peerId, info]) => ({ peerId, ...info }));
  }
  
  /**
   * Get incompatible peers (different networks)
   */
  getIncompatiblePeers() {
    return Array.from(this.#knownPeers.entries())
      .filter(([_, info]) => !info.compatible)
      .map(([peerId, info]) => ({ peerId, ...info }));
  }
  
  // ============================================================
  // HANDSHAKE PROTOCOL
  // ============================================================
  
  /**
   * Create handshake payload (no hash exposed)
   */
  createHandshake() {
    return this.#identity.getHandshakePayload();
  }
  
  /**
   * Verify incoming handshake
   */
  verifyHandshake(handshake) {
    return this.#identity.validateHandshake(handshake);
  }
  
  // ============================================================
  // UPGRADE PROPOSALS
  // ============================================================
  
  /**
   * Receive an upgrade proposal
   * Uses derived name instead of raw hash
   */
  receiveUpgradeProposal(proposal) {
    const { newCodeHash, changelog, effectiveTime, sourceUrl, signature } = proposal;
    
    if (!newCodeHash || !changelog) {
      console.log('❌ Invalid upgrade proposal: missing required fields');
      return false;
    }
    
    // Derive the new network identity
    const newIdentity = new NetworkIdentity(newCodeHash);
    
    // Store using fingerprint as key (not hash)
    this.#upgradeProposals.set(newIdentity.fingerprint, {
      newName: newIdentity.name,
      newShortId: newIdentity.shortId,
      newFingerprint: newIdentity.fingerprint,
      newVerificationPhrase: newIdentity.verificationPhrase,
      changelog,
      effectiveTime: effectiveTime || Date.now() + 7 * 24 * 60 * 60 * 1000,
      sourceUrl,
      signature,
      receivedAt: Date.now(),
      peersAccepted: new Set(),
    });
    
    console.log('\n' + '═'.repeat(60));
    console.log('⚠️  NETWORK UPGRADE PROPOSAL RECEIVED');
    console.log('═'.repeat(60));
    console.log(`Current Network: ${this.#identity.name} (${this.#identity.shortId})`);
    console.log(`New Network:     ${newIdentity.name} (${newIdentity.shortId})`);
    console.log('─'.repeat(60));
    console.log('Verification Phrases:');
    console.log(`  Current: "${this.#identity.verificationPhrase}"`);
    console.log(`  New:     "${newIdentity.verificationPhrase}"`);
    console.log('─'.repeat(60));
    console.log('Changes:');
    changelog.split('\n').forEach(line => console.log(`  ${line}`));
    console.log('─'.repeat(60));
    console.log(`Effective: ${new Date(effectiveTime).toISOString()}`);
    if (sourceUrl) {
      console.log(`Source: ${sourceUrl}`);
    }
    console.log('═'.repeat(60) + '\n');
    
    return true;
  }
  
  /**
   * Generate upgrade prompt for operator
   */
  generateUpgradePrompt(newFingerprint) {
    const proposal = this.#upgradeProposals.get(newFingerprint);
    if (!proposal) return null;
    
    const prompt = `
╔══════════════════════════════════════════════════════════════╗
║            NETWORK UPGRADE DECISION REQUIRED                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Current Network: ${(this.#identity.name + ' (' + this.#identity.shortId + ')').padEnd(38)}║
║  Verify: "${this.#identity.verificationPhrase.slice(0, 36)}..."  ║
║                                                              ║
║  Proposed Network: ${(proposal.newName + ' (' + proposal.newShortId + ')').padEnd(37)}║
║  Verify: "${proposal.newVerificationPhrase.slice(0, 36)}..."  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  CHANGES:                                                    ║
${proposal.changelog.split('\n').map(l => `║  ${l.padEnd(58)}║`).join('\n')}
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  [Y] Accept - Download new code, join new network            ║
║  [N] Decline - Stay on current network                       ║
║                                                              ║
║  ⚠️  WARNING: Declining may isolate you from upgraded nodes  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Accept upgrade? [Y/N]: `;
    
    return {
      prompt,
      proposal,
      handle: (response) => this._handleUpgradeResponse(newFingerprint, response),
    };
  }
  
  /**
   * Handle upgrade decision
   */
  _handleUpgradeResponse(newFingerprint, response) {
    const proposal = this.#upgradeProposals.get(newFingerprint);
    const accepted = response.toLowerCase() === 'y' || response.toLowerCase() === 'yes';
    
    if (accepted) {
      this.#pendingUpgrade = {
        newFingerprint,
        newName: proposal.newName,
        newShortId: proposal.newShortId,
        acceptedAt: Date.now(),
        status: 'pending_download',
      };
      
      console.log('\n✅ Upgrade accepted. Preparing to join new network...');
      console.log(`   New network: ${proposal.newName} (${proposal.newShortId})`);
      console.log('   Please restart the node after code update.\n');
      
      return { accepted: true, action: 'download_and_restart', proposal };
    } else {
      console.log('\n❌ Upgrade declined. Staying on current network.');
      console.log(`   Current: ${this.#identity.name} (${this.#identity.shortId})`);
      console.log('   Note: You may become isolated from upgraded nodes.\n');
      
      return { accepted: false, action: 'stay_current' };
    }
  }
  
  // ============================================================
  // STATUS & SERIALIZATION
  // ============================================================
  
  /**
   * Get network status (no hash exposed)
   */
  getStatus() {
    const compatibleCount = this.getCompatiblePeers().length;
    const incompatibleCount = this.getIncompatiblePeers().length;
    
    // Group incompatible peers by their network name
    const otherNetworks = new Map();
    for (const peer of this.getIncompatiblePeers()) {
      const network = peer.name;
      if (!otherNetworks.has(network)) {
        otherNetworks.set(network, []);
      }
      otherNetworks.get(network).push(peer.peerId);
    }
    
    return {
      name: this.#identity.name,
      shortId: this.#identity.shortId,
      verificationPhrase: this.#identity.verificationPhrase,
      fingerprint: this.#identity.fingerprint,
      peers: {
        compatible: compatibleCount,
        incompatible: incompatibleCount,
        total: this.#knownPeers.size,
      },
      otherNetworks: Object.fromEntries(otherNetworks),
      pendingUpgrades: this.#upgradeProposals.size,
      hasPendingUpgrade: this.#pendingUpgrade !== null,
    };
  }
  
  /**
   * Serialize for persistence (no hash)
   */
  toJSON() {
    return {
      fingerprint: this.#identity.fingerprint,
      name: this.#identity.name,
      shortId: this.#identity.shortId,
      knownPeers: Object.fromEntries(this.#knownPeers),
      upgradeProposals: Object.fromEntries(
        Array.from(this.#upgradeProposals.entries()).map(([k, v]) => [
          k,
          { ...v, peersAccepted: Array.from(v.peersAccepted) }
        ])
      ),
    };
  }
  
  /**
   * Check if saved state matches current code
   * Uses fingerprint comparison, not hash
   */
  static canRestoreFrom(savedData, currentOracle) {
    const currentIdentity = new NetworkIdentity(
      typeof currentOracle === 'string' ? currentOracle : currentOracle.selfHash
    );
    return savedData.fingerprint === currentIdentity.fingerprint;
  }
  
  /**
   * Display friendly string
   */
  toString() {
    return `GenesisNetwork: ${this.#identity.name} (${this.#identity.shortId})`;
  }
}

/**
 * Create genesis network from oracle
 */
export function createGenesisNetworkV2(oracle) {
  return new GenesisNetworkV2(oracle);
}

export default GenesisNetworkV2;
