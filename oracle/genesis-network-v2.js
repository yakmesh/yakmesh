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
import { createLogger } from '../utils/logger.js';
import { getCurrentEpoch } from './phase-epoch.js';

const log = createLogger('oracle:genesis');

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

    log.info('Genesis Network initialized', {
      name: this.#identity.name,
      id: this.#identity.shortId,
      verificationPhrase: this.#identity.verificationPhrase,
    });
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
      log.warn('Peer on different network', {
        peerId: peerId.slice(0, 8),
        theirNetwork: handshake.name,
        theirId: handshake.shortId,
        ourNetwork: this.#identity.name,
        ourId: this.#identity.shortId,
      });
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
      log.error('Invalid upgrade proposal: missing required fields');
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

    log.warn('NETWORK UPGRADE PROPOSAL RECEIVED', {
      currentNetwork: this.#identity.name,
      currentId: this.#identity.shortId,
      newNetwork: newIdentity.name,
      newId: newIdentity.shortId,
      currentPhrase: this.#identity.verificationPhrase,
      newPhrase: newIdentity.verificationPhrase,
      changelog,
      effectiveTime: new Date(effectiveTime).toISOString(),
      sourceUrl: sourceUrl || undefined,
    });

    return true;
  }  /**
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

      log.info('Upgrade accepted - preparing to join new network', {
        newNetwork: proposal.newName,
        newId: proposal.newShortId,
      });

      return { accepted: true, action: 'download_and_restart', proposal };
    } else {
      log.info('Upgrade declined - staying on current network', {
        currentNetwork: this.#identity.name,
        currentId: this.#identity.shortId,
      });

      return { accepted: false, action: 'stay_current' };
    }
  }

  // ============================================================
  // ACT — AGUWA Coordinated Transition
  // ============================================================

  /**
   * Propose an ACT coordinated upgrade transition.
   * Called when this node detects a code change (manifest hash != oracle selfHash).
   * Returns the proposal payload for gossip propagation via 'act:proposal' topic.
   *
   * @param {number} targetEpoch - The epoch at which to execute the transition
   * @returns {Object} Proposal payload for spreadRumor('act:proposal', payload)
   */
  proposeACT(targetEpoch) {
    const proposal = {
      proposerFingerprint: this.#identity.fingerprint,
      proposerName: this.#identity.name,
      proposerShortId: this.#identity.shortId,
      targetEpoch,
      currentEpoch: getCurrentEpoch(),
    };

    this._actProposal = proposal;

    log.warn('ACT: Coordinated transition proposed', {
      targetEpoch,
      currentEpoch: proposal.currentEpoch,
      network: this.#identity.name,
    });

    return proposal;
  }

  /**
   * Handle an incoming ACT consent message from a peer.
   * Consent uses JHILKE ternary: accept (+1) / abstain (0) / reject (-1).
   *
   * @param {string} peerId - The peer that sent the consent
   * @param {Object} consent - { vote: 'accept'|'abstain'|'reject', targetEpoch }
   * @returns {Object} { peerId, vote, targetEpoch }
   */
  handleACTConsent(peerId, consent) {
    const { vote, targetEpoch } = consent;

    if (!this._actConsents) this._actConsents = new Map();

    this._actConsents.set(peerId, { vote, targetEpoch, receivedAt: Date.now() });

    log.info('ACT: Consent received', {
      peer: peerId.slice(0, 16),
      vote,
      targetEpoch,
      totalConsents: this._actConsents.size,
    });

    return { peerId, vote, targetEpoch };
  }

  /**
   * Get the current ACT proposal (if any).
   * @returns {Object|null}
   */
  getACTProposal() {
    return this._actProposal || null;
  }

  /**
   * Get all ACT consents received.
   * @returns {Map}
   */
  getACTConsents() {
    return this._actConsents || new Map();
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
