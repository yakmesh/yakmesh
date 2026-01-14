/**
 * Genesis Network Identity System
 * 
 * PHILOSOPHY:
 * There is no authority - only mathematical truth.
 * Code hash = Network identity.
 * Same code → Same hash → Same network.
 * Different code → Different hash → Different network.
 * 
 * No permission needed. No governance needed.
 * Physics enforces the boundary.
 * 
 * @module oracle/genesis-network
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Network identity derived purely from code hash
 */
export class GenesisNetwork {
  constructor(oracleHash) {
    this.genesisHash = oracleHash;
    this.networkId = this._deriveNetworkId(oracleHash);
    this.knownPeers = new Map(); // peerId -> { hash, lastSeen, compatible }
    this.upgradeProposals = new Map(); // newHash -> proposal
    this.pendingUpgrade = null;
  }

  /**
   * Derive a human-readable network ID from the genesis hash
   */
  _deriveNetworkId(hash) {
    // First 8 chars of hash = network ID
    // This makes it easy to identify which network a node belongs to
    return `pq-${hash.slice(0, 8)}`;
  }

  /**
   * Check if another node is compatible (same genesis hash)
   */
  isCompatible(peerHash) {
    return peerHash === this.genesisHash;
  }

  /**
   * Register a peer and determine compatibility
   */
  registerPeer(peerId, peerHash) {
    const compatible = this.isCompatible(peerHash);
    
    this.knownPeers.set(peerId, {
      hash: peerHash,
      networkId: this._deriveNetworkId(peerHash),
      lastSeen: Date.now(),
      compatible,
    });

    if (!compatible) {
      console.log(`⚠️ Peer ${peerId.slice(0, 8)}... is on different network:`);
      console.log(`   Their network: pq-${peerHash.slice(0, 8)}`);
      console.log(`   Our network:   ${this.networkId}`);
    }

    return compatible;
  }

  /**
   * Get all compatible peers (same network)
   */
  getCompatiblePeers() {
    const compatible = [];
    for (const [peerId, info] of this.knownPeers) {
      if (info.compatible) {
        compatible.push({ peerId, ...info });
      }
    }
    return compatible;
  }

  /**
   * Get all incompatible peers (different networks)
   */
  getIncompatiblePeers() {
    const incompatible = [];
    for (const [peerId, info] of this.knownPeers) {
      if (!info.compatible) {
        incompatible.push({ peerId, ...info });
      }
    }
    return incompatible;
  }

  /**
   * Receive an upgrade proposal from the network
   */
  receiveUpgradeProposal(proposal) {
    const { newHash, changelog, effectiveTime, sourceUrl, signature } = proposal;
    
    if (!newHash || !changelog) {
      console.log('❌ Invalid upgrade proposal: missing required fields');
      return false;
    }

    // Store the proposal
    this.upgradeProposals.set(newHash, {
      newHash,
      changelog,
      effectiveTime: effectiveTime || Date.now() + 7 * 24 * 60 * 60 * 1000, // Default: 7 days
      sourceUrl,
      signature,
      receivedAt: Date.now(),
      peersAccepted: new Set(),
    });

    console.log('\n' + '═'.repeat(60));
    console.log('⚠️  NETWORK UPGRADE PROPOSAL RECEIVED');
    console.log('═'.repeat(60));
    console.log(`Current Network: ${this.networkId}`);
    console.log(`Current Hash:    ${this.genesisHash.slice(0, 32)}...`);
    console.log(`New Hash:        ${newHash.slice(0, 32)}...`);
    console.log(`New Network:     pq-${newHash.slice(0, 8)}`);
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
   * Generate upgrade prompt for node operator
   * Returns the prompt text and a callback for handling response
   */
  generateUpgradePrompt(newHash) {
    const proposal = this.upgradeProposals.get(newHash);
    if (!proposal) return null;

    const prompt = `
╔══════════════════════════════════════════════════════════════╗
║            NETWORK UPGRADE DECISION REQUIRED                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Current Network: ${this.networkId.padEnd(40)}║
║  Current Hash:    ${(this.genesisHash.slice(0, 32) + '...').padEnd(40)}║
║                                                              ║
║  Proposed Network: pq-${newHash.slice(0, 8).padEnd(37)}║
║  Proposed Hash:    ${(newHash.slice(0, 32) + '...').padEnd(40)}║
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
      handle: (response) => this._handleUpgradeResponse(newHash, response),
    };
  }

  /**
   * Handle operator's upgrade decision
   */
  _handleUpgradeResponse(newHash, response) {
    const accepted = response.toLowerCase() === 'y' || response.toLowerCase() === 'yes';
    
    if (accepted) {
      this.pendingUpgrade = {
        newHash,
        acceptedAt: Date.now(),
        status: 'pending_download',
      };
      
      console.log('\n✅ Upgrade accepted. Preparing to join new network...');
      console.log(`   New network ID will be: pq-${newHash.slice(0, 8)}`);
      console.log('   Please restart the node after code update.\n');
      
      return {
        accepted: true,
        action: 'download_and_restart',
        newHash,
      };
    } else {
      console.log('\n❌ Upgrade declined. Staying on current network.');
      console.log(`   Current network: ${this.networkId}`);
      console.log('   Note: You may become isolated from upgraded nodes.\n');
      
      return {
        accepted: false,
        action: 'stay_current',
        currentHash: this.genesisHash,
      };
    }
  }

  /**
   * Broadcast our network identity in handshake
   */
  getHandshakePayload() {
    return {
      networkId: this.networkId,
      genesisHash: this.genesisHash,
      protocolVersion: '1.0.0',
      timestamp: Date.now(),
    };
  }

  /**
   * Validate incoming handshake
   */
  validateHandshake(payload) {
    if (!payload.genesisHash) {
      return { valid: false, reason: 'MISSING_GENESIS_HASH' };
    }

    const compatible = this.isCompatible(payload.genesisHash);
    
    return {
      valid: true,
      compatible,
      theirNetwork: payload.networkId,
      ourNetwork: this.networkId,
      reason: compatible ? 'SAME_NETWORK' : 'DIFFERENT_NETWORK',
    };
  }

  /**
   * Get network status
   */
  getStatus() {
    const compatibleCount = this.getCompatiblePeers().length;
    const incompatibleCount = this.getIncompatiblePeers().length;
    
    // Group incompatible peers by their network
    const otherNetworks = new Map();
    for (const peer of this.getIncompatiblePeers()) {
      const network = peer.networkId;
      if (!otherNetworks.has(network)) {
        otherNetworks.set(network, []);
      }
      otherNetworks.get(network).push(peer.peerId);
    }

    return {
      networkId: this.networkId,
      genesisHash: this.genesisHash,
      peers: {
        compatible: compatibleCount,
        incompatible: incompatibleCount,
        total: this.knownPeers.size,
      },
      otherNetworks: Object.fromEntries(otherNetworks),
      pendingUpgrades: this.upgradeProposals.size,
      hasPendingUpgrade: this.pendingUpgrade !== null,
    };
  }

  /**
   * Serialize for persistence
   */
  toJSON() {
    return {
      genesisHash: this.genesisHash,
      networkId: this.networkId,
      knownPeers: Object.fromEntries(this.knownPeers),
      upgradeProposals: Object.fromEntries(
        Array.from(this.upgradeProposals.entries()).map(([k, v]) => [
          k,
          { ...v, peersAccepted: Array.from(v.peersAccepted) }
        ])
      ),
    };
  }

  /**
   * Restore from persistence
   */
  static fromJSON(data, currentOracleHash) {
    // If the current oracle hash differs from saved, we're on a new network
    if (data.genesisHash !== currentOracleHash) {
      console.log('⚠️ Code has changed since last run:');
      console.log(`   Previous network: pq-${data.genesisHash.slice(0, 8)}`);
      console.log(`   Current network:  pq-${currentOracleHash.slice(0, 8)}`);
      console.log('   Starting fresh on new network.\n');
      return new GenesisNetwork(currentOracleHash);
    }

    const network = new GenesisNetwork(data.genesisHash);
    
    // Restore peers (but mark as stale)
    for (const [peerId, info] of Object.entries(data.knownPeers)) {
      network.knownPeers.set(peerId, {
        ...info,
        lastSeen: info.lastSeen, // Keep original timestamp
      });
    }

    // Restore upgrade proposals
    for (const [hash, proposal] of Object.entries(data.upgradeProposals || {})) {
      network.upgradeProposals.set(hash, {
        ...proposal,
        peersAccepted: new Set(proposal.peersAccepted || []),
      });
    }

    return network;
  }
}

/**
 * Create a genesis network from an oracle instance
 */
export function createGenesisNetwork(oracle) {
  if (!oracle || !oracle.selfHash) {
    throw new Error('Oracle must be initialized with selfHash');
  }
  return new GenesisNetwork(oracle.selfHash);
}

export default GenesisNetwork;
