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
 * KeyResolver — Unified public key resolution for the YAKMESH mesh
 * 
 * Consolidates the 5+ scattered key lookup mechanisms into a single
 * resolution cascade ordered by trust and speed:
 * 
 *   1. Local identity (self — instant, maximum trust)
 *   2. Explicit registrations (manual or handshake — high trust)
 *   3. NamcheGateway DOKO cache (7-gate verified — cryptographic trust)
 *   4. Network peer map (WS handshake — connection trust)
 *   5. SHERPA registry (discovery beacons — medium trust)
 * 
 * Philosophy:
 *   - No gatekeeping: resolving a key never blocks actions
 *   - No weighting: a resolved key is equally valid regardless of source
 *   - Transparent: callers can inspect resolution source via resolveWithMeta()
 * 
 * @module identity/key-resolver
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';

const log = createLogger('identity:key-resolver');

/**
 * Resolution source descriptors, ordered by trust
 */
export const KEY_SOURCE = Object.freeze({
  SELF:       'self',        // Our own keypair
  REGISTERED: 'registered',  // Explicitly registered (handshake, auth, etc.)
  DOKO:       'doko',        // Resolved from DOKO cache (NamcheGateway)
  PEER:       'peer',        // Connected WS peer identity
  SHERPA:     'sherpa',      // SHERPA discovery beacon
});

/**
 * Unified public key resolver
 * 
 * @example
 * const resolver = new KeyResolver({ identity: nodeIdentity });
 * resolver.attachNamche(namcheGateway);
 * resolver.attachNetwork(network);
 * 
 * const pubkey = resolver.resolve('node-abc-123');
 */
export class KeyResolver {
  /**
   * @param {Object} options
   * @param {Object} options.identity - NodeIdentity instance (for self-resolution)
   * @param {number} [options.cacheSize=5000] - Max registered key entries
   */
  constructor(options = {}) {
    this.identity = options.identity || null;
    this.maxSize = options.cacheSize || 5000;

    // Registered keys: id → { publicKey, source, registeredAt }
    this.registry = new Map();

    // External sources (attached lazily as subsystems come online)
    this._namche = null;    // NamcheGateway
    this._network = null;   // mesh/network.js
    this._sherpa = null;    // SHERPA discovery
    
    this.stats = {
      resolvedSelf: 0,
      resolvedRegistry: 0,
      resolvedDoko: 0,
      resolvedPeer: 0,
      resolvedSherpa: 0,
      misses: 0,
      registrations: 0,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lazy attachment (subsystems start at different times)
  // ─────────────────────────────────────────────────────────────────────────

  /** Attach NamcheGateway for DOKO-cache resolution */
  attachNamche(namcheGateway) {
    this._namche = namcheGateway;
    log.debug('KeyResolver: NamcheGateway attached');
  }

  /** Attach mesh network for peer resolution */
  attachNetwork(network) {
    this._network = network;
    log.debug('KeyResolver: Network attached');
  }

  /** Attach SHERPA discovery for beacon-based resolution */
  attachSherpa(sherpa) {
    this._sherpa = sherpa;
    log.debug('KeyResolver: SHERPA attached');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Registration (feed keys from any source)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Register a public key from any source
   * 
   * @param {string} id - nodeId or dokoId
   * @param {string} publicKey - Hex-encoded public key
   * @param {string} [source='registered'] - Resolution source tag
   */
  register(id, publicKey, source = KEY_SOURCE.REGISTERED) {
    if (!id || !publicKey) return;

    // Evict oldest if at capacity
    if (this.registry.size >= this.maxSize && !this.registry.has(id)) {
      const oldestKey = this.registry.keys().next().value;
      this.registry.delete(oldestKey);
    }

    this.registry.set(id, {
      publicKey,
      source,
      registeredAt: Date.now(),
    });
    this.stats.registrations++;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Resolution (synchronous cascade)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Resolve a public key by nodeId or dokoId
   * 
   * Returns the hex-encoded public key, or null if not found.
   * Searches all available sources in trust-priority order.
   * 
   * @param {string} id - nodeId or dokoId to look up
   * @returns {string|null} Public key (hex) or null
   */
  resolve(id) {
    if (!id) return null;

    // 1. Self
    if (this.identity) {
      const selfId = this.identity.identity?.nodeId || this.identity.nodeId;
      const selfDokoId = this.identity.identity?.dokoId || this.identity.dokoId;
      if (id === selfId || id === selfDokoId) {
        this.stats.resolvedSelf++;
        return this.identity.identity?.publicKey || this.identity.publicKey;
      }
    }

    // 2. Explicit registry
    const registered = this.registry.get(id);
    if (registered) {
      this.stats.resolvedRegistry++;
      return registered.publicKey;
    }

    // 3. NamcheGateway DOKO cache
    if (this._namche) {
      const doko = this._namche.lookupByNodeId(id) || this._namche.lookupByHash(id);
      if (doko?.publicKey) {
        this.stats.resolvedDoko++;
        // Cache for future fast lookup
        this.register(id, doko.publicKey, KEY_SOURCE.DOKO);
        return doko.publicKey;
      }
    }

    // 4. Network peer map
    if (this._network) {
      const peers = this._network.peers || this._network._peers;
      if (peers) {
        const peer = peers.get?.(id);
        if (peer?.identity?.publicKey) {
          this.stats.resolvedPeer++;
          this.register(id, peer.identity.publicKey, KEY_SOURCE.PEER);
          return peer.identity.publicKey;
        }
      }
      // Also check relay peer keys
      const relayKey = this._network._relayPeerKeys?.get?.(id);
      if (relayKey) {
        this.stats.resolvedPeer++;
        this.register(id, relayKey, KEY_SOURCE.PEER);
        return relayKey;
      }
    }

    // 5. SHERPA registry
    if (this._sherpa) {
      const beacon = this._sherpa.registry?.get?.(id);
      if (beacon?.publicKey) {
        this.stats.resolvedSherpa++;
        this.register(id, beacon.publicKey, KEY_SOURCE.SHERPA);
        return beacon.publicKey;
      }
    }

    this.stats.misses++;
    return null;
  }

  /**
   * Resolve with full metadata (source, registration time, etc.)
   * 
   * @param {string} id - nodeId or dokoId
   * @returns {{ publicKey: string, source: string, registeredAt: number }|null}
   */
  resolveWithMeta(id) {
    if (!id) return null;

    // Self
    if (this.identity) {
      const selfId = this.identity.identity?.nodeId || this.identity.nodeId;
      const selfDokoId = this.identity.identity?.dokoId || this.identity.dokoId;
      if (id === selfId || id === selfDokoId) {
        return {
          publicKey: this.identity.identity?.publicKey || this.identity.publicKey,
          source: KEY_SOURCE.SELF,
          registeredAt: 0,
        };
      }
    }

    // Check registry (includes keys cached from DOKO/peer/sherpa lookups)
    const registered = this.registry.get(id);
    if (registered) return registered;

    // Try live lookup (which also caches the result)
    const key = this.resolve(id);
    if (key) {
      return this.registry.get(id) || { publicKey: key, source: 'unknown', registeredAt: Date.now() };
    }

    return null;
  }

  /**
   * Check if a key is known (without returning it)
   * @param {string} id - nodeId or dokoId
   * @returns {boolean}
   */
  has(id) {
    return this.resolve(id) !== null;
  }

  /**
   * Get resolver statistics
   */
  getStats() {
    return {
      ...this.stats,
      registrySize: this.registry.size,
      hasNamche: this._namche !== null,
      hasNetwork: this._network !== null,
      hasSherpa: this._sherpa !== null,
    };
  }
}

export default KeyResolver;
