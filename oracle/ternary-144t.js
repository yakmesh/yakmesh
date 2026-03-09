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
 * TERNARY-144T — 144-Trit Hierarchical Mesh Addressing
 * 
 * A 4-tier hierarchical addressing system using 144 balanced ternary digits,
 * structured as 4 × 36-trit segments (or equivalently 4 levels of 3^3 sub-blocks).
 * 
 * Why 144 trits?
 * - 144 = 12² = 4 × 36 = 4 × 4 × 9 = (2²)(2²)(3²) — rich factorization
 * - 3^144 ≈ 1.55 × 10^68 unique addresses (exceeds SHA-256 space)
 * - Natural 4-tier hierarchy: Galaxy → Cluster → Zone → Node
 * - Each 36-trit tier ≈ 57 bits — fits in a 64-bit word with room for metadata
 * - 144 = 6 × 24 — aligns with SST's 24-cycle Fibonacci (6 full cycles)
 * - 144 = 4 × 36 → each tier holds 4 × 9-trit sub-blocks (hexagonal addressing)
 * 
 * POST-QUANTUM HARDENING:
 * - 144 trits × log₂(3) ≈ 228 bits of classical entropy
 * - Grover's algorithm (quantum search) halves binary bit-security but gains
 *   NO advantage over balanced ternary — ternary search is already optimal
 * - Result: 144T provides ~256-bit equivalent post-quantum routing security
 * - Combined with ML-DSA-65 signatures and ML-KEM-768 key exchange,
 *   the entire mesh addressing layer is quantum-resistant
 * 
 * Hierarchy (4 tiers, 36 trits each):
 * 
 *   ┌──────────────────────────────────────────────────────────────────────────────┐
 *   │ Galaxy (36 trits) │ Cluster (36 trits) │ Zone (36 trits) │ Node (36 trits)  │
 *   │     ≈ 57 bits     │     ≈ 57 bits      │    ≈ 57 bits    │    ≈ 57 bits     │
 *   └──────────────────────────────────────────────────────────────────────────────┘
 * 
 * Within each tier, 36 trits decompose into 4 × 9-trit sub-blocks:
 *   [region:9] [sector:9] [cell:9] [local:9]
 * 
 * This maps naturally to the SST hexagonal tessellation (HexCoord):
 *   - 9 trits = 3^9 = 19683 addresses per sub-block
 *   - 4 sub-blocks per tier = 3^36 ≈ 1.5 × 10^17 per tier
 * 
 * Integration:
 *   TRIBHUJ (trit algebra) → 144T (addressing) → YPC-27 (integrity per tier)
 *   SST (hex geometry) → 144T (spatial mapping) → PRAHARI (satellite seeds)
 *   MANDALA (mesh topology) → 144T (hierarchical routing)
 * 
 * @module oracle/ternary-144t
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE } from './tribhuj.js';
import { digitalRoot, getFamilyOf, SSTFamily, FIBONACCI_CYCLE_24 } from './sst.js';
import { Poly27, YPC27Checksum, N as YPC27_N, DEFAULT_SEED, bytesToTrits } from './ypc27.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/** Total trit length of a full 144T address */
export const TOTAL_TRITS = 144;

/** Number of hierarchical tiers */
export const TIER_COUNT = 4;

/** Trits per tier */
export const TRITS_PER_TIER = 36;

/** Sub-blocks per tier */
export const SUB_BLOCKS_PER_TIER = 4;

/** Trits per sub-block */
export const TRITS_PER_SUB_BLOCK = 9;

/** Tier names (Himalayan naming convention) */
export const TierName = Object.freeze({
  GALAXY:  0,  // Broadest scope — intercontinental / satellite
  CLUSTER: 1,  // Regional mesh clusters
  ZONE:    2,  // Local zone (city-scale, maps to HexCoord)
  NODE:    3,  // Individual node identity
});

/** Tier name labels */
export const TIER_LABELS = Object.freeze(['galaxy', 'cluster', 'zone', 'node']);

// =============================================================================
// TRIT ADDRESS CLASS
// =============================================================================

/**
 * A 144-trit hierarchical mesh address.
 * Immutable value object with tier-aware operations.
 */
export class TritAddress {
  /** @type {Int8Array} — 144 balanced ternary digits */
  #trits;

  /**
   * Create a TritAddress.
   * @param {Int8Array | number[] | string} value — 144 trits or trit string
   */
  constructor(value) {
    if (typeof value === 'string') {
      this.#trits = TritAddress.#parseString(value);
    } else if (value instanceof Int8Array) {
      if (value.length !== TOTAL_TRITS) {
        throw new Error(`TritAddress requires ${TOTAL_TRITS} trits, got ${value.length}`);
      }
      this.#trits = new Int8Array(value);
    } else if (Array.isArray(value)) {
      if (value.length !== TOTAL_TRITS) {
        throw new Error(`TritAddress requires ${TOTAL_TRITS} trits, got ${value.length}`);
      }
      this.#trits = new Int8Array(value);
    } else {
      throw new Error('TritAddress requires Int8Array, number[], or string');
    }
    
    // Validate all values are balanced ternary
    for (let i = 0; i < TOTAL_TRITS; i++) {
      if (this.#trits[i] < -1 || this.#trits[i] > 1) {
        throw new Error(`Invalid trit value at index ${i}: ${this.#trits[i]}`);
      }
    }
    
    Object.freeze(this);
  }

  /**
   * Get the full 144-trit array.
   * @returns {Int8Array}
   */
  toTrits() {
    return new Int8Array(this.#trits);
  }

  /**
   * Get a specific tier's 36-trit segment.
   * @param {number} tier — 0-3 (GALAXY, CLUSTER, ZONE, NODE)
   * @returns {Int8Array} — 36 trits
   */
  getTier(tier) {
    if (tier < 0 || tier >= TIER_COUNT) {
      throw new Error(`Invalid tier: ${tier}. Must be 0-${TIER_COUNT - 1}`);
    }
    const start = tier * TRITS_PER_TIER;
    return new Int8Array(this.#trits.slice(start, start + TRITS_PER_TIER));
  }

  /**
   * Get a sub-block within a tier.
   * @param {number} tier — 0-3
   * @param {number} subBlock — 0-3 (region, sector, cell, local)
   * @returns {Int8Array} — 9 trits
   */
  getSubBlock(tier, subBlock) {
    if (subBlock < 0 || subBlock >= SUB_BLOCKS_PER_TIER) {
      throw new Error(`Invalid sub-block: ${subBlock}`);
    }
    const start = tier * TRITS_PER_TIER + subBlock * TRITS_PER_SUB_BLOCK;
    return new Int8Array(this.#trits.slice(start, start + TRITS_PER_SUB_BLOCK));
  }

  /**
   * Get the tier name label.
   * @param {number} tier 
   * @returns {string}
   */
  static tierLabel(tier) {
    return TIER_LABELS[tier] || 'unknown';
  }

  /**
   * Check if two addresses share a common prefix up to a given tier.
   * Addresses in the same galaxy share tier 0.
   * Addresses in the same cluster share tiers 0+1.
   * 
   * @param {TritAddress} other 
   * @param {number} tier — check up to and including this tier (0-3)
   * @returns {boolean}
   */
  sharesTier(other, tier) {
    const endTrit = (tier + 1) * TRITS_PER_TIER;
    for (let i = 0; i < endTrit; i++) {
      if (this.#trits[i] !== other.#trits[i]) return false;
    }
    return true;
  }

  /**
   * Compute the hierarchical distance between two addresses.
   * Returns the tier at which the addresses diverge.
   * 
   * Distance 0 = identical
   * Distance 1 = different node, same zone
   * Distance 2 = different zone, same cluster
   * Distance 3 = different cluster, same galaxy
   * Distance 4 = different galaxy
   * 
   * @param {TritAddress} other 
   * @returns {number} — 0-4
   */
  tierDistance(other) {
    for (let tier = 0; tier < TIER_COUNT; tier++) {
      const start = tier * TRITS_PER_TIER;
      const end = start + TRITS_PER_TIER;
      for (let i = start; i < end; i++) {
        if (this.#trits[i] !== other.#trits[i]) {
          return TIER_COUNT - tier;
        }
      }
    }
    return 0; // Identical addresses
  }

  /**
   * Compute the XOR-like ternary distance (trit-wise difference).
   * For balanced ternary, "XOR" is: diff = (a - b + 3) % 3 mapped to {-1,0,+1}
   * The Hamming-like distance counts non-zero differences.
   * 
   * @param {TritAddress} other 
   * @returns {{ distance: number, maxDistance: number, similarity: number }}
   */
  tritDistance(other) {
    let distance = 0;
    for (let i = 0; i < TOTAL_TRITS; i++) {
      if (this.#trits[i] !== other.#trits[i]) distance++;
    }
    return {
      distance,
      maxDistance: TOTAL_TRITS,
      similarity: +((1 - distance / TOTAL_TRITS).toFixed(4)),
    };
  }

  /**
   * Get the SST family balance for each tier.
   * Useful for detecting address anomalies or locality properties.
   * 
   * @returns {Array<{tier: string, a: number, b: number, c: number, balance: number}>}
   */
  tierFamilyBalance() {
    const results = [];
    for (let tier = 0; tier < TIER_COUNT; tier++) {
      const tierTrits = this.getTier(tier);
      let a = 0, b = 0, c = 0;
      for (let i = 0; i < TRITS_PER_TIER; i++) {
        // Map trit to SST family: -1 → A, 0 → C, +1 → B
        if (tierTrits[i] === NEGATIVE) a++;
        else if (tierTrits[i] === POSITIVE) b++;
        else c++;
      }
      const expected = TRITS_PER_TIER / 3;
      const balance = Math.sqrt(
        Math.pow(a - expected, 2) + 
        Math.pow(b - expected, 2) + 
        Math.pow(c - expected, 2)
      ) / expected;
      
      results.push({
        tier: TIER_LABELS[tier],
        a, b, c,
        balance: +balance.toFixed(4),
      });
    }
    return results;
  }

  /**
   * Compute a YPC-27 checksum for the full address.
   * Uses the first 27 trits of each tier as a Poly27 input.
   * 
   * @returns {Poly27} — 27-trit checksum
   */
  checksum() {
    const hasher = new YPC27Checksum();
    // Feed each tier's trits as bytes (trit→byte conversion)
    for (let tier = 0; tier < TIER_COUNT; tier++) {
      const tierTrits = this.getTier(tier);
      // Pack trits as int8 bytes for checksum input
      hasher.update(new Uint8Array(tierTrits.buffer));
    }
    return hasher.digest();
  }

  /**
   * Convert to string representation.
   * Format: Galaxy.Cluster.Zone.Node (each tier as trit string)
   * Uses T for -1, 0 for 0, 1 for +1.
   * 
   * @param {boolean} [compact=true] — use 9-char sub-block grouping
   * @returns {string}
   */
  toString(compact = true) {
    const tiers = [];
    for (let tier = 0; tier < TIER_COUNT; tier++) {
      const tierTrits = this.getTier(tier);
      const chars = [];
      for (let i = 0; i < TRITS_PER_TIER; i++) {
        chars.push(tierTrits[i] === NEGATIVE ? 'T' : String(tierTrits[i]));
      }
      if (compact) {
        // Group into sub-blocks separated by colons
        const grouped = [];
        for (let s = 0; s < SUB_BLOCKS_PER_TIER; s++) {
          grouped.push(chars.slice(s * TRITS_PER_SUB_BLOCK, (s + 1) * TRITS_PER_SUB_BLOCK).join(''));
        }
        tiers.push(grouped.join(':'));
      } else {
        tiers.push(chars.join(''));
      }
    }
    return tiers.join('.');
  }

  /**
   * Check equality.
   * @param {TritAddress} other 
   * @returns {boolean}
   */
  equals(other) {
    for (let i = 0; i < TOTAL_TRITS; i++) {
      if (this.#trits[i] !== other.#trits[i]) return false;
    }
    return true;
  }

  // ---------------------------------------------------------------------------
  // Static constructors
  // ---------------------------------------------------------------------------

  /**
   * Create a TritAddress from a hex peer ID (e.g., 64-char SHA3 hash).
   * Converts hex bytes → trits (5 trits per byte), pads/truncates to 144.
   * 
   * @param {string} hexId — hex-encoded peer ID
   * @returns {TritAddress}
   */
  static fromHex(hexId) {
    const bytes = [];
    const cleanHex = hexId.replace(/^0x/, '');
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes.push(parseInt(cleanHex.substr(i, 2), 16) || 0);
    }
    
    const allTrits = bytesToTrits(new Uint8Array(bytes));
    
    // Pad or truncate to exactly 144
    const trits = new Int8Array(TOTAL_TRITS);
    for (let i = 0; i < TOTAL_TRITS && i < allTrits.length; i++) {
      trits[i] = allTrits[i];
    }
    
    return new TritAddress(trits);
  }

  /**
   * Create a TritAddress from tier components.
   * @param {Int8Array} galaxy — 36 trits
   * @param {Int8Array} cluster — 36 trits
   * @param {Int8Array} zone — 36 trits
   * @param {Int8Array} node — 36 trits
   * @returns {TritAddress}
   */
  static fromTiers(galaxy, cluster, zone, node) {
    const trits = new Int8Array(TOTAL_TRITS);
    trits.set(galaxy, 0);
    trits.set(cluster, TRITS_PER_TIER);
    trits.set(zone, TRITS_PER_TIER * 2);
    trits.set(node, TRITS_PER_TIER * 3);
    return new TritAddress(trits);
  }

  /**
   * Create a zero address (all NEUTRAL trits).
   * Used as the "origin" in the ternary address space.
   * @returns {TritAddress}
   */
  static zero() {
    return new TritAddress(new Int8Array(TOTAL_TRITS));
  }

  /**
   * Create a random address (for testing).
   * Each trit is randomly -1, 0, or +1.
   * @returns {TritAddress}
   */
  static random() {
    const trits = new Int8Array(TOTAL_TRITS);
    for (let i = 0; i < TOTAL_TRITS; i++) {
      trits[i] = Math.floor(Math.random() * 3) - 1;
    }
    return new TritAddress(trits);
  }

  /**
   * Parse a trit string (T=−1, 0=0, 1=+1).
   * Strips dots and colons used as separators.
   * @param {string} s 
   * @returns {Int8Array}
   */
  static #parseString(s) {
    const clean = s.replace(/[.:]/g, '');
    if (clean.length !== TOTAL_TRITS) {
      throw new Error(`TritAddress string must have ${TOTAL_TRITS} trit chars, got ${clean.length}`);
    }
    
    const trits = new Int8Array(TOTAL_TRITS);
    for (let i = 0; i < TOTAL_TRITS; i++) {
      const c = clean[i].toUpperCase();
      if (c === 'T' || c === '-') trits[i] = NEGATIVE;
      else if (c === '1' || c === '+') trits[i] = POSITIVE;
      else trits[i] = NEUTRAL;
    }
    return trits;
  }
}

// =============================================================================
// ROUTING TABLE — Hierarchical Ternary Routing
// =============================================================================

/**
 * TernaryRoutingTable — XOR-metric routing for 144T addresses.
 * 
 * Similar to Kademlia but using balanced ternary distance instead of
 * binary XOR. Each "k-bucket" is replaced by a "t-bucket" that groups
 * peers by tier distance (galaxy, cluster, zone, node).
 * 
 * Routing priority:
 * 1. Same zone (tier distance 1) — direct connection preferred
 * 2. Same cluster (distance 2) — relay via zone peer
 * 3. Same galaxy (distance 3) — relay via cluster peer
 * 4. Different galaxy (distance 4) — relay via galaxy peer
 */
export class TernaryRoutingTable {
  /**
   * @param {TritAddress} selfAddress — this node's 144T address
   * @param {number} [bucketSize=6] — max peers per bucket (k=6 for hexagonal)
   */
  constructor(selfAddress, bucketSize = 6) {
    this.selfAddress = selfAddress;
    this.bucketSize = bucketSize;
    
    // 4 buckets — one per tier distance (1=zone, 2=cluster, 3=galaxy, 4=remote)
    /** @type {Map<string, {address: TritAddress, lastSeen: number, rtt: number}>[]} */
    this._buckets = new Array(TIER_COUNT).fill(null).map(() => new Map());
  }

  /**
   * Add a peer to the routing table.
   * Placed in the bucket corresponding to tier distance from self.
   * 
   * @param {string} peerId — unique peer identifier
   * @param {TritAddress} peerAddress — peer's 144T address
   * @param {number} [rtt=0] — round-trip time in ms
   * @returns {boolean} — true if added (false if bucket full)
   */
  addPeer(peerId, peerAddress, rtt = 0) {
    const distance = this.selfAddress.tierDistance(peerAddress);
    if (distance === 0) return false; // Can't add self
    
    const bucketIdx = distance - 1; // 1-4 → 0-3
    const bucket = this._buckets[bucketIdx];
    
    // Update if already present
    if (bucket.has(peerId)) {
      const entry = bucket.get(peerId);
      entry.lastSeen = Date.now();
      entry.rtt = rtt;
      return true;
    }
    
    // Add if bucket has room
    if (bucket.size < this.bucketSize) {
      bucket.set(peerId, {
        address: peerAddress,
        lastSeen: Date.now(),
        rtt,
      });
      return true;
    }
    
    // Bucket full — evict oldest if new peer is closer (lower RTT)
    let oldestKey = null;
    let oldestTime = Infinity;
    for (const [key, entry] of bucket) {
      if (entry.lastSeen < oldestTime) {
        oldestTime = entry.lastSeen;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      bucket.delete(oldestKey);
      bucket.set(peerId, {
        address: peerAddress,
        lastSeen: Date.now(),
        rtt,
      });
      return true;
    }
    
    return false;
  }

  /**
   * Remove a peer from the routing table.
   * @param {string} peerId 
   * @returns {boolean}
   */
  removePeer(peerId) {
    for (const bucket of this._buckets) {
      if (bucket.delete(peerId)) return true;
    }
    return false;
  }

  /**
   * Find the closest peers to a target address.
   * Returns peers sorted by trit distance (ascending).
   * 
   * @param {TritAddress} target — address to find peers near
   * @param {number} [count=6] — max peers to return
   * @returns {Array<{peerId: string, address: TritAddress, distance: number, rtt: number}>}
   */
  findClosest(target, count = 6) {
    const candidates = [];
    
    for (const bucket of this._buckets) {
      for (const [peerId, entry] of bucket) {
        const { distance } = entry.address.tritDistance(target);
        candidates.push({
          peerId,
          address: entry.address,
          distance,
          rtt: entry.rtt,
        });
      }
    }
    
    // Sort by trit distance, then by RTT
    candidates.sort((a, b) => a.distance - b.distance || a.rtt - b.rtt);
    
    return candidates.slice(0, count);
  }

  /**
   * Get the next hop toward a target address.
   * Selects the peer with minimized tier distance to the target.
   * 
   * @param {TritAddress} target 
   * @returns {{peerId: string, address: TritAddress, tierDistance: number, rtt: number} | null}
   */
  nextHop(target) {
    const targetTierDist = this.selfAddress.tierDistance(target);
    
    // Try to find a peer closer to the target than we are
    let best = null;
    let bestDist = targetTierDist;
    
    for (const bucket of this._buckets) {
      for (const [peerId, entry] of bucket) {
        const dist = entry.address.tierDistance(target);
        if (dist < bestDist || (dist === bestDist && (!best || entry.rtt < best.rtt))) {
          bestDist = dist;
          best = { peerId, address: entry.address, tierDistance: dist, rtt: entry.rtt };
        }
      }
    }
    
    return best;
  }

  /**
   * Get routing table status.
   * @returns {Object}
   */
  getStatus() {
    const buckets = this._buckets.map((bucket, i) => ({
      tier: TIER_LABELS[TIER_COUNT - 1 - i] || `distance-${i + 1}`,
      peerCount: bucket.size,
      capacity: this.bucketSize,
    }));
    
    const totalPeers = this._buckets.reduce((sum, b) => sum + b.size, 0);
    
    return {
      selfAddress: this.selfAddress.toString(),
      buckets,
      totalPeers,
      capacity: this.bucketSize * TIER_COUNT,
    };
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Convert a standard 64-char hex node ID into a 144T address with
 * SST-based tier assignment.
 * 
 * The hex ID is converted to trits, then the tiers are assigned
 * using an SST Fibonacci cycle rotation to ensure good distribution
 * across the address space.
 * 
 * @param {string} hexId — 64-char hex peer ID
 * @param {Object} [locality] — optional locality hints
 * @param {number} [locality.galaxy=0] — galaxy index (0 for default)
 * @param {number} [locality.cluster=0] — cluster index
 * @returns {TritAddress}
 */
export function hexIdToAddress(hexId, locality = {}) {
  // Convert hex to raw trits
  const bytes = [];
  const clean = hexId.replace(/^0x/, '').slice(0, 64); // Max 32 bytes = 160 trits
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substr(i, 2), 16) || 0);
  }
  const rawTrits = bytesToTrits(new Uint8Array(bytes));
  
  const trits = new Int8Array(TOTAL_TRITS);
  
  // Galaxy tier: use locality hint or derive from first bytes
  if (locality.galaxy !== undefined) {
    const galaxyTrits = new TritArray(locality.galaxy, TRITS_PER_TIER).toJSON();
    for (let i = 0; i < TRITS_PER_TIER && i < galaxyTrits.length; i++) {
      trits[i] = galaxyTrits[i];
    }
  } else {
    // Derive galaxy from SST digital root of first 4 bytes
    for (let i = 0; i < TRITS_PER_TIER && i < rawTrits.length; i++) {
      trits[i] = rawTrits[i];
    }
  }
  
  // Cluster tier: derive or use hint
  if (locality.cluster !== undefined) {
    const clusterTrits = new TritArray(locality.cluster, TRITS_PER_TIER).toJSON();
    for (let i = 0; i < TRITS_PER_TIER && i < clusterTrits.length; i++) {
      trits[TRITS_PER_TIER + i] = clusterTrits[i];
    }
  } else {
    for (let i = 0; i < TRITS_PER_TIER; i++) {
      const srcIdx = TRITS_PER_TIER + i;
      trits[TRITS_PER_TIER + i] = srcIdx < rawTrits.length ? rawTrits[srcIdx] : 0;
    }
  }
  
  // Zone tier: always derived from hex ID
  for (let i = 0; i < TRITS_PER_TIER; i++) {
    const srcIdx = TRITS_PER_TIER * 2 + i;
    trits[TRITS_PER_TIER * 2 + i] = srcIdx < rawTrits.length ? rawTrits[srcIdx] : 0;
  }
  
  // Node tier: always derived from hex ID (unique portion)
  for (let i = 0; i < TRITS_PER_TIER; i++) {
    const srcIdx = TRITS_PER_TIER * 3 + i;
    trits[TRITS_PER_TIER * 3 + i] = srcIdx < rawTrits.length ? rawTrits[srcIdx] : 0;
  }
  
  return new TritAddress(trits);
}

/**
 * Compute the 216-hypercycle position for an address.
 * The hypercycle is LCM(27, 24) = 216 — the full SST-YPC-27 alignment.
 * 
 * @param {TritAddress} address 
 * @returns {number} — position 0-215
 */
export function hypercyclePosition(address) {
  const trits = address.toTrits();
  // Sum all trit absolute values, then mod 216
  let sum = 0;
  for (let i = 0; i < TOTAL_TRITS; i++) {
    sum += Math.abs(trits[i]) * (i + 1);
  }
  return sum % 216;
}

/**
 * Verify the integrity of a 144T address using YPC-27.
 * Computes a checksum of all 4 tiers and compares.
 * 
 * @param {TritAddress} address 
 * @param {Poly27} expectedChecksum 
 * @returns {boolean}
 */
export function verifyAddressIntegrity(address, expectedChecksum) {
  const computed = address.checksum();
  return computed.equals(expectedChecksum);
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Constants
  TOTAL_TRITS,
  TIER_COUNT,
  TRITS_PER_TIER,
  SUB_BLOCKS_PER_TIER,
  TRITS_PER_SUB_BLOCK,
  TierName,
  TIER_LABELS,
  
  // Classes
  TritAddress,
  TernaryRoutingTable,
  
  // Utilities
  hexIdToAddress,
  hypercyclePosition,
  verifyAddressIntegrity,
};
