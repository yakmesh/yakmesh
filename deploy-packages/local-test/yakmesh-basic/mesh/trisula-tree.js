/**
 * TRISULA - Ternary Search Tree for Mesh Routing
 * 
 * त्रिशूल (Trisula) = Trident, Shiva's weapon
 * 
 * A Ternary Search Tree (TST) optimized for peer ID routing in YAKMESH.
 * Each node has three children: LEFT (less), MIDDLE (equal), RIGHT (greater).
 * 
 * Why TST for mesh routing?
 * 1. Fast prefix matching for node ID lookups
 * 2. Memory efficient (only allocates nodes for actual data)
 * 3. Natural 3-way branching aligns with ternary philosophy
 * 4. O(k) search where k = key length (not tree size)
 * 5. Supports range queries and nearest-neighbor searches
 * 
 * Use cases in YAKMESH:
 * - SHERPA: Peer discovery routing tables
 * - KHATA: Gossip propagation paths
 * - NAKPAK: Onion routing next-hop selection
 * - Content addressing: Hash-based content lookup
 * 
 * @module mesh/trisula-tree
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Trit, NEGATIVE, NEUTRAL, POSITIVE } from '../oracle/tribhuj.js';

// =============================================================================
// TST NODE
// =============================================================================

/**
 * A node in the Ternary Search Tree.
 * @template T
 */
class TSTNode {
  /** @type {string} The character at this node */
  char;
  
  /** @type {TSTNode<T> | null} Left child (less than) */
  left = null;
  
  /** @type {TSTNode<T> | null} Middle child (equal to) */
  middle = null;
  
  /** @type {TSTNode<T> | null} Right child (greater than) */
  right = null;
  
  /** @type {T | null} Value stored at this node (if end of key) */
  value = null;
  
  /** @type {boolean} Whether this node marks end of a key */
  isEnd = false;

  /**
   * Create a TST node.
   * @param {string} char - The character for this node
   */
  constructor(char) {
    this.char = char;
  }
}

// =============================================================================
// TRISULA TREE
// =============================================================================

/**
 * Ternary Search Tree for efficient string key operations.
 * @template T The type of values stored
 */
export class TrisulaTST {
  /** @type {TSTNode<T> | null} */
  #root = null;
  
  /** @type {number} */
  #size = 0;

  /** Get the number of keys in the tree */
  get size() { return this.#size; }

  /** Check if tree is empty */
  get isEmpty() { return this.#size === 0; }

  // ---------------------------------------------------------------------------
  // Core Operations
  // ---------------------------------------------------------------------------

  /**
   * Insert a key-value pair.
   * @param {string} key - The key to insert
   * @param {T} value - The value to associate with the key
   * @returns {this} For chaining
   */
  insert(key, value) {
    if (!key || key.length === 0) {
      throw new Error('Key cannot be empty');
    }
    
    this.#root = this.#insertNode(this.#root, key, value, 0);
    return this;
  }

  /**
   * Recursive insert helper.
   * @private
   */
  #insertNode(node, key, value, index) {
    const char = key[index];
    
    if (!node) {
      node = new TSTNode(char);
    }
    
    const comparison = char.localeCompare(node.char);
    
    if (comparison < 0) {
      // Go left (char is less than node.char)
      node.left = this.#insertNode(node.left, key, value, index);
    } else if (comparison > 0) {
      // Go right (char is greater than node.char)
      node.right = this.#insertNode(node.right, key, value, index);
    } else if (index < key.length - 1) {
      // Match, go middle with next character
      node.middle = this.#insertNode(node.middle, key, value, index + 1);
    } else {
      // End of key
      if (!node.isEnd) {
        this.#size++;
      }
      node.value = value;
      node.isEnd = true;
    }
    
    return node;
  }

  /**
   * Search for a key.
   * @param {string} key - The key to search for
   * @returns {T | null} The value if found, null otherwise
   */
  search(key) {
    if (!key || key.length === 0) return null;
    
    const node = this.#searchNode(this.#root, key, 0);
    return (node && node.isEnd) ? node.value : null;
  }

  /**
   * Recursive search helper.
   * @private
   */
  #searchNode(node, key, index) {
    if (!node) return null;
    
    const char = key[index];
    const comparison = char.localeCompare(node.char);
    
    if (comparison < 0) {
      return this.#searchNode(node.left, key, index);
    } else if (comparison > 0) {
      return this.#searchNode(node.right, key, index);
    } else if (index < key.length - 1) {
      return this.#searchNode(node.middle, key, index + 1);
    } else {
      return node;
    }
  }

  /**
   * Check if a key exists.
   * @param {string} key
   * @returns {boolean}
   */
  has(key) {
    if (!key || key.length === 0) return false;
    const node = this.#searchNode(this.#root, key, 0);
    return node !== null && node.isEnd;
  }

  /**
   * Delete a key.
   * @param {string} key
   * @returns {boolean} True if key was deleted
   */
  delete(key) {
    if (!key || key.length === 0) return false;
    
    const node = this.#searchNode(this.#root, key, 0);
    if (node && node.isEnd) {
      node.isEnd = false;
      node.value = null;
      this.#size--;
      // Note: We don't actually remove nodes to keep tree structure
      // A compaction method could be added for memory optimization
      return true;
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // Prefix Operations (Key for routing)
  // ---------------------------------------------------------------------------

  /**
   * Find all keys with given prefix.
   * Essential for mesh routing - find all peers in a certain "region".
   * @param {string} prefix
   * @returns {Array<{key: string, value: T}>}
   */
  prefixSearch(prefix) {
    const results = [];
    if (!prefix || prefix.length === 0) {
      // Return all keys
      this.#collectAll(this.#root, '', results);
      return results;
    }
    
    const node = this.#searchNode(this.#root, prefix, 0);
    if (!node) return results;
    
    // If prefix itself is a key
    if (node.isEnd) {
      results.push({ key: prefix, value: node.value });
    }
    
    // Collect all keys in subtree
    this.#collectAll(node.middle, prefix, results);
    
    return results;
  }

  /**
   * Collect all keys in subtree.
   * @private
   */
  #collectAll(node, prefix, results) {
    if (!node) return;
    
    // Traverse left subtree
    this.#collectAll(node.left, prefix, results);
    
    // Current node
    const currentKey = prefix + node.char;
    if (node.isEnd) {
      results.push({ key: currentKey, value: node.value });
    }
    
    // Traverse middle subtree
    this.#collectAll(node.middle, currentKey, results);
    
    // Traverse right subtree
    this.#collectAll(node.right, prefix, results);
  }

  /**
   * Find the longest key that is a prefix of the given string.
   * Useful for routing table lookups.
   * @param {string} str
   * @returns {{ key: string, value: T } | null}
   */
  longestPrefixOf(str) {
    if (!str || str.length === 0) return null;
    
    let longestEnd = null;
    let longestKey = '';
    let node = this.#root;
    let index = 0;
    let currentKey = '';
    
    while (node && index < str.length) {
      const char = str[index];
      const comparison = char.localeCompare(node.char);
      
      if (comparison < 0) {
        node = node.left;
      } else if (comparison > 0) {
        node = node.right;
      } else {
        currentKey += node.char;
        if (node.isEnd) {
          longestEnd = node;
          longestKey = currentKey;
        }
        node = node.middle;
        index++;
      }
    }
    
    return longestEnd ? { key: longestKey, value: longestEnd.value } : null;
  }

  // ---------------------------------------------------------------------------
  // Nearest Neighbor (for routing decisions)
  // ---------------------------------------------------------------------------

  /**
   * Find the key closest to the given key (lexicographically).
   * If exact match exists, returns it. Otherwise finds nearest.
   * @param {string} key
   * @returns {{ key: string, value: T, comparison: Trit } | null}
   */
  nearest(key) {
    if (!key || key.length === 0) return null;
    if (this.#size === 0) return null;
    
    // Try exact match first
    const exact = this.search(key);
    if (exact !== null) {
      return { key, value: exact, comparison: new Trit(NEUTRAL) };
    }
    
    // Find floor and ceiling
    const floor = this.#floor(key);
    const ceiling = this.#ceiling(key);
    
    if (!floor && !ceiling) return null;
    if (!floor) return { ...ceiling, comparison: new Trit(NEGATIVE) };
    if (!ceiling) return { ...floor, comparison: new Trit(POSITIVE) };
    
    // Return the closer one
    const floorDist = this.#stringDistance(key, floor.key);
    const ceilingDist = this.#stringDistance(key, ceiling.key);
    
    if (floorDist <= ceilingDist) {
      return { ...floor, comparison: new Trit(POSITIVE) }; // Key > result
    } else {
      return { ...ceiling, comparison: new Trit(NEGATIVE) }; // Key < result
    }
  }

  /**
   * Find greatest key less than given key.
   * @private
   */
  #floor(key) {
    const allKeys = [];
    this.#collectAll(this.#root, '', allKeys);
    
    let floor = null;
    for (const item of allKeys) {
      if (item.key < key && (!floor || item.key > floor.key)) {
        floor = item;
      }
    }
    return floor;
  }

  /**
   * Find smallest key greater than given key.
   * @private
   */
  #ceiling(key) {
    const allKeys = [];
    this.#collectAll(this.#root, '', allKeys);
    
    let ceiling = null;
    for (const item of allKeys) {
      if (item.key > key && (!ceiling || item.key < ceiling.key)) {
        ceiling = item;
      }
    }
    return ceiling;
  }

  /**
   * Simple string distance (number of differing characters).
   * @private
   */
  #stringDistance(a, b) {
    const maxLen = Math.max(a.length, b.length);
    let dist = 0;
    for (let i = 0; i < maxLen; i++) {
      if (a[i] !== b[i]) dist++;
    }
    return dist;
  }

  // ---------------------------------------------------------------------------
  // Iteration
  // ---------------------------------------------------------------------------

  /**
   * Get all keys in sorted order.
   * @returns {string[]}
   */
  keys() {
    const results = [];
    this.#collectAll(this.#root, '', results);
    return results.map(r => r.key).sort();
  }

  /**
   * Get all values.
   * @returns {T[]}
   */
  values() {
    const results = [];
    this.#collectAll(this.#root, '', results);
    return results.map(r => r.value);
  }

  /**
   * Get all entries.
   * @returns {Array<{key: string, value: T}>}
   */
  entries() {
    const results = [];
    this.#collectAll(this.#root, '', results);
    return results.sort((a, b) => a.key.localeCompare(b.key));
  }

  /**
   * Iterate over entries.
   */
  *[Symbol.iterator]() {
    for (const entry of this.entries()) {
      yield entry;
    }
  }

  // ---------------------------------------------------------------------------
  // Utility
  // ---------------------------------------------------------------------------

  /**
   * Clear the tree.
   */
  clear() {
    this.#root = null;
    this.#size = 0;
  }

  /**
   * Get tree statistics.
   */
  stats() {
    let nodeCount = 0;
    let maxDepth = 0;
    
    const countNodes = (node, depth) => {
      if (!node) return;
      nodeCount++;
      maxDepth = Math.max(maxDepth, depth);
      countNodes(node.left, depth + 1);
      countNodes(node.middle, depth + 1);
      countNodes(node.right, depth + 1);
    };
    
    countNodes(this.#root, 1);
    
    return {
      size: this.#size,
      nodeCount,
      maxDepth,
      avgDepth: nodeCount > 0 ? maxDepth / 2 : 0,
    };
  }
}

// =============================================================================
// ROUTING TABLE SPECIALIZED TST
// =============================================================================

/**
 * A routing table using TRISULA TST, optimized for mesh peer lookups.
 * Keys are node IDs (hex strings), values are peer connection info.
 */
export class TrisulaPeerRouter {
  /** @type {TrisulaTST<PeerInfo>} */
  #tst = new TrisulaTST();

  /**
   * @typedef {Object} PeerInfo
   * @property {string} nodeId - The peer's node ID
   * @property {string} endpoint - WebSocket endpoint
   * @property {number} lastSeen - Timestamp of last contact
   * @property {number} latency - RTT in milliseconds
   * @property {Trit} linkQuality - Link direction quality
   */

  /** Get number of peers */
  get size() { return this.#tst.size; }

  /**
   * Add or update a peer.
   * @param {string} nodeId
   * @param {Omit<PeerInfo, 'nodeId'>} info
   */
  addPeer(nodeId, info) {
    this.#tst.insert(nodeId, { nodeId, ...info });
  }

  /**
   * Remove a peer.
   * @param {string} nodeId
   */
  removePeer(nodeId) {
    this.#tst.delete(nodeId);
  }

  /**
   * Get peer info.
   * @param {string} nodeId
   * @returns {PeerInfo | null}
   */
  getPeer(nodeId) {
    return this.#tst.search(nodeId);
  }

  /**
   * Check if peer exists.
   * @param {string} nodeId
   */
  hasPeer(nodeId) {
    return this.#tst.has(nodeId);
  }

  /**
   * Find peers with ID prefix (for region-based routing).
   * @param {string} prefix
   * @returns {PeerInfo[]}
   */
  findByPrefix(prefix) {
    return this.#tst.prefixSearch(prefix).map(e => e.value);
  }

  /**
   * Find best route to a target node ID.
   * Returns the peer whose ID is closest to the target.
   * @param {string} targetId
   * @returns {PeerInfo | null}
   */
  findBestRoute(targetId) {
    const nearest = this.#tst.nearest(targetId);
    return nearest ? nearest.value : null;
  }

  /**
   * Find peers for XOR-based routing (Kademlia-style).
   * Returns peers sorted by XOR distance to target.
   * @param {string} targetId
   * @param {number} count - Maximum number to return
   * @returns {PeerInfo[]}
   */
  findClosestPeers(targetId, count = 3) {
    const entries = this.#tst.entries();
    
    // Calculate XOR distance for each peer
    const withDistance = entries.map(e => ({
      peer: e.value,
      distance: this.#xorDistance(e.key, targetId),
    }));
    
    // Sort by distance and take top N
    withDistance.sort((a, b) => a.distance.localeCompare(b.distance));
    
    return withDistance.slice(0, count).map(w => w.peer);
  }

  /**
   * Calculate XOR distance between two hex node IDs.
   * @private
   */
  #xorDistance(a, b) {
    const aBig = BigInt('0x' + a.padStart(64, '0'));
    const bBig = BigInt('0x' + b.padStart(64, '0'));
    const xor = aBig ^ bBig;
    return xor.toString(16).padStart(64, '0');
  }

  /**
   * Get all peers.
   * @returns {PeerInfo[]}
   */
  allPeers() {
    return this.#tst.values();
  }

  /**
   * Get routing table stats.
   */
  stats() {
    const tstStats = this.#tst.stats();
    return {
      ...tstStats,
      peerCount: this.#tst.size,
    };
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  TrisulaTST,
  TrisulaPeerRouter,
};
