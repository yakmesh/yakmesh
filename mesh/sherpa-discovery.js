/**
 * SHERPA - Secure Hidden Endpoint Resolution Path Architecture
 * 
 * A novel peer discovery mechanism using public web endpoints as a decentralized DHT.
 * Instead of centralized bootstrap nodes, SHERPA leverages the public-facing portion
 * of yakmesh nodes (Caddy/Abyss web servers) to create a self-organizing peer registry.
 * 
 * Key Innovation: "The web IS the DHT"
 * - Each node exposes /.well-known/yakmesh/beacon with its peer list
 * - Discovery crawls known endpoints to find new peers
 * - No central authority - truly decentralized bootstrap
 * - Works with existing CDN infrastructure
 * 
 * Etymology: Sherpas guide travelers through hidden mountain paths,
 * just like SHERPA guides nodes to discover each other.
 * 
 * @module mesh/sherpa-discovery
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { EventEmitter } from 'events';

// ============================================================
// SHERPA CONFIGURATION
// ============================================================

const SHERPA_CONFIG = {
  // Beacon endpoint
  beaconPath: '/.well-known/yakmesh/beacon',
  
  // Discovery settings
  maxPeersPerBeacon: 50,        // Max peers to advertise in beacon
  maxPeersToReturn: 20,         // Max peers to return per request
  maxCrawlDepth: 3,             // How many hops to crawl
  crawlTimeout: 5000,           // Timeout for each beacon fetch (ms)
  crawlInterval: 300000,        // Re-crawl interval (5 minutes)
  
  // Peer scoring
  minPeerScore: 0.1,            // Minimum score to keep peer
  scoreDecay: 0.95,             // Score decay per interval
  successBonus: 0.2,            // Score bonus for successful contact
  failurePenalty: 0.3,          // Score penalty for failed contact
  
  // Security
  maxBeaconSize: 65536,         // Max beacon response size (64KB)
  signatureRequired: true,      // Require signed beacons
  
  // Rate limiting
  maxCrawlsPerMinute: 10,       // Prevent crawl storms
  
  // Version
  protocolVersion: '1.0',
};

// ============================================================
// BEACON MESSAGE FORMAT
// ============================================================

/**
 * Beacon message format for /.well-known/yakmesh/beacon
 * This is what nodes advertise to help others discover peers.
 * 
 * Enhanced with NAMCHE fields for certificate integration.
 */
class BeaconMessage {
  constructor(options = {}) {
    this.version = SHERPA_CONFIG.protocolVersion;
    this.nodeId = options.nodeId;
    this.networkName = options.networkName;
    this.timestamp = options.timestamp || Date.now();
    this.ttl = options.ttl || 3600;  // 1 hour default TTL
    
    // Node capabilities
    this.capabilities = {
      wsPort: options.wsPort || null,
      httpPort: options.httpPort || null,
      supportsAnnex: options.supportsAnnex ?? true,
      supportsNakpak: options.supportsNakpak ?? true,
      supportsGossip: options.supportsGossip ?? true,
      // NAMCHE capability flags
      supportsKhata: options.supportsKhata ?? true,
      canVerifyDomains: options.canVerifyDomains ?? false,
      canRouteNakpak: options.canRouteNakpak ?? true,
    };
    
    // ════════════════════════════════════════════════════════════════════
    // NAMCHE Integration - Certificate & Trust Distribution
    // ════════════════════════════════════════════════════════════════════
    this.namche = {
      // Hash of this node's current DOKO (for verification)
      dokoHash: options.dokoHash || null,
      
      // SSL/TLS information (for hybrid trust with traditional PKI)
      ssl: {
        hasPublicCert: options.sslHasPublicCert ?? false,
        certFingerprint: options.sslCertFingerprint || null,  // SHA256 of cert
        issuer: options.sslIssuer || null,  // e.g., "letsencrypt", "zerossl"
        domains: options.sslDomains || [],  // Domains covered by cert
        expiresAt: options.sslExpiresAt || null,  // Cert expiry timestamp
      },
      
      // Domain claims this node is asserting
      domainClaims: options.domainClaims || [],
      
      // Verifier info (if this node can verify others' domains)
      verifier: options.canVerifyDomains ? {
        available: true,
        queue: options.verifierQueue || 0,  // Pending verifications
      } : null,
    };
    
    // Known peers (other nodes we know about)
    this.peers = options.peers || [];
    
    // Cryptographic proof
    this.publicKey = options.publicKey || null;
    this.signature = options.signature || null;
  }

  /**
   * Add a peer to the beacon
   */
  addPeer(peerInfo) {
    if (this.peers.length >= SHERPA_CONFIG.maxPeersPerBeacon) {
      // Remove lowest-scored peer
      this.peers.sort((a, b) => b.score - a.score);
      this.peers.pop();
    }
    
    this.peers.push({
      nodeId: peerInfo.nodeId,
      endpoint: peerInfo.endpoint,        // e.g., "https://example.com"
      wsEndpoint: peerInfo.wsEndpoint,    // e.g., "wss://example.com:9001"
      lastSeen: peerInfo.lastSeen || Date.now(),
      score: peerInfo.score || 1.0,
      networkName: peerInfo.networkName,
    });
  }

  /**
   * Get peers for discovery response (limited subset)
   */
  getPeersForDiscovery() {
    // Sort by score, return top N
    return [...this.peers]
      .sort((a, b) => b.score - a.score)
      .slice(0, SHERPA_CONFIG.maxPeersToReturn)
      .map(p => ({
        nodeId: p.nodeId,
        endpoint: p.endpoint,
        wsEndpoint: p.wsEndpoint,
        lastSeen: p.lastSeen,
        networkName: p.networkName,
      }));
  }

  /**
   * Serialize beacon for HTTP response
   */
  serialize() {
    return {
      version: this.version,
      nodeId: this.nodeId,
      networkName: this.networkName,
      timestamp: this.timestamp,
      ttl: this.ttl,
      capabilities: this.capabilities,
      namche: this.namche,  // NAMCHE integration fields
      peers: this.getPeersForDiscovery(),
      publicKey: this.publicKey,
      signature: this.signature,
    };
  }

  /**
   * Create data to sign
   */
  getSignableData() {
    return JSON.stringify({
      version: this.version,
      nodeId: this.nodeId,
      networkName: this.networkName,
      timestamp: this.timestamp,
      capabilities: this.capabilities,
      namche: this.namche,  // Include NAMCHE in signature
    });
  }

  /**
   * Deserialize beacon from HTTP response
   */
  static deserialize(data) {
    const beacon = new BeaconMessage({
      nodeId: data.nodeId,
      networkName: data.networkName,
      timestamp: data.timestamp,
      ttl: data.ttl,
      wsPort: data.capabilities?.wsPort,
      httpPort: data.capabilities?.httpPort,
      supportsAnnex: data.capabilities?.supportsAnnex,
      supportsNakpak: data.capabilities?.supportsNakpak,
      supportsGossip: data.capabilities?.supportsGossip,
      // NAMCHE capabilities
      supportsKhata: data.capabilities?.supportsKhata,
      canVerifyDomains: data.capabilities?.canVerifyDomains,
      canRouteNakpak: data.capabilities?.canRouteNakpak,
      // NAMCHE integration
      dokoHash: data.namche?.dokoHash,
      sslHasPublicCert: data.namche?.ssl?.hasPublicCert,
      sslCertFingerprint: data.namche?.ssl?.certFingerprint,
      sslIssuer: data.namche?.ssl?.issuer,
      sslDomains: data.namche?.ssl?.domains,
      sslExpiresAt: data.namche?.ssl?.expiresAt,
      domainClaims: data.namche?.domainClaims,
      verifierQueue: data.namche?.verifier?.queue,
      publicKey: data.publicKey,
      signature: data.signature,
    });
    beacon.version = data.version;
    beacon.peers = data.peers || [];
    return beacon;
  }
}

// ============================================================
// PEER REGISTRY
// ============================================================

/**
 * Maintains a registry of known peers with scoring
 */
class PeerRegistry {
  constructor(options = {}) {
    this.peers = new Map();  // nodeId -> PeerInfo
    this.networkFilter = options.networkFilter || null;  // Only accept peers from this network
    this.maxPeers = options.maxPeers || 1000;
  }

  /**
   * Add or update a peer
   */
  upsert(peerInfo) {
    const existing = this.peers.get(peerInfo.nodeId);
    
    // Filter by network if configured
    if (this.networkFilter && peerInfo.networkName !== this.networkFilter) {
      return false;
    }
    
    if (existing) {
      // Update existing peer
      existing.endpoint = peerInfo.endpoint || existing.endpoint;
      existing.wsEndpoint = peerInfo.wsEndpoint || existing.wsEndpoint;
      existing.lastSeen = Math.max(existing.lastSeen, peerInfo.lastSeen || Date.now());
      existing.score = Math.min(1.0, existing.score + SHERPA_CONFIG.successBonus);
      existing.capabilities = peerInfo.capabilities || existing.capabilities;
    } else {
      // Add new peer (evict lowest scored if at capacity)
      if (this.peers.size >= this.maxPeers) {
        this._evictLowest();
      }
      
      this.peers.set(peerInfo.nodeId, {
        nodeId: peerInfo.nodeId,
        endpoint: peerInfo.endpoint,
        wsEndpoint: peerInfo.wsEndpoint,
        lastSeen: peerInfo.lastSeen || Date.now(),
        score: peerInfo.score || 1.0,
        networkName: peerInfo.networkName,
        capabilities: peerInfo.capabilities || {},
        discoveredAt: Date.now(),
        failureCount: 0,
      });
    }
    
    return true;
  }

  /**
   * Mark a peer as failed (decrease score)
   */
  markFailed(nodeId) {
    const peer = this.peers.get(nodeId);
    if (peer) {
      peer.score = Math.max(0, peer.score - SHERPA_CONFIG.failurePenalty);
      peer.failureCount++;
      
      // Remove if score too low
      if (peer.score < SHERPA_CONFIG.minPeerScore) {
        this.peers.delete(nodeId);
        return false;
      }
    }
    return true;
  }

  /**
   * Get best peers for connection
   */
  getBestPeers(count = 10) {
    return [...this.peers.values()]
      .filter(p => p.score >= SHERPA_CONFIG.minPeerScore)
      .sort((a, b) => b.score - a.score)
      .slice(0, count);
  }

  /**
   * Get peers for beacon advertisement
   */
  getForBeacon() {
    return [...this.peers.values()]
      .filter(p => p.score >= SHERPA_CONFIG.minPeerScore && p.endpoint)
      .sort((a, b) => b.score - a.score)
      .slice(0, SHERPA_CONFIG.maxPeersPerBeacon);
  }

  /**
   * Apply score decay to all peers
   */
  decayScores() {
    for (const peer of this.peers.values()) {
      peer.score *= SHERPA_CONFIG.scoreDecay;
      
      if (peer.score < SHERPA_CONFIG.minPeerScore) {
        this.peers.delete(peer.nodeId);
      }
    }
  }

  /**
   * Evict lowest-scored peer
   */
  _evictLowest() {
    let lowest = null;
    let lowestScore = Infinity;
    
    for (const [nodeId, peer] of this.peers) {
      if (peer.score < lowestScore) {
        lowestScore = peer.score;
        lowest = nodeId;
      }
    }
    
    if (lowest) {
      this.peers.delete(lowest);
    }
  }

  size() {
    return this.peers.size;
  }

  has(nodeId) {
    return this.peers.has(nodeId);
  }

  get(nodeId) {
    return this.peers.get(nodeId);
  }
}

// ============================================================
// SHERPA DISCOVERY ENGINE
// ============================================================

/**
 * Main SHERPA discovery engine
 * Crawls beacon endpoints to discover peers in a decentralized manner
 */
class SherpaDiscovery extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.nodeId = options.nodeId;
    this.networkName = options.networkName;
    this.publicKey = options.publicKey;
    this.signFn = options.signFn;  // Function to sign beacon data
    this.verifyFn = options.verifyFn;  // Function to verify signatures
    
    // Our own endpoint info
    this.selfEndpoint = options.selfEndpoint || null;  // e.g., "https://mynode.com"
    this.wsEndpoint = options.wsEndpoint || null;
    this.capabilities = options.capabilities || {};
    
    // Peer registry
    this.registry = new PeerRegistry({
      networkFilter: options.networkFilter || this.networkName,
      maxPeers: options.maxPeers || 1000,
    });
    
    // Seed endpoints (initial known beacons to crawl)
    this.seedEndpoints = new Set(options.seedEndpoints || []);
    
    // Crawl state
    this.crawlInProgress = false;
    this.lastCrawl = 0;
    this.crawlTimer = null;
    
    // Stats
    this.stats = {
      crawlsCompleted: 0,
      beaconsFetched: 0,
      beaconsFailed: 0,
      peersDiscovered: 0,
      peersEvicted: 0,
    };
  }

  /**
   * Start periodic discovery
   */
  start() {
    if (this.crawlTimer) return;
    
    // Initial crawl
    this.crawl();
    
    // Periodic crawl
    this.crawlTimer = setInterval(() => {
      this.crawl();
      this.registry.decayScores();
    }, SHERPA_CONFIG.crawlInterval);
    
    this.emit('started');
  }

  /**
   * Stop discovery
   */
  stop() {
    if (this.crawlTimer) {
      clearInterval(this.crawlTimer);
      this.crawlTimer = null;
    }
    this.emit('stopped');
  }

  /**
   * Add a seed endpoint for initial discovery
   */
  addSeed(endpoint) {
    this.seedEndpoints.add(endpoint);
  }

  /**
   * Generate our beacon response
   */
  generateBeacon() {
    const beacon = new BeaconMessage({
      nodeId: this.nodeId,
      networkName: this.networkName,
      wsPort: this.capabilities.wsPort,
      httpPort: this.capabilities.httpPort,
      supportsAnnex: this.capabilities.supportsAnnex ?? true,
      supportsNakpak: this.capabilities.supportsNakpak ?? true,
      supportsGossip: this.capabilities.supportsGossip ?? true,
      publicKey: this.publicKey,
    });
    
    // Add known peers
    for (const peer of this.registry.getForBeacon()) {
      beacon.addPeer(peer);
    }
    
    // Sign beacon
    if (this.signFn && this.publicKey) {
      beacon.signature = this.signFn(beacon.getSignableData());
    }
    
    return beacon.serialize();
  }

  /**
   * Crawl known endpoints to discover peers
   */
  async crawl() {
    if (this.crawlInProgress) return;
    this.crawlInProgress = true;
    
    try {
      const visited = new Set();
      const toVisit = new Set([
        ...this.seedEndpoints,
        ...this.registry.getForBeacon().map(p => p.endpoint).filter(Boolean),
      ]);
      
      let depth = 0;
      
      while (toVisit.size > 0 && depth < SHERPA_CONFIG.maxCrawlDepth) {
        const batch = [...toVisit].slice(0, SHERPA_CONFIG.maxCrawlsPerMinute);
        toVisit.clear();
        
        const results = await Promise.allSettled(
          batch
            .filter(endpoint => endpoint && !visited.has(endpoint))
            .map(endpoint => this._fetchBeacon(endpoint))
        );
        
        for (let i = 0; i < results.length; i++) {
          const endpoint = batch[i];
          visited.add(endpoint);
          
          if (results[i].status === 'fulfilled') {
            const beacon = results[i].value;
            
            // Add the beacon source as a peer
            if (beacon.nodeId && beacon.nodeId !== this.nodeId) {
              this.registry.upsert({
                nodeId: beacon.nodeId,
                endpoint: endpoint,
                wsEndpoint: beacon.capabilities?.wsPort 
                  ? `wss://${new URL(endpoint).hostname}:${beacon.capabilities.wsPort}`
                  : null,
                networkName: beacon.networkName,
                capabilities: beacon.capabilities,
              });
              this.stats.peersDiscovered++;
            }
            
            // Queue peers for next depth
            for (const peer of beacon.peers || []) {
              if (peer.endpoint && !visited.has(peer.endpoint)) {
                toVisit.add(peer.endpoint);
              }
              
              // Also add these peers to our registry
              if (peer.nodeId && peer.nodeId !== this.nodeId) {
                this.registry.upsert({
                  nodeId: peer.nodeId,
                  endpoint: peer.endpoint,
                  wsEndpoint: peer.wsEndpoint,
                  networkName: peer.networkName,
                  lastSeen: peer.lastSeen,
                });
              }
            }
            
            this.stats.beaconsFetched++;
          } else {
            this.stats.beaconsFailed++;
            // Mark the peer as failed if we have them
            const peer = [...this.registry.peers.values()]
              .find(p => p.endpoint === endpoint);
            if (peer) {
              this.registry.markFailed(peer.nodeId);
            }
          }
        }
        
        depth++;
      }
      
      this.stats.crawlsCompleted++;
      this.lastCrawl = Date.now();
      this.emit('crawl-complete', { 
        peersFound: this.registry.size(),
        depth,
      });
      
    } finally {
      this.crawlInProgress = false;
    }
  }

  /**
   * Fetch a beacon from an endpoint
   */
  async _fetchBeacon(endpoint) {
    const url = new URL(SHERPA_CONFIG.beaconPath, endpoint).toString();
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SHERPA_CONFIG.crawlTimeout);
    
    try {
      const response = await fetch(url, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': `SHERPA/${SHERPA_CONFIG.protocolVersion}`,
        },
        signal: controller.signal,
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const text = await response.text();
      if (text.length > SHERPA_CONFIG.maxBeaconSize) {
        throw new Error('Beacon too large');
      }
      
      const data = JSON.parse(text);
      const beacon = BeaconMessage.deserialize(data);
      
      // Verify signature if required
      if (SHERPA_CONFIG.signatureRequired && this.verifyFn) {
        if (!beacon.publicKey || !beacon.signature) {
          throw new Error('Missing signature');
        }
        
        const valid = this.verifyFn(
          beacon.getSignableData(),
          beacon.signature,
          beacon.publicKey
        );
        
        if (!valid) {
          throw new Error('Invalid signature');
        }
      }
      
      // Check timestamp freshness
      const age = Date.now() - beacon.timestamp;
      if (age > beacon.ttl * 1000) {
        throw new Error('Beacon expired');
      }
      
      return beacon;
      
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Get connection candidates for mesh networking
   */
  getConnectionCandidates(count = 5) {
    return this.registry.getBestPeers(count)
      .filter(p => p.wsEndpoint)
      .map(p => ({
        nodeId: p.nodeId,
        wsEndpoint: p.wsEndpoint,
        score: p.score,
      }));
  }

  /**
   * Notify that we successfully connected to a peer
   */
  markConnected(nodeId) {
    const peer = this.registry.get(nodeId);
    if (peer) {
      peer.score = Math.min(1.0, peer.score + SHERPA_CONFIG.successBonus);
      peer.lastSeen = Date.now();
      peer.failureCount = 0;
    }
  }

  /**
   * Notify that connection to a peer failed
   */
  markDisconnected(nodeId) {
    this.registry.markFailed(nodeId);
  }

  getStats() {
    return {
      ...this.stats,
      registrySize: this.registry.size(),
      seedCount: this.seedEndpoints.size,
      lastCrawl: this.lastCrawl,
      crawlInProgress: this.crawlInProgress,
    };
  }
}

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

/**
 * Express middleware to serve the beacon endpoint
 */
function createBeaconMiddleware(sherpa) {
  return (req, res) => {
    try {
      const beacon = sherpa.generateBeacon();
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=60');
      res.setHeader('X-Sherpa-Version', SHERPA_CONFIG.protocolVersion);
      res.json(beacon);
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate beacon' });
    }
  };
}

// ============================================================
// EXPORTS
// ============================================================

export {
  SHERPA_CONFIG,
  BeaconMessage,
  PeerRegistry,
  SherpaDiscovery,
  createBeaconMiddleware,
};
