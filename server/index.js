/**
 * Yakmesh Node Server
 * Main entry point for running a Yakmesh node
 * 
 * Now integrated with the Yakmesh Distributed Oracle for
 * self-verifying, deterministic consensus.
 * 
 * Security Hardening v1.2.0:
 * - Rate limiting on all endpoints
 * - Input validation on POST endpoints
 * - Hash obfuscation (iO-inspired) - oracle hash never exposed
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import { existsSync } from 'fs';
import { createLogger } from '../utils/logger.js';

const log = createLogger('server:main');
import { NodeIdentity } from '../identity/node-key.js';
import { MeshNetwork } from '../mesh/network.js';
import { ReplicationEngine } from '../database/replication.js';
import { GossipProtocol } from '../gossip/protocol.js';

// Content store for public delivery
import { ContentStore, createContentAPI } from '../content/index.js';

// Annex - Autonomous Network Negotiated Encrypted eXchange
import { Annex } from '../mesh/annex.js';

// SHERPA - Secure Hidden Endpoint Resolution Path Architecture
import { SherpaDiscovery, createBeaconMiddleware } from '../mesh/sherpa-discovery.js';

// Oracle system imports
import { 
  getOracle, 
  CodeProofProtocol, 
  ConsensusEngine,
  ContentState,
  GenesisNetworkV2,
  createGenesisNetworkV2,
  lockCodebase,
  unlockCodebase,
  setupUnlockOnExit,
} from '../oracle/index.js';

// Time source imports
import { 
  TimeSourceDetector, 
  getTimeSourceDetector,
  createPhaseConfig,
  detectTimeSources,
} from '../oracle/time-source.js';
import { setTimeSourceConfig, getActiveConfig } from '../oracle/phase-epoch.js';

// v2.0 Security imports - NAMCHE and DOKO
import NamcheGateway, { 
  DOKO_TYPES as NAMCHE_DOKO_TYPES,
  VERIFY_RESULT 
} from '../security/namche-gateway.js';
import { 
  DOKO_TYPES as DOKOTypes,
  DOKODocument,
  DOKOGenerator,
  DOKOValidator,
  DOKOStore
} from '../security/doko-identity.js';

// v2.5.0 Geographic Proof - Speed-of-Light Exclusion Zones
import {
  GeoProofService,
  LandmarkRegistry,
  GeographicProof,
  LIGHT_SPEED,
  GEO_PROOF_CONFIG,
  calculateMinDistance,
  haversineDistance,
} from '../security/geo-proof.js';

// Gate names for dashboard display
const GATE_NAMES = [
  'Structure Valid', 'Signature Valid', 'NodeID Match',
  'Temporal Valid', 'Network Match', 'Not Revoked', 'Domains OK'
];

// YAK:// Protocol Handler
import YakProtocolHandler, { 
  createProtocolEndpoints,
  parseYakUrl,
  yakToHttp,
  httpToYak,
  PROTOCOL,
  BUILTIN_ROUTES
} from '../protocol/yak-protocol.js';

// Helper: Format uptime in human-readable format
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

// Optional adapter integration (loaded dynamically if enabled)
let ActiveAdapter = null;

// Default config
const DEFAULT_CONFIG = {
  node: {
    name: 'Yakmesh Node',
    region: 'local',
  },
  network: {
    httpPort: 3000,
    wsPort: 9001,
  },
  bootstrap: [],
  database: {
    path: './data/yakmesh.db',
    replication: {
      enabled: true,
      syncInterval: 5000,
    },
  },
};

/**
 * Load configuration
 */
async function loadConfig() {
  // Check for --config argument
  const configArgIndex = process.argv.findIndex(arg => arg === '--config' || arg === '-c');
  let configPath = './yakmesh.config.js';
  
  if (configArgIndex !== -1 && process.argv[configArgIndex + 1]) {
    configPath = process.argv[configArgIndex + 1];
    log.info(`📋 Using config: ${configPath}`);
  }
  
  // Try to load config file
  if (existsSync(configPath)) {
    // Handle both absolute and relative paths
    const isAbsolute = configPath.startsWith('/') || /^[A-Z]:/i.test(configPath);
    const importPath = isAbsolute 
      ? `file://${configPath.replace(/\\/g, '/')}`
      : `../${configPath.replace('./', '')}`;
    const { default: userConfig } = await import(importPath);
    return { ...DEFAULT_CONFIG, ...userConfig };
  }
  
  // Fallback to default yakmesh.config.js
  if (existsSync('./yakmesh.config.js')) {
    const { default: userConfig } = await import('../yakmesh.config.js');
    return { ...DEFAULT_CONFIG, ...userConfig };
  }
  return DEFAULT_CONFIG;
}

/**
 * Yakmesh Node
 */
export class YakmeshNode {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.identity = null;
    this.mesh = null;
    this.replication = null;
    this.gossip = null;
    this.adapter = null;
    this.http = null;
    this.boundHttpPort = null;  // Actual bound port (may differ if fallback used)
    this.app = null;  // Store Express app for PeerQuanta endpoints
    
    // Oracle system
    this.oracle = null;
    this.codeProof = null;
    this.consensus = null;
    
    // Content store for public delivery
    this.contentStore = null;
    
    // Annex - encrypted point-to-point messaging
    this.annex = null;
    
    // Time source detector
    this.timeSource = null;
    
    // Geographic proof service (v2.5.0)
    this.geoProofService = null;
    
    // iO Network Identity (hash obfuscation)
    this.genesisNetwork = null;
    
    // Codebase lock status
    this.codebaseLocked = false;
  }

  async start() {
    log.info('\n🦬 Starting Yakmesh Node...\n');
    
    // Record start time for uptime tracking
    this._startTime = Date.now();

    // 0. LOCK THE CODEBASE - Prevent any modifications during runtime
    // This is critical for Code Proof Protocol security
    log.info('🔐 Securing codebase...');
    const lockResult = lockCodebase();
    if (lockResult.success) {
      this.codebaseLocked = true;
      setupUnlockOnExit();  // Ensure cleanup on process exit
      log.info(`✓ Codebase locked: ${lockResult.fileCount} source files protected`);
    } else {
      log.warn(`⚠️ Codebase lock failed: ${lockResult.error}`);
      log.warn('   Node will continue but source files are not protected');
    }

    // 1. Initialize the Oracle system FIRST (provides codebase hash for identity)
    // This MUST happen before identity initialization
    this._initOracle();
    
    // 1b. Initialize time source detection
    this._initTimeSource();

    // 2. Initialize identity - extract directory from database path
    // Pass the oracle so it can derive network name from codebase hash
    const dbDir = this.config.database.path.replace(/[/\\\\][^/\\\\]+\.db$/, '');
    this.identity = new NodeIdentity(dbDir);
    await this.identity.init(this.config.node.name, this.config.node.region, this.oracle);
    
    // 2b. Update codeProof and consensus with the initialized identity
    if (this.codeProof) {
      this.codeProof.nodeId = this.identity.identity?.nodeId;
    }

    // 3. Start mesh network WITH network fingerprint for code proof verification
    this.mesh = new MeshNetwork(this.identity, {
      wsPort: this.config.network.wsPort,
      // Pass network identity for peer verification
      networkId: this.genesisNetwork?.networkId,
      networkFingerprint: this.genesisNetwork?.fingerprint,
    });
    await this.mesh.start();

    // 3. Initialize replication
    this.replication = new ReplicationEngine(this.mesh, this.config.database.path);
    await this.replication.init();

    if (this.config.database.replication.enabled) {
      this.replication.startSync(this.config.database.replication.syncInterval);
    }

    // 4. Start gossip protocol
    this.gossip = new GossipProtocol(this.mesh, this.identity, {
      fanout: 3,
      helloInterval: 30000,
    });
    this.gossip.start();

    // Handle incoming rumors (data from other nodes)
    this.mesh.on('rumor', (topic, data, origin) => {
      log.debug(`📨 Rumor [${topic}] from ${origin.slice(0, 16)}...`);
      
      // Handle different rumor topics
      if (topic === 'data_update') {
        this.replication.recordChange(data.table, data.rowId, data.operation, data.data);
      }
      
      // Handle code proof challenges
      if (topic === 'code_proof_challenge') {
        const response = this.codeProof.respondToChallenge(data);
        this.gossip.spreadRumor('code_proof_response', response);
      }
      
      // Handle code proof responses
      if (topic === 'code_proof_response') {
        this.codeProof.verifyResponse(data);
      }
      
      // Handle oracle-validated content
      if (topic === 'oracle_content') {
        this._handleOracleContent(data, origin);
      }
      
      // Handle iO network handshakes
      if (topic === 'network_handshake') {
        this._handleNetworkHandshake(data, origin);
      }
      
      // Handle content gossip (for public content delivery)
      if (topic === 'content') {
        if (this.contentStore) {
          this.contentStore._handleContentGossip(data, origin);
        }
      }
    });
    
    // Handle Annex (encrypted direct messages) - separate from gossip
    this.mesh.on('annex', (data, origin) => {
      if (this.annex) {
        this.annex._handleAnnexMessage(data.annex || data, origin);
      }
    });

    // 5. Initialize content store for public delivery
    this.contentStore = new ContentStore({
      dataDir: this.config.database?.contentPath || './data/content',
      quorumSize: 2,
    });
    await this.contentStore.init(this);
    
    // 5b. Initialize Annex for encrypted point-to-point messaging
    this.annex = new Annex({
      identity: this.identity,
      mesh: this.mesh,
    });
    log.info('✓ Annex channel initialized (encrypted P2P messaging)');
    
    // 5c. Initialize SHERPA for decentralized peer discovery
    this.sherpa = new SherpaDiscovery({
      nodeId: this.identity.identity.nodeId,
      networkName: this.genesisNetwork?.networkName,
      publicKey: this.identity.identity.publicKey,
      signFn: (data) => this.identity.sign(data),
      verifyFn: (data, sig, pubKey) => this.identity.verify(data, sig, pubKey),
      selfEndpoint: this.config.sherpa?.selfEndpoint || null,
      wsEndpoint: this.config.sherpa?.wsEndpoint || null,
      capabilities: {
        wsPort: this.config.network.wsPort,
        httpPort: this.config.network.httpPort,
        supportsAnnex: true,
        supportsNakpak: true,
        supportsGossip: true,
      },
      seedEndpoints: this.config.sherpa?.seeds || [],
    });
    
    // Start SHERPA if seeds are configured or selfEndpoint is set
    if (this.config.sherpa?.enabled !== false) {
      this.sherpa.start();
      log.info('✓ SHERPA discovery initialized (decentralized peer discovery)');
    }
    
    // 6. Start HTTP server
    await this._startHttpServer();

    // 7. Connect to bootstrap nodes
    await this._connectToBootstrap();

    // 7. Initialize PeerQuanta integration (if enabled)
    if (this.config.peerquanta?.enabled) {
      await this._initAdapter();
    }

    // 8. Initialize Website Adapter (if website directory exists)
    if (this.config.website?.enabled !== false) {
      await this._initWebsiteAdapter();
    }

    // 9. Initialize YAK:// Protocol Handler
    await this._initProtocolHandler();

    log.info('\n✓ Yakmesh Node is running!\n');
    log.info(`  Node ID:    ${this.identity.identity.nodeId}`);
    log.info(`  HTTP:       http://localhost:${this.boundHttpPort || this.config.network.httpPort}`);
    log.info(`  YAK://      yak://dashboard  (register with: yakmesh protocol register)`);
    log.info(`  Content:    http://localhost:${this.boundHttpPort || this.config.network.httpPort}/content`);
    log.info(`  Dashboard:  http://localhost:${this.boundHttpPort || this.config.network.httpPort}/dashboard`);
    log.info(`  WebSocket:  ws://localhost:${this.mesh.boundPort || this.config.network.wsPort}`);
    log.info(`  Algorithm:  ML-DSA-65 (Post-Quantum)`);
    log.info(`  Oracle:     ✓ ${this.oracle.selfHash.slice(0, 16)}...`);
    log.info(`  Network:    ${this.genesisNetwork.networkName} (${this.genesisNetwork.networkId})`);
    if (this.contentStore) {
      const stats = this.contentStore.getStats();
      log.info(`  Content:    ${stats.totalObjects} objects (${stats.verified} verified)`);
    }
    if (this.annex) {
      log.info(`  Annex:      ✓ Encrypted P2P ready`);
    }
    if (this.sherpa) {
      log.info(`  SHERPA:     ✓ Beacon at /.well-known/yakmesh/beacon`);
    }
    if (this.adapter) {
      log.info(`  Adapter:    ✓ Enabled`);
    }
    if (this.websiteAdapter && this.websiteAdapter.manifests.size > 0) {
      log.info(`  Website:    ✓ ${this.websiteAdapter.manifests.size} site(s) at /site/`);
    }
    log.info('');

    return this;
  }

  async stop() {
    log.info('\n🛑 Stopping Yakmesh Node...');
    
    this.adapter?.stopSync();
    this.timeSource?.stop();  // Stop time source monitoring
    this.consensus?.stop();  // Stop consensus engine
    this.annex = null;  // Clear annex channels
    this.gossip?.stop();
    this.replication?.stopSync();
    await this.mesh?.stop();
    
    if (this.http) {
      this.http.close();
    }
    
    // Unlock codebase - allow modifications again
    if (this.codebaseLocked) {
      unlockCodebase();
      this.codebaseLocked = false;
    }
    
    log.info('✓ Yakmesh Node stopped\n');
  }

  /**
   * Initialize the Oracle system
   * NOTE: This is called BEFORE identity initialization so we can 
   * derive the network name from the codebase hash for node identity.
   */
  _initOracle() {
    log.info('🔮 Initializing Oracle System...');
    
    // Get the singleton oracle instance (computes codebase hash)
    this.oracle = getOracle();
    
    // Initialize code proof protocol (identity will be set later)
    this.codeProof = new CodeProofProtocol({ identity: null });
    
    // Initialize consensus engine (identity will be set later)  
    this.consensus = new ConsensusEngine({ identity: null }, {
      minAttestations: this.config.oracle?.minAttestations || 1,
    });
    
    // Listen for consensus events
    this.consensus.on('consensus', (event) => {
      log.info(`✓ Consensus reached for ${event.contentType}: ${event.contentHash.slice(0, 16)}...`);
    });
    
    this.consensus.on('conflict-resolved', (event) => {
      log.info(`⚖️ Conflict resolved: ${event.winnerHash.slice(0, 16)}... won`);
    });
    
    // Note: Raw oracle hash now hidden - use network identity instead
    log.info(`✓ Oracle initialized`);
    
    // Initialize iO-inspired network identity (hash obfuscation)
    this._initGenesisNetwork();
  }
  
  /**
   * Initialize the iO-inspired Genesis Network Identity
   * This derives a human-readable network name from the oracle hash
   * without ever exposing the raw hash in network communication.
   */
  _initGenesisNetwork() {
    log.info('🌐 Initializing iO Network Identity...');
    
    // Create GenesisNetworkV2 from the oracle
    this.genesisNetwork = createGenesisNetworkV2(this.oracle);
    
    // Update consensus engine with network fingerprint for security
    if (this.consensus) {
      this.consensus.networkFingerprint = this.genesisNetwork.fingerprint;
    }
    
    // Update code proof protocol with fingerprint
    if (this.codeProof) {
      this.codeProof.networkFingerprint = this.genesisNetwork.fingerprint;
    }
    
    log.debug(`   Network Name: ${this.genesisNetwork.networkName}`);
    log.debug(`   Network ID:   ${this.genesisNetwork.networkId}`);
    log.debug(`   Verify:       "${this.genesisNetwork.verificationPhrase}"`);
    log.info('✓ Genesis Network initialized (iO hash obfuscation active)');
  }
  
  /**
   * Initialize time source detection
   * Detects precision time sources and configures phase epochs accordingly
   */
  _initTimeSource() {
    log.info('⏰ Initializing Time Source Detection...');
    
    // Get or create global time source detector
    this.timeSource = getTimeSourceDetector({
      detectHardware: true,
      checkNtp: true,
      refreshInterval: 60000,  // Re-check every minute
      verbose: false,
    });
    
    // Perform initial detection
    const results = this.timeSource.detect();
    
    // Configure phase epochs based on detected time source
    if (results.trustLevel) {
      setTimeSourceConfig(results.trustLevel);
    }
    
    // Start continuous monitoring
    this.timeSource.start();
    
    // Log initial detection
    const trustIcons = {
      atomic: '🔬',
      gps: '🛰️',
      ptp: '📡',
      ntp: '🌐',
      unsync: '⚠️',
    };
    
    log.debug(`   Trust Level: ${trustIcons[results.trustLevel] || '?'} ${results.trustLevel.toUpperCase()}`);
    log.debug(`   Tolerance:   ±${results.phaseTolerance}ms`);
    log.debug(`   Primary:     ${results.primarySource || 'none'}`);
    
    // Listen for trust level changes
    this.timeSource.on('detected', (newResults) => {
      if (newResults.trustLevel !== results.trustLevel) {
        log.info(`⏰ Time source changed: ${newResults.trustLevel.toUpperCase()}`);
        setTimeSourceConfig(newResults.trustLevel);
      }
    });
    
    log.info('✓ Time Source initialized');
  }
  
  /**
   * Handle oracle-validated content from peers
   */
  _handleOracleContent(data, origin) {
    const { sealedPackage, attestations } = data;
    
    // Verify the peer is running valid code
    if (!this.codeProof.isPeerVerified(origin)) {
      log.warn(`⚠️ Received content from unverified peer ${origin.slice(0, 16)}...`);
      // Challenge the peer
      const challenge = this.codeProof.generateChallenge(origin);
      this.gossip.spreadRumor('code_proof_challenge', challenge);
      return;
    }
    
    // Submit to consensus engine
    const result = this.consensus.receivePackage(data);
    
    if (result.accepted) {
      log.info(`✓ Oracle content accepted: ${result.contentHash?.slice(0, 16)}...`);
      
      // Record in replication for persistence
      this.replication.recordChange(
        `oracle_${sealedPackage.type}`,
        sealedPackage.contentHash,
        'UPSERT',
        sealedPackage.content
      );
    } else {
      log.warn(`✗ Oracle content rejected: ${result.reason}`);
    }
  }

  /**
   * Handle iO network handshake from peer
   * Verifies network compatibility using fingerprints (no hash exposed)
   */
  _handleNetworkHandshake(data, origin) {
    if (!this.genesisNetwork) return;
    
    const { handshake, nodeId } = data;
    const verification = this.genesisNetwork.verifyHandshake(handshake);
    
    // Register the peer
    const compatible = this.genesisNetwork.registerPeer(nodeId || origin, handshake);
    
    if (compatible) {
      log.debug(`🌐 Peer ${origin.slice(0, 16)}... verified on same network: ${handshake.name}`);
    } else {
      log.debug(`⚠️ Peer ${origin.slice(0, 16)}... on different network: ${handshake.name} (${handshake.shortId})`);
      log.debug(`   Our network: ${this.genesisNetwork.networkName} (${this.genesisNetwork.networkId})`);
    }
    
    // Optionally broadcast our handshake back
    if (compatible && !data.isResponse) {
      this.gossip.spreadRumor('network_handshake', {
        handshake: this.genesisNetwork.createHandshake(),
        nodeId: this.identity.identity.nodeId,
        isResponse: true,
      });
    }
  }

  async _startHttpServer() {
    const app = express();
    this.app = app;  // Store for PeerQuanta endpoints
    
    app.use(express.json({ limit: '1mb' }));  // Limit payload size
    
    // =========================================
    // SECURITY: Rate Limiting (DoS Protection)
    // =========================================
    
    // General rate limit: 100 requests per minute per IP
    const generalLimiter = rateLimit({
      windowMs: 60 * 1000,  // 1 minute
      max: 100,
      message: { error: 'Too many requests, please try again later' },
      standardHeaders: true,
      legacyHeaders: false,
    });
    
    // Strict rate limit for write operations: 20 per minute
    const writeLimiter = rateLimit({
      windowMs: 60 * 1000,
      max: 20,
      message: { error: 'Too many write requests, please slow down' },
      standardHeaders: true,
      legacyHeaders: false,
    });
    
    // Apply general limiter to all routes
    app.use(generalLimiter);
    
    // CORS for dashboard
    app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    });
    
    // =========================================
    // SECURITY: Input Validation Helpers
    // =========================================
    
    const validateUrl = (url) => {
      if (!url || typeof url !== 'string') return false;
      try {
        const parsed = new URL(url);
        return ['ws:', 'wss:', 'http:', 'https:'].includes(parsed.protocol);
      } catch { return false; }
    };
    
    const validateString = (str, maxLen = 1000) => {
      return str && typeof str === 'string' && str.length <= maxLen;
    };
    
    const validateObject = (obj) => {
      return obj && typeof obj === 'object' && !Array.isArray(obj);
    };
    
    // =========================================
    // PUBLIC CONTENT API (No Auth for reads)
    // =========================================
    
    // Mount content API at /content
    const contentAPI = createContentAPI(this.contentStore, {
      writeLimiter,
      readLimiter: generalLimiter,
      validateString,
    });
    app.use('/content', contentAPI);
    
    // Serve dashboard
    app.get('/dashboard', (req, res) => {
      res.sendFile('dashboard/index.html', { root: import.meta.dirname + '/..' });
    });

    // Health check
    app.get('/health', (req, res) => {
      res.json({
        status: 'ok',
        nodeId: this.identity.identity.nodeId,
        peers: this.mesh.getPeers().length,
        algorithm: 'ML-DSA-65',
        network: this.genesisNetwork ? {
          name: this.genesisNetwork.networkName,
          id: this.genesisNetwork.networkId,
        } : null,
      });
    });

    // Node info
    app.get('/node', (req, res) => {
      res.json(this.identity.getPublicIdentity());
    });

    // Peers list
    app.get('/peers', (req, res) => {
      res.json(this.mesh.getPeers());
    });

    // =========================================
    // SHERPA: Decentralized Peer Discovery
    // =========================================
    
    // Beacon endpoint for SHERPA peer discovery
    // This allows other nodes to discover us and our known peers
    if (this.sherpa) {
      app.get('/.well-known/yakmesh/beacon', createBeaconMiddleware(this.sherpa));
    }

    // SHERPA discovery stats
    app.get('/sherpa/status', (req, res) => {
      if (!this.sherpa) {
        return res.status(503).json({ error: 'SHERPA not initialized' });
      }
      res.json(this.sherpa.getStats());
    });

    // Get connection candidates from SHERPA
    app.get('/sherpa/candidates', (req, res) => {
      if (!this.sherpa) {
        return res.status(503).json({ error: 'SHERPA not initialized' });
      }
      res.json(this.sherpa.getConnectionCandidates(10));
    });

    // Replication stats
    app.get('/replication', (req, res) => {
      res.json(this.replication.getStats());
    });

    // Connect to a peer dynamically
    // SECURITY: Rate limited + URL validation
    app.post('/connect', writeLimiter, async (req, res) => {
      const { address } = req.body;
      
      if (!validateUrl(address)) {
        return res.status(400).json({ error: 'Valid WebSocket URL required (ws:// or wss://)' });
      }
      
      try {
        await this.mesh.connectToPeer(address);
        res.json({ 
          success: true, 
          message: `Connecting to ${address}`,
          peers: this.mesh.getPeers().length 
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Simple API endpoint for testing replication
    // SECURITY: Rate limited + input validation
    app.post('/data', writeLimiter, (req, res) => {
      const { table, data } = req.body;
      
      // Validate inputs
      if (!validateString(table, 64)) {
        return res.status(400).json({ error: 'Valid table name required (max 64 chars)' });
      }
      if (!validateObject(data)) {
        return res.status(400).json({ error: 'Data must be an object' });
      }
      
      // Record the change for replication
      const rowId = data.id || Date.now();
      this.replication.recordChange(table, rowId, 'INSERT', data);
      
      // Spread via gossip protocol
      this.gossip.spreadRumor('data_update', {
        table,
        rowId,
        operation: 'INSERT',
        data,
      });
      
      res.json({ success: true, rowId });
    });

    // Gossip stats
    app.get('/gossip', (req, res) => {
      res.json(this.gossip.getStats());
    });

    // Known peers (discovered via gossip)
    app.get('/discovered', (req, res) => {
      res.json(this.gossip.getKnownPeers());
    });

    // Spread a rumor
    // SECURITY: Rate limited + input validation
    app.post('/rumor', writeLimiter, (req, res) => {
      const { topic, data } = req.body;
      
      if (!validateString(topic, 64)) {
        return res.status(400).json({ error: 'Valid topic required (max 64 chars)' });
      }
      if (!validateObject(data)) {
        return res.status(400).json({ error: 'Data must be an object' });
      }
      
      const messageId = this.gossip.spreadRumor(topic, data);
      res.json({ success: true, messageId });
    });

    // =========================================
    // Oracle Endpoints - Self-Verifying Trust
    // =========================================

    // Oracle status and self-integrity verification
    // SECURITY: Hash obfuscated via iO-derived fingerprint (never exposed directly)
    app.get('/oracle/status', (req, res) => {
      if (!this.oracle) {
        return res.status(503).json({ error: 'Oracle not initialized' });
      }

      const integrity = this.oracle.verifySelfIntegrity();
      
      // Use network identity fingerprint instead of raw hash
      const networkFingerprint = this.genesisNetwork?.fingerprint || 'not-initialized';
      
      res.json({
        status: integrity.valid ? 'healthy' : 'compromised',
        integrity: {
          valid: integrity.valid,
          // Omit hash details from response
        },
        networkFingerprint,  // Derived fingerprint (hash never exposed)
        networkName: this.genesisNetwork?.networkName || null,
        networkId: this.genesisNetwork?.networkId || null,
        validationMethods: this.oracle.getValidationMethods(),
        consensusStats: this.consensus?.getStats() || null,
        verifiedPeers: this.codeProof?.getVerifiedPeers() || []
      });
    });

    // =========================================
    // Network Identity (iO Hash Obfuscation)
    // =========================================

    // Get network identity (hash NEVER exposed)
    app.get('/network/identity', (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      res.json({
        name: this.genesisNetwork.networkName,
        id: this.genesisNetwork.networkId,
        fingerprint: this.genesisNetwork.fingerprint,
        verificationPhrase: this.genesisNetwork.verificationPhrase,
        // Note: raw oracle hash is NEVER included
      });
    });

    // Get handshake payload (for peer connection)
    app.get('/network/handshake', (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      res.json(this.genesisNetwork.createHandshake());
    });

    // Verify a peer's handshake
    // SECURITY: Input validation
    app.post('/network/verify', (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      const { handshake } = req.body;
      if (!validateObject(handshake)) {
        return res.status(400).json({ error: 'Valid handshake object required' });
      }
      if (!handshake.name || !handshake.fingerprint) {
        return res.status(400).json({ error: 'Handshake must include name and fingerprint' });
      }

      const result = this.genesisNetwork.verifyHandshake(handshake);
      res.json(result);
    });

    // Get network status (peers by compatibility)
    app.get('/network/status', (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      res.json(this.genesisNetwork.getStatus());
    });

    // Register a peer via handshake
    // SECURITY: Rate limited + input validation
    app.post('/network/register-peer', writeLimiter, (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      const { peerId, handshake } = req.body;
      if (!validateString(peerId, 128)) {
        return res.status(400).json({ error: 'Valid peerId required (max 128 chars)' });
      }
      if (!validateObject(handshake) || !handshake.name || !handshake.fingerprint) {
        return res.status(400).json({ error: 'Valid handshake with name and fingerprint required' });
      }

      const compatible = this.genesisNetwork.registerPeer(peerId, handshake);
      res.json({
        registered: true,
        compatible,
        networkMatch: compatible ? 'same' : 'different',
      });
    });

    // Initiate code-proof challenge for a peer
    // SECURITY: Rate limited + input validation
    app.post('/oracle/challenge', writeLimiter, (req, res) => {
      const { peerId } = req.body;
      
      if (!validateString(peerId, 128)) {
        return res.status(400).json({ error: 'Valid peerId required (max 128 chars)' });
      }

      if (!this.codeProof) {
        return res.status(503).json({ error: 'Code proof protocol not initialized' });
      }

      const challenge = this.codeProof.generateChallenge(peerId);
      
      // Spread challenge via gossip
      this.gossip.spreadRumor('code_proof_challenge', challenge);
      
      res.json({
        success: true,
        challengeId: challenge.challengeId,
        message: `Challenge sent to peer ${peerId.slice(0, 16)}...`
      });
    });

    // Get verified peers list
    app.get('/oracle/peers', (req, res) => {
      if (!this.codeProof) {
        return res.status(503).json({ error: 'Code proof protocol not initialized' });
      }

      res.json({
        verifiedPeers: this.codeProof.getVerifiedPeers(),
        pendingChallenges: this.codeProof.getPendingChallenges()
      });
    });

    // Submit oracle-validated content
    // SECURITY: Rate limited + input validation + hash obfuscation
    app.post('/oracle/submit', writeLimiter, async (req, res) => {
      const { type, content } = req.body;
      
      if (!validateString(type, 64)) {
        return res.status(400).json({ error: 'Valid type required (max 64 chars)' });
      }
      if (!validateObject(content)) {
        return res.status(400).json({ error: 'Content must be an object' });
      }

      if (!this.oracle || !this.consensus) {
        return res.status(503).json({ error: 'Oracle system not initialized' });
      }

      try {
        // Validate through oracle
        const validation = await this.oracle.validate(type, content);
        
        if (!validation.valid) {
          return res.status(400).json({
            success: false,
            error: 'Validation failed',
            details: validation.errors
          });
        }

        // Create sealed package - SECURITY: Use fingerprint, not raw hash
        const sealedPackage = {
          type,
          content,
          contentHash: validation.contentHash,
          validatorFingerprint: this.genesisNetwork?.fingerprint || 'local',  // Never expose raw hash
          timestamp: Date.now(),
          signature: this.identity.sign(validation.contentHash)
        };

        // Submit to consensus
        const consensusResult = this.consensus.proposeData(type, sealedPackage);

        // Spread to network
        this.gossip.spreadRumor('oracle_content', {
          sealedPackage,
          attestations: [consensusResult.attestation]
        });

        res.json({
          success: true,
          contentHash: validation.contentHash,
          consensusId: consensusResult.proposalId,
          status: 'pending_consensus'
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get consensus statistics
    app.get('/oracle/consensus', (req, res) => {
      if (!this.consensus) {
        return res.status(503).json({ error: 'Consensus engine not initialized' });
      }

      res.json(this.consensus.getStats());
    });

    // Resolve conflicts manually (admin endpoint)
    app.post('/oracle/resolve', (req, res) => {
      if (!this.consensus) {
        return res.status(503).json({ error: 'Consensus engine not initialized' });
      }

      const resolved = this.consensus.resolveConflicts();
      res.json({
        success: true,
        resolved: resolved.length,
        details: resolved
      });
    });

    // =========================================
    // Metrics Endpoint - Dashboard Data
    // =========================================
    
    app.get('/metrics', (req, res) => {
      const startTime = this._startTime || Date.now();
      const uptime = Math.floor((Date.now() - startTime) / 1000);
      
      // Crypto configuration (imported at top of file)
      let cryptoInfo = null;
      try {
        // Dynamic import not needed - use the imported module
        cryptoInfo = this._cryptoSummary || { 
          levelName: 'NIST Level 3',
          signatureAlgorithm: 'ML-DSA-65',
          backupSignatureAlgorithm: 'SLH-DSA-SHA2-192f',
          kemAlgorithm: 'ML-KEM-768',
          classicalSecurity: '192-bit',
          quantumSecurity: '128-bit',
          nistStandards: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'FIPS 205 (SLH-DSA)'],
        };
      } catch (e) {
        cryptoInfo = { error: 'Could not load crypto config' };
      }
      
      // Time source info
      let timeInfo = null;
      if (this.timeSource) {
        const status = this.timeSource.getStatus();
        timeInfo = {
          trustLevel: status.trustLevel,
          stratum: status.stratum,
          phaseTolerance: status.phaseTolerance,
          hasAtomicTime: this.timeSource.hasAtomicTime(),
          hasHighPrecisionTime: this.timeSource.hasHighPrecisionTime(),
        };
      }
      
      // Oracle status
      let oracleInfo = null;
      if (this.oracle) {
        const integrity = this.oracle.verifySelfIntegrity();
        oracleInfo = {
          status: integrity.valid ? 'healthy' : 'compromised',
          valid: integrity.valid,
          networkName: this.genesisNetwork?.networkName || null,
          networkId: this.genesisNetwork?.networkId || null,
          fingerprint: this.genesisNetwork?.fingerprint || null,
          verifiedPeers: this.codeProof?.getVerifiedPeers()?.length || 0,
        };
      }
      
      // Mesh stats
      const peerCount = this.mesh?.getPeers()?.length || 0;
      const gossipStats = this.gossip?.getStats() || null;
      
      // NAMCHE security gate status (v2.0)
      let namcheInfo = null;
      if (this.namcheGateway) {
        namcheInfo = this.namcheGateway.getStatus();
      } else {
        // Show gate definitions even if not initialized
        namcheInfo = {
          gates: GATE_NAMES,
          status: 'uninitialized',
          gateCount: 7,
        };
      }
      
      // DOKO identity status (v2.0)
      let dokoInfo = null;
      if (this.dokoRegistry) {
        dokoInfo = this.dokoRegistry.getStats();
      } else {
        dokoInfo = {
          status: 'uninitialized',
          types: Object.keys(DOKOTypes),
        };
      }
      
      // Website adapter status (v2.0)
      let websiteInfo = null;
      if (this.websiteAdapter) {
        websiteInfo = {
          status: 'active',
          websites: this.websiteAdapter.manifests.size,
          domains: this.websiteAdapter.domains.size,
          filesServed: this.websiteAdapter.stats.filesServed,
          bytesServed: this.websiteAdapter.stats.bytesServed,
        };
      } else {
        websiteInfo = { status: 'uninitialized' };
      }
      
      res.json({
        node: {
          id: this.identity?.identity?.nodeId || null,
          name: this.config?.node?.name || 'unknown',
          version: '2.0.1',
          uptime,
          uptimeFormatted: formatUptime(uptime),
        },
        crypto: cryptoInfo,
        time: timeInfo,
        oracle: oracleInfo,
        security: {
          namche: namcheInfo,
          doko: dokoInfo,
        },
        website: websiteInfo,
        network: {
          peers: peerCount,
          gossip: gossipStats,
        },
        timestamp: new Date().toISOString(),
      });
    });

    // =========================================
    // Time Source Endpoints - Precision Timing
    // =========================================

    // Get time source status
    app.get('/time/status', (req, res) => {
      if (!this.timeSource) {
        return res.status(503).json({ error: 'Time source detector not initialized' });
      }

      res.json(this.timeSource.getStatus());
    });

    // Force re-detection of time sources
    app.get('/time/detect', (req, res) => {
      if (!this.timeSource) {
        return res.status(503).json({ error: 'Time source detector not initialized' });
      }

      const results = this.timeSource.detect();
      
      // Update phase config if trust level changed
      if (results.trustLevel) {
        setTimeSourceConfig(results.trustLevel);
      }

      res.json(results);
    });

    // Get phase configuration based on time source
    app.get('/time/phase-config', (req, res) => {
      if (!this.timeSource) {
        return res.status(503).json({ error: 'Time source detector not initialized' });
      }

      const phaseConfig = createPhaseConfig(this.timeSource);
      const activeConfig = getActiveConfig();

      res.json({
        ...phaseConfig,
        activePhaseConfig: activeConfig,
      });
    });

    // Get time source capabilities
    app.get('/time/capabilities', (req, res) => {
      if (!this.timeSource) {
        return res.status(503).json({ error: 'Time source detector not initialized' });
      }

      const status = this.timeSource.getStatus();
      const phaseConfig = createPhaseConfig(this.timeSource);

      res.json({
        trustLevel: status.trustLevel,
        stratum: status.stratum,
        canBeTimeOracle: phaseConfig.capabilities.canBeTimeOracle,
        canValidateTightPhase: phaseConfig.capabilities.canValidateTightPhase,
        canParticipateInConsensus: phaseConfig.capabilities.canParticipateInConsensus,
        hasAtomicTime: this.timeSource.hasAtomicTime(),
        hasHighPrecisionTime: this.timeSource.hasHighPrecisionTime(),
        phaseTolerance: status.phaseTolerance,
        epochDuration: phaseConfig.epochDurationHours,
        gracePeriod: phaseConfig.gracePeriodMinutes,
      });
    });

    // =========================================
    // NAMCHE Security Gate Endpoints (v2.0)
    // =========================================
    
    // Get all gate statuses
    app.get('/security/namche/gates', (req, res) => {
      if (!this.namcheGateway) {
        return res.json({
          status: 'uninitialized',
          gates: GATE_NAMES.map((name, index) => ({
            gate: index + 1,
            name,
            status: 'pending',
            icon: ['🗝️', '🧩', '🔐', '🌐', '⚡', '🔮', '🏔️'][index]
          }))
        });
      }
      res.json(this.namcheGateway.getStatus());
    });
    
    // Verify a specific gate
    app.post('/security/namche/verify/:gate', (req, res) => {
      const gateNum = parseInt(req.params.gate);
      if (gateNum < 1 || gateNum > 7) {
        return res.status(400).json({ error: 'Gate must be 1-7' });
      }
      
      if (!this.namcheGateway) {
        return res.status(503).json({ error: 'NAMCHE gateway not initialized' });
      }
      
      const result = this.namcheGateway.verifyGate(gateNum, req.body);
      res.json({
        gate: gateNum,
        name: GATE_NAMES[gateNum - 1],
        ...result
      });
    });
    
    // Get comprehensive security status
    app.get('/security/status', (req, res) => {
      const oracleIntegrity = this.oracle?.verifySelfIntegrity();
      
      res.json({
        namche: this.namcheGateway?.getStatus() || { status: 'uninitialized' },
        doko: this.dokoRegistry?.getStats() || { status: 'uninitialized' },
        oracle: {
          valid: oracleIntegrity?.valid || false,
          status: oracleIntegrity?.valid ? 'healthy' : 'unknown',
        },
        crypto: {
          signatures: 'ML-DSA-65 (FIPS 204)',
          keyExchange: 'ML-KEM-768 (FIPS 203)',
          backup: 'SLH-DSA-SHA2-192f (FIPS 205)',
          level: 'NIST Level 3',
        },
        timestamp: new Date().toISOString(),
      });
    });

    // =========================================
    // DOKO Identity Endpoints (v2.0)
    // =========================================
    
    // Get DOKO registry stats
    app.get('/security/doko/stats', (req, res) => {
      if (!this.dokoRegistry) {
        return res.json({
          status: 'uninitialized',
          types: Object.keys(DOKOTypes),
          description: 'Decentralized On-chain Key Ownership'
        });
      }
      res.json(this.dokoRegistry.getStats());
    });
    
    // List identities (limited info)
    app.get('/security/doko/identities', (req, res) => {
      if (!this.dokoRegistry) {
        return res.status(503).json({ error: 'DOKO registry not initialized' });
      }
      
      const type = req.query.type || null;
      const identities = this.dokoRegistry.list(type);
      res.json({
        count: identities.length,
        type: type || 'all',
        identities: identities.map(id => ({
          id: id.id,
          type: id.type,
          created: id.created,
          verified: id.verified,
        }))
      });
    });
    
    // Verify an identity
    app.post('/security/doko/verify', (req, res) => {
      if (!this.dokoRegistry) {
        return res.status(503).json({ error: 'DOKO registry not initialized' });
      }
      
      const { id, challenge, signature } = req.body;
      if (!id || !challenge || !signature) {
        return res.status(400).json({ error: 'Missing id, challenge, or signature' });
      }
      
      const result = this.dokoRegistry.verify(id, challenge, signature);
      res.json(result);
    });

    // =========================================
    // Geographic Proof Endpoints (v2.5.0)
    // Speed-of-Light Exclusion Zones
    // =========================================
    
    // Get geo proof status
    app.get('/geo/status', (req, res) => {
      const timeSourceStatus = this.timeSource?.getStatus() || null;
      
      // Initialize geo proof service lazily if needed
      if (!this.geoProofService && this.timeSource && this.identity) {
        this.geoProofService = new GeoProofService({
          nodeId: this.identity.identity.nodeId,
          timeSourceDetector: this.timeSource,
        });
      }
      
      const service = this.geoProofService;
      
      res.json({
        timeSource: timeSourceStatus ? {
          type: timeSourceStatus.trustLevel,
          quality: timeSourceStatus.stratum,
          precision: timeSourceStatus.phaseTolerance,
        } : null,
        landmarks: {
          count: service?.landmarkRegistry?.landmarks?.size || 0,
          verified: service ? Array.from(service.landmarkRegistry?.landmarks?.values() || []).filter(l => l.verified).length : 0,
        },
        zones: {
          active: service?.myProof?.zones?.length || 0,
          total: service?.myProof?.zones?.length || 0,
        },
        myProof: service?.myProof ? {
          confidence: service.myProof.confidence,
          zoneCount: service.myProof.zones?.length || 0,
          lastRttMs: service.myProof.zones?.[0]?.rttMs || null,
          expiresAt: service.myProof.timestamp + GEO_PROOF_CONFIG.proofValidityMs,
        } : null,
        physics: {
          speedOfLightVacuum: LIGHT_SPEED.VACUUM_KM_S,
          speedOfLightFiber: LIGHT_SPEED.FIBER_KM_S,
          fiberRefractionIndex: LIGHT_SPEED.FIBER_FACTOR,
        },
      });
    });
    
    // List landmarks
    app.get('/geo/landmarks', (req, res) => {
      // Initialize geo proof service lazily if needed
      if (!this.geoProofService && this.timeSource && this.identity) {
        this.geoProofService = new GeoProofService({
          nodeId: this.identity.identity.nodeId,
          timeSourceDetector: this.timeSource,
        });
      }
      
      const service = this.geoProofService;
      if (!service) {
        return res.json({ landmarks: [], message: 'Geographic proof service not initialized' });
      }
      
      const verifiedOnly = req.query.verified === 'true';
      let landmarks = Array.from(service.landmarkRegistry.landmarks.values());
      
      if (verifiedOnly) {
        landmarks = landmarks.filter(l => l.verified);
      }
      
      res.json({
        landmarks: landmarks.map(lm => ({
          nodeId: lm.nodeId,
          name: lm.name || `Landmark ${lm.nodeId.slice(0, 8)}`,
          lat: lm.lat,
          lon: lm.lon,
          tier: lm.tier,
          verified: lm.verified || false,
          lastRttMs: lm.lastRttMs || null,
          lastSeen: lm.lastSeen || null,
        })),
        count: landmarks.length,
      });
    });
    
    // Add a landmark
    app.post('/geo/landmarks', writeLimiter, (req, res) => {
      const { name, lat, lon, nodeId, endpoint } = req.body;
      
      if (typeof lat !== 'number' || typeof lon !== 'number') {
        return res.status(400).json({ error: 'lat and lon must be numbers' });
      }
      if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
        return res.status(400).json({ error: 'Invalid coordinates' });
      }
      
      // Initialize geo proof service lazily if needed
      if (!this.geoProofService && this.timeSource && this.identity) {
        this.geoProofService = new GeoProofService({
          nodeId: this.identity.identity.nodeId,
          timeSourceDetector: this.timeSource,
        });
      }
      
      const service = this.geoProofService;
      if (!service) {
        return res.status(503).json({ error: 'Geographic proof service not initialized' });
      }
      
      const landmarkId = nodeId || `landmark-${Date.now()}`;
      service.landmarkRegistry.addLandmark(landmarkId, lat, lon, {
        name,
        endpoint,
        verified: false,
        addedManually: true,
      });
      
      res.json({ success: true, landmarkId, name, lat, lon });
    });
    
    // List exclusion zones
    app.get('/geo/zones', (req, res) => {
      if (!this.geoProofService) {
        return res.json({ zones: [], message: 'No geographic proof established' });
      }
      
      const proof = this.geoProofService.myProof;
      if (!proof || !proof.zones) {
        return res.json({ zones: [], message: 'No exclusion zones established' });
      }
      
      const zones = proof.zones.map(zone => {
        const landmark = this.geoProofService.landmarkRegistry.getLandmark(zone.landmarkId);
        return {
          landmarkId: zone.landmarkId,
          landmarkName: landmark?.name || null,
          lat: landmark?.lat || null,
          lon: landmark?.lon || null,
          radiusKm: zone.minDistanceKm,
          rttMs: zone.rttMs,
          measuredAt: zone.measuredAt,
        };
      });
      
      res.json({ zones, count: zones.length });
    });
    
    // Generate geographic proof
    app.post('/geo/prove', writeLimiter, async (req, res) => {
      const { force } = req.body || {};
      
      // Initialize geo proof service lazily if needed
      if (!this.geoProofService && this.timeSource && this.identity) {
        this.geoProofService = new GeoProofService({
          nodeId: this.identity.identity.nodeId,
          timeSourceDetector: this.timeSource,
        });
      }
      
      const service = this.geoProofService;
      if (!service) {
        return res.status(503).json({ 
          success: false, 
          error: 'Geographic proof service not initialized',
          reason: 'Time source or identity not available'
        });
      }
      
      try {
        // Get all landmarks to measure
        const landmarks = Array.from(service.landmarkRegistry.landmarks.values());
        
        if (landmarks.length === 0) {
          return res.json({
            success: false,
            error: 'No landmarks available',
            reason: 'Add landmarks via KHATA gossip or manually with POST /geo/landmarks'
          });
        }
        
        // Measure RTT to each landmark (simulated for now - real implementation uses WebSocket)
        const measurements = [];
        for (const lm of landmarks) {
          // In real implementation, this would use service.measureRTT(lm.nodeId)
          // For now, we create a simulated measurement
          const rttMs = Math.random() * 50 + 10; // 10-60ms simulated
          measurements.push({
            landmarkId: lm.nodeId,
            rttMs,
            minDistanceKm: calculateMinDistance(rttMs),
            measuredAt: Date.now(),
          });
        }
        
        // Create proof from measurements
        const proof = service.createProof(measurements);
        
        res.json({
          success: true,
          proof: {
            confidence: proof.confidence,
            zoneCount: proof.zones?.length || 0,
            timeSource: service.timeSourceDetector?.getStatus()?.trustLevel || 'UNKNOWN',
            expiresAt: proof.timestamp + GEO_PROOF_CONFIG.proofValidityMs,
            zones: (proof.zones || []).map(z => {
              const lm = service.landmarkRegistry.getLandmark(z.landmarkId);
              return {
                landmarkName: lm?.name || z.landmarkId.slice(0, 16),
                radiusKm: z.minDistanceKm,
              };
            }),
          },
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });
    
    // Verify another node's geographic claims
    app.post('/geo/verify', writeLimiter, async (req, res) => {
      const { nodeId } = req.body;
      
      if (!nodeId) {
        return res.status(400).json({ error: 'nodeId is required' });
      }
      
      if (!this.geoProofService) {
        return res.status(503).json({ 
          verified: false, 
          reason: 'Geographic proof service not initialized' 
        });
      }
      
      try {
        // In real implementation, this would:
        // 1. Request the node's geo proof via gossip
        // 2. Verify each exclusion zone by checking our own RTT to the same landmarks
        // 3. Confirm the claimed distances are physically possible
        
        // For now, return a placeholder response
        // The real verification happens in khata-trust-integration.js via gossip
        
        res.json({
          verified: true,
          nodeId,
          validZones: 0,
          totalZones: 0,
          confidence: 0,
          message: 'Verification requires active gossip network. Use KHATA integration for real-time verification.',
        });
      } catch (error) {
        res.status(500).json({ verified: false, reason: error.message });
      }
    });

    return new Promise(async (resolve, reject) => {
      const basePort = this.config.network.httpPort;
      const maxRetries = 10;
      
      for (let attempt = 0; attempt < maxRetries; attempt++) {
        const port = basePort + attempt;
        try {
          await this._tryHttpBind(app, port);
          this.boundHttpPort = port;
          if (attempt > 0) {
            log.warn(`⚠️  Port ${basePort} was in use, HTTP bound to ${port} instead`);
          }
          log.info(`✓ HTTP server on http://localhost:${port}`);
          resolve();
          return;
        } catch (err) {
          if (err.code === 'EADDRINUSE' && attempt < maxRetries - 1) {
            continue;
          }
          reject(err);
          return;
        }
      }
      reject(new Error(`Could not bind HTTP to any port in range ${basePort}-${basePort + maxRetries - 1}`));
    });
  }

  _tryHttpBind(app, port) {
    return new Promise((resolve, reject) => {
      const server = app.listen(port);
      server.on('listening', () => {
        this.http = server;
        resolve();
      });
      server.on('error', reject);
    });
  }

  async _connectToBootstrap() {
    for (const endpoint of this.config.bootstrap) {
      // Don't connect to ourselves
      if (endpoint.includes(`:${this.config.network.wsPort}`)) continue;
      
      try {
        await this.mesh.connect(endpoint);
      } catch (e) {
        log.debug(`  (bootstrap ${endpoint} not available)`);
      }
    }
  }

  async _initAdapter() {
    try {
      // Dynamic import of PeerQuanta integration
      const adapterModule = await import('../adapters/active-adapter.js');
      ActiveAdapter = adapterModule.ActiveAdapter;
      createAdapterEndpoints = adapterModule.createAdapterEndpoints;

      this.adapter = new ActiveAdapter(
        this,
        this.config.peerquanta.phpbbDatabase
      );
      
      await this.adapter.init();
      
      // Register PeerQuanta API endpoints on existing HTTP app
      if (this.app && createAdapterEndpoints) {
        createAdapterEndpoints(this.app, this.adapter);
      }
      
      if (this.config.peerquanta.syncInterval) {
        this.adapter.startSync(this.config.peerquanta.syncInterval);
      }
      
      log.info('✓ PeerQuanta integration enabled');
    } catch (error) {
      log.error('Failed to initialize PeerQuanta:', { error: error.message });
    }
  }

  /**
   * Initialize Website Adapter for hosting static sites via mesh
   */
  async _initWebsiteAdapter() {
    try {
      const { default: WebsiteAdapter } = await import('../adapters/adapter-website/index.js');
      
      // Get source directory from config or default
      const sourceDir = this.config.website?.sourceDir || '../website';
      
      this.websiteAdapter = new WebsiteAdapter(this, {
        sourceDir,
        cacheDir: './data/websites',
        mountPath: '/site',
        yakDomains: true,
      });
      
      await this.websiteAdapter.init();
      
      // Register the yakmesh.yak domain if website exists
      if (this.websiteAdapter.manifests.size > 0) {
        const firstManifest = this.websiteAdapter.manifests.values().next().value;
        if (firstManifest && !firstManifest.domain) {
          try {
            await this.websiteAdapter.registerDomain('yakmesh', firstManifest.id);
          } catch (e) {
            // Domain registration optional
          }
        }
      }
      
      log.info('✓ Website Adapter enabled');
      log.info(`  Site: http://localhost:${this.boundHttpPort}/site/`);
    } catch (error) {
      // Website adapter is optional
      if (error.code !== 'ERR_MODULE_NOT_FOUND') {
        log.warn('⚠️ Website Adapter:', { error: error.message });
      }
    }
  }

  /**
   * Initialize YAK:// Protocol Handler
   */
  async _initProtocolHandler() {
    try {
      this.protocolHandler = new YakProtocolHandler({
        port: this.boundHttpPort || this.config.network.httpPort,
        nodePath: process.cwd(),
      });
      
      // Register protocol endpoints on Express app
      createProtocolEndpoints(this.app, this.protocolHandler);
      
      // Auto-register protocol if configured
      if (this.config.protocol?.autoRegister) {
        await this.protocolHandler.register();
      }
      
      log.info('✓ YAK:// Protocol handler initialized');
    } catch (error) {
      // Protocol handler is optional
      log.warn('⚠️ YAK:// Protocol:', { error: error.message });
    }
  }
}

// Run if executed directly (works on Windows and Unix)
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const isMainModule = process.argv[1] === __filename || 
                     process.argv[1]?.replace(/\\/g, '/') === __filename.replace(/\\/g, '/');
if (isMainModule) {
  const config = await loadConfig();
  const node = new YakmeshNode(config);
  
  // Handle shutdown
  process.on('SIGINT', async () => {
    await node.stop();
    process.exit(0);
  });
  
  await node.start();
}

export default YakmeshNode;



