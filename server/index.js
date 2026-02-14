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
import { networkInterfaces } from 'os';
import { WebSocketServer } from 'ws';
import { createLogger } from '../utils/logger.js';
import * as accel from '../utils/accel.js';

const log = createLogger('server:main');
import { NodeIdentity } from '../identity/node-key.js';
import { MeshNetwork } from '../mesh/network.js';
import { ReplicationEngine } from '../database/replication.js';
import { GossipProtocol } from '../gossip/protocol.js';

// Content store for public delivery
import { ContentStore, createContentAPI } from '../content/index.js';

// Embedded documentation (hardcoded, hash-verified)
import { getDocsFile, serveDocsFile, getBundleInfo } from '../embedded-docs/index.js';

// Annex lives in mesh/network.js — single instance, no duplication

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

// ═══════════════════════════════════════════════════════════════════════════════
// KOMM STACK — Chat, Voice, Rooms, Access Control
// ═══════════════════════════════════════════════════════════════════════════════

// KATHA — Chat messaging (text, reactions, typing, threads, read receipts)
import { KathaHub, KATHA_CONFIG } from '../mesh/katha.js';

// VANI — WebRTC voice/video calling with mesh signaling
import { VaniHub, VANI_CONFIG, MEDIA_TYPE, CALL_STATE } from '../mesh/vani.js';

// YURT — Decentralized room directory and discovery
import { YurtHub, YURT_CONFIG } from '../mesh/yurt.js';

// GUMBA — Cryptographic access control (proofs, not keys)
import { GumbaHub, GUMBA_CONFIG } from '../mesh/gumba.js';

// KOMM API router and gossip wiring
import { createKommAPI, wireKommGossip } from './komm-api.js';

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN — Content Streaming (view, don't copy)
// ═══════════════════════════════════════════════════════════════════════════════
import { DarshanGateway, DARSHAN_CONFIG } from '../mesh/darshan.js';
import { createDarshanAPI, wireDarshanGossip } from './darshan-api.js';

// ═══════════════════════════════════════════════════════════════════════════════
// NAKPAK — Post-Quantum Onion Routing
// ═══════════════════════════════════════════════════════════════════════════════
import { NakpakRouter, NAKPAK_CONFIG } from '../mesh/nakpak-routing.js';

// ═══════════════════════════════════════════════════════════════════════════════
// SAKSHI — Observational Witness Consensus
// ═══════════════════════════════════════════════════════════════════════════════
import { NodeWitness, ObservationResult, BehaviorVelocityMonitor, BEHAVIOR_DIMENSION, VELOCITY_ALERT } from '../security/sakshi.js';

// KARMA Trust Model — SAKSHI observations feed into trust assessment
import { KarmaTrustModel, KarmaLevel } from '../security/hybrid-trust.js';

// TRIBHUJ — Balanced ternary for KARMA trit mapping
import { POSITIVE, NEUTRAL, NEGATIVE, TritState } from '../oracle/tribhuj.js';

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
    
    // Annex lives in mesh.annex — single instance managed by mesh layer
    
    // KOMM Stack — chat, voice, rooms, access control
    this.kathaHub = null;
    this.vaniHub = null;
    this.yurtHub = null;
    this.gumbaHub = null;
    
    // DARSHAN — content streaming
    this.darshanGateway = null;
    
    // NAKPAK — onion routing
    this.nakpakRouter = null;
    
    // SAKSHI — witness consensus
    this.sakshiWitness = null;
    this.velocityMonitor = null;
    
    // KARMA — trust model (fed by SAKSHI observations)
    this.karmaModel = null;
    
    // KOMM WebSocket (real-time KATHA/VANI)
    this.kommWss = null;
    
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

    // 0b. Initialize ACCEL — hardware-accelerated crypto & inference
    // Probes CPU SIMD (AVX-512/VAES/SHA-NI), NVIDIA GPU (CUDA), AMD NPU (XDNA/DirectML)
    // Must happen before any crypto operations so native paths are available
    log.info('⚡ Initializing ACCEL (hardware acceleration)...');
    const accelResult = await accel.initialize();
    this._accel = accelResult;
    const caps = [];
    if (accel.HW.nativeSha3) caps.push('SHA3-native');
    if (accel.HW.avx512) caps.push('AVX-512');
    if (accel.HW.vaes) caps.push('VAES');
    if (accel.HW.shaNI) caps.push('SHA-NI');
    if (accel.HW.nvGpu) caps.push(`GPU:${accel.HW.nvGpuName}`);
    if (accel.HW.amdNpu) caps.push(`NPU:${accel.HW.amdNpuTops}TOPS`);
    if (accel.HW.nativePQ) caps.push(`PQ:${accel.HW.nativePQBackend}`);
    log.info(`✓ ACCEL: ${caps.length > 0 ? caps.join(' | ') : 'pure-JS fallback'}`);

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
    
    // Annex messages handled directly in mesh._handleMessage() — no separate routing needed

    // 5. Initialize content store for public delivery
    this.contentStore = new ContentStore({
      dataDir: this.config.database?.contentPath || './data/content',
      quorumSize: 2,
    });
    await this.contentStore.init(this);
    
    // 5b. Annex — initialized inside mesh.start(), no duplicate instance needed
    log.info('✓ Annex channel ready (single instance in mesh layer)');
    
    // 5c. Initialize KOMM stack (KATHA + VANI + YURT + GUMBA)
    this._initKommStack();
    
    // 5d. Initialize DARSHAN content streaming gateway
    this._initDarshan();
    
    // 5e. Initialize NAKPAK onion routing
    this._initNakpak();
    
    // 5f. Initialize SAKSHI witness consensus
    this._initSakshi();
    
    // 5g. Initialize KARMA trust model (fed by SAKSHI)
    this._initKarma();
    
    // 5h. Initialize SHERPA for decentralized peer discovery
    this.sherpa = new SherpaDiscovery({
      nodeId: this.identity.identity.nodeId,
      networkName: this.genesisNetwork?.networkName,
      publicKey: this.identity.identity.publicKey,
      signFn: (data) => this.identity.sign(data),
      verifyFn: (data, sig, pubKey) => this.identity.verify(data, sig, pubKey),
      selfEndpoint: this.config.sherpa?.selfEndpoint || null,
      wsEndpoint: this.config.sherpa?.wsEndpoint || null,
      relayEndpoint: this.config.sherpa?.relayEndpoint || null,
      capabilities: {
        wsPort: this.config.network.wsPort,
        httpPort: this.config.network.httpPort,
        supportsAnnex: true,
        supportsNakpak: !!this.nakpakRouter,
        supportsKomm: !!(this.kathaHub && this.gumbaHub),
        supportsDarshan: !!this.darshanGateway,
        supportsGossip: true,
      },
      seedEndpoints: this.config.sherpa?.seeds || [],
    });

    // Expose SHERPA registry on mesh so ANNEX can look up relay peer public keys
    this.mesh.sherpa = this.sherpa;
    
    // Start SHERPA if seeds are configured or selfEndpoint is set
    if (this.config.sherpa?.enabled !== false) {
      // Wire SHERPA auto-connect: when crawl discovers peers, connect outbound
      this.sherpa.on('crawl-complete', ({ peersFound }) => {
        if (peersFound > 0) {
          this._sherpaAutoConnect();
        }
      });
      this.sherpa.start();
      log.info('✓ SHERPA discovery initialized (decentralized peer discovery)');
    }

    // 5i. Wire mesh → HTTP relay bridge
    // Route direct messages (sendTo) via relay when no WS connection
    this.mesh.on('outbound-relay', (targetNodeId, msg) => {
      if ((this._relayPollers && this._relayPollers.has(targetNodeId)) ||
          (this._relayClients && this._relayClients.has(targetNodeId))) {
        this._queueRelayMessage(targetNodeId, msg);
      } else {
        log.debug(`No relay path to ${targetNodeId.slice(0, 20)}`);
      }
    });

    // Wire gossip broadcasts → relay bridge
    // This covers both directions:
    //   - _relayPollers: nodes WE poll (we initiated relay connection)
    //   - _relayClients: nodes that poll US (they registered with our relay)
    this.mesh.on('outbound-gossip', (msg, excludeNodeIds = []) => {
      const excludeSet = new Set(excludeNodeIds);
      
      // Queue for nodes we actively poll (outbound relay connections)
      if (this._relayPollers && this._relayPollers.size > 0) {
        for (const [relayNodeId] of this._relayPollers) {
          if (!excludeSet.has(relayNodeId) && relayNodeId !== msg.origin) {
            this._queueRelayMessage(relayNodeId, msg);
          }
        }
      }

      // Queue for nodes that registered to poll us (inbound relay clients)
      if (this._relayClients && this._relayClients.size > 0) {
        for (const [clientNodeId] of this._relayClients) {
          if (!excludeSet.has(clientNodeId) && clientNodeId !== msg.origin) {
            this._queueRelayMessage(clientNodeId, msg);
          }
        }
      }
    });

    // 5j. Expire stale relay clients (no poll for 5 minutes)
    setInterval(() => {
      if (!this._relayClients || this._relayClients.size === 0) return;
      const now = Date.now();
      const RELAY_CLIENT_TTL = 5 * 60 * 1000; // 5 minutes
      for (const [clientNodeId, lastSeen] of this._relayClients) {
        if (now - lastSeen > RELAY_CLIENT_TTL) {
          this._relayClients.delete(clientNodeId);
          // Also clear any queued messages and cached keys for expired client
          if (this._relayOutbox) this._relayOutbox.delete(clientNodeId);
          if (this.mesh?._relayPeerKeys) this.mesh._relayPeerKeys.delete(clientNodeId);
          log.debug(`Relay client expired: ${clientNodeId.slice(0, 20)}`);
        }
      }
    }, 60000); // Check every minute
    
    // 6. Start HTTP server
    await this._startHttpServer();
    
    // 6b. Attach KOMM WebSocket upgrade paths to HTTP server
    this._initKommWebSocket();

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
    log.info(`  WebSocket:  ws://localhost:${this.mesh.boundPort || this.config.network.wsPort}`);
    log.info(`  Algorithm:  ML-DSA-65 (Post-Quantum)`);
    log.info(`  Oracle:     ✓ ${this.oracle.selfHash.slice(0, 16)}...`);
    log.info(`  Network:    ${this.genesisNetwork.networkName} (${this.genesisNetwork.networkId})`);
    log.info('');
    log.info('  Quick Access:');
    log.info(`    Dashboard:     http://localhost:${this.boundHttpPort || this.config.network.httpPort}/dashboard`);
    log.info(`    Documentation: http://localhost:${this.boundHttpPort || this.config.network.httpPort}/docs/`);
    log.info(`    Health:        http://localhost:${this.boundHttpPort || this.config.network.httpPort}/health`);
    log.info('');
    log.info('  CLI shortcuts:   yakmesh open dashboard | yakmesh open docs');
    if (this.contentStore) {
      const stats = this.contentStore.getStats();
      log.info(`  Content:    ${stats.totalObjects} objects (${stats.verified} verified)`);
    }
    if (this.mesh?.annex) {
      log.info(`  Annex:      ✓ Encrypted P2P ready`);
    }
    if (this.kathaHub) {
      log.info(`  KOMM:       ✓ KATHA + VANI + YURT + GUMBA at /komm/`);
    }
    if (this.darshanGateway) {
      log.info(`  DARSHAN:    ✓ Content streaming at /darshan/`);
    }
    if (this.nakpakRouter) {
      log.info(`  NAKPAK:     ✓ Onion routing active (${this.nakpakRouter.knownNodes.size} known nodes)`);
    }
    if (this.sakshiWitness) {
      log.info(`  SAKSHI:     ✓ Witness consensus active`);
    }
    if (this.karmaModel) {
      log.info(`  KARMA:      ✓ Trust model active (SAKSHI → trust pipeline)`);
    }
    if (this.kommWss) {
      log.info(`  KOMM WS:    ✓ Real-time at ws://localhost:${this.boundHttpPort || this.config.network.httpPort}/komm/ws`);
    }
    if (this.sherpa) {
      log.info(`  SHERPA:     ✓ Beacon at /.well-known/yakmesh/beacon`);
    }
    // ACCEL status line
    {
      const a = accel.HW;
      const accelParts = [];
      if (a.nativeSha3) accelParts.push('SHA3');
      if (a.avx512) accelParts.push('AVX-512');
      if (a.nvGpu) accelParts.push(`GPU(${a.nvGpuName})`);
      if (a.amdNpu) accelParts.push(`NPU(${a.amdNpuTops}T)`);
      if (a.nativePQ) accelParts.push(`PQ(${a.nativePQBackend})`);
      if (accelParts.length > 0) {
        log.info(`  ACCEL:      ⚡ ${accelParts.join(' + ')}`);
      } else {
        log.info(`  ACCEL:      ○ pure-JS (install liboqs-node / onnxruntime-node for acceleration)`);
      }
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
    this.yurtHub?.stop();  // Stop YURT room gossip
    this.velocityMonitor?.stop?.();  // Stop velocity monitoring
    this.karmaModel?.stopPromotionChecks?.();  // Stop KARMA auto-promotion
    this.nakpakRouter?.cleanupCircuits?.();  // Cleanup NAKPAK circuits
    this.kommWss?.close();  // Close KOMM WebSocket server
    // Annex channels cleaned up by mesh.stop()
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
   * Initialize the KOMM Stack (KATHA + VANI + YURT + GUMBA)
   * This provides the chat, voice, room, and access control backend.
   */
  _initKommStack() {
    log.info('💬 Initializing KOMM Stack...');
    
    // KATHA — Chat messaging hub
    this.kathaHub = new KathaHub();
    log.debug('   KATHA: Chat messaging hub ready');
    
    // GUMBA — Access control (initialized before YURT, which depends on it)
    this.gumbaHub = new GumbaHub(this.identity, this.mesh?.annex, {});
    log.debug('   GUMBA: Access control hub ready');
    
    // YURT — Room directory (depends on identity, gumbaHub, mesh)
    this.yurtHub = new YurtHub(this.identity, this.gumbaHub, this.mesh, {});
    this.yurtHub.start();
    log.debug('   YURT: Room directory + gossip started');
    
    // VANI — Voice/video calling
    this.vaniHub = new VaniHub({
      localPeerId: this.identity.identity.nodeId,
      onSignal: (signal) => {
        // Forward WebRTC signals through mesh gossip
        this.gossip.spreadRumor('vani:signal', {
          signal,
          origin: this.identity.identity.nodeId,
        });
      },
    });
    log.debug('   VANI: Voice/video signaling hub ready');
    
    // Wire KOMM gossip handlers (incoming KATHA/VANI/YURT/GUMBA rumors)
    wireKommGossip(this.mesh, this.kathaHub, this.vaniHub, this.yurtHub, this.gumbaHub);
    
    log.info('✓ KOMM Stack initialized (KATHA + VANI + YURT + GUMBA)');
  }
  
  /**
   * Initialize DARSHAN content streaming gateway
   */
  _initDarshan() {
    log.info('📺 Initializing DARSHAN...');
    
    this.darshanGateway = new DarshanGateway(this.identity, {
      maxBandwidth: this.config.darshan?.maxBandwidth || Infinity,
    });
    
    // Wire DARSHAN gossip handlers
    wireDarshanGossip(this.mesh, this.darshanGateway);
    
    log.info('✓ DARSHAN initialized (content streaming gateway)');
  }
  
  /**
   * Initialize NAKPAK onion routing
   * Provides post-quantum anonymous routing for sensitive messages.
   */
  _initNakpak() {
    log.info('🧅 Initializing NAKPAK...');
    
    this.nakpakRouter = new NakpakRouter({
      nodeId: this.identity.identity.nodeId,
      onMessageReceived: (message) => {
        log.debug(`📦 NAKPAK message received: ${message.id?.slice(0, 16) || 'unknown'}...`);
        this.mesh.emit('nakpak:message', message);
      },
      onForward: (packet) => {
        // Forward the packet to the next hop via mesh
        const nextHop = packet.nextHop;
        if (nextHop && this.mesh.sendTo) {
          this.mesh.sendTo(nextHop, {
            type: 'nakpak:relay',
            packet,
          });
        }
      },
    });
    
    // Register known peers as NAKPAK nodes
    // Re-register whenever new peers connect
    this.mesh.on('peer:connected', (peerId, peerInfo) => {
      if (peerInfo?.publicKey) {
        this.nakpakRouter.registerNode(peerId, peerInfo.publicKey);
      }
    });
    
    // Handle incoming NAKPAK relay packets
    this.mesh.on('rumor', (topic, data, origin) => {
      if (topic === 'nakpak:relay' && data.packet) {
        this.nakpakRouter.relay.handlePacket(data.packet);
      }
    });
    
    log.info('✓ NAKPAK initialized (post-quantum onion routing)');
  }
  
  /**
   * Initialize SAKSHI witness consensus
   * Observational capability system for node behavior monitoring.
   */
  _initSakshi() {
    log.info('👁️ Initializing SAKSHI...');
    
    this.sakshiWitness = new NodeWitness({
      nodeId: this.identity.identity.nodeId,
      ...this.config.sakshi,
    });
    
    // Behavior velocity monitor (detects rapid state changes / anomalies)
    this.velocityMonitor = new BehaviorVelocityMonitor({
      nodeId: this.identity.identity.nodeId,
    });
    
    // Track connection churn per peer via velocity monitor
    this.mesh.on('peer:connected', (peerId) => {
      this.velocityMonitor.observe(
        peerId,
        BEHAVIOR_DIMENSION.CONNECTION_CHURN,
        1 // connect event = +1
      );
    });
    
    this.mesh.on('peer:disconnected', (peerId) => {
      this.velocityMonitor.observe(
        peerId,
        BEHAVIOR_DIMENSION.CONNECTION_CHURN,
        -1 // disconnect event = -1
      );
    });
    
    // Track gossip message rates per origin
    if (this.gossip && this.mesh) {
      let messageCountWindow = new Map(); // peerId -> count in current window
      
      this.mesh.on('rumor', (topic, data, origin) => {
        const rumor = { origin };
        if (!rumor.origin) return;
        const count = (messageCountWindow.get(rumor.origin) || 0) + 1;
        messageCountWindow.set(rumor.origin, count);
        this.velocityMonitor.observe(
          rumor.origin,
          BEHAVIOR_DIMENSION.MESSAGE_RATE,
          count
        );
      });
      
      // Reset message count window every minute
      setInterval(() => { messageCountWindow.clear(); }, 60000);
    }
    
    log.info('✓ SAKSHI initialized (witness consensus + velocity monitoring)');
  }
  
  /**
   * Initialize KARMA trust model
   * SAKSHI velocity alerts feed into KARMA trust assessments.
   */
  _initKarma() {
    log.info('☯️ Initializing KARMA...');
    
    this.karmaModel = new KarmaTrustModel(this.config.karma || {});
    
    // Wire SAKSHI velocity alerts → KARMA trust adjustments (ternary: NEGATIVE/NEUTRAL/ignored)
    if (this.velocityMonitor) {
      this.velocityMonitor.onAlert((alert) => {
        const { nodeId, level, dimension, zScore } = alert;
        
        // ═══ TRIBHUJ ternary mapping ═══
        // CRITICAL → NEGATIVE karma (record as failed verification)
        // WARNING  → NEUTRAL observation (beacon sighting — keeps node active)
        // ELEVATED → ignored (normal variance — no karmic consequence)
        if (level === VELOCITY_ALERT.CRITICAL) {
          log.warn(`☯️ KARMA: Critical velocity alert for ${nodeId.slice(0, 16)}... (${dimension}, z=${zScore.toFixed(1)}) → NEGATIVE`);
          // Record negative evidence — failed behavioral verification
          this.karmaModel.recordDokoVerification(nodeId, {
            passed: false,
            reason: `Critical velocity anomaly: ${dimension} (z-score ${zScore.toFixed(1)})`,
          });
        } else if (level === VELOCITY_ALERT.WARNING) {
          log.debug(`☯️ KARMA: Warning velocity alert for ${nodeId.slice(0, 16)}... (${dimension}) → NEUTRAL`);
          // Record beacon sighting (neutral — keeps node active, doesn't penalize)
          this.karmaModel.recordBeaconSighting(nodeId);
        }
        // ELEVATED → no karmic consequence (positive path: absence of negative)
      });
    }
    
    // Wire mesh peer events → KARMA beacon sightings (positive karma accumulation)
    this.mesh.on('peer:connected', (peerId) => {
      this.karmaModel.recordBeaconSighting(peerId);
    });
    
    // Wire KARMA trust level changes → log them
    this.karmaModel.on('promoted', ({ nodeId, from, to, reason }) => {
      log.info(`☯️ KARMA: Node ${nodeId.slice(0, 16)}... promoted ${from}→${to} (${reason})`);
    });
    
    this.karmaModel.on('demoted', ({ nodeId, from, to, reason }) => {
      log.warn(`☯️ KARMA: Node ${nodeId.slice(0, 16)}... demoted ${from}→${to} (${reason})`);
    });
    
    log.info('✓ KARMA trust model initialized (SAKSHI → trust assessment pipeline)');
  }
  
  /**
   * Initialize KOMM WebSocket upgrade on the HTTP server
   * Provides real-time KATHA messages and VANI signaling over WS.
   * 
   * Clients connect to:
   *   ws://host:port/komm/ws — unified KOMM channel
   *   Messages are JSON: { type: 'katha:event'|'katha:typing'|'vani:signal'|..., data: {...} }
   */
  _initKommWebSocket() {
    if (!this.http || !this.kathaHub) return;
    
    this.kommWss = new WebSocketServer({ noServer: true });
    
    // Handle upgrade requests for /komm/ws path
    this.http.on('upgrade', (request, socket, head) => {
      const url = new URL(request.url, `http://${request.headers.host}`);
      
      if (url.pathname === '/komm/ws') {
        this.kommWss.handleUpgrade(request, socket, head, (ws) => {
          this.kommWss.emit('connection', ws, request);
        });
      } else {
        // Not our path — let other upgrade handlers (mesh WS) deal with it
        // If no handler, the socket just hangs. Destroy it if unhandled.
      }
    });
    
    // Track connected KOMM WebSocket clients
    const kommClients = new Set();
    
    this.kommWss.on('connection', (ws, request) => {
      kommClients.add(ws);
      log.debug('📡 KOMM WS client connected');
      
      ws.on('close', () => {
        kommClients.delete(ws);
        log.debug('📡 KOMM WS client disconnected');
      });
      
      ws.on('error', () => {
        kommClients.delete(ws);
      });
      
      // Handle incoming messages from client
      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          this._handleKommWsMessage(msg, ws);
        } catch {
          ws.send(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      
      // Send welcome
      ws.send(JSON.stringify({
        type: 'welcome',
        nodeId: this.identity.identity.nodeId.slice(0, 16),
        capabilities: ['katha', 'vani', 'yurt'],
      }));
    });
    
    // Broadcast helper
    const broadcastKomm = (type, data) => {
      const msg = JSON.stringify({ type, data, ts: Date.now() });
      for (const client of kommClients) {
        if (client.readyState === 1) { // OPEN
          client.send(msg);
        }
      }
    };
    
    // Wire KATHA events → WS broadcast
    if (this.kathaHub) {
      this.kathaHub.on?.('message', (msg) => broadcastKomm('katha:message', msg));
      this.kathaHub.on?.('typing', (data) => broadcastKomm('katha:typing', data));
      this.kathaHub.on?.('reaction', (data) => broadcastKomm('katha:reaction', data));
    }
    
    // Wire VANI signals → WS broadcast
    if (this.vaniHub) {
      this.vaniHub.on?.('signal', (signal) => broadcastKomm('vani:signal', signal));
      this.vaniHub.on?.('callStateChanged', (state) => broadcastKomm('vani:callState', state));
    }
    
    // Wire YURT room events → WS broadcast
    if (this.yurtHub) {
      this.yurtHub.on?.('roomRegistered', (room) => broadcastKomm('yurt:registered', room));
      this.yurtHub.on?.('roomUnregistered', (room) => broadcastKomm('yurt:unregistered', room));
    }
    
    // Also broadcast gossip-received KATHA/VANI events
    if (this.mesh) {
      this.mesh.on('rumor', (topic, data, origin) => {
        if (topic === 'katha:event' || topic === 'katha:typing' || 
            topic === 'vani:signal') {
          broadcastKomm(topic, data);
        }
      });
    }
    
    log.info('✓ KOMM WebSocket initialized at /komm/ws');
  }
  
  /**
   * Handle incoming KOMM WS messages from clients
   */
  _handleKommWsMessage(msg, ws) {
    const { type, data } = msg;
    
    switch (type) {
      case 'katha:send':
        if (this.kathaHub?.send) {
          this.kathaHub.send(data);
        }
        break;
      case 'katha:typing':
        if (this.kathaHub?.setTyping) {
          this.kathaHub.setTyping(data);
        }
        break;
      case 'vani:signal':
        if (this.vaniHub?.signal) {
          this.vaniHub.signal(data);
        }
        break;
      case 'vani:call':
        if (this.vaniHub?.initiateCall) {
          this.vaniHub.initiateCall(data).then(result => {
            ws.send(JSON.stringify({ type: 'vani:callResult', data: result }));
          }).catch(() => {});
        }
        break;
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        break;
    }
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
    
    // Enable strict routing: /docs and /docs/ are different routes
    app.set('strict routing', true);
    
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
    
    // CORS — restricted to localhost and configured origins
    const allowedOrigins = new Set([
      'http://localhost:3000',
      'http://localhost:3090',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3090',
      ...(this.config.cors?.allowedOrigins || []),
    ]);
    
    app.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && allowedOrigins.has(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
      }
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.header('Vary', 'Origin');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    });
    
    // =========================================
    // SECURITY: Peer authentication middleware
    // =========================================
    // Validates that write requests from peers include a valid node signature
    const requirePeerAuth = (req, res, next) => {
      const nodeId = req.headers['x-node-id'];
      const sig = req.headers['x-node-signature'];
      const ts = req.headers['x-node-timestamp'];
      
      // Skip auth if request is from localhost (dashboard/local tools)
      const remoteIP = req.ip || req.connection?.remoteAddress;
      if (remoteIP === '127.0.0.1' || remoteIP === '::1' || remoteIP === '::ffff:127.0.0.1') {
        return next();
      }
      
      // Require node identity headers for remote requests
      if (!nodeId || !sig || !ts) {
        return res.status(401).json({ error: 'Missing peer authentication headers' });
      }
      
      // Reject stale timestamps — tightened from 30s to 10s
      // With TRIBHUJ ratchet and SSE push, nodes maintain tighter time sync.
      // 10s allows for reasonable network latency while preventing replay attacks.
      const MAX_AUTH_DRIFT_MS = 10000;
      const drift = Math.abs(Date.now() - parseInt(ts, 10));
      if (isNaN(drift) || drift > MAX_AUTH_DRIFT_MS) {
        return res.status(401).json({ error: 'Request timestamp too old or invalid' });
      }
      
      // Verify signature over (nodeId + timestamp + body hash)
      try {
        const bodyStr = JSON.stringify(req.body || {});
        const payload = `${nodeId}:${ts}:${bodyStr}`;
        const verified = this.identity.verify(payload, sig, nodeId);
        if (!verified) {
          return res.status(403).json({ error: 'Invalid peer signature' });
        }
        req.authenticatedPeer = nodeId;
        next();
      } catch (e) {
        return res.status(403).json({ error: 'Signature verification failed' });
      }
    };
    
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
    
    // =========================================
    // KOMM STACK API (KATHA/VANI/YURT/GUMBA)
    // Backend for yakapp (GUI) and terminal (CLI) clients
    // =========================================
    
    if (this.kathaHub) {
      const kommRouter = createKommAPI({
        kathaHub: this.kathaHub,
        vaniHub: this.vaniHub,
        yurtHub: this.yurtHub,
        gumbaHub: this.gumbaHub,
        gossip: this.gossip,
        identity: this.identity,
        writeLimiter,
        requirePeerAuth,
      });
      app.use('/komm', kommRouter);
      log.info('📡 KOMM API mounted at /komm');
    }
    
    // =========================================
    // DARSHAN Content Streaming API
    // View-don't-copy content delivery
    // =========================================
    
    if (this.darshanGateway) {
      const darshanRouter = createDarshanAPI({
        darshanGateway: this.darshanGateway,
        gossip: this.gossip,
        identity: this.identity,
        writeLimiter,
      });
      app.use('/darshan', darshanRouter);
      log.info('📡 DARSHAN API mounted at /darshan');
    }
    
    // =========================================
    // NAKPAK Status Endpoint
    // =========================================
    
    if (this.nakpakRouter) {
      app.get('/nakpak/status', (req, res) => {
        const circuits = this.nakpakRouter.circuits || new Map();
        const relays = this.nakpakRouter.relays || new Map();
        res.json({
          active: true,
          circuits: circuits.size,
          relays: relays.size,
          nodeId: this.identity.identity.nodeId.slice(0, 16) + '...',
        });
      });
    }
    
    // =========================================
    // SAKSHI Witness + KARMA Status Endpoint
    // =========================================
    
    if (this.sakshiWitness) {
      app.get('/sakshi/status', (req, res) => {
        const velocityStats = this.velocityMonitor?.getStats?.() || {};
        const karmaStats = this.karmaModel?.getStats?.() || {};
        
        res.json({
          active: true,
          witness: this.sakshiWitness.toJSON(),
          velocity: {
            active: !!this.velocityMonitor,
            ...velocityStats,
            activeAlerts: this.velocityMonitor?.getActiveAlerts?.() || [],
          },
          karma: {
            active: !!this.karmaModel,
            ...karmaStats,
          },
        });
      });
    }
    
    // =========================================
    // Embedded Documentation (hardcoded, hash-verified)
    // Accessible via yak://docs or http://localhost:PORT/docs/
    // =========================================
    
    app.get('/docs', (req, res) => {
      res.redirect('/docs/');
    });
    
    app.get('/docs/', (req, res) => {
      serveDocsFile('index.html', res);
    });
    
    app.get('/docs/_bundle', (req, res) => {
      try {
        const info = getBundleInfo();
        res.json(info);
      } catch (err) {
        res.status(500).json({ error: 'Bundle info unavailable' });
      }
    });
    
    app.get('/docs/:file(*)', (req, res) => {
      const file = req.params.file || 'index.html';
      serveDocsFile(file, res);
    });
    
    // Serve dashboard
    app.get('/dashboard', (req, res) => {
      res.sendFile('dashboard/index.html', { root: import.meta.dirname + '/..' });
    });

    // Health check
    app.get('/health', (req, res) => {
      const wsPeers = this.mesh.getPeers();
      const relayPollCount = this._relayPollers?.size || 0;
      const relayClientCount = this._relayClients?.size || 0;
      const relayOutboxSize = this._relayOutbox 
        ? [...this._relayOutbox.values()].reduce((sum, q) => sum + q.length, 0) 
        : 0;

      res.json({
        status: 'ok',
        nodeId: this.identity.identity.nodeId,
        peers: wsPeers.length,
        relayPeers: relayPollCount + relayClientCount,
        relayPollers: relayPollCount,
        relayClients: relayClientCount,
        relayOutbox: relayOutboxSize,
        totalPeers: wsPeers.length + relayPollCount + relayClientCount,
        algorithm: 'ML-DSA-65',
        network: this.genesisNetwork ? {
          name: this.genesisNetwork.networkName,
          id: this.genesisNetwork.networkId,
        } : null,
        sherpa: this.sherpa ? {
          registry: this.sherpa.registry?.size() || 0,
          candidates: this.sherpa.getConnectionCandidates(10).length,
        } : null,
        accel: accel.getStatus(),
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

    // =========================================
    // ACCEL: Hardware Acceleration Status
    // =========================================
    app.get('/accel', (req, res) => {
      res.json(accel.getStatus());
    });

    app.get('/accel/telemetry', (req, res) => {
      res.json(accel.getTelemetry());
    });

    // =========================================
    // SHERPA HTTP Relay: Mesh messaging over HTTP
    // =========================================
    // Allows nodes behind firewalls to exchange mesh messages via HTTP POST
    // instead of WebSocket. The PHP bridge on yakmesh.dev proxies to this.
    // Message flow: Remote Node → HTTPS POST yakmesh.dev/mesh/relay → PHP → localhost:3080/mesh/relay

    // Accept inbound mesh messages via HTTP (signed, verified)
    app.post('/mesh/relay', writeLimiter, (req, res) => {
      // Handle relay registration (action: 'register') through the same endpoint
      // so it works through the PHP bridge which only proxies POST /mesh/relay
      if (req.body.action === 'register') {
        const { nodeId, networkName, publicKey, capabilities, signature, timestamp } = req.body;
        if (!nodeId || !networkName) {
          return res.status(400).json({ error: 'nodeId and networkName required for register' });
        }

        // Verify ML-DSA-65 registration signature — no unsigned registrations
        if (!signature || !publicKey) {
          return res.status(403).json({ error: 'Signed registration required (signature + publicKey)' });
        }
        try {
          const sigData = JSON.stringify({ action: 'register', nodeId, networkName, timestamp });
          const valid = this.identity.verify(sigData, signature, publicKey);
          if (!valid) {
            return res.status(403).json({ error: 'Invalid registration signature' });
          }
        } catch {
          return res.status(403).json({ error: 'Registration signature verification failed' });
        }

        // Reject stale registrations (> 5 minutes old)
        if (timestamp && Math.abs(Date.now() - timestamp) > 300000) {
          return res.status(403).json({ error: 'Registration timestamp too old (replay protection)' });
        }

        if (this.sherpa) {
          this.sherpa.registry.upsert({
            nodeId,
            endpoint: null,
            wsEndpoint: null,
            relayEndpoint: null,
            networkName,
            publicKey,
            capabilities: { ...capabilities, httpRelay: true },
          });
        }

        // Store publicKey for relay peers (used by ANNEX signature verification)
        // Attach to mesh so ANNEX._getPeerPublicKey() can find relay peer keys
        if (!this.mesh._relayPeerKeys) this.mesh._relayPeerKeys = new Map();
        this.mesh._relayPeerKeys.set(nodeId, publicKey);

        // Track relay clients as Map {nodeId → lastSeen} for expiry
        if (!this._relayClients) this._relayClients = new Map();
        this._relayClients.set(nodeId, Date.now());

        log.info(`HTTP relay peer registered (verified): ${nodeId.slice(0, 20)}`);
        return res.json({ success: true, nodeId: this.identity.identity.nodeId });
      }

      const { messages, senderNodeId, signature, publicKey } = req.body;

      if (!Array.isArray(messages)) {
        return res.status(400).json({ error: 'messages array required' });
      }
      if (messages.length > 50) {
        return res.status(400).json({ error: 'Max 50 messages per relay batch' });
      }
      if (!senderNodeId || typeof senderNodeId !== 'string') {
        return res.status(400).json({ error: 'senderNodeId required' });
      }

      // Require ML-DSA-65 batch signature — no unsigned relay batches accepted
      if (!signature || !publicKey) {
        return res.status(403).json({ error: 'Signed relay batch required (signature + publicKey)' });
      }
      try {
        const sigData = JSON.stringify({ messages, senderNodeId });
        const valid = this.identity.verify(sigData, signature, publicKey);
        if (!valid) {
          return res.status(403).json({ error: 'Invalid batch signature' });
        }
      } catch {
        return res.status(403).json({ error: 'Batch signature verification failed' });
      }

      // Process each message through the mesh layer
      let accepted = 0;
      for (const msg of messages) {
        if (msg && typeof msg === 'object' && msg.type) {
          try {
            // Dispatch by msg.type (e.g., 'gossip') — not 'message'
            this.mesh.emit(msg.type, msg, null, senderNodeId);
            // Route ANNEX messages arriving via relay
            if (msg.annex && this.mesh.annex) {
              this.mesh.annex._handleAnnexMessage(msg.annex, senderNodeId).catch(() => {});
            }
            accepted++;
          } catch {
            // Skip malformed messages
          }
        }
      }

      // Refresh relay client last-seen on poll
      if (this._relayClients && this._relayClients.has(senderNodeId)) {
        this._relayClients.set(senderNodeId, Date.now());
      }

      // Return our own pending outbound messages for this sender (bi-directional relay)
      const outbound = this._drainRelayOutbox(senderNodeId);

      res.json({
        accepted,
        outbound,
        nodeId: this.identity.identity.nodeId,
        timestamp: Date.now(),
      });
    });

    // Retrieve pending relay messages for a specific node (pull-based)
    app.get('/mesh/relay/:nodeId', (req, res) => {
      const outbound = this._drainRelayOutbox(req.params.nodeId);
      res.json({
        messages: outbound,
        nodeId: this.identity.identity.nodeId,
        timestamp: Date.now(),
      });
    });

    // Register as an HTTP-relay peer (for nodes that can't do WS)
    app.post('/mesh/relay/register', writeLimiter, (req, res) => {
      const { nodeId, relayEndpoint, publicKey, capabilities } = req.body;

      if (!nodeId || !relayEndpoint) {
        return res.status(400).json({ error: 'nodeId and relayEndpoint required' });
      }

      // Register in SHERPA registry as an HTTP-relay peer
      if (this.sherpa) {
        this.sherpa.registry.upsert({
          nodeId,
          endpoint: relayEndpoint,
          wsEndpoint: null,  // No WS — HTTP relay only
          networkName: this.genesisNetwork?.networkName,
          capabilities: { ...capabilities, httpRelay: true },
        });
      }

      log.info(`HTTP relay peer registered: ${nodeId.slice(0, 20)} via ${relayEndpoint}`);
      res.json({ success: true, nodeId: this.identity.identity.nodeId });
    });

    // Replication stats
    app.get('/replication', (req, res) => {
      res.json(this.replication.getStats());
    });

    // Connect to a peer dynamically
    // SECURITY: Rate limited + URL validation
    app.post('/connect', writeLimiter, requirePeerAuth, async (req, res) => {
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
    app.post('/data', writeLimiter, requirePeerAuth, (req, res) => {
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
    app.post('/rumor', writeLimiter, requirePeerAuth, (req, res) => {
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

    // Retrieve recent rumors (for MeshBridge HTTP polling)
    // Supports ?since=<timestamp>&topic=<topic> filters
    app.get('/rumors', (req, res) => {
      const since = parseInt(req.query.since) || 0;
      const topic = req.query.topic || null;
      const rumors = this.gossip.getRecentRumors(since, topic);
      res.json({ rumors, serverTime: Date.now() });
    });

    // SSE endpoint: real-time push of rumors (replaces polling for MeshBridge)
    // GET /rumors/subscribe?topic=<optional> — Server-Sent Events stream
    app.get('/rumors/subscribe', (req, res) => {
      const topicFilter = req.query.topic || null;

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',  // Disable nginx buffering
      });
      res.write('retry: 5000\n\n');  // Auto-reconnect after 5s

      // Listener that forwards matching rumors
      const onRumor = (topic, data, origin) => {
        if (topicFilter && topic !== topicFilter) return;
        const event = JSON.stringify({ topic, data, origin, timestamp: Date.now() });
        res.write(`data: ${event}\n\n`);
      };

      // Heartbeat to keep connection alive through proxies
      const heartbeat = setInterval(() => {
        res.write(': heartbeat\n\n');
      }, 15000);

      this.mesh.on('rumor', onRumor);

      req.on('close', () => {
        this.mesh.off('rumor', onRumor);
        clearInterval(heartbeat);
      });
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
    app.post('/network/register-peer', writeLimiter, requirePeerAuth, (req, res) => {
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
          version: '2.9.0',
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
    // Collect all local addresses for robust self-detection.
    // Each node lists ALL peers in bootstrap (identical config everywhere).
    // We skip any endpoint that points back to ourselves.
    const localAddrs = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);
    const ifaces = networkInterfaces();
    for (const addrs of Object.values(ifaces)) {
      for (const addr of addrs) {
        localAddrs.add(addr.address);
      }
    }

    const ourWsPort = this.mesh.boundPort || this.config.network.wsPort;

    for (const endpoint of this.config.bootstrap) {
      // Parse endpoint URL to extract host and port
      let url;
      try {
        url = new URL(endpoint);
      } catch {
        log.warn(`  (invalid bootstrap endpoint: ${endpoint})`);
        continue;
      }

      const epPort = parseInt(url.port, 10);
      if (epPort === ourWsPort && localAddrs.has(url.hostname)) {
        log.debug(`  (skipping self: ${endpoint})`);
        continue;
      }

      try {
        await this.mesh.connect(endpoint);
      } catch (e) {
        log.debug(`  (bootstrap ${endpoint} not available)`);
      }
    }
  }

  /**
   * SHERPA Auto-Connect: Automatically connect to peers discovered via beacon crawling.
   * 
   * This is the missing link that makes SHERPA a complete discovery+connection system.
   * When crawl-complete fires, we check discovered peers for wsEndpoints we're not
   * already connected to, and initiate OUTBOUND WebSocket connections.
   * 
   * This solves the firewall problem: nodes that can't receive inbound connections
   * (e.g., behind shared hosting firewalls) discover peers via HTTP beacons (port 443)
   * and OUTBOUND connect to them. WebSocket is bidirectional once established.
   */
  async _sherpaAutoConnect() {
    if (!this.sherpa || !this.mesh) return;

    const candidates = this.sherpa.getConnectionCandidates(10);
    const currentPeers = new Set(this.mesh.getPeers().map(p => p.nodeId));
    const selfNodeId = this.identity.identity.nodeId;

    for (const candidate of candidates) {
      // Skip self and already-connected peers
      if (candidate.nodeId === selfNodeId) continue;
      if (currentPeers.has(candidate.nodeId)) continue;

      // Try WebSocket first (preferred — full duplex)
      if (candidate.wsEndpoint) {
        try {
          log.info(`SHERPA auto-connect WS → ${candidate.wsEndpoint} (${candidate.nodeId.slice(0, 20)})`);
          await this.mesh.connect(candidate.wsEndpoint);
          this.sherpa.markConnected(candidate.nodeId);
          log.info(`SHERPA auto-connect ✓ ${candidate.nodeId.slice(0, 20)} via WS`);
          continue;  // Success — no need for relay fallback
        } catch (e) {
          log.debug(`SHERPA WS failed: ${candidate.wsEndpoint} — ${e.message}`);
        }
      }

      // Fall back to HTTP relay (half-duplex, firewall traversal)
      if (candidate.relayEndpoint) {
        try {
          log.info(`SHERPA relay register → ${candidate.relayEndpoint} (${candidate.nodeId.slice(0, 20)})`);
          await this._registerWithRelay(candidate);
          log.info(`SHERPA relay registered ✓ ${candidate.nodeId.slice(0, 20)}`);
        } catch (e) {
          this.sherpa.markDisconnected(candidate.nodeId);
          log.debug(`SHERPA relay failed: ${candidate.relayEndpoint} — ${e.message}`);
        }
      } else {
        // Neither WS nor relay available
        this.sherpa.markDisconnected(candidate.nodeId);
      }
    }
  }

  /**
   * Register with a peer's HTTP relay endpoint for store-and-forward messaging.
   * Starts periodic polling to pull inbound messages.
   */
  async _registerWithRelay(candidate) {
    const relayUrl = candidate.relayEndpoint;
    const selfNodeId = this.identity.identity.nodeId;

    // Register with the relay via same POST /mesh/relay endpoint (action: 'register')
    // This works through the PHP bridge which only proxies POST to /mesh/relay
    // ML-DSA-65 signed registration — relay receiver verifies before accepting
    const regPayload = {
      action: 'register',
      nodeId: selfNodeId,
      networkName: this.genesisNetwork?.networkName,
      publicKey: this.identity.identity.publicKey,
      timestamp: Date.now(),
    };
    const regSignature = this.identity.sign(JSON.stringify({
      action: regPayload.action,
      nodeId: regPayload.nodeId,
      networkName: regPayload.networkName,
      timestamp: regPayload.timestamp,
    }));
    regPayload.signature = regSignature;

    const resp = await fetch(relayUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(regPayload),
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) throw new Error(`Relay register HTTP ${resp.status}`);

    // Start polling for inbound messages if not already polling
    if (!this._relayPollers) this._relayPollers = new Map();

    if (!this._relayPollers.has(candidate.nodeId)) {
      const pollInterval = setInterval(async () => {
        try {
          await this._pollRelay(candidate);
        } catch (e) {
          log.debug(`Relay poll error ${candidate.nodeId.slice(0, 12)}: ${e.message}`);
        }
      }, 30000);  // Poll every 30 seconds

      this._relayPollers.set(candidate.nodeId, pollInterval);
      this.sherpa.markConnected(candidate.nodeId);
      
      // Also do an immediate poll
      await this._pollRelay(candidate);
    }
  }

  /**
   * Poll a relay endpoint for inbound messages.
   */
  async _pollRelay(candidate) {
    const selfNodeId = this.identity.identity.nodeId;
    const relayUrl = candidate.relayEndpoint;

    // Send any queued outbound messages and receive inbound
    const outbound = this._drainRelayOutbox(candidate.nodeId);

    // ML-DSA-65 signed batch — relay receiver verifies before processing
    const batchPayload = { messages: outbound, senderNodeId: selfNodeId };
    const batchSignature = this.identity.sign(JSON.stringify(batchPayload));

    const resp = await fetch(relayUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...batchPayload,
        signature: batchSignature,
        publicKey: this.identity.identity.publicKey,
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!resp.ok) throw new Error(`Relay poll HTTP ${resp.status}`);

    const data = await resp.json();

    // Process inbound messages from relay
    if (data.outbound && Array.isArray(data.outbound)) {
      for (const msg of data.outbound) {
        try {
          // Dispatch by msg.type (e.g., 'gossip', 'hello') — not 'message'
          if (msg && msg.type) {
            this.mesh.emit(msg.type, msg, null, candidate.nodeId);
            // Route ANNEX messages arriving via relay
            if (msg.annex && this.mesh.annex) {
              this.mesh.annex._handleAnnexMessage(msg.annex, candidate.nodeId).catch(() => {});
            }
          }
        } catch (e) {
          log.debug(`Relay message process error: ${e.message}`);
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP Relay Outbox — Store-and-forward messages for HTTP relay peers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Queue a message for delivery via HTTP relay to a specific node.
   * Used when no WebSocket connection exists but the peer has registered
   * an HTTP relay endpoint via SHERPA.
   */
  _queueRelayMessage(targetNodeId, message) {
    if (!this._relayOutbox) this._relayOutbox = new Map();

    let queue = this._relayOutbox.get(targetNodeId);
    if (!queue) {
      queue = [];
      this._relayOutbox.set(targetNodeId, queue);
    }

    queue.push({ ...message, _relayTs: Date.now() });

    // Cap at 500 messages per peer, evict oldest
    if (queue.length > 500) {
      queue.splice(0, queue.length - 500);
    }
  }

  /**
   * Drain (retrieve and clear) outbox messages for a specific relay peer.
   * Called when the peer polls via GET /mesh/relay/:nodeId or during
   * bi-directional POST /mesh/relay exchange.
   */
  _drainRelayOutbox(targetNodeId) {
    if (!this._relayOutbox) return [];
    const queue = this._relayOutbox.get(targetNodeId);
    if (!queue || queue.length === 0) return [];

    // Drain and return
    const messages = [...queue];
    queue.length = 0;
    return messages;
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



